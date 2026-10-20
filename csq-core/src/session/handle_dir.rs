//! Handle-dir model: ephemeral `term-<pid>` directories with symlinks to `config-N`.
//!
//! Each `csq run` creates a `term-<pid>` handle directory that contains symlinks
//! pointing at the permanent `config-<N>` account directory. `csq swap` atomically
//! repoints these symlinks. The daemon sweeps orphaned handle dirs when the PID dies.
//!
//! See `specs/02-csq-handle-dir-model.md` for the authoritative spec.

use crate::accounts::identity_store::{
    account_to_identity_paths, credentials_codex_path_for, settings_path_for,
};
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::credentials::keychain;
use crate::error::CredentialError;
use crate::session::isolation::{self, SHARED_ITEMS};
use crate::session::merge::merge_settings;
use crate::types::AccountNum;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Items in the handle dir that are symlinks to `config-N/<item>`.
/// These get repointed on swap.
///
/// `.claude.json` is intentionally EXCLUDED — CC writes per-project state
/// (the `projects` map) into it, and symlinking to config-N's copy leaks
/// project history from every directory that account was ever used in.
/// This causes `--resume` to show sessions from all projects instead of
/// filtering to the current CWD. Letting CC create a fresh `.claude.json`
/// per handle dir restores correct project-scoped behavior.
///
/// `settings.json` is also intentionally EXCLUDED — it is materialized as
/// a real file by [`materialize_handle_settings`] by deep-merging the
/// user's `~/.claude/settings.json` (global customization — statusLine,
/// permissions.defaultMode, plugins) with `config-<N>/settings.json`
/// (slot-specific env block for 3P bindings). A bare symlink would
/// replace the user layer entirely because `CLAUDE_CONFIG_DIR` overrides
/// the home settings path.
/// Codex state that is SHARED across every terminal bound to one account,
/// expressed as `(handle-dir name, config-N name)`.
///
/// # Why this list exists and why it kept being wrong
///
/// A codex handle dir is provisioned by an ALLOWLIST: anything named here is
/// symlinked back to `config-N`, and **anything not named here becomes a real file
/// inside `term-<pid>/` that dies with the handle dir.** The default is therefore
/// per-terminal, and every capability codex-cli adds is silently unshared until
/// someone remembers to add it.
///
/// That is not hypothetical. Measured on a maintainer host 2026-08-19: three live
/// handle dirs each held their own `state_5.sqlite` (35M + 35M + 7.1M), which is where
/// codex-cli keeps conversation NAMES and recency. `sessions/` was correctly shared, so
/// the conversations themselves were intact while their names were not — a thread named
/// in one terminal read as unnamed in the next, and a `/rename` performed in one
/// terminal was invisible to every other.
///
/// The sqlite files carry a SCHEMA-VERSION suffix (`state_5`, `logs_2`), so naming them
/// literally would go stale the next time codex bumps one. They are matched by prefix
/// against what `config-N` actually holds instead — see `codex_shared_pairs`.
/// Whether a shared codex-home entry is a FILE or a DIRECTORY.
///
/// DECLARED, never inferred. The previous code guessed from the filename —
/// `.jsonl`/`.sqlite` meant file, everything else meant directory — so
/// `version.json`, `models_cache.json` and `installation_id` (all FILES in a
/// real `~/.codex`) were pre-created as DIRECTORIES. codex-cli then could not
/// write them and aborted with `failed to start embedded app server`, which
/// names neither the file nor the directory that caused it.
///
/// The suffix rule was a negative default: anything it had not been taught was
/// silently a directory, so ADDING a file-shaped entry was enough to break the
/// spawn (`cc-artifacts.md` Rule 10 — enumerate, do not default). With the kind
/// in the tuple the compiler makes a new entry state it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SharedKind {
    File,
    Dir,
}

const CODEX_SHARED_STATE: &[(&str, &str, SharedKind)] = &[
    ("sessions", "codex-sessions", SharedKind::Dir),
    ("history.jsonl", "codex-history.jsonl", SharedKind::File),
    // Everything below was found SPLIT on a maintainer host by
    // `session::share_audit`, not predicted. `state_<N>.sqlite` was the reported
    // symptom; these were the rest of the same profile:
    //   plugins 119.7M · thread_history_1 112.5M · state_5 104.6M · skills 1.1M,
    //   plus memories/goals/queue and the small per-profile files — ~440M of a
    //   codex profile that was being rebuilt from scratch in every terminal.
    ("skills", "codex-skills", SharedKind::Dir),
    ("plugins", "codex-plugins", SharedKind::Dir),
    (
        "session_index.jsonl",
        "codex-session_index.jsonl",
        SharedKind::File,
    ),
    (
        "models_cache.json",
        "codex-models_cache.json",
        SharedKind::File,
    ),
    ("version.json", "codex-version.json", SharedKind::File),
    ("installation_id", "codex-installation_id", SharedKind::File),
    // A lock shared by nobody is not a lock: two terminals writing one thread must
    // contend on the SAME directory, or the guard is decorative.
    (
        "thread-writer-locks",
        "codex-thread-writer-locks",
        SharedKind::Dir,
    ),
];

/// Prefixes of codex's schema-versioned sqlite state, shared account-wide.
///
/// Matched by prefix, never by exact name: `state_5.sqlite` becomes `state_6.sqlite` on
/// the next schema bump, and a literal name would silently stop matching — which is the
/// failure this whole list exists to correct, one version later.
///
/// Only the base `.sqlite` is linked. SQLite resolves a symlink before placing its
/// `-wal`/`-shm` sidecars, so those land beside the real database in `config-N` on their
/// own; linking them separately would create files the engine then has to reconcile.
/// Any `*.sqlite` in `config-N` is shared. Deliberately a SUFFIX rule rather than a
/// prefix list: the host audit found `state_5`, `logs_2`, `goals_1`, `memories_1`,
/// `queue_1` and `thread_history_1`, and a list naming today's six would miss the
/// seventh exactly as the original five-item list missed `state_5`. The question this
/// answers is "is it a database", not "is it a database I have heard of".
const CODEX_SHARED_SQLITE_SUFFIX: &str = ".sqlite";

/// Every `(handle-dir name, config-N target)` pair codex must SHARE for this account.
///
/// Fixed pairs plus each schema-versioned sqlite `config-N` actually holds, discovered
/// by prefix rather than named literally so a version bump cannot silently unshare it.
/// A `-wal`/`-shm` sidecar is deliberately skipped: SQLite places those beside the
/// resolved database itself.
fn codex_shared_pairs(config_dir: &Path) -> Vec<(String, PathBuf, SharedKind)> {
    let mut pairs: Vec<(String, PathBuf, SharedKind)> = CODEX_SHARED_STATE
        .iter()
        .map(|(name, target, kind)| ((*name).to_string(), config_dir.join(target), *kind))
        .collect();

    if let Ok(entries) = std::fs::read_dir(config_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.ends_with(CODEX_SHARED_SQLITE_SUFFIX) {
                continue;
            }
            // A `*.sqlite` discovered in config-N is a database — always a file.
            pairs.push((name.to_string(), config_dir.join(name), SharedKind::File));
        }
    }
    pairs
}

/// Link one shared item, CREATING the target when it does not exist yet.
///
/// The create is the load-bearing half. The previous behaviour skipped an absent target
/// and left codex-cli to make a real file in the handle dir — so an item that WAS on the
/// share list still ended up per-terminal, purely because it had not been written yet
/// the first time a handle dir was built. Measured on a maintainer host 2026-08-19:
/// `history.jsonl` was listed as shared and was a real per-terminal file in every live
/// handle dir, because `config-N/codex-history.jsonl` did not exist at provisioning time.
/// Being on the list has to be sufficient; otherwise the list describes an intention
/// rather than a guarantee.
/// A shared codex-home target whose on-disk shape disagrees with its DECLARED
/// kind — the state that makes codex-cli abort with `failed to start embedded
/// app server`, an error naming neither the entry nor the shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedShapeMismatch {
    /// codex-home entry name, e.g. `version.json`.
    pub name: String,
    /// The `config-N/codex-*` path that is wrong.
    pub path: PathBuf,
    /// What is on disk.
    pub found_dir: bool,
    /// What codex-cli needs.
    pub want_dir: bool,
    /// Whether the next spawn will self-heal it (an EMPTY dir where a file
    /// belongs). `false` means it needs an operator: repairing would destroy
    /// state, so csq will not do it.
    pub repairable: bool,
}

impl SharedShapeMismatch {
    /// `true` when the next spawn repairs this automatically.
    pub fn self_heals_hint(&self) -> bool {
        self.repairable
    }
}

/// Report every shared codex target in `config_dir` whose shape is wrong.
///
/// Reads the SAME `CODEX_SHARED_STATE` table the provisioning path uses, rather
/// than re-deriving a list — a diagnostic that enumerates its own copy drifts
/// from the writer and then reports on a world the product left
/// (`diagnostic-surface-parity.md`).
pub fn shared_codex_shape_mismatches(config_dir: &Path) -> Vec<SharedShapeMismatch> {
    let mut out = Vec::new();
    for (name, target, kind) in codex_shared_pairs(config_dir) {
        let Ok(meta) = target.symlink_metadata() else {
            continue; // absent is fine: the spawn path creates it correctly
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let found_dir = meta.is_dir();
        let want_dir = kind == SharedKind::Dir;
        if found_dir == want_dir {
            continue;
        }
        out.push(SharedShapeMismatch {
            name,
            found_dir,
            want_dir,
            repairable: found_dir && !want_dir && dir_is_empty(&target),
            path: target,
        });
    }
    out
}

/// `true` when `p` is a directory containing nothing.
fn dir_is_empty(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut d| d.next().is_none())
        .unwrap_or(false)
}

/// Repair a target already created with the WRONG shape, but ONLY when doing so
/// destroys nothing.
///
/// The kind used to be inferred from the filename, so hosts provisioned before
/// that fix carry `codex-version.json`, `codex-models_cache.json` and
/// `codex-installation_id` as empty DIRECTORIES. Fixing the creation path alone
/// leaves those hosts broken forever: the target already exists, so the create
/// branch never runs, and codex-cli keeps failing with `failed to start embedded
/// app server`.
///
/// Deliberately narrow. The ONLY repaired case is an EMPTY directory where a
/// file belongs — provably zero data loss. A non-empty directory, or a file
/// where a directory belongs, is LEFT ALONE and surfaced by `csq doctor`
/// instead: self-healing must never be able to delete state a user would miss.
fn repair_wrong_shaped_target(name: &str, target: &Path, kind: SharedKind) {
    let Ok(meta) = target.symlink_metadata() else {
        return;
    };
    if meta.file_type().is_symlink() {
        return; // not ours to reshape
    }
    let is_dir = meta.is_dir();
    let want_dir = kind == SharedKind::Dir;
    if is_dir == want_dir {
        return; // already correct
    }
    if is_dir && !want_dir && dir_is_empty(target) {
        if std::fs::remove_dir(target).is_ok() {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(target);
            debug!(
                item = name,
                "repaired wrong-shaped shared codex target (empty dir -> file)"
            );
        }
        return;
    }
    // Anything else would destroy data. Leave it; `csq doctor` reports it.
    debug!(
        item = name,
        is_dir, want_dir, "shared codex target has the wrong shape and cannot be repaired safely"
    );
}

fn link_shared_codex_item(
    handle_dir: &Path,
    name: &str,
    target: &Path,
    kind: SharedKind,
) -> Result<(), CredentialError> {
    repair_wrong_shaped_target(name, target, kind);
    if !target.exists() && target.symlink_metadata().is_err() {
        let created = match kind {
            SharedKind::File => std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(target)
                .map(|_| ()),
            SharedKind::Dir => std::fs::create_dir_all(target),
        };
        // Non-fatal: a target we cannot pre-create is left to codex-cli, which is the
        // old behaviour. Better a degraded share than a failed spawn.
        if let Err(e) = created {
            debug!(item = name, error = %e, "could not pre-create shared codex target");
            return Ok(());
        }
    }
    let link = handle_dir.join(name);
    create_symlink(target, &link).map_err(|e| CredentialError::Io {
        path: link,
        source: e,
    })
}

/// Handle-dir name of the Codex hooks file linked to the user-global layer.
const CODEX_HOOKS_FILE: &str = "hooks.json";

/// What `csq doctor` prints when the user-global Codex hooks file is absent. A missing
/// global creates no link (no dangling symlink, no per-handle copy), so the terminal runs
/// without global hooks; this text makes that visible.
pub const CODEX_HOOKS_GLOBAL_MISSING_MESSAGE: &str =
    "global hooks.json missing \u{2014} terminals run without global hooks";

/// Doctor note printed with the per-handle hooks rows: the handle `hooks.json` is a
/// write-through symlink to the one shared global file.
pub const CODEX_HOOKS_WRITE_THROUGH_NOTE: &str =
    "handle hooks.json is a symlink to the shared global hooks.json: an edit made through \
     one terminal edits it for every terminal";

/// Largest hooks file the subset check will read; a bigger file is foreign. Enforced AT READ
/// by `read_regular_bounded` (open, fstat, `take(limit + 1)`), never by a prior stat.
const CODEX_HOOKS_MAX_BYTES: u64 = 1 << 20;

/// The user-global Codex hooks file, `~/.codex/hooks.json`, resolved from the real home
/// directory exactly as `providers::codex::trust::source_path` resolves `~/.codex/config.toml`.
///
/// Test builds (`cfg(test)` or the `test-utils` feature) NEVER read the real home: the
/// fixture seam `CSQ_TEST_CODEX_GLOBAL_HOOKS` names the file, and an unset seam yields `None`
/// (no link), so a test that does not opt in cannot touch the developer's `~/.codex`.
pub fn codex_global_hooks_path() -> Option<PathBuf> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        std::env::var_os("CSQ_TEST_CODEX_GLOBAL_HOOKS").map(PathBuf::from)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    dirs::home_dir().map(|home| home.join(".codex").join(CODEX_HOOKS_FILE))
}

/// The ONE predicate for "the user-global hooks file exists", shared by the link path and
/// `csq doctor`: after resolving symlinks it is a REGULAR file that can be opened and read.
/// A directory, a FIFO, a dangling link or an unreadable file all count as missing. One
/// non-blocking open, then `fstat` on the open handle, then a bounded read (`open_regular`):
/// a path swapped for a FIFO between a check and the open cannot hang it.
#[must_use]
pub fn codex_global_hooks_usable(global: &Path) -> bool {
    use std::io::Read;
    let Some(file) = open_regular(global, false) else {
        return false;
    };
    let mut probe = [0u8; 1];
    file.take(1).read(&mut probe).is_ok()
}

/// Whether `local` is a subset of `global`, both parsed JSON.
///
/// Definition: every key path and every array element in `local` is present in `global`.
/// - Objects: each key of `local` exists in `global` and its value is a subset of the
///   global value at that key (extra global keys are allowed).
/// - Arrays: each element of `local` is a subset of SOME element of `global` (order and
///   extra global elements are ignored).
/// - Scalars (string, number, bool, null): equal. A type mismatch is never a subset.
///
/// An empty local object or array is a subset of any global value of the same type.
fn json_is_subset(local: &serde_json::Value, global: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (local, global) {
        (Value::Object(l), Value::Object(g)) => l
            .iter()
            .all(|(k, lv)| g.get(k).is_some_and(|gv| json_is_subset(lv, gv))),
        (Value::Array(l), Value::Array(g)) => {
            l.iter().all(|le| g.iter().any(|ge| json_is_subset(le, ge)))
        }
        (l, g) => l == g,
    }
}

/// Opens `path` once: non-blocking on unix (so a FIFO cannot hang the open) and without
/// following a final symlink when `nofollow`; then requires the OPEN handle to be a regular
/// file (`fstat`). A device, a FIFO or an unreadable path is `None`.
fn open_regular(path: &Path, nofollow: bool) -> Option<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = libc::O_NONBLOCK;
        if nofollow {
            flags |= libc::O_NOFOLLOW;
        }
        opts.custom_flags(flags);
    }
    #[cfg(not(unix))]
    let _ = nofollow;
    let file = opts.open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// Reads the regular file at `path` with the size bound enforced AT READ: `open_regular`
/// then `take(CODEX_HOOKS_MAX_BYTES + 1)`. A device, a FIFO, an unreadable file or one over
/// the limit is `None`. There is no stat-then-read gap.
pub(crate) fn read_regular_bounded(path: &Path, nofollow: bool) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = open_regular(path, nofollow)?;
    let mut buf = Vec::new();
    file.take(CODEX_HOOKS_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .ok()?;
    (buf.len() as u64 <= CODEX_HOOKS_MAX_BYTES).then_some(buf)
}

/// Whether `local` (the bytes already read from the handle's regular file) is parseable JSON
/// that is a subset of the parseable JSON file `global` ([`json_is_subset`]). Unreadable,
/// oversize or unparseable input on either side is `false`: the caller then keeps the file
/// (never deletes user content).
fn local_hooks_is_subset_of_global(local: &[u8], global: &Path) -> bool {
    let parse = |bytes: &[u8]| serde_json::from_slice::<serde_json::Value>(bytes).ok();
    match (
        parse(local),
        read_regular_bounded(global, false).and_then(|b| parse(&b)),
    ) {
        (Some(l), Some(g)) => json_is_subset(&l, &g),
        _ => false,
    }
}

/// Removes `path`, logging a failure with the fixed `tag` (a missing entry is not a failure).
/// The main action paths use this instead of discarding the error.
fn remove_file_logged(path: &Path, tag: &'static str) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(error_kind = tag, io_kind = ?e.kind(), "could not remove a handle-dir entry");
        }
    }
}

/// Removes a leftover `.swap-tmp` of ours before it is reused: a file or symlink with
/// `remove_file`, an EMPTY directory with `remove_dir`. A non-empty directory (or anything
/// else that cannot be removed) is an error: the caller refuses the link.
fn clear_swap_tmp(tmp: &Path) -> std::io::Result<()> {
    match tmp.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => std::fs::remove_dir(tmp),
        Ok(_) => std::fs::remove_file(tmp),
    }
}

/// Name prefix of a foreign `hooks.json` csq moved aside instead of overwriting (the content is
/// preserved, never deleted).
const CODEX_HOOKS_FOREIGN_PREFIX: &str = "hooks.json.csq-foreign-";

/// Marker csq writes beside a COPY of the global hooks (a host that cannot create symlinks):
/// the SHA-256 of the copied bytes. It is what tells a csq copy from a foreign regular file.
const CODEX_HOOKS_COPY_MARKER: &str = "hooks.json.csq-copy-sha256";

/// The temp name the link is staged under.
const CODEX_HOOKS_SWAP_TMP: &str = "hooks.json.swap-tmp";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Whether the symlink `link` points at `target`. On Windows `read_link` may spell the target
/// with a `\\?\` prefix, so the two are compared canonicalized there as well.
fn link_points_to(link: &Path, target: &Path) -> bool {
    let Ok(read) = std::fs::read_link(link) else {
        return false;
    };
    read == target
        || (cfg!(windows)
            && matches!(
                (std::fs::canonicalize(&read), std::fs::canonicalize(target)),
                (Ok(a), Ok(b)) if a == b
            ))
}

/// Whether a leftover `.swap-tmp` is something [`clear_swap_tmp`] cannot clear: a NON-EMPTY
/// directory. A file, a symlink or an empty directory is cleared, so it raises no alarm. The
/// link path and `csq doctor` share this predicate.
fn swap_tmp_blocked(tmp: &Path) -> bool {
    match tmp.symlink_metadata() {
        Ok(m) if m.is_dir() => std::fs::read_dir(tmp).map_or(true, |mut d| d.next().is_some()),
        _ => false,
    }
}

/// Names (never paths or content) of the foreign hooks entries csq moved aside in `handle_dir`.
#[must_use]
pub fn codex_hooks_preserved_foreign(handle_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(handle_dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|n| n.starts_with(CODEX_HOOKS_FOREIGN_PREFIX))
        .collect();
    out.sort();
    out
}

/// Per-handle state of `hooks.json` against the user-global hooks file, as `csq doctor`
/// reports it. Derived from the disk by [`codex_hooks_link_state`], which uses the same
/// [`codex_global_hooks_usable`] predicate the link path uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodexHooksLinkState {
    /// A symlink to the usable global file.
    Ok,
    /// No `hooks.json` although the global exists (a pre-upgrade handle, or the global
    /// appeared later): the next launch or repoint links it.
    Unlinked,
    /// A regular file (or other non-link) sits where the link belongs; the next launch or
    /// repoint moves it aside (content preserved) and links.
    ForeignFile,
    /// A symlink to somewhere other than the global whose target does not exist.
    Dangling,
    /// A symlink to somewhere other than the global.
    WrongTarget,
    /// The global file is absent, unreadable or not a regular file.
    MissingGlobal,
    /// A leftover non-empty `hooks.json.swap-tmp` directory csq cannot remove blocks the link.
    SwapTmpBlocked,
    /// A csq COPY of the global (the host cannot create symlinks) whose bytes equal the global.
    CopyCurrent,
    /// A csq COPY of the global that no longer equals it: relaunch or swap re-syncs it.
    CopyStale,
}

impl CodexHooksLinkState {
    /// Whether this state needs an operator row.
    #[must_use]
    pub fn is_problem(self) -> bool {
        self != Self::Ok
    }

    /// The doctor text for this state.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Ok => "linked to the global hooks.json",
            Self::Unlinked => {
                "hooks.json is not linked to the global hooks (relaunch or swap this terminal)"
            }
            Self::ForeignFile => {
                "hooks.json is a regular file, not the global link; the next launch or swap moves \
                 it aside (kept as hooks.json.csq-foreign-*) and links the global hooks"
            }
            Self::Dangling => "hooks.json is a symlink to a missing file other than the global",
            Self::WrongTarget => {
                "hooks.json is a symlink to a file other than the global hooks.json"
            }
            Self::MissingGlobal => CODEX_HOOKS_GLOBAL_MISSING_MESSAGE,
            Self::SwapTmpBlocked => {
                "hooks.json.swap-tmp cannot be removed; the hooks link was refused (remove it)"
            }
            Self::CopyCurrent => {
                "hooks.json is a copy of the global hooks (no symlink privilege); enable Windows \
                 Developer Mode for a live link"
            }
            Self::CopyStale => {
                "hooks.json is a STALE copy of the global hooks (no symlink privilege); relaunch \
                 or swap this terminal to re-sync, or enable Windows Developer Mode for a live link"
            }
        }
    }
}

/// The [`CodexHooksLinkState`] of `handle_dir`'s `hooks.json` against `global`.
#[must_use]
pub fn codex_hooks_link_state(handle_dir: &Path, global: Option<&Path>) -> CodexHooksLinkState {
    use CodexHooksLinkState as S;
    let state = link_state_ignoring_swap_tmp(handle_dir, global);
    let relink_needed = matches!(
        state,
        S::Unlinked | S::ForeignFile | S::WrongTarget | S::Dangling | S::CopyStale
    );
    if relink_needed && swap_tmp_blocked(&handle_dir.join(CODEX_HOOKS_SWAP_TMP)) {
        S::SwapTmpBlocked
    } else {
        state
    }
}

fn link_state_ignoring_swap_tmp(handle_dir: &Path, global: Option<&Path>) -> CodexHooksLinkState {
    use CodexHooksLinkState as S;
    let link = handle_dir.join(CODEX_HOOKS_FILE);
    let usable = global.filter(|g| codex_global_hooks_usable(g));
    match link.symlink_metadata() {
        Ok(m) if m.file_type().is_symlink() => {
            let Some(global) = global else {
                return S::MissingGlobal;
            };
            if link_points_to(&link, global) {
                if usable.is_some() {
                    S::Ok
                } else {
                    S::MissingGlobal
                }
            } else if link.exists() {
                S::WrongTarget
            } else {
                S::Dangling
            }
        }
        Ok(_) => copy_state(handle_dir, &link, usable).unwrap_or(S::ForeignFile),
        Err(_) if usable.is_none() => S::MissingGlobal,
        Err(_) => S::Unlinked,
    }
}

/// `Some` only when csq's copy marker sits beside `link`: the copy compared with the global by
/// digest. `None` is a foreign regular file.
fn copy_state(
    handle_dir: &Path,
    link: &Path,
    usable: Option<&Path>,
) -> Option<CodexHooksLinkState> {
    read_regular_bounded(&handle_dir.join(CODEX_HOOKS_COPY_MARKER), true)?;
    let Some(global) = usable else {
        return Some(CodexHooksLinkState::MissingGlobal);
    };
    let digest = |p: &Path, nofollow| read_regular_bounded(p, nofollow).map(|b| sha256_hex(&b));
    Some(match (digest(link, true), digest(global, false)) {
        (Some(local), Some(global)) if local == global => CodexHooksLinkState::CopyCurrent,
        _ => CodexHooksLinkState::CopyStale,
    })
}

/// Whether a Codex config turns hooks off, as observed on codex-cli 0.162.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodexHooksConfigState {
    /// Hooks are on (the default; csq never sets the flag).
    Enabled,
    /// `[features] hooks = false`, or `codex_hooks = false` when no `hooks` key is set.
    Disabled,
    /// The config is unparseable, oversize, unreadable, non-regular, or the flag has a
    /// non-boolean type (Codex refuses to load it). NEVER reported as "not disabled".
    Unknown,
    /// A top-level `profile = "…"` key: Codex 0.162.1 fails every command on it.
    LegacyProfileKey,
}

/// A handle's [`CodexHooksConfigState`] plus the profile files that would disable hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexHooksConfig {
    /// The state the base `config.toml` sets.
    pub state: CodexHooksConfigState,
    /// Names of `<name>.config.toml` profile files in the handle that set hooks off; the base
    /// state is NOT changed by them (they only apply under `--profile <name>`).
    pub profile_disabled: Vec<String>,
}

/// The state one Codex config file sets. Observed precedence: a `hooks` key, when present,
/// always wins over the legacy alias `codex_hooks` (which applies only when no `hooks` key is
/// set; key order is irrelevant); `[profiles.*]` tables are ignored by Codex; a top-level
/// `profile` key is a hard load error. An absent file is `Enabled`; a dangling link,
/// unreadable, oversize, non-UTF-8 or unparseable file, or a non-boolean flag, is `Unknown`.
fn hooks_state_of_file(path: &Path) -> CodexHooksConfigState {
    use CodexHooksConfigState as C;
    match std::fs::metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if path.symlink_metadata().is_ok() {
                C::Unknown
            } else {
                C::Enabled
            };
        }
        Err(_) => return C::Unknown,
    }
    let Some(bytes) = read_regular_bounded(path, false) else {
        return C::Unknown;
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return C::Unknown;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return C::Unknown;
    };
    if value.get("profile").is_some() {
        return C::LegacyProfileKey;
    }
    let Some(features) = value.get("features") else {
        return C::Enabled;
    };
    if !features.is_table() {
        return C::Unknown;
    }
    let (hooks, alias) = (features.get("hooks"), features.get("codex_hooks"));
    if [hooks, alias].into_iter().flatten().any(|v| !v.is_bool()) {
        return C::Unknown;
    }
    match hooks.or(alias).and_then(toml::Value::as_bool) {
        Some(false) => C::Disabled,
        _ => C::Enabled,
    }
}

/// The hooks-config state of the Codex config a handle resolves (`<handle>/config.toml`, the
/// per-slot symlink or the regular file a layered launch materializes), plus the profile files
/// (`<name>.config.toml`, layered by `codex --profile <name>`) that would disable hooks.
/// Read-only, for `csq doctor`.
#[must_use]
pub fn codex_hooks_config(handle_dir: &Path) -> CodexHooksConfig {
    let state = hooks_state_of_file(&handle_dir.join("config.toml"));
    let mut profile_disabled: Vec<String> = std::fs::read_dir(handle_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter_map(|n| n.strip_suffix(".config.toml").map(str::to_owned))
        .filter(|n| {
            !n.is_empty()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
        .filter(|n| {
            hooks_state_of_file(&handle_dir.join(format!("{n}.config.toml")))
                == CodexHooksConfigState::Disabled
        })
        .collect();
    profile_disabled.sort();
    CodexHooksConfig {
        state,
        profile_disabled,
    }
}

/// Whether the Codex config a handle resolves turns hooks off. Equivalent to
/// `codex_hooks_config(..).state == Disabled`: an unreadable or unparseable config is `false`
/// here, so a caller that must not treat that as "enabled" uses [`codex_hooks_config`].
#[must_use]
pub fn codex_hooks_disabled_by_config(handle_dir: &Path) -> bool {
    codex_hooks_config(handle_dir).state == CodexHooksConfigState::Disabled
}

/// Whether `handle_dir` has the Codex handle shape csq creates: `auth.json` is a symlink (the
/// credential link no launch path replaces) and `config.toml` is a symlink (plain launch) or a
/// regular file (the capability-layer / MCP-proxy launch materializes one in its place, see
/// `run.rs`). The same dual-marker shape [`repoint_handle_dir_codex`] guards on, relaxed only
/// for the `config.toml` a layered launch replaces.
fn is_codex_handle_shape(handle_dir: &Path) -> bool {
    let auth_is_link = handle_dir
        .join("auth.json")
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink());
    let config_ok = handle_dir
        .join("config.toml")
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink() || m.is_file());
    auth_is_link && config_ok
}

/// Every Codex handle dir under `base_dir`: a `term-*` directory with the Codex handle shape
/// (`is_codex_handle_shape`), whether its `config.toml` is the per-slot symlink or the
/// regular file a capability-layer launch materializes.
#[must_use]
pub fn codex_handle_dirs(base_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("term-"))
        })
        .map(|e| e.path())
        .filter(|p| p.is_dir() && is_codex_handle_shape(p))
        .collect();
    out.sort();
    out
}

/// A free `hooks.json.csq-foreign-<unix-ts>[-n]` name, or `None` when 1000 are taken.
fn foreign_aside_path(handle_dir: &Path) -> Option<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let free = |p: &PathBuf| p.symlink_metadata().is_err();
    let first = handle_dir.join(format!("{CODEX_HOOKS_FOREIGN_PREFIX}{ts}"));
    if free(&first) {
        return Some(first);
    }
    (1..1000)
        .map(|n| handle_dir.join(format!("{CODEX_HOOKS_FOREIGN_PREFIX}{ts}-{n}")))
        .find(free)
}

/// Puts a detached `aside` entry back at `link` when nothing has taken its place; otherwise
/// keeps it under a foreign-aside name. Never deletes it.
fn restore_aside(handle_dir: &Path, aside: &Path, link: &Path) {
    let dest = if link.symlink_metadata().is_err() {
        Some(link.to_path_buf())
    } else {
        foreign_aside_path(handle_dir)
    };
    let restored = dest.is_some_and(|d| std::fs::rename(aside, d).is_ok());
    if !restored {
        warn!(
            error_kind = "codex_hooks_aside_restore_failed",
            "could not put the detached hooks.json back; it is kept beside the handle's hooks"
        );
    }
}

/// Records the digest of a csq copy of the global hooks beside it.
fn write_copy_marker(handle_dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let marker = handle_dir.join(CODEX_HOOKS_COPY_MARKER);
    let tmp = crate::platform::fs::unique_tmp_path(&marker);
    let result = crate::platform::fs::write_new_private(&tmp, sha256_hex(bytes).as_bytes())
        .and_then(|()| crate::platform::fs::atomic_replace(&tmp, &marker));
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        std::io::Error::other(e.to_string())
    })
}

/// Whether `bytes` (the handle's regular `hooks.json`) is an unmodified csq copy: the marker's
/// digest equals the bytes' digest.
fn copy_is_ours(handle_dir: &Path, bytes: &[u8]) -> bool {
    read_regular_bounded(&handle_dir.join(CODEX_HOOKS_COPY_MARKER), true)
        .and_then(|m| String::from_utf8(m).ok())
        .is_some_and(|m| m.trim() == sha256_hex(bytes))
}

/// Links `<handle_dir>/hooks.json` to the user-global Codex `hooks.json` so a csq-launched
/// Codex terminal runs the same hooks as a vanilla one (owner directive: terminal settings
/// come from the global layer only). Used by both handle creation and repoint.
///
/// WRITE-THROUGH: `hooks.json` in a handle is a symlink to the ONE shared global file, so a
/// write through `$CODEX_HOOKS/hooks.json` in any terminal edits the global file for every
/// terminal and for vanilla Codex. `csq doctor` prints [`CODEX_HOOKS_WRITE_THROUGH_NOTE`]
/// beside the per-handle rows.
///
/// SANDBOX CAVEAT (observed, codex-cli 0.162.1, probe N10): a `workspace-write` sandboxed
/// Codex cannot write `$CODEX_HOME/hooks.json`, the symlink or its target while they sit
/// outside the workspace and `/tmp` (the real `~/.codex` layout). Codex gives `CODEX_HOME` no
/// special protection: a workspace containing `$HOME`, or a home under `/tmp`, IS writable.
/// The residual is bounded by Codex's hook trust: an edited hook is `modified` and does not
/// run until the user re-approves it, so a write-through edit cannot silently run new code.
///
/// - `global` is `None` or fails [`codex_global_hooks_usable`]: NO link is created. A
///   pre-existing hooks.json symlink whose target IS the global path is removed (it would
///   dangle; a failed removal is logged, `codex_hooks_stale_link_remove_failed`); anything else
///   is never touched. A later launch or repoint re-attempts the link once the global exists.
/// - Existing symlink already pointing at the global: kept, nothing is written.
/// - FOREIGN entry (a symlink elsewhere, or a regular file that is not a subset of the global,
///   is unparseable, oversize or not a regular file): MOVED ASIDE to
///   `hooks.json.csq-foreign-<unix-ts>` (content preserved, never deleted; warn
///   `codex_hooks_foreign_moved_aside`), then the global is linked. `csq doctor` lists it.
/// - Existing REGULAR file that is a subset of the global ([`json_is_subset`]), or an unmodified
///   csq copy: detached by a rename to an aside name, compared with what was read, and only then
///   replaced. A file that changed in the window is put back (`codex_hooks_changed_during_link`).
///   The final link creation never overwrites a file Codex recreated in the gap.
/// - A leftover `hooks.json.swap-tmp` is removed before use; if it cannot be (a non-empty
///   directory), the link is REFUSED (`codex_hooks_swap_tmp_blocked`, an `Err`) and doctor
///   shows it ([`swap_tmp_blocked`] is the shared predicate).
/// - Where the platform cannot create a symlink (Windows without Developer Mode) it makes a
///   copy or hard link instead. Launch does NOT fail: csq writes a COPY of the global, plus a
///   digest marker, re-synced on every launch and repoint; doctor reports `copy-current` or
///   `copy-stale` by digest.
fn link_codex_global_hooks(handle_dir: &Path, global: Option<&Path>) -> Result<(), std::io::Error> {
    let link = handle_dir.join(CODEX_HOOKS_FILE);
    let existing = link.symlink_metadata().ok();
    let Some(global) = global.filter(|g| codex_global_hooks_usable(g)) else {
        if let (Some(meta), Some(g)) = (existing.as_ref(), global) {
            if meta.file_type().is_symlink() && link_points_to(&link, g) {
                remove_file_logged(&link, "codex_hooks_stale_link_remove_failed");
            }
        }
        return Ok(());
    };
    let mut expected_local: Option<Vec<u8>> = None;
    let mut move_foreign = false;
    if let Some(meta) = existing.as_ref() {
        if meta.file_type().is_symlink() {
            if link_points_to(&link, global) {
                return Ok(());
            }
            warn!(
                error_kind = "codex_hooks_foreign_link",
                "handle-dir hooks.json is a symlink to a file other than the user-global \
                 Codex hooks; moving it aside"
            );
            move_foreign = true;
        } else {
            let bytes = meta
                .is_file()
                .then(|| read_regular_bounded(&link, true))
                .flatten()
                .filter(|b| {
                    copy_is_ours(handle_dir, b) || local_hooks_is_subset_of_global(b, global)
                });
            match bytes {
                Some(b) => expected_local = Some(b),
                None => {
                    warn!(
                        error_kind = "codex_hooks_foreign_file",
                        "handle-dir hooks.json is not a subset of the user-global Codex hooks; \
                         moving it aside"
                    );
                    move_foreign = true;
                }
            }
        }
    }
    let tmp = handle_dir.join(CODEX_HOOKS_SWAP_TMP);
    if let Err(e) = clear_swap_tmp(&tmp) {
        warn!(
            error_kind = "codex_hooks_swap_tmp_blocked",
            io_kind = ?e.kind(),
            "a leftover hooks.json.swap-tmp cannot be removed; hooks link refused"
        );
        return Err(e);
    }
    create_symlink(global, &tmp)?;
    #[cfg(test)]
    if FORCE_COPY_LINK.with(std::cell::Cell::get) {
        std::fs::remove_file(&tmp)?;
        std::fs::copy(global, &tmp)?;
    }
    let is_exact_link = tmp
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
        && link_points_to(&tmp, global);
    let mut copy_bytes: Option<Vec<u8>> = None;
    if !is_exact_link {
        remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
        let staged = read_regular_bounded(global, false)
            .filter(|b| crate::platform::fs::write_new_private_synced(&tmp, b).is_ok());
        let Some(bytes) = staged else {
            remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
            warn!(
                error_kind = "codex_hooks_copy_failed",
                "no symlink could be made and the global hooks could not be copied; not linked"
            );
            return Ok(());
        };
        warn!(
            error_kind = "codex_hooks_link_copy_fallback",
            "the platform cannot create a symlink; hooks.json is a copy of the global hooks, \
             re-synced on every launch and repoint (enable Windows Developer Mode for a link)"
        );
        copy_bytes = Some(bytes);
    }
    let mut aside: Option<PathBuf> = None;
    if existing.is_some() {
        #[cfg(test)]
        BEFORE_REREAD.with(|hook| {
            if let Some(f) = hook.borrow().as_ref() {
                f();
            }
        });
        if move_foreign {
            let Some(dest) = foreign_aside_path(handle_dir) else {
                remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
                warn!(
                    error_kind = "codex_hooks_foreign_aside_names_exhausted",
                    "no free hooks.json.csq-foreign-* name; the foreign entry is left in place"
                );
                return Ok(());
            };
            match std::fs::rename(&link, &dest) {
                Ok(()) => warn!(
                    error_kind = "codex_hooks_foreign_moved_aside",
                    "a foreign handle-dir hooks.json was moved aside (content kept)"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
                    warn!(
                        error_kind = "codex_hooks_foreign_move_failed",
                        io_kind = ?e.kind(),
                        "could not move a foreign hooks.json aside; left in place"
                    );
                    return Ok(());
                }
            }
        } else {
            let detached = handle_dir.join(format!(
                "{CODEX_HOOKS_FILE}.csq-aside-{}",
                std::process::id()
            ));
            match std::fs::rename(&link, &detached) {
                Ok(()) => {
                    if read_regular_bounded(&detached, true).as_deref() != expected_local.as_deref()
                    {
                        restore_aside(handle_dir, &detached, &link);
                        remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
                        warn!(
                            error_kind = "codex_hooks_changed_during_link",
                            "handle-dir hooks.json changed while it was being linked; kept"
                        );
                        return Ok(());
                    }
                    aside = Some(detached);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
                    warn!(
                        error_kind = "codex_hooks_aside_failed",
                        io_kind = ?e.kind(),
                        "could not detach hooks.json to link it; left in place"
                    );
                    return Ok(());
                }
            }
        }
    }
    #[cfg(test)]
    AFTER_ASIDE.with(|hook| {
        if let Some(f) = hook.borrow().as_ref() {
            f();
        }
    });
    let placed = match copy_bytes.as_deref() {
        Some(bytes) => {
            std::fs::rename(&tmp, &link).and_then(|()| write_copy_marker(handle_dir, bytes))
        }
        None => {
            let made = create_symlink(global, &link);
            remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
            remove_file_logged(
                &handle_dir.join(CODEX_HOOKS_COPY_MARKER),
                "codex_hooks_marker_remove_failed",
            );
            made
        }
    };
    match placed {
        Ok(()) => {
            if let Some(a) = aside.as_deref() {
                remove_file_logged(a, "codex_hooks_aside_remove_failed");
            }
            debug!(item = CODEX_HOOKS_FILE, "linked codex global hooks");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
            if let Some(a) = aside.as_deref() {
                remove_file_logged(a, "codex_hooks_aside_remove_failed");
            }
            warn!(
                error_kind = "codex_hooks_changed_during_link",
                "handle-dir hooks.json was recreated while it was being linked; kept"
            );
            Ok(())
        }
        Err(e) => {
            remove_file_logged(&tmp, "codex_hooks_tmp_remove_failed");
            if let Some(a) = aside.as_deref() {
                restore_aside(handle_dir, a, &link);
            }
            Err(e)
        }
    }
}

const ACCOUNT_BOUND_ITEMS: &[&str] = &[
    ".credentials.json",
    ".csq-account",
    ".current-account",
    ".quota-cursor",
];

// ── Ephemeral handle-dir prefix registry (positive allowlist) ──────────────
//
// Every filename PREFIX under `<base_dir>` (the `accounts/` root) that csq
// recognizes as an EPHEMERAL, csq-managed handle-dir namespace: a directory
// some producer creates transiently, that some reaper is responsible for
// eventually removing. This is a POSITIVE ALLOWLIST (`cc-artifacts.md` Rule
// 10) — a producer that invents a new ephemeral-dir name shape without
// registering its prefix here leaks forever, because every reaper in this
// module keys off a specific prefix rather than "everything under
// `accounts/` that isn't a known-permanent dir".
//
// This registry exists to close the `codex-exec-`/`gemini-exec-` incident:
// `csq exec` (`csq/src/cli/commands/exec.rs`) minted `codex-exec-<pid>` and
// `gemini-exec-<pid>` handle dirs with best-effort, error-discarding cleanup
// (`let _ = std::fs::remove_dir_all(...)`), and no sweeper's `term-`-only
// name check ever recognized the shape — so a kill, panic, or early return
// leaked the dir on disk forever. 54 such dirs were found orphaned on a
// single host.
//
// Each entry's producer + reaper:
//   "term-"                — csq run / csq swap         — sweep_dead_handles (main loop)
//   CAPTURE_DIR_PREFIX      — phase2b interactive capture — sweep_stale_capture_dirs
//   EXEC_CODEX_DIR_PREFIX   — csq exec --provider codex   — sweep_stale_exec_dirs
//   EXEC_GEMINI_DIR_PREFIX  — csq exec --provider gemini  — sweep_stale_exec_dirs
//
// Adding a new ephemeral producer? Add its prefix here AND wire a reaper
// call in `sweep_dead_handles` in the SAME change — `assert_dir_name_prefix_registered`
// (called by `create_handle_dir_named` / `create_handle_dir_codex_named`)
// refuses to create a dir whose prefix isn't registered, so a producer
// routed through those two functions fails loudly at creation time instead
// of leaking silently. A producer that mints its directory via raw
// `std::fs` calls (bypassing both `_named` helpers — as `csq exec`'s Gemini
// path does) is NOT caught by that guard; register its prefix here anyway
// so the reaper and `find_unregistered_ephemeral_looking_dirs` still see it.

/// Prefix for `csq exec --provider codex`'s ephemeral handle dirs
/// (`csq/src/cli/commands/exec.rs`, via [`create_handle_dir_codex_named`]).
/// Reaped by `sweep_stale_exec_dirs`. The producer always writes
/// `.live-pid` (`create_handle_dir_codex_named` calls
/// `markers::write_live_pid` unconditionally), so the reaper can use the
/// authoritative marker; it also tolerates a missing marker by falling
/// back to the PID embedded in the dir name itself (`codex-exec-<pid>`
/// has no further suffix, unlike `interactive-capture-<pid>-<seq>`).
pub const EXEC_CODEX_DIR_PREFIX: &str = "codex-exec-";

/// Prefix for `csq exec --provider gemini`'s ephemeral handle dirs
/// (`csq/src/cli/commands/exec.rs::create_gemini_handle_dir`). That
/// producer does NOT go through [`create_handle_dir_named`] (gemini-cli
/// reads credentials from `~/.gemini/oauth_creds.json`, not from a
/// symlinked handle dir, so none of the shared helper's symlink logic
/// applies) — it calls `std::fs::create_dir_all` directly and never
/// writes `.live-pid`. `assert_dir_name_prefix_registered` therefore
/// cannot guard this producer at creation time; the reaper
/// (`sweep_stale_exec_dirs`) falls back to parsing the PID straight out
/// of the dir name (`gemini-exec-<pid>`) for liveness.
pub const EXEC_GEMINI_DIR_PREFIX: &str = "gemini-exec-";

/// The full positive allowlist of ephemeral handle-dir prefixes. See the
/// module comment above for the producer/reaper pairing of each entry.
pub const EPHEMERAL_HANDLE_DIR_PREFIXES: &[&str] = &[
    "term-",
    CAPTURE_DIR_PREFIX,
    EXEC_CODEX_DIR_PREFIX,
    EXEC_GEMINI_DIR_PREFIX,
];

/// `true` when `name` is exactly a csq per-terminal handle dir name: `term-<digits>`.
/// The one name predicate shared by the cost cache and the Codex hook-trust prune.
#[must_use]
pub fn is_term_handle_dir_name(name: &str) -> bool {
    name.strip_prefix("term-")
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

/// The directory name csq mints for the terminal whose csq process is `pid`
/// (`term-<pid>`). THE one place the shape is spelled: the creators above and the
/// keychain orphan sweep (`credentials::keychain::orphans`), which recomputes the
/// service names of the items those dirs' terminals wrote, both call it, so the
/// sweep can never recognise a different shape than the writer produces
/// (`guard-reader-writer-parity.md` MUST-1).
pub fn term_handle_dir_name(pid: u32) -> String {
    format!("term-{pid}")
}

/// `true` when `name` starts with a registered ephemeral-handle-dir prefix.
pub fn is_registered_ephemeral_handle_dir_name(name: &str) -> bool {
    EPHEMERAL_HANDLE_DIR_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Refuses to create a handle dir whose name is neither the default
/// `term-<pid>` shape nor a registered prefix from
/// [`EPHEMERAL_HANDLE_DIR_PREFIXES`]. Called by [`create_handle_dir_named`]
/// and [`create_handle_dir_codex_named`] before any filesystem mutation —
/// a producer that invents a new prefix without registering it fails HERE,
/// loudly and immediately, instead of leaking a directory that no sweeper
/// will ever recognize (the exact bug class this registry exists to close).
fn assert_dir_name_prefix_registered(dir_name: &str) -> Result<(), CredentialError> {
    if is_registered_ephemeral_handle_dir_name(dir_name) {
        return Ok(());
    }
    Err(CredentialError::Corrupt {
        path: PathBuf::from(dir_name),
        reason: format!(
            "refusing to create ephemeral handle dir '{dir_name}': its prefix is not \
             registered in EPHEMERAL_HANDLE_DIR_PREFIXES (csq-core/src/session/handle_dir.rs). \
             Register the prefix there and wire a reaper into sweep_dead_handles before using it \
             — an unregistered ephemeral dir leaks forever, because no sweeper's name check \
             recognizes it."
        ),
    })
}

/// Top-level directory names/prefixes under `<base_dir>` (the `accounts/`
/// root) that are PERMANENT — never ephemeral, never swept. `config-<N>` is
/// prefix-matched (per-slot); `identities` and `credentials` are exact
/// names. See `specs/02-csq-handle-dir-model.md` INV-01.
const PERMANENT_TOP_LEVEL_DIR_NAMES: &[&str] = &["identities", "credentials"];
const PERMANENT_TOP_LEVEL_DIR_PREFIXES: &[&str] = &["config-"];

/// Lists directory names directly under `base_dir` that are neither a
/// registered ephemeral handle-dir prefix
/// ([`is_registered_ephemeral_handle_dir_name`]) nor a known-permanent
/// directory. A non-empty result means some producer is creating a
/// directory shape no predicate in this module recognizes — exactly the
/// `codex-exec-`/`gemini-exec-` incident this registry exists to close.
///
/// Hidden entries (`.swap-lock`, `.sweep-tombstone-*`, and similar
/// dotfile/dotdir state) and non-directory entries are excluded — this
/// function is scoped to the directory-namespace shape a handle-dir
/// producer creates, not every file under `accounts/`.
///
/// Not wired into any CLI/doctor surface yet (that wiring is a follow-up);
/// its purpose today is to give a future unregistered producer a way to
/// fail a TEST rather than leak silently and undetectably — see
/// `handle_dir_prefix_registry_flags_unregistered_dir` in this module's
/// test suite for the non-vacuity proof.
pub fn find_unregistered_ephemeral_looking_dirs(base_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return Vec::new();
    };
    let mut unrecognized = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if is_registered_ephemeral_handle_dir_name(name) {
            continue;
        }
        if PERMANENT_TOP_LEVEL_DIR_NAMES.contains(&name)
            || PERMANENT_TOP_LEVEL_DIR_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        unrecognized.push(name.to_string());
    }
    unrecognized
}

/// Creates an ephemeral handle directory `term-<pid>` under `base_dir`.
///
/// Populates it with:
/// - Symlinks to per-account items (heterogeneous target set per an internal journal entry OQ #2):
///   - `.credentials.json` → `identities/<UUID>/credentials.json` when UUID is
///     present in `profiles.json::by_slot`; falls back to `config-<N>/.credentials.json`
///     for legacy-only layouts (Phase 3 retarget, M3-3).
///   - `.csq-account`, `.current-account`, `.quota-cursor` → `config-<N>/<item>`
///     always (markers stay at slot path through Phase 4 per cross-phase constraint #3).
/// - Symlinks to `~/.claude/<item>` for each shared item
/// - A `.live-pid` file with the csq CLI PID
///
/// All account-bound symlinks are created via `create_symlink` (platform-aware:
/// Unix `std::os::unix::fs::symlink`; Windows dispatches dir-junction-vs-hardlink
/// based on target type). M1-3's [`crate::platform::fs::symlink_exclusive`] is a
/// directory-junction-only primitive and does NOT handle the file-target case on
/// Windows — production wire-in of that primitive is deferred to a future
/// sub-task that resolves the junction-vs-file mismatch.
///
/// Returns the absolute path to the created handle directory.
///
/// # Invariant — `pid` MUST equal the caller's `std::process::id()`
///
/// This function MUST only be invoked by the process whose PID will
/// own the handle dir. Production call sites (`csq run`) pass
/// `std::process::id()` at the call site. This invariant is what
/// keeps `sweep_dead_handles` safe against racing creates: the
/// sweep's `is_pid_alive(dir_pid)` check returns `true` as long as
/// the creating process is still alive, so a sweep can never
/// observe a `term-<pid>` whose dir-name PID is dead *while* that
/// process is still populating it. Breaking this invariant (e.g.
/// calling `create_handle_dir(foreign_pid)` from a helper process)
/// would open a race where the sweep deletes a live session's
/// half-populated dir before `write_live_pid` completes.
///
/// Tests may pass arbitrary PIDs because they run in isolated
/// tempdirs with no concurrent sweep.
///
/// # Errors
///
/// - If `config-<account>` doesn't exist
/// - If the handle dir already exists (PID collision from prior crash —
///   caller should sweep first)
/// - On any I/O failure
pub fn create_handle_dir(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    pid: u32,
) -> Result<PathBuf, CredentialError> {
    create_handle_dir_named(
        base_dir,
        claude_home,
        account,
        pid,
        &term_handle_dir_name(pid),
    )
}

/// Refuses (`Err`) when an existing handle dir may still be in use, so the caller may
/// remove it only on `Ok`. Returns the `.live-pid` pid recorded there (dead or absent) for
/// the caller's log line. Thin wrapper over [`refuse_if_existing_handle_dir_live_with`]
/// binding this process's pid and the real liveness probe.
fn refuse_if_existing_handle_dir_live(
    handle_dir: &Path,
    dir_name: &str,
) -> Result<Option<u32>, CredentialError> {
    refuse_if_existing_handle_dir_live_with(handle_dir, dir_name, std::process::id(), is_pid_alive)
}

/// The decision, with `own_pid` and liveness injected.
///
/// Fail CLOSED on every dir EXCEPT the one case below, because the removal that follows
/// is irreversible (`guard-reader-writer-parity.md` MUST-2). The exception: `dir_name ==
/// term-<own_pid>`, i.e. the dir a launch of THIS process is about to create. Our pid
/// cannot belong to another live process, so whatever sits there was left by a dead
/// previous holder of the pid. For that dir only:
/// - `.live-pid` is ignored when unreadable or when it names our own pid; it refuses only
///   when it is readable and names a DIFFERENT live pid;
/// - `.live-cc-pid` refuses when it names a live pid other than ours, or is present but
///   unreadable (a surviving orphan child may still hold the dir's keychain item).
///
/// Every other dir name (capture and exec dirs owned by the daemon) refuses on an
/// unreadable or live marker of either kind. An absent marker is "no holder".
fn refuse_if_existing_handle_dir_live_with(
    handle_dir: &Path,
    dir_name: &str,
    own_pid: u32,
    is_alive: impl Fn(u32) -> bool,
) -> Result<Option<u32>, CredentialError> {
    let own_dir = dir_name == format!("term-{own_pid}");
    let busy = |marker: &'static str, live_pid: Option<u32>| CredentialError::HandleDirBusy {
        dir_name: dir_name.to_string(),
        marker,
        live_pid,
    };

    let recorded_pid = match markers::read_live_pid_checked(handle_dir) {
        Ok(p) => p,
        // Unreadable `.live-pid` on our own pid's dir: written by a dead previous holder.
        Err(markers::MarkerUnreadable) if own_dir => None,
        Err(markers::MarkerUnreadable) => {
            return Err(busy(".live-pid", None));
        }
    };
    if let Some(recorded) = recorded_pid {
        let ours = own_dir && recorded == own_pid;
        if !ours && is_alive(recorded) {
            return Err(busy(".live-pid", Some(recorded)));
        }
    }
    // `.live-cc-pid`: plain liveness, as `sweep_dead_handles` uses — the marker is also
    // written for codex and other non-claude children, so an identity check would make
    // this inert for them. On macOS `csq exec` spawns `claude` as a child and a SIGKILLed
    // csq leaves it running while `.live-pid` names a dead pid.
    match markers::read_live_cc_pid_checked(handle_dir) {
        Ok(Some(cc)) if is_alive(cc) && !(own_dir && cc == own_pid) => {
            Err(busy(".live-cc-pid", Some(cc)))
        }
        Ok(_) => Ok(recorded_pid),
        Err(markers::MarkerUnreadable) => Err(busy(".live-cc-pid", None)),
    }
}

/// `create_dir` of a handle dir, under the term mint lock when `dir_name` is a
/// `term-<pid>` (see [`super::term_mint`]): the keychain orphan sweep holds that
/// lock from its last "this `term-<pid>` is gone" check through its delete, so a
/// terminal minted while the sweep is deciding either is seen by the check or
/// waits for the delete. The lock is held for the `create_dir` alone (a LEAF:
/// no other lock is taken inside it) and released before anything else is
/// written into the dir.
///
/// A creator that cannot get the lock inside its bounded wait REFUSES, with a
/// fixed message; it never creates a `term-<pid>` unlocked. Capture and exec
/// dirs are not part of the sweep's contract and create unlocked, as before.
fn create_term_dir_under_mint_lock(
    base_dir: &Path,
    dir_name: &str,
    handle_dir: &Path,
) -> Result<(), CredentialError> {
    let mint = match super::term_mint::term_pid_of(dir_name) {
        Some(_) => Some(super::term_mint::acquire_for_mint(base_dir).map_err(|e| {
            warn!(
                error_kind = "term_mint_lock_unavailable",
                "refusing to create a term dir without the term mint lock"
            );
            CredentialError::Io {
                path: super::term_mint::mint_lock_path(base_dir),
                source: std::io::Error::other(e.message()),
            }
        })?),
        None => None,
    };
    std::fs::create_dir(handle_dir).map_err(|e| CredentialError::Io {
        path: handle_dir.to_path_buf(),
        source: e,
    })?;
    // The mint ledger (still under the lock): the sweep only considers a
    // `term-<pid>` item whose pid csq recorded minting. A failed record only
    // means this terminal's item is never swept (a leak, never a delete).
    if let (Some(pid), Some(guard)) = (super::term_mint::term_pid_of(dir_name), mint.as_ref()) {
        // The launcher's own unique id and boot session, so the sweep can later tell its
        // descendants from every other process; unreadable means unrecorded (kept).
        let launcher = super::term_mint::launcher_identity(pid);
        if super::term_mint::record_mint(base_dir, pid, launcher, guard).is_err() {
            warn!(
                error_kind = "term_mint_ledger_write_failed",
                "could not record this terminal in the mint ledger; its keychain item will not be swept"
            );
        }
    }
    Ok(())
}

/// `create_handle_dir` generalized to an explicit `dir_name`.
///
/// `create_handle_dir` is the thin wrapper that passes `term-<pid>`. The
/// daemon's Phase-2b interactive subscription-capture path (`phase2b::
/// subscription_client`) passes a unique `interactive-capture-<…>` name so a
/// single daemon process (one PID) can run multiple concurrent governed-turn
/// captures without colliding on a single `term-<pid>` dir. `pid` is still
/// recorded in `.live-pid` (the daemon PID, for liveness-based crash cleanup)
/// and used in orphan-detection log lines. The caller that supplies a
/// non-`term-<pid>` name owns that dir's lifecycle (the `term-*` sweeper only
/// reaps `term-*` names — see `phase2b::subscription_client` for its
/// self-managed cleanup of the `interactive-capture-*` namespace).
pub fn create_handle_dir_named(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    pid: u32,
    dir_name: &str,
) -> Result<PathBuf, CredentialError> {
    assert_dir_name_prefix_registered(dir_name)?;
    let config_dir = base_dir.join(format!("config-{}", account));
    if !config_dir.is_dir() {
        return Err(CredentialError::Corrupt {
            path: config_dir,
            reason: format!("config-{account} does not exist"),
        });
    }

    let handle_dir = base_dir.join(dir_name);

    // Detect orphan from prior crash with same PID.
    //
    // SAFETY: Before removing, `refuse_if_existing_handle_dir_live` reads `.live-pid` and
    // `.live-cc-pid` and verifies no recorded PID is alive. Without this check, PID
    // recycling could make us wipe out a live terminal's handle dir. We remove only a dir
    // whose markers are absent or name dead PIDs. An UNREADABLE marker refuses (it may
    // belong to a live holder) with ONE exception: the `term-<own pid>` dir, where our
    // own pid proves the previous holder is dead, so an unreadable `.live-pid` is ignored.
    if handle_dir.exists() {
        let recorded_pid = refuse_if_existing_handle_dir_live(&handle_dir, dir_name)?;

        warn!(
            pid,
            dir_name,
            recorded = ?recorded_pid,
            "handle dir already exists with dead or missing PID — removing orphan"
        );
        // `keychain-fix-r11.md` S-MEDIUM-1 / D-4: this custom-named
        // namespace (`create_handle_dir_named` serves non-`term-*` callers
        // like the phase2b interactive-capture dirs) has NO daemon reaper of
        // its own — `sweep_dead_handles` only walks `term-*` names. This
        // orphan-removal path is the ONLY chance this dir's keychain item
        // (if any) will ever be cleared — once `remove_dir_all` below runs,
        // the canonicalized path that produces its keychain service name is
        // gone forever. Run the SAME dead-handle clear the term-* reaper
        // uses (`clear_dead_handle_keychain_item` -> decide+adopt, queuing a
        // pending-clear retry on an unconfirmed result), BEFORE the
        // directory disappears.
        let http_get: crate::daemon::usage_poller::HttpGetFn =
            std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
                crate::http::get_bearer_node(url, token, headers)
            });
        clear_dead_handle_keychain_item(
            &handle_dir,
            recorded_pid.unwrap_or(0),
            base_dir,
            &mut |abs| {
                keychain::decide_and_clear_dead_handle(base_dir, abs, &|account, candidate| {
                    crate::daemon::custodian::adopt_single_candidate_before_delete(
                        base_dir, account, candidate, &http_get,
                    )
                })
            },
        );
        std::fs::remove_dir_all(&handle_dir).map_err(|e| CredentialError::Io {
            path: handle_dir.clone(),
            source: e,
        })?;
    }

    // Use create_dir (not create_dir_all) to detect collisions
    create_term_dir_under_mint_lock(base_dir, dir_name, &handle_dir)?;

    // Symlink account-bound items — heterogeneous target set per an internal journal entry OQ #2.
    //
    // M3-3 retarget: `.credentials.json` uses the identity-keyed path when a UUID
    // is present in `profiles.json::by_slot` for this account.  All other items
    // (`.csq-account`, `.current-account`, `.quota-cursor`) stay at `config-<N>/`
    // through Phase 4 per cross-phase constraint #3 (marker semantics; OQ #2 Option A).
    //
    // All symlinks are created via `create_symlink` (platform-aware primitive:
    // Unix symlink; Windows dispatches dir-junction-vs-hardlink). M1-3's
    // `symlink_exclusive` is dir-junction-only on Windows and does NOT handle
    // file-target symlinks; production wire-in deferred to a future sub-task.
    let identity_paths = account_to_identity_paths(base_dir, account);
    for item in ACCOUNT_BOUND_ITEMS {
        let target = if *item == ".credentials.json" {
            // M3-3: route through identity-keyed path when UUID is present.
            //
            // M3-7: the prior HIGH-1 fallback to `config-N/.credentials.json`
            // is retired. The startup_reconciler `phase4_gate_check`
            // (renamed from the prior `phase3_gate` symbol in M4-5;
            // behavior preserved for this invariant) refuses to start
            // the daemon when any UUID-keyed slot's identity
            // credentials.json is unseeded, so by the time
            // `create_handle_dir` runs the identity path is guaranteed
            // populated for every UUID-keyed slot.
            //
            // Legacy slots without a UUID still route through this branch's
            // else arm of `is_identity_keyed`: `account_to_identity_paths`
            // returns the `config-<N>/.credentials.json` shape when no UUID
            // is resolvable. Backwards-compatible for pre-Phase-1 stores.
            identity_paths.credentials_path.clone()
        } else {
            // Markers and slot-state items always target config-N/ (OQ #2 Option A).
            config_dir.join(item)
        };
        let link = handle_dir.join(item);
        // Only create symlink if the target exists (or is a known-expected symlink)
        if target.exists() || target.symlink_metadata().is_ok() {
            // Use the platform-aware `create_symlink` primitive (Unix symlink;
            // Windows dispatches dir-junction-vs-hardlink based on target type).
            // M1-3's `symlink_exclusive` is for directory junctions specifically
            // and does NOT handle the file-target case on Windows — Phase 3 file
            // symlinks need `create_symlink_pub`'s platform-correct dispatch.
            // Wire-in of `symlink_exclusive` as a production primitive is deferred
            // to a future sub-task that addresses the junction-vs-file mismatch.
            create_symlink(&target, &link).map_err(|e| CredentialError::Io {
                path: link.clone(),
                source: e,
            })?;
            debug!(item, "linked account-bound item");
        }
    }

    // Symlink shared items to ~/.claude. Use the shape-aware
    // `ensure_shared_target` helper so file-named items
    // (`keybindings.json`, `history.jsonl`, `__store.db`, etc.)
    // get seeded as parseable files instead of directories — the
    // pre-alpha.18 bug that left CC logging a keybinding-error on
    // every launch once csq run had run once on a fresh install.
    for item in SHARED_ITEMS {
        let target = claude_home.join(item);
        let link = handle_dir.join(item);

        if let Err(e) = isolation::ensure_shared_target(&target, item) {
            warn!(path = %target.display(), error = %e, "failed to create shared target");
            continue;
        }

        if target.exists() {
            // Use ensure_symlink logic: skip if non-symlink exists
            if link.symlink_metadata().is_ok() {
                continue; // shouldn't happen in a fresh dir, but be safe
            }
            create_symlink(&target, &link).map_err(|e| CredentialError::Io {
                path: link.clone(),
                source: e,
            })?;
            debug!(item, "linked shared item");
        }
    }

    // Copy .claude.json from config-N, scoping `projects` to CWD.
    materialize_handle_claude_json(&config_dir, &handle_dir);

    // Materialize settings.json as a real file (NOT a symlink). CC reads
    // this via CLAUDE_CONFIG_DIR and treats it as the user settings layer,
    // replacing (not merging with) ~/.claude/settings.json. Deep-merge the
    // user global settings with the slot's overlay so the statusLine,
    // permissions, plugins, and any 3P env block all survive.
    //
    // M2-3: resolve UUID once at section entry (cross-phase constraint #7).
    // Pass the UUID-keyed settings path if available so the overlay sources
    // from `identities/<UUID>/settings.json` (Phase 2 canonical) rather than
    // `config-N/settings.json` (legacy fallback).
    let uuid_settings = profiles::resolve_slot_to_uuid(base_dir, account.get())
        .map(|uuid| settings_path_for(base_dir, uuid));
    materialize_handle_settings_inner(
        &handle_dir,
        claude_home,
        &config_dir,
        uuid_settings.as_deref(),
    )?;

    // Write .live-pid with the csq CLI PID
    markers::write_live_pid(&handle_dir, pid)?;

    // `keychain-fix-r11.md` S-MEDIUM-1 / D-4: PID reuse makes THIS fresh
    // dir's canonicalized path — and therefore its keychain `service_name` —
    // identical to whatever PRIOR session last occupied the same PID. Any
    // pending-clear queue entry recorded against that same service is
    // resolved — its OWN disposition run against the real keychain item —
    // now, under this dir's own per-dir swap lock and before this session's
    // own keychain write (`force_sync_for_launch`) ever lands, so a
    // surviving `Logout`-origin entry actually clears the stale item rather
    // than merely being dropped (the retired `drop_pending_clear_for_service`
    // silently left the item behind — S-MEDIUM-1). `canonicalize_for_
    // keychain_sync`/`resolve_pending_clear_at_creation` are both
    // cross-platform (the latter a no-op off macOS) — no `#[cfg]` needed at
    // this call site. `TimedOut`/`Failed` skip the resolve for this cycle
    // (fixed-tag warn) rather than proceeding unlocked — the entry, if any,
    // stays queued for the daemon's own `sweep_pending_clears` to retry.
    let (handle_dir_abs, keychain_write_allowed) =
        keychain::canonicalize_for_keychain_sync(&handle_dir);
    if keychain_write_allowed {
        match keychain::lock_handle_dir_for_swap_bounded(&handle_dir_abs) {
            keychain::BoundedLockOutcome::Acquired(_guard) => {
                keychain::resolve_pending_clear_at_creation(
                    base_dir,
                    &keychain::service_name(&handle_dir_abs),
                );
            }
            keychain::BoundedLockOutcome::NotNeeded => {
                keychain::resolve_pending_clear_at_creation(
                    base_dir,
                    &keychain::service_name(&handle_dir_abs),
                );
            }
            keychain::BoundedLockOutcome::TimedOut | keychain::BoundedLockOutcome::Failed => {
                warn!(
                    error_kind = "keychain_pending_clear_resolve_lock_unavailable",
                    "could not acquire the per-dir swap lock to resolve a stale \
                     pending-clear entry at handle-dir creation; entry, if any, \
                     stays queued for the daemon's own retry"
                );
            }
        }
    }

    info!(pid, account = %account, path = %handle_dir.display(), "handle dir created");
    Ok(handle_dir)
}

/// Creates an ephemeral Codex handle directory `term-<pid>` under
/// `base_dir` for `Surface::Codex`.
///
/// Per spec 07 §7.2.2 the Codex handle dir carries a distinct symlink
/// set from Anthropic (heterogeneous target set per an internal journal entry OQ #2 + OQ #3):
///
/// - `.csq-account` → `config-<N>/.csq-account` (always; marker stays at slot path)
/// - `auth.json` → `identities/<UUID>/credentials-codex.json` when UUID present
///   (M3-3 retarget, an internal journal entry OQ #3); falls back to `credentials/codex-<N>.json`
///   for legacy-only layouts. The legacy canonical is retained through Phase 4.
/// - `config.toml` → `config-<N>/config.toml` (daemon-writable; model
///   + `cli_auth_credentials_store` mode)
/// - `sessions` → `config-<N>/codex-sessions/` (per-account persistent
///   transcripts, per INV-P04 carveout)
/// - `history.jsonl` → `config-<N>/codex-history.jsonl` (per-account
///   persistent history)
///
/// Plus an ephemeral `log/` directory (per-terminal, ignored by the
/// sweeper) and a `.live-pid` marker.
///
/// Unlike [`create_handle_dir`] (Anthropic), this function does NOT:
/// - Symlink `SHARED_ITEMS` to `~/.claude` — Codex reads `CODEX_HOME`
///   and has no dependency on the Claude home directory.
/// - Materialize `settings.json` / `.claude.json` — Codex configuration
///   lives in `config.toml`, which is already a per-account symlink.
///
/// # Invariant — `pid` MUST equal the caller's `std::process::id()`
///
/// Same contract as [`create_handle_dir`]: the sweeper relies on this
/// to avoid racing creates against live handle dirs. See the
/// [`create_handle_dir`] docstring for the full rationale.
///
/// # Errors
///
/// - If `config-<account>` does not exist (Codex slot not provisioned —
///   PR-C3b `csq login --provider codex` must run first).
/// - If the canonical credential file `credentials/codex-<N>.json`
///   does not exist (same reason — login has not completed).
/// - If the handle dir already exists with a live PID (refuses to
///   remove — identical semantics to the Anthropic path).
/// - On any I/O failure.
pub fn create_handle_dir_codex(
    base_dir: &Path,
    account: AccountNum,
    pid: u32,
) -> Result<PathBuf, CredentialError> {
    create_handle_dir_codex_named(base_dir, account, pid, &term_handle_dir_name(pid))
}

/// `create_handle_dir_codex` generalized to an explicit `dir_name`. See
/// [`create_handle_dir_named`] for the rationale (concurrent daemon-side
/// subscription captures need unique dir names outside the `term-<pid>` space).
pub fn create_handle_dir_codex_named(
    base_dir: &Path,
    account: AccountNum,
    pid: u32,
    dir_name: &str,
) -> Result<PathBuf, CredentialError> {
    assert_dir_name_prefix_registered(dir_name)?;
    let config_dir = base_dir.join(format!("config-{}", account));
    if !config_dir.is_dir() {
        return Err(CredentialError::Corrupt {
            path: config_dir,
            reason: format!(
                "config-{account} does not exist — run `csq login {account} --provider codex` first"
            ),
        });
    }

    let canonical_cred = base_dir
        .join("credentials")
        .join(format!("codex-{account}.json"));

    // Task 5: Accept either the UUID-keyed path (post-M4-12) or the legacy
    // numeric path (pre-M4-12 / downgrade safety). A slot that was provisioned
    // after the fix will have `identities/<UUID>/credentials-codex.json` but
    // no `credentials/codex-<N>.json`. Both are valid; at least one must exist.
    let uuid_cred_path = profiles::resolve_slot_to_uuid(base_dir, account.get())
        .map(|uuid| credentials_codex_path_for(base_dir, uuid));
    let uuid_cred_exists = uuid_cred_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    let legacy_cred_exists = canonical_cred.exists();

    if !uuid_cred_exists && !legacy_cred_exists {
        // IR-M4: when a UUID mapping exists, name the UUID-keyed path in the
        // error so the operator sees the post-M4-12 authoritative path rather
        // than the retired legacy path. Fall back to the legacy path when no
        // UUID mapping is present (pure-legacy layout).
        let error_path = uuid_cred_path.unwrap_or(canonical_cred);
        return Err(CredentialError::Corrupt {
            path: error_path,
            reason: format!(
                "stat Codex canonical — neither UUID-keyed nor legacy path exists; \
                 run `csq login {account} --provider codex`"
            ),
        });
    }

    let handle_dir = base_dir.join(dir_name);

    // Same orphan-detection semantics as create_handle_dir — only
    // remove a stale handle dir whose recorded PID is dead or absent.
    if handle_dir.exists() {
        let recorded_pid = refuse_if_existing_handle_dir_live(&handle_dir, dir_name)?;

        warn!(
            pid,
            dir_name,
            recorded = ?recorded_pid,
            "codex handle dir already exists with dead or missing PID — removing orphan"
        );
        std::fs::remove_dir_all(&handle_dir).map_err(|e| CredentialError::Io {
            path: handle_dir.clone(),
            source: e,
        })?;
    }

    crate::providers::codex::trust::sync_before_handle(base_dir, account);
    create_term_dir_under_mint_lock(base_dir, dir_name, &handle_dir)?;

    // Codex symlink set per spec 07 §7.2.2 — heterogeneous target set per
    // an internal journal entry OQ #2 + OQ #3.
    //
    // M3-3 retarget: `auth.json` uses the identity-keyed path
    // (`identities/<UUID>/credentials-codex.json`) when a UUID is present in
    // `profiles.json::by_slot` for this account.  Falls back to the legacy
    // canonical `credentials/codex-<N>.json` for pre-A++ layouts.  The legacy
    // canonical file is retained through Phase 4 for downgrade safety.
    //
    // `.csq-account` and all other items stay at `config-<N>/` through Phase 4
    // per cross-phase constraint #3 (OQ #2 Option A).
    //
    // All symlinks are created via `create_symlink` (platform-aware; see the
    // Anthropic `create_handle_dir` for the M1-3 deferral rationale).
    let auth_target = {
        let identity_paths = account_to_identity_paths(base_dir, account);
        if identity_paths.is_identity_keyed {
            // Resolve the UUID directly via profiles so we can call the Codex helper.
            match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
                Some(uuid) => {
                    let p = credentials_codex_path_for(base_dir, uuid);
                    if p.exists() {
                        p
                    } else {
                        // HIGH-2 fallback: UUID present but credentials-codex.json
                        // not yet seeded (Partial-Pass-0 for Codex surface).
                        // Fall back to the legacy canonical so the handle dir is
                        // functional.  M3-7's `csq doctor --repair` handles the
                        // underlying incomplete mint.
                        tracing::warn!(
                            account = %account,
                            uuid = %uuid,
                            "Codex identity-store partial (credentials-codex.json missing): \
                             falling back to credentials/codex-N.json"
                        );
                        canonical_cred.clone()
                    }
                }
                // Shouldn't happen (is_identity_keyed == true implies UUID resolved),
                // but fall back safely.
                None => canonical_cred.clone(),
            }
        } else {
            canonical_cred.clone()
        }
    };

    // ACCOUNT-BOUND only. Shared state is linked below through
    // `codex_shared_pairs`, which pre-creates an absent target instead of skipping
    // it — see `CODEX_SHARED_STATE` for why skipping silently unshared it.
    let codex_links: &[(&str, PathBuf)] = &[
        (".csq-account", config_dir.join(".csq-account")),
        ("auth.json", auth_target),
        ("config.toml", config_dir.join("config.toml")),
    ];

    for (name, target) in codex_links {
        let link = handle_dir.join(name);
        // Only symlink items whose target exists OR is a known-expected
        // persistent state dir/file. `codex-sessions/` and
        // `codex-history.jsonl` may legitimately be absent on first
        // spawn — codex-cli creates them lazily. Skip those silently.
        if !target.exists() && target.symlink_metadata().is_err() {
            debug!(
                item = name,
                target = %target.display(),
                "codex symlink target does not exist yet; skipping"
            );
            continue;
        }
        // Use `create_symlink` (platform-aware: Unix symlink; Windows dispatches
        // dir-junction-vs-hardlink). See ClaudeCode symlink loop above for the
        // M1-3 deferral rationale.
        create_symlink(target, &link).map_err(|e| CredentialError::Io {
            path: link.clone(),
            source: e,
        })?;
        debug!(item = name, "linked codex item");
    }

    // User-global hooks (owner directive: terminal settings come from the global layer
    // only). No global hooks.json => no link.
    link_codex_global_hooks(&handle_dir, codex_global_hooks_path().as_deref()).map_err(|e| {
        CredentialError::Io {
            path: handle_dir.join(CODEX_HOOKS_FILE),
            source: e,
        }
    })?;
    // Carry existing owner approvals to this handle's keys (never originates one) after
    // dropping every stale key under this handle's name. If the slot this terminal runs on
    // cannot be cleared of a predecessor's keys (one drop-only retry already failed), the
    // launch is REFUSED: a reused PID must never inherit its predecessor's approvals or
    // `enabled = false` decisions.
    if let Err(e) = super::codex_hook_trust::carry_hook_trust(
        base_dir,
        &handle_dir,
        account,
        codex_global_hooks_path().as_deref(),
        super::codex_hook_trust::CarryMode::Create,
    ) {
        warn!(
            error_kind = "codex_hook_trust_launch_refused",
            io_kind = ?e.kind(),
            "refusing to create the Codex handle: stale hook approvals could not be cleared"
        );
        let _ = std::fs::remove_dir_all(&handle_dir);
        return Err(hook_trust_refusal(&config_dir, &e));
    }

    // SHARED state: conversation history and codex's schema-versioned sqlite
    // metadata (names, recency). Anything not linked here becomes a real file in
    // the handle dir and is destroyed with it.
    for (name, target, kind) in codex_shared_pairs(&config_dir) {
        link_shared_codex_item(&handle_dir, &name, &target, kind)?;
        debug!(item = %name, "linked shared codex state");
    }

    // Ephemeral per-terminal log dir. Codex-cli writes per-session
    // logs here; the sweeper removes it along with the handle dir.
    let log_dir = handle_dir.join("log");
    std::fs::create_dir(&log_dir).map_err(|e| CredentialError::Io {
        path: log_dir,
        source: e,
    })?;

    markers::write_live_pid(&handle_dir, pid)?;

    info!(
        pid,
        account = %account,
        surface = "codex",
        path = %handle_dir.display(),
        "codex handle dir created"
    );
    Ok(handle_dir)
}

/// Writes `<handle_dir>/settings.json` as a real file by deep-merging
/// `<claude_home>/settings.json` (base) with the slot-keyed overlay.
///
/// ## M2-3 / M4-2 overlay resolution (spec 02 §2.3.3)
///
/// The overlay source is chosen by the following priority:
/// 1. `uuid_settings_path` — when `Some(path)` AND the file exists at `path`,
///    use it as the overlay (UUID-keyed canonical, Phase 2 active path).
/// 2. `<config_dir>/settings.json` — fallback for legacy-only layouts where
///    `identities/<UUID>/settings.json` has not been materialized yet (Phase 1
///    remaining slots, fresh-install, or daemon Pass 0 not yet run).
///
/// **M4-2 invariant (spec 02 §2.3.3):** every login path that writes
/// `config-<N>/settings.json` ALSO writes a byte-equivalent
/// `identities/<UUID>/settings.json` via the `credentials::save_uuid_settings`
/// chokepoint. So the two paths are byte-equivalent during the M4-2 → M4-5
/// transition; reading either yields the same overlay. The fallback to (2) is
/// load-bearing only for pure-legacy installs and the cold-start race window
/// before daemon Pass 0 completes. M4-5 strengthens the gate; release N+1
/// retires the fallback after the v2.6.x downgrade window closes.
///
/// The base carries user-global customization (statusLine, permissions,
/// plugins, env experiments). The overlay carries slot-specific env for
/// 3P bindings (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`,
/// `ANTHROPIC_MODEL`). Precedence is slot overlay > user-global > csq
/// defaults (`default_settings`): overlay keys win on merge, and a csq
/// default fills in only when neither the user-global nor the overlay
/// sets the key. For OAuth slots where neither overlay source is present,
/// the materialized file equals the user's global settings plus any csq
/// default the user has not explicitly set (currently `effortLevel:
/// "medium"` — an explicit `effortLevel` in the global, e.g. `"xhigh"`,
/// always wins).
///
/// Failures at each step:
/// - Missing `<claude_home>/settings.json` → base is `{}`
/// - Invalid JSON in either source → logged at WARN, treated as `{}`
/// - Write / secure_file / rename → propagated as [`CredentialError`]
///
/// # Security
///
/// The overlay may contain a 3P `ANTHROPIC_AUTH_TOKEN`. `secure_file`
/// propagates (does not `.ok()`) so a permission failure fails closed
/// rather than leaving a credential file at the umask default.
///
/// Also exposed publicly so `csq run` can defensively re-materialize as a
/// belt-and-suspenders after `create_handle_dir`, in case future refactors
/// factor the step out of `create_handle_dir`. See an internal journal entry — stale
/// per-slot settings drifted silently through a csq install upgrade;
/// making the invariant explicit at the call site guards against the same
/// class of regression.
pub fn materialize_handle_settings(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
) -> Result<(), CredentialError> {
    materialize_handle_settings_inner(handle_dir, claude_home, config_dir, None)
}

/// csq-shipped default settings for materialized handle dirs, applied
/// UNDER the user-global layer: a key set explicitly in
/// `~/.claude/settings.json` or in a slot overlay always wins; the
/// default fills in only when neither sets it.
///
/// `effortLevel: "medium"` — the default effort for Claude Code CLI
/// sessions on Anthropic OAuth slots (csq 1–10), set by the maintainer
/// 2026-09-25 (previously `"high"`). Without this layer the handle inherits
/// whatever CC's built-in default is (currently `xhigh`); users who
/// explicitly set `effortLevel` in their global, or a slot overlay that
/// sets it (3P bindings pin their own), keep their choice untouched.
///
/// `crossSessionInbound: "accept"` — lets the Claude Code sessions csq
/// materializes take cross-session messages without an approval dialog.
/// Without it a bypass-permissions receiver HOLDS csq's inbox-socket notice
/// (it does not attest its permission mode) and an idle session is never
/// woken (spec 32a §5.2).
///
/// EFFECT, stated plainly: for a bypass-permissions session, ANY process
/// running as the same user that can reach the session's inbox socket can
/// put text in front of a model that can run tools without prompts, with no
/// human in the loop. The only defence is that the model treats peer text
/// as data (Claude Code frames it as a peer message, and csq's
/// `peer-message-trust` rule reinforces that); that is a model behaviour,
/// not an access control, and it does not make a bypass session safe
/// against a hostile same-user process. User approval on 2026-10-06 after
/// security review is recorded in
/// `internal-design-docs`.
/// Remove this exception and narrow accept when Claude offers per-sender or
/// allow-listed inbound mode, or csq validates the notice sender's identity;
/// revisit by the 2.22.0 release cut or 2026-12-31, whichever comes first.
/// Only csq's terminal-local materialization is written, never user-global settings.
///
/// What `accept` ADDS, precisely: peer text already reaches a bypass session through csq's
/// hook on its next turn, and csq's own MCP relay lets ANY session with csq messaging (sandboxed
/// or not) address it. `accept` makes an IDLE bypass session start a turn on peer text with no
/// human present. Live reload of this key is an upstream behavior; see the dated evidence in spec 32a.
///
/// Scope: only sessions csq materializes, not the machine. Valid in-session
/// choices take precedence over slot overlay > user-global > this default.
/// If an existing layer is unusable, the accept default is withheld; an empty
/// terminal-local file is unusable too (see `prepare_handle_settings_tmp`).
fn default_settings() -> Value {
    serde_json::json!({ "effortLevel": "medium", "crossSessionInbound": "accept" })
}

/// Account-neutral preference keys carried from the PREVIOUS handle `settings.json` into a
/// re-materialization, because Claude Code (`/config`) writes them into the handle file during
/// a session and a swap or auto-rotate would otherwise drop them. An explicit allowlist: a key
/// is added only when it is a pure UI/cost preference that cannot route a request or name a
/// credential. NEVER `env`, `apiKeyHelper`, provider, model or routing keys.
const CARRIED_PREFERENCE_KEYS: &[&str] = &["subagentPromptCacheTtl", "disableClaudeAiConnectors"];

/// Sidecar in the handle dir recording the allowlisted values csq's LAYERS supplied at the last
/// materialization (defaults < global < slot overlay, plus csq's session defaults). The previous
/// handle `settings.json` is the merged view, so a value equal to this record came from a layer
/// (it must follow that layer: removed from global it must vanish, and slot A's overlay value
/// must not cross to slot B); a value that DIFFERS from the record was written by Claude Code.
const LAYER_RECORD_FILE: &str = ".csq-layer-prefs.json";
const LAYER_RECORD_MAX_BYTES: u64 = 4096;

type LayerRecord = serde_json::Map<String, Value>;

/// The allowlisted entries of `layers` (the merged layers, before any carry-over).
fn layer_record(layers: &Value) -> LayerRecord {
    let mut rec = LayerRecord::new();
    if let Some(obj) = layers.as_object() {
        for key in CARRIED_PREFERENCE_KEYS {
            if let Some(v) = obj.get(*key) {
                rec.insert((*key).to_string(), v.clone());
            }
        }
    }
    rec
}

/// The record of the last materialization, or `None` when it is absent, oversized or
/// unreadable. With no record nothing can be attributed to Claude Code, so
/// [`carry_preferences`] carries NOTHING (a value Claude Code wrote is reset once, which is the
/// safe direction: no layer-sourced value ever crosses accounts).
fn read_layer_record(handle_dir: &Path) -> Option<LayerRecord> {
    let path = handle_dir.join(LAYER_RECORD_FILE);
    match std::fs::metadata(&path) {
        Ok(m) if m.is_file() && m.len() <= LAYER_RECORD_MAX_BYTES => {}
        _ => return None,
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
}

/// Persist `rec` (0600, atomic, tmp removed on every error branch: `security.md` §5a). On a
/// failed write the OLD record is removed so it can never be read as current; a warn with a
/// fixed tag is the only report (the settings commit it follows already succeeded).
fn write_layer_record(handle_dir: &Path, rec: &LayerRecord) {
    let path = handle_dir.join(LAYER_RECORD_FILE);
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    let body = serde_json::to_string(rec).unwrap_or_else(|_| "{}".to_string());
    let result = crate::platform::fs::write_new_private(&tmp, body.as_bytes())
        .and_then(|()| crate::platform::fs::secure_file(&tmp))
        .and_then(|()| crate::platform::fs::atomic_replace(&tmp, &path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&path);
        warn!(
            error_kind = "layer_record_write_failed",
            "layer preference record could not be written"
        );
    }
}

/// Last-known-good copy of the user-global Claude `hooks`, csq-owned and written beside the
/// handle dirs (`<accounts>/`), never inside one. Read only when the global settings file is
/// unusable.
const GLOBAL_HOOKS_RECORD_FILE: &str = ".csq-global-hooks.json";

fn global_hooks_record_path(handle_dir: &Path) -> Option<PathBuf> {
    handle_dir
        .parent()
        .map(|accounts| accounts.join(GLOBAL_HOOKS_RECORD_FILE))
}

/// Records the global's `hooks` (an empty object when it has none) after a SUCCESSFUL read,
/// atomically at 0600 (`security.md` §5a: tmp removed on every failure branch), and only when
/// the bytes changed. A failed write leaves the older record in place and logs a fixed tag.
fn write_global_hooks_record(path: &Path, base: &Value) {
    let hooks = base
        .get("hooks")
        .filter(|h| h.is_object())
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let Ok(body) = serde_json::to_vec(&serde_json::json!({ "hooks": hooks })) else {
        return;
    };
    if read_regular_bounded(path, true).as_deref() == Some(body.as_slice()) {
        return;
    }
    let tmp = crate::platform::fs::unique_tmp_path(path);
    let result = crate::platform::fs::write_new_private(&tmp, &body)
        .and_then(|()| crate::platform::fs::secure_file(&tmp))
        .and_then(|()| crate::platform::fs::atomic_replace(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "global_hooks_record_write_failed",
            "last-known-good global hooks record could not be written"
        );
    }
}

/// The recorded global hooks as a `{"hooks": …}` layer, or `None` when absent, oversize,
/// non-regular or unparseable.
fn read_global_hooks_record(path: &Path) -> Option<Value> {
    let bytes = read_regular_bounded(path, true)?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let hooks = v.get("hooks").filter(|h| h.is_object())?;
    Some(serde_json::json!({ "hooks": hooks }))
}

/// Carry [`CARRIED_PREFERENCE_KEYS`] from `previous` into `merged` when no layer sets the key
/// (an explicit user-global or slot value is newer than a stale handle copy) AND the previous
/// value is not merely the one csq itself wrote from a layer last time (`recorded`): only a
/// value Claude Code wrote survives.
fn carry_preferences(previous: &Value, recorded: Option<&LayerRecord>, merged: &mut Value) {
    // No record (a pre-sidecar handle file, or a failed record write): nothing is attributable
    // to Claude Code, so nothing is carried.
    let (Some(recorded), Some(prev), Some(dst)) =
        (recorded, previous.as_object(), merged.as_object_mut())
    else {
        return;
    };
    for key in CARRIED_PREFERENCE_KEYS {
        if dst.contains_key(*key) {
            continue;
        }
        if let Some(v) = prev.get(*key) {
            if recorded.get(*key) != Some(v) {
                dst.insert((*key).to_string(), v.clone());
            }
        }
    }
}

/// Settings csq applies to every Claude session it launches, AFTER the
/// defaults < user-global < slot-overlay merge (an internal ticket): `disableClaudeAiConnectors` defaults to
/// `true` ONLY when no layer sets it (an explicit `false` passes through). csq neither sets nor
/// rewrites `subagentPromptCacheTtl`. Neither key touches credentials or identity; both are
/// re-applied on every materialization.
fn apply_session_keys(merged: &mut Value) {
    if let Some(settings) = merged.as_object_mut() {
        settings
            .entry("disableClaudeAiConnectors")
            .or_insert(Value::Bool(true));
    }
}

/// Internal implementation for [`materialize_handle_settings`] with optional
/// UUID-keyed overlay path (M2-3).
///
/// Called by:
/// - `materialize_handle_settings` (passes `None` for `uuid_settings_path`)
/// - `create_handle_dir` (pass the resolved UUID path)
///
/// S-H1/D-F1 fix: `repoint_handle_dir` no longer calls this directly. It
/// calls [`prepare_handle_settings_tmp`] BEFORE its symlink rename loop
/// touches anything, then [`commit_prepared_handle_settings`] as the final
/// step of that same loop's commit — folding the settings write into the
/// existing rollback story instead of leaving it as an unrollback-able `?`
/// after every `ACCOUNT_BOUND_ITEMS` symlink has already moved. This
/// wrapper still performs both halves back-to-back for `create_handle_dir`
/// and the public no-UUID entry point, where there is no rename loop to
/// fold into and a failure here has nothing else to roll back.
fn materialize_handle_settings_inner(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
    uuid_settings_path: Option<&Path>,
) -> Result<(), CredentialError> {
    let (tmp, record) =
        prepare_handle_settings(handle_dir, claude_home, config_dir, uuid_settings_path)?;
    let settings_path = handle_dir.join("settings.json");
    commit_prepared_handle_settings(&tmp, &settings_path).map_err(|e| {
        CredentialError::Corrupt {
            path: settings_path,
            reason: format!("atomic replace: {e}"),
        }
    })?;
    write_layer_record(handle_dir, &record);
    Ok(())
}

/// L2 (`security.md` §5a): creates `tmp` EXCLUSIVELY (`O_EXCL` via
/// `create_new(true)`) at `mode(0o600)` on unix, then writes `content` to
/// it. `std::fs::write` — used here until this fix — opens with `O_CREAT`
/// but NOT `O_EXCL`, at umask-default permissions (typically 0o644): if an
/// attacker (or a stale leftover from a crashed prior run) has already
/// planted a symlink OR a regular file at `tmp`'s predicted path (`PID +
/// process-local counter` — `crate::platform::fs::unique_tmp_path`, not a
/// secret), `write` follows it and overwrites/exposes THAT target rather
/// than refusing, and there is a window between the write landing and a
/// separate `secure_file` call in which the content sits world-readable.
/// `create_new` fails the open with `AlreadyExists` against ANY
/// pre-existing directory entry there — including a dangling symlink whose
/// target does not even exist — instead of following it; `mode(0o600)`
/// removes the world-readable window entirely rather than relying on a
/// later `secure_file` call to close it after the fact. On a write failure
/// (not an open failure) the created tmp file is removed — an open
/// failure never created anything to clean up.
/// Thin `std::io::Result` wrapper around
/// [`write_new_private`](crate::platform::fs::write_new_private) — this
/// function used to duplicate that helper's `create_new` + `mode(0o600)`
/// body directly; kept as a named wrapper (rather than inlining the call
/// at the one production callsite) so this module's own dedicated tests
/// below stay unchanged, and because callers here propagate a bare
/// `std::io::Error` (`CredentialError::Io { source: e }`) rather than
/// `PlatformError`.
fn create_tmp_exclusive(tmp: &Path, content: &[u8]) -> std::io::Result<()> {
    crate::platform::fs::write_new_private(tmp, content)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// S-H1/D-F1: merges the settings JSON for `config_dir`/`uuid_settings_path`
/// and writes the result to a freshly-allocated temp path next to
/// `<handle_dir>/settings.json`, securing it — but does NOT touch
/// `<handle_dir>/settings.json` itself. Every failure branch here fires
/// BEFORE any mutation of `handle_dir`, so a caller that has not yet
/// mutated anything else can propagate the error as-is: there is nothing
/// to roll back (consistent with every other pre-mutation refusal in this
/// module — `CredentialError::repoint_rolled_back()` reporting `None` for
/// these variants is correct here specifically because nothing moved).
///
/// Returns the prepared temp path on success; the caller commits it via
/// [`commit_prepared_handle_settings`].
#[cfg(all(test, unix))]
fn prepare_handle_settings_tmp(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
    uuid_settings_path: Option<&Path>,
) -> Result<PathBuf, CredentialError> {
    prepare_handle_settings(handle_dir, claude_home, config_dir, uuid_settings_path)
        .map(|(tmp, _)| tmp)
}

/// [`prepare_handle_settings_tmp`]'s body, also returning the layer record the caller persists
/// with [`write_layer_record`] AFTER the settings commit succeeds (so a rolled-back swap never
/// leaves a record describing a file that was not written).
fn prepare_handle_settings(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
    uuid_settings_path: Option<&Path>,
) -> Result<(PathBuf, LayerRecord), CredentialError> {
    let (base, base_usable, _) = read_settings_layer(&claude_home.join("settings.json"), true);
    let settings_path = handle_dir.join("settings.json");
    let (mut previous, previous_usable, previous_absent) =
        read_settings_layer(&settings_path, false);
    // Previous terminal state is not an authority for compaction policy.
    super::settings_policy::strip_autocompact_overrides(&mut previous);

    // M2-3: prefer the UUID-keyed settings.json when present (Phase 2 active
    // path). Fall back to config-<N>/settings.json for legacy-only layouts.
    let overlay_path = match uuid_settings_path {
        Some(p) if p.exists() => {
            debug!(
                path = %p.display(),
                "materialize_handle_settings: using UUID-keyed settings overlay (M2-3)"
            );
            p.to_path_buf()
        }
        _ => config_dir.join("settings.json"),
    };
    let (mut overlay, overlay_usable, _) = read_settings_layer(&overlay_path, true);
    // Strip slot policy before merge so the user's global JSON settings remain intact.
    super::settings_policy::strip_autocompact_overrides(&mut overlay);
    // Slot-supplied percentage overrides are global-only; provider windows require
    // a published third-party binding. Filter the overlay so global values survive.
    // Only the canonical numeric overlay can use this exception. A selected
    // UUID overlay is distinct input and cannot borrow the numeric slot's proof.
    let allow_provider_window = overlay_path == config_dir.join("settings.json")
        && config_dir.parent().is_some_and(|base_dir| {
            super::settings_policy::slot_allows_provider_window(base_dir, config_dir)
        });
    super::settings_policy::strip_slot_autocompact_env(&mut overlay, allow_provider_window);
    // A slot may never switch off the global hooks: `disableAllHooks` is global-only, so it
    // is stripped from the slot layer BEFORE the merge and can never override the global value.
    if overlay
        .as_object_mut()
        .is_some_and(|m| m.remove(SLOT_FORBIDDEN_HOOK_KEY).is_some())
    {
        warn!(
            error_kind = "slot_disable_all_hooks_stripped",
            "slot settings carried disableAllHooks; stripped so global hooks keep running"
        );
    }
    // Three-layer merge, lowest to highest: csq defaults < user-global <
    // slot overlay (overlay > global > default). The defaults layer fills in
    // the keys of `default_settings` only when neither the user-global nor
    // the slot overlay sets them — an explicit user setting always wins, and
    // the user-global file itself is never written.
    let mut defaults = default_settings();
    // Fail closed: a settings file that EXISTS but cannot be read as a JSON
    // object (the SAME read that produced `base`/`overlay`, so no race between a check and a
    // use) is treated as `{}` above, which would let a user's explicit
    // `crossSessionInbound: "refuse"` inside it be silently replaced by
    // csq's `accept`. So no csq default for that key is applied then.
    if !base_usable || !overlay_usable || !previous_usable {
        warn!(
            reason = "settings_unusable_no_cross_session_default",
            "a settings file is unreadable; crossSessionInbound default withheld"
        );
        if let Some(m) = defaults.as_object_mut() {
            m.remove("crossSessionInbound");
        }
    }
    let mut merged = merge_settings(&merge_settings(&defaults, &base), &overlay);
    // An unusable GLOBAL settings file yields `{}` above, which would write a handle file with
    // no global hooks. Seed the hooks ONLY from the last-known-good GLOBAL hooks record
    // (`GLOBAL_HOOKS_RECORD_FILE`, written each time the global was read successfully). The
    // previous handle file is NEVER the seed: it already holds the previous slot's own hooks
    // and csq's messaging hooks, so seeding from it would carry one slot's hooks into another.
    // With no record the terminal gets no global hooks; `csq doctor` reports the unusable file.
    let record_path = global_hooks_record_path(handle_dir);
    let hooks_base = if base_usable {
        if let Some(path) = record_path.as_deref() {
            write_global_hooks_record(path, &base);
        }
        base.clone()
    } else if let Some(record) = record_path.as_deref().and_then(read_global_hooks_record) {
        warn!(
            error_kind = "global_settings_unusable_hooks_from_record",
            "global settings.json is unusable; using the last-known-good global hooks record"
        );
        record
    } else {
        warn!(
            error_kind = "global_settings_unusable_no_hooks_record",
            "global settings.json is unusable and no last-known-good hooks record exists; \
             this terminal gets no global hooks"
        );
        base.clone()
    };
    concat_hook_arrays(&mut merged, &[&hooks_base, &overlay]);

    // Preserve a stricter in-session choice, but never let the previous default
    // accept weaken the newly merged account policy. Refuse is strongest;
    // approval/hold (including the native default when absent) beats accept.
    // Other previous account settings must not survive the swap. Registration
    // below consumes this same read.
    let inbound_restriction = |choice: Option<&Value>| match choice.and_then(Value::as_str) {
        Some("accept") => 0,
        Some("refuse") => 2,
        _ => 1,
    };
    match previous.get("crossSessionInbound") {
        Some(choice) if matches!(choice.as_str(), Some("accept" | "hold" | "refuse")) => {
            let merged_unknown = merged
                .get("crossSessionInbound")
                .is_some_and(|value| !matches!(value.as_str(), Some("accept" | "hold" | "refuse")));
            if inbound_restriction(Some(choice))
                > inbound_restriction(merged.get("crossSessionInbound"))
                || (inbound_restriction(Some(choice)) >= 1 && merged_unknown)
            {
                merged["crossSessionInbound"] = choice.clone();
            }
        }
        // Every existing local file without a known choice retains native
        // approval, including a usable object whose key was withheld on a prior
        // swap. Only confirmed absence means a fresh handle may default to accept.
        // A newly merged refusal/approval remains in force.
        _ if !previous_absent && inbound_restriction(merged.get("crossSessionInbound")) == 0 => {
            if let Some(settings) = merged.as_object_mut() {
                settings.remove("crossSessionInbound");
            }
        }
        _ => {}
    }

    // Spec 32 §6: a terminal launched with messaging registered keeps its hooks and allow
    // rules across a swap. The handle dir's PREVIOUS settings.json is the only source of
    // that fact, so a dir without a registration (messaging off, or never launched by
    // `csq run`) gains none here. Fail-open: a refusal logs a fixed tag and the swap
    // proceeds without the layer.
    if let Err(e) = crate::messaging::register::carry_over(handle_dir, &previous, &mut merged) {
        warn!(
            error_kind = crate::messaging::register::LOG_TAG_FAILED,
            reason = e.tag(),
            "handle settings re-materialized without the messaging layer"
        );
    }
    let recorded = read_layer_record(handle_dir);
    let mut layers = merged.clone();
    apply_session_keys(&mut layers);
    let record = layer_record(&layers);
    carry_preferences(&previous, recorded.as_ref(), &mut merged);
    apply_session_keys(&mut merged);
    let json = serde_json::to_string_pretty(&merged).map_err(|e| CredentialError::Corrupt {
        path: settings_path.clone(),
        reason: format!("merged settings serialize failed: {e}"),
    })?;

    let tmp = crate::platform::fs::unique_tmp_path(&settings_path);
    // §5a cleanup (L2): handle dir settings.json is the MERGED view of
    // claude_home + slot's config-<N>/settings.json — and the slot's
    // settings.json carries ANTHROPIC_AUTH_TOKEN per the bind/unbind path.
    // `create_tmp_exclusive` (below) opens with `O_EXCL` + `mode(0o600)`
    // rather than `std::fs::write`'s `O_CREAT`-without-`O_EXCL` at
    // umask-default permissions — see that fn's doc for why.
    if let Err(e) = create_tmp_exclusive(&tmp, json.as_bytes()) {
        // create_tmp_exclusive already cleaned up its own tmp on a
        // WRITE failure; an `open` refusal (planted symlink/file, or a
        // genuine PID+counter collision) never created anything to clean
        // up in the first place.
        return Err(CredentialError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Corrupt {
            path: tmp,
            reason: format!("secure_file: {e}"),
        });
    }
    Ok((tmp, record))
}

/// S-H1/D-F1: commits a temp file prepared by [`prepare_handle_settings_tmp`]
/// into `settings_path` via a single rename (`atomic_replace`). This is the
/// ONLY fallible operation `repoint_handle_dir` performs after its symlink
/// rename loop has started mutating disk — folding it into the loop's own
/// rollback path (rather than leaving it as a trailing `?` with no
/// rollback) is the whole point of the prepare/commit split.
///
/// Returns the raw I/O error (rather than a `CredentialError`) so
/// `repoint_handle_dir` can carry it directly in
/// `CredentialError::RepointFailed { source: io::Error, .. }` alongside a
/// truthful `rolled_back`, exactly like a failed symlink rename. On
/// failure the temp file is removed here (`atomic_replace`'s underlying
/// `rename(2)` leaves the source in place on error) — the caller never
/// needs to clean it up itself.
fn commit_prepared_handle_settings(tmp: &Path, settings_path: &Path) -> std::io::Result<()> {
    // S-H1/D-F1 test-only fault seam — see the `thread_local!` block above
    // `repoint_lock_path` for the full contract.
    if repoint_fail_settings_commit_for_test() {
        let _ = std::fs::remove_file(tmp);
        return Err(std::io::Error::other(
            "injected test failure (repoint_fail_settings_commit_for_test)",
        ));
    }
    if let Err(e) = crate::platform::fs::atomic_replace(tmp, settings_path) {
        let _ = std::fs::remove_file(tmp);
        return Err(match e {
            crate::error::PlatformError::Io(io_err) => io_err,
            other => std::io::Error::other(other.to_string()),
        });
    }
    Ok(())
}

/// The settings key a slot may never set: it switches every hook off, so it is global-only.
const SLOT_FORBIDDEN_HOOK_KEY: &str = "disableAllHooks";

/// Rebuilds `merged.hooks` from the `layers` (lowest first: user-global, then slot overlay) so
/// every GLOBAL `hooks.<Event>` entry survives whatever a later layer holds. `merge_settings`
/// lets a later layer's `hooks` value (`null`, `[]`, a string, a per-event non-array) replace
/// the global one, so `merged.hooks` is not trusted: the first layer whose `hooks` is an
/// object seeds the result verbatim, and each later layer's object-valued `hooks` is folded in
/// per event. A later layer's `hooks` that is not an object is ignored. Per event: array +
/// array CONCATENATES in layer order, de-duplicating ONLY across layers (an entry already in
/// the earlier layers' array is not added again; duplicates inside one layer are kept); an
/// event only the later layer has is inserted as is; a later non-array value never replaces an
/// existing earlier value. The messaging layer is applied after this and appends. Keys other
/// than `hooks` keep `merge_settings` semantics. If no layer's `hooks` is an object, `merged`
/// is left as `merge_settings` produced it.
fn concat_hook_arrays(merged: &mut Value, layers: &[&Value]) {
    let mut acc: Option<serde_json::Map<String, Value>> = None;
    for layer in layers {
        let Some(hooks) = layer.get("hooks").and_then(Value::as_object) else {
            continue;
        };
        if acc.is_none() {
            acc = Some(hooks.clone());
            continue;
        }
        let Some(acc) = acc.as_mut() else {
            continue;
        };
        for (event, value) in hooks {
            match (acc.get(event), value) {
                (Some(Value::Array(prior)), Value::Array(entries)) => {
                    let prior = prior.clone();
                    let mut combined = prior.clone();
                    combined.extend(entries.iter().filter(|e| !prior.contains(e)).cloned());
                    acc.insert(event.clone(), Value::Array(combined));
                }
                (Some(_), _) => {}
                (None, _) => {
                    acc.insert(event.clone(), value.clone());
                }
            }
        }
    }
    if let (Some(acc), Some(obj)) = (acc, merged.as_object_mut()) {
        obj.insert("hooks".to_owned(), Value::Object(acc));
    }
}

/// Whether the settings file at `path` (a slot overlay) carries the global-only
/// `disableAllHooks` key. A missing, unreadable, oversize, non-regular (FIFO, device) or
/// unparseable file is `false`; the read is bounded and cannot block (`read_regular_bounded`). Used by
/// `csq doctor`; the merge strips the key regardless.
#[must_use]
pub fn settings_file_has_disable_all_hooks(path: &Path) -> bool {
    read_regular_bounded(path, false)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|v| v.get(SLOT_FORBIDDEN_HOOK_KEY).is_some())
}

/// Whether the user-global `<claude_home>/settings.json` EXISTS but cannot be used as a JSON
/// object (the same classification the materializer applies), so global hooks are not being
/// merged from it. A missing or empty file is usable (`false`).
#[must_use]
pub fn global_claude_settings_unusable(claude_home: &Path) -> bool {
    !read_settings_layer(&claude_home.join("settings.json"), true).1
}

/// One settings layer, read ONCE: its root object, usability and absence.
/// Invalid JSON, nonobjects and read errors are unusable. The terminal-local
/// layer treats NotFound as usable only when lstat confirms the entry is absent;
/// global/slot layers retain their historical missing-target compatibility.
/// The value and both flags share one content read; lstat reads only metadata.
/// Local absence is confirmed only on NotFound plus an absent directory entry;
/// all other failures conservatively retain previous-file policy.
/// Empty global/slot files retain their historical absent-layer semantics. An
/// existing empty terminal-local file is unusable: a partial write must not
/// replace an unknown in-session inbound refusal with the accept default.
fn read_settings_layer(path: &Path, empty_usable: bool) -> (Value, bool, bool) {
    let empty = || Value::Object(serde_json::Map::new());
    let content = match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => return (empty(), empty_usable, false),
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A missing local target does not mean the settings entry is absent:
            // a dangling symlink (or a read/lstat race) must not restore accept.
            // Global/slot layers retain their historical NotFound behavior. This
            // inspects only the entry; it never performs a second content read.
            let absent = empty_usable
                || std::fs::symlink_metadata(path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
            return (empty(), absent, absent);
        }
        Err(e) => {
            warn!(path = %path.display(), error_kind = ?e.kind(), "settings file unreadable, treating as empty");
            return (empty(), false, false);
        }
    };
    match serde_json::from_str::<Value>(&content) {
        Ok(v) if v.is_object() => (v, true, false),
        Ok(_) => {
            warn!(path = %path.display(), "settings file is not a JSON object, treating as empty");
            (empty(), false, false)
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "settings file has invalid JSON, treating as empty");
            (empty(), false, false)
        }
    }
}

/// F2(a): what one `ACCOUNT_BOUND_ITEMS` link held immediately before
/// [`repoint_handle_dir`]'s rename loop touched it — either it did not
/// exist, or it resolved to a specific target. Snapshotting every item
/// BEFORE the loop starts (rather than only the ones it successfully
/// moves) is what lets a failure partway through restore each
/// already-moved item to exactly what it held, rather than merely
/// reporting which items moved and leaving the rest to the caller.
enum PreRepointLinkState {
    Absent,
    Target(PathBuf),
}

/// S7: `symlink_metadata` (never `read_link` alone) is the ONLY primitive
/// that can tell "genuinely absent" apart from "exists, but is a real file
/// or directory, not a symlink" — `read_link`'s `Err` collapses both into
/// the same outcome, which is what let [`PreRepointLinkState::Absent`]
/// silently stand in for a REAL file. A caller about to rename a symlink
/// OVER that path (see the pre-flight guard in [`repoint_handle_dir`],
/// which runs before this function's result is ever used to mutate
/// anything) must see the distinction, not lose it here.
fn snapshot_link_state(handle_dir: &Path, item: &str) -> PreRepointLinkState {
    let path = handle_dir.join(item);
    let is_symlink = path
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink());
    if !is_symlink {
        return PreRepointLinkState::Absent;
    }
    match std::fs::read_link(&path) {
        Ok(target) => PreRepointLinkState::Target(target),
        // A symlink `symlink_metadata` just confirmed, but `read_link` can no
        // longer read — a race with a concurrent unlink. Genuinely absent now.
        Err(_) => PreRepointLinkState::Absent,
    }
}

/// F2: best-effort restore of one `item`'s link at `handle_dir` back to
/// `state`. Also removes any leftover `{item}.swap-tmp` — a rename that
/// failed partway can leave the temp symlink behind, and the caller's
/// message (F2(d)) is only accurate if that temp file is gone. Returns
/// `false` on any failure so the caller can tell "nothing changed" from
/// "may be partially switched" — never panics, and never leaves the
/// process in a worse state than it found it.
fn restore_link_state(handle_dir: &Path, item: &str, state: &PreRepointLinkState) -> bool {
    // S2 test-only fault seam: simulate THIS item's own restore failing
    // (e.g. the item's `create_symlink` call failing) so a caller-facing
    // test can prove a rollback that ITSELF fails is correctly reported as
    // `rolled_back: false`, distinct from a rollback that never ran.
    if repoint_fail_restore_for_item_for_test() == Some(item) {
        return false;
    }
    let link_path = handle_dir.join(item);
    let tmp_path = handle_dir.join(format!("{item}.swap-tmp"));
    let _ = std::fs::remove_file(&tmp_path);
    match state {
        PreRepointLinkState::Absent => {
            if link_path.symlink_metadata().is_ok() {
                std::fs::remove_file(&link_path).is_ok()
            } else {
                true
            }
        }
        PreRepointLinkState::Target(previous_target) => {
            if link_path.symlink_metadata().is_ok() && std::fs::remove_file(&link_path).is_err() {
                return false;
            }
            create_symlink(previous_target, &link_path).is_ok()
        }
    }
}

/// F2: restore every item named in `moved` to its snapshotted pre-repoint
/// state. `moved` names both items that were actually renamed into place
/// AND items whose old link was deleted because the new config lacked a
/// matching target (F2(c): that branch is a mutation too, not a no-op).
/// Returns `true` only if EVERY named item was fully restored — the
/// caller's F2(d) operator message is chosen from this, not from whether
/// the repoint itself failed.
fn rollback_repoint(
    handle_dir: &Path,
    snapshots: &[(&'static str, PreRepointLinkState)],
    moved: &[&'static str],
) -> bool {
    let mut fully_restored = true;
    for item in moved {
        if let Some((_, state)) = snapshots.iter().find(|(name, _)| name == item) {
            if !restore_link_state(handle_dir, item, state) {
                fully_restored = false;
            }
        }
    }
    fully_restored
}

/// F2(d)/S1/S2: are `handle_dir`'s `ACCOUNT_BOUND_ITEMS` symlinks mutually
/// consistent with the account its own `.csq-account` marker names, and no
/// `*.swap-tmp` leftover remains?
///
/// Used by a repoint failure's caller (`csq swap`, `auto_rotate`) to pick
/// between "the switch did not complete; nothing was changed" and "your
/// terminal may be partially switched — run `csq swap N` again": re-reads
/// the actual on-disk state rather than trusting an in-memory flag from
/// the failed call, so it reports correctly even across a process
/// boundary or if the failed call's own rollback attempt silently missed
/// a case.
///
/// S1 fix: the prior implementation compared every item's link PARENT
/// against a single common value, which is a legacy-only invariant — an
/// identity-keyed slot's `.credentials.json` resolves under
/// `identities/<UUID>/` while its OTHER three items resolve under
/// `config-<N>/`, so that comparison was `false` for every identity-keyed
/// dir regardless of whether anything had actually gone wrong. This
/// version instead resolves the account the dir's OWN marker names
/// (`markers::resolve_marker_to_slot`, numeric-or-UUID) and compares each
/// item's actual link target against the EXPECTED target for THAT
/// account, via the same [`account_to_identity_paths`] chokepoint
/// [`create_handle_dir`] and [`repoint_handle_dir`] both build their
/// targets from — so the comparison is correct for both layouts.
///
/// S2 fix: a link that is MISSING now counts as inconsistent whenever its
/// expected target exists on disk — the prior version silently skipped a
/// `read_link` error (`let Ok(target) = ... else { continue }`), which
/// could not distinguish "this item is legitimately absent" (e.g. no
/// `.credentials.json` for a 3P API-key slot) from "this item's symlink
/// was deleted mid-repoint and never restored".
///
/// K1 fix: S2's "missing + expected exists ⇒ inconsistent" rule is only
/// correct for `.credentials.json` and `.csq-account` — `create_handle_dir`
/// links these two whenever the CONFIG dir already carries them, and a
/// slot's config dir always has both by the time it is usable. But
/// `.current-account` and `.quota-cursor` are NOT guaranteed to exist yet
/// at handle-dir creation time (they are written later, by the first
/// quota poll or by a swap from a DIFFERENT terminal) — so a healthy dir
/// created before either existed legitimately lacks the link, and a later
/// write from elsewhere then makes `expected.exists()` true. Under the old
/// rule that flipped this healthy dir to "inconsistent" and every
/// subsequent failed-repoint report on it read "may be partially switched"
/// even after a clean rollback. A missing link for these two items is
/// therefore never itself a sign of inconsistency; a mismatched
/// (present-but-wrong-target) link for them still is.
///
/// K2/D-Lead: `expected` for `.credentials.json` is resolved through
/// [`account_to_identity_paths`], which prefers the identity-keyed path
/// once `profiles.json` maps this slot to a UUID. A handle dir created
/// while the slot was still legacy-keyed has `.credentials.json` pointed
/// at `config-<N>/.credentials.json`; if the slot migrates to a UUID
/// afterward, nothing repoints that dir's existing link. **This is NOT
/// "correctly keeping working" (the prior wording here, retracted
/// D-Lead)**: M3-7 retired csq's own writers to the legacy path for any
/// UUID-keyed slot (spec 02 INV-05 — the legacy mirror is no longer
/// written), so `config-<N>/.credentials.json` is FROZEN at whatever it
/// held at migration time. A dir still linked to it silently reads a
/// stale, never-refreshing credential snapshot while CC's keychain-first
/// read may still show the account as "working" right up until that
/// frozen token expires. This function therefore accepts ONLY the
/// identity-keyed target for `.credentials.json` once the slot has
/// migrated — for a still-legacy (unmigrated) slot,
/// [`account_to_identity_paths`] already resolves `credentials_path` to
/// `config-<N>/.credentials.json`, so the single accepted target still
/// covers that case without a separate legacy fallback.
///
/// The marker itself being unresolvable (no `by_slot` entry, corrupt
/// `profiles.json`, or the `.csq-account` link itself missing) is
/// reported as inconsistent: with no account to check targets against,
/// "consistent" cannot be established.
///
/// I2 (B3, 2026-09-26 owner directive): this function's DIRECT caller is
/// `credentials::keychain::repoint_left_mixed_links` (`base_dir`/
/// `handle_dir` are threaded straight through, unmodified) — NOT `csq
/// swap`/`auto_rotate` directly, which is what an earlier revision of this
/// doc claimed. That claim was doubly stale: at the time it was written,
/// this function had been revived as production logic only in its OWN
/// unit tests — `csq swap` and `auto_rotate` did not consult it at the
/// point a repoint failed at all (the gap B3 fixes). Post-B3,
/// `repoint_left_mixed_links` IS wired into both callers' error paths
/// (`csq swap`'s same-surface ClaudeCode route, `daemon::auto_rotate::tick`),
/// each combining this function's `false` result with
/// `CredentialError::repoint_rolled_back() == Some(false)` (the OTHER
/// half of `repoint_left_mixed_links`'s `||`) before choosing the mixed-
/// links operator line over the plain reconcile-outcome line.
pub fn handle_dir_symlinks_are_consistent(base_dir: &Path, handle_dir: &Path) -> bool {
    for item in ACCOUNT_BOUND_ITEMS {
        if handle_dir
            .join(format!("{item}.swap-tmp"))
            .symlink_metadata()
            .is_ok()
        {
            return false;
        }
    }

    let Some(account) = markers::resolve_marker_to_slot(base_dir, handle_dir) else {
        return false;
    };
    let identity_paths = account_to_identity_paths(base_dir, account);
    let config_dir = base_dir.join(format!("config-{}", account.get()));

    for item in ACCOUNT_BOUND_ITEMS {
        // K1: only `.credentials.json` and `.csq-account` are always
        // created for a usable slot; a missing link for the other two is
        // not itself inconsistent.
        let always_created = *item == ".credentials.json" || *item == ".csq-account";

        // D-Lead: `.credentials.json` accepts ONLY the identity-keyed
        // target — see this function's doc comment above for why the
        // prior "either the identity path or this slot's own legacy path"
        // acceptance was unsound (the legacy path is frozen, not merely a
        // second valid location).
        let expected_targets: Vec<PathBuf> = if *item == ".credentials.json" {
            vec![identity_paths.credentials_path.clone()]
        } else {
            vec![config_dir.join(item)]
        };

        match std::fs::read_link(handle_dir.join(item)) {
            Ok(actual) if expected_targets.contains(&actual) => {}
            Ok(_) => return false,
            Err(_) => {
                if always_created {
                    return false;
                }
                // else: legitimately absent for this item — not inconsistent.
            }
        }
    }
    true
}

// F2 test-only fault seam: when set, the `k`-th item processed by
// `repoint_handle_dir`'s rename loop (0-indexed, in the loop's own
// processing order) fails as if `std::fs::rename` returned an error —
// without touching the filesystem beyond what a real failed rename
// would leave (the temp symlink still present). Thread-local so
// concurrent tests never interfere; a `Drop` guard in the test resets it
// even on panic (the default test harness reuses OS threads across
// tests, so an unguarded set would leak into an unrelated test).
// `cfg(all(test, unix))`, not just `cfg(test)`: the only consumer is a
// `#[cfg(unix)]` test (`repoint_handle_dir` symlinks are POSIX-only), so a
// bare `cfg(test)` leaves the setter genuinely unused on a Windows test
// build — `dead_code` under `-D warnings`.
#[cfg(all(test, unix))]
thread_local! {
    static REPOINT_FAIL_AT_RENAME_INDEX: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// F2 test-only fault seam setter — see the `thread_local!` block above
/// this function for the full contract (what it simulates, why
/// thread-local, and the `Drop`-guard requirement on callers).
#[cfg(all(test, unix))]
pub(crate) fn set_repoint_fail_at_rename_index_for_test(index: Option<usize>) {
    REPOINT_FAIL_AT_RENAME_INDEX.with(|c| c.set(index));
}

#[cfg(all(test, unix))]
fn repoint_fail_at_rename_index_for_test() -> Option<usize> {
    REPOINT_FAIL_AT_RENAME_INDEX.with(|c| c.get())
}

#[cfg(not(all(test, unix)))]
fn repoint_fail_at_rename_index_for_test() -> Option<usize> {
    None
}

// S2 test-only fault seam: when set, `restore_link_state` reports failure
// for the NAMED item regardless of what its own restore logic would have
// done — lets a test prove a rollback that ITSELF fails (as opposed to one
// that never runs) is reported as `rolled_back: false`. Thread-local for
// the same reason as `REPOINT_FAIL_AT_RENAME_INDEX`; reset by the same
// `RepointFaultGuard` RAII pattern in tests.
#[cfg(all(test, unix))]
thread_local! {
    static REPOINT_FAIL_RESTORE_FOR_ITEM: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, unix))]
pub(crate) fn set_repoint_fail_restore_for_item_for_test(item: Option<&'static str>) {
    REPOINT_FAIL_RESTORE_FOR_ITEM.with(|c| c.set(item));
}

#[cfg(all(test, unix))]
fn repoint_fail_restore_for_item_for_test() -> Option<&'static str> {
    REPOINT_FAIL_RESTORE_FOR_ITEM.with(|c| c.get())
}

#[cfg(not(all(test, unix)))]
fn repoint_fail_restore_for_item_for_test() -> Option<&'static str> {
    None
}

// S-H1/D-F1 test-only fault seam: when set, `commit_prepared_handle_settings`
// fails as if the final `atomic_replace` of the prepared settings.json temp
// file returned an error — without touching the filesystem beyond what a
// real failed commit would leave (the temp file removed, `settings_path`
// untouched). Lets a test prove that a failure at THIS specific point —
// after every `ACCOUNT_BOUND_ITEMS` symlink (including `.csq-account`) has
// already been renamed — is folded into the same `rollback_repoint` +
// `RepointFailed` reporting as a mid-loop rename failure, rather than
// propagating as a bare `Corrupt`/`Io` with no rollback (S-H1/D-F1).
// Thread-local + `Drop`-guard-reset for the same reason as the two seams
// above.
#[cfg(all(test, unix))]
thread_local! {
    static REPOINT_FAIL_SETTINGS_COMMIT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
pub(crate) fn set_repoint_fail_settings_commit_for_test(fail: bool) {
    REPOINT_FAIL_SETTINGS_COMMIT.with(|c| c.set(fail));
}

#[cfg(all(test, unix))]
fn repoint_fail_settings_commit_for_test() -> bool {
    REPOINT_FAIL_SETTINGS_COMMIT.with(|c| c.get())
}

#[cfg(not(all(test, unix)))]
fn repoint_fail_settings_commit_for_test() -> bool {
    false
}

// R2 NEW-1/N2 test-only seam: runs once, with the handle dir, right after the
// `ACCOUNT_BOUND_ITEMS` rename loop and before any commit — lets a test mutate
// `.claude.json` at exactly the point a live CC writer can. Thread-local, so
// it never leaks across tests; callers reset it with `None`.
#[cfg(all(test, unix))]
type RepointAfterLoopHook = Box<dyn Fn(&Path)>;

#[cfg(all(test, unix))]
thread_local! {
    static REPOINT_AFTER_LOOP_HOOK: std::cell::RefCell<Option<RepointAfterLoopHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
pub(crate) fn set_repoint_after_loop_hook_for_test(hook: Option<RepointAfterLoopHook>) {
    REPOINT_AFTER_LOOP_HOOK.with(|c| *c.borrow_mut() = hook);
}

#[cfg(all(test, unix))]
fn run_repoint_after_loop_hook_for_test(handle_dir: &Path) {
    REPOINT_AFTER_LOOP_HOOK.with(|c| {
        if let Some(hook) = c.borrow().as_ref() {
            hook(handle_dir);
        }
    });
}

/// Resolve the per-handle-dir rename-serialization lock path (`.swap.lock`,
/// dot) used by [`repoint_handle_dir`] and [`repoint_handle_dir_codex`].
///
/// Canonicalizes `handle_dir` first so a caller that passes a raw path
/// (`csq swap` forwards `source.path()` verbatim) and a caller that passes a
/// pre-canonicalized path (`auto_rotate` canonicalizes at the top of its loop)
/// resolve to the SAME inode. Without this, a symlink component anywhere in the
/// accounts base splits the two into different lock files that never contend, so
/// the rename lock silently fails to serialize concurrent repoints (an internal ticket).
/// Falls back to the raw path when canonicalize fails (dangling dir) — the same
/// posture both callers use for their own canonicalization.
///
/// DISTINCT from [`crate::credentials::keychain::swap_lock_path`] (`.swap-lock`,
/// hyphen — the A4a keychain-desync guard). The A4a guard is held ACROSS the
/// repoint call by `csq swap` / `auto_rotate`; `lock_file` opens a fresh fd and
/// `flock`s it, and on Unix/macOS `flock` is per-open-file-description, so
/// re-`flock`-ing the SAME file from a second fd in one process blocks forever.
/// The two lock files therefore MUST stay distinct (`.swap.lock` vs `.swap-lock`).
fn repoint_lock_path(handle_dir: &Path) -> PathBuf {
    let lock_dir = std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
    lock_dir.join(".swap.lock")
}

/// Atomically repoints the account-bound symlinks in a handle dir
/// to point at a new `config-<target>` directory.
///
/// Uses rename-over (NOT delete + create) for atomicity.
///
/// # Errors
///
/// - If the handle dir is not a `term-<pid>` dir (refuses legacy `config-N`)
/// - If `config-<target>` doesn't exist
/// - On any I/O failure during repoint
///
/// Opaque preoperation native/source snapshot. Metadata is an expectation,
/// never a provider ownership proof. Captured while the caller holds swap lock.
pub struct NativeSwapCapture {
    handle: PathBuf,
    raw: Option<String>,
    marker: Option<AccountNum>,
    source_binding: Option<crate::accounts::anthropic_identity::CapturedBinding>,
}
impl NativeSwapCapture {
    #[cfg(target_os = "macos")]
    pub(crate) fn marker_account(&self) -> Option<AccountNum> {
        self.marker
    }
}

/// Native receipt reads preserve absence separately from every refusal. The
/// held descriptor is regular and bounded; path identity is checked again
/// before returning so an open-time replacement cannot become an expectation.
pub(crate) fn read_native_swap_raw(handle: &Path) -> Result<Option<String>, CredentialError> {
    use crate::accounts::anthropic_identity as ai;
    use std::io::Read;
    // Same native JSON ceiling as credentials::claude_json's legacy reader.
    const MAX_NATIVE_BYTES: u64 = 16 * 1024 * 1024;
    let path = handle.join(".claude.json");
    #[cfg(windows)]
    let before_file = {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ai::credential_refusal()),
        }
    };
    #[cfg(windows)]
    let before = before_file
        .metadata()
        .map_err(|_| ai::credential_refusal())?;
    #[cfg(not(windows))]
    let before = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ai::credential_refusal()),
    };
    if !before.is_file() || before.len() > MAX_NATIVE_BYTES {
        return Err(ai::credential_refusal());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = options.open(&path).map_err(|_| ai::credential_refusal())?;
    let opened = file.metadata().map_err(|_| ai::credential_refusal())?;
    if !opened.is_file() || opened.len() > MAX_NATIVE_BYTES {
        return Err(ai::credential_refusal());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.nlink() != 1
            || opened.uid() != unsafe { libc::geteuid() }
        {
            return Err(ai::credential_refusal());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x0400 != 0
            || opened.file_attributes() & 0x0400 != 0
            || ai::windows_file_identity(&before_file).map_err(|_| ai::credential_refusal())?
                != ai::windows_file_identity(&file).map_err(|_| ai::credential_refusal())?
            || before.len() != opened.len()
            || before.last_write_time() != opened.last_write_time()
            || before.creation_time() != opened.creation_time()
        {
            return Err(ai::credential_refusal());
        }
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_NATIVE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ai::credential_refusal())?;
    let after = file.metadata().map_err(|_| ai::credential_refusal())?;
    let current = std::fs::symlink_metadata(&path).map_err(|_| ai::credential_refusal())?;
    if bytes.len() as u64 > MAX_NATIVE_BYTES
        || bytes.len() as u64 != opened.len()
        || !after.is_file()
        || !current.is_file()
        || after.len() != opened.len()
        || current.len() != opened.len()
        || after.modified().map_err(|_| ai::credential_refusal())?
            != opened.modified().map_err(|_| ai::credential_refusal())?
        || current.modified().map_err(|_| ai::credential_refusal())?
            != opened.modified().map_err(|_| ai::credential_refusal())?
    {
        return Err(ai::credential_refusal());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != opened.dev()
            || after.ino() != opened.ino()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
            || after.ctime() != opened.ctime()
            || after.ctime_nsec() != opened.ctime_nsec()
            || current.ctime() != opened.ctime()
            || current.ctime_nsec() != opened.ctime_nsec()
        {
            return Err(ai::credential_refusal());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let named_file = options.open(&path).map_err(|_| ai::credential_refusal())?;
        let named = named_file
            .metadata()
            .map_err(|_| ai::credential_refusal())?;
        if current.file_attributes() & 0x0400 != 0
            || after.file_attributes() & 0x0400 != 0
            || ai::windows_file_identity(&named_file).map_err(|_| ai::credential_refusal())?
                != ai::windows_file_identity(&file).map_err(|_| ai::credential_refusal())?
            || named.len() != after.len()
            || named.last_write_time() != after.last_write_time()
            || named.creation_time() != after.creation_time()
            || after.last_write_time() != opened.last_write_time()
            || after.creation_time() != opened.creation_time()
        {
            return Err(ai::credential_refusal());
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ai::credential_refusal())
}

/// `reason` carried by [`profiles_lock_busy`].
const PROFILES_LOCK_BUSY_REASON: &str = "profiles_lock_busy";

/// N5: another holder (daemon verifier, sentinel clear, custodian adopt) has
/// the profiles lock. Nothing is wrong with the account's identity and
/// nothing changed — the caller must say "busy, retry", never "run csq login".
fn profiles_lock_busy() -> CredentialError {
    CredentialError::Corrupt {
        path: "anthropic-identity".into(),
        reason: PROFILES_LOCK_BUSY_REASON.into(),
    }
}

/// True when `error` is the busy-profiles-lock refusal of
/// [`capture_native_swap`] / [`repoint_handle_dir_guarded`].
pub fn is_profiles_lock_busy(error: &CredentialError) -> bool {
    matches!(error, CredentialError::Corrupt { reason, .. } if reason == PROFILES_LOCK_BUSY_REASON)
}

pub fn capture_native_swap(
    base: &Path,
    handle: &Path,
) -> Result<NativeSwapCapture, CredentialError> {
    use crate::accounts::{anthropic_identity as ai, profiles_lock::ProfilesFileLock};
    let lock = ProfilesFileLock::try_acquire(base)
        .map_err(|_| ai::credential_refusal())?
        .ok_or_else(profiles_lock_busy)?;
    capture_native_swap_locked(&lock, base, handle)
}

/// Capture native/source expectations using existing profile custody.
pub(crate) fn capture_native_swap_locked(
    lock: &crate::accounts::profiles_lock::ProfilesFileLock,
    base: &Path,
    handle: &Path,
) -> Result<NativeSwapCapture, CredentialError> {
    use crate::accounts::anthropic_identity as ai;
    if !lock.protects(base) {
        return Err(ai::credential_refusal());
    }
    let canonical_handle = std::fs::canonicalize(handle).map_err(|_| ai::credential_refusal())?;
    if !canonical_handle.is_dir() {
        return Err(ai::credential_refusal());
    }
    let marker = crate::accounts::markers::resolve_marker_to_slot(base, handle);
    let source_binding =
        marker.and_then(|slot| ai::capture_anthropic_binding_locked(lock, base, slot).ok());
    let raw = read_native_swap_raw(handle)?;
    if raw.as_deref().is_some_and(|raw| {
        serde_json::from_str::<Value>(raw).map_or(true, |json| !json.is_object())
    }) {
        return Err(ai::credential_refusal());
    }
    Ok(NativeSwapCapture {
        handle: canonical_handle,
        raw,
        marker,
        source_binding,
    })
}
fn native_context_can_rewrite(
    raw: Option<&str>,
    target: &crate::accounts::anthropic_identity::AnthropicContext,
    source: Option<&crate::accounts::anthropic_identity::AnthropicContext>,
) -> bool {
    let Some(raw) = raw else {
        return true;
    };
    let Ok(json) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    if !json.is_object() {
        return false;
    }
    let Some(account) = json.get("oauthAccount") else {
        return true;
    };
    if account.is_null()
        || account
            .as_object()
            .is_some_and(|account| account.is_empty())
    {
        return true;
    }
    let Ok(expected) = crate::accounts::anthropic_identity::parse_native_expectation(&json) else {
        return false;
    };
    expected.context() == target || source.is_some_and(|source| expected.context() == source)
}

fn native_context_matches_captured_binding(
    raw: Option<&str>,
    binding: &crate::accounts::anthropic_identity::CapturedBinding,
) -> bool {
    use crate::accounts::anthropic_identity as ai;
    let Some(raw) = raw else {
        return true;
    };
    let Ok(json) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    if !json.is_object() {
        return false;
    }
    let Some(account) = json.get("oauthAccount") else {
        return true;
    };
    if account.is_null() || account.as_object().is_some_and(|value| value.is_empty()) {
        return true;
    }
    match binding.context() {
        ai::StoredAnthropicContext::Known(context) => {
            ai::parse_native_expectation(&json).is_ok_and(|expected| expected.context() == context)
        }
        ai::StoredAnthropicContext::LegacyUnknown => {
            // A local expectation for this exact captured UUID, not provider
            // ownership. Never derive context/index/identity authority from it.
            account
                .get("emailAddress")
                .and_then(Value::as_str)
                .zip(binding.recorded_legacy_email())
                .is_some_and(|(native, recorded)| native.trim().eq_ignore_ascii_case(recorded))
        }
    }
}
pub(crate) fn native_swap_is_current_locked(
    lock: &crate::accounts::profiles_lock::ProfilesFileLock,
    base: &Path,
    handle: &Path,
    capture: &NativeSwapCapture,
    target: &crate::accounts::anthropic_identity::CapturedBinding,
) -> bool {
    use crate::accounts::anthropic_identity as ai;
    if std::fs::canonicalize(handle).ok().as_ref() != Some(&capture.handle) {
        return false;
    }
    let Ok(current_native) = read_native_swap_raw(handle) else {
        return false;
    };
    if crate::accounts::markers::resolve_marker_to_slot(base, handle) != capture.marker
        || current_native != capture.raw
    {
        return false;
    }
    if capture
        .source_binding
        .as_ref()
        .is_some_and(|source| !ai::binding_matches_locked(lock, base, source).unwrap_or(false))
    {
        return false;
    }
    let source = capture.source_binding.as_ref();
    if matches!(target.context(), ai::StoredAnthropicContext::LegacyUnknown) {
        // Both sides need independent local canonical custody. A missing source
        // is never turned into a legacy UUID by an email or directory fallback.
        return target.recorded_legacy_email().is_some()
            && source.is_some()
            && (native_context_matches_captured_binding(capture.raw.as_deref(), target)
                || source.is_some_and(|source| {
                    native_context_matches_captured_binding(capture.raw.as_deref(), source)
                }));
    }
    let ai::StoredAnthropicContext::Known(target_context) = target.context() else {
        return false;
    };
    if source.is_some_and(|source| {
        matches!(source.context(), ai::StoredAnthropicContext::LegacyUnknown)
            && native_context_matches_captured_binding(capture.raw.as_deref(), source)
    }) {
        return true;
    }
    let source = capture
        .source_binding
        .as_ref()
        .and_then(|binding| match binding.context() {
            ai::StoredAnthropicContext::Known(context) => Some(context),
            ai::StoredAnthropicContext::LegacyUnknown => None,
        });
    native_context_can_rewrite(capture.raw.as_deref(), target_context, source)
}
pub(crate) fn native_swap_is_current(
    base: &Path,
    handle: &Path,
    capture: &NativeSwapCapture,
    target: &crate::accounts::anthropic_identity::CapturedBinding,
) -> bool {
    let Ok(Some(lock)) = crate::accounts::profiles_lock::ProfilesFileLock::try_acquire(base) else {
        return false;
    };
    native_swap_is_current_locked(&lock, base, handle, capture, target)
}

/// Handle-repoint lock acquired before profile custody; both remain held
/// across force-write, symlink publication and compensation.
pub(crate) struct RepointCustody {
    pub(crate) profiles: crate::accounts::profiles_lock::ProfilesFileLock,
    handle: PathBuf,
    _repoint_guard: crate::platform::lock::FileLockGuard,
}

pub(crate) fn lock_repoint_custody(
    base: &Path,
    handle: &Path,
) -> Result<RepointCustody, CredentialError> {
    use crate::accounts::{anthropic_identity as ai, profiles_lock::ProfilesFileLock};
    if !handle
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|n| n.starts_with("term-"))
    {
        return Err(ai::credential_refusal());
    }
    let canonical = std::fs::canonicalize(handle).map_err(|_| ai::credential_refusal())?;
    let repoint = crate::platform::lock::lock_file(&repoint_lock_path(handle))
        .map_err(|_| ai::credential_refusal())?;
    let profiles = ProfilesFileLock::try_acquire(base)
        .map_err(|_| ai::credential_refusal())?
        .ok_or_else(profiles_lock_busy)?;
    Ok(RepointCustody {
        profiles,
        handle: canonical,
        _repoint_guard: repoint,
    })
}

pub fn repoint_handle_dir_guarded(
    base_dir: &Path,
    claude_home: &Path,
    handle_dir: &Path,
    target_binding: &crate::accounts::anthropic_identity::CapturedBinding,
    native_capture: &NativeSwapCapture,
) -> Result<(), CredentialError> {
    let custody = lock_repoint_custody(base_dir, handle_dir)?;
    repoint_handle_dir_guarded_locked(
        &custody,
        base_dir,
        claude_home,
        handle_dir,
        target_binding,
        native_capture,
    )
}

pub(crate) fn repoint_handle_dir_guarded_locked(
    custody: &RepointCustody,
    base_dir: &Path,
    claude_home: &Path,
    handle_dir: &Path,
    target_binding: &crate::accounts::anthropic_identity::CapturedBinding,
    native_capture: &NativeSwapCapture,
) -> Result<(), CredentialError> {
    use crate::accounts::anthropic_identity as ai;
    if !custody.profiles.protects(base_dir)
        || std::fs::canonicalize(handle_dir).ok().as_ref() != Some(&custody.handle)
    {
        return Err(ai::credential_refusal());
    }
    if !ai::binding_matches_locked(&custody.profiles, base_dir, target_binding).unwrap_or(false)
        || !native_swap_is_current_locked(
            &custody.profiles,
            base_dir,
            handle_dir,
            native_capture,
            target_binding,
        )
    {
        return Err(ai::credential_refusal());
    }
    repoint_handle_dir_impl(
        base_dir,
        claude_home,
        handle_dir,
        target_binding.slot(),
        Some(target_binding),
        Some(native_capture),
        true,
    )
}

pub fn repoint_handle_dir(
    base_dir: &Path,
    claude_home: &Path,
    handle_dir: &Path,
    target: AccountNum,
) -> Result<(), CredentialError> {
    // Raw callers cannot repoint an Anthropic login without complete captured
    // custody. The non-Anthropic route keeps its existing provider semantics.
    let Some(uuid) = crate::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get()) else {
        // API-key binding deliberately has no OAuth UUID. Require both its
        // explicit publication label and recognized provider settings; missing
        // OAuth metadata alone never authorizes this compatibility route.
        let third_party_target = || {
            profiles::load(&profiles::profiles_path(base_dir)).is_ok_and(|profiles| {
                !profiles.by_slot.contains_key(&target.get().to_string())
                    && profiles
                        .by_slot_identity
                        .get(&target.get().to_string())
                        .and_then(|label| label.strip_prefix("apikey:"))
                        .and_then(crate::providers::get_provider)
                        .is_some()
                    && crate::accounts::third_party::is_third_party_slot(base_dir, target)
                        .unwrap_or(false)
                    && matches!(
                        std::fs::symlink_metadata(
                            base_dir.join(format!("config-{target}")).join(".credentials.json")
                        ),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound
                    )
            })
        };
        // Refuse without creating lock files for an unverified legacy target.
        if !third_party_target()
            || !handle_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("term-"))
        {
            return Err(crate::accounts::anthropic_identity::credential_refusal());
        }
        let _repoint_guard = crate::platform::lock::lock_file(&repoint_lock_path(handle_dir))
            .map_err(|_| crate::accounts::anthropic_identity::credential_refusal())?;
        let _profiles_guard =
            crate::accounts::profiles_lock::ProfilesFileLock::try_acquire(base_dir)
                .map_err(|_| crate::accounts::anthropic_identity::credential_refusal())?
                .ok_or_else(crate::accounts::anthropic_identity::credential_refusal)?;
        // A compliant login/rebind cannot change provider custody through the
        // rename. Preserve the handle-before-profiles lock order.
        if !third_party_target() {
            return Err(crate::accounts::anthropic_identity::credential_refusal());
        }
        return repoint_handle_dir_impl(
            base_dir,
            claude_home,
            handle_dir,
            target,
            None,
            None,
            true,
        );
    };
    // Missing/corrupt credentials are not evidence of a non-Anthropic identity.
    // Positive provider metadata is required for this compatibility route.
    let provider = crate::accounts::identity_store::read_identity_provider(base_dir, uuid);
    if !matches!(provider.as_deref(), Some("codex" | "gemini" | "3p"))
        || crate::credentials::file::load(&crate::accounts::identity_store::credentials_path_for(
            base_dir, uuid,
        ))
        .is_ok_and(|creds| creds.anthropic().is_some())
    {
        return Err(crate::accounts::anthropic_identity::credential_refusal());
    }
    repoint_handle_dir_impl(base_dir, claude_home, handle_dir, target, None, None, false)
}

fn repoint_handle_dir_impl(
    base_dir: &Path,
    claude_home: &Path,
    handle_dir: &Path,
    target: AccountNum,
    target_binding: Option<&crate::accounts::anthropic_identity::CapturedBinding>,
    native_capture: Option<&NativeSwapCapture>,
    repoint_lock_held: bool,
) -> Result<(), CredentialError> {
    // Verify this is a handle dir, not a config dir
    let dir_name = handle_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if !dir_name.starts_with("term-") {
        return Err(CredentialError::Corrupt {
            path: handle_dir.to_path_buf(),
            reason: format!(
                "expected term-<pid> handle dir, got {dir_name}. \
                 Run `csq run {target}` to launch with handle-dir isolation."
            ),
        });
    }

    // PR-C9a CRITICAL belt-and-suspenders (an internal journal entry finding 1): refuse
    // to rewrite ACCOUNT_BOUND_ITEMS on a handle dir whose symlink set is
    // Codex-shaped. `repoint_handle_dir` only touches the Anthropic
    // `ACCOUNT_BOUND_ITEMS` (`.credentials.json`, `.csq-account`,
    // `.current-account`, `.quota-cursor`) — on a Codex handle dir those
    // items are absent or orthogonal to the real Codex symlinks
    // (`auth.json`, `config.toml`, `sessions`, `history.jsonl`, per spec
    // 07 §7.2.2), so a repoint would leave the Codex symlinks pointing at
    // the old `config-<N>` while rewriting only the ClaudeCode-shape
    // markers. The primary guard lives in `auto_rotate::find_target` (v2.1
    // auto-rotate is ClaudeCode-only), but this secondary guard catches
    // any future caller that forgets the surface check before invoking
    // repoint.
    //
    // Narrowed to items that are **Codex-unique**. `sessions` and
    // `history.jsonl` are not unique — `SHARED_ITEMS` (see
    // `session::isolation`) includes them on ClaudeCode handle dirs as
    // symlinks into `~/.claude/`. Only `auth.json` and `config.toml` are
    // Codex-exclusive markers.
    let codex_unique_items = ["auth.json", "config.toml"];
    for codex_item in codex_unique_items {
        let probe = handle_dir.join(codex_item);
        if probe.symlink_metadata().is_ok() {
            return Err(CredentialError::Corrupt {
                path: handle_dir.to_path_buf(),
                reason: format!(
                    "handle dir contains Codex-unique symlink '{codex_item}'. \
                     `repoint_handle_dir` is the Anthropic repoint path and \
                     must not run on Codex handle dirs. Codex rotation requires \
                     an explicit `csq swap` exec-replace (spec 07 §7.5 INV-P05)."
                ),
            });
        }
    }

    let new_config = base_dir.join(format!("config-{}", target));
    if !new_config.is_dir() {
        return Err(CredentialError::Corrupt {
            path: new_config,
            reason: format!("config-{target} does not exist"),
        });
    }

    // VP-final F3: pre-flight check to prevent mixed-state handle dirs.
    //
    // The rename loop has a "silently continue" path for missing items (the `if
    // !new_target.exists() && new_target.symlink_metadata().is_err()` branch).
    // When the CURRENT handle dir has a symlink for `item` but the NEW config
    // does not have the corresponding target, the loop removes the old symlink
    // without creating a new one — leaving the handle dir in a mixed-state where
    // one symlink is gone and the others still point at the old config. CC then
    // reads a stale or missing identity marker.
    //
    // Pre-flight guards the ONE item that is unconditionally required in EVERY
    // config dir — Anthropic or 3P: `.csq-account`. Without it csq cannot
    // determine which account the handle dir is on after the swap, and the
    // daemon's auto-rotate loop will skip the handle dir on every subsequent
    // tick (sees no marker → skips). All other items may legitimately be absent
    // (e.g. `.credentials.json` is absent for 3P slots that use API keys via
    // `env.ANTHROPIC_AUTH_TOKEN`; `.current-account` and `.quota-cursor` are
    // created lazily). Only `.csq-account` is structurally required in all cases.
    {
        let csq_account_target = new_config.join(".csq-account");
        if !csq_account_target.exists() && csq_account_target.symlink_metadata().is_err() {
            return Err(CredentialError::Corrupt {
                path: csq_account_target,
                reason: format!(
                    "repoint target missing .csq-account in {} — repoint aborted to prevent \
                     mixed-state handle dir",
                    new_config.display()
                ),
            });
        }
    }

    // VP-final F4: serialize concurrent swap + auto-rotate via a per-handle-dir
    // flock. Without this, two callers — e.g. `csq swap` in the terminal AND the
    // daemon's auto-rotate tick — can interleave rename operations and leave the
    // handle dir pointing at two different config-N dirs simultaneously.
    //
    // This is a DIFFERENT lock from the A4a keychain-desync guard
    // (`keychain::swap_lock_path` → `.swap-lock`, hyphen). The names are
    // deliberately distinct: `csq swap` (`SameSurfaceClaudeCode`) and
    // `auto_rotate` ALREADY hold the `.swap-lock` (hyphen) A4a guard across this
    // entire call. `lock_file` opens a fresh fd and `flock`s it; on Unix/macOS
    // flock is per-open-file-description, so re-`flock`-ing the SAME file from a
    // second fd in the same process blocks forever. Merging this inner rename
    // lock onto `.swap-lock` would therefore self-deadlock every swap and every
    // rotation — hence `.swap.lock` (dot) stays a separate file (an internal ticket).
    //
    // `repoint_lock_path` canonicalizes the dir BEFORE computing the lock path so
    // this rename lock resolves to the SAME inode whether the caller passed a raw
    // path (`csq swap` — swap.rs passes `source.path()` verbatim) or a
    // pre-canonicalized one (`auto_rotate` canonicalizes at the top of its loop).
    // Without this, a symlink component in the accounts base makes the two lock
    // different inodes and the inner lock silently fails to serialize them (an internal ticket
    // latent gap).
    //
    // `.swap.lock` lives inside the handle dir so it is automatically cleaned up
    // when the handle dir is swept. `lock_file` blocks until the lock is available
    // (blocking, not try_lock) so the slower caller is serialized, not dropped.
    let lock_path = repoint_lock_path(handle_dir);
    let _swap_guard = if repoint_lock_held {
        None
    } else {
        Some(crate::platform::lock::lock_file(&lock_path).map_err(|e| {
            CredentialError::Corrupt {
                path: lock_path.clone(),
                reason: format!("repoint lock acquisition failed: {e}"),
            }
        })?)
    };

    // M3-4: Resolve the identity-keyed paths for the swap target BEFORE the
    // mtime bump and symlink rebuild.  The bump target MUST match the
    // post-rename symlink target (PRIMARY METHODOLOGICAL DIRECTIVE 1,
    // an internal journal entry WBS line 124 + 04-phase3-readiness.md §M3-4).  Splitting
    // the two into separate commits would open a window where the bump targets
    // `config-N/.credentials.json` but the symlink resolves to
    // `identities/<UUID>/credentials.json` — a silent an internal ticket-class regression.
    let target_identity_paths = account_to_identity_paths(base_dir, target);

    // Determine the actual credentials file the symlink will point at
    // after the repoint.  This is the path `bump_mtime_above` MUST
    // operate on (spec 01 §1.4: CC re-stats the resolved path, not the
    // symlink itself).
    //
    // M3-7: the prior HIGH-1 fallback to `config-N/.credentials.json`
    // is retired. Phase 4's `phase4_gate_check` (renamed from the
    // prior `phase3_gate` symbol in M4-5; M3-7's R2 MED-1 strengthening
    // is preserved as check 3) refuses to start the daemon when any
    // UUID in `profiles.json::by_slot` lacks its
    // `identities/<UUID>/credentials.json` file. So by the time
    // `repoint_handle_dir` runs, every UUID-keyed slot's identity path
    // is guaranteed populated. Pure-legacy slots
    // (no UUID mapping) fall through to the `else` branch and target
    // `config-N/.credentials.json` which CC's own `claude auth login`
    // subprocess writes (M3-7 retired only csq's writers, not CC's).
    let new_creds_symlink_target = if let Some(binding) = target_binding {
        crate::accounts::identity_store::credentials_path_for(base_dir, binding.identity())
    } else if target_identity_paths.is_identity_keyed {
        // UUID-keyed slot: always target the identity path.
        target_identity_paths.credentials_path.clone()
    } else {
        // Legacy layout: no UUID → config-N/.credentials.json (CC-written).
        new_config.join(".credentials.json")
    };

    // an internal ticket observability: capture the credentials target's pre-swap
    // mtime + inode. CC's `invalidateOAuthCacheIfDiskChanged` (spec 01 §1.4)
    // fires only when `mtimeMs !== lastCredentialsMtimeMs`. If the post-swap
    // target happens to share the same mtime as the pre-swap target (e.g.
    // both refreshed in the same nanosecond, or filesystem clamps mtime
    // precision), CC will silently skip the reload and the swap appears
    // to "not take effect" until something else perturbs the file. The
    // pre/post traces below make the invariant visible at INFO level so a
    // future repro of an internal ticket produces actionable evidence.
    let pre_swap_creds_target = stat_creds_target(handle_dir);

    // an internal ticket fix: bump the new target's mtime strictly above the
    // pre-swap target's mtime BEFORE the atomic rename. This eliminates
    // the mtime-collision race window entirely — between the rename and a
    // post-rename bump, CC could stat the new target with the colliding
    // mtime and skip the reload. Pre-bumping ensures CC's first stat after
    // the rename always returns an advanced mtime, so the strict-inequality
    // check (`mtimeMs !== lastCredentialsMtimeMs`) fires on the next API
    // call. Failure here is non-fatal: log and proceed; the existing
    // `mtime_collision` warn below acts as a regression detector.
    //
    // M3-4: bump targets `new_creds_symlink_target` (identity-keyed when
    // UUID is present), NOT `config-N/.credentials.json`.  The bump target
    // MUST match the post-rename symlink target per PRIMARY METHODOLOGICAL
    // DIRECTIVE 1 (WBS line 124, an internal journal entry D3).  Using `new_creds_symlink_target`
    // here and in the symlink rebuild loop guarantees they are always in sync
    // in this commit; the SAME-COMMIT REQUIREMENT in the WBS makes splitting
    // the two a blocked operation.
    //
    // Best-effort vs daemon refresher race: the bump is NOT held under
    // the per-(Surface, AccountNum) write mutex from `AccountMutexTable`.
    // If the daemon refresher writes the identity credentials.json between
    // our `bump_mtime_above` and the post-stat read, the daemon's
    // `atomic_replace` produces a fresh-mtime inode on its own — CC's
    // reload still fires. The bump is the primary defense against the
    // collision case; the daemon's natural rename is a parallel path
    // that also advances mtime. Either path satisfies CC's invalidation.
    //
    // Spec amendment (an internal journal entry D2, extended by M3-4): Phase 3 retargets
    // the bump to `identities/<UUID>/credentials.json`, observed by EVERY
    // handle dir whose symlink resolves to that identity UUID — which may
    // span multiple slots after `csq move` (identity-scoped vs prior
    // slot-scoped). Sibling terminals on the swap target see a harmless
    // one-time reload of identical credentials. See specs/02 INV-04 §2.94
    // and the M3-8 spec amendment for the identity-scoped caveat.
    let baseline_ns = pre_swap_creds_target
        .as_ref()
        .map(|s| s.mtime_ns)
        .unwrap_or(0);
    // No `exists()` pre-check: `bump_mtime_above` returns Err on a missing
    // path, which is the correct surface for legitimate-absent cases (3P
    // slots without `.credentials.json`). Pre-`exists()` would also be a
    // TOCTOU window between the check and the open.
    match crate::platform::fs::bump_mtime_above(&new_creds_symlink_target, baseline_ns) {
        Ok(()) => {}
        Err(crate::error::PlatformError::Io(ref io))
            if io.kind() == std::io::ErrorKind::NotFound =>
        {
            // Legitimate-absent: the new slot has no `.credentials.json`
            // (3P slot using `env.ANTHROPIC_AUTH_TOKEN` instead). Silent.
        }
        Err(e) => {
            warn!(
                error = ?e,
                path = %crate::cli_deps::sanitize::redact_path(&new_creds_symlink_target),
                "pre-swap mtime bump failed; CC may skip credential reload (an internal ticket)"
            );
        }
    }

    // Atomic repoint: create temp symlink then rename over existing.
    // M3-4 heterogeneous symlink set (an internal journal entry OQ #2 Option A):
    //   `.credentials.json` → identity-keyed when UUID present (via
    //   `new_creds_symlink_target` resolved above).
    //   All other items stay at `config-N/<item>` through Phase 4.
    //
    // F2: `ACCOUNT_BOUND_ITEMS` is still repointed ONE RENAME AT A TIME —
    // this loop is NOT atomic across the whole set — but a failure
    // partway is no longer left as a mixed handle dir. Every item's
    // pre-repoint link state is snapshotted BEFORE the loop starts
    // (`snapshots`), so a failure on any item triggers a best-effort
    // restore of every item already moved back to that snapshot
    // (`rollback_repoint`). `.csq-account` is processed LAST WITHIN THIS
    // LOOP so that a failure among the symlinks (before settings.json is
    // ever touched) leaves the marker naming the account every other link
    // was ALSO on immediately before this call.
    //
    // S-H1/D-F1: `.csq-account` is NOT the true commit point for the call
    // as a whole — the settings.json commit below (see
    // `commit_prepared_handle_settings`) runs after this loop, and its
    // failure is folded into the SAME `rollback_repoint` machinery, undoing
    // `.csq-account` along with every other item. The true commit point is
    // that settings.json rename: only once it succeeds has this call
    // actually switched the account.
    let processing_order: Vec<&'static str> = ACCOUNT_BOUND_ITEMS
        .iter()
        .copied()
        .filter(|item| *item != ".csq-account")
        .chain(std::iter::once(".csq-account"))
        .collect();

    // S-H1/D-F1: prepare the new slot's settings.json content to a temp
    // file NOW, before any symlink is touched — this is a pure read+merge
    // of `claude_home`'s + the target slot's settings, so preparing it
    // early changes nothing about its content, only WHEN the (fallible)
    // write happens. A failure here fires before any mutation, so it
    // propagates as-is (nothing to roll back — see
    // `prepare_handle_settings_tmp`'s doc comment). The temp file is
    // committed into place as the LAST step of this call, after the
    // symlink rename loop below, folding that final rename into the same
    // rollback path as every other item instead of leaving it as an
    // unrollback-able `?` (the S-H1/D-F1 bug: a settings-materialization
    // failure AFTER every `ACCOUNT_BOUND_ITEMS` symlink — including
    // `.csq-account` — had already moved was reported with
    // `repoint_rolled_back() == None`, which callers combine via
    // `.unwrap_or(true)` and read as "fully rolled back", even though the
    // account had in fact fully switched).
    let uuid_settings_swap = target_binding
        .map(|binding| settings_path_for(base_dir, binding.identity()))
        .or_else(|| {
            crate::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get())
                .map(|uuid| settings_path_for(base_dir, uuid))
        });
    let (settings_tmp, layer_rec) = prepare_handle_settings(
        handle_dir,
        claude_home,
        &new_config,
        uuid_settings_swap.as_deref(),
    )?;

    // S7: refuse up front, before ANY mutation, if any `ACCOUNT_BOUND_ITEMS`
    // slot is occupied by a REAL file or directory rather than a symlink.
    // The rename loop below renames a freshly-created symlink OVER
    // `link_path` unconditionally (`std::fs::rename(&tmp_path, &link_path)`)
    // — POSIX rename silently replaces whatever is at the destination, so
    // without this guard a real file would be clobbered with no warning.
    //
    // K3: this fires BEFORE any mutation, so it uses the dedicated
    // `RepointRefusedRealFile` variant rather than `Corrupt` — a generic
    // `Corrupt` reads to the caller identically to every other refusal,
    // and the caller's operator line loops "run `csq swap N` again" forever
    // on this one (retrying does not remove the blocking file). On this
    // path `settings_tmp` was prepared but never committed — remove it so
    // no stray temp file survives a refusal.
    for item in &processing_order {
        let link_path = handle_dir.join(item);
        if let Ok(meta) = link_path.symlink_metadata() {
            if !meta.file_type().is_symlink() {
                let _ = std::fs::remove_file(&settings_tmp);
                return Err(CredentialError::RepointRefusedRealFile { item });
            }
        }
    }

    // Re-materialize .claude.json for the new slot. This is the bug fix
    // for alpha.10: `csq swap` used to repoint credential symlinks but
    // leave `.claude.json` as the stale copy from whichever slot the
    // handle dir was created with. CC reads account-scoped caches from
    // .claude.json — `oauthAccount`, `overageCreditGrantCache`,
    // `cachedExtraUsageDisabledReason`, `cachedGrowthBookFeatures`,
    // `additionalModelCostsCache`, `clientDataCache`, etc. — and
    // displays "you've hit your limit" from those caches without
    // necessarily making a fresh API call. Swapping without refreshing
    // .claude.json meant CC continued reporting the pre-swap account's
    // state for the remainder of the session.
    //
    // Session-scoped project entries from the old handle dir (CC writes
    // them during the session) are preserved so `--resume` and per-CWD
    // state survive the swap. See `rebuild_claude_json_for_swap` for
    // the atomic write + projects merge.
    // Compare the full account/org/email tuple; equal email alone is not
    // idempotence. Capture the exact native bytes before reconstruction and
    // refuse if a concurrent native writer changes them before publication.
    let staged_native: Option<StagedNativeMetadata> =
        if let Some((binding, capture)) = target_binding.zip(native_capture) {
            let staged_native = match binding.context() {
                crate::accounts::anthropic_identity::StoredAnthropicContext::Known(context) => {
                    let source = capture.source_binding.as_ref().and_then(|binding| {
                        match binding.context() {
                    crate::accounts::anthropic_identity::StoredAnthropicContext::Known(context) => {
                        Some(context)
                    }
                    crate::accounts::anthropic_identity::StoredAnthropicContext::LegacyUnknown => {
                        None
                    }
                }
                    });
                    stage_claude_json_for_swap_context_captured(
                        &new_config,
                        handle_dir,
                        context,
                        source,
                        capture.raw.as_deref(),
                        capture.source_binding.as_ref(),
                    )
                }
                crate::accounts::anthropic_identity::StoredAnthropicContext::LegacyUnknown => {
                    stage_claude_json_for_swap_legacy_context(
                        handle_dir,
                        binding,
                        capture.source_binding.as_ref(),
                        capture.raw.as_deref(),
                    )
                }
            };
            Some(staged_native.map_err(|failure| {
                let _ = std::fs::remove_file(&settings_tmp);
                warn!(
                    error_kind = "swap_native_metadata_not_reconciled",
                    reason = failure.fixed_tag(),
                    "swap native identity metadata reconciliation failed before any mutation"
                );
                CredentialError::Corrupt {
                    path: handle_dir.join(".claude.json"),
                    reason: format!(
                        "swap_native_metadata_not_reconciled: {}",
                        failure.fixed_tag()
                    ),
                }
            })?)
        } else {
            None
        };

    let snapshots: Vec<(&'static str, PreRepointLinkState)> = processing_order
        .iter()
        .map(|item| (*item, snapshot_link_state(handle_dir, item)))
        .collect();

    let mut repointed: Vec<&'static str> = Vec::with_capacity(processing_order.len());
    for (idx, item) in processing_order.iter().enumerate() {
        let new_target = if *item == ".credentials.json" {
            // Identity-keyed (or fallback) path computed above.
            new_creds_symlink_target.clone()
        } else {
            new_config.join(item)
        };
        let link_path = handle_dir.join(item);
        let tmp_path = handle_dir.join(format!("{item}.swap-tmp"));

        // Only repoint if the target exists in the new config dir
        if !new_target.exists() && new_target.symlink_metadata().is_err() {
            // F2(c): the new config lacks this item, so the old link is
            // DELETED rather than repointed — that is a mutation this
            // call made, not a no-op, so it MUST be recorded in
            // `repointed` or a later failure's rollback would silently
            // skip restoring it.
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
            }
            repointed.push(item);
            continue;
        }

        // Create new symlink at temp path
        if tmp_path.symlink_metadata().is_ok() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        if let Err(e) = create_symlink(&new_target, &tmp_path) {
            // The current item's own tmp file is not in `repointed` (it
            // never successfully moved), so `rollback_repoint` will not
            // clean it up — remove it here so no `*.swap-tmp` survives.
            let _ = std::fs::remove_file(&tmp_path);
            // `settings_tmp` was prepared but never committed at this
            // point (the commit happens after this whole loop) — it is
            // not one of `snapshots`/`repointed`, so `rollback_repoint`
            // does not and should not touch it; clean it up directly.
            let _ = std::fs::remove_file(&settings_tmp);
            let rolled_back = rollback_repoint(handle_dir, &snapshots, &repointed);
            warn!(
                item,
                repointed = ?repointed,
                account = %target,
                rolled_back,
                "repoint_handle_dir: failed creating the temp symlink — attempted a best-effort restore of every already-moved item to its pre-repoint state"
            );
            // S2: carry the rollback's own outcome so a caller can combine
            // it with its own disk-state check rather than trust the disk
            // check alone.
            return Err(CredentialError::RepointFailed {
                path: tmp_path.clone(),
                source: e,
                rolled_back,
            });
        }

        // Atomic rename over existing symlink — or the test-only fault
        // seam simulating exactly this failure on the `k`-th item.
        let rename_result = if repoint_fail_at_rename_index_for_test() == Some(idx) {
            Err(std::io::Error::other(
                "injected test failure (repoint_fail_at_rename_index_for_test)",
            ))
        } else {
            std::fs::rename(&tmp_path, &link_path)
        };
        if let Err(e) = rename_result {
            // The current item's tmp symlink is left behind by a failed
            // rename (real or injected); `rollback_repoint` only cleans
            // up items already recorded in `repointed`, which this one
            // is not.
            let _ = std::fs::remove_file(&tmp_path);
            // See the temp-symlink-create failure arm above: `settings_tmp`
            // is not tracked by `snapshots`/`repointed` and must be cleaned
            // up directly.
            let _ = std::fs::remove_file(&settings_tmp);
            let rolled_back = rollback_repoint(handle_dir, &snapshots, &repointed);
            warn!(
                item,
                repointed = ?repointed,
                account = %target,
                rolled_back,
                "repoint_handle_dir: failed renaming the temp symlink into place — attempted a best-effort restore of every already-moved item to its pre-repoint state"
            );
            // S2: see the temp-symlink-create failure arm above.
            return Err(CredentialError::RepointFailed {
                path: link_path.clone(),
                source: e,
                rolled_back,
            });
        }

        repointed.push(item);
        debug!(item, account = %target, "repointed symlink");
    }

    #[cfg(all(test, unix))]
    run_repoint_after_loop_hook_for_test(handle_dir);

    // Publish the staged `.claude.json` (built and written to a tmp file
    // BEFORE the rename loop). The compare-and-replace runs here, inside the
    // rollback-tracked set: a failure restores every moved link and reports
    // `RepointFailed { rolled_back }`, never a bare error after the account
    // already switched (R2 NEW-1/N2).
    let prior_native: Option<Option<String>> = staged_native
        .as_ref()
        .map(|staged| staged.expected().map(str::to_owned));
    let mut published_native = None;
    if let Some(staged) = staged_native {
        match staged.commit() {
            Ok(published) => published_native = Some(published),
            Err(failure) => {
                let _ = std::fs::remove_file(&settings_tmp);
                let rolled_back = rollback_repoint(handle_dir, &snapshots, &repointed);
                warn!(
                    error_kind = "swap_native_metadata_not_reconciled",
                    reason = failure.fixed_tag(),
                    repointed = ?repointed,
                    account = %target,
                    rolled_back,
                    "repoint_handle_dir: failed publishing the staged .claude.json — attempted a best-effort restore of every already-moved item to its pre-repoint state"
                );
                return Err(CredentialError::RepointFailed {
                    path: handle_dir.join(".claude.json"),
                    source: std::io::Error::other(format!(
                        "swap_native_metadata_not_reconciled: {}",
                        failure.fixed_tag()
                    )),
                    rolled_back,
                });
            }
        }
    }

    // Commit settings.json for the new slot so the user's global
    // customization is preserved and any 3P env block from the new
    // config-<target>/settings.json overlays correctly. `settings_tmp` was
    // PREPARED before the rename loop above (see the S-H1/D-F1 comment at
    // its call site); this is the single rename that commits it into
    // place. It is the last fallible step that can still be folded into the
    // rollback below (the `.claude.json` publish ran just before it and is
    // undone by `restore_native_metadata` if this commit fails). atomic_replace
    // keeps the swap semantics of INV-04: CC sees either the pre-swap or
    // post-swap file, never a half-written one.
    //
    // S-H1/D-F1: because every `ACCOUNT_BOUND_ITEMS` symlink — including
    // `.csq-account` — has already been renamed by the loop above, a
    // failure HERE is exactly as consequential as a failure inside that
    // loop: the account has already switched. This is why the failure
    // path below folds into the SAME `rollback_repoint` + `RepointFailed`
    // shape as every rename-loop failure, rather than propagating a bare
    // `CredentialError::Corrupt`/`Io` (whose `repoint_rolled_back()` is
    // `None` — S-LOW-4: this comment used to claim `daemon::auto_rotate`
    // combines that via `.unwrap_or(true)`; that call site was deleted in
    // the v5 rewrite (`error.rs::repoint_rolled_back`'s own doc comment
    // records it), so the CURRENT hazard is only that a HYPOTHETICAL
    // caller combining `None` via `.unwrap_or(true)` would read "fully
    // rolled back" while the account had in fact fully switched — the
    // shape this fold prevents from ever being constructible).
    let settings_path = handle_dir.join("settings.json");
    if let Err(e) = commit_prepared_handle_settings(&settings_tmp, &settings_path) {
        let native_restored = prior_native
            .as_ref()
            .zip(published_native.as_deref())
            .is_none_or(|(prior, published)| {
                restore_native_metadata(handle_dir, prior.as_deref(), published)
            });
        let rolled_back = rollback_repoint(handle_dir, &snapshots, &repointed) && native_restored;
        warn!(
            item = "settings.json",
            repointed = ?repointed,
            account = %target,
            rolled_back,
            "repoint_handle_dir: failed committing the prepared settings.json — attempted a best-effort restore of every already-moved item to its pre-repoint state"
        );
        return Err(CredentialError::RepointFailed {
            path: settings_path,
            source: e,
            rolled_back,
        });
    }
    write_layer_record(handle_dir, &layer_rec);

    // an internal ticket observability: capture post-swap target stat and emit at
    // INFO so `CSQ_LOG=info csq swap N` exposes the mtime/inode that CC's
    // next stat will resolve. See pre_swap_creds_target capture above.
    let post_swap_creds_target = stat_creds_target(handle_dir);
    info!(
        account = %target,
        handle = %handle_dir.display(),
        pre_mtime_ns = pre_swap_creds_target.as_ref().map(|s| s.mtime_ns),
        pre_ino = pre_swap_creds_target.as_ref().map(|s| s.ino),
        post_mtime_ns = post_swap_creds_target.as_ref().map(|s| s.mtime_ns),
        post_ino = post_swap_creds_target.as_ref().map(|s| s.ino),
        mtime_changed = mtime_changed(&pre_swap_creds_target, &post_swap_creds_target),
        "handle dir repointed"
    );
    // Default csq log level is `warn`, so the INFO trace above is invisible
    // to operators who haven't opted into `CSQ_LOG=info`. Emit a WARN only
    // on the exact an internal ticket failure mode (both stats succeeded + mtimes equal)
    // so the bug surfaces in default-log sessions and the next manifestation
    // can be diagnosed without first asking the operator to opt back in.
    // Spec 02 INV-04 §2.94 already acknowledges this caveat.
    if mtime_collision(&pre_swap_creds_target, &post_swap_creds_target) {
        warn!(
            account = %target,
            handle = %handle_dir.display(),
            post_mtime_ns = post_swap_creds_target.as_ref().map(|s| s.mtime_ns),
            post_ino = post_swap_creds_target.as_ref().map(|s| s.ino),
            "swap repointed but credential mtime unchanged — CC may skip reload (an internal ticket)"
        );
    }
    Ok(())
}

/// Filesystem identity of the `.credentials.json` symlink target — what
/// CC's `fs.stat()` resolves to. Captured pre/post repoint to expose the
/// invariant that drives CC's mtime-based cache invalidation (spec 01 §1.4).
#[derive(Debug, Clone, Copy)]
struct CredsTargetStat {
    mtime_ns: i128,
    ino: u64,
}

/// Stats `.credentials.json` following symlinks. Returns None if absent
/// or unstattable — the caller logs `None` rather than failing the swap,
/// since observability MUST NOT alter swap semantics.
fn stat_creds_target(handle_dir: &Path) -> Option<CredsTargetStat> {
    let path = handle_dir.join(".credentials.json");
    let meta = std::fs::metadata(&path).ok()?;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(-1);
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let ino = 0u64;
    Some(CredsTargetStat { mtime_ns, ino })
}

/// True when post-swap target stat differs from pre-swap such that CC's
/// `mtimeMs !== lastCredentialsMtimeMs` check (spec 01 §1.4) will reload.
/// The contract requires the mtime to differ, NOT the inode — CC ignores
/// inode. None on either side means we couldn't read the stat; conservative
/// default is False (caller surfaces this so a future bug repro shows it).
fn mtime_changed(pre: &Option<CredsTargetStat>, post: &Option<CredsTargetStat>) -> bool {
    match (pre, post) {
        (Some(p), Some(q)) => p.mtime_ns != q.mtime_ns,
        _ => false,
    }
}

/// True ONLY when both stats succeeded AND mtimes are identical — the exact
/// an internal ticket hypothesised failure mode where CC's `mtimeMs !== lastCredentialsMtimeMs`
/// check (spec 01 §1.4) silently skips the credential reload. Distinguishes
/// the bug condition from stat-read failures (None on either side), which
/// the caller surfaces separately. The complement of [`mtime_changed`]
/// excluding the None cases.
fn mtime_collision(pre: &Option<CredsTargetStat>, post: &Option<CredsTargetStat>) -> bool {
    match (pre, post) {
        (Some(p), Some(q)) => p.mtime_ns == q.mtime_ns,
        _ => false,
    }
}

/// The error a Codex create or repoint returns when the stale hook approvals of a previous
/// terminal could not be cleared from the slot the terminal would run on. Names the cause
/// class (never a path or file content beyond the slot config path in the error).
fn hook_trust_refusal(config_dir: &Path, e: &std::io::Error) -> CredentialError {
    CredentialError::Io {
        path: config_dir.join("config.toml"),
        source: std::io::Error::new(
            e.kind(),
            format!(
                "could not clear a previous terminal's hook approvals from this slot's config.toml ({}); refusing to launch (run `csq doctor`)",
                crate::providers::codex::surface::describe_slot_error(e)
            ),
        ),
    }
}

/// Atomically repoints the Codex ACCOUNT-IDENTITY symlinks in a Codex
/// handle dir to point at a new `config-<target>` directory.
///
/// Counterpart to [`repoint_handle_dir`] for the Codex surface. This
/// function repoints only the identity-bound triple:
/// - `.csq-account` → `config-<N>/.csq-account`
/// - `auth.json` → `credentials/codex-<N>.json` (canonical-direct)
/// - `config.toml` → `config-<N>/config.toml`
///
/// It deliberately does NOT repoint the persistent conversation-state
/// symlinks (`sessions` → `config-<N>/codex-sessions`, `history.jsonl` →
/// `config-<N>/codex-history.jsonl`, `session_index.jsonl`, and the
/// schema-versioned sqlite state) — see the comment at the call site
/// where `codex_shared_pairs` used to be repointed here for the C1
/// rationale (a live process's path-based reopen of one of those items
/// would otherwise silently continue an in-progress conversation into
/// the TARGET slot's directory, splitting one thread's on-disk record
/// across two accounts). Only `same_surface_codex` calls this function,
/// and only when the source and target slots' `tokens.account_id`
/// already MATCH, so leaving the persistent store bound to the source
/// slot for the remaining life of the running process carries no
/// cross-identity risk.
///
/// This function's caller, `same_surface_codex`, is reached only in the
/// `WhenSameAccountId` in-flight-adoption cell (spec 02 §2.3.3): codex-cli's
/// own auth-reload guard silently ignores an `auth.json` change whose
/// `tokens.account_id` differs from the running session's — verified live
/// (spec 02 §2.3.3, corrected 2026-09-13) — so this repoint changes which
/// slot the handle dir's IDENTITY items point at without any guarantee the
/// running process notices before its next restart. It replaces the prior
/// `exec`-replace path that silently dropped the user's conversation (M10,
/// an internal journal entry).
///
/// # Errors
///
/// - If the handle dir is not a `term-<pid>` dir
/// - If the handle dir is not Codex-shaped (missing `auth.json` symlink)
/// - If `config-<target>` doesn't exist
/// - If the new slot is missing `.csq-account` (mixed-state guard)
/// - If `credentials/codex-<target>.json` doesn't exist
/// - On any I/O failure during repoint
pub fn repoint_handle_dir_codex(
    base_dir: &Path,
    handle_dir: &Path,
    target: AccountNum,
) -> Result<(), CredentialError> {
    let dir_name = handle_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if !dir_name.starts_with("term-") {
        return Err(CredentialError::Corrupt {
            path: handle_dir.to_path_buf(),
            reason: format!(
                "expected term-<pid> handle dir, got {dir_name}. \
                 Run `csq run {target}` to launch with handle-dir isolation."
            ),
        });
    }

    // Surface guard (PR-C9b L-CDX-1): refuse to repoint a non-Codex handle dir.
    // Codex-shape requires BOTH `auth.json` AND `config.toml` to be present
    // AND each must be a symlink — not a regular file or directory. The
    // dual-marker check matches the inverse guard in `repoint_handle_dir`
    // (which scans both items); the is_symlink check rejects planted
    // regular files that would otherwise pass `symlink_metadata().is_ok()`
    // and trip the rename loop into overwriting attacker-controlled state.
    for codex_item in ["auth.json", "config.toml"] {
        let probe = handle_dir.join(codex_item);
        let is_symlink = probe
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !is_symlink {
            return Err(CredentialError::Corrupt {
                path: handle_dir.to_path_buf(),
                reason: format!(
                    "handle dir is not Codex-shaped: '{codex_item}' is missing or \
                     not a symlink. `repoint_handle_dir_codex` only operates on \
                     Codex handle dirs (spec 07 §7.2.2 symlink set); for ClaudeCode \
                     use `repoint_handle_dir`."
                ),
            });
        }
    }

    let new_config = base_dir.join(format!("config-{}", target));
    if !new_config.is_dir() {
        return Err(CredentialError::Corrupt {
            path: new_config,
            reason: format!("config-{target} does not exist"),
        });
    }

    // Pre-flight mirror of `repoint_handle_dir`'s VP-final F3: the
    // `.csq-account` marker is structurally required in the target slot.
    // Without it csq cannot determine the post-swap account and the
    // daemon's auto-rotate / sweep loops would skip the handle dir on
    // every tick. Refuse before any rename so the handle dir cannot end
    // up half-pointed at the old slot.
    let csq_account_target = new_config.join(".csq-account");
    if !csq_account_target.exists() && csq_account_target.symlink_metadata().is_err() {
        return Err(CredentialError::Corrupt {
            path: csq_account_target,
            reason: format!(
                "repoint target missing .csq-account in {} — repoint aborted to prevent \
                 mixed-state handle dir",
                new_config.display()
            ),
        });
    }

    // The Codex credential may live at EITHER the identity-keyed path
    // (`identities/<UUID>/credentials-codex.json`, post-M4-12) or the legacy
    // numeric mirror (`credentials/codex-<N>.json`, pre-M4-12). Both are valid;
    // at least one must exist. This mirrors the already-swept guard in
    // `create_handle_dir_codex_named` ("Task 5") — this repoint guard was left
    // behind by that migration and hard-required the legacy mirror, so a slot
    // provisioned on a current build (identity.json provider=codex +
    // credentials-codex.json, no legacy mirror) was refused with "has not
    // completed login" while the daemon polled it successfully.
    // `guard-reader-writer-parity.md` MUST-1/MUST-5: a guard MUST recognise
    // every representation its writers produce, and a content migration MUST
    // sweep every reader.
    //
    // The consumer below (`auth_symlink_target`) already resolves both forms;
    // only this precondition was narrow. `identity_codex_path` is hoisted here
    // so the guard and the symlink target are computed from ONE value and
    // cannot disagree (an internal journal entry WBS line 124 keeps them unsplit).
    let canonical_cred = base_dir
        .join("credentials")
        .join(format!("codex-{target}.json"));
    let identity_codex_path =
        crate::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get()).map(|uuid| {
            crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)
        });
    let identity_cred_exists = identity_codex_path
        .as_ref()
        .map(|p| p.exists() || p.symlink_metadata().is_ok())
        .unwrap_or(false);
    if !identity_cred_exists && !canonical_cred.exists() {
        // Name the UUID-keyed path when a mapping exists, so the operator sees
        // the authoritative post-M4-12 location rather than the retired mirror.
        let error_path = identity_codex_path
            .clone()
            .unwrap_or_else(|| canonical_cred.clone());
        return Err(CredentialError::Corrupt {
            path: error_path,
            reason: format!(
                "neither the identity-keyed nor the legacy Codex credential exists \
                 for slot {target} — Codex slot {target} has not completed login. \
                 Run `csq login {target} --provider codex` first."
            ),
        });
    }

    crate::providers::codex::trust::sync_before_handle(base_dir, target);
    // Per-handle flock (mirrors ClaudeCode VP-final F4) so concurrent
    // swaps cannot interleave renames into a split state. The lock
    // file lives inside the handle dir so it is reaped with the dir.
    //
    // Distinct from the A4a `.swap-lock` (hyphen) keychain guard and
    // canonicalized via `repoint_lock_path` for the same reasons as
    // `repoint_handle_dir` (an internal ticket): codex swaps take no outer A4a guard
    // (fresh-dir / keychain-absent), so this `.swap.lock` (dot) IS the sole
    // rename serializer for concurrent codex repoints — canonicalizing the dir
    // keeps that serialization sound even when the caller passes a raw,
    // symlink-containing path.
    let lock_path = repoint_lock_path(handle_dir);
    let _swap_guard =
        crate::platform::lock::lock_file(&lock_path).map_err(|e| CredentialError::Corrupt {
            path: lock_path.clone(),
            reason: format!("repoint lock acquisition failed: {e}"),
        })?;

    // Hook approvals, BEFORE any link moves: a handle with no purge marker (a reused PID, or a
    // create that skipped a slot) must not run on a slot whose predecessor keys could not be
    // cleared, so a failed purge of the target slot refuses the repoint and the handle stays
    // on its old slot (same error text as a create refusal). A marked handle is the owner's
    // own: its carry failure is logged and never fails the swap.
    super::codex_hook_trust::carry_hook_trust_for_repoint(
        base_dir,
        handle_dir,
        target,
        codex_global_hooks_path().as_deref(),
    )
    .map_err(|e| {
        warn!(
            error_kind = "codex_hook_trust_launch_refused",
            io_kind = ?e.kind(),
            "refusing to repoint the Codex handle: stale hook approvals could not be cleared"
        );
        hook_trust_refusal(&new_config, &e)
    })?;

    // M3-4: Resolve the identity-keyed auth path for the Codex surface.
    //
    // `credentials_codex_path_for` returns `identities/<UUID>/credentials-codex.json`.
    //
    // CORRECTED (the M3-3-era text here said this file "is NEVER written by any
    // current code path", that `exists()` was expected to be false in production,
    // and that the `credentials/codex-<N>.json` fallback was "the PRODUCTION PATH
    // for Phase 3" — all three are false against the current tree). The UUID file
    // IS written: `credentials::file::save_canonical_for`'s `Surface::Codex` arm
    // calls `save_codex_canonical_for_uuid`, reached from the Codex login paths
    // (`providers::codex::login`, `providers::codex::desktop_login`) and the
    // daemon refresh path (`refresh::check`).
    //
    // So the branch order below is now: identity-keyed path FIRST as the normal
    // case; the legacy numeric mirror is the FALLBACK for a pre-mapping (legacy)
    // layout or a partially-seeded identity, not the expected path. A slot
    // provisioned on a current build has the UUID file and NO legacy mirror —
    // see the sibling guard comment above, which `guard-reader-writer-parity.md`
    // MUST-5 already swept for exactly this reason.
    //
    // PRIMARY METHODOLOGICAL DIRECTIVE 1 applies here too (an internal journal entry WBS line 124):
    // the bump target MUST match `auth_symlink_target` — both are computed from the
    // same `identity_codex_path` variable in this commit, never split.
    // (`identity_codex_path` is computed once, above the precondition guard.)

    let auth_symlink_target = match identity_codex_path.as_ref() {
        Some(p) if p.exists() || p.symlink_metadata().is_ok() => {
            // Identity-keyed credentials-codex.json is present — use it.
            p.clone()
        }
        Some(p) => {
            // UUID resolves but file absent (HIGH-2 Partial-Pass-0 state).
            // Fall back to legacy canonical.  Log at WARN.
            warn!(
                account = %target,
                identity_path = %p.display(),
                "M3-4 codex repoint: identity credentials-codex.json absent — \
                 falling back to legacy credentials/codex-N.json"
            );
            canonical_cred.clone()
        }
        None => {
            // Legacy layout: no UUID → use legacy canonical directly.
            canonical_cred.clone()
        }
    };

    // Codex symlink set per spec 07 §7.2.2. Sources are either
    // `identities/<UUID>/credentials-codex.json` (M3-4 retarget) or
    // the legacy `credentials/codex-<N>.json`, followed by config-<N>
    // items for the remaining slots.
    //
    // PR-C9b M-CDX-1: order matters under partial-failure. Credential
    // (`auth.json`) MUST be rewritten BEFORE the marker (`.csq-account`).
    // If a mid-loop rename fails (ENOSPC, EROFS, transient I/O), the
    // marker must not flip to slot N+1 while `auth.json` still resolves
    // to slot N's tokens — that mismatch causes silent quota-attribution
    // drift in the daemon (which polls `/api/oauth/usage` keyed on the
    // marker) and trips the F3 `.csq-account` mismatch guard on the next
    // swap. ClaudeCode's `ACCOUNT_BOUND_ITEMS` follows the same
    // invariant: `.credentials.json` first, `.csq-account` second.
    // ACCOUNT-BOUND only, and the auth.json-before-.csq-account ordering above is
    // load-bearing. Shared state is repointed separately, after these.
    let codex_links: &[(&str, PathBuf)] = &[
        ("auth.json", auth_symlink_target.clone()),
        (".csq-account", new_config.join(".csq-account")),
        ("config.toml", new_config.join("config.toml")),
    ];

    // an internal ticket fix (Codex parallel, M3-4 retarget): bump the new auth.json
    // target's mtime strictly above the pre-swap target's mtime BEFORE the
    // atomic rename.  codex-cli re-reads auth.json before each API call (spec
    // 07 §7.5); an mtime collision would cause the same silent-skip bug as an internal ticket.
    // Pre-bumping is defensive.  Failure is non-fatal: the swap proceeds.
    //
    // PRIMARY METHODOLOGICAL DIRECTIVE 1: bump targets `auth_symlink_target`
    // (the identity-keyed path or fallback), NOT the raw canonical path.
    // This guarantees the mtime bump and the symlink target are always in sync.
    let pre_swap_codex_auth_mtime = std::fs::metadata(handle_dir.join("auth.json"))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    if let Err(e) =
        crate::platform::fs::bump_mtime_above(&auth_symlink_target, pre_swap_codex_auth_mtime)
    {
        warn!(
            error = ?e,
            path = %auth_symlink_target.display(),
            "pre-swap codex auth.json mtime bump failed; codex-cli may skip credential reload (an internal ticket)"
        );
    }

    for (name, new_target) in codex_links {
        let link_path = handle_dir.join(name);
        let tmp_path = handle_dir.join(format!("{name}.swap-tmp"));

        // `codex-sessions/` and `codex-history.jsonl` may legitimately
        // be absent in the new slot if the user has never used codex
        // on that account — codex-cli creates them lazily. Mirror
        // create_handle_dir_codex: skip the symlink AND remove any
        // existing one so we do not leave a dangling-link orphan
        // pointed at the old slot.
        if !new_target.exists() && new_target.symlink_metadata().is_err() {
            if link_path.symlink_metadata().is_ok() {
                remove_file_logged(&link_path, "codex_repoint_stale_link_remove_failed");
            }
            continue;
        }

        // Stage at temp path + atomic rename-over the live link
        // (matches ClaudeCode INV-04 swap semantics: codex-cli sees
        // either the pre-swap or post-swap symlink, never a half-state).
        if tmp_path.symlink_metadata().is_ok() {
            remove_file_logged(&tmp_path, "codex_repoint_tmp_remove_failed");
        }
        create_symlink(new_target, &tmp_path).map_err(|e| CredentialError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp_path, &link_path).map_err(|e| CredentialError::Io {
            path: link_path.clone(),
            source: e,
        })?;
        debug!(item = name, account = %target, "repointed codex symlink");
    }

    // Keep the user-global hooks link. The account-bound items above are already
    // repointed, so a failure here is logged with a fixed tag, not returned: failing the
    // swap now would report a half-done repoint that has in fact completed.
    if let Err(e) = link_codex_global_hooks(handle_dir, codex_global_hooks_path().as_deref()) {
        warn!(
            error_kind = "codex_hooks_link_failed",
            io_kind = ?e.kind(),
            "could not refresh the codex global hooks link after repoint"
        );
    }

    // SHARED persistent conversation state (sessions/, history.jsonl,
    // session_index.jsonl, schema-versioned sqlite) is DELIBERATELY LEFT
    // pointed at the SOURCE slot here — this function repoints a LIVE handle
    // dir (`same_surface_codex`'s in-flight adopt; no exec, no tombstone,
    // `.live-pid` unchanged), and unlike ClaudeCode's `.claude.json` (a REAL
    // file explicitly re-merged at swap time via `build_scoped_claude_json`'s
    // `preserve_handle` parameter), these Codex items are raw symlinks with NO
    // reconciliation step. A still-running process that reopens one of these
    // paths (rather than holding an fd that predates the repoint — true for a
    // small JSONL log updated open/append/close per turn) would otherwise
    // silently continue an in-progress conversation into the TARGET slot's
    // directory, splitting one thread's on-disk record across two accounts
    // (C1: "an account-A codex thread's history promotes into account-B's
    // config-<N>" — reproduced in
    // `repoint_handle_dir_codex_in_flight_does_not_split_live_conversation_across_accounts`).
    //
    // This is safe to leave behind: `same_surface_codex` is reached only when
    // the source and target slots' `tokens.account_id` MATCH (the real
    // upstream account is identical), so there is no cross-identity leak in
    // leaving the persistent store bound to whichever slot the process
    // started on — a future FRESH handle dir (a new `csq run` / exec-replace
    // swap) binds sessions/history/etc. to its own target slot from scratch
    // via `create_handle_dir_codex`, which is unaffected by this function.

    // an internal ticket observability (Codex parallel): post-swap mtime check mirrors
    // the ClaudeCode regression detector in `repoint_handle_dir`. If the
    // pre-bump failed (e.g. 0o400 permission with O_WRONLY — fixed by using
    // O_RDONLY in `bump_mtime_above`) and both the pre- and post-swap auth.json
    // resolve to the same mtime, emit a WARN so the bug surfaces in
    // default-log sessions without requiring `CSQ_LOG=info`.
    let post_swap_codex_auth_mtime = std::fs::metadata(handle_dir.join("auth.json"))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128);
    // pre_swap captured as i128 (0 on failure); post_swap is Option<i128>.
    // Collision: both reads succeeded AND mtimes are identical.
    if let Some(post_ns) = post_swap_codex_auth_mtime {
        if pre_swap_codex_auth_mtime != 0 && post_ns == pre_swap_codex_auth_mtime {
            warn!(
                account = %target,
                handle = %handle_dir.display(),
                post_mtime_ns = post_ns,
                "codex swap repointed but auth.json mtime unchanged — \
                 codex-cli may skip credential reload (an internal ticket)"
            );
        }
    }

    info!(
        account = %target,
        handle = %handle_dir.display(),
        surface = "codex",
        "codex handle dir repointed"
    );
    Ok(())
}

/// Builds a `.claude.json` for `handle_dir` from `<config_dir>/.claude.json`
/// with the `projects` map scoped to the current working directory.
///
/// CC uses `projects` in `.claude.json` to track per-project settings AND
/// to enumerate resumable sessions. If we copy the full map, `--resume`
/// shows sessions from every directory this account was ever used in.
/// If we strip it entirely, CC thinks there are no projects. The middle
/// ground: keep entries in the CWD scope, and the exact native workspace's
/// already-persisted trust flag without its unrelated resume state.
///
/// On swap (`preserve_handle_projects = Some`), project entries that CC
/// has written to the handle dir's own `.claude.json` during the session
/// are overlaid on top of the new slot's projects. This preserves
/// session-scoped state like the `--resume` list and per-project
/// settings that CC populated while the session was running, even
/// though the rest of the file is refreshed from the new slot.
///
/// Returns the merged JSON ready to write, or `None` if the new slot's
/// source file is missing or unparseable (in which case the caller
/// should leave the existing handle-dir file alone).
fn build_scoped_claude_json(source: &Path, preserve_handle: Option<&Path>) -> Option<Value> {
    let cwd = std::env::current_dir().ok()?;
    build_scoped_claude_json_at(source, preserve_handle, &cwd)
}

fn build_scoped_claude_json_at(
    source: &Path,
    preserve_handle: Option<&Path>,
    cwd: &Path,
) -> Option<Value> {
    let content = std::fs::read_to_string(source).ok()?;
    let mut json: Value = serde_json::from_str(&content).ok()?;
    let workspace_key = super::workspace_trust::native_key(cwd).ok();
    let cwd = cwd.to_str()?;

    // Collect session-scoped project entries that CC wrote into the
    // handle dir during this session. These are newer than the entries
    // in the new source file, so they win the merge.
    let mut session_projects: serde_json::Map<String, Value> = serde_json::Map::new();
    if let Some(preserve_path) = preserve_handle {
        if let Ok(old_content) = std::fs::read_to_string(preserve_path) {
            if let Ok(Value::Object(old_obj)) = serde_json::from_str::<Value>(&old_content) {
                if let Some(Value::Object(old_projects)) = old_obj.get("projects") {
                    for (k, v) in old_projects {
                        if k == cwd || k.starts_with(&format!("{cwd}/")) {
                            session_projects.insert(k.clone(), v.clone());
                        }
                    }
                    if let Some(key) = workspace_key.as_deref() {
                        super::workspace_trust::preserve_exact_workspace_state(
                            &mut session_projects,
                            old_projects,
                            key,
                        );
                    }
                }
            }
        }
    }

    // Build the final projects map: source's CWD-scoped entries, then
    // overlay session-scoped entries from the handle dir (newer wins).
    let mut scoped = serde_json::Map::new();
    if let Some(obj) = json.as_object() {
        if let Some(Value::Object(src_projects)) = obj.get("projects") {
            for (k, v) in src_projects {
                if k == cwd || k.starts_with(&format!("{cwd}/")) {
                    scoped.insert(k.clone(), v.clone());
                }
            }
            if let Some(key) = workspace_key.as_deref() {
                super::workspace_trust::preserve_exact_workspace_state(
                    &mut scoped,
                    src_projects,
                    key,
                );
            }
        }
    }
    for (k, v) in session_projects {
        scoped.insert(k, v);
    }

    if let Some(obj) = json.as_object_mut() {
        obj.insert("projects".to_string(), Value::Object(scoped));
    }

    Some(json)
}

/// Writes the handle dir's `.claude.json` from `config_dir` at
/// handle-dir-creation time. Best-effort: if the source is missing
/// or unparseable, the handle dir simply has no `.claude.json` and
/// CC will create one on first run.
fn materialize_handle_claude_json(config_dir: &Path, handle_dir: &Path) {
    let Some(json) = build_scoped_claude_json(&config_dir.join(".claude.json"), None) else {
        return;
    };
    let dst = handle_dir.join(".claude.json");
    if let Ok(out) = serde_json::to_string_pretty(&json) {
        // Non-atomic write is fine at create time — CC isn't running yet.
        let _ = std::fs::write(&dst, out);
        debug!("materialized .claude.json (scoped projects to CWD)");
    }
}

/// Rebuilds the handle dir's `.claude.json` during a swap. Unlike
/// `materialize_handle_claude_json`, this function **atomically
/// replaces** the existing file so a concurrent CC read never sees a
/// half-written one, and it preserves any session-scoped project
/// entries that CC wrote into the handle dir during the running
/// session.
///
/// On the rare event of a missing or unparseable source
/// (`<config_dir>/.claude.json`) we leave the handle dir's file alone.
/// Wiping it would strand CC with zero state, which is strictly worse
/// than keeping the stale copy.
/// an internal ticket: reconcile the handle dir's `.claude.json` `oauthAccount.emailAddress` to the
/// authoritative identity anchor after a swap — WITHOUT clobbering a foreign-account
/// signal.
///
/// `rebuild_claude_json_for_swap` sources `oauthAccount` from
/// `config-<target>/.claude.json`, but that source can be ABSENT (the rebuild bails
/// and leaves the OLD account's stale copy) or carry no `oauthAccount`. The daemon
/// then mirrors the NEW account's token into this dir's keychain, so the custodian's
/// wrong-account gate (`daemon::custodian::candidate_account_matches`) sees the NEW
/// token paired with an OLD/absent email → false-refuses the adoption until CC
/// eventually rewrites `.claude.json` (an internal journal entry FD1 / cc-keychain an internal journal entry H2).
///
/// `identity_email` is the SAME `identities/<UUID>/identity.json` value the gate uses
/// as its anchor, so writing it here makes the local signal consistent with the
/// binding on the very next tick — no wait, no false-refuse.
///
/// ## The foreign-signal safety gate (redteam R1 deep-analyst M-2)
///
/// The gate's whole invariant is `.claude.json` email == the keychain token's owner
/// (CC writes both together on `/login`). Blindly forcing the anchor would DECOUPLE
/// them: in the microsecond window between the rebuild's write and this read, a
/// concurrent CC in-session `/login <other>` writes keychain=OTHER + `.claude.json`
/// =OTHER. Overwriting that `.claude.json` back to the swap target would make the gate
/// match (target==target) while the keychain holds OTHER's LIVE token → the custodian
/// adopts a FOREIGN token into the target's account-global store (the exact
/// catastrophe the gate exists to prevent).
///
/// So this only writes when the current email is SAFE to overwrite:
/// - ABSENT / empty — no signal to lose (a concurrent CC `/login` would have written
///   a PRESENT email, so absent ⇒ no race), OR
/// - equal to `pre_swap_email` — the stale copy of the account we swapped AWAY from,
///   whose keychain token the swap already CLEARED (so it cannot be adopted).
///
/// A present email that is NEITHER the anchor NOR `pre_swap_email` was written by
/// something else (a concurrent foreign `/login`) → SKIP, leaving the gate fail-closed.
/// `pre_swap_email` is captured from the handle dir BEFORE the rebuild.
///
/// Residual (bounded by an unfixable blocker): if a concurrent `/login` targets the
/// SAME account the dir was on pre-swap (so `current == pre_swap_email`), the gate
/// cannot distinguish the fresh concurrent write from the stale copy and this may
/// overwrite it. Reaching it needs a triple-coincidence — the dir was on X pre-swap,
/// is swapped away from X, AND is concurrently re-logged into X inside the
/// rebuild→reconcile window — and it self-heals on CC's next `.claude.json` write.
/// Fully closing it would require a keychain-token OWNER signal, which does not exist
/// (the `sk-ant-oat01-` token is account-anonymous — the same fundamental limit the
/// wrong-account gate itself has, an internal journal entry). Not closable in-session.
///
/// - Surgical: overrides ONLY `oauthAccount.emailAddress`, preserving every other
///   field (esp. the CWD-scoped `projects` map the rebuild just merged).
/// - Idempotent: no write when the field already matches (ASCII-case-insensitive,
///   trimmed) — the common case where the rebuild sourced the right email.
/// - Best-effort + non-fatal: any read/parse/write failure leaves the pre-existing
///   fail-closed + self-heal path intact, so a reconcile failure never aborts the swap.
/// - Atomic (CC may be running) via the full `security.md` §5a pipeline —
///   `write` → `secure_file` (0600) → `atomic_replace`, tmp removed on every failure
///   branch — because `.claude.json` carries the account email = PII. `rebuild_
///   claude_json_for_swap` uses the identical pipeline. Serializes COMPACT
///   (`to_string`, not `to_string_pretty`) so reconciling a near-`MAX_CLAUDE_JSON_BYTES`
///   file can never inflate it past the gate's own read ceiling and re-break the gate
///   it fixes (redteam R1 deep-analyst L-2).
/// - Absent / oversized / unparseable / non-object `.claude.json`, or an empty
///   `identity_email` → skip (never clobber a file we cannot safely round-trip). A
///   still-un-round-trippable handle file after the rebuild (config-target absent AND
///   the retained copy itself corrupt) therefore keeps the pre-existing tick-based
///   self-heal — the AC's "no wait" guarantee is best-effort for that narrow sub-case.
#[derive(Debug, PartialEq, Eq)]
enum NativeMetadataReconcileFailure {
    ReadUnavailable,
    ContextChanged,
    UntrustedContext,
    WriteFailed,
}
const ACCOUNT_CACHE_KEYS: &[&str] = &[
    "overageCreditGrantCache",
    "cachedExtraUsageDisabledReason",
    "cachedGrowthBookFeatures",
    "additionalModelCostsCache",
    "clientDataCache",
];
impl NativeMetadataReconcileFailure {
    fn fixed_tag(&self) -> &'static str {
        match self {
            Self::ReadUnavailable => "native_read_unavailable",
            Self::ContextChanged => "native_context_changed",
            Self::UntrustedContext => "native_context_untrusted",
            Self::WriteFailed => "native_write_failed",
        }
    }
}
#[cfg(test)]
fn rebuild_claude_json_for_swap_context(
    config_dir: &Path,
    handle_dir: &Path,
    target: &crate::accounts::anthropic_identity::AnthropicContext,
    source: Option<&crate::accounts::anthropic_identity::AnthropicContext>,
    expected_native: Option<&str>,
) -> Result<(), NativeMetadataReconcileFailure> {
    stage_claude_json_for_swap_context_captured(
        config_dir,
        handle_dir,
        target,
        source,
        expected_native,
        None,
    )?
    .commit()
    .map(|_| ())
}

fn stage_claude_json_for_swap_context_captured(
    config_dir: &Path,
    handle_dir: &Path,
    target: &crate::accounts::anthropic_identity::AnthropicContext,
    source: Option<&crate::accounts::anthropic_identity::AnthropicContext>,
    expected_native: Option<&str>,
    source_binding: Option<&crate::accounts::anthropic_identity::CapturedBinding>,
) -> Result<StagedNativeMetadata, NativeMetadataReconcileFailure> {
    use crate::accounts::anthropic_identity as ai;
    use NativeMetadataReconcileFailure as Failure;
    let current = read_native_swap_raw(handle_dir).map_err(|_| Failure::ReadUnavailable)?;
    if current.as_deref() != expected_native {
        return Err(Failure::ContextChanged);
    }
    if !native_context_can_rewrite(current.as_deref(), target, source)
        && !source_binding.is_some_and(|binding| {
            matches!(binding.context(), ai::StoredAnthropicContext::LegacyUnknown)
                && native_context_matches_captured_binding(current.as_deref(), binding)
        })
    {
        return Err(Failure::UntrustedContext);
    }
    let mut json = match current.as_deref() {
        Some(raw) => serde_json::from_str::<Value>(raw).map_err(|_| Failure::UntrustedContext)?,
        None => serde_json::json!({}),
    };
    let object = json.as_object_mut().ok_or(Failure::UntrustedContext)?;
    // Remove the old organization/account caches even when the target's native
    // metadata is missing. Preserve unrelated globals and session projects.
    for key in ACCOUNT_CACHE_KEYS {
        object.remove(*key);
    }
    // oauthAccount siblings (roles, billing metadata, feature entitlement)
    // belong to the source account too; an unavailable target never inherits them.
    let mut target_account = serde_json::json!({});
    if let Ok(Some(raw)) = read_native_swap_raw(config_dir) {
        if let Ok(target_json) = serde_json::from_str::<Value>(&raw) {
            if ai::parse_native_expectation(&target_json)
                .is_ok_and(|context| context.context() == target)
            {
                for key in ACCOUNT_CACHE_KEYS {
                    if let Some(value) = target_json.get(*key) {
                        object.insert((*key).into(), value.clone());
                    }
                }
                if let Some(account) = target_json
                    .get("oauthAccount")
                    .filter(|value| value.is_object())
                {
                    target_account = account.clone();
                }
            }
        }
    }
    object.insert("oauthAccount".into(), target_account);
    let account = object
        .get_mut("oauthAccount")
        .ok_or(Failure::UntrustedContext)?;
    if account.is_null() {
        *account = serde_json::json!({});
    }
    let account = account.as_object_mut().ok_or(Failure::UntrustedContext)?;
    account.insert("emailAddress".into(), Value::String(target.email().into()));
    account.insert(
        "accountUuid".into(),
        Value::String(target.account_uuid().to_string()),
    );
    account.insert(
        "organizationUuid".into(),
        Value::String(target.organization_uuid().to_string()),
    );
    stage_native_swap_metadata(handle_dir, &json, expected_native)
}

fn stage_claude_json_for_swap_legacy_context(
    handle_dir: &Path,
    target: &crate::accounts::anthropic_identity::CapturedBinding,
    source: Option<&crate::accounts::anthropic_identity::CapturedBinding>,
    expected_native: Option<&str>,
) -> Result<StagedNativeMetadata, NativeMetadataReconcileFailure> {
    use NativeMetadataReconcileFailure as Failure;
    let email = target
        .recorded_legacy_email()
        .ok_or(Failure::UntrustedContext)?;
    let current = read_native_swap_raw(handle_dir).map_err(|_| Failure::ReadUnavailable)?;
    if current.as_deref() != expected_native {
        return Err(Failure::ContextChanged);
    }
    if source.is_none()
        || !(native_context_matches_captured_binding(current.as_deref(), target)
            || source.is_some_and(|source| {
                native_context_matches_captured_binding(current.as_deref(), source)
            }))
    {
        return Err(Failure::UntrustedContext);
    }
    let mut json = match current.as_deref() {
        Some(raw) => serde_json::from_str::<Value>(raw).map_err(|_| Failure::UntrustedContext)?,
        None => serde_json::json!({}),
    };
    let object = json.as_object_mut().ok_or(Failure::UntrustedContext)?;
    for key in ACCOUNT_CACHE_KEYS {
        object.remove(*key);
    }
    // Unknown provider context stays unknown. Never copy guessed account/org
    // UUIDs or entitlements from a same-email native file into this target.
    object.insert(
        "oauthAccount".into(),
        serde_json::json!({"emailAddress":email}),
    );
    stage_native_swap_metadata(handle_dir, &json, expected_native)
}

/// A `.claude.json` rebuilt for a swap, written to a private tmp file but
/// NOT yet published. Staging happens BEFORE the symlink rename loop so every
/// build/serialize/write failure fires while nothing has mutated; only the
/// compare-and-replace in [`Self::commit`] runs after the loop, inside the
/// rollback-tracked set. Dropping an uncommitted stage removes the tmp file
/// (security.md 5a: the tmp carries the account email).
#[derive(Debug)]
struct StagedNativeMetadata {
    tmp: PathBuf,
    path: PathBuf,
    handle_dir: PathBuf,
    expected: Option<String>,
    published: String,
}

impl StagedNativeMetadata {
    /// The native bytes this stage was built against (`None` = file absent).
    fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
    }

    /// Assertion, not an OS CAS: uncooperative native writers can still race
    /// after this final held-fd comparison. A measured refusal is surfaced.
    fn commit(self) -> Result<String, NativeMetadataReconcileFailure> {
        use NativeMetadataReconcileFailure as Failure;
        match read_native_swap_raw(&self.handle_dir) {
            Ok(raw) if raw.as_deref() == self.expected.as_deref() => (),
            Ok(_) => return Err(Failure::ContextChanged),
            Err(_) => return Err(Failure::ReadUnavailable),
        }
        crate::platform::fs::atomic_replace(&self.tmp, &self.path)
            .map_err(|_| Failure::WriteFailed)?;
        Ok(self.published.clone())
    }
}

impl Drop for StagedNativeMetadata {
    fn drop(&mut self) {
        // After a successful commit the tmp was renamed away (NotFound);
        // on every other path this removes the leftover secret-bearing tmp.
        let _ = std::fs::remove_file(&self.tmp);
    }
}

fn stage_native_swap_metadata(
    handle_dir: &Path,
    json: &Value,
    expected_native: Option<&str>,
) -> Result<StagedNativeMetadata, NativeMetadataReconcileFailure> {
    use NativeMetadataReconcileFailure as Failure;
    let path = handle_dir.join(".claude.json");
    let published = serde_json::to_string(&json).map_err(|_| Failure::WriteFailed)?;
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if crate::platform::fs::write_new_private(&tmp, published.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Failure::WriteFailed);
    }
    Ok(StagedNativeMetadata {
        tmp,
        path,
        handle_dir: handle_dir.to_path_buf(),
        expected: expected_native.map(str::to_owned),
        published,
    })
}

/// Best-effort restore of `.claude.json` to the bytes captured before the
/// swap (`None` = it did not exist). Used only when a step AFTER the native
/// commit fails. Returns `true` only on a complete restore.
fn restore_native_metadata(handle_dir: &Path, prior: Option<&str>, published: &str) -> bool {
    // Assertion, not an OS CAS: never knowingly overwrite an intervening
    // native writer, including deleting its file when the prior was absent.
    if !matches!(read_native_swap_raw(handle_dir), Ok(Some(raw)) if raw == published) {
        return false;
    }
    let path = handle_dir.join(".claude.json");
    match prior {
        None => match std::fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        },
        Some(raw) => {
            let tmp = crate::platform::fs::unique_tmp_path(&path);
            if crate::platform::fs::write_new_private(&tmp, raw.as_bytes()).is_err() {
                let _ = std::fs::remove_file(&tmp);
                return false;
            }
            if !matches!(read_native_swap_raw(handle_dir), Ok(Some(current)) if current == published)
            {
                let _ = std::fs::remove_file(&tmp);
                return false;
            }
            if crate::platform::fs::atomic_replace(&tmp, &path).is_err() {
                let _ = std::fs::remove_file(&tmp);
                return false;
            }
            true
        }
    }
}

#[cfg(test)]
fn reconcile_handle_dir_oauth_email(
    handle_dir: &Path,
    identity_email: &str,
    pre_swap_email: Option<&str>,
) {
    let email = identity_email.trim();
    if email.is_empty() {
        return;
    }
    let Some(content) = crate::credentials::claude_json::read_raw(handle_dir) else {
        return;
    };
    let Ok(mut json) = serde_json::from_str::<Value>(&content) else {
        return;
    };
    let Some(obj) = json.as_object_mut() else {
        return;
    };
    let current = obj
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|c| !c.is_empty());
    // Idempotent fast-path: already the anchor → no write.
    if current.is_some_and(|cur| cur.eq_ignore_ascii_case(email)) {
        return;
    }
    // Foreign-signal safety gate (M-2): overwrite ONLY an absent/empty email or the
    // stale pre-swap value. A present email that is neither is a foreign `/login`
    // signal the gate MUST keep seeing → skip.
    let safe_to_write = match current {
        None => true,
        Some(cur) => pre_swap_email
            .map(str::trim)
            .is_some_and(|old| !old.is_empty() && cur.eq_ignore_ascii_case(old)),
    };
    if !safe_to_write {
        debug!("swap: an internal ticket reconcile skipped — .claude.json names a non-pre-swap account");
        return;
    }
    // Force oauthAccount.emailAddress, creating (or replacing a non-object)
    // oauthAccount while preserving sibling fields.
    match obj.get_mut("oauthAccount").and_then(Value::as_object_mut) {
        Some(oa) => {
            oa.insert("emailAddress".to_string(), Value::String(email.to_string()));
        }
        None => {
            let mut m = serde_json::Map::new();
            m.insert("emailAddress".to_string(), Value::String(email.to_string()));
            obj.insert("oauthAccount".to_string(), Value::Object(m));
        }
    }
    let out = match serde_json::to_string(&json) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "swap: failed to serialize .claude.json for an internal ticket reconcile");
            return;
        }
    };
    let path = handle_dir.join(".claude.json");
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    // §5a: `write_new_private` creates the tmp file at 0o600 at creation —
    // the file carries the account email = PII. Closes the window a
    // separate std::fs::write + secure_file pair left open.
    if let Err(e) = crate::platform::fs::write_new_private(&tmp, out.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %tmp.display(), error = %e, "swap: an internal ticket reconcile temp write failed");
        return;
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %path.display(), error = %e, "swap: an internal ticket reconcile atomic replace failed");
        return;
    }
    debug!("swap: reconciled .claude.json oauthAccount.emailAddress to identity anchor (an internal ticket)");
}

#[cfg(all(test, unix))]
fn rebuild_claude_json_for_swap(config_dir: &Path, handle_dir: &Path) {
    let handle_claude_json = handle_dir.join(".claude.json");
    let Some(json) =
        build_scoped_claude_json(&config_dir.join(".claude.json"), Some(&handle_claude_json))
    else {
        warn!(
            src = %config_dir.join(".claude.json").display(),
            "swap: new slot has no readable .claude.json, leaving handle dir file as-is"
        );
        return;
    };

    let out = match serde_json::to_string_pretty(&json) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "swap: failed to serialize new .claude.json");
            return;
        }
    };

    // Atomic write: temp + rename. CC may be reading .claude.json
    // concurrently with this swap; a partial write would corrupt its
    // parse and potentially wipe session state.
    // §5a cleanup: .claude.json carries CC session metadata + the account email
    // (PII) — partial failure must remove the tmp so it doesn't linger at umask
    // 0o644, and the tmp is 0600'd before the rename (redteam R2 rust-specialist).
    let tmp = crate::platform::fs::unique_tmp_path(&handle_claude_json);
    if let Err(e) = crate::platform::fs::write_new_private(&tmp, out.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %tmp.display(), error = %e, "swap: temp .claude.json write failed");
        return;
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &handle_claude_json) {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            path = %handle_claude_json.display(),
            error = %e,
            "swap: atomic replace of .claude.json failed"
        );
        return;
    }
    debug!("swap: rebuilt .claude.json for new slot");
}

/// Sweeps orphaned `term-*` handle directories under `base_dir`.
///
/// A handle dir is orphaned when its recorded owner PID (in `.live-pid`)
/// is no longer alive. This function is idempotent — safe to call
/// repeatedly.
///
/// Before removing a dead handle dir, any `image-cache/<session-id>/`
/// sub-directories are moved to `claude_home/image-cache/<session-id>/`
/// so pasted images survive the sweep. See an internal journal entry for the design.
///
/// # PID recycling safety
///
/// The dir name's parsed PID is only a first-pass filter. The
/// authoritative owner is `.live-pid` (set by `create_handle_dir`).
/// We re-read `.live-pid` TWICE: once to confirm the dir is dead
/// before preservation, once more immediately before deletion to
/// catch a recycled-PID takeover during the preservation window.
/// The deletion itself uses atomic `rename` to a tombstone path,
/// which frees the `term-<pid>` name in a single syscall so a
/// concurrent `create_handle_dir` sees the path as available and
/// creates fresh rather than racing the recursive delete.
///
/// # Windows child-PID check
///
/// On non-Unix, `csq run` spawns claude as a child process (Unix
/// uses `exec`, replacing the process in place with a single PID).
/// The child's PID is recorded in `.live-cc-pid`. Sweep treats the
/// handle dir as live if EITHER the csq PID or the CC child PID is
/// alive. This closes the Windows crash-recovery case where
/// csq-cli died but CC is still running as an orphaned child.
///
/// # Tombstones
///
/// Deletion uses `rename(path, tombstone)` + `remove_dir_all(tombstone)`.
/// If the daemon is killed between rename and delete, the next sweep
/// finds a stale `.sweep-tombstone-*` entry and removes it via the
/// initial cleanup pass.
///
/// If `claude_home` is `None`, preservation is skipped entirely —
/// the sweep still removes orphans but pasted images are lost.
/// Callers should only pass `None` when they cannot safely determine
/// where `~/.claude/image-cache/` lives.
///
/// Clear the macOS keychain OAuth item for a dead `term-<pid>` handle dir
/// about to be reaped by [`sweep_dead_handles`], immediately before it is
/// deleted (the item is keyed on the dir's canonicalized path — once the dir
/// is gone, nothing can ever locate the item again).
///
/// **Cost predicate first** (`security.md` MUST-6): the reaper runs on every
/// account on a fixed cadence, so a `security` subprocess call per dead dir
/// regardless of whether it ever held an item would be wasted work on the hot
/// path. [`keychain::handle_dir_might_have_anthropic_keychain_item`] is a
/// pure filesystem check (no keychain access) that gates the call — see its
/// doc comment for why the predicate is sound, not merely convenient.
///
/// `clear_fn` is a test seam: production always passes
/// `keychain::decide_and_clear_dead_handle` (bound to `base_dir` and the
/// real single-candidate custodian adopt — see [`sweep_dead_handles`]'s own
/// doc); tests inject a counting spy so
/// the gating behavior (called vs. not-called) is provable without shelling
/// `security` — `keychain_mirror_disabled()` makes the real function return
/// `Ok(false)` unconditionally under `cfg!(test)`, which is indistinguishable
/// from "never called" by return value alone.
///
/// **Fail-open, matching an internal ticket's `clear_bound_keychain_items` posture — WITH
/// the same security-review-1386 H1 compensating mechanism.** The keychain
/// item is a MIRROR at the moment this runs (the credential also lives at
/// `identities/<UUID>/credentials.json`), so refusing the whole sweep on a
/// keychain timeout is the wrong trade — the reaper is a periodic
/// background loop touching every account and MUST NOT wedge or abort
/// because one dir's keychain is locked or unreachable (a common,
/// transient, non-macOS-Aqua-session condition). But an unconfirmed clear
/// here is a STRONGER case than logout's: the tombstone rename that deletes
/// this dir happens immediately after this call returns, so the item
/// becomes UNREACHABLE — no future code path can ever reconstruct this
/// exact `abs` again to retry — the instant that rename lands. So instead
/// of only logging and dropping it, an unconfirmed clear is queued via
/// [`keychain::record_pending_clear`], the SAME durable retry channel
/// `logout::clear_bound_keychain_items` uses, picked up by
/// [`spawn_sweep`]'s `sweep_pending_clears` call on the SAME 60s tick
/// (immediately after `sweep_dead_handles` returns) AND by `csq run` /
/// `csq exec` / the phase2b subscription client's opportunistic sweeps
/// (F10 — four convergence points now, not two, so a headless install
/// driven entirely through `csq exec` or a subscription capture with no
/// daemon and no `csq run` still drains this queue). Failures are never
/// silently dropped either way (`zero-tolerance.md` Rule 3): an unconfirmed
/// clear logs a WARN with a fixed-vocabulary `error_kind` and the dead PID
/// only — never an absolute path (`security.md` MUST-2).
///
/// `base_dir` is the accounts dir (`record_pending_clear`'s queue lives at
/// `<base_dir>/keychain-pending-clears.json` — pure file I/O against a path
/// the caller already owns, no dependency on `path`/`abs` continuing to
/// exist afterward: `sweep_pending_clears` retries by SERVICE NAME string
/// alone, never by re-deriving a directory path — see its doc comment).
fn clear_dead_handle_keychain_item(
    path: &Path,
    owner_pid: u32,
    base_dir: &Path,
    clear_fn: &mut impl FnMut(&Path) -> Result<bool, keychain::KeychainClearUnconfirmed>,
) {
    clear_dead_handle_keychain_item_inner(
        path,
        owner_pid,
        base_dir,
        clear_fn,
        &mut |b, s, acct, email, account_hint, queued_identity| {
            keychain::record_pending_clear_with_identity(
                b,
                s,
                acct,
                keychain::PendingClearOrigin::DeadHandle,
                email,
                account_hint,
                queued_identity,
            )
        },
    );
}

/// Test seam for [`clear_dead_handle_keychain_item`]: `record_fn` is the
/// pending-clear queue write the unconfirmed arm performs, injectable for the
/// SAME reason `clear_fn` is — [`keychain::record_pending_clear`] is
/// `#[cfg(not(target_os = "macos"))] {}`, a structural no-op on every non-macOS
/// target, so on the Linux CI runner "queued" and "never called" are
/// indistinguishable by observing `keychain-pending-clears.json`. Asserting on
/// that file is therefore a macOS-only instrument (`instrument-discipline.md`
/// MUST-1: off macOS no result it could produce would falsify the claim). The
/// seam keeps the WIRING — does the unconfirmed arm reach the recorder at all,
/// with this dir's own service name — provable on every platform, which is what
/// the enterprise job (Linux) can actually discriminate.
///
/// Production's only caller ([`clear_dead_handle_keychain_item`] above) always
/// passes the real `keychain::record_pending_clear`.
fn clear_dead_handle_keychain_item_inner(
    path: &Path,
    owner_pid: u32,
    base_dir: &Path,
    clear_fn: &mut impl FnMut(&Path) -> Result<bool, keychain::KeychainClearUnconfirmed>,
    record_fn: &mut impl FnMut(
        &Path,
        &str,
        Option<AccountNum>,
        Option<String>,
        Option<String>,
        Option<(u64, i64)>,
    ),
) {
    if !keychain::handle_dir_might_have_anthropic_keychain_item(path) {
        return;
    }
    // Security review 1386 M1 (mirrored from `logout::clear_bound_keychain_items`):
    // a canonicalize failure MUST NOT fall back to the non-canonical `path` — that
    // hashes to a DIFFERENT keychain service name than the one CC actually uses (CC
    // hashes the canonicalized `CLAUDE_CONFIG_DIR`), so `clear_fn` would target
    // nothing, `security` would report "no such item" (a subprocess that ran to
    // completion, `Ok(true)`), and the caller would wrongly believe the real item
    // was handled. Skip with a WARN instead.
    let Ok(abs) = std::fs::canonicalize(path) else {
        warn!(
            error_kind = "keychain_clear_canonicalize_failed",
            pid = owner_pid,
            "sweep: could not canonicalize this dead handle dir's path — its keychain \
             item (if any) was NOT targeted for clearing (non-fatal — sweep continues)"
        );
        return;
    };
    if let Err(keychain::KeychainClearUnconfirmed) = clear_fn(&abs) {
        warn!(
            error_kind = "keychain_clear_unconfirmed",
            pid = owner_pid,
            "sweep: could not confirm the keychain OAuth item was cleared for this dead \
             handle dir (non-fatal — keychain may be locked or unavailable; queued for \
             automatic retry; sweep continues)"
        );
        // `keychain-fix-r8d.md` item 1: resolve the dead dir's marker
        // account NOW, while `abs` still exists, and record it alongside
        // the service name — by retry time (`sweep_pending_clears`) this
        // dir is gone and there is nothing left to re-resolve it from.
        //
        // `keychain-fix-r9.md` S-M-2/D-F5: the OAuth email and the keychain
        // account-attribute hint are captured the SAME way, for the SAME
        // reason — `decide_and_clear_dead_handle`'s own first attempt (which
        // just returned this `Err`) already resolved and used both; the
        // retry should target the identical candidate and account
        // attribute, not `None`/a live re-derivation.
        let marker_account = crate::accounts::markers::resolve_marker_to_slot(base_dir, &abs);
        let candidate_email = crate::credentials::claude_json::read_oauth_email(&abs);
        let account_hint = keychain::keychain_account_for(&abs);
        // `keychain-fix-r11.md` S-LOW-1/D-4b: capture THIS dir's own
        // identity now, while `abs` still exists — by retry time there is
        // nothing left to re-derive it from, and this is what lets a later
        // live-collision check tell "the SAME dir this entry was queued
        // against" apart from "a DIFFERENT, NEWER dir that has since taken
        // over the reused PID".
        #[cfg(unix)]
        let queued_identity = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&abs)
                .ok()
                .map(|meta| (meta.ino(), meta.ctime()))
        };
        #[cfg(not(unix))]
        let queued_identity = None;
        record_fn(
            base_dir,
            &keychain::service_name(&abs),
            marker_account,
            candidate_email,
            Some(account_hint),
            queued_identity,
        );
    }
}

/// Returns the number of directories removed.
///
/// `keychain-fix-r8.md` C-F3: the per-dir keychain clear routes through
/// `keychain::decide_and_clear_dead_handle` — DISTINCT from `csq logout`'s
/// [`keychain::clear_handle_dir_reporting`], which deletes CC's item
/// unconditionally (intentional: logout means "this account's credentials
/// are gone everywhere"). A dead handle dir is an abandoned SESSION, not an
/// intentional account removal, so it must not destroy the only live copy
/// of a login nobody else recorded — see that function's own doc for the
/// known-token / adopt-then-delete / keep-and-re-queue disposition.
///
/// `try_adopt` is wired to `crate::daemon::custodian::adopt_single_candidate_before_delete`
/// with the same Node-transport `HttpGetFn` `daemon::server`/`daemon::refresher`
/// construct for their own `reconcile_account` calls
/// (`crate::http::get_bearer_node` — reachable crate-wide; no dependency on
/// `daemon::server`/`daemon::refresher` themselves, so this stays inside
/// `keychain-fix-r8c.md` SHARD KA's file scope: `handle_dir.rs`,
/// `keychain.rs`, `custodian.rs`).
pub fn sweep_dead_handles(base_dir: &Path, claude_home: Option<&Path>) -> usize {
    let _ = crate::sessions::lifecycle::reconcile_owned(
        base_dir,
        claude_home.and_then(crate::sessions::lifecycle::registry_home),
    );
    let http_get: crate::daemon::usage_poller::HttpGetFn =
        std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            crate::http::get_bearer_node(url, token, headers)
        });
    sweep_dead_handles_inner(base_dir, claude_home, |config_dir| {
        keychain::decide_and_clear_dead_handle(base_dir, config_dir, &|account, candidate| {
            crate::daemon::custodian::adopt_single_candidate_before_delete(
                base_dir, account, candidate, &http_get,
            )
        })
    })
}

/// Most distinct skipped-dir names remembered for warn-once; at the cap the set is cleared
/// (bounded memory, at worst one repeat warning per 1000 distinct names).
const SKIP_WARN_CAP: usize = 1000;

thread_local! {
    /// Test-only: warnings actually emitted on this thread by [`warn_skip_once`].
    #[cfg(test)]
    static SKIP_WARNS_EMITTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `true` the first time `key` is seen in `seen`. Clears `seen` when it is full.
fn first_sighting(seen: &std::sync::Mutex<std::collections::HashSet<String>>, key: &str) -> bool {
    // A poisoned lock only means another thread panicked mid-insert; the set is still usable.
    let mut set = seen.lock().unwrap_or_else(|p| p.into_inner());
    if set.contains(key) {
        return false;
    }
    if set.len() >= SKIP_WARN_CAP {
        set.clear();
    }
    set.insert(key.to_string());
    true
}

/// A sweep skipped `dir_name` because a pid marker is unreadable. The sweeps run every 60 s
/// and the same dir is skipped every tick, so warn ONCE per (kind, dir name) per process and
/// log at debug afterwards. Dir name only, never a path (`security.md`).
fn warn_skip_once(error_kind: &'static str, dir_name: &str) {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    if first_sighting(seen, &format!("{error_kind}:{dir_name}")) {
        #[cfg(test)]
        SKIP_WARNS_EMITTED.with(|c| c.set(c.get() + 1));
        warn!(
            error_kind,
            dir_name,
            "sweep: unreadable pid marker; skipping the handle dir (further skips of this dir are logged at debug)"
        );
    } else {
        debug!(
            error_kind,
            dir_name, "sweep: unreadable pid marker; skipping the handle dir"
        );
    }
}

/// Test seam for [`sweep_dead_handles`]: `clear_keychain_item` is the
/// per-dir keychain-clear call `clear_dead_handle_keychain_item` invokes,
/// injectable so tests can prove the reaper's WIRING (called for an
/// Anthropic-bound dead dir, skipped for one that never held an item)
/// without shelling `security` — production's only caller
/// ([`sweep_dead_handles`] above) always passes
/// `keychain::decide_and_clear_dead_handle`.
fn sweep_dead_handles_inner(
    base_dir: &Path,
    claude_home: Option<&Path>,
    mut clear_keychain_item: impl FnMut(&Path) -> Result<bool, keychain::KeychainClearUnconfirmed>,
) -> usize {
    let mut removed = 0;

    // Clean up any stale tombstones from a crashed previous sweep
    // before scanning for live handle dirs. Idempotent: if the
    // tombstone removal fails (ENOENT, EBUSY), the next tick retries.
    cleanup_stale_tombstones(base_dir);

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "sweep: failed to read directory entry");
                continue;
            }
        };

        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if !name.starts_with("term-") {
            continue;
        }

        let dir_pid: u32 = match name.strip_prefix("term-").and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        let path = entry.path();

        // R1/KC4-9: v4 ("switch now or say so") removed the
        // account-change-pending marker and every mechanism that existed
        // only to serve it. Nothing in this codebase writes
        // `.keychain-account-change-pending` any more, but a dev host that
        // ran a pre-v4 build may still have one on disk — best-effort
        // cleanup here is cheap insurance, not a load-bearing step.
        let stale_marker = path.join(".keychain-account-change-pending");
        if let Err(e) = std::fs::remove_file(&stale_marker) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    error_kind = "keychain_stale_account_change_marker_cleanup_failed",
                    "sweep: could not remove a leftover pre-v4 account-change-pending marker (non-fatal — retried on the next sweep)"
                );
            }
        }

        // Read the authoritative PID from `.live-pid`. Fall back to
        // the dir-name PID if the marker is missing or corrupt — a
        // crash-survivor dir with no marker is still sweepable if its
        // dir-name PID is dead.
        //
        // `initial_marker.is_some()` records whether the first read
        // saw a real marker; the re-check below bails if the marker
        // disappears between the two reads, which would signal a
        // racing `create_handle_dir` that has not yet finished
        // writing `.live-pid`.
        // An UNREADABLE marker (not merely absent) means "possibly live": skip the
        // dir (`guard-reader-writer-parity.md` MUST-2). The dir-name fallback applies
        // only when `.live-pid` is ABSENT.
        let initial_marker = match markers::read_live_pid_checked(&path) {
            Ok(m) => m,
            Err(markers::MarkerUnreadable) => {
                warn_skip_once("sweep_live_pid_unreadable", &name);
                continue;
            }
        };
        let owner_pid = initial_marker.unwrap_or(dir_pid);
        if is_pid_alive(owner_pid) {
            continue;
        }

        // Also honor `.live-cc-pid` (the spawned child). Written by any
        // spawn-capture launch (`csq run` OneShot/Interactive spawn modes,
        // `csq exec`, the codex supervisor) and on Windows; the plain Unix
        // `csq run` exec path writes none.
        let cc_pid = match markers::read_live_cc_pid_checked(&path) {
            Ok(c) => c,
            Err(markers::MarkerUnreadable) => {
                warn_skip_once("sweep_live_cc_pid_unreadable", &name);
                continue;
            }
        };
        if let Some(cc) = cc_pid {
            if is_pid_alive(cc) {
                continue;
            }
        }

        info!(
            pid = owner_pid,
            cc_pid = ?cc_pid,
            dir_name = %name,
            "sweeping orphaned handle dir"
        );

        // Preserve per-session image caches before the dead dir is deleted.
        // We cannot share `image-cache/` via SHARED_ITEMS because CC's
        // internal cleanup (`Dv7()`) deletes every entry that doesn't match
        // the live session ID, causing concurrent terminals to race on a
        // shared directory — see an internal journal entry
        if let Some(home) = claude_home {
            preserve_image_cache(&path, home);
        }

        // Re-verify ownership immediately before the destructive step.
        // A racing `csq run` with a recycled PID could have replaced
        // this dir while we were preserving. Three bail conditions:
        //   1. The marker now names a different PID than we started with.
        //   2. The marker now names a PID that is alive.
        //   3. The marker was present initially but has now disappeared
        //      — this means the dir was replaced by a `csq run` that
        //      has not yet finished writing `.live-pid`; bail.
        let Ok(current_marker) = markers::read_live_pid_checked(&path) else {
            warn!(
                error_kind = "sweep_live_pid_unreadable",
                "sweep: .live-pid became unreadable mid-sweep, bailing"
            );
            continue;
        };
        match (initial_marker, current_marker) {
            (Some(_), None) => {
                warn!(
                    original = owner_pid,
                    dir_name = %name,
                    "sweep: .live-pid disappeared mid-sweep, bailing"
                );
                continue;
            }
            (_, Some(current_owner))
                if current_owner != owner_pid || is_pid_alive(current_owner) =>
            {
                warn!(
                    original = owner_pid,
                    current = current_owner,
                    dir_name = %name,
                    "sweep: handle dir ownership changed mid-sweep, bailing"
                );
                continue;
            }
            _ => {}
        }

        // Also re-check the child CC marker on the second pass.
        match markers::read_live_cc_pid_checked(&path) {
            Ok(Some(cc)) if is_pid_alive(cc) => {
                warn!(
                    cc_pid = cc,
                    dir_name = %name,
                    "sweep: CC child became alive mid-sweep, bailing"
                );
                continue;
            }
            Err(markers::MarkerUnreadable) => {
                warn!(
                    error_kind = "sweep_live_cc_pid_unreadable",
                    "sweep: .live-cc-pid became unreadable mid-sweep, bailing"
                );
                continue;
            }
            _ => {}
        }

        // Clear this dir's macOS keychain OAuth item BEFORE it is deleted —
        // the item is keyed on the dir's canonicalized path, so once the dir
        // is gone nothing can ever locate or clear it again and it becomes a
        // permanent orphan (`account-terminal-separation.md`; an internal ticket closed
        // the equivalent gap on the `csq logout` path — this closes it on
        // the reaper path, which an internal ticket explicitly left open, see its doc
        // comment on `clear_bound_keychain_items`). That is sufficient reason
        // on its own: the imminent deletion of the keyed-on path is what
        // makes the item unreachable, independent of anything about the
        // occupant that is about to replace it.
        //
        // It is NOT primarily a defense against `term-<pid>` PID recycling.
        // an internal ticket also made `csq run`'s own keychain sync unconditionally force
        // (v4 `force_sync_for_launch` -> `force_sync_account_changed`), which
        // bypasses the newer-than-keychain guard and always overwrites-or-clears
        // — so a NEW dir created at a recycled path self-heals on its own next
        // launch whether or not this reaper ever ran. Reaping here still
        // matters for the narrower window it closes: a path that is never
        // reused would otherwise leave its item stranded forever, and a
        // recycled path would otherwise carry a stale, wrong-account item
        // for however long the dir sits dead-but-unreaped before the next
        // `csq run` lands on it.
        clear_dead_handle_keychain_item(&path, owner_pid, base_dir, &mut clear_keychain_item);

        // PROMOTE codex's sqlite state to `config-N` before the dir dies.
        //
        // `codex_shared_pairs` already symlinks any `*.sqlite` it FINDS in
        // `config-N` — but nothing ever put one there, because codex creates
        // them inside the ephemeral handle dir and this reaper deletes them.
        // The share was a chicken-and-egg: discovery-only, with no seeder. So
        // every launch rebuilt the whole index from scratch, which was cheap
        // at a few hundred rollouts and is hours once `csq sessions share`
        // pools thousands (measured 2026-09-12: 7,291 rollouts / 16.2 GB,
        // ~10 KB/s of index growth, four terminals each building their own
        // private copy and discarding it).
        //
        // Promotion is the seeder. It runs before the rename, so the FIRST
        // session pays the build and every later one links the result. A
        // PARTIAL index promotes too, and that is deliberate — codex's
        // projection is cursor-based, so an interrupted build resumes instead
        // of restarting.
        promote_codex_sqlite_state(&path);

        // Atomic rename-to-tombstone frees the term-<pid> path in
        // one syscall. Any concurrent `create_handle_dir` calls
        // after the rename see a missing path and create fresh
        // without racing the recursive delete. The tombstone is
        // deleted afterwards; if we crash in between, the next
        // sweep's initial `cleanup_stale_tombstones` pass catches
        // the leftover.
        let tombstone = base_dir.join(format!(
            ".sweep-tombstone-{}-{}",
            dir_pid,
            tombstone_suffix()
        ));
        if let Err(e) = std::fs::rename(&path, &tombstone) {
            warn!(pid = owner_pid, error = %e, "failed to rename orphan to tombstone");
            continue;
        }

        // The `term-<pid>` path is freed by the rename above. Whether
        // or not the tombstone removal succeeds, the orphan is gone
        // from the user's perspective. Count it as removed and let
        // the next sweep tick's `cleanup_stale_tombstones` pass mop
        // up any leftover.
        removed += 1;
        if let Err(e) = std::fs::remove_dir_all(&tombstone) {
            warn!(
                pid = owner_pid,
                error = %e,
                "failed to remove tombstone — will be cleaned on next tick"
            );
        }
    }

    removed += sweep_stale_capture_dirs(base_dir);
    removed += sweep_stale_exec_dirs(base_dir);

    if removed > 0 {
        info!(removed, "handle dir sweep complete");
    }
    removed
}

/// Filename prefix of the daemon's Phase-2b interactive subscription-capture
/// handle dirs (created via [`create_handle_dir_named`] /
/// [`create_handle_dir_codex_named`] with this prefix by
/// `phase2b::subscription_client`). Shared so the per-capture reaper and this
/// periodic watcher agree on the namespace.
pub(crate) const CAPTURE_DIR_PREFIX: &str = "interactive-capture-";

/// Grace before a capture dir that lacks a `.live-pid` is treated as a crash
/// leak rather than a concurrent sibling still being set up (the sibling writes
/// `.live-pid` as its final step, so a fresh pid-less dir is in-flight).
const CAPTURE_REAP_GRACE: std::time::Duration = std::time::Duration::from_secs(180);

/// Reap `interactive-capture-*` dirs left by a crashed daemon. A dir is removed
/// when its `.live-pid` records a DEAD pid; a MISSING `.live-pid` is reapable
/// only when the dir is older than [`CAPTURE_REAP_GRACE`] (else it is a sibling
/// mid-setup — reaping it would delete a live capture's dir). Returns the count
/// removed.
///
/// Called both per-capture (by `phase2b::subscription_client`, before creating a
/// new capture dir) AND from [`sweep_dead_handles`] (the 60s watcher) so a leak
/// is reaped even if no further subscription capture ever runs. The
/// `interactive-capture-*` namespace holds only credential SYMLINKS (never
/// Move a dying codex handle dir's real `*.sqlite` state into its `config-N`,
/// so the next session LINKS it instead of rebuilding it.
///
/// Best-effort and non-fatal throughout: this runs inside the reaper, whose job
/// is to free the path. A promotion that fails must never stop the sweep — the
/// worst case is the status quo ante (a rebuild next launch), never a stuck dir.
///
/// Only a REAL FILE is promoted. An entry that is already a symlink is one
/// `codex_shared_pairs` linked at creation, so its database already lives in
/// `config-N`; renaming that would replace the shared database with its own
/// link. Only a `config-N` slot that is still EMPTY is filled, so a live shared
/// database is never clobbered by a straggler handle dir reaped later.
///
/// The `-wal`/`-shm` sidecars move WITH the base database when present. A WAL
/// can hold committed-but-uncheckpointed transactions after a SIGKILL, so
/// promoting the base alone would silently drop them; moving the set keeps the
/// database consistent.
fn promote_codex_sqlite_state(handle_dir: &Path) {
    let Some(config_dir) = codex_config_dir_of_handle(handle_dir) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(handle_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.ends_with(CODEX_SHARED_SQLITE_SUFFIX) {
            continue;
        }
        let src = handle_dir.join(name);
        // symlink_metadata, not metadata: a linked database resolves to a real
        // file in config-N and would otherwise read as promotable.
        match src.symlink_metadata() {
            Ok(m) if m.file_type().is_file() => {}
            _ => continue,
        }
        let dst = config_dir.join(name);
        if dst.exists() {
            continue;
        }
        if std::fs::rename(&src, &dst).is_err() {
            continue;
        }
        for sidecar in ["-wal", "-shm"] {
            let s = handle_dir.join(format!("{name}{sidecar}"));
            if s.is_file() {
                let _ = std::fs::rename(&s, config_dir.join(format!("{name}{sidecar}")));
            }
        }
        info!(
            db = %name,
            config_dir = %config_dir.display(),
            "promoted codex sqlite state to config dir — next session links it"
        );
    }
}

/// The `config-N` a codex handle dir belongs to, resolved through the
/// `config.toml` symlink csq itself created.
///
/// Read from the LINK rather than from `.csq-account`: the marker's content is
/// an identity UUID on a post-M4-7 slot and a decimal on a legacy one
/// (`guard-reader-writer-parity.md` MUST-5), so parsing it here would need the
/// wide reader and would fail open on the form it did not recognise. The
/// `config.toml` link is unambiguous — csq wrote it, and it points at exactly
/// one `config-N`.
pub(super) fn codex_config_dir_of_handle(handle_dir: &Path) -> Option<PathBuf> {
    let target = std::fs::read_link(handle_dir.join("config.toml")).ok()?;
    let parent = target.parent()?;
    let base = parent.file_name()?.to_str()?;
    if !base.starts_with("config-") || !parent.is_dir() {
        return None;
    }
    Some(parent.to_path_buf())
}

/// copies), so `remove_dir_all` deletes links, not the real credentials.
pub(crate) fn sweep_stale_capture_dirs(base_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(CAPTURE_DIR_PREFIX) {
            continue;
        }
        let dir = entry.path();
        // Absent marker -> age fallback; UNREADABLE marker -> possibly live, skip
        // (never age-reap on an unreadable marker).
        let reapable = match markers::read_live_pid_checked(&dir) {
            Ok(Some(pid)) => !is_pid_alive(pid),
            Ok(None) => dir_age_exceeds(&dir, CAPTURE_REAP_GRACE),
            Err(markers::MarkerUnreadable) => {
                warn_skip_once("capture_sweep_live_pid_unreadable", name);
                false
            }
        };
        if reapable && std::fs::remove_dir_all(&dir).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Reap orphaned `csq exec` handle dirs (`codex-exec-<pid>` /
/// `gemini-exec-<pid>`, `csq/src/cli/commands/exec.rs`). That producer's
/// cleanup is best-effort and error-discarding
/// (`let _ = std::fs::remove_dir_all(&handle_dir)`), so a kill, panic, or
/// early return leaks the dir forever unless something else reaps it —
/// this is that something else. Wired into [`sweep_dead_handles`] so it
/// runs on the same 60s daemon cadence as the `term-*` sweep.
///
/// Both producers name their dir `<prefix><pid>` with NO further suffix
/// (unlike `interactive-capture-<pid>-<seq>`), so the owning PID is always
/// recoverable straight from the dir name — this reaper does NOT need an
/// age-based fallback. `codex-exec-*` additionally writes `.live-pid`
/// (`create_handle_dir_codex_named`); when present it is preferred as the
/// authoritative owner (covers the rare case where the OS recycled the
/// dir-name PID since creation). `gemini-exec-*` never writes `.live-pid`
/// (its producer bypasses the shared handle-dir helpers — see
/// [`EXEC_GEMINI_DIR_PREFIX`]), so it always falls back to the dir-name PID.
/// A name that doesn't parse as `<prefix><pid>` is left alone — fail safe,
/// per `reconciler-cleanup-parity.md` Rule 5 (KEEP on any doubt).
pub(crate) fn sweep_stale_exec_dirs(base_dir: &Path) -> usize {
    sweep_exec_dirs_with_prefix(base_dir, EXEC_CODEX_DIR_PREFIX)
        + sweep_exec_dirs_with_prefix(base_dir, EXEC_GEMINI_DIR_PREFIX)
}

fn sweep_exec_dirs_with_prefix(base_dir: &Path, prefix: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(name_pid) = name
            .strip_prefix(prefix)
            .and_then(|s| s.parse::<u32>().ok())
        else {
            // Either a different namespace, or a name this reaper doesn't
            // recognize the shape of — skip rather than guess (fail safe).
            continue;
        };
        let dir = entry.path();
        // The dir-name pid is the fallback only for an ABSENT marker; an unreadable
        // one means "possibly live", so the dir is kept.
        let marker_pid = match markers::read_live_pid_checked(&dir) {
            Ok(m) => m,
            Err(markers::MarkerUnreadable) => {
                warn_skip_once("exec_sweep_live_pid_unreadable", name);
                continue;
            }
        };
        let owner_pid = marker_pid.unwrap_or(name_pid);
        if is_pid_alive(owner_pid) {
            continue;
        }
        if std::fs::remove_dir_all(&dir).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// `true` when `dir`'s mtime is older than `grace`. On any stat / clock error
/// (incl. a future-dated mtime from clock skew) returns `false` (KEEP — fail
/// safe; never reap on doubt).
pub(crate) fn dir_age_exceeds(dir: &Path, grace: std::time::Duration) -> bool {
    std::fs::metadata(dir)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok())
        .map(|age| age > grace)
        .unwrap_or(false)
}

/// Generates a unique tombstone suffix so concurrent sweeps do not
/// collide on the rename target. Uses nanoseconds since epoch; the
/// `PidFile` guarantee means only one daemon runs per `base_dir`, so
/// the monotonic-ish clock is enough even under rapid sweep cycles.
fn tombstone_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{nanos:x}")
}

/// Removes any `.sweep-tombstone-*` entries left behind by a
/// previously crashed sweep. Idempotent — called at the top of
/// every sweep tick so a daemon restart doesn't leave forever-trash.
fn cleanup_stale_tombstones(base_dir: &Path) {
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !name.starts_with(".sweep-tombstone-") {
            continue;
        }
        let path = entry.path();
        if let Err(e) = std::fs::remove_dir_all(&path) {
            warn!(path = %path.display(), error = %e, "failed to remove stale tombstone");
        } else {
            debug!(path = %path.display(), "cleaned up stale tombstone");
        }
    }
}

/// Validates a directory entry name as a plausible session-id component.
///
/// CC session IDs are canonical lowercase UUIDs like
/// `01234567-89ab-4cde-8f01-23456789abcd`. We accept any non-empty
/// name up to 64 characters that contains only *lowercase* hex digits
/// and dashes. Rejecting uppercase closes an APFS/HFS+ case-folding
/// vector where `DEADBEEF-...` and `deadbeef-...` hash to the same
/// directory, which could let a buggy plugin collide an unrelated
/// session with one written earlier.
///
/// This is defense-in-depth — `read_dir` already filters `.` and `..`,
/// and POSIX/Windows filenames cannot contain path separators — but
/// restricting to the UUID alphabet keeps the shared
/// `~/.claude/image-cache/` dir free of arbitrary names that could
/// come from a buggy CC plugin or MCP server.
fn is_valid_session_name(name: &std::ffi::OsStr) -> bool {
    let s = match name.to_str() {
        Some(s) => s,
        None => return false,
    };
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c) || c == '-')
}

/// Moves `dead_handle/image-cache/<session-id>/` entries into
/// `claude_home/image-cache/<session-id>/`.
///
/// Each pasted image is stored by CC under a session-scoped directory
/// (`$CLAUDE_CONFIG_DIR/image-cache/<session-id>/`). When the handle
/// dir is swept, those entries vanish unless we preserve them.
///
/// # Symlink handling
///
/// Refuses to operate if `image-cache/` is a symlink, if any
/// `image-cache/<sid>/` entry is a symlink, or if the destination
/// `claude_home/image-cache/` is a symlink. Same-user is the csq
/// threat model, but refusing symlinks is cheap defense-in-depth
/// against a poisoned handle dir redirecting into `~/.ssh/` or
/// similar.
///
/// # Collision
///
/// If `claude_home/image-cache/<session-id>/` already exists, we skip
/// the entry. Session IDs are UUIDs so collisions are effectively
/// impossible in practice. The narrow exception is `--resume` of the
/// same session from two handle dirs; the first-to-sweep wins and
/// the second-to-sweep's newer images are lost. This is documented
/// in an internal journal entry as a known limitation — a merge-on-collision fix
/// is a follow-up.
///
/// # Cross-filesystem rename (`EXDEV`)
///
/// `std::fs::rename` fails with `EXDEV` if source and destination are
/// on different filesystems. We fall back to a recursive copy +
/// remove to preserve the data anyway. Under normal setups
/// `~/.claude/accounts/term-*` and `~/.claude/image-cache/` are on
/// the same mount, so the fallback is cold-path.
///
/// # Crash safety
///
/// If the daemon is killed mid-preservation, any sessions already
/// renamed are safe under `~/.claude/image-cache/`; the partially-
/// drained handle dir is re-swept on restart. `rename` is atomic and
/// the EXDEV fallback removes the source tree only after the copy
/// completes, so a crash during copy leaves the source intact for
/// the next tick.
///
/// Failures are logged and swallowed — preservation is best-effort
/// and MUST NOT block sweeping dead dirs. Returns the number of
/// session entries successfully moved.
fn preserve_image_cache(dead_handle: &Path, claude_home: &Path) -> usize {
    let src_cache = dead_handle.join("image-cache");

    // Source must be a real directory, not a symlink. Using symlink_metadata
    // instead of metadata prevents a poisoned handle dir from redirecting us
    // elsewhere via a symlink named `image-cache`.
    let src_meta = match src_cache.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return 0, // no image-cache at all — common case
    };
    let src_ftype = src_meta.file_type();
    if src_ftype.is_symlink() {
        warn!(
            path = %src_cache.display(),
            "image-cache is a symlink, refusing to traverse"
        );
        return 0;
    }
    if !src_ftype.is_dir() {
        return 0;
    }

    // Destination must not be a symlink — refuse to write into an
    // attacker-redirected location (e.g. `~/.claude/image-cache`
    // swapped to point at `/tmp/attacker/`).
    let dst_cache = claude_home.join("image-cache");
    if let Ok(meta) = dst_cache.symlink_metadata() {
        if meta.file_type().is_symlink() {
            warn!(
                path = %dst_cache.display(),
                "destination image-cache is a symlink, refusing to preserve"
            );
            return 0;
        }
        if !meta.file_type().is_dir() {
            warn!(
                path = %dst_cache.display(),
                "destination image-cache exists but is not a directory"
            );
            return 0;
        }
    } else if let Err(e) = std::fs::create_dir_all(&dst_cache) {
        warn!(path = %dst_cache.display(), error = %e, "failed to create shared image-cache dir");
        return 0;
    }

    let entries = match std::fs::read_dir(&src_cache) {
        Ok(e) => e,
        Err(e) => {
            warn!(path = %src_cache.display(), error = %e, "failed to read image-cache");
            return 0;
        }
    };

    let mut moved = 0;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "preserve_image_cache: directory entry read failed");
                continue;
            }
        };

        // Must be a real directory, not a symlink. `DirEntry::file_type`
        // on Unix/Windows does not follow symlinks — symlinks report
        // `is_symlink() == true` and `is_dir() == false`, so this check
        // is safe. Still, we stat the full path explicitly for safety
        // on filesystems where `d_type` is `DT_UNKNOWN`.
        let src = entry.path();
        let meta = match src.symlink_metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            continue;
        }

        let session_name = entry.file_name();
        if !is_valid_session_name(&session_name) {
            warn!(
                session = ?session_name,
                "image-cache entry name rejected by session-id validator"
            );
            continue;
        }

        let dst = dst_cache.join(&session_name);

        // Collision: the shared image-cache already has an entry for
        // this session ID. Happens when CC `--resume`s the same
        // session from a second handle dir after the first one was
        // swept. Merge file-by-file, preserving existing destination
        // files untouched (they might belong to a still-live sibling
        // terminal). New file names from the dead handle are moved in.
        if dst.symlink_metadata().is_ok() {
            match merge_session_into_existing(&src, &dst) {
                Ok(n) if n > 0 => {
                    moved += 1;
                    debug!(
                        session = ?session_name,
                        files = n,
                        "merged image-cache session into existing shared entry"
                    );
                }
                Ok(_) => {
                    debug!(
                        session = ?session_name,
                        "image-cache session had no new files to merge"
                    );
                }
                Err(e) => {
                    warn!(
                        session = ?session_name,
                        error = %e,
                        "failed to merge image-cache session"
                    );
                }
            }
            continue;
        }

        match std::fs::rename(&src, &dst) {
            Ok(_) => {
                moved += 1;
                debug!(session = ?session_name, "preserved image-cache session");
            }
            Err(e) if is_cross_device(&e) => {
                // EXDEV: fall back to recursive copy + remove.
                match copy_and_remove_tree(&src, &dst) {
                    Ok(_) => {
                        moved += 1;
                        debug!(session = ?session_name, "preserved image-cache session (EXDEV fallback)");
                    }
                    Err(e) => {
                        warn!(
                            session = ?session_name,
                            error = %e,
                            "EXDEV fallback failed for image-cache session"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(session = ?session_name, error = %e, "failed to preserve image-cache session");
            }
        }
    }

    if moved > 0 {
        info!(
            count = moved,
            handle = %dead_handle.display(),
            "preserved image-cache sessions from dead handle"
        );
    }
    moved
}

/// Returns `true` if the I/O error indicates a cross-device rename (`EXDEV`).
fn is_cross_device(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EXDEV)
    }
    #[cfg(not(unix))]
    {
        // Windows maps cross-volume moves to `ERROR_NOT_SAME_DEVICE` (17).
        err.raw_os_error() == Some(17)
    }
}

/// Copies `src` tree to `dst` then removes `src`. Used as the EXDEV
/// fallback when `rename` cannot move across filesystems.
///
/// Refuses to traverse symlinks inside the tree — an attacker-planted
/// symlink would otherwise copy its target's contents into the shared
/// image cache. All non-symlink regular files and directories are
/// copied. Sub-directories inherit the source directory's permission
/// bits; file contents are preserved bit-for-bit via `std::fs::copy`.
fn copy_and_remove_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_tree_iterative(src, dst)?;
    std::fs::remove_dir_all(src)
}

/// Iterative tree walker used by the EXDEV fallback.
///
/// Previously implemented as straight recursion, which worked in
/// practice for CC's flat `image-cache/<sid>/<file>` layout but had
/// no guardrail against pathologically deep attacker-planted trees.
/// Converted to an explicit work-queue so stack depth is bounded by
/// `DEPTH_LIMIT` regardless of filesystem contents.
fn copy_tree_iterative(root_src: &Path, root_dst: &Path) -> std::io::Result<()> {
    /// Defensive cap on walker depth. PATH_MAX on typical filesystems
    /// is 4096 bytes — an image-cache tree deep enough to hit this
    /// would already be malformed. The cap is `2048` so a legitimate
    /// nested CC project still fits with plenty of headroom.
    const DEPTH_LIMIT: usize = 2048;

    let mut stack: Vec<(PathBuf, PathBuf, usize)> =
        vec![(root_src.to_path_buf(), root_dst.to_path_buf(), 0)];

    while let Some((src, dst, depth)) = stack.pop() {
        if depth > DEPTH_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("copy_tree_iterative: depth limit {DEPTH_LIMIT} exceeded"),
            ));
        }

        let meta = src.symlink_metadata()?;
        if meta.file_type().is_symlink() {
            // Refuse to follow symlinks during copy.
            continue;
        }

        if meta.file_type().is_dir() {
            std::fs::create_dir_all(&dst)?;
            // Preserve the source directory's mode bits. `create_dir_all`
            // uses the process umask (typically dropping to 0755); CC
            // writes image-cache with 0700 under ~/.claude, so without
            // this the EXDEV fallback widens readability from private
            // to world-readable-within-mode.
            let _ = std::fs::set_permissions(&dst, meta.permissions());
            for entry in std::fs::read_dir(&src)? {
                let entry = entry?;
                stack.push((entry.path(), dst.join(entry.file_name()), depth + 1));
            }
        } else if meta.file_type().is_file() {
            std::fs::copy(&src, &dst)?;
        }
        // Sockets, fifos, device nodes — skip silently.
    }

    Ok(())
}

/// Merges `src_session` into an already-existing `dst_session`,
/// file-by-file. Preserves any file or sub-directory that already
/// exists at the destination (presumed to belong to a still-live
/// sibling terminal). Only moves entries whose full path at the
/// destination is clear.
///
/// This is the collision path of `preserve_image_cache`. It
/// replaces the previous "skip entirely" behavior so that
/// `--resume`d sessions across multiple handle dirs no longer drop
/// the second-to-sweep's newer images.
///
/// Iterative walker — bounded by the same `DEPTH_LIMIT` as
/// `copy_tree_iterative`. Refuses to follow symlinks at every
/// level. Returns the count of successfully-moved top-level
/// entries (files or whole sub-trees); individual failures are
/// logged and swallowed so a single bad entry doesn't block the
/// rest of the merge.
///
/// On EXDEV at merge time, falls back to copy-then-remove via
/// `copy_tree_iterative`.
fn merge_session_into_existing(src_session: &Path, dst_session: &Path) -> std::io::Result<usize> {
    const DEPTH_LIMIT: usize = 2048;
    let mut moved = 0;

    // Work-queue: (src, dst, depth). Each dir that already exists at
    // the destination is expanded so we can merge into it per file.
    let mut stack: Vec<(PathBuf, PathBuf, usize)> =
        vec![(src_session.to_path_buf(), dst_session.to_path_buf(), 0)];

    while let Some((src, dst, depth)) = stack.pop() {
        if depth > DEPTH_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("merge_session_into_existing: depth limit {DEPTH_LIMIT} exceeded"),
            ));
        }

        let entries = match std::fs::read_dir(&src) {
            Ok(e) => e,
            Err(e) => {
                warn!(path = %src.display(), error = %e, "merge: failed to read source dir");
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "merge: entry read failed");
                    continue;
                }
            };

            let child_src = entry.path();
            let child_meta = match child_src.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if child_meta.file_type().is_symlink() {
                // Refuse to follow symlinks — same policy as the
                // preservation walker above.
                continue;
            }

            let child_dst = dst.join(entry.file_name());

            if let Ok(dst_meta) = child_dst.symlink_metadata() {
                // Destination already exists. For files, preserve the
                // existing (live) version. For two-sided directories,
                // recurse to merge unique entries inside. For symlinks
                // at the destination (defense-in-depth — should not
                // happen since we control the shared cache), refuse
                // to traverse and preserve the existing entry.
                if dst_meta.file_type().is_symlink() {
                    warn!(
                        entry = %child_dst.display(),
                        "merge: destination entry is a symlink, refusing to recurse"
                    );
                    continue;
                }
                if dst_meta.file_type().is_dir() && child_meta.file_type().is_dir() {
                    stack.push((child_src, child_dst, depth + 1));
                }
                // Else: preserve existing destination entry, skip.
                continue;
            }

            // Destination is clear — move the whole entry in.
            match std::fs::rename(&child_src, &child_dst) {
                Ok(_) => moved += 1,
                Err(e) if is_cross_device(&e) => {
                    if child_meta.file_type().is_dir() {
                        if let Err(e) = copy_and_remove_tree(&child_src, &child_dst) {
                            warn!(
                                entry = %child_src.display(),
                                error = %e,
                                "merge: EXDEV fallback failed for sub-tree"
                            );
                        } else {
                            moved += 1;
                        }
                    } else if child_meta.file_type().is_file() {
                        if let Err(e) = std::fs::copy(&child_src, &child_dst) {
                            warn!(
                                entry = %child_src.display(),
                                error = %e,
                                "merge: EXDEV file copy failed"
                            );
                        } else {
                            let _ = std::fs::remove_file(&child_src);
                            moved += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        entry = %child_src.display(),
                        error = %e,
                        "merge: rename failed"
                    );
                }
            }
        }
    }

    // Best-effort: clean up the drained source session directory.
    // If anything is left (all files collided), remove_dir will fail
    // silently — we prefer that to `remove_dir_all` which might wipe
    // a sub-tree we just failed to merge.
    let _ = std::fs::remove_dir(src_session);

    Ok(moved)
}

/// Checks if the handle dir at `CLAUDE_CONFIG_DIR` is a `term-<pid>` dir.
/// Returns the resolved path if it is, or an error string if it's a legacy `config-N`.
pub fn resolve_handle_dir_from_env(base_dir: &Path) -> Result<PathBuf, String> {
    let raw = std::env::var("CLAUDE_CONFIG_DIR")
        .map_err(|_| "CLAUDE_CONFIG_DIR not set — run inside a csq-managed session".to_string())?;

    let config_dir = PathBuf::from(&raw);
    let dir_name = config_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if dir_name.starts_with("config-") {
        return Err(format!(
            "This terminal is using the legacy config-dir model ({dir_name}). \
             Swap affects ALL terminals sharing this config dir. \
             Relaunch with `csq run N` for per-terminal handle-dir isolation."
        ));
    }

    if !dir_name.starts_with("term-") {
        return Err(format!(
            "CLAUDE_CONFIG_DIR does not point to a csq handle dir: {raw}"
        ));
    }

    // Verify it's under base_dir
    let canon_base = base_dir
        .canonicalize()
        .map_err(|e| format!("bad base: {e}"))?;
    let canon_dir = config_dir
        .canonicalize()
        .map_err(|e| format!("bad config dir: {e}"))?;

    if !canon_dir.starts_with(&canon_base) {
        return Err(format!(
            "CLAUDE_CONFIG_DIR escapes base directory: {}",
            canon_dir.display()
        ));
    }

    Ok(canon_dir)
}

/// Cross-platform PID liveness check.
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) succeeds if the process exists AND we have permission.
        // ESRCH (3) = no such process. EPERM (1) = exists but different user.
        //
        // Uses `io::Error::last_os_error` rather than `libc::__error` /
        // `libc::__errno_location` directly — the stdlib wrapper is
        // portable across Linux/macOS/BSD without platform-specific
        // symbol juggling.
        // SAFETY: kill(pid, 0) is a pure syscall with no memory effects.
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return true;
        }
        // Any error other than ESRCH (no such process) means the
        // process exists but we couldn't signal it — EPERM (different
        // user), EINVAL (shouldn't happen for sig 0), etc.
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[cfg(windows)]
    {
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Sweep interval: 60 seconds.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Handle to a running sweep task.
pub struct SweepHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns a periodic handle-dir sweep task.
///
/// Scans `base_dir/term-*/` every 60 seconds and removes orphans
/// whose recorded owner PID is no longer alive. Pasted images under
/// each dead dir's `image-cache/` are moved to
/// `claude_home/image-cache/` so they survive the sweep (see journal
/// 0035).
///
/// `claude_home` is `Option<PathBuf>` so callers that cannot resolve
/// `~/.claude` (rare sandbox case with no `$HOME`) can pass `None`
/// and fall back to sweep-without-preservation rather than routing
/// images into a fallback directory that CC will never find. Shares
/// a cancellation token with the daemon so it stops on shutdown.
pub fn spawn_sweep(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: tokio_util::sync::CancellationToken,
) -> SweepHandle {
    let join = tokio::spawn(async move {
        // Small startup delay to avoid racing with session creation
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }

        // Worklist for the keychain orphan sweep, carried across ticks so a
        // large backlog drains a bounded batch per tick.
        let mut orphan_state = Some(keychain::orphans::OrphanSweepState::default());
        loop {
            let dir = base_dir.clone();
            let home = claude_home.clone();
            let _ = tokio::task::spawn_blocking(move || sweep_dead_handles(&dir, home.as_deref()))
                .await;

            // Security review 1386 H1: retry any macOS keychain OAuth item a
            // logout could not confirm clearing (locked/unreachable keychain
            // at the time). Piggybacks on this existing 60s tick rather than
            // its own timer — cheap when the queue is empty (one file read,
            // no subprocess calls), and this is the recurring channel for any
            // install that runs the daemon; `csq run` carries the same sweep
            // for the headless/no-daemon case.
            let dir = base_dir.clone();
            let _ = tokio::task::spawn_blocking(move || {
                crate::credentials::keychain::sweep_pending_clears(&dir)
            })
            .await;

            // Delete `Claude Code-credentials-<hash>` items whose dir no longer
            // exists and that are provably not the last copy of a login —
            // the items the per-dir reaper above never reaches (dir removed
            // by a crash/rm, or its clear evicted from the retry queue).
            // Bounded batch per tick; see `keychain::orphans`.
            if let Some(mut state) = orphan_state.take() {
                let dir = base_dir.clone();
                orphan_state = tokio::task::spawn_blocking(move || {
                    keychain::orphans::sweep_orphans(&dir, &mut state);
                    state
                })
                .await
                .ok();
                if orphan_state.is_none() {
                    // The blocking task panicked; the worklist is lost, so
                    // start over (the next enumeration rebuilds it).
                    warn!(
                        error_kind = "keychain_orphan_sweep_task_failed",
                        "orphan sweep task failed; restarting its worklist"
                    );
                    orphan_state = Some(keychain::orphans::OrphanSweepState::default());
                }
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("handle-dir sweep cancelled, exiting");
                    return;
                }
                _ = tokio::time::sleep(SWEEP_INTERVAL) => {}
            }
        }
    });

    SweepHandle { join }
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs just before the local `hooks.json` is detached in
    /// [`link_codex_global_hooks`], so a test can edit the local file in that window.
    static BEFORE_REREAD: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
    /// Test seam: makes [`link_codex_global_hooks`] see a COPY where the symlink should be,
    /// as a platform without symlink privilege would.
    static FORCE_COPY_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test seam: runs right after a hooks entry was detached and before the link is created,
    /// so a test can recreate `hooks.json` in that window.
    static AFTER_ASIDE: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Platform-specific symlink creation.
fn create_symlink(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    isolation::create_symlink_pub(target, link)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn materializer_keeps_exact_native_root_trust_without_root_resume_state() {
        use super::build_scoped_claude_json_at;
        use serde_json::json;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let cwd = root.join("child");
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        let root_key = root.to_str().unwrap();
        let cwd_key = cwd.to_str().unwrap();
        let source = root.join("source.json");
        let old = root.join("old.json");
        std::fs::write(&source, json!({"projects":{root_key:{"hasTrustDialogAccepted":true,"disabledMcpServers":["source-disabled"],"enabledMcpServers":["source-enabled"],"lastSessionId":"foreign-session"},cwd_key:{"lastSessionId":"current-session"},"/unrelated":{"hasTrustDialogAccepted":true}}}).to_string()).unwrap();
        let actual = build_scoped_claude_json_at(&source, None, &cwd).unwrap();
        assert_eq!(
            actual["projects"][root_key],
            json!({"hasTrustDialogAccepted":true,"disabledMcpServers":["source-disabled"],"enabledMcpServers":["source-enabled"]}),
            "the already-accepted native root must survive materialization"
        );
        assert_eq!(
            actual["projects"][cwd_key]["lastSessionId"],
            "current-session"
        );
        assert!(actual["projects"].get("/unrelated").is_none());
        std::fs::write(&old, json!({"projects":{root_key:{"hasTrustDialogAccepted":false,"disabledMcpServers":[],"enabledMcpServers":[],"lastSessionId":"another-root-session"}}}).to_string()).unwrap();
        let swapped = build_scoped_claude_json_at(&source, Some(&old), &cwd).unwrap();
        assert_eq!(
            swapped["projects"][root_key],
            json!({"hasTrustDialogAccepted":false,"disabledMcpServers":[],"enabledMcpServers":[]}),
            "a newer exact session trust revocation must win on swap"
        );
        std::fs::write(
            &source,
            json!({"projects":{"/":{"hasTrustDialogAccepted":true}}}).to_string(),
        )
        .unwrap();
        let untrusted = build_scoped_claude_json_at(&source, None, &cwd).unwrap();
        assert!(
            untrusted["projects"].get(root_key).is_none(),
            "ancestor trust cannot manufacture exact root trust"
        );
    }

    /// Self-heal: an EMPTY directory where a file belongs is repaired, because a
    /// host provisioned before the kind was declared already has one and the
    /// create branch never runs for an existing target.
    #[test]
    fn repair_converts_empty_dir_to_file() {
        use super::{repair_wrong_shaped_target, SharedKind};
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("codex-version.json");
        std::fs::create_dir(&t).unwrap();

        repair_wrong_shaped_target("version.json", &t, SharedKind::File);

        assert!(t.is_file(), "empty dir should have been replaced by a file");
    }

    /// The safety half: a NON-EMPTY directory is never destroyed, even though it
    /// is the wrong shape. Self-healing that can delete user state is worse than
    /// the bug it fixes; `csq doctor` surfaces this case instead.
    #[test]
    fn repair_refuses_to_destroy_a_non_empty_dir() {
        use super::{repair_wrong_shaped_target, SharedKind};
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("codex-models_cache.json");
        std::fs::create_dir(&t).unwrap();
        std::fs::write(t.join("something-a-user-cares-about"), b"data").unwrap();

        repair_wrong_shaped_target("models_cache.json", &t, SharedKind::File);

        assert!(t.is_dir(), "non-empty dir must be left alone");
        assert!(
            t.join("something-a-user-cares-about").exists(),
            "contents must survive"
        );
    }

    /// The other direction: a FILE where a directory belongs is also left alone —
    /// it may hold content, and removing it is not provably safe.
    #[test]
    fn repair_refuses_to_delete_a_file_where_a_dir_belongs() {
        use super::{repair_wrong_shaped_target, SharedKind};
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("codex-skills");
        std::fs::write(&t, b"not empty").unwrap();

        repair_wrong_shaped_target("skills", &t, SharedKind::Dir);

        assert!(t.is_file(), "file must be left alone");
        assert_eq!(std::fs::read(&t).unwrap(), b"not empty");
    }

    /// A correctly-shaped target is untouched (no churn on the happy path).
    #[test]
    fn repair_leaves_a_correct_target_alone() {
        use super::{repair_wrong_shaped_target, SharedKind};
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("codex-version.json");
        std::fs::write(&f, b"v").unwrap();
        repair_wrong_shaped_target("version.json", &f, SharedKind::File);
        assert!(f.is_file());
        assert_eq!(std::fs::read(&f).unwrap(), b"v");

        let dir = d.path().join("codex-skills");
        std::fs::create_dir(&dir).unwrap();
        repair_wrong_shaped_target("skills", &dir, SharedKind::Dir);
        assert!(dir.is_dir());
    }

    /// REGRESSION (2026-08-30): every shared codex-home entry must be created
    /// with the shape codex-cli actually uses. The kind used to be INFERRED
    /// from the filename (`.jsonl`/`.sqlite` => file, everything else =>
    /// directory), so `version.json`, `models_cache.json` and
    /// `installation_id` — all FILES in a real `~/.codex` — were pre-created as
    /// DIRECTORIES. codex-cli then aborted with `failed to start embedded app
    /// server`, an error naming neither the entry nor the shape.
    ///
    /// Pinned against the shapes observed in a live `~/.codex`, so a future
    /// entry added with the wrong kind fails here rather than at a user's spawn.
    #[test]
    fn shared_codex_state_declares_the_shape_codex_actually_uses() {
        use super::{SharedKind, CODEX_SHARED_STATE};

        // name -> the shape codex-cli uses (verified on a live ~/.codex).
        let expected: &[(&str, SharedKind)] = &[
            ("sessions", SharedKind::Dir),
            ("history.jsonl", SharedKind::File),
            ("skills", SharedKind::Dir),
            ("plugins", SharedKind::Dir),
            ("session_index.jsonl", SharedKind::File),
            ("models_cache.json", SharedKind::File),
            ("version.json", SharedKind::File),
            ("installation_id", SharedKind::File),
            ("thread-writer-locks", SharedKind::Dir),
        ];

        for (name, want) in expected {
            let got = CODEX_SHARED_STATE
                .iter()
                .find(|(n, _, _)| n == name)
                .unwrap_or_else(|| panic!("{name} missing from CODEX_SHARED_STATE"))
                .2;
            assert_eq!(got, *want, "{name} declares the wrong shape");
        }

        // Every entry is covered above: a new one must state its kind here too,
        // which is the point — the list cannot grow silently.
        assert_eq!(
            CODEX_SHARED_STATE.len(),
            expected.len(),
            "CODEX_SHARED_STATE changed; add the new entry (and its real shape) to this test"
        );

        // The old heuristic's exact blind spot: a `.json` file is NOT a directory.
        for (name, _, kind) in CODEX_SHARED_STATE {
            if name.ends_with(".json") {
                assert_eq!(*kind, SharedKind::File, "{name} is a .json FILE, not a dir");
            }
        }
    }
    use super::*;
    use tempfile::TempDir;

    // ── interactive-capture-* sweep (redteam R2 Q4) ──────────────────────────

    fn make_capture_dir(base: &Path, suffix: &str, live_pid: Option<u32>) -> PathBuf {
        let dir = base.join(format!("{CAPTURE_DIR_PREFIX}{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(pid) = live_pid {
            std::fs::write(dir.join(".live-pid"), pid.to_string()).unwrap();
        }
        dir
    }

    #[test]
    fn sweep_capture_reaps_dead_pid_dir() {
        let base = TempDir::new().unwrap();
        // 999_999_999 is not a live pid on any sane system.
        let dir = make_capture_dir(base.path(), "999999999-0", Some(999_999_999));
        assert_eq!(sweep_stale_capture_dirs(base.path()), 1);
        assert!(!dir.exists(), "dead-pid capture dir must be reaped");
    }

    #[test]
    fn sweep_capture_keeps_live_pid_dir() {
        let base = TempDir::new().unwrap();
        let dir = make_capture_dir(base.path(), "self-0", Some(std::process::id()));
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(dir.exists(), "live-pid capture dir must be kept");
    }

    #[test]
    fn sweep_capture_keeps_fresh_pidless_sibling() {
        // A dir with no `.live-pid` yet is a concurrent sibling mid-setup: KEEP
        // (it is younger than CAPTURE_REAP_GRACE).
        let base = TempDir::new().unwrap();
        let dir = make_capture_dir(base.path(), "sibling-0", None);
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(dir.exists(), "fresh pid-less sibling must not be reaped");
    }

    #[test]
    fn sweep_capture_ignores_non_capture_dirs() {
        let base = TempDir::new().unwrap();
        std::fs::create_dir_all(base.path().join("term-12345")).unwrap();
        std::fs::create_dir_all(base.path().join("config-1")).unwrap();
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(base.path().join("term-12345").exists());
        assert!(base.path().join("config-1").exists());
    }

    // ── codex-exec-*/gemini-exec-* sweep (permanent-leak fix) ────────────────
    //
    // 54 orphaned `codex-exec-<pid>` dirs were found on a maintainer host —
    // `csq exec`'s best-effort cleanup never ran (kill/panic/early-return) and
    // no sweeper's `term-`-only name check recognized the shape.

    fn make_exec_dir(base: &Path, prefix: &str, pid: u32, live_pid: Option<u32>) -> PathBuf {
        let dir = base.join(format!("{prefix}{pid}"));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(marker_pid) = live_pid {
            std::fs::write(dir.join(".live-pid"), marker_pid.to_string()).unwrap();
        }
        dir
    }

    #[test]
    fn sweep_exec_reaps_dead_codex_dir_via_live_pid_marker() {
        // codex-exec-* always writes .live-pid (create_handle_dir_codex_named).
        // A dead marker PID must be reaped even though the dir-name PID differs
        // (proves the marker, not just the name, is consulted).
        let base = TempDir::new().unwrap();
        let dir = make_exec_dir(base.path(), EXEC_CODEX_DIR_PREFIX, 111, Some(999_999_999));
        assert_eq!(sweep_stale_exec_dirs(base.path()), 1);
        assert!(
            !dir.exists(),
            "dead-marker-pid codex-exec dir must be reaped"
        );
    }

    #[test]
    fn sweep_exec_keeps_live_codex_dir_via_live_pid_marker() {
        // Non-vacuity pair for the above: a LIVE marker pid must be kept even
        // though the dir-name pid (999_999_998) is a dead placeholder — proves
        // the reaper is not merely deleting everything.
        let base = TempDir::new().unwrap();
        let dir = make_exec_dir(
            base.path(),
            EXEC_CODEX_DIR_PREFIX,
            999_999_998,
            Some(std::process::id()),
        );
        assert_eq!(sweep_stale_exec_dirs(base.path()), 0);
        assert!(dir.exists(), "live-marker-pid codex-exec dir must be kept");
    }

    #[test]
    fn sweep_exec_reaps_dead_gemini_dir_via_dir_name_pid() {
        // gemini-exec-* never writes .live-pid (its producer bypasses the
        // shared handle-dir helpers) — the reaper MUST fall back to the PID
        // embedded in the dir name itself.
        let base = TempDir::new().unwrap();
        let dir = make_exec_dir(base.path(), EXEC_GEMINI_DIR_PREFIX, 999_999_997, None);
        assert_eq!(sweep_stale_exec_dirs(base.path()), 1);
        assert!(
            !dir.exists(),
            "dead dir-name-pid gemini-exec dir must be reaped"
        );
    }

    #[test]
    fn sweep_exec_keeps_live_gemini_dir_via_dir_name_pid() {
        // Safety-critical direction: a live process's gemini-exec dir (no
        // marker at all) MUST NOT be reaped — this is the exact scenario the
        // task's safety requirement names ("a live dir MUST NOT be reaped").
        let base = TempDir::new().unwrap();
        let own_pid = std::process::id();
        let dir = make_exec_dir(base.path(), EXEC_GEMINI_DIR_PREFIX, own_pid, None);
        assert_eq!(sweep_stale_exec_dirs(base.path()), 0);
        assert!(dir.exists(), "live gemini-exec dir must be kept");
    }

    #[test]
    fn sweep_exec_ignores_non_exec_dirs() {
        let base = TempDir::new().unwrap();
        std::fs::create_dir_all(base.path().join("term-12345")).unwrap();
        std::fs::create_dir_all(base.path().join("config-1")).unwrap();
        std::fs::create_dir_all(base.path().join(format!("{CAPTURE_DIR_PREFIX}999999999-0")))
            .unwrap();
        assert_eq!(sweep_stale_exec_dirs(base.path()), 0);
        assert!(base.path().join("term-12345").exists());
        assert!(base.path().join("config-1").exists());
    }

    #[test]
    fn sweep_exec_skips_unparseable_suffix_fail_safe() {
        // A dir shaped like "codex-exec-<not-a-number>" doesn't match the
        // <prefix><pid> shape this reaper understands. Fail safe: skip, don't
        // guess (reconciler-cleanup-parity.md Rule 5 — KEEP on any doubt).
        let base = TempDir::new().unwrap();
        let dir = base
            .path()
            .join(format!("{EXEC_CODEX_DIR_PREFIX}not-a-pid"));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(sweep_stale_exec_dirs(base.path()), 0);
        assert!(dir.exists(), "unparseable-suffix dir must be kept");
    }

    #[test]
    fn sweep_dead_handles_reaps_orphaned_exec_dirs_end_to_end() {
        // sweep_dead_handles is the function actually wired into the 60s
        // daemon watcher (spawn_sweep) — prove the exec-dir reap is reachable
        // from THAT entrypoint, not only from the unit-level helper.
        let base = TempDir::new().unwrap();
        let dead = make_exec_dir(base.path(), EXEC_CODEX_DIR_PREFIX, 111, Some(999_999_996));
        let live = make_exec_dir(
            base.path(),
            EXEC_GEMINI_DIR_PREFIX,
            std::process::id(),
            None,
        );
        let removed = sweep_dead_handles(base.path(), None);
        assert_eq!(removed, 1);
        assert!(
            !dead.exists(),
            "orphaned codex-exec dir reaped via sweep_dead_handles"
        );
        assert!(
            live.exists(),
            "live gemini-exec dir untouched via sweep_dead_handles"
        );
    }

    // ── ephemeral handle-dir prefix registry (positive allowlist) ────────────

    #[test]
    fn assert_dir_name_prefix_registered_accepts_every_registered_prefix() {
        for name in [
            "term-123",
            "interactive-capture-1-0",
            "codex-exec-1",
            "gemini-exec-1",
        ] {
            assert!(
                assert_dir_name_prefix_registered(name).is_ok(),
                "registered-prefix name '{name}' must be accepted"
            );
        }
    }

    #[test]
    fn assert_dir_name_prefix_registered_rejects_unregistered_prefix() {
        // Non-vacuity: an unregistered producer prefix MUST fail loudly at
        // creation time rather than silently mint a dir no sweeper recognizes.
        let err = assert_dir_name_prefix_registered("foo-exec-123")
            .expect_err("unregistered prefix must be rejected");
        match err {
            CredentialError::Corrupt { reason, .. } => {
                assert!(reason.contains("EPHEMERAL_HANDLE_DIR_PREFIXES"));
            }
            other => panic!("expected CredentialError::Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn create_handle_dir_named_rejects_unregistered_dir_name() {
        // End-to-end: the guard is actually wired into the production
        // constructor, not just callable in isolation.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        setup_config_dir(base, 1);
        let result = create_handle_dir_named(
            base,
            &claude_home,
            account,
            4242,
            "unregistered-prefix-4242",
        );
        assert!(result.is_err(), "unregistered dir_name must be refused");
        assert!(
            !base.join("unregistered-prefix-4242").exists(),
            "no directory should be created on refusal"
        );
    }

    #[test]
    fn create_handle_dir_codex_named_rejects_unregistered_dir_name() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(base.join("credentials")).unwrap();
        std::fs::write(base.join("credentials").join("codex-1.json"), "{}").unwrap();
        let result = create_handle_dir_codex_named(base, account, 4242, "unregistered-prefix-4242");
        assert!(result.is_err(), "unregistered dir_name must be refused");
        assert!(
            !base.join("unregistered-prefix-4242").exists(),
            "no directory should be created on refusal"
        );
    }

    #[test]
    fn find_unregistered_ephemeral_looking_dirs_flags_unregistered_producer() {
        // Non-vacuity (fires): an unregistered producer's dir is surfaced.
        let base = TempDir::new().unwrap();
        std::fs::create_dir_all(base.path().join("foo-exec-1234")).unwrap();
        let unrecognized = find_unregistered_ephemeral_looking_dirs(base.path());
        assert_eq!(unrecognized, vec!["foo-exec-1234".to_string()]);
    }

    #[test]
    fn find_unregistered_ephemeral_looking_dirs_silent_on_registered_and_permanent() {
        // Non-vacuity (silent): every registered prefix AND every known
        // permanent dir must NOT be flagged — proves the detector isn't
        // simply flagging everything.
        let base = TempDir::new().unwrap();
        for name in [
            "term-1",
            "interactive-capture-1-0",
            "codex-exec-1",
            "gemini-exec-1",
            "config-1",
            "config-42",
            "identities",
            "credentials",
        ] {
            std::fs::create_dir_all(base.path().join(name)).unwrap();
        }
        // Hidden state (lock files, tombstones) and non-directory entries are
        // also excluded.
        std::fs::create_dir_all(base.path().join(".swap-lock")).unwrap();
        std::fs::write(base.path().join("profiles.json"), "{}").unwrap();
        let unrecognized = find_unregistered_ephemeral_looking_dirs(base.path());
        assert!(
            unrecognized.is_empty(),
            "expected no unrecognized dirs, got {unrecognized:?}"
        );
    }

    #[test]
    fn dir_age_exceeds_keeps_fresh_dir() {
        // A freshly created dir is NOT older than an hour → KEEP (false). This is
        // the safety-critical direction (never reap a fresh sibling).
        let base = TempDir::new().unwrap();
        let dir = base.path().join("fresh");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!dir_age_exceeds(&dir, std::time::Duration::from_secs(3600)));
    }

    #[test]
    fn dir_age_exceeds_reaps_when_older_than_grace() {
        // The reap direction: any real dir's age exceeds a ZERO grace, so a
        // pidless crash-leak older than CAPTURE_REAP_GRACE is reapable.
        let base = TempDir::new().unwrap();
        let dir = base.path().join("old");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir_age_exceeds(&dir, std::time::Duration::ZERO));
    }

    #[test]
    fn dir_age_exceeds_missing_dir_is_false() {
        // Stat error → KEEP (fail safe).
        let base = TempDir::new().unwrap();
        assert!(!dir_age_exceeds(
            &base.path().join("nope"),
            std::time::Duration::ZERO
        ));
    }

    fn setup_config_dir(base: &Path, account: u16) -> PathBuf {
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();
        // Write minimal credential marker
        std::fs::write(config.join(".csq-account"), account.to_string()).unwrap();
        std::fs::write(config.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config.join("settings.json"), "{}").unwrap();
        std::fs::write(config.join(".claude.json"), "{}").unwrap();
        config
    }

    // Positive swap fixtures establish authority through the real verified-login
    // publication/finalization APIs. The fake transport proves the exact grant;
    // no direct CapturedBinding/VerifiedAnthropicContext constructor is used.
    fn stage_verified_repoint_slots(base: &Path, slots: &[u16]) {
        use crate::accounts::anthropic_identity as ai;
        use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
        // Two passes, deliberately: every commit below walks EVERY sibling's saved
        // credential for the held-elsewhere comparison, so every slot's prior must be
        // structurally valid BEFORE the first walk. Old coexisting fixtures carry
        // deliberately minimal '{}' bytes, which the strict comparison reader cannot
        // parse (SiblingCustodyUnreadable), so a single stage-then-commit pass refuses
        // on the still-minimal priors of the slots staged after the first one.
        struct Staged {
            slot: AccountNum,
            native_path: std::path::PathBuf,
            native: Option<Vec<u8>>,
            json: Value,
            email: String,
            account_uuid: uuid::Uuid,
            organization_uuid: uuid::Uuid,
            access: String,
            credential: CredentialFile,
        }
        let mut staged: Vec<Staged> = Vec::new();
        for &n in slots {
            let config = base.join(format!("config-{n}"));
            if !config.exists() {
                continue;
            }
            let slot = AccountNum::try_from(n).unwrap();
            let native_path = config.join(".claude.json");
            let native = std::fs::read(&native_path).ok();
            let json: Value = native
                .as_ref()
                .map(|b| serde_json::from_slice(b).unwrap())
                .unwrap_or_else(|| serde_json::json!({}));
            let email = json
                .pointer("/oauthAccount/emailAddress")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("fixture-slot-{n}@test.invalid"));
            let account_uuid =
                uuid::Uuid::parse_str(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap();
            let organization_uuid =
                uuid::Uuid::parse_str(&format!("11111111-1111-4111-8111-{n:012x}")).unwrap();
            let access = format!("fake-repoint-access-{n}");
            let credential = CredentialFile::Anthropic(AnthropicCredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: crate::types::AccessToken::new(access.clone()),
                    refresh_token: crate::types::RefreshToken::new(format!(
                        "fake-repoint-refresh-{n}"
                    )),
                    expires_at: 4_102_444_800_000, // 2100: fixture must outlive the codebase.
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: std::collections::HashMap::new(),
                },
                extra: std::collections::HashMap::new(),
            });
            // Make that prior credential structurally valid before any capture roams
            // it; it remains LegacyUnknown, and verified publication selects a new ID.
            if let Some(id) = profiles::resolve_slot_to_uuid(base, n) {
                let prior_path = crate::accounts::identity_store::credentials_path_for(base, id);
                crate::credentials::save(&prior_path, &credential).unwrap();
            }
            staged.push(Staged {
                slot,
                native_path,
                native,
                json,
                email,
                account_uuid,
                organization_uuid,
                access,
                credential,
            });
        }
        for Staged {
            slot,
            native_path,
            native,
            mut json,
            email,
            account_uuid,
            organization_uuid,
            access,
            credential,
        } in staged
        {
            let http: crate::daemon::usage_poller::HttpGetFn =
                std::sync::Arc::new(move |url, bearer, headers| {
                    assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
                    assert_eq!(
                        bearer, access,
                        "fixture must prove its exact incoming grant"
                    );
                    assert_eq!(headers, &[("anthropic-beta", "oauth-2025-04-20")]);
                    Ok((
                        200,
                        serde_json::to_vec(&serde_json::json!({
                            "account":{"uuid":account_uuid,"email":email},
                            "organization":{"uuid":organization_uuid},
                        }))
                        .unwrap(),
                    ))
                });
            let prior = ai::capture_login_prior(base, slot).unwrap();
            let committed =
                ai::commit_anthropic_login_with(base, slot, &credential, &http, None, prior)
                    .unwrap();
            let ai::StoredAnthropicContext::Known(context) = committed.context() else {
                panic!("verified fixture publication must yield Known context");
            };
            let native_account = serde_json::json!({"emailAddress":context.email(),
                "accountUuid":context.account_uuid(),"organizationUuid":context.organization_uuid()});
            crate::accounts::login::finalize_verified_login(base, slot, committed).unwrap();
            // Retain an intentionally absent target file; the missing-target
            // reconciliation test still exercises that exact branch.
            if native.is_some() {
                json["oauthAccount"] = native_account;
                std::fs::write(&native_path, serde_json::to_vec(&json).unwrap()).unwrap();
                crate::platform::fs::secure_file(&native_path).unwrap();
            }
        }
    }

    #[cfg(unix)]
    fn verified_fixture_credentials(base: &Path, slot: u16) -> PathBuf {
        let id = profiles::resolve_slot_to_uuid(base, slot).unwrap();
        crate::accounts::identity_store::credentials_path_for(base, id)
    }

    fn repoint_verified_fixture(
        base: &Path,
        home: &Path,
        handle: &Path,
        slot: AccountNum,
    ) -> Result<(), CredentialError> {
        let binding = crate::accounts::anthropic_identity::capture_anthropic_binding(base, slot)
            .map_err(|_| crate::accounts::anthropic_identity::credential_refusal())?;
        let native = capture_native_swap(base, handle)?;
        repoint_handle_dir_guarded(base, home, handle, &binding, &native)
    }

    fn repoint_fixture_snapshot(
        base: &Path,
    ) -> std::collections::BTreeMap<PathBuf, (u32, u8, Vec<u8>, std::time::SystemTime)> {
        fn visit(
            root: &Path,
            path: &Path,
            out: &mut std::collections::BTreeMap<
                PathBuf,
                (u32, u8, Vec<u8>, std::time::SystemTime),
            >,
        ) {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode()
            };
            #[cfg(not(unix))]
            let mode = u32::from(metadata.permissions().readonly());
            let (kind, bytes) = if metadata.file_type().is_symlink() {
                (
                    1,
                    std::fs::read_link(path)
                        .unwrap()
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec(),
                )
            } else if metadata.is_dir() {
                (2, vec![])
            } else {
                (3, std::fs::read(path).unwrap())
            };
            out.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                (mode, kind, bytes, metadata.modified().unwrap()),
            );
            if metadata.is_dir() {
                for entry in std::fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), out);
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        visit(base, base, &mut out);
        out
    }

    #[cfg(unix)]
    fn assert_verified_repoint_race(
        base: &Path,
        home: &Path,
        handle: &Path,
        first: (
            Result<(), CredentialError>,
            crate::accounts::anthropic_identity::CapturedBinding,
            NativeSwapCapture,
        ),
        second: (
            Result<(), CredentialError>,
            crate::accounts::anthropic_identity::CapturedBinding,
            NativeSwapCapture,
        ),
    ) {
        assert_ne!(
            first.0.is_ok(),
            second.0.is_ok(),
            "same-source snapshots must yield exactly one winner"
        );
        let (winner, loser) = if first.0.is_ok() {
            (&first, &second)
        } else {
            (&second, &first)
        };
        assert!(
            matches!(&loser.0, Err(CredentialError::Corrupt { reason, .. }) if reason == "identity_authority_refused")
        );
        assert_eq!(
            markers::resolve_marker_to_slot(base, handle),
            Some(winner.1.slot())
        );
        assert!(handle_dir_symlinks_are_consistent(base, handle));
        assert_eq!(
            std::fs::read_link(handle.join(".credentials.json")).unwrap(),
            verified_fixture_credentials(base, winner.1.slot().get())
        );
        assert_eq!(
            read_materialized_settings(handle)["fixtureWinner"],
            serde_json::json!(winner.1.slot().get())
        );
        let native: Value =
            serde_json::from_slice(&std::fs::read(handle.join(".claude.json")).unwrap()).unwrap();
        let crate::accounts::anthropic_identity::StoredAnthropicContext::Known(context) =
            winner.1.context()
        else {
            panic!("Known winner required")
        };
        assert_eq!(
            crate::accounts::anthropic_identity::parse_native_expectation(&native)
                .unwrap()
                .context(),
            context
        );
        // Replay the exact rejected snapshot after the winner has closed. This
        // verifies the loser cannot write a partial channel after serialization.
        let before = (
            repoint_fixture_snapshot(base),
            repoint_fixture_snapshot(home),
        );
        let replay = repoint_handle_dir_guarded(base, home, handle, &loser.1, &loser.2);
        assert!(
            matches!(replay, Err(CredentialError::Corrupt { reason, .. }) if reason == "identity_authority_refused")
        );
        assert_eq!(
            before,
            (
                repoint_fixture_snapshot(base),
                repoint_fixture_snapshot(home)
            )
        );
    }

    /// Hold the term mint lock from ANOTHER thread, as a sweep in another
    /// process would; returns (release, join).
    fn hold_mint_lock_elsewhere(
        base: &Path,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let base = base.to_path_buf();
        let join = std::thread::spawn(move || {
            let _guard = crate::session::term_mint::acquire_for_mint(&base).unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx.recv().unwrap();
        (release_tx, join)
    }

    /// RED against a creator that does not take the term mint lock: with the
    /// lock held elsewhere, a `term-<pid>` creation REFUSES with the fixed
    /// message and creates nothing; once the lock is free it succeeds.
    #[test]
    fn create_handle_dir_refuses_without_the_term_mint_lock_and_creates_nothing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        let _short = crate::session::term_mint::ShortWait::set();

        let (release, join) = hold_mint_lock_elsewhere(base);
        let err = create_handle_dir(base, &claude_home, account, 77_001).unwrap_err();
        let shown = format!("{err}");
        assert!(
            shown.contains("term mint lock busy"),
            "fixed refusal message, got {shown}"
        );
        assert!(
            !base.join("term-77001").exists(),
            "a refused creation must not leave a dir behind"
        );
        release.send(()).unwrap();
        join.join().unwrap();
        create_handle_dir(base, &claude_home, account, 77_001).unwrap();
        assert!(base.join("term-77001").is_dir());
    }

    /// The Codex creator mints the same `term-<pid>` shape, so it takes the same
    /// lock: refused with the fixed message and no dir while it is held.
    #[test]
    fn create_handle_dir_codex_refuses_without_the_term_mint_lock() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_config_dir(base, 1);
        std::fs::create_dir_all(base.join("credentials")).unwrap();
        std::fs::write(base.join("credentials").join("codex-1.json"), "{}").unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        let _short = crate::session::term_mint::ShortWait::set();

        let (release, join) = hold_mint_lock_elsewhere(base);
        let err = create_handle_dir_codex(base, account, 77_002).unwrap_err();
        assert!(
            format!("{err}").contains("term mint lock busy"),
            "fixed refusal message, got {err}"
        );
        assert!(!base.join("term-77002").exists());
        release.send(()).unwrap();
        join.join().unwrap();
    }

    /// Capture dirs are not `term-<pid>` and are outside the sweep's contract:
    /// they never wait on the term mint lock.
    #[test]
    fn a_capture_dir_does_not_take_the_term_mint_lock() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        let _short = crate::session::term_mint::ShortWait::set();

        let (release, join) = hold_mint_lock_elsewhere(base);
        let name = format!("{CAPTURE_DIR_PREFIX}test-1");
        create_handle_dir_named(base, &claude_home, account, 77_003, &name).unwrap();
        assert!(base.join(&name).is_dir());
        release.send(()).unwrap();
        join.join().unwrap();
    }

    /// The lock is held for the `create_dir` alone: after a creation returns it
    /// is free (a sweep can take it), and the creation took no other lock
    /// while holding it (the order violation would have refused it).
    #[test]
    fn create_handle_dir_releases_the_term_mint_lock_before_it_returns() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        create_handle_dir(base, &claude_home, account, 77_004).unwrap();
        assert!(matches!(
            crate::session::term_mint::try_acquire_for_sweep(base),
            crate::session::term_mint::SweepLock::Held(_)
        ));
    }

    #[test]
    fn create_handle_dir_populates_symlinks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 99999).unwrap();

        assert!(handle.exists());
        assert_eq!(handle.file_name().unwrap().to_str().unwrap(), "term-99999");

        // Account-bound symlinks should exist
        #[cfg(unix)]
        {
            let cred_link = handle.join(".credentials.json");
            assert!(cred_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            let target = std::fs::read_link(&cred_link).unwrap();
            assert!(target.ends_with("config-1/.credentials.json"));
        }

        // .live-pid should contain PID
        assert_eq!(markers::read_live_pid(&handle), Some(99999));
    }

    /// `keychain-fix-r11.md` S-MEDIUM-1 / D-4 — INVERTED from the retired
    /// `keychain-fix-r10.md` S-M-2 test (`create_handle_dir_drops_stale_
    /// pending_clear_for_reused_pid_service`, which asserted the entry was
    /// DROPPED). The regression that fix introduced: dropping the entry
    /// stopped a later retry from misfiring, but also threw away the ONLY
    /// remaining chance to actually clear whatever the entry was queued to
    /// clear. Creation now RESOLVES the entry instead (its own disposition,
    /// run against the real keychain item) and removes it only on a
    /// CONFIRMED clear (`Ok(true)`) — under test, `clear_service_reporting`
    /// short-circuits to `Ok(false)` (`keychain_mirror_disabled()`), a
    /// structural no-op that clears nothing, so the entry now correctly
    /// SURVIVES creation rather than evaporating. Real file I/O throughout
    /// (`record_pending_clear` is not gated by `keychain_mirror_disabled()`),
    /// macOS-only for the same reason every other pending-clear-queue test
    /// in this module is: off macOS `record_pending_clear`/
    /// `resolve_pending_clear_at_creation` are both
    /// `#[cfg(not(target_os = "macos"))] {}` no-ops, so the file would be
    /// absent whichever way this ran and no result would falsify the claim
    /// (`instrument-discipline.md` MUST-1).
    #[cfg(target_os = "macos")]
    #[test]
    fn create_handle_dir_resolves_stale_pending_clear_for_reused_pid_service() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        let pid = 88_813u32;

        // Simulate a PRIOR session at this exact pid: create the dir once
        // to learn its canonicalized service name, then remove it (as
        // logout or the dead-handle reaper would), leaving a stale queue
        // entry behind — exactly what a Logout-origin retry would act on.
        let first = create_handle_dir(base, &claude_home, account, pid).unwrap();
        let abs = std::fs::canonicalize(&first).unwrap();
        let stale_service = crate::credentials::keychain::service_name(&abs);
        std::fs::remove_dir_all(&first).unwrap();
        crate::credentials::keychain::record_pending_clear(
            base,
            &stale_service,
            Some(account),
            crate::credentials::keychain::PendingClearOrigin::Logout,
            None,
            None,
        );
        let queue_path = base.join("keychain-pending-clears.json");
        assert!(
            std::fs::read_to_string(&queue_path)
                .unwrap()
                .contains(&stale_service),
            "sanity: the stale entry must actually be queued before the fresh create"
        );

        // Fresh session reuses the SAME pid — same `term-<pid>` path, same
        // canonicalized service name as the prior (now-gone) session.
        let _second = create_handle_dir(base, &claude_home, account, pid).unwrap();

        let queue_raw = std::fs::read_to_string(&queue_path).unwrap_or_default();
        assert!(
            queue_raw.contains(&stale_service),
            "under test the keychain mirror is disabled, so resolving the entry \
             is a structural no-op (Ok(false)) that clears nothing — the entry \
             must SURVIVE creation, not be dropped unconfirmed: {queue_raw}"
        );
    }

    #[test]
    fn repoint_handle_dir_changes_targets() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 88888).unwrap();

        // Repoint to account 2
        repoint_verified_fixture(base, &claude_home, &handle, account2).unwrap();

        #[cfg(unix)]
        {
            let target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
            assert_eq!(target, verified_fixture_credentials(base, 2));
            let target = std::fs::read_link(handle.join(".csq-account")).unwrap();
            assert!(target.ends_with("config-2/.csq-account"));
        }
    }

    #[test]
    fn repoint_guarded_profiles_contention_refuses_without_namespace_change() {
        use crate::accounts::anthropic_identity as ai;
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        stage_verified_repoint_slots(dir.path(), &[1, 2]);
        let source = AccountNum::try_from(1u16).unwrap();
        let target = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(dir.path(), home.path(), source, 88889).unwrap();
        let binding = ai::capture_anthropic_binding(dir.path(), target).unwrap();
        let native = capture_native_swap(dir.path(), &handle).unwrap();
        // Initialize the persistent repoint lock before the byte/mode/mtime
        // snapshot. Only lock contention, not first-use lock creation, is tested.
        drop(crate::platform::lock::lock_file(&repoint_lock_path(&handle)).unwrap());
        // Another thread: a Windows mutex is re-entrant for its holding thread.
        let profiles = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(dir.path());
        let before = repoint_fixture_snapshot(dir.path());
        assert!(capture_native_swap(dir.path(), &handle).is_err());
        // N5: contention is reported as BUSY (retry), not the identity refusal.
        let busy = repoint_handle_dir_guarded(dir.path(), home.path(), &handle, &binding, &native)
            .unwrap_err();
        assert!(is_profiles_lock_busy(&busy), "got {busy:?}");
        assert_ne!(busy.to_string(), ai::credential_refusal().to_string());
        assert_eq!(repoint_fixture_snapshot(dir.path()), before);
        drop(profiles);
        // The same captured authority succeeds once contention is gone.
        repoint_handle_dir_guarded(dir.path(), home.path(), &handle, &binding, &native).unwrap();
        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle),
            Some(target)
        );
    }

    fn stage_legacy_repoint_slots(base: &Path) {
        use crate::accounts::{identity_store, profiles_lock::ProfilesFileLock};
        profiles::save(
            &profiles::profiles_path(base),
            &profiles::ProfilesFile::empty(),
        )
        .unwrap();
        for slot in [1u16, 2] {
            setup_config_dir(base, slot);
            let id = identity_store::IdentityId::new_v4();
            crate::daemon::identity_mint::write_legacy_anthropic_metadata_fixture(
                base,
                id,
                "same@example.test",
            )
            .unwrap();
            let credential: crate::credentials::CredentialFile = serde_json::from_value(serde_json::json!({
                "claudeAiOauth":{"accessToken":format!("fake-legacy-access-{slot}"),
                    "refreshToken":format!("fake-legacy-refresh-{slot}"),"expiresAt":4102444800000u64,"scopes":[]}
            })).unwrap();
            crate::credentials::save(&identity_store::credentials_path_for(base, id), &credential)
                .unwrap();
            let lock = ProfilesFileLock::acquire(base).unwrap();
            profiles::reserve_legacy_anthropic_slot(&lock, base, slot, id).unwrap();
            drop(lock);
            let config = base.join(format!("config-{slot}"));
            markers::write_csq_account(&config, id).unwrap();
            std::fs::write(
                config.join(".claude.json"),
                br#"{"oauthAccount":{"emailAddress":"same@example.test"},"fixtureRetain":true}"#,
            )
            .unwrap();
            crate::platform::fs::secure_file(&config.join(".claude.json")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for directory in [
                    base.join("identities"),
                    identity_store::identity_path(base, id),
                ] {
                    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
            }
        }
        assert!(profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .anthropic_contexts
            .is_empty());
    }

    #[test]
    fn repoint_legacy_local_custody_keeps_own_uuid_and_never_invents_context() {
        use crate::accounts::{anthropic_identity as ai, identity_store};
        let _env_guard = crate::platform::test_env::lock();
        for known in [None, Some(1u16), Some(2u16)] {
            let dir = TempDir::new().unwrap();
            let home = TempDir::new().unwrap();
            stage_legacy_repoint_slots(dir.path());
            if let Some(slot) = known {
                stage_verified_repoint_slots(dir.path(), &[slot]);
            }
            let source = AccountNum::try_from(1u16).unwrap();
            let target = AccountNum::try_from(2u16).unwrap();
            let source_id = profiles::resolve_slot_to_uuid(dir.path(), 1).unwrap();
            let target_id = profiles::resolve_slot_to_uuid(dir.path(), 2).unwrap();
            assert_ne!(source_id, target_id);
            let paths = [
                identity_store::identity_json_path_for(dir.path(), source_id),
                identity_store::identity_json_path_for(dir.path(), target_id),
                profiles::profiles_path(dir.path()),
            ];
            let before = paths
                .iter()
                .map(|path| std::fs::read(path).unwrap())
                .collect::<Vec<_>>();
            let handle = create_handle_dir(dir.path(), home.path(), source, 88890).unwrap();
            let path = handle.join(".claude.json");
            let mut native: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            native["cachedGrowthBookFeatures"] = serde_json::json!({"source-only":true});
            native["oauthAccount"]["organizationRole"] = Value::String("source-only".into());
            std::fs::write(&path, serde_json::to_vec(&native).unwrap()).unwrap();
            let binding = ai::capture_anthropic_binding(dir.path(), target).unwrap();
            let capture = capture_native_swap(dir.path(), &handle).unwrap();
            repoint_handle_dir_guarded(dir.path(), home.path(), &handle, &binding, &capture)
                .unwrap();
            assert_eq!(
                markers::resolve_marker_to_slot(dir.path(), &handle),
                Some(target)
            );
            assert_eq!(
                std::fs::read_link(handle.join(".credentials.json")).unwrap(),
                identity_store::credentials_path_for(dir.path(), target_id)
            );
            assert_eq!(
                paths
                    .iter()
                    .map(|path| std::fs::read(path).unwrap())
                    .collect::<Vec<_>>(),
                before
            );
            let rebuilt: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert!(rebuilt.get("cachedGrowthBookFeatures").is_none());
            assert!(rebuilt["oauthAccount"].get("organizationRole").is_none());
            if known != Some(2) {
                assert_eq!(
                    rebuilt["oauthAccount"],
                    serde_json::json!({"emailAddress":"same@example.test"})
                );
                assert_eq!(
                    ai::read_stored_anthropic_context(dir.path(), target_id).unwrap(),
                    ai::StoredAnthropicContext::LegacyUnknown
                );
            } else {
                let ai::StoredAnthropicContext::Known(context) = binding.context() else {
                    panic!("verified target must remain Known");
                };
                assert_eq!(
                    ai::parse_native_expectation(&rebuilt).unwrap().context(),
                    context
                );
            }
        }
    }

    /// N5: a busy profiles lock is reported as busy (retry), distinct from the
    /// identity refusal that tells the operator to run `csq login`.
    #[cfg(unix)]
    #[test]
    fn capture_native_swap_busy_profiles_lock_is_distinct_from_identity_refusal() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        stage_legacy_repoint_slots(dir.path());
        let source = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(dir.path(), home.path(), source, 88894).unwrap();
        let held = ProfilesFileLock::acquire(dir.path()).unwrap();
        let busy = capture_native_swap(dir.path(), &handle)
            .err()
            .expect("busy lock must refuse");
        assert!(is_profiles_lock_busy(&busy), "got {busy:?}");
        drop(held);
        // A genuine identity refusal (non-directory handle) is NOT busy.
        let refused = capture_native_swap(dir.path(), &dir.path().join("missing"))
            .err()
            .expect("missing handle must refuse");
        assert!(!is_profiles_lock_busy(&refused), "got {refused:?}");
    }

    /// R2 NEW-1/N2: CC rewrites `.claude.json` AFTER the symlink loop but
    /// before the publish. The repoint must roll every link back and report
    /// `RepointFailed { rolled_back: true }` — never a bare `Corrupt` after
    /// the account already switched. RED without the staged-commit-inside-
    /// rollback change: the late mutation surfaces as `Corrupt` with the
    /// symlinks and marker left on the target.
    #[cfg(unix)]
    #[test]
    fn repoint_native_metadata_mutated_after_loop_rolls_back_fully() {
        use crate::accounts::anthropic_identity as ai;
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        stage_legacy_repoint_slots(dir.path());
        let source = AccountNum::try_from(1u16).unwrap();
        let target = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(dir.path(), home.path(), source, 88893).unwrap();
        let binding = ai::capture_anthropic_binding(dir.path(), target).unwrap();
        let capture = capture_native_swap(dir.path(), &handle).unwrap();
        let pre_targets: Vec<(&str, Option<PathBuf>)> = ACCOUNT_BOUND_ITEMS
            .iter()
            .map(|item| (*item, std::fs::read_link(handle.join(item)).ok()))
            .collect();
        let native_path = handle.join(".claude.json");
        let before_native = std::fs::read(&native_path).unwrap();
        let _guard = RepointFaultGuard;
        set_repoint_after_loop_hook_for_test(Some(Box::new(|handle_dir: &Path| {
            std::fs::write(
                handle_dir.join(".claude.json"),
                br#"{"oauthAccount":{"emailAddress":"cc-wrote-this@example.test"}}"#,
            )
            .unwrap();
        })));
        let err = repoint_handle_dir_guarded(dir.path(), home.path(), &handle, &binding, &capture)
            .unwrap_err();
        assert!(
            matches!(
                err,
                CredentialError::RepointFailed {
                    rolled_back: true,
                    ..
                }
            ),
            "expected RepointFailed{{rolled_back:true}}, got {err:?}"
        );
        for (item, before) in &pre_targets {
            assert_eq!(
                std::fs::read_link(handle.join(item)).ok(),
                *before,
                "{item} must be restored"
            );
        }
        assert_ne!(
            std::fs::read(&native_path).unwrap(),
            before_native,
            "CC's own write is left alone"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&handle)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "tmp leftovers: {leftovers:?}");
    }

    #[test]
    fn repoint_legacy_native_race_and_rebind_refuse_without_partial_writes() {
        use crate::accounts::{anthropic_identity as ai, profiles_lock::ProfilesFileLock};
        let _env_guard = crate::platform::test_env::lock();
        for rebind in [false, true] {
            let dir = TempDir::new().unwrap();
            let home = TempDir::new().unwrap();
            stage_legacy_repoint_slots(dir.path());
            let source = AccountNum::try_from(1u16).unwrap();
            let target = AccountNum::try_from(2u16).unwrap();
            let handle = create_handle_dir(dir.path(), home.path(), source, 88891).unwrap();
            let binding = ai::capture_anthropic_binding(dir.path(), target).unwrap();
            let capture = capture_native_swap(dir.path(), &handle).unwrap();
            drop(crate::platform::lock::lock_file(&repoint_lock_path(&handle)).unwrap());
            if rebind {
                let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
                profiles::swap_slot_mapping(&lock, dir.path(), 1, 2).unwrap();
            } else {
                std::fs::write(
                    handle.join(".claude.json"),
                    br#"{"oauthAccount":{"emailAddress":"foreign@example.test"}}"#,
                )
                .unwrap();
            }
            let before = repoint_fixture_snapshot(dir.path());
            assert_eq!(
                repoint_handle_dir_guarded(dir.path(), home.path(), &handle, &binding, &capture)
                    .unwrap_err()
                    .to_string(),
                ai::credential_refusal().to_string()
            );
            assert_eq!(repoint_fixture_snapshot(dir.path()), before);
        }
    }

    /// an internal ticket invariant pin: post-swap `.credentials.json` follows-symlink
    /// stat MUST resolve to a different inode than pre-swap. CC's
    /// `invalidateOAuthCacheIfDiskChanged` (spec 01 §1.4) keys cache reload
    /// off `mtimeMs !== lastCredentialsMtimeMs`; the swap contract relies on
    /// the new target being a different file with a different mtime. This
    /// test pins the inode-differ guarantee — a regression that left the
    /// symlink resolving to the same inode (e.g. by accidentally creating
    /// a hardlink-ish layout, or by failing to repoint at all) would be
    /// caught here even before mtime collision is exercised.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_changes_credentials_target_inode() {
        let _env_guard = crate::platform::test_env::lock();
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 77777).unwrap();

        let pre_meta = std::fs::metadata(handle.join(".credentials.json")).unwrap();
        let pre_ino = pre_meta.ino();

        repoint_verified_fixture(base, &claude_home, &handle, account2).unwrap();

        let post_meta = std::fs::metadata(handle.join(".credentials.json")).unwrap();
        let post_ino = post_meta.ino();

        assert_ne!(
            pre_ino, post_ino,
            "post-swap credentials target inode must differ from pre-swap; \
             same inode means CC's stat will see identical metadata and skip \
             reload (spec 01 §1.4 invariant)"
        );
    }

    /// F2: a rename failure on the `k`-th item MUST leave every already-
    /// repointed item restored to its pre-repoint target — not merely
    /// "logged as partially repointed" (the pre-F2 behaviour). Exercises
    /// EVERY item position (k = 0..3) via the `repoint_fail_at_rename_index`
    /// test-only fault seam.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_rolls_back_every_item_on_rename_failure_at_each_index() {
        let _env_guard = crate::platform::test_env::lock();
        for k in 0..4usize {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let claude_home = dir.path().join(".claude");
            std::fs::create_dir_all(&claude_home).unwrap();
            let config_1 = setup_config_dir(base, 1);
            let config_2 = setup_config_dir(base, 2);
            // All FOUR ACCOUNT_BOUND_ITEMS must be present in both configs so
            // every item actually attempts a rename (none take the "absent in
            // target" skip branch) — `setup_config_dir` only writes
            // `.credentials.json` and `.csq-account`.
            for extra in [".current-account", ".quota-cursor"] {
                std::fs::write(config_1.join(extra), "1").unwrap();
                std::fs::write(config_2.join(extra), "2").unwrap();
            }

            let account1 = AccountNum::try_from(1u16).unwrap();
            let account2 = AccountNum::try_from(2u16).unwrap();
            stage_verified_repoint_slots(base, &[1, 2, 3]);
            let handle = create_handle_dir(base, &claude_home, account1, 60000 + k as u32).unwrap();

            // Snapshot the pre-repoint targets of every item.
            let pre_targets: Vec<(&str, PathBuf)> = ACCOUNT_BOUND_ITEMS
                .iter()
                .map(|item| (*item, std::fs::read_link(handle.join(item)).unwrap()))
                .collect();

            let _guard = RepointFaultGuard;
            set_repoint_fail_at_rename_index_for_test(Some(k));

            let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
            assert!(
                result.is_err(),
                "k={k}: repoint must fail when the fault seam fires"
            );

            // Every item's link must be restored to EXACTLY its pre-repoint
            // target — not merely "some items moved, logged for the caller".
            for (item, pre_target) in &pre_targets {
                let post_target = std::fs::read_link(handle.join(item)).unwrap_or_else(|e| {
                    panic!("k={k}: item {item} must still resolve after rollback: {e}")
                });
                assert_eq!(
                    &post_target, pre_target,
                    "k={k}: item {item} must be restored to its pre-repoint target"
                );
            }

            // No leftover `*.swap-tmp` may survive a rolled-back repoint.
            for item in ACCOUNT_BOUND_ITEMS {
                let tmp = handle.join(format!("{item}.swap-tmp"));
                assert!(
                    tmp.symlink_metadata().is_err(),
                    "k={k}: leftover {item}.swap-tmp must be removed after rollback"
                );
            }
        }
    }

    /// Test gap: the rollback coverage above never exercises F2(c) — an
    /// item DELETED (not renamed) because the new config lacks a matching
    /// target. `config-2` here omits `.current-account`/`.quota-cursor`,
    /// so repointing to it deletes those two links before the fault seam
    /// fires on the LAST item (`.csq-account`). Rollback must RECREATE
    /// both deleted links pointing back at `config-1` — not merely
    /// restore the items that were renamed.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_rollback_restores_f2c_deleted_items() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let config_1 = setup_config_dir(base, 1);
        let _config_2 = setup_config_dir(base, 2);
        for extra in [".current-account", ".quota-cursor"] {
            std::fs::write(config_1.join(extra), "1").unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 60300).unwrap();

        let pre_targets: Vec<(&str, PathBuf)> = ACCOUNT_BOUND_ITEMS
            .iter()
            .map(|item| (*item, std::fs::read_link(handle.join(item)).unwrap()))
            .collect();

        let _guard = RepointFaultGuard;
        // processing_order = [.credentials.json, .current-account,
        // .quota-cursor, .csq-account] — index 3 is the LAST item
        // (.csq-account), processed after both F2(c) deletions above.
        set_repoint_fail_at_rename_index_for_test(Some(3));

        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
        match result {
            Err(CredentialError::RepointFailed { rolled_back, .. }) => {
                assert!(rolled_back, "rollback must fully succeed here");
            }
            other => panic!("expected Err(RepointFailed), got {other:?}"),
        }

        for (item, pre_target) in &pre_targets {
            let post_target = std::fs::read_link(handle.join(item))
                .unwrap_or_else(|e| panic!("item {item} must be restored after rollback: {e}"));
            assert_eq!(
                &post_target, pre_target,
                "item {item} (including F2(c)-deleted ones) must be restored to its pre-repoint target"
            );
        }
    }

    /// Test gap: the rollback coverage above only uses a legacy-only
    /// fixture. An identity-keyed slot's `.credentials.json` link target
    /// (`identities/<UUID>/credentials.json`) is a DIFFERENT shape from
    /// its other three items' targets (`config-N/<item>`) — prove the
    /// snapshot/restore machinery restores that heterogeneous shape
    /// correctly too, not just the legacy uniform-parent shape.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_rollback_restores_identity_keyed_credentials_target() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::{
            coexisting_fixture, fixture_uuid_for_slot, write_uuid_account_marker,
        };

        let dir = coexisting_fixture(2);
        let base = dir.path();
        let claude_home = TempDir::new().unwrap();

        for slot in [1u16, 2u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&creds, b"{}").unwrap();
            let cfg = base.join(format!("config-{slot}"));
            write_uuid_account_marker(base, &cfg, slot);
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".current-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join(".quota-cursor"), "0").unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, claude_home.path(), account1, 60301).unwrap();

        let pre_creds_target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        assert!(
            pre_creds_target.to_string_lossy().contains("identities"),
            "fixture precondition: expected an identity-keyed pre-repoint target, got {pre_creds_target:?}"
        );

        let _guard = RepointFaultGuard;
        // Fail on the LAST item (.csq-account) so every OTHER item,
        // including the identity-keyed `.credentials.json`, has already
        // been renamed and must be rolled back.
        set_repoint_fail_at_rename_index_for_test(Some(3));

        let result = repoint_verified_fixture(base, claude_home.path(), &handle, account2);
        assert!(
            result.is_err(),
            "repoint must fail when the fault seam fires"
        );

        let post_creds_target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        assert_eq!(
            post_creds_target, pre_creds_target,
            "identity-keyed .credentials.json must be restored to its exact pre-repoint target"
        );
        assert!(
            handle_dir_symlinks_are_consistent(base, &handle),
            "a fully-restored identity-keyed dir must read back as consistent"
        );
    }

    /// Test gap: every rollback test so far assumes the rollback itself
    /// SUCCEEDS. S2's `CredentialError::RepointFailed::rolled_back` exists
    /// specifically to report the OTHER case — inject a restore failure on
    /// one already-repointed item via the fault seam, and confirm
    /// `rolled_back` reports `false`, AND that the disk-level consistency
    /// check independently agrees the dir is left mixed (the two signals
    /// this finding requires a caller to combine, both correctly firing).
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_reports_rolled_back_false_when_restore_itself_fails() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 60302).unwrap();

        let _guard = RepointFaultGuard;
        // Fail the RENAME on the last item (.csq-account, idx 3), so
        // `.credentials.json` (idx 0) has already been successfully
        // repointed to config-2 by the time rollback runs — then make
        // THAT item's own restore fail.
        set_repoint_fail_at_rename_index_for_test(Some(3));
        set_repoint_fail_restore_for_item_for_test(Some(".credentials.json"));

        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
        match result {
            Err(CredentialError::RepointFailed { rolled_back, .. }) => {
                assert!(
                    !rolled_back,
                    "the injected restore failure must be reported as rolled_back: false"
                );
            }
            other => panic!("expected Err(RepointFailed), got {other:?}"),
        }

        // The disk-level check independently agrees: `.credentials.json`
        // is left pointing at config-2 while the other items were rolled
        // back to config-1 -- a genuinely mixed, "partially switched" dir.
        assert!(
            !handle_dir_symlinks_are_consistent(base, &handle),
            "a dir left mixed by a failed rollback must read back as inconsistent"
        );
    }

    /// S-H1/D-F1: a settings.json-commit failure AFTER every
    /// `ACCOUNT_BOUND_ITEMS` symlink (including `.csq-account`) has already
    /// been renamed must be treated exactly like a mid-loop rename failure —
    /// every already-repointed item rolled back to its pre-repoint target,
    /// and the error reports `rolled_back: true` (via
    /// `CredentialError::repoint_rolled_back()`), never `None`. Before the
    /// fix this failure propagated a bare `Corrupt`/`Io` with no rollback at
    /// all: the symlinks stayed on the NEW account while
    /// `repoint_rolled_back()` returned `None`, which
    /// `daemon::auto_rotate`'s `.unwrap_or(true)` combinator reads as "fully
    /// rolled back" — reporting "nothing was changed" while the account had
    /// in fact fully switched.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_rolls_back_symlinks_when_settings_commit_fails() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let config_1 = setup_config_dir(base, 1);
        let config_2 = setup_config_dir(base, 2);
        // Every ACCOUNT_BOUND_ITEMS symlink is only created when its source
        // target exists (`create_handle_dir`'s `target.exists() || ...`
        // guard) — `setup_config_dir` writes only `.csq-account` and
        // `.credentials.json`, so `.current-account`/`.quota-cursor` need
        // to be seeded on BOTH config dirs for every item's pre/post target
        // to actually resolve via `read_link` below.
        for cfg in [&config_1, &config_2] {
            for extra in [".current-account", ".quota-cursor"] {
                std::fs::write(cfg.join(extra), "1").unwrap();
            }
        }
        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 60310).unwrap();

        let pre_targets: Vec<(&str, PathBuf)> = ACCOUNT_BOUND_ITEMS
            .iter()
            .map(|item| (*item, std::fs::read_link(handle.join(item)).unwrap()))
            .collect();

        let _guard = RepointFaultGuard;
        // No rename-index fault: every ACCOUNT_BOUND_ITEMS symlink (incl.
        // `.csq-account`) renames successfully. Only the settings.json
        // commit — the true final step per S-H1/D-F1 — fails.
        set_repoint_fail_settings_commit_for_test(true);

        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
        match result {
            Err(ref e @ CredentialError::RepointFailed { rolled_back, .. }) => {
                assert!(
                    rolled_back,
                    "a settings-commit failure with a clean restore must report rolled_back: true"
                );
                assert_eq!(
                    e.repoint_rolled_back(),
                    Some(true),
                    "repoint_rolled_back() must be Some(true), never None, once every symlink \
                     (including .csq-account) has already been renamed"
                );
            }
            other => panic!("expected Err(RepointFailed), got {other:?}"),
        }

        // The bug this test pins: without the fix, every symlink stayed on
        // account 2 here. With the fix, every item is restored to its
        // EXACT pre-repoint (account 1) target.
        for (item, pre_target) in &pre_targets {
            let post_target = std::fs::read_link(handle.join(item))
                .unwrap_or_else(|e| panic!("item {item} must still resolve after rollback: {e}"));
            assert_eq!(
                &post_target, pre_target,
                "item {item} must be restored to its pre-repoint (account 1) target, \
                 not left on account 2"
            );
        }
        assert!(
            handle_dir_symlinks_are_consistent(base, &handle),
            "a fully-restored dir must read back as consistent with its (unchanged) account 1 marker"
        );

        // §5a: the prepared settings.json temp file must not linger.
        let leaked: Vec<_> = std::fs::read_dir(&handle)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("settings.json"))
                    .unwrap_or(false)
                    && e.file_name() != std::ffi::OsStr::new("settings.json")
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "§5a leaked settings.json temp files: {leaked:?}"
        );
    }

    #[test]
    fn native_metadata_rollback_preserves_concurrent_writer_and_restores_own_publication() {
        for prior in [None, Some(r#"{"projects":{"old":true}}"#)] {
            for concurrent_writer in [false, true] {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join(".claude.json");
                if let Some(raw) = prior {
                    crate::platform::fs::write_new_private(&path, raw.as_bytes()).unwrap();
                }
                let staged = stage_native_swap_metadata(
                    dir.path(),
                    &serde_json::json!({"oauthAccount":{"emailAddress":"target@example.test"}}),
                    prior,
                )
                .unwrap();
                let published = staged.commit().unwrap();
                assert_eq!(std::fs::read_to_string(&path).unwrap(), published);
                let concurrent = r#"{"projects":{"native-writer":true}}"#;
                if concurrent_writer {
                    std::fs::write(&path, concurrent).unwrap();
                }
                let restored = restore_native_metadata(dir.path(), prior, &published);
                assert_eq!(
                    restored, !concurrent_writer,
                    "rollback must report an intervening writer as incomplete"
                );
                if concurrent_writer {
                    assert_eq!(std::fs::read_to_string(&path).unwrap(), concurrent);
                } else if let Some(raw) = prior {
                    assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);
                } else {
                    assert!(!path.exists());
                }
                assert!(std::fs::read_dir(dir.path())
                    .unwrap()
                    .flatten()
                    .all(|entry| entry.file_name() == ".claude.json"));
            }
        }
    }

    /// S-H1/D-F1 companion: when a settings-commit failure's OWN rollback
    /// ALSO fails to restore one item, the error must report `rolled_back:
    /// false` (never silently drop to `None`), and the disk-level
    /// consistency check must independently agree the dir is left mixed —
    /// the same two-signal contract `repoint_handle_dir_reports_rolled_back_false_when_restore_itself_fails`
    /// pins for a mid-loop rename failure, now proven for the settings-commit
    /// failure path too.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_reports_rolled_back_false_when_settings_commit_and_restore_both_fail() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 60311).unwrap();

        let _guard = RepointFaultGuard;
        set_repoint_fail_settings_commit_for_test(true);
        set_repoint_fail_restore_for_item_for_test(Some(".credentials.json"));

        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
        match result {
            Err(CredentialError::RepointFailed { rolled_back, .. }) => {
                assert!(
                    !rolled_back,
                    "the injected restore failure must be reported as rolled_back: false, \
                     never collapsed to None"
                );
            }
            other => panic!("expected Err(RepointFailed), got {other:?}"),
        }

        assert!(
            !handle_dir_symlinks_are_consistent(base, &handle),
            "a dir left mixed by a failed rollback (following a settings-commit failure) \
             must read back as inconsistent"
        );
    }

    /// S-H1/D-F1: a failure BEFORE any mutation must report
    /// `repoint_rolled_back() == None` — "nothing to roll back" is the
    /// correct answer only when nothing was ever mutated, which this test
    /// independently confirms by asserting every symlink is untouched
    /// (still on account 1). Distinguishes this pre-mutation case from the
    /// post-rename-loop settings-commit failure above, which MUST NOT
    /// report `None`.
    ///
    /// Making the handle dir read-only (0o500) fires the FIRST fallible
    /// step that follows it — verified by RED-proof debug print to be
    /// `lock_repoint_path`'s own `.swap.lock` file creation inside the
    /// handle dir (`repoint lock acquisition failed: ... Permission
    /// denied`), not `prepare_handle_settings_tmp`'s later
    /// `std::fs::write` as an earlier draft of this comment claimed
    /// (`doc-property-claims.md`: name the mechanism actually exercised).
    /// Both are pre-mutation refusals reported through the SAME
    /// `CredentialError::Corrupt`/`Io` path this test pins, so the
    /// invariant under test — "nothing mutated ⇒ `None`" — holds either
    /// way; only the specific fallible call this 0o500 fixture happens to
    /// trip changes.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_reports_none_when_failure_is_before_any_mutation() {
        let _env_guard = crate::platform::test_env::lock();
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let config_1 = setup_config_dir(base, 1);
        let config_2 = setup_config_dir(base, 2);
        // See the sibling settings-commit-failure test above: every
        // ACCOUNT_BOUND_ITEMS symlink is only created when its source
        // target exists, so `.current-account`/`.quota-cursor` need to be
        // seeded for `read_link` below to resolve on every item.
        for cfg in [&config_1, &config_2] {
            for extra in [".current-account", ".quota-cursor"] {
                std::fs::write(cfg.join(extra), "1").unwrap();
            }
        }
        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 60312).unwrap();

        let pre_targets: Vec<(&str, PathBuf)> = ACCOUNT_BOUND_ITEMS
            .iter()
            .map(|item| (*item, std::fs::read_link(handle.join(item)).unwrap()))
            .collect();

        // Read-only handle dir: the FIRST fallible step that follows —
        // `lock_repoint_path`'s own `.swap.lock` creation inside the
        // handle dir — fails with permission denied before the S7
        // pre-flight guard, `prepare_handle_settings_tmp`, or the rename
        // loop ever run; nothing has been mutated yet (RED-proof verified;
        // see the doc comment above this test).
        std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
        std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            Err(ref e @ (CredentialError::Io { .. } | CredentialError::Corrupt { .. })) => {
                assert_eq!(
                    e.repoint_rolled_back(),
                    None,
                    "a failure before any mutation must report None, not Some(_)"
                );
            }
            other => panic!("expected Err(Io) or Err(Corrupt), got {other:?}"),
        }

        // Independently confirm nothing was mutated: every symlink still
        // resolves to its original (account 1) target.
        for (item, pre_target) in &pre_targets {
            let post_target = std::fs::read_link(handle.join(item)).unwrap();
            assert_eq!(
                &post_target, pre_target,
                "item {item} must be completely untouched by a pre-mutation failure"
            );
        }
    }

    /// RAII guard resetting the F2 test-only rename-failure fault seam even
    /// if the test body panics mid-assertion — the default test harness
    /// reuses OS threads across tests, so an unguarded `set_...(Some(k))`
    /// could otherwise leak into an unrelated later test on the same thread.
    #[cfg(unix)]
    struct RepointFaultGuard;
    #[cfg(unix)]
    impl Drop for RepointFaultGuard {
        fn drop(&mut self) {
            set_repoint_fail_at_rename_index_for_test(None);
            set_repoint_fail_restore_for_item_for_test(None);
            set_repoint_fail_settings_commit_for_test(false);
            set_repoint_after_loop_hook_for_test(None);
        }
    }

    /// S7: `repoint_handle_dir` must refuse — before touching anything —
    /// when an `ACCOUNT_BOUND_ITEMS` slot is occupied by a REAL file
    /// rather than a symlink. Before the fix, `snapshot_link_state` used
    /// `read_link` alone, which cannot tell a real file from a genuinely
    /// absent item; the rename loop then renames a symlink OVER
    /// `link_path` unconditionally, which would have silently clobbered
    /// the real file with no warning.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_refuses_when_item_is_a_real_file_not_symlink() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, &claude_home, account1, 60200).unwrap();

        // Replace `.current-account` with a REAL file (not a symlink) —
        // the exact shape a caller must never rename over.
        std::fs::write(handle.join(".current-account"), "not a symlink").unwrap();

        let pre_creds_target = std::fs::read_link(handle.join(".credentials.json")).unwrap();

        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);
        let err = result.expect_err("must refuse rather than rename over a real file");

        // K3: this fires before any mutation — `repoint_rolled_back()` must
        // report `Some(true)` (nothing to roll back) and
        // `repoint_refused_item()` must name the blocked item, so a caller
        // can print "nothing was changed" plus the specific offending item
        // instead of the generic loop-inducing "may be partially switched".
        assert_eq!(err.repoint_rolled_back(), Some(true));
        assert_eq!(err.repoint_refused_item(), Some(".current-account"));

        // Nothing else was mutated: `.credentials.json` still resolves
        // exactly where it did before the refused call.
        let post_creds_target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        assert_eq!(pre_creds_target, post_creds_target);
        // The real file itself must survive untouched.
        assert_eq!(
            std::fs::read_to_string(handle.join(".current-account")).unwrap(),
            "not a symlink"
        );
    }

    /// F2(d): a freshly-created (never repointed) handle dir is
    /// consistent — every item resolves under the SAME `config-1`.
    #[test]
    #[cfg(unix)]
    fn handle_dir_symlinks_are_consistent_true_for_fresh_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 60100).unwrap();
        assert!(handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// F2(d): a handle dir whose items resolve under TWO different
    /// config-<N> dirs (the exact shape a non-rolled-back partial repoint
    /// leaves) is reported inconsistent.
    #[test]
    #[cfg(unix)]
    fn handle_dir_symlinks_are_consistent_false_for_mixed_targets() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 60101).unwrap();

        // Manually repoint ONE item to config-2, simulating a partial
        // repoint that was never rolled back.
        let link = handle.join(".credentials.json");
        std::fs::remove_file(&link).unwrap();
        create_symlink(&base.join("config-2").join(".credentials.json"), &link).unwrap();

        assert!(!handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// F2(d): a leftover `*.swap-tmp` — an aborted rename that was never
    /// cleaned up — is reported inconsistent even when every real symlink
    /// still agrees.
    #[test]
    #[cfg(unix)]
    fn handle_dir_symlinks_are_consistent_false_with_leftover_swap_tmp() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 60102).unwrap();

        std::fs::write(handle.join(".credentials.json.swap-tmp"), "leftover").unwrap();

        assert!(!handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// S1: a fresh identity-keyed handle dir — `.credentials.json` resolves
    /// under `identities/<UUID>/`, the other three items under `config-N/`
    /// — must be reported CONSISTENT. The prior "single common parent"
    /// implementation returned `false` here unconditionally, because it
    /// compared `.credentials.json`'s parent against the other items'
    /// parent and the two are never equal for an identity-keyed slot.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn handle_dir_symlinks_are_consistent_true_for_identity_keyed_fresh_dir() {
        use crate::testing::identity_fixtures::{
            coexisting_fixture, fixture_uuid_for_slot, write_uuid_account_marker,
        };

        let dir = coexisting_fixture(2);
        let base = dir.path();
        let claude_home = TempDir::new().unwrap();

        for slot in [1u16, 2u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&creds, b"{}").unwrap();
            let cfg = base.join(format!("config-{slot}"));
            write_uuid_account_marker(base, &cfg, slot);
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account1, 61001).unwrap();

        assert!(handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// S1: an identity-keyed handle dir whose `.credentials.json` was
    /// manually repointed to a DIFFERENT slot's identity credentials
    /// (the exact shape a non-rolled-back partial repoint leaves) while
    /// its marker still names the original slot — must be reported
    /// INCONSISTENT.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn handle_dir_symlinks_are_consistent_false_for_identity_keyed_mixed_account() {
        use crate::testing::identity_fixtures::{
            coexisting_fixture, fixture_uuid_for_slot, write_uuid_account_marker,
        };

        let dir = coexisting_fixture(2);
        let base = dir.path();
        let claude_home = TempDir::new().unwrap();

        for slot in [1u16, 2u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&creds, b"{}").unwrap();
            let cfg = base.join(format!("config-{slot}"));
            write_uuid_account_marker(base, &cfg, slot);
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account1, 61002).unwrap();

        // Manually repoint `.credentials.json` to slot 2's identity path,
        // while the `.csq-account` marker still names slot 1.
        let link = handle.join(".credentials.json");
        std::fs::remove_file(&link).unwrap();
        let uuid2 = fixture_uuid_for_slot(2);
        create_symlink(
            &base
                .join("identities")
                .join(uuid2.to_canonical_string())
                .join("credentials.json"),
            &link,
        )
        .unwrap();

        assert!(!handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// K1: a healthy handle dir created before `.current-account` existed
    /// in its config dir legitimately lacks that link. A later write to
    /// `config-N/.current-account` (e.g. a swap FROM a different terminal
    /// bound to the same slot) makes the expected target exist on disk
    /// without ever repointing this dir's link — that MUST still read
    /// consistent, not "may be partially switched".
    #[test]
    #[cfg(unix)]
    fn handle_dir_symlinks_are_consistent_true_when_current_account_missing_but_target_exists() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1); // no `.current-account` / `.quota-cursor` yet
        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 60103).unwrap();

        // The handle dir has no `.current-account` link — setup_config_dir
        // never wrote one, so create_handle_dir's target-exists guard (line
        // ~629) skipped it. Now something else (a poller, a sibling
        // terminal's swap) populates the config dir's copy.
        assert!(handle.join(".current-account").symlink_metadata().is_err());
        std::fs::write(base.join("config-1").join(".current-account"), "1").unwrap();

        assert!(handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// D-Lead (retracts the prior K2 "must still read consistent" claim
    /// for this exact scenario): a handle dir created while its slot was
    /// still legacy-keyed has `.credentials.json` -> `config-N/.credentials.json`.
    /// If the slot later migrates to a UUID (`profiles.json::by_slot` gains
    /// an entry), this dir's link is never repointed — and unlike the
    /// retracted claim, that is NOT harmless: M3-7 retired csq's writers to
    /// the legacy path for a migrated slot (spec 02 INV-05), so the linked
    /// file is frozen and never refreshed again. This MUST read
    /// inconsistent, so a failed repoint on this dir is reported as
    /// "partially switched — run `csq swap` again" rather than "nothing
    /// changed".
    #[test]
    #[cfg(unix)]
    fn handle_dir_symlinks_are_consistent_false_for_legacy_credentials_after_slot_migrates_to_uuid()
    {
        use crate::testing::identity_fixtures::write_uuid_account_marker;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let cfg = setup_config_dir(base, 1);
        let account1 = AccountNum::try_from(1u16).unwrap();
        // Dir created while slot 1 was legacy: link targets config-1/.credentials.json.
        let handle = create_handle_dir(base, &claude_home, account1, 60104).unwrap();

        // Slot 1 migrates to a UUID after the fact; the handle dir's
        // existing links are left untouched by the migration itself.
        write_uuid_account_marker(base, &cfg, 1);
        let uuid1 = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        std::fs::create_dir_all(base.join("identities").join(uuid1.to_canonical_string())).unwrap();
        std::fs::write(
            base.join("identities")
                .join(uuid1.to_canonical_string())
                .join("credentials.json"),
            "{}",
        )
        .unwrap();

        assert!(!handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// K2 (negative control, unaffected by the D-Lead fix above): after the
    /// same migration, a REAL partial repoint — `.credentials.json`
    /// pointed at a DIFFERENT slot's identity path — must still be
    /// reported inconsistent.
    #[test]
    #[cfg(unix)]
    fn handle_dir_symlinks_are_consistent_false_for_real_partial_after_slot_migrates_to_uuid() {
        use crate::testing::identity_fixtures::write_uuid_account_marker;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let cfg = setup_config_dir(base, 1);
        setup_config_dir(base, 2);
        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 60105).unwrap();

        write_uuid_account_marker(base, &cfg, 1);
        let uuid1 = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        std::fs::create_dir_all(base.join("identities").join(uuid1.to_canonical_string())).unwrap();
        std::fs::write(
            base.join("identities")
                .join(uuid1.to_canonical_string())
                .join("credentials.json"),
            "{}",
        )
        .unwrap();

        // Simulate a non-rolled-back partial repoint toward slot 2's legacy path.
        let link = handle.join(".credentials.json");
        std::fs::remove_file(&link).unwrap();
        create_symlink(&base.join("config-2").join(".credentials.json"), &link).unwrap();

        assert!(!handle_dir_symlinks_are_consistent(base, &handle));
    }

    /// an internal ticket fix regression test: when the two config dirs have
    /// `.credentials.json` files with IDENTICAL mtimes (the exact bug
    /// condition — daemon refresh in same nanosecond, FS precision clamp,
    /// etc.), the pre-swap mtime bump in `repoint_handle_dir` MUST advance
    /// the new target's mtime strictly above the pre-swap mtime so CC's
    /// strict-inequality reload check (spec 01 §1.4) fires.
    ///
    /// Without the fix, the new symlink resolves to a target with the same
    /// mtime as the prior target, CC silently skips reload, and the swap
    /// "appears not to take effect" until something else perturbs the
    /// file (an internal ticket user repro).
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_advances_mtime_when_targets_collide() {
        let _env_guard = crate::platform::test_env::lock();
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        // Force IDENTICAL mtimes on both slots' credentials files — the
        // exact an internal ticket bug condition. Pick a fixed mtime in the past so the
        // bump's `max(now, ...)` branch is the one being exercised.
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for slot in [1u16, 2u16] {
            let creds = verified_fixture_credentials(base, slot);
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&creds)
                .unwrap();
            f.set_modified(collision_time).unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 88888).unwrap();

        // Pre-swap: stat through the symlink to capture what CC's invalidate
        // check sees on its first stat.
        let pre_mtime = std::fs::metadata(handle.join(".credentials.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            pre_mtime, collision_time,
            "test setup invariant: pre-swap symlink resolves to slot 1's collision mtime"
        );

        repoint_verified_fixture(base, &claude_home, &handle, account2).unwrap();

        // Post-swap: stat through the symlink (now resolves to slot 2).
        // The fix MUST have bumped slot 2's target mtime strictly above
        // the collision_time. CC's `mtimeMs !== lastCredentialsMtimeMs`
        // check then fires on the next stat.
        let post_mtime = std::fs::metadata(handle.join(".credentials.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > pre_mtime,
            "an internal ticket regression: post-swap mtime ({post_mtime:?}) must be \
             strictly greater than pre-swap mtime ({pre_mtime:?}). Same mtime \
             means CC silently skips credential reload. The pre-rename mtime \
             bump in repoint_handle_dir failed to advance the target."
        );
    }

    /// an internal ticket fix regression test (Codex parallel): same invariant as
    /// the Anthropic test above but for `repoint_handle_dir_codex`. Pins
    /// the defensive bump on `credentials/codex-<N>.json` against the same
    /// mtime-collision class.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_codex_advances_auth_mtime_when_targets_collide() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Codex requires a different on-disk shape than Anthropic.
        // Build minimal codex config dirs + canonical credentials.
        for slot in [1u16, 2u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml
            std::fs::write(cfg.join(".credentials.json"), "{}").unwrap();
            std::fs::write(cfg.join("settings.json"), "{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), "{}").unwrap();
        }
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        for slot in [1u16, 2u16] {
            std::fs::write(creds_dir.join(format!("codex-{slot}.json")), "{}").unwrap();
        }

        // Force collision on canonical codex credential files AND apply the
        // INV-P08 mode (0o400) that `save_canonical_for` sets after Codex
        // login/refresh. Without this, the test does not cover the production
        // case where `bump_mtime_above` opens a 0o400 file — the bug that
        // made the Codex an internal ticket fix non-functional before the O_RDONLY fix.
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for slot in [1u16, 2u16] {
            let cred_path = creds_dir.join(format!("codex-{slot}.json"));
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&cred_path)
                .unwrap();
            f.set_modified(collision_time).unwrap();
            drop(f);
            // Apply INV-P08: canonical Codex credentials sit at 0o400.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir_codex(base, account1, 88889).unwrap();

        let pre_mtime = std::fs::metadata(handle.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            pre_mtime, collision_time,
            "test setup invariant: pre-swap codex auth.json resolves to slot 1's collision mtime"
        );

        repoint_handle_dir_codex(base, &handle, account2).unwrap();

        let post_mtime = std::fs::metadata(handle.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > pre_mtime,
            "an internal ticket regression (codex): post-swap auth.json mtime ({post_mtime:?}) \
             must be strictly greater than pre-swap ({pre_mtime:?})"
        );
    }

    /// Companion to inode-differ test: when the two config dirs have
    /// distinct credential files (the normal case), `mtime_changed` MUST
    /// report true so the post-swap INFO trace tells the truth. A regression
    /// here would mean an internal ticket's observability is silently lying.
    #[test]
    fn mtime_changed_returns_true_for_distinct_stats() {
        let pre = Some(super::CredsTargetStat {
            mtime_ns: 1_000_000_000,
            ino: 1,
        });
        let post = Some(super::CredsTargetStat {
            mtime_ns: 2_000_000_000,
            ino: 2,
        });
        assert!(super::mtime_changed(&pre, &post));
    }

    /// Mtime-collision case: two config dirs whose credentials happen to
    /// share an mtime (rare but possible — same-instant daemon refresh,
    /// filesystem precision clamp). `mtime_changed` MUST report false so
    /// the trace surfaces the failure mode that an internal ticket hypothesizes.
    #[test]
    fn mtime_changed_returns_false_for_colliding_mtimes() {
        let same_mtime = 1_500_000_000_i128;
        let pre = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 1,
        });
        let post = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 2, // different inode but same mtime — exact bug class
        });
        assert!(
            !super::mtime_changed(&pre, &post),
            "mtime collision MUST be reported — CC's reload won't fire"
        );
    }

    /// Conservative default: when either stat is unreadable, treat the
    /// invariant as unverified (false). Caller surfaces the None separately.
    #[test]
    fn mtime_changed_returns_false_when_either_stat_missing() {
        let stat = Some(super::CredsTargetStat {
            mtime_ns: 1_000_000_000,
            ino: 1,
        });
        assert!(!super::mtime_changed(&None, &stat));
        assert!(!super::mtime_changed(&stat, &None));
        assert!(!super::mtime_changed(&None, &None));
    }

    /// `mtime_collision` is the gate for the WARN emit that surfaces issue
    /// an internal ticket's failure mode in default-log sessions. It MUST fire only when
    /// both stats succeeded AND mtimes match — distinguishing the bug class
    /// from stat-read failures (None) and from the happy path (mtimes
    /// differ). A regression that returns true for None inputs would emit
    /// a spurious WARN on first-bind handle dirs; one that returns false
    /// for the bug condition would silently lose an internal ticket's signal. Pin both.
    #[test]
    fn mtime_collision_fires_only_when_both_stats_present_and_mtimes_equal() {
        let same_mtime = 1_500_000_000_i128;
        let stat_a = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 1,
        });
        let stat_b = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 2, // different inode but identical mtime — the an internal ticket bug class
        });
        let stat_c = Some(super::CredsTargetStat {
            mtime_ns: 2_000_000_000,
            ino: 3,
        });

        // Bug condition: both stats valid + mtimes equal → WARN must fire.
        assert!(
            super::mtime_collision(&stat_a, &stat_b),
            "mtime collision MUST fire when both stats succeed with identical mtimes"
        );

        // Happy path: both stats valid + mtimes differ → WARN must stay silent.
        assert!(
            !super::mtime_collision(&stat_a, &stat_c),
            "mtime collision MUST NOT fire when mtimes differ (happy path)"
        );

        // Stat-error cases: WARN must stay silent because the caller surfaces
        // the None separately via the INFO trace; spurious WARN here would
        // poison default-log sessions on first-bind handle dirs.
        assert!(!super::mtime_collision(&None, &stat_a));
        assert!(!super::mtime_collision(&stat_a, &None));
        assert!(!super::mtime_collision(&None, &None));
    }

    #[test]
    fn create_handle_dir_materializes_user_settings() {
        // The core bug alpha.9 fixes: user has statusLine + bypass mode
        // in ~/.claude/settings.json, but csq run N used to symlink the
        // handle dir's settings.json at a (usually empty) config-N copy,
        // so CC — reading CLAUDE_CONFIG_DIR — saw no customization.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{
                "statusLine": { "type": "command", "command": "echo hi" },
                "permissions": { "defaultMode": "bypassPermissions" },
                "enabledPlugins": { "my-plugin": true }
            }"#,
        )
        .unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77777).unwrap();

        let materialized = handle.join("settings.json");
        // MUST be a real file, not a symlink. CC reads this as the
        // user-settings layer and CLAUDE_CONFIG_DIR replaces the home
        // settings path, so a symlink to an empty config-N copy would
        // silently drop everything.
        #[cfg(unix)]
        assert!(
            !materialized
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "handle dir settings.json must be a real file"
        );

        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&materialized).unwrap()).unwrap();
        assert_eq!(
            json.pointer("/statusLine/type").and_then(|v| v.as_str()),
            Some("command"),
            "user statusLine must survive materialization"
        );
        assert_eq!(
            json.pointer("/permissions/defaultMode")
                .and_then(|v| v.as_str()),
            Some("bypassPermissions"),
            "user bypassPermissions must survive materialization"
        );
        assert_eq!(
            json.pointer("/enabledPlugins/my-plugin")
                .and_then(|v| v.as_bool()),
            Some(true),
            "user plugin list must survive materialization"
        );
    }

    #[test]
    fn create_handle_dir_merges_third_party_env_overlay() {
        // 3P slot: user has global statusLine, and config-N/settings.json
        // carries the provider env block. Both must appear in the
        // materialized handle dir settings.json — the user keeps their
        // statusline, CC picks up ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{
                "statusLine": { "type": "command", "command": "echo hi" },
                "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" }
            }"#,
        )
        .unwrap();

        let config = base.join("config-9");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "9").unwrap();
        std::fs::write(
            config.join("settings.json"),
            r#"{
                "env": {
                    "ANTHROPIC_BASE_URL": "https://api.minimax.io/anthropic",
                    "ANTHROPIC_AUTH_TOKEN": "sk-slot-test",
                    "ANTHROPIC_MODEL": "MiniMax-M2"
                }
            }"#,
        )
        .unwrap();

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(9u16).unwrap(),
            66666,
        )
        .unwrap();

        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();

        // User keeps statusline
        assert_eq!(
            json.pointer("/statusLine/command").and_then(|v| v.as_str()),
            Some("echo hi")
        );
        // 3P env block merged in
        let env = json.get("env").unwrap();
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").and_then(|v| v.as_str()),
            Some("https://api.minimax.io/anthropic")
        );
        assert_eq!(
            env.get("ANTHROPIC_AUTH_TOKEN").and_then(|v| v.as_str()),
            Some("sk-slot-test")
        );
        // User's other env keys also preserved alongside the 3P overlay
        assert_eq!(
            env.get("CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS")
                .and_then(|v| v.as_str()),
            Some("1")
        );
    }

    #[test]
    fn create_handle_dir_tolerates_missing_user_settings() {
        // Fresh install: no ~/.claude/settings.json yet. Handle dir
        // materialization must not fail; the file is just the config-N
        // overlay (or empty for OAuth slots).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 2);

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(2u16).unwrap(),
            55555,
        )
        .unwrap();

        let content = std::fs::read_to_string(handle.join("settings.json")).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        assert!(json.is_object());
    }

    #[test]
    fn create_handle_dir_tolerates_malformed_user_settings() {
        // User has a typo in ~/.claude/settings.json. We log a warning
        // and proceed with an empty base — the alternative is leaving
        // the user stranded with no handle dir at all.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), r#"{ not valid json"#).unwrap();
        setup_config_dir(base, 3);

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(3u16).unwrap(),
            44444,
        )
        .unwrap();

        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert!(json.is_object());
    }

    #[test]
    fn repoint_rewrites_claude_json_for_new_slot() {
        let _env_guard = crate::platform::test_env::lock();
        // Alpha.10 regression fix: csq swap used to leave .claude.json
        // as the copy from whichever slot the handle dir was created
        // with. CC reads per-account caches from that file
        // (oauthAccount, overageCreditGrantCache,
        // cachedExtraUsageDisabledReason, cachedGrowthBookFeatures,
        // etc.) and displays "you've hit your limit" off the stale
        // cache without hitting Anthropic for a fresh answer. This
        // test asserts swap rewrites .claude.json so the new slot's
        // state wins.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Two slots. Each has a distinct .claude.json with account
        // identity and an account-scoped cache.
        let slot1 = base.join("config-1");
        std::fs::create_dir_all(&slot1).unwrap();
        std::fs::write(slot1.join(".csq-account"), "1").unwrap();
        std::fs::write(slot1.join(".credentials.json"), "{}").unwrap();
        std::fs::write(
            slot1.join(".claude.json"),
            r#"{
                "oauthAccount": { "emailAddress": "one@example.com", "accountUuid": "uuid-1" },
                "cachedExtraUsageDisabledReason": "org_level_disabled",
                "overageCreditGrantCache": { "uuid-1": { "info": { "available": false } } }
            }"#,
        )
        .unwrap();

        let slot2 = base.join("config-2");
        std::fs::create_dir_all(&slot2).unwrap();
        std::fs::write(slot2.join(".csq-account"), "2").unwrap();
        std::fs::write(slot2.join(".credentials.json"), "{}").unwrap();
        std::fs::write(
            slot2.join(".claude.json"),
            r#"{
                "oauthAccount": { "emailAddress": "two@example.com", "accountUuid": "uuid-2" }
            }"#,
        )
        .unwrap();

        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(1u16).unwrap(),
            22222,
        )
        .unwrap();

        // Before swap: handle dir's .claude.json matches slot 1.
        let pre: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(
            pre.pointer("/oauthAccount/emailAddress")
                .and_then(|v| v.as_str()),
            Some("one@example.com")
        );
        assert_eq!(
            pre.pointer("/cachedExtraUsageDisabledReason")
                .and_then(|v| v.as_str()),
            Some("org_level_disabled"),
            "pre-swap should reflect slot 1's stale cache"
        );

        // Swap to slot 2.
        repoint_verified_fixture(
            base,
            &claude_home,
            &handle,
            AccountNum::try_from(2u16).unwrap(),
        )
        .unwrap();

        // Post-swap: handle dir's .claude.json matches slot 2. Stale
        // cache from slot 1 must be gone — slot 2 never had it.
        let post: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(
            post.pointer("/oauthAccount/emailAddress")
                .and_then(|v| v.as_str()),
            Some("two@example.com"),
            "swap must rewrite .claude.json to reflect new slot identity"
        );
        assert!(
            post.get("cachedExtraUsageDisabledReason").is_none(),
            "swap must drop account-scoped cache from previous slot: {post}"
        );
        assert!(
            post.get("overageCreditGrantCache").is_none(),
            "swap must drop overage credit cache from previous slot: {post}"
        );
    }

    #[test]
    fn repoint_preserves_session_scoped_projects() {
        let _env_guard = crate::platform::test_env::lock();
        // CC writes per-project state into .claude.json's projects map
        // during a session (MCP server state, model selection, resume
        // list, etc.). That state is scoped to the current CWD and must
        // survive a swap — otherwise --resume forgets the current
        // session and users lose their continuity.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        // Write slot 2's .claude.json with a project entry for a
        // DIFFERENT cwd (should be stripped on swap).
        std::fs::write(
            base.join("config-2/.claude.json"),
            r#"{
                "oauthAccount": { "emailAddress": "two@example.com" },
                "projects": {
                    "/some/other/dir": { "lastModel": "old" }
                }
            }"#,
        )
        .unwrap();

        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(1u16).unwrap(),
            11111,
        )
        .unwrap();

        // Simulate CC writing a session-scoped project entry after
        // handle dir creation. Use the CWD so the scoping preserves it.
        let cwd = std::env::current_dir().unwrap();
        let cwd_str = cwd.to_string_lossy().to_string();
        let handle_cj = handle.join(".claude.json");
        let existing: Value = serde_json::from_str(
            &std::fs::read_to_string(&handle_cj).unwrap_or_else(|_| "{}".into()),
        )
        .unwrap_or(Value::Object(serde_json::Map::new()));
        let mut existing_obj = existing.as_object().cloned().unwrap_or_default();
        let mut projects = serde_json::Map::new();
        projects.insert(
            cwd_str.clone(),
            serde_json::json!({ "cc_session_state": "session-in-progress" }),
        );
        existing_obj.insert("projects".to_string(), Value::Object(projects));
        std::fs::write(
            &handle_cj,
            serde_json::to_string_pretty(&Value::Object(existing_obj)).unwrap(),
        )
        .unwrap();

        // Swap to slot 2.
        repoint_verified_fixture(
            base,
            &claude_home,
            &handle,
            AccountNum::try_from(2u16).unwrap(),
        )
        .unwrap();

        let post: Value =
            serde_json::from_str(&std::fs::read_to_string(&handle_cj).unwrap()).unwrap();

        // Slot 2 identity is now in place.
        assert_eq!(
            post.pointer("/oauthAccount/emailAddress")
                .and_then(|v| v.as_str()),
            Some("two@example.com")
        );

        // Session-scoped project entry survived the swap (CC's
        // running-session state is preserved).
        assert_eq!(
            post.pointer(&format!(
                "/projects/{}/cc_session_state",
                cwd_str.replace('/', "~1")
            ))
            .and_then(|v| v.as_str()),
            Some("session-in-progress"),
            "session-scoped project state must survive swap: {post}"
        );

        // Slot 2's unrelated-CWD project entry was stripped.
        assert!(
            post.pointer("/projects/~1some~1other~1dir").is_none(),
            "foreign-CWD project from new slot must be stripped: {post}"
        );
    }

    #[test]
    fn repoint_rewrites_materialized_settings_for_new_slot() {
        let _env_guard = crate::platform::test_env::lock();
        // Swap from OAuth slot 1 (no env block) to 3P slot 9 (has env
        // block). The handle dir's settings.json must be re-materialized
        // so the new slot's env lands in it.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{"statusLine": {"type": "command", "command": "user-cmd"}}"#,
        )
        .unwrap();
        setup_config_dir(base, 1);

        stage_verified_repoint_slots(base, &[1]);
        // Exercise the real API-key publication shape: no OAuth UUID.
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "zai",
            AccountNum::try_from(9u16).unwrap(),
            Some("sk-fixture-zai"),
            None,
        )
        .unwrap();
        assert!(profiles::resolve_slot_to_uuid(base, 9).is_none());

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(1u16).unwrap(),
            33333,
        )
        .unwrap();

        // Before swap: only user statusline, no env block
        let pre: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert!(pre.pointer("/env/ANTHROPIC_BASE_URL").is_none());

        // Swap → slot 9
        repoint_handle_dir(
            base,
            &claude_home,
            &handle,
            AccountNum::try_from(9u16).unwrap(),
        )
        .unwrap();

        let post: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        // User statusline preserved
        assert_eq!(
            post.pointer("/statusLine/command").and_then(|v| v.as_str()),
            Some("user-cmd")
        );
        // New slot's env block materialized
        assert_eq!(
            post.pointer("/env/ANTHROPIC_BASE_URL")
                .and_then(|v| v.as_str()),
            Some("https://api.z.ai/api/anthropic")
        );
        assert_eq!(
            post.pointer("/env/ANTHROPIC_AUTH_TOKEN")
                .and_then(|v| v.as_str()),
            Some("sk-fixture-zai")
        );
    }

    #[test]
    fn repoint_third_party_refuses_incomplete_authority_without_mutation() {
        let _env_guard = crate::platform::test_env::lock();
        for damage in ["label", "profiles", "oauth_file", "uuid"] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let home = base.join(".claude");
            std::fs::create_dir_all(&home).unwrap();
            setup_config_dir(base, 1);
            stage_verified_repoint_slots(base, &[1]);
            crate::accounts::third_party::bind_provider_to_slot(
                base,
                "zai",
                AccountNum::try_from(9u16).unwrap(),
                Some("sk-fixture-zai"),
                None,
            )
            .unwrap();
            let handle =
                create_handle_dir(base, &home, AccountNum::try_from(1u16).unwrap(), 33334).unwrap();
            let path = profiles::profiles_path(base);
            match damage {
                "label" => {
                    let mut value = profiles::load(&path).unwrap();
                    value.by_slot_identity.remove("9");
                    profiles::save(&path, &value).unwrap();
                }
                "profiles" => std::fs::write(&path, b"{broken").unwrap(),
                "oauth_file" => {
                    std::fs::write(base.join("config-9/.credentials.json"), b"{}").unwrap();
                }
                "uuid" => {
                    let mut value = profiles::load(&path).unwrap();
                    let oauth = *value.by_slot.get("1").unwrap();
                    value.by_slot.insert("9".into(), oauth);
                    profiles::save(&path, &value).unwrap();
                }
                _ => unreachable!(),
            }
            let before = repoint_fixture_snapshot(base);
            let result =
                repoint_handle_dir(base, &home, &handle, AccountNum::try_from(9u16).unwrap());
            assert!(
                matches!(result, Err(CredentialError::Corrupt { reason, .. }) if reason == "identity_authority_refused"),
                "unverified target must refuse: {damage}"
            );
            assert_eq!(before, repoint_fixture_snapshot(base), "{damage}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn repoint_third_party_refuses_dangling_credential_symlink() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let home = base.join(".claude");
        std::fs::create_dir_all(&home).unwrap();
        setup_config_dir(base, 1);
        stage_verified_repoint_slots(base, &[1]);
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "zai",
            AccountNum::try_from(9u16).unwrap(),
            Some("sk-fixture-zai"),
            None,
        )
        .unwrap();
        let handle =
            create_handle_dir(base, &home, AccountNum::try_from(1u16).unwrap(), 33335).unwrap();
        std::os::unix::fs::symlink(
            base.join("absent-oauth"),
            base.join("config-9/.credentials.json"),
        )
        .unwrap();
        let before = repoint_fixture_snapshot(base);
        assert!(
            repoint_handle_dir(base, &home, &handle, AccountNum::try_from(9u16).unwrap(),).is_err()
        );
        assert_eq!(before, repoint_fixture_snapshot(base));
    }

    #[test]
    fn repoint_refuses_legacy_config_dir() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let before = repoint_fixture_snapshot(base);
        let result = repoint_handle_dir(
            base,
            &claude_home,
            &config,
            AccountNum::try_from(2u16).unwrap(),
        );
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CredentialError::Corrupt { reason, .. }) if reason == "identity_authority_refused")
        );
        assert_eq!(before, repoint_fixture_snapshot(base));
    }

    #[test]
    fn sweep_removes_dead_handles() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Create a handle dir with PID 1 (init, always alive on Unix)
        // and one with a definitely-dead PID
        let alive = base.join("term-1");
        std::fs::create_dir_all(&alive).unwrap();
        std::fs::write(alive.join(".live-pid"), "1").unwrap();

        let dead = base.join("term-999999999");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999999").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(!dead.exists(), "dead handle dir should be removed");
        // PID 1 (init) should still be alive on unix, so term-1 stays
        #[cfg(unix)]
        assert!(alive.exists(), "live handle dir should remain");

        assert!(removed >= 1);
    }

    // R1/KC4-9: a leftover pre-v4 `.keychain-account-change-pending` marker
    // in a LIVE (not dead) handle dir MUST be removed best-effort by the
    // sweep, even though the dir itself survives.
    //
    // RED against the pre-R1 sweep (no cleanup step) would print:
    // assertion failed: !stale_marker.exists() — the file survives the sweep.
    #[test]
    fn sweep_removes_leftover_pre_v4_account_change_pending_marker() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let alive = base.join("term-1");
        std::fs::create_dir_all(&alive).unwrap();
        std::fs::write(alive.join(".live-pid"), "1").unwrap();
        let stale_marker = alive.join(".keychain-account-change-pending");
        std::fs::write(&stale_marker, b"").unwrap();

        sweep_dead_handles(base, Some(&claude_home));

        #[cfg(unix)]
        {
            assert!(alive.exists(), "the live handle dir itself must survive");
            assert!(
                !stale_marker.exists(),
                "a leftover pre-v4 account-change-pending marker must be removed"
            );
        }
    }

    // ── dead-handle reaper clears the keychain OAuth item (fix/sweep-dead-
    // handles-clears-keychain) ──────────────────────────────────────────
    //
    // an internal ticket closed the keychain-orphan gap on `csq logout`; its own doc
    // comment on `clear_bound_keychain_items` names this reaper path as the
    // one still open. The item is keyed on the dir's canonicalized path, and
    // the reaper is about to delete that path — once it does, nothing can
    // locate the item again unless a future `csq run` happens to recycle the
    // same `term-<pid>` path, so an unreaped item risks becoming a
    // PERMANENT orphan (see `clear_dead_handle_keychain_item` above). an internal ticket
    // separately made `csq run` always pass `account_changed=true` on its
    // own keychain sync, so even a recycled path self-heals on its NEXT
    // launch regardless of this reaper — what reaping here closes is the
    // orphan/litter window, not a credential-collision risk.
    //
    // An unconfirmed clear is also routed into the security-review-1386 H1
    // pending-clear queue (`keychain::record_pending_clear`), the SAME
    // mechanism `logout::clear_bound_keychain_items` uses. That is proven on
    // TWO axes, because one instrument cannot carry both:
    //
    // - **Queue CONTENT**, by reading `keychain-pending-clears.json` directly
    //   rather than spying — `record_pending_clear` is pure file I/O and is NOT
    //   gated by `keychain_mirror_disabled()` (see its own doc comment), so this
    //   exercises the real write. macOS-ONLY: that function is
    //   `#[cfg(not(target_os = "macos"))] {}`, a structural no-op elsewhere, so
    //   off macOS the file is absent whether the arm queued or was deleted
    //   outright — an instrument that cannot return the other answer
    //   (`instrument-discipline.md` MUST-1). Same gate the sibling
    //   `..._all_drain_arms` below and keychain.rs's own pending-clear block
    //   already carry.
    // - **WIRING**, on EVERY platform including the Linux enterprise runner, via
    //   the `clear_dead_handle_keychain_item_inner` `record_fn` seam — the same
    //   argument that made `clear_fn` a seam, applied to the recorder.

    /// `clear_dead_handle_keychain_item` MUST invoke `clear_fn` for a dead
    /// dir whose `.credentials.json` is Anthropic-shaped — this is the
    /// "sweeper clears the item" half. Uses an injected spy (not the real
    /// `keychain::clear_handle_dir_reporting`, which is `Ok(false)`
    /// unconditionally under `cfg!(test)` and therefore CANNOT distinguish
    /// "called" from "never called" by its return value alone).
    #[test]
    fn clear_dead_handle_keychain_item_calls_clear_fn_for_anthropic_bound_dir() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
        )
        .unwrap();

        let mut called = false;
        let mut spy = |_p: &Path| {
            called = true;
            Ok(true)
        };
        clear_dead_handle_keychain_item(dir.path(), 999_999_998, base.path(), &mut spy);

        assert!(
            called,
            "an Anthropic-shaped dead dir must trigger the keychain clear call"
        );
    }

    /// The cost predicate half: a dead dir that never held an Anthropic
    /// credential (absent `.credentials.json`) MUST NOT trigger a keychain
    /// call at all — proven with the same spy technique, discriminating
    /// "not called" from "called and happened to no-op".
    #[test]
    fn clear_dead_handle_keychain_item_skips_clear_fn_when_no_credential_file() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        // No `.credentials.json` written at all.

        let mut called = false;
        let mut spy = |_p: &Path| {
            called = true;
            Ok(true)
        };
        clear_dead_handle_keychain_item(dir.path(), 999_999_997, base.path(), &mut spy);

        assert!(
            !called,
            "a dir that never held an Anthropic credential must not trigger a \
             keychain call — this is the cost predicate the reaper needs on its \
             every-account, every-tick hot path"
        );
    }

    /// Same cost-predicate proof for a non-Anthropic (Codex/3P) credential
    /// shape — a `term-*` handle dir CAN be bound to a 3P provider, and its
    /// `.credentials.json` never has the `claudeAiOauth` shape the Anthropic
    /// keychain mirror writes under.
    #[test]
    fn clear_dead_handle_keychain_item_skips_clear_fn_for_non_anthropic_credential() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"openaiAuth":{"token":"x"}}"#,
        )
        .unwrap();

        let mut called = false;
        let mut spy = |_p: &Path| {
            called = true;
            Ok(true)
        };
        clear_dead_handle_keychain_item(dir.path(), 999_999_996, base.path(), &mut spy);

        assert!(
            !called,
            "a non-Anthropic credential shape must not trigger a keychain call"
        );
    }

    /// An unconfirmed clear (`Err(KeychainClearUnconfirmed)`, e.g. a locked
    /// keychain) MUST NOT panic and MUST NOT abort the caller — the reaper's
    /// fail-open posture. Proven by simply not panicking; the WARN log this
    /// path emits is covered by `security.md` MUST-2 / `zero-tolerance.md`
    /// Rule 3 (fixed-vocabulary `error_kind`, no path) by code inspection —
    /// matching `logout.rs`'s equivalent handling of the same error variant.
    #[test]
    fn clear_dead_handle_keychain_item_does_not_panic_on_unconfirmed_clear() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
        )
        .unwrap();

        let mut spy = |_p: &Path| Err(crate::credentials::keychain::KeychainClearUnconfirmed);
        clear_dead_handle_keychain_item(dir.path(), 999_999_995, base.path(), &mut spy);
        // Reaching here without panicking is the assertion.
    }

    /// Security review 1386 H1, mirrored here: an unconfirmed clear MUST be
    /// durably queued for retry, not just logged and dropped — this dir is
    /// deleted (tombstone-renamed) immediately after this call returns, so
    /// the item is UNREACHABLE the instant that happens; this is a
    /// STRONGER case than logout's (logout's file copies are merely deleted
    /// moments later — this caller cannot even reconstruct `abs` again
    /// afterward). Proven by reading `keychain-pending-clears.json`
    /// directly (not a spy) — `record_pending_clear` is real file I/O, not
    /// gated by `keychain_mirror_disabled()`, so this is genuine coverage
    /// of the write, not a stand-in for it.
    ///
    /// **macOS-only, and not to dodge a red job.** `record_pending_clear` is
    /// `#[cfg(not(target_os = "macos"))] pub fn record_pending_clear(_, _) {}`
    /// — a structural no-op on every other target, because there is no keychain
    /// there to have queued anything for. So off macOS this file is absent
    /// whether the production arm queues correctly or the `record_fn` call is
    /// deleted outright: no result this instrument can produce would falsify
    /// the claim (`instrument-discipline.md` MUST-1), and it panicked on the
    /// Linux enterprise runner for exactly that reason. Same gate the sibling
    /// `clear_dead_handle_keychain_item_all_drain_arms` below and every
    /// pending-clear test in `keychain.rs` already carry. The platform-
    /// independent half — that the unconfirmed arm reaches the recorder at all,
    /// with this dir's own service name — is
    /// `clear_dead_handle_keychain_item_wiring_reaches_recorder_on_unconfirmed`
    /// below, which DOES run on Linux.
    #[cfg(target_os = "macos")]
    #[test]
    fn clear_dead_handle_keychain_item_queues_unconfirmed_clear_for_retry() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
        )
        .unwrap();
        let abs = std::fs::canonicalize(dir.path()).unwrap();
        let expected_service = crate::credentials::keychain::service_name(&abs);

        let mut spy = |_p: &Path| Err(crate::credentials::keychain::KeychainClearUnconfirmed);
        clear_dead_handle_keychain_item(dir.path(), 999_999_994, base.path(), &mut spy);

        let queue_raw = std::fs::read_to_string(base.path().join("keychain-pending-clears.json"))
            .expect("an unconfirmed clear must persist the pending-clears queue file");
        let queue: serde_json::Value = serde_json::from_str(&queue_raw).unwrap();
        // Security review 1386 round 2: each entry is now an object
        // ({service, attempts, next_attempt_unix_secs}), not a bare string —
        // pull the `service` field out of each.
        let services: Vec<&str> = queue["services"]
            .as_array()
            .expect("queue file must have a services array")
            .iter()
            .map(|v| v["service"].as_str().unwrap())
            .collect();
        assert_eq!(
            services,
            vec![expected_service.as_str()],
            "the dead dir's own service name must be queued for retry"
        );
    }

    /// The cost predicate ALSO gates the pending-clear queue write — a dir
    /// that never had an Anthropic credential must not just skip the
    /// keychain call, it must not touch the queue file either (no service
    /// name to even compute).
    #[test]
    fn clear_dead_handle_keychain_item_skips_queue_write_when_no_credential_file() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        // No `.credentials.json` written at all.

        let mut spy = |_p: &Path| Err(crate::credentials::keychain::KeychainClearUnconfirmed);
        clear_dead_handle_keychain_item(dir.path(), 999_999_993, base.path(), &mut spy);

        assert!(
            !base.path().join("keychain-pending-clears.json").exists(),
            "a dir with no Anthropic credential must never reach the queue write"
        );
    }

    /// The platform-independent half of the H1 retry-queue proof — this one
    /// runs on the LINUX enterprise runner, where the two file-reading tests
    /// above cannot discriminate anything (`record_pending_clear` is a
    /// `#[cfg(not(target_os = "macos"))]` no-op there, so the queue file is
    /// absent either way).
    ///
    /// Spies on the `record_fn` seam instead of the file, so it pins the
    /// WIRING on every target: the unconfirmed arm reaches the recorder, with
    /// the caller's own `base_dir` and THIS dir's canonicalized service name —
    /// and the cost predicate gates the recorder too, not just `clear_fn`.
    ///
    /// Mutations this catches, on Linux as well as macOS: deleting the
    /// `record_fn(...)` call (arm 1 sees 0 calls); moving it above the
    /// `handle_dir_might_have_anthropic_keychain_item` gate or out of the
    /// `if let Err(..)` arm (arms 2 and 3 see a spurious call); passing the
    /// non-canonical `path` or a hardcoded/parent service name (arm 1's
    /// service assert); passing the wrong `base_dir` (arm 1's base assert).
    #[test]
    fn clear_dead_handle_keychain_item_wiring_reaches_recorder_on_unconfirmed() {
        let anthropic = r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#;
        // (credential contents, clear_fn verdict, expected recorder calls)
        let cases: [(&str, Option<&str>, Result<bool, _>, usize); 3] = [
            (
                "unconfirmed clear on an Anthropic dir",
                Some(anthropic),
                Err(crate::credentials::keychain::KeychainClearUnconfirmed),
                1,
            ),
            (
                "confirmed clear must NOT queue",
                Some(anthropic),
                Ok(true),
                0,
            ),
            (
                "no credential file — cost predicate gates the recorder too",
                None,
                Err(crate::credentials::keychain::KeychainClearUnconfirmed),
                0,
            ),
        ];

        for (label, creds, verdict, expected_calls) in cases {
            let base = TempDir::new().unwrap();
            let dir = TempDir::new().unwrap();
            if let Some(raw) = creds {
                std::fs::write(dir.path().join(".credentials.json"), raw).unwrap();
            }

            let mut recorded: Vec<(std::path::PathBuf, String)> = Vec::new();
            let mut clear_spy = |_p: &Path| verdict;
            let mut record_spy =
                |b: &Path,
                 s: &str,
                 _acct: Option<AccountNum>,
                 _email: Option<String>,
                 _hint: Option<String>,
                 _queued_identity: Option<(u64, i64)>| {
                    recorded.push((b.to_path_buf(), s.to_string()))
                };
            clear_dead_handle_keychain_item_inner(
                dir.path(),
                999_999_991,
                base.path(),
                &mut clear_spy,
                &mut record_spy,
            );

            assert_eq!(
                recorded.len(),
                expected_calls,
                "{label}: expected {expected_calls} recorder call(s), got {}",
                recorded.len()
            );
            if expected_calls == 1 {
                let abs = std::fs::canonicalize(dir.path()).unwrap();
                assert_eq!(
                    recorded[0].0,
                    base.path(),
                    "{label}: the recorder must be handed the caller's own base_dir"
                );
                assert_eq!(
                    recorded[0].1,
                    crate::credentials::keychain::service_name(&abs),
                    "{label}: the recorder must be handed THIS dead dir's own \
                     canonicalized service name — a non-canonical or borrowed one \
                     hashes to an item nothing will ever retry"
                );
            }
        }
    }

    /// `keychain-fix-r10.md` T-f: the retry-queue recorder must actually
    /// receive the resolved candidate email and keychain-account hint at
    /// queue time (not `None`/`None`) — by retry time (`sweep_pending_clears`)
    /// this dir is gone and there is nothing left to re-resolve either from
    /// (`clear_dead_handle_keychain_item_inner`'s own doc). The sibling wiring
    /// test above discards both fields (`_email`, `_hint`) entirely, so it
    /// could not have caught either one silently regressing to `None`.
    ///
    /// `.csq-keychain-account` is [`crate::credentials::keychain::RECORDED_ACCOUNT_FILE`]
    /// (private to that module) — a valid recorded hint here makes
    /// `keychain_account_for` return it directly with NO live keychain call
    /// (hermetic, per COMMON.md's hard limits).
    ///
    /// RED: reverting either `email` or `Some(account_hint)` in the
    /// production `record_fn(...)` call to `None` makes this test's
    /// corresponding assertion fail.
    #[test]
    fn clear_dead_handle_keychain_item_records_email_and_hint_at_queue_time() {
        let base = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"dead-dir@test.invalid"}}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(".csq-keychain-account"), "recorded-hint").unwrap();

        let mut recorded_email: Option<Option<String>> = None;
        let mut recorded_hint: Option<Option<String>> = None;
        let mut clear_spy = |_p: &Path| Err(crate::credentials::keychain::KeychainClearUnconfirmed);
        let mut record_spy = |_b: &Path,
                              _s: &str,
                              _acct: Option<AccountNum>,
                              email: Option<String>,
                              hint: Option<String>,
                              _queued_identity: Option<(u64, i64)>| {
            recorded_email = Some(email);
            recorded_hint = Some(hint);
        };
        clear_dead_handle_keychain_item_inner(
            dir.path(),
            999_999_990,
            base.path(),
            &mut clear_spy,
            &mut record_spy,
        );

        assert_eq!(
            recorded_email,
            Some(Some("dead-dir@test.invalid".to_string())),
            "the resolved candidate email must be recorded at queue time, not None"
        );
        // The hint is resolved by `keychain_account_for`, which reads the
        // recorded file ONLY on macOS; off macOS it is a documented
        // structural no-op returning "" (no keychain account exists there).
        // Either way the resolved value must reach `record_fn` — never None.
        #[cfg(target_os = "macos")]
        let expected_hint = "recorded-hint";
        #[cfg(not(target_os = "macos"))]
        let expected_hint = "";
        assert_eq!(
            recorded_hint,
            Some(Some(expected_hint.to_string())),
            "the resolved keychain-account hint must be recorded at queue time, not None"
        );
    }

    /// Security review 1386 F1 + N1, closed on the shared `drain_service_inner`
    /// loop this reaper's production `clear_fn`
    /// (`keychain::clear_handle_dir_reporting` -> `clear_service_reporting` ->
    /// `drain_service` -> `drain_service_inner`) delegates to. Two upstream
    /// fixes landed in sequence and each changed what a single exit code
    /// means here:
    ///
    /// - **F1**: before it, a refusing-but-completed `security` call (a
    ///   prompt non-zero exit, NOT a hang) was scored identical to a real
    ///   success, so this reaper's `Err` branch — and therefore
    ///   `record_pending_clear` — was UNREACHABLE from a refusal.
    /// - **N1**: `security delete-generic-password` removes exactly ONE
    ///   matching item per call, so a lone exit `0` means PROGRESS (a
    ///   duplicate was deleted, a sibling may remain), never ABSENCE by
    ///   itself. Only `SECURITY_ITEM_NOT_FOUND` (44) confirms absence; the
    ///   loop keeps calling on `0` up to `MAX_DUPLICATE_DELETE_ITERATIONS`
    ///   before giving up unconfirmed.
    ///
    /// This test drives the REAL loop (`keychain::drain_service_inner`) with
    /// a SCRIPTED SEQUENCE of exit codes per case — not a single classified
    /// value — so it fails if the loop's shape ever changes, not just if
    /// this reaper's own wrapper logic regresses:
    ///
    /// | script                              | verdict     | expected reaper behavior | mutation this arm CATCHES (not merely represents) |
    /// |---------------------------------------|-------------|---------------------------|------|
    /// | `[SECURITY_ITEM_NOT_FOUND]`            | confirmed   | NOT queued                | a fix that queues on ANY exit, including `44` |
    /// | `[0, SECURITY_ITEM_NOT_FOUND]`         | confirmed   | NOT queued (the N1 case — one duplicate drained, then absence) | `Some(0) => return Err(..)` — progress misread as FAILURE |
    /// | `[0; MAX_DUPLICATE_DELETE_ITERATIONS]` | unconfirmed | queued (cap exhausted, never confirms) | `Some(0) => return Ok(true)` — progress misread as ABSENCE (the actual pre-N1 bug) |
    /// | `[51]`                                 | unconfirmed | queued (a refusal)        | a fix that confirms on ANY exit, including a refusal (the F1 bug) |
    ///
    /// **Verified, not assumed** (a prior review round claimed the `[0, 44]`
    /// arm was the one that "pins N1" — it is not; RE-RUNNING the
    /// `Some(0) => return Ok(true)` mutation against it shows it returns
    /// `Ok(true)` on the FIRST element either way, buggy or fixed, so it
    /// cannot distinguish them for THAT mutation). It DOES distinguish the
    /// opposite error (`Some(0) => return Err(..)`, above), which is why it
    /// stays: the two arms guard opposite misreadings of the SAME match arm,
    /// not the same one twice. Do not delete `[0, 44]` as "redundant" after
    /// observing it pass under the `return Ok(true)` mutation — it is
    /// discriminating against a different one.
    ///
    /// The must-NOT-queue arms matter as much as the must-queue ones: an
    /// over-eager fix that queued on ANY `0` would pass a test that checked
    /// only the refusal case, then leave every genuinely-cleared duplicate
    /// permanently in the retry queue; a fix that confirmed on a LONE `0`
    /// (the pre-N1 bug, reached a different way) would silently leave a
    /// shadowing sibling's live token unqueued.
    ///
    /// The fifth logical arm — a genuine HANG (`security` never returns,
    /// `run_security_bounded` yields `None`) — has no exit code to construct
    /// and is already covered by
    /// `clear_dead_handle_keychain_item_queues_unconfirmed_clear_for_retry`
    /// above.
    #[cfg(target_os = "macos")]
    #[test]
    fn clear_dead_handle_keychain_item_all_drain_arms() {
        let not_found = crate::credentials::keychain::SECURITY_ITEM_NOT_FOUND;
        let cap = crate::credentials::keychain::MAX_DUPLICATE_DELETE_ITERATIONS as usize;
        let cap_exhausted: Vec<i32> = vec![0; cap];

        let cases: [(&str, &[i32], bool); 4] = [
            // Catches: queuing on ANY exit, including a genuine not-found.
            ("no item, immediately confirmed", &[not_found], false),
            // Catches: `Some(0) => return Err(..)` — progress on the FIRST
            // element misread as a failure. Does NOT catch `Some(0) =>
            // return Ok(true)` (that mutation also confirms on the first
            // element here) — see the cap-exhausted arm below for that one.
            (
                "one duplicate drained, then confirmed (the N1 case)",
                &[0, not_found],
                false,
            ),
            // Catches: `Some(0) => return Ok(true)` — progress misread as
            // ABSENCE (the actual pre-N1 bug: a lone `0` confirms
            // immediately instead of looping). This is the arm that fired
            // against that exact mutation.
            (
                "cap exhausted — never confirms",
                cap_exhausted.as_slice(),
                true,
            ),
            // Catches: confirming on ANY exit, including a refusal (the F1 bug).
            ("refused", &[51], true),
        ];

        for (label, script, expect_queued) in cases {
            let base = TempDir::new().unwrap();
            let dir = TempDir::new().unwrap();
            std::fs::write(
                dir.path().join(".credentials.json"),
                r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
            )
            .unwrap();

            // Drive the REAL loop with the scripted sequence — this is the
            // verdict `clear_handle_dir_reporting` would produce in
            // production for a keychain that behaved this way.
            let mut remaining = script.iter().copied();
            let mut delete_fn = |_svc: &str| remaining.next();
            let verdict = crate::credentials::keychain::drain_service_inner(
                "fake-service-for-test",
                &mut delete_fn,
            );

            let mut spy = |_p: &Path| verdict;
            clear_dead_handle_keychain_item(dir.path(), 999_999_992, base.path(), &mut spy);

            let queued = base.path().join("keychain-pending-clears.json").exists();
            assert_eq!(
                queued, expect_queued,
                "{label} (script={script:?}): verdict={verdict:?}, queued={queued}, \
                 expected queued={expect_queued}"
            );
        }
    }

    /// End-to-end wiring, mirroring `logout.rs`'s
    /// `logout_reaches_keychain_clear_step_for_dead_bound_handle_dir`: a
    /// dead, Anthropic-bound `term-<pid>` handle dir is reaped through the
    /// REAL production path (`sweep_dead_handles`, not the `_inner` test
    /// seam) without panicking, and is actually removed. Under `cfg!(test)`
    /// the real `keychain::decide_and_clear_dead_handle` short-circuits to
    /// `Ok(false)` (the SAME `keychain_mirror_disabled()` guard
    /// `clear_handle_dir_reporting` shares — host safety, never shells
    /// `security` from a unit
    /// test), so this proves reachability + no regression on the delete
    /// path, not the real macOS clear (that is
    /// `clear_dead_handle_keychain_item_calls_clear_fn_for_anthropic_bound_dir`
    /// above, via the injectable seam).
    #[test]
    fn sweep_dead_handles_reaches_keychain_clear_step_for_anthropic_bound_dead_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead_pid: u32 = 999_999_994;
        let dead = base.join(format!("term-{dead_pid}"));
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), dead_pid.to_string()).unwrap();
        std::fs::write(
            dead.join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
        )
        .unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(
            !dead.exists(),
            "the Anthropic-bound dead dir must still be reaped after the \
             keychain-clear step is added"
        );
        assert!(removed >= 1);
    }

    /// S2 (an internal ticket): a dead handle dir carrying a non-empty ephemeral
    /// `coc-plugin/` subtree (the CC Level-2 native-materialization surface) is
    /// swept whole — `sweep_dead_handles` renames to a tombstone + recursive
    /// `remove_dir_all`, so the plugin tree tears down with the rest of
    /// `term-<pid>` (spec 07 §7.2.1.1 lifetime guarantee; no new teardown logic).
    #[test]
    fn sweep_removes_dead_handle_with_coc_plugin_subtree() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999999");
        // Populate a realistic coc-plugin/ tree: manifest + one agent/skill/command.
        std::fs::create_dir_all(dead.join("coc-plugin").join(".claude-plugin")).unwrap();
        std::fs::create_dir_all(dead.join("coc-plugin").join("agents")).unwrap();
        std::fs::create_dir_all(dead.join("coc-plugin").join("skills").join("SKILL-Z")).unwrap();
        std::fs::create_dir_all(dead.join("coc-plugin").join("commands")).unwrap();
        std::fs::write(
            dead.join("coc-plugin")
                .join(".claude-plugin")
                .join("plugin.json"),
            b"{}",
        )
        .unwrap();
        std::fs::write(
            dead.join("coc-plugin").join("agents").join("AGENT-Y.md"),
            b"a",
        )
        .unwrap();
        std::fs::write(
            dead.join("coc-plugin")
                .join("skills")
                .join("SKILL-Z")
                .join("SKILL.md"),
            b"s",
        )
        .unwrap();
        std::fs::write(
            dead.join("coc-plugin").join("commands").join("CMD-W.md"),
            b"c",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999999").unwrap();

        // Red-team R1 (deep-analyst): a symlink planted INSIDE coc-plugin must be
        // removed as a LINK, not followed out of the tree — the recursive
        // teardown the CC carve-out (spec 07 §7.2.1.1) depends on must not
        // dereference an interior symlink and delete external content.
        #[cfg(unix)]
        let external = {
            let ext = base.join("external-keep");
            std::fs::create_dir(&ext).unwrap();
            std::fs::write(ext.join("precious.txt"), b"do not delete").unwrap();
            std::os::unix::fs::symlink(&ext, dead.join("coc-plugin").join("escape-link")).unwrap();
            ext
        };

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(
            !dead.exists(),
            "dead handle dir with a non-empty coc-plugin/ subtree must be swept whole"
        );
        #[cfg(unix)]
        assert!(
            external.join("precious.txt").exists(),
            "sweep must NOT follow an interior coc-plugin symlink and delete external content"
        );
        assert!(removed >= 1);
    }

    #[test]
    fn sweep_ignores_config_dirs() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 0);
        assert!(config.exists(), "config dirs must not be swept");
    }

    #[test]
    fn sweep_preserves_image_cache_entries() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Dead handle dir with a populated per-session image cache.
        let dead = base.join("term-999999999");
        let session_a = "01f5a2b8-1234-4abc-9def-fedcba987654";
        let session_b = "02a1b2c3-d4e5-6f70-8910-abcdef012345";
        std::fs::create_dir_all(dead.join("image-cache").join(session_a)).unwrap();
        std::fs::create_dir_all(dead.join("image-cache").join(session_b)).unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_a)
                .join("pasted-0.png"),
            b"PNG-A",
        )
        .unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_b)
                .join("pasted-0.png"),
            b"PNG-B",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999999").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(!dead.exists(), "dead handle dir should be removed");
        assert_eq!(removed, 1);

        let preserved_a = claude_home
            .join("image-cache")
            .join(session_a)
            .join("pasted-0.png");
        let preserved_b = claude_home
            .join("image-cache")
            .join(session_b)
            .join("pasted-0.png");
        assert!(preserved_a.exists(), "session A image should be preserved");
        assert!(preserved_b.exists(), "session B image should be preserved");
        assert_eq!(std::fs::read(preserved_a).unwrap(), b"PNG-A");
        assert_eq!(std::fs::read(preserved_b).unwrap(), b"PNG-B");
    }

    #[test]
    fn sweep_merges_image_cache_on_collision_preserving_live_side() {
        // Dead and live sides share the same session id. The merge
        // branch preserves the live side for any colliding filename,
        // moves in only unique filenames from the dead side. (The old
        // "skip entirely" behavior was a round-1 known limitation —
        // see sweep_merges_colliding_image_cache_session for the
        // positive merge case.)
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let session_id = "deadbeef-1234-4abc-9def-000000000000";

        let existing = claude_home.join("image-cache").join(session_id);
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("live.png"), b"LIVE").unwrap();

        let dead = base.join("term-999999998");
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache").join(session_id).join("dead.png"),
            b"DEAD",
        )
        .unwrap();
        // Same filename as the live side — must NOT be clobbered.
        std::fs::write(
            dead.join("image-cache").join(session_id).join("live.png"),
            b"DEAD-COLLIDER",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999998").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(!dead.exists(), "dead handle dir should still be removed");
        assert_eq!(removed, 1);

        // Live side untouched
        assert_eq!(
            std::fs::read(existing.join("live.png")).unwrap(),
            b"LIVE",
            "pre-existing session data must not be clobbered"
        );
        // New filename merged in
        assert_eq!(
            std::fs::read(existing.join("dead.png")).unwrap(),
            b"DEAD",
            "unique filename from dead side must be merged into live session"
        );
    }

    #[test]
    fn sweep_handles_missing_image_cache() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Dead handle dir with no image-cache subdir — common case.
        let dead = base.join("term-999999997");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999997").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);
        assert!(!dead.exists());
    }

    // ─── hardening tests from redteam round 1 ─────────────────────

    #[test]
    fn is_valid_session_name_accepts_uuids_and_rejects_hostile_names() {
        // Valid (canonical lowercase UUID)
        assert!(is_valid_session_name(std::ffi::OsStr::new(
            "01234567-89ab-4cde-8f01-23456789abcd"
        )));
        assert!(is_valid_session_name(std::ffi::OsStr::new("deadbeef")));
        assert!(is_valid_session_name(std::ffi::OsStr::new(
            "0123456789abcdef"
        )));

        // Hostile / non-UUID names
        assert!(!is_valid_session_name(std::ffi::OsStr::new("")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("..")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("foo/bar")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("foo.png")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("foo bar")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("GHIJKL")));

        // Uppercase hex rejected — APFS/HFS+ case-folding could
        // otherwise collide `DEADBEEF-...` with `deadbeef-...`.
        assert!(!is_valid_session_name(std::ffi::OsStr::new(
            "DEADBEEF-1234-4ABC-9DEF-000000000000"
        )));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("ABCDEF")));

        // Too long
        assert!(!is_valid_session_name(std::ffi::OsStr::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefX"
        )));
    }

    #[test]
    fn sweep_rejects_non_uuid_session_names() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999996");
        // Valid name — should move
        let valid = "01234567-89ab-4cde-8f01-23456789abcd";
        // Hostile name — should be skipped (not moved, not clobbering anything)
        let hostile = "hostile.dir";
        std::fs::create_dir_all(dead.join("image-cache").join(valid)).unwrap();
        std::fs::create_dir_all(dead.join("image-cache").join(hostile)).unwrap();
        std::fs::write(dead.join("image-cache").join(valid).join("ok.png"), b"OK").unwrap();
        std::fs::write(
            dead.join("image-cache").join(hostile).join("evil.png"),
            b"EVIL",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999996").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert_eq!(removed, 1);
        assert!(
            claude_home
                .join("image-cache")
                .join(valid)
                .join("ok.png")
                .exists(),
            "valid session should be preserved"
        );
        assert!(
            !claude_home.join("image-cache").join(hostile).exists(),
            "hostile session name must not land in shared cache"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlink_src_image_cache() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Something sensitive the attacker wants to redirect to.
        let sensitive = dir.path().join("sensitive-target");
        std::fs::create_dir_all(&sensitive).unwrap();
        std::fs::write(sensitive.join("id_rsa"), b"SECRET").unwrap();

        // Dead handle dir with image-cache as a symlink to sensitive/
        let dead = base.join("term-999999995");
        std::fs::create_dir_all(&dead).unwrap();
        std::os::unix::fs::symlink(&sensitive, dead.join("image-cache")).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999995").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        // Sweep still removes the dead dir (removing a symlink doesn't
        // touch the target).
        assert_eq!(removed, 1);

        // Sensitive file must NOT have been moved into the shared cache.
        assert!(
            sensitive.join("id_rsa").exists(),
            "symlink target must survive sweep"
        );
        assert!(
            !claude_home.join("image-cache").join("id_rsa").exists(),
            "symlink must not have redirected sweep into target dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlink_session_entry() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let sensitive = dir.path().join("secrets");
        std::fs::create_dir_all(&sensitive).unwrap();
        std::fs::write(sensitive.join("key"), b"SECRET").unwrap();

        // Dead handle dir; image-cache/<session-id>/ is a symlink
        let dead = base.join("term-999999994");
        let session_id = "01234567-89ab-4cde-8f01-23456789abcd";
        std::fs::create_dir_all(dead.join("image-cache")).unwrap();
        std::os::unix::fs::symlink(&sensitive, dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999994").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert_eq!(removed, 1);
        // Sensitive data untouched
        assert!(sensitive.join("key").exists());
        // No corresponding entry under the shared cache
        assert!(!claude_home.join("image-cache").join(session_id).exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlink_dst_image_cache() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Attacker-planted symlink: claude_home/image-cache -> /tmp/attacker
        let attacker = dir.path().join("attacker-controlled");
        std::fs::create_dir_all(&attacker).unwrap();
        std::os::unix::fs::symlink(&attacker, claude_home.join("image-cache")).unwrap();

        let dead = base.join("term-999999993");
        let session_id = "01234567-89ab-4cde-8f01-23456789abcd";
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache").join(session_id).join("img.png"),
            b"DATA",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999993").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        // Sweep still removes dead dir, but must NOT write into the
        // redirected attacker location.
        assert_eq!(removed, 1);
        assert!(
            !attacker.join(session_id).exists(),
            "preservation must not follow a symlink at the destination"
        );
    }

    #[test]
    fn sweep_none_claude_home_skips_preservation_but_still_sweeps() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let dead = base.join("term-999999992");
        let session_id = "01234567-89ab-4cde-8f01-23456789abcd";
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache").join(session_id).join("img.png"),
            b"DATA",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999992").unwrap();

        let removed = sweep_dead_handles(base, None);

        assert_eq!(removed, 1);
        assert!(!dead.exists(), "sweep still removes orphan");
        // Image is lost — documented fallback behavior.
    }

    #[test]
    fn sweep_skips_when_live_pid_alive_but_dir_name_pid_dead() {
        // Scenario: handle dir is `term-999999991` but `.live-pid`
        // contains PID 1 (init). The dir-name PID is dead; the
        // marker PID is alive. The authoritative check is .live-pid,
        // so the dir must NOT be swept.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead_dirname = base.join("term-999999991");
        std::fs::create_dir_all(&dead_dirname).unwrap();
        // Marker says PID 1 (init, always alive on Unix)
        std::fs::write(dead_dirname.join(".live-pid"), "1").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        #[cfg(unix)]
        {
            assert_eq!(removed, 0, "dir with alive .live-pid must not be swept");
            assert!(dead_dirname.exists());
        }
        // On non-unix we can't guarantee PID 1 is alive, so skip the
        // assertion there.
        #[cfg(not(unix))]
        {
            let _ = removed;
        }
    }

    #[test]
    fn copy_tree_recursive_preserves_nested_subdirs_and_files() {
        // Not strictly needed for rename (which is atomic on directories)
        // but the EXDEV fallback path must handle nested trees correctly.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("sub1").join("sub2")).unwrap();
        std::fs::write(src.join("top.png"), b"TOP").unwrap();
        std::fs::write(src.join("sub1").join("mid.png"), b"MID").unwrap();
        std::fs::write(src.join("sub1").join("sub2").join("deep.png"), b"DEEP").unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&src, &dst).unwrap();

        assert_eq!(std::fs::read(dst.join("top.png")).unwrap(), b"TOP");
        assert_eq!(
            std::fs::read(dst.join("sub1").join("mid.png")).unwrap(),
            b"MID"
        );
        assert_eq!(
            std::fs::read(dst.join("sub1").join("sub2").join("deep.png")).unwrap(),
            b"DEEP"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_recursive_preserves_directory_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(src.join("a"), b"X").unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&src, &dst).unwrap();

        let mode = dst.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "copy must preserve source dir mode bits (got {:o})",
            mode
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_live_pid_refuses_symlink() {
        // Targets markers::read_live_pid — the sweep path consumes
        // it via the shared markers module rather than a local
        // duplicate. A symlink-at-.live-pid must not be followed.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-12345");
        std::fs::create_dir_all(&handle).unwrap();

        // Plant a symlink at .live-pid pointing at a regular file
        // with "1" (init, always alive). Without the symlink refusal
        // this would read through and report PID 1 alive.
        let target = dir.path().join("outside-file");
        std::fs::write(&target, "1").unwrap();
        std::os::unix::fs::symlink(&target, handle.join(".live-pid")).unwrap();

        assert_eq!(
            markers::read_live_pid(&handle),
            None,
            "symlink .live-pid must be refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_recursive_refuses_symlinks() {
        // Verifies that the EXDEV fallback's tree walker refuses to
        // follow symlinks, closing the same attack surface as
        // sweep_refuses_symlink_session_entry but at the copy layer.
        let dir = TempDir::new().unwrap();
        let sensitive = dir.path().join("secret");
        std::fs::create_dir_all(&sensitive).unwrap();
        std::fs::write(sensitive.join("key"), b"TOP-SECRET").unwrap();

        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("normal.txt"), b"ok").unwrap();
        std::os::unix::fs::symlink(&sensitive, src.join("redirect")).unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&src, &dst).unwrap();

        assert!(dst.join("normal.txt").exists());
        assert!(
            !dst.join("redirect").exists(),
            "symlink copy must not follow"
        );
        assert!(
            !dst.join("redirect").join("key").exists(),
            "symlink target must not leak into destination"
        );
    }

    // ─── residual-risk resolution tests (post-redteam round 6) ────

    #[test]
    fn sweep_merges_colliding_image_cache_session() {
        // Terminal A ran session UUID-1, pasted image-0.png, was
        // swept → ~/.claude/image-cache/UUID-1/image-0.png. Terminal B
        // resumed UUID-1, pasted image-1.png in a new handle dir, died.
        // Sweep must MERGE image-1.png into the existing shared
        // session without clobbering image-0.png.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let session_id = "deadbeef-1234-4abc-9def-111111111111";

        let existing = claude_home.join("image-cache").join(session_id);
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("image-0.png"), b"A0").unwrap();

        let dead = base.join("term-999999990");
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_id)
                .join("image-1.png"),
            b"B1",
        )
        .unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_id)
                .join("image-0.png"),
            b"B0-newer",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999990").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);
        assert!(!dead.exists());

        assert_eq!(
            std::fs::read(existing.join("image-1.png")).unwrap(),
            b"B1",
            "new filename must be merged"
        );
        assert_eq!(
            std::fs::read(existing.join("image-0.png")).unwrap(),
            b"A0",
            "existing file must not be clobbered"
        );
    }

    #[test]
    fn sweep_merges_colliding_session_with_nested_dirs() {
        // Merge handles sub-directory collision by recursing: a
        // `subfolder/` existing on both sides must not be clobbered,
        // but unique files inside the dead side's `subfolder/` must
        // be moved in.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let sid = "deadbeef-5678-4abc-9def-222222222222";
        let existing = claude_home.join("image-cache").join(sid);
        std::fs::create_dir_all(existing.join("sub")).unwrap();
        std::fs::write(existing.join("sub").join("live.png"), b"LIVE").unwrap();

        let dead = base.join("term-999999989");
        std::fs::create_dir_all(dead.join("image-cache").join(sid).join("sub")).unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(sid)
                .join("sub")
                .join("new.png"),
            b"NEW",
        )
        .unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(sid)
                .join("sub")
                .join("live.png"),
            b"COLLIDER",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999989").unwrap();

        sweep_dead_handles(base, Some(&claude_home));

        assert_eq!(
            std::fs::read(existing.join("sub").join("live.png")).unwrap(),
            b"LIVE"
        );
        assert_eq!(
            std::fs::read(existing.join("sub").join("new.png")).unwrap(),
            b"NEW"
        );
    }

    #[test]
    fn copy_tree_iterative_handles_deep_nesting() {
        // 64 levels — well under the 2048 DEPTH_LIMIT — verifies the
        // iterative walker handles nesting without stack overflow.
        let dir = TempDir::new().unwrap();
        let mut p = dir.path().join("src");
        std::fs::create_dir_all(&p).unwrap();
        for i in 0..64 {
            p = p.join(format!("level-{i}"));
            std::fs::create_dir(&p).unwrap();
        }
        std::fs::write(p.join("leaf.png"), b"LEAF").unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&dir.path().join("src"), &dst).unwrap();

        let mut dst_p = dst.clone();
        for i in 0..64 {
            dst_p = dst_p.join(format!("level-{i}"));
        }
        assert_eq!(std::fs::read(dst_p.join("leaf.png")).unwrap(), b"LEAF");
    }

    #[test]
    fn sweep_leaves_no_tombstone_after_success() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999988");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999988").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);

        let residue: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-")
            })
            .collect();
        assert!(
            residue.is_empty(),
            "tombstones left behind: {:?}",
            residue.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    // ── codex sqlite promotion on reap ────────────────────────────────
    //
    // The share was discovery-only: `codex_shared_pairs` links any `*.sqlite`
    // it finds in `config-N`, but codex creates them in the ephemeral handle
    // dir and the reaper deleted them, so `config-N` was never seeded and every
    // launch rebuilt the index. These pin the seeder.

    /// Builds a dead codex handle dir wired the way `create_handle_dir_codex`
    /// wires a live one: a `config.toml` SYMLINK into `config-N`, which is what
    /// `codex_config_dir_of_handle` resolves the owning slot through.
    #[cfg(unix)]
    fn dead_codex_handle(base: &Path, pid: &str, slot: u16) -> (PathBuf, PathBuf) {
        let config_dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), b"# slot config").unwrap(); // CI-ALLOW-fs-write-config-toml
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), pid).unwrap();
        std::os::unix::fs::symlink(config_dir.join("config.toml"), handle.join("config.toml"))
            .unwrap();
        (handle, config_dir)
    }

    /// Falsifying result, named up front: without the promotion call the reaper
    /// deletes the dir and `config-12/state_5.sqlite` never appears — which is
    /// the shipped behaviour this fixes.
    #[cfg(unix)]
    #[test]
    fn reap_promotes_codex_sqlite_into_config_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let (handle, config_dir) = dead_codex_handle(base, "999999971", 12);

        std::fs::write(handle.join("state_5.sqlite"), b"INDEX").unwrap();
        std::fs::write(handle.join("state_5.sqlite-wal"), b"WAL").unwrap();
        std::fs::write(handle.join("state_5.sqlite-shm"), b"SHM").unwrap();

        assert_eq!(sweep_dead_handles(base, Some(&claude_home)), 1);

        assert_eq!(
            std::fs::read(config_dir.join("state_5.sqlite")).unwrap(),
            b"INDEX",
            "the database must survive the reap in config-N"
        );
        // The WAL can hold committed-but-uncheckpointed transactions after a
        // SIGKILL; promoting the base alone would silently drop them.
        assert_eq!(
            std::fs::read(config_dir.join("state_5.sqlite-wal")).unwrap(),
            b"WAL"
        );
        assert_eq!(
            std::fs::read(config_dir.join("state_5.sqlite-shm")).unwrap(),
            b"SHM"
        );
        assert!(!handle.exists(), "the handle dir is still reaped");
    }

    /// A LIVE shared database must never be clobbered by a straggler handle dir
    /// reaped later — that would swap a full index for a stale one.
    #[cfg(unix)]
    #[test]
    fn reap_does_not_overwrite_an_existing_config_sqlite() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let (handle, config_dir) = dead_codex_handle(base, "999999972", 12);

        std::fs::write(config_dir.join("state_5.sqlite"), b"ESTABLISHED").unwrap();
        std::fs::write(handle.join("state_5.sqlite"), b"STRAGGLER").unwrap();

        assert_eq!(sweep_dead_handles(base, Some(&claude_home)), 1);
        assert_eq!(
            std::fs::read(config_dir.join("state_5.sqlite")).unwrap(),
            b"ESTABLISHED",
            "an occupied config-N slot must not be overwritten"
        );
    }

    /// An entry that is ALREADY a symlink was linked at creation, so its
    /// database already lives in config-N. Renaming it would replace the shared
    /// database with its own link — the file must be left alone.
    #[cfg(unix)]
    #[test]
    fn reap_skips_a_symlinked_sqlite() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let (handle, config_dir) = dead_codex_handle(base, "999999973", 12);

        let shared = config_dir.join("logs_2.sqlite");
        std::fs::write(&shared, b"SHARED").unwrap();
        std::os::unix::fs::symlink(&shared, handle.join("logs_2.sqlite")).unwrap();

        assert_eq!(sweep_dead_handles(base, Some(&claude_home)), 1);
        assert_eq!(
            std::fs::read(&shared).unwrap(),
            b"SHARED",
            "the shared database must still be a real file with its content"
        );
        assert!(shared.symlink_metadata().unwrap().file_type().is_file());
    }

    /// A NON-codex handle dir has no `config.toml` symlink, so there is no slot
    /// to promote into and the reaper must behave exactly as before.
    #[cfg(unix)]
    #[test]
    fn reap_of_a_non_codex_handle_promotes_nothing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let handle = base.join("term-999999974");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), "999999974").unwrap();
        std::fs::write(handle.join("state_5.sqlite"), b"ORPHAN").unwrap();

        assert_eq!(sweep_dead_handles(base, Some(&claude_home)), 1);
        assert!(!handle.exists());
        let strays: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".sqlite"))
            .collect();
        assert!(strays.is_empty(), "nothing promoted to base: {strays:?}");
    }

    #[test]
    fn sweep_cleans_up_stale_tombstones_from_previous_crash() {
        // Simulate a previous sweep that crashed mid-delete, leaving
        // a .sweep-tombstone-* dir behind. Next sweep removes it via
        // the initial cleanup pass.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let tomb = base.join(".sweep-tombstone-12345-abc");
        std::fs::create_dir_all(tomb.join("junk")).unwrap();
        std::fs::write(tomb.join("junk").join("file"), b"X").unwrap();

        sweep_dead_handles(base, Some(&claude_home));
        assert!(
            !tomb.exists(),
            "stale tombstone must be cleaned up on sweep entry"
        );
    }

    #[test]
    fn sweep_skips_when_live_cc_pid_alive() {
        // Windows crash-recovery path: .live-pid names a dead csq-cli
        // PID but .live-cc-pid names an alive CC child. Sweep must
        // honor the live child and skip the dir.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999987");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999987").unwrap();
        // PID 1 (init) is always alive on Unix.
        std::fs::write(dead.join(".live-cc-pid"), "1").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        #[cfg(unix)]
        {
            assert_eq!(removed, 0);
            assert!(
                dead.exists(),
                "dir with alive .live-cc-pid must not be swept"
            );
        }
        #[cfg(not(unix))]
        {
            let _ = removed;
        }
    }

    #[test]
    fn sweep_proceeds_when_live_cc_pid_dead() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999986");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999986").unwrap();
        std::fs::write(dead.join(".live-cc-pid"), "999999985").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);
        assert!(!dead.exists());
    }

    #[cfg(unix)]
    #[test]
    fn read_live_cc_pid_refuses_symlink() {
        // Same symlink defense as read_live_pid, applied to the
        // new Windows child PID marker.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-54321");
        std::fs::create_dir_all(&handle).unwrap();

        let target = dir.path().join("outside");
        std::fs::write(&target, "1").unwrap();
        std::os::unix::fs::symlink(&target, handle.join(".live-cc-pid")).unwrap();

        assert_eq!(
            markers::read_live_cc_pid(&handle),
            None,
            "symlink .live-cc-pid must be refused"
        );
    }

    // ── Issue 2 reproduction: onboarding "re-init" claim ────────────
    //
    // User reports that after `csq install` + manual keybindings.json
    // + first `csq run`, their `~/.claude/settings.json` and
    // statusline "disappear". The tests below pin the actual contract
    // so any future regression is caught:
    //
    //   - `create_handle_dir` must NEVER mutate `~/.claude/settings.json`.
    //   - The handle dir's materialized settings MUST carry through
    //     every user-customized key (statusLine, permissions, plugins,
    //     mcpServers, env).
    //   - On fresh install the global `keybindings.json` must be a
    //     file (issue 1 regression) so a user who manually edits it
    //     doesn't have their `{"bindings": []}` overwritten by a
    //     later `csq run` turning it into a dir.

    #[test]
    #[cfg(unix)]
    fn user_global_settings_json_is_byte_identical_after_csq_run() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Realistic user global: statusLine, permissions, plugins,
        // mcpServers, env. Mirrors what `csq install` + a few weeks
        // of customization would leave behind.
        let user_settings = r#"{
          "$schema": "https://json.schemastore.org/claude-code-settings.json",
          "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" },
          "permissions": {
            "allow": ["Bash(git rm:*)", "WebSearch"],
            "defaultMode": "bypassPermissions"
          },
          "statusLine": { "type": "command", "command": "csq statusline" },
          "enabledPlugins": { "rust-analyzer-lsp@claude-plugins-official": true },
          "alwaysThinkingEnabled": true,
          "effortLevel": "xhigh"
        }
        "#;
        std::fs::write(claude_home.join("settings.json"), user_settings).unwrap();
        let settings_path = claude_home.join("settings.json");
        let before_bytes = std::fs::read(&settings_path).unwrap();

        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 55555).unwrap();
        assert!(handle.exists());

        // The global MUST be untouched — not a single byte changed.
        let after_bytes = std::fs::read(&settings_path).unwrap();
        assert_eq!(
            before_bytes, after_bytes,
            "csq run must never mutate ~/.claude/settings.json"
        );
    }

    #[test]
    #[cfg(unix)]
    fn handle_dir_settings_carries_every_user_customization() {
        // Core of the "re-init" claim: the handle dir CC reads must
        // expose the same keys the user set in the global, so CC
        // doesn't behave as if this is a first-run session.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let user_settings = r#"{
          "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" },
          "permissions": {
            "allow": ["Bash(git *)"],
            "defaultMode": "bypassPermissions"
          },
          "statusLine": { "type": "command", "command": "csq statusline" },
          "enabledPlugins": { "frontend-design@claude-plugins-official": true },
          "enableAllProjectMcpServers": true,
          "alwaysThinkingEnabled": true,
          "effortLevel": "xhigh",
          "voiceEnabled": true
        }
        "#;
        std::fs::write(claude_home.join("settings.json"), user_settings).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 44444).unwrap();

        let materialized: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();

        // Every user-touched key must be present in the handle dir.
        assert_eq!(
            materialized
                .pointer("/statusLine/command")
                .and_then(|v| v.as_str()),
            Some("csq statusline"),
        );
        assert_eq!(
            materialized
                .pointer("/permissions/defaultMode")
                .and_then(|v| v.as_str()),
            Some("bypassPermissions"),
        );
        assert_eq!(
            materialized
                .pointer("/permissions/allow/0")
                .and_then(|v| v.as_str()),
            Some("Bash(git *)"),
        );
        assert_eq!(
            materialized
                .pointer("/enabledPlugins/frontend-design@claude-plugins-official")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            materialized
                .pointer("/env/CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS")
                .and_then(|v| v.as_str()),
            Some("1"),
        );
        assert_eq!(
            materialized
                .pointer("/enableAllProjectMcpServers")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            materialized
                .pointer("/alwaysThinkingEnabled")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            materialized
                .pointer("/effortLevel")
                .and_then(|v| v.as_str()),
            Some("xhigh"),
        );
        assert_eq!(
            materialized
                .pointer("/voiceEnabled")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
    }

    /// Reads the materialized handle settings.json for a finished
    /// `create_handle_dir` call.
    #[cfg(unix)]
    fn read_materialized_settings(handle: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
            .unwrap()
    }

    #[test]
    #[cfg(unix)]
    fn materialized_settings_default_effort_medium_when_no_layer_sets_it() {
        // Neither the user-global nor the slot overlay sets
        // `effortLevel` → the csq default layer supplies "medium".
        // Non-vacuity: this assertion fails if the default resolves to
        // anything other than "medium" (e.g. the former "high", or CC's
        // own "xhigh"), and fails if the key is absent.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{ "permissions": { "defaultMode": "bypassPermissions" } }"#,
        )
        .unwrap();
        setup_config_dir(base, 1); // empty {} overlay

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77777).unwrap();

        let materialized = read_materialized_settings(&handle);
        assert_eq!(
            materialized
                .pointer("/effortLevel")
                .and_then(|v| v.as_str()),
            Some("medium"),
        );
        // The default must not shadow other user-global keys.
        assert_eq!(
            materialized
                .pointer("/permissions/defaultMode")
                .and_then(|v| v.as_str()),
            Some("bypassPermissions"),
        );
        // The user-global itself is untouched — no effortLevel written back.
        let global: Value = serde_json::from_str(
            &std::fs::read_to_string(claude_home.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert!(
            global.get("effortLevel").is_none(),
            "csq must never write its default into the user-global"
        );
    }

    #[test]
    #[cfg(unix)]
    fn handle_local_cross_session_refuse_survives_account_swap() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let global = base.join(".claude");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(global.join("settings.json"), "{}").unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle =
            create_handle_dir(base, &global, AccountNum::try_from(1u16).unwrap(), 77801).unwrap();
        let mut settings = read_materialized_settings(&handle);
        settings["crossSessionInbound"] = serde_json::json!("refuse");
        std::fs::write(
            handle.join("settings.json"),
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        repoint_verified_fixture(base, &global, &handle, AccountNum::try_from(2u16).unwrap())
            .unwrap();
        assert_eq!(
            read_materialized_settings(&handle)["crossSessionInbound"],
            serde_json::json!("refuse")
        );
    }

    #[test]
    #[cfg(unix)]
    fn default_accept_cannot_override_new_slot_refuse_on_swap() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let global = dir.path().join(".claude");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(global.join("settings.json"), "{}").unwrap();
        setup_config_dir(dir.path(), 1);
        let next = setup_config_dir(dir.path(), 2);
        std::fs::write(
            next.join("settings.json"),
            r#"{"crossSessionInbound":"refuse"}"#,
        )
        .unwrap();
        stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
        let handle = create_handle_dir(
            dir.path(),
            &global,
            AccountNum::try_from(1u16).unwrap(),
            77803,
        )
        .unwrap();
        assert_eq!(
            read_materialized_settings(&handle)["crossSessionInbound"],
            serde_json::json!("accept")
        );
        repoint_verified_fixture(
            dir.path(),
            &global,
            &handle,
            AccountNum::try_from(2u16).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_materialized_settings(&handle)["crossSessionInbound"],
            serde_json::json!("refuse")
        );
    }

    #[test]
    #[cfg(unix)]
    fn handle_local_cross_session_choices_keep_the_stricter_swap_policy() {
        let _env_guard = crate::platform::test_env::lock();
        for (previous_choice, next_choice, expected) in [
            ("accept", "accept", "accept"),
            ("accept", "hold", "hold"),
            ("accept", "refuse", "refuse"),
            ("hold", "accept", "hold"),
            ("hold", "hold", "hold"),
            ("hold", "refuse", "refuse"),
            ("refuse", "accept", "refuse"),
            ("refuse", "hold", "refuse"),
            ("refuse", "refuse", "refuse"),
        ] {
            let dir = TempDir::new().unwrap();
            let global = dir.path().join(".claude");
            std::fs::create_dir_all(&global).unwrap();
            std::fs::write(global.join("settings.json"), "{}").unwrap();
            setup_config_dir(dir.path(), 1);
            let next = setup_config_dir(dir.path(), 2);
            std::fs::write(
                next.join("settings.json"),
                serde_json::json!({"crossSessionInbound":next_choice,"effortLevel":"high"})
                    .to_string(),
            )
            .unwrap();
            stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
            let handle = create_handle_dir(
                dir.path(),
                &global,
                AccountNum::try_from(1u16).unwrap(),
                77804,
            )
            .unwrap();
            let mut previous = read_materialized_settings(&handle);
            previous["crossSessionInbound"] = serde_json::json!(previous_choice);
            previous["effortLevel"] = serde_json::json!("low");
            std::fs::write(
                handle.join("settings.json"),
                serde_json::to_vec(&previous).unwrap(),
            )
            .unwrap();
            repoint_verified_fixture(
                dir.path(),
                &global,
                &handle,
                AccountNum::try_from(2u16).unwrap(),
            )
            .unwrap();
            let materialized = read_materialized_settings(&handle);
            assert_eq!(
                materialized["crossSessionInbound"],
                serde_json::json!(expected),
                "previous={previous_choice}, next={next_choice}"
            );
            assert_eq!(materialized["effortLevel"], serde_json::json!("high"));
        }
    }

    #[test]
    #[cfg(unix)]
    fn changed_global_refuse_overrides_previous_default_accept() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let global = dir.path().join(".claude");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(global.join("settings.json"), "{}").unwrap();
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
        let handle = create_handle_dir(
            dir.path(),
            &global,
            AccountNum::try_from(1u16).unwrap(),
            77805,
        )
        .unwrap();
        std::fs::write(
            global.join("settings.json"),
            r#"{"crossSessionInbound":"refuse"}"#,
        )
        .unwrap();
        repoint_verified_fixture(
            dir.path(),
            &global,
            &handle,
            AccountNum::try_from(2u16).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_materialized_settings(&handle)["crossSessionInbound"],
            serde_json::json!("refuse")
        );
    }

    #[test]
    #[cfg(unix)]
    fn invalid_previous_inbound_choice_never_widens_to_accept() {
        let _env_guard = crate::platform::test_env::lock();
        for invalid in [
            serde_json::json!("unknown"),
            serde_json::json!(42),
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            for next_choice in ["accept", "hold", "refuse"] {
                let dir = TempDir::new().unwrap();
                let global = dir.path().join(".claude");
                std::fs::create_dir_all(&global).unwrap();
                std::fs::write(global.join("settings.json"), "{}").unwrap();
                setup_config_dir(dir.path(), 1);
                let next = setup_config_dir(dir.path(), 2);
                std::fs::write(
                    next.join("settings.json"),
                    serde_json::json!({"crossSessionInbound":next_choice}).to_string(),
                )
                .unwrap();
                stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
                let handle = create_handle_dir(
                    dir.path(),
                    &global,
                    AccountNum::try_from(1u16).unwrap(),
                    77807,
                )
                .unwrap();
                let mut previous = read_materialized_settings(&handle);
                previous["crossSessionInbound"] = invalid.clone();
                std::fs::write(
                    handle.join("settings.json"),
                    serde_json::to_vec(&previous).unwrap(),
                )
                .unwrap();
                repoint_verified_fixture(
                    dir.path(),
                    &global,
                    &handle,
                    AccountNum::try_from(2u16).unwrap(),
                )
                .unwrap();
                let actual = read_materialized_settings(&handle);
                if next_choice == "accept" {
                    assert!(
                        actual.get("crossSessionInbound").is_none(),
                        "invalid={invalid}"
                    );
                } else {
                    assert_eq!(
                        actual["crossSessionInbound"],
                        serde_json::json!(next_choice)
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn r4_missing_previous_choice_remains_native_approval_across_swaps() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let global = dir.path().join(".claude");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(global.join("settings.json"), "{}").unwrap();
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
        let handle = create_handle_dir(
            dir.path(),
            &global,
            AccountNum::try_from(1u16).unwrap(),
            77808,
        )
        .unwrap();
        let mut previous = read_materialized_settings(&handle);
        previous
            .as_object_mut()
            .unwrap()
            .remove("crossSessionInbound");
        std::fs::write(
            handle.join("settings.json"),
            serde_json::to_vec(&previous).unwrap(),
        )
        .unwrap();
        for next in [2u16, 1] {
            repoint_verified_fixture(
                dir.path(),
                &global,
                &handle,
                AccountNum::try_from(next).unwrap(),
            )
            .unwrap();
            assert!(
                read_materialized_settings(&handle)
                    .get("crossSessionInbound")
                    .is_none(),
                "existing native approval widened on swap to {next}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn r4_unknown_or_unusable_choice_never_accepts_after_two_swaps() {
        let _env_guard = crate::platform::test_env::lock();
        for previous in [
            r#"{"crossSessionInbound":"unknown"}"#,
            r#"{"crossSessionInbound":42}"#,
            "",
            r#"{"crossSessionInbound":"refuse", "#,
            "[]",
        ] {
            let dir = TempDir::new().unwrap();
            let global = dir.path().join(".claude");
            std::fs::create_dir_all(&global).unwrap();
            std::fs::write(global.join("settings.json"), "{}").unwrap();
            setup_config_dir(dir.path(), 1);
            setup_config_dir(dir.path(), 2);
            stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
            let handle = create_handle_dir(
                dir.path(),
                &global,
                AccountNum::try_from(1u16).unwrap(),
                77809,
            )
            .unwrap();
            std::fs::write(handle.join("settings.json"), previous).unwrap();
            for (swap, next) in [2u16, 1].into_iter().enumerate() {
                repoint_verified_fixture(
                    dir.path(),
                    &global,
                    &handle,
                    AccountNum::try_from(next).unwrap(),
                )
                .unwrap();
                assert!(
                    read_materialized_settings(&handle)
                        .get("crossSessionInbound")
                        .is_none(),
                    "previous={previous:?} widened on swap {}",
                    swap + 1
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn r4_known_approval_replaces_unknown_merged_choice() {
        let _env_guard = crate::platform::test_env::lock();
        for prior_choice in ["hold", "refuse"] {
            for unknown in [
                serde_json::json!("unknown"),
                serde_json::json!(42),
                serde_json::json!(null),
                serde_json::json!([]),
                serde_json::json!({}),
            ] {
                let dir = TempDir::new().unwrap();
                let global = dir.path().join(".claude");
                std::fs::create_dir_all(&global).unwrap();
                std::fs::write(global.join("settings.json"), "{}").unwrap();
                setup_config_dir(dir.path(), 1);
                let config = setup_config_dir(dir.path(), 2);
                std::fs::write(
                    config.join("settings.json"),
                    serde_json::json!({"crossSessionInbound":unknown}).to_string(),
                )
                .unwrap();
                stage_verified_repoint_slots(dir.path(), &[1, 2, 3]);
                let handle = create_handle_dir(
                    dir.path(),
                    &global,
                    AccountNum::try_from(1u16).unwrap(),
                    77810,
                )
                .unwrap();
                let mut previous = read_materialized_settings(&handle);
                previous["crossSessionInbound"] = serde_json::json!(prior_choice);
                std::fs::write(
                    handle.join("settings.json"),
                    serde_json::to_vec(&previous).unwrap(),
                )
                .unwrap();
                repoint_verified_fixture(
                    dir.path(),
                    &global,
                    &handle,
                    AccountNum::try_from(2u16).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    read_materialized_settings(&handle)["crossSessionInbound"],
                    serde_json::json!(prior_choice),
                    "unknown={unknown}"
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn unusable_handle_local_settings_withholds_accept_on_rematerialization() {
        let dir = TempDir::new().unwrap();
        let global = dir.path().join(".claude");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(global.join("settings.json"), "{}").unwrap();
        let config = setup_config_dir(dir.path(), 1);
        let handle = create_handle_dir(
            dir.path(),
            &global,
            AccountNum::try_from(1u16).unwrap(),
            77802,
        )
        .unwrap();
        std::fs::write(
            handle.join("settings.json"),
            r#"{"crossSessionInbound":"refuse", "#,
        )
        .unwrap();
        materialize_handle_settings(&handle, &global, &config).unwrap();
        assert!(read_materialized_settings(&handle)
            .get("crossSessionInbound")
            .is_none());
    }

    #[test]
    #[cfg(unix)]
    fn empty_local_settings_withholds_accept_but_empty_account_layers_keep_default() {
        for empty in ["", " \n\t"] {
            let dir = TempDir::new().unwrap();
            let global = dir.path().join(".claude");
            std::fs::create_dir_all(&global).unwrap();
            std::fs::write(global.join("settings.json"), empty).unwrap();
            let config = setup_config_dir(dir.path(), 1);
            std::fs::write(config.join("settings.json"), empty).unwrap();
            let handle = create_handle_dir(
                dir.path(),
                &global,
                AccountNum::try_from(1u16).unwrap(),
                77804,
            )
            .unwrap();
            assert_eq!(
                read_materialized_settings(&handle)["crossSessionInbound"],
                serde_json::json!("accept")
            );
            std::fs::write(handle.join("settings.json"), empty).unwrap();
            materialize_handle_settings(&handle, &global, &config).unwrap();
            assert!(read_materialized_settings(&handle)
                .get("crossSessionInbound")
                .is_none());
        }
    }

    #[test]
    #[cfg(unix)]
    fn dangling_local_settings_withhold_accept_and_account_layers_keep_default() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let global = dir.path().join(".claude");
        std::fs::create_dir_all(&global).unwrap();
        let config = setup_config_dir(dir.path(), 1);
        let missing_global = global.join("missing-settings-target");
        let missing_slot = config.join("missing-settings-target");
        symlink(&missing_global, global.join("settings.json")).unwrap();
        std::fs::remove_file(config.join("settings.json")).unwrap();
        symlink(&missing_slot, config.join("settings.json")).unwrap();
        let handle = create_handle_dir(
            dir.path(),
            &global,
            AccountNum::try_from(1u16).unwrap(),
            77806,
        )
        .unwrap();
        assert_eq!(
            read_materialized_settings(&handle)["crossSessionInbound"],
            serde_json::json!("accept")
        );
        let missing_local = handle.join("missing-settings-target");
        std::fs::remove_file(handle.join("settings.json")).unwrap();
        symlink(&missing_local, handle.join("settings.json")).unwrap();
        materialize_handle_settings(&handle, &global, &config).unwrap();
        assert!(read_materialized_settings(&handle)
            .get("crossSessionInbound")
            .is_none());
        assert!(!missing_local.exists() && !missing_global.exists() && !missing_slot.exists());
        assert!(std::fs::symlink_metadata(handle.join("settings.json"))
            .unwrap()
            .is_file());
        assert!(std::fs::symlink_metadata(global.join("settings.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::symlink_metadata(config.join("settings.json"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    #[cfg(unix)]
    fn nonobject_and_nonfile_local_settings_withhold_accept() {
        for content in ["[]", "null"] {
            let dir = TempDir::new().unwrap();
            let global = dir.path().join(".claude");
            std::fs::create_dir_all(&global).unwrap();
            let config = setup_config_dir(dir.path(), 1);
            let handle = create_handle_dir(
                dir.path(),
                &global,
                AccountNum::try_from(1u16).unwrap(),
                77805,
            )
            .unwrap();
            std::fs::write(handle.join("settings.json"), content).unwrap();
            materialize_handle_settings(&handle, &global, &config).unwrap();
            assert!(read_materialized_settings(&handle)
                .get("crossSessionInbound")
                .is_none());
            std::fs::remove_file(handle.join("settings.json")).unwrap();
            std::fs::create_dir(handle.join("settings.json")).unwrap();
            let prepared = prepare_handle_settings_tmp(&handle, &global, &config, None).unwrap();
            let settings: Value =
                serde_json::from_str(&std::fs::read_to_string(&prepared).unwrap()).unwrap();
            assert!(settings.get("crossSessionInbound").is_none());
            std::fs::remove_file(prepared).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn materialized_settings_accept_cross_session_inbound_by_default() {
        // Falsifier: without the default key the handle has no
        // `crossSessionInbound` and a bypass-permissions receiver holds the notice.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), "{}").unwrap();
        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77779).unwrap();
        assert_eq!(
            read_materialized_settings(&handle)
                .pointer("/crossSessionInbound")
                .and_then(|v| v.as_str()),
            Some("accept"),
        );
        let global: Value = serde_json::from_str(
            &std::fs::read_to_string(claude_home.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert!(global.get("crossSessionInbound").is_none());
    }

    #[test]
    #[cfg(unix)]
    fn materialized_settings_user_global_cross_session_inbound_wins() {
        for choice in ["refuse", "hold"] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let claude_home = base.join(".claude");
            std::fs::create_dir_all(&claude_home).unwrap();
            std::fs::write(
                claude_home.join("settings.json"),
                format!(r#"{{ "crossSessionInbound": "{choice}" }}"#),
            )
            .unwrap();
            setup_config_dir(base, 1);
            let account = AccountNum::try_from(1u16).unwrap();
            let handle = create_handle_dir(base, &claude_home, account, 77780).unwrap();
            assert_eq!(
                read_materialized_settings(&handle)
                    .pointer("/crossSessionInbound")
                    .and_then(|v| v.as_str()),
                Some(choice),
            );
        }
    }

    /// Falsifier: with no unparseable-file guard, the malformed global reads as `{}`
    /// and the default `accept` is applied over the user's `refuse`.
    #[test]
    #[cfg(unix)]
    fn malformed_settings_file_withholds_the_accept_default() {
        for which in ["global", "overlay"] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let claude_home = base.join(".claude");
            std::fs::create_dir_all(&claude_home).unwrap();
            setup_config_dir(base, 1);
            let bad = r#"{"crossSessionInbound":"refuse", "#; // truncated JSON
            if which == "global" {
                std::fs::write(claude_home.join("settings.json"), bad).unwrap();
            } else {
                std::fs::write(base.join("config-1").join("settings.json"), bad).unwrap();
            }
            let account = AccountNum::try_from(1u16).unwrap();
            let handle = create_handle_dir(base, &claude_home, account, 77781).unwrap();
            let m = read_materialized_settings(&handle);
            assert_ne!(
                m.pointer("/crossSessionInbound").and_then(|v| v.as_str()),
                Some("accept"),
                "{which}"
            );
            assert!(m.get("crossSessionInbound").is_none(), "{which}");
        }
    }

    /// INVEST-2: every shape of unusable global settings withholds `accept`. Falsifier: the
    /// pre-fix read treated each as `{}` and applied the default.
    #[test]
    #[cfg(unix)]
    fn every_unusable_settings_shape_withholds_the_accept_default() {
        use std::os::unix::fs::PermissionsExt;
        for shape in ["chmod000", "directory", "array"] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let claude_home = base.join(".claude");
            std::fs::create_dir_all(&claude_home).unwrap();
            setup_config_dir(base, 1);
            let g = claude_home.join("settings.json");
            match shape {
                "chmod000" => {
                    std::fs::write(&g, r#"{"crossSessionInbound":"refuse"}"#).unwrap();
                    std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o000)).unwrap();
                    // This case cannot execute as root: that privilege bypasses mode bits.
                    // SAFETY: geteuid takes no arguments and touches no memory.
                    if unsafe { libc::geteuid() } == 0 {
                        std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                        continue;
                    }
                }
                "directory" => std::fs::create_dir(&g).unwrap(),
                _ => std::fs::write(&g, "[]").unwrap(),
            }
            let account = AccountNum::try_from(1u16).unwrap();
            let handle = create_handle_dir(base, &claude_home, account, 77790).unwrap();
            let m = read_materialized_settings(&handle);
            assert!(m.get("crossSessionInbound").is_none(), "{shape}");
            if shape == "chmod000" {
                std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn slot_overlay_cross_session_inbound_beats_global_beats_default() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{ "crossSessionInbound": "hold" }"#,
        )
        .unwrap();
        setup_config_dir(base, 1);
        std::fs::write(
            base.join("config-1").join("settings.json"),
            r#"{ "crossSessionInbound": "refuse" }"#,
        )
        .unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77782).unwrap();
        assert_eq!(
            read_materialized_settings(&handle)
                .pointer("/crossSessionInbound")
                .and_then(|v| v.as_str()),
            Some("refuse"),
            "overlay > global"
        );
    }

    #[test]
    #[cfg(unix)]
    fn materialized_settings_user_global_effort_wins_over_default() {
        // An explicit `effortLevel` in the user-global is an override,
        // not a candidate for the default: "xhigh" must survive into the
        // handle unchanged. Guards against a blanket clobber regression.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{ "effortLevel": "xhigh" }"#,
        )
        .unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77778).unwrap();

        let materialized = read_materialized_settings(&handle);
        assert_eq!(
            materialized
                .pointer("/effortLevel")
                .and_then(|v| v.as_str()),
            Some("xhigh"),
        );
    }

    #[test]
    #[cfg(unix)]
    fn materialized_settings_slot_overlay_effort_wins_over_default_and_global() {
        // The slot overlay is the highest-precedence layer: an
        // `effortLevel` pinned in config-<N>/settings.json beats both
        // the csq default and the user-global.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{ "effortLevel": "xhigh" }"#,
        )
        .unwrap();
        let config = setup_config_dir(base, 1);
        std::fs::write(config.join("settings.json"), r#"{ "effortLevel": "low" }"#).unwrap();

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77779).unwrap();

        let materialized = read_materialized_settings(&handle);
        assert_eq!(
            materialized
                .pointer("/effortLevel")
                .and_then(|v| v.as_str()),
            Some("low"),
        );
    }

    #[test]
    #[cfg(unix)]
    fn keybindings_json_stays_a_file_through_multiple_csq_runs() {
        // The pre-alpha.18 bug turned `~/.claude/keybindings.json`
        // into a directory the first time csq run was invoked on a
        // fresh install. If the user then tried to manually create
        // `{"bindings":[]}` they'd hit "is a directory" or end up
        // writing INTO the dir — which the user reports as "settings
        // and statusline disappears" (CC fails to parse its config).
        //
        // Post-fix: the file gets seeded with parseable JSON, and
        // subsequent runs must never promote it to a dir.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        // First run: seeds keybindings.json as a FILE.
        let h1 = create_handle_dir(base, &claude_home, account, 11111).unwrap();
        let kb = claude_home.join("keybindings.json");
        let meta = std::fs::metadata(&kb).unwrap();
        assert!(
            meta.is_file(),
            "first csq run must leave keybindings.json as a file"
        );
        let first_content = std::fs::read_to_string(&kb).unwrap();
        let _: serde_json::Value = serde_json::from_str(&first_content)
            .expect("seeded keybindings.json must be valid JSON");

        // User now edits keybindings.json with their custom bindings.
        std::fs::write(&kb, r#"{"bindings":[{"key":"cmd+s","cmd":"save"}]}"#).unwrap();

        // Clean up first handle so second run can reuse PID 11111
        // (simulates `exec` or the handle-dir being swept).
        std::fs::remove_dir_all(&h1).unwrap();

        // Second run: must not overwrite or promote to dir.
        let _h2 = create_handle_dir(base, &claude_home, account, 22222).unwrap();
        let meta = std::fs::metadata(&kb).unwrap();
        assert!(meta.is_file(), "second csq run must preserve the file");
        let second_content = std::fs::read_to_string(&kb).unwrap();
        assert!(
            second_content.contains("cmd+s"),
            "user custom bindings must not be overwritten"
        );
    }

    // ── VP-final F3: pre-flight existence guard ───────────────────────────

    /// Regression guard: VP-final F3.
    ///
    /// `repoint_handle_dir` must refuse to start the rename loop when the
    /// `.csq-account` marker is absent from the target `config-<N>` directory.
    /// Without it csq cannot determine which account the handle dir is on after
    /// the swap. The old "silently continue" path would remove the existing
    /// `.csq-account` symlink without creating a new one.
    #[test]
    #[cfg(unix)]
    fn repoint_aborts_when_target_config_missing_csq_account() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Config-1: complete
        setup_config_dir(base, 1);
        // Config-2: intentionally missing .csq-account (the required marker)
        let config_2 = base.join("config-2");
        std::fs::create_dir_all(&config_2).unwrap();
        // NOT writing .csq-account — this is the missing item under test
        std::fs::write(config_2.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config_2.join("settings.json"), "{}").unwrap();
        std::fs::write(config_2.join(".claude.json"), "{}").unwrap();

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        std::fs::remove_file(config_2.join(".csq-account")).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 55551).unwrap();

        // Attempt to repoint to account 2 — should fail because .csq-account
        // is missing from config-2, preventing a mixed-state handle dir.
        let result = repoint_verified_fixture(base, &claude_home, &handle, account2);

        assert!(
            result.is_err(),
            "repoint must return Err when target config is missing .csq-account"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(".csq-account"),
            "error must name the missing item, got: {err_msg}"
        );
        assert!(
            err_msg.contains("mixed-state") || err_msg.contains("repoint aborted"),
            "error must describe the abort reason, got: {err_msg}"
        );

        // Handle dir must still be bound to account 1 (no partial repoint)
        assert_eq!(
            markers::resolve_marker_to_slot(base, &handle),
            Some(account1),
            "handle dir must remain on account 1 after aborted repoint"
        );
    }

    // ── an internal ticket: repoint rename-lock path canonicalization ───────────────────

    /// Regression guard: an internal ticket.
    ///
    /// The inner rename lock (`repoint_lock_path`) MUST resolve to the SAME
    /// file whether the caller passes a raw, symlink-containing path (`csq swap`
    /// forwards `source.path()` verbatim) or a pre-canonicalized one
    /// (`auto_rotate`). Before the fix, `csq swap` locked `raw/.swap.lock` while
    /// `auto_rotate` locked `canonical/.swap.lock` — different inodes on any host
    /// whose accounts base has a symlink component, so the lock silently failed
    /// to serialize concurrent repoints.
    #[test]
    #[cfg(unix)]
    fn repoint_lock_path_is_canonical_and_symlink_invariant() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        // Real handle dir at <root>/real/term-1.
        let real_parent = dir.path().join("real");
        std::fs::create_dir_all(&real_parent).unwrap();
        let real_handle = real_parent.join("term-1");
        std::fs::create_dir_all(&real_handle).unwrap();

        // A symlinked view of the SAME handle dir: <root>/link -> <root>/real.
        let link_parent = dir.path().join("link");
        symlink(&real_parent, &link_parent).unwrap();
        let via_symlink = link_parent.join("term-1");

        let canonical = std::fs::canonicalize(&real_handle).unwrap();

        let lock_via_raw = repoint_lock_path(&via_symlink);
        let lock_via_canonical = repoint_lock_path(&canonical);

        // Both callers resolve to the SAME lock file (the an internal ticket invariant).
        assert_eq!(
            lock_via_raw, lock_via_canonical,
            "raw and canonical callers must resolve to the same rename lock; \
             raw={lock_via_raw:?} canonical={lock_via_canonical:?}"
        );
        assert!(
            lock_via_raw.ends_with(".swap.lock"),
            "rename lock must be `.swap.lock` (dot), got {lock_via_raw:?}"
        );
        // And it must be under the canonical parent, not the symlinked one.
        assert_eq!(
            lock_via_raw,
            canonical.join(".swap.lock"),
            "rename lock must live under the canonicalized handle dir"
        );

        // The inner rename lock MUST stay a DIFFERENT file from the A4a
        // `.swap-lock` (hyphen) keychain guard — merging them self-deadlocks a
        // process that holds the outer guard across the repoint call (an internal ticket).
        let a4a_guard = crate::credentials::keychain::swap_lock_path(&canonical);
        assert_ne!(
            lock_via_raw, a4a_guard,
            "the rename lock (.swap.lock) and the A4a guard (.swap-lock) must be \
             distinct files or a same-process re-flock self-deadlocks"
        );

        // Canonicalize-failure fallback: a non-existent (dangling) dir cannot be
        // canonicalized, so the helper falls back to the raw path joined with
        // `.swap.lock`. (The repoint itself fails downstream for such a dir; this
        // only pins the fallback so it never silently drops the filename.)
        let dangling = dir.path().join("does-not-exist").join("term-2");
        assert_eq!(
            repoint_lock_path(&dangling),
            dangling.join(".swap.lock"),
            "canonicalize-fail fallback must return raw dir joined with .swap.lock"
        );
    }

    // ── VP-final F4: concurrent swap serialization ────────────────────────

    /// Regression guard: VP-final F4.
    ///
    /// Two threads both calling `repoint_handle_dir` on the SAME handle dir
    /// but with DIFFERENT targets must produce a consistent final state:
    /// all symlinks must resolve to the SAME winning binding (credential UUID
    /// plus slot markers). Without the flock the two threads can interleave
    /// rename operations, leaving the handle dir in a mixed-state where
    /// `.credentials.json` points at config-2 but `.csq-account` still
    /// points at config-3.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_serializes_concurrent_writers() {
        let _env_guard = crate::platform::test_env::lock();
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Create three accounts: handle starts on 1, threads race to set 2 vs 3
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        setup_config_dir(dir.path(), 3);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();

        std::fs::write(
            base.join("config-1/settings.json"),
            serde_json::json!({"fixtureWinner":1}).to_string(),
        )
        .unwrap();
        std::fs::write(
            base.join("config-2/settings.json"),
            serde_json::json!({"fixtureWinner":2}).to_string(),
        )
        .unwrap();
        std::fs::write(
            base.join("config-3/settings.json"),
            serde_json::json!({"fixtureWinner":3}).to_string(),
        )
        .unwrap();
        stage_verified_repoint_slots(&base, &[1, 2, 3]);
        let handle = create_handle_dir(dir.path(), &claude_home, account1, 55552).unwrap();

        let binding_a =
            crate::accounts::anthropic_identity::capture_anthropic_binding(&base, account2)
                .unwrap();
        let binding_b =
            crate::accounts::anthropic_identity::capture_anthropic_binding(&base, account3)
                .unwrap();
        let native_a = capture_native_swap(&base, &handle).unwrap();
        let native_b = capture_native_swap(&base, &handle).unwrap();
        // Both snapshots capture the same source before the barrier.
        let barrier = Arc::new(Barrier::new(2));

        let base_a = base.clone();
        let claude_a = claude_home.clone();
        let handle_a = handle.clone();
        let barrier_a = barrier.clone();
        let t1 = thread::spawn(move || {
            barrier_a.wait();
            let result =
                repoint_handle_dir_guarded(&base_a, &claude_a, &handle_a, &binding_a, &native_a);
            (result, binding_a, native_a)
        });

        let base_b = base.clone();
        let claude_b = claude_home.clone();
        let handle_b = handle.clone();
        let barrier_b = barrier.clone();
        let t2 = thread::spawn(move || {
            barrier_b.wait();
            let result =
                repoint_handle_dir_guarded(&base_b, &claude_b, &handle_b, &binding_b, &native_b);
            (result, binding_b, native_b)
        });

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        assert_verified_repoint_race(&base, &claude_home, &handle, r1, r2);

        // The handle dir must be in a CONSISTENT state: all symlinks point
        // at the SAME config-<N>. Read the account marker to determine winner.
        let final_account = markers::resolve_marker_to_slot(&base, &handle)
            .expect("handle dir must have a readable .csq-account after concurrent repoint");

        // Verify every symlink that EXISTS in the handle dir resolves to the
        // winner's config dir. Optional items (.current-account, .quota-cursor)
        // may be absent if they were never created in config-<N> — skip those.
        // Required items (.credentials.json, .csq-account) must be consistent.
        let winner_config = base.join(format!("config-{}", final_account));
        for item in ACCOUNT_BOUND_ITEMS {
            let link = handle.join(item);
            // If the item is absent, it was never created in either config dir —
            // skip. This handles optional items that don't exist yet.
            if link.symlink_metadata().is_err() {
                continue;
            }
            let resolved = std::fs::read_link(&link).unwrap_or_else(|e| {
                panic!("{item} link exists but read_link failed: {e}");
            });
            let expected = if *item == ".credentials.json" {
                verified_fixture_credentials(&base, final_account.get())
            } else {
                winner_config.join(item)
            };
            assert!(
                resolved == expected,
                "{item} points at {} but winner config is {} — mixed-state handle dir \
                 (concurrent repoint without flock would allow this)",
                resolved.display(),
                winner_config.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn settings_local_and_default_are_files_not_directories() {
        // Same bug class as keybindings.json — any file-named
        // SHARED_ITEMS entry must land as a FILE on fresh install.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let _h = create_handle_dir(base, &claude_home, account, 33333).unwrap();

        for name in [
            "keybindings.json",
            "settings.local.json",
            "settings-default.json",
            "stats-cache.json",
        ] {
            let path = claude_home.join(name);
            if !path.exists() {
                continue;
            }
            let meta = std::fs::metadata(&path).unwrap();
            assert!(meta.is_file(), "{name} must be a FILE");
            let content = std::fs::read_to_string(&path).unwrap();
            let _: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|_| panic!("{name} must be valid JSON"));
        }

        // Non-JSON file-shaped items also check out.
        for name in ["history.jsonl", "__store.db"] {
            let path = claude_home.join(name);
            if !path.exists() {
                continue;
            }
            assert!(
                std::fs::metadata(&path).unwrap().is_file(),
                "{name} must be a file"
            );
        }
    }

    // ── create_handle_dir_codex (PR-C3a) ───────────────────────────────

    fn setup_codex_slot(base: &Path, account: u16) -> PathBuf {
        // Create config-<N> with the Codex-specific bits: marker,
        // config.toml, codex-sessions dir, codex-history.jsonl file.
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), account.to_string()).unwrap();
        std::fs::write(config.join("config.toml"), "[model]\nname = \"o1\"\n").unwrap(); // CI-ALLOW-fs-write-config-toml
        std::fs::create_dir_all(config.join("codex-sessions")).unwrap();
        std::fs::write(config.join("codex-history.jsonl"), "").unwrap();

        // Canonical credential file that auth.json will symlink to.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join(format!("codex-{account}.json")),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","id_token":"it","account_id":"uuid"}}"#,
        )
        .unwrap();

        config
    }

    /// Holds the shared env lock and points the Codex global-hooks fixture seam at a
    /// hermetic path; restores the previous value on drop (panic included).
    #[cfg(unix)]
    struct GlobalHooksEnv {
        _lock: crate::platform::test_env::EnvTestGuard,
        prev: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    impl GlobalHooksEnv {
        fn set(path: Option<&Path>) -> Self {
            let lock = crate::platform::test_env::lock();
            let prev = std::env::var_os("CSQ_TEST_CODEX_GLOBAL_HOOKS");
            // SAFETY: the workspace-wide env lock is held for this guard's lifetime.
            unsafe {
                match path {
                    Some(p) => std::env::set_var("CSQ_TEST_CODEX_GLOBAL_HOOKS", p),
                    None => std::env::remove_var("CSQ_TEST_CODEX_GLOBAL_HOOKS"),
                }
            }
            Self { _lock: lock, prev }
        }
    }

    #[cfg(unix)]
    impl Drop for GlobalHooksEnv {
        fn drop(&mut self) {
            // SAFETY: the env lock is still held (the field drops after this body).
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var("CSQ_TEST_CODEX_GLOBAL_HOOKS", v),
                    None => std::env::remove_var("CSQ_TEST_CODEX_GLOBAL_HOOKS"),
                }
            }
        }
    }

    #[cfg(unix)]
    const GLOBAL_HOOKS: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"x"}]}],"Stop":[{"hooks":[{"type":"command","command":"y"}]}]}}"#;

    #[cfg(unix)]
    fn write_global_hooks(dir: &Path) -> PathBuf {
        let p = dir.join("global-codex").join("hooks.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, GLOBAL_HOOKS).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn codex_handle_links_user_global_hooks_json() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 2);
        let global = write_global_hooks(dir.path());
        let _env = GlobalHooksEnv::set(Some(&global));

        let handle =
            create_handle_dir_codex(&base, AccountNum::try_from(2u16).unwrap(), 88801).unwrap();

        let link = handle.join("hooks.json");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), global);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), GLOBAL_HOOKS);
    }

    #[cfg(unix)]
    #[test]
    fn codex_repoint_keeps_or_recreates_global_hooks_link() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 4);
        setup_codex_slot(&base, 9);
        let global = write_global_hooks(dir.path());
        let _env = GlobalHooksEnv::set(Some(&global));
        let handle =
            create_handle_dir_codex(&base, AccountNum::try_from(4u16).unwrap(), 88802).unwrap();
        let to = AccountNum::try_from(9u16).unwrap();

        // Kept: present before, present after.
        repoint_handle_dir_codex(&base, &handle, to).unwrap();
        assert_eq!(
            std::fs::read_link(handle.join("hooks.json")).unwrap(),
            global
        );

        // Recreated: a handle dir that lost the link regains it on the next repoint.
        std::fs::remove_file(handle.join("hooks.json")).unwrap();
        repoint_handle_dir_codex(&base, &handle, AccountNum::try_from(4u16).unwrap()).unwrap();
        assert_eq!(
            std::fs::read_link(handle.join("hooks.json")).unwrap(),
            global
        );

        // A symlink pointing elsewhere is moved aside (kept) and the global linked.
        std::fs::remove_file(handle.join("hooks.json")).unwrap();
        let elsewhere = dir.path().join("elsewhere.json");
        std::os::unix::fs::symlink(&elsewhere, handle.join("hooks.json")).unwrap();
        repoint_handle_dir_codex(&base, &handle, to).unwrap();
        assert_eq!(
            std::fs::read_link(handle.join("hooks.json")).unwrap(),
            global
        );
        let kept = codex_hooks_preserved_foreign(&handle);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(
            std::fs::read_link(handle.join(&kept[0])).unwrap(),
            elsewhere
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_handle_without_global_hooks_gets_no_link_and_no_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 2);
        setup_codex_slot(&base, 3);
        // The seam names a path that does not exist.
        let missing = dir.path().join("no-such-dir").join("hooks.json");
        let _env = GlobalHooksEnv::set(Some(&missing));

        let handle =
            create_handle_dir_codex(&base, AccountNum::try_from(2u16).unwrap(), 88803).unwrap();
        assert!(handle.join("hooks.json").symlink_metadata().is_err());
        repoint_handle_dir_codex(&base, &handle, AccountNum::try_from(3u16).unwrap()).unwrap();
        assert!(handle.join("hooks.json").symlink_metadata().is_err());
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn codex_hooks_regular_file_replaced_only_when_subset_of_global() {
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let _env = GlobalHooksEnv::set(None);

        // Foreign (not a subset): MOVED ASIDE byte-identical, never deleted, then linked.
        let foreign_dir = dir.path().join("h-foreign");
        std::fs::create_dir_all(&foreign_dir).unwrap();
        let foreign = br#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"NOT-IN-GLOBAL"}]}]}}"#;
        std::fs::write(foreign_dir.join("hooks.json"), foreign).unwrap();
        link_codex_global_hooks(&foreign_dir, Some(&global)).unwrap();
        assert_eq!(
            std::fs::read_link(foreign_dir.join("hooks.json")).unwrap(),
            global
        );
        let kept = codex_hooks_preserved_foreign(&foreign_dir);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert!(kept[0].starts_with("hooks.json.csq-foreign-"));
        assert_eq!(std::fs::read(foreign_dir.join(&kept[0])).unwrap(), foreign);
        assert!(foreign_dir
            .join("hooks.json.swap-tmp")
            .symlink_metadata()
            .is_err());

        // Subset: replaced by the link, nothing preserved.
        let subset_dir = dir.path().join("h-subset");
        std::fs::create_dir_all(&subset_dir).unwrap();
        std::fs::write(
            subset_dir.join("hooks.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"y"}]}]}}"#,
        )
        .unwrap();
        link_codex_global_hooks(&subset_dir, Some(&global)).unwrap();
        assert_eq!(
            std::fs::read_link(subset_dir.join("hooks.json")).unwrap(),
            global
        );
        assert!(codex_hooks_preserved_foreign(&subset_dir).is_empty());
        assert_eq!(
            std::fs::read_dir(&subset_dir).unwrap().count(),
            1,
            "the detached subset file must not be left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_hooks_unparseable_local_file_is_preserved() {
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let _env = GlobalHooksEnv::set(None);
        let h = dir.path().join("h");
        std::fs::create_dir_all(&h).unwrap();
        let junk = b"{ this is not json";
        std::fs::write(h.join("hooks.json"), junk).unwrap();
        link_codex_global_hooks(&h, Some(&global)).unwrap();
        assert_eq!(std::fs::read_link(h.join("hooks.json")).unwrap(), global);
        let kept = codex_hooks_preserved_foreign(&h);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(std::fs::read(h.join(&kept[0])).unwrap(), junk);
    }

    /// OWNER RULING 2026-10-15: carry approvals over. csq copies existing owner approvals for
    /// byte-identical hooks, and never originates one. End to end through the real create and
    /// repoint paths: a new handle inherits an existing approval for an unchanged hook, a
    /// repoint onto the slot does too, a dead handle's key is pruned, and an edited global
    /// carries nothing.
    #[cfg(unix)]
    #[test]
    fn codex_create_and_repoint_carry_existing_hook_approvals() {
        const STOP_TRUE: &str =
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"}]}]}}"#;
        const H_TRUE: &str =
            "sha256:2ba34c7a02841fada06b868a093d041fd3d9de81883c789a321916b0aa118851";
        let dir = TempDir::new().unwrap();
        let base = dir.path().canonicalize().unwrap().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 4);
        setup_codex_slot(&base, 9);
        let global = dir.path().join("g-hooks.json");
        std::fs::write(&global, STOP_TRUE).unwrap();
        let _env = GlobalHooksEnv::set(Some(&global));
        let key = |h: &Path| format!("{}/hooks.json:stop:0:0", h.display());
        let slot_cfg = |n: u16| base.join(format!("config-{n}/config.toml"));
        let state = |n: u16| -> toml::Table {
            let doc: toml::Table =
                toml::from_str(&std::fs::read_to_string(slot_cfg(n)).unwrap()).unwrap();
            doc.get("hooks")
                .and_then(|h| h.get("state"))
                .and_then(|s| s.as_table())
                .cloned()
                .unwrap_or_default()
        };
        let a4 = AccountNum::try_from(4u16).unwrap();
        let a9 = AccountNum::try_from(9u16).unwrap();

        // First handle: nothing to copy from, so nothing is created.
        let first = create_handle_dir_codex(&base, a4, 88901).unwrap();
        assert!(state(4).is_empty(), "an entry appeared without a source");

        // Codex approves the first handle's hook (written by Codex, not csq), plus a stale
        // key of a handle that no longer exists.
        let dead = base.join("term-88999");
        let mut cfg = std::fs::read_to_string(slot_cfg(4)).unwrap();
        cfg.push_str(&format!(
            "\n[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = true\n\n[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\n",
            key(&first),
            key(&dead)
        ));
        std::fs::write(slot_cfg(4), cfg).unwrap(); // CI-ALLOW-fs-write-config-toml

        // Second handle on the slot inherits it; the dead handle's key is pruned.
        let second = create_handle_dir_codex(&base, a4, 88902).unwrap();
        let st = state(4);
        assert_eq!(st[&key(&second)]["trusted_hash"].as_str(), Some(H_TRUE));
        assert_eq!(st[&key(&second)]["enabled"].as_bool(), Some(true));
        assert!(st.contains_key(&key(&first)));
        assert!(!st.contains_key(&key(&dead)), "dead handle key survived");

        // Repoint a handle onto slot 9, which holds an approval under another handle's key.
        let mut cfg9 = std::fs::read_to_string(slot_cfg(9)).unwrap();
        cfg9.push_str(&format!(
            "\n[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = true\n",
            key(&first)
        ));
        std::fs::write(slot_cfg(9), cfg9).unwrap(); // CI-ALLOW-fs-write-config-toml
        repoint_handle_dir_codex(&base, &second, a9).unwrap();
        assert_eq!(
            state(9)[&key(&second)]["trusted_hash"].as_str(),
            Some(H_TRUE)
        );

        // An edited global: a third handle gets nothing (the source hash is stale).
        std::fs::write(
            &global,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true "}]}]}}"#,
        )
        .unwrap();
        let third = create_handle_dir_codex(&base, a4, 88903).unwrap();
        assert!(!state(4).contains_key(&key(&third)));
    }

    #[cfg(unix)]
    const TC_STOP_TRUE: &str =
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"}]}]}}"#;
    #[cfg(unix)]
    const TC_H_TRUE: &str =
        "sha256:2ba34c7a02841fada06b868a093d041fd3d9de81883c789a321916b0aa118851";

    /// A hermetic accounts base (canonical path) with Codex slots 4 and 9 and a global hooks
    /// file holding one Stop hook.
    #[cfg(unix)]
    fn trust_world() -> (TempDir, PathBuf, PathBuf) {
        let dir = TempDir::new().unwrap();
        let base = dir.path().canonicalize().unwrap().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 4);
        setup_codex_slot(&base, 9);
        let global = dir.path().join("g-hooks.json");
        std::fs::write(&global, TC_STOP_TRUE).unwrap();
        (dir, base, global)
    }

    #[cfg(unix)]
    fn tc_key(home: &Path) -> String {
        format!("{}/hooks.json:stop:0:0", home.display())
    }

    #[cfg(unix)]
    fn tc_entry(home: &Path, enabled: Option<bool>) -> String {
        let en = enabled.map_or(String::new(), |b| format!("enabled = {b}\n"));
        format!(
            "\n[hooks.state.\"{}\"]\ntrusted_hash = \"{TC_H_TRUE}\"\n{en}",
            tc_key(home)
        )
    }

    #[cfg(unix)]
    fn tc_append(base: &Path, slot: u16, text: &str) {
        let p = base.join(format!("config-{slot}/config.toml"));
        let mut cur = std::fs::read_to_string(&p).unwrap();
        cur.push_str(text);
        std::fs::write(&p, cur).unwrap(); // CI-ALLOW-fs-write-config-toml
    }

    #[cfg(unix)]
    fn tc_state(base: &Path, slot: u16) -> toml::Table {
        let doc: toml::Table = toml::from_str(
            &std::fs::read_to_string(base.join(format!("config-{slot}/config.toml"))).unwrap(),
        )
        .unwrap();
        doc.get("hooks")
            .and_then(|h| h.get("state"))
            .and_then(|s| s.as_table())
            .cloned()
            .unwrap_or_default()
    }

    /// Item 1: sources that disagree on `enabled` copy NOTHING; a single disable is copied
    /// faithfully (one source, nothing to disagree with).
    #[cfg(unix)]
    #[test]
    fn codex_carry_copies_nothing_when_sources_disagree_on_enabled() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88001"), Some(true)));
        tc_append(&base, 4, &tc_entry(&base.join("term-88002"), Some(false)));
        let h = create_handle_dir_codex(&base, a4, 88010).unwrap();
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&h)),
            "disagreeing sources were copied"
        );
        // one remaining source: its decision is copied faithfully
        std::fs::write(
            base.join("config-4/config.toml"),
            "[model]\nname = \"o1\"\n",
        )
        .unwrap(); // CI-ALLOW-fs-write-config-toml
        tc_append(&base, 4, &tc_entry(&base.join("term-88002"), Some(false)));
        let h2 = create_handle_dir_codex(&base, a4, 88011).unwrap();
        assert_eq!(
            tc_state(&base, 4)[&tc_key(&h2)]["enabled"].as_bool(),
            Some(false),
            "a single source's decision is copied faithfully"
        );
    }

    /// Item 2: a PID reused on another slot never inherits a predecessor's keys in a third
    /// slot after a swap: create purges the handle's own keys from EVERY slot.
    #[cfg(unix)]
    #[test]
    fn codex_reused_pid_stale_key_in_another_slot_is_gone_after_swap() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        let a9 = AccountNum::try_from(9u16).unwrap();
        tc_append(&base, 9, &tc_entry(&base.join("term-88020"), Some(false)));
        let h = create_handle_dir_codex(&base, a4, 88020).unwrap();
        assert!(
            !tc_state(&base, 9).contains_key(&tc_key(&h)),
            "create left the stale own key in slot 9"
        );
        repoint_handle_dir_codex(&base, &h, a9).unwrap();
        assert!(
            !tc_state(&base, 9).contains_key(&tc_key(&h)),
            "the swap adopted a predecessor's disabled entry"
        );
    }

    /// Items 3 and 4: a write that lands while csq's create-time carry is mid-write (Codex
    /// takes no lock) is neither lost nor allowed to skip the carry: the pass re-runs, so the
    /// reused PID's stale own key is still dropped and the approval is still copied.
    #[cfg(unix)]
    #[test]
    fn codex_create_survives_a_concurrent_write_and_still_drops_stale_own_keys() {
        use crate::providers::codex::surface::test_seam::BEFORE_RENAME;
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88060"), Some(true)));
        tc_append(&base, 4, &tc_entry(&base.join("term-88061"), Some(false)));
        let cfg = base.join("config-4/config.toml");
        let fired = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let f2 = fired.clone();
        BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |t: &Path| {
                f2.set(f2.get() + 1);
                if f2.get() == 1 {
                    let mut cur = std::fs::read_to_string(t).unwrap();
                    cur.push_str("\n[codex_user]\nkeep = 1\n");
                    std::fs::write(t, cur).unwrap(); // CI-ALLOW-fs-write-config-toml
                }
            }));
        });
        let h = create_handle_dir_codex(&base, a4, 88061).unwrap();
        BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
        assert_eq!(
            doc.get("codex_user")
                .and_then(|t| t.get("keep"))
                .and_then(|v| v.as_integer()),
            Some(1),
            "a write landing mid-carry was lost"
        );
        let st = tc_state(&base, 4);
        assert_eq!(
            st.get(&tc_key(&h))
                .and_then(|e| e.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true),
            "stale own key survived or the copy was skipped"
        );
    }

    /// Item 3: two terminals created together on one slot both drop their stale own keys and
    /// both end with their copied approval.
    #[cfg(unix)]
    #[test]
    fn codex_two_terminals_created_together_on_one_slot_both_carry() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88070"), Some(true)));
        // stale own keys of the two reused PIDs: a disable under a hash that is no longer
        // current, so neither can act as a source for the other terminal's copy
        for pid in [88071, 88072] {
            tc_append(
                &base,
                4,
                &tc_entry(&base.join(format!("term-{pid}")), Some(false))
                    .replace(TC_H_TRUE, "sha256:stale"),
            );
        }
        let handles: Vec<PathBuf> = std::thread::scope(|sc| {
            let jobs: Vec<_> = [88071u32, 88072]
                .into_iter()
                .map(|pid| {
                    let base = &base;
                    sc.spawn(move || create_handle_dir_codex(base, a4, pid).unwrap())
                })
                .collect();
            jobs.into_iter().map(|j| j.join().unwrap()).collect()
        });
        let st = tc_state(&base, 4);
        for h in &handles {
            let e = st.get(&tc_key(h));
            assert!(
                e.is_some_and(|e| e.get("trusted_hash").and_then(|v| v.as_str())
                    == Some(TC_H_TRUE)
                    && e.get("enabled").and_then(|v| v.as_bool()) != Some(false)),
                "{} lost its carry or kept the stale disable",
                h.display()
            );
        }
    }

    /// Item 4: a target slot that cannot be cleared of a predecessor's keys REFUSES the
    /// launch (no half-built handle dir), with a clear message and a doctor flag.
    #[cfg(unix)]
    #[test]
    fn codex_create_refuses_when_the_target_slot_cannot_be_purged() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        std::fs::write(base.join("config-4/config.toml"), "x = [").unwrap(); // CI-ALLOW-fs-write-config-toml
        let e = create_handle_dir_codex(&base, a4, 88100).unwrap_err();
        assert!(e.to_string().contains("refusing to launch"), "{e}");
        assert!(
            !base.join("term-88100").exists(),
            "half-built handle dir left"
        );
        assert!(
            crate::providers::codex::surface::slot_write_statuses(&base, a4)
                .contains(&crate::providers::codex::surface::SlotWriteStatus::PurgeFailed)
        );
    }

    /// Item 4: the refusal comes only after ONE drop-only retry: five consecutive concurrent
    /// writes exhaust the first pass, the retry succeeds, and the stale own key is gone.
    #[cfg(unix)]
    #[test]
    fn codex_create_retries_the_drop_once_before_refusing() {
        use crate::providers::codex::surface::test_seam::BEFORE_RENAME;
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88110"), Some(false)));
        let n = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let n2 = n.clone();
        BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |t: &Path| {
                n2.set(n2.get() + 1);
                if n2.get() <= 5 {
                    let mut cur = std::fs::read_to_string(t).unwrap();
                    cur.push_str(&format!("\n# concurrent {}\n", n2.get()));
                    std::fs::write(t, cur).unwrap(); // CI-ALLOW-fs-write-config-toml
                }
            }));
        });
        let r = create_handle_dir_codex(&base, a4, 88110);
        BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
        let h = r.expect("one drop-only retry must precede the refusal");
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&h)),
            "the stale own key survived the retry"
        );
    }

    /// Resets every thread-local test seam the r4 tests set (panic included).
    #[cfg(unix)]
    struct R4Seams;
    #[cfg(unix)]
    impl Drop for R4Seams {
        fn drop(&mut self) {
            use crate::providers::codex::surface::test_seam as s;
            s::BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
            s::AFTER_EXCHANGE.with(|h| *h.borrow_mut() = None);
            s::EXCHANGE_FAIL_NTH.with(|c| c.set(None));
            s::EXCHANGE_COUNT.with(|c| c.set(0));
            s::LOCK_ATTEMPTS.with(|c| c.set(None));
            super::super::codex_hook_trust::test_seam::AFTER_TARGET_REWRITE
                .with(|h| *h.borrow_mut() = None);
        }
    }

    #[cfg(unix)]
    fn slot_statuses(
        base: &Path,
        slot: u16,
    ) -> Vec<crate::providers::codex::surface::SlotWriteStatus> {
        crate::providers::codex::surface::slot_write_statuses(
            base,
            AccountNum::try_from(slot).unwrap(),
        )
    }

    /// r4 item 3 (sec L2): a handle whose dir carries no purge marker (a reused PID, or a
    /// create that skipped a slot) must not swap onto a slot it could not purge: the repoint
    /// is refused, the handle stays on its old slot, and the slot is flagged. A handle WITH
    /// the marker is the owner's own and is not refused.
    #[cfg(unix)]
    #[test]
    fn codex_repoint_without_a_marker_is_refused_when_the_target_slot_cannot_be_purged() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        let a9 = AccountNum::try_from(9u16).unwrap();
        let h = create_handle_dir_codex(&base, a4, 88200).unwrap();
        // a reused PID's handle never had a marker; the predecessor's key sits in slot 9
        std::fs::remove_file(h.join(".csq-hook-trust-purged")).unwrap();
        std::fs::write(base.join("config-9/config.toml"), "x = [").unwrap(); // CI-ALLOW-fs-write-config-toml
        let e = repoint_handle_dir_codex(&base, &h, a9).unwrap_err();
        assert!(e.to_string().contains("refusing"), "{e}");
        let link = std::fs::read_link(h.join("config.toml")).unwrap();
        assert!(
            link.ends_with("config-4/config.toml"),
            "the handle moved off its old slot: {}",
            link.display()
        );
        let acct = std::fs::read_to_string(h.join(".csq-account"))
            .or_else(|_| std::fs::read_to_string(base.join("config-4/.csq-account")))
            .unwrap();
        assert_eq!(acct.trim(), "4");
        assert!(slot_statuses(&base, 9)
            .contains(&crate::providers::codex::surface::SlotWriteStatus::PurgeFailed));
    }

    #[cfg(unix)]
    #[test]
    fn codex_repoint_with_a_marker_proceeds_over_a_broken_target_config() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        let a9 = AccountNum::try_from(9u16).unwrap();
        let h = create_handle_dir_codex(&base, a4, 88201).unwrap();
        assert!(h.join(".csq-hook-trust-purged").is_file());
        std::fs::write(base.join("config-9/config.toml"), "x = [").unwrap(); // CI-ALLOW-fs-write-config-toml
        repoint_handle_dir_codex(&base, &h, a9).expect("a marked handle is the owner's own");
        let link = std::fs::read_link(h.join("config.toml")).unwrap();
        assert!(link.ends_with("config-9/config.toml"), "{}", link.display());
    }

    /// r4 item 6 (corr L3): the refusal keeps the cause class.
    #[cfg(unix)]
    #[test]
    fn codex_create_refusal_names_the_cause_class() {
        use crate::providers::codex::surface::test_seam as s;
        let a4 = AccountNum::try_from(4u16).unwrap();
        // malformed
        {
            let (_d, base, global) = trust_world();
            let _env = GlobalHooksEnv::set(Some(&global));
            std::fs::write(base.join("config-4/config.toml"), "x = [").unwrap(); // CI-ALLOW-fs-write-config-toml
            let e = create_handle_dir_codex(&base, a4, 88240).unwrap_err();
            assert!(e.to_string().contains("is malformed"), "{e}");
        }
        // oversize
        {
            let (_d, base, global) = trust_world();
            let _env = GlobalHooksEnv::set(Some(&global));
            std::fs::write(
                base.join("config-4/config.toml"), // CI-ALLOW-fs-write-config-toml
                format!("#{}\n", "x".repeat((1 << 20) + 16)),
            )
            .unwrap();
            let e = create_handle_dir_codex(&base, a4, 88241).unwrap_err();
            assert!(e.to_string().contains("exceeds 1 MiB"), "{e}");
        }
        // kept changing (both the first pass and the drop-only retry exhaust)
        {
            let (_d, base, global) = trust_world();
            let _env = GlobalHooksEnv::set(Some(&global));
            let _r = R4Seams;
            let n = std::rc::Rc::new(std::cell::Cell::new(0u32));
            let n2 = n.clone();
            s::BEFORE_RENAME.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |t: &Path| {
                    n2.set(n2.get() + 1);
                    let mut cur = std::fs::read_to_string(t).unwrap();
                    cur.push_str(&format!("\n# concurrent {}\n", n2.get()));
                    std::fs::write(t, cur).unwrap(); // CI-ALLOW-fs-write-config-toml
                }));
            });
            tc_append(&base, 4, &tc_entry(&base.join("term-88242"), Some(false)));
            let e = create_handle_dir_codex(&base, a4, 88242).unwrap_err();
            assert!(e.to_string().contains("kept changing"), "{e}");
        }
        // locked by another csq writer
        {
            let (_d, base, global) = trust_world();
            let _env = GlobalHooksEnv::set(Some(&global));
            let _r = R4Seams;
            s::LOCK_ATTEMPTS.with(|c| c.set(Some(2)));
            let _held = crate::providers::codex::surface::lock_slot_config(&base, a4).unwrap();
            let e = create_handle_dir_codex(&base, a4, 88243).unwrap_err();
            assert!(e.to_string().contains("locked by another csq"), "{e}");
        }
    }

    /// r4 item 4 (corr L1): another terminal's successful purge of the slot must not clear
    /// the flag for a handle whose stale keys are still there; only that handle's own later
    /// successful purge of that slot clears it.
    #[cfg(unix)]
    #[test]
    fn codex_purge_failed_is_cleared_only_by_the_same_handles_success() {
        use crate::providers::codex::surface::SlotWriteStatus::PurgeFailed;
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        let a9 = AccountNum::try_from(9u16).unwrap();
        std::fs::write(base.join("config-9/config.toml"), "x = [").unwrap(); // CI-ALLOW-fs-write-config-toml
        let a = create_handle_dir_codex(&base, a4, 88210).unwrap();
        assert!(
            slot_statuses(&base, 9).contains(&PurgeFailed),
            "create did not flag slot 9"
        );
        // slot 9 is repaired; another terminal's create purges it successfully
        std::fs::write(
            base.join("config-9/config.toml"),
            "[model]\nname = \"o1\"\n",
        )
        .unwrap(); // CI-ALLOW-fs-write-config-toml
        let _b = create_handle_dir_codex(&base, a4, 88211).unwrap();
        assert!(
            slot_statuses(&base, 9).contains(&PurgeFailed),
            "another terminal's success cleared this handle's purge-failed flag"
        );
        // the failing handle's own successful purge of slot 9 (a repoint onto it) clears it
        repoint_handle_dir_codex(&base, &a, a9).unwrap();
        assert!(
            !slot_statuses(&base, 9).contains(&PurgeFailed),
            "the handle's own successful purge did not clear the flag"
        );
    }

    /// r4 item 5 (corr L2): a carry skipped because the first pass failed with a raced
    /// exchange (not only "kept changing") is flagged for the doctor.
    #[cfg(unix)]
    #[test]
    fn codex_carry_skipped_is_flagged_for_a_raced_exchange_too() {
        use crate::providers::codex::surface::test_seam as s;
        use crate::providers::codex::surface::SlotWriteStatus::CarrySkipped;
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let _r = R4Seams;
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88220"), Some(true)));
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let f2 = fired.clone();
        s::BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |t: &Path| {
                if !f2.replace(true) {
                    let mut cur = std::fs::read_to_string(t).unwrap();
                    cur.push_str("\n# concurrent\n");
                    std::fs::write(t, cur).unwrap(); // CI-ALLOW-fs-write-config-toml
                }
            }));
        });
        s::EXCHANGE_COUNT.with(|c| c.set(0));
        s::EXCHANGE_FAIL_NTH.with(|c| c.set(Some(2)));
        let h = create_handle_dir_codex(&base, a4, 88221).unwrap();
        assert!(
            slot_statuses(&base, 4).contains(&CarrySkipped),
            "a raced first pass skipped the carry without a flag"
        );
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&h)),
            "the approval was copied although the carry was abandoned"
        );
    }

    /// r4 item 8 (sec note): a predecessor's own-key entry that reappears between the carry's
    /// write and the launch (a Codex rename landing late) is purged again once; if it keeps
    /// coming back the launch is refused.
    #[cfg(unix)]
    #[test]
    fn codex_post_carry_reread_purges_a_resurrected_own_key_once_then_refuses() {
        use super::super::codex_hook_trust::test_seam::AFTER_TARGET_REWRITE;
        let a4 = AccountNum::try_from(4u16).unwrap();
        let resurrect = |home: PathBuf| {
            move |cfg: &Path| {
                let mut cur = std::fs::read_to_string(cfg).unwrap();
                cur.push_str(&format!(
                    "\n[hooks.state.\"{}/hooks.json:stop:7:0\"]\ntrusted_hash = \"{TC_H_TRUE}\"\nenabled = false\n",
                    home.display()
                ));
                std::fs::write(cfg, cur).unwrap(); // CI-ALLOW-fs-write-config-toml
            }
        };
        // once: purged again, launch proceeds, the carried approval is intact
        {
            let (_d, base, global) = trust_world();
            let _env = GlobalHooksEnv::set(Some(&global));
            let _r = R4Seams;
            // a LIVE source handle (a dead one is pruned by the first pass, leaving the second
            // pass nothing to copy from)
            std::fs::create_dir(base.join("term-88230")).unwrap();
            tc_append(&base, 4, &tc_entry(&base.join("term-88230"), Some(true)));
            let fire = resurrect(base.join("term-88231"));
            let fired = std::rc::Rc::new(std::cell::Cell::new(false));
            AFTER_TARGET_REWRITE.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |cfg: &Path| {
                    if !fired.replace(true) {
                        fire(cfg);
                    }
                }));
            });
            let h = create_handle_dir_codex(&base, a4, 88231).unwrap();
            let st = tc_state(&base, 4);
            let stray = format!("{}/hooks.json:stop:7:0", h.display());
            assert!(!st.contains_key(&stray), "the resurrected key survived");
            assert!(
                st.contains_key(&tc_key(&h)),
                "the carried approval was lost"
            );
        }
        // every time: refused, no half-built dir
        {
            let (_d, base, global) = trust_world();
            let _env = GlobalHooksEnv::set(Some(&global));
            let _r = R4Seams;
            let fire = resurrect(base.join("term-88232"));
            AFTER_TARGET_REWRITE.with(|h| *h.borrow_mut() = Some(Box::new(fire)));
            let e = create_handle_dir_codex(&base, a4, 88232).unwrap_err();
            assert!(e.to_string().contains("refusing to launch"), "{e}");
            assert!(!base.join("term-88232").exists());
        }
    }

    /// r4 item 5: a global hooks file csq cannot use skips the carry (the terminal starts
    /// untrusted); the flag is per handle, survives another terminal's complete carry, and is
    /// cleared only when THAT handle's own carry completes.
    #[cfg(unix)]
    #[test]
    fn codex_carry_skipped_is_per_handle_and_cleared_only_by_its_own_carry() {
        use crate::providers::codex::surface::SlotWriteStatus::CarrySkipped;
        let (d, base, global) = trust_world();
        let a4 = AccountNum::try_from(4u16).unwrap();
        let bad = d.path().join("bad-hooks.json");
        std::fs::write(&bad, "{ not json").unwrap();
        let h1 = {
            let _env = GlobalHooksEnv::set(Some(&bad));
            create_handle_dir_codex(&base, a4, 88250).unwrap()
        };
        assert!(
            slot_statuses(&base, 4).contains(&CarrySkipped),
            "an unusable global hooks file skipped the carry without a flag"
        );
        let _env = GlobalHooksEnv::set(Some(&global));
        let _h2 = create_handle_dir_codex(&base, a4, 88251).unwrap();
        assert!(
            slot_statuses(&base, 4).contains(&CarrySkipped),
            "another terminal's complete carry cleared this handle's flag"
        );
        super::super::codex_hook_trust::carry_hook_trust(
            &base,
            &h1,
            a4,
            Some(&global),
            super::super::codex_hook_trust::CarryMode::Repoint,
        )
        .unwrap();
        assert!(
            !slot_statuses(&base, 4).contains(&CarrySkipped),
            "the handle's own complete carry did not clear its flag"
        );
    }

    /// r4 item 5: a config near the size bound skips the copy half; that is a skipped carry
    /// and is flagged like every other.
    #[cfg(unix)]
    #[test]
    fn codex_carry_skipped_is_flagged_when_the_config_is_near_the_size_bound() {
        use crate::providers::codex::surface::SlotWriteStatus::CarrySkipped;
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        std::fs::create_dir(base.join("term-88260")).unwrap();
        std::fs::write(
            base.join("config-4/config.toml"), // CI-ALLOW-fs-write-config-toml
            format!("# {}\n", "p".repeat(800_000)),
        )
        .unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88260"), Some(true)));
        let h = create_handle_dir_codex(&base, a4, 88261).unwrap();
        assert!(
            slot_statuses(&base, 4).contains(&CarrySkipped),
            "a size-skipped carry was not flagged"
        );
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&h)),
            "the near-limit config still received an approval"
        );
    }

    /// Corr L5: a `codex-exec-<pid>` create drops its own stale keys (no copy).
    #[cfg(unix)]
    #[test]
    fn codex_exec_create_drops_its_own_stale_keys_and_copies_nothing() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(&base, 4, &tc_entry(&base.join("term-88090"), Some(true)));
        tc_append(
            &base,
            4,
            &tc_entry(&base.join("codex-exec-88091"), Some(false)),
        );
        let exec = create_handle_dir_codex_named(&base, a4, 88091, "codex-exec-88091").unwrap();
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&exec)),
            "an exec create inherited (or copied) a key under its own name"
        );
    }

    /// Items 5 and 9: project keys and other bases' keys are not sources; exec dirs do not
    /// carry; dead exec and capture keys are pruned by a term create.
    #[cfg(unix)]
    #[test]
    fn codex_carry_sources_exec_dirs_and_prune_scope() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        tc_append(
            &base,
            4,
            &tc_entry(Path::new("/some/repo/.codex"), Some(true)),
        );
        tc_append(
            &base,
            4,
            &tc_entry(Path::new("/other/accounts/term-100"), Some(true)),
        );
        let h = create_handle_dir_codex(&base, a4, 88040).unwrap();
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&h)),
            "a project or foreign-base key was used as a source"
        );

        // a real source for the slot, then an exec dir: nothing is copied to it
        tc_append(&base, 4, &tc_entry(&base.join("term-88041"), Some(true)));
        let exec = create_handle_dir_codex_named(&base, a4, 88042, "codex-exec-88042").unwrap();
        assert!(
            !tc_state(&base, 4).contains_key(&tc_key(&exec)),
            "an exec dir carried"
        );

        // dead exec and capture keys are pruned by the next term create
        tc_append(&base, 4, &tc_entry(&exec, None));
        tc_append(&base, 4, &tc_entry(&base.join("codex-exec-555"), None));
        tc_append(
            &base,
            4,
            &tc_entry(&base.join("interactive-capture-9-1"), None),
        );
        let _h2 = create_handle_dir_codex(&base, a4, 88043).unwrap();
        let st = tc_state(&base, 4);
        assert!(
            !st.contains_key(&tc_key(&base.join("codex-exec-555"))),
            "dead exec key kept"
        );
        assert!(
            !st.contains_key(&tc_key(&base.join("interactive-capture-9-1"))),
            "dead capture key kept"
        );
        assert!(st.contains_key(&tc_key(&exec)), "live exec key must stay");
    }

    /// `codex sandbox` creates `$CODEX_HOME/tmp/arg0/...` inside the handle dir (probed).
    /// No csq handle check may read that subtree as foreign or corrupt.
    #[cfg(unix)]
    #[test]
    fn a_codex_tmp_subtree_in_a_handle_dir_is_not_foreign_or_corrupt() {
        let (_d, base, global) = trust_world();
        let _env = GlobalHooksEnv::set(Some(&global));
        let a4 = AccountNum::try_from(4u16).unwrap();
        let a9 = AccountNum::try_from(9u16).unwrap();
        let h = create_handle_dir_codex(&base, a4, 88050).unwrap();
        let arg0 = h.join("tmp/arg0/codex-arg0abc123");
        std::fs::create_dir_all(&arg0).unwrap();
        std::fs::write(arg0.join(".lock"), "").unwrap();
        std::os::unix::fs::symlink("/bin/sh", arg0.join("apply_patch")).unwrap();
        assert!(codex_hooks_preserved_foreign(&h).is_empty());
        assert_eq!(
            codex_hooks_link_state(&h, Some(&global)),
            CodexHooksLinkState::Ok
        );
        assert_eq!(codex_hooks_config(&h).state, CodexHooksConfigState::Enabled);
        repoint_handle_dir_codex(&base, &h, a9).unwrap();
        assert!(
            arg0.join(".lock").exists(),
            "repoint touched the tmp subtree"
        );
    }

    /// csq's OWN hooks-link writes add no hook trust/approval state. Codex keeps hook trust
    /// in `config.toml` under `[hooks.state."<key>"]` and writes it itself when the user
    /// approves; csq never authors it. This asserts only that creating and repointing with a
    /// global hooks file adds EXACTLY the `hooks.json` link to the handle dir (compared
    /// against the same flow with no global file) and that no slot `config.toml` gains a
    /// `hooks` mention. It does NOT claim `config.toml` never changes: Codex rewrites it on
    /// approval, and the slot-config writers carry `[hooks.state]` through
    /// (`providers::codex::surface`, `trust`, `coc::translate::codex_merge`).
    #[cfg(unix)]
    #[test]
    fn codex_hooks_link_writes_no_trust_state() {
        let names = |h: &Path| -> std::collections::BTreeSet<String> {
            std::fs::read_dir(h)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        };
        let run = |global: Option<&Path>, pid: u32| {
            let dir = TempDir::new().unwrap();
            let base = dir.path().join("accounts");
            std::fs::create_dir_all(&base).unwrap();
            setup_codex_slot(&base, 4);
            setup_codex_slot(&base, 9);
            let _env = GlobalHooksEnv::set(global);
            let handle =
                create_handle_dir_codex(&base, AccountNum::try_from(4u16).unwrap(), pid).unwrap();
            let after_create = names(&handle);
            repoint_handle_dir_codex(&base, &handle, AccountNum::try_from(9u16).unwrap()).unwrap();
            let cfgs: Vec<Vec<u8>> = [4, 9]
                .iter()
                .map(|n| std::fs::read(base.join(format!("config-{n}/config.toml"))).unwrap())
                .collect();
            (after_create, names(&handle), cfgs)
        };
        let g = TempDir::new().unwrap();
        let global = write_global_hooks(g.path());
        let (c0, r0, cfg0) = run(None, 88820);
        let (c1, r1, cfg1) = run(Some(&global), 88821);
        let only_hooks = std::collections::BTreeSet::from(["hooks.json".to_owned()]);
        assert_eq!(
            c1.difference(&c0)
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            only_hooks
        );
        assert_eq!(
            r1.difference(&r0)
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            only_hooks
        );
        assert!(c0.difference(&c1).next().is_none() && r0.difference(&r1).next().is_none());
        assert_eq!(
            cfg0, cfg1,
            "slot config.toml must not change because of the hooks link"
        );
        for c in &cfg1 {
            let text = String::from_utf8_lossy(c).to_lowercase();
            assert!(
                !text.contains("hook"),
                "no hook state in config.toml: {text}"
            );
        }
    }

    /// Fixture: global settings + slot overlay settings, then materialize; returns the
    /// command list of `hooks.<event>` in the written handle settings.
    fn materialized_hook_commands(global: &str, slot: &str, event: &str) -> Vec<String> {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-2");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("settings.json"), slot).unwrap();
        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), global).unwrap();
        let handle = base.join("term-88830");
        std::fs::create_dir_all(&handle).unwrap();
        materialize_handle_settings(&handle, &claude_home, &config).unwrap();
        let out: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        out["hooks"][event]
            .as_array()
            .unwrap_or_else(|| panic!("hooks.{event} missing in {out}"))
            .iter()
            .filter_map(|e| e.pointer("/hooks/0/command").and_then(|c| c.as_str()))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn global_and_slot_hook_arrays_concatenate_global_first() {
        let cmds = materialized_hook_commands(
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"global-pre"}]}]}}"#,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"slot-pre"}]}]}}"#,
            "PreToolUse",
        );
        assert_eq!(cmds, vec!["global-pre".to_owned(), "slot-pre".to_owned()]);
    }

    #[test]
    fn identical_global_and_slot_hook_entry_is_kept_once() {
        let entry = r#"{"matcher":"Bash","hooks":[{"type":"command","command":"same"}]}"#;
        let cmds = materialized_hook_commands(
            &format!(r#"{{"hooks":{{"PreToolUse":[{entry}]}}}}"#),
            &format!(
                r#"{{"hooks":{{"PreToolUse":[{entry},{{"hooks":[{{"type":"command","command":"slot-only"}}]}}]}}}}"#
            ),
            "PreToolUse",
        );
        assert_eq!(cmds, vec!["same".to_owned(), "slot-only".to_owned()]);
    }

    /// Fixture: materialize `global` + `slot` settings (an optional PREVIOUS handle file) and
    /// return the written handle settings.
    fn materialized_settings(global: &str, slot: &str) -> serde_json::Value {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-2");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("settings.json"), slot).unwrap();
        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), global).unwrap();
        let handle = base.join("term-88831");
        std::fs::create_dir_all(&handle).unwrap();
        materialize_handle_settings(&handle, &claude_home, &config).unwrap();
        assert_eq!(
            std::fs::read(config.join("settings.json")).unwrap(),
            slot.as_bytes()
        );
        assert_eq!(
            std::fs::read(claude_home.join("settings.json")).unwrap(),
            global.as_bytes()
        );
        serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
            .unwrap()
    }

    #[test]
    fn autocompact_root_override_is_global_only() {
        let _env_guard = crate::platform::test_env::lock();
        for (global, slot) in [
            (r#"{"autoCompactWindow":1000000,"keepGlobal":true}"#, "{}"),
            ("{}", r#"{"autoCompactWindow":null,"keepSlot":true}"#),
        ] {
            let out = materialized_settings(global, slot);
            let global_value: Value = serde_json::from_str(global).unwrap();
            assert_eq!(
                out.get("autoCompactWindow"),
                global_value.get("autoCompactWindow")
            );
            for source in [global, slot] {
                let source: Value = serde_json::from_str(source).unwrap();
                for key in ["keepGlobal", "keepSlot"] {
                    if let Some(value) = source.get(key) {
                        assert_eq!(out.get(key), Some(value));
                    }
                }
            }
        }
    }

    #[test]
    fn autocompact_model_overrides_respect_global_scope_and_provider_env() {
        let _env_guard = crate::platform::test_env::lock();
        let models = serde_json::json!({
            "modelSettings": {
                "remove-only": {"autoCompactWindow": 1000000},
                "keep-other": {"autoCompactWindow": false, "effort": "high"},
                "already-empty": {},
                "non-object": null
            },
            "env": {
                "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "1048576",
                "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "1048576",
                "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE": "50"
            },
            "unrelated": {"autoCompactWindow": 42}
        });
        let expected_models = serde_json::json!({
            "keep-other": {"effort": "high"}, "already-empty": {}, "non-object": null
        });
        for (global, slot) in [
            (models.to_string(), "{}".to_owned()),
            ("{}".to_owned(), models.to_string()),
        ] {
            let out = materialized_settings(&global, &slot);
            if global != "{}" {
                assert_eq!(out["modelSettings"], models["modelSettings"]);
            } else {
                assert_eq!(out["modelSettings"], expected_models);
            }
            let mut expected_env = models["env"].clone();
            if slot != "{}" {
                expected_env
                    .as_object_mut()
                    .unwrap()
                    .remove("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE");
                expected_env
                    .as_object_mut()
                    .unwrap()
                    .remove("CLAUDE_CODE_AUTO_COMPACT_WINDOW");
            }
            assert_eq!(out["env"], expected_env);
            assert_eq!(out["unrelated"], models["unrelated"]);
        }
    }

    #[cfg(unix)]
    #[test]
    fn autocompact_launch_and_guarded_uuid_swap_preserve_sources_and_sibling() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();
        for slot in [2u16, 3u16] {
            let config = base.join(format!("config-{slot}"));
            std::fs::write(config.join(".claude.json"), b"{}").unwrap();
        }
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let home = TempDir::new().unwrap();
        let global_path = home.path().join("settings.json");
        let global = br#"{"autoCompactWindow":777777,"modelSettings":{"global-only":{"autoCompactWindow":888888}},"globalKeep":true}"#;
        std::fs::write(&global_path, global).unwrap();
        let mut sources = vec![(global_path, global.to_vec())];
        for slot in [2u16, 3u16] {
            let id = profiles::resolve_slot_to_uuid(base, slot).unwrap();
            let uuid_path = settings_path_for(base, id);
            let overlay = serde_json::json!({
                "autoCompactWindow": 1000000,
                "modelSettings": {"slot-only": {"autoCompactWindow": 1000000, "effort": "high"}},
                "env": {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "1048576"},
                "slotKeep": slot
            });
            let bytes = serde_json::to_vec_pretty(&overlay).unwrap();
            std::fs::write(&uuid_path, &bytes).unwrap();
            sources.push((uuid_path, bytes));
            let legacy_path = base.join(format!("config-{slot}/settings.json"));
            let legacy = br#"{"legacyMustNotWin":true,"autoCompactWindow":1000000}"#;
            std::fs::write(&legacy_path, legacy).unwrap();
            sources.push((legacy_path, legacy.to_vec()));
        }
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, home.path(), account2, 21831).unwrap();
        let sibling = create_handle_dir(base, home.path(), account2, 21832).unwrap();
        let sibling_bytes = std::fs::read(sibling.join("settings.json")).unwrap();
        let sibling_target = std::fs::read_link(sibling.join(".credentials.json")).unwrap();
        let assert_settings = |handle: &Path, slot: u16| {
            let out: Value =
                serde_json::from_slice(&std::fs::read(handle.join("settings.json")).unwrap())
                    .unwrap();
            assert_eq!(out["autoCompactWindow"], 777777);
            assert_eq!(
                out["modelSettings"],
                serde_json::json!({"global-only":{"autoCompactWindow":888888},"slot-only":{"effort":"high"}})
            );
            assert!(out
                .pointer("/env/CLAUDE_CODE_AUTO_COMPACT_WINDOW")
                .is_none());
            assert_eq!(out["globalKeep"], true);
            assert_eq!(out["slotKeep"], slot);
            assert!(out.get("legacyMustNotWin").is_none());
        };
        assert_settings(&handle, 2);
        // Simulate Claude writing both forbidden forms in the previous handle as well.
        let previous_path = handle.join("settings.json");
        let mut previous: Value =
            serde_json::from_slice(&std::fs::read(&previous_path).unwrap()).unwrap();
        previous["autoCompactWindow"] = serde_json::json!(1000000);
        previous["modelSettings"]["previous"] = serde_json::json!({"autoCompactWindow":1000000});
        std::fs::write(previous_path, serde_json::to_vec(&previous).unwrap()).unwrap();
        repoint_verified_fixture(
            base,
            home.path(),
            &handle,
            AccountNum::try_from(3u16).unwrap(),
        )
        .unwrap();
        assert_settings(&handle, 3);
        let target_id = profiles::resolve_slot_to_uuid(base, 3).unwrap();
        assert_eq!(
            std::fs::read_link(handle.join(".credentials.json")).unwrap(),
            crate::accounts::identity_store::credentials_path_for(base, target_id)
        );
        assert_eq!(
            std::fs::read(sibling.join("settings.json")).unwrap(),
            sibling_bytes
        );
        assert_eq!(
            std::fs::read_link(sibling.join(".credentials.json")).unwrap(),
            sibling_target
        );
        for (path, bytes) in sources {
            assert_eq!(
                std::fs::read(path).unwrap(),
                bytes,
                "source settings changed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn r2_final_materializer_uuid_overlay_does_not_borrow_stale_legacy_provider_proof() {
        let _guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = AccountNum::try_from(9u16).unwrap();
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "zai",
            slot,
            Some("sk-fixture-zai"),
            None,
        )
        .unwrap();
        let config = base.join("config-9");
        assert!(crate::session::settings_policy::slot_allows_provider_window(base, &config));
        assert!(!config.join(".credentials.json").exists());
        assert!(!base.join("credentials/9.json").exists());
        let uuid = "11111111-1111-4111-8111-111111111111"
            .parse::<crate::accounts::identity_store::IdentityId>()
            .unwrap();
        let uuid_path = crate::accounts::identity_store::settings_path_for(base, uuid);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        std::fs::write(
            &uuid_path,
            br#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576","keepUUID":"yes"}}"#,
        )
        .unwrap();
        let home = TempDir::new().unwrap();
        std::fs::write(
            home.path().join("settings.json"),
            br#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"777777"}}"#,
        )
        .unwrap();
        let handle = base.join("term-21839");
        std::fs::create_dir(&handle).unwrap();
        let sources: Vec<_> = [
            config.join("settings.json"),
            config.join(".csq-account"),
            base.join("profiles.json"),
            uuid_path.clone(),
            home.path().join("settings.json"),
        ]
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
        let prepared =
            prepare_handle_settings_tmp(&handle, home.path(), &config, Some(&uuid_path)).unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&prepared).unwrap()).unwrap();
        std::fs::remove_file(prepared).unwrap();
        for (path, bytes) in sources {
            assert!(
                std::fs::read(path).unwrap() == bytes,
                "source settings changed"
            );
        }
        assert_eq!(
            value["env"]["keepUUID"], "yes",
            "actual UUID overlay was not selected"
        );
        assert_eq!(
            value["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"], "777777",
            "UUID window borrowed stale legacy API-key proof"
        );
    }

    #[test]
    fn r1_h2_slot_percentage_is_removed_before_global_merge() {
        let _guard = crate::platform::test_env::lock();
        let out = materialized_settings(
            r#"{"env":{"CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":"70","keepGlobal":"yes"}}"#,
            r#"{"env":{"CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":"50","keepSlot":"yes"}}"#,
        );
        assert_eq!(out["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"], "70");
        assert_eq!(out["env"]["keepGlobal"], "yes");
        assert_eq!(out["env"]["keepSlot"], "yes");
    }

    #[test]
    fn r1_h2_unproven_slot_window_is_removed_before_global_merge() {
        let _guard = crate::platform::test_env::lock();
        let out = materialized_settings(
            r#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"777777"}}"#,
            r#"{"env":{"CLAUDE_CODE_AUTO_COMPACT_WINDOW":"1048576","CLAUDE_CODE_MAX_CONTEXT_TOKENS":"1048576"}}"#,
        );
        assert_eq!(out["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"], "777777");
        assert_eq!(out["env"]["CLAUDE_CODE_MAX_CONTEXT_TOKENS"], "1048576");
    }

    #[test]
    fn r1_h2_published_third_party_keeps_window_but_removes_percentage() {
        let _guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = AccountNum::try_from(9u16).unwrap();
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "zai",
            slot,
            Some("sk-fixture-zai"),
            None,
        )
        .unwrap();
        let config = base.join("config-9");
        let overlay_path = config.join("settings.json");
        let mut overlay: Value =
            serde_json::from_slice(&std::fs::read(&overlay_path).unwrap()).unwrap();
        overlay["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = serde_json::json!("1048576");
        overlay["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] = serde_json::json!("50");
        let source = serde_json::to_vec(&overlay).unwrap();
        std::fs::write(&overlay_path, &source).unwrap();
        let home = TempDir::new().unwrap();
        std::fs::write(home.path().join("settings.json"), b"{}").unwrap();
        let handle = create_handle_dir(base, home.path(), slot, 21835).unwrap();
        let out: Value =
            serde_json::from_slice(&std::fs::read(handle.join("settings.json")).unwrap()).unwrap();
        assert_eq!(out["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"], "1048576");
        assert!(
            out.pointer("/env/CLAUDE_AUTOCOMPACT_PCT_OVERRIDE")
                .is_none(),
            "slot percentage leaked"
        );
        assert_eq!(std::fs::read(overlay_path).unwrap(), source);
    }

    #[test]
    fn r1_h2_global_only_environment_overrides_pass_unchanged() {
        let _guard = crate::platform::test_env::lock();
        let global = serde_json::json!({"env": {
            "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":"70",
            "CLAUDE_CODE_AUTO_COMPACT_WINDOW":"777777"
        }});
        let out = materialized_settings(&global.to_string(), "{}");
        assert_eq!(out["env"], global["env"]);
    }

    #[test]
    fn r1_m1_global_root_override_survives_conflicting_slot_override() {
        let _guard = crate::platform::test_env::lock();
        let out = materialized_settings(
            r#"{"autoCompactWindow":777777,"keepGlobal":true}"#,
            r#"{"autoCompactWindow":1048576,"keepSlot":true}"#,
        );
        assert_eq!(
            out["autoCompactWindow"], 777777,
            "global root override was removed"
        );
        assert_eq!(out["keepGlobal"], true);
        assert_eq!(out["keepSlot"], true);
    }

    #[test]
    fn r1_m1_global_model_override_survives_conflicting_slot_override() {
        let _guard = crate::platform::test_env::lock();
        let out = materialized_settings(
            r#"{"modelSettings":{"shared":{"autoCompactWindow":777777,"globalKeep":true},"globalOnly":{"autoCompactWindow":888888}}}"#,
            r#"{"modelSettings":{"shared":{"autoCompactWindow":1048576,"effort":"high"},"slotOnly":{"autoCompactWindow":1048576},"alreadyEmpty":{}}}"#,
        );
        assert_eq!(
            out["modelSettings"],
            serde_json::json!({
                "shared":{"autoCompactWindow":777777,"globalKeep":true,"effort":"high"},
                "globalOnly":{"autoCompactWindow":888888},"alreadyEmpty":{}
            }),
            "global per-model override was removed"
        );
    }

    const GLOBAL_PRE: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"global-pre"}]}]}}"#;

    fn commands_of(out: &serde_json::Value, event: &str) -> Vec<String> {
        out["hooks"][event]
            .as_array()
            .unwrap_or_else(|| panic!("hooks.{event} missing in {out}"))
            .iter()
            .filter_map(|e| e.pointer("/hooks/0/command").and_then(|c| c.as_str()))
            .map(str::to_owned)
            .collect()
    }

    /// Whatever the slot's `hooks` value is, every global event entry survives.
    #[test]
    fn slot_hooks_value_of_any_shape_never_drops_global_hooks() {
        for slot_hooks in [
            r#"null"#,
            r#"[]"#,
            r#""x""#,
            r#"false"#,
            r#"0"#,
            r#"{"PreToolUse":null}"#,
            r#"{"PreToolUse":"x"}"#,
            r#"{"PreToolUse":{}}"#,
            r#"{"PreToolUse":[]}"#,
        ] {
            let out = materialized_settings(GLOBAL_PRE, &format!(r#"{{"hooks":{slot_hooks}}}"#));
            assert_eq!(
                commands_of(&out, "PreToolUse"),
                vec!["global-pre".to_owned()],
                "slot hooks={slot_hooks}"
            );
        }
    }

    /// A slot `disableAllHooks` never reaches the handle and never overrides the global value.
    #[test]
    fn slot_disable_all_hooks_is_stripped_before_the_merge() {
        let out = materialized_settings(GLOBAL_PRE, r#"{"disableAllHooks":true}"#);
        assert!(out.get("disableAllHooks").is_none(), "leaked: {out}");
        assert_eq!(
            commands_of(&out, "PreToolUse"),
            vec!["global-pre".to_owned()]
        );

        let global_false = r#"{"disableAllHooks":false,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"global-pre"}]}]}}"#;
        let out = materialized_settings(global_false, r#"{"disableAllHooks":true}"#);
        assert_eq!(out["disableAllHooks"], serde_json::json!(false), "{out}");

        let dir = TempDir::new().unwrap();
        let carrier = dir.path().join("settings.json");
        std::fs::write(&carrier, r#"{"disableAllHooks":false}"#).unwrap();
        assert!(settings_file_has_disable_all_hooks(&carrier));
        std::fs::write(&carrier, r#"{"other":1}"#).unwrap();
        assert!(!settings_file_has_disable_all_hooks(&carrier));
        assert!(!settings_file_has_disable_all_hooks(
            &dir.path().join("absent.json")
        ));
    }

    /// An unparseable global settings file never yields a hookless handle file: the hooks the
    /// previous materialization wrote are kept.
    #[test]
    fn unusable_global_settings_keeps_previously_materialized_hooks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-2");
        std::fs::create_dir_all(&config).unwrap();
        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), GLOBAL_PRE).unwrap();
        let handle = base.join("term-88832");
        std::fs::create_dir_all(&handle).unwrap();
        materialize_handle_settings(&handle, &claude_home, &config).unwrap();
        assert!(!global_claude_settings_unusable(&claude_home));

        for broken in ["{ not json", "[1,2]"] {
            std::fs::write(claude_home.join("settings.json"), broken).unwrap();
            assert!(global_claude_settings_unusable(&claude_home), "{broken}");
            materialize_handle_settings(&handle, &claude_home, &config).unwrap();
            let out: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(handle.join("settings.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                commands_of(&out, "PreToolUse"),
                vec!["global-pre".to_owned()],
                "global={broken}"
            );
        }
    }

    /// Fixture for the unusable-global cases: two slots (`config-2`, `config-3`) with their own
    /// overlay hooks, one shared `claude_home`, one accounts dir.
    struct HooksFixture {
        _dir: TempDir,
        base: PathBuf,
        claude_home: PathBuf,
    }

    impl HooksFixture {
        fn new(global: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let base = dir.path().to_path_buf();
            for (n, cmd) in [(2, "slot-a-own"), (3, "slot-b-own")] {
                let c = base.join(format!("config-{n}"));
                std::fs::create_dir_all(&c).unwrap();
                std::fs::write(
                    c.join("settings.json"),
                    format!(
                        r#"{{"hooks":{{"Stop":[{{"hooks":[{{"type":"command","command":"{cmd}"}}]}}]}}}}"#
                    ),
                )
                .unwrap();
            }
            let claude_home = base.join("claude_home");
            std::fs::create_dir_all(&claude_home).unwrap();
            std::fs::write(claude_home.join("settings.json"), global).unwrap();
            Self {
                _dir: dir,
                base,
                claude_home,
            }
        }

        fn materialize(&self, slot: u16, pid: &str) -> serde_json::Value {
            let handle = self.base.join(format!("term-{pid}"));
            std::fs::create_dir_all(&handle).unwrap();
            materialize_handle_settings(
                &handle,
                &self.claude_home,
                &self.base.join(format!("config-{slot}")),
            )
            .unwrap();
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap()
        }
    }

    const GLOBAL_STOP: &str =
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"global-stop"}]}]}}"#;

    /// F7/N9: with the global unusable and a last-known-good global record, a terminal gets
    /// the RECORDED global hooks plus its own slot's hooks, and never another slot's.
    #[test]
    fn unusable_global_seeds_hooks_from_the_global_record_never_another_slot() {
        let fx = HooksFixture::new(GLOBAL_STOP);
        let a = fx.materialize(2, "1001");
        assert_eq!(
            commands_of(&a, "Stop"),
            vec!["global-stop".to_owned(), "slot-a-own".to_owned()]
        );
        std::fs::write(fx.claude_home.join("settings.json"), "{ not json").unwrap();
        // Slot B terminal, created fresh and repointed from slot A's handle.
        let b = fx.materialize(3, "1002");
        let cmds = commands_of(&b, "Stop");
        assert!(cmds.contains(&"global-stop".to_owned()), "{cmds:?}");
        assert!(cmds.contains(&"slot-b-own".to_owned()), "{cmds:?}");
        assert!(!cmds.contains(&"slot-a-own".to_owned()), "leaked: {cmds:?}");
        // Re-materializing slot A's handle as slot B (a swap) also never carries A's hooks.
        let handle_a = fx.base.join("term-1001");
        materialize_handle_settings(&handle_a, &fx.claude_home, &fx.base.join("config-3")).unwrap();
        let swapped: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(handle_a.join("settings.json")).unwrap())
                .unwrap();
        let cmds = commands_of(&swapped, "Stop");
        assert!(!cmds.contains(&"slot-a-own".to_owned()), "leaked: {cmds:?}");
        assert!(cmds.contains(&"slot-b-own".to_owned()), "{cmds:?}");
    }

    /// An unusable global with NO record gives no global hooks (and no other slot's), and the
    /// record file is private (0600) when written.
    #[test]
    fn unusable_global_without_a_record_gives_no_hooks_and_never_another_slots() {
        let fx = HooksFixture::new("{ not json");
        let a = fx.materialize(2, "2001");
        assert_eq!(commands_of(&a, "Stop"), vec!["slot-a-own".to_owned()]);
        let b = fx.materialize(3, "2002");
        assert_eq!(commands_of(&b, "Stop"), vec!["slot-b-own".to_owned()]);
        let record = fx.base.join(GLOBAL_HOOKS_RECORD_FILE);
        assert!(record.symlink_metadata().is_err(), "no record may appear");
    }

    #[cfg(unix)]
    #[test]
    fn global_hooks_record_is_written_private() {
        use std::os::unix::fs::PermissionsExt;
        let fx = HooksFixture::new(GLOBAL_STOP);
        fx.materialize(2, "3001");
        let record = fx.base.join(GLOBAL_HOOKS_RECORD_FILE);
        let mode = std::fs::metadata(&record).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["Stop"][0]["hooks"][0]["command"],
            serde_json::json!("global-stop")
        );
    }

    /// De-dup is ACROSS layers only: duplicates inside one layer are kept.
    #[test]
    fn duplicate_hook_entries_inside_one_layer_are_kept() {
        let a = r#"{"hooks":[{"type":"command","command":"a"}]}"#;
        let b = r#"{"hooks":[{"type":"command","command":"b"}]}"#;
        let cmds = materialized_hook_commands(
            &format!(r#"{{"hooks":{{"Stop":[{a},{a}]}}}}"#),
            &format!(r#"{{"hooks":{{"Stop":[{b},{b},{a}]}}}}"#),
            "Stop",
        );
        assert_eq!(
            cmds,
            ["a", "a", "b", "b"].map(str::to_owned).to_vec(),
            "global dupes kept, slot dupes kept, slot copy of a global entry dropped"
        );
    }

    /// F3a: the handle's resolved config (the slot config symlink) disables hooks.
    #[cfg(unix)]
    #[test]
    fn codex_hooks_disabled_by_config_reads_features_hooks_and_the_legacy_alias() {
        let dir = TempDir::new().unwrap();
        let check = |name: &str, cfg: Option<&str>| -> bool {
            let h = dir.path().join(name);
            std::fs::create_dir_all(&h).unwrap();
            if let Some(cfg) = cfg {
                let slot_cfg = dir.path().join(format!("{name}-slot.toml"));
                std::fs::write(&slot_cfg, cfg).unwrap(); // CI-ALLOW-fs-write-config-toml
                std::os::unix::fs::symlink(&slot_cfg, h.join("config.toml")).unwrap();
            }
            codex_hooks_disabled_by_config(&h)
        };
        assert!(check("a", Some("[features]\nhooks = false\n")));
        assert!(check("b", Some("[features]\ncodex_hooks = false\n")));
        assert!(!check("c", Some("[features]\nhooks = true\n")));
        assert!(!check(
            "d",
            Some("[features]\nhooks = true\ncodex_hooks = false\n")
        ));
        assert!(!check("e", Some("model = \"m\"\n")));
        assert!(check("f", Some("[features]\nhooks = false")));
        assert!(!check("g", Some("not = [toml")));
        assert!(!check("h", None));
    }

    #[cfg(unix)]
    fn fixture_handle(dir: &Path, name: &str) -> PathBuf {
        let h = dir.join(name);
        std::fs::create_dir_all(&h).unwrap();
        h
    }

    /// Falsifying result: with the link removal branch deleted the dangling link survives.
    /// N5: the observed codex-cli 0.162.1 precedence, case by case.
    #[cfg(unix)]
    #[test]
    fn codex_hooks_config_follows_the_observed_precedence() {
        use CodexHooksConfigState as C;
        let dir = TempDir::new().unwrap();
        let state = |name: &str, cfg: &str| -> C {
            let h = dir.path().join(name);
            std::fs::create_dir_all(&h).unwrap();
            std::fs::write(h.join("config.toml"), cfg).unwrap(); // CI-ALLOW-fs-write-config-toml
            codex_hooks_config(&h).state
        };
        // A `hooks` key wins over `codex_hooks`, whichever comes first.
        assert_eq!(
            state("c3", "[features]\nhooks = true\ncodex_hooks = false\n"),
            C::Enabled
        );
        assert_eq!(
            state("c3r", "[features]\ncodex_hooks = false\nhooks = true\n"),
            C::Enabled
        );
        assert_eq!(
            state("c4", "[features]\nhooks = false\ncodex_hooks = true\n"),
            C::Disabled
        );
        assert_eq!(
            state("c4r", "[features]\ncodex_hooks = true\nhooks = false\n"),
            C::Disabled
        );
        // The alias applies only when no `hooks` key is set.
        assert_eq!(
            state("c2", "[features]\ncodex_hooks = false\n"),
            C::Disabled
        );
        assert_eq!(state("c1", "[features]\nhooks = false\n"), C::Disabled);
        assert_eq!(state("c0", ""), C::Enabled);
        // `[profiles.*]` tables are ignored by Codex: they never disable.
        assert_eq!(
            state("p5a", "[profiles.p.features]\nhooks = false\n"),
            C::Enabled
        );
        // A top-level `profile` key makes Codex fail every command.
        assert_eq!(
            state(
                "p6a",
                "profile = \"p\"\n[profiles.p.features]\nhooks = false\n"
            ),
            C::LegacyProfileKey
        );
        // Unparseable, mistyped or duplicate-key configs are UNKNOWN, never "not disabled".
        assert_eq!(state("u7a", "[features"), C::Unknown);
        assert_eq!(state("u7b", "[features]\nhooks = \"nope\"\n"), C::Unknown);
        assert_eq!(
            state("u7c", "[features]\nhooks = true\nhooks = false\n"),
            C::Unknown
        );
        assert_eq!(state("u7e", "features = 3\n"), C::Unknown);
        let over = dir.path().join("over");
        std::fs::create_dir_all(&over).unwrap();
        std::fs::write(
            over.join("config.toml"),
            vec![b'#'; CODEX_HOOKS_MAX_BYTES as usize + 1],
        )
        .unwrap(); // CI-ALLOW-fs-write-config-toml
        assert_eq!(codex_hooks_config(&over).state, C::Unknown);
        let dangling = dir.path().join("dangling");
        std::fs::create_dir_all(&dangling).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("nowhere.toml"),
            dangling.join("config.toml"),
        )
        .unwrap();
        assert_eq!(codex_hooks_config(&dangling).state, C::Unknown);
        let absent = dir.path().join("absent");
        std::fs::create_dir_all(&absent).unwrap();
        assert_eq!(codex_hooks_config(&absent).state, C::Enabled);
        // The bool wrapper keeps "unknown" distinct from disabled.
        assert!(!codex_hooks_disabled_by_config(&over));
    }

    /// N5: `<name>.config.toml` profile files are noted, without changing the base state.
    #[test]
    fn codex_hooks_config_notes_profile_files_that_disable_hooks() {
        let dir = TempDir::new().unwrap();
        let h = dir.path().join("h");
        std::fs::create_dir_all(&h).unwrap();
        let put = |name: &str, cfg: &str| {
            std::fs::write(h.join(name), cfg).unwrap(); // CI-ALLOW-fs-write-config-toml
        };
        put("config.toml", "[features]\nhooks = true\n");
        put("off.config.toml", "[features]\nhooks = false\n");
        put("alias.config.toml", "[features]\ncodex_hooks = false\n");
        put(
            "winner.config.toml",
            "[features]\nhooks = true\ncodex_hooks = false\n",
        );
        put("bad name.config.toml", "[features]\nhooks = false\n");
        put("broken.config.toml", "[features");
        let cfg = codex_hooks_config(&h);
        assert_eq!(cfg.state, CodexHooksConfigState::Enabled);
        assert_eq!(
            cfg.profile_disabled,
            vec!["alias".to_owned(), "off".to_owned()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_planted_link_is_removed_when_global_is_deleted() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 4);
        setup_codex_slot(&base, 9);
        let global = write_global_hooks(dir.path());
        let _env = GlobalHooksEnv::set(Some(&global));
        let handle =
            create_handle_dir_codex(&base, AccountNum::try_from(4u16).unwrap(), 88840).unwrap();
        assert_eq!(
            std::fs::read_link(handle.join("hooks.json")).unwrap(),
            global
        );

        std::fs::remove_file(&global).unwrap();
        repoint_handle_dir_codex(&base, &handle, AccountNum::try_from(9u16).unwrap()).unwrap();
        assert!(
            handle.join("hooks.json").symlink_metadata().is_err(),
            "the stale link must be removed"
        );
        assert_eq!(
            codex_hooks_link_state(&handle, Some(&global)),
            CodexHooksLinkState::MissingGlobal
        );
    }

    /// F5: a handle whose link is missing because the global was absent re-links once the
    /// global appears, on the next repoint and on the next create.
    #[cfg(unix)]
    #[test]
    fn codex_missing_link_self_heals_when_the_global_appears() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        setup_codex_slot(&base, 4);
        setup_codex_slot(&base, 9);
        let global = dir.path().join("global-codex").join("hooks.json");
        let _env = GlobalHooksEnv::set(Some(&global));
        let handle =
            create_handle_dir_codex(&base, AccountNum::try_from(4u16).unwrap(), 88841).unwrap();
        assert!(handle.join("hooks.json").symlink_metadata().is_err());

        write_global_hooks(dir.path());
        assert_eq!(
            codex_hooks_link_state(&handle, Some(&global)),
            CodexHooksLinkState::Unlinked
        );
        repoint_handle_dir_codex(&base, &handle, AccountNum::try_from(9u16).unwrap()).unwrap();
        assert_eq!(
            std::fs::read_link(handle.join("hooks.json")).unwrap(),
            global
        );
        assert_eq!(
            codex_hooks_link_state(&handle, Some(&global)),
            CodexHooksLinkState::Ok
        );
    }

    /// One shared predicate: a directory (or dangling link) at the global path is MISSING for
    /// both the link path and doctor.
    #[cfg(unix)]
    #[test]
    fn codex_global_hooks_directory_counts_as_missing_everywhere() {
        let dir = TempDir::new().unwrap();
        let global_dir = dir.path().join("hooks.json");
        std::fs::create_dir_all(&global_dir).unwrap();
        assert!(!codex_global_hooks_usable(&global_dir));
        let h = fixture_handle(dir.path(), "h");
        link_codex_global_hooks(&h, Some(&global_dir)).unwrap();
        assert!(h.join("hooks.json").symlink_metadata().is_err());
        assert_eq!(
            codex_hooks_link_state(&h, Some(&global_dir)),
            CodexHooksLinkState::MissingGlobal
        );
        let real = write_global_hooks(dir.path());
        assert!(codex_global_hooks_usable(&real));
        let dangling = dir.path().join("dangling.json");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(!codex_global_hooks_usable(&dangling));
    }

    /// Every doctor state, each produced by a distinct on-disk shape.
    #[cfg(unix)]
    #[test]
    fn codex_hooks_link_state_names_each_shape() {
        use CodexHooksLinkState as S;
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let elsewhere = dir.path().join("elsewhere.json");
        std::fs::write(&elsewhere, "{}").unwrap();
        let link = |h: &Path, target: &Path| {
            std::os::unix::fs::symlink(target, h.join("hooks.json")).unwrap();
        };
        let g = Some(global.as_path());

        let ok = fixture_handle(dir.path(), "ok");
        link(&ok, &global);
        assert_eq!(codex_hooks_link_state(&ok, g), S::Ok);

        let unlinked = fixture_handle(dir.path(), "unlinked");
        assert_eq!(codex_hooks_link_state(&unlinked, g), S::Unlinked);

        let foreign = fixture_handle(dir.path(), "foreign");
        std::fs::write(foreign.join("hooks.json"), "{}").unwrap();
        assert_eq!(codex_hooks_link_state(&foreign, g), S::ForeignFile);

        let dangling = fixture_handle(dir.path(), "dangling");
        link(&dangling, &dir.path().join("nowhere.json"));
        assert_eq!(codex_hooks_link_state(&dangling, g), S::Dangling);

        let wrong = fixture_handle(dir.path(), "wrong");
        link(&wrong, &elsewhere);
        assert_eq!(codex_hooks_link_state(&wrong, g), S::WrongTarget);

        let blocked = fixture_handle(dir.path(), "blocked");
        std::fs::create_dir_all(blocked.join("hooks.json.swap-tmp")).unwrap();
        std::fs::write(blocked.join("hooks.json.swap-tmp/keep"), "x").unwrap();
        assert_eq!(codex_hooks_link_state(&blocked, g), S::SwapTmpBlocked);

        assert_eq!(codex_hooks_link_state(&unlinked, None), S::MissingGlobal);
        assert_eq!(codex_hooks_link_state(&ok, None), S::MissingGlobal);
        assert!(!S::Ok.is_problem() && S::Unlinked.is_problem());
    }

    /// F6: a leftover `.swap-tmp` of a non-file type is removed before use; one that cannot
    /// be removed refuses the link (an `Err`, and doctor shows it).
    #[cfg(unix)]
    #[test]
    fn codex_swap_tmp_of_non_file_type_is_cleared_or_link_is_refused() {
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let elsewhere = dir.path().join("elsewhere.json");
        std::fs::write(&elsewhere, "{}").unwrap();

        let planted_link = fixture_handle(dir.path(), "h-link");
        std::os::unix::fs::symlink(&elsewhere, planted_link.join("hooks.json.swap-tmp")).unwrap();
        link_codex_global_hooks(&planted_link, Some(&global)).unwrap();
        assert_eq!(
            std::fs::read_link(planted_link.join("hooks.json")).unwrap(),
            global
        );
        assert!(planted_link
            .join("hooks.json.swap-tmp")
            .symlink_metadata()
            .is_err());

        let empty_dir = fixture_handle(dir.path(), "h-emptydir");
        std::fs::create_dir(empty_dir.join("hooks.json.swap-tmp")).unwrap();
        link_codex_global_hooks(&empty_dir, Some(&global)).unwrap();
        assert_eq!(
            std::fs::read_link(empty_dir.join("hooks.json")).unwrap(),
            global
        );

        let full_dir = fixture_handle(dir.path(), "h-fulldir");
        let tmp = full_dir.join("hooks.json.swap-tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("keep"), "x").unwrap();
        assert!(link_codex_global_hooks(&full_dir, Some(&global)).is_err());
        assert!(full_dir.join("hooks.json").symlink_metadata().is_err());
        assert_eq!(
            codex_hooks_link_state(&full_dir, Some(&global)),
            CodexHooksLinkState::SwapTmpBlocked
        );
        assert!(
            tmp.join("keep").exists(),
            "an unremovable tmp is never emptied"
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_symlink_elsewhere_is_moved_aside_not_deleted() {
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let elsewhere = dir.path().join("elsewhere.json");
        std::fs::write(&elsewhere, "{}").unwrap();
        let h = fixture_handle(dir.path(), "h");
        std::os::unix::fs::symlink(&elsewhere, h.join("hooks.json")).unwrap();
        assert_eq!(
            codex_hooks_link_state(&h, Some(&global)),
            CodexHooksLinkState::WrongTarget
        );
        link_codex_global_hooks(&h, Some(&global)).unwrap();
        assert_eq!(std::fs::read_link(h.join("hooks.json")).unwrap(), global);
        assert_eq!(
            codex_hooks_link_state(&h, Some(&global)),
            CodexHooksLinkState::Ok
        );
        let kept = codex_hooks_preserved_foreign(&h);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(std::fs::read_link(h.join(&kept[0])).unwrap(), elsewhere);
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"{}");
        // The missing-global branch never touches a link that is not ours.
        let gone = dir.path().join("gone.json");
        link_codex_global_hooks(&h, Some(&gone)).unwrap();
        assert_eq!(std::fs::read_link(h.join("hooks.json")).unwrap(), global);
    }

    /// N8 window: `hooks.json` recreated between the detach and the link creation is never
    /// overwritten by the link.
    #[cfg(unix)]
    #[test]
    fn codex_hooks_recreated_in_the_detach_window_is_never_overwritten() {
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let h = fixture_handle(dir.path(), "h");
        let local = h.join("hooks.json");
        std::fs::write(
            &local,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"y"}]}]}}"#,
        )
        .unwrap();
        let writer = local.clone();
        AFTER_ASIDE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(&writer, b"RECREATED-BY-CODEX").unwrap()
            }));
        });
        link_codex_global_hooks(&h, Some(&global)).unwrap();
        AFTER_ASIDE.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(std::fs::read(&local).unwrap(), b"RECREATED-BY-CODEX");
        assert!(local.symlink_metadata().unwrap().is_file());
        assert!(h.join("hooks.json.swap-tmp").symlink_metadata().is_err());
    }

    /// The doctor's swap-tmp predicate equals the link path's: an empty directory is cleared
    /// (no alarm), a non-empty one blocks whatever else sits at `hooks.json`.
    #[cfg(unix)]
    #[test]
    fn codex_swap_tmp_doctor_predicate_matches_the_link_path() {
        use CodexHooksLinkState as S;
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let g = Some(global.as_path());
        // An EMPTY swap-tmp directory is cleared by the link path, so doctor raises no alarm.
        let empty = fixture_handle(dir.path(), "h-empty");
        std::fs::create_dir(empty.join("hooks.json.swap-tmp")).unwrap();
        assert_eq!(codex_hooks_link_state(&empty, g), S::Unlinked);
        link_codex_global_hooks(&empty, g).unwrap();
        assert_eq!(codex_hooks_link_state(&empty, g), S::Ok);
        // A blocked swap-tmp next to a foreign file is SwapTmpBlocked, not ForeignFile.
        let blocked = fixture_handle(dir.path(), "h-blocked");
        std::fs::write(blocked.join("hooks.json"), "{}").unwrap();
        let tmp = blocked.join("hooks.json.swap-tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("keep"), "x").unwrap();
        assert_eq!(codex_hooks_link_state(&blocked, g), S::SwapTmpBlocked);
        assert!(link_codex_global_hooks(&blocked, g).is_err());
        // Beside a wrong-target link too.
        let wrong = fixture_handle(dir.path(), "h-wrong");
        std::os::unix::fs::symlink(dir.path().join("elsewhere.json"), wrong.join("hooks.json"))
            .unwrap();
        let tmp = wrong.join("hooks.json.swap-tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("keep"), "x").unwrap();
        assert_eq!(codex_hooks_link_state(&wrong, g), S::SwapTmpBlocked);
        // A correct link never reports the blocked tmp (the link path returns early too).
        let ok = fixture_handle(dir.path(), "h-ok");
        std::os::unix::fs::symlink(&global, ok.join("hooks.json")).unwrap();
        let tmp = ok.join("hooks.json.swap-tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("keep"), "x").unwrap();
        assert_eq!(codex_hooks_link_state(&ok, g), S::Ok);
        link_codex_global_hooks(&ok, g).unwrap();
    }

    /// Subset-to-rename race: the local file changing after the subset check aborts the
    /// handle; the user's new content survives.
    #[cfg(unix)]
    #[test]
    fn codex_local_hooks_changed_before_rename_aborts_the_handle() {
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let h = fixture_handle(dir.path(), "h");
        let local = h.join("hooks.json");
        std::fs::write(
            &local,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"y"}]}]}}"#,
        )
        .unwrap();
        let edited =
            br#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"USER-EDIT"}]}]}}"#;
        let writer = local.clone();
        BEFORE_REREAD.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || std::fs::write(&writer, edited).unwrap()));
        });
        link_codex_global_hooks(&h, Some(&global)).unwrap();
        BEFORE_REREAD.with(|hook| *hook.borrow_mut() = None);
        let meta = local.symlink_metadata().unwrap();
        assert!(meta.is_file() && !meta.file_type().is_symlink());
        assert_eq!(std::fs::read(&local).unwrap(), edited);
        assert!(h.join("hooks.json.swap-tmp").symlink_metadata().is_err());
        assert_eq!(
            codex_hooks_link_state(&h, Some(&global)),
            CodexHooksLinkState::ForeignFile
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_copy_fallback_materializes_a_resynced_copy() {
        use CodexHooksLinkState as S;
        let dir = TempDir::new().unwrap();
        let global = write_global_hooks(dir.path());
        let g = Some(global.as_path());
        let h = fixture_handle(dir.path(), "h");
        let set_copy = |on: bool| FORCE_COPY_LINK.with(|c| c.set(on));

        // No symlink privilege: launch does NOT fail; hooks.json is a COPY plus a digest marker.
        set_copy(true);
        link_codex_global_hooks(&h, g).unwrap();
        let meta = h.join("hooks.json").symlink_metadata().unwrap();
        assert!(meta.is_file() && !meta.file_type().is_symlink());
        assert_eq!(
            std::fs::read(h.join("hooks.json")).unwrap(),
            std::fs::read(&global).unwrap()
        );
        assert!(h.join("hooks.json.swap-tmp").symlink_metadata().is_err());
        assert_eq!(codex_hooks_link_state(&h, g), S::CopyCurrent);
        assert!(S::CopyCurrent.message().contains("Developer Mode"));

        // The global changes: doctor says STALE; the next launch re-syncs (no foreign file).
        std::fs::write(&global, r#"{"hooks":{"Stop":[]}}"#).unwrap();
        assert_eq!(codex_hooks_link_state(&h, g), S::CopyStale);
        link_codex_global_hooks(&h, g).unwrap();
        assert_eq!(codex_hooks_link_state(&h, g), S::CopyCurrent);
        assert_eq!(
            std::fs::read(h.join("hooks.json")).unwrap(),
            br#"{"hooks":{"Stop":[]}}"#
        );
        assert!(codex_hooks_preserved_foreign(&h).is_empty());

        // A user-edited copy is foreign: preserved, then a fresh copy is made.
        std::fs::write(h.join("hooks.json"), b"USER-EDIT").unwrap();
        link_codex_global_hooks(&h, g).unwrap();
        let kept = codex_hooks_preserved_foreign(&h);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(std::fs::read(h.join(&kept[0])).unwrap(), b"USER-EDIT");
        assert_eq!(codex_hooks_link_state(&h, g), S::CopyCurrent);

        // Once symlinks work again the copy is replaced by the link and the marker removed.
        set_copy(false);
        link_codex_global_hooks(&h, g).unwrap();
        assert_eq!(std::fs::read_link(h.join("hooks.json")).unwrap(), global);
        assert!(h
            .join("hooks.json.csq-copy-sha256")
            .symlink_metadata()
            .is_err());
        assert_eq!(codex_hooks_link_state(&h, g), S::Ok);
    }

    /// F8: the bound is enforced at read on the OPEN handle.
    #[cfg(unix)]
    #[test]
    fn read_regular_bounded_refuses_devices_fifos_symlinks_and_oversize() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let ok = dir.path().join("ok.json");
        std::fs::write(&ok, b"{}").unwrap();
        assert_eq!(read_regular_bounded(&ok, true).as_deref(), Some(&b"{}"[..]));

        let at_limit = dir.path().join("at-limit");
        std::fs::write(&at_limit, vec![b' '; CODEX_HOOKS_MAX_BYTES as usize]).unwrap();
        assert!(read_regular_bounded(&at_limit, true).is_some());
        let over = dir.path().join("over");
        std::fs::write(&over, vec![b' '; CODEX_HOOKS_MAX_BYTES as usize + 1]).unwrap();
        assert!(read_regular_bounded(&over, true).is_none());

        // A character device reports length 0 and never ends: refused by the fstat.
        assert!(read_regular_bounded(Path::new("/dev/zero"), true).is_none());

        let fifo = dir.path().join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(read_regular_bounded(&fifo, true).is_none());

        let sym = dir.path().join("sym.json");
        std::os::unix::fs::symlink(&ok, &sym).unwrap();
        assert!(read_regular_bounded(&sym, true).is_none(), "nofollow");
        assert!(read_regular_bounded(&sym, false).is_some());
    }

    /// Runs `f` on a thread and fails (instead of hanging the suite) when it does not finish.
    #[cfg(unix)]
    fn finishes_within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the call blocked on a FIFO")
    }

    /// N7: a FIFO at the global hooks path, or at a slot `settings.json`, cannot hang the
    /// link predicate or the doctor's `disableAllHooks` read.
    #[cfg(unix)]
    #[test]
    fn a_fifo_cannot_hang_the_link_predicate_or_the_disable_all_hooks_read() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("fifo");
        make_fifo(&fifo);
        let f = fifo.clone();
        assert!(!finishes_within(move || codex_global_hooks_usable(&f)));
        let f = fifo.clone();
        assert!(!finishes_within(move || {
            settings_file_has_disable_all_hooks(&f)
        }));
        let handle = dir.path().join("h");
        std::fs::create_dir_all(&handle).unwrap();
        let f = fifo.clone();
        let h = handle.clone();
        assert_eq!(
            finishes_within(move || codex_hooks_link_state(&h, Some(&f))),
            CodexHooksLinkState::MissingGlobal
        );
        let ok = dir.path().join("ok.json");
        std::fs::write(&ok, b"{}").unwrap();
        assert!(codex_global_hooks_usable(&ok));
    }

    #[test]
    fn json_subset_semantics() {
        use serde_json::json;
        let g = json!({"a":{"b":1,"c":[1,2,{"d":3,"e":4}]},"f":"x"});
        assert!(json_is_subset(&json!({}), &g));
        assert!(json_is_subset(&json!({"a":{"c":[{"d":3}]}}), &g));
        assert!(json_is_subset(&json!({"a":{"c":[2,1]}}), &g));
        assert!(!json_is_subset(&json!({"a":{"b":2}}), &g));
        assert!(!json_is_subset(&json!({"z":1}), &g));
        assert!(!json_is_subset(&json!({"a":{"c":[9]}}), &g));
        assert!(!json_is_subset(&json!({"f":["x"]}), &g));
    }

    /// A user-global Claude hook must reach the terminal beside csq's messaging hook:
    /// arrays under `hooks.<Event>` are concatenated, never replaced.
    #[test]
    fn materialize_handle_settings_keeps_global_hooks_beside_messaging_stop() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-2");
        std::fs::create_dir_all(&config).unwrap();
        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{"hooks":{
                "PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"global-pre"}]}],
                "Stop":[{"hooks":[{"type":"command","command":"global-stop"}]}]}}"#,
        )
        .unwrap();
        // The terminal was launched with messaging registered.
        let handle = base.join("term-88810");
        std::fs::create_dir_all(&handle).unwrap();
        let mut previous = serde_json::json!({});
        crate::messaging::register::apply_settings_layer(&mut previous, "csq").unwrap();
        std::fs::write(handle.join("settings.json"), previous.to_string()).unwrap();

        materialize_handle_settings(&handle, &claude_home, &config).unwrap();

        let out: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        let cmds = |ev: &str| -> Vec<String> {
            out["hooks"][ev]
                .as_array()
                .unwrap_or_else(|| panic!("hooks.{ev} missing in {out}"))
                .iter()
                .filter_map(|e| e.pointer("/hooks/0/command").and_then(|c| c.as_str()))
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(cmds("PreToolUse"), vec!["global-pre".to_owned()]);
        let stop = cmds("Stop");
        assert!(stop.contains(&"global-stop".to_owned()), "stop={stop:?}");
        assert!(
            stop.iter()
                .any(|c| c.ends_with("sessions inbox --messages --hook Stop")),
            "messaging Stop hook missing: {stop:?}"
        );
    }

    #[test]
    fn create_handle_dir_codex_populates_codex_symlink_set() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 2);

        let account = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 88888).unwrap();

        assert!(handle.exists());
        assert_eq!(handle.file_name().unwrap().to_str().unwrap(), "term-88888");

        #[cfg(unix)]
        {
            // Every Codex symlink in the set should land and resolve
            // to its spec-defined target.
            let auth = handle.join("auth.json");
            assert!(auth.symlink_metadata().unwrap().file_type().is_symlink());
            let target = std::fs::read_link(&auth).unwrap();
            assert!(
                target.ends_with("credentials/codex-2.json"),
                "auth.json target: {:?}",
                target
            );

            let csq_acc = handle.join(".csq-account");
            assert!(csq_acc.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(std::fs::read_link(&csq_acc)
                .unwrap()
                .ends_with("config-2/.csq-account"));

            let cfg = handle.join("config.toml");
            assert!(cfg.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(std::fs::read_link(&cfg)
                .unwrap()
                .ends_with("config-2/config.toml"));

            let sessions = handle.join("sessions");
            assert!(sessions
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            assert!(std::fs::read_link(&sessions)
                .unwrap()
                .ends_with("config-2/codex-sessions"));

            let hist = handle.join("history.jsonl");
            assert!(hist.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(std::fs::read_link(&hist)
                .unwrap()
                .ends_with("config-2/codex-history.jsonl"));
        }

        // Ephemeral per-terminal log dir is a real directory, not a symlink.
        let log = handle.join("log");
        assert!(log.is_dir());
        #[cfg(unix)]
        assert!(!log.symlink_metadata().unwrap().file_type().is_symlink());

        // .live-pid contains the supplied PID.
        let pid_str = std::fs::read_to_string(handle.join(".live-pid")).unwrap();
        assert_eq!(pid_str.trim(), "88888");
    }

    #[test]
    fn create_handle_dir_codex_does_not_materialize_settings_or_claude_json() {
        // Codex handle dirs MUST NOT carry settings.json or
        // .claude.json — those are Anthropic-specific (PR-C3a
        // docstring). Confirm they are absent after creation.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 3);

        let account = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 88889).unwrap();

        assert!(
            !handle.join("settings.json").exists(),
            "Codex handle dir must not carry settings.json"
        );
        assert!(
            !handle.join(".claude.json").exists(),
            "Codex handle dir must not carry .claude.json"
        );
        assert!(
            !handle.join(".credentials.json").exists(),
            "Codex handle dir must not carry Anthropic-shaped .credentials.json"
        );
    }

    /// End-to-end subprocess test: with `CODEX_HOME` pointing at the
    /// handle dir, a subprocess that reads `$CODEX_HOME/config.toml`
    /// sees the merged user-global content. This is the exact
    /// resolution chain Codex CLI walks at startup:
    /// `CODEX_HOME=<handle-dir>` → handle-dir's `config.toml` symlink →
    /// `config-<N>/config.toml` (merged via `write_config_toml`).
    ///
    /// Without this test, unit tests verified each link of the chain
    /// in isolation but nothing verified the chain end-to-end as the
    /// subprocess (Codex) experiences it. This is the test that
    /// closes the "did you actually test with subprocesses" gap from
    /// the 2026-05-15 user-reported codex sandbox bug.
    #[cfg(unix)]
    #[test]
    fn handle_dir_codex_subprocess_reads_merged_config_toml_end_to_end() {
        use crate::providers::codex::surface as codex_surface;
        use std::process::Command;

        // Acquire workspace-wide env lock (testing.md MUST Rule 6) so
        // CODEX_USER_CONFIG mutation is race-safe against concurrent
        // codex tests.
        let _shared = crate::platform::test_env::lock();

        // Install a fixture user-global with sandbox + approval policy
        // keys (the exact keys the 2026-05-15 bug reporter wanted
        // propagated).
        let user_global_dir = TempDir::new().unwrap();
        let user_global_path = user_global_dir.path().join("user-config.toml");
        std::fs::write(
            &user_global_path,
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        )
        .unwrap();
        let prev_env = std::env::var_os(codex_surface::USER_CONFIG_ENV_OVERRIDE);
        // SAFETY: shared env lock held; restored before test exits.
        unsafe {
            std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, &user_global_path);
        }

        let base_dir_tmp = TempDir::new().unwrap();
        let base = base_dir_tmp.path();
        let account_num = 14u16;
        let account = AccountNum::try_from(account_num).unwrap();

        // Provision the slot: credential file + write config-N/config.toml
        // via the production path (which merges user-global).
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join(format!("codex-{account_num}.json")),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","id_token":"it","account_id":"uuid"}}"#,
        )
        .unwrap();
        let config_dir = base.join(format!("config-{account_num}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join(".csq-account"), account_num.to_string()).unwrap();
        std::fs::create_dir_all(config_dir.join("codex-sessions")).unwrap();
        std::fs::write(config_dir.join("codex-history.jsonl"), "").unwrap();
        codex_surface::write_config_toml(base, account, Some("gpt-test-model")).unwrap();

        // Build the handle dir with the codex symlink set.
        let handle = create_handle_dir_codex(base, account, 88891).unwrap();

        // The exact subprocess shape `csq run` produces for Codex:
        // CODEX_HOME=<handle-dir>, env_clear() + stdlib allowlist
        // (rules/testing.md MUST Rule 4a). Use `sh -c 'cat ...'` —
        // does the same fopen+read chain Codex CLI does at startup
        // for its config.toml.
        let mut cmd = Command::new("sh");
        cmd.env_clear();
        for k in ["HOME", "PATH", "LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        cmd.env(codex_surface::HOME_ENV_VAR, &handle);
        cmd.args(["-c", "cat \"$CODEX_HOME/config.toml\""]);
        let output = cmd.output().expect("sh subprocess must spawn");

        // Restore env BEFORE any panic-able assertion so a test failure
        // doesn't poison concurrent tests' view of CODEX_USER_CONFIG.
        // SAFETY: shared env lock still held.
        unsafe {
            match prev_env {
                Some(v) => std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, v),
                None => std::env::remove_var(codex_surface::USER_CONFIG_ENV_OVERRIDE),
            }
        }

        assert!(
            output.status.success(),
            "sh `cat $CODEX_HOME/config.toml` must succeed; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let content = String::from_utf8(output.stdout).expect("config.toml is UTF-8");

        // csq-controlled baseline keys survive the merge.
        assert!(
            content.contains("cli_auth_credentials_store = \"file\""),
            "csq directive must reach the subprocess via $CODEX_HOME/config.toml; got:\n{content}"
        );
        assert!(
            content.contains("model = \"gpt-test-model\""),
            "csq-set model must reach the subprocess; got:\n{content}"
        );

        // The bug-fix invariant: user-global preferences propagate
        // end-to-end through CODEX_HOME → handle-dir symlink →
        // config-N/config.toml.
        assert!(
            content.contains("approval_policy = \"never\""),
            "user-global approval_policy MUST reach the subprocess; \
             this is the exact chain Codex CLI walks at startup. Got:\n{content}"
        );
        assert!(
            content.contains("sandbox_mode = \"danger-full-access\""),
            "user-global sandbox_mode MUST reach the subprocess. Got:\n{content}"
        );
    }

    #[test]
    fn create_handle_dir_codex_refuses_when_config_dir_missing() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();
        let result = create_handle_dir_codex(dir.path(), account, 1);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("config-5"),
                    "error must name the missing config dir: {reason}"
                );
                assert!(
                    reason.contains("login"),
                    "error must hint at `csq login ... --provider codex`: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing config-N, got: {other:?}"),
        }
    }

    #[test]
    fn create_handle_dir_codex_refuses_when_canonical_credential_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // Provision config-<N> but NOT the canonical credential file.
        let config = base.join("config-6");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "6").unwrap();
        std::fs::write(config.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml

        let account = AccountNum::try_from(6u16).unwrap();
        let result = create_handle_dir_codex(base, account, 1);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                // Post-M4-12: the error message names the canonical path check
                // ("neither UUID-keyed nor legacy path exists") and the recovery
                // action ("csq login N --provider codex"), not a specific filename.
                assert!(
                    reason.contains("csq login 6 --provider codex")
                        || reason.contains("codex-6.json"),
                    "error must name the missing canonical credential and/or recovery action: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing canonical, got: {other:?}"),
        }
    }

    #[test]
    fn create_handle_dir_codex_refuses_live_pid_collision() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 7);

        let account = AccountNum::try_from(7u16).unwrap();
        // Pre-create a handle dir (NOT our own pid's name, so the own-pid rule does
        // not apply) whose `.live-pid` names a live process (ours). The function must
        // refuse rather than clobber it.
        let live = std::process::id();
        let pid = 999_999_021u32;
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), live.to_string()).unwrap();

        let result = create_handle_dir_codex(base, account, pid);
        match result {
            Err(CredentialError::HandleDirBusy {
                marker, live_pid, ..
            }) => {
                assert_eq!(marker, ".live-pid");
                assert_eq!(live_pid, Some(live));
            }
            other => panic!("expected HandleDirBusy for live pid collision, got: {other:?}"),
        }
    }

    fn orphan_dir_with(base: &Path, pid: u32, live_pid: &str, cc_pid: Option<String>) -> PathBuf {
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), live_pid).unwrap();
        std::fs::write(handle.join("sentinel"), "keep").unwrap();
        if let Some(cc) = cc_pid {
            std::fs::write(handle.join(".live-cc-pid"), cc).unwrap();
        }
        handle
    }

    /// `.live-pid` dead but `.live-cc-pid` names a live NON-claude child (a
    /// codex child, or anything else): refuse and leave the dir untouched.
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_refuses_when_child_is_live() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 7);
        let account = AccountNum::try_from(7u16).unwrap();
        let mut child = crate::platform::process::spawn_foreign_test_process();
        let pid = 999_999_001u32;
        let handle = orphan_dir_with(base, pid, "999999002", Some(child.id().to_string()));
        let result = create_handle_dir_codex(base, account, pid);
        let _ = child.kill();
        let _ = child.wait();
        match result {
            Err(ref e @ CredentialError::HandleDirBusy { .. }) => {
                let reason = e.to_string();
                assert!(reason.contains(".live-cc-pid"), "{reason}");
                assert!(reason.contains("left untouched"), "{reason}");
                assert!(
                    reason.contains("a different process id and so a different directory"),
                    "{reason}"
                );
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        assert!(handle.join("sentinel").exists(), "dir must be untouched");
    }

    // --- warn-once ---

    #[test]
    fn first_sighting_is_true_once_and_bounded() {
        let seen = std::sync::Mutex::new(std::collections::HashSet::new());
        assert!(first_sighting(&seen, "k:term-1"));
        assert!(!first_sighting(&seen, "k:term-1"));
        assert!(first_sighting(&seen, "k:term-2"));
        for i in 0..(SKIP_WARN_CAP * 3) {
            first_sighting(&seen, &format!("k:flood-{i}"));
        }
        assert!(
            seen.lock().unwrap().len() <= SKIP_WARN_CAP,
            "set must stay bounded"
        );
    }

    #[test]
    fn repeated_sweeps_of_an_unreadable_marker_warn_once() {
        let base = TempDir::new().unwrap();
        // Unique name: the seen-set is process-global.
        let pid = 999_999_031u32;
        let handle = orphan_dir_with(base.path(), pid, "999999032", None);
        plant_unreadable(&handle.join(".live-cc-pid"), "oversized");
        let before = SKIP_WARNS_EMITTED.with(|c| c.get());
        for _ in 0..5 {
            assert_eq!(
                sweep_dead_handles_inner(base.path(), None, |_| Ok(false)),
                0
            );
        }
        let after = SKIP_WARNS_EMITTED.with(|c| c.get());
        assert_eq!(
            after - before,
            1,
            "five ticks over one dir must emit one warning"
        );
        assert!(handle.join("sentinel").exists());
    }

    // --- own-pid rule, with own_pid + liveness injected (no dependence on the real pid) ---

    const OWN: u32 = 4_242_001;
    const OTHER_LIVE: u32 = 4_242_002;
    const DEAD: u32 = 4_242_003;
    fn alive(pid: u32) -> bool {
        pid == OWN || pid == OTHER_LIVE
    }

    fn leftover(base: &Path, name: &str, live: Option<&str>, cc: Option<&str>) -> PathBuf {
        let h = base.join(name);
        std::fs::create_dir_all(&h).unwrap();
        if let Some(v) = live {
            std::fs::write(h.join(".live-pid"), v).unwrap();
        }
        if let Some(v) = cc {
            std::fs::write(h.join(".live-cc-pid"), v).unwrap();
        }
        h
    }

    fn verdict(h: &Path, name: &str) -> Result<Option<u32>, CredentialError> {
        refuse_if_existing_handle_dir_live_with(h, name, OWN, alive)
    }

    #[test]
    fn own_pid_dir_with_own_live_pid_marker_is_removable() {
        let t = TempDir::new().unwrap();
        let name = format!("term-{OWN}");
        let h = leftover(t.path(), &name, Some(&OWN.to_string()), None);
        assert_eq!(verdict(&h, &name).unwrap(), Some(OWN));
    }

    #[test]
    fn own_pid_dir_with_unreadable_live_pid_is_removable() {
        let t = TempDir::new().unwrap();
        let name = format!("term-{OWN}");
        let h = leftover(t.path(), &name, Some("not-a-pid"), None);
        assert_eq!(verdict(&h, &name).unwrap(), None);
    }

    #[test]
    fn own_pid_dir_with_other_live_pid_marker_refuses() {
        let t = TempDir::new().unwrap();
        let name = format!("term-{OWN}");
        let h = leftover(t.path(), &name, Some(&OTHER_LIVE.to_string()), None);
        match verdict(&h, &name) {
            Err(CredentialError::HandleDirBusy {
                marker, live_pid, ..
            }) => {
                assert_eq!((marker, live_pid), (".live-pid", Some(OTHER_LIVE)));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn own_pid_dir_with_live_other_cc_pid_refuses() {
        let t = TempDir::new().unwrap();
        let name = format!("term-{OWN}");
        let h = leftover(
            t.path(),
            &name,
            Some(&OWN.to_string()),
            Some(&OTHER_LIVE.to_string()),
        );
        match verdict(&h, &name) {
            Err(CredentialError::HandleDirBusy {
                marker, live_pid, ..
            }) => assert_eq!((marker, live_pid), (".live-cc-pid", Some(OTHER_LIVE))),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn own_pid_dir_with_unreadable_cc_pid_refuses() {
        let t = TempDir::new().unwrap();
        let name = format!("term-{OWN}");
        let h = leftover(t.path(), &name, Some(&OWN.to_string()), Some("garbage"));
        match verdict(&h, &name) {
            Err(CredentialError::HandleDirBusy {
                marker, live_pid, ..
            }) => assert_eq!((marker, live_pid), (".live-cc-pid", None)),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn own_pid_dir_with_own_or_dead_cc_pid_is_removable() {
        let t = TempDir::new().unwrap();
        let name = format!("term-{OWN}");
        let h = leftover(
            t.path(),
            &name,
            Some(&OWN.to_string()),
            Some(&OWN.to_string()),
        );
        assert!(verdict(&h, &name).is_ok(), "own pid in cc marker");
        std::fs::write(h.join(".live-cc-pid"), DEAD.to_string()).unwrap();
        assert!(verdict(&h, &name).is_ok(), "dead pid in cc marker");
    }

    #[test]
    fn non_own_dir_with_unreadable_marker_still_refuses() {
        for name in [
            format!("term-{DEAD}"),
            "interactive-capture-1-2".to_string(),
        ] {
            for (live, cc, want) in [
                (Some("garbage"), None, ".live-pid"),
                (Some(&*DEAD.to_string()), Some("garbage"), ".live-cc-pid"),
            ] {
                let t = TempDir::new().unwrap();
                let h = leftover(t.path(), &name, live, cc);
                match verdict(&h, &name) {
                    Err(CredentialError::HandleDirBusy {
                        marker, live_pid, ..
                    }) => assert_eq!((marker, live_pid), (want, None), "{name}"),
                    other => panic!("{name}: expected refusal, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn non_own_dir_naming_own_pid_in_marker_refuses() {
        // A daemon-owned capture dir whose marker names OUR pid is held by us: refuse.
        let t = TempDir::new().unwrap();
        let name = "interactive-capture-9-9";
        let h = leftover(t.path(), name, Some(&OWN.to_string()), None);
        assert!(matches!(
            verdict(&h, name),
            Err(CredentialError::HandleDirBusy {
                marker: ".live-pid",
                live_pid: Some(OWN),
                ..
            })
        ));
    }

    #[test]
    fn handle_dir_busy_message_names_marker_and_says_retry() {
        let m = crate::error::handle_dir_busy_message("term-7", ".live-cc-pid", None);
        assert!(
            m.contains("term-7") && m.contains(".live-cc-pid") && m.contains("Retry"),
            "{m}"
        );
        assert!(!m.contains('/'), "dir name only, never a path: {m}");
        let m = crate::error::handle_dir_busy_message("term-7", ".live-pid", Some(55));
        assert!(m.contains("PID 55") && m.contains("Retry"), "{m}");
    }

    /// End to end through the public entry: a leftover `term-<real own pid>` carrying an
    /// unreadable `.live-pid` is removed and recreated (the daemon-free launch path).
    #[test]
    fn create_handle_dir_codex_recreates_leftover_own_pid_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 7);
        let account = AccountNum::try_from(7u16).unwrap();
        let me = std::process::id();
        let handle = base.join(format!("term-{me}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), "garbage").unwrap();
        std::fs::write(handle.join("stale-sentinel"), "x").unwrap();
        let out = create_handle_dir_codex(base, account, me).unwrap();
        assert!(!out.join("stale-sentinel").exists(), "old dir must be gone");
        assert_eq!(markers::read_live_pid(&out), Some(me));
    }

    /// An unreadable marker (a directory; an oversized file) the destructive callers
    /// must treat as possibly live.
    fn plant_unreadable(path: &Path, kind: &str) {
        match kind {
            "dir" => std::fs::create_dir(path).unwrap(),
            _ => std::fs::write(path, "9".repeat(4096)).unwrap(),
        }
    }

    #[test]
    fn sweep_skips_handle_dir_with_unreadable_live_cc_pid() {
        for kind in ["dir", "oversized"] {
            let base = TempDir::new().unwrap();
            let pid = 999_999_011u32;
            let handle = orphan_dir_with(base.path(), pid, "999999012", None);
            plant_unreadable(&handle.join(".live-cc-pid"), kind);
            let mut cleared = 0;
            let removed = sweep_dead_handles_inner(base.path(), None, |_| {
                cleared += 1;
                Ok(false)
            });
            assert_eq!(removed, 0, "{kind}");
            assert_eq!(cleared, 0, "{kind}: keychain must not be touched");
            assert!(handle.join("sentinel").exists(), "{kind}: dir must survive");
        }
    }

    #[test]
    fn sweep_skips_handle_dir_with_unreadable_live_pid() {
        for kind in ["dir", "oversized"] {
            let base = TempDir::new().unwrap();
            let pid = 999_999_013u32;
            let handle = orphan_dir_with(base.path(), pid, "999999014", None);
            std::fs::remove_file(handle.join(".live-pid")).unwrap();
            plant_unreadable(&handle.join(".live-pid"), kind);
            let removed = sweep_dead_handles_inner(base.path(), None, |_| Ok(false));
            assert_eq!(removed, 0, "{kind}");
            assert!(handle.join("sentinel").exists(), "{kind}: dir must survive");
        }
    }

    /// Absent markers keep today's behaviour: a dead dir-name pid is still swept.
    #[test]
    fn sweep_still_removes_dead_dir_with_absent_markers() {
        let base = TempDir::new().unwrap();
        let handle = orphan_dir_with(base.path(), 999_999_015, "999999016", None);
        std::fs::remove_file(handle.join(".live-pid")).unwrap();
        let removed = sweep_dead_handles_inner(base.path(), None, |_| Ok(false));
        assert_eq!(removed, 1);
        assert!(!handle.exists());
    }

    #[test]
    fn create_handle_dir_refuses_and_keeps_dir_on_unreadable_markers() {
        for (marker, kind) in [
            (".live-cc-pid", "dir"),
            (".live-cc-pid", "oversized"),
            (".live-pid", "dir"),
            (".live-pid", "oversized"),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            setup_codex_slot(base, 7);
            let account = AccountNum::try_from(7u16).unwrap();
            let pid = 999_999_017u32;
            let handle = orphan_dir_with(base, pid, "999999018", None);
            if marker == ".live-pid" {
                std::fs::remove_file(handle.join(".live-pid")).unwrap();
            }
            plant_unreadable(&handle.join(marker), kind);
            let result = create_handle_dir_codex(base, account, pid);
            assert!(
                matches!(result, Err(CredentialError::HandleDirBusy { .. })),
                "{marker} {kind}: {result:?}"
            );
            assert!(handle.join("sentinel").exists(), "{marker} {kind}");
        }
    }

    #[test]
    fn create_handle_dir_anthropic_refuses_on_unreadable_live_cc_pid() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_config_dir(base, 7);
        let account = AccountNum::try_from(7u16).unwrap();
        let pid = 999_999_019u32;
        let handle = orphan_dir_with(base, pid, "999999020", None);
        plant_unreadable(&handle.join(".live-cc-pid"), "dir");
        let claude_home = dir.path().join("claude-home");
        let result = create_handle_dir(base, &claude_home, account, pid);
        assert!(
            matches!(result, Err(CredentialError::HandleDirBusy { .. })),
            "{result:?}"
        );
        assert!(handle.join("sentinel").exists());
    }

    /// Run `f` on a thread; fail if it does not return within 20 s (a FIFO read blocks).
    #[cfg(unix)]
    fn within_20s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(20))
            .expect("call blocked on a FIFO .live-pid")
    }

    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_live_pid_does_not_block_or_reap_capture_exec_and_create() {
        let base = TempDir::new().unwrap();
        let b = base.path().to_path_buf();
        let cap = b.join(format!("{CAPTURE_DIR_PREFIX}fifo-0"));
        std::fs::create_dir_all(&cap).unwrap();
        make_fifo(&cap.join(".live-pid"));
        let exe = b.join(format!("{EXEC_CODEX_DIR_PREFIX}999999021"));
        std::fs::create_dir_all(&exe).unwrap();
        make_fifo(&exe.join(".live-pid"));
        let (b2, cap2, exe2) = (b.clone(), cap.clone(), exe.clone());
        let removed = within_20s(move || {
            let n = sweep_stale_capture_dirs(&b2) + sweep_stale_exec_dirs(&b2);
            assert!(cap2.exists() && exe2.exists());
            n
        });
        assert_eq!(removed, 0);

        setup_codex_slot(&b, 7);
        let account = AccountNum::try_from(7u16).unwrap();
        let handle = b.join("term-999999022");
        std::fs::create_dir_all(&handle).unwrap();
        make_fifo(&handle.join(".live-pid"));
        let b3 = b.clone();
        let result = within_20s(move || create_handle_dir_codex(&b3, account, 999_999_022));
        assert!(
            matches!(result, Err(CredentialError::HandleDirBusy { .. })),
            "{result:?}"
        );
        assert!(handle.exists());
    }

    /// An unreadable marker must NOT fall back to reaping by directory age.
    // Unix only: setting a DIRECTORY's mtime needs `File::open(dir)`, which fails on Windows.
    #[cfg(unix)]
    #[test]
    fn sweep_capture_unreadable_marker_does_not_age_reap() {
        let base = TempDir::new().unwrap();
        let dir = make_capture_dir_unreadable(base.path());
        let f = std::fs::File::open(&dir).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
        assert!(
            dir_age_exceeds(&dir, CAPTURE_REAP_GRACE),
            "fixture must be old"
        );
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(dir.exists());
    }

    #[cfg(unix)]
    fn make_capture_dir_unreadable(base: &Path) -> PathBuf {
        let dir = base.join(format!("{CAPTURE_DIR_PREFIX}oversized-0"));
        std::fs::create_dir_all(&dir).unwrap();
        plant_unreadable(&dir.join(".live-pid"), "oversized");
        dir
    }

    #[test]
    fn create_handle_dir_proceeds_when_both_pids_dead() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 7);
        let account = AccountNum::try_from(7u16).unwrap();
        let pid = 999_999_004u32;
        orphan_dir_with(base, pid, "999999005", Some("999999006".to_string()));
        let result = create_handle_dir_codex(base, account, pid);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn create_handle_dir_codex_tolerates_missing_sessions_and_history() {
        // codex-sessions/ and codex-history.jsonl may be absent on first spawn.
        //
        // The function must not ERROR on that — but it must also not SKIP the link,
        // which is what it used to do. Skipping left codex-cli to create a real file
        // inside the handle dir, so an item on the share list still became
        // per-terminal state and died with the terminal. Measured on a maintainer
        // host 2026-08-19: `history.jsonl` was a real per-terminal file in every live
        // handle dir for exactly this reason. The target is now pre-created so the
        // share holds from the first spawn.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-8");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "8").unwrap();
        std::fs::write(config.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml
                                                                 // Deliberately DO NOT create codex-sessions/ or codex-history.jsonl.

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("codex-8.json"),
            r#"{"tokens":{"access_token":"at"}}"#,
        )
        .unwrap();

        let account = AccountNum::try_from(8u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 88880).expect("should succeed");

        assert!(handle.exists());
        // Required symlinks present:
        assert!(handle.join("auth.json").symlink_metadata().is_ok());
        assert!(handle.join("config.toml").symlink_metadata().is_ok());
        assert!(handle.join(".csq-account").symlink_metadata().is_ok());
        // Shared state is LINKED even though its target did not exist — the target
        // is created first. Asserting the symlink resolves INTO config-8 is the
        // discriminating check: a real file in the handle dir would satisfy
        // `.exists()` while being exactly the per-terminal state this prevents.
        for (item, target) in [
            ("sessions", config.join("codex-sessions")),
            ("history.jsonl", config.join("codex-history.jsonl")),
        ] {
            assert!(
                handle.join(item).symlink_metadata().is_ok(),
                "{item} must be linked, not skipped, when its target is absent"
            );
            assert_shared_storage(&handle.join(item), &target, item);
        }
        // log/ is always created fresh.
        assert!(handle.join("log").is_dir());
    }

    /// Assert `handle_item` and `config_target` are the SAME storage.
    ///
    /// Tests the PROPERTY (shared) rather than the MECHANISM (symlink), because the
    /// mechanism is platform-dependent and the property is not: `create_symlink`
    /// dispatches to a directory junction or a HARDLINK on Windows, and a hardlink is
    /// not a reparse point — `read_link` fails on it with os error 4390 even though the
    /// two paths share one inode and the state is correctly shared. Asserting
    /// `read_link` therefore FAILS ON WINDOWS for a tree behaving exactly right, which
    /// is what CI caught here.
    ///
    /// Writing through one side and reading through the other holds under a symlink, a
    /// junction and a hardlink alike, and is false for the per-terminal copy this
    /// guards against — which is the whole discrimination the test needs.
    fn assert_shared_storage(handle_item: &Path, config_target: &Path, label: &str) {
        if config_target.is_dir() {
            let probe = format!("{label}.probe");
            std::fs::write(config_target.join(&probe), b"shared").unwrap();
            let via_handle = handle_item.join(&probe);
            let seen = std::fs::read(&via_handle).unwrap_or_else(|e| {
                panic!(
                    "{label} must be shared: reading {} failed: {e}",
                    via_handle.display()
                )
            });
            assert_eq!(seen, b"shared", "{label} directory is not shared storage");
        } else {
            let marker = format!("shared-{label}").into_bytes();
            std::fs::write(config_target, &marker).unwrap();
            let seen = std::fs::read(handle_item).unwrap_or_else(|e| {
                panic!(
                    "{label} must be shared: reading {} failed: {e}",
                    handle_item.display()
                )
            });
            assert_eq!(
                seen, marker,
                "{label} is a per-terminal copy, not shared storage"
            );
        }
    }

    /// Regression: codex's schema-versioned sqlite metadata is SHARED, not per-terminal.
    ///
    /// codex-cli keeps conversation NAMES and recency in `state_<N>.sqlite`. That file
    /// was on no share list, so every terminal got its own — a thread named in one
    /// terminal read as unnamed in the next, and `/rename` was invisible everywhere
    /// else. Measured on a maintainer host 2026-08-19: three live handle dirs holding
    /// 35M + 35M + 7.1M of separate metadata while `sessions/` was correctly shared, so
    /// the conversations survived and only their names were lost.
    ///
    /// The version suffix is matched by PREFIX deliberately. Naming `state_5.sqlite`
    /// literally would stop matching at codex's next schema bump — silently, and
    /// reintroducing exactly this bug one version later. `state_9` below is a version
    /// this repo has never seen, which is the point: the assertion must not depend on
    /// the number.
    #[test]
    fn create_handle_dir_codex_shares_versioned_sqlite_state() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-9");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "9").unwrap();
        std::fs::write(config.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml
                                                                 // A schema version that does not exist today, and its sidecars.
        std::fs::write(config.join("state_9.sqlite"), b"db").unwrap();
        std::fs::write(config.join("state_9.sqlite-wal"), b"wal").unwrap();
        std::fs::write(config.join("logs_3.sqlite"), b"db").unwrap();

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("codex-9.json"),
            r#"{"tokens":{"access_token":"at"}}"#,
        )
        .unwrap();

        let account = AccountNum::try_from(9u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 99990).expect("should succeed");

        for item in ["state_9.sqlite", "logs_3.sqlite"] {
            assert_shared_storage(&handle.join(item), &config.join(item), item);
        }

        // The -wal/-shm sidecars are deliberately NOT linked: SQLite resolves the
        // symlink and places them beside the real database. Linking them would create
        // files the engine then has to reconcile against its own.
        assert!(
            handle
                .join("state_9.sqlite-wal")
                .symlink_metadata()
                .is_err(),
            "sidecars must not be linked; SQLite places them beside the resolved db"
        );
    }

    // ── PR-C9a CRITICAL belt-and-suspenders: repoint refuses Codex-shape ──

    /// Regression guard: an internal journal entry finding 1 belt-and-suspenders.
    ///
    /// `repoint_handle_dir` is the ClaudeCode repoint path. It touches
    /// `ACCOUNT_BOUND_ITEMS` (`.credentials.json`, `.csq-account`,
    /// `.current-account`, `.quota-cursor`) only — if called on a Codex
    /// handle dir it would rewrite those Anthropic-shape markers while
    /// leaving the real Codex symlinks (`auth.json`, `config.toml`,
    /// `sessions`, `history.jsonl` per spec 07 §7.2.2) pointing at the
    /// old `config-<N>`. The primary guard lives in
    /// `auto_rotate::find_target`, but this secondary refusal catches
    /// any caller that forgets the surface check.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_refuses_codex_shape_handle_dir() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
        use crate::types::AccountNum;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        let base = dir.path();

        // Codex slot 5 with canonical credentials + config.toml.
        let codex_account = AccountNum::try_from(5u16).unwrap();
        let codex_creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("uuid-5".into()),
                access_token: "eyJaccess.codex-5.sig".into(),
                refresh_token: Some("rt_codex_5".into()),
                id_token: Some("eyJid.codex-5.sig".into()),
                extra: std::collections::HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: std::collections::HashMap::new(),
        });
        crate::credentials::save(&base.join("credentials").join("codex-5.json"), &codex_creds)
            .unwrap();
        let codex_config = base.join("config-5");
        std::fs::create_dir_all(&codex_config).unwrap();
        markers::write_csq_account_legacy(&codex_config, codex_account).unwrap();
        std::fs::write(
            codex_config.join("config.toml"),
            "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-5.4\"\n",
        )
        .unwrap();

        // A plausible ClaudeCode target dir (doesn't matter whether it's
        // valid; the guard refuses before new_config is inspected).
        let target_config = base.join("config-1");
        std::fs::create_dir_all(&target_config).unwrap();
        let target_account = AccountNum::try_from(1u16).unwrap();
        markers::write_csq_account_legacy(&target_config, target_account).unwrap();

        // Create a Codex handle dir.
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir_codex(base, codex_account, 70001).unwrap();

        // Precondition: handle dir has Codex-shape symlinks.
        assert!(
            handle.join("auth.json").symlink_metadata().is_ok(),
            "test precondition: auth.json symlink exists"
        );
        assert!(
            handle.join("config.toml").symlink_metadata().is_ok(),
            "test precondition: config.toml symlink exists"
        );

        // Act: attempt to repoint to target slot 1.
        let result = repoint_verified_fixture(base, claude_home.path(), &handle, target_account);

        // Assert: refused with a clear error.
        assert!(
            result.is_err(),
            "repoint_handle_dir MUST refuse a Codex-shape handle dir"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("Codex-unique")
                || err_msg.contains("auth.json")
                || err_msg.contains("config.toml"),
            "error must name the Codex-unique item that triggered the refusal: {err_msg}"
        );

        // Assert: Codex symlinks are intact (the guard refused without
        // touching anything).
        assert!(
            handle.join("auth.json").symlink_metadata().is_ok(),
            "auth.json symlink must survive the refused repoint"
        );
        assert!(
            handle.join("config.toml").symlink_metadata().is_ok(),
            "config.toml symlink must survive the refused repoint"
        );
    }

    // ── repoint_handle_dir_codex (M10 / an internal journal entry) ──────────────────

    /// Happy path: repointing a Codex handle dir from slot A → slot B
    /// rewrites the ACCOUNT-IDENTITY Codex symlinks (`.csq-account`,
    /// `auth.json`, `config.toml`) to the new slot atomically. The
    /// persistent conversation-state symlinks (`sessions`,
    /// `history.jsonl`) are DELIBERATELY LEFT pointed at the source slot
    /// — see the C1 fix rationale on `repoint_handle_dir_codex` and
    /// `repoint_handle_dir_codex_in_flight_does_not_split_live_conversation_across_accounts`.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_repoints_codex_symlinks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Provision two Codex slots.
        setup_codex_slot(base, 4);
        setup_codex_slot(base, 9);

        // Create the handle dir bound to slot 4.
        let from = AccountNum::try_from(4u16).unwrap();
        let to = AccountNum::try_from(9u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70010).unwrap();

        // Precondition: handle dir is bound to slot 4.
        assert!(std::fs::read_link(handle.join("auth.json"))
            .unwrap()
            .ends_with("credentials/codex-4.json"));
        assert!(std::fs::read_link(handle.join("config.toml"))
            .unwrap()
            .ends_with("config-4/config.toml"));

        // Act: repoint to slot 9.
        repoint_handle_dir_codex(base, &handle, to).expect("repoint must succeed");

        // Assert: the account-identity symlinks now point at slot 9.
        assert!(std::fs::read_link(handle.join(".csq-account"))
            .unwrap()
            .ends_with("config-9/.csq-account"));
        assert!(std::fs::read_link(handle.join("auth.json"))
            .unwrap()
            .ends_with("credentials/codex-9.json"));
        assert!(std::fs::read_link(handle.join("config.toml"))
            .unwrap()
            .ends_with("config-9/config.toml"));

        // Assert: the persistent conversation-state symlinks (C1) are NOT
        // repointed — they stay bound to the SOURCE slot for the remaining
        // life of the process that already has them open.
        assert!(
            std::fs::read_link(handle.join("sessions"))
                .unwrap()
                .ends_with("config-4/codex-sessions"),
            "C1: sessions/ must stay on the source slot across an in-flight repoint"
        );
        assert!(
            std::fs::read_link(handle.join("history.jsonl"))
                .unwrap()
                .ends_with("config-4/codex-history.jsonl"),
            "C1: history.jsonl must stay on the source slot across an in-flight repoint"
        );

        // No exec-replace happened: the handle dir survives in-place.
        assert!(
            handle.exists(),
            "handle dir must remain after in-flight repoint"
        );
        // No tombstone was created (the cross-surface path's signature).
        let tombstone_count = std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-")
            })
            .count();
        assert_eq!(
            tombstone_count, 0,
            "same-surface Codex repoint MUST NOT create a sweep tombstone (M10)"
        );
    }

    /// C1 regression (cross-account codex session bleed — never diagnosed until
    /// this test). `repoint_handle_dir_codex` is invoked ONLY by the same-surface
    /// in-flight adopt path (`same_surface_codex`, reached when both slots'
    /// Codex `tokens.account_id` MATCH) — the handle dir's owning PID is left
    /// untouched; no process is exec-replaced, no tombstone is created. Unlike
    /// ClaudeCode's `.claude.json` (a REAL file explicitly re-merged at swap
    /// time via `build_scoped_claude_json`'s `preserve_handle` parameter),
    /// Codex's persistent conversation state (`sessions`, `history.jsonl`,
    /// `session_index.jsonl`, schema-versioned sqlite state) are raw symlinks
    /// into `config-<N>` with NO reconciliation step. Repointing them mid-flight
    /// lets a SINGLE in-progress conversation split across TWO `config-<N>`
    /// directories: any write the still-running process makes by re-opening a
    /// path (rather than through an fd that predates the repoint) lands under
    /// the NEW slot, silently carrying that thread's continuation into a
    /// directory the swap target never asked to inherit mid-conversation state
    /// from — "an account-A codex thread's history promotes into account-B's
    /// config-<N>".
    ///
    /// This test simulates the still-running process by writing to
    /// `history.jsonl` THROUGH THE HANDLE DIR both before and after the
    /// repoint — the shape a live process's path-based reopen takes (`open`,
    /// `append`, `close`, as opposed to holding one fd for its entire life).
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_in_flight_does_not_split_live_conversation_across_accounts() {
        use std::io::Write;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        setup_codex_slot(base, 4);
        setup_codex_slot(base, 9);

        let from = AccountNum::try_from(4u16).unwrap();
        let to = AccountNum::try_from(9u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70050).unwrap();

        // Turn 1 of an in-progress conversation, written THROUGH the handle dir
        // BEFORE the swap — resolves via the pre-swap symlink to
        // config-4/codex-history.jsonl.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(handle.join("history.jsonl"))
                .unwrap();
            writeln!(
                f,
                r#"{{"session_id":"thread-1","ts":1,"text":"turn 1 (account 4)"}}"#
            )
            .unwrap();
        }

        // Act: in-flight repoint to slot 9 — same_surface_codex's operation.
        repoint_handle_dir_codex(base, &handle, to).expect("repoint must succeed");
        assert_eq!(
            std::fs::read_to_string(handle.join(".live-pid"))
                .unwrap()
                .trim(),
            "70050",
            "precondition: this is an IN-FLIGHT repoint — the owning process \
             never restarted"
        );

        // Turn 2 of the SAME conversation: the still-running process appends
        // the next turn by re-opening history.jsonl BY PATH through the handle
        // dir, exactly as a small JSONL log is commonly updated.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(handle.join("history.jsonl"))
                .unwrap();
            writeln!(
                f,
                r#"{{"session_id":"thread-1","ts":2,"text":"turn 2 (still account 4's thread)"}}"#
            )
            .unwrap();
        }

        // Assert: BOTH turns of thread-1 stay under the SOURCE slot (4) — an
        // in-flight repoint must not let one conversation's continuation land
        // in the TARGET slot's (9) persistent store.
        let slot4_history =
            std::fs::read_to_string(base.join("config-4").join("codex-history.jsonl")).unwrap();
        assert!(
            slot4_history.contains("turn 1") && slot4_history.contains("turn 2"),
            "both turns of the in-flight conversation must stay on the source \
             slot (config-4); got:\n{slot4_history}"
        );

        let slot9_history =
            std::fs::read_to_string(base.join("config-9").join("codex-history.jsonl")).unwrap();
        assert!(
            !slot9_history.contains("turn 1") && !slot9_history.contains("turn 2"),
            "the target slot (config-9) must NOT receive any part of a \
             conversation that was already in progress when the in-flight swap \
             happened; got:\n{slot9_history}"
        );
    }

    /// Surface guard: a ClaudeCode-shape handle dir (no `auth.json`
    /// symlink) must be refused with a clear error. Symmetry with the
    /// existing `repoint_handle_dir_refuses_codex_shape_handle_dir`
    /// guard for the inverse direction.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_non_codex_handle_dir() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        let base = dir.path();

        // Provision a ClaudeCode slot and target Codex slot.
        setup_config_dir(base, 1);
        setup_codex_slot(base, 2);

        // Create a ClaudeCode handle dir.
        let cc_account = AccountNum::try_from(1u16).unwrap();
        let codex_account = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), cc_account, 70011).unwrap();

        // Precondition: handle dir has NO auth.json (ClaudeCode shape).
        assert!(handle.join("auth.json").symlink_metadata().is_err());

        // Act: attempt Codex repoint on ClaudeCode handle dir.
        let result = repoint_handle_dir_codex(base, &handle, codex_account);

        // Assert: refused with a clear error naming the missing marker.
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("auth.json") || reason.contains("Codex-shaped"),
                    "error must name the missing Codex marker: {reason}"
                );
            }
            other => panic!("expected Corrupt for non-Codex handle dir, got: {other:?}"),
        }
    }

    /// Refuses non-`term-<pid>` source paths (legacy `config-N` or
    /// arbitrary dirs). Codex never had a pre-handle-dir layout, so a
    /// non-`term-` source is always a misuse.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_non_handle_dir_source() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 5);

        // A `config-N` directory is not a handle dir.
        let bogus = base.join("config-5");
        let target = AccountNum::try_from(5u16).unwrap();

        let result = repoint_handle_dir_codex(base, &bogus, target);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("term-"),
                    "error must mention the required term-<pid> shape: {reason}"
                );
            }
            other => panic!("expected Corrupt for non-handle source, got: {other:?}"),
        }
    }

    /// Regression (2026-09-12): a Codex slot provisioned on a CURRENT build has
    /// `identities/<UUID>/credentials-codex.json` and NO legacy
    /// `credentials/codex-<N>.json`. The repoint precondition used to hard-require
    /// the legacy mirror, so `csq swap <N>` refused such a slot with "has not
    /// completed login" while the daemon polled it successfully — the reader was
    /// narrower than its writers (`guard-reader-writer-parity.md` MUST-1/MUST-5).
    /// REDs if that guard is narrowed back to `canonical_cred.exists()`.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_accepts_identity_keyed_credential_without_legacy_mirror() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        setup_codex_slot(base, 6);
        setup_codex_slot(base, 7);

        // Make slot 7 look like a post-M4-12 slot: identity-keyed credential
        // present, legacy mirror gone.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(7);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert("7".to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let id_cred = crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(id_cred.parent().unwrap()).unwrap();
        std::fs::write(
            &id_cred,
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","id_token":"it","account_id":"uuid"}}"#,
        )
        .unwrap();
        std::fs::remove_file(base.join("credentials").join("codex-7.json")).unwrap();

        let from = AccountNum::try_from(6u16).unwrap();
        let to = AccountNum::try_from(7u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70013).unwrap();

        repoint_handle_dir_codex(base, &handle, to).expect(
            "a slot with an identity-keyed codex credential and no legacy mirror \
                     MUST be swappable — this is the shape every current login produces",
        );

        // auth.json must resolve to the identity-keyed credential, not a dangling
        // legacy path.
        let auth = handle.join("auth.json");
        let resolved = std::fs::read_link(&auth).unwrap_or_else(|_| auth.clone());
        assert!(
            resolved.ends_with("credentials-codex.json"),
            "auth.json must point at the identity-keyed credential, got: {}",
            resolved.display()
        );
    }

    /// Refuses repointing when the canonical credential file for the
    /// target slot is missing (login has not completed). Without the
    /// canonical file, `auth.json` would symlink to a dangling path
    /// and codex-cli would fail on the next API call.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_canonical_credential_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Source slot 6 fully provisioned.
        setup_codex_slot(base, 6);
        // Target slot 7: provision config-7 + .csq-account but DELETE the
        // canonical credential file.
        setup_codex_slot(base, 7);
        std::fs::remove_file(base.join("credentials").join("codex-7.json")).unwrap();

        let from = AccountNum::try_from(6u16).unwrap();
        let to = AccountNum::try_from(7u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70012).unwrap();

        let result = repoint_handle_dir_codex(base, &handle, to);
        match result {
            Err(CredentialError::Corrupt { reason, path }) => {
                // No by_slot mapping in this fixture, so the error names the
                // legacy path. Assert on the STRUCTURED field, not prose.
                assert!(
                    path.ends_with("codex-7.json"),
                    "error must name the credential path it checked: {}",
                    path.display()
                );
                assert!(
                    reason.contains("has not completed login"),
                    "reason must tell the operator what to do: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing canonical, got: {other:?}"),
        }

        // Source symlinks must be untouched (refusal happens pre-flight).
        assert!(std::fs::read_link(handle.join("auth.json"))
            .unwrap()
            .ends_with("credentials/codex-6.json"));
    }

    /// Refuses repointing when the target slot is missing the
    /// `.csq-account` marker. Without it the daemon's auto-rotate /
    /// sweep loops cannot identify the account post-swap. Mirrors the
    /// VP-final F3 guard on the ClaudeCode path.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_target_missing_csq_account() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        setup_codex_slot(base, 11);
        setup_codex_slot(base, 12);
        // Strip .csq-account from target slot 12.
        std::fs::remove_file(base.join("config-12").join(".csq-account")).unwrap();

        let from = AccountNum::try_from(11u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70013).unwrap();

        let result = repoint_handle_dir_codex(base, &handle, to);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains(".csq-account"),
                    "error must name the missing marker: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing marker, got: {other:?}"),
        }
    }

    // ── PR-C9b round 2 fixes ──────────────────────────────────────────

    /// M-CDX-1 regression: the credential symlink (`auth.json`) MUST be
    /// rewritten BEFORE the marker (`.csq-account`) inside the rename
    /// loop. Otherwise a mid-loop I/O failure could flip the marker to
    /// the new slot while `auth.json` still resolved to the old slot's
    /// tokens — silent quota-attribution drift in the daemon plus a
    /// trip on the F3 mismatch guard at the next swap. This test pins
    /// the static `codex_links` slice ordering by introspecting the
    /// post-repoint mtime relationship — the file with the LATER mtime
    /// was written last, so we assert `.csq-account` mtime ≥ `auth.json`
    /// mtime (NEVER the inverse).
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_writes_credential_before_marker() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 21);
        setup_codex_slot(base, 22);

        let from = AccountNum::try_from(21u16).unwrap();
        let to = AccountNum::try_from(22u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70021).unwrap();

        // Sleep enough to make sub-nanosecond mtime ordering observable
        // even on filesystems with coarse mtime resolution (e.g. HFS+
        // 1s; APFS 1ns; ext4 1ns; some tempfs 1us).
        std::thread::sleep(std::time::Duration::from_millis(20));
        repoint_handle_dir_codex(base, &handle, to).unwrap();

        let auth_meta = std::fs::symlink_metadata(handle.join("auth.json")).unwrap();
        let marker_meta = std::fs::symlink_metadata(handle.join(".csq-account")).unwrap();

        // Ordering invariant: marker is written AT OR AFTER credential.
        // Use ctime (inode-change time, reflects the rename) for the
        // strictest check; mtime is the symlink's own mtime which
        // matches ctime under rename-replace semantics.
        let auth_ctime = (auth_meta.ctime(), auth_meta.ctime_nsec());
        let marker_ctime = (marker_meta.ctime(), marker_meta.ctime_nsec());
        assert!(
            marker_ctime >= auth_ctime,
            "M-CDX-1: .csq-account ctime ({:?}) must be >= auth.json ctime ({:?}) — \
             credential must be written before marker so a mid-loop failure cannot \
             leave the marker pointing at a slot whose credential is still the old one",
            marker_ctime,
            auth_ctime,
        );
    }

    /// L-CDX-1 regression: the surface guard MUST refuse a handle dir
    /// where `auth.json` is a regular file (not a symlink). The pre-fix
    /// guard accepted any `symlink_metadata().is_ok()` entry, which
    /// would let a planted file slip past and trigger the rename loop
    /// to overwrite attacker-controlled state.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_auth_json_is_regular_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 31);
        setup_codex_slot(base, 32);

        // Build a handle dir manually with `auth.json` as a regular file
        // and `config.toml` as a regular file too — both Codex-unique
        // markers present but neither is a symlink.
        let handle = base.join("term-70031");
        std::fs::create_dir(&handle).unwrap();
        std::fs::write(handle.join("auth.json"), b"planted, not a symlink").unwrap();
        std::fs::write(handle.join("config.toml"), b"planted, not a symlink").unwrap(); // CI-ALLOW-fs-write-config-toml

        let to = AccountNum::try_from(32u16).unwrap();
        let result = repoint_handle_dir_codex(base, &handle, to);

        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("not a symlink") || reason.contains("Codex-shaped"),
                    "L-CDX-1: error must name the non-symlink marker: {reason}"
                );
            }
            other => panic!("expected Corrupt for regular-file marker, got: {other:?}"),
        }

        // Planted files MUST still exist — guard refused before any rename.
        assert_eq!(
            std::fs::read(handle.join("auth.json")).unwrap(),
            b"planted, not a symlink",
            "guard must refuse before touching the planted file"
        );
    }

    /// L-CDX-1 regression: the dual-marker check requires BOTH
    /// `auth.json` AND `config.toml`. A handle dir with only `auth.json`
    /// (corrupted partial-create) MUST be refused.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_config_toml_symlink_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 41);
        setup_codex_slot(base, 42);

        let from = AccountNum::try_from(41u16).unwrap();
        let to = AccountNum::try_from(42u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70041).unwrap();

        // Strip the `config.toml` symlink to simulate a corrupted handle dir.
        std::fs::remove_file(handle.join("config.toml")).unwrap();

        let result = repoint_handle_dir_codex(base, &handle, to);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("config.toml"),
                    "L-CDX-1: error must name the missing config.toml: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing config.toml, got: {other:?}"),
        }
    }

    /// Materialize `global` (user settings.json text, if any) over a fresh handle dir and
    /// return the merged `settings.json`.
    fn materialize_with_global(global: Option<&str>) -> Value {
        let dir = TempDir::new().unwrap();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        if let Some(g) = global {
            std::fs::write(claude_home.join("settings.json"), g).unwrap();
        }
        let config_dir = dir.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        let handle_dir = dir.path().join("term-99002");
        std::fs::create_dir_all(&handle_dir).unwrap();
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();
        // A second materialization is the swap / auto-rotate re-merge path.
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();
        serde_json::from_str(&std::fs::read_to_string(handle_dir.join("settings.json")).unwrap())
            .unwrap()
    }

    #[test]
    fn fresh_handle_settings_disable_connectors_and_never_invent_a_cache_ttl() {
        let merged = materialize_with_global(None);
        assert!(
            merged.get("subagentPromptCacheTtl").is_none(),
            "absent stays absent"
        );
        assert_eq!(merged["disableClaudeAiConnectors"], true);
    }

    #[test]
    fn a_user_cache_ttl_passes_through_unchanged() {
        for user in [r#""5m""#, r#""1h""#, r#""bogus""#, "5"] {
            let merged =
                materialize_with_global(Some(&format!(r#"{{"subagentPromptCacheTtl":{user}}}"#)));
            let want: Value = serde_json::from_str(user).unwrap();
            assert_eq!(merged["subagentPromptCacheTtl"], want, "user value {user}");
        }
    }

    #[test]
    fn connectors_default_true_only_when_absent_and_an_explicit_false_passes_through() {
        let merged = materialize_with_global(Some(r#"{"disableClaudeAiConnectors":false}"#));
        assert_eq!(merged["disableClaudeAiConnectors"], false);
        let merged = materialize_with_global(Some(r#"{"disableClaudeAiConnectors":true}"#));
        assert_eq!(merged["disableClaudeAiConnectors"], true);
        assert_eq!(
            materialize_with_global(None)["disableClaudeAiConnectors"],
            true
        );
    }

    #[test]
    fn previous_handle_preferences_survive_a_remerge_but_env_and_routing_never_do() {
        let dir = TempDir::new().unwrap();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let config_dir = dir.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        let handle_dir = dir.path().join("term-99003");
        std::fs::create_dir_all(&handle_dir).unwrap();
        // A first materialization writes the layer record; the file is then edited in-session.
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();
        std::fs::write(
            handle_dir.join("settings.json"),
            r#"{"subagentPromptCacheTtl":"5m","env":{"ANTHROPIC_AUTH_TOKEN":"old"},"apiKeyHelper":"x","model":"m"}"#,
        )
        .unwrap();
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();
        let merged: Value = serde_json::from_str(
            &std::fs::read_to_string(handle_dir.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(merged["subagentPromptCacheTtl"], "5m");
        for k in ["env", "apiKeyHelper", "model"] {
            assert!(merged.get(k).is_none(), "{k} must not be carried: {merged}");
        }
        // An explicit global value is newer than the stale handle copy.
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{"subagentPromptCacheTtl":"1h"}"#,
        )
        .unwrap();
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();
        let merged: Value = serde_json::from_str(
            &std::fs::read_to_string(handle_dir.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(merged["subagentPromptCacheTtl"], "1h");
    }

    /// Fixture for the carry-over tests: a claude home, two slot config dirs and a handle dir.
    fn carry_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let dir = TempDir::new().unwrap();
        let claude_home = dir.path().join(".claude");
        let a = dir.path().join("config-1");
        let b = dir.path().join("config-2");
        let handle = dir.path().join("term-99004");
        for d in [&claude_home, &a, &b, &handle] {
            std::fs::create_dir_all(d).unwrap();
        }
        (dir, claude_home, a, b, handle)
    }

    fn handle_ttl(handle: &Path) -> Option<Value> {
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        v.get("subagentPromptCacheTtl").cloned()
    }

    #[test]
    fn a_pre_sidecar_handle_file_carries_nothing_so_slot_a_never_reaches_slot_b() {
        let (_d, home, a, b, handle) = carry_fixture();
        // A handle file from before the layer record existed: it holds slot A's overlay value
        // and there is NO `.csq-layer-prefs.json`, so nothing is attributable to Claude Code.
        std::fs::write(
            a.join("settings.json"),
            r#"{"subagentPromptCacheTtl":"5m"}"#,
        )
        .unwrap();
        std::fs::write(
            handle.join("settings.json"),
            r#"{"subagentPromptCacheTtl":"5m","disableClaudeAiConnectors":false}"#,
        )
        .unwrap();
        assert!(!handle.join(LAYER_RECORD_FILE).exists());
        materialize_handle_settings(&handle, &home, &b).unwrap();
        assert_eq!(
            handle_ttl(&handle),
            None,
            "no record: nothing crosses to slot B"
        );
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(
            v["disableClaudeAiConnectors"], true,
            "reset once to csq's default"
        );
    }

    #[test]
    fn a_preference_removed_from_global_does_not_persist_in_the_handle() {
        let (_d, home, a, _b, handle) = carry_fixture();
        std::fs::write(
            home.join("settings.json"),
            r#"{"subagentPromptCacheTtl":"1h"}"#,
        )
        .unwrap();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        assert_eq!(handle_ttl(&handle), Some(Value::from("1h")));
        std::fs::write(home.join("settings.json"), "{}").unwrap();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        assert_eq!(
            handle_ttl(&handle),
            None,
            "a layer-supplied value follows its layer"
        );
    }

    #[test]
    fn slot_a_overlay_preference_does_not_reach_slot_b_after_a_swap() {
        let (_d, home, a, b, handle) = carry_fixture();
        std::fs::write(
            a.join("settings.json"),
            r#"{"subagentPromptCacheTtl":"5m"}"#,
        )
        .unwrap();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        assert_eq!(handle_ttl(&handle), Some(Value::from("5m")));
        materialize_handle_settings(&handle, &home, &b).unwrap();
        assert_eq!(
            handle_ttl(&handle),
            None,
            "slot A's value must not cross to slot B"
        );
    }

    #[test]
    fn a_claude_code_written_preference_survives_repeated_remerges_and_swaps() {
        let (_d, home, a, b, handle) = carry_fixture();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        // Claude Code (`/config`) writes the key into the handle file mid-session.
        let mut v: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        v["subagentPromptCacheTtl"] = Value::from("1h");
        std::fs::write(handle.join("settings.json"), v.to_string()).unwrap();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        assert_eq!(handle_ttl(&handle), Some(Value::from("1h")));
        materialize_handle_settings(&handle, &home, &b).unwrap();
        assert_eq!(
            handle_ttl(&handle),
            Some(Value::from("1h")),
            "still CC's after a swap"
        );
    }

    #[test]
    fn a_claude_code_connectors_choice_survives_a_remerge_and_the_record_is_private() {
        let (_d, home, a, _b, handle) = carry_fixture();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        let mut v: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(v["disableClaudeAiConnectors"], true);
        v["disableClaudeAiConnectors"] = Value::Bool(false);
        std::fs::write(handle.join("settings.json"), v.to_string()).unwrap();
        materialize_handle_settings(&handle, &home, &a).unwrap();
        let after: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(after["disableClaudeAiConnectors"], false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(handle.join(LAYER_RECORD_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// §5a regression — site 4 (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `materialize_handle_settings`
    /// fails after the tmp file would have been created (handle dir
    /// read-only → write fails), no `.tmp.` file must remain.
    ///
    /// The merged settings.json in the handle dir may carry an
    /// ANTHROPIC_AUTH_TOKEN copied from the slot's `config-<N>/settings.json`.
    #[cfg(unix)]
    #[test]
    fn materialize_handle_settings_partial_failure_cleans_tmp_file() {
        use crate::platform::fs::assert_no_tmp_leak_on_readonly_parent;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Precursor: a config dir with settings.json carrying a token.
        let config_dir = base.join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-secret-token"}}"#,
        )
        .unwrap();

        // A handle dir where the write will succeed initially, then fail.
        let handle_dir = base.join("term-99001");
        std::fs::create_dir_all(&handle_dir).unwrap();

        // Verify the happy path works first (dir is writable).
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();

        // Act + Assert: read-only handle_dir → write fails → no tmp leak.
        assert_no_tmp_leak_on_readonly_parent(&handle_dir, || {
            materialize_handle_settings(&handle_dir, &claude_home, &config_dir)
        });
    }

    /// Spec 32 §6 / INV-32-07: a re-materialization (the swap path) keeps a terminal's
    /// messaging registration when its previous settings carried one, adds none when it did
    /// not, and never writes the user-global settings.
    #[test]
    fn rematerialization_carries_the_messaging_registration_only_when_present() {
        use crate::messaging::register;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let user = claude_home.join("settings.json");
        std::fs::write(
            &user,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"user-stop"}]}]}}"#,
        )
        .unwrap();
        let user_before = std::fs::read(&user).unwrap();
        let config_dir = base.join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();

        // Registered terminal: swap re-merge keeps csq's hooks beside the user's own.
        let reg = base.join("term-1");
        std::fs::create_dir_all(&reg).unwrap();
        materialize_handle_settings(&reg, &claude_home, &config_dir).unwrap();
        register::register_handle_settings(&reg, "/bin/csq").unwrap();
        materialize_handle_settings(&reg, &claude_home, &config_dir).unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(reg.join("settings.json")).unwrap())
                .unwrap();
        assert!(register::has_registration(&v), "{v}");
        assert_eq!(
            v["hooks"]["Stop"].as_array().unwrap().len(),
            2,
            "user hook + csq hook: {v}"
        );
        assert_eq!(
            v["permissions"]["allow"].as_array().unwrap().len(),
            register::ALLOW_ENTRIES.len()
        );

        // Unregistered terminal (messaging off): the re-merge adds nothing.
        let plain = base.join("term-2");
        std::fs::create_dir_all(&plain).unwrap();
        materialize_handle_settings(&plain, &claude_home, &config_dir).unwrap();
        materialize_handle_settings(&plain, &claude_home, &config_dir).unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(plain.join("settings.json")).unwrap())
                .unwrap();
        assert!(!register::has_registration(&v), "{v}");
        assert!(v.get("permissions").is_none());

        assert_eq!(
            std::fs::read(&user).unwrap(),
            user_before,
            "user-global settings untouched"
        );
    }

    /// M1: a terminal launched with messaging OFF stays off through the Claude to Claude
    /// re-materialization, even when its previous settings carry csq hooks. Falsifier: the old
    /// registration-only test registered such a terminal on the next swap.
    #[test]
    fn rematerialization_obeys_the_launch_decision_marker() {
        use crate::messaging::register;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), "{}").unwrap();
        let config_dir = base.join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        let hd = base.join("term-3");
        std::fs::create_dir_all(&hd).unwrap();
        materialize_handle_settings(&hd, &claude_home, &config_dir).unwrap();
        register::register_handle_settings(&hd, "/bin/csq").unwrap();
        register::record_decision(&hd, false).unwrap();
        materialize_handle_settings(&hd, &claude_home, &config_dir).unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(hd.join("settings.json")).unwrap())
                .unwrap();
        assert!(
            !register::has_registration(&v),
            "off at launch, off after swap: {v}"
        );
    }

    /// §5a regression — site 5 (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `rebuild_claude_json_for_swap`
    /// fails after the tmp file would have been created (handle dir
    /// read-only → write fails), no `.tmp.` file must remain.
    ///
    /// `.claude.json` in the handle dir carries CC session metadata
    /// (oauthAccount, GrowthBook flags); partial-failure must not leave
    /// it at umask 0o644.
    #[cfg(unix)]
    #[test]
    fn rebuild_claude_json_for_swap_partial_failure_cleans_tmp_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // A config dir with a valid .claude.json (source for the swap).
        let config_dir = base.join("config-2");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"b2@example.com","accountUuid":"u-2"}}"#,
        )
        .unwrap();

        // A handle dir with an existing .claude.json (preserved during swap).
        let handle_dir = base.join("term-99002");
        std::fs::create_dir_all(&handle_dir).unwrap();
        std::fs::write(handle_dir.join(".claude.json"), r#"{}"#).unwrap();

        // Verify the happy path first.
        rebuild_claude_json_for_swap(&config_dir, &handle_dir);
        assert!(handle_dir.join(".claude.json").exists());

        // Act + Assert: read-only handle_dir → write fails → no tmp leak.
        // rebuild_claude_json_for_swap returns (), but the §5a contract
        // still requires no tmp file survives on failure. We verify
        // directly after making the dir read-only.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&handle_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        rebuild_claude_json_for_swap(&config_dir, &handle_dir);
        std::fs::set_permissions(&handle_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let leaked: Vec<_> = std::fs::read_dir(&handle_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
    }

    // ── an internal ticket: reconcile_handle_dir_oauth_email ───────────────────────────────

    fn read_oauth_email_field(handle_dir: &Path) -> Option<String> {
        let content = std::fs::read_to_string(handle_dir.join(".claude.json")).ok()?;
        let json: Value = serde_json::from_str(&content).ok()?;
        json.get("oauthAccount")?
            .get("emailAddress")?
            .as_str()
            .map(str::to_owned)
    }

    #[test]
    fn reconcile_overrides_stale_email_and_preserves_other_fields() {
        // The DA-1 case: handle .claude.json names the OLD (pre-swap) account; force
        // it to the identity anchor while preserving projects + other caches.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"old@a.com","accountUuid":"u-old"},"projects":{"/x":{"n":1}},"numStartups":7}"#,
        )
        .unwrap();
        // pre_swap_email = the OLD account → safe to overwrite.
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("new@b.com")
        );
        // Other fields preserved.
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(json["projects"]["/x"]["n"], 1);
        assert_eq!(json["numStartups"], 7);
        // Sibling oauthAccount field preserved.
        assert_eq!(json["oauthAccount"]["accountUuid"], "u-old");
    }

    #[test]
    fn reconcile_skips_foreign_email_not_matching_pre_swap() {
        // M-2 (redteam R1 deep-analyst): the race case. Between the rebuild and this
        // read, a concurrent CC `/login foreign@c.com` wrote .claude.json=foreign.
        // pre_swap was old@a.com. The current email is NEITHER the anchor NOR the
        // pre-swap value → it is a foreign signal the gate MUST keep seeing → SKIP.
        // Overwriting it would blind the gate to a foreign keychain token.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"foreign@c.com"}}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        // Foreign email preserved — gate stays fail-closed.
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("foreign@c.com")
        );
    }

    #[test]
    fn reconcile_skips_present_email_when_pre_swap_unknown() {
        // Conservative: if pre_swap_email is None (couldn't resolve the old account),
        // a PRESENT non-anchor email cannot be confirmed as the safe stale value →
        // skip (do not risk clobbering a foreign signal).
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"present@a.com"}}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", None);
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("present@a.com")
        );
    }

    #[test]
    fn reconcile_is_idempotent_when_already_matching() {
        // Already-consistent (case-insensitive) → NO write (byte-identical content).
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        let body = r#"{"oauthAccount":{"emailAddress":"Me@Example.com"}}"#;
        std::fs::write(handle.join(".claude.json"), body).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "me@example.com", Some("old@a.com"));
        // No rewrite: content unchanged (a rewrite would re-serialize compactly).
        assert_eq!(
            std::fs::read_to_string(handle.join(".claude.json")).unwrap(),
            body
        );
    }

    #[test]
    fn reconcile_creates_oauth_account_when_absent() {
        // Populated file with no oauthAccount → absent email is always safe to set.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".claude.json"), r#"{"numStartups":3}"#).unwrap();
        // Even with pre_swap unknown, an absent oauthAccount has no signal to lose.
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", None);
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("new@b.com")
        );
    }

    #[test]
    fn reconcile_replaces_non_object_oauth_account() {
        // oauthAccount present but non-object → no usable email (current == None) →
        // safe to replace with a proper object carrying the anchor.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":"garbage","numStartups":3}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", None);
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("new@b.com")
        );
    }

    #[test]
    fn reconcile_skips_absent_unparseable_non_object_and_empty_email() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        // Absent .claude.json → no file created.
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert!(!handle.join(".claude.json").exists());
        // Unparseable (M-1) → unchanged (never clobber a file we can't round-trip).
        std::fs::write(handle.join(".claude.json"), r#"not json {"#).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert_eq!(
            std::fs::read_to_string(handle.join(".claude.json")).unwrap(),
            "not json {"
        );
        // Non-object → unchanged.
        std::fs::write(handle.join(".claude.json"), r#"[1,2,3]"#).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert_eq!(
            std::fs::read_to_string(handle.join(".claude.json")).unwrap(),
            "[1,2,3]"
        );
        // Empty identity email → no-op even on a valid stale file.
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"old@a.com"}}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "   ", Some("old@a.com"));
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("old@a.com")
        );
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_partial_failure_cleans_tmp_file() {
        // §5a: a write/secure_file/atomic_replace failure must leave no tmp behind
        // (`.claude.json` carries the account email = PII). Mirror of the sibling
        // `rebuild_claude_json_for_swap_partial_failure_cleans_tmp_file`.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        // A stale (pre-swap-matching) file so the reconcile decides to WRITE.
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"old@a.com"}}"#,
        )
        .unwrap();
        // Read-only handle dir → the tmp create/write fails → no tmp may linger.
        std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(0o500)).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(0o700)).unwrap();
        let leaked: Vec<_> = std::fs::read_dir(&handle)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
    }

    #[test]
    fn reconcile_skips_oversized_file() {
        // A `.claude.json` past the read ceiling → read_raw None → skip (never buffer
        // + rewrite an unbounded file). Intermediate-reviewer NIT.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        let pad = "x".repeat(17 * 1024 * 1024);
        let body = format!(r#"{{"oauthAccount":{{"emailAddress":"old@a.com"}},"_pad":"{pad}"}}"#);
        std::fs::write(handle.join(".claude.json"), &body).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        // Unchanged (oversized → skipped).
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("old@a.com")
        );
    }

    // ── M2-3 / M4-2 acceptance tests ─────────────────────────────────────

    /// M4-2 Criterion: `materialize_handle_settings_inner` prefers the
    /// UUID-keyed settings.json when it exists on disk.
    ///
    /// Arrange: base dir with a UUID settings path containing `"uuid_key": 1`
    /// and a config-2/settings.json containing `"config_key": 2`. The UUID
    /// path must win in the overlay.
    ///
    /// (Renamed from `materialize_handle_settings_prefers_uuid_path_when_present`
    /// to match the M4-2 WBS acceptance-criterion name in
    /// `internal-design-docs`.)
    #[test]
    fn materialize_handle_settings_prefers_identities_uuid_source() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Write uuid settings.json with a sentinel key
        let uuid_settings = crate::accounts::identity_store::settings_path_for(base, uuid);
        std::fs::create_dir_all(uuid_settings.parent().unwrap()).unwrap();
        std::fs::write(&uuid_settings, r#"{"uuid_key": 1}"#).unwrap();

        // Write config-2/settings.json with a different key
        let config_settings = base.join("config-2").join("settings.json");
        std::fs::write(&config_settings, r#"{"config_key": 2}"#).unwrap();

        // Write empty global settings.json (claude_home)
        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), "{}").unwrap();

        let handle_dir = base.join("term-11111");
        std::fs::create_dir_all(&handle_dir).unwrap();

        // Act
        let result = materialize_handle_settings_inner(
            &handle_dir,
            &claude_home,
            &base.join("config-2"),
            Some(uuid_settings.as_path()),
        );
        assert!(
            result.is_ok(),
            "materialize_handle_settings_inner failed: {result:?}"
        );

        // Assert: materialized settings.json contains uuid_key (UUID path won)
        let merged_raw = std::fs::read_to_string(handle_dir.join("settings.json")).unwrap();
        let merged: serde_json::Value = serde_json::from_str(&merged_raw).unwrap();
        assert_eq!(
            merged["uuid_key"].as_u64(),
            Some(1),
            "UUID-keyed key must appear in merged settings when UUID path present"
        );
        assert!(
            merged.get("config_key").is_none() || merged["config_key"].as_u64() != Some(2),
            "config-N key must NOT override UUID-keyed overlay; merged={merged}"
        );
    }

    /// M4-2 Criterion: `materialize_handle_settings_inner` falls back to
    /// `config-N/settings.json` when no UUID path is provided (legacy-only layout).
    ///
    /// (Renamed from `materialize_handle_settings_falls_back_to_config_n_when_uuid_missing`
    /// to match the M4-2 WBS acceptance-criterion name in
    /// `internal-design-docs`.)
    #[test]
    fn materialize_handle_settings_legacy_fallback_when_uuid_absent() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        // Write config-2/settings.json with a sentinel key
        let config_settings = base.join("config-2").join("settings.json");
        std::fs::write(&config_settings, r#"{"legacy_key": 42}"#).unwrap();

        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), "{}").unwrap();

        let handle_dir = base.join("term-22222");
        std::fs::create_dir_all(&handle_dir).unwrap();

        // Act: pass None for uuid_settings_path (legacy fallback)
        let result = materialize_handle_settings_inner(
            &handle_dir,
            &claude_home,
            &base.join("config-2"),
            None,
        );
        assert!(
            result.is_ok(),
            "materialize_handle_settings_inner failed: {result:?}"
        );

        // Assert: materialized settings.json contains legacy_key (config-N won)
        let merged_raw = std::fs::read_to_string(handle_dir.join("settings.json")).unwrap();
        let merged: serde_json::Value = serde_json::from_str(&merged_raw).unwrap();
        assert_eq!(
            merged["legacy_key"].as_u64(),
            Some(42),
            "config-N key must appear in merged settings when UUID path is None"
        );
    }

    // ── M3-3 acceptance criteria tests ───────────────────────────────────────
    //
    // All 8 tests from 02-plans/04-phase3-readiness.md § M3-3 acceptance
    // criteria, plus the inverted Phase 2/3 boundary test.

    /// M3-3 AC1: Under a coexisting fixture (slot 3, account 2), `.credentials.json`
    /// symlink resolves to `identities/<UUID>/credentials.json`.
    ///
    /// an internal journal entry OQ #2 Option A: M3-3 retargets `.credentials.json` to the
    /// identity-keyed path when a UUID is present.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting_fixture(3) has config-1..3 + identities/<UUID>/
        // Write credentials.json into the identity dir so the symlink target exists.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);
        let identity_creds = base
            .join("identities")
            .join(uuid.to_canonical_string())
            .join("credentials.json");
        std::fs::write(&identity_creds, b"{}").unwrap();

        // Also ensure config-2/.csq-account exists (required for handle dir creation).
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11001;

        // Act
        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Assert: .credentials.json symlink targets identities/<UUID>/credentials.json
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC1: .credentials.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid.to_canonical_string()),
            "AC1: .credentials.json must target the UUID dir for slot 2, got: {target_str}"
        );
        assert!(
            target_str.ends_with("credentials.json"),
            "AC1: symlink must end with credentials.json, got: {target_str}"
        );
    }

    /// M3-3 AC2: Under a legacy-only fixture (no UUID in profiles.json),
    /// `.credentials.json` symlink resolves to `config-2/.credentials.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_falls_back_to_config_n_when_uuid_missing() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange: legacy_only_fixture(3) has config-1..3 but no profiles.json UUIDs.
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11002;

        // Act
        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Assert: .credentials.json symlink targets config-2/.credentials.json
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("config-2"),
            "AC2: legacy fallback must target config-2/, got: {target_str}"
        );
        assert!(
            target_str.ends_with(".credentials.json"),
            "AC2: symlink must end with .credentials.json, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC2: legacy fallback must NOT target identities/, got: {target_str}"
        );
    }

    /// M3-3 AC3: Codex parallel — under a coexisting fixture, `auth.json`
    /// symlink resolves to `identities/<UUID>/credentials-codex.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_codex_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Write credentials-codex.json into the identity dir.
        let identity_dir = base.join("identities").join(uuid.to_canonical_string());
        std::fs::create_dir_all(&identity_dir).unwrap();
        let codex_creds = identity_dir.join("credentials-codex.json");
        std::fs::write(&codex_creds, b"{}").unwrap();

        // Ensure config-2/ Codex items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml

        // Codex also needs the legacy canonical to exist for the precondition check.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-2.json"), b"{}").unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11003;

        // Act
        let handle = create_handle_dir_codex(base, account, pid).unwrap();

        // Assert: auth.json symlink targets identities/<UUID>/credentials-codex.json
        let link = handle.join("auth.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC3: auth.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid.to_canonical_string()),
            "AC3: auth.json must target the UUID dir for slot 2, got: {target_str}"
        );
        assert!(
            target_str.ends_with("credentials-codex.json"),
            "AC3: auth.json must end with credentials-codex.json, got: {target_str}"
        );
    }

    /// M3-3 AC4: Codex parallel — under a legacy-only fixture, `auth.json`
    /// resolves to the legacy `credentials/codex-N.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_codex_falls_back_to_config_n_when_uuid_missing() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        let dir = legacy_only_fixture(3);
        let base = dir.path();

        // Set up Codex-required items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-2.json"), b"{}").unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11004;

        // Act
        let handle = create_handle_dir_codex(base, account, pid).unwrap();

        // Assert: auth.json symlink targets credentials/codex-2.json
        let link = handle.join("auth.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("codex-2"),
            "AC4: legacy fallback must target codex-2.json, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC4: legacy fallback must NOT target identities/, got: {target_str}"
        );
    }

    /// M3-3 AC5: `.csq-account` symlink ALWAYS targets `config-N/.csq-account`
    /// (OQ #2 Option A hardcode), and the marker FILE CONTENT is numeric (e.g. `b"2"`).
    ///
    /// This is cross-phase constraint #3: markers stay at slot path through Phase 4.
    /// The numeric content ensures terminal-attribution continues to work via
    /// `rules/account-terminal-separation.md` MUST NOT Rule 3.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_marker_symlink_resolves_to_numeric_marker_source() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: even with a UUID present, .csq-account stays at config-N/.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();
        // Write the identity-keyed credentials so the creds symlink can be created.
        {
            use crate::testing::identity_fixtures::fixture_uuid_for_slot;
            let uuid = fixture_uuid_for_slot(2);
            let identity_creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11005;

        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Assert 1: .csq-account symlink target contains config-2 (not identities/)
        let link = handle.join(".csq-account");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("config-2"),
            "AC5: .csq-account must target config-2/, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC5: .csq-account must NOT target identities/, got: {target_str}"
        );

        // Assert 2: the FILE CONTENT the symlink resolves to is numeric
        let content = std::fs::read_to_string(&link).unwrap();
        let parsed: u16 = content
            .trim()
            .parse()
            .expect("AC5: .csq-account content must be a numeric slot number");
        assert_eq!(parsed, 2, "AC5: marker content must equal account slot 2");
    }

    /// M3-3 AC6: `symlink_exclusive` primitive contract — a pre-existing path
    /// at the link destination causes `symlink_exclusive` to return
    /// `Err(PlatformError::AlreadyExists)`, never silently overwriting.
    ///
    /// The body directly calls `symlink_exclusive` on an already-existing symlink
    /// to prove the AlreadyExists contract of the M1-3 primitive.  The structural
    /// wire-in proof (every `std::os::unix::fs::symlink` call in non-test code has
    /// been replaced by `symlink_exclusive`) is verified by the grep audit at
    /// `rules/redteam-discipline.md` Rule 2: zero raw `symlink` callsites in
    /// production code.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn symlink_exclusive_refuses_pre_existing_link_at_account_bound_path() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();

        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();
        {
            use crate::testing::identity_fixtures::fixture_uuid_for_slot;
            let uuid = fixture_uuid_for_slot(2);
            let identity_creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11006;

        // Pre-create the handle dir and place a regular file at .credentials.json.
        // This simulates a partially-created handle dir where the link path already
        // exists (e.g., from a racing concurrent create or stale orphan).
        let handle_dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle_dir).unwrap();
        std::fs::write(handle_dir.join(".credentials.json"), b"stale").unwrap();
        // Also write .live-pid so the orphan-detection path removes it safely.
        // (We want the handle dir creation to proceed past orphan-detection and
        // reach the symlink phase — but we need to set up the dir as an orphan
        // with a dead PID so create_handle_dir removes and recreates it.)
        //
        // Actually — to test the AlreadyExists refusal, we need create_handle_dir
        // to fail at the symlink step, not at the "orphan with live PID" check.
        // Create the handle dir WITHOUT a .live-pid (corrupt orphan case) so
        // create_handle_dir removes it and recreates it.  After remove+recreate
        // the dir is fresh, so we cannot pre-place the file this way.
        //
        // Instead: pre-create a stale handle dir with a live-looking PID to force
        // the function to *refuse* deletion — but that tests a different path.
        //
        // The correct shape: drop the pre-created dir, let create_handle_dir
        // succeed on first call, then call again (PID collision with dead PID via
        // .live-pid pointing at a dead PID) — the second call will remove+recreate.
        // That still doesn't get us a pre-existing .credentials.json at the SYMLINK
        // step because remove_dir_all clears it.
        //
        // Correct test: Remove the pre-created handle dir.  Let the first
        // create_handle_dir succeed.  Then manually recreate a conflicting
        // regular file inside the handle dir at an item path AND call
        // `symlink_exclusive` directly to verify the AlreadyExists contract.
        std::fs::remove_dir_all(&handle_dir).unwrap();

        // First call succeeds — establishes the handle dir with the correct symlinks.
        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Verify the .credentials.json is a symlink (not a regular file).
        let creds_link = handle.join(".credentials.json");
        assert!(
            creds_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "AC6: .credentials.json in handle dir must be a symlink"
        );

        // Verify: calling symlink_exclusive on an already-existing symlink path
        // returns Err (AlreadyExists).  This is the direct wire-in proof.
        let dummy_target = base.join("config-2").join(".credentials.json");
        let err = crate::platform::fs::symlink_exclusive(&dummy_target, &creds_link).unwrap_err();
        assert!(
            matches!(err, crate::error::PlatformError::AlreadyExists),
            "AC6: symlink_exclusive on an existing path must return AlreadyExists, got: {err:?}"
        );
    }

    // M3-7: tests `create_handle_dir_handles_concurrent_identity_mint_race`
    // and `create_handle_dir_falls_back_to_config_n_when_uuid_present_but_identity_credentials_missing`
    // retired alongside the HIGH-1 runtime fallback. Phase 4's
    // `phase4_gate_check` (renamed from the prior `phase3_gate` symbol
    // in M4-5; M3-7's IdentityCredentialsUnseeded invariant preserved
    // as check 3) makes the Partial-Pass-0 state impossible at
    // daemon-runtime; the positive-shape test
    // `create_handle_dir_targets_identity_uuid_path_when_present` (below)
    // and the M3-7 acceptance test
    // `handle_dir_credentials_read_resolves_to_identity_path_after_mirror_retirement`
    // pin the M3-7 contract that `.credentials.json` always points at the
    // identity path when a UUID is present.

    // M3-3 AC8: The inverted Phase 2/3 boundary test is in csq/src/cli/commands/run.rs
    // as `run_command_handle_dir_symlinks_target_identity_uuid`.

    /// M3-7 acceptance test #12 (WBS line 269):
    /// `handle_dir_credentials_read_resolves_to_identity_path_after_mirror_retirement`.
    ///
    /// With M3-7 the HIGH-1 fallback to `config-N/.credentials.json` is
    /// retired. When a slot has a UUID in `profiles.json`, the handle
    /// dir's `.credentials.json` symlink ALWAYS targets the identity-keyed
    /// path `identities/<UUID>/credentials.json`. Phase 3's fail-closed
    /// gate guarantees this path is seeded before any daemon-mediated
    /// handle dir creation, so the symlink is always live.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn handle_dir_credentials_read_resolves_to_identity_path_after_mirror_retirement() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture has UUID in profiles + identity dir.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Seed the identity credentials.json (Phase 3 fail-closed gate
        // guarantees this is true at daemon runtime — we mimic that here).
        let identity_creds = uuid_creds_path(base, uuid);
        std::fs::create_dir_all(identity_creds.parent().unwrap()).unwrap();
        std::fs::write(&identity_creds, b"{\"claudeAiOauth\":{}}").unwrap();

        // Set up other config-N items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 12101;

        let handle = create_handle_dir(base, claude_home.path(), account, pid)
            .expect("create_handle_dir succeeds with seeded identity creds");

        // M3-7 invariant: `.credentials.json` symlink targets the identity path.
        let creds_link = handle.join(".credentials.json");
        assert!(creds_link
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        let target = std::fs::read_link(&creds_link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("/identities/"),
            "M3-7: .credentials.json symlink MUST target identities/<UUID>/, got: {target_str}"
        );
        assert!(
            !target_str.contains("config-"),
            "M3-7: .credentials.json symlink MUST NOT target config-N/, got: {target_str}"
        );

        // Resolving the symlink lands on the identity credentials we seeded.
        let resolved = std::fs::read_to_string(&creds_link).unwrap();
        assert_eq!(
            resolved, "{\"claudeAiOauth\":{}}",
            "M3-7: reading through the handle-dir symlink MUST yield the identity-keyed payload"
        );
    }

    /// HIGH-2 regression: `create_handle_dir_codex` must fall back to
    /// `credentials/codex-N.json` when UUID is present in `profiles.json` but
    /// `identities/<UUID>/credentials-codex.json` does NOT exist.
    ///
    /// Before the fix: `credentials_codex_path_for` returns a nonexistent path;
    /// the existence check at line ~387 sees it missing → skip → handle dir has
    /// NO `auth.json` → Codex CLI fails on first API call.
    ///
    /// After the fix: fallback to `credentials/codex-N.json` (which exists).
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_codex_falls_back_to_legacy_when_uuid_present_but_identity_credentials_codex_missing(
    ) {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture has UUID but does NOT have
        // identities/<UUID>/credentials-codex.json (only identity.json).
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Verify precondition: credentials-codex.json is absent.
        let identity_dir = base.join("identities").join(uuid.to_canonical_string());
        let codex_creds = identity_dir.join("credentials-codex.json");
        assert!(
            !codex_creds.exists(),
            "Precondition: identity credentials-codex.json must NOT exist in coexisting fixture"
        );

        // Set up Codex-required items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml

        // Legacy canonical DOES exist.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let legacy_codex = creds_dir.join("codex-2.json");
        std::fs::write(&legacy_codex, b"{}").unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 12002;

        // Act
        let result = create_handle_dir_codex(base, account, pid);

        // Assert: succeeds
        assert!(
            result.is_ok(),
            "HIGH-2: create_handle_dir_codex must succeed when identity credentials-codex.json \
             is absent; got: {result:?}"
        );
        let handle = result.unwrap();

        // Assert: auth.json symlink EXISTS
        let auth_link = handle.join("auth.json");
        assert!(
            auth_link.symlink_metadata().is_ok(),
            "HIGH-2: auth.json symlink must exist in handle dir (fallback to legacy canonical)"
        );
        assert!(
            auth_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "HIGH-2: auth.json in handle dir must be a symlink"
        );

        // Assert: symlink target is the legacy canonical, NOT identities/
        let target = std::fs::read_link(&auth_link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("codex-2"),
            "HIGH-2: fallback symlink must target codex-2.json, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "HIGH-2: fallback symlink must NOT target identities/, got: {target_str}"
        );
    }

    // ── M3-4 acceptance criteria tests ───────────────────────────────────────
    //
    // 9 tests from the M3-4 WBS (an internal workspace Phase 3, an internal ticket).
    // Tests cover: repoint identity UUID targeting, mtime bump on identity path,
    // Codex repoint parallel, fallback scenarios (legacy + Partial-Pass-0), and
    // concurrent writer regression guard.

    /// M3-4 AC1: `repoint_handle_dir` retargets `.credentials.json` to the
    /// identity-keyed path when the identity credentials file exists.
    ///
    /// Arrange: coexisting_fixture(3) — slot 2 and slot 3 both have config-N/
    /// and identities/<UUID>/credentials.json. Create a handle dir bound to
    /// slot 2, then repoint to slot 3. Post-swap, the symlink must resolve
    /// to `identities/<UUID-for-3>/credentials.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_targets_identity_uuid_path_when_present() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: fixture with slots 1..3 in coexisting layout.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write identity credentials for slots 2 and 3 (fixture provides config-N/
        // and identity.json but NOT credentials.json in identity dir).
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        // Complete config-N layout for both slots.
        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, claude_home.path(), account2, 21001).unwrap();

        // Act: repoint from slot 2 → slot 3.
        repoint_verified_fixture(base, claude_home.path(), &handle, account3).unwrap();

        // Assert: symlink resolves to identities/<UUID-for-slot-3>/credentials.json
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        let uuid3 = profiles::resolve_slot_to_uuid(base, 3).unwrap();
        assert!(
            target_str.contains("identities"),
            "AC1: .credentials.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid3.to_canonical_string()),
            "AC1: .credentials.json must target UUID dir for slot 3 ({}), got: {target_str}",
            uuid3.to_canonical_string()
        );
        assert!(
            target_str.ends_with("credentials.json"),
            "AC1: symlink must end with credentials.json, got: {target_str}"
        );
    }

    /// an internal ticket: the real DA-1 case — `config-<target>/.claude.json` is ABSENT, so
    /// `rebuild_claude_json_for_swap` bails and the handle retains the OLD (pre-swap)
    /// account's stale `.claude.json`. `repoint_handle_dir` then reconciles
    /// `oauthAccount.emailAddress` to the swap target's identity anchor (the current
    /// email equals the captured pre-swap value → safe to overwrite), so the custodian
    /// wrong-account gate matches on the next tick.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_reconciles_oauth_email_to_identity_anchor() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            std::fs::write(
                base.join("identities")
                    .join(uuid.to_canonical_string())
                    .join("credentials.json"),
                b"{}",
            )
            .unwrap();
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
        }
        // config-2 carries slot-2's email — the handle inherits it at create, so it
        // becomes the pre-swap value. config-3/.claude.json is deliberately ABSENT →
        // the rebuild bails → the handle keeps the slot-2 (pre-swap) copy → the
        // reconcile's safety gate recognizes it as the pre-swap value and overwrites
        // it with the slot-3 identity anchor.
        std::fs::write(
            base.join("config-2/.claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-2@test.invalid"},"projects":{}}"#,
        )
        .unwrap();
        // (config-3/.claude.json intentionally NOT written.)

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let handle = create_handle_dir(base, claude_home.path(), account2, 21051).unwrap();
        // Precondition: the handle inherited slot-2's email (the pre-swap value).
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("fixture-slot-2@test.invalid")
        );

        repoint_verified_fixture(base, claude_home.path(), &handle, account3).unwrap();

        // The handle's oauthAccount.emailAddress is now the slot-3 IDENTITY anchor —
        // the gate matches; no wait for CC to rewrite.
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("fixture-slot-3@test.invalid"),
            "AC: swap must reconcile oauthAccount.emailAddress to the identity anchor"
        );
    }

    /// M3-4 AC2 (Codex parallel): `repoint_handle_dir_codex` retargets
    /// `auth.json` to `identities/<UUID>/credentials-codex.json` when present.
    ///
    /// Arrange: coexisting_fixture(3), write credentials-codex.json into identity
    /// dirs for slots 2 and 3, then repoint a Codex handle dir from slot 2 → 3.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write credentials-codex.json into identity dirs for slots 2 and 3.
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_dir = base.join("identities").join(uuid.to_canonical_string());
            std::fs::create_dir_all(&identity_dir).unwrap();
            std::fs::write(identity_dir.join("credentials-codex.json"), b"{}").unwrap();
        }

        // Complete config-N layout for Codex (requires .csq-account + config.toml).
        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml
        }

        // Legacy canonical codex credentials (required by precondition check).
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        for slot in [2u16, 3u16] {
            std::fs::write(creds_dir.join(format!("codex-{slot}.json")), b"{}").unwrap();
        }

        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir_codex(base, account2, 21002).unwrap();

        // Act: repoint Codex handle dir from slot 2 → slot 3.
        repoint_handle_dir_codex(base, &handle, account3).unwrap();

        // Assert: auth.json symlink resolves to identities/<UUID-for-3>/credentials-codex.json
        let link = handle.join("auth.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        let uuid3 = fixture_uuid_for_slot(3);
        assert!(
            target_str.contains("identities"),
            "AC2(Codex): auth.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid3.to_canonical_string()),
            "AC2(Codex): auth.json must target UUID dir for slot 3 ({}), got: {target_str}",
            uuid3.to_canonical_string()
        );
        assert!(
            target_str.ends_with("credentials-codex.json"),
            "AC2(Codex): auth.json must end with credentials-codex.json, got: {target_str}"
        );
    }

    /// M3-4 AC3: `repoint_handle_dir` mtime bump targets the identity-keyed
    /// credentials.json, not config-N/.credentials.json, when UUID present.
    ///
    /// Pin the identity credentials.json to a past mtime, then repoint.
    /// Post-swap, reading the mtime through the symlink must be strictly above
    /// the pre-swap baseline — proving `bump_mtime_above` ran against the
    /// identity path.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_preserves_mtime_bump_against_identity_credentials_json() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::time::{Duration, SystemTime};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write identity credentials for slot 3 (the swap target).
        let uuid3 = fixture_uuid_for_slot(3);
        let identity_dir = base.join("identities").join(uuid3.to_canonical_string());
        let identity_creds = identity_dir.join("credentials.json");
        std::fs::write(&identity_creds, b"{}").unwrap();

        // Also write identity creds for slot 2 (the swap source handle dir).
        let uuid2 = fixture_uuid_for_slot(2);
        let identity_dir2 = base.join("identities").join(uuid2.to_canonical_string());
        let identity_creds2 = identity_dir2.join("credentials.json");
        std::fs::write(&identity_creds2, b"{}").unwrap();

        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        // Pin identity credentials.json for slot 3 to a known past mtime.
        stage_verified_repoint_slots(base, &[1, 2, 3]);
        let identity_creds = verified_fixture_credentials(base, 3);
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&identity_creds)
            .unwrap();
        f.set_modified(collision_time).unwrap();
        drop(f);

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account2, 21003).unwrap();

        // Act: repoint from slot 2 → slot 3.
        repoint_verified_fixture(base, claude_home.path(), &handle, account3).unwrap();

        // Assert: reading mtime through the symlink is strictly above collision_time.
        let post_mtime = std::fs::metadata(handle.join(".credentials.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > collision_time,
            "AC3: mtime bump must advance identity credentials.json above baseline \
             ({collision_time:?}), got: {post_mtime:?}"
        );

        // Additionally assert the symlink resolves to identities/ (not config-N/).
        let target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC3: symlink must target identities/ after repoint, got: {target_str}"
        );
    }

    /// M3-4 AC4 (Codex parallel): `repoint_handle_dir_codex` mtime bump targets
    /// `identities/<UUID>/credentials-codex.json` when present.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_preserves_mtime_bump_against_identity_credentials_codex_json() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::time::{Duration, SystemTime};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write credentials-codex.json into identity dirs for slots 2 and 3.
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_dir = base.join("identities").join(uuid.to_canonical_string());
            std::fs::create_dir_all(&identity_dir).unwrap();
            std::fs::write(identity_dir.join("credentials-codex.json"), b"{}").unwrap();
        }

        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml
        }

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        for slot in [2u16, 3u16] {
            std::fs::write(creds_dir.join(format!("codex-{slot}.json")), b"{}").unwrap();
        }

        // Pin identity credentials-codex.json for slot 3 to a known past mtime.
        let uuid3 = fixture_uuid_for_slot(3);
        let identity_codex3 = base
            .join("identities")
            .join(uuid3.to_canonical_string())
            .join("credentials-codex.json");
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&identity_codex3)
            .unwrap();
        f.set_modified(collision_time).unwrap();
        drop(f);

        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir_codex(base, account2, 21004).unwrap();

        // Act: repoint from slot 2 → slot 3.
        repoint_handle_dir_codex(base, &handle, account3).unwrap();

        // Assert: mtime through auth.json symlink is strictly above collision_time.
        let post_mtime = std::fs::metadata(handle.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > collision_time,
            "AC4(Codex): mtime bump must advance identity credentials-codex.json above \
             baseline ({collision_time:?}), got: {post_mtime:?}"
        );

        // Additionally assert the symlink resolves to identities/.
        let target = std::fs::read_link(handle.join("auth.json")).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC4(Codex): auth.json must target identities/ after repoint, got: {target_str}"
        );
    }

    /// Retired M3-4 AC5: an unverified legacy-only Anthropic target must
    /// refuse with exact custody preservation; raw fallback is not authority.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_refuses_legacy_config_n_when_uuid_missing() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange: legacy_only_fixture — no profiles.json UUIDs.
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account2, 21005).unwrap();
        let before = repoint_fixture_snapshot(base);

        // Retired unverified Anthropic fallback must refuse without ANY mutation.
        let result = repoint_handle_dir(base, claude_home.path(), &handle, account3);
        assert!(
            matches!(result, Err(CredentialError::Corrupt { reason, .. }) if reason == "identity_authority_refused")
        );
        assert_eq!(before, repoint_fixture_snapshot(base));
    }

    // M3-7: test `repoint_handle_dir_falls_back_to_config_n_when_uuid_present_but_identity_credentials_missing`
    // retired alongside the HIGH-1 runtime fallback in `repoint_handle_dir`.
    // Phase 4's `phase4_gate_check` (renamed from the prior `phase3_gate`
    // symbol in M4-5) makes the Partial-Pass-0 state impossible at
    // daemon-runtime. The positive-shape test
    // `repoint_handle_dir_targets_identity_uuid_path_when_present` (below)
    // pins the M3-7 contract that `.credentials.json` always points at
    // the identity path when a UUID is present.

    /// M3-4 AC9: Concurrent writers under identity targets — porting the
    /// existing concurrent-writer regression guard to the identity fixture.
    ///
    /// Two threads simultaneously repoint the SAME handle dir to different
    /// slots under a coexisting fixture. The post-condition is that exactly
    /// ONE of the two target accounts "wins" — the handle dir symlinks are
    /// self-consistent (both `.credentials.json` and `.csq-account` agree).
    /// No intermediate "half-repointed" state is observable.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_serializes_concurrent_writers_under_identity_targets() {
        let _env_guard = crate::platform::test_env::lock();
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::sync::Arc;

        let dir = coexisting_fixture(3);
        let base = dir.path().to_path_buf();

        // Write identity credentials for slots 2 and 3.
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_dir = base.join("identities").join(uuid.to_canonical_string());
            let identity_creds = identity_dir.join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        for slot in [1u16, 2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        // Slot 1 source (for initial handle dir; legacy path is fine as source).
        {
            let uuid1 = fixture_uuid_for_slot(1);
            let id1 = base.join("identities").join(uuid1.to_canonical_string());
            std::fs::write(id1.join("credentials.json"), b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let claude_home_path = claude_home.path().to_path_buf();
        let account1 = AccountNum::try_from(1u16).unwrap();
        std::fs::write(
            base.join("config-1/settings.json"),
            serde_json::json!({"fixtureWinner":1}).to_string(),
        )
        .unwrap();
        std::fs::write(
            base.join("config-2/settings.json"),
            serde_json::json!({"fixtureWinner":2}).to_string(),
        )
        .unwrap();
        std::fs::write(
            base.join("config-3/settings.json"),
            serde_json::json!({"fixtureWinner":3}).to_string(),
        )
        .unwrap();
        stage_verified_repoint_slots(&base, &[1, 2, 3]);
        let handle = create_handle_dir(&base, &claude_home_path, account1, 21009).unwrap();

        let base_arc = Arc::new(base.clone());
        let handle_arc = Arc::new(handle.clone());
        let ch_arc = Arc::new(claude_home_path.clone());

        let base2 = Arc::clone(&base_arc);
        let handle2 = Arc::clone(&handle_arc);
        let ch2 = Arc::clone(&ch_arc);

        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();

        let binding_a =
            crate::accounts::anthropic_identity::capture_anthropic_binding(&base, account2)
                .unwrap();
        let binding_b =
            crate::accounts::anthropic_identity::capture_anthropic_binding(&base, account3)
                .unwrap();
        let native_a = capture_native_swap(&base, &handle).unwrap();
        let native_b = capture_native_swap(&base, &handle).unwrap();
        // Both pre-captured snapshots race through the real guarded route.
        let t1 = std::thread::spawn(move || {
            let result =
                repoint_handle_dir_guarded(&base_arc, &ch_arc, &handle_arc, &binding_a, &native_a);
            (result, binding_a, native_a)
        });
        let t2 = std::thread::spawn(move || {
            let result = repoint_handle_dir_guarded(&base2, &ch2, &handle2, &binding_b, &native_b);
            (result, binding_b, native_b)
        });
        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();
        assert_verified_repoint_race(&base, &claude_home_path, &handle, r1, r2);

        // Assert: symlinks are self-consistent — both point to the SAME slot.
        let creds_target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        let marker_target = std::fs::read_link(handle.join(".csq-account")).unwrap();
        let creds_str = creds_target.to_string_lossy();
        let marker_str = marker_target.to_string_lossy();

        // Determine which slot won by reading the marker file.
        let winner_slot = markers::resolve_marker_to_slot(&base, &handle)
            .unwrap()
            .get();
        assert!(
            winner_slot == 2 || winner_slot == 3,
            "AC9: winner slot must be 2 or 3, got {winner_slot}"
        );

        // Both symlinks must point to the same winner.
        assert!(
            creds_str.contains(&format!("config-{winner_slot}"))
                || creds_str.contains("identities"),
            "AC9: .credentials.json must resolve consistently, got: {creds_str}"
        );
        assert!(
            marker_str.contains(&format!("config-{winner_slot}")),
            "AC9: .csq-account must target config-{winner_slot}/, got: {marker_str}"
        );
    }

    /// L2 (`security.md` §5a): `create_tmp_exclusive` MUST refuse to write
    /// through a symlink an attacker (or a crashed prior run) has already
    /// planted at the exact tmp path — and the symlink's real target must
    /// be left completely untouched, never overwritten and never exposed
    /// via a follow-through open. Deterministic (no dependency on
    /// `unique_tmp_path`'s process-global counter): this test picks its own
    /// tmp path and plants the symlink there itself.
    #[test]
    #[cfg(unix)]
    fn create_tmp_exclusive_refuses_a_planted_symlink_target_untouched() {
        use super::create_tmp_exclusive;

        let dir = tempfile::tempdir().unwrap();
        let real_secret = dir.path().join("unrelated-real-file.json");
        std::fs::write(&real_secret, b"PRE-EXISTING CONTENT, MUST NEVER CHANGE").unwrap();

        let tmp = dir.path().join("settings.json.tmp.planted");
        std::os::unix::fs::symlink(&real_secret, &tmp).unwrap();

        let result = create_tmp_exclusive(&tmp, b"{\"attacker\":\"payload\"}");

        assert!(
            result.is_err(),
            "create_new(true) must refuse to write through a planted \
             symlink, got: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&real_secret).unwrap(),
            "PRE-EXISTING CONTENT, MUST NEVER CHANGE",
            "the symlink's real target must be untouched by the refused write"
        );
        // The symlink itself is also untouched (not replaced, not deleted).
        assert!(
            std::fs::symlink_metadata(&tmp)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted symlink entry itself must be left exactly as it was"
        );
    }

    /// The happy path, same fn: no pre-existing entry at `tmp` — the file
    /// is created at 0o600 (never world-readable, even momentarily) and
    /// holds exactly the written content.
    #[test]
    #[cfg(unix)]
    fn create_tmp_exclusive_creates_fresh_file_at_0600() {
        use super::create_tmp_exclusive;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("settings.json.tmp.fresh");

        create_tmp_exclusive(&tmp, b"{\"real\":\"content\"}").expect("fresh create must succeed");

        assert_eq!(std::fs::read(&tmp).unwrap(), b"{\"real\":\"content\"}");
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "must be owner-only from creation, got {mode:o}"
        );
    }
    #[test]
    fn native_swap_org_identity_regression_full_context_null_and_foreign_are_distinct() {
        use crate::accounts::anthropic_identity as ai;
        let target = ai::AnthropicContext::new(
            "same@example.test",
            uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        )
        .unwrap();
        let old = ai::AnthropicContext::new(
            "same@example.test",
            target.account_uuid(),
            uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config-2");
        let handle = dir.path().join("term-999999");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&handle).unwrap();
        let path = handle.join(".claude.json");
        for oauth in [
            serde_json::Value::Null,
            serde_json::json!({
                "emailAddress":old.email(),"accountUuid":old.account_uuid(),"organizationUuid":old.organization_uuid(),"organizationRole":"source-only-role"
            }),
        ] {
            let raw = serde_json::to_string(
                &serde_json::json!({"oauthAccount":oauth,"projects":{"preserve":true},"cachedGrowthBookFeatures":{"foreign-org":true},"overageCreditGrantCache":{"foreign-org":true}}),
            )
            .unwrap();
            std::fs::write(&path, &raw).unwrap();
            crate::platform::fs::secure_file(&path).unwrap();
            assert!(native_context_can_rewrite(Some(&raw), &target, Some(&old)));
            rebuild_claude_json_for_swap_context(&config, &handle, &target, Some(&old), Some(&raw))
                .unwrap();
            let result: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                ai::parse_native_expectation(&result).unwrap().context(),
                &target
            );
            assert_eq!(result["projects"]["preserve"], true);
            assert!(result.get("cachedGrowthBookFeatures").is_none());
            assert!(result.get("overageCreditGrantCache").is_none());
            assert!(result["oauthAccount"].get("organizationRole").is_none());
        }
        let foreign = serde_json::to_string(&serde_json::json!({"oauthAccount":{
            "emailAddress":old.email(),"accountUuid":old.account_uuid(),"organizationUuid":old.organization_uuid()
        }})).unwrap();
        assert!(!native_context_can_rewrite(Some(&foreign), &target, None));
        assert!(!native_context_can_rewrite(
            Some(r#"{"oauthAccount":{"emailAddress":"same@example.test"}}"#),
            &target,
            Some(&old)
        ));
        std::fs::write(&path, &foreign).unwrap();
        assert_eq!(
            rebuild_claude_json_for_swap_context(&config, &handle, &target, None, Some(&foreign)),
            Err(NativeMetadataReconcileFailure::UntrustedContext)
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), foreign);
    }

    #[test]
    fn native_swap_org_identity_regression_interleaved_native_login_preserves_foreign_bytes() {
        use crate::accounts::anthropic_identity as ai;
        let target = ai::AnthropicContext::new(
            "same@example.test",
            uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config-2");
        let handle = dir.path().join("term-999999");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&handle).unwrap();
        let path = handle.join(".claude.json");
        let captured = r#"{"oauthAccount":null,"projects":{"retain":1}}"#;
        std::fs::write(&path, captured).unwrap();
        crate::platform::fs::secure_file(&path).unwrap();
        let receipt = capture_native_swap(dir.path(), &handle).unwrap();
        assert_eq!(receipt.raw.as_deref(), Some(captured));
        assert_eq!(receipt.handle, std::fs::canonicalize(&handle).unwrap());
        let foreign = r#"{"oauthAccount":{"emailAddress":"foreign@example.test","accountUuid":"33333333-3333-4333-8333-333333333333","organizationUuid":"44444444-4444-4444-8444-444444444444"},"projects":{"retain":2}}"#;
        std::fs::write(&path, foreign).unwrap();
        assert_eq!(
            rebuild_claude_json_for_swap_context(
                &config,
                &handle,
                &target,
                None,
                receipt.raw.as_deref(),
            ),
            Err(NativeMetadataReconcileFailure::ContextChanged)
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), foreign);
    }
    #[cfg(unix)]
    #[test]
    fn native_swap_org_identity_regression_fifo_and_symlink_refuse_without_touching_target() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let handle = dir.path().join("term-999999");
        std::fs::create_dir(&handle).unwrap();
        let path = handle.join(".claude.json");
        assert_eq!(read_native_swap_raw(&handle).unwrap(), None);
        let target = dir.path().join("unrelated.json");
        crate::platform::fs::write_new_private(&target, br#"{"preserve":"fake-fixture"}"#).unwrap();
        let before = std::fs::read(&target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_native_swap_raw(&handle).is_err());
        assert!(capture_native_swap(dir.path(), &handle).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), before);
        assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
        std::fs::remove_file(&path).unwrap();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        // No writer is opened: a blocking FIFO reader would hang here. The
        // production reader rejects irregular metadata before opening and also
        // uses O_NONBLOCK if a replacement races that metadata check.
        assert!(read_native_swap_raw(&handle).is_err());
        assert!(capture_native_swap(dir.path(), &handle).is_err());
        assert!(!path.symlink_metadata().unwrap().is_file());
        assert_eq!(std::fs::read(target).unwrap(), before);
    }
}
