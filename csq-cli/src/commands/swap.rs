//! `csq swap N` — swap the active account in the current terminal.
//!
//! # Three paths
//!
//! 1. **Same-surface ClaudeCode** (source + target both Anthropic or
//!    3P) — atomic symlink repoint in `term-<pid>`. CC re-reads on
//!    next API call. In-flight swap, no process restart.
//! 2. **Same-surface Codex** (source + target both Codex) — atomic
//!    symlink repoint in `term-<pid>` via the Codex-aware mirror
//!    `repoint_handle_dir_codex` (spec 07 §7.2.2 symlink set). codex-cli
//!    re-stats `auth.json` before each API call so the next request
//!    resolves through the new symlink; UNIX open-after-rename keeps
//!    in-flight session fds valid until close. Resolves M10 / journal
//!    0023 — the pre-PR-C9a behavior was to take the exec-replace path,
//!    which silently dropped the user's conversation.
//! 3. **Cross-surface** (source ≠ target surface) — INV-P05 requires
//!    prompt-and-confirm (`--yes` bypasses), then INV-P10 requires
//!    renaming the source handle dir to a sweep tombstone BEFORE
//!    `exec`ing the target binary. Conversation does not transfer.
//!
//! # Legacy fallback
//!
//! If `CLAUDE_CONFIG_DIR` points at a `config-<N>` dir (pre-handle-dir
//! layout), falls back to the credential-copy `rotation::swap_to` with
//! a deprecation warning. Never exec-replaces from legacy mode — the
//! user needs to relaunch via `csq run N` to get per-terminal
//! isolation before csq will consider cross-surface swaps.

use anyhow::{anyhow, Result};
use csq_core::accounts::discovery;
use csq_core::providers::catalog::Surface;
use csq_core::providers::codex::surface as codex_surface;
use csq_core::rotation;
use csq_core::session::handle_dir;
use csq_core::types::AccountNum;
use std::path::{Path, PathBuf};

/// One of the two env vars a csq-managed terminal sets pointing at its
/// handle dir. Which one is set tells us the source surface without
/// any on-disk introspection.
enum SourceHandle {
    /// `CLAUDE_CONFIG_DIR` set → source is ClaudeCode (Anthropic or 3P).
    ClaudeCode(PathBuf),
    /// `CODEX_HOME` set → source is Codex.
    Codex(PathBuf),
}

impl SourceHandle {
    fn path(&self) -> &Path {
        match self {
            Self::ClaudeCode(p) | Self::Codex(p) => p,
        }
    }

    fn surface(&self) -> Surface {
        match self {
            Self::ClaudeCode(_) => Surface::ClaudeCode,
            Self::Codex(_) => Surface::Codex,
        }
    }
}

/// Pure dispatch decision for `handle()`. Extracted as a free function
/// (PR-C9b L-CDX-3) so the routing matrix is unit-testable without the
/// env-var + filesystem setup that `handle()` requires. Any future
/// refactor of the dispatcher MUST keep `route()` in lockstep — the
/// `route_*` unit tests pin the matrix.
#[derive(Debug, PartialEq, Eq)]
enum RouteKind {
    /// Source + target both ClaudeCode (Anthropic or 3P). In-flight
    /// symlink repoint; no exec, no tombstone.
    SameSurfaceClaudeCode,
    /// Source + target both Codex. In-flight symlink repoint via the
    /// Codex-aware mirror (M10 / journal 0023). No exec, no tombstone.
    SameSurfaceCodex,
    /// Source ≠ target surface. INV-P05 confirm + INV-P10 tombstone +
    /// `exec` of the target binary. Conversation does not transfer.
    CrossSurface,
}

fn route(source: Surface, target: Surface) -> RouteKind {
    match (source, target) {
        (Surface::ClaudeCode, Surface::ClaudeCode) => RouteKind::SameSurfaceClaudeCode,
        (Surface::Codex, Surface::Codex) => RouteKind::SameSurfaceCodex,
        _ => RouteKind::CrossSurface,
    }
}

/// PR-C7 entry point. `yes` bypasses the cross-surface confirmation
/// prompt (INV-P05 `--yes`).
pub fn handle(base_dir: &Path, target: AccountNum, yes: bool) -> Result<()> {
    let source = detect_source_handle()?;
    let target_surface = resolve_target_surface(base_dir, target)?;

    match route(source.surface(), target_surface) {
        RouteKind::SameSurfaceClaudeCode => {
            same_surface_claude_code(base_dir, source.path(), target)
        }
        RouteKind::SameSurfaceCodex => same_surface_codex(base_dir, source.path(), target),
        RouteKind::CrossSurface => {
            cross_surface_exec(base_dir, source, target, target_surface, yes)
        }
    }
}

// ─── Source-surface detection ────────────────────────────────────────

fn detect_source_handle() -> Result<SourceHandle> {
    // Both env vars may be set by a well-meaning parent shell. Prefer
    // CODEX_HOME when it points at a csq-managed handle dir, because
    // `csq run N` for a Codex slot explicitly sets CODEX_HOME and
    // scrubs CLAUDE_CONFIG_DIR (run.rs strip_sensitive_env).
    if let Ok(raw) = std::env::var("CODEX_HOME") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::Codex(p));
        }
    }
    if let Ok(raw) = std::env::var("CLAUDE_CONFIG_DIR") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::ClaudeCode(p));
        }
        // Legacy config-N fallback — pre-handle-dir layout. The
        // downstream caller (legacy_swap) preserves the deprecation
        // warning; here we flag it as ClaudeCode so same-surface
        // ClaudeCode routing catches it.
        if is_legacy_config_dir(&p) {
            return Ok(SourceHandle::ClaudeCode(p));
        }
        return Err(anyhow!(
            "CLAUDE_CONFIG_DIR does not point to a csq-managed directory: {raw}"
        ));
    }
    Err(anyhow!(
        "neither CLAUDE_CONFIG_DIR nor CODEX_HOME is set — \
         csq swap must run inside a csq-managed session"
    ))
}

fn is_term_handle_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("term-"))
        .unwrap_or(false)
}

fn is_legacy_config_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("config-"))
        .unwrap_or(false)
}

fn resolve_target_surface(base_dir: &Path, target: AccountNum) -> Result<Surface> {
    let accounts = discovery::discover_all(base_dir);
    accounts
        .iter()
        .find(|a| a.id == target.get())
        .map(|a| a.surface)
        .ok_or_else(|| {
            anyhow!(
                "account {target} not found — run `csq login {target}` first, \
                 or check `csq status` for available accounts"
            )
        })
}

// ─── Same-surface ClaudeCode (existing behavior) ────────────────────

fn same_surface_claude_code(base_dir: &Path, source_dir: &Path, target: AccountNum) -> Result<()> {
    let dir_name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if dir_name.starts_with("term-") {
        // Handle-dir model: repoint symlinks + re-materialize settings.json
        let claude_home = super::claude_home()?;
        handle_dir::repoint_handle_dir(base_dir, &claude_home, source_dir, target)?;
        notify_daemon_cache_invalidation(base_dir);
        println!(
            "Swapped to account {} — CC will pick up on next API call",
            target
        );
    } else if dir_name.starts_with("config-") {
        // Legacy model: credential copy (with deprecation warning)
        eprintln!(
            "warning: running in legacy config-dir mode ({dir_name}). \
             Swap affects ALL terminals sharing this dir. \
             Relaunch with `csq run {target}` for per-terminal isolation."
        );
        let validated = super::validated_config_dir(base_dir)?;
        let result = rotation::swap_to(base_dir, &validated, target, Surface::ClaudeCode)?;
        let expires_in_min = (result.expires_at_ms / 1000).saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        ) / 60;
        notify_daemon_cache_invalidation(base_dir);
        println!(
            "Swapped to account {} — token valid {}m",
            result.account, expires_in_min
        );
    } else {
        return Err(anyhow!(
            "source dir is not a csq-managed directory: {}",
            source_dir.display()
        ));
    }
    Ok(())
}

// ─── Same-surface Codex (M10 / journal 0023) ────────────────────────

/// Same-surface Codex→Codex symlink repoint. Mirrors
/// `same_surface_claude_code` but uses the Codex-aware
/// [`handle_dir::repoint_handle_dir_codex`] (spec 07 §7.2.2 symlink
/// set). No exec-replace, no tombstone — the running codex process
/// keeps its open fds and picks up the new auth.json on the next API
/// call.
///
/// Legacy `config-N` Codex source dirs are not supported: there is no
/// pre-handle-dir layout for Codex (the surface launched after the
/// handle-dir model was already in place), so any Codex source must be
/// a `term-<pid>` dir. Returns a clear error otherwise.
fn same_surface_codex(base_dir: &Path, source_dir: &Path, target: AccountNum) -> Result<()> {
    let dir_name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !dir_name.starts_with("term-") {
        return Err(anyhow!(
            "Codex source dir is not a csq-managed handle dir: {}. \
             Relaunch with `csq run {target}` to get per-terminal isolation.",
            source_dir.display()
        ));
    }

    handle_dir::repoint_handle_dir_codex(base_dir, source_dir, target)?;
    notify_daemon_cache_invalidation(base_dir);
    println!(
        "Swapped to account {} — codex will pick up on next API call",
        target
    );
    Ok(())
}

// ─── Cross-surface exec-replace path ────────────────────────────────

fn cross_surface_exec(
    base_dir: &Path,
    source: SourceHandle,
    target: AccountNum,
    target_surface: Surface,
    yes: bool,
) -> Result<()> {
    let source_surface = source.surface();
    let is_cross_surface = source_surface != target_surface;

    if is_cross_surface && !yes {
        confirm_cross_surface(source_surface, target_surface)?;
    }

    // INV-P10 (journal 0021 finding 10): rename source handle dir to a
    // tombstone BEFORE exec. The old code called `remove_dir_all`
    // which (a) opens a signal-window between rename-to-oblivion and
    // the exec syscall — a Ctrl-C there leaves the user with a dead
    // csq process and no running CLI — and (b) destroys files under
    // the live `codex` / `claude` process's open fds when swap is
    // called mid-session.
    //
    // Renaming instead:
    //   - is a single atomic syscall (no signal window)
    //   - keeps the directory alive for the running process's fds
    //     (the tombstone inode survives until the last fd closes)
    //   - is swept by the daemon sweep on its next tick via the
    //     shared `cleanup_stale_tombstones` (`.sweep-tombstone-*`
    //     prefix)
    //
    // If `exec` fails after the rename, the csq process returns an
    // error to the user and the tombstone is reaped at the next sweep
    // — so neither success nor failure leaves a live handle dir
    // pointing at a dead surface (INV-P10 preserved).
    let source_path = source.path();
    if is_term_handle_dir(source_path) {
        rename_handle_dir_to_sweep_tombstone(source_path).map_err(|e| {
            anyhow!(
                "failed to tombstone source handle dir {} before cross-surface exec: {e}",
                source_path.display()
            )
        })?;
    }
    // Legacy config-N source: do NOT remove the config dir (permanent
    // account home per spec 02 INV-01). Just exec; the config dir
    // stays as-is for future csq runs.

    let pid = std::process::id();

    match target_surface {
        Surface::Codex => exec_codex(base_dir, target, pid),
        Surface::ClaudeCode => exec_claude_code(base_dir, target, pid),
    }
}

/// Atomically renames `source_path` to a
/// `.sweep-tombstone-swap-<pid>-<nanos>` sibling so the source is
/// structurally unreachable from subsequent csq commands while
/// remaining intact for any still-running process holding fds into
/// it. The daemon sweep's `cleanup_stale_tombstones` picks up the
/// `.sweep-tombstone-` prefix and reaps it.
///
/// The `-swap-` infix distinguishes swap tombstones from the sweep's
/// own rename-then-remove tombstones; both share the cleanup path
/// but the infix is debuggable evidence for which created it.
fn rename_handle_dir_to_sweep_tombstone(source_path: &Path) -> std::io::Result<()> {
    let base = source_path
        .parent()
        .ok_or_else(|| std::io::Error::other("source handle dir has no parent"))?;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let tombstone = base.join(format!(".sweep-tombstone-swap-{pid}-{nanos:x}"));
    std::fs::rename(source_path, &tombstone)
}

fn confirm_cross_surface(source: Surface, target: Surface) -> Result<()> {
    use std::io::{BufRead, Write};
    eprintln!(
        "Warning: swapping from {source} to {target} — the current \
         conversation will not transfer across surfaces."
    );
    eprint!("Continue? [y/N]: ");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    if !line.trim().eq_ignore_ascii_case("y") {
        return Err(anyhow!("swap cancelled"));
    }
    Ok(())
}

#[cfg(unix)]
fn exec_codex(base_dir: &Path, target: AccountNum, pid: u32) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let handle_dir = csq_core::session::handle_dir::create_handle_dir_codex(base_dir, target, pid)
        .map_err(|e| anyhow!("failed to create Codex handle dir for slot {target}: {e}"))?;

    let mut cmd = std::process::Command::new(codex_surface::CLI_BINARY);
    cmd.env(codex_surface::HOME_ENV_VAR, &handle_dir);
    // Scrub any inherited CLAUDE_CONFIG_DIR so codex doesn't see a
    // stale Anthropic handle dir in its env.
    cmd.env_remove("CLAUDE_CONFIG_DIR");

    let err = cmd.exec();
    Err(anyhow!(
        "exec `{}` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {err}",
        codex_surface::CLI_BINARY
    ))
}

#[cfg(unix)]
fn exec_claude_code(base_dir: &Path, target: AccountNum, pid: u32) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let claude_home = super::claude_home()?;
    let handle_dir =
        csq_core::session::handle_dir::create_handle_dir(base_dir, &claude_home, target, pid)
            .map_err(|e| {
                anyhow!("failed to create ClaudeCode handle dir for slot {target}: {e}")
            })?;

    let mut cmd = std::process::Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir);
    cmd.env_remove(codex_surface::HOME_ENV_VAR);

    let err = cmd.exec();
    Err(anyhow!(
        "exec `claude` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {err}"
    ))
}

#[cfg(not(unix))]
fn exec_codex(_base_dir: &Path, _target: AccountNum, _pid: u32) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

#[cfg(not(unix))]
fn exec_claude_code(_base_dir: &Path, _target: AccountNum, _pid: u32) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

// ─── Daemon cache invalidation (unchanged from pre-PR-C7) ───────────

/// Best-effort cache invalidation: POST /api/invalidate-cache to
/// the daemon if it's reachable.
#[cfg(unix)]
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    let sock = csq_core::daemon::socket_path(base_dir);
    if !sock.exists() {
        return;
    }
    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
}

#[cfg(not(unix))]
fn notify_daemon_cache_invalidation(_base_dir: &Path) {
    // Windows named-pipe invalidation is not yet implemented (M8-03).
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(dead_code)] // ensure markers/Surface paths compile on all targets
mod tests {
    use super::*;

    // Unit tests exercise the pure helpers (source detection +
    // target-surface resolution). Full swap integration is covered
    // by the handle_dir repoint tests and the new cross-surface
    // integration tests in csq-cli/tests/.

    #[test]
    fn is_term_handle_dir_accepts_term_prefix() {
        assert!(is_term_handle_dir(Path::new("/base/term-42")));
        assert!(is_term_handle_dir(Path::new("/base/term-1001")));
    }

    #[test]
    fn is_term_handle_dir_rejects_config_prefix() {
        assert!(!is_term_handle_dir(Path::new("/base/config-3")));
        assert!(!is_term_handle_dir(Path::new("/base/not-a-handle")));
    }

    #[test]
    fn is_legacy_config_dir_accepts_config_prefix() {
        assert!(is_legacy_config_dir(Path::new("/base/config-7")));
        assert!(!is_legacy_config_dir(Path::new("/base/term-99")));
    }

    #[test]
    fn source_handle_surface_matches_variant() {
        let ch = SourceHandle::ClaudeCode(PathBuf::from("/x/term-1"));
        assert_eq!(ch.surface(), Surface::ClaudeCode);
        let cx = SourceHandle::Codex(PathBuf::from("/x/term-2"));
        assert_eq!(cx.surface(), Surface::Codex);
    }

    // ── PR-C9b L-CDX-3 — dispatcher routing matrix ────────────────────

    /// Pinning: ClaudeCode→ClaudeCode MUST stay on the same-surface
    /// in-flight repoint path.
    #[test]
    fn route_claudecode_to_claudecode_is_same_surface_claudecode() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::ClaudeCode),
            RouteKind::SameSurfaceClaudeCode
        );
    }

    /// Pinning: Codex→Codex MUST stay on the same-surface in-flight
    /// repoint path (M10 / journal 0023). Regression guard against any
    /// future refactor that re-routes through cross_surface_exec and
    /// silently drops the user's conversation again.
    #[test]
    fn route_codex_to_codex_is_same_surface_codex() {
        assert_eq!(
            route(Surface::Codex, Surface::Codex),
            RouteKind::SameSurfaceCodex
        );
    }

    /// Pinning: any cross-surface combination MUST take the exec-replace
    /// path (INV-P05 confirm + INV-P10 tombstone + exec).
    #[test]
    fn route_cross_surface_is_cross_surface() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::Codex),
            RouteKind::CrossSurface
        );
        assert_eq!(
            route(Surface::Codex, Surface::ClaudeCode),
            RouteKind::CrossSurface
        );
    }

    // ── PR-C9a journal 0021 finding 10 — rename-to-tombstone ─

    /// The tombstone rename MUST atomically move the source handle
    /// dir to a sibling path with the `.sweep-tombstone-` prefix so
    /// the daemon's existing `cleanup_stale_tombstones` sweep reaps
    /// it. The source path is free; the directory inode survives for
    /// any process still holding fds into it.
    #[test]
    fn rename_handle_dir_to_sweep_tombstone_moves_dir() {
        let base = tempfile::TempDir::new().unwrap();
        let source = base.path().join("term-99999");
        std::fs::create_dir(&source).unwrap();
        // Seed a sentinel to prove the inode survived the move.
        std::fs::write(source.join("sentinel"), b"alive").unwrap();

        rename_handle_dir_to_sweep_tombstone(&source).unwrap();

        // Source path is gone.
        assert!(
            !source.exists(),
            "source handle dir must be gone after rename"
        );
        // A .sweep-tombstone-swap-<pid>-<nanos> sibling exists with
        // the sentinel intact.
        let mut tombstone_names: Vec<String> = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(".sweep-tombstone-swap-"))
            .collect();
        assert_eq!(
            tombstone_names.len(),
            1,
            "exactly one swap tombstone must exist"
        );
        let name = tombstone_names.pop().unwrap();
        let tomb = base.path().join(&name);
        assert!(tomb.is_dir(), "tombstone must be a directory");
        let sentinel = tomb.join("sentinel");
        let body = std::fs::read(&sentinel).expect("sentinel readable after rename");
        assert_eq!(body, b"alive", "tombstone preserves contents");
        // Prefix matches the daemon's cleanup harness.
        assert!(
            name.starts_with(".sweep-tombstone-"),
            "must share prefix with sweep's existing tombstone cleanup: {name}"
        );
    }

    /// Guard against the regression the old `remove_dir_all` had:
    /// if the sibling process had an open fd, the rename must NOT
    /// disturb the on-disk file — exactly one atomic syscall and the
    /// contents must be readable through the new name. (Unix only;
    /// Windows rename-over-open-handle semantics differ and this
    /// path is Unix-only anyway via `cross_surface_exec`.)
    #[cfg(unix)]
    #[test]
    fn rename_handle_dir_preserves_contents_during_atomic_swap() {
        let base = tempfile::TempDir::new().unwrap();
        let source = base.path().join("term-77777");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("a"), b"one").unwrap();
        std::fs::write(source.join("b"), b"two").unwrap();

        rename_handle_dir_to_sweep_tombstone(&source).unwrap();

        let tomb = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-swap-")
            })
            .expect("tombstone present")
            .path();
        assert_eq!(std::fs::read(tomb.join("a")).unwrap(), b"one");
        assert_eq!(std::fs::read(tomb.join("b")).unwrap(), b"two");
    }
}
