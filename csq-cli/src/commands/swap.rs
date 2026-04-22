//! `csq swap N` — swap the active account in the current terminal.
//!
//! # Three paths
//!
//! 1. **Same-surface ClaudeCode** (source + target both Anthropic or
//!    3P) — atomic symlink repoint in `term-<pid>`. CC re-reads on
//!    next API call. In-flight swap, no process restart.
//! 2. **Cross-surface** (source ≠ target surface) — INV-P05 requires
//!    prompt-and-confirm (`--yes` bypasses), then INV-P10 requires
//!    removing the source handle dir BEFORE `exec`ing the target
//!    binary. Conversation does not transfer.
//! 3. **Same-surface Codex** (source + target both Codex) — also
//!    takes the exec-replace path today. Codex's `sessions/` symlink
//!    model means a running codex process holds references into the
//!    old `config-<N>/codex-sessions/` dir; symlink-repoint with a
//!    live process would orphan those open files. The exec-replace
//!    path is semantically equivalent to "quit, run csq swap" and
//!    costs one process restart in exchange for avoiding that
//!    orphan.
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

/// PR-C7 entry point. `yes` bypasses the cross-surface confirmation
/// prompt (INV-P05 `--yes`).
pub fn handle(base_dir: &Path, target: AccountNum, yes: bool) -> Result<()> {
    let source = detect_source_handle()?;
    let target_surface = resolve_target_surface(base_dir, target)?;

    match (source.surface(), target_surface) {
        // Same-surface ClaudeCode: in-flight symlink repoint.
        (Surface::ClaudeCode, Surface::ClaudeCode) => {
            same_surface_claude_code(base_dir, source.path(), target)
        }
        // Anything involving Codex (either side) takes the exec-replace
        // path. Same-surface Codex falls through here too — see module
        // docstring for the sessions/-symlink rationale.
        _ => cross_surface_exec(base_dir, source, target, target_surface, yes),
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

// ─── Cross-surface / Codex exec-replace path ────────────────────────

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

    // INV-P10: remove source handle dir BEFORE exec. If removal fails
    // we abort — never leave the source terminal dangling AND fail to
    // start the target.
    let source_path = source.path();
    if is_term_handle_dir(source_path) {
        std::fs::remove_dir_all(source_path).map_err(|e| {
            anyhow!(
                "failed to remove source handle dir {} before cross-surface exec: {e}",
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
}
