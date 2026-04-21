//! `csq statusline` — reads CC JSON from stdin, runs snapshot + sync,
//! and outputs the formatted statusline (account + quota + model +
//! project + context window + session cost + git).
//!
//! Replaces the shell-script + jq + Rust composition from v1. All
//! parsing and rendering now live in Rust so csq has zero runtime
//! dependencies beyond the system git binary (used only when the
//! user is inside a git repo).
//!
//! ## Account/Terminal Separation
//!
//! This command is a TERMINAL operation. It reads and displays account
//! quota data but NEVER writes it. Quota data is written exclusively
//! by the daemon's usage poller, which polls Anthropic's `/api/oauth/usage`
//! endpoint directly per account.
//!
//! See `rules/account-terminal-separation.md` for the full spec.

use anyhow::Result;
use csq_core::accounts::{markers, snapshot};
use csq_core::broker::{fanout::is_broker_failed, sync};
use csq_core::quota::format::{
    account_label, is_swap_stuck, parse_cc_stdin, parse_workspace_dir, rich_statusline,
    should_report_broker_failed, statusline_str, GitStatus, StatuslineContext,
};
use csq_core::quota::state;
use csq_core::types::AccountNum;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

/// Maximum bytes of CC JSON we accept on stdin.
/// Real CC payloads are <16KB; 64KB is generous and prevents DoS.
const MAX_STDIN: u64 = 65_536;

pub fn handle(base_dir: &Path) -> Result<()> {
    let config_dir = match super::current_config_dir() {
        Some(d) => d,
        None => {
            println!("csq: no config dir");
            return Ok(());
        }
    };

    // Drain CC's JSON payload. Used for rich rendering (model, cwd,
    // ctx tokens, cost). The payload is NOT used for quota updates —
    // that's the daemon's job via Anthropic's usage API.
    let mut stdin_buf = String::new();
    let _ = std::io::stdin()
        .take(MAX_STDIN)
        .read_to_string(&mut stdin_buf);

    // ── Snapshot: identify which account CC is running ──
    let _ = snapshot::snapshot_account(&config_dir, base_dir);

    // Determine active account from snapshot result (.current-account),
    // falling back to .csq-account marker.
    let account: AccountNum = match markers::read_current_account(&config_dir)
        .or_else(|| markers::read_csq_account(&config_dir))
    {
        Some(a) => a,
        None => {
            println!("csq: no active account");
            return Ok(());
        }
    };

    // ── Sync: backsync (live→canonical) + pullsync (canonical→live) ──
    // Best-effort, never blocks the statusline render.
    let _ = sync::backsync(&config_dir, base_dir);
    let _ = sync::pullsync(&config_dir, base_dir);

    // ── Gather account + quota state ──
    let quota = state::load_state(base_dir).unwrap_or_else(|_| csq_core::quota::QuotaFile::empty());
    let account_quota = quota.get(account.get());
    let label = account_label(base_dir, account);
    let stuck = is_swap_stuck(&config_dir, base_dir);
    let broker_failed =
        should_report_broker_failed(base_dir, account) || is_broker_failed(base_dir, account);

    // ── Compose rich line from CC stdin + git probe ──
    //
    // Failure at any step below degrades gracefully to the minimal
    // `account + quota` line that `csq-statusline` v1.x produced.
    let line = match build_rich_line(
        &stdin_buf,
        base_dir,
        account,
        &label,
        account_quota,
        stuck,
        broker_failed,
    ) {
        Some(s) => s,
        None => statusline_str(account, &label, account_quota, stuck, broker_failed),
    };

    println!("{line}");
    Ok(())
}

/// Builds the rich statusline using the parsed CC stdin + a git
/// probe in the workspace directory. Returns `None` when stdin is
/// empty / unparseable and there's nothing rich to add — the caller
/// falls back to [`statusline_str`] in that case.
fn build_rich_line(
    stdin_buf: &str,
    base_dir: &Path,
    account: AccountNum,
    label: &str,
    account_quota: Option<&csq_core::quota::AccountQuota>,
    stuck: bool,
    broker_failed: bool,
) -> Option<String> {
    if stdin_buf.trim().is_empty() {
        return None;
    }

    let mut ctx: StatuslineContext = parse_cc_stdin(stdin_buf);
    ctx.is_csq_terminal = is_csq_managed_terminal(base_dir);
    ctx.git = parse_workspace_dir(stdin_buf)
        .as_deref()
        .and_then(git_status);

    Some(rich_statusline(
        account,
        label,
        account_quota,
        stuck,
        broker_failed,
        &ctx,
    ))
}

/// Returns true when `CLAUDE_CONFIG_DIR` is set AND points inside
/// the csq base dir (handle dirs or legacy config-N). Missing env
/// var or CC running outside csq's tree → false. The distinction
/// controls whether the `⚡csq ` prefix appears on the line.
fn is_csq_managed_terminal(base_dir: &Path) -> bool {
    let Some(config) = std::env::var_os("CLAUDE_CONFIG_DIR") else {
        return false;
    };
    let config_path = Path::new(&config);

    // Canonicalize both paths so a symlinked `~/.claude/accounts`
    // compares equal to its resolved target. Canonicalize failures
    // (deleted dir mid-run) collapse to string prefix comparison
    // rather than returning false incorrectly.
    let base_canon = std::fs::canonicalize(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    let config_canon =
        std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());

    config_canon.starts_with(&base_canon)
}

/// Best-effort git probe in `dir`. Runs three short git commands;
/// returns `None` if the first one (`rev-parse --git-dir`) reports
/// this isn't a repo OR the binary is missing. The branch command
/// returns an empty string on detached HEAD — reported as the
/// literal `"detached"` to match the v1 shell script.
fn git_status(dir: &str) -> Option<GitStatus> {
    let workdir = Path::new(dir);
    if !workdir.is_dir() {
        return None;
    }

    // Stage 1: is this a git repo at all?
    let inside = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .arg("rev-parse")
        .arg("--git-dir")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !inside.success() {
        return None;
    }

    // Stage 2: current branch. Empty stdout on detached HEAD.
    let branch_out = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .arg("branch")
        .arg("--show-current")
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let branch_raw = String::from_utf8_lossy(&branch_out.stdout)
        .trim()
        .to_string();
    let branch = if branch_raw.is_empty() {
        "detached".to_string()
    } else {
        branch_raw
    };

    // Stage 3: dirty? `git diff --quiet` returns 0 clean, 1 dirty.
    // Any other status (missing binary, aborted) → treat as clean
    // rather than inventing a dirty flag.
    let worktree_dirty = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .arg("diff")
        .arg("--quiet")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.code() == Some(1))
        .unwrap_or(false);
    let index_dirty = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .arg("diff")
        .arg("--cached")
        .arg("--quiet")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.code() == Some(1))
        .unwrap_or(false);

    Some(GitStatus {
        branch,
        dirty: worktree_dirty || index_dirty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serialises tests that mutate `CLAUDE_CONFIG_DIR`.
    ///
    /// `std::env::set_var` is process-wide; running two env-mutating
    /// tests in parallel produces a read/write race where one test
    /// sees the other's value. Predates PR-A1 — surfaced when the
    /// auto-rotate test additions shifted the workspace-wide test
    /// scheduling. Fix follows `zero-tolerance.md` Rule 1.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn run_git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git not available on PATH — tests require git");
        assert!(status.success(), "git {:?} failed", args);
    }

    #[test]
    fn git_status_none_outside_repo() {
        // A non-existent dir shouldn't be probed.
        assert!(git_status("/definitely/not/a/real/path/12345").is_none());

        // A real dir that isn't a repo also → None.
        let tmp = TempDir::new().unwrap();
        assert!(git_status(tmp.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn git_status_clean_repo_reports_branch_not_dirty() {
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        // Fresh repo with no commits is still considered "in a repo".
        // Create an initial commit so `--show-current` returns `main`.
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);

        let g = git_status(tmp.path().to_str().unwrap()).expect("in repo → Some");
        assert_eq!(g.branch, "main");
        assert!(!g.dirty, "freshly-committed repo should be clean");
    }

    #[test]
    fn git_status_reports_worktree_dirty() {
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        // Touch the committed file — worktree now diverges from index.
        std::fs::write(tmp.path().join("README"), "hello + new").unwrap();

        let g = git_status(tmp.path().to_str().unwrap()).unwrap();
        assert!(g.dirty, "worktree edit should flip dirty=true");
    }

    #[test]
    fn git_status_reports_staged_dirty() {
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        // Stage a new file but don't commit — index diverges from HEAD.
        std::fs::write(tmp.path().join("NEW"), "x").unwrap();
        run_git(tmp.path(), &["add", "NEW"]);

        let g = git_status(tmp.path().to_str().unwrap()).unwrap();
        assert!(g.dirty, "staged file should flip dirty=true");
    }

    #[test]
    fn is_csq_managed_terminal_matches_subdirectory() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let base = TempDir::new().unwrap();
        let term_dir = base.path().join("term-12345");
        std::fs::create_dir_all(&term_dir).unwrap();

        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", &term_dir) };
        let result = is_csq_managed_terminal(base.path());
        if let Some(p) = prev {
            unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", p) };
        } else {
            unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
        }

        assert!(result, "handle dir under base_dir must be recognized");
    }

    #[test]
    fn is_csq_managed_terminal_rejects_unrelated_path() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let base = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();

        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", other.path()) };
        let result = is_csq_managed_terminal(base.path());
        if let Some(p) = prev {
            unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", p) };
        } else {
            unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
        }

        assert!(!result);
    }
}
