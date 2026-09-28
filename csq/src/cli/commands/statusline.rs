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
use csq_core::accounts::snapshot;
use csq_core::quota::format::{
    account_label, parse_cc_stdin, parse_workspace_dir, rich_statusline,
    should_report_broker_failed, statusline_str, GitStatus, StatuslineContext,
};
use csq_core::quota::state;
use csq_core::refresh::{sentinel::is_broker_failed, sync};
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

    // ── Resolve the active account: authority-first (`.csq-account`), with
    // `.current-account` demoted to a self-healing cache. snapshot_account
    // owns the full resolution (numeric marker → slot directly; UUID marker →
    // reverse-resolved via by_slot) and self-heals a drifted cache, so the
    // statusline no longer second-guesses it with a numeric-only re-read that
    // returned None for UUID markers and trusted a stale cache otherwise
    // (workspace an internal workspace).
    let account: AccountNum = match snapshot::snapshot_account(&config_dir, base_dir) {
        Some(a) => a,
        None => {
            println!("csq: no active account");
            return Ok(());
        }
    };

    // ── Sync: backsync (live→canonical) — best-effort, never blocks render.
    // M3-7: pullsync (canonical→live) retired — handle dirs read credentials
    // through identity-keyed symlinks, so daemon canonical writes are
    // visible without a push step.
    let _ = sync::backsync(&config_dir, base_dir);

    // ── Gather account + quota state ──
    // an internal ticket: salvage per-row. Statusline is read-only by
    // `account-terminal-separation.md` MUST-2, so salvaging cannot write a
    // truncated file back; one bad row costs one row.
    let quota = state::load_state_salvage(base_dir);
    let account_quota = quota.get(account.get());
    let label = account_label(base_dir, account);
    // M3-7 fix-wave R1 M2-DA: `is_swap_stuck` is retired (no production
    // "stuck" semantic under the handle-dir model). The statusline no
    // longer renders a `!` glyph for divergence between live mirror and
    // canonical — handle dir symlinks resolve to a single inode written
    // by the daemon refresher.
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
        broker_failed,
    ) {
        Some(s) => s,
        None => statusline_str(account, &label, account_quota, broker_failed),
    };

    println!("{line}");
    Ok(())
}

/// Read context metadata from the same runtime snapshot path as model commands.
fn model_context_window(base_dir: &Path, model: &str) -> Result<Option<u64>> {
    let manifest = csq_core::providers::model_manifest::ModelManifest::load(base_dir)?;
    Ok(manifest
        .catalog()
        .find(model)
        .and_then(|row| row.context_window))
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
    broker_failed: bool,
) -> Option<String> {
    if stdin_buf.trim().is_empty() {
        return None;
    }

    let mut ctx: StatuslineContext = parse_cc_stdin(stdin_buf);
    ctx.is_csq_terminal = is_csq_managed_terminal(base_dir);
    // Resolve the model's TRUE context window from csq's catalog so the context %
    // is recomputed against it. CC computes `used_percentage` against its own ~200k
    // assumption for the Anthropic-compatible endpoint; 3P models with a larger real
    // window (deepseek-v4-pro / minimax / glm = 1M) otherwise render a wildly inflated
    // % (e.g. 177k → 89% against 200k instead of 18% against 1M).
    //
    // Source of the model id: the slot's `config-<slot>/settings.json`
    // (`model_id_for_slot`) — the SAME on-disk source the daemon poller reads.
    // NOT `std::env::var("ANTHROPIC_MODEL")`: `csq run` strips every `ANTHROPIC_*`
    // var from CC's spawn env (`strip_sensitive_env`), so the process env is an
    // unreliable channel (whether CC re-exports settings.json `env` to the
    // spawned statusLine subprocess is a CC-internal behavior csq doesn't control).
    // Env var kept only as a last-resort fallback. Keyed on the model id/alias.
    let model_id = csq_core::providers::settings::model_id_for_slot(base_dir, account.get())
        .or_else(|| {
            std::env::var("ANTHROPIC_MODEL")
                .ok()
                .filter(|m| !m.is_empty())
        });
    ctx.ctx_window_true = model_id.and_then(|m| match model_context_window(base_dir, &m) {
        Ok(window) => window,
        Err(error) => {
            tracing::warn!(
                error_kind = "model_manifest_invalid",
                "model context unavailable: {error}"
            );
            None
        }
    });
    ctx.git = parse_workspace_dir(stdin_buf)
        .as_deref()
        .and_then(git_status);

    Some(rich_statusline(
        account,
        label,
        account_quota,
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
    // THREE outcomes, not two: `Some(false)` (clean), `Some(true)`
    // (dirty), or `None` when git could not answer at all — spawn
    // failure, or any exit that is neither 0 nor 1. That last case
    // covers a missing binary, an aborted diff (exit 128), AND a
    // signal-killed git process (`ExitStatus::code()` returns `None`
    // on Unix) — the collapse that made this function report a
    // confident `dirty: false` for a killed-under-load git process,
    // indistinguishable from a genuinely clean repo (an internal ticket).
    // `None` is NOT inferred to be clean here; only the render site
    // in `quota::format::rich_statusline` decides how to DISPLAY an
    // unmeasured repo, and it deliberately renders `None` the same as
    // clean — see that function's doc for why display and knowledge
    // are different questions.
    let diff_dirty = |status: std::io::Result<std::process::ExitStatus>| -> Option<bool> {
        match status.ok().and_then(|s| s.code()) {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        }
    };
    let worktree_dirty = diff_dirty(
        Command::new("git")
            .arg("-C")
            .arg(workdir)
            .arg("diff")
            .arg("--quiet")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
    let index_dirty = diff_dirty(
        Command::new("git")
            .arg("-C")
            .arg(workdir)
            .arg("diff")
            .arg("--cached")
            .arg("--quiet")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
    // A confirmed dirty from EITHER side wins even if the other side
    // could not be measured — dirty is dirty. Only when neither side
    // confirms dirty AND at least one side is unmeasured does the
    // combined result become `None` rather than a confident `false`.
    let dirty = match (worktree_dirty, index_dirty) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    };

    Some(GitStatus { branch, dirty })
}

#[cfg(test)]
mod tests {
    #[test]
    fn model_manifest_statusline_context_reads_updates_and_rejects_invalid_data() {
        use csq_core::providers::model_manifest::{manifest_path, ModelManifest};
        let base = tempfile::TempDir::new().unwrap();
        assert_eq!(
            super::model_context_window(base.path(), "deepseek-flash[1m]").unwrap(),
            Some(1_000_000)
        );
        let mut manifest = ModelManifest::bundled();
        manifest
            .models
            .iter_mut()
            .find(|m| m.id == "deepseek-flash")
            .unwrap()
            .context_window = Some(2_000_000);
        let path = manifest_path(base.path());
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(
            super::model_context_window(base.path(), "deepseek-flash[1m]").unwrap(),
            Some(2_000_000)
        );
        std::fs::write(path, b"invalid").unwrap();
        assert!(super::model_context_window(base.path(), "deepseek-flash[1m]").is_err());
    }

    use super::*;
    use tempfile::TempDir;

    /// Serialises tests that mutate `CLAUDE_CONFIG_DIR`.
    ///
    /// `std::env::set_var` is process-wide; running two env-mutating
    /// tests in parallel produces a read/write race where one test
    /// sees the other's value.
    ///
    /// MUST acquire the WORKSPACE-WIDE mutex
    /// (`csq_core::platform::test_env::lock()`), not a module-local
    /// one, per `testing.md` MUST Rule 6. A module-local `Mutex` only
    /// serialized statusline's own env tests — it did NOT serialize
    /// against `swap.rs`'s `detect_source_handle` tests, which mutate
    /// the SAME `CLAUDE_CONFIG_DIR` under the canonical lock. The two
    /// locks were disjoint, so the suites raced cross-module: a
    /// statusline test rewriting `CLAUDE_CONFIG_DIR` between a swap
    /// test's `EnvVarGuard::set` and its `detect_source_handle` call
    /// made the swap test observe statusline's value and return the
    /// wrong error variant. macOS-only by CI thread-scheduling luck
    /// (green on an internal ticket macOS + an internal ticket ubuntu/windows, red on an internal ticket
    /// macOS). Root-caused + fixed per `zero-tolerance.md` Rule 1
    /// during the v2.8.0-rc.1 cut; see an internal journal entry
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        csq_core::platform::test_env::lock()
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            // Hermetic: a maintainer's global `commit.gpgsign=true` makes the
            // temp-repo `git commit` try to GPG-sign in a non-interactive
            // context and fail ("gpg failed to sign the data"). Force signing
            // off so the test passes regardless of global git config. CI has no
            // gpgsign, so this only surfaced on signing-configured dev hosts.
            .arg("-c")
            .arg("commit.gpgsign=false")
            .arg("-c")
            .arg("tag.gpgsign=false")
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
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        // A non-existent dir shouldn't be probed.
        assert!(git_status("/definitely/not/a/real/path/12345").is_none());

        // A real dir that isn't a repo also → None.
        let tmp = TempDir::new().unwrap();
        assert!(git_status(tmp.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn git_status_clean_repo_reports_branch_not_dirty() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        // Fresh repo with no commits is still considered "in a repo".
        // Create an initial commit so `--show-current` returns `main`.
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);

        let g = git_status(tmp.path().to_str().unwrap()).expect("in repo → Some");
        assert_eq!(g.branch, "main");
        assert_eq!(
            g.dirty,
            Some(false),
            "freshly-committed repo should be clean"
        );
    }

    #[test]
    fn git_status_reports_worktree_dirty() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        // Touch the committed file — worktree now diverges from index.
        std::fs::write(tmp.path().join("README"), "hello + new").unwrap();

        let g = git_status(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(g.dirty, Some(true), "worktree edit should flip dirty=true");
    }

    #[test]
    fn git_status_reports_staged_dirty() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        // Stage a new file but don't commit — index diverges from HEAD.
        std::fs::write(tmp.path().join("NEW"), "x").unwrap();
        run_git(tmp.path(), &["add", "NEW"]);

        let g = git_status(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(g.dirty, Some(true), "staged file should flip dirty=true");
    }

    /// an internal ticket / an internal ticket row 18 regression guard: `git diff --quiet` can exit with
    /// something other than 0 or 1 — on Unix a signal-killed git process makes
    /// `ExitStatus::code()` return `None`; a repo whose index git cannot parse
    /// (this test's reproduction) makes it exit 128. Both must land on
    /// `dirty: None` ("could not measure"), never on the same `Some(false)` a
    /// genuinely clean repo reports. Without this case the suite cannot tell
    /// `Option<bool>` apart from a `bool` that happens to be right today —
    /// deleting the `None` arm and collapsing it into `Some(false)` must RED
    /// this test (proven by mutation, not asserted).
    ///
    /// WHY A CORRUPT INDEX AND NOT AN UNREADABLE FILE. The first version of
    /// this test chmod'd a tracked file to `0o000`. That is NOT portable and
    /// shipped red: macOS git cannot hash the file and exits 128, but Linux
    /// git treats it as modified and exits 1, so the assertion read
    /// `Some(true)` on ubuntu and enterprise CI while passing locally. An
    /// unparseable index is a fatal in git's index-reading path on every
    /// platform, needs no permission semantics, and therefore also needs no
    /// root guard — root parses a corrupt index exactly as badly as anyone
    /// else, whereas `0o000` is bypassed by DAC_OVERRIDE.
    ///
    /// Stages 1 and 2 of `git_status` still succeed: `rev-parse --git-dir`
    /// and `branch --show-current` read HEAD and the gitdir, never the index.
    /// Only stage 3 fails, which is precisely the arm under test.
    #[test]
    fn git_status_reports_none_when_diff_cannot_measure() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        let readme = tmp.path().join("README");
        std::fs::write(&readme, "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);

        // Replace the index with bytes git cannot parse. `git diff --quiet`
        // then exits 128 ("bad index file") — neither 0 (clean) nor 1
        // (dirty) — reproducing the same "git ran but could not answer"
        // shape a signal-killed process produces, deterministically and
        // without depending on filesystem permission semantics.
        std::fs::write(tmp.path().join(".git").join("index"), b"NOT-A-GIT-INDEX").unwrap();

        let g = git_status(tmp.path().to_str().unwrap())
            .expect("in a repo → Some, even when diff could not measure");
        assert_eq!(
            g.dirty, None,
            "git diff exited non-0/1 on an unparseable index — must report \
             None (could not measure), not a confident Some(false) \
             indistinguishable from clean, nor Some(true)"
        );
    }

    #[test]
    fn is_csq_managed_terminal_matches_subdirectory() {
        let _guard = env_guard();
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
        let _guard = env_guard();
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
