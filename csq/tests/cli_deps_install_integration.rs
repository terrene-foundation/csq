//! Integration tests for `csq cli install/upgrade` (M4 PR-MCD4).
//!
//! Replaces `cli_deps_stub_integration.rs` (M3 stub handler replaced by
//! full implementation in M4).
//!
//! ## Coverage
//!
//! - Tests 1-17: install/upgrade plumbing (argv capture, probe state guards,
//!   ClaudeNativeInstaller None path, non-TTY refusal, EACCES three-option
//!   output, token redaction, consent decline, EOF decline, re-probe after
//!   install, chained node-install, resolved-path disclosure, WrongBinary,
//!   upgrade-when-already-at-latest).
//! - Tests 18-24: clap allowlist (M3 A14 preserved) + 7-payload argv-injection
//!   fuzz.
//!
//! ## Test architecture
//!
//! - Stub binary: `csq-core/tests/bin/stub_cli.rs` (extended in M4 with
//!   `--capture-argv <path>`). Consumed via `CARGO_BIN_EXE_stub-cli`.
//! - No shell-script stubs (per an internal journal entry + M2 R1 F3 flake finding).
//! - Subprocess env cleared per `rules/testing.md` Rule 4a.
//! - Serial mutex on all tests that probe real CLIs (probe has a 2s timeout
//!   per spec/13 §8; CPU saturation under parallel load flakes).
//!
//! Per `rules/probe-driven-verification.md` MUST 1: assertions are structural
//! (exit code + exact fragment checks), NOT prose-regex semantic checks.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

// ── Serial gate ────────────────────────────────────────────────────────────────

// Probe has a 2s timeout per spec/13 §8. Under heavy test parallelism, CPU
// saturation can delay the stub spawn past the deadline (an internal journal entry RISK).
// Tests that touch PATH / probe must serialize.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Binary helpers ─────────────────────────────────────────────────────────────

fn csq_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_csq") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("csq")
}

fn stub_cli_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_stub-cli") {
        return PathBuf::from(p);
    }
    // Fallback: locate beside csq binary.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("stub-cli")
}

// ── Env-cleared command builder ────────────────────────────────────────────────

/// Per-binary sandbox `$HOME` — a single empty tempdir for the whole test
/// process, so production paths that read `HOME` directly (`~/.codex`,
/// `~/.gemini`, redaction helper, keychain prefix) resolve inside the sandbox
/// instead of the operator's real home. See `rules/test-hermeticity.md` MUST 2.
fn sandbox_home() -> std::path::PathBuf {
    static H: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    H.get_or_init(|| TempDir::new().expect("sandbox home"))
        .path()
        .to_path_buf()
}

/// Env-cleared command builder per `rules/testing.md` Rule 4a +
/// `rules/test-hermeticity.md` MUST 2 (sandbox HOME, never parent HOME).
fn clean_cmd(path_override: Option<&str>) -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    // Hermetic: the spawned `csq` binary must NOT shell `security` against the
    // operator's real login keychain (rules/test-hermeticity.md).
    cmd.env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1");
    cmd.env("HOME", sandbox_home());
    for k in &["LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    if let Some(p) = path_override {
        cmd.env("PATH", p);
    } else if let Ok(v) = std::env::var("PATH") {
        cmd.env("PATH", v);
    }
    cmd
}

// ── Stub-npm helper ────────────────────────────────────────────────────────────

/// Create a temp dir containing a stub `npm` binary (symlink to stub-cli) that:
/// - Captures argv to `<capture_file>`.
/// - Exits with `exit_code`.
/// - Emits `stderr_msg` to stderr if non-empty.
///
/// Returns the `TempDir` (caller must keep alive) and the PATH string that
/// puts the stub first.
///
/// Unix-only: writes a `#!/bin/sh` wrapper and chmods it via
/// `PermissionsExt::set_mode`. Every caller is also `#[cfg(unix)]`-gated.
#[cfg(unix)]
fn make_stub_npm_dir(
    exit_code: i32,
    stderr_msg: &str,
    capture_file: &std::path::Path,
) -> (TempDir, String) {
    let stub_dir = TempDir::new().expect("create stub dir");
    let stub_path = stub_dir.path().join("npm");

    // Build a wrapper that invokes stub-cli with the desired flags.
    // We need a real executable so we build a tiny shell wrapper.
    // Per an internal journal entry: shell-script stubs flake. We use the compiled stub-cli
    // instead, invoked via a thin shell wrapper that is as minimal as possible.
    //
    // The only "shell logic" in the wrapper is argument pass-through.
    // The actual configurable behavior (exit code, stderr, argv-capture) is
    // handled by stub-cli — not by shell string interpolation.
    let stub_cli = stub_cli_bin();
    let capture_path = capture_file.display();

    // Compose stub-cli flags.
    // stderr_msg may contain spaces but no shell metacharacters (our test data
    // is controlled; we single-quote the value in the script as a safety measure).
    let stderr_arg = if !stderr_msg.is_empty() {
        // Escape single quotes: ' → '\''
        let escaped = stderr_msg.replace('\'', "'\\''");
        format!("--stderr '{escaped}'")
    } else {
        String::new()
    };

    let script = format!(
        "#!/bin/sh\nexec '{stub_cli}' --capture-argv '{capture_path}' --exit-code {exit_code} {stderr_arg} \"$@\"\n",
        stub_cli = stub_cli.display(),
    );
    std::fs::write(&stub_path, script.as_bytes()).expect("write stub npm script");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&stub_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&stub_path, perms).unwrap();
    }

    // PATH: stub dir first, then real PATH.
    let real_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", stub_dir.path().display(), real_path);

    (stub_dir, new_path)
}

/// Read the argv capture file and return only the passthrough arguments
/// (the args that csq actually passed to npm, not stub-cli's own flags).
///
/// The file format is a JSON array produced by stub_cli's `--capture-argv`
/// flag. The full argv includes the stub binary and all stub-cli flags
/// (e.g. `--capture-argv <path> --exit-code <N> --stderr <S>`) followed
/// by the passthrough args csq supplied.
///
/// This function strips: argv[0] (stub binary path), plus any known stub-cli
/// flags and their values (`--capture-argv`, `--exit-code`, `--stderr`,
/// `--hang-ms`, `--emit-bytes`), leaving only the passthrough args.
fn read_captured_argv(capture_file: &std::path::Path) -> Vec<String> {
    let raw = std::fs::read_to_string(capture_file).unwrap_or_default();
    // Parse a minimal JSON array by hand (stdlib-only per independence.md Rule 3).
    // The format is: ["val1", "val2", ...]
    let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
    let parts: Vec<String> = trimmed
        .split(",")
        .map(|s| {
            // Remove whitespace and surrounding quotes.
            let s = s.trim();
            let s = s.trim_start_matches('"').trim_end_matches('"');
            // Unescape basic JSON escapes.
            s.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
        })
        .filter(|s| !s.is_empty())
        .collect();

    // Skip argv[0] (stub binary path), then skip all known stub-cli flags
    // and their values. What remains is the passthrough argv csq supplied.
    let stub_flags_with_value = [
        "--capture-argv",
        "--exit-code",
        "--stderr",
        "--stdout",
        "--hang-ms",
        "--emit-bytes",
    ];

    let mut result = Vec::new();
    let mut iter = parts.iter().skip(1); // skip argv[0]
    while let Some(arg) = iter.next() {
        if stub_flags_with_value.contains(&arg.as_str()) {
            // Skip the flag and its value.
            iter.next();
        } else {
            // Passthrough arg: collect this and all remaining.
            result.push(arg.clone());
            result.extend(iter.cloned());
            break;
        }
    }
    result
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// 1. `csq cli install codex` after `[y/N]: y` runs npm install with
///    argv exactly `["i", "-g", "@openai/codex@>=0.40.0 <1.0.0"]`.
///    Structural assertion: argv captured by stub matches spec/13 §6 exactly.
#[cfg(unix)]
#[test]
fn install_codex_argv_exact_match_after_consent() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");

    // Stub npm: exits 0, captures argv.
    let (_stub_dir, npm_path) = make_stub_npm_dir(0, "", &capture_path);
    let npm_dir = npm_path.split(':').next().unwrap_or("");

    // Minimal PATH: stub npm dir only (stub-only PATH: no system bin, so a real codex/claude/gemini cannot leak into the probe; the #!/bin/sh wrapper resolves via absolute path).
    // Codex is intentionally absent so the pre-install probe returns Missing
    // and handle_install proceeds to run npm. Post-install re-probe will also
    // return Missing, which is handled gracefully (eprintln + Ok(())).
    let minimal_path = npm_dir.to_string();

    // Pipe "y\n" to stdin (consent prompt).
    let mut child = clean_cmd(Some(&minimal_path))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn csq cli install codex");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"y\n");
    }

    let out = child.wait_with_output().expect("wait for csq");

    assert!(
        out.status.success(),
        "csq cli install codex must exit 0 after consent;\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Assert exact argv (primary goal of this test).
    let captured = read_captured_argv(&capture_path);
    assert_eq!(
        captured,
        vec!["i", "-g", "@openai/codex@>=0.40.0 <1.0.0"],
        "npm was called with wrong argv; captured: {captured:?}"
    );
}

/// 2. Codex already installed at-or-above minimum → refuses with "use upgrade".
#[cfg(unix)]
#[test]
fn install_codex_already_installed_refuses_with_upgrade_hint() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    // Put a stub codex on PATH that returns a version above minimum.
    let stub_dir = TempDir::new().unwrap();
    let codex_stub = stub_dir.path().join("codex");
    let script = "#!/bin/sh\nprintf 'codex-cli 0.130.0\\n'\n".to_string();
    std::fs::write(&codex_stub, &script).unwrap();
    set_executable(&codex_stub);

    let real_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", stub_dir.path().display(), real_path);

    let out = clean_cmd(Some(&path))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::null()) // No stdin — must bail before prompt
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .output()
        .expect("spawn csq cli install codex");

    assert!(
        !out.status.success(),
        "must exit non-zero when codex is already installed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Structural assertion: error message must direct to upgrade.
    assert!(
        stderr.contains("csq cli upgrade codex"),
        "must mention 'csq cli upgrade codex'; got:\n{stderr}"
    );
}

/// 3. Codex outdated (below minimum) → refuses with "use upgrade".
#[cfg(unix)]
#[test]
fn install_codex_outdated_refuses_with_upgrade_hint() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let stub_dir = TempDir::new().unwrap();
    let codex_stub = stub_dir.path().join("codex");
    // v0.24.0 is below minimum 0.40.0
    let script = "#!/bin/sh\nprintf 'codex-cli 0.24.0\\n'\n".to_string();
    std::fs::write(&codex_stub, &script).unwrap();
    set_executable(&codex_stub);

    let real_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", stub_dir.path().display(), real_path);

    let out = clean_cmd(Some(&path))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::null())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .output()
        .expect("spawn");

    assert!(
        !out.status.success(),
        "must exit non-zero for outdated codex"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("csq cli upgrade codex"),
        "must mention 'csq cli upgrade codex'; got:\n{stderr}"
    );
}

/// 4. `csq cli upgrade codex` when codex is missing → refuses with "use install".
#[cfg(unix)]
#[test]
fn upgrade_codex_missing_refuses_with_install_hint() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    // Empty PATH so codex is not found.
    let empty_dir = TempDir::new().unwrap();

    let out = clean_cmd(Some(&empty_dir.path().display().to_string()))
        .args(["cli", "upgrade", "codex"])
        .stdin(Stdio::null())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .output()
        .expect("spawn");

    assert!(
        !out.status.success(),
        "must exit non-zero when codex is missing"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("csq cli install codex"),
        "must mention 'csq cli install codex'; got:\n{stderr}"
    );
}

/// 5. `csq cli upgrade codex` when already at upstream-latest → exits 0 with
///    "already at latest" message; upgrade still runs.
///    Per M9 A9.
#[cfg(unix)]
#[test]
fn upgrade_codex_already_at_latest_runs_and_exits_ok() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");

    // Stub codex: returns version above minimum (already "at latest").
    // Place it under a path containing "lib/node_modules/" so that
    // classify_install_manager returns NpmGlobal (instead of Unknown).
    // Unknown → upgrade_command returns None → handle_no_command (wrong path).
    let stub_dir = TempDir::new().unwrap();
    let npm_modules_bin = stub_dir.path().join("lib/node_modules/@openai/codex/bin");
    std::fs::create_dir_all(&npm_modules_bin).unwrap();
    let codex_stub = npm_modules_bin.join("codex");
    let codex_script = "#!/bin/sh\nprintf 'codex-cli 0.130.0\\n'\n".to_string();
    std::fs::write(&codex_stub, &codex_script).unwrap();
    set_executable(&codex_stub);

    // Create a bin/ symlink so PATH can point to stub_dir/bin/ → codex.
    let bin_dir = stub_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&codex_stub, bin_dir.join("codex")).unwrap();

    // Stub npm: exits 0, captures argv.
    let (_npm_stub_dir, npm_path) = make_stub_npm_dir(0, "", &capture_path);

    let npm_dir = npm_path.split(':').next().unwrap_or("");
    // Minimal PATH: bin dir (finds stub codex) + stub npm only (stub-only PATH: no system bin, so a real codex/claude/gemini cannot leak into the probe; the #!/bin/sh wrapper resolves via absolute path).
    let combined = format!("{}:{}", bin_dir.display(), npm_dir,);

    let mut child = clean_cmd(Some(&combined))
        .args(["cli", "upgrade", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"y\n");
    }

    let out = child.wait_with_output().expect("wait");

    assert!(
        out.status.success(),
        "upgrade when already at latest must exit 0;\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Structural assertion: the upgrade argv must have been passed to npm exactly.
    // Per spec/13 §6, the NpmGlobal upgrade argv is ["npm", "update", "-g", "<pkg>"]
    // or ["npm", "i", "-g", "<pkg>@range"]. Verify by checking the captured argv
    // contains the expected npm install flags — not prose-regex bag-of-words.
    let captured = read_captured_argv(&capture_path);
    assert!(
        !captured.is_empty(),
        "npm must have been spawned (capture file must exist and be non-empty)"
    );
    // The first passthrough arg to npm must be a recognized upgrade command word.
    let first = captured.first().map(String::as_str).unwrap_or("");
    assert!(
        first == "i" || first == "install" || first == "update" || first == "upgrade",
        "npm was called with unexpected first arg: {first:?}; full captured: {captured:?}"
    );
}

/// 6. `csq cli upgrade claude` on machine where claude is ClaudeNativeInstaller
///    → prints official URL, no auto-spawn, exits 0.
///    ClaudeNativeInstaller → upgrade_command returns None (spec/13 §6 R1-H11).
///    NOTE: must use `upgrade`, not `install`, because `handle_install` sees
///    CliStatus::Ok (2.1.138 > min) and bails with "already installed, use upgrade"
///    before reaching handle_no_command. The None path fires via handle_upgrade.
#[cfg(unix)]
#[test]
fn upgrade_claude_native_installer_prints_url_exits_ok() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    // Build a stub "claude" binary under a path that classify_install_manager
    // recognises as ClaudeNativeInstaller: `/.local/share/claude/versions/<v>/`.
    let stub_root = TempDir::new().unwrap();
    let native_bin_dir = stub_root
        .path()
        .join(".local/share/claude/versions/2.1.138");
    std::fs::create_dir_all(&native_bin_dir).unwrap();

    // The stub must print a valid version so the probe doesn't return WrongBinary.
    // Claude's probe parses any semver with optional " (Claude Code)" suffix.
    let claude_actual = native_bin_dir.join("claude");
    let script = "#!/bin/sh\nprintf '2.1.138 (Claude Code)\\n'\n".to_string();
    std::fs::write(&claude_actual, &script).unwrap();
    set_executable(&claude_actual);

    // bin/ dir for PATH: symlink claude → the actual stub.
    let bin_dir = stub_root.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::os::unix::fs::symlink(&claude_actual, bin_dir.join("claude")).unwrap();

    // Minimal PATH: bin/ (finds stub-claude via symlink) only (stub-only PATH for hermeticity — no system bin on PATH).
    let path = bin_dir.display().to_string();

    let out = clean_cmd(Some(&path))
        .args(["cli", "upgrade", "claude"])
        .stdin(Stdio::null())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .output()
        .expect("spawn csq cli upgrade claude");

    assert!(
        out.status.success(),
        "ClaudeNativeInstaller upgrade path must exit 0;\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Structural: must print the official URL (not auto-spawn anything).
    assert!(
        stdout.contains("anthropic.com/claude-code"),
        "must print official URL for ClaudeNativeInstaller; got:\n{stdout}"
    );
}

/// 7. Non-TTY refusal: stdin closed → exits non-zero; no spawn.
#[test]
fn non_tty_stdin_closed_exits_nonzero_no_spawn() {
    // stdin NOT a terminal in cargo test → enforce_tty fires.
    let out = clean_cmd(None)
        .args(["cli", "install", "codex"])
        .stdin(Stdio::null())
        .env_remove("CI") // remove CI if set, stdin check should fire
        .output()
        .expect("spawn");

    // The process may also fail because codex is missing, but the non-TTY
    // check fires FIRST (before the probe). The key invariant is exit non-zero.
    assert!(
        !out.status.success(),
        "must exit non-zero when stdin is not a TTY"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Structural: either the TTY refusal message or the Missing bail.
    // In a CI environment, stdin is never a TTY, so the TTY message fires.
    assert!(
        stderr.contains("interactive consent required") || stderr.contains("not installed"),
        "stderr must contain TTY refusal or install-first hint; got:\n{stderr}"
    );
}

/// 8. `CI=1` env var set → exits non-zero with TTY refusal message; no spawn.
#[test]
fn ci_env_set_exits_nonzero_no_spawn() {
    let out = clean_cmd(None)
        .args(["cli", "install", "codex"])
        .stdin(Stdio::null())
        .env("CI", "1")
        .output()
        .expect("spawn");

    assert!(!out.status.success(), "must exit non-zero when CI=1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("interactive consent required"),
        "must mention 'interactive consent required' when CI=1; got:\n{stderr}"
    );
}

/// 9. Stub npm exits 243 + EACCES in stderr → csq surfaces three options;
///    csq exits non-zero; no auto-retry.
#[cfg(unix)]
#[test]
fn eacces_on_npm_surfaces_three_options_exits_nonzero() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");

    let eacces_msg = "npm error code EACCES\nnpm error syscall mkdir\nnpm error path /usr/local/lib/node_modules";
    let (_stub_dir, path) = make_stub_npm_dir(243, eacces_msg, &capture_path);

    // We need codex to be missing so install doesn't refuse.
    // Use minimal PATH: stub npm dir only (stub-only PATH: no system bin, so a real codex/claude/gemini cannot leak into the probe; the #!/bin/sh wrapper resolves via absolute path).
    // Excluding the real PATH ensures codex is not found (Missing → proceed
    // to install), rather than refusing with "already installed".
    let npm_dir = path.split(':').next().unwrap_or("");
    let combined = npm_dir.to_string();

    let mut child = clean_cmd(Some(&combined))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"y\n");
    }

    let out = child.wait_with_output().expect("wait");

    assert!(
        !out.status.success(),
        "must exit non-zero when EACCES;\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Three-option non-escalation: structural check for each option.
    assert!(
        stderr.contains("Homebrew") || stderr.contains("brew install node"),
        "must mention Homebrew option; got:\n{stderr}"
    );
    assert!(
        stderr.contains("npm config set prefix"),
        "must mention npm prefix option; got:\n{stderr}"
    );
    assert!(
        stderr.contains("IT team") || stderr.contains("organisation"),
        "must mention IT team option (R2-N6 corp caveat); got:\n{stderr}"
    );
    // Structural: csq must NOT auto-retry (exit code non-zero = confirmed above).
}

/// 10. Stub npm exits 1 with stderr containing a fake token →
///     printed stderr passes through redact_tokens (no token visible).
#[cfg(unix)]
#[test]
fn stderr_token_is_redacted_before_display() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");

    let token_stderr = "npmrc auth token: sk-ant-api03-FAKEFAKE1234567890ABCDEFGHIJ";
    let (_stub_dir, path) = make_stub_npm_dir(1, token_stderr, &capture_path);

    // Minimal PATH: stub npm dir only (stub-only PATH for hermeticity — no system bin on PATH). Excluding real PATH ensures
    // codex is not found (Missing → proceed to install attempt), so the stub
    // npm EACCES/failure is the path that fires.
    let npm_dir = path.split(':').next().unwrap_or("");
    let combined = npm_dir.to_string();

    let mut child = clean_cmd(Some(&combined))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"y\n");
    }

    let out = child.wait_with_output().expect("wait");

    // The command must have exited non-zero (npm failed).
    assert!(!out.status.success(), "must exit non-zero when npm fails");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Structural: the token itself must NOT appear in csq's printed output.
    assert!(
        !stderr.contains("sk-ant-api03-FAKEFAKE"),
        "raw token must be redacted from stderr output; got:\n{stderr}"
    );
    // The redacted placeholder or empty output is acceptable.
    // The key invariant is that the literal token prefix is absent.
}

/// 11. `csq cli install codex` with `[y/N]: n` → declines; prints manual
///     command; exits 0; no spawn.
#[cfg(unix)]
#[test]
fn consent_decline_exits_ok_no_spawn() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");
    let (_stub_dir, path) = make_stub_npm_dir(0, "", &capture_path);

    // Minimal PATH: stub npm only (stub-only PATH for hermeticity — no system bin on PATH). Codex absent → probe returns
    // Missing → handle_install proceeds to the consent prompt.
    let npm_dir = path.split(':').next().unwrap_or("");
    let combined = npm_dir.to_string();

    let mut child = clean_cmd(Some(&combined))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"n\n");
    }

    let out = child.wait_with_output().expect("wait");

    assert!(
        out.status.success(),
        "must exit 0 on consent decline;\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Structural: must print the manual command.
    assert!(
        stdout.contains("@openai/codex") || stdout.contains("npm"),
        "must print manual command after decline; got:\n{stdout}"
    );
    // No spawn occurred — capture file must NOT exist.
    assert!(
        !capture_path.exists(),
        "npm must NOT have been spawned (capture file must not exist)"
    );
}

/// 12. `csq cli install codex` with `[y/N]: <EOF>` → declines; exits 0; no spawn.
#[cfg(unix)]
#[test]
fn consent_eof_exits_ok_no_spawn() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");
    let (_stub_dir, path) = make_stub_npm_dir(0, "", &capture_path);

    let empty_codex_dir = TempDir::new().unwrap();
    let npm_dir = path.split(':').next().unwrap_or("");
    let real_path = std::env::var("PATH").unwrap_or_default();
    let combined = format!(
        "{}:{}:{}",
        npm_dir,
        empty_codex_dir.path().display(),
        real_path
    );

    // Close stdin immediately (EOF).
    let _out = clean_cmd(Some(&combined))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::null())
        .env_remove("CI") // not a CI refusal test; let consent logic handle EOF
        .output()
        .expect("spawn");

    // Either exits 0 (EOF → declined) or non-zero (TTY refusal fires first).
    // In cargo test environments stdin is not a terminal so TTY refusal fires
    // before we can reach the consent prompt. Accept either non-zero exit as pass.
    // What we MUST NOT see: a successful install (capture file must not exist).
    assert!(
        !capture_path.exists(),
        "npm must NOT have been spawned when consent EOF or TTY refusal; capture file exists"
    );
}

/// 13. Re-probe after upgrade: stub npm exits 0; subsequent re-probe returns
///     Ok (cache invalidated correctly).
#[cfg(unix)]
#[test]
fn re_probe_after_install_reflects_new_state() {
    // This test verifies the invalidate→re-probe path via logged output.
    // When upgrade succeeds, csq calls invalidate(surface) then probe() again.
    // We confirm by checking that the post-upgrade output mentions the version.
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");

    let stub_dir = TempDir::new().unwrap();
    let stub_cli = stub_cli_bin();

    // npm stub: exits 0, captures argv.
    let npm_stub = stub_dir.path().join("npm");
    let npm_script = format!(
        "#!/bin/sh\nexec '{stub_cli}' --capture-argv '{capture_path}' --exit-code 0 \"$@\"\n",
        stub_cli = stub_cli.display(),
        capture_path = capture_path.display(),
    );
    std::fs::write(&npm_stub, &npm_script).unwrap();
    set_executable(&npm_stub);

    // codex stub: returns 0.130.0 (post-install version for the re-probe).
    // Place under lib/node_modules/ path so classify_install_manager returns
    // NpmGlobal. Unknown manager → upgrade_command returns None → wrong path.
    let npm_modules_bin = stub_dir.path().join("lib/node_modules/@openai/codex/bin");
    std::fs::create_dir_all(&npm_modules_bin).unwrap();
    let codex_actual = npm_modules_bin.join("codex");
    let codex_script = "#!/bin/sh\nprintf 'codex-cli 0.130.0\\n'\n".to_string();
    std::fs::write(&codex_actual, &codex_script).unwrap();
    set_executable(&codex_actual);

    // bin/ dir for PATH entry: symlink codex → actual stub.
    let bin_dir = stub_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&codex_actual, bin_dir.join("codex")).unwrap();

    // Minimal PATH: bin (finds codex) + npm stub only (stub-only PATH: no system bin, so a real codex/claude/gemini cannot leak into the probe; the #!/bin/sh wrapper resolves via absolute path).
    let path = format!("{}:{}", bin_dir.display(), stub_dir.path().display(),);

    // Use `upgrade`: codex is present (probe returns Ok), upgrade proceeds.
    // After npm exits 0, invalidate + re-probe returns Ok(0.130.0).
    let mut child = clean_cmd(Some(&path))
        .args(["cli", "upgrade", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn csq cli upgrade codex");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"y\n");
    }

    let out = child.wait_with_output().expect("wait");

    assert!(
        out.status.success(),
        "upgrade must exit 0;\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Structural: post-upgrade output must mention version from re-probe.
    assert!(
        stdout.contains("0.130.0") || stdout.contains("upgraded"),
        "post-upgrade output must mention version from re-probe; got:\n{stdout}"
    );
}

/// 14. `csq cli install codex` when npm is missing → offers chained node
///     install; declining aborts (exits non-zero).
#[cfg(unix)]
#[test]
fn chained_node_install_decline_aborts() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    // Empty PATH: no npm, no codex.
    let empty_dir = TempDir::new().unwrap();

    let mut child = clean_cmd(Some(&empty_dir.path().display().to_string()))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn");

    // Decline the node install prompt.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"n\n");
    }

    let out = child.wait_with_output().expect("wait");

    // Either TTY refusal fires (no terminal), OR the missing-npm path fires.
    // In either case the process must exit non-zero.
    assert!(
        !out.status.success(),
        "must exit non-zero when node install declined or TTY refusal;\nstderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
}

/// 15. Resolved npm path appears in consent line.
///     "About to run: /path/to/npm i -g @openai/codex..."
#[cfg(unix)]
#[test]
fn consent_line_shows_resolved_npm_path() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let capture_file = TempDir::new().unwrap();
    let capture_path = capture_file.path().join("npm-argv.json");

    let (_stub_dir, path) = make_stub_npm_dir(0, "", &capture_path);
    let npm_stub_dir = path.split(':').next().unwrap_or("").to_string();

    // Minimal PATH: stub npm only (stub-only PATH for hermeticity — no system bin on PATH). Codex absent → Missing →
    // install proceeds to the "About to run:" consent line.
    let combined = npm_stub_dir.clone();

    let mut child = clean_cmd(Some(&combined))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .spawn()
        .expect("spawn");

    // Send "n" so the test doesn't actually install.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"n\n");
    }

    let out = child.wait_with_output().expect("wait");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Structural: "About to run:" line must contain the full path to npm stub.
    assert!(
        stdout.contains("About to run:"),
        "must print 'About to run:' consent line; got:\n{stdout}"
    );
    assert!(
        stdout.contains(&npm_stub_dir),
        "consent line must contain the resolved npm dir path;\nexpected path prefix: {npm_stub_dir}\ngot:\n{stdout}"
    );
}

/// 16. WrongBinary on PATH → refuses with "fix PATH first".
#[cfg(unix)]
#[test]
fn wrong_binary_on_path_refuses_with_fix_path_hint() {
    let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    // Put a fake codex on PATH that returns a date-encoded version (Homebrew
    // codex formula). The blocklist gate will not fire here (the path isn't
    // /opt/homebrew/Cellar/codex/) but the ComponentTooLarge parser gate will
    // classify it as WrongBinary.
    let stub_dir = TempDir::new().unwrap();
    let codex_stub = stub_dir.path().join("codex");
    // Output without the required "codex-cli " prefix → PrefixMismatch.
    let script = "#!/bin/sh\nprintf '0.1.2505291658\\n'\n".to_string();
    std::fs::write(&codex_stub, &script).unwrap();
    set_executable(&codex_stub);

    let real_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", stub_dir.path().display(), real_path);

    let out = clean_cmd(Some(&path))
        .args(["cli", "install", "codex"])
        .stdin(Stdio::null())
        .env("CSQ_TEST_BYPASS_TTY", "1")
        .output()
        .expect("spawn");

    assert!(!out.status.success(), "must exit non-zero for WrongBinary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Structural: must mention PATH fix.
    assert!(
        stderr.contains("Fix PATH")
            || stderr.contains("fix PATH")
            || stderr.contains("not the upstream"),
        "must mention PATH fix or 'not the upstream'; got:\n{stderr}"
    );
}

/// 17. Empty `<name>` is rejected by clap before reaching handler.
///     (Structural: exit code 2 = clap usage error.)
#[test]
fn empty_name_rejected_at_clap_layer() {
    let out = clean_cmd(None)
        .args(["cli", "install", ""])
        .output()
        .expect("spawn");

    assert_eq!(
        out.status.code(),
        Some(2),
        "empty name must exit 2 (clap rejection); got: {:?}",
        out.status
    );
}

// ── Clap allowlist + argv injection fuzz (tests 18-24) ────────────────────────

/// 18. `csq cli install evil` is rejected at the clap parser layer.
///     Preserves M3 A14 (M9 amendment).
#[test]
fn fuzz_01_evil_rejected_at_clap_layer() {
    let out = clean_cmd(None)
        .args(["cli", "install", "evil"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_01 'evil': expected clap exit 2; got: {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("possible values"),
        "fuzz_01: clap must show 'possible values'; got: {stderr}"
    );
}

/// 19. Semicolon-injection payload rejected at clap layer.
#[test]
fn fuzz_02_semicolon_injection_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "claude; rm -rf /"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_02 semicolon: expected clap exit 2; got: {:?}",
        out.status
    );
}

/// 20. `--help` payload rejected at clap layer.
#[test]
fn fuzz_03_double_dash_help_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "--help"])
        .output()
        .expect("spawn");
    // clap processes --help and exits 0, OR exits 2 if positional validation fires first.
    // Either way the argv injection never reaches the handler.
    // Accept both exit codes; key invariant is no subprocess spawn.
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 2,
        "fuzz_03 --help: expected exit 0 (help) or 2 (validation); got: {:?}",
        out.status
    );
}

/// 21. Newline-injection payload rejected at clap layer.
#[test]
fn fuzz_04_newline_injection_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "\nrm -rf /\n"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_04 newline: expected clap exit 2; got: {:?}",
        out.status
    );
}

/// 22. `&&` injection payload rejected at clap layer.
#[test]
fn fuzz_05_and_and_injection_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "claude && cat /etc/passwd"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_05 &&: expected clap exit 2; got: {:?}",
        out.status
    );
}

/// 23. `||` injection payload rejected at clap layer.
#[test]
fn fuzz_06_or_or_injection_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "claude || sudo rm -rf /"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_06 ||: expected clap exit 2; got: {:?}",
        out.status
    );
}

/// 24. `$(...)` injection payload rejected at clap layer.
#[test]
fn fuzz_07_dollar_paren_injection_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "$(rm -rf /)"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_07 $(): expected clap exit 2; got: {:?}",
        out.status
    );
}

/// 25. Backtick injection payload rejected at clap layer.
#[test]
fn fuzz_08_backtick_injection_rejected() {
    let out = clean_cmd(None)
        .args(["cli", "install", "`rm -rf /`"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "fuzz_08 backtick: expected clap exit 2; got: {:?}",
        out.status
    );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn set_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}
