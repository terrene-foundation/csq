//! Integration tests for `csq login` CLI-deps pre-flight probe (PR-MCD2).
//!
//! Tests verify the disposition table from spec/13 §3 for both
//! `handle_codex` (via `csq login N --provider codex`) and
//! `handle_gemini_oauth` (via `csq login N --provider gemini`):
//!
//! | Variant               | Default               | `--ignore-cli-version` |
//! | --------------------- | --------------------- | ---------------------- |
//! | `Ok`                  | proceed (no bail)     | proceed (no bail)      |
//! | `Outdated`            | BAIL                  | WARN + proceed         |
//! | `UnrecognizedVersion` | BAIL                  | WARN + proceed         |
//! | `Missing`             | BAIL (unconditional)  | BAIL (unconditional)   |
//! | `WrongBinary`         | BAIL (unconditional)  | BAIL (unconditional)   |
//! | `ProbeTimedOut`       | WARN + proceed        | WARN + proceed         |
//!
//! Per `rules/probe-driven-verification.md` MUST 1: assertions are structural
//! (exit code + specific bail message patterns), NOT regex/keyword matches.
//!
//! Per `rules/testing.md` Rule 4a: subprocess commands use `env_clear()` +
//! whitelist to avoid inheriting live `CLAUDE_CONFIG_DIR`.
//!
//! Per `workspaces/multi-cli-deps/journal/0008-RISK-test-parallelism-vs-probe-timeout.md`:
//! all tests acquire the `SERIAL` mutex to prevent CPU-saturation flakes.
//!
//! ## Test strategy for interactive prompts
//!
//! `handle_codex` blocks on stdin Enter before the probe fires.
//! Tests that verify probe bail/warn pass a single `\n` on stdin so the Enter
//! unblocks, the probe fires, and the process exits.
//!
//! `handle_gemini_oauth` runs the probe first (no interactive prompt), then
//! calls `gemini::oauth_login::perform` which reads `~/.gemini/oauth_creds.json`.
//! In an isolated TempDir, that file does NOT exist, so a downstream error
//! always fires for successful-probe cases. Tests verify the probe bail was NOT
//! the exit cause.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

// Workspace-local serial mutex (journal 0008): cli_deps probe has a 2s
// timeout that races under cargo's parallel test load. All tests serialize
// on this mutex to prevent CPU-saturation flakes.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Binary path ──────────────────────────────────────────────────────────────

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

// ── Subprocess helper ────────────────────────────────────────────────────────

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
/// `rules/test-hermeticity.md` MUST 2 (sandbox HOME + CLAUDE_HOME, never parent).
/// Mirrors the pattern in `cli_deps_doctor_integration.rs`.
fn clean_cmd(path_override: Option<&str>) -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    // Sandbox HOME and CLAUDE_HOME — never re-inject the parent's live values.
    // Callers may still override CLAUDE_HOME per-test via `.env("CLAUDE_HOME", ...)`.
    cmd.env("HOME", sandbox_home());
    cmd.env("CLAUDE_HOME", sandbox_home());
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

// ── Stub helpers ─────────────────────────────────────────────────────────────

/// Write a shell script stub at `<stub_dir>/<name>` that prints `stdout_line`
/// and exits 0. Mirrors the helper in `cli_deps_doctor_integration.rs`.
#[cfg(unix)]
fn write_stub(stub_dir: &std::path::Path, name: &str, stdout_line: &str) -> PathBuf {
    let path = stub_dir.join(name);
    let line = stdout_line.trim_end_matches('\n');
    let escaped = line.replace('\'', "'\\''");
    let script = format!("#!/bin/sh\nprintf '%s\\n' '{escaped}'\n");
    std::fs::write(&path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// Write a shell stub that hangs for `hang_secs` seconds.
#[cfg(unix)]
fn write_hang_stub(stub_dir: &std::path::Path, name: &str, hang_secs: u64) -> PathBuf {
    let path = stub_dir.join(name);
    // Use a portable sleep; prefer /bin/sleep for the stub itself.
    let script = format!("#!/bin/sh\nsleep {hang_secs}\n");
    std::fs::write(&path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// Write a minimal Codex credential file (authenticated slot).
fn write_codex_cred(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json = r#"{"tokens":{"access_token":"codex-tok"}}"#;
    std::fs::write(dir.join(format!("codex-{n}.json")), json).unwrap();
}

/// Write a minimal Gemini credential file (authenticated slot).
fn write_gemini_cred(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json =
        r#"{"v":1,"auth":{"mode":"api_key"},"model_name":"auto","created_unix_secs":1714000000}"#;
    std::fs::write(dir.join(format!("gemini-{n}.json")), json).unwrap();
}

// ── KNOWN-BAIL assertion helper ──────────────────────────────────────────────

/// Assert that a login invocation bailed due to the pre-flight probe.
///
/// The exit code MUST be non-zero AND the combined (stdout + stderr) MUST
/// contain `expected_fragment`. This is a structural assertion, not a
/// prose-regex semantic check — `expected_fragment` MUST be a literal
/// fragment of the error message produced by `pre_flight_check`, not a
/// vague keyword.
fn assert_probe_bail(output: &std::process::Output, expected_fragment: &str, test_name: &str) {
    assert_ne!(
        output.status.code(),
        Some(0),
        "[{test_name}] expected non-zero exit from probe bail, got 0"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(expected_fragment),
        "[{test_name}] expected fragment {expected_fragment:?} not found in output;\n\
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Assert that a login invocation did NOT bail due to the pre-flight probe.
///
/// We cannot assert "exit 0" because downstream (OAuth, gemini credentials)
/// will also fail in our isolated tempdir. We instead assert that the
/// probe-bail fragment is ABSENT, confirming the probe gate was passed.
fn assert_no_probe_bail(output: &std::process::Output, absence_fragment: &str, test_name: &str) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains(absence_fragment),
        "[{test_name}] probe-bail fragment {absence_fragment:?} unexpectedly found in output;\n\
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// handle_codex tests (tests 1-12)
// ═══════════════════════════════════════════════════════════════════════════

/// (1) handle_codex: codex at minimum version (0.40.0) — probe Ok, no bail.
/// The downstream spawn will fail in our stub (stub exits 0 but there's no
/// ChatGPT OAuth session). We verify probe bail fragment is absent.
#[test]
#[cfg(unix)]
fn test_codex_01_ok_version_no_bail() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // Stub codex that echoes ok version then exits 0 (simulates the real binary).
    write_stub(stubs.path(), "codex", "codex-cli 0.40.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    // Send Enter to unblock the "Press Enter" prompt; probe fires next.
    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // Probe passed → bail fragment absent.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "codex_01_ok_version_no_bail",
    );
    assert_no_probe_bail(&output, "is not installed", "codex_01_ok_version_no_bail");
}

/// (2) handle_codex: outdated version (0.24.0) — probe Outdated, bail.
/// Must include "min 0.40.0" AND "csq cli upgrade codex" in output.
#[test]
#[cfg(unix)]
fn test_codex_02_outdated_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    assert_probe_bail(
        &output,
        "is below the minimum supported",
        "codex_02_outdated_bails",
    );
    assert_probe_bail(&output, "csq cli upgrade codex", "codex_02_outdated_bails");
    assert_probe_bail(&output, "0.40.0", "codex_02_outdated_bails");
}

/// (3) handle_codex: outdated + `--ignore-cli-version` — warn and proceed.
/// Bail fragment must be absent; WARN fragment must be present.
#[test]
#[cfg(unix)]
fn test_codex_03_outdated_with_ignore_flag_proceeds_with_warn() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex", "--ignore-cli-version"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // Probe bail did NOT fire.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "codex_03_ignore_flag",
    );

    // WARN emitted on every honor (spec/13 §3.1, R2-N3).
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("below minimum") && combined.contains("--ignore-cli-version honored"),
        "test_codex_03: expected WARN line containing 'below minimum' and '--ignore-cli-version honored'; got:\n{combined}"
    );
}

/// (4) handle_codex: unrecognized version — bail.
#[test]
#[cfg(unix)]
fn test_codex_04_unrecognized_version_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // Codex prefix is required ("codex-cli "); emit valid prefix but unparseable semver.
    write_stub(stubs.path(), "codex", "codex-cli not-a-version");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    assert_probe_bail(
        &output,
        "Cannot determine codex-cli version",
        "codex_04_unrecognized_bails",
    );
    assert_probe_bail(
        &output,
        "--ignore-cli-version",
        "codex_04_unrecognized_bails",
    );
}

/// (5) handle_codex: unrecognized + `--ignore-cli-version` — warn and proceed.
#[test]
#[cfg(unix)]
fn test_codex_05_unrecognized_with_ignore_flag_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli not-a-version");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex", "--ignore-cli-version"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    assert_no_probe_bail(
        &output,
        "Cannot determine codex-cli version",
        "codex_05_unrecognized_ignore",
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--ignore-cli-version honored"),
        "test_codex_05: expected WARN with '--ignore-cli-version honored'; got:\n{combined}"
    );
}

/// (6) handle_codex: codex missing — unconditional bail; flag has no effect.
#[test]
#[cfg(unix)]
fn test_codex_06_missing_bails_unconditionally() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // No codex binary in stubs dir.

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    assert_probe_bail(&output, "codex-cli is not installed", "codex_06_missing");
    assert_probe_bail(&output, "csq cli install codex", "codex_06_missing");
}

/// (6b) handle_codex: codex missing + `--ignore-cli-version` — still bails
/// (Missing is an unconditional bail; flag has no effect).
#[test]
#[cfg(unix)]
fn test_codex_06b_missing_with_ignore_still_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex", "--ignore-cli-version"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // Missing is always a bail.
    assert_probe_bail(
        &output,
        "codex-cli is not installed",
        "codex_06b_missing_ignore",
    );
}

/// (7) handle_codex: WrongBinary (PrefixMismatch via stub returning wrong prefix)
/// — unconditional bail mentioning PATH-shadowing.
#[test]
#[cfg(unix)]
fn test_codex_07_wrong_binary_prefix_mismatch_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // Output doesn't start with "codex-cli " → PrefixMismatch → WrongBinary.
    write_stub(stubs.path(), "codex", "not-codex 0.40.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    assert_probe_bail(&output, "which -a codex", "codex_07_wrong_binary_prefix");
}

/// (8) handle_codex: WrongBinary (ComponentTooLarge via date-encoded version)
/// — unconditional bail mentioning malformed semver.
#[test]
#[cfg(unix)]
fn test_codex_08_wrong_binary_component_too_large_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // Date-encoded version like homebrew formula codex: component > 5 digits.
    write_stub(stubs.path(), "codex", "codex-cli 0.1.2505291658");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // ComponentTooLarge → WrongBinary → unconditional bail.
    assert_probe_bail(
        &output,
        "malformed semver segment",
        "codex_08_component_too_large",
    );
    assert_probe_bail(&output, "2505291658", "codex_08_component_too_large");
}

/// (9) handle_codex: probe times out (stub hangs > 2s) — ProbeTimedOut,
/// spawn proceeds with WARN (don't punish slow upstream `--version`, R1-C1).
#[test]
#[cfg(unix)]
fn test_codex_09_probe_timeout_warns_and_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // Hang for 3 seconds — exceeds the 2s probe budget → ProbeTimedOut.
    write_hang_stub(stubs.path(), "codex", 3);

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // Probe bail did NOT fire (ProbeTimedOut proceeds).
    assert_no_probe_bail(&output, "codex-cli is not installed", "codex_09_timeout");
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "codex_09_timeout",
    );

    // WARN emitted.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("probe timed out"),
        "test_codex_09: expected 'probe timed out' WARN; got:\n{combined}"
    );
}

/// (10) handle_codex: probe disabled via env — proceeds with disclosure WARN,
/// exactly one probe-disabled line in stderr.
#[test]
#[cfg(unix)]
fn test_codex_10_probe_disabled_proceeds_with_disclosure() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    // Stub version that would be outdated — but probe is disabled.
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["login", "1", "--provider", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // Probe bail did NOT fire.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "codex_10_probe_disabled",
    );

    // Probe-disabled disclosure appears on stderr (emitted by probe() per R2-N4).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("probe disabled"),
        "test_codex_10: expected 'probe disabled' in stderr; got:\n{stderr}"
    );
}

/// (11) handle_codex: ok version + `--ignore-cli-version` set — flag is
/// a no-op for happy path; no WARN line emitted.
#[test]
#[cfg(unix)]
fn test_codex_11_ok_version_with_flag_no_warn() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.40.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex", "--ignore-cli-version"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // No probe bail.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "codex_11_ok_ignore_no_warn",
    );
    // No WARN for ignore-cli-version on an Ok result.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("--ignore-cli-version honored"),
        "test_codex_11: WARN must not fire when probe returns Ok; got:\n{combined}"
    );
}

/// (12) handle_codex: WrongBinary with `--ignore-cli-version` — still bails
/// (WrongBinary is an unconditional bail; flag has no effect).
#[test]
#[cfg(unix)]
fn test_codex_12_wrong_binary_with_ignore_still_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "not-codex 0.40.0");

    let mut child = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1", "--provider", "codex", "--ignore-cli-version"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn csq login");

    {
        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("failed to wait");

    // WrongBinary is unconditional — flag has no effect.
    assert_probe_bail(&output, "which -a codex", "codex_12_wrong_binary_ignore");
}

// ═══════════════════════════════════════════════════════════════════════════
// handle_gemini_oauth tests (tests 13-22)
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: run `csq login N --provider gemini` with the given PATH and base dir.
/// Returns the output. Since gemini probe fires before the credential check,
/// tests that verify bail can assert immediately. Tests that verify proceed
/// will see a downstream error from the missing `~/.gemini/oauth_creds.json`.
#[cfg(unix)]
fn run_gemini_login(
    base: &std::path::Path,
    path_override: &str,
    extra_args: &[&str],
    extra_env: Option<(&str, &str)>,
) -> std::process::Output {
    let mut cmd = clean_cmd(Some(path_override));
    cmd.env("CSQ_BASE_DIR", base);
    cmd.args(["login", "1", "--provider", "gemini"]);
    cmd.args(extra_args);
    if let Some((k, v)) = extra_env {
        cmd.env(k, v);
    }
    // gemini handler has no interactive Enter prompt — runs probe immediately.
    cmd.output().expect("failed to spawn csq login gemini")
}

/// (13) handle_gemini: gemini at minimum version (0.41.2) — probe Ok, no bail.
/// Downstream errors (missing ~/.gemini/oauth_creds.json) are expected.
#[test]
#[cfg(unix)]
fn test_gemini_13_ok_version_no_bail() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    write_stub(stubs.path(), "gemini", "0.41.2");

    let output = run_gemini_login(base.path(), stubs.path().to_str().unwrap(), &[], None);

    // Probe passed — no probe-bail fragment. Use "csq cli install gemini" as the
    // structural discriminator: the probe bail message always includes it, but the
    // downstream OAuth error ("gemini-cli is not installed or its layout has changed")
    // does NOT include it.
    assert_no_probe_bail(&output, "csq cli install gemini", "gemini_13_ok");
    assert_no_probe_bail(&output, "is below the minimum supported", "gemini_13_ok");
}

/// (14) handle_gemini: outdated version (0.38.0) — probe Outdated, bail.
#[test]
#[cfg(unix)]
fn test_gemini_14_outdated_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    write_stub(stubs.path(), "gemini", "0.38.0");

    let output = run_gemini_login(base.path(), stubs.path().to_str().unwrap(), &[], None);

    assert_probe_bail(
        &output,
        "is below the minimum supported",
        "gemini_14_outdated",
    );
    assert_probe_bail(&output, "csq cli upgrade gemini", "gemini_14_outdated");
    assert_probe_bail(&output, "0.41.2", "gemini_14_outdated");
}

/// (15) handle_gemini: outdated + `--ignore-cli-version` — warn and proceed.
#[test]
#[cfg(unix)]
fn test_gemini_15_outdated_with_ignore_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    write_stub(stubs.path(), "gemini", "0.38.0");

    let output = run_gemini_login(
        base.path(),
        stubs.path().to_str().unwrap(),
        &["--ignore-cli-version"],
        None,
    );

    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "gemini_15_outdated_ignore",
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("below minimum") && combined.contains("--ignore-cli-version honored"),
        "test_gemini_15: expected WARN with 'below minimum' + '--ignore-cli-version honored'; got:\n{combined}"
    );
}

/// (16) handle_gemini: unrecognized version — bail.
#[test]
#[cfg(unix)]
fn test_gemini_16_unrecognized_version_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    // Gemini has no required prefix; any non-semver output → UnrecognizedVersion.
    write_stub(stubs.path(), "gemini", "not-a-version");

    let output = run_gemini_login(base.path(), stubs.path().to_str().unwrap(), &[], None);

    assert_probe_bail(
        &output,
        "Cannot determine gemini-cli version",
        "gemini_16_unrecognized",
    );
    assert_probe_bail(&output, "--ignore-cli-version", "gemini_16_unrecognized");
}

/// (17) handle_gemini: unrecognized + `--ignore-cli-version` — warn and proceed.
#[test]
#[cfg(unix)]
fn test_gemini_17_unrecognized_with_ignore_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    write_stub(stubs.path(), "gemini", "not-a-version");

    let output = run_gemini_login(
        base.path(),
        stubs.path().to_str().unwrap(),
        &["--ignore-cli-version"],
        None,
    );

    assert_no_probe_bail(
        &output,
        "Cannot determine gemini-cli version",
        "gemini_17_unrecognized_ignore",
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--ignore-cli-version honored"),
        "test_gemini_17: expected WARN '--ignore-cli-version honored'; got:\n{combined}"
    );
}

/// (18) handle_gemini: gemini missing — unconditional bail.
#[test]
#[cfg(unix)]
fn test_gemini_18_missing_bails_unconditionally() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    // No gemini binary.

    let output = run_gemini_login(base.path(), stubs.path().to_str().unwrap(), &[], None);

    assert_probe_bail(&output, "gemini-cli is not installed", "gemini_18_missing");
    assert_probe_bail(&output, "csq cli install gemini", "gemini_18_missing");
}

/// (19) handle_gemini: missing + `--ignore-cli-version` — still bails
/// (Missing is unconditional).
#[test]
#[cfg(unix)]
fn test_gemini_19_missing_with_ignore_still_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);

    let output = run_gemini_login(
        base.path(),
        stubs.path().to_str().unwrap(),
        &["--ignore-cli-version"],
        None,
    );

    assert_probe_bail(
        &output,
        "gemini-cli is not installed",
        "gemini_19_missing_ignore",
    );
}

/// (20) handle_gemini: probe times out (hang stub > 2s) — ProbeTimedOut,
/// proceeds with WARN (R1-C1).
#[test]
#[cfg(unix)]
fn test_gemini_20_probe_timeout_warns_and_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    write_hang_stub(stubs.path(), "gemini", 3);

    let output = run_gemini_login(base.path(), stubs.path().to_str().unwrap(), &[], None);

    // Probe bail did NOT fire. Use the same structural discriminator as test 13:
    // probe bail for Missing includes "csq cli install gemini"; downstream OAuth
    // errors do not.
    assert_no_probe_bail(&output, "csq cli install gemini", "gemini_20_timeout");
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "gemini_20_timeout",
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("probe timed out"),
        "test_gemini_20: expected 'probe timed out' WARN; got:\n{combined}"
    );
}

/// (21) handle_gemini: probe disabled via env — proceeds with disclosure WARN.
#[test]
#[cfg(unix)]
fn test_gemini_21_probe_disabled_proceeds_with_disclosure() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    // Outdated stub — would fail without disable.
    write_stub(stubs.path(), "gemini", "0.38.0");

    let output = run_gemini_login(
        base.path(),
        stubs.path().to_str().unwrap(),
        &[],
        Some(("CSQ_CLI_DEPS_PROBE_DISABLE", "1")),
    );

    // Probe bail did NOT fire.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "gemini_21_probe_disabled",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("probe disabled"),
        "test_gemini_21: expected 'probe disabled' disclosure in stderr; got:\n{stderr}"
    );
}

/// (22) handle_gemini: ok version + `--ignore-cli-version` — flag is no-op,
/// no WARN emitted for happy path.
#[test]
#[cfg(unix)]
fn test_gemini_22_ok_with_ignore_no_warn() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_gemini_cred(base.path(), 1);
    write_stub(stubs.path(), "gemini", "0.41.2");

    let output = run_gemini_login(
        base.path(),
        stubs.path().to_str().unwrap(),
        &["--ignore-cli-version"],
        None,
    );

    // No probe bail.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "gemini_22_ok_ignore",
    );
    // No WARN for Ok + flag.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("--ignore-cli-version honored"),
        "test_gemini_22: WARN must not fire when probe returns Ok; got:\n{combined}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// handle_direct (Anthropic) end-to-end fresh-install test (#633)
// ═══════════════════════════════════════════════════════════════════════════

/// Write a stub `claude` binary that simulates `claude auth login`: on
/// invocation it writes the OAuth `.credentials.json` + `.claude.json`
/// (with `oauthAccount.emailAddress`) into `$CLAUDE_CONFIG_DIR` and exits 0
/// — exactly what real CC does after a successful browser auth. This lets
/// the FULL Anthropic `handle_direct` path run end-to-end without real OAuth.
#[cfg(unix)]
fn write_claude_auth_stub(stub_dir: &std::path::Path, creds_json: &str, email: &str) -> PathBuf {
    let path = stub_dir.join("claude");
    // Single-quote the heredoc delimiters so the shell does not expand the
    // JSON payloads; escape any embedded single quotes in creds_json.
    let creds_escaped = creds_json.replace('\'', "'\\''");
    let claude_json = format!(r#"{{"oauthAccount":{{"emailAddress":"{email}"}}}}"#);
    let claude_json_escaped = claude_json.replace('\'', "'\\''");
    // The stub only acts on `auth login`; any other invocation exits 0 quietly.
    // No `mkdir` — `handle_direct` creates `config-N` before spawning, and the
    // test PATH is the stub dir only (no /bin), so external commands are absent.
    // `printf`, `[`, and `exit` are POSIX-sh builtins → the stub is PATH-independent.
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = \"auth\" ] && [ \"$2\" = \"login\" ]; then\n\
         printf '%s' '{creds_escaped}' > \"$CLAUDE_CONFIG_DIR/.credentials.json\"\n\
         printf '%s' '{claude_json_escaped}' > \"$CLAUDE_CONFIG_DIR/.claude.json\"\n\
         fi\n\
         exit 0\n"
    );
    std::fs::write(&path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// (25) #633 regression — the originating bug: on a FRESH install (empty
/// profiles.json, no `by_slot` mapping), the first `csq login N` (Anthropic)
/// must complete and persist credentials. Before the fix, `save_canonical_for`
/// fail-closed on the absent UUID (M4-12) because the mint ran only in
/// `finalize` AFTER the save → "no credentials configured".
///
/// This drives the REAL `handle_direct` → stub-`claude auth login` →
/// `ensure_login_identity_minted` → `save_canonical_for` chain end-to-end.
#[test]
#[cfg(unix)]
fn test_anthropic_25_fresh_install_login_mints_uuid_and_persists_creds() {
    use csq_core::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use csq_core::types::{AccessToken, RefreshToken};

    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    // Serialize a real CredentialFile so the stub writes a byte-shape that
    // credentials::load actually parses (no hand-rolled rename guesswork).
    let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
        claude_ai_oauth: OAuthPayload {
            access_token: AccessToken::new("sk-ant-oat01-e2e-633".into()),
            refresh_token: RefreshToken::new("sk-ant-ort01-e2e-633".into()),
            expires_at: 4_102_444_800_000, // 2100-01-01 — no time-bomb (testing.md Rule 1)
            scopes: vec!["user:inference".into()],
            subscription_type: Some("max".into()),
            rate_limit_tier: None,
            extra: std::collections::HashMap::new(),
        },
        extra: std::collections::HashMap::new(),
    });
    let creds_json = serde_json::to_string(&creds).unwrap();

    write_claude_auth_stub(stubs.path(), &creds_json, "e2e-633@test.invalid");

    // FRESH install: empty base, no profiles.json, no by_slot mapping.
    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["login", "1"]) // no --provider → Anthropic handle_direct
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn csq login");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // 1. The command must SUCCEED (pre-fix: non-zero "no credentials configured").
    assert_eq!(
        output.status.code(),
        Some(0),
        "#633: fresh-install `csq login 1` must exit 0; got {:?}\noutput:\n{combined}",
        output.status.code()
    );

    // 2. The slot's UUID must be minted into profiles.json::by_slot.
    let profiles_path = base.path().join("profiles.json");
    let profiles_raw = std::fs::read_to_string(&profiles_path)
        .expect("#633: profiles.json must exist after login");
    let profiles: serde_json::Value = serde_json::from_str(&profiles_raw).unwrap();
    let uuid = profiles
        .get("by_slot")
        .and_then(|m| m.get("1"))
        .and_then(|v| v.as_str())
        .expect("#633: by_slot[\"1\"] must hold a minted UUID after fresh login");

    // 3. The canonical credential file must exist at the UUID-keyed path —
    //    proving save_canonical_for ran (it would have fail-closed pre-fix).
    let uuid_creds = base
        .path()
        .join("identities")
        .join(uuid)
        .join("credentials.json");
    assert!(
        uuid_creds.exists(),
        "#633: identities/{uuid}/credentials.json must exist after login;\noutput:\n{combined}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-cutting clap tests (tests 23-24)
// ═══════════════════════════════════════════════════════════════════════════

/// (23) clap rejects an unknown flag spelled like `--ignore-X-version`.
#[test]
fn test_clap_23_unknown_flag_rejected() {
    let out = Command::new(csq_bin())
        .args(["login", "1", "--provider", "codex", "--ignore-X-version"])
        .output()
        .expect("failed to spawn csq");

    assert_ne!(
        out.status.code(),
        Some(0),
        "clap must reject unknown flag --ignore-X-version"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // clap error for unknown argument.
    assert!(
        combined.contains("error") || combined.contains("unexpected"),
        "expected clap error for unknown flag; got:\n{combined}"
    );
}

/// (24) `--ignore-cli-version` appears in `csq login --help` output.
#[test]
fn test_clap_24_ignore_flag_in_help() {
    let out = Command::new(csq_bin())
        .args(["login", "--help"])
        .output()
        .expect("failed to spawn csq login --help");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ignore-cli-version"),
        "`csq login --help` must mention '--ignore-cli-version'; got:\n{stdout}"
    );
}
