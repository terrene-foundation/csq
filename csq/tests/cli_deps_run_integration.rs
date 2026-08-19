//! Integration tests for `csq run` CLI-deps pre-flight probe (PR-MCD2.5).
//!
//! Tests verify the disposition table from spec/13 §3 for `csq run`:
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
//! M9 A12 (WrongBinary for csq run not tested) is addressed here:
//! `test_run_r04_codex_wrong_binary_bails_unconditionally` and
//! `test_run_r04b_codex_wrong_binary_with_flag_still_bails`.
//!
//! Per `rules/testing.md` Rule 4a: subprocess commands use `env_clear()` +
//! whitelist to avoid inheriting live `CLAUDE_CONFIG_DIR`.
//!
//! Per `internal-design-docs`:
//! all tests acquire the `SERIAL` mutex to prevent CPU-saturation flakes.
//!
//! ## Strategy for distinguishing probe bails vs downstream errors
//!
//! When the probe bails, `csq run` exits non-zero with a structural message
//! such as "is below the minimum supported" or "is not installed". When the
//! probe passes, `csq run` fails downstream (daemon not running, missing
//! credentials, etc.) — those downstream messages are distinct. Tests assert
//! either the probe-bail fragment IS present (for bail cases) or IS ABSENT
//! while a different downstream-error fragment IS present (for proceed cases).

use std::path::PathBuf;
use std::process::Command;
#[cfg(unix)]
use tempfile::TempDir;

// Workspace-local serial mutex (an internal journal entry): cli_deps probe has a 2s
// timeout that races under cargo's parallel test load. All tests serialize
// on this mutex to prevent CPU-saturation flakes.
#[cfg(unix)]
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
#[cfg(unix)]
fn sandbox_home() -> std::path::PathBuf {
    static H: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    H.get_or_init(|| TempDir::new().expect("sandbox home"))
        .path()
        .to_path_buf()
}

/// Env-cleared command builder per `rules/testing.md` Rule 4a +
/// `rules/test-hermeticity.md` MUST 2 (sandbox HOME + CLAUDE_HOME, never parent).
#[cfg(unix)]
fn clean_cmd(path_override: Option<&str>) -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    // Hermetic: the spawned `csq` binary must NOT shell `security` against the
    // operator's real login keychain (per-user, not redirected by sandbox HOME).
    // See `rules/test-hermeticity.md` + keychain::keychain_mirror_disabled.
    cmd.env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1");
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
/// and exits 0.
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

/// Write a minimal Codex canonical credential file so `csq run` dispatches
/// to the Codex path. The file content just needs to exist (symlink_metadata
/// checks existence only, not content validity).
#[cfg(unix)]
fn write_codex_canonical(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json = r#"{"tokens":{"access_token":"codex-tok"}}"#;
    std::fs::write(dir.join(format!("codex-{n}.json")), json).unwrap();
}

/// Write a minimal Gemini canonical credential file so `surface_cli_for_slot`
/// returns Some(Gemini). Mirrors `write_codex_canonical` for the Gemini surface.
#[cfg(unix)]
fn write_gemini_canonical(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json =
        r#"{"v":1,"auth":{"mode":"oauth"},"model_name":"auto","created_unix_secs":1714000000}"#;
    std::fs::write(dir.join(format!("gemini-{n}.json")), json).unwrap();
}

/// Write a minimal Claude canonical credential file so `csq run` dispatches
/// to the Claude/Anthropic path.
#[cfg(unix)]
fn write_claude_canonical(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    // Minimal Anthropic credential shape; the daemon path may further read
    // config-N but the probe fires before that.
    let json = r#"{"claudeAiOauth":{"accessToken":"tok","refreshToken":"rtok","expiresAt":4102444800000,"scopes":[],"tokenType":"Bearer"}}"#;
    std::fs::write(dir.join(format!("{n}.json")), json).unwrap();
}

/// Write config-N/settings.json with ANTHROPIC_BASE_URL pointing at localhost
/// (Ollama pattern) so `discover_per_slot_third_party` classifies it as 3P.
#[cfg(unix)]
fn write_third_party_settings(base: &std::path::Path, n: u16) {
    let config_dir = base.join(format!("config-{n}"));
    std::fs::create_dir_all(&config_dir).unwrap();
    // "localhost" is the Ollama classifier pattern in discovery.rs §provider_from_base_url.
    let json =
        r#"{"env":{"ANTHROPIC_BASE_URL":"http://localhost:11434","ANTHROPIC_AUTH_TOKEN":"key"}}"#;
    std::fs::write(config_dir.join("settings.json"), json).unwrap();
}

// ── Assertion helpers ────────────────────────────────────────────────────────

/// Assert that a `csq run` invocation bailed due to the pre-flight probe.
#[cfg(unix)]
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

/// Assert that the probe-bail fragment is absent (probe gate was passed).
///
/// We cannot assert exit 0 because downstream errors (daemon not running,
/// missing credentials, etc.) will cause non-zero exit even when probe passes.
#[cfg(unix)]
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
// Codex-slot csq run tests (R01–R09)
// ═══════════════════════════════════════════════════════════════════════════

/// (R01) csq run on Codex slot with codex at minimum version (0.40.0) →
/// probe Ok, no bail. Downstream fails (daemon not running) — that's expected.
#[test]
#[cfg(unix)]
fn test_run_r01_codex_ok_version_no_bail() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.40.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // Probe passed → bail fragment absent.
    assert_no_probe_bail(&output, "is below the minimum supported", "run_r01_ok");
    assert_no_probe_bail(&output, "codex-cli is not installed", "run_r01_ok");
}

/// (R02) csq run on Codex slot with outdated codex (0.24.0) → bail with
/// "min 0.40.0" + "csq cli upgrade codex" + "csq run".
#[test]
#[cfg(unix)]
fn test_run_r02_codex_outdated_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    assert_probe_bail(
        &output,
        "is below the minimum supported",
        "run_r02_outdated",
    );
    assert_probe_bail(&output, "csq cli upgrade codex", "run_r02_outdated");
    assert_probe_bail(&output, "0.40.0", "run_r02_outdated");
    assert_probe_bail(&output, "csq run", "run_r02_outdated");
}

/// (R03) csq run on Codex slot with outdated + `--ignore-cli-version` →
/// proceeds with WARN (bail fragment absent; WARN fragment present).
#[test]
#[cfg(unix)]
fn test_run_r03_codex_outdated_with_ignore_flag_warns_and_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1", "--ignore-cli-version"])
        .output()
        .expect("failed to spawn csq run");

    // Probe bail did NOT fire.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "run_r03_outdated_ignore",
    );

    // WARN emitted on every honor per spec/13 §3.1 (R2-N3).
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("below minimum") && combined.contains("--ignore-cli-version honored"),
        "run_r03: expected WARN 'below minimum' + '--ignore-cli-version honored'; got:\n{combined}"
    );
}

/// (R04) M9 A12: csq run on Codex slot with WrongBinary → bails with
/// same message shape as login WrongBinary. Flag has NO effect.
#[test]
#[cfg(unix)]
fn test_run_r04_codex_wrong_binary_bails_unconditionally() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    // Stub without "codex-cli " prefix → PrefixMismatch → WrongBinary.
    write_stub(stubs.path(), "codex", "not-codex 0.40.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // WrongBinary → unconditional bail; message mentions PATH-shadowing.
    assert_probe_bail(&output, "which -a codex", "run_r04_wrong_binary");
}

/// (R04b) M9 A12: WrongBinary + `--ignore-cli-version` → still bails
/// (WrongBinary is an unconditional bail; flag has no effect).
#[test]
#[cfg(unix)]
fn test_run_r04b_codex_wrong_binary_with_flag_still_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    write_stub(stubs.path(), "codex", "not-codex 0.40.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1", "--ignore-cli-version"])
        .output()
        .expect("failed to spawn csq run");

    // Flag has no effect on WrongBinary.
    assert_probe_bail(&output, "which -a codex", "run_r04b_wrong_binary_with_flag");
}

/// (R05) csq run on Codex slot with Missing (no codex on PATH) → bails with
/// "not installed" + "csq cli install codex". Flag has no effect.
#[test]
#[cfg(unix)]
fn test_run_r05_codex_missing_bails_unconditionally() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    // No codex stub → Missing.

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    assert_probe_bail(&output, "codex-cli is not installed", "run_r05_missing");
    assert_probe_bail(&output, "csq cli install codex", "run_r05_missing");
}

/// (R06) csq run on Claude slot with outdated claude (1.0.0) → bails
/// with claude-specific message naming "min 2.0.0".
#[test]
#[cfg(unix)]
fn test_run_r06_claude_slot_outdated_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_claude_canonical(base.path(), 1);
    // Claude 1.0.0 is below min 2.0.0 → Outdated.
    write_stub(stubs.path(), "claude", "1.0.0 (Claude Code)");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    assert_probe_bail(
        &output,
        "is below the minimum supported",
        "run_r06_claude_outdated",
    );
    assert_probe_bail(&output, "2.0.0", "run_r06_claude_outdated");
    assert_probe_bail(&output, "csq run", "run_r06_claude_outdated");
}

/// (R07) csq run on Claude slot with outdated + `--ignore-cli-version` →
/// proceeds with WARN.
#[test]
#[cfg(unix)]
fn test_run_r07_claude_slot_outdated_with_flag_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_claude_canonical(base.path(), 1);
    write_stub(stubs.path(), "claude", "1.0.0 (Claude Code)");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1", "--ignore-cli-version"])
        .output()
        .expect("failed to spawn csq run");

    // Probe bail did NOT fire.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "run_r07_claude_ignore",
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("below minimum") && combined.contains("--ignore-cli-version honored"),
        "run_r07: expected WARN; got:\n{combined}"
    );
}

/// (R08) csq run on Claude slot with claude at OK version (2.1.138) →
/// probe passes, no bail.
#[test]
#[cfg(unix)]
fn test_run_r08_claude_slot_ok_version_no_bail() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_claude_canonical(base.path(), 1);
    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // Probe passed → bail fragments absent.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "run_r08_claude_ok",
    );
    assert_no_probe_bail(&output, "claude-cli is not installed", "run_r08_claude_ok");
}

/// Regression for an internal ticket: `csq run <N>` against a slot with NO identity
/// record anywhere (no `config-N/`, no `credentials/N.json`, no
/// `profiles.json` `by_slot` entry — i.e. a deleted/never-configured slot)
/// MUST refuse with the "no identity record" error AND MUST NOT create
/// `config-N/` as a side effect of the refusal.
///
/// Pre-fix, `handle()` unconditionally ran `create_dir_all(config_dir)` +
/// wrote `.csq-account` / `.current-account` + called
/// `session::mark_onboarding_complete` (which writes a 36-byte
/// `.claude.json`) BEFORE checking `resolve_slot_to_uuid`, so this exact
/// invocation silently resurrected a byte-identical phantom `config-N/`
/// directory even though the command correctly refused to launch. The probe
/// (claude version check) passes first — via the stub below — so this test
/// reaches the identity gate under test rather than bailing earlier.
#[test]
#[cfg(unix)]
fn test_run_r08b_claude_slot_orphaned_no_identity_creates_no_config_dir() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    // Deliberately NOT calling write_claude_canonical / any config-N setup —
    // slot 99 has zero footprint anywhere under `base`.
    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");

    let config_dir = base.path().join("config-99");
    assert!(
        !config_dir.exists(),
        "precondition: config-99 must not exist before the run"
    );

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "99"])
        .output()
        .expect("failed to spawn csq run");

    assert_ne!(
        output.status.code(),
        Some(0),
        "run_r08b: expected non-zero exit for an orphaned slot"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("no identity record for account 99"),
        "run_r08b: expected the no-identity-record refusal; got:\n{combined}"
    );

    // The regression assertion: the refusal MUST NOT have created config-99
    // or any of the three phantom files (`.claude.json`, `.csq-account`,
    // `.current-account`) as a side effect.
    assert!(
        !config_dir.exists(),
        "run_r08b: config-99 was created despite the identity gate refusing \
         to launch — the pre-an internal ticket-fix phantom-slot bug has regressed"
    );
}

/// (R09) csq run on 3P slot → SKIPS pre-flight entirely (no probe spawn).
/// The 3P slot has no versioned CLI binary — probe must not fire.
/// Verification: the probe-bail for a missing binary is absent even when
/// no `claude` binary is on PATH.
#[test]
#[cfg(unix)]
fn test_run_r09_third_party_slot_skips_preflight() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap(); // empty — no claude/codex/gemini on PATH

    // Set up a 3P slot (no canonical credential files; just settings.json).
    write_third_party_settings(base.path(), 1);

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // If probe fired and detected Missing, we'd see "claude-cli is not installed".
    // Since 3P skips the probe, that message must be absent.
    assert_no_probe_bail(
        &output,
        "claude-cli is not installed",
        "run_r09_3p_skips_probe",
    );
    // Also confirm no codex/gemini probe messages (belt-and-suspenders).
    assert_no_probe_bail(
        &output,
        "codex-cli is not installed",
        "run_r09_3p_skips_probe",
    );
    assert_no_probe_bail(
        &output,
        "gemini-cli is not installed",
        "run_r09_3p_skips_probe",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Probe-disabled tests (R10–R11)
// ═══════════════════════════════════════════════════════════════════════════

/// (R10) csq run on Codex slot with probe disabled → proceeds with
/// disclosure WARN (emitted by probe() per R2-N4).
#[test]
#[cfg(unix)]
fn test_run_r10_probe_disabled_codex_proceeds_with_disclosure() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    // Outdated stub — would bail without disable.
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // Probe bail did NOT fire.
    assert_no_probe_bail(
        &output,
        "is below the minimum supported",
        "run_r10_probe_disabled",
    );

    // Probe-disabled disclosure on stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("probe disabled"),
        "run_r10: expected 'probe disabled' in stderr; got:\n{stderr}"
    );
}

/// (R11) `--ignore-cli-version` appears in `csq run --help` output.
#[test]
fn test_run_r11_ignore_flag_in_help() {
    let out = Command::new(csq_bin())
        .args(["run", "--help"])
        .output()
        .expect("failed to spawn csq run --help");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ignore-cli-version"),
        "`csq run --help` must mention '--ignore-cli-version'; got:\n{stdout}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ProbeTimedOut test (R12)
// ═══════════════════════════════════════════════════════════════════════════

/// (R12) csq run on Codex slot with probe timing out (stub hangs > 2s) →
/// ProbeTimedOut, proceeds with WARN (R1-C1: don't punish slow `--version`).
#[test]
#[cfg(unix)]
fn test_run_r12_probe_timeout_warns_and_proceeds() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    // Hang for 3 seconds — exceeds the 2s probe budget → ProbeTimedOut.
    write_hang_stub(stubs.path(), "codex", 3);

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // Probe bail did NOT fire.
    assert_no_probe_bail(&output, "codex-cli is not installed", "run_r12_timeout");
    assert_no_probe_bail(&output, "is below the minimum supported", "run_r12_timeout");

    // WARN emitted.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("probe timed out"),
        "run_r12: expected 'probe timed out' WARN; got:\n{combined}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// F5 — --ignore-cli-version non-persistence test (R13)
// ═══════════════════════════════════════════════════════════════════════════

/// (R13) Failure F5: `--ignore-cli-version` is per-invocation only and does NOT
/// persist across separate `csq run` invocations.
///
/// Two sequential subprocess invocations:
/// 1. `csq run 1 --ignore-cli-version` with outdated codex → WARN + proceed
///    (bail fragment absent).
/// 2. `csq run 1` without the flag → BAIL with "is below the minimum supported".
///
/// This test defends against any accidental persistence mechanism (e.g. a flag
/// written to settings.json or a marker file) that would cause the flag to
/// carry over between processes.
#[test]
#[cfg(unix)]
fn test_run_r13_ignore_flag_does_not_persist() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);
    // Outdated codex — would bail without the flag.
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    // Invocation 1: with --ignore-cli-version → bail fragment must be absent.
    let output_with_flag = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1", "--ignore-cli-version"])
        .output()
        .expect("failed to spawn csq run (with flag)");

    assert_no_probe_bail(
        &output_with_flag,
        "is below the minimum supported",
        "run_r13_with_flag",
    );

    // Invocation 2: without --ignore-cli-version → bail must fire.
    let output_without_flag = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run (without flag)");

    assert_probe_bail(
        &output_without_flag,
        "is below the minimum supported",
        "run_r13_without_flag",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// H2 — 3P collision detection test (R14)
// ═══════════════════════════════════════════════════════════════════════════

/// (R14) H2 collision defence: a slot with BOTH a 3P settings.json binding
/// AND a Codex canonical symlink present is an incoherent state.
///
/// `csq run` MUST bail with a distinct "inconsistent state" message
/// (not silently route to either path) when this collision is detected.
#[test]
#[cfg(unix)]
fn test_run_r14_3p_codex_collision_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    // Set up 3P binding (settings.json with ANTHROPIC_BASE_URL).
    write_third_party_settings(base.path(), 1);

    // Also set up a Codex canonical credential file — incoherent state.
    write_codex_canonical(base.path(), 1);

    // Codex stub (version OK) — if probe fires despite the guard, it would
    // pass; the collision guard must fire BEFORE the probe.
    write_stub(stubs.path(), "codex", "codex-cli 0.40.0");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    // Must bail with the collision message.
    assert_probe_bail(&output, "inconsistent state", "run_r14_3p_codex_collision");
    // The message must tell the user to run csq logout to repair.
    assert_probe_bail(&output, "csq logout", "run_r14_3p_codex_collision");
}

/// (R14b) H2 collision defence (symmetric Gemini path; M2 R2 N2): a slot with
/// BOTH a 3P settings.json binding AND a Gemini canonical credential file
/// present is the same incoherent state as R14's Codex variant. `csq run`
/// MUST bail with the same "inconsistent state" message.
#[test]
#[cfg(unix)]
fn test_run_r14b_3p_gemini_collision_bails() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_third_party_settings(base.path(), 1);
    write_gemini_canonical(base.path(), 1);

    // Gemini stub (version OK) — collision guard must fire BEFORE the probe.
    write_stub(stubs.path(), "gemini", "0.41.2");

    let output = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run");

    assert_probe_bail(
        &output,
        "inconsistent state",
        "run_r14b_3p_gemini_collision",
    );
    assert_probe_bail(&output, "csq logout", "run_r14b_3p_gemini_collision");
}
