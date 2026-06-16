//! Integration tests for `csq doctor` CLI-deps wiring (PR-MCD1.5).
//!
//! Tests verify:
//! - Per-surface row rendering (text and JSON) for all `CliStatus` variants.
//! - Slot-suppression: surface row appears only when authenticated slots exist.
//! - Stale-slot variant: `Missing | WrongBinary` with slots configured.
//! - Empty-state row: no slots on any surface.
//! - `schema_version: 8` in JSON output (bumped 7 → 8 when the
//!   `identity_store.consistency` field became a list of issues).
//! - Absent-key test: `codex_cli` omitted when no codex slots (R1-L2).
//! - Probe-disabled disclosure via env var.
//! - Half-migrated handle dir does not trigger surface row.
//!
//! Per `rules/probe-driven-verification.md` MUST 1: assertions are
//! structural (`serde_json::Value` equality), NOT regex/keyword matches.
//!
//! Per `rules/testing.md` Rule 4a: subprocess commands use `env_clear()`
//! + whitelist to avoid inheriting live `CLAUDE_CONFIG_DIR`.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

// Workspace-local serial mutex: cli_deps probe has a 2s timeout that races
// under heavy parallel test load (CPU saturation can delay shell-script spawn
// past the deadline). All tests serialize on this mutex per `rules/testing.md`
// Rule 6 spirit (the rule's `csq_core::platform::test_env::lock()` is
// `#[cfg(test)]`-gated to csq-core, so csq's integration tests use a local
// equivalent).
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Binary path ──────────────────────────────────────────────────────────────

fn csq_bin() -> PathBuf {
    // Locate the built `csq` binary via the Cargo-provided env var.
    // Falls back to a path relative to the workspace root for IDE runs.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_csq") {
        return PathBuf::from(p);
    }
    // Fallback: walk up from the test file's manifest dir.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = manifest
        .parent() // csq crate root -> workspace root
        .unwrap()
        .join("target")
        .join("debug")
        .join("csq");
    target
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
/// `rules/test-hermeticity.md` MUST 2.
///
/// M-4: `CLAUDE_HOME` is sandboxed (NOT re-injected from the parent) so a test
/// running inside a CC session that set `CLAUDE_HOME` does not inherit the live
/// value. Callers may still override it per-test via `.env("CLAUDE_HOME", tempdir)`.
fn clean_cmd(path_override: Option<&str>) -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    // Sandbox HOME and CLAUDE_HOME — never re-inject the parent's live values.
    cmd.env("HOME", sandbox_home());
    cmd.env("CLAUDE_HOME", sandbox_home());
    for k in &["LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    // PATH is always required (for shell tool resolution on macOS/Linux).
    // Use the caller-supplied override when set, else inherit the real PATH.
    if let Some(p) = path_override {
        cmd.env("PATH", p);
    } else if let Ok(v) = std::env::var("PATH") {
        cmd.env("PATH", v);
    }
    cmd
}

// ── Fixture builders ─────────────────────────────────────────────────────────

/// Write a minimal Anthropic credential file at `credentials/<n>.json`.
fn write_anthropic_cred(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json = r#"{"claudeAiOauth":{"accessToken":"tok","refreshToken":"rtok","expiresAt":4102444800000,"scopes":[]}}"#;
    std::fs::write(dir.join(format!("{n}.json")), json).unwrap();
}

/// Write a minimal Codex credential file at `credentials/codex-<n>.json`.
fn write_codex_cred(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json = r#"{"tokens":{"access_token":"codex-tok"}}"#;
    std::fs::write(dir.join(format!("codex-{n}.json")), json).unwrap();
}

/// Write a minimal Gemini binding file at `credentials/gemini-<n>.json`.
fn write_gemini_cred(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json =
        r#"{"v":1,"auth":{"mode":"api_key"},"model_name":"auto","created_unix_secs":1714000000}"#;
    std::fs::write(dir.join(format!("gemini-{n}.json")), json).unwrap();
}

/// Write a shell script stub at `<stub_dir>/<name>` that prints `stdout_line`
/// followed by a newline and exits 0.
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
    let sleep_bin = find_bin("sleep").unwrap_or_else(|| "/bin/sleep".into());
    let script = format!("#!/bin/sh\n{sleep_bin} {hang_secs}\n");
    std::fs::write(&path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

fn find_bin(name: &str) -> Option<String> {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

// ── Run helpers ──────────────────────────────────────────────────────────────

/// Run `csq doctor --json` with the given base dir and PATH override.
/// Returns the parsed JSON `Value`.
fn run_doctor_json(base: &std::path::Path, path_override: &str) -> Value {
    let out = clean_cmd(Some(path_override))
        .env("CSQ_BASE_DIR", base)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to spawn csq doctor --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON from csq doctor --json: {e}\nstdout={stdout}"))
}

/// Run `csq doctor --json` with probe disabled.
fn run_doctor_json_probe_disabled(base: &std::path::Path) -> Value {
    let out = clean_cmd(None)
        .env("CSQ_BASE_DIR", base)
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to spawn csq doctor --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout={stdout}"))
}

/// Run `csq doctor` (text output) with the given base dir and PATH override.
fn run_doctor_text(base: &std::path::Path, path_override: &str) -> String {
    let out = clean_cmd(Some(path_override))
        .env("CSQ_BASE_DIR", base)
        .args(["doctor"])
        .output()
        .expect("failed to spawn csq doctor");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// (1) Doctor renders three rows when all 3 surfaces have authenticated slots;
/// happy path matches flow 01-doctor-happy-path.md shape.
#[test]
#[cfg(unix)]
fn test_1_all_surfaces_with_stubs_render_three_rows() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_anthropic_cred(base.path(), 1);
    write_codex_cred(base.path(), 1);
    write_gemini_cred(base.path(), 1);

    // Stub binaries: claude, codex, gemini with ok versions.
    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");
    write_stub(stubs.path(), "codex", "codex-cli 0.130.0");
    write_stub(stubs.path(), "gemini", "0.41.2");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    // schema_version is edition-specific (M2 T2.5): community 16, enterprise 17
    // (enterprise adds the optional `audit_trust_plane_grade` field).
    let expected_schema = if cfg!(feature = "enterprise") { 17 } else { 16 };
    assert_eq!(
        json["schema_version"], expected_schema,
        "schema_version must equal the edition-active value (community 16 / enterprise 17)"
    );
    assert_eq!(json["claude_code"]["status"], "ok");
    assert_eq!(json["codex_cli"]["status"], "ok");
    assert_eq!(json["gemini_cli"]["status"], "ok");
    assert_eq!(json["claude_code"]["version"], "2.1.138");
    assert_eq!(json["codex_cli"]["version"], "0.130.0");
    assert_eq!(json["gemini_cli"]["version"], "0.41.2");
}

/// (2) Doctor suppresses codex row when no codex slots; suppresses gemini row
/// when no gemini slots.
#[test]
#[cfg(unix)]
fn test_2_surface_row_suppressed_when_no_slots() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    // Only Anthropic slot.
    write_anthropic_cred(base.path(), 1);
    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");
    // Also place codex/gemini stubs in PATH to confirm they're not probed.
    write_stub(stubs.path(), "codex", "codex-cli 0.130.0");
    write_stub(stubs.path(), "gemini", "0.41.2");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    assert!(
        json["claude_code"].is_object(),
        "claude_code must be present"
    );
    assert!(
        json["codex_cli"].is_null(),
        "codex_cli must be absent (null in serde_json::Value::get)"
    );
    assert!(json["gemini_cli"].is_null(), "gemini_cli must be absent");
    // JSON string must NOT contain the key at all (not null).
    let raw = serde_json::to_string(&json).unwrap();
    assert!(
        !raw.contains("\"codex_cli\""),
        "codex_cli key must be omitted entirely, not null"
    );
    assert!(
        !raw.contains("\"gemini_cli\""),
        "gemini_cli key must be omitted entirely, not null"
    );
}

/// (3) Doctor renders ✓ row with inline `(min 0.40.0)` for codex at exactly minimum.
#[test]
#[cfg(unix)]
fn test_3_codex_at_minimum_shows_ok_with_min_annotation() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.40.0");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    assert_eq!(json["codex_cli"]["status"], "ok");
    assert_eq!(json["codex_cli"]["version"], "0.40.0");
    assert_eq!(json["codex_cli"]["min_version"], "0.40.0");

    // Text output must contain the inline min annotation.
    let text = run_doctor_text(base.path(), stubs.path().to_str().unwrap());
    assert!(
        text.contains("(min 0.40.0)"),
        "text output must contain '(min 0.40.0)'; got:\n{text}"
    );
}

/// (4) Doctor renders ⚠ outdated row for codex 0.24.0.
///
/// F2: Text output MUST include both the found version ("0.24.0") AND the
/// minimum ("min 0.40.0") so operators can see what they have and what they need.
#[test]
#[cfg(unix)]
fn test_4_codex_outdated_version() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);
    write_stub(stubs.path(), "codex", "codex-cli 0.24.0");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    assert_eq!(json["codex_cli"]["status"], "outdated");
    assert_eq!(json["codex_cli"]["version"], "0.24.0");
    assert_eq!(json["codex_cli"]["min_version"], "0.40.0");

    // F2: text path must show both versions, not just one.
    let text = run_doctor_text(base.path(), stubs.path().to_str().unwrap());
    assert!(
        text.contains("0.24.0"),
        "F2: outdated text must include found version '0.24.0'; got:\n{text}"
    );
    assert!(
        text.contains("0.40.0"),
        "F2: outdated text must include minimum version '0.40.0'; got:\n{text}"
    );
}

/// (5) Doctor renders stale-slot variant when codex slot exists but binary
/// uninstalled (Missing) — text contains both `csq cli install codex` AND
/// `csq logout`.
#[test]
#[cfg(unix)]
fn test_5_stale_slot_variant_missing_binary_with_slots() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    // Codex slot is present but no `codex` binary on PATH.
    write_codex_cred(base.path(), 1);
    // No stub written for codex in stubs dir.

    let text = run_doctor_text(base.path(), stubs.path().to_str().unwrap());

    assert!(
        text.contains("csq cli install codex"),
        "stale-slot variant must contain 'csq cli install codex'; got:\n{text}"
    );
    assert!(
        text.contains("csq logout"),
        "stale-slot variant must contain 'csq logout'; got:\n{text}"
    );
    assert!(
        text.contains("missing"),
        "stale-slot variant must say 'missing'; got:\n{text}"
    );

    // JSON: status must be "missing".
    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());
    assert_eq!(json["codex_cli"]["status"], "missing");
}

/// (6) Doctor renders empty-state row "No slots configured" when zero slots
/// across ALL surfaces.
#[test]
#[cfg(unix)]
fn test_6_empty_state_row_no_slots() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    // No credentials written.
    std::fs::create_dir_all(base.path().join("credentials")).unwrap();

    let text = run_doctor_text(base.path(), "/dev/null");

    assert!(
        text.contains("No slots configured"),
        "empty-state must say 'No slots configured'; got:\n{text}"
    );
    assert!(
        text.contains("csq login 1"),
        "empty-state must mention 'csq login 1'; got:\n{text}"
    );

    // JSON must have no claude_code, codex_cli, gemini_cli keys.
    let json = run_doctor_json(base.path(), "/dev/null");
    let raw = serde_json::to_string(&json).unwrap();
    assert!(!raw.contains("\"claude_code\""));
    assert!(!raw.contains("\"codex_cli\""));
    assert!(!raw.contains("\"gemini_cli\""));
}

/// (7) Doctor renders ⚠ wrong binary row with `brew uninstall codex` line
/// for `/opt/homebrew/Cellar/codex/` path.
#[test]
#[cfg(unix)]
fn test_7_wrong_binary_row_with_brew_uninstall_line() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let _stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);

    // Write a stub codex binary rooted under a fake Cellar/codex path so the
    // blocklist gate fires.  We can't symlink /opt/homebrew in CI, so we
    // place the script in a real temp dir but route its canonical path to
    // appear blocklisted by adding a matching segment to the stub dir name.
    //
    // Alternative: use a dir named to contain "Cellar/codex/" so the
    // blocklist substring match fires on the resolved canonical path.
    let cellar_dir = base
        .path()
        .join("opt/homebrew/Cellar/codex/0.1.2505291658/bin");
    std::fs::create_dir_all(&cellar_dir).unwrap();
    write_stub(&cellar_dir, "codex", "codex-cli 0.130.0");
    let cellar_path = cellar_dir.to_str().unwrap().to_string();

    let text = run_doctor_text(base.path(), &cellar_path);
    let json = run_doctor_json(base.path(), &cellar_path);

    // JSON: status must be "wrong_binary".
    assert_eq!(
        json["codex_cli"]["status"], "wrong_binary",
        "wrong-binary codex must report status=wrong_binary; json={json}"
    );

    // Text: must contain brew uninstall fix line (flow 04-wrong-binary-on-path.md).
    assert!(
        text.contains("brew uninstall codex"),
        "wrong-binary row must include 'brew uninstall codex'; got:\n{text}"
    );
}

/// (8) Doctor renders ⚠ probe timed out row when probe hangs.
#[test]
#[cfg(unix)]
fn test_8_probe_timed_out_row() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);

    // A stub that hangs for 10s — probe's 2s budget fires first.
    write_hang_stub(stubs.path(), "codex", 10);

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    assert_eq!(
        json["codex_cli"]["status"], "probe_timed_out",
        "hanging codex must report probe_timed_out; json={json}"
    );
}

/// (9) Doctor renders ⚠ probe disabled row when env var is set.
#[test]
fn test_9_probe_disabled_row() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    write_codex_cred(base.path(), 1);

    let json = run_doctor_json_probe_disabled(base.path());

    assert_eq!(
        json["codex_cli"]["status"], "probe_disabled",
        "probe disabled must report status=probe_disabled; json={json}"
    );
}

/// (10) JSON output: top-level has the current `"schema_version"`.
/// Journal 0042 bumped 4 → 5 when the `phase4_incomplete` top-level
/// field landed.
#[test]
#[cfg(unix)]
fn test_10_json_schema_version_2() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    write_anthropic_cred(base.path(), 1);

    let stubs = TempDir::new().unwrap();
    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    // schema_version is edition-specific (M2 T2.5): community 16, enterprise 17.
    let expected_schema: u64 = if cfg!(feature = "enterprise") { 17 } else { 16 };
    assert_eq!(
        json["schema_version"],
        Value::Number(serde_json::Number::from(expected_schema)),
        "schema_version must equal the edition-active value (community 16 / enterprise 17)"
    );
}

/// (11) JSON output: `codex_cli` key absent when no codex slots (R1-L2).
#[test]
#[cfg(unix)]
fn test_11_json_codex_key_absent_when_no_codex_slots() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    write_anthropic_cred(base.path(), 1);

    let stubs = TempDir::new().unwrap();
    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());
    let raw = serde_json::to_string(&json).unwrap();

    assert!(
        !raw.contains("\"codex_cli\""),
        "codex_cli must be absent (not null) when no codex slots; raw={raw}"
    );
}

/// (12) JSON output: `codex_cli` key present (object) when codex slots exist.
#[test]
#[cfg(unix)]
fn test_12_json_codex_key_present_when_codex_slots_exist() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    write_codex_cred(base.path(), 1);

    let stubs = TempDir::new().unwrap();
    write_stub(stubs.path(), "codex", "codex-cli 0.130.0");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());

    assert!(
        json["codex_cli"].is_object(),
        "codex_cli must be an object when slots exist; json={json}"
    );
    assert_eq!(json["codex_cli"]["status"], "ok");
}

/// (13) JSON output: 18 parameterized cases — for each (surface, status),
/// assert `serde_json::Value` shape.
///
/// Covers 6 variants × 3 surfaces using a parameterized helper.
/// Uses hand-written expected `Value` per `M9 A3` (no snapshot crate).
#[derive(Debug)]
struct ParamCase {
    surface_key: &'static str,
    setup_cred: fn(&std::path::Path),
    stub_name: &'static str,
    stub_output: &'static str,
    hang: bool,
    probe_disabled: bool,
    expected_status: &'static str,
    expected_found: bool,
    expected_version: Option<&'static str>,
}

/// Build 18 test cases across (surface × status).
fn param_cases() -> Vec<ParamCase> {
    vec![
        // ── Claude ───────────────────────────────────────────────────────
        ParamCase {
            surface_key: "claude_code",
            setup_cred: |b| write_anthropic_cred(b, 1),
            stub_name: "claude",
            stub_output: "2.1.138 (Claude Code)",
            hang: false,
            probe_disabled: false,
            expected_status: "ok",
            expected_found: true,
            expected_version: Some("2.1.138"),
        },
        ParamCase {
            surface_key: "claude_code",
            setup_cred: |b| write_anthropic_cred(b, 1),
            stub_name: "claude",
            stub_output: "1.9.0",
            hang: false,
            probe_disabled: false,
            expected_status: "outdated",
            expected_found: true,
            expected_version: Some("1.9.0"),
        },
        ParamCase {
            surface_key: "claude_code",
            setup_cred: |b| write_anthropic_cred(b, 1),
            stub_name: "claude",
            stub_output: "", // no stub written → Missing
            hang: false,
            probe_disabled: false,
            expected_status: "missing",
            expected_found: false,
            expected_version: None,
        },
        ParamCase {
            surface_key: "claude_code",
            setup_cred: |b| write_anthropic_cred(b, 1),
            stub_name: "claude",
            stub_output: "not-a-valid-version",
            hang: false,
            probe_disabled: false,
            expected_status: "unrecognized_version",
            expected_found: true,
            expected_version: None,
        },
        ParamCase {
            surface_key: "claude_code",
            setup_cred: |b| write_anthropic_cred(b, 1),
            stub_name: "claude",
            stub_output: "",
            hang: true,
            probe_disabled: false,
            expected_status: "probe_timed_out",
            expected_found: true,
            expected_version: None,
        },
        ParamCase {
            surface_key: "claude_code",
            setup_cred: |b| write_anthropic_cred(b, 1),
            stub_name: "claude",
            stub_output: "2.1.138 (Claude Code)",
            hang: false,
            probe_disabled: true,
            expected_status: "probe_disabled",
            expected_found: false,
            expected_version: None,
        },
        // ── Codex ────────────────────────────────────────────────────────
        ParamCase {
            surface_key: "codex_cli",
            setup_cred: |b| write_codex_cred(b, 1),
            stub_name: "codex",
            stub_output: "codex-cli 0.130.0",
            hang: false,
            probe_disabled: false,
            expected_status: "ok",
            expected_found: true,
            expected_version: Some("0.130.0"),
        },
        ParamCase {
            surface_key: "codex_cli",
            setup_cred: |b| write_codex_cred(b, 1),
            stub_name: "codex",
            stub_output: "codex-cli 0.24.0",
            hang: false,
            probe_disabled: false,
            expected_status: "outdated",
            expected_found: true,
            expected_version: Some("0.24.0"),
        },
        ParamCase {
            surface_key: "codex_cli",
            setup_cred: |b| write_codex_cred(b, 1),
            stub_name: "codex",
            stub_output: "",
            hang: false,
            probe_disabled: false,
            expected_status: "missing",
            expected_found: false,
            expected_version: None,
        },
        ParamCase {
            surface_key: "codex_cli",
            setup_cred: |b| write_codex_cred(b, 1),
            stub_name: "codex",
            stub_output: "codex-cli no-semver",
            hang: false,
            probe_disabled: false,
            expected_status: "unrecognized_version",
            expected_found: true,
            expected_version: None,
        },
        ParamCase {
            surface_key: "codex_cli",
            setup_cred: |b| write_codex_cred(b, 1),
            stub_name: "codex",
            stub_output: "",
            hang: true,
            probe_disabled: false,
            expected_status: "probe_timed_out",
            expected_found: true,
            expected_version: None,
        },
        ParamCase {
            surface_key: "codex_cli",
            setup_cred: |b| write_codex_cred(b, 1),
            stub_name: "codex",
            stub_output: "codex-cli 0.130.0",
            hang: false,
            probe_disabled: true,
            expected_status: "probe_disabled",
            expected_found: false,
            expected_version: None,
        },
        // ── Gemini ───────────────────────────────────────────────────────
        ParamCase {
            surface_key: "gemini_cli",
            setup_cred: |b| write_gemini_cred(b, 1),
            stub_name: "gemini",
            stub_output: "0.41.2",
            hang: false,
            probe_disabled: false,
            expected_status: "ok",
            expected_found: true,
            expected_version: Some("0.41.2"),
        },
        ParamCase {
            surface_key: "gemini_cli",
            setup_cred: |b| write_gemini_cred(b, 1),
            stub_name: "gemini",
            stub_output: "0.38.0",
            hang: false,
            probe_disabled: false,
            expected_status: "outdated",
            expected_found: true,
            expected_version: Some("0.38.0"),
        },
        ParamCase {
            surface_key: "gemini_cli",
            setup_cred: |b| write_gemini_cred(b, 1),
            stub_name: "gemini",
            stub_output: "",
            hang: false,
            probe_disabled: false,
            expected_status: "missing",
            expected_found: false,
            expected_version: None,
        },
        ParamCase {
            surface_key: "gemini_cli",
            setup_cred: |b| write_gemini_cred(b, 1),
            stub_name: "gemini",
            stub_output: "not-a-version",
            hang: false,
            probe_disabled: false,
            expected_status: "unrecognized_version",
            expected_found: true,
            expected_version: None,
        },
        ParamCase {
            surface_key: "gemini_cli",
            setup_cred: |b| write_gemini_cred(b, 1),
            stub_name: "gemini",
            stub_output: "",
            hang: true,
            probe_disabled: false,
            expected_status: "probe_timed_out",
            expected_found: true,
            expected_version: None,
        },
        ParamCase {
            surface_key: "gemini_cli",
            setup_cred: |b| write_gemini_cred(b, 1),
            stub_name: "gemini",
            stub_output: "0.41.2",
            hang: false,
            probe_disabled: true,
            expected_status: "probe_disabled",
            expected_found: false,
            expected_version: None,
        },
    ]
}

#[test]
#[cfg(unix)]
fn test_13_parameterized_18_cases_json_shape() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let cases = param_cases();
    assert_eq!(cases.len(), 18, "exactly 18 cases required");

    for (i, case) in cases.iter().enumerate() {
        let base = TempDir::new().unwrap();
        let stubs = TempDir::new().unwrap();

        (case.setup_cred)(base.path());

        if case.hang {
            write_hang_stub(stubs.path(), case.stub_name, 10);
        } else if !case.stub_output.is_empty() {
            write_stub(stubs.path(), case.stub_name, case.stub_output);
        }
        // If stub_output is "" and not hang, no binary is placed → Missing.

        let json = if case.probe_disabled {
            run_doctor_json_probe_disabled(base.path())
        } else {
            run_doctor_json(base.path(), stubs.path().to_str().unwrap())
        };

        let surface = &json[case.surface_key];
        assert!(
            surface.is_object(),
            "case {i}: {} must be present; json={json}",
            case.surface_key
        );

        let expected_status = Value::String(case.expected_status.into());
        assert_eq!(
            surface["status"], expected_status,
            "case {i} ({} {}): status mismatch; got json={}",
            case.surface_key, case.expected_status, json
        );

        let expected_found = Value::Bool(case.expected_found);
        assert_eq!(
            surface["found"], expected_found,
            "case {i} ({} {}): found mismatch",
            case.surface_key, case.expected_status
        );

        match case.expected_version {
            Some(v) => {
                assert_eq!(
                    surface["version"],
                    Value::String(v.into()),
                    "case {i}: version mismatch"
                );
            }
            None => {
                assert!(
                    surface["version"].is_null(),
                    "case {i}: expected null version but got {}",
                    surface["version"]
                );
            }
        }
    }
}

/// (14) Half-migrated handle dir (slot dir present, no `.credentials.json`)
/// does NOT trigger surface row in doctor.
#[test]
fn test_14_half_migrated_handle_dir_not_shown() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    // Create the credentials dir but write an incomplete file (directory only,
    // no `.credentials.json`).  `discover_codex` loads the file via
    // `credentials::load`; if the file does not parse as Codex credentials,
    // `has_credentials` is false and the slot is not counted as authenticated.
    let creds_dir = base.path().join("credentials");
    std::fs::create_dir_all(&creds_dir).unwrap();
    // Write an empty JSON object — valid JSON but not a Codex credential shape.
    std::fs::write(creds_dir.join("codex-1.json"), "{}").unwrap();

    let json = run_doctor_json_probe_disabled(base.path());
    let raw = serde_json::to_string(&json).unwrap();

    assert!(
        !raw.contains("\"codex_cli\""),
        "half-migrated slot must not trigger codex_cli row; raw={raw}"
    );
}

/// (15) Mixed slots (codex + anthropic) render both rows; suppression works
/// per-surface — gemini row stays suppressed.
#[test]
#[cfg(unix)]
fn test_15_mixed_surfaces_both_rows_rendered() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_anthropic_cred(base.path(), 1);
    write_codex_cred(base.path(), 1);
    // No gemini credential.

    write_stub(stubs.path(), "claude", "2.1.138 (Claude Code)");
    write_stub(stubs.path(), "codex", "codex-cli 0.130.0");

    let json = run_doctor_json(base.path(), stubs.path().to_str().unwrap());
    let raw = serde_json::to_string(&json).unwrap();

    assert!(
        json["claude_code"].is_object(),
        "claude_code must be present"
    );
    assert!(json["codex_cli"].is_object(), "codex_cli must be present");
    assert!(
        !raw.contains("\"gemini_cli\""),
        "gemini_cli must be absent; raw={raw}"
    );
}

/// (F9) Stale-slot count: 3 valid codex credentials + 1 credential dir entry
/// that does NOT parse as a valid codex credential → the doctor row is still
/// present (because 3 valid slots exist) AND the stale-slot variant does NOT
/// fire (slot count is accurate — no phantom 4th slot treated as stale).
///
/// This guards against off-by-one in the slot-counting logic where malformed
/// files inflate the authenticated count and trigger a spurious stale warning.
#[test]
fn test_f9_stale_slot_count_excludes_invalid_cred_entries() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();

    // 3 valid codex credentials.
    write_codex_cred(base.path(), 1);
    write_codex_cred(base.path(), 2);
    write_codex_cred(base.path(), 3);

    // 1 entry that looks like a slot but does NOT have valid codex credential
    // JSON — an empty JSON object (same shape as test_14_half_migrated_handle_dir).
    let creds_dir = base.path().join("credentials");
    std::fs::write(creds_dir.join("codex-4.json"), "{}").unwrap();

    // probe disabled so we don't wait for a subprocess.
    let json = run_doctor_json_probe_disabled(base.path());

    // The codex_cli row must be present (3 valid slots trigger surface output).
    assert!(
        json["codex_cli"].is_object(),
        "F9: codex_cli row must be present with 3 valid slots; json={json}"
    );

    // The row status must be probe_disabled (not missing), confirming that the
    // 3 valid slots caused the surface to appear and probe was fired/skipped.
    assert_eq!(
        json["codex_cli"]["status"], "probe_disabled",
        "F9: codex_cli status must be probe_disabled (not missing); json={json}"
    );
}

/// (F1-sibling) When `CSQ_CLI_DEPS_PROBE_DISABLE=1` and PATH is set to an
/// empty-stub directory, doctor must return `probe_disabled` for all surfaces
/// that have authenticated slots — it MUST NOT execute any subprocess
/// (a hang stub that exists in PATH must not be reached).
///
/// This verifies that the kill-switch fires before the PATH walk, not after.
#[test]
#[cfg(unix)]
fn test_f1_probe_disabled_kill_switch_fires_before_path_walk() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();

    write_codex_cred(base.path(), 1);

    // Write a codex stub that hangs for 60s — if probe fires, the test
    // will timeout well before the assertion runs.
    write_hang_stub(stubs.path(), "codex", 60);

    let out = clean_cmd(Some(stubs.path().to_str().unwrap()))
        .env("CSQ_BASE_DIR", base.path())
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to spawn csq doctor --json");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout={stdout}"));

    // The row must be present and status must be probe_disabled, not
    // probe_timed_out (which would mean the hang stub was reached).
    assert_eq!(
        json["codex_cli"]["status"], "probe_disabled",
        "F1-sibling: kill-switch must fire before PATH walk; got probe_timed_out or similar; json={json}"
    );
}
