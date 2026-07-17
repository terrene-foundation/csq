//! Integration (binary-smoke) tests for the M06 `--no-audit` flag on
//! `csq run` (.pending/ fail-loud tightening, workspace
//! an internal workspace).
//!
//! These exercise the BUILT `csq` binary against a TempDir-rooted
//! `CSQ_BASE_DIR` per `rules/user-path-verification.md` (binary smoke) and
//! `rules/testing.md` Rule 4 (TempDir, never `~/.claude`) + Rule 4a
//! (`env_clear` + whitelist).
//!
//! Scope: the `--no-audit` per-invocation escape MUST
//!  (a) be a recognized flag (`csq run --help` lists it), and
//!  (b) log the explicit acknowledgement to stderr when set.
//!
//! The fail-loud `.pending/`-write-failure path (non-zero exit + remediation
//! message) is verified TWO ways:
//!  - unit: `csq/src/cli/audit_emit.rs::tests::pending_write_failure_surfaces_nonzero_exit`
//!    exercises the fallible `try_flush_now` function directly.
//!  - binary smoke (M06 H1, `audit_write_failure_exits_3_with_remediation`
//!    below): the BUILT binary, with a fully-staged Anthropic slot + absent
//!    daemon + unwritable `.pending/`, reaches the real `exec_or_spawn` →
//!    `try_flush_now` → `fail_loud_on_audit_write_failure` path and exits 3
//!    with the operator remediation on stderr — BEFORE the Unix `cmd.exec()`,
//!    so no `claude` binary is required. This is the user-path-verification
//!    Rule 1 end-to-end check the H1 fix demands.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

// Workspace-local serial mutex: the cli_deps probe has a timeout that races
// under cargo's parallel test load. Mirror the sibling run-integration suite.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

/// Per-binary sandbox `$HOME` — a single empty tempdir for the whole test
/// process, so production paths that read `HOME` directly resolve inside the
/// sandbox instead of the operator's real home. See `rules/test-hermeticity.md` MUST 2.
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

/// Write a minimal Codex canonical credential file so `csq run N` dispatches
/// to the Codex surface (existence check only). Mirrors the sibling suite's
/// `write_codex_canonical`.
fn write_codex_canonical(base: &std::path::Path, n: u16) {
    let dir = base.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    let json = r#"{"tokens":{"access_token":"codex-tok"}}"#;
    std::fs::write(dir.join(format!("codex-{n}.json")), json).unwrap();
}

/// Stage a complete A++ Anthropic slot the way `csq login N` leaves it, per
/// `rules/testing.md` Rule 8 (fixtures mirror real csq mint-path output). The
/// cc launch path resolves the slot through `profiles.json::by_slot` to a UUID,
/// then `credentials::load(identities/<UUID>/credentials.json)` MUST succeed
/// (run.rs:347-361) before it reaches `exec_or_spawn`. Mirrors
/// `csq-core/tests/auto_rotate_integration.rs::setup_slot_uuid`:
///  - `profiles.json::by_slot[N] = fixture_uuid_for_slot(N)` (the canonical
///    deterministic test UUID),
///  - `identities/<UUID>/credentials.json` (valid Anthropic OAuth shape),
///  - `config-<N>/` dir (hard-required by `create_handle_dir`).
///
/// No `broker_failed` sentinel is written, so `is_broker_failed` is false and
/// the launch is not short-circuited into the LOGIN-NEEDED branch.
fn stage_anthropic_identity_slot(base: &std::path::Path, n: u16) {
    use csq_core::accounts::{identity_store, profiles};
    use csq_core::testing::identity_fixtures::fixture_uuid_for_slot;

    let uuid = fixture_uuid_for_slot(n);

    let profiles_path = profiles::profiles_path(base);
    let mut pf = profiles::load(&profiles_path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
    pf.by_slot.insert(n.to_string(), uuid);
    profiles::save(&profiles_path, &pf).unwrap();

    // Identity-store credentials (the canonical reader the launch path uses).
    // expiresAt 4102444800000 = 2100-01-01 in ms (testing.md Rule 1 — no
    // wall-clock time-bomb).
    let identity_cred_path = identity_store::credentials_path_for(base, uuid);
    std::fs::create_dir_all(identity_cred_path.parent().unwrap()).unwrap();
    let json = r#"{"claudeAiOauth":{"accessToken":"tok","refreshToken":"rtok","expiresAt":4102444800000,"scopes":[],"tokenType":"Bearer"}}"#;
    std::fs::write(&identity_cred_path, json).unwrap();

    // `create_handle_dir` hard-errors if `config-<N>/` is absent.
    std::fs::create_dir_all(base.join(format!("config-{n}"))).unwrap();
}

/// (M06-1) `--no-audit` appears in `csq run --help` output.
///
/// MUST spawn through the hermetic `clean_cmd()` (env_clear + whitelist), NOT a
/// raw `Command::new(csq_bin())`. The raw form inherited the CI runner's full
/// parent environment and emitted empty stdout on `windows-latest` while passing
/// on macOS/Linux (an internal ticket) — the exact `rules/testing.md` Rule 4a /
/// `rules/test-hermeticity.md` MUST-2 bug class: an inherited parent-env var
/// perturbs the spawned binary's output on Windows only. Every sibling subprocess
/// test in this file already uses `clean_cmd()` and is green on Windows; this was
/// the lone raw-spawn outlier. Exit status + combined stdout/stderr are asserted
/// so a genuine empty-output regression still fails loudly (it cannot be masked
/// as a capture artifact).
#[test]
fn no_audit_flag_in_run_help() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let out = clean_cmd(None)
        .args(["run", "--help"])
        .output()
        .expect("failed to spawn csq run --help");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "`csq run --help` must exit 0; status={:?}\noutput:\n{combined}",
        out.status
    );
    assert!(
        combined.contains("no-audit"),
        "`csq run --help` must mention '--no-audit'; got (stdout+stderr):\n{combined}"
    );
}

/// (M06-2) `csq run --no-audit N` logs the explicit acknowledgement to stderr.
///
/// Staged with a Codex slot + probe disabled so `handle()` resolves the
/// explicit account, constructs the (disabled) emitter, and prints the
/// acknowledgement BEFORE the surface dispatch fails (no daemon). The run
/// itself is expected to fail downstream — we assert ONLY that the
/// acknowledgement reached stderr (the audit gap was surfaced to the
/// operator).
#[test]
#[cfg(unix)]
fn no_audit_flag_emits_acknowledgement_on_stderr() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();

    write_codex_canonical(base.path(), 1);

    let output = clean_cmd(None)
        .env("CSQ_BASE_DIR", base.path())
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["run", "--no-audit", "1"])
        .output()
        .expect("failed to spawn csq run --no-audit");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--no-audit set; this invocation's audit record will not be written."),
        "csq run --no-audit must acknowledge the gap on stderr; got:\n{stderr}"
    );
}

/// (M06 H1) Binary smoke: the BUILT `csq` binary exits **3**
/// (`EXIT_CODE_AUDIT_WRITE_FAILED`) with the operator remediation on stderr
/// when the audit record cannot be persisted — daemon absent (live-IPC POST
/// fails) AND `.pending/` made unwritable (`chmod 0o000`, the fallback write
/// fails). This is the end-to-end user-path verification the H1 fix demands:
/// the cc launch path (capability layer OFF → Inherit) reaches the real
/// `exec_or_spawn`, which calls `try_flush_now` → `fail_loud_on_audit_write_failure`
/// BEFORE the Unix `cmd.exec()`, so exit 3 fires without ever needing a real
/// `claude` binary on PATH.
#[test]
#[cfg(unix)]
fn audit_write_failure_exits_3_with_remediation() {
    use std::os::unix::fs::PermissionsExt;

    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();

    // Fully-staged Anthropic slot so `csq run 1` resolves to the cc launch
    // path and reaches `exec_or_spawn` (no `--no-audit`, so the real emitter
    // is constructed and flushed).
    stage_anthropic_identity_slot(base.path(), 1);

    // Make the `.pending/` dir exist but be unwritable. `pending_dir` =
    // `<base>/csq-runs/.pending` (see run.rs). With the daemon absent the
    // live-IPC POST fails, the fallback `.pending/` write then fails on the
    // 0o000 dir, and `try_flush_now` returns `Err(PendingWriteFailed)`.
    let pending = base.path().join("csq-runs").join(".pending");
    std::fs::create_dir_all(&pending).unwrap();
    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o000)).unwrap();

    // A separate CLAUDE_HOME inside the tempdir so `run_env_preflight` and
    // `create_handle_dir`'s shared-item symlinks never touch the real
    // `~/.claude` (testing.md Rule 4 + 4a).
    let claude_home = base.path().join("claude-home");
    std::fs::create_dir_all(&claude_home).unwrap();

    let output = clean_cmd(None)
        .env("CSQ_BASE_DIR", base.path())
        .env("CLAUDE_HOME", &claude_home)
        // Probe disabled so the cc launch is not gated on a real `claude`
        // version probe; the fix path under test is downstream of the probe.
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["run", "1"])
        .output()
        .expect("failed to spawn csq run 1");

    // Restore writability so TempDir teardown can recurse-remove the dir.
    let _ = std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o700));

    assert_eq!(
        output.status.code(),
        Some(3),
        "audit-write failure must exit 3 (EXIT_CODE_AUDIT_WRITE_FAILED); got {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit record could not be written"),
        "fail-loud stderr must carry the remediation header; got:\n{stderr}"
    );
    assert!(
        stderr.contains("FOR THIS INVOCATION ONLY: re-run with --no-audit"),
        "fail-loud stderr must name the --no-audit escape; got:\n{stderr}"
    );
}

/// (M06 MED, same class as H1) Binary smoke: the bench-mode env-gate failure
/// path flushes the held audit record BEFORE its `std::process::exit(64)`.
///
/// `handle_bench_mode_layer_only`'s env gate (`CSQ_BENCH_MODE != "1"`) is a
/// precondition refusal reached AFTER the capability-layer preflight succeeded
/// and the owning emitter in `launch_*` holds a record. The `process::exit(64)`
/// bypasses `Drop`, so before the H1-class fix the record was lost with no
/// `.pending/` write and no WARN — the exact fail-open M06 closes.
///
/// This drives the BUILT binary with a fully-staged Anthropic slot (capability
/// layer OFF → preflight returns `Inherit`, bench gate fires before any spawn),
/// the daemon socket absent (live-IPC POST fails → `.pending/` fallback), and
/// `CSQ_BENCH_MODE` UNSET (clean_cmd's env_clear whitelist excludes it). The
/// expected outcome: exit 64 AND a `.pending/<run_id>.jsonl` record carrying
/// the honest precondition-refusal verdict `result_state=Fail`,
/// `decision=Reject`. Without the flush-before-exit, no `.pending/` file would
/// exist at all.
#[test]
#[cfg(unix)]
fn bench_mode_env_gate_flushes_record_before_exit() {
    let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
        SERIAL.clear_poison();
        p.into_inner()
    });
    let base = TempDir::new().unwrap();

    // Fully-staged Anthropic slot so `csq run 1 --bench-mode layer-only`
    // resolves to the cc launch path, runs the (layer-OFF) preflight, and
    // reaches the bench-mode env gate with a constructed+populated emitter.
    stage_anthropic_identity_slot(base.path(), 1);

    // Separate CLAUDE_HOME inside the tempdir (testing.md Rule 4 + 4a).
    let claude_home = base.path().join("claude-home");
    std::fs::create_dir_all(&claude_home).unwrap();

    // NOTE: clean_cmd() env_clears and re-injects only the stdlib whitelist,
    // so CSQ_BENCH_MODE is NOT inherited from the parent — the env gate fails
    // exactly as a real operator who forgot to export it.
    let output = clean_cmd(None)
        .env("CSQ_BASE_DIR", base.path())
        .env("CLAUDE_HOME", &claude_home)
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .args(["run", "1", "--bench-mode", "layer-only"])
        .output()
        .expect("failed to spawn csq run 1 --bench-mode layer-only");

    // The env gate exits 64 (EX_USAGE) after flushing the record.
    assert_eq!(
        output.status.code(),
        Some(64),
        "bench-mode env-gate refusal must exit 64; got {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // The held record MUST have been flushed to `.pending/` before the exit.
    // (Daemon socket absent → live IPC fails → `.pending/` fallback writes.)
    let pending = base.path().join("csq-runs").join(".pending");
    let entries: Vec<_> = std::fs::read_dir(&pending)
        .unwrap_or_else(|e| panic!("`.pending/` must exist after flush-before-exit: {e}"))
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "exactly one `.pending/` record must exist (flush-before-exit, no double-emit); got {}",
        entries.len()
    );

    // The record carries the honest precondition-refusal verdict.
    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    let parsed: csq_core::audit::AuditRecord = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("`.pending/` record must parse as AuditRecord: {e}\n{content}"));
    assert_eq!(
        parsed.result_state,
        csq_core::audit::ResultState::Fail,
        "bench-mode env-gate refusal record must be result_state=Fail"
    );
    assert_eq!(
        parsed.decision,
        csq_core::audit::Decision::Reject,
        "bench-mode env-gate refusal record must be decision=Reject"
    );
}
