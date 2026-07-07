//! Integration tests for `csq_core::cli_deps::probe` using the `stub-cli` binary.
//!
//! Each test constructs a private temp directory with a shell-script wrapper
//! named after the CLI under test, adds only that directory to a custom PATH
//! string, and overrides the PATH environment variable just for the probe call.
//!
//! PATH-mutating tests acquire a global mutex to prevent parallel tests
//! from interfering with each other (PATH is process-wide on Unix).
//!
//! Per `rules/probe-driven-verification.md` MUST 1: assertions are structural
//! (match enum variant + field values), NOT regex/keyword matches.

use csq_core::cli_deps::{
    probe::{invalidate, probe},
    sanitize_for_display,
    version::{meets_minimum, parse as parse_version},
    CliStatus, InstallManager, SurfaceCli, Version, WrongBinaryReason,
};
use std::path::PathBuf;
use std::sync::Mutex;
use tempfile::TempDir;

/// Global mutex serialising all tests that mutate PATH.
/// All tests that call `probe_with_isolated_path` must hold this lock.
static PATH_MUTEX: Mutex<()> = Mutex::new(());

// ── Fixture helpers ──────────────────────────────────────────────────

/// Write a shell script wrapper at `<tmp>/<bin_name>` that emits
/// `stdout_line` (with a real trailing newline) using `printf`.
///
/// This approach avoids `exec stub-cli --stdout '...\n'` where `\n`
/// would be passed as a literal backslash-n.  `printf '%s\n'` emits
/// a real newline.
#[cfg(unix)]
fn write_version_stub(tmp: &TempDir, bin_name: &str, stdout_line: &str) -> PathBuf {
    let script_path = tmp.path().join(bin_name);
    // Escape single-quotes in the line for safe shell embedding.
    // Strip any trailing \n the caller may have included (printf adds its own).
    let line = stdout_line.trim_end_matches('\n');
    let escaped = line.replace('\'', "'\\''");
    let script = format!("#!/bin/sh\nprintf '%s\\n' '{escaped}'\n");
    std::fs::write(&script_path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }
    script_path
}

/// Write a shell script that hangs for `hang_ms` milliseconds.
/// Uses `sleep` with integer seconds (rounded up) for POSIX portability.
///
/// The script invokes `sleep` by its absolute path so it works even when
/// the test has restricted PATH to only the stub's temp directory.
#[cfg(unix)]
fn write_hang_stub(tmp: &TempDir, bin_name: &str, hang_ms: u64) -> PathBuf {
    let script_path = tmp.path().join(bin_name);
    // Round up to whole seconds for POSIX `sleep` compatibility.
    let secs = hang_ms.div_ceil(1000);
    // Resolve absolute path to `sleep` so the script works with a restricted PATH.
    let sleep_bin = std::process::Command::new("which")
        .arg("sleep")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "/bin/sleep".to_string());
    let script = format!("#!/bin/sh\n{sleep_bin} {secs}\n");
    std::fs::write(&script_path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }
    script_path
}

/// Write a shell script that emits N 'x' bytes with no newline.
/// Uses Python3 by absolute path so it works with a restricted PATH.
#[cfg(unix)]
fn write_emit_bytes_stub(tmp: &TempDir, bin_name: &str, n_bytes: usize) -> PathBuf {
    let script_path = tmp.path().join(bin_name);
    // Resolve absolute path to python3 so the script works with a restricted PATH.
    let python3_bin = std::process::Command::new("which")
        .arg("python3")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "/usr/bin/python3".to_string());
    // Use python3 to emit n_bytes × 'x' with no newline.
    let script = format!(
        "#!/bin/sh\n{python3_bin} -c \"import sys; sys.stdout.buffer.write(b'x' * {n_bytes}); sys.stdout.buffer.flush()\"\n"
    );
    std::fs::write(&script_path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }
    script_path
}

/// Run `probe(cli)` with `PATH` set to ONLY `path_dir` (no system PATH).
/// Acquires `PATH_MUTEX` to prevent parallel tests from interfering.
///
/// Lock order (testing.md MUST Rule 6): workspace-wide `test_env::lock()`
/// FIRST, then in-module `PATH_MUTEX`. Any other test crate that mutates
/// or reads PATH via `test_env::lock()` races with this helper otherwise.
fn probe_with_isolated_path(cli: SurfaceCli, path_dir: &std::path::Path) -> CliStatus {
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _guard = PATH_MUTEX.lock().unwrap();
    invalidate(cli);
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    // SAFETY: PATH_MUTEX serialises all PATH mutations in this test binary.
    unsafe {
        std::env::set_var("PATH", path_dir.to_str().unwrap());
    }
    let result = probe(cli);
    unsafe {
        std::env::set_var("PATH", &old_path);
    }
    invalidate(cli); // clean up cache after test
    result
}

/// Run `probe(cli)` with `PATH` set to ONLY `path_dir` AND `var=val` env var set.
/// Acquires `PATH_MUTEX` to prevent parallel tests from interfering.
#[cfg(unix)]
fn probe_with_isolated_path_and_env(
    cli: SurfaceCli,
    path_dir: &std::path::Path,
    var: &str,
    val: &str,
) -> CliStatus {
    // Lock order (testing.md MUST Rule 6): shared mutex BEFORE in-module mutex.
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _guard = PATH_MUTEX.lock().unwrap();
    invalidate(cli);
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let old_val = std::env::var_os(var);
    unsafe {
        std::env::set_var("PATH", path_dir.to_str().unwrap());
        std::env::set_var(var, val);
    }
    let result = probe(cli);
    unsafe {
        std::env::set_var("PATH", &old_path);
        match old_val {
            Some(v) => std::env::set_var(var, v),
            None => std::env::remove_var(var),
        }
    }
    invalidate(cli);
    result
}

// ── Pure-function tests (no subprocess, no PATH mutation) ────────────

/// AC: `meets_minimum(0.41.2-rc.1, 0.41.2) == true` (spec/13 §8).
#[test]
fn meets_minimum_prerelease_counts_as_meeting_floor() {
    let found = parse_version("0.41.2-rc.1").unwrap();
    let min = Version::new(0, 41, 2);
    assert!(meets_minimum(&found, &min));
}

/// AC: `meets_minimum(0.40.0, 0.41.2) == false`.
#[test]
fn meets_minimum_below_floor_is_false() {
    let found = Version::new(0, 40, 0);
    let min = Version::new(0, 41, 2);
    assert!(!meets_minimum(&found, &min));
}

/// AC: sanitize_for_display strips OSC-52 escape sequence.
#[test]
fn sanitize_strips_osc52() {
    let raw = "\x1b]52;c;SGVsbG8gV29ybGQ=\x07";
    let out = sanitize_for_display(raw);
    assert!(!out.contains('\x1b'));
    assert!(!out.contains('\x07'));
}

/// AC: install-path blocklist for codex contains `/opt/homebrew/Cellar/codex/`.
#[test]
fn install_path_blocklist_codex_cellar() {
    use csq_core::cli_deps::minimum::install_path_blocklist;
    let list = install_path_blocklist(SurfaceCli::Codex);
    assert!(list.contains(&"/opt/homebrew/Cellar/codex/"));
}

/// classify_install_manager pure-function tests.
#[test]
fn classify_install_manager_patterns() {
    use csq_core::cli_deps::install_path::classify_install_manager;

    let cases: &[(&str, InstallManager)] = &[
        (
            "/home/u/.local/share/claude/versions/2.0/claude",
            InstallManager::ClaudeNativeInstaller,
        ),
        (
            "/opt/homebrew/Caskroom/claude-code/2.1.138/claude",
            InstallManager::BrewCask,
        ),
        (
            "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex",
            InstallManager::NpmGlobal,
        ),
        (
            "/opt/homebrew/Cellar/gemini-cli/0.41.2/bin/gemini",
            InstallManager::BrewFormula,
        ),
        ("/usr/bin/claude", InstallManager::Unknown),
    ];
    for (path, expected) in cases {
        let p = PathBuf::from(path);
        assert_eq!(
            classify_install_manager(&p),
            *expected,
            "path {path:?} should classify as {expected:?}"
        );
    }
}

// ── Subprocess-based integration tests ───────────────────────────────

/// AC: `probe(Codex)` on stub returning `codex-cli 0.40.0\n` → `Ok { version: 0.40.0 }`.
#[test]
#[cfg(unix)]
fn probe_codex_ok_at_floor() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "codex-cli 0.40.0\n");
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::Ok { version, .. } if version == &Version::new(0, 40, 0)),
        "expected Ok {{ 0.40.0 }}; got {result:?}"
    );
}

/// AC: stub returning `codex-cli 0.24.0\n` → `Outdated { version: 0.24.0, min_required: 0.40.0 }`.
#[test]
#[cfg(unix)]
fn probe_codex_outdated() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "codex-cli 0.24.0\n");
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(
            &result,
            CliStatus::Outdated { version, min_required, .. }
            if version == &Version::new(0, 24, 0) && min_required == &Version::new(0, 40, 0)
        ),
        "expected Outdated {{ 0.24.0, min: 0.40.0 }}; got {result:?}"
    );
}

/// AC: stub returning `0.1.2505291658\n` (no prefix) → `WrongBinary { PrefixMismatch }`.
/// Codex's prefix gate fires first (before ComponentTooLarge parse).
#[test]
#[cfg(unix)]
fn probe_codex_no_prefix_returns_prefix_mismatch() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "0.1.2505291658\n");
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(
            &result,
            CliStatus::WrongBinary {
                reason: WrongBinaryReason::PrefixMismatch { .. },
                ..
            }
        ),
        "expected WrongBinary(PrefixMismatch); got {result:?}"
    );
}

/// AC: stub hanging 3000ms → `ProbeTimedOut` (elapsed_ms ≥ 1000, ≤ 6000).
///
/// Upper bound is 6000ms (not 3500): the 500ms slack over the 3000ms stub was
/// too thin under the load the M10 test binary adds, producing a latent flake
/// (deep-F6). 6000ms still proves the timeout class (a fast-parse would return
/// in <1000ms), while absorbing scheduling jitter on a loaded CI box.
#[test]
#[cfg(unix)]
fn probe_codex_timeout() {
    let tmp = TempDir::new().unwrap();
    write_hang_stub(&tmp, "codex", 3000);
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. } if *elapsed_ms >= 1000 && *elapsed_ms <= 6000),
        "expected ProbeTimedOut 1000..6000ms; got {result:?}"
    );
}

/// AC: stub emitting 10000 bytes with no newline → NOT `UnrecognizedVersion`.
/// Either `ProbeTimedOut` (killed before hitting 8KB) or
/// `WrongBinary { ComponentTooLarge }` (partial line at cap).
#[test]
#[cfg(unix)]
fn probe_codex_cap_exceeded_not_unrecognized_version() {
    let tmp = TempDir::new().unwrap();
    write_emit_bytes_stub(&tmp, "codex", 10_000);
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        !matches!(&result, CliStatus::UnrecognizedVersion { .. }),
        "must NOT be UnrecognizedVersion for cap-exceeded output; got {result:?}"
    );
    assert!(
        matches!(
            &result,
            CliStatus::ProbeTimedOut { .. }
                | CliStatus::WrongBinary {
                    reason: WrongBinaryReason::ComponentTooLarge { .. },
                    ..
                }
        ),
        "expected ProbeTimedOut or WrongBinary(ComponentTooLarge); got {result:?}"
    );
}

/// AC: `CSQ_CLI_DEPS_PROBE_DISABLE=1` → `Ok { version: 0.0.0, manager: Unknown }`.
#[test]
#[cfg(unix)]
fn probe_kill_switch_returns_ok_unparsed() {
    let tmp = TempDir::new().unwrap();
    // Binary irrelevant — kill-switch fires before PATH lookup.
    write_version_stub(&tmp, "codex", "codex-cli 0.128.0\n");
    let result = probe_with_isolated_path_and_env(
        SurfaceCli::Codex,
        tmp.path(),
        "CSQ_CLI_DEPS_PROBE_DISABLE",
        "1",
    );
    assert!(
        matches!(
            &result,
            CliStatus::Ok { version, .. }
            if version.major == 0 && version.minor == 0 && version.patch == 0
        ),
        "kill-switch must return Ok {{ 0.0.0 }}; got {result:?}"
    );
}

/// AC: binary absent from PATH → `Missing`.
#[test]
#[cfg(unix)]
fn probe_missing_binary() {
    // Create an isolated, empty-dir-only PATH.
    let tmp = TempDir::new().unwrap();
    // Don't write any "codex" — just an empty temp dir.
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::Missing),
        "expected Missing; got {result:?}"
    );
}

/// AC: stub returning `codex-cli 0.128.0\n` → `Ok { version: 0.128.0 }`.
#[test]
#[cfg(unix)]
fn probe_codex_above_floor_returns_ok() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "codex-cli 0.128.0\n");
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::Ok { version, .. } if version.minor == 128),
        "expected Ok {{ 0.128.0 }}; got {result:?}"
    );
}

/// AC: stub with correct prefix but no semver → `UnrecognizedVersion`.
#[test]
#[cfg(unix)]
fn probe_codex_unrecognized_version() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "codex-cli not-a-version\n");
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::UnrecognizedVersion { .. }),
        "expected UnrecognizedVersion; got {result:?}"
    );
}

/// AC: Claude `2.1.138 (Claude Code)\n` → `Ok { version: 2.1.138 }`.
#[test]
#[cfg(unix)]
fn probe_claude_ok() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "claude", "2.1.138 (Claude Code)\n");
    let result = probe_with_isolated_path(SurfaceCli::Claude, tmp.path());
    assert!(
        matches!(&result, CliStatus::Ok { version, .. } if version.major == 2),
        "expected Ok Claude 2.x; got {result:?}"
    );
}

/// AC: Gemini `0.41.2\n` → `Ok { version: 0.41.2 }`.
#[test]
#[cfg(unix)]
fn probe_gemini_ok_at_floor() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "gemini", "0.41.2\n");
    let result = probe_with_isolated_path(SurfaceCli::Gemini, tmp.path());
    assert!(
        matches!(&result, CliStatus::Ok { version, .. } if version == &Version::new(0, 41, 2)),
        "expected Ok {{ 0.41.2 }}; got {result:?}"
    );
}

/// AC: Cache works — second probe in SAME context returns same result.
/// After `invalidate`, changing the stub changes the result.
#[test]
#[cfg(unix)]
fn probe_cache_and_invalidate() {
    // Lock order (testing.md MUST Rule 6): shared mutex BEFORE in-module mutex.
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _guard = PATH_MUTEX.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "codex-cli 0.40.0\n");

    // First probe — populates cache.
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    unsafe {
        std::env::set_var("PATH", tmp.path().to_str().unwrap());
    }
    invalidate(SurfaceCli::Codex);
    let r1 = probe(SurfaceCli::Codex);
    assert!(
        matches!(&r1, CliStatus::Ok { version, .. } if version.minor == 40),
        "first probe must be Ok {{ 0.40.0 }}; got {r1:?}"
    );

    // Second probe — cache hit, returns same result.
    let r2 = probe(SurfaceCli::Codex);
    assert_eq!(r1, r2, "second probe must be cache hit");

    // Overwrite stub with different version, WITHOUT invalidating.
    write_version_stub(&tmp, "codex", "codex-cli 0.128.0\n");
    let r3 = probe(SurfaceCli::Codex);
    assert_eq!(r2, r3, "without invalidation, cached result unchanged");

    // Now invalidate and re-probe (PATH still set to tmp dir).
    invalidate(SurfaceCli::Codex);
    let r4 = probe(SurfaceCli::Codex);
    assert!(
        matches!(&r4, CliStatus::Ok { version, .. } if version.minor == 128),
        "after invalidate, must get new version 0.128.0; got {r4:?}"
    );

    unsafe {
        std::env::set_var("PATH", &old_path);
    }
    invalidate(SurfaceCli::Codex);
}

/// AC: Gemini outdated → `Outdated`.
#[test]
#[cfg(unix)]
fn probe_gemini_outdated() {
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "gemini", "0.38.0\n");
    let result = probe_with_isolated_path(SurfaceCli::Gemini, tmp.path());
    assert!(
        matches!(&result, CliStatus::Outdated { version, .. } if version == &Version::new(0, 38, 0)),
        "expected Outdated {{ 0.38.0 }}; got {result:?}"
    );
}

/// AC: WrongBinary — install path is blocklisted (pure function, no subprocess).
#[test]
fn probe_blocklisted_path_pure() {
    use csq_core::cli_deps::minimum::install_path_blocklist;
    let p = PathBuf::from("/opt/homebrew/Cellar/codex/0.1.2505291658/bin/codex");
    let path_str = p.to_string_lossy();
    let blocklist = install_path_blocklist(SurfaceCli::Codex);
    assert!(
        blocklist.iter().any(|pat| path_str.contains(*pat)),
        "Cellar/codex must be blocked"
    );
}

/// M9 A18: Zombie-reap test.
/// On Unix: probe returns ProbeTimedOut (child was killed promptly; the 5s stub
/// sleep is never fully awaited because the probe deadline fires first).
/// On Windows: skip (needs windows crate).
///
/// The structural assertion is "the probe RETURNED `ProbeTimedOut` rather than
/// blocking on `child.wait()` indefinitely" — a hung `child.wait()` would never
/// return and the test would hang the whole suite. The upper bound exists only
/// to catch the genuine indefinite-block regression, NOT to assert tight
/// latency: under a CPU-saturated full-workspace `cargo test` the spawn + kill +
/// reap path has been observed at ~7.5s, so the bound is 15s (was 6s, which
/// flaked under saturation — the 6s figure assumed only macOS shell-spawn
/// latency, not the contention of the entire workspace test running in
/// parallel). 15s still catches the ≥∞ block (a real zombie/hang never returns)
/// while tolerating worst-case load. The lower bound (≥1000ms) confirms the
/// probe actually waited for the deadline rather than failing fast on a missing
/// binary.
#[test]
#[cfg_attr(
    windows,
    ignore = "windows-zombie-reap-needs-windows-crate; see internal-design-docs"
)]
#[cfg(unix)]
fn probe_timeout_child_reaped_promptly() {
    let tmp = TempDir::new().unwrap();
    write_hang_stub(&tmp, "codex", 5000);
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. } if *elapsed_ms >= 1000 && *elapsed_ms < 15_000),
        "expected ProbeTimedOut 1000..15000ms; got {result:?}"
    );
}

// ── RAII ProbeGuard (F8) ──────────────────────────────────────────────

/// RAII guard that invalidates the cache entry on drop.
/// Wraps `probe_with_isolated_path` so tests that exit early (panic/assert)
/// still clean up the cache.
///
/// F8: Every subprocess integration test MUST use `ProbeGuard` or call
/// `invalidate` explicitly in both the success and failure paths.
#[allow(dead_code)]
struct ProbeGuard {
    cli: SurfaceCli,
    result: CliStatus,
}

impl ProbeGuard {
    fn run(cli: SurfaceCli, path_dir: &std::path::Path) -> Self {
        let result = probe_with_isolated_path(cli, path_dir);
        ProbeGuard { cli, result }
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        invalidate(self.cli);
    }
}

// ── H-3 regression: child kill + wait prevents blocking ──────────────

/// H-3 regression: stub that emits 8 KB then hangs 5 s.
///
/// # Structural invariant
///
/// The reader thread hits the 8 KiB cap and sends collected bytes to the main
/// thread.  The main thread kills + waits the child.  The probe MUST return
/// well before the stub's 5 s sleep expires.
///
/// # Why the previous wall-clock bound was the wrong axis
///
/// The prior test measured `total_elapsed` starting BEFORE `ProbeGuard::run`,
/// which blocks on `PATH_MUTEX` before spawning anything.  Under parallel
/// `cargo test --workspace` load the H-4 test holds PATH_MUTEX for up to
/// 5 × 2 s = 10 s, making `total_elapsed` = mutex_wait + probe_time.  Two
/// successive bound bumps (2db8ea8 → 12 000 ms, 353000b → 20 000 ms) did not
/// fix the flake because they were measuring the wrong quantity.
///
/// # Structural fix (Option 1 from the task brief)
///
/// Start timing AFTER PATH_MUTEX is acquired.  That makes `elapsed` measure
/// only `probe()` execution time — the actual H-3 claim — eliminating the
/// PATH_MUTEX wait from the measurement entirely.
///
/// The bound is 7 000 ms:
/// - ~2 500 ms probe timeout + reader-channel recv_timeout (2 s + spawn jitter)
/// - ~  500 ms kill() + wait() reap
/// - ~3 000 ms healthy path total
/// - 7 000 ms leaves 2x headroom for macOS scheduler jitter INSIDE probe(),
///   while remaining well below the 5 s stub sleep.
///
/// Under the H-3 regression (child.wait() blocks on the 5 s sleep), elapsed
/// would be ≥ 5 000 ms regardless of PATH_MUTEX wait time, so the bound
/// still catches the regression.
#[test]
#[cfg(unix)]
fn h3_cap_exceeded_returns_before_hang_completes() {
    use std::time::Instant;

    // Write a stub that emits 9000 'x' bytes then sleeps 5 s.
    let tmp = TempDir::new().unwrap();
    let python3_bin = std::process::Command::new("which")
        .arg("python3")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "/usr/bin/python3".to_string());

    let sleep_bin = std::process::Command::new("which")
        .arg("sleep")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "/bin/sleep".to_string());

    let script_path = tmp.path().join("codex");
    let script = format!(
        "#!/bin/sh\n\
         {python3_bin} -c \"import sys; sys.stdout.buffer.write(b'x' * 9000); sys.stdout.buffer.flush()\"\n\
         {sleep_bin} 5\n"
    );
    std::fs::write(&script_path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    // Lock order (testing.md MUST Rule 6): workspace-wide `test_env::lock()`
    // FIRST, then in-module `PATH_MUTEX`. Without the shared guard, any other
    // test crate that mutates `PATH` (or any env var) via `test_env::lock()`
    // races against this test's PATH mutation.
    let _shared_env_guard = csq_core::platform::test_env::lock();
    // Acquire PATH_MUTEX FIRST (after the shared guard), then start the clock.
    // This excludes PATH_MUTEX wait time from `elapsed`, so the measurement
    // reflects only probe() execution — the H-3 structural invariant.
    let _path_guard = PATH_MUTEX.lock().unwrap();
    invalidate(SurfaceCli::Codex);
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    // SAFETY: PATH_MUTEX serialises all PATH mutations in this test binary.
    unsafe {
        std::env::set_var("PATH", tmp.path().to_str().unwrap());
    }

    let start = Instant::now();
    let _result = probe(SurfaceCli::Codex);
    let elapsed = start.elapsed().as_millis();

    // Restore PATH and invalidate cache before any assertion (panic-safe).
    unsafe {
        std::env::set_var("PATH", &old_path);
    }
    invalidate(SurfaceCli::Codex);

    // The structural claim: probe() returned before the 5 s stub sleep expired.
    // Healthy path: ~3 000 ms (timeout + kill/reap).
    // H-3 regression path: ≥ 5 000 ms (child.wait() blocks on sleep).
    // Bound of 7 000 ms catches the regression while tolerating macOS
    // scheduler jitter inside probe() itself.
    assert!(
        elapsed < 7000,
        "H-3: probe() must return within 7 000 ms after PATH_MUTEX acquired; \
         took {elapsed} ms — if this fails, child.wait() is blocking on the 5 s sleep \
         (H-3 regression).  PATH_MUTEX wait is excluded from this measurement."
    );
}

// ── H-4 regression: reader thread is joined, no FD leak ──────────────

/// H-4 regression: run 50 probes with hang stubs; assert open FD count
/// does not grow unboundedly across the runs.
///
/// Without the H-4 fix the `std::thread::spawn` JoinHandle was dropped
/// without joining, leaving the thread's pipe FDs open until the thread
/// exited on its own.  After 50 probes the FD count would grow by ~150+.
/// With the fix all FDs are released before the probe returns, so the
/// count stays flat.
#[test]
#[cfg(unix)]
fn h4_no_fd_leak_across_repeated_probes() {
    use std::fs;

    let tmp = TempDir::new().unwrap();
    write_hang_stub(&tmp, "codex", 3000);

    // Helper: count /proc/self/fd entries (Linux) or /dev/fd (macOS).
    fn open_fd_count() -> usize {
        let fd_dir = if std::path::Path::new("/proc/self/fd").exists() {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        fs::read_dir(fd_dir)
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    // Run 5 probes with timeout stubs.  5 × 2s = 10s total, which is enough
    // to detect FD leaks (each leaked FD = one unclosed pipe end) while not
    // monopolizing the PATH_MUTEX long enough to starve concurrent tests.
    // Note: each ProbeGuard::run acquires+releases PATH_MUTEX per call; the
    // loop does NOT hold the mutex across iterations.
    let fd_before = open_fd_count();
    for _ in 0..5 {
        let _g = ProbeGuard::run(SurfaceCli::Codex, tmp.path());
    }

    let fd_after = open_fd_count();
    // With the H-4 fix, all pipe FDs are closed before probe() returns.
    // Without the fix, each probe leaks ~3 FDs (stdin/stdout/stderr of the
    // spawned thread).  5 probes → 15 leaked FDs is clearly detectable.
    // Allow 10 FD headroom for test framework noise (e.g. tempfile handles).
    assert!(
        fd_after <= fd_before + 10,
        "H-4: FD count grew by {} after 5 timeout-probes (before={}, after={}) — \
         likely reader thread FDs not closed (H-4 regression)",
        fd_after.saturating_sub(fd_before),
        fd_before,
        fd_after
    );
}

// ── H-2 regression: PATH walk bounded ────────────────────────────────

/// H-2 regression: PATH walk with 5000 entries returns within 100ms.
///
/// Without the H-2 fix an adversarially-long PATH (e.g. 100k entries) would
/// cause `find_in_path` to iterate indefinitely.  With `MAX_PATH_ENTRIES=4096`
/// the walk stops after 4096 entries.  5000 entries is enough to exercise the
/// cap while keeping wall-clock cost low.
#[test]
#[cfg(unix)]
fn h2_path_walk_bounded_under_5000_entries() {
    use csq_core::cli_deps::install_path::find_in_path;
    use std::time::Instant;

    // Build a PATH string with 5000 nonexistent directories.
    let entries: Vec<String> = (0..5000)
        .map(|i| format!("/nonexistent/path/entry/{i}"))
        .collect();
    let long_path = entries.join(":");

    // Lock order (testing.md MUST Rule 6): shared mutex BEFORE in-module mutex.
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let _guard = PATH_MUTEX.lock().unwrap();
    // SAFETY: PATH_MUTEX serialises all PATH mutations in this test binary.
    unsafe {
        std::env::set_var("PATH", &long_path);
    }

    let start = Instant::now();
    let result = find_in_path("__csq_h2_nonexistent_binary__");
    let elapsed = start.elapsed().as_millis();

    unsafe {
        std::env::set_var("PATH", old_path);
    }

    assert!(
        result.is_none(),
        "H-2: binary must not be found in fake PATH"
    );
    assert!(
        elapsed < 100,
        "H-2: PATH walk with 5000 entries must complete in <100ms; took {elapsed}ms"
    );
}
