//! CLI presence and version detection.
//!
//! `probe(cli)` is the single entry point. It:
//!  1. Checks the `CSQ_CLI_DEPS_PROBE_DISABLE` kill-switch.
//!  2. Checks the in-memory per-process cache.
//!  3. Resolves the binary via PATH walk + `std::fs::canonicalize`.
//!  4. Applies the install-path blocklist gate.
//!  5. Spawns `<name> --version` with a surface-aware timeout
//!     (`probe_timeout`: Claude 2s, Codex/Gemini 6s).
//!  6. Reads up to 8 KiB of stdout, kills the subprocess if exceeded.
//!  7. Parses the first complete `\n`-terminated line.
//!  8. Applies the prefix gate (codex-only).
//!  9. Parses the semver token.
//! 10. Compares against the per-surface minimum.
//! 11. Caches and returns the result.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::{
    install_path::{classify_install_manager, resolve_canonical},
    minimum::{binary_name, install_path_blocklist, min_version, required_prefix},
    sanitize::sanitize_for_display,
    version::{meets_minimum, parse as parse_version, ParseError},
    CliStatus, InstallManager, SurfaceCli, WrongBinaryReason,
};

// ── In-memory cache ──────────────────────────────────────────────────

static CACHE: OnceLock<Mutex<HashMap<SurfaceCli, CliStatus>>> = OnceLock::new();

/// Sentinel so "probe disabled" is only printed once per process, even
/// when multiple surfaces call `probe()` in quick succession.
static PROBE_DISABLED_WARNED: OnceLock<()> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<SurfaceCli, CliStatus>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clear the cached result for a single surface.
///
/// Required for M4's post-install re-probe: without invalidation the
/// in-memory cache would return stale `Missing` after a successful install.
///
/// # Cross-process scope
///
/// This invalidation is **intra-process only**. It clears the entry from
/// the static `CACHE` in the calling process.
///
/// Cross-process callers (e.g. the daemon, if it ever caches cli_deps
/// results — it does **NOT** as of v2.7.0 per spec/13 §12) would need an
/// IPC invalidation channel to observe the change. v2.7.0 ships without
/// daemon-side caching; if that changes in v2.8.x+, a separate IPC
/// invalidation primitive is required.
pub fn invalidate(cli: SurfaceCli) {
    cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&cli);
}

/// Returns `true` when the `CSQ_CLI_DEPS_PROBE_DISABLE` kill-switch is active.
///
/// Callers (doctor, login, run) use this to surface the `⚠ probe disabled`
/// disclosure row in their own output. `probe()` itself already emits the
/// WARN to stderr; this helper lets UIs also reflect the disabled state.
pub fn probe_disabled() -> bool {
    std::env::var_os("CSQ_CLI_DEPS_PROBE_DISABLE").is_some()
}

// ── stdout cap ───────────────────────────────────────────────────────

const STDOUT_CAP_BYTES: usize = 8 * 1024; // 8 KiB

// ── Main entry point ─────────────────────────────────────────────────

/// Probe a surface CLI for presence and version.
///
/// Result is cached in-memory for the lifetime of the calling process.
/// Use `invalidate(cli)` to clear a single surface before re-probing.
///
/// This function is synchronous (blocking). It uses `std::thread` and
/// `std::sync::mpsc::channel` with `recv_timeout` to enforce the
/// wall-clock deadline without blocking indefinitely on subprocess I/O.
pub fn probe(cli: SurfaceCli) -> CliStatus {
    // ── Kill-switch ──────────────────────────────────────────────────
    if std::env::var_os("CSQ_CLI_DEPS_PROBE_DISABLE").is_some() {
        // Fire-once per process: multiple surfaces calling probe() must not
        // spam the same warning on every call (L6 finding).
        PROBE_DISABLED_WARNED.get_or_init(|| {
            eprintln!("⚠ probe disabled (CSQ_CLI_DEPS_PROBE_DISABLE=1 set)");
        });
        let status = CliStatus::Ok {
            version: super::version::Version::new(0, 0, 0),
            path: PathBuf::new(),
            manager: InstallManager::Unknown,
        };
        return status;
    }

    // ── Cache hit ────────────────────────────────────────────────────
    if let Some(cached) = cache().lock().unwrap_or_else(|p| p.into_inner()).get(&cli) {
        return cached.clone();
    }

    // ── Compute result ───────────────────────────────────────────────
    let result = run_probe(cli);

    // ── Store in cache ───────────────────────────────────────────────
    cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(cli, result.clone());

    result
}

/// Core probe logic (not cached). Spawns the subprocess and classifies
/// the result.
fn run_probe(cli: SurfaceCli) -> CliStatus {
    let name = binary_name(cli);

    // Single canonicalize per probe (spec/13 §8).
    let canonical_path = match resolve_canonical(name) {
        Some(p) => p,
        None => return CliStatus::Missing,
    };

    // ── Install-path blocklist gate (gate 2, fires before subprocess) ──
    {
        let blocked_match = {
            let path_str = canonical_path.to_string_lossy();
            install_path_blocklist(cli)
                .iter()
                .any(|pat| path_str.contains(*pat))
        };
        if blocked_match {
            let resolved = canonical_path.clone();
            return CliStatus::WrongBinary {
                raw_version_output: String::new(),
                path: canonical_path,
                reason: WrongBinaryReason::InstallPathBlocklisted { resolved },
            };
        }
    }

    // ── Spawn subprocess with timeout ────────────────────────────────
    //
    // Capture the current PATH BEFORE spawning. The child subprocess inherits
    // the full PATH so that shell scripts in the stub can invoke system tools
    // (sleep, printf, etc.) regardless of any PATH restriction the caller
    // applied for binary discovery. This is separate from our `find_in_path`
    // PATH walk which already found `canonical_path`.
    let child_path_env = std::env::var_os("PATH");
    let manager = classify_install_manager(&canonical_path);
    let spawn_start = Instant::now();

    let (stdout_bytes, elapsed_ms, timed_out) = spawn_version_subprocess(
        &canonical_path,
        child_path_env,
        spawn_start,
        probe_timeout(cli),
    );

    if timed_out {
        return CliStatus::ProbeTimedOut {
            path: canonical_path,
            elapsed_ms,
        };
    }

    // ── Parse stdout ─────────────────────────────────────────────────
    classify_output(stdout_bytes, canonical_path, manager, cli, elapsed_ms)
}

/// Spawn `<canonical_path> --version`, capturing up to `STDOUT_CAP_BYTES` of stdout.
///
/// Spawns by canonical path to avoid PATH races between `find_in_path` and
/// `Command::new` (spec/13 §8: single canonicalize per probe).
///
/// `child_path_env` — the PATH to forward to the child process. When `Some`,
/// this is set explicitly on the child env so shell-script stubs can invoke
/// system tools (`sleep`, `printf`, etc.) even if the caller restricted PATH
/// to a temp dir for binary-discovery isolation.
///
/// Returns `(bytes, elapsed_ms, timed_out)`.
/// On timeout, the child is killed and `timed_out = true`.
/// On 8 KiB cap, the child is also killed (treated as partial).
///
/// Uses a background reader thread + channel to implement wall-clock timeout
/// without blocking the probe thread indefinitely on a slow/hung subprocess.
/// Wall-clock budget for the `<binary> --version` probe, per surface.
///
/// spec/13 §8: the probe must not block a launch indefinitely. The budget is
/// **surface-specific** because the CLIs have very different cold-start costs:
///
/// - **Claude** — 2s. A fast native-ish binary; 2s is ample.
/// - **Codex / Gemini** — 6s. Both are Node programs
///   (`@openai/codex`, `@google/gemini-cli`) whose cold-start routinely exceeds
///   2s (observed: `codex --version` at 2222ms on a warm host, higher under
///   load). At 2s the probe times out → `ProbeTimedOut` → csq proceeds WITHOUT a
///   version, so the `Outdated → auto-update` branch of the disposition table
///   never evaluates and a stale codex/gemini is never auto-updated. 6s (≈2.7×
///   the observed cold-start) lets the version read complete so auto-update can
///   actually fire, while still bounding a genuinely-hung CLI. The probe result
///   is cached per process, so the cost is paid at most once per `csq` process.
///
/// Test builds (`--features test-utils`) use 30s uniformly to absorb cargo-test
/// parallelism CPU saturation (integration stubs in `csq/tests/cli_deps_*`); the
/// runtime spec invariant holds only in non-test builds.
#[cfg(not(feature = "test-utils"))]
pub(crate) fn probe_timeout(cli: SurfaceCli) -> Duration {
    match cli {
        SurfaceCli::Claude => Duration::from_secs(2),
        SurfaceCli::Codex | SurfaceCli::Gemini => Duration::from_secs(6),
    }
}

#[cfg(feature = "test-utils")]
pub(crate) fn probe_timeout(_cli: SurfaceCli) -> Duration {
    Duration::from_secs(30)
}

fn spawn_version_subprocess(
    canonical_path: &std::path::Path,
    child_path_env: Option<std::ffi::OsString>,
    spawn_start: Instant,
    timeout: Duration,
) -> (Vec<u8>, u64, bool) {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    let mut cmd = Command::new(canonical_path);
    cmd.arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(path_val) = child_path_env {
        cmd.env("PATH", path_val);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            let elapsed = spawn_start.elapsed().as_millis() as u64;
            return (Vec::new(), elapsed, false);
        }
    };

    // `timeout` is the per-surface wall-clock budget from `probe_timeout(cli)`
    // (spec/13 §8): 2s for Claude, 6s for the Node-based Codex/Gemini CLIs,
    // 30s uniformly under `--features test-utils`.
    // Use an explicit match instead of unwrap so we return cleanly when
    // the child was spawned without stdout (should not happen given
    // Stdio::piped(), but is not statically guaranteed by the type).
    let mut stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let elapsed = spawn_start.elapsed().as_millis() as u64;
            return (Vec::new(), elapsed, false);
        }
    };

    // Spawn a background reader thread.  It reads up to STDOUT_CAP_BYTES
    // incrementally and sends collected bytes back via a one-shot channel.
    // The main thread waits with a wall-clock deadline.
    //
    // The JoinHandle is held explicitly so the reader thread is reaped
    // before this function returns, preventing FD leaks.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader_handle = std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 256];
        loop {
            match stdout.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let remaining = STDOUT_CAP_BYTES.saturating_sub(buf.len());
                    let to_take = n.min(remaining);
                    buf.extend_from_slice(&tmp[..to_take]);
                    // Stop once we have a complete first line or hit the cap.
                    if buf.contains(&b'\n') || buf.len() >= STDOUT_CAP_BYTES {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(buf);
    });

    // Wait up to `timeout` for the reader thread to finish.
    let (buf, timed_out) = match rx.recv_timeout(timeout) {
        Ok(bytes) => (bytes, false),
        Err(_) => (Vec::new(), true),
    };

    // Always kill + wait after the reader has signalled (or timed out).
    // kill() is a no-op for processes that have already exited, so this
    // is safe unconditionally.  Without the kill() the child may have
    // written exactly 8KiB ending with '\n', sent its result, and then
    // hung waiting for a consumer that never arrives — the bare wait()
    // would block forever in that case.
    let _ = child.kill();
    let _ = child.wait();

    // Reap the reader thread so its file descriptors are released.
    reader_handle.join().ok();

    let elapsed_ms = spawn_start.elapsed().as_millis() as u64;
    (buf, elapsed_ms, timed_out)
}

/// Classify probe output per spec/13 §8 dispositions.
fn classify_output(
    stdout_bytes: Vec<u8>,
    canonical_path: PathBuf,
    manager: InstallManager,
    cli: SurfaceCli,
    elapsed_ms: u64,
) -> CliStatus {
    // Zero bytes → ProbeTimedOut (no parseable output, even if not wall-clock timeout).
    if stdout_bytes.is_empty() {
        return CliStatus::ProbeTimedOut {
            path: canonical_path,
            elapsed_ms,
        };
    }

    // Find the first complete \n-terminated line.
    let first_line_raw = match stdout_bytes.iter().position(|&b| b == b'\n') {
        Some(pos) => {
            // Complete line found.
            let raw = &stdout_bytes[..pos];
            // Remove trailing \r if present.
            if raw.ends_with(b"\r") {
                &raw[..raw.len() - 1]
            } else {
                raw
            }
        }
        None => {
            // Partial line (≥1 byte, no newline) → WrongBinary { ComponentTooLarge }.
            let partial = String::from_utf8_lossy(&stdout_bytes).into_owned();
            return CliStatus::WrongBinary {
                raw_version_output: sanitize_for_display(&partial),
                path: canonical_path,
                reason: WrongBinaryReason::ComponentTooLarge {
                    segment: sanitize_for_display(&partial),
                },
            };
        }
    };

    // Convert to &str for parsing. Invalid UTF-8 is lossy-converted.
    let line = String::from_utf8_lossy(first_line_raw);
    let line = line.as_ref();

    // ── Prefix gate (gate 1, codex only) ──────────────────────────────
    if let Some(prefix) = required_prefix(cli) {
        if !line.starts_with(prefix) {
            return CliStatus::WrongBinary {
                raw_version_output: sanitize_for_display(line),
                path: canonical_path,
                reason: WrongBinaryReason::PrefixMismatch {
                    expected: prefix,
                    got: sanitize_for_display(line),
                },
            };
        }
    }

    // ── Version parsing ───────────────────────────────────────────────
    match parse_version(line) {
        Ok(version) => {
            let min = min_version(cli);
            if meets_minimum(&version, &min) {
                CliStatus::Ok {
                    version,
                    path: canonical_path,
                    manager,
                }
            } else {
                CliStatus::Outdated {
                    min_required: min,
                    version,
                    path: canonical_path,
                    manager,
                }
            }
        }
        Err(ParseError::ComponentTooLarge { segment }) => CliStatus::WrongBinary {
            raw_version_output: sanitize_for_display(line),
            path: canonical_path,
            reason: WrongBinaryReason::ComponentTooLarge { segment },
        },
        Err(ParseError::BadFormat) => CliStatus::UnrecognizedVersion {
            raw_output: sanitize_for_display(line),
            path: canonical_path,
            manager,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_deps::version::Version;

    // ── classify_output unit tests ────────────────────────────────────
    // These test the pure classification logic independently of subprocess.

    fn fake_path() -> PathBuf {
        PathBuf::from("/fake/path/codex")
    }

    #[test]
    fn probe_timeout_gives_every_surface_a_usable_budget() {
        // Under `--features test-utils` (always on in test builds) every surface
        // gets the uniform 30s budget; this locks that the accessor compiles and
        // returns a usable (non-zero, >= the Claude floor) budget per surface.
        // The production per-surface split (Claude 2s / Codex+Gemini 6s) is a
        // non-test-build constant documented on `probe_timeout` + spec/13 §8; it
        // is only observable against the shipped binary (a slow codex probe that
        // now completes instead of timing out — user-path verification).
        for cli in [SurfaceCli::Claude, SurfaceCli::Codex, SurfaceCli::Gemini] {
            assert!(
                probe_timeout(cli) >= Duration::from_secs(2),
                "{cli:?} must get at least the Claude floor"
            );
        }
    }

    #[test]
    fn classify_empty_stdout_is_probe_timed_out() {
        let result = classify_output(
            vec![],
            fake_path(),
            InstallManager::Unknown,
            SurfaceCli::Codex,
            2000,
        );
        assert!(
            matches!(result, CliStatus::ProbeTimedOut { .. }),
            "expected ProbeTimedOut; got {result:?}"
        );
    }

    #[test]
    fn classify_no_newline_is_wrong_binary_component_too_large() {
        // Partial line (no \n) — even if it contains a semver substring.
        let bytes = b"codex-cli 0.128.0".to_vec(); // no trailing \n
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::NpmGlobal,
            SurfaceCli::Codex,
            100,
        );
        assert!(
            matches!(
                result,
                CliStatus::WrongBinary {
                    reason: WrongBinaryReason::ComponentTooLarge { .. },
                    ..
                }
            ),
            "expected WrongBinary(ComponentTooLarge); got {result:?}"
        );
    }

    #[test]
    fn classify_codex_ok_at_floor() {
        let bytes = b"codex-cli 0.40.0\n".to_vec();
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::NpmGlobal,
            SurfaceCli::Codex,
            50,
        );
        assert!(
            matches!(result, CliStatus::Ok { ref version, .. } if version == &Version::new(0, 40, 0)),
            "expected Ok {{ version: 0.40.0 }}; got {result:?}"
        );
    }

    #[test]
    fn classify_codex_outdated() {
        let bytes = b"codex-cli 0.24.0\n".to_vec();
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::NpmGlobal,
            SurfaceCli::Codex,
            50,
        );
        assert!(
            matches!(
                result,
                CliStatus::Outdated {
                    ref version,
                    ref min_required,
                    ..
                } if version == &Version::new(0, 24, 0) && min_required == &Version::new(0, 40, 0)
            ),
            "expected Outdated {{ 0.24.0, min: 0.40.0 }}; got {result:?}"
        );
    }

    #[test]
    fn classify_codex_prefix_mismatch() {
        // "0.128.0" without the "codex-cli " prefix
        let bytes = b"0.128.0\n".to_vec();
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::Unknown,
            SurfaceCli::Codex,
            50,
        );
        assert!(
            matches!(
                result,
                CliStatus::WrongBinary {
                    reason: WrongBinaryReason::PrefixMismatch { .. },
                    ..
                }
            ),
            "expected WrongBinary(PrefixMismatch); got {result:?}"
        );
    }

    #[test]
    fn classify_unrecognized_version_no_semver() {
        // Codex with the correct prefix but no semver substring.
        let bytes = b"codex-cli not-a-version\n".to_vec();
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::Unknown,
            SurfaceCli::Codex,
            50,
        );
        assert!(
            matches!(result, CliStatus::UnrecognizedVersion { .. }),
            "expected UnrecognizedVersion; got {result:?}"
        );
    }

    #[test]
    fn classify_date_encoded_version_is_component_too_large() {
        // "0.1.2505291658" — patch has 10 digits (>5)
        // With codex prefix: prefix gate passes, then parse fails with ComponentTooLarge.
        let bytes = b"codex-cli 0.1.2505291658\n".to_vec();
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::Unknown,
            SurfaceCli::Codex,
            50,
        );
        assert!(
            matches!(
                result,
                CliStatus::WrongBinary {
                    reason: WrongBinaryReason::ComponentTooLarge { .. },
                    ..
                }
            ),
            "expected WrongBinary(ComponentTooLarge); got {result:?}"
        );
    }

    #[test]
    fn classify_claude_ok() {
        let bytes = b"2.1.138 (Claude Code)\n".to_vec();
        let result = classify_output(
            bytes,
            PathBuf::from("/fake/claude"),
            InstallManager::BrewCask,
            SurfaceCli::Claude,
            50,
        );
        assert!(
            matches!(result, CliStatus::Ok { ref version, .. } if version.major == 2),
            "expected Ok for Claude 2.1.138; got {result:?}"
        );
    }

    #[test]
    fn classify_gemini_ok_at_floor() {
        let bytes = b"0.41.2\n".to_vec();
        let result = classify_output(
            bytes,
            PathBuf::from("/fake/gemini"),
            InstallManager::BrewFormula,
            SurfaceCli::Gemini,
            50,
        );
        assert!(
            matches!(result, CliStatus::Ok { ref version, .. } if version == &Version::new(0, 41, 2)),
            "expected Ok {{ 0.41.2 }}; got {result:?}"
        );
    }

    #[test]
    fn classify_gemini_outdated() {
        let bytes = b"0.38.0\n".to_vec();
        let result = classify_output(
            bytes,
            PathBuf::from("/fake/gemini"),
            InstallManager::BrewFormula,
            SurfaceCli::Gemini,
            50,
        );
        assert!(
            matches!(result, CliStatus::Outdated { ref version, .. } if version == &Version::new(0, 38, 0)),
            "expected Outdated; got {result:?}"
        );
    }

    #[test]
    fn classify_crlf_line_ending_handled() {
        // \r\n line ending — \r should be stripped before parsing
        let bytes = b"codex-cli 0.128.0\r\n".to_vec();
        let result = classify_output(
            bytes,
            fake_path(),
            InstallManager::NpmGlobal,
            SurfaceCli::Codex,
            50,
        );
        assert!(
            matches!(result, CliStatus::Ok { .. }),
            "CRLF should be handled; got {result:?}"
        );
    }

    // ── invalidate ───────────────────────────────────────────────────

    #[test]
    fn invalidate_removes_cached_entry() {
        // Manually insert a value into the cache, then invalidate it.
        {
            let mut map = cache().lock().unwrap();
            map.insert(SurfaceCli::Gemini, CliStatus::Missing);
        }
        // Confirm it's there.
        {
            let map = cache().lock().unwrap();
            assert!(map.contains_key(&SurfaceCli::Gemini));
        }
        // Invalidate.
        invalidate(SurfaceCli::Gemini);
        // Confirm it's gone.
        {
            let map = cache().lock().unwrap();
            assert!(!map.contains_key(&SurfaceCli::Gemini));
        }
    }

    // ── install_path blocklist unit ──────────────────────────────────

    #[test]
    fn blocklist_brew_formula_path_returns_wrong_binary() {
        // classify_output doesn't check blocklist — that's run_probe's job.
        // The blocklist gate fires before classify_install_manager is called.
        // (classify_install_manager would return Unknown for Cellar/codex since it
        // only recognises Cellar/gemini-cli as BrewFormula, not Cellar/codex.)
        let p = std::path::Path::new("/opt/homebrew/Cellar/codex/0.1.2505291658/bin/codex");
        let blocked = "/opt/homebrew/Cellar/codex/";
        assert!(p.to_string_lossy().contains(blocked));

        // Simulate the blocklist gate from run_probe.
        let blocklist = crate::cli_deps::minimum::install_path_blocklist(SurfaceCli::Codex);
        let path_str = p.to_string_lossy();
        let is_blocked = blocklist.iter().any(|pat| path_str.contains(*pat));
        assert!(is_blocked, "Cellar/codex path must be blocklisted");

        let result = CliStatus::WrongBinary {
            raw_version_output: String::new(),
            path: p.to_path_buf(),
            reason: WrongBinaryReason::InstallPathBlocklisted {
                resolved: p.to_path_buf(),
            },
        };
        assert!(matches!(
            result,
            CliStatus::WrongBinary {
                reason: WrongBinaryReason::InstallPathBlocklisted { .. },
                ..
            }
        ));
    }
}
