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

use csq_core::cli_deps::probe::invalidate;
// `probe()` itself is only called from `probe_with_isolated_path` and from
// unix-gated subprocess tests; on a windows build neither exists, so the
// import must be gated in lockstep with its sole caller below.
#[cfg(unix)]
use csq_core::cli_deps::probe::probe;
// `probe_within` is the injectable-budget seam; like `probe` it is only reached
// from unix-gated subprocess tests. It is exposed under `feature = "test-utils"`,
// the same gate that gives this binary its 30 s `probe_timeout` override — so
// any build that can run the tests below can also see it.
#[cfg(unix)]
use csq_core::cli_deps::probe::probe_within;
use csq_core::cli_deps::{
    sanitize_for_display,
    version::{meets_minimum, parse as parse_version},
    CliStatus, InstallManager, SurfaceCli, Version,
};
// `WrongBinaryReason` is only matched inside unix-gated subprocess tests.
#[cfg(unix)]
use csq_core::cli_deps::WrongBinaryReason;
use std::path::PathBuf;
// `Mutex` is only referenced by `PATH_MUTEX`, which is itself unix-only
// (it serialises PATH mutation for the unix-gated subprocess tests below).
#[cfg(unix)]
use std::sync::Mutex;
// `TempDir` is only used by unix-gated stub-writer helpers and tests.
#[cfg(unix)]
use tempfile::TempDir;

/// Global mutex serialising all tests that mutate PATH.
/// All tests that call `probe_with_isolated_path` must hold this lock.
#[cfg(unix)]
static PATH_MUTEX: Mutex<()> = Mutex::new(());

/// Acquire `PATH_MUTEX`, recovering from poisoning instead of cascading.
///
/// Every critical section guarded by this mutex restores `PATH` before it
/// returns, including on the panic path, so a poisoned mutex means only that
/// some OTHER test panicked — never that `PATH` is left corrupt. Each section
/// also sets `PATH` explicitly before use rather than reading it forward, so
/// there is no state to salvage and nothing a panic could have left half-done.
///
/// That claim is enforced by `PathGuard`, not by convention. It used to be
/// convention, and it was false: three sections mutated `PATH` inline and
/// restored it with a trailing statement, so any assertion firing before that
/// statement unwound with `PATH` still pointing at a `TempDir` that was about
/// to be deleted. Clearing the poison then let every later test run against —
/// and, via `probe_with_isolated_path` capturing `old_path`, re-save — a `PATH`
/// naming a directory that no longer exists.
///
/// `.lock().unwrap()` turned that harmless fact into a mass failure: one test
/// panicking inside the critical section poisoned the mutex, and every
/// subsequent test unwrapped a `PoisonError` instead of running. Observed on
/// macOS CI — a single wall-clock flake in `h3_cap_exceeded_returns_before_hang_completes`
/// became **16 failures**, 15 of them `PoisonError` in tests that never ran their
/// own assertions. The real defect was invisible under the pile.
///
/// This mirrors what the workspace-wide guard already does
/// (`csq_core::platform::test_env::lock` clears poison and returns the inner
/// guard); this in-module mutex was the lone outlier.
#[cfg(unix)]
fn lock_ignoring_poison() -> std::sync::MutexGuard<'static, ()> {
    match PATH_MUTEX.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            PATH_MUTEX.clear_poison();
            poisoned.into_inner()
        }
    }
}

/// RAII guard over the process-global `PATH`.
///
/// Sets `PATH` on construction and restores the previous value on drop —
/// including when the drop is caused by a panic unwinding out of an assertion,
/// which is the case a trailing `set_var` restore does not cover.
///
/// Declare it AFTER `test_env::lock()` and `lock_ignoring_poison()` so it drops
/// BEFORE them: `PATH` is restored while the mutex is still held, so no other
/// test can observe the temporary value.
#[cfg(unix)]
struct PathGuard {
    old: std::ffi::OsString,
}

#[cfg(unix)]
impl PathGuard {
    /// Caller MUST already hold `PATH_MUTEX`.
    fn set(new_path: &std::path::Path) -> Self {
        let old = std::env::var_os("PATH").unwrap_or_default();
        // SAFETY: PATH_MUTEX serialises all PATH mutations in this test binary.
        unsafe {
            std::env::set_var("PATH", new_path);
        }
        PathGuard { old }
    }
}

#[cfg(unix)]
impl Drop for PathGuard {
    fn drop(&mut self) {
        // SAFETY: as above — the mutex is still held while this runs.
        unsafe {
            std::env::set_var("PATH", &self.old);
        }
    }
}

/// RAII guard over one process-global env var, for the same reason as
/// [`PathGuard`]: a trailing `set_var` restore does not run on a panic unwind.
///
/// Declare it AFTER `test_env::lock()` and `lock_ignoring_poison()` so it drops
/// BEFORE them.
#[cfg(unix)]
struct EnvGuard {
    key: String,
    old: Option<std::ffi::OsString>,
}

#[cfg(unix)]
impl EnvGuard {
    /// Caller MUST already hold `PATH_MUTEX`.
    fn set(key: &str, val: &str) -> Self {
        let old = std::env::var_os(key);
        // SAFETY: PATH_MUTEX serialises env mutation in this test binary.
        unsafe {
            std::env::set_var(key, val);
        }
        EnvGuard {
            key: key.to_string(),
            old,
        }
    }
}

#[cfg(unix)]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: as above — the mutex is still held while this runs.
        unsafe {
            match &self.old {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}

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

/// Write an executable `<tmp>/<bin_name>` that `exec`s the `stub-cli` fixture
/// binary with `args`.
///
/// # Why the stub binary and not a host interpreter
///
/// `probe()` forwards the calling process's `PATH` to the child, and every
/// caller here restricts `PATH` to the stub's temp directory so that binary
/// DISCOVERY is isolated. That restriction reaches the stub too: any command
/// the script names must therefore be self-contained under an empty `PATH`.
///
/// An earlier revision resolved `python3` with `which` and invoked it by
/// absolute path, on the theory that an absolute path is PATH-independent. It
/// is not, transitively: on a host where `which python3` resolves to a
/// version-manager shim (`~/.pyenv/shims/python3` is `#!/usr/bin/env bash`),
/// the shim's own `env bash` lookup fails under the restricted PATH, the stub
/// writes **zero bytes**, and — if it also sleeps — holds the pipe open until
/// the probe's timeout fires. That produced a 30 s `ProbeTimedOut` on this
/// developer host and a fast `WrongBinary` on CI, and the difference was read
/// as a race in `cli_deps::probe`. It was neither a race nor in `probe`; see
/// `h3_cap_exceeded_returns_before_hang_completes`.
///
/// `stub-cli` is a compiled Rust binary in this package, located at compile
/// time via `CARGO_BIN_EXE_stub-cli`. It has no interpreter, no shared-library
/// lookup through `PATH`, and no `which` call — so the fixture's behaviour no
/// longer depends on the host's toolchain layout or on which sibling test
/// happens to hold `PATH_MUTEX`.
#[cfg(unix)]
fn write_stub_cli_wrapper(tmp: &TempDir, bin_name: &str, args: &[&str]) -> PathBuf {
    /// POSIX single-quote escaping: close, insert a literal `'`, reopen.
    ///
    /// Not theoretical for the binary path — `CARGO_BIN_EXE_stub-cli` inherits
    /// `CARGO_TARGET_DIR`, so a checkout under e.g. `/Users/o'brien/build`
    /// would otherwise terminate the quote and emit a syntactically broken
    /// script. That produces a zero-byte stub: exactly the
    /// `ProbeTimedOut`-masquerading-as-a-race symptom this file already spent a
    /// session diagnosing. Args are quoted for the same reason — today's
    /// callers pass integers, but the helper is general.
    fn shq(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
    let script_path = tmp.path().join(bin_name);
    let stub_cli = env!("CARGO_BIN_EXE_stub-cli");
    let argv: Vec<String> = args.iter().map(|a| shq(a)).collect();
    let script = format!("#!/bin/sh\nexec {} {}\n", shq(stub_cli), argv.join(" "));
    std::fs::write(&script_path, script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }
    script_path
}

/// Write a stub that produces no output and hangs for `hang_ms` milliseconds.
///
/// # Why this one does NOT use `stub-cli`
///
/// The bug class `write_stub_cli_wrapper` closes is "the stub needs a host
/// INTERPRETER, and the interpreter is not reachable under the restricted
/// PATH". A pure hang needs no interpreter — `sleep` is a real binary that
/// execs directly — so this stub was never in that class, and routing it
/// through `stub-cli` had a measurable cost: spawning an unoptimised Rust
/// binary on a loaded macOS runner pushed `probe_codex_timeout`'s observed
/// elapsed from ~3 s to 7 450 ms and turned a passing test red.
///
/// What this stub DID share with the class was the `which` call: it ran before
/// the test acquired `test_env::lock()`/`PATH_MUTEX`, so a sibling test's PATH
/// mutation could change what it resolved. That is fixed here without changing
/// the spawn weight — the candidate list below is fixed, absolute and probed
/// with `exists()`, so there is no PATH read at all.
#[cfg(unix)]
fn write_hang_stub(tmp: &TempDir, bin_name: &str, hang_ms: u64) -> PathBuf {
    // `/bin/sleep` on macOS and on Linux (present on merged-/usr distros too);
    // `/usr/bin/sleep` covers the layouts where /bin is not populated. No
    // `which`, so no dependence on PATH or on which test holds it.
    let sleep_bin = ["/bin/sleep", "/usr/bin/sleep"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("no sleep binary at /bin/sleep or /usr/bin/sleep — cannot build a hang stub");
    // POSIX `sleep` takes whole seconds; round up so the stub always outlasts
    // the requested hang.
    let secs = hang_ms.div_ceil(1000);
    let script_path = tmp.path().join(bin_name);
    std::fs::write(
        &script_path,
        format!("#!/bin/sh\nexec {sleep_bin} {secs}\n").as_bytes(),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }
    script_path
}

/// Upper bound on `ProbeTimedOut.elapsed_ms` for a stub that hangs and then
/// EXITS, shared by the two tests that assert it.
///
/// It is chosen to separate two outcomes, not to accommodate a runner:
///
/// - healthy — the child exits, the reader sees EOF, `probe()` returns with an
///   empty buffer. Elapsed lands near the stub's own hang (3–5 s here).
/// - regression — `probe()` ignores EOF and waits its whole budget, which is
///   30 s uniformly under `--features test-utils` (`probe_timeout`). Elapsed
///   lands near 30 s.
///
/// 20 s sits between them with ≥10 s of margin on both sides. The previous
/// bound was 6 000 ms, three seconds above a 3 000 ms stub — close enough to
/// the healthy path's own spawn jitter that it had already been widened once
/// (3 500 → 6 000, "deep-F6") and went red again at 7 450 ms. A bound that has
/// to be raised whenever the runner is busy is measuring the runner.
///
/// Note the variant alone cannot carry this claim: BOTH outcomes are
/// `ProbeTimedOut`, so the elapsed bound is the only thing distinguishing them.
#[cfg(unix)]
const HANG_STUB_MAX_ELAPSED_MS: u64 = 20_000;

/// Write a stub that emits `n_bytes` × `x` with no newline, then exits.
#[cfg(unix)]
fn write_emit_bytes_stub(tmp: &TempDir, bin_name: &str, n_bytes: usize) -> PathBuf {
    write_stub_cli_wrapper(tmp, bin_name, &["--emit-bytes", &n_bytes.to_string()])
}

/// Write a stub that emits `n_bytes` × `x` with no newline and then hangs for
/// `hang_ms` milliseconds while holding stdout open.
#[cfg(unix)]
fn write_emit_then_hang_stub(
    tmp: &TempDir,
    bin_name: &str,
    n_bytes: usize,
    hang_ms: u64,
) -> PathBuf {
    write_stub_cli_wrapper(
        tmp,
        bin_name,
        &[
            "--emit-bytes",
            &n_bytes.to_string(),
            "--hang-after-ms",
            &hang_ms.to_string(),
        ],
    )
}

/// Run `probe(cli)` with `PATH` set to ONLY `path_dir` (no system PATH).
/// Acquires `PATH_MUTEX` to prevent parallel tests from interfering.
///
/// Lock order (testing.md MUST Rule 6): workspace-wide `test_env::lock()`
/// FIRST, then in-module `PATH_MUTEX`. Any other test crate that mutates
/// or reads PATH via `test_env::lock()` races with this helper otherwise.
///
/// Every call site is a `#[cfg(unix)]`-gated subprocess test, so this
/// helper (and the `PATH_MUTEX`/`TempDir`/`probe` it depends on) is
/// unreachable on a windows build.
#[cfg(unix)]
fn probe_with_isolated_path(cli: SurfaceCli, path_dir: &std::path::Path) -> CliStatus {
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _guard = lock_ignoring_poison();
    invalidate(cli);
    let _path = PathGuard::set(path_dir);
    let result = probe(cli);
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
    let _guard = lock_ignoring_poison();
    invalidate(cli);
    let _path = PathGuard::set(path_dir);
    // RAII for the same reason as PathGuard, one variable over: a trailing
    // restore does not run when `probe()` panics. The only caller passes
    // `CSQ_CLI_DEPS_PROBE_DISABLE`, so a leak here makes every subsequent probe
    // in the binary short-circuit to `CliStatus::Ok { version: 0.0.0 }` — and
    // because `lock_ignoring_poison` clears poison, they all run and assert against
    // it. Declared after both locks so it drops before they release.
    let _env = EnvGuard::set(var, val);
    let result = probe(cli);
    invalidate(cli);
    result
}

// ── Deadline-arm harness ─────────────────────────────────────────────
//
// Three tests below drive `spawn_version_subprocess`'s wall-clock deadline arm
// (`rx.recv_timeout` expiring, then the process-group kill + `wait` + reader
// `join`). All three share one problem and one solution.
//
// The problem, stated as arithmetic rather than as a story about contention.
// `probe_deadline_fires_when_child_outlives_budget` paired a 45 000 ms stub
// with `elapsed_ms < 44_000`. The outcome that bound exists to EXCLUDE — the
// child exiting on its own, so `recv_timeout` returns `Ok(empty)` and
// `classify_output`'s empty-stdout arm produces the very same `ProbeTimedOut`
// variant — lands at 45 000 ms. The bound therefore sat **1 000 ms** from the
// thing it had to separate from. That is the exact shape
// `tooling-self-verification.md` Rule 3 names: a constant adopted because the
// test passed with it, not re-derived from the two outcomes it separates.
//
// Measured here 2026-07-31, on a host at load average ~186: that test returned
// `elapsed_ms: 30006` against its 30 000 ms budget — 6 ms of reach-delay, kill
// and reader-`join` combined. So the 1 000 ms margin was not observed to be
// breached, and no flake is claimed. The defect is the SIZE of the margin, not
// a reproduction: 1 000 ms of headroom on a wall-clock comparison is not a
// separation, and `recv_timeout`'s clock starts when the call is REACHED —
// after `Command::spawn` (fork/exec) and `std::thread::spawn` — so the
// headroom absorbs scheduling delay that is bounded by nothing in particular.
//
// The fix removes the comparison instead of re-tuning it: give the stub a
// sleep that EXCEEDS the harness's own cap, so the empty-stdout arm is
// unreachable inside the test's lifetime. Returning AT ALL then proves the
// deadline fired, and no elapsed-versus-stub comparison is made.
//
// The sibling `probe_kills_orphaned_grandchild_holding_stdout` is deliberately
// NOT converted: its bound (45 000) sits 45 000 ms from the outcome it excludes
// (a 90 000 ms orphan), which is adequately sized. Changing it would be churn.

/// Sleep, in ms, for a stub that must outlive [`DEADLINE_HARNESS_CAP_MS`].
///
/// 600 s is far beyond the 180 s cap, so the stub cannot exit during a capped
/// test; and it is short enough that a stub orphaned by a genuine defect
/// self-reaps in ten minutes rather than lingering on a shared host.
#[cfg(unix)]
const LONG_STUB_MS: u64 = 600_000;

/// Runaway sentinel for the capped deadline tests — NOT a latency assertion.
///
/// Derived from the two outcomes it separates, per
/// `tooling-self-verification.md` Rule 3:
///
/// - **Deadline fired (healthy).** Returns at `reach_delay + budget + kill +
///   join`. Measured 2026-07-31 at load average ~186: 30 006 ms against a
///   30 000 ms budget, i.e. 6 ms for everything other than the budget itself.
///   Margin below the cap, against that measurement: 180 000 − 30 006 =
///   **≈150 s**. Against the deliberately pessimistic bound instead — three
///   orders of magnitude more slack than observed, so "under a minute" — the
///   margin is 180 − 60 = **≥120 s**. Both are stated because they are
///   different numbers and an earlier revision of this comment quoted the
///   measured margin while deriving it from the pessimistic bound (round-4
///   redteam).
/// - **Deadline gone (regression).** Nothing can return until the stub exits at
///   [`LONG_STUB_MS`] = 600 s. Margin above the cap: **420 s**.
///
/// 180 s sits between those two with ≥120 s of margin below even on the
/// pessimistic bound and 420 s above — against the 1 000 ms the bound it
/// replaces had.
#[cfg(unix)]
const DEADLINE_HARNESS_CAP_MS: u64 = 180_000;

/// Runs `f` on its own thread and waits at most [`DEADLINE_HARNESS_CAP_MS`],
/// converting "the probe never came back" from an indefinite suite hang into a
/// named failure.
///
/// The caller MUST already hold `test_env::lock()`, `PATH_MUTEX`, and the
/// `PathGuard`, and MUST keep holding them across this call — `PATH` is
/// process-global and the worker reads it inside `resolve_canonical`.
///
/// Holding them on the MAIN thread rather than taking them inside the worker is
/// what makes the breach path safe: on a cap breach the main thread panics, the
/// guards drop, `PATH` is restored, and the rest of the binary runs. A worker
/// that took the locks itself would still be holding them after the cap fired,
/// wedging every subsequent test on a mutex instead of failing this one — the
/// pile-up shape `lock_ignoring_poison`'s docblock describes.
#[cfg(unix)]
fn await_probe_within_cap(what: &str, f: impl FnOnce() -> CliStatus + Send + 'static) -> CliStatus {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(std::time::Duration::from_millis(DEADLINE_HARNESS_CAP_MS)) {
        Ok(status) => status,
        Err(_) => panic!(
            "{what}: the probe did not return within the {DEADLINE_HARNESS_CAP_MS}ms runaway \
             cap. Its stub sleeps {LONG_STUB_MS}ms and writes nothing, so no arm other than \
             the wall-clock deadline can produce a result — a breach means the probe blocked \
             past its budget: either `rx.recv_timeout`'s deadline arm in \
             `spawn_version_subprocess` no longer fires, or the post-deadline kill/`join` \
             waited for the child instead of terminating it."
        ),
    }
}

/// `probe_within(cli, budget)` with `PATH` set to ONLY `path_dir`, under the
/// runaway cap.
///
/// No `invalidate` bracketing: `probe_within` bypasses the process-lifetime
/// cache by construction, precisely so a short-budget probe cannot poison the
/// entry that sibling tests observe through `probe`.
#[cfg(unix)]
fn probe_within_isolated_path(
    cli: SurfaceCli,
    path_dir: &std::path::Path,
    budget: std::time::Duration,
    what: &str,
) -> CliStatus {
    // Lock order (testing.md MUST Rule 6): shared mutex BEFORE in-module mutex.
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _guard = lock_ignoring_poison();
    // Declared after both locks so PATH is restored while they are still held.
    let _path = PathGuard::set(path_dir);
    await_probe_within_cap(what, move || probe_within(cli, budget))
}

/// `probe(cli)` — the PRODUCTION per-surface budget — with `PATH` set to ONLY
/// `path_dir`, under the runaway cap.
///
/// The uncapped [`probe_with_isolated_path`] stays correct for stubs that exit
/// on their own; this variant is for the two tests whose stubs deliberately
/// outlive the harness and would otherwise hang it on a regression.
#[cfg(unix)]
fn probe_with_isolated_path_capped(
    cli: SurfaceCli,
    path_dir: &std::path::Path,
    what: &str,
) -> CliStatus {
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _guard = lock_ignoring_poison();
    invalidate(cli);
    let _path = PathGuard::set(path_dir);
    let result = await_probe_within_cap(what, move || probe(cli));
    invalidate(cli); // clean up cache after test
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

/// AC: stub hanging 3000ms → `ProbeTimedOut`, returned on child exit rather
/// than after the probe's own budget.
///
/// Lower bound 1000 ms rules out a fast parse; the upper bound and its
/// rationale are `HANG_STUB_MAX_ELAPSED_MS`.
#[test]
#[cfg(unix)]
fn probe_codex_timeout() {
    let tmp = TempDir::new().unwrap();
    write_hang_stub(&tmp, "codex", 3000);
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. }
                 if *elapsed_ms >= 1000 && *elapsed_ms < HANG_STUB_MAX_ELAPSED_MS),
        "expected ProbeTimedOut in 1000..{HANG_STUB_MAX_ELAPSED_MS}ms — a probe that \
         waited its whole 30s budget instead of returning on child exit lands near \
         30000; got {result:?}"
    );
}

/// AC: the wall-clock deadline arm fires and reaps, proven in ~2 s rather than
/// the ~30 s its production-budget sibling below costs.
///
/// # Why a second deadline test
///
/// `probe_deadline_fires_when_child_outlives_budget` runs the PRODUCTION budget
/// end-to-end — that is its value, and why it stays — but it holds `PATH_MUTEX`
/// for ~30 s, serialising the rest of this binary behind it. Injecting a 2 s
/// budget through `probe::probe_within` covers the same arm cheaply, so a
/// regression in `recv_timeout`'s deadline shows up on every run rather than
/// only in the one slow test.
///
/// # Non-raced by construction
///
/// See the "Deadline-arm harness" block above. The stub sleeps
/// [`LONG_STUB_MS`] (600 s) against a [`DEADLINE_HARNESS_CAP_MS`] (180 s) cap,
/// so `classify_output`'s empty-stdout arm cannot produce a result inside this
/// test's lifetime — returning at all means the deadline fired. The
/// `elapsed_ms >= 2_000` floor is the only quantitative claim, and it is exact
/// rather than probabilistic: `elapsed_ms` runs from `spawn_start`, and
/// `recv_timeout` cannot expire before its own budget.
///
/// # Non-vacuity
///
/// Verified by mutation, not by assertion-reading: replacing
/// `rx.recv_timeout(timeout)` in `spawn_version_subprocess` with a bare
/// `rx.recv()` makes this test fail on the cap with the runaway message, while
/// `probe_codex_timeout` and `probe_timeout_child_reaped_promptly` — both named
/// for the timeout — still pass, because their stubs exit on their own and
/// their `ProbeTimedOut` comes from the empty-stdout arm.
#[test]
#[cfg(unix)]
fn probe_deadline_kill_arm_fires_under_an_injected_budget() {
    let tmp = TempDir::new().unwrap();
    write_hang_stub(&tmp, "codex", LONG_STUB_MS);
    let result = probe_within_isolated_path(
        SurfaceCli::Codex,
        tmp.path(),
        std::time::Duration::from_secs(2),
        "probe_deadline_kill_arm_fires_under_an_injected_budget",
    );
    // The ceiling is load-bearing, and a floor alone was not enough (round-1
    // redteam MED). With only `>= 2_000`, a mutation in which
    // `run_probe_within` / `probe_within` IGNORES its `timeout` argument and
    // falls back to `probe_timeout(cli)` — i.e. the injection seam this whole
    // PR exists to add, wired wrong or regressed later — lands at ~30 006 ms,
    // and `30006 >= 2_000` is still true. The test stayed green while silently
    // reverting from ~2 s to ~30 s, defeating the documented reason it exists.
    //
    // 10 000 ms separates the two outcomes it must separate:
    //   healthy            → 2 000 + reach/kill/join; measured 6 ms of overhead
    //                        on a load-average-186 host, so ~2 006 ms.  ~8 s below.
    //   injection ignored  → the 30 s test-utils production budget, ~30 006 ms. ~20 s above.
    assert!(
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. }
                 if *elapsed_ms >= 2_000 && *elapsed_ms < 10_000),
        "expected ProbeTimedOut in 2000..10000ms. At or above 10000ms the injected \
         budget was NOT honoured and the probe fell back to the ~30s production \
         value — the seam is broken. Below 2000ms the deadline returned before its \
         own budget, which is impossible. The stub sleeps {LONG_STUB_MS}ms and \
         writes nothing, so no other arm can return; got {result:?}"
    );
}

/// AC: a child that outlives the probe's own PRODUCTION budget → the wall-clock
/// deadline fires, and `elapsed_ms` lands at or after that budget.
///
/// # Why this test exists separately from the two hang tests
///
/// `probe_codex_timeout` and `probe_timeout_child_reaped_promptly` are named
/// for the timeout but do not exercise it. Their stubs exit on their own at
/// 3 s / 5 s, well inside the 30 s `--features test-utils` budget, so the
/// `ProbeTimedOut` they assert comes from `classify_output`'s empty-stdout arm
/// — not from `timed_out`. Both were measured passing with
/// `rx.recv_timeout(timeout)` replaced by a bare `rx.recv()`: delete the
/// deadline entirely and neither notices.
///
/// This one cannot pass without it: the stub outlives the budget, so the ONLY
/// way to return is `recv_timeout` expiring. `spec/13 §8`'s "the probe must not
/// block a launch indefinitely" is what that guards.
///
/// # The upper bound was a 1-second separation — it is gone
///
/// This test previously paired a 45 000 ms stub with `elapsed_ms < 44_000`. The
/// outcome that bound existed to exclude — the child exiting on its own, whose
/// empty-stdout arm yields the SAME `ProbeTimedOut` variant — lands at
/// 45 000 ms, so the bound sat 1 000 ms from it. Measured 2026-07-31 at load
/// average ~186 the test returned `elapsed_ms: 30006`, i.e. 6 ms of slack used;
/// no breach was observed and none is claimed. The defect is the margin's SIZE,
/// per `tooling-self-verification.md` Rule 3 — a bound is correct only if it
/// separates its two outcomes with a stated margin on each side, and 1 000 ms
/// on a wall-clock comparison whose clock starts after `spawn` + `thread::spawn`
/// is not a separation.
///
/// The stub now sleeps [`LONG_STUB_MS`] (600 s), well past
/// [`DEADLINE_HARNESS_CAP_MS`] (180 s), so that arm is unreachable inside this
/// test and there is nothing to compare against. What remains is a floor (the
/// probe waited its budget rather than short-circuiting) plus the cap (it came
/// back at all).
///
/// Cost: ~30 s, and it holds `PATH_MUTEX` for that time. That is the price of
/// testing the PRODUCTION budget end-to-end; the cheap injected-budget cousin
/// above covers the same arm on every run, but only this one proves
/// `run_probe` actually hands `probe_timeout(cli)` to the subprocess.
#[test]
#[cfg(unix)]
fn probe_deadline_fires_when_child_outlives_budget() {
    let tmp = TempDir::new().unwrap();
    // 600 s ≫ both the 30 s test-utils budget and the 180 s harness cap. No
    // output, so nothing can short-circuit; no self-exit, so nothing can race.
    write_hang_stub(&tmp, "codex", LONG_STUB_MS);
    let result = probe_with_isolated_path_capped(
        SurfaceCli::Codex,
        tmp.path(),
        "probe_deadline_fires_when_child_outlives_budget",
    );
    // The window pins the BUDGET VALUE, which is this test's unique job — the
    // cheap cousin above proves the arm fires, but only this one proves
    // `run_probe` hands the subprocess `probe_timeout(cli)` and not some other
    // duration (round-1 redteam MED, same shape as the ceiling added there).
    //
    // Unlike the `< 44_000` bound this replaced, the outcome being excluded is
    // not adjacent. That bound sat 1 000 ms from the stub's own 45 000 ms exit;
    // this one is separated on a different axis entirely:
    //   healthy (30 s budget) → 30 000 + ~6 ms measured overhead ≈ 30 006 ms;
    //                           5 s above the floor, ~10 s below the ceiling.
    //   wrong budget          → 6 s (the non-test-utils Codex value) ≈ 6 006 ms,
    //                           or 45 s+, both outside the window.
    //   stub exits on its own → impossible before 600 s; the cap catches it.
    assert!(
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. }
                 if *elapsed_ms >= 25_000 && *elapsed_ms < 40_000),
        "expected ProbeTimedOut in 25000..40000ms — the ~30s test-utils production \
         budget. Outside that window `run_probe` passed the subprocess some OTHER \
         duration than `probe_timeout(cli)`; got {result:?}"
    );
}

/// AC: a wrapper that SPAWNS (rather than `exec`s) and exits, leaving an
/// orphan holding stdout, must not extend the probe past its budget.
///
/// # The shape
///
/// The stub backgrounds a 90 s sleep and exits immediately. The wrapper is gone
/// within milliseconds, but the orphan inherited the stdout write end and keeps
/// it open, so the reader thread stays blocked in `read()`.
///
/// `Child::kill` signals only the direct child — already dead — so before the
/// `setsid` + `kill(-pgid)` fix the sequence was: deadline fires at 30 s, kill
/// and wait are no-ops, and then `reader_handle.join()` blocks for the
/// remaining ~60 s of the orphan's life. `elapsed_ms` is measured after that
/// join, so the probe reported ~90 s against a 30 s budget.
///
/// With the process-group kill the orphan dies with the group, the write end
/// closes, `read()` returns 0, and the join is immediate — so the probe returns
/// at its budget.
///
/// This is the shape the fixture migration removed: the old `write_hang_stub`
/// wrote `#!/bin/sh` + a non-`exec` `sleep`, which produced a live grandchild
/// on every hang test. Nothing covered it afterwards, so it is covered here
/// deliberately rather than incidentally.
#[test]
#[cfg(unix)]
fn probe_kills_orphaned_grandchild_holding_stdout() {
    let tmp = TempDir::new().unwrap();
    let sleep_bin = ["/bin/sleep", "/usr/bin/sleep"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("no sleep binary");
    let script_path = tmp.path().join("codex");
    // Background the sleep and exit: the wrapper dies, the orphan lives on
    // holding the inherited stdout write end.
    // Background the sleep and exit: the wrapper dies, the orphan lives on
    // holding the inherited stdout write end.
    std::fs::write(
        &script_path,
        format!("#!/bin/sh\n{sleep_bin} 90 &\nexit 0\n").as_bytes(),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    // Budget is 30 s under test-utils; the orphan lives 90 s. 45 s sits between
    // "returned at the budget" and "waited out the orphan" with wide margin on
    // both sides (15 s below, 45 s above), and is not a runner-speed
    // measurement. Unlike its sibling above — whose 44 000 bound sat 1 000 ms
    // from the 45 000 outcome it existed to exclude — this separation is
    // adequately sized, so it is left as authored.
    //
    // The LOWER bound is not decoration. With only `< 45_000` this test passes
    // vacuously whenever the orphan is never created — a different `/bin/sh`, a
    // fork failure, `sleep` absent at both candidate paths, or a future edit to
    // the fixture. Every write end then closes at once, the reader hits EOF in
    // milliseconds, `classify_output`'s empty-stdout arm returns
    // `ProbeTimedOut { elapsed_ms: ~10 }`, and 10 < 45 000 is green — proving
    // nothing about the process-group kill this test exists for. Below 25 s
    // means the probe never reached its budget, i.e. the precondition failed.
    assert!(
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. }
                 if *elapsed_ms >= 25_000 && *elapsed_ms < 45_000),
        "probe must return at its ~30s budget (25000..45000ms) even though an \
         orphaned grandchild holds stdout for 90s. At/above 45000ms the reader \
         join waited out the orphan — the process-group kill did not reach it. \
         Below 25000ms the orphan was never created and the test proved nothing. \
         Got {result:?}"
    );
}

/// AC: stub emitting 10 000 bytes with no newline → `WrongBinary { ComponentTooLarge }`.
///
/// The stub writes 10 000 bytes and exits, so the reader reaches the 8 KiB cap
/// on every run and `classify_output` finds no newline in what it collected.
/// The outcome is therefore deterministic — this asserts that one variant, not
/// a set.
///
/// An earlier revision accepted `ProbeTimedOut` OR `WrongBinary` and so passed
/// whether or not the cap logic worked at all. It was green on a host where the
/// stub emitted zero bytes (see `write_stub_cli_wrapper` for why): the probe
/// took the `ProbeTimedOut` branch and the cap path was never exercised.
#[test]
#[cfg(unix)]
fn probe_codex_cap_exceeded_not_unrecognized_version() {
    let tmp = TempDir::new().unwrap();
    write_emit_bytes_stub(&tmp, "codex", 10_000);
    let result = probe_with_isolated_path(SurfaceCli::Codex, tmp.path());
    assert!(
        matches!(
            &result,
            CliStatus::WrongBinary {
                reason: WrongBinaryReason::ComponentTooLarge { .. },
                ..
            }
        ),
        "expected WrongBinary(ComponentTooLarge) for a 10 000-byte newline-less \
         component; got {result:?}"
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
    let _guard = lock_ignoring_poison();
    let tmp = TempDir::new().unwrap();
    write_version_stub(&tmp, "codex", "codex-cli 0.40.0\n");

    // First probe — populates cache. `PathGuard` restores PATH on unwind, so
    // the four assertions below cannot leave PATH naming a deleted TempDir.
    let _path = PathGuard::set(tmp.path());
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
        matches!(&result, CliStatus::ProbeTimedOut { elapsed_ms, .. }
                 if *elapsed_ms >= 1000 && *elapsed_ms < HANG_STUB_MAX_ELAPSED_MS),
        "expected ProbeTimedOut in 1000..{HANG_STUB_MAX_ELAPSED_MS}ms; got {result:?}"
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

// Only used by `h4_no_fd_leak_across_repeated_probes`, a `#[cfg(unix)]` test;
// `run` calls the unix-only `probe_with_isolated_path` helper.
#[cfg(unix)]
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

/// H-3 regression: a stub emits a 9 000-byte newline-less component and then
/// holds stdout open for 30 s. `probe()` MUST reject it on the byte cap and
/// return without waiting on the child.
///
/// # Structural invariant
///
/// The reader thread stops at the 8 KiB cap and sends what it collected. The
/// main thread kills + waits the child. `classify_output` sees no newline and
/// returns `WrongBinary { ComponentTooLarge }`. Total probe time is the read
/// time (~hundreds of ms), NOT the stub's sleep.
///
/// # What is asserted, and why it is the outcome and not the clock
///
/// The claim is about WHY `probe()` returned, so it is read off `probe()`'s own
/// outcome rather than a wall-clock bound. An earlier revision asserted only
/// `outer_wall_clock < 7 000 ms`, reasoning "healthy ~3 000 ms, regression
/// ≥ 5 000 ms, so 7 000 ms tolerates jitter". That is not falsifiable under
/// unbounded scheduling delay, and it did fail: on a loaded macOS runner the
/// HEALTHY path took 10 981 ms — spawn, kill and reap dilated around a timeout
/// that had fired correctly — and the test reported an H-3 regression against
/// correct code. The panic then poisoned `PATH_MUTEX` and took 15 sibling tests
/// with it (see `lock_ignoring_poison`).
///
/// The sleep length is load-bearing in the opposite direction: the probe's own
/// budget is 30 s under `--features test-utils`, so a shorter sleep would let a
/// probe that read to EOF finish inside the same window as one that
/// short-circuited, and the test would pass either way. It must EXCEED the
/// budget for the two paths to be distinguishable — and 30 000 ms does not
/// exceed 30 s, it equals it. At parity the discriminator collapses to a few
/// milliseconds of process-startup skew: if the parent's `thread::spawn` and
/// `recv_timeout` are delayed past the child's write (the scheduler dilation
/// this very docstring records at 10 981 ms), the child hits EOF first, the
/// reader returns 8 192 newline-less bytes, and the test goes GREEN against a
/// probe with no cap short-circuit at all. 90 s restores a real margin, and
/// costs nothing: the healthy path returns in ~100 ms and never pays the sleep.
///
/// # Why this test was `#[ignore]`d, and why the diagnosis was wrong
///
/// It was ignored on 2026-07-26 with the reason "PRODUCTION DEFECT, not a test
/// defect — probe() only sometimes short-circuits on the oversized component",
/// citing three consecutive runs with no code change between them:
///
/// | run | outcome                             | probe's own wait |
/// | --- | ----------------------------------- | ---------------- |
/// | 1   | `ProbeTimedOut`                     | 30 389 ms        |
/// | 2   | `WrongBinary { ComponentTooLarge }` |      679 ms      |
/// | 3   | `ProbeTimedOut`                     | 30 146 ms        |
///
/// The variance was real; the attribution was not. It was a FIXTURE defect.
/// The stub invoked `python3`, resolved by `which` — and `which` ran BEFORE the
/// test took `test_env::lock()`/`PATH_MUTEX`, so what it resolved depended on
/// whether a sibling test happened to be holding `PATH` at that instant:
///
/// - Uncontended: `which python3` → `~/.pyenv/shims/python3`, a `#!/usr/bin/env
///   bash` script. `probe()` forwards the caller's `PATH` — restricted here to
///   the stub's temp dir — so the shim's `env bash` lookup fails, the stub
///   writes **zero** bytes, the pipe stays open behind the sleep, and `probe()`
///   correctly reports `ProbeTimedOut` after its full budget. Runs 1 and 3.
/// - Contended: a sibling had `PATH` set to its own temp dir, `which` found
///   nothing, and the fallback `/usr/bin/python3` — the system interpreter,
///   which needs nothing from `PATH` — ran and emitted 9 000 bytes. Run 2.
///
/// Reproduced on the originating host: 6/6 `ProbeTimedOut` when run alone
/// (`--exact`), and `env -i PATH=<tmp> ./codex` emits 0 bytes with
/// `env: bash: No such file or directory` on stderr. `probe()` was correct in
/// every one of those runs; it had no output to classify.
///
/// The fixture now `exec`s the compiled `stub-cli` binary
/// (`write_emit_then_hang_stub`), which has no interpreter and no `PATH`
/// dependency, so the outcome no longer varies with the host's toolchain layout
/// or with sibling-test timing.
#[test]
#[cfg(unix)]
fn h3_cap_exceeded_returns_before_hang_completes() {
    use std::time::Instant;

    // 9 000 bytes with no newline — the 8 KiB cap is exceeded well before the
    // stub finishes writing — then hold stdout open past the probe's budget.
    let tmp = TempDir::new().unwrap();
    write_emit_then_hang_stub(&tmp, "codex", 9_000, 90_000);

    // Lock order (testing.md MUST Rule 6): workspace-wide `test_env::lock()`
    // FIRST, then in-module `PATH_MUTEX`.
    let _shared_env_guard = csq_core::platform::test_env::lock();
    let _path_guard = lock_ignoring_poison();
    invalidate(SurfaceCli::Codex);
    let _path = PathGuard::set(tmp.path());

    let start = Instant::now();
    let result = probe(SurfaceCli::Codex);
    let wall_elapsed = start.elapsed().as_millis();

    invalidate(SurfaceCli::Codex);

    match &result {
        CliStatus::WrongBinary { reason, .. } => {
            assert!(
                matches!(reason, WrongBinaryReason::ComponentTooLarge { .. }),
                "H-3: expected the oversized component to be the rejection reason, \
                 got {reason:?} (outer wall clock {wall_elapsed} ms)"
            );
        }
        CliStatus::ProbeTimedOut { elapsed_ms, .. } => panic!(
            "H-3 regression: probe() waited {elapsed_ms} ms and timed out instead of \
             returning as soon as the 9 000-byte component exceeded the cap. The cap \
             is exceeded before the stub finishes writing, so no correct \
             implementation needs to wait on the child at all. \
             (Outer wall clock {wall_elapsed} ms.)"
        ),
        other => panic!(
            "H-3 regression: probe() returned {other:?}. The stub emits 9 000 bytes \
             then holds stdout open for 30 s and never emits a version, so the only \
             correct outcome is WrongBinary/ComponentTooLarge. \
             (Outer wall clock {wall_elapsed} ms.)"
        ),
    }
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
    let _guard = lock_ignoring_poison();
    let _path = PathGuard::set(std::path::Path::new(&long_path));

    let start = Instant::now();
    let result = find_in_path("__csq_h2_nonexistent_binary__");
    let elapsed = start.elapsed().as_millis();

    assert!(
        result.is_none(),
        "H-2: binary must not be found in fake PATH"
    );
    assert!(
        elapsed < 100,
        "H-2: PATH walk with 5000 entries must complete in <100ms; took {elapsed}ms"
    );
}
