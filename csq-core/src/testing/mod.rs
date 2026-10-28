//! Test-only utilities for csq-core.
//!
//! Gated by `#[cfg(any(test, feature = "test-utils"))]` so this module
//! compiles into:
//!
//! - The crate's own `cargo test` runs (via `cfg(test)`).
//! - External test consumers that enable `csq-core/test-utils`
//!   (integration tests, `coc-eval`, M1-4 acceptance tests).
//!
//! It MUST NOT be compiled into production binaries. The `test-utils` feature
//! in `csq-core/Cargo.toml` is `test-utils = ["dep:tempfile", "secret-in-memory"]`;
//! `tempfile` is an optional regular dependency gated by that feature (it is
//! also a dev-dependency for the crate's own `cfg(test)` builds). This is the
//! canonical pattern established by `discovery_test_utils_feature_gate_pattern`.

pub mod child_lifetime;
pub mod identity_fixtures;
/// Shared short-root Unix socket fixtures. Unix-only: the fixture uses
/// `sun_path`-bounded pathname sockets and unix file modes.
#[cfg(unix)]
pub mod socket_fixture;

/// Resolve a crate's manifest directory at TEST RUN TIME.
///
/// `env!("CARGO_MANIFEST_DIR")` bakes the BUILD machine's absolute path into the
/// test binary. Cargo's metadata hash does not include the workspace's absolute
/// path, so a `target/` directory carried across two workspace locations — or a
/// shared `CARGO_TARGET_DIR` — treats the binary as fresh while it still points
/// at the path that existed at BUILD time. Any test that joins a source path
/// onto it then fails with ENOENT even though the tree it is running from has
/// the file. Measured 2026-10-16: a reused `csq_sdk_enterprise` test binary in
/// the rebuild4b sign-off pointed at a build tree that no longer existed and
/// failed with `No such file or directory` reading
/// `{compile-time manifest dir}/Cargo.toml` — a file present in the tree it was
/// actually running from. `the enterprise SDK crate/src/lib.rs` was only where the
/// panic surfaced; the missing path was the stale tree's `Cargo.toml`.
///
/// Cargo exports `CARGO_MANIFEST_DIR` to the process it runs, so the runtime
/// value names the tree the test is actually running from. The compile-time
/// value is the fallback for a harness that sets neither variable — the only
/// case in which the old behaviour is correct. Callers pass their own
/// `env!("CARGO_MANIFEST_DIR")` so each crate keeps its own build-time value:
///
/// ```ignore
/// let root = csq_core::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"));
/// let fixture = root.join("tests/fixtures/foo");
/// ```
///
/// A path that is consumed by `include_str!`/`include_bytes!` (or any other
/// compile-time macro) MUST keep the direct `env!()` form: those are tracked
/// rebuild dependencies, not runtime reads.
pub fn manifest_dir(compile_time: &str) -> std::path::PathBuf {
    resolve_manifest_dir(
        std::env::var_os("CARGO_MANIFEST_DIR").as_deref(),
        compile_time,
    )
}

/// The testable core of [`manifest_dir`]: prefer a non-empty runtime value,
/// else the compile-time fallback. Factored out so the precedence can be
/// unit-tested without mutating the process environment (which every other
/// test in a parallel run would observe).
pub fn resolve_manifest_dir(
    runtime: Option<&std::ffi::OsStr>,
    compile_time: &str,
) -> std::path::PathBuf {
    match runtime {
        Some(value) if !value.is_empty() => std::path::PathBuf::from(value),
        _ => std::path::PathBuf::from(compile_time),
    }
}

/// Serialises every test in this crate that installs a scoped tracing
/// dispatcher (`tracing::subscriber::with_default`) to capture events.
///
/// `with_default` is thread-local, but entering and leaving it also updates
/// tracing's process-global max-level filter, which `warn!` consults before
/// dispatching. Two captures running concurrently can transiently lower that
/// filter while the other thread's event is evaluated, so the capture sees
/// nothing: a false RED for "event emitted" and a false GREEN for "no event".
/// One lock shared by every capturing test closes that window. A test that
/// reaches a captured callsite WITHOUT capturing it takes the lock too: its
/// first hit can cache the callsite as disabled mid-capture.
///
/// The lock alone cannot stop that second race, because the uncapturing test is
/// often in another module that never takes it. The cause is in tracing-core:
/// while exactly ONE dispatcher is registered, a callsite registered for the first
/// time computes its interest from the REGISTERING thread's default dispatcher
/// (`Rebuilder::JustOne` → `dispatcher::get_default`), not from every live
/// dispatcher. A capture that is the only registered dispatcher therefore has its
/// callsites cached as `never` by any sibling thread that reaches them first, and
/// the capture sees nothing for the rest of the process. [`CaptureLock::lock`]
/// registers a permanent no-op anchor dispatcher first, so a live capture is never
/// the only one. A first registration then combines the capture's `always` with the
/// anchor's `never` into `sometimes`, and each event asks its own thread's dispatcher.
///
/// The anchor covers callsites whose FIRST hit happens after a capture has
/// registered it. A callsite already cached as `never` BEFORE the first capture
/// ran is not repaired by the anchor; [`settle_capture_interest`] closes that
/// gap for a capture that needs it, by priming the callsite from the capturing
/// thread and then rebuilding tracing's interest cache.
pub static TRACING_CAPTURE_LOCK: CaptureLock = CaptureLock::new();

/// The capture lock; see [`TRACING_CAPTURE_LOCK`].
pub struct CaptureLock {
    inner: std::sync::Mutex<()>,
}

/// Never dropped: keeps a second dispatcher registered for the life of the process.
static CAPTURE_ANCHOR: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();

impl CaptureLock {
    const fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(()),
        }
    }

    /// Registers the anchor dispatcher (once per process), then takes the lock.
    pub fn lock(&'static self) -> std::sync::LockResult<std::sync::MutexGuard<'static, ()>> {
        CAPTURE_ANCHOR
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        self.inner.lock()
    }

    /// Test-only: takes the lock WITHOUT registering the anchor, so a test can
    /// reproduce the pre-anchor `never` cache that [`settle_capture_interest`]
    /// repairs. Meaningful only in a process where no earlier test has taken
    /// [`CaptureLock::lock`]; the settle test's doc names the isolated run.
    #[cfg(test)]
    pub fn lock_without_anchor(
        &'static self,
    ) -> std::sync::LockResult<std::sync::MutexGuard<'static, ()>> {
        self.inner.lock()
    }
}

/// Repairs a scoped capture against a callsite whose interest was cached
/// `never` before any capture had registered the anchor. Call right after
/// installing the capture dispatcher, with a closure that hits that callsite
/// once; discard whatever the closure captured.
///
/// Why it is needed (tracing-core 0.1.36, `callsite::dispatchers`): a callsite's
/// interest is computed once, on its first hit, and cached. If that first hit
/// happened while the capture was the ONLY live dispatcher (before
/// [`CaptureLock::lock`] registered the anchor), the interest can be cached as
/// `never` and the capturing thread's later event is dropped before it reaches
/// the dispatcher. `prime` makes the capturing thread register the callsite if
/// nobody has, and `rebuild_interest_cache` recomputes an interest another
/// thread already cached as `never`; after both, the callsite is registered and
/// its interest includes this dispatcher.
pub fn settle_capture_interest(prime: impl FnOnce()) {
    prime();
    tracing::callsite::rebuild_interest_cache();
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<String>>>);
    struct Msg<'a>(&'a mut String);
    impl tracing::field::Visit for Msg<'_> {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            if f.name() == "message" {
                self.0.push_str(&format!("{v:?}"));
            }
        }
    }
    impl tracing::Subscriber for Lines {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(&mut Msg(&mut line));
            self.0.lock().unwrap().push(line);
        }
    }

    // Each fn is its own callsite.
    fn emit_unsettled() {
        tracing::warn!("unsettled");
    }
    fn emit_settled() {
        tracing::warn!("settled");
    }

    // Another thread makes the FIRST hit of both callsites while the capture is live (the
    // refresher flake's sequence). The settled callsite is then delivered. The unsettled
    // one is reported, not asserted: whether the other thread's first hit caches `never`
    // depends on whether this dispatcher is the only live one, which a parallel run cannot
    // control; `cargo test -p csq-core --lib --features test-utils capture_tests --
    // --test-threads=1 --nocapture` prints the contrast (raw delivered 0 of 1). Reds if
    // `settle_capture_interest` did not rebuild the cached interest, in that isolated run.
    #[test]
    fn a_first_hit_by_another_thread_does_not_blind_a_settled_capture() {
        // `lock_without_anchor` (not `lock`): this test reproduces the PRE-ANCHOR
        // `never` cache that settle repairs, so it must run in a process where the
        // anchor was never registered — the filtered isolated run
        // (`capture_tests::a_first_hit_by_another_thread_does_not_blind_a_settled_capture
        // -- --test-threads=1`) is that process. In a full parallel suite the anchor
        // may already exist, which only strengthens delivery; the assertion still holds.
        let _lock = TRACING_CAPTURE_LOCK
            .lock_without_anchor()
            .unwrap_or_else(|e| e.into_inner());
        let lines = Lines::default();
        let guard = tracing::subscriber::set_default(lines.clone());
        std::thread::spawn(|| {
            emit_unsettled();
            emit_settled();
        })
        .join()
        .unwrap();
        emit_unsettled();
        let raw = lines
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.as_str() == "unsettled")
            .count();
        settle_capture_interest(emit_settled);
        lines.0.lock().unwrap().clear();
        emit_settled();
        let settled = lines.0.lock().unwrap().clone();
        drop(guard);
        eprintln!("unsettled capture delivered {raw} of 1 events; settled: {settled:?}");
        assert_eq!(settled, vec!["settled".to_string()]);
    }

    // G2-rebuild resolution (ROOT decision (a)): the anchor alone must keep a sibling's
    // FIRST hit from blinding a capture that never calls `settle_capture_interest`.
    // Discrimination: with the anchor registration removed this reds WHEN the capture is
    // the only live dispatcher, which the isolated run (`--test-threads=1`) establishes;
    // a parallel run may carry another live dispatcher and mask the difference, so the
    // mutation proof is measured in isolation.
    #[test]
    fn a_first_hit_by_another_thread_is_not_blinded_by_the_anchor() {
        let _lock = TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let lines = Lines::default();
        let guard = tracing::subscriber::set_default(lines.clone());
        std::thread::spawn(emit_unsettled).join().unwrap();
        emit_unsettled();
        let delivered = lines.0.lock().unwrap().clone();
        drop(guard);
        assert_eq!(
            delivered,
            vec!["unsettled".to_string()],
            "the anchor must keep a sibling thread's first hit from caching the callsite \
             as never (no settle call in this test)"
        );
    }
}

#[cfg(test)]
mod manifest_dir_tests {
    use super::resolve_manifest_dir;
    use std::ffi::OsStr;

    #[test]
    fn runtime_value_wins_over_the_compile_time_fallback() {
        let resolved =
            resolve_manifest_dir(Some(OsStr::new("/runtime/tree/crate")), "/build/tree/crate");
        assert_eq!(resolved, std::path::PathBuf::from("/runtime/tree/crate"));
    }

    #[test]
    fn compile_time_value_is_the_fallback_when_no_runtime_value_exists() {
        let resolved = resolve_manifest_dir(None, "/build/tree/crate");
        assert_eq!(resolved, std::path::PathBuf::from("/build/tree/crate"));
    }

    #[test]
    fn empty_runtime_value_is_treated_as_absent() {
        let resolved = resolve_manifest_dir(Some(OsStr::new("")), "/build/tree/crate");
        assert_eq!(resolved, std::path::PathBuf::from("/build/tree/crate"));
    }

    /// ROOT's RED equivalent, in process: a path that was valid at BUILD time is
    /// gone at RUN time, and the tree the test actually runs from answers. The
    /// OLD shape (join onto the compile-time value) reads A and fails; the NEW
    /// shape resolves to B and reads. Both halves are asserted, so a test that
    /// silently accepted either path cannot pass this.
    #[test]
    fn stale_compile_time_dir_fails_while_the_runtime_dir_reads() {
        let stale = tempfile::tempdir().expect("stale tree");
        let live = tempfile::tempdir().expect("live tree");
        std::fs::write(stale.path().join("marker.txt"), "from-stale").expect("write stale marker");
        std::fs::write(live.path().join("marker.txt"), "from-live").expect("write live marker");

        let compile_time = stale.path().to_string_lossy().into_owned();
        // The build tree disappears (the shared-target scenario: the workspace
        // that compiled the binary no longer exists on this host).
        std::fs::remove_dir_all(stale.path()).expect("remove stale tree");

        let old_shape =
            std::fs::read_to_string(std::path::Path::new(&compile_time).join("marker.txt"));
        assert!(
            old_shape.is_err(),
            "the OLD shape must fail once the build tree is gone — otherwise this \
             fixture does not reproduce the incident"
        );

        let resolved = resolve_manifest_dir(Some(live.path().as_os_str()), &compile_time);
        let body = std::fs::read_to_string(resolved.join("marker.txt"))
            .expect("the NEW shape must read the tree the test runs from");
        assert_eq!(body, "from-live");
    }

    /// The premise of the fix, measured rather than assumed: cargo exports
    /// `CARGO_MANIFEST_DIR` to the test process, and the helper returns it.
    ///
    /// Deliberately does NOT compare the runtime value against the compile-time
    /// one. A reused binary is the incident this helper exists to SURVIVE, not
    /// to fail on: under reuse the runtime value names the tree the test
    /// actually runs from, which is exactly what the helper must return. Making
    /// that disagreement red would reintroduce the incident as a test failure.
    /// The mutant-killer is the child-process test below, which pins the
    /// runtime-over-compile-time precedence with the two values known to differ.
    #[test]
    fn cargo_exports_a_manifest_dir_to_the_test_process() {
        let runtime = std::env::var_os("CARGO_MANIFEST_DIR").expect(
            "cargo must export CARGO_MANIFEST_DIR to the test process — the runtime \
             manifest-dir resolution depends on it; run tests through cargo/nextest",
        );
        assert!(
            !runtime.is_empty(),
            "CARGO_MANIFEST_DIR must not be empty — an empty value falls back to the \
             compile-time path"
        );
        let resolved = crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(resolved.as_path(), std::path::Path::new(&runtime));
    }

    /// The discriminator for the whole helper: re-exec THIS test binary with a
    /// `CARGO_MANIFEST_DIR` that is deliberately not the build-time value, and
    /// assert the helper returns the runtime value. A mutant whose
    /// `resolve_manifest_dir` always returns the compile-time argument reds
    /// here — measured on the rebuilding review round.
    ///
    /// Out of process on purpose: `CARGO_MANIFEST_DIR` is process-wide, so
    /// mutating it in a parallel test run would race every sibling test.
    #[test]
    fn manifest_dir_honours_the_runtime_cargo_manifest_dir_in_a_child_process() {
        const CHILD_FLAG: &str = "CSQ_MANIFEST_DIR_REEXEC_CHILD";
        if std::env::var_os(CHILD_FLAG).is_some() {
            let runtime = std::env::var_os("CARGO_MANIFEST_DIR")
                .expect("the parent sets CARGO_MANIFEST_DIR for the child");
            let resolved = crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"));
            assert_eq!(
                resolved.as_path(),
                std::path::Path::new(&runtime),
                "the runtime CARGO_MANIFEST_DIR must win over the compiled-in value"
            );
            // Non-vacuity. If CSQ_MANIFEST_DIR_REEXEC_CHILD were set in the
            // AMBIENT environment, this branch would run inside the ordinary
            // cargo test process, where CARGO_MANIFEST_DIR is csq-core itself —
            // and the equality above would hold trivially. Comparing against the
            // compile-time `env!` value would prove the same thing, but a bare
            // compile-time read is exactly what
            // `scripts/verify/runtime-manifest-dir.sh` bans (the rule this
            // helper exists to enforce), so a crate checkout is rejected
            // structurally instead: the parent's tempdir contains none of these
            // files.
            for probe in ["Cargo.toml", "src/testing/mod.rs"] {
                assert!(
                    !std::path::Path::new(&runtime).join(probe).exists(),
                    "the child's CARGO_MANIFEST_DIR ({}) contains {probe}, so it is a crate \
                     checkout rather than the parent's tempdir — is \
                     CSQ_MANIFEST_DIR_REEXEC_CHILD set in the ambient environment?",
                    std::path::Path::new(&runtime).display()
                );
            }
            eprintln!("CSQ_MANIFEST_DIR_CHILD_OK resolved={}", resolved.display());
            return;
        }

        let dir = tempfile::tempdir().expect("child manifest dir");
        let exe = std::env::current_exe().expect("current_exe");
        // `--exact` needs libtest's fully qualified unit-test name, which is the
        // module path with the crate name stripped (what `cargo test -- --list`
        // prints). With the child flag set, the re-run takes the branch above
        // and cannot recurse; if this filter ever stops matching, the run exits
        // green with 0 tests and the marker assertion below fails loudly.
        let out = std::process::Command::new(&exe)
            .args([
                "--exact",
                "testing::manifest_dir_tests::manifest_dir_honours_the_runtime_cargo_manifest_dir_in_a_child_process",
                "--nocapture",
            ])
            .env(CHILD_FLAG, "1")
            .env("CARGO_MANIFEST_DIR", dir.path())
            .output()
            .expect("re-exec the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "the child run failed: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            out.status
        );
        assert!(
            stdout.contains("CSQ_MANIFEST_DIR_CHILD_OK")
                || stderr.contains("CSQ_MANIFEST_DIR_CHILD_OK"),
            "the child never reached its assertions — the filter matched no test? \
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}
