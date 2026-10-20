//! Shared `#[cfg(all(test, unix))]` support for the three TMPDIR
//! `*_outlives_*` regressions (`codex_supervise`, `gate_row_audit`, and
//! `swap`'s messaging-proxy test module): a bounded, hermetic re-exec that
//! moves each regression's process-TMPDIR mutation into an exact child test
//! process, so the PARENT SUITE PROCESS contains ZERO TMPDIR mutators (the
//! mutation exists only in the marked child invocation of the same binary)
//! and a transient's deletion can never cascade into a sibling test's
//! fixture.
//!
//! Parent discipline (per `test-subprocess-hermeticity.md` MUST-2 and the
//! `provider_session_fence_tests` precedent): `env_clear()` + stdlib/Windows
//! whitelist (this module is unix-only by its declaration, so `APPDATA` /
//! `LOCALAPPDATA` are deliberately absent rather than re-injected); HOME /
//! `CSQ_BASE_DIR` / TMPDIR / TEMP / TMP all pointed INSIDE a parent-owned
//! stable sandbox (never the real HOME or a mutable ambient root); the
//! child's cwd and stdin are the sandbox and null; child output drains to
//! sandbox FILES (no pipe-fill deadlock), size-capped by METADATA before the
//! read (1 MiB, hard failure beyond — the real bounding mechanism is the 10s
//! deadline); a 10s deadline whose expiry kills AND reaps BEFORE the captures
//! are read (complete diagnostics) and before any cleanup; and an exact
//! libtest-summary assertion plus a test-name binding, so neither a drifted
//! selector running zero tests nor a wrong-but-passing test can read as
//! coverage. The parent NEVER mutates TMPDIR — the mutation exists only
//! inside the child.
//!
//! CONTRACT for child bodies: they MUST NOT spawn descendant processes. The
//! kill/reap below covers the DIRECT child only (no process-group kill); a
//! future child body that spawns would need process-group placement added
//! here first. Today all three bodies are fixture-only.
//!
//! Override note: the three fixture helpers key their root on [`SANDBOX_ENV`]
//! PRESENCE, which only the parent dispatch sets. A concurrent ordinary test
//! cannot pick it up (`Command::env` never mutates the parent's env); the
//! only exposure is an ambient `SANDBOX_ENV` in the operator/CI environment,
//! which RELOCATES sibling fixtures (and fails loudly if the path is absent)
//! rather than corrupting them.

use std::process::{Command, Stdio};

/// Parent-owned sandbox root handed down to the child. The child's transient
/// TMPDIR root and the fixture helper's root are placed under it, so the
/// parent's sandbox drop after reap IS the exact owned cleanup.
pub(crate) const SANDBOX_ENV: &str = "CSQ_TEST_TMPDIR_OUTLIVES_SANDBOX";
/// Marker selecting the child body when the test binary is re-executed.
/// Set only by [`spawn_outlives_child`]; a child body `.expect`s
/// [`SANDBOX_ENV`], so a stray ambient `CHILD_ENV` without it fails loudly
/// rather than passing vacuously.
pub(crate) const CHILD_ENV: &str = "CSQ_TEST_TMPDIR_OUTLIVES_CHILD";

/// Per-stream capture cap; a larger log is a hard failure, never a truncation.
const MAX_LOG_BYTES: u64 = 1 << 20;
/// Bounded child lifetime; expiry = kill + reap + fail-with-diagnostics.
const CHILD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

fn read_capture(name: &str, path: &std::path::Path) -> String {
    // Fail CLOSED on an unmeasurable capture: `map(...).unwrap_or(0)` would
    // treat an unknown size as zero and read an unbounded file — a metadata
    // failure must abort BEFORE any read, never widen the cap.
    let md = std::fs::metadata(path).unwrap_or_else(|e| {
        panic!(
            "cannot stat outlives child {name} capture at {path:?}: {e} — refusing to read an unmeasured capture"
        )
    });
    assert!(
        md.len() <= MAX_LOG_BYTES,
        "outlives child {name} capture is {} bytes (> {MAX_LOG_BYTES}) — hard-fail on unbounded capture",
        md.len()
    );
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read outlives child {name} capture at {path:?}: {e}"))
}

/// Parent side of a regression: re-executes `exact_test` (the caller's own
/// full test path) in a child process carrying [`CHILD_ENV`], and asserts the
/// child ran EXACTLY that one test to success — and emitted the call site's
/// `witness` token, printed by the CHILD BODY itself.
///
/// Why a witness and not just `log.contains(exact_test)`: the selector string
/// trivially appears in the log whenever the selected test passes, so binding
/// the log to the SELECTOR cannot detect a wrong-but-passing selector (a
/// copy-pasted literal pointing at a sibling test) — measured: the parent
/// stayed GREEN with the selector repointed at
/// `swap_exec_claude_registers_messaging_before_the_resume_flag`. The child
/// BODY prints its own per-call-site constant, which the selected test cannot
/// know if it is the wrong test, so the mismatch is detectable.
pub(crate) fn spawn_outlives_child(exact_test: &str, witness: &str) {
    let sandbox = tempfile::TempDir::new_in("/tmp").expect("parent sandbox");
    let home = sandbox.path().join("home");
    let base = sandbox.path().join("base");
    let tmp = sandbox.path().join("tmp");
    for d in [&home, &base, &tmp] {
        std::fs::create_dir(d).expect("sandbox subdir");
    }
    let out_path = sandbox.path().join("child.stdout.log");
    let err_path = sandbox.path().join("child.stderr.log");
    let out_file = std::fs::File::create(&out_path).expect("child stdout capture file");
    let err_file = std::fs::File::create(&err_path).expect("child stderr capture file");

    let mut cmd = Command::new(std::env::current_exe().expect("current test executable"));
    cmd.env_clear();
    for k in [
        "PATH",
        "LANG",
        "LC_ALL",
        "TERM",
        "USER",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    let mut child = cmd
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("CSQ_BASE_DIR", &base)
        .env("TMPDIR", &tmp)
        .env("TEMP", &tmp)
        .env("TMP", &tmp)
        .env(SANDBOX_ENV, sandbox.path())
        .env(CHILD_ENV, "1")
        .current_dir(&sandbox)
        .stdin(Stdio::null())
        .args(["--exact", exact_test, "--nocapture"])
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .expect("re-exec the test binary for the outlives child");

    let deadline = std::time::Instant::now() + CHILD_DEADLINE;
    let mut status = None;
    while status.is_none() && std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(s)) => status = Some(s),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
            Err(e) => {
                // Never leave a live child over a deleted sandbox.
                let _ = child.kill();
                let _ = child.wait();
                panic!("try_wait failed on the outlives child ({e}); killed and reaped");
            }
        }
    }
    let timed_out = status.is_none();
    if timed_out {
        // Kill AND reap BEFORE reading captures (complete diagnostics) and
        // before the sandbox drops: cleanup must never race a live child.
        let _ = child.kill();
        let _ = child.wait();
    } else {
        // try_wait already reaped on its Some path; the explicit wait() keeps
        // EVERY path covered (clippy::zombie_processes) — a no-op Err here.
        let _ = child.wait();
    }
    let out = read_capture("stdout", &out_path);
    let err = read_capture("stderr", &err_path);
    let log = format!("{out}{err}");
    if timed_out {
        panic!(
            "outlives child exceeded {CHILD_DEADLINE:?}; killed and reaped. child output:\n{log}"
        );
    }
    let status = status.expect("status is Some when not timed out");
    assert!(
        status.success(),
        "outlives child failed ({status:?}). child output:\n{log}"
    );
    assert!(
        log.contains("test result: ok. 1 passed; 0 failed; 0 ignored"),
        "outlives child did not run EXACTLY one passing test (selector drift runs 0 or >1 — refusing a vacuous pass). child output:\n{log}"
    );
    assert!(
        log.contains(witness),
        "outlives child never emitted this call site's witness ({witness}) — the selector ran a DIFFERENT test (wrong-but-passing selectors must not read as coverage). child output:\n{log}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-read cap must REFUSE an unmeasurable capture rather than read
    /// it: treating a metadata failure as size 0 would bypass MAX_LOG_BYTES.
    #[test]
    #[should_panic(expected = "refusing to read an unmeasured capture")]
    fn read_capture_missing_file_refuses_before_read() {
        let dir = tempfile::TempDir::new_in("/tmp").unwrap();
        let _ = read_capture("stdout", &dir.path().join("absent.log"));
    }

    /// An oversized capture fails hard from METADATA — the read never runs.
    #[test]
    #[should_panic(expected = "hard-fail on unbounded capture")]
    fn read_capture_oversized_refuses_before_read() {
        let dir = tempfile::TempDir::new_in("/tmp").unwrap();
        let big = dir.path().join("big.log");
        std::fs::write(&big, vec![b'x'; MAX_LOG_BYTES as usize + 1]).unwrap();
        let _ = read_capture("stdout", &big);
    }
}
