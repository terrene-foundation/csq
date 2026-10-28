//! Cross-platform daemon cache-invalidation notify chokepoint (an internal ticket).
//!
//! Before this module existed, four independent CLI call sites
//! (`swap`/`login`/`logout`/`move`) each carried their own copy of the
//! "POST /api/invalidate-cache to the daemon if reachable" body, and every
//! copy had a `#[cfg(not(unix))]` no-op — Windows silently never invalidated
//! the daemon's cache after a swap/login/logout/move, even though Windows is
//! a CI-tested, shipped target. `move_slot.rs`'s targeted per-slot variant
//! (`POST /api/slot-swap`, SEC-2.11) had the same gap.
//!
//! This module is the single production chokepoint for both notifications,
//! on both transports. Do NOT re-inline a copy at a new call site — add the
//! caller here instead.
//!
//! # Fire-and-forget semantics
//!
//! Both notifications are best-effort: a missing daemon (no Unix socket, no
//! Windows named pipe) is the expected common case — most CLI invocations
//! run with no daemon started — and is silently treated as success on both
//! platforms, mirroring the pre-existing Unix behavior. A daemon that IS
//! reachable but whose POST fails logs a `tracing::warn!`; the daemon simply
//! picks up the change at its next periodic poll tick, so this is
//! diagnostic only, never fatal, and callers never see a `Result`.

use std::path::Path;

use super::socket_path;

/// Fire-and-forget: `POST /api/invalidate-cache` to the running daemon
/// (Unix socket or Windows named pipe, transparently). No-ops silently if
/// no daemon is reachable.
pub fn cache_invalidation(base_dir: &Path) {
    let target = socket_path(base_dir);
    #[cfg(unix)]
    unix_post(&target, "/api/invalidate-cache", None);
    #[cfg(windows)]
    windows_post(
        &target,
        "/api/invalidate-cache",
        None,
        "daemon_cache_invalidate_failed",
    );
    #[cfg(not(any(unix, windows)))]
    let _ = target;
}

/// Fire-and-forget: `POST /api/slot-swap {"from":N,"to":M}` — targeted
/// per-slot cache invalidation after `csq move FROM TO` (SEC-2.11). The
/// daemon drops `RefreshStatus` cache entries for both slot numbers.
pub fn slot_swap(base_dir: &Path, from: u16, to: u16) {
    let target = socket_path(base_dir);
    let body = format!(r#"{{"from":{from},"to":{to}}}"#);
    #[cfg(unix)]
    unix_post(&target, "/api/slot-swap", Some(&body));
    #[cfg(windows)]
    windows_post(
        &target,
        "/api/slot-swap",
        Some(&body),
        "daemon_cache_invalidate_failed",
    );
    #[cfg(not(any(unix, windows)))]
    let _ = (target, body);
}

/// Fire-and-forget: `POST /api/slot-rebind {"slot":N}` — wake the daemon's
/// usage poller for an IMMEDIATE targeted re-poll of that slot after a
/// successful login/re-auth of it (login-followup: no slot should wait up to
/// 5 minutes for its first quota row). Best-effort by construction — the
/// login has already committed; changing an absent-or-down daemon into a
/// failed login would be strictly worse. When no daemon wakes, the poller
/// picks the new binding up at its next periodic tick, exactly as before.
///
/// Unix arm delegates to [`super::client::notify_slot_rebind`] (same
/// transport + error mapping as the `slot_swap` client fn it mirrors);
/// the Windows arm reuses `windows_post`, so the an internal ticket cross-platform
/// gap cannot reopen here. Both arms log `daemon_slot_rebind_notify_failed`
/// on a non-2xx answer (login-followup R1 LOW-6: the Windows arm used to
/// report the cache-invalidate kind for a rebind failure).
pub fn slot_rebind(base_dir: &Path, slot: u16) {
    let target = socket_path(base_dir);
    #[cfg(unix)]
    {
        if let Err(e) = super::client::notify_slot_rebind(&target, slot) {
            tracing::warn!(
                error_kind = "daemon_slot_rebind_notify_failed",
                route = "/api/slot-rebind",
                error = %e,
                "failed to wake the daemon usage poller; it will pick the rebind up \
                 at its next periodic tick"
            );
        }
    }
    #[cfg(windows)]
    {
        let body = format!(r#"{{"slot":{slot}}}"#);
        windows_post(
            &target,
            "/api/slot-rebind",
            Some(&body),
            "daemon_slot_rebind_notify_failed",
        );
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (target, slot);
}

#[cfg(unix)]
fn unix_post(sock: &Path, path_and_query: &str, body: Option<&str>) {
    // The common case (no daemon running) — silent, matches the historical
    // per-call-site `if !sock.exists() { return; }` guard.
    if !sock.exists() {
        return;
    }
    let result = match body {
        Some(b) => super::client::http_post_unix_json(sock, path_and_query, b),
        None => super::client::http_post_unix(sock, path_and_query),
    };
    match result {
        Ok(resp) if (200..300).contains(&resp.status) => {}
        // login-followup R1 MED-1: a non-2xx answer (404 on a version-skewed
        // daemon, or a 400/500 refusal) means the notification did NOT take
        // effect. Pre-fix this was silently counted as success.
        Ok(resp) => {
            tracing::warn!(
                error_kind = "daemon_cache_invalidate_failed",
                route = path_and_query,
                status = resp.status,
                "daemon refused the notify; daemon will pick up changes at next periodic tick"
            );
        }
        Err(e) => {
            tracing::warn!(
                error_kind = "daemon_cache_invalidate_failed",
                route = path_and_query,
                error = %e,
                "failed to notify daemon; daemon will pick up changes at next periodic tick"
            );
        }
    }
}

/// Runs a blocking notify body without ever calling `block_on` on a thread
/// the caller's tokio runtime drives.
///
/// Inside a runtime (`Handle::try_current()` is `Ok` — which includes both
/// an async worker and a `spawn_blocking` thread, so the check is
/// conservative) the body runs on a plain `std::thread` and this function
/// joins it. With no runtime current it runs inline, with no thread spawn,
/// which is the shape every CLI notify call site has.
///
/// This exists because building a SECOND runtime and `block_on`ing it from
/// inside a runtime panics (`Cannot start a runtime from within a
/// runtime`). login-followup HIGH-1 (execution-confirmed on tokio 1.52.3):
/// the desktop's registered login command called the Windows arm from a
/// tauri async worker, so every successful Add Account on Windows panicked
/// AFTER the login had committed. The command-side fix (running the notify
/// on the blocking pool) and this shim are deliberately BOTH kept: the
/// call-site move keeps the runtime worker free (pinned for the login
/// command only, by `notify_step_never_blocks_the_async_worker` in the
/// desktop crate; the other desktop commands are covered by their own
/// call-site routing, not by that test), while the shim keeps every future
/// caller safe regardless of context.
///
/// Returns `None` when the OS refuses a thread or the body panics: this is
/// a fire-and-forget layer and MUST NOT raise into a caller that has
/// already committed a login/swap/logout (login-followup R2 LOW-5). Both
/// failures log a fixed-vocabulary `warn!` (no error text).
#[cfg(any(windows, test))]
fn run_off_runtime<F, R>(body: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_err() {
        return Some(body());
    }
    let handle = match std::thread::Builder::new()
        .name("csq-daemon-notify".into())
        .spawn(body)
    {
        Ok(h) => h,
        Err(_) => {
            tracing::warn!(
                error_kind = "daemon_notify_thread_spawn_failed",
                "could not start the daemon-notify thread; daemon will pick up \
                 changes at next periodic tick"
            );
            return None;
        }
    };
    match handle.join() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(
                error_kind = "daemon_notify_task_panicked",
                "daemon-notify body panicked; daemon will pick up changes at next \
                 periodic tick"
            );
            None
        }
    }
}

/// Windows bridge, runtime-safe entry point used by every Windows notify
/// arm. Hands the blocking body to [`run_off_runtime`], so this function is
/// safe from ANY context: on a plain synchronous CLI handler it runs
/// inline; inside a tokio runtime it runs the body on a plain
/// `std::thread` instead of `block_on`ing on the caller's runtime — which
/// is the login-followup HIGH-1 panic (`Cannot start a runtime from
/// within a runtime`) when a tauri async command called this.
///
/// `error_kind` is the caller's fixed-vocabulary failure tag, so a failed
/// rebind reports `daemon_slot_rebind_notify_failed` rather than the
/// cache-invalidate kind (login-followup R1 LOW-6).
#[cfg(windows)]
fn windows_post(pipe: &Path, path_and_query: &str, body: Option<&str>, error_kind: &'static str) {
    // Owned copies so the shim can move the body onto a 'static thread.
    let pipe = pipe.to_path_buf();
    let path_and_query = path_and_query.to_string();
    let body = body.map(str::to_string);
    // Statement position on purpose: the body returns `()`, so a `let _ =`
    // binding here is `clippy::let_unit_value` (red on the Windows
    // cross-target clippy lane, `test.yml`).
    run_off_runtime(move || {
        windows_post_blocking(&pipe, &path_and_query, body.as_deref(), error_kind)
    });
}

/// The blocking Windows notify body: runs the async
/// [`super::client_windows::http_post_pipe`] / `http_post_pipe_json` to
/// completion on a short-lived current-thread tokio runtime — the same
/// ephemeral-runtime idiom already used for one-off async work from a sync
/// CLI path (`csq/src/cli/commands/{daemon,login,run,eval}.rs`,
/// `csq-core/src/daemon/usage_poller/kimi.rs` tests).
///
/// MUST NOT be called directly from a runtime context; that is exactly what
/// [`windows_post`]'s [`run_off_runtime`] shim exists to guarantee.
///
/// A missing pipe (`DaemonClientError::Connect`, the daemon-not-running
/// case — `ERROR_FILE_NOT_FOUND` from `ClientOptions::open`) is silent,
/// mirroring the Unix `sock.exists()` early return. A non-2xx answer, any
/// other failure, or exceeding [`WINDOWS_NOTIFY_TIMEOUT`] (bounding the
/// whole call so a wedged pipe cannot hang `csq swap`/`login`/`logout`/
/// `move`) logs a `tracing::warn!` under the caller's `error_kind` —
/// fire-and-forget, never propagated to the caller.
#[cfg(windows)]
fn windows_post_blocking(
    pipe: &Path,
    path_and_query: &str,
    body: Option<&str>,
    error_kind: &'static str,
) {
    use super::client_windows::{http_post_pipe, http_post_pipe_json, DaemonClientError};

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(
                error_kind = "daemon_notify_runtime_build_failed",
                error = %e,
                "failed to build tokio runtime for daemon named-pipe notify; \
                 daemon will pick up changes at next periodic tick"
            );
            return;
        }
    };

    let call = async {
        match body {
            Some(b) => http_post_pipe_json(pipe, path_and_query, b).await,
            None => http_post_pipe(pipe, path_and_query).await,
        }
    };

    // The timeout MUST be constructed INSIDE the runtime context.
    //
    // `tokio::time::timeout` builds a `Sleep`, and a `Sleep` registers with the
    // runtime's time driver at CONSTRUCTION, not at first poll. Writing
    //
    //     rt.block_on(tokio::time::timeout(D, call))     // WRONG
    //
    // evaluates `timeout(..)` to produce `block_on`'s argument, which happens
    // BEFORE `block_on` enters the runtime — so the `Sleep` looks for a driver
    // that is not yet current and panics:
    //
    //     there is no reactor running, must be called from the context of a
    //     Tokio 1.x runtime
    //
    // That is not a test artifact. It would panic on EVERY `csq swap` / `login`
    // / `logout` / `move` on Windows — strictly worse than the silent no-op this
    // module replaced. Wrapping in an `async` block defers construction until
    // `block_on` has entered the runtime.
    //
    // Cross-compiling (`cargo clippy --target x86_64-pc-windows-gnu`) cannot
    // catch this: it type-checks without executing, and this fn is
    // `#[cfg(windows)]` so no Unix test ever runs it. It took the
    // `windows-latest` CI job actually running the two missing-daemon tests.
    // Keep those tests — they are the only oracle for this class.
    let result = rt.block_on(async { tokio::time::timeout(WINDOWS_NOTIFY_TIMEOUT, call).await });

    match result {
        Ok(Ok(response)) if (200..300).contains(&response.status) => {}
        // No daemon pipe reachable — the expected common case, silent
        // (mirrors the Unix `sock.exists()` early return).
        Ok(Err(DaemonClientError::Connect(_))) => {}
        // login-followup R1 MED-1: a non-2xx answer means the notification
        // did NOT take effect (404 on a version-skewed daemon, or a refusal).
        Ok(Ok(response)) => {
            tracing::warn!(
                error_kind = error_kind,
                route = path_and_query,
                status = response.status,
                "daemon refused the notify; daemon will pick up changes at next periodic tick"
            );
        }
        Ok(Err(e)) => {
            tracing::warn!(
                error_kind = error_kind,
                route = path_and_query,
                error = %e,
                "failed to notify daemon; daemon will pick up changes at next periodic tick"
            );
        }
        Err(_elapsed) => {
            tracing::warn!(
                error_kind = error_kind,
                route = path_and_query,
                "timed out notifying daemon; daemon will pick up changes at next periodic tick"
            );
        }
    }
}

/// Hard ceiling on the whole Windows notify round-trip (connect + write +
/// read), independent of the per-read-chunk timeouts already inside
/// `client_windows`'s primitives. Bounds worst case: several trickling
/// reads under 64 KiB, each individually under `client_windows::
/// DEFAULT_TIMEOUT` (2s), could otherwise chain past what an interactive
/// `csq swap`/`login`/`logout`/`move` should ever block for.
#[cfg(windows)]
const WINDOWS_NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::testing::socket_fixture::UnixSocketFixture;

    /// Non-vacuity + behavior: with no daemon running at all (fresh tempdir,
    /// nothing bound), both notify calls MUST return without panicking or
    /// blocking beyond a trivial bound — the missing-daemon case is a
    /// pure no-op on whichever platform this test runs on.
    #[test]
    fn cache_invalidation_is_silent_noop_when_daemon_absent() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        // Must return promptly; if this hangs, the test times out (cargo
        // test's own default) rather than silently passing.
        cache_invalidation(&base);
    }

    #[test]
    fn slot_swap_is_silent_noop_when_daemon_absent() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        slot_swap(&base, 1, 2);
    }

    /// Non-vacuity guard for the two no-op tests above (`instrument-
    /// discipline.md` MUST-2): those tests would pass identically even if
    /// `unix_post`/`windows_post` were replaced with an empty body that
    /// never attempts a connection at all — "returns without panicking
    /// when nothing is listening" carries zero information about whether
    /// the notify path is real code. This test binds an actual listener
    /// and asserts the connect + POST is observed, so a regression that
    /// makes `unix_post` an unconditional no-op reds this test even though
    /// it would leave the two no-op tests above green.
    ///
    /// Deliberately bypasses the module's public API (`cache_invalidation`,
    /// which resolves its target via the global `socket_path`) and calls
    /// the private `unix_post` directly with an explicit tempdir-scoped
    /// path — `socket_path` ignores `base_dir` on Linux in favor of the
    /// process-wide `$XDG_RUNTIME_DIR/csq.sock` (see `detect.rs`'s
    /// `SOCKET_TEST_MUTEX` doc comment), which this crate's other daemon
    /// tests already serialize on; testing the private helper directly
    /// avoids that shared-path contention entirely rather than adding a
    /// second lock users of this file would need to know about.
    #[cfg(unix)]
    #[test]
    fn unix_post_reaches_a_real_listener_and_delivers_the_route() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = UnixSocketFixture::new().unwrap();
        let sock = dir.socket_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = tx.send(request);
            }
        });

        unix_post(&sock, "/api/invalidate-cache", None);

        let request = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("unix_post must have connected to the listening socket");
        let _ = server.join();
        assert!(
            request.starts_with("POST /api/invalidate-cache HTTP/1.1"),
            "request: {request:?}"
        );
    }

    /// Same non-vacuity proof for the JSON-body (slot-swap) path — confirms
    /// the body is actually written on the wire, not silently dropped.
    #[cfg(unix)]
    #[test]
    fn unix_post_delivers_the_json_body() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = UnixSocketFixture::new().unwrap();
        let sock = dir.socket_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = tx.send(request);
            }
        });

        unix_post(&sock, "/api/slot-swap", Some(r#"{"from":3,"to":7}"#));

        let request = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("unix_post must have connected to the listening socket");
        let _ = server.join();
        assert!(
            request.contains(r#"{"from":3,"to":7}"#),
            "request: {request:?}"
        );
    }

    /// The load-bearing part of the `windows_post_blocking` body, reduced to
    /// a function: build a SECOND current-thread runtime and `block_on` it.
    /// Off a runtime-driven thread this returns 42; ON one it panics with
    /// "Cannot start a runtime from within a runtime". Also returns the
    /// thread it ran on, so the probes below can show the shim moved it.
    fn windows_post_shaped_body() -> (u8, std::thread::ThreadId) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let value = rt.block_on(async { 42u8 });
        (value, std::thread::current().id())
    }

    /// login-followup HIGH-1 regression, runnable on Linux (where
    /// `windows_post` itself is `#[cfg(windows)]` and never compiles): the
    /// shim MUST run a `block_on`-shaped body off the runtime's thread, so
    /// the pre-fix panic cannot come back through any Windows caller.
    /// Reverting the shim to call the body inline reds this test with the
    /// nested-`block_on` panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_safe_shim_moves_the_body_off_a_multi_thread_runtime_worker() {
        let caller = std::thread::current().id();
        let (value, body_thread) =
            run_off_runtime(windows_post_shaped_body).expect("the shim must run the body");
        assert_eq!(value, 42, "the shim must run the body and return its value");
        assert_ne!(
            body_thread, caller,
            "inside a runtime the body must run on a plain std thread, \
             never on the runtime worker"
        );
    }

    /// The same probe on the current-thread flavor — the flavor the daemon's
    /// own `serve` / poller tasks run under, and the one a tauri async
    /// command worker most resembles for this class of bug.
    #[tokio::test]
    async fn runtime_safe_shim_moves_the_body_off_a_current_thread_runtime() {
        let caller = std::thread::current().id();
        let (value, body_thread) =
            run_off_runtime(windows_post_shaped_body).expect("the shim must run the body");
        assert_eq!(value, 42);
        assert_ne!(body_thread, caller);
    }

    /// The other branch: with NO runtime current the shim runs the body
    /// inline — no thread spawn — which is the shape every CLI notify call
    /// site has today.
    #[test]
    fn runtime_safe_shim_runs_inline_outside_any_runtime() {
        let caller = std::thread::current().id();
        let (value, body_thread) =
            run_off_runtime(windows_post_shaped_body).expect("the shim must run the body");
        assert_eq!(value, 42);
        assert_eq!(
            body_thread, caller,
            "with no runtime current the body must run inline"
        );
    }

    /// Control that keeps the three probes above honest: the PRE-FIX shape —
    /// `block_on`ing a nested runtime from a runtime-driven thread — really
    /// does panic in this tokio (`1.52.3` at this revision). If a future
    /// tokio ever allows it, this control fails and the probes must be
    /// re-instrumented rather than trusted (`instrument-discipline.md`
    /// MUST-2: a probe whose subject can no longer fail is vacuous).
    #[tokio::test]
    #[should_panic]
    async fn control_nested_block_on_on_a_runtime_driven_thread_panics() {
        let _ = windows_post_shaped_body();
    }

    /// LOW-5: a panicking body inside a runtime is contained — `None`, never
    /// a re-raise into the (already committed) caller.
    #[tokio::test]
    async fn shim_contains_a_panicking_body() {
        let out = run_off_runtime(|| -> u8 { panic!("notify body panic") });
        assert!(
            out.is_none(),
            "a panicking body must yield None, not unwind"
        );
    }

    /// LOW-4: the three notify entry points, driven INSIDE a runtime with no
    /// daemon present, must return without panicking — on every platform,
    /// so `test-windows.yml --lib` exercises the Windows arm (the
    /// nested-runtime `block_on` panic of HIGH-1 would red here). They are
    /// called from inside the runtime on purpose: that is the shape of the
    /// regression. `base` is an empty tempdir; `socket_path` may resolve to
    /// a process-wide path on Linux, but no daemon listens in these tests.
    fn drive_all_three_with_no_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        cache_invalidation(&base);
        slot_swap(&base, 1, 2);
        slot_rebind(&base, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notify_fns_absent_daemon_inside_multi_thread_runtime() {
        drive_all_three_with_no_daemon();
    }

    #[tokio::test]
    async fn notify_fns_absent_daemon_inside_current_thread_runtime() {
        drive_all_three_with_no_daemon();
    }
}
