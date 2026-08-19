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
    windows_post(&target, "/api/invalidate-cache", None);
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
    windows_post(&target, "/api/slot-swap", Some(&body));
    #[cfg(not(any(unix, windows)))]
    let _ = (target, body);
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
    if let Err(e) = result {
        tracing::warn!(
            error_kind = "daemon_cache_invalidate_failed",
            route = path_and_query,
            error = %e,
            "failed to notify daemon; daemon will pick up changes at next periodic tick"
        );
    }
}

/// Windows bridge: runs the async [`super::client_windows::http_post_pipe`]
/// / `http_post_pipe_json` to completion on a short-lived current-thread
/// tokio runtime — the same ephemeral-runtime idiom already used for
/// one-off async work from a sync CLI path (`csq/src/cli/commands/{daemon,
/// login,run,eval}.rs`, `csq-core/src/daemon/usage_poller/kimi.rs` tests).
///
/// MUST NOT be called from inside an existing tokio runtime — building a
/// second runtime and blocking on it from within one panics
/// ("Cannot start a runtime from within a runtime"). Every current call
/// site (`swap`/`login`/`logout`/`move` CLI command handlers) is a plain
/// synchronous `fn`, none of which run under `#[tokio::main]` or inside a
/// `block_on` of their own — verified by reading each call site's
/// enclosing fn signature before wiring this in.
///
/// A missing pipe (`DaemonClientError::Connect`, the daemon-not-running
/// case — `ERROR_FILE_NOT_FOUND` from `ClientOptions::open`) is silent,
/// mirroring the Unix `sock.exists()` early return. Any other failure, or
/// exceeding [`WINDOWS_NOTIFY_TIMEOUT`] (bounding the whole call so a
/// wedged pipe cannot hang `csq swap`/`login`/`logout`/`move`), logs a
/// `tracing::warn!` — fire-and-forget, never propagated to the caller.
#[cfg(windows)]
fn windows_post(pipe: &Path, path_and_query: &str, body: Option<&str>) {
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
        Ok(Ok(_response)) => {}
        // No daemon pipe reachable — the expected common case, silent
        // (mirrors the Unix `sock.exists()` early return).
        Ok(Err(DaemonClientError::Connect(_))) => {}
        Ok(Err(e)) => {
            tracing::warn!(
                error_kind = "daemon_cache_invalidate_failed",
                route = path_and_query,
                error = %e,
                "failed to notify daemon; daemon will pick up changes at next periodic tick"
            );
        }
        Err(_elapsed) => {
            tracing::warn!(
                error_kind = "daemon_cache_invalidate_timeout",
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
    // `#[cfg(unix)]`: PathBuf is used ONLY by the two `#[cfg(unix)]` listener
    // tests below, so an unconditional import is an `unused_imports` error
    // under `-D warnings` on the Windows lane — which is the one lane this
    // module exists to fix. Caught by
    // `cargo clippy --target x86_64-pc-windows-gnu`, not by any Unix gate.
    #[cfg(unix)]
    use std::path::PathBuf;

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

        let dir = tempfile::tempdir().unwrap();
        let sock: PathBuf = dir.path().join("notify-test.sock");
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

        let dir = tempfile::tempdir().unwrap();
        let sock: PathBuf = dir.path().join("notify-test-body.sock");
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
}
