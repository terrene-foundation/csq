//! csq self-update: check, download, verify, and atomic binary replacement.
//!
//! # Public API
//!
//! - [`check_for_update`] — check GitHub Releases for a newer version.
//! - [`download_and_apply`] — download, verify (SHA256 + Ed25519), and atomically replace.
//! - [`auto_update_bg`] — spawn a background task that checks on launch and
//!   prints a one-line notice if a newer version is available. Caches the
//!   check result for 24 hours.
//!
//! # Architecture
//!
//! ```text
//! mod.rs (public API)
//!  ├── github.rs   — version checker (static latest.json manifest, CDN; no REST API)
//!  ├── verify.rs   — SHA256 checksum + Ed25519 signature verification
//!  └── apply.rs    — download, verify, atomic binary replacement
//! ```
//!
//! # Security
//!
//! All downloads are HTTPS-only. The binary is verified against:
//! 1. SHA256 checksum (from a `SHA256SUMS` file in the release assets)
//! 2. Ed25519 signature (from a `.sig` file signed with the Foundation's
//!    release key pinned in `verify.rs`)
//!
//! The current binary is never modified until both checks pass.
//!
//! # Background check
//!
//! `auto_update_bg` is a fire-and-forget tokio task. It:
//! - Reads a timestamp file `~/.claude/accounts/.csq-update-check`
//! - Skips the network check if the timestamp is less than 24 hours old
//! - Otherwise, calls `check_for_update` and, if a newer version exists,
//!   prints a one-line notice to stderr
//! - Updates the timestamp file on success (regardless of whether an update
//!   was found)
//! - Never auto-installs (too risky for a CLI tool with credential access)
//!
//! The task is spawned with `tokio::spawn` but does NOT block the main
//! command dispatch. Any error in the background task is silently discarded.

pub mod apply;
pub mod github;
pub mod verify;

use crate::http::{self, FullResponse};
pub use github::UpdateInfo;

use std::path::Path;

/// Checks GitHub Releases for a version newer than the current binary.
///
/// Returns `Ok(Some(info))` if an update is available for the current
/// platform. Returns `Ok(None)` if already up to date, or if the release
/// assets for this platform are missing.
///
/// Uses the real HTTP transport. For testable code, use
/// `github::check_latest_version` with an injectable transport directly.
pub fn check_for_update() -> anyhow::Result<Option<UpdateInfo>> {
    github::check_latest_version(http::get_with_headers_full)
}

/// Downloads, verifies, and atomically replaces the current binary.
///
/// Calls `apply::download_and_apply` with the real HTTP transport.
/// On success, prints `"csq v{version} installed. Restart csq to use the new version."`.
pub fn download_and_apply(info: &UpdateInfo) -> anyhow::Result<()> {
    apply::download_and_apply(info, http::get_with_headers)
}

/// Spawns a background OS thread that:
///
/// 1. Checks the update-check cache at `~/.claude/accounts/.csq-update-check`.
/// 2. If the last check was less than 24 hours ago, exits silently.
/// 3. Otherwise fetches the static `latest.json` manifest (CDN, no REST API).
/// 4. If a newer version exists, prints a one-line notice to stderr.
/// 5. Writes the current timestamp to the cache file.
///
/// Uses a plain OS thread (not a tokio task) so it works from both
/// synchronous CLI dispatch and async daemon contexts without needing an
/// active tokio runtime. The thread is detached — errors are silently
/// discarded. This must never block the main command dispatch.
///
/// `base_dir` is the csq accounts directory (`~/.claude/accounts`).
pub fn auto_update_bg(base_dir: std::path::PathBuf) {
    std::thread::spawn(move || {
        let _ = run_update_check(base_dir);
    });
}

/// Inner function for `auto_update_bg`. Uses the real HTTP transport.
fn run_update_check(base_dir: std::path::PathBuf) -> anyhow::Result<()> {
    run_update_check_with(base_dir, http::get_with_headers_full, default_notice_sink)
}

/// Testable variant of [`run_update_check`] with an injectable HTTP
/// transport and notice sink. The transport returns `(status, headers, body)`
/// matching `http::get_with_headers_full` so tests can drive the cache-fresh
/// path, the happy path (update found), and the up-to-date path without
/// touching the network. `notice_sink` receives the one-line stderr
/// message so tests can assert on the output without capturing stderr.
fn run_update_check_with<T, S>(
    base_dir: std::path::PathBuf,
    http_get: T,
    mut notice_sink: S,
) -> anyhow::Result<()>
where
    T: Fn(&str, &[(&str, &str)]) -> Result<FullResponse, String>,
    S: FnMut(&str),
{
    let cache_path = base_dir.join(".csq-update-check");

    // Check if the cache is still fresh (< 24 hours).
    if is_cache_fresh(&cache_path) {
        return Ok(());
    }

    // Write the backoff timestamp BEFORE the network check, so the next check
    // is suppressed for the full TTL even when THIS check fails. Previously the
    // timestamp was written AFTER `check_latest_version`, behind the `?` — so a
    // failed check (the unauthenticated GitHub Releases API is 60 req/hour per
    // IP and is easily exhausted) returned early and NEVER wrote the cache. The
    // cache then stayed stale, so every subsequent `csq statusline` render
    // across every terminal retried the check, kept the 60/hour limit
    // exhausted, and the cache could never recover — a positive-feedback loop
    // that made "GitHub is rate-limited" a permanent state. Writing first also
    // collapses the thundering herd: the first of N concurrent renders to pass
    // `is_cache_fresh` writes the timestamp immediately, so the others skip
    // before issuing their own request. (Cost: a transient failure backs off
    // 24h before retrying — acceptable for a non-urgent update check.)
    write_cache_timestamp(&cache_path);

    let result = github::check_latest_version(http_get)?;

    if let Some(info) = result {
        notice_sink(&format!(
            "csq v{} available — run `csq update install` to upgrade",
            info.version
        ));
    }

    Ok(())
}

/// Default notice sink used in production: writes to stderr.
fn default_notice_sink(msg: &str) {
    eprintln!("{msg}");
}

/// Returns `true` if the cache file exists and its mtime is less than 24 hours ago.
fn is_cache_fresh(cache_path: &Path) -> bool {
    use std::time::{Duration, SystemTime};

    const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

    let metadata = match std::fs::metadata(cache_path) {
        Ok(m) => m,
        Err(_) => return false, // no file → not fresh
    };

    let mtime = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return false,
    };

    match SystemTime::now().duration_since(mtime) {
        Ok(age) => age < CACHE_TTL,
        Err(_) => false, // clock skew → treat as stale
    }
}

/// Writes (or overwrites) the cache timestamp file by touching it.
fn write_cache_timestamp(cache_path: &Path) {
    // Create parent directory if needed (should already exist as base_dir).
    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Write an empty file — only the mtime matters.
    let _ = std::fs::write(cache_path, b"");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn cache_fresh_returns_false_when_file_missing() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".csq-update-check");

        // Act / Assert
        assert!(!is_cache_fresh(&path), "missing file must not be fresh");
    }

    #[test]
    fn cache_fresh_returns_true_for_newly_written_file() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".csq-update-check");
        write_cache_timestamp(&path);

        // Act / Assert
        assert!(is_cache_fresh(&path), "newly written file must be fresh");
    }

    #[test]
    fn cache_fresh_returns_false_for_old_file() {
        use std::time::{Duration, SystemTime};

        // Arrange: write a file then backdate its mtime by 25 hours
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".csq-update-check");
        std::fs::write(&path, b"").unwrap();

        // Set mtime to 25 hours ago
        let past = SystemTime::now() - Duration::from_secs(25 * 60 * 60);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        // Use filetime crate? We don't have it. Use a different approach:
        // Just drop the file, wait, and rely on the mtime being in the past.
        // Instead, we set the file's mtime via std::fs on Unix.
        #[cfg(unix)]
        {
            // Use libc's utimes to set mtime to 25 hours ago
            let past_secs = past
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let path_cstr = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            unsafe {
                let times = [
                    libc::timeval {
                        tv_sec: past_secs as libc::time_t,
                        tv_usec: 0,
                    },
                    libc::timeval {
                        tv_sec: past_secs as libc::time_t,
                        tv_usec: 0,
                    },
                ];
                libc::utimes(path_cstr.as_ptr(), times.as_ptr());
            }
            drop(file);
            assert!(
                !is_cache_fresh(&path),
                "file with mtime 25h ago must not be fresh"
            );
        }
        #[cfg(not(unix))]
        {
            drop(file);
            // On Windows, we can't easily backdate. Skip the assertion.
            let _ = past;
        }
    }

    // ── run_update_check_with (T2 coverage) ─────────────────────

    use std::cell::RefCell;
    use std::rc::Rc;

    /// Builds a fake `latest.json` manifest body (the Tauri-updater manifest
    /// the version check now reads — a static CDN asset, not the REST API).
    /// Only `version` is consumed by `check_latest_version`.
    fn fake_release_json(version: &str) -> Vec<u8> {
        format!(
            r#"{{"version": "{version}", "pub_date": "2026-01-01T00:00:00Z", "platforms": {{}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn run_update_check_with_skips_when_cache_is_fresh() {
        // Arrange: fresh cache file, transport that would panic if called.
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join(".csq-update-check");
        write_cache_timestamp(&cache);

        let calls = Rc::new(RefCell::new(0usize));
        let calls_clone = Rc::clone(&calls);
        let transport = move |_url: &str, _hdrs: &[(&str, &str)]| -> Result<FullResponse, String> {
            *calls_clone.borrow_mut() += 1;
            Err("transport must not be called when cache is fresh".into())
        };
        let notices = Rc::new(RefCell::new(Vec::<String>::new()));
        let notices_clone = Rc::clone(&notices);
        let sink = move |msg: &str| {
            notices_clone.borrow_mut().push(msg.to_string());
        };

        // Act
        let result = run_update_check_with(dir.path().to_path_buf(), transport, sink);

        // Assert
        assert!(result.is_ok());
        assert_eq!(*calls.borrow(), 0, "no network calls when cache is fresh");
        assert!(notices.borrow().is_empty(), "no notice when cache is fresh");
    }

    #[test]
    fn run_update_check_with_writes_cache_on_up_to_date() {
        // Arrange: stale cache (no file yet). Transport returns the
        // CURRENT version so check_latest_version reports None.
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join(".csq-update-check");
        assert!(!cache.exists());

        let current = env!("CARGO_PKG_VERSION");
        let json = fake_release_json(current);
        let transport = move |_url: &str, _hdrs: &[(&str, &str)]| -> Result<FullResponse, String> {
            Ok((200, std::collections::HashMap::new(), json.clone()))
        };

        let notices = Rc::new(RefCell::new(Vec::<String>::new()));
        let notices_clone = Rc::clone(&notices);
        let sink = move |msg: &str| {
            notices_clone.borrow_mut().push(msg.to_string());
        };

        // Act
        let result = run_update_check_with(dir.path().to_path_buf(), transport, sink);

        // Assert
        assert!(
            result.is_ok(),
            "up-to-date path should return Ok: {result:?}"
        );
        assert!(cache.exists(), "cache timestamp must be written");
        assert!(
            notices.borrow().is_empty(),
            "no notice when already up to date"
        );
    }

    #[test]
    fn run_update_check_with_writes_cache_even_when_check_fails() {
        // Regression for the GitHub-quota-exhausted-forever loop: a FAILED check
        // (rate-limit / network error) MUST still write the backoff cache, so
        // the next render skips for the TTL instead of immediately retrying.
        // Before the fix the timestamp was written AFTER the `?`, so a failure
        // never backed off and every statusline render across every terminal
        // kept hammering the 60/hour unauthenticated limit, wedging it
        // exhausted permanently.
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join(".csq-update-check");
        assert!(!cache.exists());

        // Simulate the unauthenticated 403 rate-limit envelope.
        let transport = move |_url: &str, _hdrs: &[(&str, &str)]| -> Result<FullResponse, String> {
            let mut h = std::collections::HashMap::new();
            h.insert("x-ratelimit-remaining".to_string(), "0".to_string());
            h.insert("x-ratelimit-reset".to_string(), "4102444800".to_string());
            Ok((403, h, br#"{"message":"API rate limit exceeded"}"#.to_vec()))
        };
        let sink = |_: &str| {};

        let result = run_update_check_with(dir.path().to_path_buf(), transport, sink);

        assert!(
            result.is_err(),
            "a rate-limited check still propagates its error"
        );
        assert!(
            cache.exists(),
            "backoff cache MUST be written even when the check fails — otherwise \
             every render retries and the GitHub limit stays exhausted"
        );
    }

    #[test]
    fn write_cache_timestamp_creates_parent_dirs() {
        // Arrange: nested path whose parent does not yet exist
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("deep")
            .join("nested")
            .join(".csq-update-check");

        // Act
        write_cache_timestamp(&path);

        // Assert
        assert!(
            path.exists(),
            "write_cache_timestamp must create parent dirs"
        );
    }
}
