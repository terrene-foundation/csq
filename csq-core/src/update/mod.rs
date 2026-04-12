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
//!  ├── github.rs   — GitHub Releases API client
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

use crate::http;
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
    github::check_latest_version(http::get_with_headers)
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
/// 3. Otherwise calls the GitHub Releases API.
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

/// Inner function for `auto_update_bg`. Separated for testability.
fn run_update_check(base_dir: std::path::PathBuf) -> anyhow::Result<()> {
    let cache_path = base_dir.join(".csq-update-check");

    // Check if the cache is still fresh (< 24 hours).
    if is_cache_fresh(&cache_path) {
        return Ok(());
    }

    let result = check_for_update()?;

    // Update the cache timestamp regardless of whether an update was found.
    write_cache_timestamp(&cache_path);

    if let Some(info) = result {
        eprintln!(
            "csq v{} available — run `csq update install` to upgrade",
            info.version
        );
    }

    Ok(())
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
