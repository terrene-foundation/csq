//! Platform abstraction layer.
//!
//! Provides cross-platform APIs for file operations, locking, and process
//! detection. Each submodule uses `cfg(target_os)` to select the correct
//! implementation at compile time.

pub mod env_check;
pub mod fs;
#[cfg(unix)]
pub mod fs_symlink_unix;
#[cfg(windows)]
pub mod fs_symlink_windows;
pub mod lock;
pub mod process;
pub mod secret;
// Available to in-crate tests AND to external integration tests that opt in
// via `--features csq-core/test-utils`. Required by `tests/cli_deps_integration.rs`
// to honor `testing.md` MUST Rule 6 (shared env mutex before in-module mutex)
// across both the in-binary tests and integration tests in `tests/`.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_env;

/// Target platform, detected at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
}

impl Platform {
    /// Returns the platform this binary was compiled for.
    #[inline]
    pub fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Platform::MacOS
        }
        #[cfg(target_os = "linux")]
        {
            Platform::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Windows => write!(f, "Windows"),
        }
    }
}

/// Compile-time platform constants.
pub const IS_MACOS: bool = cfg!(target_os = "macos");
pub const IS_LINUX: bool = cfg!(target_os = "linux");
pub const IS_WINDOWS: bool = cfg!(target_os = "windows");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_current_returns_valid_variant() {
        let p = Platform::current();
        // On macOS CI/dev machines:
        #[cfg(target_os = "macos")]
        assert_eq!(p, Platform::MacOS);
        #[cfg(target_os = "linux")]
        assert_eq!(p, Platform::Linux);
        #[cfg(target_os = "windows")]
        assert_eq!(p, Platform::Windows);
        // Display works
        let s = format!("{p}");
        assert!(!s.is_empty());
    }

    #[test]
    fn compile_time_constants_match_platform() {
        // These are compile-time constants, so we verify them via const assertion.
        #[cfg(target_os = "macos")]
        const {
            assert!(IS_MACOS && !IS_LINUX && !IS_WINDOWS)
        }
        #[cfg(target_os = "linux")]
        const {
            assert!(!IS_MACOS && IS_LINUX && !IS_WINDOWS)
        }
        #[cfg(target_os = "windows")]
        const {
            assert!(!IS_MACOS && !IS_LINUX && IS_WINDOWS)
        }
    }
}
