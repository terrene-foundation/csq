//! PATH walking and install-manager classification.
//!
//! Per `independence.md` Rule 3, the `which` crate is NOT used.
//! This module hand-rolls a PATH walk matching `std::process::Command`'s
//! own lookup semantics.

use std::path::{Path, PathBuf};

use super::InstallManager;

/// Walk `PATH` and return the first entry that contains an executable
/// named `name`.
///
/// Unix: splits on `:`, checks `<entry>/<name>` existence + executable bit.
/// Windows: splits on `;`, tries `<entry>/<name>`, `<entry>/<name>.exe`,
/// `<entry>/<name>.cmd`, `<entry>/<name>.bat`.
///
/// Returns the first match (NOT canonicalized). Returns `None` if the
/// binary is not found in any PATH entry.
/// Maximum number of PATH entries to inspect before giving up.
/// Defends against adversarially-crafted 100k-entry PATH values.
const MAX_PATH_ENTRIES: usize = 4096;

/// Maximum byte length of a single PATH entry to inspect.
/// Entries longer than PATH_MAX cannot contain a valid executable path.
const MAX_PATH_ENTRY_BYTES: usize = 4096;

pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let separator = if cfg!(windows) { ';' } else { ':' };

    for (count, dir) in std::env::split_paths(&path_var).enumerate() {
        if count >= MAX_PATH_ENTRIES {
            break;
        }
        // Skip entries that are longer than PATH_MAX — they can't be real.
        // Use as_os_str().len() which returns the byte length of the
        // underlying OS string representation.
        if dir.as_os_str().len() > MAX_PATH_ENTRY_BYTES {
            continue;
        }

        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }

        // On Windows also try with common PATHEXT extensions.
        #[cfg(windows)]
        for ext in &[".exe", ".cmd", ".bat"] {
            let with_ext = dir.join(format!("{name}{ext}"));
            if is_executable(&with_ext) {
                return Some(with_ext);
            }
        }

        // Suppress unused warning on non-Windows.
        let _ = separator;
    }

    None
}

/// Returns `true` if `path` exists and is executable by the current process.
fn is_executable(path: &Path) -> bool {
    use std::fs;

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    if !meta.is_file() {
        return false;
    }

    // On Unix, check the executable bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        // Any of owner/group/other execute bits set.
        mode & 0o111 != 0
    }

    // On Windows, existence of a file in PATH is sufficient
    // (extensions are handled by the caller).
    #[cfg(not(unix))]
    {
        true
    }
}

/// Canonicalize `name` via `find_in_path` → `std::fs::canonicalize`.
///
/// This is the ONLY callsite of `std::fs::canonicalize` in `cli_deps/`
/// (per spec/13 §8: "single canonicalize per probe"). The resolved path is
/// captured into the cached `CliStatus` so subsequent gate sites reuse it
/// without re-canonicalizing.
///
/// Returns `None` if the binary is not found in PATH or if canonicalization
/// fails (e.g. dangling symlink).
pub fn resolve_canonical(name: &str) -> Option<PathBuf> {
    find_in_path(name).and_then(|p| std::fs::canonicalize(p).ok())
}

/// Classify the install manager from a canonicalized binary path.
///
/// Path patterns per spec/13 §5:
///
/// | Pattern                                   | Manager                  |
/// |-------------------------------------------|--------------------------|
/// | `/.local/share/claude/versions/`          | `ClaudeNativeInstaller`  |
/// | `/Caskroom/claude-code/`                  | `BrewCask`               |
/// | `/lib/node_modules/`                      | `NpmGlobal`              |
/// | `/.npm-global/lib/`                       | `NpmGlobal`              |
/// | `/Cellar/gemini-cli/`                     | `BrewFormula`            |
/// | (anything else)                           | `Unknown`                |
pub fn classify_install_manager(canonical_path: &Path) -> InstallManager {
    let s = canonical_path.to_string_lossy();

    if s.contains("/.local/share/claude/versions/") {
        return InstallManager::ClaudeNativeInstaller;
    }
    if s.contains("/Caskroom/claude-code/") {
        return InstallManager::BrewCask;
    }
    // npm-global covers both Homebrew-managed and manual installs:
    // /opt/homebrew/lib/node_modules/
    // /usr/local/lib/node_modules/
    // ~/.npm-global/lib/node_modules/
    if s.contains("/lib/node_modules/") || s.contains("/.npm-global/lib/") {
        return InstallManager::NpmGlobal;
    }
    if s.contains("/Cellar/gemini-cli/") {
        return InstallManager::BrewFormula;
    }

    InstallManager::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── classify_install_manager ─────────────────────────────────────

    #[test]
    fn classify_claude_native_installer() {
        let p = PathBuf::from("/home/user/.local/share/claude/versions/2.1.138/claude");
        assert_eq!(
            classify_install_manager(&p),
            InstallManager::ClaudeNativeInstaller
        );
    }

    #[test]
    fn classify_brew_cask_claude() {
        let p = PathBuf::from("/opt/homebrew/Caskroom/claude-code/2.1.138/claude");
        assert_eq!(classify_install_manager(&p), InstallManager::BrewCask);
    }

    #[test]
    fn classify_npm_global_homebrew() {
        let p = PathBuf::from("/opt/homebrew/lib/node_modules/@openai/codex/bin/codex");
        assert_eq!(classify_install_manager(&p), InstallManager::NpmGlobal);
    }

    #[test]
    fn classify_npm_global_usr_local() {
        let p = PathBuf::from("/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude");
        assert_eq!(classify_install_manager(&p), InstallManager::NpmGlobal);
    }

    #[test]
    fn classify_npm_global_npm_prefix() {
        let p = PathBuf::from("/home/user/.npm-global/lib/node_modules/@openai/codex/bin/codex");
        assert_eq!(classify_install_manager(&p), InstallManager::NpmGlobal);
    }

    #[test]
    fn classify_brew_formula_gemini() {
        let p = PathBuf::from("/opt/homebrew/Cellar/gemini-cli/0.41.2/bin/gemini");
        assert_eq!(classify_install_manager(&p), InstallManager::BrewFormula);
    }

    #[test]
    fn classify_unknown_for_unrecognised_path() {
        let p = PathBuf::from("/usr/bin/codex");
        assert_eq!(classify_install_manager(&p), InstallManager::Unknown);
    }

    #[test]
    fn classify_unknown_for_home_bin() {
        let p = PathBuf::from("/home/user/bin/claude");
        assert_eq!(classify_install_manager(&p), InstallManager::Unknown);
    }

    // ── find_in_path ─────────────────────────────────────────────────

    /// Construct a temp dir with a fake executable, prepend it to PATH,
    /// and confirm find_in_path returns it.
    #[test]
    fn find_in_path_finds_binary_in_first_path_entry() {
        use std::fs;
        use tempfile::TempDir;

        // Per rules/testing.md MUST Rule 6, env-mutating tests must hold
        // the workspace-wide env lock before any other test reads PATH.
        let _env_guard = crate::platform::test_env::lock();

        let tmp = TempDir::new().unwrap();
        // Append the platform's executable suffix so Windows PATHEXT
        // matching in `find_in_path` (which adds `.exe`/`.cmd`/`.bat`
        // to the query) resolves to a file that actually exists on disk.
        let bin_name = format!("fake-binary-csq-test{}", std::env::consts::EXE_SUFFIX);
        let bin = tmp.path().join(&bin_name);

        // Write a minimal shell script and mark executable.
        fs::write(&bin, b"#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let old_path = std::env::var_os("PATH").unwrap_or_default();
        // Use `std::env::join_paths` so the separator is platform-correct
        // (`;` on Windows, `:` elsewhere). Hand-formatted "{}:{}" breaks
        // Windows because `:` is part of drive letters (`C:\…`).
        let mut paths = vec![tmp.path().to_path_buf()];
        paths.extend(std::env::split_paths(&old_path));
        let new_path = std::env::join_paths(paths).expect("join PATH entries");

        // Temporarily override PATH. We restore it at the end.
        // SAFETY: `_env_guard` above serializes against concurrent env mutations
        // across the workspace; nothing else reads/writes PATH while held.
        unsafe {
            std::env::set_var("PATH", &new_path);
        }

        let result = find_in_path("fake-binary-csq-test");

        // Restore PATH.
        unsafe {
            std::env::set_var("PATH", old_path);
        }

        assert!(result.is_some(), "should find the binary");
        assert_eq!(result.unwrap(), bin);
    }

    #[test]
    fn find_in_path_returns_none_for_nonexistent() {
        // Use a name that is extremely unlikely to exist.
        let result = find_in_path("__csq_nonexistent_binary_zzz__");
        assert!(result.is_none());
    }

    // ── resolve_canonical ────────────────────────────────────────────

    #[test]
    fn resolve_canonical_returns_none_for_nonexistent() {
        let result = resolve_canonical("__csq_nonexistent_binary_zzz__");
        assert!(result.is_none());
    }
}
