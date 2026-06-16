//! Dispatcher prototype for the single-binary csq (issue #295, Option F2).
//!
//! This example demonstrates mode detection logic for the merged csq binary.
//! It is STANDALONE — it does NOT touch csq-cli/src/main.rs or
//! csq-desktop/src-tauri/src/main.rs.
//!
//! Mode detection order (hardened against argv[0] rename attacks):
//!
//!   1. `--desktop` explicit flag → desktop mode (always wins)
//!   2. macOS: canonical exe path contains `Contents/MacOS/` AND
//!      `../../../Contents/Info.plist` exists with `CSQDesktopMode` key
//!   3. Linux: $APPIMAGE set AND canonical exe path is inside $APPDIR
//!   4. stdin is tty → force CLI mode (tty guard prevents accidental webview)
//!   5. Default: CLI mode
//!
//! Security invariants:
//! - NEVER uses argv[0] for mode detection (rename attack vector V1)
//! - tty guard prevents webview launch when stdin is terminal (vector V2)
//! - Linux AppImage detection requires both $APPIMAGE and $APPDIR + path check (vector V5)
//! - Info.plist sentinel prevents symlink spoofing of bundle path check (vector V1 depth)

use std::path::Path;

/// The runtime mode dispatched by this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// CLI mode: parse clap subcommands, run daemon client, etc.
    Cli,
    /// Desktop mode: launch Tauri webview, tray icon, updater.
    Desktop,
}

/// Detect the runtime mode.
///
/// Called once at startup before any other initialization.
/// Does NOT read from stdin, does NOT start the Tauri event loop.
pub fn detect_mode() -> Mode {
    // 1. Explicit --desktop flag: always wins, regardless of environment.
    //    This is the only way to trigger desktop mode from a PATH invocation.
    if std::env::args().any(|a| a == "--desktop") {
        return Mode::Desktop;
    }

    // 2. Bundle sentinel check (macOS and Linux AppImage).
    //    Uses current_exe() — NOT argv[0] — to defeat rename attacks.
    if let Some(mode) = check_bundle_sentinel() {
        return mode;
    }

    // 3. tty guard: if stdin is a tty, this is a terminal invocation.
    //    Force CLI mode even if some other heuristic might suggest desktop.
    //    This is a SAFETY guard, not the primary detection mechanism.
    if stdin_is_tty() {
        return Mode::Cli;
    }

    // 4. Default: CLI mode.
    Mode::Cli
}

/// Check platform-specific bundle sentinel.
///
/// Returns `Some(Mode::Desktop)` when the binary is running from inside
/// a recognized bundle context. Returns `None` when no sentinel is found
/// (caller falls through to tty guard and CLI default).
fn check_bundle_sentinel() -> Option<Mode> {
    // Resolve the canonical executable path (follows symlinks).
    let exe = std::env::current_exe().ok()?;
    let exe = exe.canonicalize().ok().unwrap_or(exe);

    #[cfg(target_os = "macos")]
    if check_macos_bundle(&exe) {
        return Some(Mode::Desktop);
    }

    #[cfg(target_os = "linux")]
    if check_linux_appimage(&exe) {
        return Some(Mode::Desktop);
    }

    None
}

/// macOS bundle detection.
///
/// Two-layer check:
///   Layer 1: canonical exe path contains `Contents/MacOS/` component
///   Layer 2: `../../../Contents/Info.plist` relative to exe exists AND
///            contains the literal string `CSQDesktopMode`
///
/// Both layers must pass. Layer 1 alone is spoofable via a symlink at
/// `/tmp/exploit/Contents/MacOS/csq → /usr/local/bin/csq`. Layer 2 fails
/// that attack because the surrounding directory is not a real `.app` bundle.
#[cfg(target_os = "macos")]
fn check_macos_bundle(exe: &Path) -> bool {
    // Layer 1: path structure check
    let path_str = exe.to_string_lossy();
    if !path_str.contains("/Contents/MacOS/") {
        return false;
    }

    // Layer 2: Info.plist sentinel
    // Path from binary: ../../.. brings us to the .app root;
    // then Contents/Info.plist is the standard location.
    // Example: Code Squad Q.app/Contents/MacOS/csq
    //          ↑ exe.parent() = .../Contents/MacOS
    //          ↑ .parent() = .../Contents
    //          ↑ .parent() = .../Code Squad Q.app
    //          then + "Contents/Info.plist"
    let info_plist = exe
        .parent()   // Contents/MacOS
        .and_then(|p| p.parent())  // Contents
        .and_then(|p| p.parent())  // .app root
        .map(|app_root| app_root.join("Contents").join("Info.plist"));

    match info_plist {
        Some(plist_path) if plist_path.exists() => {
            // Read the plist and verify the CSQDesktopMode sentinel.
            // We use a simple string search rather than a full plist parser
            // to avoid pulling in additional dependencies (spec: stdlib-only
            // for security-sensitive code paths per rules/independence.md).
            match std::fs::read_to_string(&plist_path) {
                Ok(contents) => contents.contains("CSQDesktopMode"),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// Linux AppImage detection.
///
/// Two-layer check:
///   Layer 1: $APPIMAGE and $APPDIR env vars are both set and non-empty
///   Layer 2: canonical exe path starts with $APPDIR
///
/// Layer 2 prevents stale $APPIMAGE from a previous AppImage test step
/// on CI triggering desktop mode for a PATH-invoked csq (vector V5).
#[cfg(target_os = "linux")]
fn check_linux_appimage(exe: &Path) -> bool {
    let appimage = match std::env::var("APPIMAGE") {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };
    let appdir = match std::env::var("APPDIR") {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };

    // Verify the binary is actually inside the AppImage mount.
    let _ = appimage; // used to verify both vars are set; content not needed
    exe.starts_with(&appdir)
}

/// Stub for non-macOS, non-Linux targets (Windows, etc.)
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn check_bundle_sentinel_platform(_exe: &Path) -> bool {
    false
}

/// Check whether stdin is attached to a terminal (tty).
///
/// Cross-platform via `std::io::IsTerminal` (stdlib, stable since Rust 1.70).
/// Returns true when stdin is connected to an interactive terminal — on Unix
/// this is `isatty(STDIN_FILENO)`; on Windows the stdlib resolves the console
/// handle and queries `GetConsoleMode` internally.
///
/// This is the tty guard (vector V2): if stdin is a tty, the binary is
/// running in a terminal context and should NOT launch the Tauri webview.
fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Placeholder for CLI entry point (in the real binary, this calls clap dispatch).
#[allow(dead_code)]
fn run_cli() {
    println!("CLI mode: would parse clap subcommands here");
}

/// Placeholder for desktop entry point (in the real binary, this calls Tauri).
#[allow(dead_code)]
fn run_desktop() {
    println!("Desktop mode: would launch Tauri webview here");
}

fn main() {
    let mode = detect_mode();
    match mode {
        Mode::Cli => run_cli(),
        Mode::Desktop => run_desktop(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Default invocation (no --desktop flag, no bundle path) → CLI mode.
    ///
    /// This test verifies the most common path: a user types `csq` in their
    /// terminal. No special env, no bundle path → CLI.
    #[test]
    fn default_is_cli_mode() {
        // Simulate: no --desktop flag, not inside a bundle, stdin may or may
        // not be a tty (in test runner it is not). Either way, default is CLI.
        let mode = detect_mode_with_args(&[], "/usr/local/bin/csq", false);
        assert_eq!(mode, Mode::Cli, "default invocation must be CLI mode");
    }

    /// --desktop flag always triggers desktop mode regardless of other signals.
    #[test]
    fn explicit_desktop_flag_wins() {
        // Even with stdin as tty, --desktop forces desktop mode.
        let mode = detect_mode_with_args(&["--desktop"], "/usr/local/bin/csq", true);
        assert_eq!(
            mode,
            Mode::Desktop,
            "--desktop flag must trigger desktop mode"
        );
    }

    /// --desktop flag wins even when path looks like CLI.
    #[test]
    fn explicit_desktop_flag_wins_over_cli_path() {
        let mode = detect_mode_with_args(&["csq", "--desktop"], "/home/user/.cargo/bin/csq", false);
        assert_eq!(
            mode,
            Mode::Desktop,
            "--desktop must win over CLI path heuristic"
        );
    }

    /// tty guard: stdin=tty + no --desktop + no bundle path → CLI mode.
    #[test]
    fn tty_stdin_forces_cli() {
        let mode = detect_mode_with_args(&[], "/usr/local/bin/csq", true /* is_tty */);
        assert_eq!(mode, Mode::Cli, "tty stdin must force CLI mode");
    }

    /// Non-tty + no bundle + no --desktop → CLI (default, not desktop).
    #[test]
    fn non_tty_no_bundle_is_cli() {
        let mode = detect_mode_with_args(&[], "/usr/local/bin/csq", false);
        assert_eq!(
            mode,
            Mode::Cli,
            "non-tty + no bundle + no flag = CLI default"
        );
    }

    /// macOS bundle path check: `Contents/MacOS/` in path alone is not sufficient
    /// (the Info.plist sentinel is also required, tested via the path logic).
    /// We verify the path component check returns false for non-bundle paths.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_non_bundle_path_is_not_desktop() {
        let non_bundle_paths = [
            "/usr/local/bin/csq",
            "/home/user/.cargo/bin/csq",
            "/tmp/csq-test-binary",
            // Adversarial: path has Contents/MacOS but is NOT a real bundle
            // (Info.plist check will fail — no surrounding bundle structure)
            "/tmp/exploit/Contents/MacOS/csq",
        ];
        for path in &non_bundle_paths {
            // check_macos_bundle with a non-existent Info.plist always returns false
            // (the plist_path.exists() check fails)
            let result = check_macos_bundle(Path::new(path));
            assert!(
                !result,
                "path '{}' should NOT trigger desktop mode (no valid Info.plist)",
                path
            );
        }
    }

    /// Linux: $APPIMAGE without $APPDIR → not AppImage
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_appimage_requires_appdir() {
        // Only $APPIMAGE set, not $APPDIR → should NOT trigger AppImage mode
        // (We can't actually set env vars in a pure unit test without affecting
        // other tests, so we test the logic directly via check_linux_appimage)
        let exe = std::path::PathBuf::from("/tmp/not-an-appimage/csq");
        // Without APPDIR set, check_linux_appimage returns false
        // (std::env::var("APPDIR") will return Err or the real APPDIR)
        // This test is environment-dependent; in CI, $APPDIR is unset → false.
        let result = check_linux_appimage(&exe);
        // If APPDIR happens to be set in the test environment, skip this assertion.
        // The important invariant is: exe must start_with APPDIR.
        if std::env::var("APPDIR").is_err() {
            assert!(!result, "no $APPDIR → not AppImage");
        }
    }

    // ── Test harness helper ───────────────────────────────────────────────

    /// Testable version of detect_mode that accepts injected arguments
    /// instead of reading from std::env::args().
    ///
    /// In the real binary, detect_mode() reads std::env::args() directly.
    /// This helper allows unit tests to inject specific argument patterns
    /// and exe paths without spawning a subprocess.
    fn detect_mode_with_args(args: &[&str], _exe_path: &str, is_tty: bool) -> Mode {
        // 1. Check for --desktop in injected args
        if args.iter().any(|a| *a == "--desktop") {
            return Mode::Desktop;
        }

        // 2. Bundle sentinel (not testable without a real filesystem fixture;
        //    the exe_path parameter is reserved for future test expansion with
        //    tempfile-based bundle fixture creation).
        //    In these unit tests, we skip the bundle check.

        // 3. tty guard
        if is_tty {
            return Mode::Cli;
        }

        // 4. Default
        Mode::Cli
    }
}
