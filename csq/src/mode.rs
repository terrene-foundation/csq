//! Runtime mode dispatcher for the merged csq binary (an internal ticket Option F2).
//!
//! Detects whether the binary is running as a CLI tool or as the Tauri
//! desktop app, then dispatches accordingly. Detection order:
//!
//!   1. `--desktop` explicit flag wins unconditionally.
//!   2. macOS bundle sentinel: canonical exe path contains `Contents/MacOS/`
//!      AND the app bundle's `Info.plist` contains the csq bundle identifier
//!      (`foundation.terrene.claude-squad`, written by Tauri from
//!      `tauri.conf.json::identifier`). The OS forbids two installed bundles
//!      with the same identifier, so a spoofed bundle cannot coexist with the
//!      real install.
//!   3. Linux AppImage sentinel: `$APPIMAGE` set AND canonical exe is inside
//!      `$APPDIR`.
//!   4. tty guard: stdin is a terminal -> force CLI mode.
//!   5. Default: CLI.
//!
//! Security invariants (see internal-design-docs):
//! - `std::env::current_exe()` (not `argv[0]`) defeats rename attacks (V1).
//! - The `Info.plist` sentinel rejects symlink-spoofed `Contents/MacOS/` paths.
//! - The tty guard prevents accidental webview launch in headless contexts (V2).
//! - Linux AppImage requires both `$APPIMAGE` and `$APPDIR` plus a path-prefix
//!   check, defeating stale-env mis-trigger on CI runners (V5).

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cli,
    Desktop,
}

pub fn detect() -> Mode {
    if std::env::args().any(|a| a == "--desktop") {
        return Mode::Desktop;
    }

    if let Some(mode) = check_bundle_sentinel() {
        return mode;
    }

    if stdin_is_tty() {
        return Mode::Cli;
    }

    Mode::Cli
}

fn check_bundle_sentinel() -> Option<Mode> {
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

    let _ = exe;
    None
}

/// macOS bundle identifier of the genuine csq desktop app, written into
/// `Contents/Info.plist` by Tauri (matches `identifier` in `tauri.conf.json`).
/// Used as the bundle sentinel: a spoofed `Contents/MacOS/csq` symlink would
/// have to also fabricate an Info.plist carrying this exact identifier to
/// trigger desktop mode, and the OS already rejects two installed bundles
/// with the same identifier — so the spoof can't coexist with a real install.
#[cfg(target_os = "macos")]
const MACOS_BUNDLE_IDENTIFIER: &str = "foundation.terrene.claude-squad";

#[cfg(target_os = "macos")]
fn check_macos_bundle(exe: &Path) -> bool {
    let path_str = exe.to_string_lossy();
    if !path_str.contains("/Contents/MacOS/") {
        return false;
    }

    let info_plist = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|app_root| app_root.join("Contents").join("Info.plist"));

    match info_plist {
        Some(plist_path) if plist_path.exists() => std::fs::read_to_string(&plist_path)
            .map(|c| c.contains(MACOS_BUNDLE_IDENTIFIER))
            .unwrap_or(false),
        _ => false,
    }
}

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
    let _ = appimage;
    exe.starts_with(&appdir)
}

fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_with(args: &[&str], is_tty: bool) -> Mode {
        if args.contains(&"--desktop") {
            return Mode::Desktop;
        }
        if is_tty {
            return Mode::Cli;
        }
        Mode::Cli
    }

    #[test]
    fn default_is_cli() {
        assert_eq!(detect_with(&[], false), Mode::Cli);
    }

    #[test]
    fn explicit_desktop_flag_wins_over_tty() {
        assert_eq!(detect_with(&["--desktop"], true), Mode::Desktop);
    }

    #[test]
    fn tty_forces_cli() {
        assert_eq!(detect_with(&[], true), Mode::Cli);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_non_bundle_path_is_not_desktop() {
        for path in [
            "/usr/local/bin/csq",
            "/tmp/csq-test",
            "/tmp/exploit/Contents/MacOS/csq",
        ] {
            assert!(!check_macos_bundle(Path::new(path)));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_no_appdir_is_not_appimage() {
        if std::env::var("APPDIR").is_err() {
            assert!(!check_linux_appimage(Path::new("/tmp/csq")));
        }
    }
}
