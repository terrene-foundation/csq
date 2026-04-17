//! Account login helpers shared between csq-cli and csq-desktop.
//!
//! - [`find_claude_binary`] locates the `claude` CLI from BOTH the
//!   inherited `$PATH` and a fixed list of well-known install
//!   directories. The well-known list matters because Finder-launched
//!   macOS apps (the desktop bundle) inherit only a minimal `PATH`
//!   (`/usr/bin:/bin:/usr/sbin:/sbin`) — the user's shell-installed
//!   `claude` (typically in `/usr/local/bin`, `/opt/homebrew/bin`, or
//!   `~/.npm-global/bin`) is invisible to plain `Command::new("claude")`.
//!   The desktop's `start_claude_login` Tauri command was disabled in
//!   alpha.5 (per journal 0040 §2) precisely because of this PATH gap.
//!
//! - [`read_email_from_claude_json`] reads the OAuth account email
//!   that CC writes to `<config_dir>/.claude.json` after a successful
//!   `claude auth login`. Both `csq login N` and the desktop Add
//!   Account modal use this to populate the `profiles.json` entry.
//!
//! - [`finalize_login`] does the post-login bookkeeping shared by
//!   both code paths: writes the `.csq-account` marker, reads the
//!   email, updates `profiles.json`, clears the broker-failed flag.

use crate::accounts::{markers, profiles};
use crate::error::ConfigError;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

/// Returns the absolute path to the `claude` CLI binary, if
/// installed and executable.
///
/// Search order:
///  1. Walk `$PATH` (matches the legacy `which_claude` behaviour).
///  2. Walk a fixed list of well-known install directories that
///     survive a Finder launch (i.e. don't depend on the shell rc).
///  3. Walk `$HOME/<sub>` for common per-user install layouts
///     (`.local/bin`, `.npm-global/bin`, `.bun/bin`, `.cargo/bin`).
///
/// Returns `None` if no executable `claude` is found anywhere.
pub fn find_claude_binary() -> Option<PathBuf> {
    // 1. $PATH walk.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if let Some(p) = check_dir(&dir) {
                return Some(p);
            }
        }
    }

    // 2. System-wide well-known locations.
    for sys_dir in SYSTEM_WIDE_DIRS {
        if let Some(p) = check_dir(Path::new(sys_dir)) {
            return Some(p);
        }
    }

    // 3. Per-user well-known locations under $HOME.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in PER_USER_SUBDIRS {
            if let Some(p) = check_dir(&home.join(sub)) {
                return Some(p);
            }
        }
    }

    None
}

/// Reads the OAuth account email out of `<config_dir>/.claude.json`.
///
/// CC writes `oauthAccount.emailAddress` to its local `.claude.json`
/// during `claude auth login`. This is a file-only read with no
/// subprocess and no race window — it's the preferred source over
/// `claude auth status --json`, which has a documented timing
/// window where stdout can lack `email` if csq runs it too soon
/// after auth completes (see journal 0040 §1).
///
/// Returns `None` if the file is missing, malformed, or has no
/// non-empty `emailAddress` field. Callers should fall back to
/// `"unknown"` in that case rather than fail the whole login.
pub fn read_email_from_claude_json(config_dir: &Path) -> Option<String> {
    let path = config_dir.join(".claude.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let email = json
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(|v| v.as_str())?;
    if email.is_empty() {
        None
    } else {
        Some(email.to_string())
    }
}

/// Post-login bookkeeping shared by `csq login` and the desktop
/// Add Account flow.
///
/// 1. Writes the `.csq-account` marker for `account` inside its
///    `config-N/` directory (best-effort if the dir doesn't exist
///    yet — the canonical save in `credentials::save_canonical`
///    will create it).
/// 2. **Unbinds any third-party provider pinned to this slot.** If a
///    user ran `csq setkey mm --slot N` earlier (intentionally or by
///    accidentally submitting a junk key, journal 0058), slot N's
///    `settings.json` contains `ANTHROPIC_BASE_URL` +
///    `ANTHROPIC_AUTH_TOKEN` env vars that override OAuth
///    credentials at CC startup. Strip them here so the fresh OAuth
///    tokens actually route to Anthropic.
/// 3. Reads the OAuth email from `config-N/.claude.json` and
///    updates `profiles.json`. Falls back to `"unknown"` if the
///    email is missing — non-fatal because the credential file is
///    already written and CC can use the account.
/// 4. Clears the `broker_failed` sentinel for this account so the
///    daemon retries refresh on the next tick.
///
/// Errors are propagated only when the *bookkeeping* itself fails
/// (e.g. profiles.json save fails). The credential file is
/// authoritative — losing the profile entry is recoverable, losing
/// the credential file is not.
pub fn finalize_login(base_dir: &Path, account: AccountNum) -> Result<String, ConfigError> {
    let config_dir = base_dir.join(format!("config-{}", account));
    if config_dir.exists() {
        // Best-effort — save_canonical above already created the
        // dir, but the marker may not be there yet.
        let _ = markers::write_csq_account(&config_dir, account);
    }

    // Strip any pre-existing 3P binding. If this fails we let the
    // error propagate — we'd rather the user see "login cleanup
    // failed" than a silent-success followed by "my OAuth login
    // didn't take because the slot is still pinned to MiniMax".
    match crate::accounts::third_party::unbind_provider_from_slot(base_dir, account) {
        Ok(true) => {
            tracing::info!(
                account = account.get(),
                "finalize_login: stripped third-party provider binding"
            );
        }
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    let email = read_email_from_claude_json(&config_dir).unwrap_or_else(|| "unknown".to_string());

    let path = profiles::profiles_path(base_dir);
    let mut file = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
    file.set_profile(
        account.get(),
        profiles::AccountProfile {
            email: email.clone(),
            method: "oauth".to_string(),
            extra: std::collections::HashMap::new(),
        },
    );
    profiles::save(&path, &file)?;

    crate::broker::fanout::clear_broker_failed(base_dir, account);

    Ok(email)
}

/// System-wide install directories searched after `$PATH`.
///
/// Order is deliberate: Homebrew on Apple Silicon (`/opt/homebrew/bin`)
/// is checked before Intel Homebrew / manual installs (`/usr/local/bin`)
/// because Apple Silicon machines often have BOTH and the user wants
/// the modern one.
const SYSTEM_WIDE_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];

/// Per-user install subdirectories, joined to `$HOME`.
const PER_USER_SUBDIRS: &[&str] = &[
    ".local/bin",
    ".npm-global/bin",
    ".bun/bin",
    ".cargo/bin",
    ".volta/bin",
    "n/bin",
];

/// If `dir/claude` (or `dir/claude.exe` on Windows) is an executable
/// regular file, returns its path. Otherwise returns `None`.
fn check_dir(dir: &Path) -> Option<PathBuf> {
    let candidate = dir.join("claude");
    if is_executable_file(&candidate) {
        return Some(candidate);
    }
    #[cfg(windows)]
    {
        let exe = dir.join("claude.exe");
        if is_executable_file(&exe) {
            return Some(exe);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_dir_finds_executable_claude() {
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh\necho hi").unwrap();
        make_executable(&claude);

        let found = check_dir(dir.path()).expect("should find claude");
        assert_eq!(found, claude);
    }

    #[cfg(unix)]
    #[test]
    fn check_dir_skips_non_executable() {
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh\necho hi").unwrap();
        // Mode 0o644 — readable but not executable.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&claude).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&claude, perms).unwrap();

        assert!(check_dir(dir.path()).is_none());
    }

    #[test]
    fn check_dir_returns_none_for_missing_dir() {
        let missing = Path::new("/definitely/not/a/real/path/12345abcde");
        assert!(check_dir(missing).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn find_claude_binary_picks_up_path_entry() {
        // Override $PATH and $HOME to point at an isolated tempdir
        // so the assertion is hermetic regardless of what's installed
        // on the test machine.
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh").unwrap();
        make_executable(&claude);

        // SAFETY: tests in this crate run single-threaded by default
        // for env vars; this test does not enable threads.
        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("PATH", dir.path());
        // Point HOME at an empty dir so the per-user fallbacks miss.
        let empty_home = TempDir::new().unwrap();
        std::env::set_var("HOME", empty_home.path());

        let found = find_claude_binary();

        // Restore env before asserting so a panic doesn't poison
        // sibling tests.
        match prev_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(found, Some(claude));
    }
}
