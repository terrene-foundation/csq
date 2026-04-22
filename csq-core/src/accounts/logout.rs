//! Account logout / removal.
//!
//! Removes every trace of an account from the csq base directory:
//! the canonical credential file, the permanent `config-N` directory
//! (with its live credentials and markers), and the `profiles.json`
//! entry. Refuses if a live `claude` process is still bound to the
//! account through any handle dir.
//!
//! See `specs/02-csq-handle-dir-model.md` INV-01 — `config-N` is
//! permanent for the lifetime of an account. Logout ends that
//! lifetime, so removing the directory is correct (and required so
//! the slot becomes available again to the desktop Add Account flow).

use crate::accounts::{markers, profiles};
use crate::credentials::file::{canonical_path, live_path};
use crate::platform::process::is_pid_alive;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

/// Summary of what was removed during a successful logout.
#[derive(Debug, Clone)]
pub struct LogoutSummary {
    pub account: AccountNum,
    pub canonical_removed: bool,
    pub config_dir_removed: bool,
    pub profiles_entry_removed: bool,
    pub quota_entry_removed: bool,
}

/// Failure modes for [`logout_account`].
#[derive(Debug)]
pub enum LogoutError {
    /// The account is currently bound to one or more live `claude`
    /// processes via handle dirs. The user must exit those terminals
    /// before logging out — refusing to delete state from under a
    /// running process is the safest default.
    InUse { account: AccountNum, pids: Vec<u32> },
    /// No credential file or config dir exists for this account.
    /// Logout is a no-op against an empty slot.
    NotConfigured { account: AccountNum },
    /// A filesystem operation failed mid-removal.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Loading or saving `profiles.json` failed.
    Profiles(crate::error::ConfigError),
}

impl std::fmt::Display for LogoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogoutError::InUse { account, pids } => write!(
                f,
                "account {} is in use by live claude process(es): {:?} — exit those terminals first",
                account, pids
            ),
            LogoutError::NotConfigured { account } => {
                write!(f, "account {} is not configured", account)
            }
            LogoutError::Io { path, source } => {
                write!(f, "filesystem error at {}: {}", path.display(), source)
            }
            LogoutError::Profiles(e) => write!(f, "profiles.json error: {}", e),
        }
    }
}

impl std::error::Error for LogoutError {}

/// Removes account `account` from the csq base directory.
///
/// Steps (in order):
///  1. Verify the account is actually configured. Returns `NotConfigured`
///     if neither the canonical credential file nor the live config
///     dir exists.
///  2. Scan `term-*` handle dirs for any live process whose
///     `.csq-account` symlink resolves to `account`. If any exist,
///     return `InUse` listing the PIDs.
///  3. Delete `credentials/N.json` (best-effort if absent).
///  4. Delete `config-N/` recursively (best-effort if absent).
///  5. Remove the `account` entry from `profiles.json` (if present).
///
/// Daemon cache invalidation is the caller's responsibility — this
/// helper only touches on-disk state so tests do not need a daemon.
pub fn logout_account(base_dir: &Path, account: AccountNum) -> Result<LogoutSummary, LogoutError> {
    let canonical = canonical_path(base_dir, account);
    let live = live_path(base_dir, account);
    let config_dir = live
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| base_dir.join(format!("config-{}", account)));

    if !canonical.exists() && !config_dir.exists() {
        return Err(LogoutError::NotConfigured { account });
    }

    let bound_pids = scan_live_handle_dirs_for_account(base_dir, account);
    if !bound_pids.is_empty() {
        return Err(LogoutError::InUse {
            account,
            pids: bound_pids,
        });
    }

    let canonical_removed = match std::fs::remove_file(&canonical) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(LogoutError::Io {
                path: canonical,
                source: e,
            })
        }
    };

    let config_dir_removed = match std::fs::remove_dir_all(&config_dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(LogoutError::Io {
                path: config_dir,
                source: e,
            })
        }
    };

    let profiles_entry_removed = remove_profiles_entry(base_dir, account)?;
    let quota_entry_removed = remove_quota_entry(base_dir, account);

    Ok(LogoutSummary {
        account,
        canonical_removed,
        config_dir_removed,
        profiles_entry_removed,
        quota_entry_removed,
    })
}

/// Removes the `account` entry from `quota.json` so a recycled slot
/// can't display the previous tenant's usage. Best-effort — failures
/// are logged but don't fail the logout, since the credential file
/// is already gone and the daemon will just write fresh data on the
/// next poll cycle.
fn remove_quota_entry(base_dir: &Path, account: AccountNum) -> bool {
    use crate::quota::state as quota_state;

    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = match crate::platform::lock::lock_file(&lock_path) {
        Ok(g) => g,
        Err(_) => return false,
    };

    let mut quota = match quota_state::load_state(base_dir) {
        Ok(q) => q,
        Err(_) => return false,
    };

    let key = account.get().to_string();
    if quota.accounts.remove(&key).is_none() {
        return false;
    }

    quota_state::save_state(base_dir, &quota).is_ok()
}

/// Returns the PIDs of any live `claude` processes whose handle dir
/// is currently bound to `account` via the `.csq-account` symlink.
///
/// Scans `base_dir/term-*` for symlinked markers; resolves each
/// `.csq-account` and checks both the marker value and the
/// `.live-pid` sentinel for liveness. Dead PIDs are ignored — those
/// handle dirs are stale and the next sweep tick will collect them.
fn scan_live_handle_dirs_for_account(base_dir: &Path, account: AccountNum) -> Vec<u32> {
    let mut bound = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return bound,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("term-") {
            continue;
        }
        // Read the account marker through the handle dir's symlink.
        let bound_account = match markers::read_csq_account(&path) {
            Some(a) => a,
            None => continue,
        };
        if bound_account != account {
            continue;
        }
        let pid = markers::read_live_pid(&path)
            .or_else(|| name.strip_prefix("term-").and_then(|s| s.parse().ok()));
        let Some(pid) = pid else { continue };
        if is_pid_alive(pid) {
            bound.push(pid);
        }
    }

    bound
}

/// Removes the `account` entry from `profiles.json`. Returns true if
/// an entry was actually removed, false if the file or entry was
/// absent.
fn remove_profiles_entry(base_dir: &Path, account: AccountNum) -> Result<bool, LogoutError> {
    let path = profiles::profiles_path(base_dir);
    if !path.exists() {
        return Ok(false);
    }
    let mut file = profiles::load(&path).map_err(LogoutError::Profiles)?;
    let key = account.get().to_string();
    if file.accounts.remove(&key).is_none() {
        return Ok(false);
    }
    profiles::save(&path, &file).map_err(LogoutError::Profiles)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::profiles::{AccountProfile, ProfilesFile};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    fn account(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn provision_account(base: &Path, n: u16) {
        let canonical_dir = base.join("credentials");
        fs::create_dir_all(&canonical_dir).unwrap();
        fs::write(canonical_dir.join(format!("{n}.json")), "{}").unwrap();

        let config_dir = base.join(format!("config-{n}"));
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join(".credentials.json"), "{}").unwrap();
        fs::write(config_dir.join(".csq-account"), n.to_string()).unwrap();
        fs::write(config_dir.join("settings.json"), "{}").unwrap();
    }

    fn write_profiles(base: &Path, accounts: &[(u16, &str)]) {
        let mut file = ProfilesFile::empty();
        for (n, email) in accounts {
            file.set_profile(
                *n,
                AccountProfile {
                    email: email.to_string(),
                    method: "oauth".into(),
                    extra: HashMap::new(),
                },
            );
        }
        profiles::save(&profiles::profiles_path(base), &file).unwrap();
    }

    fn write_quota_for(base: &Path, n: u16, pct_7d: f64) {
        use crate::quota::state as quota_state;
        use crate::quota::{AccountQuota, QuotaFile, UsageWindow};
        let mut q = quota_state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());
        q.set(
            n,
            AccountQuota {
                // resets_at deliberately in the year 2100 so
                // clear_expired() doesn't null the window mid-test.
                seven_day: Some(UsageWindow {
                    used_percentage: pct_7d,
                    resets_at: 4_102_444_800,
                }),
                ..Default::default()
            },
        );
        quota_state::save_state(base, &q).unwrap();
    }

    #[test]
    fn logout_removes_canonical_and_config_dir() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 3);

        let summary = logout_account(dir.path(), account(3)).unwrap();

        assert!(summary.canonical_removed);
        assert!(summary.config_dir_removed);
        assert!(!dir.path().join("credentials/3.json").exists());
        assert!(!dir.path().join("config-3").exists());
    }

    #[test]
    fn logout_removes_profiles_entry() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 5);
        write_profiles(dir.path(), &[(5, "alice@example.com")]);

        let summary = logout_account(dir.path(), account(5)).unwrap();
        assert!(summary.profiles_entry_removed);

        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(!reloaded.accounts.contains_key("5"));
    }

    #[test]
    fn logout_returns_not_configured_when_account_missing() {
        let dir = TempDir::new().unwrap();
        match logout_account(dir.path(), account(7)) {
            Err(LogoutError::NotConfigured { account: a }) => assert_eq!(a, account(7)),
            other => panic!("expected NotConfigured, got {other:?}"),
        }
    }

    #[test]
    fn logout_preserves_other_accounts() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        provision_account(dir.path(), 2);
        provision_account(dir.path(), 3);
        write_profiles(
            dir.path(),
            &[
                (1, "a@example.com"),
                (2, "b@example.com"),
                (3, "c@example.com"),
            ],
        );

        logout_account(dir.path(), account(2)).unwrap();

        assert!(dir.path().join("credentials/1.json").exists());
        assert!(dir.path().join("credentials/3.json").exists());
        assert!(dir.path().join("config-1").exists());
        assert!(dir.path().join("config-3").exists());
        assert!(!dir.path().join("credentials/2.json").exists());
        assert!(!dir.path().join("config-2").exists());

        let reloaded = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert!(reloaded.accounts.contains_key("1"));
        assert!(reloaded.accounts.contains_key("3"));
        assert!(!reloaded.accounts.contains_key("2"));
    }

    #[test]
    fn logout_refuses_when_handle_dir_alive() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 4);

        // Create a handle dir bound to account 4 with our own PID
        // (which is, by definition, alive).
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        // .csq-account symlink → ../config-4/.csq-account
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-4").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-4").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        match logout_account(dir.path(), account(4)) {
            Err(LogoutError::InUse { account: a, pids }) => {
                assert_eq!(a, account(4));
                assert!(pids.contains(&my_pid), "expected my PID in {pids:?}");
            }
            other => panic!("expected InUse, got {other:?}"),
        }

        // State must be intact after a refused logout.
        assert!(dir.path().join("credentials/4.json").exists());
        assert!(dir.path().join("config-4").exists());
    }

    #[test]
    fn logout_allows_when_handle_dir_dead() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 6);

        // Pick a PID above `/proc/sys/kernel/pid_max` (4_194_304 on Linux
        // default, 99999 on macOS) so it is never in use, but below
        // `i32::MAX` so it is not reinterpreted as -1 ("every process")
        // by kill(2). The earlier version spawned `true` and used the
        // reaped child's PID — this was flaky because Linux can reuse
        // a reaped PID within microseconds on a busy CI runner, at
        // which point `is_pid_alive` returned true and the test
        // panicked. The constant below bypasses the reuse race entirely.
        let dead_pid: u32 = 2_000_000_000;

        let handle = dir.path().join(format!("term-{dead_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-6").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-6").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), dead_pid.to_string()).unwrap();

        // Should succeed because the bound process is dead.
        let summary = logout_account(dir.path(), account(6)).unwrap();
        assert!(summary.config_dir_removed);
    }

    #[test]
    fn logout_ignores_unrelated_handle_dirs() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 8);
        provision_account(dir.path(), 9);

        // Handle dir bound to account 9 with our (live) PID — should
        // NOT block logout of account 8.
        let my_pid = std::process::id();
        let handle = dir.path().join(format!("term-{my_pid}"));
        fs::create_dir_all(&handle).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("config-9").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("config-9").join(".csq-account"),
            handle.join(".csq-account"),
        )
        .unwrap();
        fs::write(handle.join(".live-pid"), my_pid.to_string()).unwrap();

        logout_account(dir.path(), account(8)).unwrap();
        assert!(!dir.path().join("config-8").exists());
        assert!(dir.path().join("config-9").exists());
    }

    #[test]
    fn logout_removes_quota_entry() {
        use crate::quota::state as quota_state;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 11);
        write_quota_for(dir.path(), 11, 87.5);

        let summary = logout_account(dir.path(), account(11)).unwrap();
        assert!(summary.quota_entry_removed);

        let q = quota_state::load_state(dir.path()).unwrap();
        assert!(
            q.get(11).is_none(),
            "quota entry must be cleared after logout — otherwise a recycled slot inherits the previous tenant's stale percentage"
        );
    }

    #[test]
    fn logout_quota_cleanup_does_not_touch_other_accounts() {
        use crate::quota::state as quota_state;

        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 12);
        provision_account(dir.path(), 13);
        write_quota_for(dir.path(), 12, 50.0);
        write_quota_for(dir.path(), 13, 75.0);

        logout_account(dir.path(), account(12)).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        assert!(q.get(12).is_none());
        let still = q.get(13).expect("account 13's quota must survive");
        assert_eq!(still.seven_day_pct(), 75.0);
    }

    #[test]
    fn logout_quota_cleanup_silent_when_no_entry() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 14);
        // No quota.json written for account 14 at all.

        let summary = logout_account(dir.path(), account(14)).unwrap();
        assert!(!summary.quota_entry_removed);
    }

    #[test]
    fn logout_no_profiles_file_is_fine() {
        let dir = TempDir::new().unwrap();
        provision_account(dir.path(), 1);
        // Note: no profiles.json written.

        let summary = logout_account(dir.path(), account(1)).unwrap();
        assert!(!summary.profiles_entry_removed);
    }
}
