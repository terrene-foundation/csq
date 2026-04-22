//! Background auto-rotation loop — handle-dir-native (PR-A1, v2.0.1).
//!
//! Scans all `accounts/term-<pid>` handle dirs every 30 seconds and
//! repoints the active account whenever the current account's 5-hour
//! quota exceeds the configured threshold.
//!
//! # PR-A1 structural fix (journal 0064, Option A)
//!
//! v2.0.0 shipped `swap_to(base_dir, config_dir, target)` which writes
//! target account M's `.credentials.json` INTO `config-N/`. Under the
//! handle-dir model (spec 02, INV-01), `config-<N>/.credentials.json`
//! is PERMANENT account-N credentials — overwriting it corrupts identity
//! for every terminal whose `term-<pid>/` symlinks back through that
//! config-N. PR-A1 replaces that guard (which refused to run when any
//! `term-*/` exists) with the structural fix: walk `term-<pid>/` handle
//! dirs and call `handle_dir::repoint_handle_dir`, which atomically
//! repoints symlinks WITHOUT touching `config-<N>/`.
//!
//! # Cooldown map
//!
//! The cooldown is keyed on the *handle-dir path* (not the account
//! number and not the config dir) so each terminal session has an
//! independent cooldown. This prevents one busy session from blocking
//! rotation of other sessions.
//!
//! # claude_home requirement
//!
//! `repoint_handle_dir` must re-materialize `settings.json` after the
//! repoint (it deep-merges `~/.claude/settings.json` with the new
//! slot's overlay). If `claude_home` cannot be resolved at spawn time,
//! the rotator logs a WARN and becomes a no-op — fail-safe is "don't
//! rotate" rather than "rotate with an empty settings base".
//!
//! # Shutdown
//!
//! The loop respects the shared `CancellationToken` so it exits within
//! one tick interval after `shutdown.cancel()`.

use crate::accounts::markers;
use crate::quota::state as quota_state;
use crate::rotation::config as rotation_config;
use crate::session::handle_dir::repoint_handle_dir;
use crate::types::AccountNum;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Tick interval: 30 seconds.
pub const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Startup delay: 15 seconds. Lets the usage poller run its first tick
/// and populate `quota.json` before we attempt any rotation decision.
pub const STARTUP_DELAY: Duration = Duration::from_secs(15);

/// Handle to a running auto-rotation task.
pub struct AutoRotateHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns the auto-rotation background task on the current tokio runtime.
///
/// `claude_home` is `Option<PathBuf>` so callers that cannot resolve
/// `~/.claude` (rare sandbox / missing $HOME) can pass `None`. The
/// rotator logs a single WARN at spawn time and becomes a no-op for
/// every tick — fail-safe is "don't rotate" rather than "rotate with
/// an empty base settings file that would overwrite user customization".
pub fn spawn(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
) -> AutoRotateHandle {
    spawn_with_config(
        base_dir,
        claude_home,
        shutdown,
        TICK_INTERVAL,
        STARTUP_DELAY,
    )
}

/// Like [`spawn`] but with explicit intervals for testing.
pub fn spawn_with_config(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) -> AutoRotateHandle {
    if claude_home.is_none() {
        warn!(
            "auto-rotation: claude_home is None — rotator will be a no-op. \
             Cannot repoint handle dirs without a known ~/.claude path \
             (materialize_handle_settings requires it). Check that $HOME is set."
        );
    }

    let cooldowns: HashMap<PathBuf, Instant> = HashMap::new();

    let join = tokio::spawn(async move {
        run_loop(
            base_dir,
            claude_home,
            shutdown,
            interval,
            startup_delay,
            cooldowns,
        )
        .await;
    });

    AutoRotateHandle { join }
}

async fn run_loop(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
    mut cooldowns: HashMap<PathBuf, Instant>,
) {
    info!(
        interval_secs = interval.as_secs(),
        startup_delay_secs = startup_delay.as_secs(),
        "auto-rotation loop starting"
    );

    tokio::select! {
        _ = shutdown.cancelled() => {
            info!("auto-rotation cancelled during startup delay");
            return;
        }
        _ = tokio::time::sleep(startup_delay) => {}
    }

    loop {
        tick(&base_dir, claude_home.as_deref(), &mut cooldowns);

        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("auto-rotation cancelled, exiting loop");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Same-surface filter for auto-rotation candidates.
///
/// v2.0.1: trivially accepts every candidate because all existing
/// providers are Surface::ClaudeCode. Codex PR-C1 (v2.1) replaces this
/// with a real Surface enum check per spec 07 INV-P11. Keeping this as
/// a named function (rather than inline) makes the flip a one-line
/// change without restructuring the rotator.
const fn same_surface_as_active(_candidate: AccountNum) -> bool {
    // TODO(PR-C1): replace with Surface enum dispatch per spec 07 INV-P11
    true
}

/// Runs a single auto-rotation tick.
///
/// Exposed `pub` for both unit tests and integration tests.
///
/// When `claude_home` is `None`, returns immediately (no-op). This is the
/// fail-safe path for environments where $HOME is unavailable — the rotator
/// cannot safely repoint without knowing where `~/.claude/settings.json` lives.
pub fn tick(
    base_dir: &Path,
    claude_home: Option<&Path>,
    cooldowns: &mut HashMap<PathBuf, Instant>,
) {
    // Fail-safe: without claude_home we cannot re-materialize settings.json
    // after repoint. Do not rotate.
    let claude_home = match claude_home {
        Some(p) => p,
        None => {
            debug!("auto-rotation: claude_home is None, skipping tick (no-op)");
            return;
        }
    };

    // Load config fresh on every tick so changes to rotation.json
    // take effect within one tick interval without restarting the daemon.
    let cfg = match rotation_config::load(base_dir) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "auto-rotation: failed to load rotation config, skipping tick");
            return;
        }
    };

    if !cfg.enabled {
        debug!("auto-rotation disabled, skipping tick");
        return;
    }

    let cooldown_duration = Duration::from_secs(cfg.cooldown_secs);

    // Scan term-* handle dirs under base_dir (PR-A1: walk handle dirs,
    // not config-* dirs). Each term-<pid>/ is a running terminal session;
    // we repoint its symlinks, never touching config-N/.
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "auto-rotation: failed to read base_dir");
            return;
        }
    };

    let mut rotated = 0usize;
    let mut skipped = 0usize;

    for entry in entries.flatten() {
        let handle_dir = entry.path();

        // Only consider term-* directories (handle dirs).
        let name = match handle_dir.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("term-") {
            continue;
        }
        if !handle_dir.is_dir() {
            continue;
        }

        // Read which account this handle dir is currently bound to.
        // The symlink `term-<pid>/.csq-account` → `config-<current>/.csq-account`
        // resolves to the current account's canonical marker.
        let current_account = match markers::read_csq_account(&handle_dir) {
            Some(a) => a,
            None => {
                debug!(dir = %handle_dir.display(), "auto-rotation: no .csq-account marker in handle dir, skipping");
                skipped += 1;
                continue;
            }
        };

        // Check per-handle-dir cooldown (keyed on handle_dir path, not account).
        if let Some(&last_rotated) = cooldowns.get(&handle_dir) {
            if last_rotated.elapsed() < cooldown_duration {
                debug!(
                    dir = %handle_dir.display(),
                    remaining_secs = (cooldown_duration - last_rotated.elapsed()).as_secs(),
                    "auto-rotation: in cooldown, skipping"
                );
                skipped += 1;
                continue;
            }
        }

        // Check quota for current account.
        let quota = match quota_state::load_state(base_dir) {
            Ok(q) => q,
            Err(e) => {
                warn!(error = %e, "auto-rotation: failed to load quota state");
                skipped += 1;
                continue;
            }
        };

        let five_hour_pct = quota
            .get(current_account.get())
            .map(|q| q.five_hour_pct())
            .unwrap_or(0.0);

        if five_hour_pct < cfg.threshold_percent {
            debug!(
                dir = %handle_dir.display(),
                account = current_account.get(),
                pct = five_hour_pct,
                threshold = cfg.threshold_percent,
                "auto-rotation: below threshold, skipping"
            );
            skipped += 1;
            continue;
        }

        // Account has exceeded the threshold — find a better account.
        let target = find_target(base_dir, current_account, &cfg.exclude_accounts);

        let target = match target {
            Some(t) => t,
            None => {
                debug!(
                    dir = %handle_dir.display(),
                    account = current_account.get(),
                    "auto-rotation: no better account available, skipping"
                );
                skipped += 1;
                continue;
            }
        };

        // PR-A1 structural fix: repoint the handle dir's symlinks to the
        // target account. This atomically updates `.credentials.json`,
        // `.csq-account`, `.claude.json`, and `.quota-cursor` symlinks
        // and re-materializes `settings.json`. config-N/.credentials.json
        // is NEVER written (INV-01 preserved).
        match repoint_handle_dir(base_dir, claude_home, &handle_dir, target) {
            Ok(()) => {
                info!(
                    dir = %handle_dir.display(),
                    from = current_account.get(),
                    to = target.get(),
                    threshold = cfg.threshold_percent,
                    pct = five_hour_pct,
                    "auto-rotation: repointed handle dir to new account"
                );
                cooldowns.insert(handle_dir.clone(), Instant::now());
                rotated += 1;
            }
            Err(e) => {
                warn!(
                    dir = %handle_dir.display(),
                    account = current_account.get(),
                    error = %e,
                    "auto-rotation: repoint failed"
                );
                skipped += 1;
            }
        }
    }

    if rotated > 0 || skipped > 0 {
        info!(rotated, skipped, "auto-rotation tick complete");
    } else {
        debug!("auto-rotation tick: no handle dirs processed");
    }
}

/// Finds the best rotation target, respecting the user's exclusion list
/// and the same-surface filter.
///
/// Additionally filters out any accounts in `exclude_accounts`. If the
/// first candidate is in the exclusion list, we iterate until we find
/// one that isn't — or return None if no eligible account exists.
fn find_target(
    base_dir: &Path,
    current: AccountNum,
    exclude_accounts: &[u16],
) -> Option<AccountNum> {
    use crate::accounts::discovery;
    use crate::quota::state as qs;

    let accounts = discovery::discover_anthropic(base_dir);
    let quota = qs::load_state(base_dir).ok()?;

    // Build a combined exclusion set: current + user list.
    let extra_excludes: Vec<AccountNum> = exclude_accounts
        .iter()
        .filter_map(|&id| AccountNum::try_from(id).ok())
        .collect();

    let excluded_ids: std::collections::HashSet<u16> = extra_excludes
        .iter()
        .map(|a| a.get())
        .chain(std::iter::once(current.get()))
        .collect();

    // Collect candidates: has credentials, not current, not excluded,
    // passes the same-surface filter (stub: always true pre-PR-C1).
    let candidates: Vec<(AccountNum, f64, u64)> = accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .filter_map(|a| {
            let num = AccountNum::try_from(a.id).ok()?;
            if excluded_ids.contains(&num.get()) {
                return None;
            }
            // Surface filter: PR-C1 will replace this with a real check.
            if !same_surface_as_active(num) {
                return None;
            }
            let pct = quota
                .get(num.get())
                .map(|q| q.five_hour_pct())
                .unwrap_or(0.0);
            let resets_at = quota
                .get(num.get())
                .and_then(|q| q.five_hour.as_ref().map(|w| w.resets_at))
                .unwrap_or(u64::MAX);
            Some((num, pct, resets_at))
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Prefer non-exhausted accounts (pct < 100), pick lowest usage.
    let non_exhausted: Vec<_> = candidates
        .iter()
        .filter(|(_, pct, _)| *pct < 100.0)
        .collect();

    if !non_exhausted.is_empty() {
        return non_exhausted
            .iter()
            .min_by(|(_, a, _), (_, b, _)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(num, _, _)| *num);
    }

    // All exhausted — pick earliest reset.
    candidates
        .iter()
        .min_by_key(|(_, _, resets)| *resets)
        .map(|(num, _, _)| *num)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::markers;
    use crate::credentials::{self, file as cred_file, CredentialFile, OAuthPayload};
    use crate::quota::{state as quota_state, AccountQuota, QuotaFile, UsageWindow};
    use crate::rotation::config::{save as save_rotation_config, RotationConfig};
    use crate::session::handle_dir::create_handle_dir;
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    // ── helpers ──────────────────────────────────────────────────────────

    fn make_creds(access: &str, refresh: &str) -> CredentialFile {
        CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        }
    }

    fn setup_account(base: &Path, account: u16) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = make_creds(&format!("at-{account}"), &format!("rt-{account}"));
        credentials::save(&cred_file::canonical_path(base, target), &creds).unwrap();
    }

    fn setup_quota(base: &Path, account: u16, five_hour_pct: f64) {
        let mut quota = quota_state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: five_hour_pct,
                    // Far-future reset so clear_expired doesn't drop these
                    // during the load cycle. Year 2100 = 4102444800 seconds.
                    resets_at: 4_102_444_800,
                }),
                ..Default::default()
            },
        );
        quota_state::save_state(base, &quota).unwrap();
    }

    /// Creates `config-<account>/` with a .csq-account marker.
    fn setup_config_dir(base: &Path, account: u16) -> PathBuf {
        let config_dir = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        let target = AccountNum::try_from(account).unwrap();
        markers::write_csq_account(&config_dir, target).unwrap();
        config_dir
    }

    /// Creates a `term-<pid>/` handle dir with symlinks pointing at
    /// `config-<account>/`. Uses `create_handle_dir` so the structure
    /// matches production exactly. The `claude_home` is a fresh temp dir
    /// so shared-items symlinks don't escape into `~/.claude`.
    fn setup_handle_dir(base: &Path, claude_home: &Path, pid: u32, account: u16) -> PathBuf {
        let account_num = AccountNum::try_from(account).unwrap();
        create_handle_dir(base, claude_home, account_num, pid).unwrap()
    }

    // ── adapted existing tests ────────────────────────────────────────────

    #[test]
    fn tick_disabled_config_no_swaps() {
        // Arrange: two accounts, account 1 over threshold, rotation DISABLED
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 99.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10001, 1);

        let cfg = RotationConfig {
            enabled: false,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir still bound to account 1 (no repoint happened)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_enabled_below_threshold_no_swap() {
        // Arrange: account 1 at 50% — below the 95% default threshold
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 50.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10002, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: no repoint, still on account 1
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_missing_config_uses_defaults_disabled() {
        // When no rotation.json exists, defaults have enabled=false.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 99.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10003, 1);

        // Act: no rotation.json written — defaults have enabled=false
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: default config has enabled=false — no rotation
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
    }

    // ── handle-dir-native repoint tests (PR-A1) ──────────────────────────

    #[test]
    fn tick_enabled_above_threshold_repoints_handle_dir() {
        // Arrange: account 1 at 97% — above threshold
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10004, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir's .csq-account symlink now resolves to account 2
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle dir should be repointed to account 2"
        );
        // Cooldown entry keyed on handle_dir path
        assert!(
            cooldowns.contains_key(&handle_dir),
            "cooldown entry should be set for the handle dir"
        );
    }

    #[test]
    fn tick_respects_cooldown_per_handle_dir() {
        // Arrange: account 1 at 97%, cooldown active after first tick
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10005, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();

        // First tick: rotates to account 2
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "first tick should repoint to account 2"
        );

        // Simulate account 2 also going over threshold
        setup_quota(dir.path(), 2, 98.0);
        setup_quota(dir.path(), 1, 10.0); // account 1 recovered
                                          // Manually repoint back to account 2 to simulate post-first-tick state
        let acc2 = AccountNum::try_from(2u16).unwrap();
        markers::write_csq_account(&handle_dir.join(".csq-account"), acc2).ok();

        // Second tick: cooldown prevents rotation (keyed on handle_dir)
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Still on account 2 because cooldown is active for this handle dir
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle dir should stay on account 2 during cooldown"
        );
    }

    #[test]
    fn tick_no_better_account_no_swap() {
        // Only one account — nothing to rotate to
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);
        setup_config_dir(dir.path(), 1);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10006, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // No other account — should stay on account 1, no cooldown entry
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_respects_exclude_accounts() {
        // Account 2 excluded — should rotate to 3 instead
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_account(dir.path(), 3);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 20.0);
        setup_quota(dir.path(), 3, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        setup_config_dir(dir.path(), 3);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10007, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            exclude_accounts: vec![2],
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Should have repointed to account 3 (not 2, which was excluded)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(3u16).unwrap())
        );
    }

    // ── PR-A1 invariant tests ─────────────────────────────────────────────

    #[test]
    fn auto_rotate_walks_handle_dirs_not_config_dirs() {
        // Arrange: config-1 has a sentinel credential file. A handle dir
        // (term-10008) is on account 1 over threshold. After tick, the
        // sentinel in config-1/.credentials.json MUST be unchanged
        // (INV-01), while the handle dir's .csq-account resolves to account 2.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir_1 = setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10008, 1);

        // Write a sentinel into config-1/.credentials.json that we can
        // verify is untouched after the tick.
        let live_cred = config_dir_1.join(".credentials.json");
        std::fs::write(&live_cred, b"account-1-creds-sentinel").unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert 1: config-1/.credentials.json is UNCHANGED (INV-01)
        let contents = std::fs::read(&live_cred).unwrap();
        assert_eq!(
            contents, b"account-1-creds-sentinel",
            "config-N/.credentials.json MUST NOT be rewritten by the rotator (INV-01)"
        );

        // Assert 2: handle dir's .csq-account symlink now resolves to account 2
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle dir should be repointed to account 2"
        );
    }

    #[test]
    fn auto_rotate_preserves_config_n_when_repointing() {
        // Arrange: config-1 and config-2 have distinct credential bytes.
        // Handle dir on account 1, account 1 over threshold.
        // After tick, BOTH config dirs' credential files must be byte-identical
        // to their pre-tick content.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir_1 = setup_config_dir(dir.path(), 1);
        let config_dir_2 = setup_config_dir(dir.path(), 2);
        let _handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10009, 1);

        let cred_path_1 = config_dir_1.join(".credentials.json");
        let cred_path_2 = config_dir_2.join(".credentials.json");
        std::fs::write(&cred_path_1, b"creds-account-1-distinct").unwrap();
        std::fs::write(&cred_path_2, b"creds-account-2-distinct").unwrap();

        let pre_creds_1 = std::fs::read(&cred_path_1).unwrap();
        let pre_creds_2 = std::fs::read(&cred_path_2).unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: both config dirs' credential files are byte-identical pre/post
        let post_creds_1 = std::fs::read(&cred_path_1).unwrap();
        let post_creds_2 = std::fs::read(&cred_path_2).unwrap();
        assert_eq!(
            pre_creds_1, post_creds_1,
            "config-1/.credentials.json MUST NOT be modified by the rotator"
        );
        assert_eq!(
            pre_creds_2, post_creds_2,
            "config-2/.credentials.json MUST NOT be modified by the rotator"
        );
    }

    #[test]
    fn same_surface_stub_always_true_pre_c1() {
        // Regression guard: same_surface_as_active must return true for any
        // account number until Codex PR-C1 flips it to a real Surface enum
        // check. If this test fails, it means PR-C1 landed without this test
        // being updated — verify the Surface filter is correct before removing.
        let acc = AccountNum::try_from(5u16).unwrap();
        assert!(
            same_surface_as_active(acc),
            "same_surface_as_active should return true for all accounts pre-PR-C1"
        );
        let acc1 = AccountNum::try_from(1u16).unwrap();
        assert!(same_surface_as_active(acc1));
        let acc7 = AccountNum::try_from(7u16).unwrap();
        assert!(same_surface_as_active(acc7));
    }

    #[test]
    fn tick_noop_when_claude_home_none() {
        // Arrange: handle dir on account 1, account 1 over threshold,
        // but claude_home is None.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10010, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act: pass None for claude_home
        let mut cooldowns = HashMap::new();
        tick(dir.path(), None, &mut cooldowns);

        // Assert: handle dir is unchanged (tick is a no-op when claude_home is None)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "tick with claude_home=None must be a no-op"
        );
        assert!(
            cooldowns.is_empty(),
            "no cooldown entries should be set when tick is a no-op"
        );
    }

    #[test]
    fn tick_cooldown_keyed_on_handle_dir_not_account() {
        // Two handle dirs both pointing at account 1. Account 1 over threshold.
        // Both should get their own independent cooldown map entries keyed on
        // their own path — not on the account number.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir_a = setup_handle_dir(dir.path(), claude_home.path(), 10011, 1);
        let handle_dir_b = setup_handle_dir(dir.path(), claude_home.path(), 10012, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: both handle dirs were repointed (both had account 1 over threshold)
        assert_eq!(
            markers::read_csq_account(&handle_dir_a),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle_dir_a should be repointed to account 2"
        );
        assert_eq!(
            markers::read_csq_account(&handle_dir_b),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle_dir_b should be repointed to account 2"
        );

        // Assert: cooldown map has TWO entries, each keyed on a distinct handle dir path
        assert_eq!(
            cooldowns.len(),
            2,
            "cooldown map must have one entry per handle dir, not per account"
        );
        assert!(
            cooldowns.contains_key(&handle_dir_a),
            "cooldown keyed on handle_dir_a path"
        );
        assert!(
            cooldowns.contains_key(&handle_dir_b),
            "cooldown keyed on handle_dir_b path"
        );
        // Verify the two keys are different paths (not the same account key)
        assert_ne!(
            handle_dir_a, handle_dir_b,
            "two distinct handle dirs must have distinct cooldown keys"
        );
    }
}
