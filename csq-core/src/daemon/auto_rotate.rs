//! Background auto-rotation loop.
//!
//! Scans all `config-*` directories every 30 seconds and swaps the
//! active account whenever the current account's 5-hour quota exceeds
//! the configured threshold.
//!
//! # M5a scope
//!
//! - Reads `{base_dir}/rotation.json` on each tick (live config reload).
//! - Applies a per-config-dir cooldown so the same directory is not
//!   rotated more than once per `cooldown_secs`.
//! - Delegates account selection to `rotation::picker::pick_best`.
//! - Delegates the actual swap to `rotation::swap::swap_to`.
//! - Does NOT block swap for live CC processes — `swap_to` is atomic
//!   and CC reads the new `.credentials.json` on its next API call.
//!
//! # Cooldown map
//!
//! The cooldown is keyed on the *config-dir path* (not the account
//! number) so each terminal session has an independent cooldown.
//! This prevents one busy session from blocking rotation of other sessions.
//!
//! # Shutdown
//!
//! The loop respects the shared `CancellationToken` so it exits within
//! one tick interval after `shutdown.cancel()`.

use crate::accounts::markers;
use crate::quota::state as quota_state;
use crate::rotation::{config as rotation_config, pick_best, swap_to};
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
pub fn spawn(base_dir: PathBuf, shutdown: CancellationToken) -> AutoRotateHandle {
    spawn_with_config(base_dir, shutdown, TICK_INTERVAL, STARTUP_DELAY)
}

/// Like [`spawn`] but with explicit intervals for testing.
pub fn spawn_with_config(
    base_dir: PathBuf,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) -> AutoRotateHandle {
    let cooldowns: HashMap<PathBuf, Instant> = HashMap::new();

    let join = tokio::spawn(async move {
        run_loop(base_dir, shutdown, interval, startup_delay, cooldowns).await;
    });

    AutoRotateHandle { join }
}

async fn run_loop(
    base_dir: PathBuf,
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
        tick(&base_dir, &mut cooldowns);

        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("auto-rotation cancelled, exiting loop");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Runs a single auto-rotation tick.
///
/// Exposed `pub(crate)` for unit tests.
pub(crate) fn tick(base_dir: &Path, cooldowns: &mut HashMap<PathBuf, Instant>) {
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

    // Handle-dir model guard (journal 0064, P0-1). Under the handle-
    // dir model (spec 02, INV-01), config-<N>/.credentials.json is
    // permanent account-N credentials. Auto-rotation's legacy `swap_to`
    // path writes target account M's credentials INTO config-N, which
    // silently corrupts identity for every terminal whose handle dir
    // symlinks back through config-N. The structural fix is to rotate
    // `term-<pid>` handle-dir symlinks instead of config-N files; that
    // redesign ships in 2.0.1. For 2.0.0 we refuse-to-run when any
    // handle dir exists and leave a clear WARN so the user knows the
    // feature is deferred, rather than running and corrupting state.
    if handle_dirs_present(base_dir) {
        warn!(
            "auto-rotation: skipping tick — handle-dir mode detected \
             (term-*/ directories present). Auto-rotation in handle-dir \
             mode is deferred to csq 2.0.1 pending a handle-dir-native \
             rotator. See journal 0064."
        );
        return;
    }

    let cooldown_duration = Duration::from_secs(cfg.cooldown_secs);

    // Scan config-* directories under base_dir.
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
        let config_dir = entry.path();

        // Only consider config-* directories.
        let name = match config_dir.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("config-") {
            continue;
        }
        if !config_dir.is_dir() {
            continue;
        }

        // Read which account this config dir is currently using.
        let current_account = match markers::read_csq_account(&config_dir) {
            Some(a) => a,
            None => {
                debug!(dir = %config_dir.display(), "auto-rotation: no .csq-account marker, skipping");
                skipped += 1;
                continue;
            }
        };

        // Check per-config-dir cooldown.
        if let Some(&last_rotated) = cooldowns.get(&config_dir) {
            if last_rotated.elapsed() < cooldown_duration {
                debug!(
                    dir = %config_dir.display(),
                    remaining_secs = (cooldown_duration - last_rotated.elapsed()).as_secs(),
                    "auto-rotation: in cooldown, skipping"
                );
                skipped += 1;
                continue;
            }
        }

        // Check quota for current account.
        let quota_state = match quota_state::load_state(base_dir) {
            Ok(q) => q,
            Err(e) => {
                warn!(error = %e, "auto-rotation: failed to load quota state");
                skipped += 1;
                continue;
            }
        };

        let five_hour_pct = quota_state
            .get(current_account.get())
            .map(|q| q.five_hour_pct())
            .unwrap_or(0.0);

        if five_hour_pct < cfg.threshold_percent {
            debug!(
                dir = %config_dir.display(),
                account = current_account.get(),
                pct = five_hour_pct,
                threshold = cfg.threshold_percent,
                "auto-rotation: below threshold, skipping"
            );
            skipped += 1;
            continue;
        }

        // Account has exceeded the threshold — find a better account.
        // Build the effective exclude set: current account + user-specified exclusions.
        // pick_best already excludes the current account; we apply user exclusions
        // by calling pick_best and then filtering out excluded targets.
        let target = find_target(base_dir, current_account, &cfg.exclude_accounts);

        let target = match target {
            Some(t) => t,
            None => {
                debug!(
                    dir = %config_dir.display(),
                    account = current_account.get(),
                    "auto-rotation: no better account available, skipping"
                );
                skipped += 1;
                continue;
            }
        };

        // Perform the swap.
        match swap_to(base_dir, &config_dir, target) {
            Ok(result) => {
                info!(
                    dir = %config_dir.display(),
                    from = current_account.get(),
                    to = result.account.get(),
                    threshold = cfg.threshold_percent,
                    pct = five_hour_pct,
                    "auto-rotation: rotated account"
                );
                cooldowns.insert(config_dir.clone(), Instant::now());
                rotated += 1;
            }
            Err(e) => {
                warn!(
                    dir = %config_dir.display(),
                    account = current_account.get(),
                    error = %e,
                    "auto-rotation: swap failed"
                );
                skipped += 1;
            }
        }
    }

    if rotated > 0 || skipped > 0 {
        info!(rotated, skipped, "auto-rotation tick complete");
    } else {
        debug!("auto-rotation tick: no config dirs processed");
    }
}

/// Returns true when at least one `term-<pid>` handle directory exists
/// directly under `base_dir`. Presence of any handle dir is the signal
/// that the installation is using the handle-dir model (spec 02);
/// auto-rotation's legacy swap path is unsafe in that mode. Journal
/// 0064. A read-dir error returns false so a genuinely empty / missing
/// base_dir doesn't flip the feature on by accident.
fn handle_dirs_present(base_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with("term-") && entry.path().is_dir() {
            return true;
        }
    }
    false
}

/// Finds the best rotation target, respecting the user's exclusion list.
///
/// `pick_best` already excludes the current account; this function
/// additionally filters out any accounts in `exclude_accounts`. If the
/// first `pick_best` result is in the exclusion list, we iterate until
/// we find one that isn't — or return None if no eligible account exists.
fn find_target(
    base_dir: &Path,
    current: AccountNum,
    exclude_accounts: &[u16],
) -> Option<AccountNum> {
    if exclude_accounts.is_empty() {
        return pick_best(base_dir, Some(current));
    }

    // Build a combined exclusion set: current + user list.
    // We ask pick_best repeatedly, each time adding the rejected candidate
    // to a temporary exclude set, until we get an acceptable target or
    // run out of candidates.
    //
    // In practice, the number of accounts is small (≤7), so this loop
    // terminates very quickly.
    let extra_excludes: Vec<AccountNum> = exclude_accounts
        .iter()
        .filter_map(|&id| AccountNum::try_from(id).ok())
        .collect();

    // Temporarily combine current + extra_excludes into a single exclusion
    // by iterating candidates from quota state directly.
    // Since pick_best only accepts a single exclude, we use the quota state
    // to find the best account not in our combined exclusion set.
    use crate::accounts::discovery;
    use crate::quota::state as qs;

    let accounts = discovery::discover_anthropic(base_dir);
    let quota = qs::load_state(base_dir).ok()?;

    // Collect candidates: has credentials, not current, not excluded.
    let excluded_ids: std::collections::HashSet<u16> = extra_excludes
        .iter()
        .map(|a| a.get())
        .chain(std::iter::once(current.get()))
        .collect();

    let candidates: Vec<(AccountNum, f64, u64)> = accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .filter_map(|a| {
            let num = AccountNum::try_from(a.id).ok()?;
            if excluded_ids.contains(&num.get()) {
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
                    resets_at: 9999999999,
                }),
                seven_day: None,
                rate_limits: None,
                updated_at: 0.0,
            },
        );
        quota_state::save_state(base, &quota).unwrap();
    }

    fn setup_config_dir(base: &Path, dir_name: &str, account: u16) -> PathBuf {
        let config_dir = base.join(dir_name);
        std::fs::create_dir_all(&config_dir).unwrap();
        let target = AccountNum::try_from(account).unwrap();
        markers::write_csq_account(&config_dir, target).unwrap();
        config_dir
    }

    // ── tests ────────────────────────────────────────────────────────────

    #[test]
    fn tick_disabled_config_no_swaps() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 99.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        // Arrange: disabled rotation config
        let cfg = RotationConfig {
            enabled: false,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // Assert: account 1 is still active (no swap happened)
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_enabled_below_threshold_no_swap() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        // Account 1 at 50% — below the 95% default threshold
        setup_quota(dir.path(), 1, 50.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // No swap — still on account 1
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_enabled_above_threshold_swaps() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        // Account 1 at 97% — above threshold
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // Should have rotated to account 2
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(2u16).unwrap())
        );
        // Cooldown entry should be set for this config dir
        assert!(cooldowns.contains_key(&config_dir));
    }

    #[test]
    fn tick_respects_cooldown_on_second_call() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();

        // First tick: rotates
        tick(dir.path(), &mut cooldowns);
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(2u16).unwrap())
        );

        // Simulate account 2 also going over threshold — would want to rotate back
        setup_quota(dir.path(), 2, 98.0);
        setup_quota(dir.path(), 1, 10.0); // account 1 recovered
                                          // Put account marker back to simulate it was on account 2
        let target2 = AccountNum::try_from(2u16).unwrap();
        markers::write_csq_account(&config_dir, target2).unwrap();

        // Second tick: cooldown prevents rotation
        tick(dir.path(), &mut cooldowns);

        // Still on account 2 because cooldown is active
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(2u16).unwrap())
        );
    }

    #[test]
    fn tick_no_better_account_no_swap() {
        let dir = TempDir::new().unwrap();
        // Only one account — nothing to rotate to
        setup_account(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // No other account — should stay on account 1
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_respects_exclude_accounts() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_account(dir.path(), 3);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 20.0);
        setup_quota(dir.path(), 3, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        // Exclude account 2 — should rotate to 3 instead
        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            exclude_accounts: vec![2],
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // Should have rotated to account 3 (not 2, which was excluded)
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(3u16).unwrap())
        );
    }

    #[test]
    fn tick_missing_config_uses_defaults_disabled() {
        // When no rotation.json exists, defaults have enabled=false.
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 99.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // Default config has enabled=false — no rotation should happen
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
    }

    // ── handle-dir guard (journal 0064, P0-1) ────────────────────────────

    #[test]
    fn handle_dirs_present_detects_term_dir() {
        let dir = TempDir::new().unwrap();
        assert!(!handle_dirs_present(dir.path()));

        std::fs::create_dir_all(dir.path().join("term-12345")).unwrap();
        assert!(handle_dirs_present(dir.path()));
    }

    #[test]
    fn handle_dirs_present_ignores_config_dirs() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("config-1")).unwrap();
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        assert!(!handle_dirs_present(dir.path()));
    }

    #[test]
    fn handle_dirs_present_ignores_files_named_term() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("term-regular-file"), b"x").unwrap();
        assert!(!handle_dirs_present(dir.path()));
    }

    #[test]
    fn tick_enabled_with_handle_dir_refuses_to_swap() {
        // Journal 0064 regression: with rotation enabled AND a handle
        // dir present, tick MUST short-circuit rather than call
        // swap_to on config-N. Writing account M's credentials into
        // config-N violates INV-01 and corrupts identity for every
        // terminal symlinking to that config dir.
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0); // above threshold
        setup_quota(dir.path(), 2, 10.0);
        let config_dir = setup_config_dir(dir.path(), "config-1", 1);

        // Seed a handle dir to signal handle-dir mode.
        std::fs::create_dir_all(dir.path().join("term-9999")).unwrap();

        // Snapshot config-1/.credentials.json BEFORE tick. It was
        // written by setup_account via canonical_path — but only the
        // credentials/1.json canonical, not the live config-1 copy.
        // For this test we write a marker file ("account 1 lives
        // here") and verify it's untouched.
        let live_cred = config_dir.join(".credentials.json");
        std::fs::write(&live_cred, b"account-1-creds-sentinel").unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), &mut cooldowns);

        // Asserts: config-1/.credentials.json is UNCHANGED. Account-1
        // marker is UNCHANGED. No cooldown entry (tick short-circuited
        // before reaching cooldown tracking).
        let contents = std::fs::read(&live_cred).unwrap();
        assert_eq!(
            contents, b"account-1-creds-sentinel",
            "config-N/.credentials.json MUST NOT be rewritten under handle-dir mode"
        );
        assert_eq!(
            markers::read_csq_account(&config_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "config-N marker must remain account 1 — handle-dir guard failed"
        );
        assert!(
            cooldowns.is_empty(),
            "cooldowns must be empty — guard should short-circuit before tracking"
        );
    }
}
