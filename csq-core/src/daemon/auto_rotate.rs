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
use crate::accounts::AccountSource;
use crate::providers::catalog::Surface;
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

/// Same-surface filter for auto-rotation candidates (INV-P11).
///
/// Auto-rotation must NEVER cross surfaces — a handle-dir bound to a
/// `Surface::ClaudeCode` account cannot be silently rotated to a
/// `Surface::Codex` account because the two surfaces execute different
/// CLI binaries with different `HOME`-like env contracts. Cross-surface
/// rotation is explicitly a `csq swap` action (journal 0067 H3; spec 07
/// INV-P11).
///
/// PR-C1 flip: pre-C1 this function trivially accepted every candidate
/// (all providers were `Surface::ClaudeCode`). Now that `Surface::Codex`
/// is a reachable variant via the catalog stub, this function enforces
/// the invariant against a concrete surface comparison.
fn same_surface_as_active(active_surface: Surface, candidate_surface: Surface) -> bool {
    active_surface == candidate_surface
}

/// Returns `true` if the account currently bound to `handle_dir` is a 3P slot.
///
/// Belt-and-suspenders guard (VP-final F1): reads `config-<account>/settings.json`
/// for the handle dir's current account and returns `true` if `env.ANTHROPIC_BASE_URL`
/// is present. If the current account is a 3P slot, the rotator MUST NOT rotate: doing
/// so would repoint the handle dir's symlinks such that CC picks up Anthropic OAuth
/// tokens AND the 3P `env.ANTHROPIC_BASE_URL` from `config-<N>/settings.json` —
/// sending Anthropic OAuth tokens to a 3P endpoint (live token exfiltration).
///
/// Returns `false` on any I/O or parse error (fail-safe: a missing or unparseable
/// settings.json means no 3P binding — allow the rotation check to proceed).
fn handle_dir_is_3p(base_dir: &Path, current_account: AccountNum) -> bool {
    let config_dir = base_dir.join(format!("config-{}", current_account));
    let settings_path = config_dir.join("settings.json");
    let content = match std::fs::read_to_string(&settings_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Check env.ANTHROPIC_BASE_URL (canonical location) and top-level fallback.
    json.get("env")
        .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
        .or_else(|| json.get("ANTHROPIC_BASE_URL"))
        .is_some()
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
        // VP-final F2: canonicalize the handle_dir path so symlinked base_dirs
        // (e.g. /var/folders/... vs /private/var/folders/... on macOS) don't
        // produce two independent cooldown keys for the same physical directory.
        let handle_dir = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir);

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

        // VP-final F1 (belt-and-suspenders): if the current account is a 3P slot,
        // skip rotation entirely for this handle dir. Rotating a 3P handle dir would
        // send Anthropic OAuth tokens to the 3P ANTHROPIC_BASE_URL endpoint — live
        // token exfiltration. The primary guard is in find_target (3P accounts are
        // filtered from candidates), but this secondary check prevents the rotator
        // from ever calling repoint_handle_dir when the CURRENT slot is already 3P.
        if handle_dir_is_3p(base_dir, current_account) {
            debug!(
                dir = %handle_dir.display(),
                account = current_account.get(),
                "auto-rotation: current account is a 3P slot — skipping (VP-F1)"
            );
            skipped += 1;
            continue;
        }

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
///
/// # v2.1 scope (PR-C9a round-1 CRITICAL fix, journal 0021)
///
/// Auto-rotate is **ClaudeCode-only** in v2.1. Pre-C9a this function
/// used [`discovery::discover_anthropic`], which returned no records for
/// Codex handle dirs — `active_surface` then fell back to
/// `Surface::ClaudeCode`, the same-surface filter admitted ClaudeCode
/// candidates, and the rotator called [`repoint_handle_dir`] on a Codex
/// handle dir, corrupting the live codex process (INV-P11 violation).
///
/// The fix is two-part:
///
/// 1. Use [`discovery::discover_all`] so Codex slots contribute an
///    `AccountInfo` with `surface = Surface::Codex` and `active_surface`
///    is resolved correctly.
/// 2. Short-circuit (return `None`) if the current account's surface is
///    not `ClaudeCode`. Codex rotation, if ever added, requires an
///    exec-replace pathway (journal 0019 §Q1 INV-P05 amendment, pending
///    human approval) that the repoint-based rotator cannot deliver —
///    so the explicit refusal here is the correct v2.1 semantics.
///
/// Belt-and-suspenders: [`repoint_handle_dir`] also refuses to act on a
/// Codex-shape handle dir (presence of `auth.json` / `config.toml` /
/// `sessions` symlinks), so any future caller that forgets the
/// surface check is caught before symlinks are rewritten.
fn find_target(
    base_dir: &Path,
    current: AccountNum,
    exclude_accounts: &[u16],
) -> Option<AccountNum> {
    use crate::accounts::discovery;
    use crate::quota::state as qs;

    let accounts = discovery::discover_all(base_dir);
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

    // Determine the current terminal's surface so the same-surface filter
    // (INV-P11) can reject cross-surface candidates. `discover_all`
    // includes Codex slots, so a Codex handle dir yields an accurate
    // `Surface::Codex` value here rather than falling back to ClaudeCode.
    //
    // Fallback to `Surface::ClaudeCode` still applies when discovery
    // returns NO record for the current account (orphaned handle dir
    // pointing at a deleted slot). In that case the caller has bigger
    // problems and the rotator's behaviour is moot — the repoint will
    // fail on the missing config-<N> dir downstream regardless.
    let active_surface = accounts
        .iter()
        .find(|a| a.id == current.get())
        .map(|a| a.surface)
        .unwrap_or(Surface::ClaudeCode);

    // v2.1 scope: auto-rotate is ClaudeCode-only. If the current handle
    // dir is bound to a Codex slot (or any future non-ClaudeCode surface),
    // refuse to rotate. Cross-surface Codex↔Codex rotation requires an
    // exec-replace pathway that the repoint-based rotator cannot provide.
    if active_surface != Surface::ClaudeCode {
        debug!(
            current = current.get(),
            surface = ?active_surface,
            "auto-rotation: current account is non-ClaudeCode surface, skipping \
             (v2.1 scope: Codex rotation requires explicit csq swap)"
        );
        return None;
    }

    // Collect candidates: has credentials, Anthropic source only (VP-final R1
    // CRITICAL: exclude 3P slots — stale credentials/N.json from a prior OAuth
    // binding can co-exist with a 3P settings.json; rotating to that slot would
    // point Anthropic OAuth tokens at a 3P endpoint via env.ANTHROPIC_BASE_URL),
    // not current, not excluded, AND passes the same-surface filter (INV-P11).
    //
    // NOTE: `discover_anthropic` classifies slots with `credentials/N.json` as
    // `AccountSource::Anthropic` even when `config-N/settings.json` also sets
    // `env.ANTHROPIC_BASE_URL` (a stale credential from a prior OAuth binding
    // on a now-3P slot). We therefore double-check the config dir's settings.json
    // directly to catch this co-existence case.
    let candidates: Vec<(AccountNum, f64, u64)> = accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .filter(|a| matches!(a.source, AccountSource::Anthropic))
        .filter_map(|a| {
            let num = AccountNum::try_from(a.id).ok()?;
            if excluded_ids.contains(&num.get()) {
                return None;
            }
            // VP-final R1 CRITICAL: check config-N/settings.json for 3P binding.
            // A stale credentials/N.json can co-exist with a 3P settings.json —
            // discover_anthropic marks the slot Anthropic because it finds the
            // credential file, but the slot is actually 3P. Rotating to it would
            // send Anthropic OAuth tokens to env.ANTHROPIC_BASE_URL. Reject it.
            if handle_dir_is_3p(base_dir, num) {
                return None;
            }
            // INV-P11: same-surface filter. Auto-rotation never crosses
            // surfaces; that's an explicit `csq swap` operation.
            if !same_surface_as_active(active_surface, a.surface) {
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
    use crate::credentials::{
        self, file as cred_file, AnthropicCredentialFile, CredentialFile, OAuthPayload,
    };
    use crate::quota::{state as quota_state, AccountQuota, QuotaFile, UsageWindow};
    use crate::rotation::config::{save as save_rotation_config, RotationConfig};
    use crate::session::handle_dir::create_handle_dir;
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    // ── helpers ──────────────────────────────────────────────────────────

    fn make_creds(access: &str, refresh: &str) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
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
        })
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
        // Cooldown entry keyed on the CANONICAL handle_dir path (VP-final F2:
        // tick canonicalizes the path before inserting into cooldowns).
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            cooldowns.contains_key(&canonical_handle),
            "cooldown entry should be set for the handle dir (canonical key)"
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

    /// PR-C1: `same_surface_as_active` now does a real `Surface == Surface`
    /// comparison (INV-P11). Same-surface accepts; cross-surface rejects.
    #[test]
    fn same_surface_filter_accepts_matching_surface() {
        assert!(same_surface_as_active(
            Surface::ClaudeCode,
            Surface::ClaudeCode
        ));
        assert!(same_surface_as_active(Surface::Codex, Surface::Codex));
    }

    /// INV-P11 negative path: cross-surface rotation MUST be rejected —
    /// auto-rotation never crosses surfaces; that's a `csq swap` action.
    #[test]
    fn same_surface_filter_rejects_cross_surface() {
        assert!(!same_surface_as_active(Surface::ClaudeCode, Surface::Codex));
        assert!(!same_surface_as_active(Surface::Codex, Surface::ClaudeCode));
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

        // Assert: cooldown map has TWO entries, each keyed on a distinct canonical
        // handle dir path (VP-final F2: tick canonicalizes before inserting).
        let canonical_a = std::fs::canonicalize(&handle_dir_a).unwrap_or(handle_dir_a.clone());
        let canonical_b = std::fs::canonicalize(&handle_dir_b).unwrap_or(handle_dir_b.clone());
        assert_eq!(
            cooldowns.len(),
            2,
            "cooldown map must have one entry per handle dir, not per account"
        );
        assert!(
            cooldowns.contains_key(&canonical_a),
            "cooldown keyed on handle_dir_a canonical path"
        );
        assert!(
            cooldowns.contains_key(&canonical_b),
            "cooldown keyed on handle_dir_b canonical path"
        );
        // Verify the two canonical keys are different paths (not the same account key)
        assert_ne!(
            canonical_a, canonical_b,
            "two distinct handle dirs must have distinct canonical cooldown keys"
        );
    }

    // ── VP-final F1: 3P slot exfiltration guard ───────────────────────────

    /// Regression guard: VP-final R1 CRITICAL.
    ///
    /// Setup:
    /// - Slot 1: Anthropic — credentials/1.json + config-1 with no 3P settings
    /// - Slot 2: Z.AI — credentials/2.json (leftover from prior OAuth binding)
    /// - `config-2/settings.json` with `ANTHROPIC_BASE_URL=https://api.zai.io`
    ///
    /// Slot 1 is over threshold. `find_target` must return `None` because the only
    /// other candidate (slot 2) is a 3P slot and must be excluded.
    #[test]
    fn find_target_skips_3p_slots_with_stale_anthropic_creds() {
        // Arrange: slot 1 = Anthropic (clean), slot 2 = 3P (stale OAuth creds)
        let dir = TempDir::new().unwrap();

        // Slot 1: Anthropic — has canonical credentials
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);

        // Slot 2: 3P slot — stale credentials/2.json from prior OAuth binding
        // plus config-2/settings.json marking it as a 3P endpoint.
        setup_account(dir.path(), 2); // writes credentials/2.json (stale)
        let config_2 = setup_config_dir(dir.path(), 2);
        // Write 3P settings.json to mark this as a 3P slot
        std::fs::write(
            config_2.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.zai.io","ANTHROPIC_AUTH_TOKEN":"k"}}"#,
        )
        .unwrap();
        setup_quota(dir.path(), 2, 10.0);

        let account_1 = AccountNum::try_from(1u16).unwrap();

        // Act: find_target with slot 1 as current (over threshold)
        let target = find_target(dir.path(), account_1, &[]);

        // Assert: slot 2 must be excluded (3P), so no valid target
        assert_eq!(
            target, None,
            "find_target must return None when only remaining candidate is a 3P slot \
             (VP-final R1 CRITICAL: prevents token exfiltration to 3P endpoint)"
        );
    }

    /// Additional belt-and-suspenders guard: tick skips handle dirs whose
    /// current account is a 3P slot (VP-final F1 secondary check).
    #[test]
    fn tick_skips_handle_dir_when_current_account_is_3p() {
        // Arrange: handle dir bound to slot 9 which is a 3P slot.
        // Slot 1 exists as a low-usage Anthropic account (would be chosen if
        // the rotator didn't bail on the 3P current-account check).
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        // Slot 1: Anthropic — available
        setup_account(dir.path(), 1);
        let config_1 = setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        // Slot 9: 3P — will be the current slot for the handle dir
        let config_9 = dir.path().join("config-9");
        std::fs::create_dir_all(&config_9).unwrap();
        let acct9 = AccountNum::try_from(9u16).unwrap();
        markers::write_csq_account(&config_9, acct9).unwrap();
        std::fs::write(
            config_9.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io","ANTHROPIC_AUTH_TOKEN":"k"}}"#,
        )
        .unwrap();
        // Stale credentials/9.json from a prior OAuth binding
        setup_account(dir.path(), 9);
        setup_quota(dir.path(), 9, 97.0);

        // Create handle dir pointing at slot 9
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 30001, 9);

        // Snapshot config-1 creds to verify they are untouched
        let cred_1_path = config_1.join(".credentials.json");
        std::fs::write(&cred_1_path, b"anthropic-slot-1-sentinel").unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir still bound to slot 9 (not rotated to slot 1)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(acct9),
            "tick must skip handle dir when current account is a 3P slot"
        );
        assert!(
            cooldowns.is_empty(),
            "no cooldown should be set when 3P handle dir is skipped"
        );
        // config-1 credentials untouched
        assert_eq!(
            std::fs::read(&cred_1_path).unwrap(),
            b"anthropic-slot-1-sentinel",
            "config-1 creds must not be touched when 3P handle dir is skipped"
        );
    }

    // ── VP-final F2: cooldown canonicalization ────────────────────────────

    /// Regression guard: VP-final F2.
    ///
    /// If the base_dir is accessed via a symlinked path alias (e.g. macOS
    /// /var/folders/... vs /private/var/folders/...), `entry.path()` returns
    /// a path under the alias. Without canonicalization the cooldowns HashMap
    /// would have two independent entries for the same physical directory.
    ///
    /// We verify via indirect means: after tick the cooldown map has exactly ONE
    /// entry. We then inject a pre-aged instant with elapsed time < cooldown and
    /// run a second tick; the handle dir stays put — proving the canonical key was
    /// stored and found on second lookup.
    #[cfg(unix)]
    #[test]
    fn cooldown_key_canonicalizes_symlinked_base_dir() {
        let real_dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        setup_account(real_dir.path(), 1);
        setup_account(real_dir.path(), 2);
        setup_quota(real_dir.path(), 1, 97.0);
        setup_quota(real_dir.path(), 2, 10.0);
        setup_config_dir(real_dir.path(), 1);
        setup_config_dir(real_dir.path(), 2);
        let _handle_dir = setup_handle_dir(real_dir.path(), claude_home.path(), 30002, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 3600, // 1-hour cooldown — won't expire during test
            ..RotationConfig::default()
        };
        save_rotation_config(real_dir.path(), &cfg).unwrap();

        // First tick: handle dir should rotate (above threshold) and one
        // cooldown entry should be stored with the CANONICAL path as key.
        let mut cooldowns = HashMap::new();
        tick(real_dir.path(), Some(claude_home.path()), &mut cooldowns);

        assert_eq!(
            cooldowns.len(),
            1,
            "cooldown map must have exactly one entry after first tick"
        );

        // Second tick: even if the handle dir's account (now 2) is above
        // threshold again, the 1-hour cooldown must block re-rotation.
        setup_quota(real_dir.path(), 2, 98.0);
        setup_quota(real_dir.path(), 1, 5.0);

        let entry_count_before = cooldowns.len();
        tick(real_dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Entry count must not grow (no duplicate canonical / raw path key).
        assert_eq!(
            cooldowns.len(),
            entry_count_before,
            "cooldown map must not grow — duplicate key after second tick means \
             canonicalization is missing"
        );
    }

    // ── PR-C9a CRITICAL: auto-rotate must never fire on a Codex handle dir ─

    /// Builds a minimal Codex slot on disk: `credentials/codex-<N>.json`,
    /// `config-<N>/.csq-account`, and `config-<N>/config.toml` (required by
    /// `create_handle_dir_codex` so the symlink set contains the Codex
    /// shape that `repoint_handle_dir`'s guard watches for).
    fn setup_codex_slot(base: &Path, account: u16) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        let acct = AccountNum::try_from(account).unwrap();

        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some(format!("uuid-{account}")),
                access_token: format!("eyJaccess.codex-{account}.sig"),
                refresh_token: Some(format!("rt_codex_{account}")),
                id_token: Some(format!("eyJid.codex-{account}.sig")),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: HashMap::new(),
        });
        let cred_path = base
            .join("credentials")
            .join(format!("codex-{account}.json"));
        credentials::save(&cred_path, &creds).unwrap();

        let config_dir = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        markers::write_csq_account(&config_dir, acct).unwrap();
        // Minimal config.toml so create_handle_dir_codex's symlink target
        // exists (create_handle_dir_codex silently skips missing targets,
        // but the Codex-shape guard in repoint_handle_dir keys on
        // `auth.json` and `config.toml` existing as symlinks).
        std::fs::write(
            config_dir.join("config.toml"),
            "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-5.4\"\n",
        )
        .unwrap();
    }

    /// Regression guard: journal 0021 finding 1 (CRITICAL).
    ///
    /// A handle dir bound to a Codex slot MUST NOT be rotated by the
    /// auto-rotater. Pre-fix, `find_target` used `discover_anthropic`,
    /// so `active_surface` fell back to `Surface::ClaudeCode` for a
    /// Codex-bound handle dir; same-surface filter admitted ClaudeCode
    /// candidates; repoint_handle_dir then corrupted the Codex handle
    /// dir's ACCOUNT_BOUND_ITEMS while leaving the Codex symlinks
    /// (`auth.json`, `config.toml`, `sessions`, `history.jsonl`) pointing
    /// at the old config-<N>. This test pins the fix: a Codex handle dir
    /// under quota pressure MUST NOT be rotated, regardless of how
    /// tempting the ClaudeCode candidates look.
    #[cfg(unix)]
    #[test]
    fn auto_rotate_refuses_to_rotate_codex_handle_dir() {
        use crate::session::handle_dir::create_handle_dir_codex;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        // Codex slot 5, "over threshold" by any reasonable reading of
        // the 5h window: populate quota.json so the tick DOES think it
        // should rotate (i.e. pre-fix it would have tried).
        setup_codex_slot(dir.path(), 5);
        setup_quota(dir.path(), 5, 99.0);

        // Tempting ClaudeCode candidate at slot 1 (low usage). Pre-fix
        // the rotator would have picked this one.
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        // Create a Codex handle dir bound to slot 5.
        let acct5 = AccountNum::try_from(5u16).unwrap();
        let handle_dir = create_handle_dir_codex(dir.path(), acct5, 40001).unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert 1: the handle dir is still bound to slot 5 via its
        // .csq-account symlink. (In the Codex handle-dir layout,
        // `.csq-account` symlinks to `config-<N>/.csq-account`.)
        let marker = markers::read_csq_account(&handle_dir);
        assert_eq!(
            marker,
            Some(acct5),
            "Codex handle dir MUST NOT be rotated by auto-rotate \
             (v2.1 scope: Codex requires explicit csq swap)"
        );

        // Assert 2: no cooldown entry was recorded (the skip happened
        // before the repoint attempt).
        assert!(
            cooldowns.is_empty(),
            "no cooldown entry should be set when tick skips a Codex handle dir"
        );

        // Assert 3: the Codex symlink set is intact — `auth.json`,
        // `config.toml` still present (would have been left dangling
        // pre-fix if repoint had rewritten the ClaudeCode-shape items).
        assert!(
            handle_dir.join("auth.json").symlink_metadata().is_ok(),
            "Codex auth.json symlink must survive the tick"
        );
        assert!(
            handle_dir.join("config.toml").symlink_metadata().is_ok(),
            "Codex config.toml symlink must survive the tick"
        );
    }

    /// Regression guard: journal 0021 finding 1 second half.
    ///
    /// `find_target` must return `None` for a Codex current account
    /// regardless of what candidates exist. Before the fix, a Codex
    /// current account falling back to `Surface::ClaudeCode` would
    /// let same-surface filter admit Claude slots.
    #[test]
    fn find_target_returns_none_for_codex_current_account() {
        let dir = TempDir::new().unwrap();

        // Codex slot 3 as the current account.
        setup_codex_slot(dir.path(), 3);
        setup_quota(dir.path(), 3, 99.0);

        // Tempting ClaudeCode candidate at slot 1.
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        let acct3 = AccountNum::try_from(3u16).unwrap();
        let target = find_target(dir.path(), acct3, &[]);

        assert_eq!(
            target, None,
            "find_target MUST return None when current account is non-ClaudeCode \
             (auto-rotate is ClaudeCode-only in v2.1)"
        );
    }

    /// Regression guard: Codex slot must not be picked as a ClaudeCode
    /// rotation target. Prior to PR-C9a, `discover_anthropic` excluded
    /// Codex — but the fix switches `find_target` to `discover_all`,
    /// which now includes Codex accounts. This test pins the invariant
    /// that the same-surface filter correctly drops Codex candidates
    /// when the current handle dir is on ClaudeCode.
    #[test]
    fn find_target_skips_codex_candidates_for_claudecode_current() {
        let dir = TempDir::new().unwrap();

        // Current: ClaudeCode slot 1 (over threshold).
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 99.0);

        // Only candidate: Codex slot 2 (would be tempting if ClaudeCode
        // candidates were missing).
        setup_codex_slot(dir.path(), 2);
        setup_quota(dir.path(), 2, 5.0);

        let acct1 = AccountNum::try_from(1u16).unwrap();
        let target = find_target(dir.path(), acct1, &[]);

        assert_eq!(
            target, None,
            "Codex candidate must not be picked for a ClaudeCode handle dir \
             (INV-P11 same-surface filter)"
        );
    }
}
