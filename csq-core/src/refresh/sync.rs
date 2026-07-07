//! Credential backsync from CC-written live files into canonical storage.
//!
//! - **Backsync**: live `.credentials.json` → canonical `credentials/N.json`
//!   when CC refreshes a token in place (live is newer than canonical).
//!
//! M3-7: `pullsync` (canonical → live mirror) is retired. Handle-dir symlinks
//! resolve (post-M3-3/M3-4) to `identities/<UUID>/credentials.json`, so the
//! daemon's canonical write IS visible to CC via the symlink — no separate
//! mirror push needed. The live `<handle_dir>/.credentials.json` may still
//! materialise as a regular file (e.g. CC's atomic_replace), and backsync
//! continues to detect that case and promote it to canonical.
//!
//! Monotonicity guard: only writes if live `expiresAt` is strictly newer than canonical.

use crate::accounts::{identity_store, markers, profiles};
use crate::credentials::{self, file};
use crate::platform::lock;
use std::path::Path;
use tracing::debug;

/// Backsyncs a live credential file into canonical storage.
///
/// When CC refreshes a token directly (bypassing csq), the live
/// `.credentials.json` may be newer than `credentials/N.json`.
/// This function detects that and updates canonical.
///
/// Identity resolution: reads the `.csq-account` marker — the SOLE
/// authority for "which account is this session using" per
/// `account-terminal-separation.md` MUST NOT Rule 3 and spec 02 INV-03.
/// In the handle-dir model the marker symlinks to
/// `config-<current-account>/.csq-account`, so the read always returns
/// the current account number correctly without needing token-content
/// derivation. M4-3: replaced `identity::match_refresh_token` (terminal-
/// derived token-content channel — BLOCKED by `account-terminal-
/// separation.md` MUST NOT Rule 1) with the marker channel (slot-
/// lifecycle parameter, channel (c)).
///
/// Monotonicity guard: only writes if live `expiresAt` > canonical
/// `expiresAt`. Re-reads canonical inside the lock to prevent races.
pub fn backsync(config_dir: &Path, base_dir: &Path) -> Result<bool, crate::error::CsqError> {
    let live_path = config_dir.join(".credentials.json");
    let live_creds = match credentials::load(&live_path) {
        Ok(c) => c,
        Err(_) => return Ok(false), // no live creds, nothing to sync
    };

    // Resolve account via the marker — the SOLE authority per
    // `account-terminal-separation.md` MUST NOT Rule 3.
    let account = match markers::read_csq_account(config_dir) {
        Some(a) => a,
        None => {
            debug!(dir = %config_dir.display(), "backsync: cannot determine account");
            return Ok(false);
        }
    };

    // RN1-C (M4-12): resolve UUID-keyed identity path when by_slot is populated.
    // The numeric credentials/N.json path is retired as a WRITE destination;
    // reading it for the freshness check (canonical_expires) returns 0 for
    // post-RN1-C accounts, causing backsync to always promote live → unnecessary
    // writes every tick. Mirrors the pattern in broker_codex_check / broker_check.
    // Legacy fallback: if no UUID mapping exists, read numeric path (pre-RN1-C install).
    let canonical_path = match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => identity_store::credentials_path_for(base_dir, uuid),
        None => file::canonical_path(base_dir, account),
    };
    let lock_path = canonical_path.with_extension("lock");

    // Ensure the directory containing the canonical path exists before acquiring
    // the lock file — backsync may be the first writer for a newly-provisioned
    // account where the identity dir or credentials dir has never been written yet.
    if let Some(parent) = canonical_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Acquire per-canonical lock
    let _guard = lock::lock_file(&lock_path)?;

    // Re-read canonical inside lock (monotonicity guard AND
    // subscription-metadata preservation source, an internal journal entry P1-1).
    //
    // VP-H2 (HIGH): distinguish NotFound from Corrupt. Previously `.ok()`
    // collapsed both into None. If the canonical file is CORRUPT (not
    // merely absent), we must NOT overwrite it with a live token that may
    // carry `subscription_type: None` — that is the exact Max-tier-loss
    // bug PR-B5 guards against. Abort backsync instead.
    let canonical_existing = match credentials::load(&canonical_path) {
        Ok(c) => Some(c),
        Err(crate::error::CredentialError::NotFound { .. }) => None,
        Err(_e) => {
            tracing::warn!(
                account = %account,
                error_kind = "backsync_canonical_corrupt",
                "backsync aborting: canonical credential file unreadable, refusing to overwrite"
            );
            return Ok(false);
        }
    };
    let canonical_expires = canonical_existing
        .as_ref()
        .map(|c| c.expect_anthropic().claude_ai_oauth.expires_at)
        .unwrap_or(0);

    if live_creds.expect_anthropic().claude_ai_oauth.expires_at <= canonical_expires {
        debug!(account = %account, "backsync: live is not newer, skipping");
        return Ok(false);
    }

    // Subscription preservation guard. Anthropic's token endpoint
    // does NOT return `subscription_type` or `rate_limit_tier`; CC
    // backfills them into the live file on its first API call after
    // a fresh login. If CC just wrote a fresh `.credentials.json`
    // (post-re-login) and backsync fires before CC makes its first
    // API call, live carries `None` for both fields. Without this
    // guard we'd overwrite canonical's `Some(max)` with `None` and
    // the user's Max tier vanishes until the next daemon refresh
    // backfills it — typically up to 5 hours. Preserve canonical's
    // value when live is None. (Per `account-terminal-separation.md`
    // MUST Rule 4 — the WRITE-side invariant; the parallel READ-side
    // guards in `rotation::swap_to` and `broker::fanout` were retired
    // under M3-7 and `rotation::swap_to` itself was deleted in M4-8,
    // so only this and the daemon-refresher write paths carry the
    // preservation logic now.)
    let mut to_save = live_creds.clone();
    if let Some(existing) = canonical_existing.as_ref() {
        if to_save
            .expect_anthropic()
            .claude_ai_oauth
            .subscription_type
            .is_none()
        {
            to_save
                .expect_anthropic_mut()
                .claude_ai_oauth
                .subscription_type = existing
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .clone();
        }
        if to_save
            .expect_anthropic()
            .claude_ai_oauth
            .rate_limit_tier
            .is_none()
        {
            to_save
                .expect_anthropic_mut()
                .claude_ai_oauth
                .rate_limit_tier = existing
                .expect_anthropic()
                .claude_ai_oauth
                .rate_limit_tier
                .clone();
        }
    }

    // Live is newer — update canonical (UUID-keyed write at
    // identities/<UUID>/credentials.json — M4-12: fail-closed if UUID absent).
    credentials::save_canonical_for(base_dir, account, &to_save)?;
    debug!(account = %account, "backsync: canonical updated from live");
    Ok(true)
}

// M3-7: `pullsync` (canonical → live mirror) retired. Pre-M3-7, pullsync
// pushed daemon-refreshed canonical credentials into each CC session's
// `config-N/.credentials.json` mirror so CC would see the fresh token on
// its next API call. Post-M3-7, the live mirror does not exist; handle
// dirs read credentials through their identity-keyed symlinks, and CC
// re-stats the symlink before every API call (spec 01 §1.4) — daemon
// canonical writes are visible without a push step.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Provisions a deterministic UUID mapping in `profiles.json::by_slot` for
    /// the given account number. Required because `save_canonical_for` is
    /// fail-closed (M4-12): it returns `Err(NoCredentials)` when no UUID
    /// mapping exists, which would cause backsync to fail at the write step.
    fn provision_uuid_for_account(base: &Path, account: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(account.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
    }

    fn make_creds(access: &str, refresh: &str, expires_at: u64) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    /// Writes credentials to the UUID-keyed identity path when by_slot is populated.
    /// RN1-C: backsync reads the UUID path for the freshness check; seed it here.
    fn save_creds_uuid(base: &Path, account: u16, creds: &crate::credentials::CredentialFile) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_path, creds).unwrap();
    }

    fn setup_backsync(
        base: &Path,
        account: u16,
        canonical_expires: u64,
        live_expires: u64,
    ) -> PathBuf {
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();

        let acct = AccountNum::try_from(account).unwrap();
        markers::write_csq_account_legacy(&config, acct).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for (called by
        // backsync when live is newer) can locate the identity write path.
        provision_uuid_for_account(base, account);

        let rt = format!("rt-{account}");
        let canonical = make_creds(&format!("at-can-{account}"), &rt, canonical_expires);
        // RN1-C: backsync reads UUID path for freshness check; seed it AND numeric path.
        save_creds_uuid(base, account, &canonical);
        credentials::save(&file::canonical_path(base, acct), &canonical).unwrap();

        let live = make_creds(&format!("at-live-{account}"), &rt, live_expires);
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        config
    }

    #[test]
    fn backsync_live_newer_updates_canonical() {
        let dir = TempDir::new().unwrap();
        let config = setup_backsync(dir.path(), 1, 1000, 2000);

        let synced = backsync(&config, dir.path()).unwrap();
        assert!(synced);

        // M4-12: backsync writes via save_canonical_for which now writes to
        // identities/<UUID>/credentials.json (numeric path retired).
        let uuid1 = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid1);
        let canonical = credentials::load(&uuid_path).unwrap();
        assert_eq!(
            canonical.expect_anthropic().claude_ai_oauth.expires_at,
            2000
        );
    }

    #[test]
    fn backsync_live_older_skips() {
        let dir = TempDir::new().unwrap();
        let config = setup_backsync(dir.path(), 2, 2000, 1000);

        let synced = backsync(&config, dir.path()).unwrap();
        assert!(!synced);

        let acct = AccountNum::try_from(2u16).unwrap();
        let canonical = credentials::load(&file::canonical_path(dir.path(), acct)).unwrap();
        assert_eq!(
            canonical.expect_anthropic().claude_ai_oauth.expires_at,
            2000
        );
    }

    #[test]
    fn backsync_no_live_creds() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();

        let synced = backsync(&config, dir.path()).unwrap();
        assert!(!synced);
    }

    /// M4-3 regression: backsync MUST resolve the account via the
    /// `.csq-account` marker, NOT via refresh-token content matching.
    /// `account-terminal-separation.md` MUST NOT Rule 1 blocks
    /// terminal-derived (token-content) slot-id channels in writers.
    ///
    /// Setup: live `.credentials.json` exists with a refresh token that
    /// matches `credentials/9.json` on disk, but the marker says
    /// account 4. The OLD path matched by RT and returned 9; the
    /// post-M4-3 path reads the marker and returns 4. The post-write
    /// state proves the marker won: `credentials/4.json` is updated,
    /// `credentials/9.json` is untouched.
    #[test]
    fn backsync_account_resolution_uses_marker_not_refresh_token_match() {
        let dir = TempDir::new().unwrap();

        // M4-12: provision UUID mappings for both accounts before backsync
        // writes via save_canonical_for. Account 9 must also be provisioned
        // even though it should NOT be written (to avoid masking bugs).
        provision_uuid_for_account(dir.path(), 9);
        provision_uuid_for_account(dir.path(), 4);

        // Seed canonical credentials for account 9 with refresh token "rt-shared"
        // and an older expires_at (so backsync would update it if it picked
        // account 9 via RT match).
        let acct9 = AccountNum::try_from(9u16).unwrap();
        let canonical9 = make_creds("at-can-9", "rt-shared", 1000);
        credentials::save(&file::canonical_path(dir.path(), acct9), &canonical9).unwrap();

        // Seed canonical credentials for account 4 with a different RT and
        // an older expires_at (so backsync MUST update it if it correctly
        // picks account 4 via the marker).
        let acct4 = AccountNum::try_from(4u16).unwrap();
        let canonical4 = make_creds("at-can-4", "rt-acct4", 1000);
        credentials::save(&file::canonical_path(dir.path(), acct4), &canonical4).unwrap();

        // Live carries refresh token "rt-shared" (would match account 9
        // under the OLD RT-match path) but the handle dir's marker says 4.
        let config = dir.path().join("handle-dir");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account_legacy(&config, acct4).unwrap();
        let live = make_creds("at-live", "rt-shared", 2000);
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        // Act
        let synced = backsync(&config, dir.path()).unwrap();
        assert!(synced, "marker says 4 → backsync MUST update account 4");

        // Assert: account 4 (marker-resolved) was updated — read from UUID path.
        // M4-12: save_canonical_for writes to identities/<UUID>/credentials.json;
        // numeric path (credentials/4.json) is no longer the write destination.
        let uuid4 = crate::testing::identity_fixtures::fixture_uuid_for_slot(4);
        let uuid_path4 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid4);
        let post4 = credentials::load(&uuid_path4).unwrap();
        assert_eq!(
            post4.expect_anthropic().claude_ai_oauth.expires_at,
            2000,
            "marker resolution must drive the canonical write to account 4"
        );

        // Assert: account 9 (RT-match-resolved under old path) was NOT touched.
        // Account 9's numeric path was written by setup above; UUID path should
        // NOT exist (backsync must not write to it).
        let uuid9 = crate::testing::identity_fixtures::fixture_uuid_for_slot(9);
        let uuid_path9 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid9);
        assert!(
            !uuid_path9.exists(),
            "RT-match path is retired; account 9 UUID credential must not be touched"
        );
        let post9 = credentials::load(&file::canonical_path(dir.path(), acct9)).unwrap();
        assert_eq!(
            post9.expect_anthropic().claude_ai_oauth.expires_at,
            1000,
            "RT-match path is retired; account 9 numeric credential must not be touched"
        );
    }

    /// Regression for an internal journal entry P1-1: when live.subscription_type is
    /// None (Anthropic's token endpoint doesn't include it; CC backfills
    /// on first API call), backsync must preserve canonical's Some(max)
    /// rather than overwriting with None. Without the guard, the user's
    /// Max tier silently disappears until the next daemon refresh.
    #[test]
    fn backsync_preserves_subscription_type_when_live_has_none() {
        let dir = TempDir::new().unwrap();
        let acct = AccountNum::try_from(5u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path.
        provision_uuid_for_account(dir.path(), 5);

        // Canonical has Max.
        let mut canonical = make_creds("at-canonical", "rt-5", 1000);
        canonical
            .expect_anthropic_mut()
            .claude_ai_oauth
            .subscription_type = Some("max".to_string());
        canonical
            .expect_anthropic_mut()
            .claude_ai_oauth
            .rate_limit_tier = Some("tier_4".to_string());
        // RN1-C: backsync reads UUID path for freshness check AND subscription preservation.
        save_creds_uuid(dir.path(), 5, &canonical);
        credentials::save(&file::canonical_path(dir.path(), acct), &canonical).unwrap();

        // Live is fresh (newer expires_at) but subscription fields
        // are None — matches the post-re-login state before CC
        // makes its first API call.
        let config = dir.path().join("config-5");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account_legacy(&config, acct).unwrap();
        let live = make_creds("at-live-fresh", "rt-5", 2000);
        assert!(live
            .expect_anthropic()
            .claude_ai_oauth
            .subscription_type
            .is_none());
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        // Act
        let synced = backsync(&config, dir.path()).unwrap();
        assert!(synced, "live is newer — backsync must update canonical");

        // Assert: expires_at updated (freshness carried over) AND
        // subscription_type/rate_limit_tier preserved from canonical.
        // M4-12: read from UUID-keyed identity path (numeric path retired as write dest).
        let uuid5 = crate::testing::identity_fixtures::fixture_uuid_for_slot(5);
        let uuid_path5 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid5);
        let post = credentials::load(&uuid_path5).unwrap();
        assert_eq!(post.expect_anthropic().claude_ai_oauth.expires_at, 2000);
        assert_eq!(
            post.expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("max"),
            "subscription_type must be preserved when live has None"
        );
        assert_eq!(
            post.expect_anthropic()
                .claude_ai_oauth
                .rate_limit_tier
                .as_deref(),
            Some("tier_4"),
            "rate_limit_tier must be preserved when live has None"
        );
    }

    /// When live has a subscription_type (e.g. CC already made its
    /// first API call and backfilled), backsync must take live's
    /// value — not cling to canonical's stale one.
    #[test]
    fn backsync_takes_live_subscription_type_when_present() {
        let dir = TempDir::new().unwrap();
        let acct = AccountNum::try_from(6u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path.
        provision_uuid_for_account(dir.path(), 6);

        let mut canonical = make_creds("at-canonical", "rt-6", 1000);
        canonical
            .expect_anthropic_mut()
            .claude_ai_oauth
            .subscription_type = Some("max".to_string());
        // RN1-C: backsync reads UUID path for freshness check AND subscription preservation.
        save_creds_uuid(dir.path(), 6, &canonical);
        credentials::save(&file::canonical_path(dir.path(), acct), &canonical).unwrap();

        let config = dir.path().join("config-6");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account_legacy(&config, acct).unwrap();
        let mut live = make_creds("at-live", "rt-6", 2000);
        live.expect_anthropic_mut()
            .claude_ai_oauth
            .subscription_type = Some("pro".to_string());
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        backsync(&config, dir.path()).unwrap();

        // M4-12: read from UUID-keyed identity path (numeric path retired as write dest).
        let uuid6 = crate::testing::identity_fixtures::fixture_uuid_for_slot(6);
        let uuid_path6 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid6);
        let post = credentials::load(&uuid_path6).unwrap();
        assert_eq!(
            post.expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("pro"),
            "live's Some value must win over canonical's when present"
        );
    }

    /// M3-7 acceptance test #8 (WBS line 265):
    /// `broker_sync_does_not_write_config_n_credentials_json`.
    ///
    /// Pullsync is retired; only `backsync` remains. Backsync READS from
    /// `<config_dir>/.credentials.json` (CC may have written it directly,
    /// bypassing the symlink via atomic_replace) and writes the promoted
    /// payload to CANONICAL — never back to the config-N mirror.
    ///
    /// This test asserts that running `backsync` against a fixture-seeded
    /// live file does NOT modify that file (mtime stability), even on the
    /// successful-promote path.
    #[test]
    fn broker_sync_does_not_write_config_n_credentials_json() {
        let dir = TempDir::new().unwrap();
        let config = setup_backsync(dir.path(), 8, 1000, 2000); // canonical older, live newer
        let live_path = config.join(".credentials.json");
        let pre_mtime = std::fs::metadata(&live_path)
            .ok()
            .and_then(|m| m.modified().ok());
        std::thread::sleep(std::time::Duration::from_millis(10));

        // backsync promotes live → canonical (live is newer)
        let synced = backsync(&config, dir.path()).unwrap();
        assert!(synced, "live is newer — backsync MUST promote to canonical");

        let post_mtime = std::fs::metadata(&live_path)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            pre_mtime, post_mtime,
            "M3-7: broker::sync MUST NOT write to config-N/.credentials.json; \
             pre={pre_mtime:?} post={post_mtime:?}"
        );
    }
    // ── VP-H2: distinguish Corrupt from NotFound in backsync ─────────

    /// VP-H2 (HIGH): when the canonical credential file is CORRUPT (exists
    /// on disk but is not valid JSON), backsync MUST abort rather than
    /// overwrite it with a live token that may carry `subscription_type:
    /// None`. Overwriting would silently strip the Max tier.
    ///
    /// Contract: returns `Ok(false)` AND the malformed canonical file is
    /// untouched on disk (still contains the original garbage bytes).
    #[test]
    fn backsync_aborts_when_canonical_is_corrupt() {
        {
            // Arrange
            let dir = TempDir::new().unwrap();
            let acct = AccountNum::try_from(7u16).unwrap();

            // Write a MALFORMED canonical credential file.
            let canonical_path = file::canonical_path(dir.path(), acct);
            std::fs::create_dir_all(canonical_path.parent().unwrap()).unwrap();
            let corrupt_bytes = b"{{ this is NOT valid json !!!";
            std::fs::write(&canonical_path, corrupt_bytes).unwrap();

            // Live is valid but subscription_type is None — the token state that
            // would cause Max-tier loss if backsync were allowed to overwrite.
            let config = dir.path().join("config-7");
            std::fs::create_dir_all(&config).unwrap();
            markers::write_csq_account_legacy(&config, acct).unwrap();
            let live = make_creds("at-live-new", "rt-7", 9999);
            assert!(live
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .is_none());
            credentials::save(&config.join(".credentials.json"), &live).unwrap();

            // Act
            let result = backsync(&config, dir.path());

            // Assert — backsync returns Ok(false), NOT an error.
            assert!(
                matches!(result, Ok(false)),
                "backsync must return Ok(false) when canonical is corrupt, got: {{result:?}}"
            );

            // The canonical file must still contain the original corrupt bytes.
            let on_disk = std::fs::read(&canonical_path).unwrap();
            assert_eq!(
                on_disk, corrupt_bytes,
                "corrupt canonical file must not be overwritten by backsync"
            );
        }
    }

    /// RN1-C regression: backsync MUST read from identities/<UUID>/credentials.json
    /// for the freshness check (canonical_expires) when by_slot is populated.
    ///
    /// Pre-fix: backsync read file::canonical_path (numeric) → file not found →
    /// canonical_expires = 0 always → backsync always promoted live, creating
    /// unnecessary writes every daemon tick even when canonical was already fresh.
    ///
    /// Setup: UUID-keyed canonical has expires_at=3000 (newer than live 2000).
    /// credentials/N.json does NOT exist. Assert: backsync returns Ok(false)
    /// (correctly reads UUID canonical as newer, does NOT promote stale live).
    #[test]
    fn backsync_reads_uuid_path() {
        let dir = TempDir::new().unwrap();
        let acct = AccountNum::try_from(20u16).unwrap();

        // Set up the config dir with marker + live creds (expires_at=2000).
        let config = dir.path().join("config-20");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account_legacy(&config, acct).unwrap();
        let live = make_creds("at-live-20", "rt-20", 2000);
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        // Provision UUID mapping and write canonical with a NEWER expires_at (3000).
        provision_uuid_for_account(dir.path(), 20);
        let uuid20 = crate::testing::identity_fixtures::fixture_uuid_for_slot(20);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid20);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        let canonical = make_creds("at-canonical-20", "rt-20", 3000);
        credentials::save(&uuid_path, &canonical).unwrap();

        // Verify the numeric path does NOT exist (post-RN1-C account).
        let numeric_path = file::canonical_path(dir.path(), acct);
        assert!(
            !numeric_path.exists(),
            "test precondition: numeric credentials/N.json must NOT exist"
        );

        // Act: backsync should read UUID path, see canonical (3000) > live (2000),
        // and return Ok(false) — skipping the write.
        let result = backsync(&config, dir.path()).unwrap();
        assert!(
            !result,
            "backsync must return false when UUID canonical (3000) is newer than live (2000)"
        );

        // Assert: the UUID-keyed canonical was NOT modified.
        let post = credentials::load(&uuid_path).unwrap();
        assert_eq!(
            post.expect_anthropic().claude_ai_oauth.expires_at,
            3000,
            "UUID canonical must not be overwritten when it is newer than live"
        );
    }

    /// VP-H2 (HIGH): when the canonical credential file is simply ABSENT
    /// (NotFound, not corrupt), backsync must proceed normally and write
    /// the canonical from live — preserving any subscription tier live
    /// carries.
    ///
    /// This test verifies the NotFound arm does NOT trigger the abort path.
    #[test]
    fn backsync_proceeds_when_canonical_is_notfound() {
        {
            // Arrange
            let dir = TempDir::new().unwrap();
            let acct = AccountNum::try_from(8u16).unwrap();

            // No canonical file — directory does not exist yet.
            // backsync creates the credentials dir before locking so the
            // lock_file call does not fail with NotFound.
            let config = dir.path().join("config-8");
            std::fs::create_dir_all(&config).unwrap();
            markers::write_csq_account_legacy(&config, acct).unwrap();

            // M4-12: provision UUID mapping so save_canonical_for can write
            // via the identity-keyed path when canonical is absent.
            provision_uuid_for_account(dir.path(), 8);

            // Live has subscription_type "max" — must be preserved in canonical.
            let mut live = make_creds("at-live-8", "rt-8", 5000);
            live.expect_anthropic_mut()
                .claude_ai_oauth
                .subscription_type = Some("max".to_string());
            live.expect_anthropic_mut().claude_ai_oauth.rate_limit_tier =
                Some("tier_4".to_string());
            credentials::save(&config.join(".credentials.json"), &live).unwrap();

            // Act
            let result = backsync(&config, dir.path());

            // Assert — backsync ran successfully and wrote the canonical.
            assert!(
                matches!(result, Ok(true)),
                "backsync must return Ok(true) when canonical is absent, got: {{result:?}}"
            );

            // M4-12: read from UUID-keyed identity path (numeric path retired as write dest).
            let uuid8 = crate::testing::identity_fixtures::fixture_uuid_for_slot(8);
            let uuid_path8 =
                crate::accounts::identity_store::credentials_path_for(dir.path(), uuid8);
            let written = credentials::load(&uuid_path8).unwrap();
            assert_eq!(
                written
                    .expect_anthropic()
                    .claude_ai_oauth
                    .subscription_type
                    .as_deref(),
                Some("max"),
                "Max tier from live must be preserved in newly-written canonical"
            );
            assert_eq!(
                written
                    .expect_anthropic()
                    .claude_ai_oauth
                    .rate_limit_tier
                    .as_deref(),
                Some("tier_4"),
                "rate_limit_tier from live must be preserved in newly-written canonical"
            );
        }
    }
}
