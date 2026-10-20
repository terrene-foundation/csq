//! Integration tests for the auto-rotation loop — handle-dir-native (PR-A1).
//!
//! These tests prove that two independent terminals (handle dirs) rotate
//! independently: each gets its own cooldown entry, each is repointed
//! without writing to config-N/, and the two can diverge independently
//! once their cooldowns expire at different times.

// Uses the `test-utils` surface of csq-core; a plain `cargo test -p csq-core` builds it
// as an empty test binary instead of failing to compile. Gated here rather than with
// `required-features` so the manifest never names a file the community extraction removes.
#![cfg(feature = "test-utils")]

use csq_core::accounts::markers;
use csq_core::credentials::{
    self, file as cred_file, AnthropicCredentialFile, CredentialFile, OAuthPayload,
};
use csq_core::daemon::auto_rotate::tick;
use csq_core::quota::{state as quota_state, AccountQuota, UsageWindow};
use csq_core::rotation::config::{save as save_rotation_config, RotationConfig};
use csq_core::session::handle_dir::{create_handle_dir, sweep_dead_handles};
use csq_core::types::{AccessToken, AccountNum, RefreshToken};
use std::collections::HashMap;
use std::path::Path;
use tempfile::TempDir;

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
    let num = AccountNum::try_from(account).unwrap();
    let creds = make_creds(&format!("at-{account}"), &format!("rt-{account}"));
    credentials::save(&cred_file::canonical_path(base, num), &creds).unwrap();
}

fn setup_quota(base: &Path, account: u16, five_hour_pct: f64) {
    // The writers' unfiltered read (`load_state_or_skip`): the filtered reader would drop sibling rows whose organization binding
    // is not yet (or no longer) matched by a stamp, and the save would erase them.
    let mut quota = quota_state::load_state_or_skip(base).unwrap();
    quota.set(
        account,
        AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: five_hour_pct,
                // Far-future reset: year 2100 = 4102444800 seconds.
                resets_at: 4_102_444_800,
            }),
            ..Default::default()
        },
    );
    quota_state::save_state(base, &quota).unwrap();
    stamp_quota_origins(base);
}

/// The usage poller stamps each Anthropic row with the slot's origin; an organization-bound
/// slot shows only a row carrying its current stamp. Stamp every row whose slot is bound
/// (a no-op for slots without a binding yet, and again after `setup_slot_uuid`).
fn stamp_quota_origins(base: &Path) {
    let mut quota = quota_state::load_state_or_skip(base).unwrap();
    for (slot, row) in quota.accounts.iter_mut() {
        let Ok(num) = slot.parse::<u16>().map(AccountNum::try_from) else {
            continue;
        };
        if let Some(origin) = num
            .ok()
            .and_then(|n| csq_core::quota::origin::stamp_for_tests(base, n))
        {
            row.extras = Some(serde_json::json!({ "csq_anthropic_origin": origin }));
        }
    }
    quota_state::save_state(base, &quota).unwrap();
}

fn setup_config_dir(base: &Path, account: u16) {
    let config_dir = base.join(format!("config-{account}"));
    std::fs::create_dir_all(&config_dir).unwrap();
    let num = AccountNum::try_from(account).unwrap();
    markers::write_csq_account_legacy(&config_dir, num).unwrap();
}

fn setup_handle_dir(base: &Path, claude_home: &Path, pid: u32, account: u16) -> std::path::PathBuf {
    let num = AccountNum::try_from(account).unwrap();
    create_handle_dir(base, claude_home, num, pid).unwrap()
}

/// Registers a deterministic UUID in `profiles.json::by_slot[slot]` AND
/// seeds `identities/<UUID>/credentials.json`.
///
/// Post-M3-4 (an internal ticket, an internal journal entry), `find_target` skips candidates without
/// UUIDs to defend against partial-Pass-0 state where `resolve_slot_to_uuid`
/// returns `None` mid-tick. Integration tests that exercise the
/// `tick → find_target → repoint_handle_dir` chain MUST register UUIDs for
/// every slot they want to participate in rotation.
///
/// Post-M4-4 (Phase 4 reader flip), the discovery layer's `discover_anthropic`
/// reads through `by_slot`. The `phase3_gate_check` guarantees the
/// identity-keyed credentials are seeded in production; tests satisfy the
/// same invariant by seeding them here.
///
/// Uses the same deterministic UUID derivation as
/// `csq_core::testing::identity_fixtures::fixture_uuid_for_slot` (canonical).
#[cfg(any(test, feature = "test-utils"))]
fn setup_slot_uuid(base: &Path, slot: u16) {
    setup_slot_identity(base, slot, true);
}

/// `org_bound = true` is what a fresh login mints today: `identity.json` carries the
/// verified email, account UUID and organization UUID, and `profiles.json` indexes that
/// context in `anthropic_contexts`. `false` is the migrated pre-organization state: the
/// email alone, no index row (`StoredAnthropicContext::LegacyUnknown`).
///
/// Either way `identity.json` declares provider "anthropic" at 0600. Without the provider
/// the quota origin classifies the slot Invalid and hides every quota row; without the
/// email (legacy) or the context index (bound) the rotation target's binding capture is
/// refused, so the tick never repoints.
#[cfg(any(test, feature = "test-utils"))]
fn setup_slot_identity(base: &Path, slot: u16, org_bound: bool) {
    use csq_core::accounts::anthropic_identity::AnthropicContextEntry;
    use csq_core::accounts::identity_store;
    use csq_core::accounts::profiles;
    use csq_core::testing::identity_fixtures::fixture_uuid_for_slot;

    let uuid = fixture_uuid_for_slot(slot);
    let path = profiles::profiles_path(base);
    let mut pf = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
    pf.by_slot.insert(slot.to_string(), uuid);
    // A real mint bumps the slot's binding generation; a zero would make the origin
    // stamp indistinguishable from the pre-generation legacy form.
    pf.slot_binding_generations.insert(slot.to_string(), 1);
    let email = format!("slot{slot}@example.com");
    let account_uuid = uuid::Uuid::from_u128(0xA000 + u128::from(slot));
    let organization_uuid = uuid::Uuid::from_u128(0xB000 + u128::from(slot));
    let body = if org_bound {
        pf.anthropic_contexts.push(AnthropicContextEntry {
            email: email.clone(),
            account_uuid,
            organization_uuid,
            identity_uuid: uuid,
            extra: Default::default(),
        });
        format!(
            r#"{{"provider":"anthropic","email":"{email}","account_uuid":"{account_uuid}","organization_uuid":"{organization_uuid}","created_at":"fixture","key_id":null}}"#
        )
    } else {
        format!(
            r#"{{"provider":"anthropic","email":"{email}","created_at":"fixture","key_id":null}}"#
        )
    };
    profiles::save(&path, &pf).unwrap();

    let identity_json = identity_store::identity_json_path_for(base, uuid);
    std::fs::create_dir_all(identity_json.parent().unwrap()).unwrap();
    std::fs::write(&identity_json, body).unwrap();
    csq_core::platform::fs::secure_file(&identity_json).unwrap();
    // M4-4: also seed identities/<UUID>/credentials.json so the post-flip reader finds
    // credentials for this slot (same content as the legacy path setup_account writes).
    let creds = make_creds(&format!("at-{slot}"), &format!("rt-{slot}"));
    credentials::save(&identity_store::credentials_path_for(base, uuid), &creds).unwrap();
    stamp_quota_origins(base);
}

/// Two independent terminals rotate independently.
///
/// Setup: two term-<pid>/ dirs both on account 1. Account 1 over threshold.
/// Tick: both repoint to account 2 (or some lower-usage account).
/// Assert: neither config-1 nor config-2 credentials were written.
/// Assert: cooldown map has two distinct entries keyed on handle dir paths.
#[test]
fn two_terminals_rotate_independently() {
    let dir = TempDir::new().unwrap();
    let claude_home = TempDir::new().unwrap();

    setup_account(dir.path(), 1);
    setup_account(dir.path(), 2);
    setup_quota(dir.path(), 1, 97.0);
    setup_quota(dir.path(), 2, 10.0);
    setup_config_dir(dir.path(), 1);
    setup_config_dir(dir.path(), 2);
    // Post-M3-4 (an internal ticket): auto_rotate::find_target filters slots without UUIDs.
    // Register both slots' UUIDs so the rotation candidate selection sees them
    // as valid targets. See an internal journal entry + M3-4 verification block.
    setup_slot_uuid(dir.path(), 1);
    setup_slot_uuid(dir.path(), 2);

    // Snapshot config-N credential paths before tick
    let cred_path_1 = dir.path().join("config-1").join(".credentials.json");
    let cred_path_2 = dir.path().join("config-2").join(".credentials.json");
    std::fs::write(&cred_path_1, b"config-1-creds-sentinel").unwrap();
    std::fs::write(&cred_path_2, b"config-2-creds-sentinel").unwrap();
    let pre_1 = std::fs::read(&cred_path_1).unwrap();
    let pre_2 = std::fs::read(&cred_path_2).unwrap();

    // Create two independent terminals both on account 1
    let handle_a = setup_handle_dir(dir.path(), claude_home.path(), 20001, 1);
    let handle_b = setup_handle_dir(dir.path(), claude_home.path(), 20002, 1);

    let cfg = RotationConfig {
        enabled: true,
        threshold_percent: 95.0,
        cooldown_secs: 300,
        ..RotationConfig::default()
    };
    save_rotation_config(dir.path(), &cfg).unwrap();

    let mut cooldowns = HashMap::new();
    tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

    // Both handle dirs repointed to account 2
    assert_eq!(
        markers::read_csq_account(&handle_a),
        Some(AccountNum::try_from(2u16).unwrap()),
        "handle_a should be repointed to account 2"
    );
    assert_eq!(
        markers::read_csq_account(&handle_b),
        Some(AccountNum::try_from(2u16).unwrap()),
        "handle_b should be repointed to account 2"
    );

    // config-N credential files are byte-identical pre/post tick (INV-01)
    assert_eq!(
        std::fs::read(&cred_path_1).unwrap(),
        pre_1,
        "config-1/.credentials.json MUST NOT be modified"
    );
    assert_eq!(
        std::fs::read(&cred_path_2).unwrap(),
        pre_2,
        "config-2/.credentials.json MUST NOT be modified"
    );

    // Cooldown map has two independent entries.
    // VP-final F2: tick canonicalizes handle dir paths before inserting into
    // the cooldowns map. On macOS, TempDir may return /var/folders/... which
    // resolves to /private/var/folders/... — use canonical keys for lookups.
    let canonical_a = std::fs::canonicalize(&handle_a).unwrap_or(handle_a.clone());
    let canonical_b = std::fs::canonicalize(&handle_b).unwrap_or(handle_b.clone());
    assert_eq!(
        cooldowns.len(),
        2,
        "cooldown map must have one entry per handle dir"
    );
    assert!(
        cooldowns.contains_key(&canonical_a),
        "cooldown must contain canonical key for handle_a"
    );
    assert!(
        cooldowns.contains_key(&canonical_b),
        "cooldown must contain canonical key for handle_b"
    );
    assert_ne!(handle_a, handle_b, "handle dirs must have distinct paths");
}

/// After rotating, the two handle dirs can diverge.
///
/// Simulate: handle_a cooldown expires (remove from map); handle_b still
/// in cooldown. account 2 now over threshold, account 1 recovered.
/// Tick: only handle_a repoints back to account 1; handle_b stays on 2.
#[test]
fn two_terminals_diverge_after_independent_cooldown_expiry() {
    let dir = TempDir::new().unwrap();
    let claude_home = TempDir::new().unwrap();

    setup_account(dir.path(), 1);
    setup_account(dir.path(), 2);
    setup_quota(dir.path(), 1, 97.0);
    setup_quota(dir.path(), 2, 10.0);
    setup_config_dir(dir.path(), 1);
    setup_config_dir(dir.path(), 2);
    // Post-M3-4 (an internal ticket): auto_rotate::find_target filters slots without UUIDs.
    // Register both slots' UUIDs so the rotation candidate selection sees them
    // as valid targets. See an internal journal entry + M3-4 verification block.
    setup_slot_uuid(dir.path(), 1);
    setup_slot_uuid(dir.path(), 2);

    let handle_a = setup_handle_dir(dir.path(), claude_home.path(), 20003, 1);
    let handle_b = setup_handle_dir(dir.path(), claude_home.path(), 20004, 1);

    let cfg = RotationConfig {
        enabled: true,
        threshold_percent: 95.0,
        cooldown_secs: 300,
        ..RotationConfig::default()
    };
    save_rotation_config(dir.path(), &cfg).unwrap();

    // First tick: both rotate to account 2
    let mut cooldowns = HashMap::new();
    tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
    assert_eq!(
        markers::read_csq_account(&handle_a),
        Some(AccountNum::try_from(2u16).unwrap())
    );
    assert_eq!(
        markers::read_csq_account(&handle_b),
        Some(AccountNum::try_from(2u16).unwrap())
    );

    // Now account 2 is over threshold, account 1 has recovered
    setup_quota(dir.path(), 2, 98.0);
    setup_quota(dir.path(), 1, 5.0);

    // Simulate handle_a's cooldown expiring (remove from map).
    // VP-final F2: tick stores the CANONICAL path as the cooldown key;
    // must remove with the canonical key so the second tick sees handle_a
    // as uncooled and actually rotates it.
    let canonical_a = std::fs::canonicalize(&handle_a).unwrap_or(handle_a.clone());
    cooldowns.remove(&canonical_a);
    // handle_b's cooldown entry remains with current Instant (300s cooldown)

    // Second tick: only handle_a should rotate (cooldown expired)
    tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

    // handle_a repointed back to account 1 (account 2 over threshold, account 1 free)
    assert_eq!(
        markers::read_csq_account(&handle_a),
        Some(AccountNum::try_from(1u16).unwrap()),
        "handle_a should repoint to account 1 after its cooldown expired"
    );
    // handle_b stays on account 2 (still in cooldown)
    assert_eq!(
        markers::read_csq_account(&handle_b),
        Some(AccountNum::try_from(2u16).unwrap()),
        "handle_b should stay on account 2 — still in cooldown"
    );
}

/// VP-final F8: sweep_dead_handles and tick compose cleanly.
///
/// Setup:
/// - handle_a: live PID (current process) bound to account 1 (over threshold)
/// - handle_b: dead PID (99997, above macOS PID ceiling) bound to account 1
///
/// Step 1: tick — both handle dirs are above threshold; tick rotates both.
/// Step 2: sweep_dead_handles — removes handle_b (dead PID), leaves handle_a.
/// Step 3: verify handle_a still exists and is repointed; handle_b is gone;
///   config-N credential files are byte-identical (INV-01) through both ops.
///
/// This test guards against the regression where sweep and tick would race
/// to remove or repoint the same handle dir simultaneously, leaving the
/// accounts/ directory in an inconsistent state.
#[test]
fn sweep_races_rotate_on_dead_handle_dir() {
    let dir = TempDir::new().unwrap();
    let claude_home = TempDir::new().unwrap();

    setup_account(dir.path(), 1);
    setup_account(dir.path(), 2);
    setup_quota(dir.path(), 1, 97.0);
    setup_quota(dir.path(), 2, 10.0);
    setup_config_dir(dir.path(), 1);
    setup_config_dir(dir.path(), 2);
    // Post-M3-4 (an internal ticket): auto_rotate::find_target filters slots without UUIDs.
    // Register both slots' UUIDs so the rotation candidate selection sees them
    // as valid targets. See an internal journal entry + M3-4 verification block.
    setup_slot_uuid(dir.path(), 1);
    setup_slot_uuid(dir.path(), 2);

    // Snapshot config-N credential paths before any operation
    let cred_path_1 = dir.path().join("config-1").join(".credentials.json");
    let cred_path_2 = dir.path().join("config-2").join(".credentials.json");
    std::fs::write(&cred_path_1, b"config-1-sentinel").unwrap();
    std::fs::write(&cred_path_2, b"config-2-sentinel").unwrap();
    let pre_1 = std::fs::read(&cred_path_1).unwrap();
    let pre_2 = std::fs::read(&cred_path_2).unwrap();

    // handle_a: live PID (current process) — will survive sweep
    let live_pid = std::process::id();
    let handle_a = setup_handle_dir(dir.path(), claude_home.path(), live_pid, 1);

    // handle_b: dead PID guaranteed not alive.
    // On Unix, kill(pid, 0) checks liveness. u32::MAX as i32 = -1 (broadcast
    // target — returns success even with no such process). Use PID 99997,
    // which is above macOS's typical PID ceiling (~99998) and therefore
    // guaranteed to be dead, with a positive i32 representation.
    let dead_pid = 99997u32;
    let handle_b = setup_handle_dir(dir.path(), claude_home.path(), dead_pid, 1);

    let cfg = RotationConfig {
        enabled: true,
        threshold_percent: 95.0,
        cooldown_secs: 300,
        ..RotationConfig::default()
    };
    save_rotation_config(dir.path(), &cfg).unwrap();

    // Step 1: tick — both handle dirs are over threshold; tick rotates both
    let mut cooldowns = HashMap::new();
    tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

    // handle_a (live PID) should have been rotated and have a cooldown entry
    let canonical_a = std::fs::canonicalize(&handle_a).unwrap_or(handle_a.clone());
    assert!(
        cooldowns.contains_key(&canonical_a),
        "handle_a (live PID) should have a cooldown entry after tick"
    );

    // Step 2: sweep — removes handle_b (dead PID), leaves handle_a (live PID)
    let swept = sweep_dead_handles(dir.path(), Some(claude_home.path()));
    assert!(
        swept >= 1,
        "sweep must remove at least the dead-PID handle dir"
    );

    // Step 3: verify handle_a still exists and was repointed
    assert!(handle_a.exists(), "handle_a (live PID) must survive sweep");
    assert_eq!(
        markers::read_csq_account(&handle_a),
        Some(AccountNum::try_from(2u16).unwrap()),
        "handle_a should be repointed to account 2 by tick"
    );

    // handle_b must be gone
    assert!(
        !handle_b.exists(),
        "handle_b (dead PID) must be removed by sweep"
    );

    // INV-01: config-N credential files byte-identical through both tick + sweep
    assert_eq!(
        std::fs::read(&cred_path_1).unwrap(),
        pre_1,
        "config-1/.credentials.json MUST NOT be modified by tick or sweep"
    );
    assert_eq!(
        std::fs::read(&cred_path_2).unwrap(),
        pre_2,
        "config-2/.credentials.json MUST NOT be modified by tick or sweep"
    );
}

/// The migrated pre-organization state (email only, no context index) is a real state on
/// upgraded installs; rotation must work there too.
#[test]
fn legacy_unbound_identities_still_rotate() {
    let dir = TempDir::new().unwrap();
    let claude_home = TempDir::new().unwrap();
    setup_account(dir.path(), 1);
    setup_account(dir.path(), 2);
    setup_quota(dir.path(), 1, 97.0);
    setup_quota(dir.path(), 2, 10.0);
    setup_config_dir(dir.path(), 1);
    setup_config_dir(dir.path(), 2);
    setup_slot_identity(dir.path(), 1, false);
    setup_slot_identity(dir.path(), 2, false);
    let handle = setup_handle_dir(dir.path(), claude_home.path(), 20001, 1);
    let cfg = RotationConfig {
        enabled: true,
        threshold_percent: 95.0,
        cooldown_secs: 300,
        ..RotationConfig::default()
    };
    save_rotation_config(dir.path(), &cfg).unwrap();
    let mut cooldowns = HashMap::new();
    tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
    assert_eq!(
        markers::read_csq_account(&handle),
        Some(AccountNum::try_from(2u16).unwrap()),
        "legacy-bound handle must be repointed to account 2"
    );
}
