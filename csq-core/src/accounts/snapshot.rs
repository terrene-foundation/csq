//! Account snapshot — statusline-triggered identity check with PID caching.
//!
//! Called on every statusline render. Uses a cheap PID-alive check to
//! avoid expensive process tree walks on every render cycle.

use super::{markers, profiles};
use crate::platform::process::{find_cc_pid, is_pid_alive};
use crate::types::AccountNum;
use std::path::Path;
use tracing::debug;

/// Resolves the authoritative slot for a config/handle dir from the
/// `.csq-account` marker — the SOLE authority per
/// `account-terminal-separation.md` MUST NOT Rule 3.
///
/// - **Numeric** marker (`"7"`) → that slot directly. Covers pure-legacy
///   installs, format-drifted slots, and all non-OAuth surfaces
///   (codex/gemini/3P carry numeric markers).
/// - **UUID** marker (Phase-4 content for Anthropic OAuth slots) →
///   reverse-resolved via `profiles::resolve_uuid_to_slot` (`by_slot`).
///   This is the channel that was MISSING — without it a UUID marker had
///   no numeric resolution and the drift-prone `.current-account` cache
///   became load-bearing (the `csq swap N` → wrong-slot bug).
/// - Marker absent / unparseable, or UUID with no `by_slot` entry → `None`.
///   Never invents a slot.
fn resolve_authority(config_dir: &Path, base_dir: &Path) -> Option<AccountNum> {
    let marker = markers::read_identity_marker(config_dir)?;
    if let Some(numeric) = marker.numeric {
        return Some(numeric);
    }
    if let Some(uuid) = marker.uuid {
        return profiles::resolve_uuid_to_slot(base_dir, uuid);
    }
    None
}

/// Snapshots the current account for statusline rendering.
///
/// **Authority-first** (workspace `an internal workspace`): the slot
/// is ALWAYS resolved from `.csq-account` (the SOLE authority per
/// `account-terminal-separation.md` MUST NOT Rule 3) via [`resolve_authority`]
/// — numeric markers resolve directly, UUID markers reverse-resolve through
/// `by_slot`. `.current-account` is demoted to a perf cache that is
/// **self-healed** whenever it disagrees with the authority, so a stale
/// cache value can no longer be returned (the prior cheap path returned the
/// cached `.current-account` for as long as the CC PID was alive, which let
/// a stale value — e.g. a pre-handle-dir-migration leftover — surface
/// forever after a swap).
///
/// `.live-pid`'s sole remaining purpose is to skip the expensive
/// `find_cc_pid` process-tree walk: when a live PID is already cached we do
/// not re-run it. Authority resolution itself is cheap (one marker read,
/// plus one `profiles.json` load only for UUID markers).
///
/// M4-3: replaced `identity::which_account` (dir-name parsing + `claude auth
/// status` shell-out — terminal-derived channels BLOCKED) with the marker
/// channel. `base_dir` is now load-bearing: it is the root for the
/// `profiles.json` reverse lookup.
///
/// Returns the resolved slot, or — only when the authority is genuinely
/// unresolvable (no/corrupt marker, or a UUID absent from `by_slot`) — the
/// `.current-account` cache as a degraded last resort. Returns `None` when
/// neither is available. NEVER falls back to directory-name parsing.
pub fn snapshot_account(config_dir: &Path, base_dir: &Path) -> Option<AccountNum> {
    let pid_alive = markers::read_live_pid(config_dir)
        .map(is_pid_alive)
        .unwrap_or(false);

    if let Some(account) = resolve_authority(config_dir, base_dir) {
        // Self-heal the cache whenever it disagrees with the authority. This
        // is what closes the stale-`.current-account` drift class structurally.
        //
        // Write the canonical `config-N/.current-account`, NOT `config_dir`:
        // in production `config_dir` is the handle dir, whose `.current-account`
        // is a SYMLINK into config-N (`session::handle_dir::ACCOUNT_BOUND_ITEMS`).
        // `write_current_account` → `atomic_replace` → `rename` would replace
        // that symlink with a regular file, diverging the handle dir from
        // config-N. Writing config-N directly fixes the cache for EVERY terminal
        // bound to this slot at once and leaves the symlink intact.
        let canonical = base_dir.join(format!("config-{}", account.get()));
        if canonical.is_dir() && markers::read_current_account(&canonical) != Some(account) {
            if let Err(e) = markers::write_current_account(&canonical, account) {
                debug!(error = %e, "failed to self-heal .current-account");
            }
        }

        // The find_cc_pid walk is the only expensive step; skip it when a live
        // PID is already cached. (.live-pid no longer gates RESOLUTION.)
        if !pid_alive {
            if let Ok(Some(cc_pid)) = find_cc_pid() {
                if let Err(e) = markers::write_live_pid(config_dir, cc_pid) {
                    debug!(error = %e, "failed to write .live-pid");
                }
            }
        }

        return Some(account);
    }

    // Authority unresolvable: degraded last resort is the numeric cache, if
    // any. NEVER invent a slot and NEVER parse the directory name.
    debug!("snapshot: .csq-account authority unresolved; falling back to .current-account cache");
    markers::read_current_account(config_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn snapshot_writes_markers() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-4");
        std::fs::create_dir_all(&config).unwrap();

        // Seed the .csq-account marker — the SOLE authority for identity
        // per `account-terminal-separation.md` MUST NOT Rule 3. M4-3
        // retired the dir-name fallback path.
        let account = AccountNum::try_from(4u16).unwrap();
        markers::write_csq_account_legacy(&config, account).unwrap();

        let result = snapshot_account(&config, dir.path());
        assert_eq!(result, Some(account));

        // Should have cached .current-account from the marker read
        assert_eq!(markers::read_current_account(&config), Some(account));
    }

    #[test]
    fn snapshot_falls_back_to_cache_when_no_authority_marker() {
        // R1 review LOW-4: with no `.csq-account`, the authority is
        // unresolvable, so `snapshot_account` returns the `.current-account`
        // cache as the documented degraded last resort. (`.live-pid` no longer
        // gates resolution post-rewrite — it only skips the find_cc_pid walk.)
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-2");
        std::fs::create_dir_all(&config).unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        // Cache present, but NO `.csq-account` authority marker.
        markers::write_current_account(&config, account).unwrap();
        markers::write_live_pid(&config, std::process::id()).unwrap();

        let result = snapshot_account(&config, dir.path());
        assert_eq!(result, Some(account), "degraded fallback returns the cache");
    }

    #[test]
    fn snapshot_re_snapshots_when_pid_dead() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-6");
        std::fs::create_dir_all(&config).unwrap();

        let account = AccountNum::try_from(6u16).unwrap();

        // Set up stale cached state with a dead PID.
        // The .csq-account marker must be present so the expensive path
        // can re-snapshot (M4-3: marker is SOLE authority; dir-name and
        // CC-auth fallbacks retired).
        markers::write_csq_account_legacy(&config, account).unwrap();
        markers::write_current_account(&config, account).unwrap();
        markers::write_live_pid(&config, 99_999_999).unwrap();

        // Should re-snapshot (dead PID triggers expensive path)
        let result = snapshot_account(&config, dir.path());
        assert_eq!(result, Some(account));
    }

    #[test]
    fn snapshot_returns_none_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("unknown");
        std::fs::create_dir_all(&config).unwrap();

        // No .csq-account marker → expensive path returns None per
        // `account-terminal-separation.md` MUST NOT Rule 3 (no
        // dir-name fallback under M4-3).
        assert_eq!(snapshot_account(&config, dir.path()), None);
    }

    /// M4-3 regression: the expensive path MUST NOT fall back to
    /// dir-name parsing. A directory named `config-N` with NO
    /// `.csq-account` marker MUST return None — `account-terminal-
    /// separation.md` MUST NOT Rule 3 ("identity derivation uses
    /// marker, not directory name") is enforced structurally by the
    /// absence of the dir-name parser in the call chain.
    #[test]
    fn snapshot_does_not_fall_back_to_dir_name() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-9");
        std::fs::create_dir_all(&config).unwrap();
        // NOTE: no markers::write_csq_account call — the marker is absent.

        let result = snapshot_account(&config, dir.path());
        assert_eq!(
            result, None,
            "M4-3: dir-name fallback retired; missing marker must return None"
        );
    }

    /// an internal workspace: a stale `.current-account` MUST be
    /// self-healed even when the CC PID is alive (the prior cheap path
    /// returned the stale cache forever). Authority (`.csq-account`) wins.
    #[test]
    fn snapshot_heals_stale_current_account_when_pid_alive() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-7");
        std::fs::create_dir_all(&config).unwrap();

        // Authority says slot 7; cache is stale at 6 (the reported bug shape);
        // a live PID would have pinned the stale value under the old cheap path.
        markers::write_csq_account_legacy(&config, AccountNum::try_from(7u16).unwrap()).unwrap();
        markers::write_current_account(&config, AccountNum::try_from(6u16).unwrap()).unwrap();
        markers::write_live_pid(&config, std::process::id()).unwrap();

        let result = snapshot_account(&config, dir.path());
        assert_eq!(
            result,
            Some(AccountNum::try_from(7u16).unwrap()),
            "authority must win over the stale cache"
        );
        assert_eq!(
            markers::read_current_account(&config),
            Some(AccountNum::try_from(7u16).unwrap()),
            "the stale cache must be self-healed to the authority value"
        );
    }

    /// R1 review LOW-5: the production shape — `config_dir` is a `term-<pid>`
    /// handle dir DISTINCT from `config-N`, with `.csq-account`/`.current-account`
    /// symlinked into config-N. The self-heal MUST write the canonical
    /// `config-N/.current-account` (fixing every terminal at once) and MUST
    /// NOT replace the handle dir's symlink with a regular file (which
    /// `atomic_replace`/rename would do). This is the load-bearing rationale
    /// in `snapshot_account`'s doc-comment.
    #[cfg(unix)]
    #[test]
    fn snapshot_heals_canonical_not_handle_dir_symlink() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-7");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account_legacy(&config, AccountNum::try_from(7u16).unwrap()).unwrap();
        markers::write_current_account(&config, AccountNum::try_from(6u16).unwrap()).unwrap(); // stale

        // Handle dir with the production symlink set into config-7.
        let handle = base.join("term-99999");
        std::fs::create_dir_all(&handle).unwrap();
        symlink(config.join(".csq-account"), handle.join(".csq-account")).unwrap();
        symlink(
            config.join(".current-account"),
            handle.join(".current-account"),
        )
        .unwrap();
        markers::write_live_pid(&handle, std::process::id()).unwrap();

        let result = snapshot_account(&handle, base);
        assert_eq!(
            result,
            Some(AccountNum::try_from(7u16).unwrap()),
            "resolves slot 7 through the handle dir's symlinked marker"
        );
        // Canonical config-7 healed to 7.
        assert_eq!(
            markers::read_current_account(&config),
            Some(AccountNum::try_from(7u16).unwrap()),
            "self-heal writes the canonical config-N file"
        );
        // The handle dir's .current-account is STILL a symlink (not clobbered).
        assert!(
            std::fs::symlink_metadata(handle.join(".current-account"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "handle dir symlink must survive — heal did not write through it"
        );
    }

    /// A UUID `.csq-account` marker resolves to its slot via `by_slot`
    /// (the reverse resolver) — the modern OAuth-slot path.
    #[test]
    fn snapshot_resolves_uuid_marker_via_profiles() {
        use crate::accounts::identity_store::IdentityId;
        use crate::accounts::profiles::{profiles_path, save, ProfilesFile};

        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();

        let uuid = IdentityId::new_v4();
        markers::write_csq_account(&config, uuid).unwrap(); // UUID-content marker
        let mut profiles = ProfilesFile::empty();
        profiles.by_slot.insert("3".into(), uuid);
        save(&profiles_path(dir.path()), &profiles).unwrap();

        assert_eq!(
            snapshot_account(&config, dir.path()),
            Some(AccountNum::try_from(3u16).unwrap()),
            "UUID marker must reverse-resolve to slot 3 via by_slot"
        );
    }

    /// A UUID marker with NO `by_slot` mapping (e.g. profiles.json missing)
    /// resolves to `None` via the authority path; the degraded fallback then
    /// returns the numeric cache if present — never an invented slot.
    #[test]
    fn snapshot_uuid_without_mapping_uses_cache_then_none() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-4");
        std::fs::create_dir_all(&config).unwrap();

        // UUID marker, but no profiles.json → authority unresolvable.
        markers::write_csq_account(&config, IdentityId::new_v4()).unwrap();

        // No cache → None (no invented slot).
        assert_eq!(snapshot_account(&config, dir.path()), None);

        // With a cache present → degraded fallback returns it.
        markers::write_current_account(&config, AccountNum::try_from(4u16).unwrap()).unwrap();
        assert_eq!(
            snapshot_account(&config, dir.path()),
            Some(AccountNum::try_from(4u16).unwrap())
        );
    }
}
