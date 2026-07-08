//! `account_id` chokepoint per an internal journal entry D4. Returns the account's permanent
//! UUID when `profiles.json` `by_slot` maps the slot (A++ / an internal ticket has
//! shipped), else the slot number as a string (`"1"`, `"4"`) for legacy layouts
//! or a missing `profiles.json`. The chokepoint is the SOLE caller-visible
//! function for "give me a stable identifier for this slot's ledger / config
//! dir / etc."
//!
//! Every call site that needs a stable identifier (for ledger filenames, for
//! handle-dir symlink targets, for any persisted state keyed by "the account")
//! goes through this single function.

use crate::types::AccountNum;
use std::path::Path;

/// Returns a stable identifier for the account at `slot`. The result is safe
/// to use as a filename component (alphanumeric + dash; no path separators,
/// no NUL bytes).
///
/// Post-A++ (an internal ticket, Phase 2 M2-1): returns the account's permanent UUID
/// string when `profiles.json` has a `by_slot` mapping for this slot.
/// Falls back to the decimal slot number string when UUID is absent (legacy
/// layout or missing profiles.json).
pub fn resolve_account_id(base: &Path, slot: AccountNum) -> String {
    crate::accounts::profiles::resolve_slot_to_uuid(base, slot.get())
        .map(|id| id.to_string())
        .unwrap_or_else(|| slot.get().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::identity_fixtures::{
        coexisting_fixture, fixture_uuid_for_slot, legacy_only_fixture,
    };
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── AC-5: renamed from `resolve_account_id_returns_decimal_slot_number_pre_aplusplus`
    #[test]
    fn resolve_account_id_legacy_fallback_returns_decimal_slot_number() {
        // Arrange — fresh tmpdir, no profiles.json (pure legacy fallback)
        let base = PathBuf::from("/tmp");
        let slot = AccountNum::try_from(7u16).unwrap();

        // Act
        let result = resolve_account_id(&base, slot);

        // Assert — must be the decimal slot string
        assert_eq!(result, "7");
    }

    // ── AC-1: UUID returned when by_slot is populated
    #[test]
    fn resolve_account_id_returns_uuid_when_by_slot_populated() {
        // Arrange — coexisting_fixture(3) populates by_slot for slots 1, 2, 3
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let slot = AccountNum::try_from(2u16).unwrap();

        // The deterministic UUID for slot 2 (from identity_fixtures)
        let expected_uuid = fixture_uuid_for_slot(2);

        // Act
        let result = resolve_account_id(base, slot);

        // Assert — must be UUID string, NOT "2"
        assert_eq!(
            result,
            expected_uuid.to_string(),
            "expected UUID {expected_uuid} for slot 2, got {result:?}"
        );
        assert_ne!(result, "2", "result must NOT be the decimal slot number");
    }

    // ── AC-2: slot decimal returned when legacy_only (no by_slot)
    #[test]
    fn resolve_account_id_falls_back_to_slot_when_uuid_missing() {
        // Arrange — legacy_only_fixture(3): no profiles.json by_slot entries
        let dir = legacy_only_fixture(3);
        let base = dir.path();
        let slot = AccountNum::try_from(2u16).unwrap();

        // Act
        let result = resolve_account_id(base, slot);

        // Assert — must be the decimal slot number
        assert_eq!(result, "2", "legacy layout must fall back to slot number");
    }

    // ── AC-3: no panic when profiles.json absent
    #[test]
    fn resolve_account_id_no_panic_on_missing_profiles_json() {
        // Arrange — fresh tmpdir with NO profiles.json at all
        let dir = TempDir::new().expect("TempDir::new");
        let base = dir.path();
        let slot = AccountNum::try_from(2u16).unwrap();

        // Act — must not panic
        let result = resolve_account_id(base, slot);

        // Assert — returns decimal slot string
        assert_eq!(
            result, "2",
            "missing profiles.json must produce decimal slot fallback"
        );
    }

    // ── AC-4: filename-safe check for both fixture shapes
    #[test]
    fn resolve_account_id_filename_safe() {
        // Part A — legacy shape (decimal slot numbers are trivially filename-safe)
        {
            let dir_legacy = legacy_only_fixture(3);
            let base = dir_legacy.path();
            for n in [1u16, 2, 3] {
                let slot = AccountNum::try_from(n).unwrap();
                let id = resolve_account_id(base, slot);
                assert!(
                    id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                    "legacy id {id:?} contains non-filename-safe char"
                );
                assert!(
                    !id.contains('/'),
                    "legacy id {id:?} contains path separator"
                );
                assert!(!id.contains('\0'), "legacy id {id:?} contains NUL");
            }
        }

        // Part B — coexisting shape (UUID strings: hex + dashes, always safe)
        {
            let dir_coex = coexisting_fixture(3);
            let base = dir_coex.path();
            for n in [1u16, 2, 3] {
                let slot = AccountNum::try_from(n).unwrap();
                let id = resolve_account_id(base, slot);
                assert!(
                    id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                    "coexisting id {id:?} contains non-filename-safe char"
                );
                assert!(
                    !id.contains('/'),
                    "coexisting id {id:?} contains path separator"
                );
                assert!(!id.contains('\0'), "coexisting id {id:?} contains NUL");
            }
        }
    }
}
