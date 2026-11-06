//! One answer to "may the daemon rotator ever move this terminal?".
//!
//! The rotator (`daemon::auto_rotate`) skips a handle dir unless its current
//! account is a Claude Code OAuth slot: not bound to a third-party
//! `ANTHROPIC_BASE_URL` (token-exfiltration guard, VP-F1) and not on a
//! non-Claude surface (Codex, Gemini, Kimi, Grok). A per-session setting on any
//! other terminal would be recorded and never acted on, so every surface that
//! offers or accepts the setting (desktop Sessions view, `csq rotation session`,
//! `csq run --auto-swap`) asks this module instead of re-deriving the test.
//!
//! The two predicates below use the SAME inputs and the SAME order as the
//! rotator: the surface of the account in `accounts` (an account missing from
//! discovery is read as Claude Code, as `find_target` does), then
//! [`slot_pins_anthropic_base_url`], the single env-transport discriminator
//! `daemon::auto_rotate::handle_dir_is_3p` itself delegates to.

use crate::accounts::markers;
use crate::accounts::{AccountInfo, AccountSource};
use crate::providers::catalog::Surface;
use crate::providers::settings::slot_pins_anthropic_base_url;
use std::path::Path;

/// `true` when the rotator can move a terminal currently bound to `slot`.
/// `accounts` is a `discover_all` result for `base`.
#[must_use]
pub fn slot_rotation_eligible(base: &Path, accounts: &[AccountInfo], slot: u16) -> bool {
    // Any discovered entry for the slot that is not a plain Claude Code OAuth
    // account refuses (fail closed): a non-Claude surface, or a third-party
    // source. The latter covers cloud-Claude (Vertex/Bedrock) slots, which
    // discovery reports as `Surface::ClaudeCode` with a `ThirdParty` source and
    // no `ANTHROPIC_BASE_URL` for the settings check below to see.
    let account_ok = accounts.iter().filter(|a| a.id == slot).all(|a| {
        a.surface == Surface::ClaudeCode && !matches!(a.source, AccountSource::ThirdParty { .. })
    });
    // `slot_pins_anthropic_base_url` is fail-closed: an unreadable settings.json
    // is "pinned" here, so a terminal is never offered the setting on a guess.
    account_ok && !slot_pins_anthropic_base_url(base, slot)
}

/// `true` when the rotator can move the terminal whose handle dir is
/// `handle_dir`. The account is read through the marker resolver the rotator
/// uses; a handle dir whose marker does not resolve is skipped by the rotator
/// (it cannot tell what the terminal is bound to), so it is not eligible.
#[must_use]
pub fn session_rotation_eligible(base: &Path, accounts: &[AccountInfo], handle_dir: &Path) -> bool {
    markers::resolve_marker_to_slot(base, handle_dir)
        .is_some_and(|slot| slot_rotation_eligible(base, accounts, slot.get()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountInfo, AccountSource, BillingMode};
    use tempfile::TempDir;

    fn info(id: u16, surface: Surface) -> AccountInfo {
        AccountInfo {
            id,
            label: format!("a{id}"),
            oauth_email: None,
            source: AccountSource::Anthropic,
            surface,
            method: "oauth".into(),
            has_credentials: true,
            billing_mode: BillingMode::default(),
        }
    }

    #[test]
    fn claude_oauth_slot_is_eligible_and_unknown_slot_reads_as_claude() {
        let base = TempDir::new().unwrap();
        assert!(slot_rotation_eligible(
            base.path(),
            &[info(1, Surface::ClaudeCode)],
            1
        ));
        assert!(slot_rotation_eligible(base.path(), &[], 2));
    }

    #[test]
    fn non_claude_surfaces_are_not_eligible() {
        let base = TempDir::new().unwrap();
        for surface in [
            Surface::Codex,
            Surface::Gemini,
            Surface::Kimi,
            Surface::Grok,
        ] {
            assert!(
                !slot_rotation_eligible(base.path(), &[info(3, surface)], 3),
                "{surface:?}"
            );
        }
    }

    #[test]
    fn a_slot_pinning_a_third_party_base_url_is_not_eligible() {
        let base = TempDir::new().unwrap();
        let cfg = base.path().join("config-4");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.z.ai/api/anthropic"}}"#,
        )
        .unwrap();
        assert!(!slot_rotation_eligible(
            base.path(),
            &[info(4, Surface::ClaudeCode)],
            4
        ));
    }

    #[test]
    fn a_slot_with_unreadable_settings_is_not_eligible() {
        let base = TempDir::new().unwrap();
        let cfg = base.path().join("config-6");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("settings.json"), [0xffu8, 0xfe]).unwrap();
        assert!(!slot_rotation_eligible(
            base.path(),
            &[info(6, Surface::ClaudeCode)],
            6
        ));
    }

    #[test]
    fn a_cloud_claude_slot_is_not_eligible() {
        let base = TempDir::new().unwrap();
        for provider in ["claude-vertex", "claude-bedrock"] {
            let mut account = info(7, Surface::ClaudeCode);
            account.source = AccountSource::ThirdParty {
                provider: provider.to_string(),
            };
            assert!(
                !slot_rotation_eligible(base.path(), &[account], 7),
                "{provider}"
            );
        }
    }

    #[test]
    fn a_handle_dir_without_a_resolvable_marker_is_not_eligible() {
        let base = TempDir::new().unwrap();
        let handle = base.path().join("term-77");
        std::fs::create_dir_all(&handle).unwrap();
        assert!(!session_rotation_eligible(base.path(), &[], &handle));
    }

    #[test]
    fn a_handle_dir_follows_the_slot_its_marker_resolves_to() {
        let base = TempDir::new().unwrap();
        let handle = base.path().join("term-78");
        std::fs::create_dir_all(&handle).unwrap();
        crate::accounts::markers::write_csq_account_legacy(
            &handle,
            crate::types::AccountNum::try_from(5u16).unwrap(),
        )
        .unwrap();
        assert!(session_rotation_eligible(
            base.path(),
            &[info(5, Surface::ClaudeCode)],
            &handle
        ));
        assert!(!session_rotation_eligible(
            base.path(),
            &[info(5, Surface::Codex)],
            &handle
        ));
    }
}
