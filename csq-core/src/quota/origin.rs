//! Metadata-only attribution for Anthropic quota and poll-attempt health.
//!
//! These readers never acquire profiles or canonical-credential locks. Take
//! snapshots on both sides of a quota read; writers preserve the raw file and
//! stamp the pre-request origin. A changed binding makes that row unavailable.

use crate::accounts::anthropic_identity::{read_stored_anthropic_context, StoredAnthropicContext};
use crate::accounts::identity_store::IdentityId;
use crate::accounts::{identity_store, profiles};
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

pub const ORIGIN_KEY: &str = "csq_anthropic_origin";

/// Attribution, not an ownership proof. No token, email, or raw provider ID is
/// persisted here. Generation distinguishes a slot's A -> B -> A publications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaOrigin {
    pub schema_version: u8,
    pub slot: u16,
    pub identity_uuid: Option<IdentityId>,
    pub context_digest: Option<[u8; 32]>,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotOrigin {
    Known(QuotaOrigin),
    Legacy(QuotaOrigin),
    Other,
    Invalid,
}

impl SlotOrigin {
    pub(crate) fn stamp(self) -> Option<QuotaOrigin> {
        match self {
            Self::Known(origin) | Self::Legacy(origin) => Some(origin),
            _ => None,
        }
    }
    fn allows(self, stamp: Option<QuotaOrigin>) -> bool {
        match self {
            Self::Known(origin) => stamp == Some(origin),
            Self::Legacy(origin) => {
                (stamp.is_none() && origin.generation == 0) || stamp == Some(origin)
            }
            Self::Other | Self::Invalid => false,
        }
    }
}

pub(crate) struct OriginSnapshot {
    slots: HashMap<String, SlotOrigin>,
    valid: bool,
}

impl OriginSnapshot {
    pub(crate) fn capture(base: &Path) -> Self {
        let pf = match profiles::load(&profiles::profiles_path(base)) {
            Ok(pf) => pf,
            Err(_) => {
                return Self {
                    slots: HashMap::new(),
                    valid: false,
                }
            }
        };
        let mut slots = HashMap::new();
        for (slot, identity) in &pf.by_slot {
            let Some(number) = slot
                .parse::<u16>()
                .ok()
                .and_then(|n| AccountNum::try_from(n).ok())
                .map(|a| a.get())
            else {
                continue;
            };
            let origin = QuotaOrigin {
                schema_version: 1,
                slot: number,
                identity_uuid: Some(*identity),
                context_digest: None,
                generation: pf.slot_binding_generations.get(slot).copied().unwrap_or(0),
            };
            let state = match identity_store::read_identity_provider(base, *identity).as_deref() {
                Some(provider) if provider != "anthropic" => SlotOrigin::Other,
                Some("anthropic") => match read_stored_anthropic_context(base, *identity) {
                    Ok(StoredAnthropicContext::LegacyUnknown) => {
                        if pf
                            .anthropic_contexts
                            .iter()
                            .any(|entry| entry.identity_uuid == *identity)
                        {
                            SlotOrigin::Invalid
                        } else {
                            SlotOrigin::Legacy(origin)
                        }
                    }
                    Ok(StoredAnthropicContext::Known(context)) => {
                        let matching = pf
                            .anthropic_contexts
                            .iter()
                            .filter(|entry| {
                                entry.identity_uuid == *identity
                                    || entry.context().as_ref() == Ok(&context)
                            })
                            .collect::<Vec<_>>();
                        if matching.len() != 1
                            || matching[0].identity_uuid != *identity
                            || matching[0].context().as_ref() != Ok(&context)
                        {
                            SlotOrigin::Invalid
                        } else {
                            let mut hash = Sha256::new();
                            hash.update(b"csq-anthropic-quota-context-v1\0");
                            let account_uuid = context.account_uuid();
                            let organization_uuid = context.organization_uuid();
                            for value in [
                                context.normalized_email().as_bytes(),
                                account_uuid.as_bytes(),
                                organization_uuid.as_bytes(),
                            ] {
                                hash.update((value.len() as u64).to_be_bytes());
                                hash.update(value);
                            }
                            SlotOrigin::Known(QuotaOrigin {
                                context_digest: Some(hash.finalize().into()),
                                ..origin
                            })
                        }
                    }
                    Err(_) => SlotOrigin::Invalid,
                },
                _ => SlotOrigin::Invalid,
            };
            slots.insert(slot.clone(), state);
        }
        // Generations also survive an unbind, so an old numeric row cannot
        // become visible again after A -> unbound -> A.
        for (slot, generation) in &pf.slot_binding_generations {
            if !slots.contains_key(slot) {
                if let Ok(slot_number) = slot.parse::<u16>() {
                    slots.insert(
                        slot.clone(),
                        SlotOrigin::Legacy(QuotaOrigin {
                            schema_version: 1,
                            slot: slot_number,
                            identity_uuid: None,
                            context_digest: None,
                            generation: *generation,
                        }),
                    );
                }
            }
        }
        Self { slots, valid: true }
    }
    pub(crate) fn slot(&self, number: u16) -> SlotOrigin {
        if !self.valid {
            return SlotOrigin::Invalid;
        }
        self.slots
            .get(&number.to_string())
            .copied()
            .unwrap_or(SlotOrigin::Legacy(QuotaOrigin {
                schema_version: 1,
                slot: number,
                identity_uuid: None,
                context_digest: None,
                generation: 0,
            }))
    }
}

pub(crate) fn capture(base: &Path, slot: AccountNum) -> SlotOrigin {
    OriginSnapshot::capture(base).slot(slot.get())
}

pub(crate) fn filter_visible(
    quota: &mut super::QuotaFile,
    before: &OriginSnapshot,
    after: &OriginSnapshot,
) {
    quota.accounts.retain(|slot, row| {
        let Ok(number) = slot.parse::<u16>() else {
            return false;
        };
        let old = before.slot(number);
        let current = after.slot(number);
        if old != current || current == SlotOrigin::Invalid {
            return false;
        }
        if row.surface != "claude-code" {
            // Other providers retain their existing read contract; a known
            // Anthropic binding cannot inherit a former provider's quota.
            return !matches!(current, SlotOrigin::Known(_));
        }
        let stamp = row
            .extras
            .as_ref()
            .and_then(|extras| extras.get(ORIGIN_KEY));
        let parsed = match stamp {
            Some(stamp) => match serde_json::from_value::<QuotaOrigin>(stamp.clone()) {
                Ok(origin) => Some(origin),
                Err(_) => return false,
            },
            None => None,
        };
        old == current && current.allows(parsed)
    });
    quota.poller_health.retain(|slot, health| {
        let Ok(number) = slot.parse::<u16>() else {
            return false;
        };
        let old = before.slot(number);
        let current = after.slot(number);
        old == current
            && match current {
                // Unstamped health from other providers retains its historical
                // contract. A stamped Anthropic attempt cannot follow a rebind.
                SlotOrigin::Other => health.origin.is_none(),
                _ => current.allows(health.origin),
            }
    });
}

/// The origin stamp the usage poller writes on `slot`'s quota row, for integration-test
/// fixtures that must publish a row a reader will show (a bound organization requires the
/// stamp). An unbound slot gets the identity-less legacy stamp the poller writes too;
/// `None` for a non-Anthropic slot and for every `Invalid` case: an unreadable or
/// inconsistent `profiles.json`, a missing identity, an unreadable stored context, or a
/// context-index mismatch.
#[cfg(feature = "test-utils")]
pub fn stamp_for_tests(base: &Path, slot: AccountNum) -> Option<QuotaOrigin> {
    capture(base, slot).stamp()
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    pub(crate) fn known(
        base: &Path,
        slot: u16,
        identity: IdentityId,
        organization: uuid::Uuid,
        generation: u64,
    ) {
        let context = crate::accounts::anthropic_identity::AnthropicContext::new(
            "fixture@example.invalid",
            uuid::Uuid::from_u128(17),
            organization,
        )
        .unwrap();
        let path = identity_store::identity_json_path_for(base, identity);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::fs::write_new_private(&path, serde_json::to_string(&serde_json::json!({
            "provider": "anthropic", "email": context.email(),
            "account_uuid": context.account_uuid(), "organization_uuid": context.organization_uuid(),
            "created_at": "fixture", "key_id": null,
        })).unwrap().as_bytes()).unwrap();
        let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        pf.by_slot.insert(slot.to_string(), identity);
        pf.slot_binding_generations
            .insert(slot.to_string(), generation);
        pf.anthropic_contexts
            .retain(|entry| entry.identity_uuid != identity);
        pf.anthropic_contexts
            .push(crate::accounts::anthropic_identity::AnthropicContextEntry {
                email: context.email().to_string(),
                account_uuid: context.account_uuid(),
                organization_uuid: context.organization_uuid(),
                identity_uuid: identity,
                extra: Default::default(),
            });
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
    }
    pub(crate) fn quota(origin: Option<QuotaOrigin>) -> super::super::AccountQuota {
        super::super::AccountQuota {
            updated_at: 1_700_000_000.0,
            extras: origin.map(|origin| serde_json::json!({"csq_anthropic_origin": origin})),
            ..Default::default()
        }
    }
    pub(crate) fn health(origin: Option<QuotaOrigin>) -> super::super::PollerHealth {
        super::super::PollerHealth {
            origin,
            last_attempt_at: 1_700_000_000.0,
            last_outcome: super::super::PollOutcome::Transport,
            consecutive_failures: 1,
            cooldown_until: None,
            next_retry_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{state, QuotaFile};
    use super::*;
    use fixtures::*;
    use tempfile::TempDir;
    fn ids() -> (IdentityId, uuid::Uuid) {
        (uuid::Uuid::from_u128(41).into(), uuid::Uuid::from_u128(51))
    }

    #[test]
    fn known_org_hides_unstamped_usage_and_health_from_both_reader_loaders() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(None));
        raw.set_health(4, health(None));
        state::save_state(dir.path(), &raw).unwrap();
        let original = std::fs::read(state::quota_path(dir.path())).unwrap();
        for visible in [
            state::load_state(dir.path()).unwrap(),
            state::load_state_salvage(dir.path()),
        ] {
            assert!(visible.get(4).is_none());
            assert!(visible.get_health(4).is_none());
        }
        assert_eq!(
            std::fs::read(state::quota_path(dir.path())).unwrap(),
            original
        );
        assert!(state::load_state_or_skip(dir.path())
            .unwrap()
            .get(4)
            .is_some());
    }
    #[test]
    fn exact_origin_visible_without_reading_any_credentials() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        assert!(!identity_store::credentials_path_for(dir.path(), id).exists());
        let origin = capture(dir.path(), AccountNum::try_from(4).unwrap())
            .stamp()
            .unwrap();
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(Some(origin)));
        raw.set_health(4, health(Some(origin)));
        state::save_state(dir.path(), &raw).unwrap();
        let visible = state::load_state(dir.path()).unwrap();
        assert!(visible.get(4).is_some());
        assert!(visible.get_health(4).is_some());
    }
    #[test]
    fn aba_generation_hides_old_origin_even_when_uuid_and_context_return() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        let old = capture(dir.path(), AccountNum::try_from(4).unwrap())
            .stamp()
            .unwrap();
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(Some(old)));
        raw.set_health(4, health(Some(old)));
        state::save_state(dir.path(), &raw).unwrap();
        let mut pf = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        pf.slot_binding_generations.insert("4".into(), 3);
        profiles::save(&profiles::profiles_path(dir.path()), &pf).unwrap();
        let visible = state::load_state(dir.path()).unwrap();
        assert!(visible.get(4).is_none());
        assert!(visible.get_health(4).is_none());
    }
    #[test]
    fn context_digest_refuses_different_provider_account_same_email_org_uuid_generation() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        let old = capture(dir.path(), AccountNum::try_from(4).unwrap())
            .stamp()
            .unwrap();
        let path = identity_store::identity_json_path_for(dir.path(), id);
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        metadata["account_uuid"] = serde_json::json!(uuid::Uuid::from_u128(18));
        std::fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let mut pf = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        pf.anthropic_contexts[0].account_uuid = uuid::Uuid::from_u128(18);
        profiles::save(&profiles::profiles_path(dir.path()), &pf).unwrap();
        let current = capture(dir.path(), AccountNum::try_from(4).unwrap())
            .stamp()
            .unwrap();
        assert_ne!(old.context_digest, current.context_digest);
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(Some(old)));
        state::save_state(dir.path(), &raw).unwrap();
        assert!(state::load_state(dir.path()).unwrap().get(4).is_none());
    }
    #[test]
    fn binding_change_across_quota_read_refuses_even_matching_new_row() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        let before = OriginSnapshot::capture(dir.path());
        known(
            dir.path(),
            4,
            uuid::Uuid::from_u128(42).into(),
            uuid::Uuid::from_u128(52),
            2,
        );
        let after = OriginSnapshot::capture(dir.path());
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(after.slot(4).stamp()));
        raw.set_health(4, health(after.slot(4).stamp()));
        filter_visible(&mut raw, &before, &after);
        assert!(raw.get(4).is_none());
        assert!(raw.get_health(4).is_none());
    }
    #[test]
    fn unrelated_raw_writer_preserves_hidden_sibling_rows() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(None));
        raw.set_health(4, health(None));
        state::save_state(dir.path(), &raw).unwrap();
        let mut write = state::load_state_or_skip(dir.path()).unwrap();
        write.set(
            9,
            super::super::AccountQuota {
                surface: "codex".into(),
                ..quota(None)
            },
        );
        state::save_state(dir.path(), &write).unwrap();
        let final_raw = state::load_state_or_skip(dir.path()).unwrap();
        assert_eq!(final_raw.get(4), raw.get(4));
        assert_eq!(final_raw.get_health(4), raw.get_health(4));
        assert!(state::load_state(dir.path()).unwrap().get(9).is_some());
    }
    #[test]
    fn legacy_unknown_and_other_provider_unstamped_health_remain_visible() {
        let dir = TempDir::new().unwrap();
        let (id, _) = ids();
        let path = identity_store::identity_json_path_for(dir.path(), id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::fs::write_new_private(
            &path,
            br#"{"email":"fixture@example.invalid","provider":"codex"}"#,
        )
        .unwrap();
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert("9".into(), id);
        profiles::save(&profiles::profiles_path(dir.path()), &pf).unwrap();
        let mut raw = QuotaFile::empty();
        raw.set(4, quota(None));
        raw.set_health(4, health(None));
        raw.set(
            9,
            super::super::AccountQuota {
                surface: "codex".into(),
                ..quota(None)
            },
        );
        raw.set_health(9, health(None));
        state::save_state(dir.path(), &raw).unwrap();
        let visible = state::load_state(dir.path()).unwrap();
        assert!(visible.get(4).is_some());
        assert!(visible.get_health(4).is_some());
        assert!(visible.get(9).is_some());
        assert!(visible.get_health(9).is_some());
    }
    #[test]
    fn malformed_and_future_origin_are_unavailable_not_legacy() {
        let dir = TempDir::new().unwrap();
        let (id, org) = ids();
        known(dir.path(), 4, id, org, 1);
        let origin = capture(dir.path(), AccountNum::try_from(4).unwrap())
            .stamp()
            .unwrap();
        for stamp in [
            serde_json::json!({"bad":1}),
            serde_json::to_value(QuotaOrigin {
                schema_version: 2,
                ..origin
            })
            .unwrap(),
        ] {
            let mut raw = QuotaFile::empty();
            raw.set(
                4,
                super::super::AccountQuota {
                    extras: Some(serde_json::json!({"csq_anthropic_origin":stamp})),
                    ..quota(None)
                },
            );
            state::save_state(dir.path(), &raw).unwrap();
            assert!(state::load_state_salvage(dir.path()).get(4).is_none());
        }
    }
}
