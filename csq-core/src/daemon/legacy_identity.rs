//! Bounded daemon-only authentication of existing legacy UUID identities.
//! No render caller, remint, by-email lookup, or shared identity promotion.
use crate::accounts::{anthropic_identity as ai, identity_store};
use crate::daemon::usage_poller::HttpGetFn;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LegacyVerificationSummary {
    pub attempted: usize,
    pub upgraded: usize,
    pub repaired: usize,
    pub deferred: usize,
    pub refused: usize,
}
#[derive(Default)]
pub struct LegacyVerifier {
    negative: HashMap<(identity_store::IdentityId, ai::CredentialVersion), (u32, Instant)>,
}
impl LegacyVerifier {
    pub fn tick(&mut self, base: &Path, budget: usize) -> LegacyVerificationSummary {
        let http: HttpGetFn = std::sync::Arc::new(crate::http::get_bearer_node);
        self.tick_impl(base, budget, Instant::now(), &http)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn tick_with(
        &mut self,
        base: &Path,
        budget: usize,
        now: Instant,
        http: &HttpGetFn,
    ) -> LegacyVerificationSummary {
        self.tick_impl(base, budget, now, http)
    }
    fn tick_impl(
        &mut self,
        base: &Path,
        budget: usize,
        now: Instant,
        http: &HttpGetFn,
    ) -> LegacyVerificationSummary {
        let mut result = LegacyVerificationSummary::default();
        let entries = match std::fs::read_dir(identity_store::identities_dir(base)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return result,
            Err(_) => {
                result.refused += 1;
                return result;
            }
        };
        let mut ids = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                result.refused += 1;
                continue;
            };
            // File type is checked without following a symlink.
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            if let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<identity_store::IdentityId>().ok())
            {
                ids.push(id);
            }
        }
        ids.sort_by_key(|id| id.to_canonical_string());
        // Lock-free pre-filter: one bounded snapshot plus a per-identity metadata
        // read decide who needs a locked repair; most ticks take no lock at all.
        let snapshot = match ai::read_profiles_snapshot(base) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                result.refused += 1;
                tracing::warn!(
                    error_kind = "anthropic_legacy_profiles_snapshot_refused",
                    "legacy verification skipped: profiles snapshot unreadable"
                );
                return result;
            }
        };
        // Two phases over the sorted identities. Phase 1 completes every index repair
        // (an upgrade that crashed between its metadata and index writes) and collects the
        // identities that still need verification. Phase 2 upgrades. An upgrade must never
        // run before a repair that is still owed: the owed row is one the upgrade has to
        // see, otherwise an identity sorted ahead of the crashed one could take its
        // context and leave the crashed identity refused until a forced re-login.
        let mut unverified = Vec::new();
        for identity in ids {
            // Only a live slot can authorize verification or index recovery.
            // Old UUID directories are retained after logout/migration; they
            // must not generate repeated metadata warnings or profile requests.
            // This snapshot is a pre-filter, never publication authority: the
            // repair/upgrade writers recheck binding and tombstone under lock.
            if !snapshot.by_slot.values().any(|bound| *bound == identity)
                || identity_store::is_identity_removed(base, identity)
            {
                continue;
            }
            // Codex/foreign UUIDs are outside this verifier; malformed Anthropic
            // metadata is refused, never interpreted as absent or a new identity.
            if identity_store::read_identity_provider(base, identity).as_deref()
                != Some("anthropic")
            {
                continue;
            }
            match ai::read_stored_anthropic_context(base, identity) {
                Ok(ai::StoredAnthropicContext::LegacyUnknown) => unverified.push(identity),
                Ok(ai::StoredAnthropicContext::Known(_)) => {
                    if snapshot
                        .anthropic_contexts
                        .iter()
                        .any(|entry| entry.identity_uuid == identity)
                    {
                        continue;
                    }
                    match ai::repair_legacy_context_index(base, identity) {
                        Ok(ai::LegacyRepair::Repaired) => result.repaired += 1,
                        Ok(ai::LegacyRepair::Unneeded) => (),
                        Ok(ai::LegacyRepair::Deferred) => result.deferred += 1,
                        Err(_) => {
                            result.refused += 1;
                            tracing::warn!(
                                error_kind = "anthropic_legacy_metadata_repair_refused",
                                "legacy identity requires metadata repair; no remint was attempted"
                            );
                        }
                    }
                    continue;
                }
                Err(_) => {
                    result.refused += 1;
                    tracing::warn!(
                        error_kind = "anthropic_legacy_metadata_unreadable",
                        "legacy identity metadata is unreadable; no remint was attempted"
                    );
                    continue;
                }
            }
        }
        for identity in unverified {
            let source = match ai::legacy_verification_source(base, identity) {
                Ok(Some(source)) => source,
                Ok(None) => continue,
                Err(_) => {
                    result.refused += 1;
                    tracing::warn!(
                        error_kind = "anthropic_legacy_verification_source_refused",
                        "legacy identity credential is unreadable; no remint was attempted"
                    );
                    continue;
                }
            };
            let version = match ai::CredentialVersion::for_credentials(&source) {
                Ok(version) => version,
                Err(_) => {
                    result.refused += 1;
                    tracing::warn!(
                        error_kind = "anthropic_legacy_credential_version_refused",
                        "legacy identity credential version could not be derived"
                    );
                    continue;
                }
            };
            let key = (identity, version);
            if self
                .negative
                .get(&key)
                .is_some_and(|(_, retry)| now < *retry)
                || result.attempted >= budget.min(2)
            {
                result.deferred += 1;
                continue;
            }
            if !self.negative.contains_key(&key) && self.negative.len() >= 4096 {
                self.negative.retain(|_, (_, retry)| *retry > now);
                if self.negative.len() >= 4096 {
                    result.deferred += 1;
                    continue;
                }
            }
            result.attempted += 1;
            // Production supplies only the pinned profile transport. Injection
            // is gated at tick_with; complete exact-grant proof stays opaque.
            let outcome = match ai::verify_anthropic_context_impl_for_daemon(&source, http) {
                Ok(verified) => {
                    match ai::upgrade_verified_legacy_identity(base, identity, &verified) {
                        Ok(()) => Ok(()),
                        // A busy lock is deferral, not a refusal: no backoff entry.
                        Err(ai::IdentityError::BindingBusy) => {
                            result.deferred += 1;
                            continue;
                        }
                        Err(_) => Err(()),
                    }
                }
                Err(_) => Err(()),
            };
            match outcome {
                Ok(()) => {
                    self.negative.remove(&key);
                    result.upgraded += 1;
                }
                Err(()) => {
                    let failures = self
                        .negative
                        .get(&key)
                        .map_or(1, |(n, _)| n.saturating_add(1));
                    let seconds = 60u64
                        .saturating_mul(1u64 << failures.saturating_sub(1).min(6))
                        .min(3600);
                    // Admission above bounds the cache without evicting active
                    // backoff entries or retrying a rejected identity prematurely.
                    self.negative
                        .insert(key, (failures, now + Duration::from_secs(seconds)));
                    result.refused += 1;
                    tracing::warn!(
                        error_kind = "anthropic_legacy_profile_verification_refused",
                        "legacy identity remains unconfirmed; retry is bounded"
                    );
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::profiles::{self, ProfilesFile};
    use crate::credentials::{self, CredentialFile};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn stage_legacy(base: &Path, bound: bool) -> identity_store::IdentityId {
        let identity = identity_store::IdentityId::new_v4();
        crate::daemon::identity_mint::write_legacy_anthropic_metadata_fixture(
            base,
            identity,
            "legacy-verifier@test.invalid",
        )
        .unwrap();
        let credential: CredentialFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "fake-legacy-verifier-access",
                "refreshToken": "fake-legacy-verifier-refresh",
                "expiresAt": 4102444800000u64,
                "scopes": []
            }
        }))
        .unwrap();
        credentials::file::save(
            &identity_store::credentials_path_for(base, identity),
            &credential,
        )
        .unwrap();
        let mut profiles = ProfilesFile::empty();
        if bound {
            profiles.by_slot.insert("1".into(), identity);
            profiles
                .by_email
                .insert("legacy-verifier@test.invalid".into(), identity);
        }
        profiles::save(&profiles::profiles_path(base), &profiles).unwrap();
        identity
    }

    fn make_metadata_malformed(base: &Path, identity: identity_store::IdentityId) {
        // Valid JSON/provider, but an incomplete malformed context. This reaches
        // the metadata refusal rather than the foreign-provider pre-filter.
        std::fs::write(
            identity_store::identity_json_path_for(base, identity),
            br#"{"provider":"anthropic","email":"legacy-verifier@test.invalid","account_uuid":"not-a-uuid"}"#,
        )
        .unwrap();
    }

    #[test]
    fn legacy_tick_filters_inactive_leftovers_but_preserves_live_refusal_and_upgrade() {
        for (bound, tombstoned, malformed) in [
            (false, false, false),
            (false, false, true),
            (true, true, false),
            (true, true, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path();
            let identity = stage_legacy(base, bound);
            if malformed {
                make_metadata_malformed(base, identity);
            }
            if tombstoned {
                identity_store::mark_identity_removed(base, identity);
                assert!(identity_store::is_identity_removed(base, identity));
            }
            let metadata_path = identity_store::identity_json_path_for(base, identity);
            let canonical_path = identity_store::credentials_path_for(base, identity);
            let profiles_path = profiles::profiles_path(base);
            let metadata = std::fs::read(&metadata_path).unwrap();
            let canonical = std::fs::read(&canonical_path).unwrap();
            let profiles = std::fs::read(&profiles_path).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let http: HttpGetFn = Arc::new(move |_, _, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Err("unexpected fake request for an inactive identity".into())
            });
            let now = Instant::now();
            let mut verifier = LegacyVerifier::default();
            for tick in [now, now + Duration::from_secs(3601)] {
                let summary = verifier.tick_with(base, 2, tick, &http);
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    0,
                    "inactive UUID must not authenticate"
                );
                assert_eq!(
                    summary,
                    LegacyVerificationSummary::default(),
                    "inactive leftovers must not recur as refusals"
                );
                assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata);
                assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical);
                assert_eq!(std::fs::read(&profiles_path).unwrap(), profiles);
            }
            assert!(verifier.negative.is_empty());
        }
        // Positive and refusing live controls prevent a global-ignore repair.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let identity = stage_legacy(base, true);
        let metadata_path = identity_store::identity_json_path_for(base, identity);
        let canonical_path = identity_store::credentials_path_for(base, identity);
        let original_metadata = std::fs::read(&metadata_path).unwrap();
        let canonical = std::fs::read(&canonical_path).unwrap();
        make_metadata_malformed(base, identity);
        let malformed = std::fs::read(&metadata_path).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let http: HttpGetFn = Arc::new(move |url, token, headers| {
            observed.fetch_add(1, Ordering::SeqCst);
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(token, "fake-legacy-verifier-access");
            assert_eq!(headers, &[("anthropic-beta", "oauth-2025-04-20")]);
            Ok((200, br#"{"account":{"uuid":"11111111-1111-4111-8111-111111111111","email":"legacy-verifier@test.invalid"},"organization":{"uuid":"22222222-2222-4222-8222-222222222222"}}"#.to_vec()))
        });
        let now = Instant::now();
        let mut verifier = LegacyVerifier::default();
        for tick in [now, now + Duration::from_secs(3601)] {
            let summary = verifier.tick_with(base, 2, tick, &http);
            assert_eq!(
                summary.refused, 1,
                "still-bound malformed authority must refuse"
            );
            assert_eq!(summary.attempted, 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(std::fs::read(&metadata_path).unwrap(), malformed);
            assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical);
        }
        std::fs::write(&metadata_path, original_metadata).unwrap();
        let summary = verifier.tick_with(base, 2, now, &http);
        assert_eq!(
            (summary.attempted, summary.upgraded, summary.refused),
            (1, 1, 0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let profiles = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(profiles.by_slot.get("1"), Some(&identity));
        assert_eq!(profiles.anthropic_contexts.len(), 1);
        assert_eq!(profiles.anthropic_contexts[0].identity_uuid, identity);
        assert_eq!(std::fs::read(canonical_path).unwrap(), canonical);
    }

    /// The crash shape from the security review: identity Y's upgrade died between its
    /// metadata write and its index write (Y is Known with no row), and X, which sorts
    /// FIRST, is still legacy with a token of the same organization. Repairs run before
    /// every upgrade, so Y's row exists when X's upgrade is judged and X is refused;
    /// without that ordering X would take the context and Y would stay refused.
    #[test]
    fn legacy_tick_repairs_a_crashed_upgrade_before_any_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        // Deterministic ids: x sorts before y.
        let x = identity_store::IdentityId::from(uuid::Uuid::from_u128(1));
        let y = identity_store::IdentityId::from(uuid::Uuid::from_u128(2));
        assert!(x.to_canonical_string() < y.to_canonical_string());
        let creds = |tag: &str| -> CredentialFile {
            serde_json::from_value(serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": format!("fake-{tag}-access"),
                    "refreshToken": format!("fake-{tag}-refresh"),
                    "expiresAt": 4102444800000u64,
                    "scopes": []
                }
            }))
            .unwrap()
        };
        for (id, tag) in [(x, "x"), (y, "y")] {
            crate::daemon::identity_mint::write_legacy_anthropic_metadata_fixture(
                base,
                id,
                "legacy-verifier@test.invalid",
            )
            .unwrap();
            credentials::file::save(&identity_store::credentials_path_for(base, id), &creds(tag))
                .unwrap();
        }
        // Y's metadata as the upgrade's first write leaves it.
        let y_version =
            ai::CredentialVersion::for_credentials(creds("y").anthropic().unwrap()).unwrap();
        let y_metadata = identity_store::identity_json_path_for(base, y);
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&y_metadata).unwrap()).unwrap();
        json["account_uuid"] = serde_json::json!("11111111-1111-4111-8111-111111111111");
        json["organization_uuid"] = serde_json::json!("22222222-2222-4222-8222-222222222222");
        json["legacy_upgrade_source_version"] = serde_json::to_value(y_version).unwrap();
        std::fs::write(&y_metadata, serde_json::to_vec(&json).unwrap()).unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), x);
        pf.by_slot.insert("2".into(), y);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        let x_metadata = identity_store::identity_json_path_for(base, x);
        let x_metadata_before = std::fs::read(&x_metadata).unwrap();
        let x_canonical = std::fs::read(identity_store::credentials_path_for(base, x)).unwrap();

        let y_row_seen_when_x_is_verified = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = y_row_seen_when_x_is_verified.clone();
        let observed_base = base.to_path_buf();
        let http: HttpGetFn = Arc::new(move |_, token, _| {
            assert_eq!(
                token, "fake-x-access",
                "only X is verified; Y is already Known"
            );
            let rows = profiles::load(&profiles::profiles_path(&observed_base))
                .unwrap()
                .anthropic_contexts;
            seen.store(
                rows.iter().any(|row| row.identity_uuid == y),
                Ordering::SeqCst,
            );
            Ok((200, br#"{"account":{"uuid":"11111111-1111-4111-8111-111111111111","email":"legacy-verifier@test.invalid"},"organization":{"uuid":"22222222-2222-4222-8222-222222222222"}}"#.to_vec()))
        });
        let mut verifier = LegacyVerifier::default();
        let summary = verifier.tick_with(base, 2, Instant::now(), &http);

        assert_eq!(
            summary.repaired, 1,
            "Y's owed index row is repaired: {summary:?}"
        );
        assert_eq!(
            summary.upgraded, 0,
            "X must not take Y's context: {summary:?}"
        );
        assert!(
            y_row_seen_when_x_is_verified.load(Ordering::SeqCst),
            "the repair must complete before X's verification and upgrade"
        );
        let after = profiles::load(&profiles::profiles_path(base)).unwrap();
        let rows: Vec<_> = after
            .anthropic_contexts
            .iter()
            .map(|r| r.identity_uuid)
            .collect();
        assert_eq!(rows, vec![y], "exactly Y holds the organization");
        assert_eq!(
            ai::read_stored_anthropic_context(base, x).unwrap(),
            ai::StoredAnthropicContext::LegacyUnknown
        );
        assert_eq!(std::fs::read(&x_metadata).unwrap(), x_metadata_before);
        assert_eq!(
            std::fs::read(identity_store::credentials_path_for(base, x)).unwrap(),
            x_canonical
        );
    }
}
