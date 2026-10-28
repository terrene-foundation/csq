//! Keychain custodian (Option A) — daemon-side per-account reconcile.
//!
//! Recent Claude Code reads OAuth credentials keychain-first and self-refreshes
//! each session's token; Anthropic rotates the refresh-token on every refresh,
//! invalidating the prior one. So when several CC sessions run on one account,
//! one session's self-refresh strands its siblings (and csq's store) on a
//! rotated-dead token. The custodian dissolves that refresh war: each tick it
//! HARVESTS the freshest token across the account's live handle-dir keychains,
//! VALIDATES it against Anthropic (the only authority on chain liveness), and
//! ADOPTS the freshest LIVE token into the canonical store — which the existing
//! post-tick keychain sweep then redistributes to every sibling session.
//!
//! ## Why validate-before-adopt (an internal journal entry/0004)
//!
//! The canonical store is account-GLOBAL: a wrong write 401s every session of the
//! account. A harvested token's `expiresAt` being in the future does NOT prove its
//! refresh-CHAIN is live — a rotated-dead token keeps a future `expiresAt` until its
//! own TTL lapses, yet Anthropic 401s it immediately (confirmed by live probe,
//! an internal journal entry). So `max(expiresAt)` alone can promote a dead token. The custodian
//! therefore validates each candidate (freshest-first) with a single server call
//! and adopts only a server-confirmed-LIVE token:
//!   - **200 → Live**  → adopt, done.
//!   - **401 → Dead**  → discard, try the next-freshest candidate.
//!   - **429/other → Unknown** → cannot confirm; adopt NOTHING this tick, retry next
//!     tick (a 429 is neither "dead" nor "live"; fail-closed avoids promoting an
//!     unconfirmed token AND avoids hammering the rate-limited endpoint).
//!
//! That single call is `/api/oauth/profile` (see `verify_token_owner`), NOT
//! `/api/oauth/usage`: a 200 from `/api/oauth/profile` proves BOTH liveness AND that
//! the token belongs to this account (its `account.email`), closing the
//! "liveness ≠ ownership" gap in Part 2 without a second round-trip.
//!
//! Slot-id channel (`account-terminal-separation.md` MUST Rule 1): `account` is
//! supplied by the daemon's per-account tick iteration (channel (a)), never derived
//! from terminal-scoped state.
//!
//! ## Why validate-OWNER-before-adopt — the wrong-account guard (Part 2)
//!
//! A harvested keychain token is ACCOUNT-ANONYMOUS: the opaque `sk-ant-oat01-`
//! access token + the `claudeAiOauth` payload carry no account identity, the
//! keychain item's account attribute is the constant system username, and
//! `/api/oauth/usage` confirms LIVENESS, not OWNERSHIP. So a live token belonging
//! to a DIFFERENT account (a dir whose keychain CC wrote a foreign token into via
//! in-session `/login`, or a keychain/binding mismatch) would pass the liveness
//! gate and corrupt the account-GLOBAL store (401s every session of the account).
//! Two gates enforce this, defence-in-depth:
//!   1. `candidate_account_matches` — a cheap PRE-filter on the bound account's
//!      `identity.json` email vs the candidate dir's `.claude.json`
//!      `oauthAccount.emailAddress` (captured under the swap lock as
//!      `HarvestCandidate.candidate_email`). Fail-closed on any absence/mismatch.
//!   2. `verify_token_owner` — the AUTHORITATIVE gate, immediately before the adopt
//!      write: `/api/oauth/profile` with the candidate TOKEN returns the account it
//!      actually belongs to. The `.claude.json` email is a handle-dir SELF-REPORT
//!      and can DISAGREE with the token's real owner (a scrambled keychain, or a
//!      swap/login race where the keychain token and `.claude.json` are momentarily
//!      out of sync). Gate 1 alone let a foreign live token whose dir happened to
//!      self-report the right email be adopted → the cross-slot credential scramble.
//!      Gate 2 verifies the token itself, fail-closed on any mismatch/absence/error.
//!
//! The ingest gate confines verified candidates to the captured UUID. Writes use
//! `credentials::file::save_anthropic_canonical_guarded`, which rechecks binding,
//! context and credential version under the publication locks and requires a
//! strictly fresher candidate. Legacy own-UUID proof grants no Known metadata or
//! cross-context history authority. Explicit login publication uses the separate
//! verified login transaction; a numeric config path alone is no ownership proof.

use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::accounts::{anthropic_identity as ai, identity_store, profiles};
use crate::credentials::{self, file, CredentialFile};
#[cfg(test)]
use crate::daemon::usage_poller::anthropic::ANTHROPIC_BASE_URL;
use crate::daemon::usage_poller::HttpGetFn;
use crate::refresh::sentinel;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Hard ceiling on a harvested raw keychain payload before we parse/adopt it
/// (security H2). A normal `claudeAiOauth` credential is a few hundred bytes;
/// anything past this is rejected without parsing.
const MAX_RAW_CANDIDATE_BYTES: usize = 64 * 1024;

/// `keychain-fix-r9.md` D-F7: the worst case `client::HARVEST_TIMEOUT`'s doc
/// derives its budget from — "up to 2 of those candidates going on to a live
/// validation call" — was a DOCUMENTED ASSUMPTION, not something the loop in
/// [`reconcile_candidates_inner`] actually enforced: nothing stopped it from
/// sending every remaining candidate to `verify_token_owner` (a live
/// `/api/oauth/profile` call) if enough of them passed gate 1 and parsed.
/// This constant is what makes that assumption TRUE rather than merely
/// stated (`rules/doc-property-claims.md` MUST-1: name the mechanism). Once
/// reached without an Adopted/Mismatch verdict, the reconcile stops and
/// returns [`ReconcileOutcome::SkippedUnknown`] — on the fresher path AND on
/// the older-login path (`record_superseded_owner_verified`) — the same
/// "cannot confirm this tick, retry next tick" semantics already used for a
/// transport failure — rather than continuing to spend the shared, IP-wide rate-limit
/// budget (D-F6) validating ever-older candidates.
pub(crate) const MAX_VALIDATIONS_PER_RECONCILE: usize = 2;

/// Server verdict on whether a candidate token BELONGS to the bound account.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum OwnerVerdict {
    /// `/api/oauth/profile` returned 200 and its complete account/org/email
    /// context equals the captured Known identity. The token is live and owned
    /// by the bound account — safe to adopt.
    Match,
    /// Verified candidate allowed only into the captured legacy UUID. This is
    /// neither organization ownership nor authority to publish Known metadata.
    LegacyOwnUuid,
    /// 200 but `account.email` != anchor — a FOREIGN token (live, but another
    /// account's). Decisive: never adopt it into this account's store.
    Mismatch,
    /// 401 — the token's refresh chain is revoked. Discard; try the next candidate.
    Dead,
    /// 429 — per-IP Cloudflare throttle; propagate to the tick's cross-account backoff.
    RateLimited,
    /// Deterministic legacy refusal: shared custody or a stable verified
    /// context mismatch. Cached for the captured own version/binding generation.
    /// Repairable metadata errors, races and an own canonical token's 401 are
    /// Unknown and never cached.
    Refused,
    /// Transport / 5xx / parse / absent `account.email` / absent anchor — cannot
    /// confirm ownership. Fail-closed: adopt nothing.
    Unknown,
}

/// Repairable identity metadata is neither a token verdict nor adoption authority.
/// Retry suppression and warning throttling have their own bounded in-memory maps.
const METADATA_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(10 * 60);
const METADATA_RETRY_MAX: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum MetadataIssue {
    Unparseable,
    UnsafePermissions,
    MultipleLinks,
}

impl MetadataIssue {
    fn from_error(error: ai::IdentityError) -> Option<Self> {
        match error {
            ai::IdentityError::LegacyEmailUnparseable => Some(Self::Unparseable),
            ai::IdentityError::UnsafePermissions => Some(Self::UnsafePermissions),
            ai::IdentityError::MultipleLinks => Some(Self::MultipleLinks),
            _ => None,
        }
    }

    fn diagnostic(self) -> (&'static str, &'static str) {
        match self {
            Self::Unparseable => (
                "custodian_identity_metadata_unparseable",
                "run csq login for the affected slot to authenticate its legacy email",
            ),
            Self::UnsafePermissions => (
                "custodian_identity_metadata_unsafe_permissions",
                "inspect identity.json and credentials.json; restore private permissions only after confirming provenance, or run csq logout then csq login for the slot",
            ),
            Self::MultipleLinks => (
                "custodian_identity_metadata_multiple_links",
                "inspect identity.json and credentials.json; remove extra hard links only after confirming contents, or run csq logout then csq login for the slot",
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MetadataRetryKey {
    identity: identity_store::IdentityId,
    own_version: ai::CredentialVersion,
    generation: u64,
    candidate_version: ai::CredentialVersion,
}

impl MetadataRetryKey {
    fn new(
        binding: &ai::CapturedBinding,
        creds: &crate::credentials::AnthropicCredentialFile,
    ) -> Option<Self> {
        Some(Self {
            identity: binding.identity(),
            own_version: binding.credential_version(),
            generation: binding.generation(),
            candidate_version: ai::CredentialVersion::for_credentials(creds).ok()?,
        })
    }
}

#[derive(Default)]
struct MetadataRetryMaps {
    warnings:
        std::collections::HashMap<(identity_store::IdentityId, MetadataIssue), std::time::Instant>,
    backoffs: std::collections::HashMap<MetadataRetryKey, std::time::Instant>,
    /// Sibling slots whose saved credential could not be read for comparison, keyed by the
    /// SIBLING (`None` = a key that is not a canonical account number), never by the slot
    /// being adopted. An entry both throttles the warning and suppresses legacy adoption
    /// validation (no profile calls) until the window elapses.
    siblings: std::collections::HashMap<Option<u16>, std::time::Instant>,
    /// A Known identity's adoption refused because a same-email LEGACY sibling stands,
    /// keyed by the adopting identity and the sibling slot. Throttles the warning and
    /// suppresses that identity's profile validation until the window elapses.
    known_same_email:
        std::collections::HashMap<(identity_store::IdentityId, Option<u16>), std::time::Instant>,
    /// A Known identity's adoption refused because ANOTHER identity's canonical already holds
    /// the candidate grant, keyed by the adopting identity and the holding slot.
    known_grant_held:
        std::collections::HashMap<(identity_store::IdentityId, Option<u16>), std::time::Instant>,
}

#[derive(Default)]
struct MetadataRetryState(std::sync::Mutex<MetadataRetryMaps>);

fn remember_metadata_retry<K: Copy + Eq + std::hash::Hash>(
    map: &mut std::collections::HashMap<K, std::time::Instant>,
    key: K,
    now: std::time::Instant,
) {
    map.retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
    if map.len() >= METADATA_RETRY_MAX && !map.contains_key(&key) {
        if let Some(oldest) = map.iter().min_by_key(|(_, at)| *at).map(|(key, _)| *key) {
            map.remove(&oldest);
        }
    }
    map.insert(key, now);
}

impl MetadataRetryState {
    /// Record an unreadable SIBLING. Warns once per backoff window per sibling with a fixed
    /// tag and names the sibling, never the slot being adopted.
    fn record_sibling(&self, sibling: ai::SlotKey, now: std::time::Instant) {
        let key = sibling.account().map(AccountNum::get);
        let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        maps.siblings
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        let first = !maps.siblings.contains_key(&key);
        remember_metadata_retry(&mut maps.siblings, key, now);
        drop(maps);
        if first {
            warn!(sibling_slot = %sibling, error_kind = "custodian_sibling_custody_unreadable",
                "custodian: another slot's saved credential is unreadable, so legacy adoption is refused and HTTP validation deferred for up to ten minutes; inspect that slot or run csq login or csq logout for it");
        }
    }

    /// Record that a Known identity's adoption is blocked by a same-email legacy sibling.
    /// Warns once per backoff window per (identity, sibling), naming the sibling only.
    fn record_known_same_email(
        &self,
        identity: identity_store::IdentityId,
        sibling: ai::SlotKey,
        now: std::time::Instant,
    ) {
        let key = (identity, sibling.account().map(AccountNum::get));
        let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        maps.known_same_email
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        let first = !maps.known_same_email.contains_key(&key);
        remember_metadata_retry(&mut maps.known_same_email, key, now);
        drop(maps);
        if first {
            warn!(sibling_slot = %sibling, error_kind = "anthropic_known_adoption_same_email_legacy_sibling",
                "custodian: adoption for this slot is refused because another slot is still a legacy sign-in with the same email, and HTTP validation is deferred for up to ten minutes; run csq login for that other slot");
        }
    }

    /// Record that a Known identity's adoption is blocked because another identity's canonical
    /// already holds the candidate grant. Warns once per backoff window per (identity, holder),
    /// naming the holding slot only.
    fn record_known_grant_held(
        &self,
        identity: identity_store::IdentityId,
        holder: ai::SlotKey,
        now: std::time::Instant,
    ) {
        let key = (identity, holder.account().map(AccountNum::get));
        let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        maps.known_grant_held
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        let first = !maps.known_grant_held.contains_key(&key);
        remember_metadata_retry(&mut maps.known_grant_held, key, now);
        drop(maps);
        if first {
            warn!(sibling_slot = %holder, error_kind = "anthropic_known_adoption_grant_held_elsewhere",
                "custodian: adoption for this slot is refused because another slot's saved credential already holds this sign-in, and HTTP validation is deferred for up to ten minutes; run csq login for the affected slot");
        }
    }

    /// True while `identity` is inside a same-email-sibling or held-elsewhere backoff window.
    fn known_sibling_backoff_active(
        &self,
        identity: identity_store::IdentityId,
        now: std::time::Instant,
    ) -> bool {
        let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        maps.known_same_email
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        maps.known_grant_held
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        maps.known_same_email.keys().any(|(id, _)| *id == identity)
            || maps.known_grant_held.keys().any(|(id, _)| *id == identity)
    }

    /// True while any sibling is inside its backoff window (the scan that failed is
    /// slot-independent, so every legacy adoption would hit the same sibling).
    fn sibling_backoff_active(&self, now: std::time::Instant) -> bool {
        let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        maps.siblings
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        !maps.siblings.is_empty()
    }

    fn warn_issue(
        &self,
        identity: identity_store::IdentityId,
        slot: AccountNum,
        issue: MetadataIssue,
        now: std::time::Instant,
    ) {
        let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        maps.warnings
            .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
        if maps.warnings.contains_key(&(identity, issue)) {
            return;
        }
        remember_metadata_retry(&mut maps.warnings, (identity, issue), now);
        drop(maps);
        let (error_kind, repair_hint) = issue.diagnostic();
        warn!(account = slot.get(), error_kind, repair_hint,
            "custodian: identity metadata needs repair; adoption refused and HTTP validation deferred for up to ten minutes");
    }

    fn record(
        &self,
        binding: &ai::CapturedBinding,
        creds: &crate::credentials::AnthropicCredentialFile,
        issue: MetadataIssue,
        now: std::time::Instant,
    ) {
        if let Some(key) = MetadataRetryKey::new(binding, creds) {
            let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
            remember_metadata_retry(&mut maps.backoffs, key, now);
        }
        self.warn_issue(binding.identity(), binding.slot(), issue, now);
    }

    fn should_defer(
        &self,
        base: &Path,
        binding: &ai::CapturedBinding,
        creds: &crate::credentials::AnthropicCredentialFile,
        now: std::time::Instant,
    ) -> bool {
        let Some(key) = MetadataRetryKey::new(binding, creds) else {
            return false;
        };
        {
            let mut maps = self.0.lock().unwrap_or_else(|e| e.into_inner());
            maps.backoffs
                .retain(|_, at| now.saturating_duration_since(*at) < METADATA_RETRY_BACKOFF);
            if !maps.backoffs.contains_key(&key) {
                return false;
            }
        }
        // Local repair can lift a retry delay immediately without rotating the
        // token, incrementing generation, or manufacturing ownership proof.
        match ai::capture_anthropic_binding(base, binding.slot()) {
            Ok(current) if &current == binding && binding.belongs_to(base) => {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .backoffs
                    .remove(&key);
                false
            }
            Err(error) => {
                if let Some(issue) = MetadataIssue::from_error(error) {
                    self.warn_issue(binding.identity(), binding.slot(), issue, now);
                }
                true
            }
            _ => true,
        }
    }
}

/// Confirm a candidate access token's ACTUAL account ownership via
/// `GET /api/oauth/profile`, comparing the server-returned `account.email`
/// against the bound account's `anchor_email` (its `identity.json` email).
///
/// This closes the "liveness ≠ ownership" gap that a usage-only liveness check
/// leaves open: `/api/oauth/usage` proves the token's refresh chain is alive, NOT
/// that the token belongs to `anchor_email`. A harvested keychain token is
/// account-anonymous in its bytes, and the handle dir's `.claude.json` email
/// (checked by [`candidate_account_matches`]) is the dir's SELF-REPORT — it can
/// disagree with the token's real owner when the keychain is scrambled or a
/// swap/login race left the token and `.claude.json` out of sync. Adopting on the
/// self-report alone corrupts the account-global store with a foreign token (the
/// cross-slot quota-scramble bug). `/api/oauth/profile` is the authoritative
/// owner signal (200 also proves liveness, so this SUPERSEDES the usage-based
/// liveness check on the adopt path — no extra round-trip).
///
/// NEVER logs the token or the returned email. Fail-closed: any `None` /
/// parse / transport error, or a missing anchor, → [`OwnerVerdict::Unknown`].
fn verify_candidate_owner(
    base_dir: &Path,
    creds: &crate::credentials::AnthropicCredentialFile,
    binding: Option<&ai::CapturedBinding>,
    http_get: &HttpGetFn,
    metadata_retry: &MetadataRetryState,
) -> (
    OwnerVerdict,
    Option<ai::VerifiedAnthropicContext>,
    Option<ai::LegacyOwnUuidProof>,
) {
    if binding.is_some_and(|binding| {
        metadata_retry.should_defer(base_dir, binding, creds, std::time::Instant::now())
    }) {
        return (OwnerVerdict::Unknown, None, None);
    }
    if binding.is_some_and(|binding| {
        matches!(binding.context(), ai::StoredAnthropicContext::LegacyUnknown)
    }) && metadata_retry.sibling_backoff_active(std::time::Instant::now())
    {
        return (OwnerVerdict::Unknown, None, None);
    }
    // r6 M-1: a Known identity whose adoption a sibling blocks is not re-validated against
    // the profile endpoint every tick while that sibling stands.
    if let Some(binding) =
        binding.filter(|b| matches!(b.context(), ai::StoredAnthropicContext::Known(_)))
    {
        let now = std::time::Instant::now();
        if metadata_retry.sibling_backoff_active(now)
            || metadata_retry.known_sibling_backoff_active(binding.identity(), now)
        {
            return (OwnerVerdict::Unknown, None, None);
        }
    }
    #[cfg(any(test, feature = "test-utils"))]
    let checked = ai::verify_anthropic_context_with(creds, http_get);
    #[cfg(not(any(test, feature = "test-utils")))]
    let checked = {
        let _ = http_get;
        ai::verify_anthropic_context(creds)
    };
    let verified = match checked {
        Ok(proof) => proof,
        Err(ai::ProfileCheckFailure::Dead) => return (OwnerVerdict::Dead, None, None),
        Err(ai::ProfileCheckFailure::RateLimited) => {
            return (OwnerVerdict::RateLimited, None, None)
        }
        Err(ai::ProfileCheckFailure::Unknown) => return (OwnerVerdict::Unknown, None, None),
    };
    let Some(binding) = binding else {
        return (OwnerVerdict::Unknown, None, None);
    };
    match ai::compare_verified_owner(binding.context(), &verified) {
        ai::OwnerVerdict::Owned => {
            // The guarded write refuses a Known adoption while a same-email legacy sibling
            // (or an unreadable one) stands. Establish that here, once, so the refusal is a
            // throttled named warning plus a backoff, not an anonymous write failure and a
            // profile call on every tick.
            if let ai::StoredAnthropicContext::Known(known) = binding.context() {
                if let Ok(pf) = ai::read_profiles_snapshot(base_dir) {
                    let now = std::time::Instant::now();
                    match ai::known_sibling_block(base_dir, &pf, binding.identity(), known) {
                        Some(ai::KnownSiblingBlock::SameEmail(sibling)) => {
                            metadata_retry.record_known_same_email(
                                binding.identity(),
                                sibling,
                                now,
                            );
                            return (OwnerVerdict::Unknown, None, None);
                        }
                        Some(ai::KnownSiblingBlock::Unreadable(sibling)) => {
                            metadata_retry.record_sibling(sibling, now);
                            return (OwnerVerdict::Unknown, None, None);
                        }
                        None => (),
                    }
                    // r7 item 5: the guarded write ALSO refuses while another identity's
                    // canonical holds this very grant, or cannot be read. Establish that here
                    // too, so it is a named, throttled warning plus a backoff.
                    match ai::candidate_pair_holder(base_dir, &pf, binding.identity(), creds) {
                        Ok(None) => (),
                        Ok(Some(holder)) => {
                            metadata_retry.record_known_grant_held(binding.identity(), holder, now);
                            return (OwnerVerdict::Unknown, None, None);
                        }
                        Err(ai::IdentityError::SiblingCustodyUnreadable { sibling }) => {
                            metadata_retry.record_sibling(sibling, now);
                            return (OwnerVerdict::Unknown, None, None);
                        }
                        Err(_) => {
                            metadata_retry.record_sibling(ai::SlotKey::from_key(""), now);
                            return (OwnerVerdict::Unknown, None, None);
                        }
                    }
                }
            }
            (OwnerVerdict::Match, Some(verified), None)
        }
        ai::OwnerVerdict::Mismatch => (OwnerVerdict::Mismatch, None, None),
        ai::OwnerVerdict::Unknown => {
            // Canonicalization failure and a concurrent upgrade/rebind/refresh
            // invalidate this snapshot; they are retryable, never 15-minute refusals.
            if !binding.belongs_to(base_dir) {
                return (OwnerVerdict::Unknown, None, None);
            }
            match ai::capture_anthropic_binding(base_dir, binding.slot()) {
                Ok(current) if &current == binding => {}
                Err(
                    error @ (ai::IdentityError::LegacyEmailUnparseable
                    | ai::IdentityError::UnsafePermissions
                    | ai::IdentityError::MultipleLinks),
                ) => {
                    if let Some(issue) = MetadataIssue::from_error(error) {
                        metadata_retry.record(binding, creds, issue, std::time::Instant::now());
                    }
                    return (OwnerVerdict::Unknown, None, None);
                }
                _ => return (OwnerVerdict::Unknown, None, None),
            }
            // A verified different email may diagnose legacy contamination;
            // matching email gives no organization authority. A separate
            // restricted witness permits fresher writes only to this own UUID.
            match ai::compare_captured_legacy_email(base_dir, binding, &verified) {
                ai::OwnerVerdict::Mismatch => (OwnerVerdict::Mismatch, None, None),
                _ => {
                    // Email equality is not enough: this UUID's OWN canonical
                    // token must verify first and equal the candidate's
                    // account+organization. Until then adoption is refused.
                    // When the candidate IS the identity's own canonical token its
                    // verification already is the own verification: no second call.
                    let own_checked =
                        if verified.credential_version() == binding.credential_version() {
                            Ok(None)
                        } else {
                            #[cfg(any(test, feature = "test-utils"))]
                            let own = ai::verify_legacy_own_canonical_with(
                                base_dir,
                                binding.identity(),
                                http_get,
                            );
                            #[cfg(not(any(test, feature = "test-utils")))]
                            let own = ai::verify_legacy_own_canonical(base_dir, binding.identity());
                            own.map(Some)
                        };
                    match own_checked {
                        Ok(own) => {
                            let own = own.as_ref().unwrap_or(&verified);
                            // InvalidContext also represents snapshot movement. Establish
                            // a stable own-token/context witness before classifying a
                            // verified difference as a deterministic candidate refusal.
                            if !binding.belongs_to(base_dir)
                                || own.credential_version() != binding.credential_version()
                            {
                                return (OwnerVerdict::Unknown, None, None);
                            }
                            match ai::capture_anthropic_binding(base_dir, binding.slot()) {
                                Ok(current) if &current == binding => {}
                                Err(
                                    error @ (ai::IdentityError::LegacyEmailUnparseable
                                    | ai::IdentityError::UnsafePermissions
                                    | ai::IdentityError::MultipleLinks),
                                ) => {
                                    if let Some(issue) = MetadataIssue::from_error(error) {
                                        metadata_retry.record(
                                            binding,
                                            creds,
                                            issue,
                                            std::time::Instant::now(),
                                        );
                                    }
                                    return (OwnerVerdict::Unknown, None, None);
                                }
                                _ => return (OwnerVerdict::Unknown, None, None),
                            }
                            if own.context() != verified.context() {
                                return (OwnerVerdict::Refused, None, None);
                            }
                            match ai::legacy_own_uuid_proof(
                                base_dir, binding, &verified, own, creds,
                            ) {
                                Ok(legacy) => {
                                    (OwnerVerdict::LegacyOwnUuid, Some(verified), Some(legacy))
                                }
                                Err(
                                    ai::IdentityError::SharedLegacyIdentity
                                    | ai::IdentityError::DamagedContextIndexRow,
                                ) => (OwnerVerdict::Refused, None, None),
                                Err(ai::IdentityError::SiblingCustodyUnreadable { sibling }) => {
                                    // The fault is the SIBLING's, never this slot's: no
                                    // MetadataIssue, no per-slot retry key.
                                    metadata_retry
                                        .record_sibling(sibling, std::time::Instant::now());
                                    (OwnerVerdict::Unknown, None, None)
                                }
                                Err(error) => {
                                    if let Some(issue) = MetadataIssue::from_error(error) {
                                        metadata_retry.record(
                                            binding,
                                            creds,
                                            issue,
                                            std::time::Instant::now(),
                                        );
                                    }
                                    (OwnerVerdict::Unknown, None, None)
                                }
                            }
                        }
                        Err(ai::ProfileCheckFailure::RateLimited) => {
                            (OwnerVerdict::RateLimited, None, None)
                        }
                        Err(ai::ProfileCheckFailure::Dead) => {
                            warn!(
                                error_kind = "custodian_legacy_own_token_dead",
                                "custodian: legacy adoption refused because the identity's own token is dead; run csq login for the slot"
                            );
                            // Access expiry or a concurrent refresh can produce this
                            // 401; it is no deterministic ownership refusal.
                            (OwnerVerdict::Unknown, None, None)
                        }
                        Err(_) => {
                            warn!(
                                error_kind = "custodian_legacy_own_token_unverified",
                                "custodian: legacy adoption refused until the identity's own token is verified; run csq login for the slot"
                            );
                            (OwnerVerdict::Unknown, None, None)
                        }
                    }
                }
            }
        }
    }
}

// Compatibility fixture adapter for the older direct-verifier unit tests.
// Production always supplies a captured complete identity binding above.
#[cfg(test)]
fn verify_token_owner(
    token: &str,
    anchor_email: Option<&str>,
    http_get: &HttpGetFn,
) -> OwnerVerdict {
    let Some(email) = anchor_email else {
        return OwnerVerdict::Unknown;
    };
    let Ok(context) = ai::AnthropicContext::new(
        email,
        uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
    ) else {
        return OwnerVerdict::Unknown;
    };
    let creds: CredentialFile = serde_json::from_value(serde_json::json!({
        "claudeAiOauth": { "accessToken": token, "refreshToken": "fixture-refresh",
            "expiresAt": 4102444800000u64, "scopes": ["user:inference"] }
    }))
    .unwrap();
    match ai::verify_anthropic_context_with(creds.anthropic().unwrap(), http_get) {
        Ok(proof) => {
            match ai::compare_verified_owner(&ai::StoredAnthropicContext::Known(context), &proof) {
                ai::OwnerVerdict::Owned => OwnerVerdict::Match,
                ai::OwnerVerdict::Mismatch => OwnerVerdict::Mismatch,
                ai::OwnerVerdict::Unknown => OwnerVerdict::Unknown,
            }
        }
        Err(ai::ProfileCheckFailure::Dead) => OwnerVerdict::Dead,
        Err(ai::ProfileCheckFailure::RateLimited) => OwnerVerdict::RateLimited,
        Err(ai::ProfileCheckFailure::Unknown) => OwnerVerdict::Unknown,
    }
}

/// Ownership status of a slot's Anthropic STORE token, for the `csq doctor` /
/// `csq repair` contamination detector (an internal ticket follow-up).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SlotOwnership {
    /// The store token's `/api/oauth/profile` account matches the slot's
    /// `identity.json` anchor — healthy.
    Owned,
    /// The store token belongs to a DIFFERENT account than the slot's anchor —
    /// the cross-slot credential-scramble class. The store shows the right label
    /// but polls a foreign account's quota. Heal: `csq login <slot>`.
    Contaminated,
    /// Cannot confirm (no UUID mapping / no anchor / no store token / transport /
    /// parse / 401 / 429). Fail-closed: NEVER reported as contaminated on doubt.
    Unknown,
}

/// Resolve the Anthropic **store** credential path for `slot` — the single file
/// that [`check_slot_store_token_ownership`] reads and that
/// `csq repair --heal-contaminated` clears. UUID-keyed
/// (`identities/<UUID>/credentials.json`) when `by_slot` is populated, legacy
/// numeric (`credentials/N.json`) otherwise — mirroring `reconcile_account`'s
/// store-path resolution.
///
/// Exposed so the detector and the heal act on the SAME path (one keep-set across
/// consumers — `reconciler-cleanup-parity.md` Rule 4). Path resolution only;
/// performs no I/O and never touches another slot's identity dir.
pub fn slot_store_credential_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    match profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        Some(u) => identity_store::credentials_path_for(base_dir, u),
        None => file::canonical_path(base_dir, slot),
    }
}

/// Detect whether slot `slot`'s Anthropic **store** token actually belongs to the
/// account bound to that slot (its `identity.json` anchor email).
///
/// This is the diagnostic counterpart to the custodian's ingest gate
/// (`verify_token_owner`): the gate PREVENTS new cross-slot contamination
/// (an internal ticket), but a store already scrambled before that fix landed does not
/// self-heal — the store token keeps a `future`-enough expiry that the refresher
/// never replaces it, yet it polls a foreign account's quota. `csq doctor` had no
/// way to see this (it trusts the label); this surfaces it so an operator can
/// re-login the affected slot.
///
/// **Read-only.** Performs at most one `GET /api/oauth/profile` with the store
/// token and mutates nothing. `http_get` is injected so the detector is
/// unit-testable without the network. Resolves the store path + anchor exactly
/// as the custodian's `reconcile_account` does (UUID-keyed, legacy fallback).
///
/// NEVER logs the token or the returned email.
pub fn check_slot_store_token_ownership(
    base_dir: &Path,
    slot: AccountNum,
    http_get: &HttpGetFn,
) -> SlotOwnership {
    let captured = match ai::capture_anthropic_binding(base_dir, slot) {
        Ok(captured) => captured,
        Err(_) => return SlotOwnership::Unknown,
    };
    let store_path = identity_store::credentials_path_for(base_dir, captured.identity());
    let store_cred = match file::load(&store_path) {
        Ok(c) => c,
        Err(_) => return SlotOwnership::Unknown,
    };
    let Some(anth) = store_cred.anthropic() else {
        return SlotOwnership::Unknown;
    };
    let (verdict, _, _) = verify_candidate_owner(
        base_dir,
        anth,
        Some(&captured),
        http_get,
        &production_negative_cache().metadata_retry,
    );
    // A profile reply must not be attributed to a slot rebound during HTTP.
    let Ok(Some(lock)) = ProfilesFileLock::try_acquire(base_dir) else {
        return SlotOwnership::Unknown;
    };
    if !ai::binding_matches_locked(&lock, base_dir, &captured).unwrap_or(false) {
        return SlotOwnership::Unknown;
    }
    match verdict {
        OwnerVerdict::Match => SlotOwnership::Owned,
        OwnerVerdict::Mismatch => SlotOwnership::Contaminated,
        OwnerVerdict::LegacyOwnUuid
        | OwnerVerdict::Dead
        | OwnerVerdict::RateLimited
        | OwnerVerdict::Refused
        | OwnerVerdict::Unknown => SlotOwnership::Unknown,
    }
}

/// Wrong-account adopt guard (fail-closed). Returns `true` ONLY when the bound
/// account's anchor email and the candidate session's CC-recorded email are BOTH
/// present and, after trimming, equal **ASCII-case-insensitively** (OAuth emails
/// are ASCII and case-insensitive; the anchor is already trim+lowercased at mint,
/// so trimming the candidate makes the comparison symmetric — redteam R1 LOW). Any
/// `None` or empty-after-trim on EITHER side (absent `.claude.json`, absent
/// `identity.json` email, unparseable UUID) → `false` → do NOT adopt.
///
/// This is the structural defense against adopting a live token that belongs to a
/// DIFFERENT account than the one being reconciled. A harvested keychain token is
/// account-anonymous — the opaque `sk-ant-oat01-` access token and the
/// `claudeAiOauth` payload carry no account identity, the keychain item's account
/// attribute is the constant system username, and `/api/oauth/usage` confirms
/// liveness, not ownership. So a positive same-account match on the only available
/// local identity signal (the candidate dir's `.claude.json` `oauthAccount` email
/// vs the bound `identity.json` email) is REQUIRED before any write to the
/// account-global store. Fail-closed: doubt → refuse → the refresh war persists
/// for this account this tick (non-catastrophic, self-heals next tick) rather than
/// corrupting the account-global store with a foreign token (catastrophic — 401s
/// every session of the account).
pub(crate) fn candidate_account_matches(
    anchor_email: Option<&str>,
    candidate_email: Option<&str>,
) -> bool {
    match (anchor_email, candidate_email) {
        (Some(a), Some(c)) => {
            let (a, c) = (a.trim(), c.trim());
            !a.is_empty() && !c.is_empty() && a.eq_ignore_ascii_case(c)
        }
        _ => false,
    }
}

/// Compute the fixed-vocabulary `reason` tag for an identity-unconfirmed candidate
/// rejection (the `warn!` telemetry field). Pure + unit-testable — the tracing
/// field is otherwise unobservable in tests (redteam R2 testing-specialist F1).
///
/// The `candidate_email == None` case is split into `candidate_email_drift` (a
/// PRESENT `.claude.json` the wrong-account gate can't read an email from — the
/// an internal ticket format drift) vs `candidate_email_absent` (absent/empty file — benign
/// not-yet-populated OR no handle dir survives to classify at all), via
/// [`crate::credentials::claude_json::classify_oauth_account`], so the daemon
/// log carries the same drift-vs-fresh signal as the `csq doctor` custodian
/// canary (redteam R1 F6 — cross-surface parity). Telemetry only: the adopt
/// decision stays fail-closed on `candidate_email == None` regardless of this
/// tag.
///
/// `handle_dir_tag` is [`crate::credentials::keychain::HarvestCandidate::handle_dir_tag`]
/// — `Some(basename)` ONLY when the candidate's `term-<pid>` handle dir still
/// exists to be classified (the harvest sweep and the dead-handle reaper);
/// `None` for the pending-clear retry path, whose candidate carries a keychain
/// SERVICE name in `source_tag`, not a handle-dir basename (`keychain-fix-
/// r9.md` S-L-3). Classification is skipped entirely on `None` — no path is
/// ever built from a service name — and the honest, structurally-forced
/// answer for "no dir to inspect" is `candidate_email_absent`.
fn identity_unconfirmed_reason(
    base_dir: &Path,
    handle_dir_tag: Option<&str>,
    anchor_email: Option<&str>,
    candidate_email: Option<&str>,
) -> &'static str {
    use crate::credentials::claude_json::{classify_oauth_account, OauthAccountState};
    match (anchor_email, candidate_email) {
        (None, _) => "anchor_email_absent",
        (_, None) => match handle_dir_tag {
            Some(tag) => {
                let handle_dir = base_dir.join(tag);
                match classify_oauth_account(&handle_dir) {
                    OauthAccountState::FieldMissing => "candidate_email_drift",
                    _ => "candidate_email_absent",
                }
            }
            None => "candidate_email_absent",
        },
        _ => "email_mismatch",
    }
}

/// Outcome of [`reconcile_account`] — telemetry/test surface, carries no secrets.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ReconcileOutcome {
    /// Adopted a harvested live token into the store (it was strictly fresher).
    Adopted,
    /// The store already holds a token at-or-fresher than every candidate.
    StoreFreshest,
    /// No live handle-dir held a harvestable candidate for this account.
    NoCandidates,
    /// Candidates existed and beat the store, but none was usable: every one was
    /// rejected BEFORE validation (oversized / unparseable / non-Anthropic). Distinct
    /// from `AllDead` (which means candidates were validated and came back revoked).
    NoEligibleCandidate,
    /// Every candidate that reached validation came back Dead (all chains rotated away).
    AllDead,
    /// At least one candidate beat the store but its account could not be confirmed
    /// as the bound account. Covers BOTH gates: gate 1 — the session's CC-recorded
    /// `.claude.json` `oauthAccount.emailAddress` did not match the bound account's
    /// `identity.json` email (`error_kind = "custodian_identity_unconfirmed"`); and
    /// gate 2 — the harvested TOKEN's real owner (per `/api/oauth/profile`) was
    /// foreign (`error_kind = "custodian_owner_mismatch"`). Fail-closed: adopted
    /// NOTHING. Distinct from `AllDead` (chains revoked) and `NoEligibleCandidate`
    /// (pre-validation rejects). The two gates are distinguishable in the logs but
    /// map to the same outcome here.
    IdentityUnconfirmed,
    /// A validation call returned Unknown (transport/5xx) — retry next tick.
    SkippedUnknown,
    /// A validation call returned 429 — the endpoint is rate-limiting; the tick MUST
    /// back off (`rate_limited_this_tick`). Retry next tick.
    RateLimited,
    /// The store write was rejected/failed under the lock (logged, no overwrite).
    NotAdopted,
}

/// Reconcile one Anthropic account: harvest → validate (freshest-first) → adopt the
/// first server-confirmed-live token strictly fresher than the store.
///
/// `account_uuid` is the account's identity-store UUID (the harvest binding key).
/// Pure of terminal-derived slot ids — `account` comes from the tick iteration.
///
/// `negative` is the verdict cache the pass consults and feeds. Callers never
/// choose it — this fn is private, and the only on-demand entry points take an
/// [`OnDemandView`], a type constructible solely through
/// [`NegativeCache::on_demand_view`] / `NegativeCache::on_demand_view_over` (test-only):
/// they go through [`reconcile_account_periodic`] (the daemon's
/// refresher tick: [`production_negative_cache`] directly, so a persistently
/// bad candidate does not spend the validation budget every tick) or
/// [`reconcile_account_on_demand`] / [`reconcile_account_on_demand_with`] (the
/// `/api/harvest-account` route behind `csq swap`, and auto_rotate's pre-write
/// check: a [`NegativeCache::on_demand_view`] — shared Mismatch only, Dead kept
/// local, so a transient 401 cached by an earlier tick cannot block a forced
/// write, yet a permanent foreign-token Mismatch is never re-spent).
/// Native atomic replacement can turn a credential symlink into a regular
/// live file. Collect that case in the daemon, never in statusline rendering.
fn harvest_live_file_candidates(
    base: &Path,
    binding: &ai::CapturedBinding,
) -> Vec<credentials::keychain::HarvestCandidate> {
    let email = match binding.context() {
        ai::StoredAnthropicContext::Known(context) => context.email(),
        ai::StoredAnthropicContext::LegacyUnknown => {
            let Some(email) = binding.recorded_legacy_email() else {
                return Vec::new();
            };
            // A legacy UUID shared by several slots, or unreadable sharing state,
            // fails closed: those slots need a per-slot verified login.
            if ai::legacy_identity_is_shared(base, binding.identity()).unwrap_or(true) {
                warn!(
                    error_kind = "custodian_legacy_shared_harvest_refused",
                    "custodian: shared legacy identity not harvested; run csq login for each affected slot"
                );
                return Vec::new();
            }
            email
        }
    };
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with("term-") {
            continue;
        }
        let Ok(Some(pid)) = crate::accounts::markers::read_live_pid_checked(&path) else {
            continue;
        };
        if !crate::platform::process::is_pid_alive(pid)
            || crate::accounts::markers::resolve_marker_to_slot(base, &path) != Some(binding.slot())
            || crate::accounts::markers::read_csq_account_uuid(&path) != Some(binding.identity())
        {
            continue;
        }
        let credentials_path = path.join(".credentials.json");
        // The held-fd reader refuses symlinks, irregular/private-ownership
        // failures and growth. The ordinary canonical symlink is not harvested.
        let Ok(parsed) = ai::load_anthropic_canonical(&credentials_path) else {
            continue;
        };
        let Some(anthropic) = parsed.anthropic() else {
            continue;
        };
        let native_matches = match binding.context() {
            ai::StoredAnthropicContext::Known(context) => {
                ai::read_native_expectation(&path).is_ok_and(|native| native.context() == context)
            }
            ai::StoredAnthropicContext::LegacyUnknown => {
                // Email is only a local candidate prefilter. Adoption still
                // requires provider verification and the captured own-UUID
                // witness under the canonical/profiles write guards.
                crate::session::handle_dir::read_native_swap_raw(&path)
                    .ok()
                    .flatten()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                    .and_then(|json| {
                        json.get("oauthAccount")?
                            .get("emailAddress")?
                            .as_str()
                            .map(str::to_owned)
                    })
                    .is_some_and(|native| native.trim().eq_ignore_ascii_case(email))
            }
        };
        if !native_matches
            || anthropic.claude_ai_oauth.expires_at <= credentials::keychain::now_ms()
        {
            continue;
        }
        let Ok(raw) = serde_json::to_string(&parsed) else {
            continue;
        };
        if raw.len() > MAX_RAW_CANDIDATE_BYTES {
            continue;
        }
        candidates.push(credentials::keychain::HarvestCandidate {
            raw_json: raw.into(),
            expiry_ms: anthropic.claude_ai_oauth.expires_at,
            source_tag: "live_credential_file".into(),
            candidate_email: Some(email.into()),
            handle_dir_tag: Some(name),
        });
    }
    candidates
}

fn reconcile_account(
    base_dir: &Path,
    account: AccountNum,
    account_uuid: &str,
    http_get: &HttpGetFn,
    negative: &NegativeCache,
) -> ReconcileOutcome {
    // Baseline: the store's current Anthropic token expiry (None = no/invalid store
    // token — then any live candidate is an improvement). Resolve the store path the
    // SAME way broker_check does: UUID-keyed when by_slot is populated, legacy numeric
    // fallback otherwise.
    let store_path = match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => identity_store::credentials_path_for(base_dir, uuid),
        None => file::canonical_path(base_dir, account),
    };
    let store_cred = file::load(&store_path).ok();
    let store_expiry = store_cred
        .as_ref()
        .and_then(|c| c.anthropic())
        .map(|a| a.claude_ai_oauth.expires_at);

    let binding = match ai::capture_anthropic_binding(base_dir, account) {
        Ok(binding) if binding.identity().to_string() == account_uuid => binding,
        Err(error) if MetadataIssue::from_error(error).is_some() => {
            if let (Ok(identity), Some(issue)) =
                (account_uuid.parse(), MetadataIssue::from_error(error))
            {
                negative.metadata_retry.warn_issue(
                    identity,
                    account,
                    issue,
                    std::time::Instant::now(),
                );
            }
            return ReconcileOutcome::SkippedUnknown;
        }
        _ => {
            warn!(
                account = account.get(),
                error_kind = "custodian_binding_unavailable",
                "custodian: selected UUID custody unavailable; reconciliation refused"
            );
            return ReconcileOutcome::SkippedUnknown;
        }
    };

    // Freshest-first candidates across the account's LIVE handle-dir keychains.
    let mut candidates = credentials::keychain::harvest_account_candidates(base_dir, account_uuid);
    candidates.extend(harvest_live_file_candidates(base_dir, &binding));
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.expiry_ms));
    if candidates.is_empty() {
        return ReconcileOutcome::NoCandidates;
    }

    // Wrong-account adopt anchor: the bound account's authenticated OAuth email
    // (identity.json, written at mint). A harvested keychain token is account-
    // anonymous, so the ONLY local signal of a candidate session's account is its
    // handle dir's `.claude.json` `oauthAccount.emailAddress` (what CC recorded).
    // The guard below adopts a candidate ONLY when that matches this anchor —
    // fail-closed on absent/mismatch (a CC in-session `/login` to another account
    // rewrites `.claude.json`; a stale/unknown dir cannot be confirmed). See
    // `candidate_account_matches`.
    //
    // The identity is parsed ONCE here and that exact `IdentityId` is threaded to
    // every consumer (anchor email, older-login recorder). The custodian never
    // re-resolves the slot afterwards: a `csq login N` to a different email
    // between harvest and record must not redirect this identity's checks onto
    // another identity's list (the recorder additionally re-checks the binding
    // under the list lock).
    let identity = account_uuid.parse::<identity_store::IdentityId>().ok();
    let anchor_email = identity.and_then(|id| identity_store::read_identity_email(base_dir, id));

    let ctx = ReconcileCtx {
        base_dir,
        account,
        identity,
        anchor_email: anchor_email.as_deref(),
        binding: Some(binding),
        http_get,
        require_email_prefilter_on_absent_candidate_email: true,
        negative,
    };
    reconcile_candidates(&ctx, &candidates, store_expiry)
}

/// Periodic (refresher tick) entry: the shared production cache for both
/// verdict kinds.
pub(crate) fn reconcile_account_periodic(
    base_dir: &Path,
    account: AccountNum,
    account_uuid: &str,
    http_get: &HttpGetFn,
) -> ReconcileOutcome {
    reconcile_account(
        base_dir,
        account,
        account_uuid,
        http_get,
        production_negative_cache(),
    )
}

/// On-demand entry with a CALLER-OWNED view (auto_rotate builds one per tick and
/// shares it across that tick's terminals: a Dead or Mismatch verdict learned
/// for one terminal is not re-validated for the rest of the tick; an `Unknown`
/// verdict is never cached, so later terminals re-validate it).
///
/// The parameter type is [`OnDemandView`], which only
/// [`NegativeCache::on_demand_view`] / `NegativeCache::on_demand_view_over` (test-only)
/// can produce, so a plain `&NegativeCache` or `production_negative_cache()`
/// fails to compile (E0308). No `compile_fail` doctest: these items are
/// `pub(crate)`, so an external doctest would fail on the import (E0603) and
/// pass vacuously; the guard was verified by an in-crate mutation instead.
pub(crate) fn reconcile_account_on_demand_with(
    base_dir: &Path,
    account: AccountNum,
    account_uuid: &str,
    http_get: &HttpGetFn,
    view: &OnDemandView<'_>,
) -> ReconcileOutcome {
    reconcile_account(base_dir, account, account_uuid, http_get, view)
}

/// On-demand entry with a call-local view (`real_reconcile`, `csq swap`).
pub(crate) fn reconcile_account_on_demand(
    base_dir: &Path,
    account: AccountNum,
    account_uuid: &str,
    http_get: &HttpGetFn,
) -> ReconcileOutcome {
    reconcile_account_on_demand_with(
        base_dir,
        account,
        account_uuid,
        http_get,
        &NegativeCache::on_demand_view(),
    )
}

/// Everything one reconcile pass threads through its helpers. `identity` is the
/// `IdentityId` resolved ONCE by the caller and never re-resolved; `negative`
/// is the older-login verdict cache (production passes the process-wide one,
/// every test its own instance).
pub(crate) struct ReconcileCtx<'a> {
    pub(crate) base_dir: &'a Path,
    pub(crate) account: AccountNum,
    pub(crate) identity: Option<identity_store::IdentityId>,
    pub(crate) anchor_email: Option<&'a str>,
    pub(crate) binding: Option<ai::CapturedBinding>,
    pub(crate) http_get: &'a HttpGetFn,
    /// See [`reconcile_candidates_inner`]'s doc (D-F3).
    pub(crate) require_email_prefilter_on_absent_candidate_email: bool,
    pub(crate) negative: &'a NegativeCache<'a>,
}

/// The post-harvest decision loop, factored out of [`reconcile_account`] so the
/// wrong-account guard + outcome wiring are unit-testable WITHOUT the macOS
/// keychain (harvest is macOS-only; this consumes the already-harvested
/// candidate list). Validates freshest-first and adopts the first
/// server-confirmed-live candidate that is strictly fresher than the store AND
/// passes the wrong-account guard.
///
/// Assumes a non-empty slice: the production caller [`reconcile_account`] returns
/// `NoCandidates` upstream when the harvest is empty, so an empty slice here maps
/// to `NoEligibleCandidate` by construction (redteam R2 NIT — contract note).
pub(crate) fn reconcile_candidates(
    ctx: &ReconcileCtx<'_>,
    candidates: &[credentials::keychain::HarvestCandidate],
    store_expiry: Option<u64>,
) -> ReconcileOutcome {
    reconcile_candidates_inner(ctx, candidates, store_expiry)
}

/// `keychain-fix-r9.md` D-F3: `ctx.require_email_prefilter_on_absent_candidate_email`
/// gates ONLY the "candidate has no captured `.claude.json` self-report"
/// branch of gate 1 ([`candidate_account_matches`]) — when `false` AND
/// `cand.candidate_email` is `None`, gate 1 is skipped entirely for that
/// candidate and it proceeds straight to gate 2 ([`verify_token_owner`], the
/// AUTHORITATIVE server-side owner check), instead of being rejected outright.
/// A PRESENT-but-mismatched `candidate_email` is still rejected by gate 1
/// regardless of this flag — this only relaxes the "we could not capture a
/// self-report at all" case, never the "we captured one and it disagrees"
/// case.
///
/// [`adopt_single_candidate_before_delete`] passes `false`: its callers (the
/// dead-handle-dir reaper and the pending-clear retry queue) hold exactly ONE
/// candidate — the keychain item about to be deleted — which by construction
/// is THIS account's own stranded item, not a harvest sweep across many live
/// sessions' dirs where an absent self-report is a genuinely ambiguous
/// signal. Refusing to adopt purely because no `.claude.json` self-report
/// survived the handle dir's teardown would defeat the retry/reaper path on
/// exactly the entries it exists to rescue, when the authoritative
/// server-side owner check (gate 2) is available and sufficient on its own.
///
/// [`reconcile_account`]'s harvest-across-many-live-sessions path (via
/// [`reconcile_candidates`], above) passes `true` unchanged: there, an absent
/// self-report is one of several candidates and staying fail-closed on it is
/// the correct posture.
fn reconcile_candidates_inner(
    ctx: &ReconcileCtx<'_>,
    candidates: &[credentials::keychain::HarvestCandidate],
    store_expiry: Option<u64>,
) -> ReconcileOutcome {
    let ReconcileCtx {
        base_dir,
        account,
        identity,
        anchor_email,
        ref binding,
        http_get,
        require_email_prefilter_on_absent_candidate_email,
        negative,
    } = *ctx;
    // Set only when a candidate actually REACHED validation and came back Dead —
    // distinguishes "all chains revoked" (AllDead) from "candidates all rejected
    // pre-validation" (NoEligibleCandidate). A candidate dropped for oversize / parse
    // / non-Anthropic never sets this.
    let mut validated_dead = false;
    // Set when a candidate beat the store but failed the wrong-account guard
    // (identity absent/mismatched) — surfaces the fail-closed wrong-account outcome.
    let mut identity_unconfirmed = false;
    let mut refused = false;
    // D-F7: bounds candidates that reach the authoritative verifier. A metadata
    // retry delay may return Unknown before HTTP; rejected payloads never count.
    let mut validations_performed = 0usize;
    for (idx, cand) in candidates.iter().enumerate() {
        // security H2: reject an oversized payload without parsing.
        if cand.raw_json.len() > MAX_RAW_CANDIDATE_BYTES {
            warn!(
                source_tag = %cand.source_tag,
                "custodian: candidate rejected (raw payload exceeds ceiling)"
            );
            continue;
        }

        // Candidates are sorted freshest-first: once one is not strictly fresher than
        // the store, none of the rest are either → the store is already freshest.
        // They are NEVER adopted, but each is a live session's login that may
        // be an older login of THIS account: owner-verify and record it so the
        // keychain write gate recognises it (see
        // [`record_superseded_owner_verified`]). Only the verdict-less outcome
        // `StoreFreshest`, `SkippedUnknown` (budget/transport) or the shared
        // rate-limit signal can result.
        if let Some(se) = store_expiry {
            if cand.expiry_ms <= se {
                return record_superseded_owner_verified(
                    ctx,
                    &candidates[idx..],
                    validations_performed,
                );
            }
        }

        // Wrong-account guard (fail-closed) — BEFORE the network validation call
        // and the adopt write. `cand.candidate_email` was captured atomically with
        // the keychain bytes under the per-dir swap lock (no lock-free re-read —
        // redteam R1 MED). A foreign-account token (CC in-session `/login` to a
        // different account, or any keychain/binding mismatch) is account-anonymous
        // in its bytes but its dir's `.claude.json` names the wrong account →
        // rejected here, never adopted into the account-global store. A legitimately
        // bound dir whose `.claude.json` is absent / not-yet-CC-populated also fails
        // closed (refused this tick; self-heals once CC writes oauthAccount).
        let candidate_email = cand.candidate_email.as_deref();
        // D-F3: a single-candidate caller that opted out of the prefilter for the
        // absent-self-report case (see `reconcile_candidates_inner`'s doc) skips
        // straight past gate 1 here — but ONLY when `candidate_email` is `None`; a
        // PRESENT-and-mismatched self-report is never bypassed.
        let skip_gate1_for_absent_self_report =
            !require_email_prefilter_on_absent_candidate_email && candidate_email.is_none();
        if !skip_gate1_for_absent_self_report
            && !candidate_account_matches(anchor_email, candidate_email)
        {
            // Distinct reason tags so an operator can tell a benign not-yet-populated
            // dir (candidate_email_absent) or a missing anchor (anchor_email_absent —
            // mint crash window) from a real wrong-account rejection (email_mismatch)
            // — redteam R1 LOW.
            let reason = identity_unconfirmed_reason(
                base_dir,
                cand.handle_dir_tag.as_deref(),
                anchor_email,
                candidate_email,
            );
            warn!(
                account = account.get(),
                source_tag = %cand.source_tag,
                error_kind = "custodian_identity_unconfirmed",
                reason,
                "custodian: candidate rejected — session account identity unconfirmed or mismatched"
            );
            identity_unconfirmed = true;
            continue;
        }

        // Parse (untagged → Anthropic variant for a claudeAiOauth payload). A
        // non-Anthropic or unparseable candidate is skipped (fail-closed), never
        // logged with its bytes.
        let parsed: CredentialFile = match serde_json::from_str(&cand.raw_json) {
            Ok(c) => c,
            Err(_) => {
                warn!(source_tag = %cand.source_tag, "custodian: candidate parse failed");
                continue;
            }
        };
        let anth = match parsed.anthropic() {
            Some(a) => a,
            None => continue, // not an Anthropic credential — skip
        };

        // A candidate already judged Dead/Mismatch within its TTL costs no call,
        // so persistently bad fresher candidates cannot consume the validation
        // budget every tick. The cached verdict still feeds the outcome.
        let neg_key = identity.zip(th_fingerprint(&cand.raw_json));
        if let Some((id, fp)) = neg_key {
            match negative.cached_candidate(id, fp, binding.as_ref(), std::time::Instant::now()) {
                Some(NegativeKind::Dead) => {
                    log_verdict_cache_hit("dead", account, &cand.source_tag);
                    validated_dead = true;
                    continue;
                }
                Some(NegativeKind::Mismatch) => {
                    log_verdict_cache_hit("mismatch", account, &cand.source_tag);
                    identity_unconfirmed = true;
                    continue;
                }
                // Same outcome the live verdict produced: nothing adopted,
                // retry later — but with zero HTTP.
                Some(NegativeKind::Refused) => {
                    log_verdict_cache_hit("refused", account, &cand.source_tag);
                    refused = true;
                    continue;
                }
                None => {}
            }
        }

        // D-F7: enforce the validation budget before entering the verifier.
        // Metadata pacing can return Unknown locally without spending HTTP.
        if validations_performed >= MAX_VALIDATIONS_PER_RECONCILE {
            warn!(
                account = account.get(),
                error_kind = "custodian_validation_budget_exhausted",
                cap = MAX_VALIDATIONS_PER_RECONCILE,
                "custodian: validation cap reached this reconcile; deferring \
                 remaining candidates to the next tick rather than spending \
                 more of the shared rate-limit budget"
            );
            return ReconcileOutcome::SkippedUnknown;
        }
        validations_performed += 1;

        // A0 gate: only a token that is server-confirmed-live AND server-confirmed
        // to BELONG to this account may be adopted. `/api/oauth/profile` proves
        // BOTH (200 ⇒ live; `account.email` ⇒ owner), so it supersedes the
        // usage-based liveness check on the adopt path — the `.claude.json`
        // self-report (`candidate_account_matches`, above) is necessary but not
        // sufficient: a scrambled keychain / swap race can pair a foreign token
        // with the right `.claude.json` email. Verifying the TOKEN's real owner
        // here is the structural fix for the cross-slot credential scramble.
        let (verdict, proof, legacy_proof) = verify_candidate_owner(
            base_dir,
            anth,
            binding.as_ref(),
            http_get,
            &negative.metadata_retry,
        );
        match verdict {
            OwnerVerdict::Match | OwnerVerdict::LegacyOwnUuid => {
                match adopt_candidate(
                    base_dir,
                    account,
                    parsed,
                    store_expiry,
                    binding.as_ref(),
                    proof.as_ref(),
                    legacy_proof.as_ref(),
                ) {
                    Ok(file::GuardedWriteOutcome::Written) => {
                        info!(
                            account = account.get(),
                            source_tag = %cand.source_tag,
                            "custodian: adopted fresher live token into canonical store"
                        );
                        return ReconcileOutcome::Adopted;
                    }
                    // Guard rejected under the lock (a concurrent login/refresh won the
                    // race) — store already fresher; do not keep trying older candidates.
                    Ok(file::GuardedWriteOutcome::NotFresher) => {
                        return ReconcileOutcome::StoreFreshest
                    }
                    Ok(file::GuardedWriteOutcome::BindingChanged) => {
                        warn!(
                            account = account.get(),
                            error_kind = "custodian_adopt_binding_changed",
                            "custodian: candidate custody changed; adoption refused"
                        );
                        return ReconcileOutcome::SkippedUnknown;
                    }
                    Err(_) => {
                        warn!(
                            account = account.get(),
                            error_kind = "custodian_adopt_write_failed",
                            "custodian: adopt write failed (non-fatal)"
                        );
                        return ReconcileOutcome::NotAdopted;
                    }
                }
            }
            // Live but FOREIGN: the token's real owner (per /api/oauth/profile) is a
            // different account than the one being reconciled. NEVER adopt it — this
            // is the exact write that scrambled the store. Reject and keep trying the
            // next-freshest candidate (a correctly-owned one may still be present).
            OwnerVerdict::Mismatch => {
                warn!(
                    account = account.get(),
                    source_tag = %cand.source_tag,
                    error_kind = "custodian_owner_mismatch",
                    "custodian: candidate rejected — token owner != bound account (foreign token)"
                );
                if let Some((id, fp)) = neg_key {
                    negative.remember(id, fp, std::time::Instant::now(), NegativeKind::Mismatch);
                }
                identity_unconfirmed = true;
                continue;
            }
            // Rotated-dead chain: discard and fall back to the next-freshest candidate.
            OwnerVerdict::Dead => {
                if let Some((id, fp)) = neg_key {
                    negative.remember(id, fp, std::time::Instant::now(), NegativeKind::Dead);
                }
                validated_dead = true;
                continue;
            }
            // 429 — propagate to the tick's cross-account IP backoff; stop here.
            OwnerVerdict::RateLimited => return ReconcileOutcome::RateLimited,
            // Deterministic refusal: remember it so later ticks cost no HTTP.
            OwnerVerdict::Refused => {
                if let Some((id, fp)) = neg_key {
                    negative.remember_refused(id, fp, binding.as_ref(), std::time::Instant::now());
                }
                refused = true;
                continue;
            }
            // Transport/5xx/parse/absent-email: cannot confirm ownership; adopt
            // nothing this tick.
            OwnerVerdict::Unknown => return ReconcileOutcome::SkippedUnknown,
        }
    }

    // Loop exhausted with no early return. Outcome precedence: IdentityUnconfirmed
    // is reported ahead of AllDead when both occurred this tick — an unconfirmed-
    // identity candidate is the more actionable operator signal (a possible
    // wrong-account / contaminated dir) than a dead sibling chain (redteam R1 NIT).
    // Both are non-adopting, so precedence is telemetry-only; it never changes the
    // adopt decision.
    if refused {
        ReconcileOutcome::SkippedUnknown
    } else if identity_unconfirmed {
        ReconcileOutcome::IdentityUnconfirmed
    } else if validated_dead {
        ReconcileOutcome::AllDead
    } else {
        ReconcileOutcome::NoEligibleCandidate
    }
}

/// Fixed-vocabulary tag logged when an older login is recorded.
const SUPERSEDED_OWNER_VERIFIED_TAG: &str = "custodian_superseded_owner_verified";

/// Fixed-vocabulary trace of a negative-cache hit: verdict kind, account and
/// source tag only — never token bytes or an email. For readers of the shared
/// cache a cached Mismatch's WARN fires once per TTL (an on-demand view's
/// local Dead is re-validated, so its WARN is not rate-limited that way); this
/// line is the per-hit signal.
fn log_verdict_cache_hit(kind: &'static str, account: AccountNum, source_tag: &str) {
    debug!(
        error_kind = "custodian_verdict_cache_hit",
        verdict = kind,
        account = account.get(),
        source_tag = %source_tag,
        "custodian: candidate skipped on cached verdict"
    );
}

/// Bound on the process-wide negative cache of older-login verdicts.
const NEGATIVE_CACHE_MAX: usize = 256;
/// How long a Mismatch verdict suppresses a re-check of the same
/// (identity, fingerprint). A refresh token's owner never changes, so the TTL
/// only bounds memory/staleness for Mismatch.
const NEGATIVE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);
/// How long a Dead verdict suppresses a re-check. Shorter than the Mismatch
/// TTL: a single transient 401 is indistinguishable from a revoked chain, and
/// caching it for hours could outlast the login's remaining life.
const NEGATIVE_CACHE_DEAD_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Which verdict a negative-cache entry records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NegativeKind {
    Dead,
    Mismatch,
    /// Deterministic legacy refusal, scoped to own credential version and
    /// binding generation. Local like Dead in on-demand views.
    Refused,
}

impl NegativeKind {
    fn ttl(self) -> std::time::Duration {
        match self {
            NegativeKind::Dead | NegativeKind::Refused => NEGATIVE_CACHE_DEAD_TTL,
            NegativeKind::Mismatch => NEGATIVE_CACHE_TTL,
        }
    }
}

/// Fingerprint of a harvested candidate exactly as the keychain write gate
/// computes it (`fingerprint_from_raw_json`: `None` for an empty refresh token).
fn th_fingerprint(raw_json: &str) -> Option<credentials::token_history::Fingerprint> {
    credentials::token_history::fingerprint_from_raw_json(raw_json)
}

type RefusalCacheKey = (
    identity_store::IdentityId,
    credentials::token_history::Fingerprint,
    Option<(ai::CredentialVersion, u64)>,
);

/// Bounded, TTL'd negative verdicts. Dead/Mismatch use (identity, fingerprint);
/// Refused additionally uses the own canonical version and binding generation.
/// An instance owns its own state: production uses the
/// single [`production_negative_cache`]; tests build their own, so no test can
/// evict another's entries.
#[derive(Default)]
pub(crate) struct NegativeCache<'p> {
    /// `Some` for an ON-DEMAND VIEW (see [`NegativeCache::on_demand_view`]):
    /// Mismatch verdicts are read from and written to this shared cache;
    /// Dead verdicts never touch it. `None` for an ordinary (shared or
    /// test-local) cache.
    mismatch_parent: Option<&'p NegativeCache<'p>>,
    /// HTTP pacing only. Contains no Dead/Mismatch/Refused verdicts.
    metadata_retry: std::sync::Arc<MetadataRetryState>,
    map: std::sync::Mutex<
        std::collections::HashMap<RefusalCacheKey, (std::time::Instant, NegativeKind)>,
    >,
}

/// A [`NegativeCache`] configured as an ON-DEMAND VIEW (shared Mismatch, local
/// Dead). The field is private to this module and the only constructors are
/// [`NegativeCache::on_demand_view`] and `NegativeCache::on_demand_view_over` (test-only),
/// so `reconcile_account_on_demand_with` (and auto_rotate's `ReconcileAccountFn`)
/// cannot be handed the production cache or a plain `NegativeCache::new()`.
pub(crate) struct OnDemandView<'p>(NegativeCache<'p>);

impl<'p> std::ops::Deref for OnDemandView<'p> {
    type Target = NegativeCache<'p>;
    fn deref(&self) -> &NegativeCache<'p> {
        &self.0
    }
}

impl<'p> NegativeCache<'p> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A call-local (or per-tick) VIEW over `shared` for ON-DEMAND callers.
    ///
    /// A Mismatch is permanent (key = identity + refresh-token fingerprint: the
    /// token belongs to another account no matter when it is re-asked), so the
    /// view reads Mismatch from `shared` and writes Mismatch to `shared`. A
    /// Dead may be a transient 401, so the view NEVER reads Dead from `shared`
    /// (an earlier tick's transient Dead must not block a last-chance forced
    /// write) and keeps the Dead it learns in its own local map, which dies
    /// with the view and never reaches `shared`.
    ///
    /// Test-only: production code has exactly one constructor,
    /// [`Self::on_demand_view`], which always wraps the process-wide production
    /// cache — so no production path can build a view over an empty or other
    /// cache.
    #[cfg(test)]
    pub(crate) fn on_demand_view_over(shared: &'p NegativeCache<'p>) -> OnDemandView<'p> {
        Self::view_over(shared)
    }

    fn view_over(shared: &'p NegativeCache<'p>) -> OnDemandView<'p> {
        OnDemandView(NegativeCache {
            mismatch_parent: Some(shared),
            metadata_retry: std::sync::Arc::clone(&shared.metadata_retry),
            map: Default::default(),
        })
    }

    /// The on-demand view over the process-wide production cache — the only
    /// view constructor outside tests (see `on_demand_view_over`).
    pub(crate) fn on_demand_view() -> OnDemandView<'static> {
        NegativeCache::view_over(production_negative_cache())
    }

    /// Refusal authority depends on the own canonical token and captured binding.
    /// Dead/Mismatch remain token-specific and use the unscoped key.
    fn cached_candidate(
        &self,
        id: identity_store::IdentityId,
        fp: credentials::token_history::Fingerprint,
        binding: Option<&ai::CapturedBinding>,
        now: std::time::Instant,
    ) -> Option<NegativeKind> {
        self.cached(id, fp, now).or_else(|| {
            let binding = binding?;
            self.cached_scoped(
                id,
                fp,
                Some((binding.credential_version(), binding.generation())),
                now,
            )
        })
    }

    fn remember_refused(
        &self,
        id: identity_store::IdentityId,
        fp: credentials::token_history::Fingerprint,
        binding: Option<&ai::CapturedBinding>,
        now: std::time::Instant,
    ) {
        if let Some(binding) = binding {
            self.remember_scoped(
                id,
                fp,
                Some((binding.credential_version(), binding.generation())),
                now,
                NegativeKind::Refused,
            );
        }
    }

    /// The Dead/Mismatch verdict for (`id`, `fp`) if younger than its TTL.
    pub(crate) fn cached(
        &self,
        id: identity_store::IdentityId,
        fp: credentials::token_history::Fingerprint,
        now: std::time::Instant,
    ) -> Option<NegativeKind> {
        self.cached_scoped(id, fp, None, now)
    }

    fn cached_scoped(
        &self,
        id: identity_store::IdentityId,
        fp: credentials::token_history::Fingerprint,
        scope: Option<(ai::CredentialVersion, u64)>,
        now: std::time::Instant,
    ) -> Option<NegativeKind> {
        if let Some(shared) = self.mismatch_parent {
            // View: a shared Mismatch wins; a shared Dead is never consulted.
            if shared.cached(id, fp, now) == Some(NegativeKind::Mismatch) {
                return Some(NegativeKind::Mismatch);
            }
        }
        let mut c = self.map.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|_, (at, k)| now.saturating_duration_since(*at) < k.ttl());
        c.get(&(id, fp, scope)).map(|(_, k)| *k)
    }

    /// Remember a Dead/Mismatch verdict. Bounded: at the cap the oldest entry
    /// is evicted (an evicted entry only costs one future re-check).
    pub(crate) fn remember(
        &self,
        id: identity_store::IdentityId,
        fp: credentials::token_history::Fingerprint,
        now: std::time::Instant,
        kind: NegativeKind,
    ) {
        self.remember_scoped(id, fp, None, now, kind);
    }

    fn remember_scoped(
        &self,
        id: identity_store::IdentityId,
        fp: credentials::token_history::Fingerprint,
        scope: Option<(ai::CredentialVersion, u64)>,
        now: std::time::Instant,
        kind: NegativeKind,
    ) {
        if let (Some(shared), NegativeKind::Mismatch) = (self.mismatch_parent, kind) {
            shared.remember(id, fp, now, kind);
            return;
        }
        let mut c = self.map.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|_, (at, k)| now.saturating_duration_since(*at) < k.ttl());
        if c.len() >= NEGATIVE_CACHE_MAX && !c.contains_key(&(id, fp, scope)) {
            if let Some(oldest) = c.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| *k) {
                c.remove(&oldest);
            }
        }
        c.insert((id, fp, scope), (now, kind));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// The one process-wide instance production reconciles share.
pub(crate) fn production_negative_cache() -> &'static NegativeCache<'static> {
    static CACHE: std::sync::OnceLock<NegativeCache<'static>> = std::sync::OnceLock::new();
    CACHE.get_or_init(NegativeCache::new)
}

/// For candidates NOT strictly fresher than the store: server-verify (gate 1
/// email prefilter, then [`verify_token_owner`]) that each is an older login of
/// THIS account and persist its fingerprint in the owner-verified list
/// (`token_history::record_owner_verified_if`) — a strong recognition channel
/// for `keychain::decide_cc_keychain_write`. NEVER adopts into the store.
///
/// `ctx.identity` is the `IdentityId` [`reconcile_account`] resolved BEFORE the
/// harvest and the anchor-email read; it is the ONLY identity this function
/// writes under (the list path is keyed by it; the slot is never re-resolved
/// for the path). `None` ⇒ nothing to key by ⇒ nothing recorded. The locked
/// `still_bound` re-check is a conservative early stop (slot no longer maps to
/// the identity ⇒ stop scanning), not serialisation against `csq login`.
///
/// A wrong-account login is never recognised: only `OwnerVerdict::Match`
/// records; Mismatch/Dead/Unknown/gate-1 failure record nothing (fail closed).
/// These cost NO network call: a candidate whose token is already expired (it
/// can only 401), whose fingerprint is the store's own, already recorded in the
/// owner-verified list, or in `ctx.negative` (Dead within
/// [`NEGATIVE_CACHE_DEAD_TTL`], Mismatch within [`NEGATIVE_CACHE_TTL`], at most
/// [`NEGATIVE_CACHE_MAX`] entries). The ordered token history is deliberately
/// NOT a skip channel: the write gate consults it for an older login only when
/// the fingerprint sits strictly before the store's own fingerprint in the
/// bounded history and, for a history-only match, the keychain token's expiry
/// is no later than the intended token's — so it is not a reliable skip
/// channel, and skipping on it could re-create the permanent swap refusal; a
/// recorded fingerprint is free thereafter.
/// Every other candidate spends from the SAME `MAX_VALIDATIONS_PER_RECONCILE`
/// budget as the fresher path (`validations_performed` carries over).
///
/// Outcome, exactly: budget exhaustion, or any Unknown verdict / failed record
/// (`deferred`) ⇒ `SkippedUnknown` (retry next tick), including when a rebound
/// slot stops the scan after `deferred` was set; `RateLimited` ⇒ `RateLimited`
/// (always wins, the tick feeds the shared gate); otherwise `StoreFreshest`.
fn record_superseded_owner_verified(
    ctx: &ReconcileCtx<'_>,
    older: &[credentials::keychain::HarvestCandidate],
    mut validations_performed: usize,
) -> ReconcileOutcome {
    use crate::credentials::token_history as th;
    let ReconcileCtx {
        base_dir,
        account,
        identity,
        anchor_email,
        ref binding,
        http_get,
        require_email_prefilter_on_absent_candidate_email,
        negative,
    } = *ctx;
    let Some(uuid) = identity else {
        // No identity to key the list by — nothing to record against.
        return ReconcileOutcome::StoreFreshest;
    };
    let store_fp = file::load(&identity_store::credentials_path_for(base_dir, uuid))
        .ok()
        .and_then(|c| th::fingerprint_from_credential_file(&c));
    let mut known = th::read_owner_verified_for_slot(base_dir, account);
    let now_ms = credentials::keychain::now_ms();
    let mut deferred = false;
    for cand in older {
        if cand.raw_json.len() > MAX_RAW_CANDIDATE_BYTES {
            warn!(
                source_tag = %cand.source_tag,
                "custodian: candidate rejected (raw payload exceeds ceiling)"
            );
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<CredentialFile>(&cand.raw_json) else {
            warn!(source_tag = %cand.source_tag, "custodian: candidate parse failed");
            continue;
        };
        let Some(anth) = parsed.anthropic() else {
            continue; // not an Anthropic credential — skip
        };
        // Fingerprint EXACTLY as the write gate does (`fingerprint_from_raw_json`
        // returns None for an empty refresh token): a fingerprint the gate cannot
        // compute can never be recognised, so recording it would be dead data.
        let Some(fp) = th::fingerprint_from_raw_json(&cand.raw_json) else {
            continue;
        };
        // An expired access token can only 401 — no verdict is obtainable.
        if anth.claude_ai_oauth.expires_at <= now_ms {
            continue;
        }
        if Some(fp) == store_fp || known.contains(&fp) {
            continue; // already recognised
        }
        if let Some(kind) =
            negative.cached_candidate(uuid, fp, binding.as_ref(), std::time::Instant::now())
        {
            log_verdict_cache_hit(
                match kind {
                    NegativeKind::Dead => "dead",
                    NegativeKind::Mismatch => "mismatch",
                    NegativeKind::Refused => "refused",
                },
                account,
                &cand.source_tag,
            );
            if kind == NegativeKind::Refused {
                deferred = true; // same as the live verdict: retry later
            }
            continue; // already judged Dead/Mismatch/Refused
        }
        let candidate_email = cand.candidate_email.as_deref();
        let skip_gate1 =
            !require_email_prefilter_on_absent_candidate_email && candidate_email.is_none();
        if !skip_gate1 && !candidate_account_matches(anchor_email, candidate_email) {
            let reason = identity_unconfirmed_reason(
                base_dir,
                cand.handle_dir_tag.as_deref(),
                anchor_email,
                candidate_email,
            );
            warn!(
                account = account.get(),
                source_tag = %cand.source_tag,
                error_kind = "custodian_identity_unconfirmed",
                reason,
                "custodian: older candidate rejected — session account identity unconfirmed or mismatched"
            );
            continue;
        }
        if validations_performed >= MAX_VALIDATIONS_PER_RECONCILE {
            warn!(
                account = account.get(),
                error_kind = "custodian_validation_budget_exhausted",
                cap = MAX_VALIDATIONS_PER_RECONCILE,
                "custodian: validation cap reached; deferring older candidates"
            );
            return ReconcileOutcome::SkippedUnknown;
        }
        validations_performed += 1;
        let (verdict, proof, _) = verify_candidate_owner(
            base_dir,
            anth,
            binding.as_ref(),
            http_get,
            &negative.metadata_retry,
        );
        match verdict {
            OwnerVerdict::LegacyOwnUuid => {
                // Equal email is not organization authority for v2 history.
                // Keep the verified candidate confined to its own UUID adopt
                // path; older candidates cannot grant cross-context recognition.
                warn!(
                    account = account.get(),
                    error_kind = "custodian_legacy_history_unconfirmed",
                    "custodian: legacy candidate cannot publish organization owner history"
                );
                deferred = true;
            }
            OwnerVerdict::Match => {
                let recorded = match (binding.as_ref(), proof.as_ref()) {
                    (Some(binding), Some(proof)) => {
                        th::record_owner_verified_v2(base_dir, binding, proof)
                    }
                    _ => th::OwnerVerifiedRecord::Failed,
                };
                match recorded {
                    th::OwnerVerifiedRecord::Written => {
                        known.push(fp);
                        info!(
                            account = account.get(),
                            source_tag = %cand.source_tag,
                            event = SUPERSEDED_OWNER_VERIFIED_TAG,
                            "custodian: older login owner-verified as this account's (not adopted)"
                        );
                    }
                    // Slot rebound to another identity mid-reconcile: the
                    // anchor email no longer describes this slot. Stop.
                    th::OwnerVerifiedRecord::Rebound => {
                        return if deferred {
                            ReconcileOutcome::SkippedUnknown
                        } else {
                            ReconcileOutcome::StoreFreshest
                        };
                    }
                    // Identity dir gone / lock or write failure: nothing was
                    // recorded, so this must retry next tick (never read as
                    // "recorded" or "judged"); the binding is unchanged, so
                    // later candidates may still be worth checking.
                    th::OwnerVerifiedRecord::Failed => deferred = true,
                }
            }
            OwnerVerdict::RateLimited => return ReconcileOutcome::RateLimited,
            OwnerVerdict::Unknown => deferred = true, // transport trouble: retry next tick
            OwnerVerdict::Refused => {
                negative.remember_refused(uuid, fp, binding.as_ref(), std::time::Instant::now());
                deferred = true;
            }
            OwnerVerdict::Mismatch => {
                negative.remember(uuid, fp, std::time::Instant::now(), NegativeKind::Mismatch);
            }
            OwnerVerdict::Dead => {
                negative.remember(uuid, fp, std::time::Instant::now(), NegativeKind::Dead);
            }
        }
    }
    if deferred {
        ReconcileOutcome::SkippedUnknown
    } else {
        ReconcileOutcome::StoreFreshest
    }
}

#[cfg(test)]
thread_local! {
    static ADOPT_AFTER_WRITE_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Adopt a validated-live candidate into the canonical store. Returns
/// `GuardedWriteOutcome::Written`, `NotFresher` or `BindingChanged` according to
/// the writer's checks under the locks. On a successful adopt, clears any stale
/// `broker_failed` sentinel (sentinel-clearing-parity: adopt is a new "account
/// healthy" success boundary — without this, `csq doctor` would keep reporting
/// LOGIN-NEEDED on a now-healthy account; the an internal ticket class).
///
/// **Subscription metadata (Rule 5)** is preserved by the write chokepoint itself:
/// `save_anthropic_canonical_guarded_locked` → `save_uuid_credentials` →
/// `save_uuid_credentials_impl` → `preserve_subscription_metadata`. The guarded
/// writer holds the profiles, slot and canonical locks while preservation reads
/// the current credential and backfills absent `subscription_type` /
/// `rate_limit_tier`; the custodian does not merge a pre-lock snapshot.
fn adopt_candidate(
    base_dir: &Path,
    account: AccountNum,
    parsed: CredentialFile,
    store_expiry: Option<u64>,
    binding: Option<&ai::CapturedBinding>,
    proof: Option<&ai::VerifiedAnthropicContext>,
    legacy_proof: Option<&ai::LegacyOwnUuidProof>,
) -> Result<file::GuardedWriteOutcome, crate::error::CredentialError> {
    // TOCTOU-guarded write: re-reads the store expiry under the per-account mutex and
    // writes only if still strictly fresher than both the pre-lock baseline and the
    // current store. Re-serializes the canonical field set (never the raw bytes).
    let (Some(binding), Some(proof), Some(anth)) = (binding, proof, parsed.anthropic()) else {
        return Ok(file::GuardedWriteOutcome::BindingChanged);
    };
    let witness = match binding.context() {
        ai::StoredAnthropicContext::Known(_) => file::AnthropicWriteWitness::Profile(proof),
        // The legacy witness is minted only after the identity's own token was
        // verified (verify_candidate_owner); no proof, no adoption.
        ai::StoredAnthropicContext::LegacyUnknown => match legacy_proof {
            Some(legacy) => file::AnthropicWriteWitness::LegacyOwnUuid(legacy),
            None => return Ok(file::GuardedWriteOutcome::BindingChanged),
        },
    };
    let outcome = {
        let profiles = ProfilesFileLock::try_acquire(base_dir)
            .map_err(|_| ai::credential_refusal())?
            .ok_or_else(ai::credential_refusal)?;
        file::save_anthropic_canonical_guarded_locked(
            &profiles,
            base_dir,
            binding,
            anth,
            witness,
            Some(store_expiry.unwrap_or(0)),
        )?
    };
    if matches!(outcome, file::GuardedWriteOutcome::Written) {
        #[cfg(test)]
        ADOPT_AFTER_WRITE_TEST_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        clear_adopted_broker_failure(base_dir, account, binding, proof);
    }
    Ok(outcome)
}

fn clear_adopted_broker_failure(
    base: &Path,
    account: AccountNum,
    original: &ai::CapturedBinding,
    saved: &ai::VerifiedAnthropicContext,
) {
    if account != original.slot() {
        return;
    }
    let Ok(Some(profiles)) = ProfilesFileLock::try_acquire(base) else {
        return;
    };
    if !ai::binding_custody_matches_locked(&profiles, base, original).unwrap_or(false) {
        return;
    }
    let Ok(current) = ai::capture_anthropic_binding_locked(&profiles, base, account) else {
        return;
    };
    if current.credential_version() == saved.credential_version() {
        sentinel::clear_broker_failed(base, account);
    }
}

/// `keychain-fix-r8.md` C-F3 — single-candidate adopt for the dead-handle-dir
/// reaper and the pending-clear retry queue
/// (`credentials::keychain::decide_and_clear_dead_handle`'s `try_adopt`
/// parameter). Those callers are not harvesting across every live handle dir
/// for an account like [`reconcile_account`] does — they hold exactly ONE
/// candidate (the keychain item about to be deleted), so there is nothing to
/// compare it against for "freshest across many": `store_expiry` is passed
/// as `None`, which skips [`reconcile_candidates_inner`]'s freshest-cutoff
/// early return.
///
/// The SAME authoritative `verify_token_owner` liveness+ownership check
/// (gate 2) always runs. Gate 1 (the local `.claude.json` self-report
/// pre-filter, [`candidate_account_matches`]) is DIFFERENT here from
/// [`reconcile_account`]'s harvest-across-many path (`keychain-fix-r9.md`
/// D-F3): this function passes `require_email_prefilter_on_absent_candidate_email
/// = false`, so when `candidate.candidate_email` is `None` gate 1 is skipped
/// for this candidate and gate 2 alone decides. A PRESENT-but-mismatched
/// self-report is still rejected by gate 1 regardless. This caller holds
/// exactly one already-known candidate — the keychain item about to be
/// deleted — so an absent self-report here is not the same ambiguity as an
/// absent self-report in a multi-candidate harvest sweep, and refusing to
/// adopt on that absence alone would defeat the reaper/retry path on exactly
/// the entries it exists to rescue.
///
/// Returns `true` ONLY on [`ReconcileOutcome::Adopted`] — every other
/// outcome (identity unconfirmed, dead, rate-limited, transport-unknown, or
/// the store already fresher) means "do not delete this item"; the caller
/// maps that to its own keep-and-re-queue disposition.
///
/// `keychain-fix-r10.md` S-M-1/C-B2 (item 2), C-B1/S-L-5: honours the SAME
/// shared, IP-wide validation gate `refresher.rs`'s custodian call and
/// `auto_rotate.rs`'s opportunistic harvest already do (D-F6) — a 429
/// observed anywhere means this call's own live validation HTTP request
/// would 429 too, so it returns `false` (keep, re-queue) WITHOUT making
/// that request at all. And on a fresh `RateLimited` observed by THIS call,
/// it marks the same shared gate so the next caller on any of the three
/// surfaces short-circuits too, rather than each rediscovering the 429
/// independently.
pub(crate) fn adopt_single_candidate_before_delete(
    base_dir: &Path,
    account: AccountNum,
    candidate: &crate::credentials::keychain::HarvestCandidate,
    http_get: &HttpGetFn,
) -> bool {
    adopt_single_candidate_before_delete_with_gate(
        base_dir,
        account,
        candidate,
        http_get,
        &crate::daemon::server::harvest_gate::ip_rate_limit_gate(),
    )
}

/// [`adopt_single_candidate_before_delete`]'s real body, with the shared
/// gate made an explicit, injectable parameter (`keychain-fix-r10.md`
/// S-M-1/C-B2 item 2, C-B1/S-L-5) — mirroring `daemon::server::run_with`'s
/// own production-singleton-vs-fresh-gate split. A test passes a fresh
/// [`crate::daemon::server::harvest_gate::new_ip_rate_limit_gate`] so it can
/// assert this call marked (or honoured) the gate without touching the
/// process-wide singleton every OTHER test in this binary also reads
/// (`ip_rate_limit_gate`'s own doc: 600s cooldown, shared across the whole
/// test binary).
pub(crate) fn adopt_single_candidate_before_delete_with_gate(
    base_dir: &Path,
    account: AccountNum,
    candidate: &crate::credentials::keychain::HarvestCandidate,
    http_get: &HttpGetFn,
    gate: &crate::daemon::server::harvest_gate::IpRateLimitGate,
) -> bool {
    if crate::daemon::server::harvest_gate::gate_is_rate_limited(gate) {
        return false;
    }
    let binding = match ai::capture_anthropic_binding(base_dir, account) {
        Ok(binding) => Some(binding),
        Err(_) => {
            warn!(
                account = account.get(),
                error_kind = "custodian_binding_unavailable",
                "custodian: delete-time candidate custody unavailable; adoption refused"
            );
            return false;
        }
    };
    let identity = binding.as_ref().map(ai::CapturedBinding::identity);
    let anchor_email =
        identity.and_then(|uuid| identity_store::read_identity_email(base_dir, uuid));
    let ctx = ReconcileCtx {
        base_dir,
        account,
        identity,
        anchor_email: anchor_email.as_deref(),
        binding,
        http_get,
        // D-F3: an absent `candidate_email` on this single, already-known
        // candidate must not fail-closed before ever asking the server —
        // `verify_token_owner` (gate 2) is the authoritative check here.
        require_email_prefilter_on_absent_candidate_email: false,
        // A single already-known candidate about to be deleted: it never
        // consults or feeds the harvest path's verdict cache (a cached Dead
        // from a transient 401 must not suppress this last-chance check).
        negative: &NegativeCache::new(),
    };
    let outcome = reconcile_candidates_inner(&ctx, std::slice::from_ref(candidate), None);
    if matches!(outcome, ReconcileOutcome::RateLimited) {
        crate::daemon::server::harvest_gate::gate_mark_rate_limited(gate);
    }
    matches!(outcome, ReconcileOutcome::Adopted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn http_status(status: u16, body: impl Into<Vec<u8>>) -> HttpGetFn {
        let body: Vec<u8> = body.into();
        Arc::new(move |_url: &str, _tok: &str, _hdrs: &[(&str, &str)]| Ok((status, body.clone())))
    }

    /// Body shape returned by `/api/oauth/profile` for a given account email.
    fn profile_body_org(email: &str, org: &str) -> Vec<u8> {
        format!(r#"{{"account":{{"uuid":"11111111-1111-4111-8111-111111111111","email":"{email}"}},"organization":{{"uuid":"{org}"}}}}"#).into_bytes()
    }
    const HELD_ORG: &str = "22222222-2222-4222-8222-222222222222";
    const FREE_ORG: &str = "33333333-3333-4333-8333-333333333333";
    fn profile_body(email: &str) -> Vec<u8> {
        format!(r#"{{"account":{{"uuid":"11111111-1111-4111-8111-111111111111","email":"{email}"}},"organization":{{"uuid":"22222222-2222-4222-8222-222222222222"}}}}"#).into_bytes()
    }

    #[test]
    fn owner_200_matching_email_is_match() {
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Match
        );
    }

    #[test]
    fn owner_200_matching_email_is_case_insensitive_and_trimmed() {
        let g = http_status(200, profile_body("Jack@ResearchRoom.SG"));
        assert_eq!(
            verify_token_owner("tok", Some("  jack@researchroom.sg  "), &g),
            OwnerVerdict::Match
        );
    }

    #[test]
    fn owner_200_foreign_email_is_mismatch() {
        // The exact scramble: the live token belongs to integrum, but the account
        // being reconciled is researchroom. MUST reject.
        let g = http_status(200, profile_body("jack@integrum.global"));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Mismatch
        );
    }

    #[test]
    fn owner_401_is_dead() {
        let g = http_status(401, b"{}");
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Dead
        );
    }

    #[test]
    fn owner_429_is_rate_limited() {
        let g = http_status(429, b"");
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::RateLimited
        );
    }

    #[test]
    fn owner_500_is_unknown() {
        let g = http_status(500, b"err");
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_transport_error_is_unknown() {
        let g: HttpGetFn = Arc::new(|_u: &str, _t: &str, _h: &[(&str, &str)]| Err("boom".into()));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_absent_anchor_is_unknown_fail_closed() {
        // No anchor to compare against → cannot confirm ownership → fail-closed.
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert_eq!(verify_token_owner("tok", None, &g), OwnerVerdict::Unknown);
        assert_eq!(
            verify_token_owner("tok", Some("   "), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_200_missing_account_email_is_unknown_fail_closed() {
        let g = http_status(200, br#"{"account":{"uuid":"u"}}"#);
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_200_empty_account_email_is_unknown_not_mismatch() {
        // An empty/whitespace `account.email` is "cannot confirm" (Unknown), NOT
        // "confirmed foreign" (Mismatch) — both fail-closed, but the classification
        // must stay honest (security review L1).
        let g = http_status(200, profile_body(""));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
        let g_ws = http_status(200, profile_body("   "));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g_ws),
            OwnerVerdict::Unknown
        );
    }

    // ── check_slot_store_token_ownership (doctor/repair detector) ─────────────

    /// Materialize slot `slot` → uuid with an `identity.json` anchor + an
    /// Anthropic store `credentials.json` carrying `token`.
    fn setup_slot_store(
        base: &Path,
        slot: u16,
        uuid: identity_store::IdentityId,
        anchor_email: &str,
        token: &str,
    ) {
        let path = profiles::profiles_path(base);
        let mut pf = if path.exists() {
            profiles::load(&path).unwrap()
        } else {
            profiles::ProfilesFile::empty()
        };
        pf.by_slot.insert(slot.to_string(), uuid);
        pf.by_email.insert(anchor_email.to_string(), uuid);
        pf.anthropic_contexts
            .retain(|entry| entry.identity_uuid != uuid);
        pf.anthropic_contexts.push(ai::AnthropicContextEntry {
            email: anchor_email.to_string(),
            account_uuid: uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            organization_uuid: uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .unwrap(),
            identity_uuid: uuid,
            extra: Default::default(),
        });
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        let cred_path = identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
        crate::platform::fs::secure_dir(cred_path.parent().unwrap()).unwrap();
        // identity.json (the anchor) lives beside credentials.json.
        std::fs::write(
            cred_path.parent().unwrap().join("identity.json"),
            format!(
                r#"{{"email":{},"provider":"anthropic","created_at":"t","key_id":null,"account_uuid":"11111111-1111-4111-8111-111111111111","organization_uuid":"22222222-2222-4222-8222-222222222222"}}"#,
                serde_json::to_string(anchor_email).unwrap()
            ),
        )
        .unwrap();

        let cred = CredentialFile::Anthropic(crate::credentials::AnthropicCredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: crate::types::AccessToken::new(token.into()),
                refresh_token: crate::types::RefreshToken::new("sk-ant-ort01-x".into()),
                expires_at: 4_102_444_800_000,
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: None,
                extra: std::collections::HashMap::new(),
            },
            extra: std::collections::HashMap::new(),
        });
        file::save(&cred_path, &cred).unwrap();
        crate::platform::fs::secure_file(&cred_path.parent().unwrap().join("identity.json"))
            .unwrap();
    }

    /// Exercise the actual migration writer, not Known publication followed by
    /// stripping its context. Established legacy namespaces may be mode 0755.
    fn setup_legacy_slot_store(
        base: &Path,
        slot: AccountNum,
        email: &str,
        token: &str,
    ) -> identity_store::IdentityId {
        let config = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&config).unwrap();
        profiles::save(
            &profiles::profiles_path(base),
            &profiles::ProfilesFile::empty(),
        )
        .unwrap();
        let creds: CredentialFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken":token,"refreshToken":"fake-legacy-refresh",
                "expiresAt":4102444800000u64,"scopes":["user:inference"]},
            "oauthAccount":{"emailAddress":email}
        }))
        .unwrap();
        file::save(&file::canonical_path(base, slot), &creds).unwrap();
        file::save(&config.join(".credentials.json"), &creds).unwrap();
        let minted = crate::daemon::identity_mint::run_if_unsentineled(base).unwrap();
        assert!(minted.slot_errors.is_empty());
        assert_eq!(minted.slots_fresh, 1);
        let id = profiles::resolve_slot_to_uuid(base, slot.get()).unwrap();
        file::save(&identity_store::credentials_path_for(base, id), &creds).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for directory in [
                base.join("identities"),
                identity_store::identity_path(base, id),
            ] {
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
        }
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert!(pf.anthropic_contexts.is_empty());
        assert!(matches!(
            ai::capture_anthropic_binding(base, slot).unwrap().context(),
            ai::StoredAnthropicContext::LegacyUnknown
        ));
        id
    }

    #[test]
    fn slot_ownership_owned_when_store_token_matches_anchor() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-store",
        );
        // /api/oauth/profile reports the SAME account as the anchor.
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Owned
        );
    }

    #[test]
    fn slot_ownership_org_identity_regression_same_email_different_organization_is_contaminated() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        let email = "org-identity@example.test";
        let account_uuid = "11111111-1111-4111-8111-111111111111";
        let expected_org_uuid = "22222222-2222-4222-8222-222222222222";
        let different_org_uuid = "33333333-3333-4333-8333-333333333333";
        let token = "sk-ant-oat01-FAKETESTtity-fixture";
        setup_slot_store(dir.path(), 2, uuid, email, token);

        // Mirror the Anthropic mint path: both profile maps and canonical
        // identity metadata are present. Provider UUIDs are not the local UUID.
        let profiles_path = profiles::profiles_path(dir.path());
        let mut pf = profiles::load(&profiles_path).unwrap();
        pf.by_email.insert(email.to_string(), uuid);
        profiles::save(&profiles_path, &pf).unwrap();
        let identity_path = identity_store::credentials_path_for(dir.path(), uuid)
            .parent()
            .unwrap()
            .join("identity.json");
        std::fs::write(
            identity_path,
            serde_json::to_vec(&serde_json::json!({
                "email": email,
                "provider": "anthropic",
                "created_at": "2026-01-01T00:00:00Z",
                "key_id": null,
                "account_uuid": account_uuid,
                "organization_uuid": expected_org_uuid,
            }))
            .unwrap(),
        )
        .unwrap();

        // Native Claude 2.1.296 reads account.uuid/email and organization.uuid
        // from /api/oauth/profile (vendor-static-context.json). A matching
        // email/account cannot prove ownership of a different organization.
        let body = serde_json::to_vec(&serde_json::json!({
            "account": { "uuid": account_uuid, "email": email },
            "organization": { "uuid": different_org_uuid },
        }))
        .unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let g: HttpGetFn = Arc::new(move |url, actual_token, _headers| {
            assert_eq!(url, format!("{ANTHROPIC_BASE_URL}/api/oauth/profile"));
            assert_eq!(actual_token, token);
            observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((200, body.clone()))
        });
        let ownership =
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(ownership, SlotOwnership::Contaminated);
    }

    #[test]
    fn slot_ownership_contaminated_when_store_token_is_foreign() {
        // The exact an internal ticket scramble: slot 2 is bound to researchroom, but its STORE
        // token actually belongs to integrum → the detector MUST flag it.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-foreign",
        );
        let g = http_status(200, profile_body("jack@integrum.global"));
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Contaminated
        );
    }

    #[test]
    fn slot_ownership_unknown_when_no_store_token() {
        // No profiles / no store cred → cannot confirm → Unknown (never a false
        // contamination alarm). The http_get must not even be consulted.
        let dir = tempfile::TempDir::new().unwrap();
        let g: HttpGetFn = Arc::new(|_u: &str, _t: &str, _h: &[(&str, &str)]| {
            panic!("http_get must not be called")
        });
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Unknown
        );
    }

    #[test]
    fn slot_ownership_unknown_on_401_not_contaminated() {
        // A revoked store token (401) is "cannot confirm ownership", NOT foreign.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-dead",
        );
        let g = http_status(401, b"{}".to_vec());
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Unknown
        );
    }

    // ── slot_store_credential_path (shared detector/heal path resolution) ─────

    #[test]
    fn store_path_is_uuid_keyed_when_slot_has_uuid_and_matches_detector_read() {
        // The heal MUST clear the SAME file the detector read. `setup_slot_store`
        // writes the store at the UUID-keyed path; `slot_store_credential_path`
        // must resolve to exactly that file (and it must exist).
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-store",
        );
        let resolved = slot_store_credential_path(dir.path(), AccountNum::try_from(2u16).unwrap());
        assert_eq!(
            resolved,
            identity_store::credentials_path_for(dir.path(), uuid),
            "must resolve to the UUID-keyed store the detector reads"
        );
        assert!(
            resolved.exists(),
            "the resolved store file must be the real one"
        );
    }

    #[test]
    fn store_path_falls_back_to_legacy_when_no_uuid_mapping() {
        // A legacy slot with no `by_slot` UUID resolves to the numeric canonical
        // path (`credentials/N.json`) — the same fallback the detector uses.
        let dir = tempfile::TempDir::new().unwrap();
        let resolved = slot_store_credential_path(dir.path(), AccountNum::try_from(5u16).unwrap());
        assert_eq!(
            resolved,
            file::canonical_path(dir.path(), AccountNum::try_from(5u16).unwrap()),
            "no UUID → legacy numeric canonical path"
        );
    }

    // ── Wrong-account guard (candidate_account_matches) ───────────────────────

    #[test]
    fn account_matches_when_both_present_and_equal() {
        assert!(candidate_account_matches(
            Some("user@example.com"),
            Some("user@example.com")
        ));
    }

    #[test]
    fn account_matches_is_case_insensitive() {
        // OAuth emails are case-insensitive; CC and the mint may differ in case.
        assert!(candidate_account_matches(
            Some("User@Example.COM"),
            Some("user@example.com")
        ));
    }

    #[test]
    fn account_mismatch_rejected() {
        // The catastrophic case: a live token whose session is on a DIFFERENT
        // account than the one being reconciled. Fail-closed.
        assert!(!candidate_account_matches(
            Some("bound@example.com"),
            Some("foreign@example.com")
        ));
    }

    #[test]
    fn account_unconfirmed_when_anchor_absent() {
        // No identity.json email for the bound account → cannot confirm → refuse.
        assert!(!candidate_account_matches(None, Some("user@example.com")));
    }

    #[test]
    fn account_unconfirmed_when_candidate_absent() {
        // The candidate dir's .claude.json has no oauthAccount email → refuse.
        assert!(!candidate_account_matches(Some("user@example.com"), None));
    }

    #[test]
    fn account_unconfirmed_when_both_absent() {
        assert!(!candidate_account_matches(None, None));
    }

    #[test]
    fn account_unconfirmed_when_anchor_empty() {
        // Defensive: an empty anchor string must never match an empty candidate.
        assert!(!candidate_account_matches(Some(""), Some("")));
        assert!(!candidate_account_matches(
            Some(""),
            Some("user@example.com")
        ));
    }

    #[test]
    fn account_matches_trims_whitespace() {
        // Anchor is trim+lowercased at mint; candidate is CC-raw. Trimming both
        // makes the comparison symmetric so a stray space/newline does not
        // false-reject a legitimate same-account token (redteam R1 LOW).
        assert!(candidate_account_matches(
            Some("user@example.com"),
            Some("  user@example.com\n")
        ));
    }

    #[test]
    fn account_unconfirmed_when_candidate_empty_or_whitespace() {
        // Symmetric empty rejection (redteam R1 NIT): an empty/whitespace
        // candidate must never match, regardless of the anchor.
        assert!(!candidate_account_matches(
            Some("user@example.com"),
            Some("")
        ));
        assert!(!candidate_account_matches(
            Some("user@example.com"),
            Some("   ")
        ));
    }

    // ── reconcile_candidates wiring (the guard's integration path) ────────────
    //
    // These exercise the actual decision loop (anchor vs cand.candidate_email →
    // skip/adopt → outcome), not just the pure matcher — the gap redteam R1
    // flagged HIGH. harvest itself is macOS-only, so the loop was factored out to
    // consume an already-built candidate list and is testable on every platform.

    fn mk_candidate(
        email: Option<&str>,
        expiry_ms: u64,
    ) -> crate::credentials::keychain::HarvestCandidate {
        crate::credentials::keychain::HarvestCandidate {
            raw_json: r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-test","refreshToken":"sk-ant-ort01-test","expiresAt":4102444800000}}"#.to_string().into(),
            expiry_ms,
            source_tag: "term-1".to_string(),
            candidate_email: email.map(str::to_owned),
            handle_dir_tag: Some("term-1".to_string()),
        }
    }

    /// An http_get that fails the test if validation is ever invoked — proves a
    /// guard-rejected candidate never reaches the network call (or the adopt write).
    fn never_called() -> HttpGetFn {
        Arc::new(|_u: &str, _t: &str, _h: &[(&str, &str)]| {
            panic!("validation MUST NOT run for a candidate rejected by the wrong-account guard")
        })
    }

    /// Fresher-path wiring helper: genuine captured Known authority for the
    /// token-profile path, while identity=None keeps older-history recording
    /// outside these loop tests. An absent anchor remains unprovisioned.
    fn reconcile_no_identity(
        base: &Path,
        acct: AccountNum,
        anchor: Option<&str>,
        cands: &[credentials::keychain::HarvestCandidate],
        store_expiry: Option<u64>,
        http: &HttpGetFn,
    ) -> ReconcileOutcome {
        if let Some(email) = anchor {
            setup_slot_store(
                base,
                acct.get(),
                identity_store::IdentityId::new_v4(),
                email,
                "fake-prior",
            );
        }
        let neg = NegativeCache::new();
        let ctx = ReconcileCtx {
            base_dir: base,
            account: acct,
            identity: None,
            anchor_email: anchor,
            binding: ai::capture_anthropic_binding(base, acct).ok(),
            http_get: http,
            require_email_prefilter_on_absent_candidate_email: true,
            negative: &neg,
        };
        reconcile_candidates(&ctx, cands, store_expiry)
    }

    #[test]
    fn reconcile_candidates_rejects_mismatched_identity() {
        // The catastrophic case end-to-end: a live token whose dir names a
        // FOREIGN account is refused → IdentityUnconfirmed, store untouched,
        // validation never called.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("foreign@example.com"), 4102444800000)];
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &never_called(),
        );
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_rejects_absent_candidate_email() {
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(None, 4102444800000)];
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &never_called(),
        );
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_rejects_absent_anchor() {
        // Mint crash window: no identity.json email → cannot confirm → refuse.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("bound@example.com"), 4102444800000)];
        let out = reconcile_no_identity(dir.path(), acct, None, &cands, None, &never_called());
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_matched_candidate_reaches_validation() {
        // Positive wiring: a same-account candidate (case-insensitive) PASSES the
        // guard and reaches validation — proven by 401→Dead→AllDead (the network
        // call ran). The guard does not block legitimate same-account healing.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("Bound@Example.com"), 4102444800000)];
        let dead = http_status(401, b"{}");
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &dead,
        );
        assert_eq!(out, ReconcileOutcome::AllDead);
    }

    /// Counts calls, always returning 401 (Dead) — used by the D-F7 cap test
    /// below to prove the loop stops calling `verify_token_owner` at the cap
    /// rather than continuing through every remaining candidate.
    fn counting_dead(counter: Arc<std::sync::atomic::AtomicUsize>) -> HttpGetFn {
        Arc::new(move |_url: &str, _tok: &str, _hdrs: &[(&str, &str)]| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((401u16, b"{}".to_vec()))
        })
    }

    #[test]
    fn reconcile_candidates_stops_after_the_validation_cap_is_reached() {
        // D-F7: 3 candidates, all passing gate 1 and parsing cleanly — without
        // the cap every one of them would reach `verify_token_owner` (a live
        // network call). With `MAX_VALIDATIONS_PER_RECONCILE` (2) enforced,
        // only the two freshest do; the 3rd is deferred via `SkippedUnknown`
        // rather than spending a 3rd call against the shared, IP-wide
        // rate-limit budget (D-F6).
        //
        // RED: deleting the `if validations_performed >= ... { return ... }`
        // check makes `calls.load(..)` come back `3`, not `2`, and the
        // outcome `AllDead` (all three actually validated), not
        // `SkippedUnknown`.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![
            mk_candidate(Some("bound@example.com"), 4_102_444_800_000),
            mk_candidate(Some("bound@example.com"), 4_102_444_700_000),
            mk_candidate(Some("bound@example.com"), 4_102_444_600_000),
        ];
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &counting_dead(Arc::clone(&calls)),
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            MAX_VALIDATIONS_PER_RECONCILE,
            "exactly the capped number of live validation calls must run, \
             never all 3 candidates"
        );
        assert_eq!(
            out,
            ReconcileOutcome::SkippedUnknown,
            "hitting the cap without an Adopted/Mismatch verdict defers the \
             remaining candidates to the next tick"
        );
    }

    #[test]
    fn reconcile_candidates_rejects_foreign_token_owner_past_gate1() {
        // Gate 2 end-to-end — THE cross-slot scramble case: the candidate's
        // `.claude.json` SELF-REPORTS the bound account (passes gate 1
        // `candidate_account_matches`), but the harvested TOKEN's real owner (per
        // `/api/oauth/profile`) is FOREIGN. verify_token_owner returns Mismatch →
        // the candidate is rejected, the store is NEVER written, outcome is
        // IdentityUnconfirmed. This is the exact write the old code performed and
        // this fix prevents.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("bound@example.com"), 4102444800000)];
        // Passes gate 1 (self-report == anchor), but the profile endpoint reports the
        // token actually belongs to a DIFFERENT account.
        let foreign = http_status(200, profile_body("foreign@example.com"));
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &foreign,
        );
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_owner_mismatch_does_not_abort_scan() {
        // A foreign fresher token no longer aborts the scan: gate-2 Mismatch does
        // `continue`, so a later candidate is still evaluated. Proven by the call
        // COUNT reaching 2 (both candidates hit the network) — the outcome itself
        // stays IdentityUnconfirmed because that precedence outranks the 2nd
        // candidate's Dead verdict.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![
            cand_rt("rt-foreign", Some("bound@example.com"), 4102444800001), // freshest, foreign token
            cand_rt("rt-owned-dead", Some("bound@example.com"), 4102444800000), // owned-report, 401 dead
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let g: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            let n = calls_c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // gate-1 passes; gate-2 sees a FOREIGN owner → Mismatch → continue.
                Ok((200, profile_body("foreign@example.com")))
            } else {
                Ok((401, b"{}".to_vec())) // 2nd candidate → Dead
            }
        });
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &g,
        );
        // Both candidates reached verify_token_owner → the Mismatch did NOT short-circuit.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // identity_unconfirmed (gate-2 Mismatch) outranks the 2nd candidate's Dead.
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_store_fresher_returns_store_freshest() {
        // store_expiry strictly newer than the candidate → freshest-cutoff fires
        // BEFORE the guard/validation: no adopt, validation never called. Pins the
        // store_expiry forwarding + early-return ordering (redteam R2 NIT).
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        // A gate-1-failing (foreign self-report) older candidate keeps the
        // "validation never called" pin: older candidates are owner-verified
        // only AFTER the email prefilter (see `record_superseded_owner_verified`).
        let cands = vec![mk_candidate(Some("foreign@example.com"), 1_000)];
        let out = reconcile_no_identity(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            Some(2_000),
            &never_called(),
        );
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
    }

    // ── superseded-login owner verification (live incident: refresh war) ──

    fn cand_rt(
        rt: &str,
        email: Option<&str>,
        expiry_ms: u64,
    ) -> credentials::keychain::HarvestCandidate {
        credentials::keychain::HarvestCandidate {
            raw_json: format!(
                r#"{{"claudeAiOauth":{{"accessToken":"sk-ant-oat01-{rt}","refreshToken":"{rt}","expiresAt":4102444800000}}}}"#
            ).into(),
            expiry_ms,
            source_tag: "term-1".to_string(),
            candidate_email: email.map(str::to_owned),
            handle_dir_tag: Some("term-1".to_string()),
        }
    }

    fn fp_of(
        c: &credentials::keychain::HarvestCandidate,
    ) -> credentials::token_history::Fingerprint {
        credentials::token_history::fingerprint_from_raw_json(&c.raw_json).unwrap()
    }

    /// base with slot 2 -> uuid mapping and an existing identity dir.
    fn base_with_slot2() -> (tempfile::TempDir, AccountNum, identity_store::IdentityId) {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(dir.path(), 2, uuid, "bound@example.com", "fake-canonical");
        (dir, AccountNum::try_from(2u16).unwrap(), uuid)
    }

    fn read_org_proof(
        base: &Path,
        uuid: identity_store::IdentityId,
    ) -> Vec<credentials::token_history::Fingerprint> {
        let profiles = profiles::load(&profiles::profiles_path(base)).unwrap();
        let Some(slot) = profiles
            .by_slot
            .iter()
            .find_map(|(slot, id)| (*id == uuid).then_some(slot))
        else {
            return Vec::new();
        };
        let slot = AccountNum::try_from(slot.parse::<u16>().unwrap()).unwrap();
        credentials::token_history::read_owner_verified_for_slot(base, slot)
    }

    fn counting_profile(
        status: u16,
        email: &'static str,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> HttpGetFn {
        Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if status == 200 {
                Ok((
                    200u16,
                    format!(r#"{{"account":{{"uuid":"11111111-1111-4111-8111-111111111111","email":"{email}"}},"organization":{{"uuid":"22222222-2222-4222-8222-222222222222"}}}}"#).into_bytes(),
                ))
            } else {
                Ok((status, b"{}".to_vec()))
            }
        })
    }

    fn run_older(
        cands: &[credentials::keychain::HarvestCandidate],
        status: u16,
        email: &'static str,
    ) -> (
        ReconcileOutcome,
        Vec<credentials::token_history::Fingerprint>,
        usize,
    ) {
        let (dir, acct, uuid) = base_with_slot2();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let http = counting_profile(status, email, Arc::clone(&calls));
        let neg = NegativeCache::new();
        let out = reconcile_candidates(
            &older_ctx(dir.path(), acct, uuid, &http, &neg),
            cands,
            Some(2_000),
        );
        let rec = read_org_proof(dir.path(), uuid);
        (out, rec, calls.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[test]
    fn older_candidate_owner_match_records_fingerprint_never_adopts() {
        let c = cand_rt("rt-older", Some("bound@example.com"), 1_000);
        let (out, rec, calls) = run_older(std::slice::from_ref(&c), 200, "bound@example.com");
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
        assert_eq!(rec, vec![fp_of(&c)]);
        assert_eq!(calls, 1);
    }

    #[test]
    fn older_candidate_owner_mismatch_dead_unknown_and_gate1_record_nothing() {
        let c = cand_rt("rt-older", Some("bound@example.com"), 1_000);
        for (status, email) in [(200u16, "foreign@example.com"), (401, ""), (500, "")] {
            let (out, rec, calls) = run_older(std::slice::from_ref(&c), status, email);
            let want = if status == 500 {
                ReconcileOutcome::SkippedUnknown
            } else {
                ReconcileOutcome::StoreFreshest
            };
            assert_eq!(out, want, "status {status}");
            assert!(rec.is_empty(), "status {status} must record nothing");
            assert_eq!(calls, 1, "status {status}");
        }
        let foreign = cand_rt("rt-older", Some("foreign@example.com"), 1_000);
        let (out, rec, calls) = run_older(std::slice::from_ref(&foreign), 200, "bound@example.com");
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
        assert!(rec.is_empty(), "gate 1 failure must record nothing");
        assert_eq!(calls, 0, "gate 1 failure must not reach the network");
    }

    #[test]
    fn older_candidate_rate_limited_propagates_and_records_nothing() {
        let c = cand_rt("rt-older", Some("bound@example.com"), 1_000);
        let (out, rec, _) = run_older(std::slice::from_ref(&c), 429, "");
        assert_eq!(out, ReconcileOutcome::RateLimited);
        assert!(rec.is_empty());
    }

    #[test]
    fn older_candidates_respect_validation_budget() {
        let cands: Vec<_> = (0..4)
            .map(|i| cand_rt(&format!("rt-old-{i}"), Some("bound@example.com"), 1_000 - i))
            .collect();
        let (out, rec, calls) = run_older(&cands, 200, "bound@example.com");
        // Budget exhaustion is "retry next tick", same as the fresher path.
        assert_eq!(out, ReconcileOutcome::SkippedUnknown);
        assert_eq!(calls, MAX_VALIDATIONS_PER_RECONCILE);
        assert_eq!(rec.len(), MAX_VALIDATIONS_PER_RECONCILE);
    }

    fn older_ctx<'a>(
        base: &'a Path,
        acct: AccountNum,
        uuid: identity_store::IdentityId,
        http: &'a HttpGetFn,
        neg: &'a NegativeCache,
    ) -> ReconcileCtx<'a> {
        ReconcileCtx {
            base_dir: base,
            account: acct,
            identity: Some(uuid),
            anchor_email: Some("bound@example.com"),
            binding: ai::capture_anthropic_binding(base, acct).ok(),
            http_get: http,
            require_email_prefilter_on_absent_candidate_email: true,
            negative: neg,
        }
    }

    /// Run `reconcile_candidates` for the older path against an existing base,
    /// sharing the caller's negative cache across calls.
    fn reconcile_older_with(
        neg: &NegativeCache<'_>,
        dir: &tempfile::TempDir,
        acct: AccountNum,
        uuid: identity_store::IdentityId,
        cands: &[credentials::keychain::HarvestCandidate],
        http: &HttpGetFn,
    ) -> ReconcileOutcome {
        reconcile_candidates(
            &older_ctx(dir.path(), acct, uuid, http, neg),
            cands,
            Some(2_000),
        )
    }

    /// As [`reconcile_older_with`] with a FRESH negative cache (no test shares
    /// one; there is no process-wide state to leak between tests).
    fn reconcile_older_in(
        dir: &tempfile::TempDir,
        acct: AccountNum,
        uuid: identity_store::IdentityId,
        cands: &[credentials::keychain::HarvestCandidate],
        http: &HttpGetFn,
    ) -> ReconcileOutcome {
        reconcile_older_with(&NegativeCache::new(), dir, acct, uuid, cands, http)
    }

    /// Fresher-path run (store has no token, so the candidate is a strict
    /// improvement) with a CALLER-OWNED verdict cache and a real identity.
    fn run_fresher(
        neg: &NegativeCache<'_>,
        dir: &tempfile::TempDir,
        acct: AccountNum,
        uuid: identity_store::IdentityId,
        cand: &credentials::keychain::HarvestCandidate,
        http: &HttpGetFn,
    ) -> ReconcileOutcome {
        reconcile_candidates(
            &older_ctx(dir.path(), acct, uuid, http, neg),
            std::slice::from_ref(cand),
            None,
        )
    }

    #[test]
    fn fresher_dead_verdict_is_cached_second_call_costs_no_network_call() {
        let (dir, acct, uuid) = base_with_slot2();
        let cand = cand_rt("rt-fresher-dead", Some("bound@example.com"), 3_000);
        let neg = NegativeCache::new();
        let calls = calls_counter();
        let http = counting_profile(401, "", Arc::clone(&calls));
        assert_eq!(
            run_fresher(&neg, &dir, acct, uuid, &cand, &http),
            ReconcileOutcome::AllDead
        );
        assert_eq!(n(&calls), 1, "positive control: first call validates");
        assert_eq!(
            run_fresher(&neg, &dir, acct, uuid, &cand, &http),
            ReconcileOutcome::AllDead
        );
        assert_eq!(n(&calls), 1, "cached Dead: the second call makes NO call");
    }

    #[test]
    fn fresher_mismatch_verdict_is_cached_second_call_costs_no_network_call() {
        let (dir, acct, uuid) = base_with_slot2();
        let cand = cand_rt("rt-fresher-foreign", Some("bound@example.com"), 3_000);
        let neg = NegativeCache::new();
        let calls = calls_counter();
        let http = counting_profile(200, "foreign@example.com", Arc::clone(&calls));
        assert_eq!(
            run_fresher(&neg, &dir, acct, uuid, &cand, &http),
            ReconcileOutcome::IdentityUnconfirmed
        );
        assert_eq!(n(&calls), 1, "positive control: first call validates");
        assert_eq!(
            run_fresher(&neg, &dir, acct, uuid, &cand, &http),
            ReconcileOutcome::IdentityUnconfirmed
        );
        assert_eq!(
            n(&calls),
            1,
            "cached Mismatch: the second call makes NO call"
        );
    }

    #[test]
    fn on_demand_fresh_cache_reconsults_network_despite_shared_cached_dead() {
        // The shared (tick) cache already holds Dead for this fresher candidate.
        // The tick-style call honours it (no network); the on-demand call with a
        // FRESH cache — what `/api/harvest-account` and auto_rotate pass — MUST
        // re-validate, and the live answer (200, owned) adopts.
        let (dir, acct, uuid) = base_with_slot2();
        let cand = cand_rt("rt-fresher-revived", Some("bound@example.com"), 3_000);
        let canonical = identity_store::credentials_path_for(dir.path(), uuid);
        let mut prior = file::load(&canonical).unwrap();
        prior.expect_anthropic_mut().claude_ai_oauth.expires_at = 1;
        file::save(&canonical, &prior).unwrap();
        let shared = NegativeCache::new();
        shared.remember(
            uuid,
            fp_of(&cand),
            std::time::Instant::now(),
            NegativeKind::Dead,
        );
        let calls = calls_counter();
        let http = counting_profile(200, "bound@example.com", Arc::clone(&calls));
        assert_eq!(
            run_fresher(&shared, &dir, acct, uuid, &cand, &http),
            ReconcileOutcome::AllDead
        );
        assert_eq!(n(&calls), 0, "shared-cache tick call: NO network call");
        assert_eq!(
            run_fresher(&NegativeCache::new(), &dir, acct, uuid, &cand, &http),
            ReconcileOutcome::Adopted
        );
        assert_eq!(n(&calls), 1, "fresh-cache on-demand call: the call IS made");
    }

    fn mk_fp(tag: &str) -> credentials::token_history::Fingerprint {
        fp_of(&cand_rt(tag, None, 1))
    }

    /// F1 view contract: a view over a shared cache primed with Dead AND
    /// Mismatch returns the Mismatch and NOT the Dead.
    #[test]
    fn on_demand_view_reads_shared_mismatch_never_shared_dead() {
        let id = identity_store::IdentityId::new_v4();
        let (fd, fm) = (mk_fp("rt-dead"), mk_fp("rt-mismatch"));
        let shared = NegativeCache::new();
        let now = std::time::Instant::now();
        shared.remember(id, fd, now, NegativeKind::Dead);
        shared.remember(id, fm, now, NegativeKind::Mismatch);
        let view = NegativeCache::on_demand_view_over(&shared);
        assert_eq!(view.cached(id, fm, now), Some(NegativeKind::Mismatch));
        assert_eq!(
            view.cached(id, fd, now),
            None,
            "shared Dead must be invisible"
        );
        assert_eq!(shared.cached(id, fd, now), Some(NegativeKind::Dead));
    }

    /// F1 view contract: a Dead learned on-demand stays local; a Mismatch
    /// learned on-demand lands in the shared cache.
    #[test]
    fn on_demand_view_dead_stays_local_mismatch_goes_shared() {
        let id = identity_store::IdentityId::new_v4();
        let (fd, fm) = (mk_fp("rt-dead"), mk_fp("rt-mismatch"));
        let shared = NegativeCache::new();
        let now = std::time::Instant::now();
        let view = NegativeCache::on_demand_view_over(&shared);
        view.remember(id, fd, now, NegativeKind::Dead);
        view.remember(id, fm, now, NegativeKind::Mismatch);
        assert_eq!(view.cached(id, fd, now), Some(NegativeKind::Dead));
        assert_eq!(
            shared.cached(id, fd, now),
            None,
            "Dead must never reach shared"
        );
        assert_eq!(shared.cached(id, fm, now), Some(NegativeKind::Mismatch));
    }

    /// F1/F2 scenario: two foreign Mismatch candidates already in the shared
    /// cache sit AHEAD of the account's own older login. An on-demand pass
    /// skips both for free and records the own login within the 2-validation
    /// budget; an EMPTY cache (the round-4 behaviour) spends the budget on them.
    #[test]
    fn on_demand_view_skips_shared_foreign_mismatches_and_records_own_login() {
        let (dir, acct, uuid) = base_with_slot2();
        let f1 = cand_rt("rt-foreign-1", Some("bound@example.com"), 1_100);
        let f2 = cand_rt("rt-foreign-2", Some("bound@example.com"), 1_050);
        let own = cand_rt("rt-own", Some("bound@example.com"), 1_000);
        let shared = NegativeCache::new();
        let now = std::time::Instant::now();
        shared.remember(uuid, fp_of(&f1), now, NegativeKind::Mismatch);
        shared.remember(uuid, fp_of(&f2), now, NegativeKind::Mismatch);
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        let http: HttpGetFn = Arc::new(move |_u: &str, t: &str, _h: &[(&str, &str)]| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let email = if t.contains("rt-foreign") {
                "foreign@example.com"
            } else {
                "bound@example.com"
            };
            Ok((
                200u16,
                format!(r#"{{"account":{{"uuid":"11111111-1111-4111-8111-111111111111","email":"{email}"}},"organization":{{"uuid":"22222222-2222-4222-8222-222222222222"}}}}"#).into_bytes(),
            ))
        });
        let own_fp = fp_of(&own);
        let cands = [f1, f2, own];
        let view = NegativeCache::on_demand_view_over(&shared);
        let out = reconcile_older_with(&view, &dir, acct, uuid, &cands, &http);
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
        assert_eq!(n(&calls), 1, "foreign Mismatches skipped; one call for own");
        assert_eq!(read_org_proof(dir.path(), uuid), vec![own_fp]);
        // Negative control: an empty cache spends the budget on the foreigners.
        let (dir2, acct2, uuid2) = base_with_slot2();
        let calls2 = calls_counter();
        let c3 = Arc::clone(&calls2);
        let http2: HttpGetFn = Arc::new(move |_u: &str, t: &str, _h: &[(&str, &str)]| {
            c3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let email = if t.contains("rt-foreign") {
                "foreign@example.com"
            } else {
                "bound@example.com"
            };
            Ok((
                200u16,
                format!(r#"{{"account":{{"uuid":"11111111-1111-4111-8111-111111111111","email":"{email}"}},"organization":{{"uuid":"22222222-2222-4222-8222-222222222222"}}}}"#).into_bytes(),
            ))
        });
        let out2 = reconcile_older_in(&dir2, acct2, uuid2, &cands, &http2);
        assert_eq!(out2, ReconcileOutcome::SkippedUnknown);
        assert!(read_org_proof(dir2.path(), uuid2).is_empty());
    }

    fn calls_counter() -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::new(std::sync::atomic::AtomicUsize::new(0))
    }

    fn n(c: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
        c.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `expiresAt` in the past (the shared `cand_rt` is year-2100).
    fn cand_rt_expired(rt: &str) -> credentials::keychain::HarvestCandidate {
        let mut c = cand_rt(rt, Some("bound@example.com"), 1_000);
        c.raw_json = c.raw_json.replace("4102444800000", "1000").into();
        c
    }

    #[test]
    fn already_recorded_older_candidate_costs_no_network_call() {
        let (dir, acct, uuid) = base_with_slot2();
        let recorded = cand_rt("rt-recorded", Some("bound@example.com"), 1_000);
        let fresh = cand_rt("rt-unrecorded", Some("bound@example.com"), 900);
        let binding = ai::capture_anthropic_binding(dir.path(), acct).unwrap();
        let parsed = serde_json::from_str::<CredentialFile>(&recorded.raw_json).unwrap();
        let proof = ai::verify_anthropic_context_with(
            parsed.expect_anthropic(),
            &http_status(200, profile_body("bound@example.com")),
        )
        .unwrap();
        assert!(matches!(
            credentials::token_history::record_owner_verified_v2(dir.path(), &binding, &proof),
            credentials::token_history::OwnerVerifiedRecord::Written
        ));
        let fresh_fp = fp_of(&fresh);
        let calls = calls_counter();
        let out = reconcile_older_in(
            &dir,
            acct,
            uuid,
            &[recorded, fresh],
            &counting_profile(200, "bound@example.com", Arc::clone(&calls)),
        );
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
        // Positive control: ONLY the unrecorded candidate costs a call. Without
        // the `known.contains` skip this is 2.
        assert_eq!(n(&calls), 1);
        assert!(read_org_proof(dir.path(), uuid).contains(&fresh_fp));
    }

    #[test]
    fn store_own_token_older_candidate_costs_no_network_call() {
        let (dir, acct, uuid) = base_with_slot2();
        let same = cand_rt("rt-store", Some("bound@example.com"), 2_000);
        let other = cand_rt("rt-other", Some("bound@example.com"), 1_000);
        std::fs::write(
            identity_store::credentials_path_for(dir.path(), uuid),
            &same.raw_json,
        )
        .unwrap();
        let calls = calls_counter();
        let out = reconcile_older_in(
            &dir,
            acct,
            uuid,
            &[same, other],
            &counting_profile(200, "bound@example.com", Arc::clone(&calls)),
        );
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
        // Control: the other candidate IS validated (1 call); the store's own
        // token is not. Without the `Some(fp) == store_fp` skip this is 2.
        assert_eq!(n(&calls), 1);
    }

    #[test]
    fn dead_fresher_candidate_shares_budget_with_older_path() {
        // fresher (dead) + 2 older: the dead fresher one spends 1 of the 2
        // budget slots, so exactly ONE older candidate is validated, and the
        // second older one is deferred (SkippedUnknown).
        let (dir, acct, uuid) = base_with_slot2();
        let cands = vec![
            cand_rt("rt-fresh", Some("bound@example.com"), 5_000),
            cand_rt("rt-old-a", Some("bound@example.com"), 1_000),
            cand_rt("rt-old-b", Some("bound@example.com"), 900),
        ];
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        let g: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            if c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok((401u16, b"{}".to_vec()))
            } else {
                Ok((200u16, profile_body("bound@example.com")))
            }
        });
        let out = reconcile_older_in(&dir, acct, uuid, &cands, &g);
        assert_eq!(out, ReconcileOutcome::SkippedUnknown);
        assert_eq!(n(&calls), MAX_VALIDATIONS_PER_RECONCILE);
        assert_eq!(read_org_proof(dir.path(), uuid).len(), 1);
    }

    #[test]
    fn expired_older_candidate_costs_no_call_on_consecutive_reconciles() {
        let (dir, acct, uuid) = base_with_slot2();
        let expired = cand_rt_expired("rt-expired");
        let live = cand_rt("rt-live", Some("bound@example.com"), 900);
        let calls = calls_counter();
        let http = counting_profile(200, "bound@example.com", Arc::clone(&calls));
        reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&expired), &http);
        reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&expired), &http);
        assert_eq!(n(&calls), 0, "an expired token can only 401 — no call");
        // Positive control: a non-expired candidate through the same path IS counted.
        reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&live), &http);
        assert_eq!(n(&calls), 1);
    }

    #[test]
    fn dead_and_mismatch_older_results_are_negatively_cached() {
        for (status, email) in [(401u16, ""), (200, "foreign@example.com")] {
            let (dir, acct, uuid) = base_with_slot2();
            let c = cand_rt("rt-neg", Some("bound@example.com"), 1_000);
            let calls = calls_counter();
            let http = counting_profile(status, email, Arc::clone(&calls));
            let neg = NegativeCache::new();
            reconcile_older_with(&neg, &dir, acct, uuid, std::slice::from_ref(&c), &http);
            assert_eq!(n(&calls), 1, "status {status}: first reconcile checks");
            reconcile_older_with(&neg, &dir, acct, uuid, std::slice::from_ref(&c), &http);
            assert_eq!(n(&calls), 1, "status {status}: second reconcile is free");
        }
    }

    #[test]
    fn unknown_older_result_is_not_cached_and_retries() {
        let (dir, acct, uuid) = base_with_slot2();
        let c = cand_rt("rt-unk", Some("bound@example.com"), 1_000);
        let calls = calls_counter();
        let http = counting_profile(500, "", Arc::clone(&calls));
        let neg = NegativeCache::new();
        let out = reconcile_older_with(&neg, &dir, acct, uuid, std::slice::from_ref(&c), &http);
        assert_eq!(out, ReconcileOutcome::SkippedUnknown);
        reconcile_older_with(&neg, &dir, acct, uuid, std::slice::from_ref(&c), &http);
        assert_eq!(n(&calls), 2, "Unknown must be retried, never remembered");
    }

    /// The ordered token history is NOT a skip channel: the write gate consults
    /// it for an older login only when the fingerprint sits strictly before the
    /// store's own in the bounded history and (history-only) the keychain
    /// token's expiry is no later than the intended token's, so a history-known
    /// fingerprint must be verified ONCE and recorded, then be free.
    #[test]
    fn history_known_older_candidate_is_verified_once_then_free() {
        let (dir, acct, uuid) = base_with_slot2();
        let hist = cand_rt("rt-hist", Some("bound@example.com"), 1_000);
        let hist_fp = fp_of(&hist);
        credentials::token_history::append_history(dir.path(), uuid, hist_fp);
        let calls = calls_counter();
        let http = counting_profile(200, "bound@example.com", Arc::clone(&calls));
        reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&hist), &http);
        assert_eq!(n(&calls), 1, "first reconcile must spend one profile call");
        assert!(
            read_org_proof(dir.path(), uuid).contains(&hist_fp),
            "the fingerprint must be recorded where the write gate reads it"
        );
        reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&hist), &http);
        assert_eq!(n(&calls), 1, "second reconcile is free");
    }

    /// An unwritable proof destination after a Match makes the record `Failed`:
    /// identity custody remains intact, nothing is recorded, the scan CONTINUES,
    /// and the outcome is `SkippedUnknown` so the next tick retries.
    #[test]
    fn record_failure_after_match_defers_and_continues_scan() {
        let (dir, acct, uuid) = base_with_slot2();
        let a = cand_rt("rt-a", Some("bound@example.com"), 1_000);
        let b = cand_rt("rt-b", Some("bound@example.com"), 900);
        let proof_path =
            identity_store::identity_path(dir.path(), uuid).join("token-owner-verified-v2");
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        let http: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Keep the full captured identity valid, but refuse proof storage.
            std::fs::create_dir_all(&proof_path).unwrap();
            Ok((200u16, profile_body("bound@example.com")))
        });
        let out = reconcile_older_in(&dir, acct, uuid, &[a, b], &http);
        assert_eq!(out, ReconcileOutcome::SkippedUnknown);
        assert_eq!(n(&calls), 2, "a Failed record must not stop the scan");
        assert!(read_org_proof(dir.path(), uuid).is_empty());
    }

    /// A rebound slot stops the scan; with an earlier Unknown already
    /// deferred, the outcome stays `SkippedUnknown` (not `StoreFreshest`).
    #[test]
    fn rebound_after_unknown_stays_skipped_unknown_and_stops() {
        let (dir, acct, uuid) = base_with_slot2();
        let a = cand_rt("rt-a-unknown", Some("bound@example.com"), 1_000);
        let b = cand_rt("rt-b-match", Some("bound@example.com"), 900);
        let c = cand_rt("rt-c-never", Some("bound@example.com"), 800);
        let uuid_b = identity_store::IdentityId::new_v4();
        let base = dir.path().to_path_buf();
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        let http: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            if c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return Ok((500u16, b"{}".to_vec()));
            }
            let mut pf = profiles::load(&profiles::profiles_path(&base)).unwrap();
            pf.by_slot.insert("2".to_string(), uuid_b);
            profiles::save(&profiles::profiles_path(&base), &pf).unwrap();
            Ok((200u16, profile_body("bound@example.com")))
        });
        let out = reconcile_older_in(&dir, acct, uuid, &[a, b, c], &http);
        assert_eq!(out, ReconcileOutcome::SkippedUnknown);
        assert_eq!(
            n(&calls),
            2,
            "the rebound stops the scan before candidate c"
        );
    }

    #[test]
    fn unknown_candidate_ahead_of_match_still_records_the_match() {
        let (dir, acct, uuid) = base_with_slot2();
        let a = cand_rt("rt-a-unknown", Some("bound@example.com"), 1_000);
        let b = cand_rt("rt-b-match", Some("bound@example.com"), 900);
        let b_fp = fp_of(&b);
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        let http: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            if c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok((500u16, b"{}".to_vec()))
            } else {
                Ok((200u16, profile_body("bound@example.com")))
            }
        });
        let out = reconcile_older_in(&dir, acct, uuid, &[a, b], &http);
        assert_eq!(out, ReconcileOutcome::SkippedUnknown);
        assert_eq!(n(&calls), 2);
        assert_eq!(read_org_proof(dir.path(), uuid), vec![b_fp]);
    }

    #[test]
    fn slot_remapped_between_harvest_and_record_writes_to_neither_identity() {
        let (dir, acct, uuid) = base_with_slot2();
        let c = cand_rt("rt-race", Some("bound@example.com"), 1_000);
        let uuid_b = identity_store::IdentityId::new_v4();
        let base = dir.path().to_path_buf();
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        // The owner check itself remaps slot 2 to another identity — i.e. a
        // `csq login 2` lands between the harvest and the record.
        let http: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut pf = profiles::load(&profiles::profiles_path(&base)).unwrap();
            pf.by_slot.insert("2".to_string(), uuid_b);
            profiles::save(&profiles::profiles_path(&base), &pf).unwrap();
            Ok((200u16, profile_body("bound@example.com")))
        });
        let out = reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&c), &http);
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
        assert_eq!(n(&calls), 1);
        assert!(
            read_org_proof(dir.path(), uuid_b).is_empty(),
            "the NEW identity must never receive the old identity's fingerprint"
        );
        assert!(
            read_org_proof(dir.path(), uuid).is_empty(),
            "the mapping moved, so the old identity's write is skipped too"
        );
    }

    #[test]
    fn negative_cache_expires_and_is_bounded() {
        let id = identity_store::IdentityId::new_v4();
        let fp = fp_of(&cand_rt("rt-ttl", None, 1));
        let t0 = std::time::Instant::now();
        let cache = NegativeCache::new();
        cache.remember(id, fp, t0, NegativeKind::Mismatch);
        assert_eq!(cache.cached(id, fp, t0), Some(NegativeKind::Mismatch));
        assert_eq!(cache.cached(id, fp, t0 + NEGATIVE_CACHE_TTL), None);
        for i in 0..(NEGATIVE_CACHE_MAX + 40) {
            let f = fp_of(&cand_rt(&format!("b{i}"), None, 1));
            cache.remember(id, f, std::time::Instant::now(), NegativeKind::Dead);
        }
        let len = cache.len();
        assert!(len <= NEGATIVE_CACHE_MAX, "cache grew to {len}");
    }

    #[test]
    fn dead_verdict_expires_at_fifteen_minutes_mismatch_stays_cached() {
        let id = identity_store::IdentityId::new_v4();
        let fp_dead = fp_of(&cand_rt("rt-dead-ttl", None, 1));
        let fp_mis = fp_of(&cand_rt("rt-mis-ttl", None, 1));
        let t0 = std::time::Instant::now();
        let cache = NegativeCache::new();
        cache.remember(id, fp_dead, t0, NegativeKind::Dead);
        cache.remember(id, fp_mis, t0, NegativeKind::Mismatch);
        let just_before = t0 + NEGATIVE_CACHE_DEAD_TTL - std::time::Duration::from_secs(1);
        assert_eq!(
            cache.cached(id, fp_dead, just_before),
            Some(NegativeKind::Dead)
        );
        let at = t0 + NEGATIVE_CACHE_DEAD_TTL;
        assert_eq!(
            cache.cached(id, fp_dead, at),
            None,
            "Dead expires at 15 min"
        );
        assert_eq!(
            cache.cached(id, fp_mis, at),
            Some(NegativeKind::Mismatch),
            "Mismatch keeps its 6h TTL"
        );
    }

    #[test]
    fn dead_fresher_candidates_are_cached_so_older_match_is_recorded_next_tick() {
        // Budget is 2: two fresher Dead candidates consume it on tick 1, so the
        // older Match is deferred. Tick 2 skips both cached Dead for free and
        // records the Match.
        let (dir, acct, uuid) = base_with_slot2();
        let cands = vec![
            cand_rt("rt-fresh-a", Some("bound@example.com"), 5_000),
            cand_rt("rt-fresh-b", Some("bound@example.com"), 4_000),
            cand_rt("rt-old", Some("bound@example.com"), 1_000),
        ];
        let calls = calls_counter();
        let c2 = Arc::clone(&calls);
        let g: HttpGetFn = Arc::new(move |_u: &str, t: &str, _h: &[(&str, &str)]| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if t.contains("rt-old") || t.contains("old") {
                Ok((200u16, profile_body("bound@example.com")))
            } else {
                Ok((401u16, b"{}".to_vec()))
            }
        });
        let neg = NegativeCache::new();
        let out1 = reconcile_older_with(&neg, &dir, acct, uuid, &cands, &g);
        assert_eq!(out1, ReconcileOutcome::SkippedUnknown);
        assert!(read_org_proof(dir.path(), uuid).is_empty());
        let out2 = reconcile_older_with(&neg, &dir, acct, uuid, &cands, &g);
        assert_eq!(out2, ReconcileOutcome::StoreFreshest);
        assert_eq!(
            read_org_proof(dir.path(), uuid).len(),
            1,
            "the older Match is recorded once the Dead fresher ones are cached"
        );
    }

    #[test]
    fn older_candidate_with_empty_refresh_token_records_nothing() {
        let (dir, acct, uuid) = base_with_slot2();
        let mut c = cand_rt("x", Some("bound@example.com"), 1_000);
        c.raw_json = c
            .raw_json
            .replace("\"refreshToken\":\"x\"", "\"refreshToken\":\"\"")
            .into();
        assert!(
            c.raw_json.contains("\"refreshToken\":\"\""),
            "fixture must carry an empty refresh token"
        );
        let calls = calls_counter();
        let http = counting_profile(200, "bound@example.com", Arc::clone(&calls));
        reconcile_older_in(&dir, acct, uuid, std::slice::from_ref(&c), &http);
        assert!(read_org_proof(dir.path(), uuid).is_empty());
    }

    // ── identity_unconfirmed_reason (the daemon-log drift/fresh tag) ───────────
    // R2 testing-specialist F1: the candidate_email_drift branch was structurally
    // unreachable from any test. These exercise every reason arm directly.

    #[test]
    fn reason_anchor_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), Some("term-1"), None, Some("c@x.com")),
            "anchor_email_absent"
        );
    }

    #[test]
    fn reason_email_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identity_unconfirmed_reason(
                dir.path(),
                Some("term-1"),
                Some("a@x.com"),
                Some("b@x.com")
            ),
            "email_mismatch"
        );
    }

    #[test]
    fn reason_candidate_absent_is_fresh_not_drift() {
        // No term-1 dir → classify_oauth_account → NotYetPopulated → absent (fresh).
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), Some("term-1"), Some("a@x.com"), None),
            "candidate_email_absent"
        );
    }

    #[test]
    fn reason_candidate_drift_when_populated_no_oauth_account() {
        // Populated .claude.json without oauthAccount → classify FieldMissing →
        // "candidate_email_drift" (the an internal ticket degradation surfaced in the daemon log).
        let dir = tempfile::TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"numStartups":3,"userID":"x"}"#,
        )
        .unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), Some("term-1"), Some("a@x.com"), None),
            "candidate_email_drift"
        );
    }

    /// `keychain-fix-r9.md` S-L-3: the pending-clear RETRY path's
    /// `HarvestCandidate.source_tag` is a keychain SERVICE name, not a
    /// handle-dir basename — `handle_dir_tag: None` for that path. A
    /// directory that happens to share the service's name under `base_dir`
    /// (a coincidence, not a real handle dir for this candidate) MUST NOT be
    /// consulted: no path may ever be built from a service name, and the
    /// logged reason must stay the truthful "no dir to inspect"
    /// (`candidate_email_absent`), never the misleading `candidate_email_drift`
    /// a stray directory of that name would otherwise produce.
    #[test]
    fn reason_none_handle_dir_tag_never_builds_a_path_from_service_name() {
        let dir = tempfile::TempDir::new().unwrap();
        // A directory that happens to share the retry queue's service-name
        // string, populated so that IF it were consulted it would report
        // "candidate_email_drift" — proving the None branch never joins it.
        let coincidental = dir.path().join("csq-account-7");
        std::fs::create_dir_all(&coincidental).unwrap();
        std::fs::write(
            coincidental.join(".claude.json"),
            r#"{"numStartups":3,"userID":"x"}"#,
        )
        .unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), None, Some("a@x.com"), None),
            "candidate_email_absent"
        );
    }

    // ── adopt_single_candidate_before_delete (keychain-fix-r8.md C-F3) ────────

    /// Materialize a slot -> uuid mapping with an `identity.json` anchor —
    /// the minimum `adopt_single_candidate_before_delete` needs to resolve
    /// `anchor_email`. Deliberately does NOT write a store `credentials.json`
    /// (unlike `setup_slot_store`): this function passes `store_expiry: None`
    /// unconditionally, so it never reads one.
    fn setup_slot_anchor(
        base: &Path,
        slot: u16,
        uuid: identity_store::IdentityId,
        anchor_email: &str,
    ) {
        setup_slot_store(base, slot, uuid, anchor_email, "fake-prior");
        let path = identity_store::credentials_path_for(base, uuid);
        let mut creds = file::load(&path).unwrap();
        creds.expect_anthropic_mut().claude_ai_oauth.expires_at = 1;
        file::save(&path, &creds).unwrap();
    }

    #[test]
    fn adopt_single_candidate_true_when_owner_confirmed() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(Some("jack@researchroom.sg"), 4_102_444_800_000);
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert!(adopt_single_candidate_before_delete(
            dir.path(),
            acct,
            &cand,
            &g
        ));
    }

    #[test]
    fn adopt_single_candidate_false_when_owner_mismatch() {
        // Gate 1 passes (self-report matches anchor) but gate 2's server
        // check reveals the token actually belongs to a different account —
        // must never adopt.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(Some("jack@researchroom.sg"), 4_102_444_800_000);
        let g = http_status(200, profile_body("jack@integrum.global"));
        assert!(!adopt_single_candidate_before_delete(
            dir.path(),
            acct,
            &cand,
            &g
        ));
    }

    #[test]
    fn adopt_single_candidate_false_when_dead() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(Some("jack@researchroom.sg"), 4_102_444_800_000);
        let g = http_status(401, b"{}".to_vec());
        assert!(!adopt_single_candidate_before_delete(
            dir.path(),
            acct,
            &cand,
            &g
        ));
    }

    #[test]
    fn adopt_single_candidate_true_when_owner_confirmed_and_no_self_report() {
        // D-F3: no `.claude.json` self-report at all (candidate_email: None) —
        // gate 1 must be skipped for this single-candidate caller, and the
        // authoritative server-side owner check (gate 2) alone decides.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(None, 4_102_444_800_000);
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert!(adopt_single_candidate_before_delete(
            dir.path(),
            acct,
            &cand,
            &g
        ));
    }

    #[test]
    fn adopt_single_candidate_false_when_owner_mismatch_and_no_self_report() {
        // D-F3: no self-report AND the server-side check says the token
        // belongs to a different account — must never adopt.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(None, 4_102_444_800_000);
        let g = http_status(200, profile_body("jack@integrum.global"));
        assert!(!adopt_single_candidate_before_delete(
            dir.path(),
            acct,
            &cand,
            &g
        ));
    }

    #[test]
    fn adopt_single_candidate_false_when_no_anchor() {
        // No profiles/identity.json at all -> anchor_email resolves to None
        // -> the wrong-account guard refuses before ever calling http_get.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(Some("jack@researchroom.sg"), 4_102_444_800_000);
        assert!(!adopt_single_candidate_before_delete(
            dir.path(),
            acct,
            &cand,
            &never_called()
        ));
    }

    // ── `keychain-fix-r10.md` item 2, C-B1/S-L-5: shared gate wiring ──────

    /// CONSUMER half: a gate already marked BEFORE this call must return
    /// `false` (keep, re-queue) WITHOUT ever calling `http_get` — mirrors
    /// `auto_rotate.rs`'s own pre-marked-gate suppression test. Uses a
    /// FRESH gate (never `ip_rate_limit_gate()`'s process-wide singleton,
    /// which every other test in this binary also reads/writes — see that
    /// function's own doc).
    ///
    /// RED: dropping the `if gate_is_rate_limited(gate) { return false }`
    /// early-return makes this call fall through to `reconcile_candidates_inner`,
    /// which calls the `never_called()` closure and panics — proving the
    /// gate check is load-bearing, not merely decorative.
    #[test]
    fn adopt_single_candidate_pre_marked_gate_returns_false_without_http_call() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(Some("jack@researchroom.sg"), 4_102_444_800_000);

        let gate = crate::daemon::server::harvest_gate::new_ip_rate_limit_gate();
        crate::daemon::server::harvest_gate::gate_mark_rate_limited(&gate);

        assert!(!adopt_single_candidate_before_delete_with_gate(
            dir.path(),
            acct,
            &cand,
            &never_called(),
            &gate,
        ));
    }

    /// PRODUCER half: a fresh `RateLimited` observed by THIS call marks the
    /// shared gate, so a later caller on any of the three surfaces
    /// (refresher, auto-rotate, this reaper/retry path) short-circuits too.
    ///
    /// RED: dropping the `gate_mark_rate_limited(gate)` call after a
    /// `RateLimited` outcome makes this assertion fail — the gate would
    /// stay unmarked despite the 429 this call itself just observed.
    #[test]
    fn adopt_single_candidate_rate_limited_marks_the_shared_gate() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, uuid, "jack@researchroom.sg");
        let acct = AccountNum::try_from(2u16).unwrap();
        let cand = mk_candidate(Some("jack@researchroom.sg"), 4_102_444_800_000);
        let g = http_status(429, b"".to_vec());

        let gate = crate::daemon::server::harvest_gate::new_ip_rate_limit_gate();
        assert!(!crate::daemon::server::harvest_gate::gate_is_rate_limited(
            &gate
        ));

        assert!(!adopt_single_candidate_before_delete_with_gate(
            dir.path(),
            acct,
            &cand,
            &g,
            &gate,
        ));

        assert!(
            crate::daemon::server::harvest_gate::gate_is_rate_limited(&gate),
            "a RateLimited outcome observed by this call must mark the shared gate"
        );
    }
    #[test]
    fn custodian_org_identity_regression_adopt_return_rebind_preserves_new_slot_failure() {
        for rebind in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let source = identity_store::IdentityId::new_v4();
            let sibling = identity_store::IdentityId::new_v4();
            let slot = AccountNum::try_from(2u16).unwrap();
            setup_slot_store(
                dir.path(),
                2,
                source,
                "source@example.test",
                "fake-old-access",
            );
            setup_slot_store(
                dir.path(),
                3,
                sibling,
                "foreign@example.test",
                "fake-sibling-access",
            );
            let source_path = identity_store::credentials_path_for(dir.path(), source);
            let sibling_path = identity_store::credentials_path_for(dir.path(), sibling);
            let sibling_before = std::fs::read(&sibling_path).unwrap();
            let captured = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            let mut parsed = file::load(&source_path).unwrap();
            let CredentialFile::Anthropic(ref mut incoming) = parsed else {
                unreachable!()
            };
            incoming.claude_ai_oauth.access_token =
                crate::types::AccessToken::new("fake-adopted-access".into());
            incoming.claude_ai_oauth.refresh_token =
                crate::types::RefreshToken::new("fake-adopted-refresh".into());
            let baseline = incoming.claude_ai_oauth.expires_at;
            incoming.claude_ai_oauth.expires_at += 1000;
            let proof = ai::verify_anthropic_context_with(
                incoming,
                &http_status(200, profile_body("source@example.test")),
            )
            .unwrap();
            sentinel::set_broker_failed(dir.path(), slot, "old_failure").unwrap();
            if rebind {
                let base = dir.path().to_path_buf();
                ADOPT_AFTER_WRITE_TEST_HOOK.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        let _lock = ProfilesFileLock::acquire(&base).unwrap();
                        let path = profiles::profiles_path(&base);
                        let mut pf = profiles::load(&path).unwrap();
                        pf.by_slot.insert("2".into(), sibling);
                        *pf.slot_binding_generations.entry("2".into()).or_default() += 1;
                        profiles::save(&path, &pf).unwrap();
                        sentinel::set_broker_failed(&base, slot, "new_identity_failure").unwrap();
                    }));
                });
            }
            assert!(matches!(
                adopt_candidate(
                    dir.path(),
                    slot,
                    parsed,
                    Some(baseline),
                    Some(&captured),
                    Some(&proof),
                    None
                )
                .unwrap(),
                file::GuardedWriteOutcome::Written
            ));
            assert_eq!(
                file::load(&source_path)
                    .unwrap()
                    .expect_anthropic()
                    .claude_ai_oauth
                    .refresh_token
                    .expose_secret(),
                "fake-adopted-refresh"
            );
            assert_eq!(std::fs::read(sibling_path).unwrap(), sibling_before);
            if rebind {
                assert_eq!(
                    sentinel::read_broker_failed_reason(dir.path(), slot).as_deref(),
                    Some("new_identity_failure")
                );
            } else {
                assert!(!sentinel::is_broker_failed(dir.path(), slot));
            }
        }
    }

    #[test]
    fn custodian_adopted_sentinel_profiles_contention_preserves_failure_then_clears() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity_store::IdentityId::new_v4();
        let slot = AccountNum::try_from(2u16).unwrap();
        setup_slot_store(
            dir.path(),
            slot.get(),
            id,
            "same@example.test",
            "fake-own-access",
        );
        let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
        let creds = file::load(&identity_store::credentials_path_for(dir.path(), id)).unwrap();
        let proof = ai::verify_anthropic_context_with(
            creds.expect_anthropic(),
            &http_status(200, profile_body("same@example.test")),
        )
        .unwrap();
        sentinel::set_broker_failed(dir.path(), slot, "retained_while_busy").unwrap();
        let lock = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(dir.path());
        clear_adopted_broker_failure(dir.path(), slot, &binding, &proof);
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), slot).as_deref(),
            Some("retained_while_busy")
        );
        drop(lock);
        clear_adopted_broker_failure(dir.path(), slot, &binding, &proof);
        assert!(!sentinel::is_broker_failed(dir.path(), slot));
    }

    #[test]
    fn slot_ownership_org_identity_regression_legacy_email_mismatch_diagnoses_without_ownership() {
        for (observed_email, expected) in [
            ("foreign@example.test", SlotOwnership::Contaminated),
            ("recorded@example.test", SlotOwnership::Unknown),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let id = setup_legacy_slot_store(
                dir.path(),
                slot,
                "recorded@example.test",
                "fake-legacy-access",
            );
            let metadata = identity_store::identity_json_path_for(dir.path(), id);
            let path = profiles::profiles_path(dir.path());
            assert!(matches!(
                ai::capture_anthropic_binding(dir.path(), slot)
                    .unwrap()
                    .context(),
                ai::StoredAnthropicContext::LegacyUnknown
            ));
            let canonical = identity_store::credentials_path_for(dir.path(), id);
            let before = [
                std::fs::read(&canonical).unwrap(),
                std::fs::read(&metadata).unwrap(),
                std::fs::read(&path).unwrap(),
            ];
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let body = profile_body(observed_email);
            let http: HttpGetFn = Arc::new(move |_, token, _| {
                assert_eq!(token, "fake-legacy-access");
                observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok((200, body.clone()))
            });
            assert_eq!(
                check_slot_store_token_ownership(dir.path(), slot, &http),
                expected
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                [
                    std::fs::read(&canonical).unwrap(),
                    std::fs::read(&metadata).unwrap(),
                    std::fs::read(&path).unwrap()
                ],
                before
            );
            assert!(!identity_store::identity_path(dir.path(), id)
                .join("token-owner-verified-v2")
                .exists());
        }
    }

    #[test]
    fn custodian_legacy_candidate_adopts_only_own_uuid_without_context_or_sibling_change() {
        for scenario in [
            "own",
            "foreign",
            "rebound",
            "held_elsewhere",
            "own_unverified",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let id = setup_legacy_slot_store(
                dir.path(),
                slot,
                "same@example.test",
                "fake-legacy-access",
            );
            let sibling = identity_store::IdentityId::new_v4();
            setup_slot_store(
                dir.path(),
                3,
                sibling,
                "same@example.test",
                "fake-sibling-access",
            );
            let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            let source = identity_store::credentials_path_for(dir.path(), id);
            let sibling_path = identity_store::credentials_path_for(dir.path(), sibling);
            let metadata = identity_store::identity_json_path_for(dir.path(), id);
            let profile_path = profiles::profiles_path(dir.path());
            let source_before = std::fs::read(&source).unwrap();
            let sibling_before = std::fs::read(&sibling_path).unwrap();
            let metadata_before = std::fs::read(&metadata).unwrap();
            let profiles_before = std::fs::read(&profile_path).unwrap();
            sentinel::set_broker_failed(dir.path(), slot, "legacy_pending").unwrap();
            let parsed: CredentialFile = serde_json::from_value(serde_json::json!({
                "claudeAiOauth":{"accessToken":"fake-candidate-access","refreshToken":"fake-candidate-refresh",
                    "expiresAt":4102444860000u64,"scopes":["user:inference"]}
            })).unwrap();
            let handle = dir.path().join(format!("term-{}", std::process::id()));
            std::fs::create_dir(&handle).unwrap();
            crate::accounts::markers::write_live_pid(&handle, std::process::id()).unwrap();
            crate::accounts::markers::write_csq_account(&handle, id).unwrap();
            file::save(&handle.join(".credentials.json"), &parsed).unwrap();
            let native = handle.join(".claude.json");
            crate::platform::fs::write_new_private(
                &native,
                br#"{"oauthAccount":{"emailAddress":"foreign@example.test"}}"#,
            )
            .unwrap();
            assert!(harvest_live_file_candidates(dir.path(), &binding).is_empty());
            std::fs::write(
                &native,
                br#"{"oauthAccount":{"emailAddress":"same@example.test"}}"#,
            )
            .unwrap();
            crate::accounts::markers::write_csq_account(&handle, sibling).unwrap();
            assert!(harvest_live_file_candidates(dir.path(), &binding).is_empty());
            crate::accounts::markers::write_csq_account(&handle, id).unwrap();
            let mut collected = harvest_live_file_candidates(dir.path(), &binding);
            assert_eq!(collected.len(), 1);
            let candidate = collected.pop().unwrap();
            assert_eq!(candidate.source_tag, "live_credential_file");
            let base = dir.path().to_path_buf();
            let http: HttpGetFn = Arc::new(move |url, token, _| {
                assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
                if token == "fake-legacy-access" {
                    // The identity's OWN canonical token is verified first.
                    if scenario == "own_unverified" {
                        return Ok((401, Vec::new()));
                    }
                    return Ok((200, profile_body_org("same@example.test", FREE_ORG)));
                }
                assert_eq!(token, "fake-candidate-access");
                if scenario == "rebound" {
                    let _lock = ProfilesFileLock::acquire(&base).unwrap();
                    let path = profiles::profiles_path(&base);
                    let mut pf = profiles::load(&path).unwrap();
                    pf.by_slot.insert("2".into(), sibling);
                    *pf.slot_binding_generations.entry("2".into()).or_default() += 1;
                    profiles::save(&path, &pf).unwrap();
                }
                // The sibling identity holds HELD_ORG; "held_elsewhere" offers it.
                let org = if scenario == "held_elsewhere" {
                    HELD_ORG
                } else {
                    FREE_ORG
                };
                Ok((
                    200,
                    profile_body_org(
                        if scenario == "foreign" {
                            "foreign@example.test"
                        } else {
                            "same@example.test"
                        },
                        org,
                    ),
                ))
            });
            let negative = NegativeCache::new();
            let ctx = ReconcileCtx {
                base_dir: dir.path(),
                account: slot,
                identity: Some(id),
                anchor_email: Some("same@example.test"),
                binding: Some(binding),
                http_get: &http,
                require_email_prefilter_on_absent_candidate_email: true,
                negative: &negative,
            };
            let outcome = reconcile_candidates(&ctx, &[candidate], Some(4_102_444_800_000));
            if scenario == "own" {
                assert_eq!(outcome, ReconcileOutcome::Adopted);
                assert_eq!(
                    file::load(&source)
                        .unwrap()
                        .expect_anthropic()
                        .claude_ai_oauth
                        .refresh_token
                        .expose_secret(),
                    "fake-candidate-refresh"
                );
                assert!(!sentinel::is_broker_failed(dir.path(), slot));
            } else {
                assert_eq!(
                    outcome,
                    if scenario == "foreign" {
                        ReconcileOutcome::IdentityUnconfirmed
                    } else {
                        ReconcileOutcome::SkippedUnknown
                    }
                );
                assert_eq!(std::fs::read(&source).unwrap(), source_before);
                assert!(sentinel::is_broker_failed(dir.path(), slot));
            }
            assert_eq!(std::fs::read(sibling_path).unwrap(), sibling_before);
            assert_eq!(std::fs::read(metadata).unwrap(), metadata_before);
            if scenario != "rebound" {
                assert_eq!(std::fs::read(profile_path).unwrap(), profiles_before);
            }
            assert_eq!(
                ai::read_stored_anthropic_context(dir.path(), id).unwrap(),
                ai::StoredAnthropicContext::LegacyUnknown
            );
            assert!(!identity_store::identity_path(dir.path(), id)
                .join("token-owner-verified-v2")
                .exists());
        }
    }

    /// Two legacy identities that have NO index row must never end up holding one
    /// refresh pair. Y is legacy and holds pair P; a live X-bound handle dir also
    /// holds P (fresher than X's store) and X's OWN token verifies to the same
    /// (email, account, organization) as P. Nothing in the index can tell the two
    /// identities apart, so adoption would give X and Y one refresh grant and the
    /// refresher would then race itself. `no_other_holder` is the non-vacuity arm:
    /// the same candidate is adopted when no other identity holds its pair.
    #[test]
    fn custodian_legacy_candidate_pair_held_by_another_legacy_identity_is_never_adopted() {
        for scenario in ["no_other_holder", "other_legacy_holds_pair"] {
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let x =
                setup_legacy_slot_store(dir.path(), slot, "same@example.test", "fake-x-own-access");
            let y = identity_store::IdentityId::new_v4();
            // Y records a DIFFERENT email than X: a same-email legacy sibling is refused as
            // ambiguous authority before any token is compared (r4 SEC-H1), and this test
            // isolates the token-level pair check.
            crate::daemon::identity_mint::write_legacy_anthropic_metadata_fixture(
                dir.path(),
                y,
                "other-y@example.test",
            )
            .unwrap();
            let held_refresh = if scenario == "other_legacy_holds_pair" {
                "fake-shared-refresh"
            } else {
                "fake-y-private-refresh"
            };
            let y_creds: CredentialFile = serde_json::from_value(serde_json::json!({
                "claudeAiOauth":{"accessToken":"fake-y-access","refreshToken":held_refresh,
                    "expiresAt":4102444800000u64,"scopes":["user:inference"]}
            }))
            .unwrap();
            file::save(
                &identity_store::credentials_path_for(dir.path(), y),
                &y_creds,
            )
            .unwrap();
            let profile_path = profiles::profiles_path(dir.path());
            let mut pf = profiles::load(&profile_path).unwrap();
            pf.by_slot.insert("3".into(), y);
            profiles::save(&profile_path, &pf).unwrap();
            assert!(
                pf.anthropic_contexts.is_empty(),
                "both identities are legacy, no row"
            );
            let x_canonical = identity_store::credentials_path_for(dir.path(), x);
            let y_canonical = identity_store::credentials_path_for(dir.path(), y);
            let x_before = std::fs::read(&x_canonical).unwrap();
            let y_before = std::fs::read(&y_canonical).unwrap();
            // The live X-bound handle dir holds pair P: the same refresh token Y holds.
            let candidate: CredentialFile = serde_json::from_value(serde_json::json!({
                "claudeAiOauth":{"accessToken":"fake-shared-access","refreshToken":"fake-shared-refresh",
                    "expiresAt":4102444860000u64,"scopes":["user:inference"]}
            }))
            .unwrap();
            let handle = dir.path().join(format!("term-{}", std::process::id()));
            std::fs::create_dir(&handle).unwrap();
            crate::accounts::markers::write_live_pid(&handle, std::process::id()).unwrap();
            crate::accounts::markers::write_csq_account(&handle, x).unwrap();
            file::save(&handle.join(".credentials.json"), &candidate).unwrap();
            crate::platform::fs::write_new_private(
                &handle.join(".claude.json"),
                br#"{"oauthAccount":{"emailAddress":"same@example.test"}}"#,
            )
            .unwrap();
            // Every token verifies to the SAME (email, account, organization).
            let http: HttpGetFn = Arc::new(move |_, token, _| {
                assert!(
                    ["fake-x-own-access", "fake-shared-access"].contains(&token),
                    "only the identity's own token and the candidate may be verified"
                );
                Ok((200, profile_body_org("same@example.test", FREE_ORG)))
            });
            let outcome = reconcile_account_periodic(dir.path(), slot, &x.to_string(), &http);
            let refresh_of = |path: &Path| {
                file::load(path)
                    .unwrap()
                    .expect_anthropic()
                    .claude_ai_oauth
                    .refresh_token
                    .expose_secret()
                    .to_owned()
            };
            if scenario == "no_other_holder" {
                assert_eq!(outcome, ReconcileOutcome::Adopted);
                assert_eq!(refresh_of(&x_canonical), "fake-shared-refresh");
            } else {
                assert_ne!(
                    outcome,
                    ReconcileOutcome::Adopted,
                    "X must not adopt a pair another identity's canonical holds"
                );
                assert_eq!(std::fs::read(&x_canonical).unwrap(), x_before);
            }
            assert_eq!(
                std::fs::read(&y_canonical).unwrap(),
                y_before,
                "Y untouched"
            );
            if scenario == "other_legacy_holds_pair" {
                assert_ne!(
                    refresh_of(&x_canonical),
                    refresh_of(&y_canonical),
                    "two identities must never hold one refresh pair"
                );
            }
        }
    }

    #[test]
    fn slot_ownership_org_identity_regression_missing_profile_org_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity_store::IdentityId::new_v4();
        setup_slot_store(dir.path(), 2, id, "same@example.test", "fake-access");
        let http = http_status(200,br#"{"account":{"uuid":"11111111-1111-4111-8111-111111111111","email":"same@example.test"}}"#);
        assert_eq!(
            check_slot_store_token_ownership(
                dir.path(),
                AccountNum::try_from(2u16).unwrap(),
                &http
            ),
            SlotOwnership::Unknown
        );
    }

    #[test]
    fn custodian_org_identity_regression_profile_rebind_never_redirects_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let source = identity_store::IdentityId::new_v4();
        let sibling = identity_store::IdentityId::new_v4();
        setup_slot_anchor(dir.path(), 2, source, "same@example.test");
        setup_slot_store(
            dir.path(),
            3,
            sibling,
            "same@example.test",
            "fake-sibling-access",
        );
        let source_path = identity_store::credentials_path_for(dir.path(), source);
        let sibling_path = identity_store::credentials_path_for(dir.path(), sibling);
        let original = std::fs::read(&source_path).unwrap();
        let sibling_original = std::fs::read(&sibling_path).unwrap();
        let base = dir.path().to_path_buf();
        let http: HttpGetFn = Arc::new(move |_, _, _| {
            let lock = ProfilesFileLock::acquire(&base).unwrap();
            let path = profiles::profiles_path(&base);
            let mut profiles = profiles::load(&path).unwrap();
            profiles.by_slot.insert("2".into(), sibling);
            profiles::save(&path, &profiles).unwrap();
            drop(lock);
            Ok((200, profile_body("same@example.test")))
        });
        let candidate = mk_candidate(Some("same@example.test"), 4_102_444_800_000);
        let gate = crate::daemon::server::harvest_gate::new_ip_rate_limit_gate();
        assert!(!adopt_single_candidate_before_delete_with_gate(
            dir.path(),
            AccountNum::try_from(2u16).unwrap(),
            &candidate,
            &http,
            &gate
        ));
        assert_eq!(std::fs::read(source_path).unwrap(), original);
        assert_eq!(std::fs::read(sibling_path).unwrap(), sibling_original);
    }
    #[test]
    fn daemon_org_identity_regression_atomic_replaced_live_file_is_harvested_and_foreign_org_refused(
    ) {
        for foreign in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let id = identity_store::IdentityId::new_v4();
            setup_slot_anchor(dir.path(), 2, id, "same@example.test");
            let handle = dir.path().join(format!("term-{}", std::process::id()));
            std::fs::create_dir(&handle).unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            crate::accounts::markers::write_live_pid(&handle, std::process::id()).unwrap();
            crate::accounts::markers::write_csq_account(&handle, id).unwrap();
            let native=serde_json::to_vec(&serde_json::json!({"oauthAccount":{
                "emailAddress":"same@example.test","accountUuid":"11111111-1111-4111-8111-111111111111","organizationUuid":"22222222-2222-4222-8222-222222222222"
            }})).unwrap();
            crate::platform::fs::write_new_private(&handle.join(".claude.json"), &native).unwrap();
            let canonical = identity_store::credentials_path_for(dir.path(), id);
            let before = std::fs::read(&canonical).unwrap();
            let mut candidate = file::load(&canonical).unwrap();
            candidate.expect_anthropic_mut().claude_ai_oauth.expires_at = 4_102_444_800_000;
            candidate
                .expect_anthropic_mut()
                .claude_ai_oauth
                .access_token = crate::types::AccessToken::new("fake-live-access".into());
            candidate
                .expect_anthropic_mut()
                .claude_ai_oauth
                .refresh_token = crate::types::RefreshToken::new("fake-live-refresh".into());
            file::save(&handle.join(".credentials.json"), &candidate).unwrap();
            assert!(handle
                .join(".credentials.json")
                .symlink_metadata()
                .unwrap()
                .is_file());
            let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            assert_eq!(harvest_live_file_candidates(dir.path(), &binding).len(), 1);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let body = profile_body("same@example.test");
            let body = if foreign {
                String::from_utf8(body)
                    .unwrap()
                    .replace(
                        "22222222-2222-4222-8222-222222222222",
                        "33333333-3333-4333-8333-333333333333",
                    )
                    .into_bytes()
            } else {
                body
            };
            let http: HttpGetFn = Arc::new(move |_, token, _| {
                assert_eq!(token, "fake-live-access");
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok((200, body.clone()))
            });
            let result = reconcile_account_periodic(dir.path(), slot, &id.to_string(), &http);
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            if foreign {
                assert_eq!(result, ReconcileOutcome::IdentityUnconfirmed);
                assert_eq!(std::fs::read(&canonical).unwrap(), before);
            } else {
                assert_eq!(result, ReconcileOutcome::Adopted);
                assert_eq!(
                    file::load(&canonical)
                        .unwrap()
                        .expect_anthropic()
                        .claude_ai_oauth
                        .refresh_token
                        .expose_secret(),
                    "fake-live-refresh"
                );
            }
        }
    }

    /// Organization mismatch is cached; an own canonical 401 is retryable.
    /// The second tick exercises the actual validator and refusal cache.
    #[test]
    fn permanent_legacy_refusal_costs_zero_http_on_the_next_tick() {
        let _env_guard = crate::platform::test_env::lock();
        for scenario in ["held_elsewhere", "own_dead"] {
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let id = setup_legacy_slot_store(
                dir.path(),
                slot,
                "same@example.test",
                "fake-legacy-access",
            );
            let sibling = identity_store::IdentityId::new_v4();
            setup_slot_store(
                dir.path(),
                3,
                sibling,
                "same@example.test",
                "fake-sibling-access",
            );
            let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            let parsed: CredentialFile = serde_json::from_value(serde_json::json!({
                "claudeAiOauth":{"accessToken":"fake-candidate-access","refreshToken":"fake-candidate-refresh",
                    "expiresAt":4102444860000u64,"scopes":["user:inference"]}
            }))
            .unwrap();
            let handle = dir.path().join(format!("term-{}", std::process::id()));
            std::fs::create_dir(&handle).unwrap();
            crate::accounts::markers::write_live_pid(&handle, std::process::id()).unwrap();
            crate::accounts::markers::write_csq_account(&handle, id).unwrap();
            file::save(&handle.join(".credentials.json"), &parsed).unwrap();
            crate::platform::fs::write_new_private(
                &handle.join(".claude.json"),
                br#"{"oauthAccount":{"emailAddress":"same@example.test"}}"#,
            )
            .unwrap();
            let mut collected = harvest_live_file_candidates(dir.path(), &binding);
            assert_eq!(collected.len(), 1);
            let candidate = collected.pop().unwrap();

            let calls = calls_counter();
            let counter = calls.clone();
            let http: HttpGetFn = Arc::new(move |_url, token, _| {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if token == "fake-legacy-access" {
                    if scenario == "own_dead" {
                        return Ok((401, Vec::new()));
                    }
                    return Ok((200, profile_body_org("same@example.test", FREE_ORG)));
                }
                let org = if scenario == "held_elsewhere" {
                    HELD_ORG
                } else {
                    FREE_ORG
                };
                Ok((200, profile_body_org("same@example.test", org)))
            });
            let negative = NegativeCache::new();
            let ctx = ReconcileCtx {
                base_dir: dir.path(),
                account: slot,
                identity: Some(id),
                anchor_email: Some("same@example.test"),
                binding: Some(binding),
                http_get: &http,
                require_email_prefilter_on_absent_candidate_email: true,
                negative: &negative,
            };
            let first = reconcile_candidates(&ctx, &[candidate], Some(4_102_444_800_000));
            assert_eq!(first, ReconcileOutcome::SkippedUnknown, "{scenario}");
            assert!(
                n(&calls) > 0,
                "{scenario}: first tick must have asked the server"
            );
            let before = n(&calls);
            let mut again = harvest_live_file_candidates(dir.path(), ctx.binding.as_ref().unwrap());
            assert_eq!(again.len(), 1);
            let second =
                reconcile_candidates(&ctx, &[again.pop().unwrap()], Some(4_102_444_800_000));
            assert_eq!(second, ReconcileOutcome::SkippedUnknown, "{scenario}");
            if scenario == "own_dead" {
                assert_eq!(
                    negative.len(),
                    0,
                    "own canonical 401 must not enter the refusal cache"
                );
                assert_eq!(
                    n(&calls),
                    before + 2,
                    "own 401 must retry both profile checks next tick"
                );
            } else {
                assert_eq!(
                    n(&calls),
                    before,
                    "deterministic refusal costs zero HTTP next tick"
                );
                assert_eq!(negative.len(), 1);
            }
        }
    }

    fn legacy_cache_candidate(token: &str, expiry: u64) -> credentials::keychain::HarvestCandidate {
        let mut candidate = mk_candidate(Some("same@example.test"), expiry);
        candidate.raw_json = serde_json::json!({"claudeAiOauth":{
            "accessToken":token,"refreshToken":format!("{token}-refresh"),
            // Year 2100 keeps the fixture independent of wall-clock expiry.
            "expiresAt":expiry,"scopes":["user:inference"]
        }})
        .to_string()
        .into();
        candidate
    }

    fn legacy_cache_ctx<'a>(
        base: &'a Path,
        binding: ai::CapturedBinding,
        http: &'a HttpGetFn,
        negative: &'a NegativeCache<'a>,
    ) -> ReconcileCtx<'a> {
        ReconcileCtx {
            base_dir: base,
            account: binding.slot(),
            identity: Some(binding.identity()),
            anchor_email: Some("same@example.test"),
            binding: Some(binding),
            http_get: http,
            require_email_prefilter_on_absent_candidate_email: true,
            negative,
        }
    }

    #[test]
    fn custodian_retryable_snapshot_failures_never_enter_refusal_cache() {
        let _env_guard = crate::platform::test_env::lock();
        for scenario in [
            "own_version_race",
            "upgrade",
            "namespace",
            "invalid_metadata",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("accounts");
            let slot = AccountNum::try_from(2u16).unwrap();
            let id =
                setup_legacy_slot_store(&base, slot, "same@example.test", "fake-legacy-access");
            let binding = ai::capture_anthropic_binding(&base, slot).unwrap();
            let canonical = identity_store::credentials_path_for(&base, id);
            let own = file::load(&canonical).unwrap();
            let mut candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
            // These races must reach legacy proof even when candidate verification
            // itself is the canonical witness; no second HTTP call can hide them.
            if scenario != "own_version_race" {
                candidate.raw_json = serde_json::to_string(&own).unwrap().into();
                candidate.expiry_ms = own.expect_anthropic().claude_ai_oauth.expires_at;
            }
            let modified_base = base.clone();
            let moved = dir.path().join("moved");
            let modified_moved = moved.clone();
            let calls = calls_counter();
            let observed = calls.clone();
            let http: HttpGetFn = Arc::new(move |_, token, _| {
                let first = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
                if first {
                    match scenario {
                        "own_version_race" => {
                            let mut replacement = own.clone();
                            replacement
                                .expect_anthropic_mut()
                                .claude_ai_oauth
                                .access_token =
                                crate::types::AccessToken::new("fake-refreshed-access".into());
                            file::save(
                                &identity_store::credentials_path_for(&modified_base, id),
                                &replacement,
                            )
                            .unwrap();
                        }
                        "upgrade" => setup_slot_store(
                            &modified_base,
                            2,
                            id,
                            "same@example.test",
                            "fake-legacy-access",
                        ),
                        "namespace" => std::fs::rename(&modified_base, &modified_moved).unwrap(),
                        "invalid_metadata" => {
                            let metadata =
                                identity_store::identity_json_path_for(&modified_base, id);
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
                            value["provider"] = serde_json::json!("other");
                            std::fs::write(metadata, serde_json::to_vec(&value).unwrap()).unwrap();
                        }
                        _ => unreachable!(),
                    }
                }
                assert!(!token.is_empty());
                Ok((200, profile_body_org("same@example.test", FREE_ORG)))
            });
            let negative = NegativeCache::new();
            let ctx = legacy_cache_ctx(&base, binding, &http, &negative);
            assert_eq!(
                reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
                ReconcileOutcome::SkippedUnknown,
                "{scenario}"
            );
            assert_eq!(
                negative.len(),
                0,
                "{scenario}: a race is never a cached refusal"
            );
            if scenario == "namespace" {
                std::fs::rename(&moved, &base).unwrap();
            }
            let before = n(&calls);
            let _ = reconcile_candidates(&ctx, &[candidate], None);
            assert!(
                n(&calls) > before,
                "{scenario}: next tick must reach the validator"
            );
        }
    }

    #[test]
    fn custodian_refusal_cache_expires_on_own_version_or_binding_generation_change() {
        let _env_guard = crate::platform::test_env::lock();
        for older in [false, true] {
            for repair in ["own_version", "binding_generation"] {
                let dir = tempfile::tempdir().unwrap();
                let slot = AccountNum::try_from(2u16).unwrap();
                let id = setup_legacy_slot_store(
                    dir.path(),
                    slot,
                    "same@example.test",
                    "fake-legacy-access",
                );
                let canonical = identity_store::credentials_path_for(dir.path(), id);
                let mut own = file::load(&canonical).unwrap();
                let expiry = 4_102_444_860_000;
                if older {
                    own.expect_anthropic_mut().claude_ai_oauth.expires_at = expiry + 60_000;
                    file::save(&canonical, &own).unwrap();
                }
                if repair == "binding_generation" {
                    let path = profiles::profiles_path(dir.path());
                    let mut pf = profiles::load(&path).unwrap();
                    pf.by_slot.insert("4".into(), id);
                    profiles::save(&path, &pf).unwrap();
                }
                let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
                let candidate = legacy_cache_candidate("fake-candidate-access", expiry);
                let calls = calls_counter();
                let observed = calls.clone();
                let http: HttpGetFn = Arc::new(move |_, token, _| {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let org = if repair == "own_version" && token == "fake-legacy-access" {
                        HELD_ORG
                    } else {
                        FREE_ORG
                    };
                    Ok((200, profile_body_org("same@example.test", org)))
                });
                let negative = NegativeCache::new();
                let ctx = legacy_cache_ctx(dir.path(), binding, &http, &negative);
                let cutoff = older.then_some(expiry + 60_000);
                assert_eq!(
                    reconcile_candidates(&ctx, std::slice::from_ref(&candidate), cutoff),
                    ReconcileOutcome::SkippedUnknown
                );
                assert_eq!(negative.len(), 1);
                let before_cached = n(&calls);
                assert_eq!(
                    reconcile_candidates(&ctx, std::slice::from_ref(&candidate), cutoff),
                    ReconcileOutcome::SkippedUnknown
                );
                assert_eq!(
                    n(&calls),
                    before_cached,
                    "unchanged captured refusal must cache"
                );
                if repair == "own_version" {
                    own.expect_anthropic_mut().claude_ai_oauth.access_token =
                        crate::types::AccessToken::new("fake-refreshed-access".into());
                    file::save(&canonical, &own).unwrap();
                } else {
                    let path = profiles::profiles_path(dir.path());
                    let mut pf = profiles::load(&path).unwrap();
                    pf.by_slot.remove("4");
                    *pf.slot_binding_generations.entry("2".into()).or_default() += 1;
                    profiles::save(&path, &pf).unwrap();
                }
                let ctx = legacy_cache_ctx(
                    dir.path(),
                    ai::capture_anthropic_binding(dir.path(), slot).unwrap(),
                    &http,
                    &negative,
                );
                assert_eq!(
                    reconcile_candidates(&ctx, &[candidate], cutoff),
                    if older {
                        ReconcileOutcome::SkippedUnknown
                    } else {
                        ReconcileOutcome::Adopted
                    },
                    "{repair}, older={older}"
                );
                assert_eq!(
                    n(&calls),
                    before_cached + 2,
                    "{repair}, older={older}: repaired custody must be revalidated"
                );
            }
        }
    }

    #[test]
    fn custodian_candidate_refusal_continues_to_owned_candidate_live_and_cached() {
        let _env_guard = crate::platform::test_env::lock();
        for cached in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let id = setup_legacy_slot_store(
                dir.path(),
                slot,
                "same@example.test",
                "fake-legacy-access",
            );
            let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            let bad = legacy_cache_candidate("fake-foreign-org", 4_102_444_920_000);
            let good = legacy_cache_candidate("fake-owned-access", 4_102_444_860_000);
            let http: HttpGetFn = Arc::new(|_, token, _| {
                Ok((
                    200,
                    profile_body_org(
                        "same@example.test",
                        if token == "fake-foreign-org" {
                            HELD_ORG
                        } else {
                            FREE_ORG
                        },
                    ),
                ))
            });
            let negative = NegativeCache::new();
            let ctx = legacy_cache_ctx(dir.path(), binding, &http, &negative);
            if cached {
                assert_eq!(
                    reconcile_candidates(&ctx, std::slice::from_ref(&bad), None),
                    ReconcileOutcome::SkippedUnknown
                );
                assert_eq!(negative.len(), 1);
            }
            assert_eq!(
                reconcile_candidates(&ctx, &[bad, good], None),
                ReconcileOutcome::Adopted,
                "cached={cached}"
            );
            let adopted =
                file::load(&identity_store::credentials_path_for(dir.path(), id)).unwrap();
            assert_eq!(
                adopted
                    .expect_anthropic()
                    .claude_ai_oauth
                    .access_token
                    .expose_secret(),
                "fake-owned-access"
            );
            assert_eq!(
                ai::read_stored_anthropic_context(dir.path(), id).unwrap(),
                ai::StoredAnthropicContext::LegacyUnknown
            );
        }
    }

    #[derive(Clone, Default)]
    struct MetadataWarningEvent {
        level: Option<tracing::Level>,
        fields: std::collections::BTreeMap<String, String>,
    }

    impl tracing::field::Visit for MetadataWarningEvent {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields.insert(field.name().into(), value.into());
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().into(), format!("{value:?}"));
        }
    }

    struct MetadataWarningCapture(Arc<std::sync::Mutex<Vec<MetadataWarningEvent>>>);

    impl tracing::Subscriber for MetadataWarningCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
            Some(tracing::metadata::LevelFilter::TRACE)
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut captured = MetadataWarningEvent {
                level: Some(*event.metadata().level()),
                ..Default::default()
            };
            event.record(&mut captured);
            self.0.lock().unwrap().push(captured);
        }
    }

    /// r4 SEC-H2: a SIBLING's unreadable custody is not a metadata fault of the slot being
    /// adopted, so it is never recorded against that slot (which would tell the operator
    /// to log it out). The three metadata faults still classify.
    #[test]
    fn metadata_issue_never_attributes_sibling_custody_or_login_errors_to_the_slot() {
        assert_eq!(
            MetadataIssue::from_error(ai::IdentityError::SiblingCustodyUnreadable {
                sibling: ai::SlotKey::from_key("2")
            }),
            None
        );
        assert_eq!(
            MetadataIssue::from_error(ai::IdentityError::LoginCredentialHeldElsewhere {
                holder: ai::SlotKey::from_key("2")
            }),
            None
        );
        assert_eq!(
            MetadataIssue::from_error(ai::IdentityError::UnsafePermissions),
            Some(MetadataIssue::UnsafePermissions)
        );
        assert_eq!(
            MetadataIssue::from_error(ai::IdentityError::MultipleLinks),
            Some(MetadataIssue::MultipleLinks)
        );
    }

    /// r4 F3/L1: an unreadable sibling is throttled by the SIBLING's key with an injected
    /// clock: one warning per window, a retry after it, and never an `account` attribution.
    #[test]
    fn custodian_sibling_backoff_warns_once_per_window_and_names_the_sibling() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = MetadataRetryState::default();
        let two = ai::SlotKey::from_key("2");
        let now = std::time::Instant::now();
        assert!(!state.sibling_backoff_active(now));
        tracing::subscriber::with_default(MetadataWarningCapture(events.clone()), || {
            for tick in 0..10u64 {
                state.record_sibling(two, now + std::time::Duration::from_secs(tick));
            }
            state.record_sibling(
                ai::SlotKey::from_key("3"),
                now + std::time::Duration::from_secs(11),
            );
            assert!(state.sibling_backoff_active(now + std::time::Duration::from_secs(12)));
            assert!(
                !state.sibling_backoff_active(now + METADATA_RETRY_BACKOFF * 2),
                "the window elapses"
            );
            state.record_sibling(two, now + METADATA_RETRY_BACKOFF * 2);
        });
        let captured = events.lock().unwrap();
        let named: Vec<_> = captured
            .iter()
            .map(|e| e.fields.get("sibling_slot").cloned().unwrap_or_default())
            .collect();
        assert_eq!(
            named,
            ["2", "3", "2"],
            "one warn per sibling per window, then a retry"
        );
        for event in captured.iter() {
            assert_eq!(event.level, Some(tracing::Level::WARN));
            assert_eq!(
                event.fields.get("error_kind").unwrap(),
                "custodian_sibling_custody_unreadable"
            );
            assert!(
                !event.fields.contains_key("account"),
                "never the slot being adopted"
            );
        }
        assert!(state.0.lock().unwrap().backoffs.is_empty());
    }

    /// r4 F3/L1 end to end: slot 2 adopts while slot 3's saved credential is garbage. The
    /// first tick validates once and refuses; later ticks in the window make ZERO profile
    /// calls and add no warning, and the one warning names slot 3, never slot 2.
    #[cfg(unix)]
    #[test]
    fn custodian_unreadable_sibling_defers_profile_calls_and_never_blames_the_slot() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("accounts");
        let slot = AccountNum::try_from(2u16).unwrap();
        setup_legacy_slot_store(&base, slot, "same@example.test", "fake-legacy-access");
        let sibling = identity_store::IdentityId::new_v4();
        let mut pf = profiles::load(&profiles::profiles_path(&base)).unwrap();
        pf.by_slot.insert("3".to_owned(), sibling);
        profiles::save(&profiles::profiles_path(&base), &pf).unwrap();
        let sibling_credential = identity_store::credentials_path_for(&base, sibling);
        std::fs::create_dir_all(sibling_credential.parent().unwrap()).unwrap();
        std::fs::write(&sibling_credential, b"{ not json").unwrap();
        let binding = ai::capture_anthropic_binding(&base, slot).unwrap();
        let calls = calls_counter();
        let observed = calls.clone();
        let http: HttpGetFn = Arc::new(move |_, _, _| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((200, profile_body_org("same@example.test", FREE_ORG)))
        });
        let negative = NegativeCache::new();
        let candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = std::sync::atomic::AtomicUsize::new(0);
        tracing::subscriber::with_default(MetadataWarningCapture(events.clone()), || {
            for tick in 0..5 {
                let ctx = legacy_cache_ctx(&base, binding.clone(), &http, &negative);
                assert_eq!(
                    reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
                    ReconcileOutcome::SkippedUnknown
                );
                if tick == 0 {
                    first_calls.store(n(&calls), std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        let first = first_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(first > 0, "tick 0 reached the profile endpoint");
        assert_eq!(
            n(&calls),
            first,
            "ticks 1..5 in the window make no profile call"
        );
        let captured = events.lock().unwrap();
        let sibling_warnings: Vec<_> = captured
            .iter()
            .filter(|e| {
                e.fields.get("error_kind").map(String::as_str)
                    == Some("custodian_sibling_custody_unreadable")
            })
            .collect();
        assert_eq!(sibling_warnings.len(), 1, "one warning per window");
        assert_eq!(sibling_warnings[0].fields.get("sibling_slot").unwrap(), "3");
        assert!(
            captured.iter().all(|e| !e.fields.contains_key("account")),
            "no metadata warning blames the slot being adopted"
        );
        assert_eq!(
            negative.len(),
            0,
            "an unreadable sibling is never a cached verdict"
        );
    }

    /// r6 M-1 + L2: a KNOWN slot whose same-email LEGACY sibling stands is refused at the
    /// guarded write on every tick. The profile call and the generic write-failed warning
    /// must not repeat: ticks 1..5 make ZERO profile calls, and the one fixed-vocabulary
    /// warning names the sibling slot (3), never the slot being adopted.
    #[cfg(unix)]
    #[test]
    fn custodian_known_slot_with_same_email_legacy_sibling_defers_profile_calls() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("accounts");
        let legacy_slot = AccountNum::try_from(3u16).unwrap();
        setup_legacy_slot_store(
            &base,
            legacy_slot,
            "same@example.test",
            "fake-legacy-access",
        );
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(&base, 2, uuid, "same@example.test", "fake-known-access");
        let slot = AccountNum::try_from(2u16).unwrap();
        let binding = ai::capture_anthropic_binding(&base, slot).unwrap();
        assert!(matches!(
            binding.context(),
            ai::StoredAnthropicContext::Known(_)
        ));
        let calls = calls_counter();
        let observed = calls.clone();
        let http: HttpGetFn = Arc::new(move |_, _, _| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((200, profile_body_org("same@example.test", HELD_ORG)))
        });
        let negative = NegativeCache::new();
        let candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = std::sync::atomic::AtomicUsize::new(0);
        tracing::subscriber::with_default(MetadataWarningCapture(events.clone()), || {
            for tick in 0..5 {
                let ctx = legacy_cache_ctx(&base, binding.clone(), &http, &negative);
                let outcome = reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None);
                assert_eq!(outcome, ReconcileOutcome::SkippedUnknown, "tick {tick}");
                if tick == 0 {
                    first_calls.store(n(&calls), std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        let first = first_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(first > 0, "tick 0 reached the profile endpoint");
        assert_eq!(n(&calls), first, "ticks 1..5 make no profile call");
        let captured = events.lock().unwrap();
        let named: Vec<_> = captured
            .iter()
            .filter(|e| {
                e.fields.get("error_kind").map(String::as_str)
                    == Some("anthropic_known_adoption_same_email_legacy_sibling")
            })
            .collect();
        assert_eq!(named.len(), 1, "one warning per window");
        assert_eq!(named[0].fields.get("sibling_slot").unwrap(), "3");
        assert!(
            captured.iter().all(|e| {
                e.fields.get("error_kind").map(String::as_str)
                    != Some("custodian_adopt_write_failed")
            }),
            "the generic write-failed warning never repeats"
        );
        assert_eq!(negative.len(), 0, "never a cached refusal");
    }

    /// r7 item 5 (corr L-5): the guarded write also refuses a Known adoption while ANOTHER
    /// identity's canonical holds the candidate grant, or cannot be read. Both are named
    /// once and back off, instead of a profile call and an anonymous write-failed warning
    /// on every tick.
    #[cfg(unix)]
    #[test]
    fn custodian_known_slot_with_a_held_or_unreadable_sibling_grant_defers_profile_calls() {
        for (scenario, expected_kind) in [
            ("held", "anthropic_known_adoption_grant_held_elsewhere"),
            ("unreadable", "custodian_sibling_custody_unreadable"),
        ] {
            let _env_guard = crate::platform::test_env::lock();
            let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("accounts");
            // Slot 3 has a DIFFERENT email, so the same-email legacy walk finds nothing.
            let sibling = identity_store::IdentityId::new_v4();
            let sibling_token = if scenario == "held" {
                "fake-candidate-access"
            } else {
                "fake-sibling-access"
            };
            setup_slot_store(&base, 3, sibling, "other@example.test", sibling_token);
            let uuid = identity_store::IdentityId::new_v4();
            setup_slot_store(&base, 2, uuid, "same@example.test", "fake-known-access");
            if scenario == "unreadable" {
                std::fs::write(
                    identity_store::credentials_path_for(&base, sibling),
                    b"{ not json",
                )
                .unwrap();
                crate::platform::fs::secure_file(&identity_store::credentials_path_for(
                    &base, sibling,
                ))
                .unwrap();
            }
            let slot = AccountNum::try_from(2u16).unwrap();
            let binding = ai::capture_anthropic_binding(&base, slot).unwrap();
            let calls = calls_counter();
            let observed = calls.clone();
            let http: HttpGetFn = Arc::new(move |_, _, _| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok((200, profile_body_org("same@example.test", HELD_ORG)))
            });
            let negative = NegativeCache::new();
            let candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let first_calls = std::sync::atomic::AtomicUsize::new(0);
            tracing::subscriber::with_default(MetadataWarningCapture(events.clone()), || {
                for tick in 0..5 {
                    let ctx = legacy_cache_ctx(&base, binding.clone(), &http, &negative);
                    let outcome =
                        reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None);
                    assert_eq!(
                        outcome,
                        ReconcileOutcome::SkippedUnknown,
                        "{scenario} tick {tick}"
                    );
                    if tick == 0 {
                        first_calls.store(n(&calls), std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
            let first = first_calls.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                n(&calls),
                first,
                "{scenario}: ticks 1..5 make no profile call"
            );
            let captured = events.lock().unwrap();
            let named = captured
                .iter()
                .filter(|e| e.fields.get("error_kind").map(String::as_str) == Some(expected_kind))
                .count();
            assert_eq!(named, 1, "{scenario}: one named warning per window");
            assert!(
                captured.iter().all(|e| {
                    e.fields.get("error_kind").map(String::as_str)
                        != Some("custodian_adopt_write_failed")
                }),
                "{scenario}: the generic write-failed warning never appears"
            );
            assert_eq!(negative.len(), 0, "{scenario}: never a cached refusal");
        }
    }

    /// The Known-sibling warning and backoff are per adopting identity and per window.
    #[test]
    fn custodian_known_sibling_backoff_is_per_identity_and_expires() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = MetadataRetryState::default();
        let id = identity_store::IdentityId::new_v4();
        let other = identity_store::IdentityId::new_v4();
        let now = std::time::Instant::now();
        let sibling = ai::SlotKey::from_key("3");
        tracing::subscriber::with_default(MetadataWarningCapture(events.clone()), || {
            assert!(!state.known_sibling_backoff_active(id, now));
            state.record_known_same_email(id, sibling, now);
            state.record_known_same_email(id, sibling, now + std::time::Duration::from_secs(5));
            assert!(state.known_sibling_backoff_active(id, now + std::time::Duration::from_secs(6)));
            assert!(
                !state.known_sibling_backoff_active(other, now),
                "another identity is not held back"
            );
            assert!(!state.known_sibling_backoff_active(id, now + METADATA_RETRY_BACKOFF * 2));
            state.record_known_same_email(id, sibling, now + METADATA_RETRY_BACKOFF * 2);
        });
        assert_eq!(
            events.lock().unwrap().len(),
            2,
            "one warn per window, then a retry"
        );
    }

    #[test]
    fn custodian_metadata_warning_rate_limit_is_per_identity_variant_and_expires() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = MetadataRetryState::default();
        let id = identity_store::IdentityId::new_v4();
        let other = identity_store::IdentityId::new_v4();
        let slot = AccountNum::try_from(2u16).unwrap();
        let now = std::time::Instant::now();
        tracing::subscriber::with_default(MetadataWarningCapture(events.clone()), || {
            for error in [
                ai::IdentityError::LegacyEmailUnparseable,
                ai::IdentityError::UnsafePermissions,
                ai::IdentityError::MultipleLinks,
            ] {
                let issue = MetadataIssue::from_error(error).unwrap();
                state.warn_issue(id, slot, issue, now);
                state.warn_issue(id, slot, issue, now + std::time::Duration::from_secs(1));
            }
            state.warn_issue(other, slot, MetadataIssue::Unparseable, now);
            state.warn_issue(
                id,
                slot,
                MetadataIssue::Unparseable,
                now + METADATA_RETRY_BACKOFF,
            );
        });
        let captured = events.lock().unwrap();
        assert_eq!(
            captured.len(),
            5,
            "per-variant/per-UUID throttle expires at ten minutes"
        );
        for (event, expected_tag, hint_fragment) in [
            (
                &captured[0],
                "custodian_identity_metadata_unparseable",
                "csq login",
            ),
            (
                &captured[1],
                "custodian_identity_metadata_unsafe_permissions",
                "private permissions",
            ),
            (
                &captured[2],
                "custodian_identity_metadata_multiple_links",
                "extra hard links",
            ),
            (
                &captured[3],
                "custodian_identity_metadata_unparseable",
                "csq login",
            ),
            (
                &captured[4],
                "custodian_identity_metadata_unparseable",
                "csq login",
            ),
        ] {
            assert_eq!(event.level, Some(tracing::Level::WARN));
            assert_eq!(event.fields.get("error_kind").unwrap(), expected_tag);
            assert!(event
                .fields
                .get("repair_hint")
                .unwrap()
                .contains(hint_fragment));
            assert_eq!(
                event.fields.keys().map(String::as_str).collect::<Vec<_>>(),
                vec!["account", "error_kind", "message", "repair_hint"]
            );
        }
        assert!(
            state.0.lock().unwrap().backoffs.is_empty(),
            "warning throttle holds no verdict or candidate backoff"
        );
    }

    #[test]
    fn custodian_metadata_retry_cap_evicts_oldest_and_retries_it() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(2u16).unwrap();
        let id =
            setup_legacy_slot_store(dir.path(), slot, "same@example.test", "fake-legacy-access");
        let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
        let metadata = identity_store::identity_json_path_for(dir.path(), id);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
        value["email"] = serde_json::json!("unknown");
        std::fs::write(&metadata, serde_json::to_vec(&value).unwrap()).unwrap();

        let now = std::time::Instant::now();
        let state = MetadataRetryState::default();
        let mut keys = Vec::new();
        let mut candidates = Vec::new();
        {
            let mut maps = state.0.lock().unwrap();
            for index in 0..513u64 {
                let candidate =
                    legacy_cache_candidate(&format!("fake-cap-access-{index}"), 4_102_444_860_000);
                let parsed: CredentialFile = serde_json::from_str(&candidate.raw_json).unwrap();
                let key = MetadataRetryKey::new(&binding, parsed.expect_anthropic()).unwrap();
                keys.push(key);
                candidates.push(parsed);
                remember_metadata_retry(
                    &mut maps.backoffs,
                    key,
                    now - std::time::Duration::from_millis(513 - index),
                );
            }
            assert_eq!(maps.backoffs.len(), 512, "cap is an absolute entry bound");
            assert!(
                !maps.backoffs.contains_key(&keys[0]),
                "oldest key is evicted"
            );
            assert!(
                keys[1..].iter().all(|key| maps.backoffs.contains_key(key)),
                "only the oldest key is evicted, not a younger key"
            );
        }
        assert!(
            state.should_defer(dir.path(), &binding, candidates[1].expect_anthropic(), now),
            "unchanged invalid metadata keeps a retained key backed off"
        );
        assert!(
            !state.should_defer(dir.path(), &binding, candidates[0].expect_anthropic(), now),
            "eviction allows the oldest candidate to retry immediately"
        );
        let calls = calls_counter();
        let observed = calls.clone();
        let http: HttpGetFn = Arc::new(move |_, _, _| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((200, profile_body_org("same@example.test", FREE_ORG)))
        });
        let (verdict, proof, legacy_proof) = verify_candidate_owner(
            dir.path(),
            candidates[0].expect_anthropic(),
            Some(&binding),
            &http,
            &state,
        );
        assert_eq!(verdict, OwnerVerdict::Unknown);
        assert!(proof.is_none() && legacy_proof.is_none());
        assert_eq!(n(&calls), 1, "evicted key actually reaches HTTP validation");
        assert_eq!(state.0.lock().unwrap().backoffs.len(), 512);
    }

    #[test]
    fn custodian_metadata_http_backoff_expires_and_on_demand_views_share_it() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(2u16).unwrap();
        let id =
            setup_legacy_slot_store(dir.path(), slot, "same@example.test", "fake-legacy-access");
        let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
        let metadata = identity_store::identity_json_path_for(dir.path(), id);
        let calls = calls_counter();
        let observed = calls.clone();
        let http: HttpGetFn = Arc::new(move |_, _, _| {
            if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
                value["email"] = serde_json::json!("unknown");
                std::fs::write(&metadata, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            Ok((200, profile_body_org("same@example.test", FREE_ORG)))
        });
        let shared = NegativeCache::new();
        let candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
        {
            let view = NegativeCache::on_demand_view_over(&shared);
            let ctx = legacy_cache_ctx(dir.path(), binding.clone(), &http, &view);
            assert_eq!(
                reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
                ReconcileOutcome::SkippedUnknown
            );
            assert_eq!(n(&calls), 1);
            assert_eq!(view.len(), 0);
        }
        let next_view = NegativeCache::on_demand_view_over(&shared);
        let ctx = legacy_cache_ctx(dir.path(), binding.clone(), &http, &next_view);
        assert_eq!(
            reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
            ReconcileOutcome::SkippedUnknown
        );
        assert_eq!(
            n(&calls),
            1,
            "fresh view in next tick shares pacing, never a negative verdict"
        );
        assert_eq!(shared.len(), 0);
        assert_eq!(next_view.len(), 0);
        let parsed: CredentialFile = serde_json::from_str(&candidate.raw_json).unwrap();
        let now = std::time::Instant::now();
        assert!(shared.metadata_retry.should_defer(
            dir.path(),
            &binding,
            parsed.expect_anthropic(),
            now
        ));
        assert!(!shared.metadata_retry.should_defer(
            dir.path(),
            &binding,
            parsed.expect_anthropic(),
            now + METADATA_RETRY_BACKOFF
        ));
        assert_eq!(
            reconcile_candidates(&ctx, &[candidate], None),
            ReconcileOutcome::SkippedUnknown
        );
        assert_eq!(
            n(&calls),
            2,
            "expired pacing permits a new real validator request"
        );
        assert_eq!(shared.len(), 0);
    }

    #[test]
    fn custodian_repairable_metadata_errors_back_off_without_negative_cache() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for scenario in ["legacy_email", "permissions", "links"] {
            // Attribute error variants are Unix-specific; legacy-email executes everywhere.
            if !cfg!(unix) && scenario != "legacy_email" {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let id = setup_legacy_slot_store(
                dir.path(),
                slot,
                "same@example.test",
                "fake-legacy-access",
            );
            let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            let candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
            let metadata = identity_store::identity_json_path_for(dir.path(), id);
            let modified = metadata.clone();
            let calls = calls_counter();
            let observed = calls.clone();
            let http: HttpGetFn = Arc::new(move |_, _, _| {
                if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    match scenario {
                        "legacy_email" => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&std::fs::read(&modified).unwrap()).unwrap();
                            value["email"] = serde_json::json!("unknown");
                            std::fs::write(&modified, serde_json::to_vec(&value).unwrap()).unwrap();
                        }
                        #[cfg(unix)]
                        "permissions" => {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &modified,
                                std::fs::Permissions::from_mode(0o644),
                            )
                            .unwrap();
                        }
                        #[cfg(unix)]
                        "links" => {
                            std::fs::hard_link(&modified, modified.with_extension("link")).unwrap()
                        }
                        _ => unreachable!(),
                    }
                }
                Ok((200, profile_body_org("same@example.test", FREE_ORG)))
            });
            let negative = NegativeCache::new();
            let ctx = legacy_cache_ctx(dir.path(), binding, &http, &negative);
            assert_eq!(
                reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
                ReconcileOutcome::SkippedUnknown,
                "{scenario}"
            );
            assert_eq!(
                negative.len(),
                0,
                "{scenario}: metadata can be repaired in place"
            );
            assert_eq!(
                n(&calls),
                1,
                "repairable metadata error stops before the own-token request"
            );
            assert_eq!(
                reconcile_candidates(&ctx, &[candidate], None),
                ReconcileOutcome::SkippedUnknown
            );
            assert_eq!(
                n(&calls),
                1,
                "{scenario}: second tick within metadata backoff must spend zero HTTP"
            );
            assert_eq!(negative.len(), 0, "HTTP pacing is never a negative verdict");
        }
    }

    #[test]
    fn custodian_metadata_repair_adopts_immediately_with_same_version_and_generation() {
        let _env_guard = crate::platform::test_env::lock();
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for scenario in ["legacy_email", "permissions", "links"] {
            if !cfg!(unix) && scenario != "legacy_email" {
                continue; // File attribute variants are Unix-specific.
            }
            let dir = tempfile::tempdir().unwrap();
            let slot = AccountNum::try_from(2u16).unwrap();
            let id = setup_legacy_slot_store(
                dir.path(),
                slot,
                "same@example.test",
                "fake-legacy-access",
            );
            let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            let canonical = identity_store::credentials_path_for(dir.path(), id);
            let own_before = std::fs::read(&canonical).unwrap();
            let metadata = identity_store::identity_json_path_for(dir.path(), id);
            let metadata_before = std::fs::read(&metadata).unwrap();
            let profiles_path = profiles::profiles_path(dir.path());
            let profiles_before = std::fs::read(&profiles_path).unwrap();
            let modified = metadata.clone();
            let calls = calls_counter();
            let observed = calls.clone();
            let damaged = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let modify_once = damaged.clone();
            let http: HttpGetFn = Arc::new(move |_, token, _| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Damage after the OWN profile witness, so this reaches the
                // second binding recapture rather than only the first gate.
                if token == "fake-legacy-access"
                    && !modify_once.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    match scenario {
                        "legacy_email" => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&std::fs::read(&modified).unwrap()).unwrap();
                            value["email"] = serde_json::json!("unknown");
                            std::fs::write(&modified, serde_json::to_vec(&value).unwrap()).unwrap();
                        }
                        #[cfg(unix)]
                        "permissions" => {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &modified,
                                std::fs::Permissions::from_mode(0o644),
                            )
                            .unwrap();
                        }
                        #[cfg(unix)]
                        "links" => {
                            std::fs::hard_link(&modified, modified.with_extension("link")).unwrap()
                        }
                        _ => unreachable!(),
                    }
                }
                Ok((200, profile_body_org("same@example.test", FREE_ORG)))
            });
            let negative = NegativeCache::new();
            let ctx = legacy_cache_ctx(dir.path(), binding.clone(), &http, &negative);
            let candidate = legacy_cache_candidate("fake-candidate-access", 4_102_444_860_000);
            assert_eq!(
                reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
                ReconcileOutcome::SkippedUnknown
            );
            assert!(damaged.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(n(&calls), 2, "candidate and own profile were verified");
            assert_eq!(std::fs::read(&canonical).unwrap(), own_before);
            assert_eq!(
                reconcile_candidates(&ctx, std::slice::from_ref(&candidate), None),
                ReconcileOutcome::SkippedUnknown
            );
            assert_eq!(
                n(&calls),
                2,
                "late metadata error also suppresses next-tick HTTP"
            );
            assert_eq!(negative.len(), 0);
            // Simulate the operator correcting only the damaged metadata.
            match scenario {
                "legacy_email" => std::fs::write(&metadata, &metadata_before).unwrap(),
                #[cfg(unix)]
                "permissions" => crate::platform::fs::secure_file(&metadata).unwrap(),
                #[cfg(unix)]
                "links" => std::fs::remove_file(metadata.with_extension("link")).unwrap(),
                _ => unreachable!(),
            }
            let repaired = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
            assert_eq!(
                repaired, binding,
                "repair keeps the exact version, generation and legacy context"
            );
            assert_eq!(std::fs::read(&profiles_path).unwrap(), profiles_before);
            assert_eq!(std::fs::read(&metadata).unwrap(), metadata_before);
            // Reuse the original captured binding AND original cache. No TTL
            // passage, credential rotation or generation bump can explain success.
            assert_eq!(
                reconcile_candidates(&ctx, &[candidate], None),
                ReconcileOutcome::Adopted,
                "{scenario}: repair must take effect immediately"
            );
            assert_eq!(
                n(&calls),
                4,
                "repaired metadata must permit both profile checks"
            );
            assert_eq!(negative.len(), 0);
            let adopted = file::load(&canonical).unwrap();
            assert_eq!(
                adopted
                    .expect_anthropic()
                    .claude_ai_oauth
                    .access_token
                    .expose_secret(),
                "fake-candidate-access"
            );
            assert_eq!(std::fs::read(&profiles_path).unwrap(), profiles_before);
            assert_eq!(std::fs::read(&metadata).unwrap(), metadata_before);
        }
    }

    #[test]
    fn harvest_refuses_legacy_identity_shared_by_several_slots() {
        let dir = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(2u16).unwrap();
        let id =
            setup_legacy_slot_store(dir.path(), slot, "same@example.test", "fake-legacy-access");
        let binding = ai::capture_anthropic_binding(dir.path(), slot).unwrap();
        let parsed: CredentialFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth":{"accessToken":"fake-candidate-access","refreshToken":"fake-candidate-refresh",
                "expiresAt":4102444860000u64,"scopes":["user:inference"]}
        }))
        .unwrap();
        let handle = dir.path().join(format!("term-{}", std::process::id()));
        std::fs::create_dir(&handle).unwrap();
        crate::accounts::markers::write_live_pid(&handle, std::process::id()).unwrap();
        crate::accounts::markers::write_csq_account(&handle, id).unwrap();
        file::save(&handle.join(".credentials.json"), &parsed).unwrap();
        crate::platform::fs::write_new_private(
            &handle.join(".claude.json"),
            br#"{"oauthAccount":{"emailAddress":"same@example.test"}}"#,
        )
        .unwrap();
        // Negative control: the unshared identity harvests its live file.
        assert_eq!(harvest_live_file_candidates(dir.path(), &binding).len(), 1);
        let path = profiles::profiles_path(dir.path());
        let mut pf = profiles::load(&path).unwrap();
        pf.by_slot.insert("4".into(), id);
        profiles::save(&path, &pf).unwrap();
        assert!(harvest_live_file_candidates(dir.path(), &binding).is_empty());
    }
}
