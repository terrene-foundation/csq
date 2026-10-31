//! Exact-grant Anthropic identity and publication authority.
//! Metadata describes an identity; only the injected profile verifier creates
//! ownership proof. Lock order is profiles -> slot -> canonical -> proof.
use super::identity_store::{self, IdentityId};
use super::profiles::{self, ProfilesFile};
use super::profiles_lock::ProfilesFileLock;
use crate::credentials::token_history::{self, Fingerprint};
use crate::credentials::{self, AnthropicCredentialFile, CredentialFile};
use crate::daemon::usage_poller::HttpGetFn;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("anthropic_identity_invalid_context")]
    InvalidContext,
    #[error("anthropic_identity_metadata_refused: run `csq logout N` then `csq login N`; do not hand-edit identity metadata or profiles.json")]
    InvalidMetadata,
    #[error("anthropic_identity_legacy_email_unparseable: the recorded legacy email cannot be verified; run `csq login N` to authenticate the affected slot")]
    LegacyEmailUnparseable,
    #[error("anthropic_identity_bound_metadata_missing: run `csq logout {account}` then `csq login {account}` to replace the broken slot binding")]
    BoundIdentityMetadataMissing { account: u16 },
    #[error("anthropic_identity_snapshot_changed: the file changed while it was read; retry the operation")]
    SnapshotChanged,
    #[error("anthropic_identity_unsafe_permissions: inspect identity.json and credentials.json; restore private permissions only after confirming no other user modified the file, or run `csq logout N` then `csq login N`")]
    UnsafePermissions,
    #[error("anthropic_identity_multiple_links: identity.json or credentials.json has extra hard links; remove the extra links after confirming the file contents, or run `csq logout N` then `csq login N`")]
    MultipleLinks,
    #[error("anthropic_identity_profiles_permissions_refused: run chmod 600 on profiles.json after confirming no other user modified it; if its provenance is untrusted, restore a trusted backup")]
    ProfilesUnsafePermissions,
    #[error("anthropic_identity_profiles_links_refused: remove the extra hard links to profiles.json after confirming its contents; otherwise restore a trusted backup")]
    ProfilesMultipleLinks,
    #[error("anthropic_identity_profiles_snapshot_changed: profiles.json kept changing while it was read; retry the operation")]
    ProfilesSnapshotChanged,
    #[error("anthropic_identity_profiles_read_refused: profiles.json could not be safely read; restore a trusted backup; do not hand-edit identity metadata or profiles.json")]
    ProfilesReadRefused,
    #[error("anthropic_identity_profiles_busy")]
    BindingBusy,
    #[error("anthropic_identity_binding_missing")]
    MissingBinding,
    #[error("anthropic_identity_binding_changed")]
    BindingChanged,
    #[error("anthropic_identity_credential_refused")]
    CredentialRefused,
    #[error("anthropic_identity_io_refused")]
    Io,
    #[error("anthropic_identity_profile_refused")]
    ProfileRefused,
    #[error("anthropic_identity_target_advanced_publication_failed")]
    TargetAdvancedPublicationFailed,
    #[error("anthropic_identity_shared_legacy_refused: this legacy identity is shared by several slots or its organization is already held by another identity; run `csq login N` for each affected slot so each one is verified individually")]
    SharedLegacyIdentity,
    #[error("anthropic_identity_context_index_row_damaged: profiles.json holds a damaged organization record that may belong to this account; restore a trusted profiles.json backup; do not hand-edit identity metadata or profiles.json")]
    DamagedContextIndexRow,
    /// Another slot's saved credential could not be safely read for comparison. The fault
    /// is in THAT slot's custody, never in the slot being adopted: the remedy names no
    /// logout for the slot at hand. The warning that accompanies this error names the
    /// sibling slot.
    #[error("anthropic_identity_sibling_custody_unreadable: slot {sibling}'s saved credential or metadata could not be safely read for comparison; inspect that slot's files (the slot being adopted is unaffected)")]
    SiblingCustodyUnreadable { sibling: SlotKey },
    /// A login produced a credential pair that another identity's saved credential already
    /// holds; publishing it would put two identities on one grant.
    #[error("anthropic_identity_login_credential_held_elsewhere: this login produced a credential that slot {holder} already holds; run `csq login N` again so a fresh credential is issued")]
    LoginCredentialHeldElsewhere { holder: SlotKey },
}
/// A `by_slot` key carried on an error. Display prints the slot number for a key that is a
/// canonical valid [`AccountNum`] and the fixed token `another slot` for anything else, so
/// no attacker-controlled text from `profiles.json` reaches a message or a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotKey(Option<AccountNum>);
impl SlotKey {
    pub fn from_key(key: &str) -> Self {
        // Canonical only: "+1" and "01" parse as u16 but are not the key the writers mint.
        let parsed = key
            .parse::<u16>()
            .ok()
            .and_then(|n| AccountNum::try_from(n).ok())
            .filter(|n| n.to_string() == key);
        SlotKey(parsed)
    }
    pub fn account(self) -> Option<AccountNum> {
        self.0
    }
}
impl fmt::Display for SlotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(n) => write!(f, "{n}"),
            None => f.write_str("another slot"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileCheckFailure {
    #[error("anthropic_profile_dead")]
    Dead,
    #[error("anthropic_profile_rate_limited")]
    RateLimited,
    #[error("anthropic_profile_unknown")]
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AnthropicContext {
    normalized_email: String,
    account_uuid: Uuid,
    organization_uuid: Uuid,
}
impl fmt::Debug for AnthropicContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AnthropicContext([REDACTED])")
    }
}
impl AnthropicContext {
    pub fn new(
        email: &str,
        account_uuid: Uuid,
        organization_uuid: Uuid,
    ) -> Result<Self, IdentityError> {
        let email = email.trim();
        if email.is_empty()
            || email.eq_ignore_ascii_case("unknown")
            || email.len() > 320
            || email.chars().any(|c| c.is_control() || c.is_whitespace())
            || !email.contains('@')
            || account_uuid.is_nil()
            || organization_uuid.is_nil()
        {
            return Err(IdentityError::InvalidContext);
        }
        Ok(Self {
            normalized_email: email.to_ascii_lowercase(),
            account_uuid,
            organization_uuid,
        })
    }
    pub fn email(&self) -> &str {
        &self.normalized_email
    }
    pub fn normalized_email(&self) -> &str {
        &self.normalized_email
    }
    pub fn account_uuid(&self) -> Uuid {
        self.account_uuid
    }
    pub fn organization_uuid(&self) -> Uuid {
        self.organization_uuid
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredAnthropicContext {
    Known(AnthropicContext),
    LegacyUnknown,
}
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialVersion([u8; 32]);
impl fmt::Debug for CredentialVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialVersion([REDACTED])")
    }
}
impl CredentialVersion {
    pub fn for_credentials(creds: &AnthropicCredentialFile) -> Result<Self, IdentityError> {
        let oauth = &creds.claude_ai_oauth;
        let access = oauth.access_token.expose_secret();
        let refresh = oauth.refresh_token.expose_secret();
        if access.is_empty() || refresh.is_empty() || oauth.expires_at == 0 {
            return Err(IdentityError::CredentialRefused);
        }
        let mut digest = Sha256::new();
        digest.update(b"csq-anthropic-exact-pair-v1\0");
        for bytes in [access.as_bytes(), refresh.as_bytes()] {
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        digest.update(oauth.expires_at.to_be_bytes());
        Ok(Self(digest.finalize().into()))
    }
}
pub struct VerifiedAnthropicContext {
    context: AnthropicContext,
    version: CredentialVersion,
    fingerprint: Fingerprint,
}
impl fmt::Debug for VerifiedAnthropicContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedAnthropicContext([REDACTED])")
    }
}
impl VerifiedAnthropicContext {
    pub fn context(&self) -> &AnthropicContext {
        &self.context
    }
    pub fn credential_version(&self) -> CredentialVersion {
        self.version
    }
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeContextExpectation {
    context: AnthropicContext,
}
impl NativeContextExpectation {
    pub fn context(&self) -> &AnthropicContext {
        &self.context
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedBinding {
    namespace: PathBuf,
    slot: AccountNum,
    identity: IdentityId,
    context: StoredAnthropicContext,
    credential_version: CredentialVersion,
    generation: u64,
    legacy_email: Option<String>,
}
impl fmt::Debug for CapturedBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapturedBinding([REDACTED])")
    }
}
impl CapturedBinding {
    pub(crate) fn belongs_to(&self, base: &Path) -> bool {
        std::fs::canonicalize(base).ok().as_ref() == Some(&self.namespace)
    }
    pub fn slot(&self) -> AccountNum {
        self.slot
    }
    pub fn identity(&self) -> IdentityId {
        self.identity
    }
    pub fn context(&self) -> &StoredAnthropicContext {
        &self.context
    }
    pub fn credential_version(&self) -> CredentialVersion {
        self.credential_version
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Display/custody metadata only; equality never grants organization ownership.
    pub fn recorded_legacy_email(&self) -> Option<&str> {
        self.legacy_email.as_deref()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicContextEntry {
    pub email: String,
    pub account_uuid: Uuid,
    pub organization_uuid: Uuid,
    pub identity_uuid: IdentityId,
    /// Preserve future row fields without treating them as identity authority.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}
impl AnthropicContextEntry {
    pub fn context(&self) -> Result<AnthropicContext, IdentityError> {
        AnthropicContext::new(&self.email, self.account_uuid, self.organization_uuid)
    }
    fn new(context: &AnthropicContext, identity_uuid: IdentityId) -> Self {
        Self {
            email: context.email().into(),
            account_uuid: context.account_uuid(),
            organization_uuid: context.organization_uuid(),
            identity_uuid,
            extra: Default::default(),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerVerdict {
    Owned,
    Mismatch,
    Unknown,
}
pub fn compare_verified_owner(
    expected: &StoredAnthropicContext,
    observed: &VerifiedAnthropicContext,
) -> OwnerVerdict {
    match expected {
        StoredAnthropicContext::Known(c) if c == observed.context() => OwnerVerdict::Owned,
        StoredAnthropicContext::Known(_) => OwnerVerdict::Mismatch,
        StoredAnthropicContext::LegacyUnknown => OwnerVerdict::Unknown,
    }
}
/// Negative-only legacy diagnostic. Email equality cannot establish ownership.
/// Call only after exact-grant complete profile verification and custody checks.
pub(crate) fn compare_captured_legacy_email(
    base: &Path,
    captured: &CapturedBinding,
    verified: &VerifiedAnthropicContext,
) -> OwnerVerdict {
    if !captured.belongs_to(base)
        || !matches!(captured.context(), StoredAnthropicContext::LegacyUnknown)
    {
        return OwnerVerdict::Unknown;
    }
    let metadata = match read_json(
        &identity_store::identity_json_path_for(base, captured.identity()),
        true,
    ) {
        Ok(metadata) => metadata,
        Err(_) => return OwnerVerdict::Unknown,
    };
    if metadata.get("provider").and_then(|value| value.as_str()) != Some("anthropic")
        || metadata.get("account_uuid").is_some()
        || metadata.get("organization_uuid").is_some()
    {
        return OwnerVerdict::Unknown;
    }
    let Some(email) = metadata.get("email").and_then(|value| value.as_str()) else {
        return OwnerVerdict::Unknown;
    };
    let email = email.trim();
    if email.is_empty()
        || email.eq_ignore_ascii_case("unknown")
        || email.len() > 320
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
        || !email.contains('@')
    {
        return OwnerVerdict::Unknown;
    }
    if email.eq_ignore_ascii_case(verified.context().normalized_email()) {
        OwnerVerdict::Unknown
    } else {
        OwnerVerdict::Mismatch
    }
}
/// Opaque authority to write a verified candidate ONLY to the captured legacy UUID.
/// Email equality here does not grant organization ownership or index authority.
pub struct LegacyOwnUuidProof {
    captured: CapturedBinding,
    candidate: CredentialVersion,
    context: AnthropicContext,
}
impl fmt::Debug for LegacyOwnUuidProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyOwnUuidProof([REDACTED])")
    }
}
impl LegacyOwnUuidProof {
    pub(crate) fn permits(
        &self,
        base: &Path,
        captured: &CapturedBinding,
        candidate: &AnthropicCredentialFile,
    ) -> bool {
        // The ambiguity re-check runs under the caller's profiles lock, so a
        // second slot bound to this UUID after the proof was minted is seen.
        self.captured.belongs_to(base)
            && self.captured == *captured
            && CredentialVersion::for_credentials(candidate).ok() == Some(self.candidate)
            && read_profiles_snapshot(base).is_ok_and(|pf| {
                legacy_authority_ambiguity(base, &pf, self.captured.identity, &self.context)
                    .is_ok()
                    // Unreadable sibling custody is not "not held": only an
                    // affirmative `Ok(false)` permits the write.
                    && candidate_pair_held_elsewhere(base, &pf, self.captured.identity, candidate)
                        == Ok(false)
            })
    }
}
/// Refuse legacy adoption/upgrade when the authority is ambiguous: the legacy
/// UUID is referenced by more than one `by_slot` entry, the candidate's
/// complete context may be held by another identity's index row, or another
/// `by_slot`-bound identity already carries a Known context for it without an
/// index row (a crash between the upgrade's metadata and index writes). Those slots
/// need a per-slot verified login. Fixed-vocabulary log; no identifier is printed.
pub(crate) fn legacy_authority_ambiguity(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> Result<(), IdentityError> {
    legacy_authority_ambiguity_impl(base, pf, identity, context, true)
}
/// The metadata-only upgrade's ambiguity check. It adopts NO candidate credential: it only
/// records the identity's own verified organization, which is exactly what resolves two
/// legacy slots that share an email. The same-normalised-email clause therefore does not
/// apply here; every other clause does. Mint and `permits` keep the clause.
pub(crate) fn legacy_authority_ambiguity_for_upgrade(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> Result<(), IdentityError> {
    legacy_authority_ambiguity_impl(base, pf, identity, context, false)
}
/// Warn that the F4 exemption was USED, once the upgrade has committed. Names both slots
/// (fixed vocabulary, slot keys only) so the operator can confirm which organization each
/// slot should hold. Emitted only after the metadata and index row are published, so the
/// claim "this slot's upgrade records its own verified organization" is true when read.
fn warn_exemption_used(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) {
    let own = pf
        .by_slot
        .iter()
        .find(|(_, id)| **id == identity)
        .map(|(key, _)| SlotKey::from_key(key));
    for sibling in exempted_same_email_siblings(base, pf, identity, context) {
        tracing::warn!(
            error_kind = "anthropic_legacy_upgrade_same_email_exemption",
            slot = %own.map_or_else(|| "another slot".to_owned(), |k| k.to_string()),
            sibling_slot = %sibling,
            "a legacy slot with the same email stands; this slot's upgrade records its own verified organization; confirm which organization each of the two slots should hold"
        );
    }
}
/// Slot-bound LegacyUnknown siblings with no index row that record the same normalised
/// email as `context`: exactly the identities `known_unindexed_identity_collides` skips
/// when its same-email clause is off. Pure read; unreadable siblings are not listed (the
/// ambiguity check has already refused on those that matter).
fn exempted_same_email_siblings(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> Vec<SlotKey> {
    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for (sibling_slot, other) in pf.by_slot.iter().map(|(slot, id)| (slot, *id)) {
        if other == identity
            || !seen.insert(other)
            || pf
                .anthropic_contexts
                .iter()
                .any(|entry| entry.identity_uuid == other)
        {
            continue;
        }
        if matches!(
            read_stored_anthropic_context_for_comparison(base, other),
            Ok(StoredAnthropicContext::LegacyUnknown)
        ) && matches!(
            recorded_legacy_email_for_comparison(base, other),
            Ok(Some(email)) if email == context.email()
        ) {
            found.push(SlotKey::from_key(sibling_slot));
        }
    }
    found.sort_by_key(|key| key.account().map(AccountNum::get));
    found
}
fn legacy_authority_ambiguity_impl(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
    same_email_clause: bool,
) -> Result<(), IdentityError> {
    let references = pf.by_slot.values().filter(|id| **id == identity).count();
    // Full-context index check: a foreign row that MAY match (a damaged field is a
    // wildcard, as in `validate_target_index`) is ambiguity, and ambiguity refuses. So is
    // a foreign row for the SAME account and organization under ANY email: that is one
    // grant principal, and a provider-side email change leaves stale-email rows behind.
    let foreign_rows = || {
        pf.anthropic_contexts.iter().filter(|entry| {
            entry.identity_uuid != identity
                && (row_may_match_context(entry, context)
                    || (entry.account_uuid == context.account_uuid()
                        && entry.organization_uuid == context.organization_uuid()))
        })
    };
    let held_elsewhere = foreign_rows().next().is_some();
    // A DAMAGED row (its recorded context does not parse) is a different remedy from a
    // healthy one: logging in again cannot clear it, because login refuses on the same
    // row. It takes precedence so the operator is never sent to the command that fails.
    if foreign_rows().any(|entry| entry.context().is_err()) {
        tracing::warn!(
            error_kind = "anthropic_legacy_damaged_index_row_refused",
            "a damaged organization record may belong to this account; restore a trusted profiles.json"
        );
        return Err(IdentityError::DamagedContextIndexRow);
    }
    // The index alone cannot see an identity whose upgrade crashed after its metadata
    // write: that identity is Known with no row. Its context is as much held as an
    // indexed one, so it is read from the metadata the writer produced.
    if references > 1
        || held_elsewhere
        || known_unindexed_identity_collides(base, pf, identity, context, same_email_clause)
    {
        tracing::warn!(
            error_kind = "anthropic_legacy_shared_authority_refused",
            "legacy identity is shared or its organization is held elsewhere; run csq login for each affected slot"
        );
        return Err(IdentityError::SharedLegacyIdentity);
    }
    Ok(())
}
/// True when another identity bound through `by_slot` has NO index row and either
/// carries a Known context that may collide with `context` (equal, or the same account
/// and organization under any email) or has metadata that cannot be classified. Fails
/// CLOSED: this guards a credential write, so an unreadable sibling is not "no
/// collision". Only an absent identity.json (no recorded context at all), an indexed
/// identity (its row is checked by the caller), a LegacyUnknown one (no context to
/// collide) and a positively non-Anthropic one are skipped.
fn known_unindexed_identity_collides(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
    same_email_clause: bool,
) -> bool {
    let mut seen = std::collections::HashSet::new();
    for (sibling_slot, other) in pf.by_slot.iter().map(|(slot, id)| (slot, *id)) {
        if other == identity
            || !seen.insert(other)
            || pf
                .anthropic_contexts
                .iter()
                .any(|entry| entry.identity_uuid == other)
        {
            continue;
        }
        let metadata = identity_store::identity_json_path_for(base, other);
        if matches!(std::fs::symlink_metadata(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        if identity_store::read_identity_provider(base, other).is_some_and(|p| p != "anthropic") {
            continue;
        }
        // Sibling metadata is read for COMPARISON only (see
        // `read_stored_anthropic_context_for_comparison`), never for custody.
        match read_stored_anthropic_context_for_comparison(base, other) {
            Ok(StoredAnthropicContext::LegacyUnknown) => {
                if same_email_clause
                    && legacy_sibling_email_collides(base, sibling_slot, other, context)
                {
                    return true;
                }
            }
            Ok(StoredAnthropicContext::Known(known)) => {
                if known == *context
                    || (known.account_uuid() == context.account_uuid()
                        && known.organization_uuid() == context.organization_uuid())
                {
                    return true;
                }
            }
            Err(_) => {
                warn_sibling_unreadable(sibling_slot, "anthropic_sibling_metadata_unreadable");
                return true;
            }
        }
    }
    false
}
/// Another legacy identity recording the SAME normalised email may be the same grant
/// principal under a rotation that has not reached its saved file yet, so token equality
/// cannot rule it out: that is ambiguous authority, and it needs a per-slot verified login.
/// A recorded email that cannot be read cannot be ruled out either (fails closed, warning
/// names the sibling slot). Shared by the legacy witness (`known_unindexed_identity_collides`)
/// and the Profile (Known) witness (`legacy_sibling_shares_email`).
fn legacy_sibling_email_collides(
    base: &Path,
    sibling_slot: &str,
    other: IdentityId,
    context: &AnthropicContext,
) -> bool {
    match recorded_legacy_email_for_comparison(base, other) {
        Ok(Some(email)) => email == context.email(),
        Ok(None) => false,
        Err(_) => {
            warn_sibling_unreadable(sibling_slot, "anthropic_sibling_metadata_unreadable");
            true
        }
    }
}
/// The Profile (Known) witness's counterpart of the legacy clause: true when a slot-bound
/// LegacyUnknown sibling records the same normalised email as `context`. Its saved file may
/// hold the pre-rotation pair of the very grant the candidate belongs to, which token
/// equality cannot see. Fails closed on a sibling whose metadata cannot be classified.
pub(crate) fn legacy_sibling_shares_email(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> bool {
    known_sibling_block(base, pf, identity, context).is_some()
}
/// Why a sibling blocks a Known identity's adoption (r6): the sibling slot, via [`SlotKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownSiblingBlock {
    /// A slot-bound LegacyUnknown sibling records the same normalised email.
    SameEmail(SlotKey),
    /// A sibling's metadata could not be classified or read.
    Unreadable(SlotKey),
}
/// The first sibling that blocks `identity`'s Known adoption, or `None`. Same walk and
/// fail-closed rules as [`legacy_sibling_shares_email`], which it backs; the custodian
/// uses the reason to warn once and to back off instead of re-validating every tick.
pub(crate) fn known_sibling_block(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> Option<KnownSiblingBlock> {
    let mut seen = std::collections::HashSet::new();
    for (sibling_slot, other) in pf.by_slot.iter().map(|(slot, id)| (slot, *id)) {
        if other == identity || !seen.insert(other) {
            continue;
        }
        let metadata = identity_store::identity_json_path_for(base, other);
        if matches!(std::fs::symlink_metadata(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        if identity_store::read_identity_provider(base, other).is_some_and(|p| p != "anthropic") {
            continue;
        }
        match read_stored_anthropic_context_for_comparison(base, other) {
            Ok(StoredAnthropicContext::LegacyUnknown) => {
                match recorded_legacy_email_for_comparison(base, other) {
                    Ok(Some(email)) if email == context.email() => {
                        return Some(KnownSiblingBlock::SameEmail(SlotKey::from_key(
                            sibling_slot,
                        )));
                    }
                    Ok(_) => (),
                    Err(_) => {
                        warn_sibling_unreadable(
                            sibling_slot,
                            "anthropic_sibling_metadata_unreadable",
                        );
                        return Some(KnownSiblingBlock::Unreadable(SlotKey::from_key(
                            sibling_slot,
                        )));
                    }
                }
            }
            Ok(StoredAnthropicContext::Known(_)) => (),
            Err(_) => {
                warn_sibling_unreadable(sibling_slot, "anthropic_sibling_metadata_unreadable");
                return Some(KnownSiblingBlock::Unreadable(SlotKey::from_key(
                    sibling_slot,
                )));
            }
        }
    }
    None
}
/// Fixed-vocabulary warning that another slot's custody could not be read. It names the
/// SIBLING slot (a slot key, never a token or path) so the operator inspects the slot at
/// fault; it never suggests logout for the slot being adopted.
fn warn_sibling_unreadable(sibling_slot: &str, kind: &'static str) {
    tracing::warn!(
        error_kind = kind,
        sibling_slot = %sibling_slot,
        "another slot's saved credential or metadata could not be read for comparison, so adoption is refused; inspect that slot's files"
    );
}
/// True when more than one slot references this legacy identity (lock-free read).
pub(crate) fn legacy_identity_is_shared(
    base: &Path,
    identity: IdentityId,
) -> Result<bool, IdentityError> {
    let pf = read_profiles_snapshot(base)?;
    Ok(pf.by_slot.values().filter(|id| **id == identity).count() > 1)
}
/// True when `candidate` shares its refresh token or its access token with the canonical
/// credential of ANOTHER identity still bound through `by_slot`. Two identities must never
/// hold one grant: each one's refresher would rotate the shared refresh token and strand
/// the other. Two legacy identities carry no index row, so the index cannot show this; the
/// credentials themselves are the only witness. An identity that positively is not
/// Anthropic holds no Anthropic canonical and is skipped, as is an absent canonical file.
/// A canonical that exists but cannot be read is NOT "not held": the error refuses.
/// Fixed-vocabulary log; no identifier or token is printed.
pub(crate) fn candidate_pair_held_elsewhere(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    candidate: &AnthropicCredentialFile,
) -> Result<bool, IdentityError> {
    candidate_pair_holder(base, pf, identity, candidate).map(|holder| holder.is_some())
}
/// Like [`candidate_pair_held_elsewhere`], but names the slot that holds the grant.
pub(crate) fn candidate_pair_holder(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    candidate: &AnthropicCredentialFile,
) -> Result<Option<SlotKey>, IdentityError> {
    candidate_pair_scan(base, pf, identity, None, candidate)
}
/// The login writer's scan. The slot being logged in is about to REPLACE its prior binding,
/// so an identity referenced ONLY by that slot is not a sibling: once the publication
/// lands nothing refreshes it, it cannot race the new identity, and a damaged canonical
/// of the outgoing binding must not block the login that repairs it. An identity ALSO
/// referenced by another slot stays a sibling, and every other unreadable sibling still
/// refuses.
pub(crate) fn candidate_pair_holder_for_login(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    target_slot_key: &str,
    candidate: &AnthropicCredentialFile,
) -> Result<Option<SlotKey>, IdentityError> {
    candidate_pair_scan(base, pf, identity, Some(target_slot_key), candidate)
}
fn candidate_pair_scan(
    base: &Path,
    pf: &ProfilesFile,
    identity: IdentityId,
    replaced_slot: Option<&str>,
    candidate: &AnthropicCredentialFile,
) -> Result<Option<SlotKey>, IdentityError> {
    use subtle::ConstantTimeEq;
    let wanted = &candidate.claude_ai_oauth;
    let mut seen = std::collections::HashSet::new();
    for (sibling_slot, other) in pf.by_slot.iter().map(|(slot, id)| (slot, *id)) {
        if other == identity || !seen.insert(other) {
            continue;
        }
        // Name the OTHER slot that references this identity when the target slot also does,
        // so an error never blames the slot being logged in.
        let mut sibling_slot = sibling_slot;
        if let Some(target) = replaced_slot {
            let mut referencing = pf
                .by_slot
                .iter()
                .filter(|(_, bound)| **bound == other)
                .map(|(slot, _)| slot)
                .filter(|slot| slot.as_str() != target);
            match referencing.next() {
                None => continue,
                Some(first_other) => sibling_slot = first_other,
            }
        }
        // No provider-metadata skip: a sibling whose identity.json is wrong or damaged must
        // still be compared. A non-Anthropic credential file is skipped below by shape.
        let path = identity_store::credentials_path_for(base, other);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                warn_sibling_unreadable(sibling_slot, "anthropic_sibling_canonical_unreadable");
                return Err(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key(sibling_slot),
                });
            }
            Ok(_) => (),
        }
        let held = match load_anthropic_canonical_for_comparison(&path) {
            Ok(held) => held,
            Err(_) => {
                warn_sibling_unreadable(sibling_slot, "anthropic_sibling_canonical_unreadable");
                return Err(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key(sibling_slot),
                });
            }
        };
        let Some(held) = held.anthropic() else {
            continue;
        };
        let held = &held.claude_ai_oauth;
        // Bitwise `|`, not `||`: both comparisons always run, in constant time.
        let same_grant = held
            .refresh_token
            .expose_secret()
            .as_bytes()
            .ct_eq(wanted.refresh_token.expose_secret().as_bytes())
            | held
                .access_token
                .expose_secret()
                .as_bytes()
                .ct_eq(wanted.access_token.expose_secret().as_bytes());
        if bool::from(same_grant) {
            tracing::warn!(
                error_kind = "anthropic_candidate_pair_held_elsewhere_refused",
                "candidate grant is already held by another identity; run csq login for the affected slot"
            );
            return Ok(Some(SlotKey::from_key(sibling_slot)));
        }
    }
    Ok(None)
}
/// Mint authority to adopt `verified` (the candidate) into a LegacyUnknown UUID.
/// Email equality alone never suffices: `own` MUST be the profile verification of
/// this identity's OWN canonical token (the version captured with the binding),
/// and the candidate's email+account+organization MUST equal it. A shared legacy
/// UUID, an organization already held by another identity, or a candidate grant that
/// another identity's canonical credential already holds, is refused.
pub fn legacy_own_uuid_proof(
    base: &Path,
    captured: &CapturedBinding,
    verified: &VerifiedAnthropicContext,
    own: &VerifiedAnthropicContext,
    candidate: &AnthropicCredentialFile,
) -> Result<LegacyOwnUuidProof, IdentityError> {
    if !captured.belongs_to(base)
        || captured.context != StoredAnthropicContext::LegacyUnknown
        || captured.legacy_email.as_deref() != Some(verified.context().email())
        || recorded_legacy_email(base, captured.identity)?.as_deref()
            != captured.legacy_email.as_deref()
    {
        return Err(IdentityError::InvalidContext);
    }
    if own.version != captured.credential_version || own.context != verified.context {
        tracing::warn!(
            error_kind = "anthropic_legacy_adoption_own_unverified",
            "legacy adoption refused until the identity's own token is verified and matches"
        );
        return Err(IdentityError::InvalidContext);
    }
    // The credential handed in must be the one that was verified.
    if CredentialVersion::for_credentials(candidate)? != verified.version {
        return Err(IdentityError::InvalidContext);
    }
    let pf = read_profiles_snapshot(base)?;
    legacy_authority_ambiguity(base, &pf, captured.identity, &own.context)?;
    if candidate_pair_held_elsewhere(base, &pf, captured.identity, candidate)? {
        return Err(IdentityError::SharedLegacyIdentity);
    }
    Ok(LegacyOwnUuidProof {
        captured: captured.clone(),
        candidate: verified.version,
        context: own.context.clone(),
    })
}
/// Verify the identity's OWN canonical token with the pinned profile transport.
/// Production only; test builds inject the transport via `_with`.
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) fn verify_legacy_own_canonical(
    base: &Path,
    identity: IdentityId,
) -> Result<VerifiedAnthropicContext, ProfileCheckFailure> {
    let http: HttpGetFn = std::sync::Arc::new(crate::http::get_bearer_node);
    verify_legacy_own_canonical_impl(base, identity, &http)
}
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn verify_legacy_own_canonical_with(
    base: &Path,
    identity: IdentityId,
    http_get: &HttpGetFn,
) -> Result<VerifiedAnthropicContext, ProfileCheckFailure> {
    verify_legacy_own_canonical_impl(base, identity, http_get)
}
fn verify_legacy_own_canonical_impl(
    base: &Path,
    identity: IdentityId,
    http_get: &HttpGetFn,
) -> Result<VerifiedAnthropicContext, ProfileCheckFailure> {
    let source = legacy_verification_source(base, identity)
        .map_err(|_| ProfileCheckFailure::Unknown)?
        .ok_or(ProfileCheckFailure::Unknown)?;
    verify_anthropic_context_impl_for_daemon(&source, http_get)
}
fn normalized_legacy_email(value: &serde_json::Value) -> Result<String, IdentityError> {
    let email = value
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or(IdentityError::LegacyEmailUnparseable)?;
    // Reuse strict context email validation without inventing provider UUID authority.
    AnthropicContext::new(email, Uuid::from_u128(1), Uuid::from_u128(1))
        .map(|c| c.normalized_email)
        .map_err(|_| IdentityError::LegacyEmailUnparseable)
}
fn recorded_legacy_email(
    base: &Path,
    identity: IdentityId,
) -> Result<Option<String>, IdentityError> {
    recorded_legacy_email_with(base, identity, true)
}
/// Comparison-only: a SIBLING's recorded email. See `read_stored_anthropic_context_for_comparison`.
fn recorded_legacy_email_for_comparison(
    base: &Path,
    identity: IdentityId,
) -> Result<Option<String>, IdentityError> {
    recorded_legacy_email_with(base, identity, false)
}
fn recorded_legacy_email_with(
    base: &Path,
    identity: IdentityId,
    private: bool,
) -> Result<Option<String>, IdentityError> {
    let json = read_json(
        &identity_store::identity_json_path_for(base, identity),
        private,
    )?;
    if json.get("provider").and_then(|v| v.as_str()) != Some("anthropic") {
        return Err(IdentityError::InvalidMetadata);
    }
    match (json.get("account_uuid"), json.get("organization_uuid")) {
        (None, None) => normalized_legacy_email(&json).map(Some),
        (Some(_), Some(_)) => Ok(None),
        _ => Err(IdentityError::InvalidMetadata),
    }
}
/// UUID-only refresh continuity. The caller separately holds canonical authority
/// and compares the exact original credential version before publishing a rotation.
/// The persisted version is upgrade provenance, never stand-alone write authority.
pub fn refresh_context_matches(
    base: &Path,
    captured: &CapturedBinding,
) -> Result<bool, IdentityError> {
    if !captured.belongs_to(base) || identity_store::is_identity_removed(base, captured.identity) {
        return Ok(false);
    }
    refresh_context_matches_for(
        base,
        captured.identity,
        &captured.context,
        captured.credential_version,
        captured.legacy_email.as_deref(),
    )
}

/// Shared body of [`refresh_context_matches`], also used by ADOPTION
/// (D237 round-2 H-c) so the rescue path re-runs the exact same predicate
/// from the persisted witness rather than a re-implementation.
fn refresh_context_matches_for(
    base: &Path,
    identity: IdentityId,
    captured_context: &StoredAnthropicContext,
    source_version: CredentialVersion,
    legacy_email: Option<&str>,
) -> Result<bool, IdentityError> {
    let current = read_stored_anthropic_context(base, identity)?;
    if &current == captured_context {
        return if *captured_context == StoredAnthropicContext::LegacyUnknown {
            Ok(recorded_legacy_email(base, identity)?.as_deref() == legacy_email)
        } else {
            Ok(true)
        };
    }
    if let (StoredAnthropicContext::LegacyUnknown, StoredAnthropicContext::Known(context)) =
        (captured_context, current)
    {
        let metadata = read_json(
            &identity_store::identity_json_path_for(base, identity),
            true,
        )?;
        let source: CredentialVersion = serde_json::from_value(
            metadata
                .get("legacy_upgrade_source_version")
                .cloned()
                .ok_or(IdentityError::InvalidMetadata)?,
        )
        .map_err(|_| IdentityError::InvalidMetadata)?;
        return Ok(source == source_version && legacy_email == Some(context.email()));
    }
    Ok(false)
}
fn parse_context(
    json: &serde_json::Value,
    email: &str,
    account: &str,
    organization: &str,
) -> Result<AnthropicContext, IdentityError> {
    let e = json
        .pointer(email)
        .and_then(|v| v.as_str())
        .ok_or(IdentityError::InvalidContext)?;
    let a = json
        .pointer(account)
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(IdentityError::InvalidContext)?;
    let o = json
        .pointer(organization)
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(IdentityError::InvalidContext)?;
    AnthropicContext::new(e, a, o)
}
/// Held Windows handle identity; timestamps alone cannot bind a pathname.
#[cfg(windows)]
pub(crate) fn windows_file_identity(file: &std::fs::File) -> Result<(u32, u64), IdentityError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: the live File owns the handle and info points to writable storage.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, info.as_mut_ptr()) };
    if ok == 0 {
        return Err(IdentityError::Io);
    }
    // SAFETY: a successful call initialized the structure.
    let info = unsafe { info.assume_init() };
    if info.dwFileAttributes & 0x0400 != 0 || info.nNumberOfLinks != 1 {
        return Err(IdentityError::InvalidMetadata);
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}
/// Bounded, no-follow parsed snapshot for observational queue bookkeeping.
/// A genuinely absent file returns empty, matching profiles::load. A present
/// empty/malformed body, oversized file, symlink, or read error always refuses.
/// This performs no HTTP, lock acquisition, writes, index validation, or authority
/// grant; callers must independently check selected custody under their witness.
pub(crate) fn read_profiles_snapshot(base: &Path) -> Result<ProfilesFile, IdentityError> {
    read_profiles_file_at(&profiles::profiles_path(base), false)
}
/// The one secure profiles reader (bounded, no-follow, owner-checked). Absent file
/// is empty. `blank_body_is_empty` documents the ONE difference between callers:
/// `profiles::load` historically treats a present whitespace-only body as empty,
/// while the snapshot refuses it.
pub(crate) fn read_profiles_file_at(
    path: &Path,
    blank_body_is_empty: bool,
) -> Result<ProfilesFile, IdentityError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProfilesFile::empty())
        }
        Err(_) => return Err(IdentityError::Io),
        Ok(_) => (),
    }
    read_json_with(path, false, |bytes| {
        if blank_body_is_empty && std::str::from_utf8(bytes).is_ok_and(|t| t.trim().is_empty()) {
            return Ok(ProfilesFile::empty());
        }
        serde_json::from_slice(bytes).map_err(|_| IdentityError::InvalidMetadata)
    })
}
/// Preserve the secure profiles reader's refusal category without forwarding
/// its path or arbitrary parse error text to an operator surface.
fn profiles_read_error(error: crate::error::ConfigError) -> IdentityError {
    if let crate::error::ConfigError::InvalidJson { reason, .. } = error {
        if reason.starts_with("profiles_permissions_refused:") {
            return IdentityError::ProfilesUnsafePermissions;
        }
        if reason.starts_with("profiles_links_refused:") {
            return IdentityError::ProfilesMultipleLinks;
        }
        if reason.starts_with("anthropic_identity_snapshot_changed") {
            return IdentityError::ProfilesSnapshotChanged;
        }
    }
    IdentityError::ProfilesReadRefused
}

/// Read metadata boundedly, refusing symlinks and nonprivate files.
fn read_json(path: &Path, private: bool) -> Result<serde_json::Value, IdentityError> {
    read_json_with(path, private, |bytes| {
        serde_json::from_slice(bytes).map_err(|_| IdentityError::InvalidMetadata)
    })
}
fn read_json_with<T>(
    path: &Path,
    private: bool,
    inspect: impl FnOnce(&[u8]) -> Result<T, IdentityError>,
) -> Result<T, IdentityError> {
    const MAX_BYTES: u64 = 1024 * 1024;
    #[cfg(windows)]
    let before_file = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(path)
            .map_err(|_| IdentityError::Io)?
    };
    #[cfg(windows)]
    let before = before_file.metadata().map_err(|_| IdentityError::Io)?;
    #[cfg(not(windows))]
    let before = std::fs::symlink_metadata(path).map_err(|_| IdentityError::Io)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x0400 != 0 {
            return Err(IdentityError::InvalidMetadata);
        }
    }
    if !before.is_file() || before.len() > MAX_BYTES {
        return Err(IdentityError::InvalidMetadata);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
                                           // Unix permission bits are checked below; Windows file access remains
                                           // governed by the process's existing ACL, not a guessed POSIX mode.
        let _ = private;
    }
    let mut file = options.open(path).map_err(|_| IdentityError::Io)?;
    let held = file.metadata().map_err(|_| IdentityError::Io)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if held.file_attributes() & 0x0400 != 0 {
            return Err(IdentityError::InvalidMetadata);
        }
        if windows_file_identity(&before_file)? != windows_file_identity(&file)?
            || before.len() != held.len()
            || before.last_write_time() != held.last_write_time()
            || before.creation_time() != held.creation_time()
        {
            return Err(IdentityError::SnapshotChanged);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no memory or synchronization preconditions.
        let uid = unsafe { libc::geteuid() };
        if held.uid() != uid {
            return Err(IdentityError::InvalidMetadata);
        }
        if (private && held.mode() & 0o077 != 0) || held.mode() & 0o022 != 0 {
            return Err(IdentityError::UnsafePermissions);
        }
        if held.nlink() != 1 {
            return Err(IdentityError::MultipleLinks);
        }
        if held.dev() != before.dev() || held.ino() != before.ino() {
            return Err(IdentityError::SnapshotChanged);
        }
    }
    if !held.is_file() || held.len() > MAX_BYTES {
        return Err(IdentityError::InvalidMetadata);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IdentityError::Io)?;
    #[cfg(test)]
    profiles::run_profiles_read_hook_for_test(path);
    let after = file.metadata().map_err(|_| IdentityError::Io)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| IdentityError::Io)?;
    if !named.is_file() {
        return Err(IdentityError::InvalidMetadata);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let named_file = options.open(path).map_err(|_| IdentityError::Io)?;
        let named_held = named_file.metadata().map_err(|_| IdentityError::Io)?;
        if named.file_attributes() & 0x0400 != 0 || named_held.file_attributes() & 0x0400 != 0 {
            return Err(IdentityError::InvalidMetadata);
        }
        if windows_file_identity(&named_file)? != windows_file_identity(&file)?
            || named_held.len() != after.len()
            || named_held.last_write_time() != after.last_write_time()
            || named_held.creation_time() != after.creation_time()
            || after.len() != held.len()
            || after.last_write_time() != held.last_write_time()
            || after.creation_time() != held.creation_time()
        {
            return Err(IdentityError::SnapshotChanged);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Unsafe attributes are terminal refusals, never retryable movement.
        if after.uid() != held.uid() || named.uid() != held.uid() {
            return Err(IdentityError::InvalidMetadata);
        }
        if (private && (after.mode() | named.mode()) & 0o077 != 0)
            || (after.mode() | named.mode()) & 0o022 != 0
        {
            return Err(IdentityError::UnsafePermissions);
        }
        if named.nlink() != 1 {
            return Err(IdentityError::MultipleLinks);
        }
        if after.dev() != named.dev()
            || after.ino() != named.ino()
            || after.len() != held.len()
            || after.mtime() != held.mtime()
            || after.mtime_nsec() != held.mtime_nsec()
            || after.ctime() != held.ctime()
            || after.ctime_nsec() != held.ctime_nsec()
        {
            return Err(IdentityError::SnapshotChanged);
        }
    }
    if !named.is_file() || bytes.len() as u64 > MAX_BYTES || bytes.len() as u64 != held.len() {
        return Err(IdentityError::InvalidMetadata);
    }
    inspect(&bytes)
}
pub fn read_native_expectation(
    config_dir: &Path,
) -> Result<NativeContextExpectation, IdentityError> {
    let json = read_json(&config_dir.join(".claude.json"), false)?;
    parse_native_expectation(&json)
}
pub fn parse_native_expectation(
    json: &serde_json::Value,
) -> Result<NativeContextExpectation, IdentityError> {
    Ok(NativeContextExpectation {
        context: parse_context(
            json,
            "/oauthAccount/emailAddress",
            "/oauthAccount/accountUuid",
            "/oauthAccount/organizationUuid",
        )?,
    })
}
/// Metadata-only authority for readers; does not load token files.
pub fn read_stored_context(
    base: &Path,
    identity: IdentityId,
) -> Result<StoredAnthropicContext, String> {
    read_stored_anthropic_context(base, identity).map_err(|error| error.to_string())
}
pub(crate) fn load_anthropic_canonical(path: &Path) -> Result<CredentialFile, IdentityError> {
    read_json_with(path, true, |bytes| {
        serde_json::from_slice(bytes).map_err(|_| IdentityError::CredentialRefused)
    })
}
/// Read a SIBLING's saved credential for token comparison only. Same custody checks as
/// [`load_anthropic_canonical`] (owner, regular file with no symlink, one link, not group/
/// other writable, size cap) except the private-mode bit test: permission bits do not
/// change whether two tokens match, and a loose mode on someone else's file must not
/// block this slot's adoption.
fn load_anthropic_canonical_for_comparison(path: &Path) -> Result<CredentialFile, IdentityError> {
    read_json_with(path, false, |bytes| {
        serde_json::from_slice(bytes).map_err(|_| IdentityError::CredentialRefused)
    })
}
pub fn read_stored_anthropic_context(
    base: &Path,
    identity: IdentityId,
) -> Result<StoredAnthropicContext, IdentityError> {
    read_stored_anthropic_context_with(base, identity, true)
}
/// Read a SIBLING's recorded context for COMPARISON only, never for custody. Keeps the
/// owner, no-group/other-write, one-link, no-symlink and size checks of
/// [`read_stored_anthropic_context`] and drops only the private-mode (`0o077`) test: mode
/// bits do not change which email or context a file records, and a loose mode on
/// another slot's metadata must not block this slot's adoption.
pub(crate) fn read_stored_anthropic_context_for_comparison(
    base: &Path,
    identity: IdentityId,
) -> Result<StoredAnthropicContext, IdentityError> {
    read_stored_anthropic_context_with(base, identity, false)
}
fn read_stored_anthropic_context_with(
    base: &Path,
    identity: IdentityId,
    private: bool,
) -> Result<StoredAnthropicContext, IdentityError> {
    let path = identity_store::identity_json_path_for(base, identity);
    let json = read_json(&path, private)?;
    if json.get("provider").and_then(|v| v.as_str()) != Some("anthropic") {
        return Err(IdentityError::InvalidMetadata);
    }
    match (json.get("account_uuid"), json.get("organization_uuid")) {
        (None, None) => Ok(StoredAnthropicContext::LegacyUnknown),
        (Some(_), Some(_)) => Ok(StoredAnthropicContext::Known(parse_context(
            &json,
            "/email",
            "/account_uuid",
            "/organization_uuid",
        )?)),
        _ => Err(IdentityError::InvalidMetadata),
    }
}
pub fn verify_anthropic_context(
    creds: &AnthropicCredentialFile,
) -> Result<VerifiedAnthropicContext, ProfileCheckFailure> {
    let http: HttpGetFn = std::sync::Arc::new(crate::http::get_bearer_node);
    verify_anthropic_context_impl_for_daemon(creds, &http)
}
#[cfg(any(test, feature = "test-utils"))]
pub fn verify_anthropic_context_with(
    creds: &AnthropicCredentialFile,
    http_get: &HttpGetFn,
) -> Result<VerifiedAnthropicContext, ProfileCheckFailure> {
    verify_anthropic_context_impl_for_daemon(creds, http_get)
}
pub(crate) fn verify_anthropic_context_impl_for_daemon(
    creds: &AnthropicCredentialFile,
    http_get: &HttpGetFn,
) -> Result<VerifiedAnthropicContext, ProfileCheckFailure> {
    let version =
        CredentialVersion::for_credentials(creds).map_err(|_| ProfileCheckFailure::Unknown)?;
    let (status, body) = http_get(
        "https://api.anthropic.com/api/oauth/profile",
        creds.claude_ai_oauth.access_token.expose_secret(),
        &[("anthropic-beta", "oauth-2025-04-20")],
    )
    .map_err(|_| ProfileCheckFailure::Unknown)?;
    match status {
        401 => return Err(ProfileCheckFailure::Dead),
        429 => return Err(ProfileCheckFailure::RateLimited),
        200 => (),
        _ => return Err(ProfileCheckFailure::Unknown),
    }
    let body = zeroize::Zeroizing::new(body);
    if body.len() > 1024 * 1024 {
        return Err(ProfileCheckFailure::Unknown);
    }
    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| ProfileCheckFailure::Unknown)?;
    let context = parse_context(
        &json,
        "/account/email",
        "/account/uuid",
        "/organization/uuid",
    )
    .map_err(|_| ProfileCheckFailure::Unknown)?;
    let fingerprint =
        token_history::fingerprint_from_credential_file(&CredentialFile::Anthropic(creds.clone()))
            .ok_or(ProfileCheckFailure::Unknown)?;
    Ok(VerifiedAnthropicContext {
        context,
        version,
        fingerprint,
    })
}
/// Read the selected UUID's own pair for daemon-only verification.
/// No slot resolution, email lookup, or HTTP occurs here.
pub(crate) fn legacy_verification_source(
    base: &Path,
    identity: IdentityId,
) -> Result<Option<AnthropicCredentialFile>, IdentityError> {
    // A removed identity or an absent credential has nothing to verify: not an
    // error. Unreadable or malformed state below stays refused.
    if identity_store::is_identity_removed(base, identity) {
        return Ok(None);
    }
    if read_stored_anthropic_context(base, identity)? != StoredAnthropicContext::LegacyUnknown {
        return Ok(None);
    }
    recorded_legacy_email(base, identity)?;
    let credentials_path = identity_store::credentials_path_for(base, identity);
    match std::fs::symlink_metadata(&credentials_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(IdentityError::Io),
        Ok(_) => (),
    }
    crate::credentials::file::prepare_anthropic_refresh_directory(base, identity)
        .map_err(|_| IdentityError::Io)?;
    let credential = load_anthropic_canonical(&credentials_path)?;
    credential
        .anthropic()
        .cloned()
        .map(Some)
        .ok_or(IdentityError::CredentialRefused)
}
fn publish_metadata(path: &Path, metadata: &serde_json::Value) -> Result<(), IdentityError> {
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(metadata).map_err(|_| IdentityError::InvalidMetadata)?,
    );
    publish_metadata_bytes(path, &bytes)
}
fn publish_metadata_bytes(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let tmp = crate::platform::fs::unique_tmp_path(path);
    publish_metadata_bytes_at(path, bytes, tmp)
}

fn publish_metadata_bytes_at(
    path: &Path,
    bytes: &[u8],
    tmp: std::path::PathBuf,
) -> Result<(), IdentityError> {
    let result = crate::platform::fs::write_new_private_retained(&tmp, bytes)
        .and_then(|writer| writer.replace(path));
    result.map_err(|_| IdentityError::Io)
}
fn validate_upgrade_index(
    pf: &ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> Result<(), IdentityError> {
    validate_target_index(pf, Some(identity), Some(context), false).map(|_| ())
}
fn publish_upgrade_index(
    base: &Path,
    pf: &mut ProfilesFile,
    identity: IdentityId,
    context: &AnthropicContext,
) -> Result<(), IdentityError> {
    validate_upgrade_index(pf, identity, context)?;
    if pf
        .anthropic_contexts
        .iter()
        .any(|entry| entry.identity_uuid == identity)
    {
        return Ok(());
    }
    let sentinel = identity_store::store_version_path(base);
    if sentinel.exists()
        && crate::daemon::identity_mint::read_store_version_schema(base)
            .is_none_or(|v| v > crate::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT)
    {
        return Err(IdentityError::InvalidMetadata);
    }
    crate::daemon::identity_mint::write_sentinel(&sentinel).map_err(|_| IdentityError::Io)?;
    pf.anthropic_contexts
        .push(AnthropicContextEntry::new(context, identity));
    profiles::save(&profiles::profiles_path(base), pf).map_err(|_| IdentityError::Io)
}
/// Outcome of a metadata-first crash-window repair attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyRepair {
    Repaired,
    Unneeded,
    /// A lock was busy; nothing was done and nothing was refused.
    Deferred,
}
/// Recover the metadata-first crash window under the same profiles -> canonical
/// order. Both locks are try-acquired (busy => Deferred) so the refresher never
/// stalls behind a long holder. Only an identity whose metadata carries a parsable
/// `legacy_upgrade_source_version` (the upgrade's own marker) is re-indexed; any
/// other missing row (e.g. a logout interrupted before cleanup) is refused.
pub(crate) fn repair_legacy_context_index(
    base: &Path,
    identity: IdentityId,
) -> Result<LegacyRepair, IdentityError> {
    let Some(lock) = ProfilesFileLock::try_acquire(base).map_err(|_| IdentityError::Io)? else {
        return Ok(LegacyRepair::Deferred);
    };
    if !lock.protects(base) || identity_store::is_identity_removed(base, identity) {
        return Err(IdentityError::BindingChanged);
    }
    let mut pf = profiles::load(&profiles::profiles_path(base)).map_err(profiles_read_error)?;
    if !pf.by_slot.values().any(|bound| *bound == identity) {
        return Err(IdentityError::BindingChanged);
    }
    crate::credentials::file::prepare_anthropic_refresh_directory(base, identity)
        .map_err(|_| IdentityError::Io)?;
    let path = identity_store::credentials_path_for(base, identity);
    let Some(_canonical) = crate::platform::lock::try_lock_file(&path.with_extension("lock"))
        .map_err(|_| IdentityError::Io)?
    else {
        return Ok(LegacyRepair::Deferred);
    };
    let StoredAnthropicContext::Known(context) = read_stored_anthropic_context(base, identity)?
    else {
        return Ok(LegacyRepair::Unneeded);
    };
    validate_upgrade_index(&pf, identity, &context)?;
    if pf
        .anthropic_contexts
        .iter()
        .any(|entry| entry.identity_uuid == identity)
    {
        return Ok(LegacyRepair::Unneeded);
    }
    let metadata = read_json(
        &identity_store::identity_json_path_for(base, identity),
        true,
    )?;
    let has_upgrade_marker = metadata
        .get("legacy_upgrade_source_version")
        .is_some_and(|value| serde_json::from_value::<CredentialVersion>(value.clone()).is_ok());
    if !has_upgrade_marker {
        tracing::warn!(
            error_kind = "anthropic_index_repair_without_upgrade_marker_refused",
            "known identity lacks an index row and an upgrade marker; operator repair required"
        );
        return Err(IdentityError::InvalidMetadata);
    }
    // The repair is metadata-only; no token is a new proof and no HTTP is performed.
    publish_upgrade_index(base, &mut pf, identity, &context)?;
    Ok(LegacyRepair::Repaired)
}
pub(crate) fn upgrade_verified_legacy_identity(
    base: &Path,
    identity: IdentityId,
    verified: &VerifiedAnthropicContext,
) -> Result<(), IdentityError> {
    upgrade_verified_legacy_identity_with(base, identity, verified, |_, _| Ok(()))
}
fn upgrade_verified_legacy_identity_with(
    base: &Path,
    identity: IdentityId,
    verified: &VerifiedAnthropicContext,
    after_metadata: impl FnOnce(&Path, IdentityId) -> Result<(), IdentityError>,
) -> Result<(), IdentityError> {
    // Busy locks surface as BindingBusy (deferred), never a blocking wait.
    let Some(lock) = ProfilesFileLock::try_acquire(base).map_err(|_| IdentityError::Io)? else {
        return Err(IdentityError::BindingBusy);
    };
    if !lock.protects(base) || identity_store::is_identity_removed(base, identity) {
        return Err(IdentityError::BindingChanged);
    }
    let mut pf = profiles::load(&profiles::profiles_path(base)).map_err(profiles_read_error)?;
    // A retained UUID or email alias is not a live slot's upgrade authority.
    // Check before even repairing directory permissions or writing metadata.
    if !pf.by_slot.values().any(|bound| *bound == identity) {
        return Err(IdentityError::BindingChanged);
    }
    crate::credentials::file::prepare_anthropic_refresh_directory(base, identity)
        .map_err(|_| IdentityError::Io)?;
    let path = identity_store::credentials_path_for(base, identity);
    let Some(_canonical) = crate::platform::lock::try_lock_file(&path.with_extension("lock"))
        .map_err(|_| IdentityError::Io)?
    else {
        return Err(IdentityError::BindingBusy);
    };
    legacy_authority_ambiguity_for_upgrade(base, &pf, identity, verified.context())?;
    validate_upgrade_index(&pf, identity, verified.context())?;
    if read_stored_anthropic_context(base, identity)? != StoredAnthropicContext::LegacyUnknown
        || recorded_legacy_email(base, identity)?.as_deref() != Some(verified.context().email())
    {
        return Err(IdentityError::InvalidContext);
    }
    let current = load_anthropic_canonical(&path)?;
    if CredentialVersion::for_credentials(
        current
            .anthropic()
            .ok_or(IdentityError::CredentialRefused)?,
    )? != verified.version
    {
        return Err(IdentityError::BindingChanged);
    }
    crate::credentials::file::prepare_anthropic_refresh_directory(base, identity)
        .map_err(|_| IdentityError::Io)?;
    let metadata_path = identity_store::identity_json_path_for(base, identity);
    let (mut metadata, original_bytes) = read_json_with(&metadata_path, true, |bytes| {
        let metadata: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| IdentityError::InvalidMetadata)?;
        Ok((metadata, zeroize::Zeroizing::new(bytes.to_vec())))
    })?;
    let fields = metadata
        .as_object_mut()
        .ok_or(IdentityError::InvalidMetadata)?;
    fields.insert(
        "account_uuid".into(),
        serde_json::json!(verified.context().account_uuid()),
    );
    fields.insert(
        "organization_uuid".into(),
        serde_json::json!(verified.context().organization_uuid()),
    );
    fields.insert(
        "legacy_upgrade_source_version".into(),
        serde_json::to_value(verified.version).map_err(|_| IdentityError::InvalidMetadata)?,
    );
    // Metadata FIRST. A crash here is recovered by repair_legacy_context_index.
    publish_metadata(&metadata_path, &metadata)?;
    after_metadata(base, identity)?;
    if let Err(error) = publish_upgrade_index(base, &mut pf, identity, verified.context()) {
        // Exact old metadata is restored on an observed publication error.
        // If restoration itself fails, the validated repair path handles the crash window.
        if publish_metadata_bytes(&metadata_path, &original_bytes).is_err() {
            tracing::warn!(
                error_kind = "anthropic_legacy_upgrade_rollback_failed",
                "legacy metadata needs validated recovery"
            );
        }
        return Err(error);
    }
    warn_exemption_used(base, &pf, identity, verified.context());
    Ok(())
}
pub fn check_native_expectation(
    expected: &NativeContextExpectation,
    observed: &VerifiedAnthropicContext,
) -> Result<(), IdentityError> {
    if expected.context == observed.context {
        Ok(())
    } else {
        Err(IdentityError::InvalidContext)
    }
}
/// Invalid fields are unknown discriminators. A damaged row may match only
/// when every valid discriminator is compatible; such ambiguity always refuses.
fn row_may_match_context(entry: &AnthropicContextEntry, target: &AnthropicContext) -> bool {
    let email = AnthropicContext::new(&entry.email, Uuid::from_u128(1), Uuid::from_u128(1))
        .ok()
        .map(|context| context.normalized_email);
    email.as_deref().is_none_or(|email| email == target.email())
        && (entry.account_uuid.is_nil() || entry.account_uuid == target.account_uuid())
        && (entry.organization_uuid.is_nil()
            || entry.organization_uuid == target.organization_uuid())
}
/// Validate exactly the target's authority, preserving unrelated damaged rows.
/// This never declares the complete index healthy or discards foreign material.
pub(crate) fn validate_target_index(
    pf: &ProfilesFile,
    identity: Option<IdentityId>,
    context: Option<&AnthropicContext>,
    require_entry: bool,
) -> Result<Option<IdentityId>, IdentityError> {
    if identity.is_some_and(|identity| identity.as_uuid().is_nil()) {
        return Err(IdentityError::InvalidMetadata);
    }
    let mut selected_rows = 0;
    let mut context_rows = 0;
    let mut found = None;
    let mut seen_identities = std::collections::HashSet::new();
    let mut seen_contexts = std::collections::HashSet::new();
    let mut unrelated_damage = false;
    for entry in &pf.anthropic_contexts {
        let parsed = entry.context();
        let selected = identity == Some(entry.identity_uuid);
        let possible = context.is_some_and(|target| row_may_match_context(entry, target));
        if selected {
            selected_rows += 1;
            if context.is_none() || parsed.as_ref().ok() != context {
                return Err(IdentityError::InvalidMetadata);
            }
        }
        if possible {
            let target = context.ok_or(IdentityError::InvalidContext)?;
            if parsed.as_ref().ok() != Some(target)
                || identity.is_some_and(|identity| identity != entry.identity_uuid)
            {
                return Err(IdentityError::InvalidContext);
            }
            context_rows += 1;
            found = Some(entry.identity_uuid);
        }
        if selected_rows > 1 || context_rows > 1 {
            return Err(IdentityError::InvalidMetadata);
        }
        if !seen_identities.insert(entry.identity_uuid) {
            unrelated_damage = true;
        }
        match parsed {
            Ok(parsed) => {
                if !seen_contexts.insert(parsed) {
                    unrelated_damage = true;
                }
            }
            Err(_) => unrelated_damage = true,
        }
    }
    // A reusable target UUID must not also occur in a different context row.
    if identity.is_none() {
        if let Some(found) = found {
            let rows: Vec<_> = pf
                .anthropic_contexts
                .iter()
                .filter(|entry| entry.identity_uuid == found)
                .collect();
            if rows.len() != 1
                || rows[0].context().as_ref().ok() != context
                || found.as_uuid().is_nil()
            {
                return Err(IdentityError::InvalidMetadata);
            }
        }
    }
    if require_entry && (selected_rows != 1 || context_rows != 1) {
        return Err(IdentityError::InvalidMetadata);
    }
    if unrelated_damage {
        tracing::warn!(
            error_kind = "anthropic_context_index_foreign_damage",
            "unrelated context rows preserved; correct their recorded metadata without reminting"
        );
    }
    Ok(found)
}
fn capture_with_profiles(
    base: &Path,
    slot: AccountNum,
    pf: &ProfilesFile,
) -> Result<CapturedBinding, IdentityError> {
    let identity = pf
        .by_slot
        .get(&slot.to_string())
        .copied()
        .ok_or(IdentityError::MissingBinding)?;
    if matches!(std::fs::symlink_metadata(identity_store::identity_json_path_for(base, identity)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(IdentityError::BoundIdentityMetadataMissing {
            account: slot.get(),
        });
    }
    let context = read_stored_anthropic_context(base, identity)?;
    match &context {
        StoredAnthropicContext::Known(context) => {
            validate_target_index(pf, Some(identity), Some(context), true)?;
        }
        StoredAnthropicContext::LegacyUnknown => {
            validate_target_index(pf, Some(identity), None, false)?;
        }
    }
    let canonical = load_anthropic_canonical(&identity_store::credentials_path_for(base, identity))
        .map_err(|_| IdentityError::CredentialRefused)?;
    let credential_version = CredentialVersion::for_credentials(
        canonical
            .anthropic()
            .ok_or(IdentityError::CredentialRefused)?,
    )?;
    Ok(CapturedBinding {
        namespace: std::fs::canonicalize(base).map_err(|_| IdentityError::Io)?,
        slot,
        identity,
        legacy_email: if context == StoredAnthropicContext::LegacyUnknown {
            recorded_legacy_email(base, identity)?
        } else {
            None
        },
        context,
        credential_version,
        generation: pf
            .slot_binding_generations
            .get(&slot.to_string())
            .copied()
            .unwrap_or(0),
    })
}
/// Bounded capture. Callers already holding profiles authority must use the
/// explicit locked variant; a second open never blocks on the caller's own lock.
pub fn capture_anthropic_binding(
    base: &Path,
    slot: AccountNum,
) -> Result<CapturedBinding, IdentityError> {
    let lock = ProfilesFileLock::try_acquire(base)
        .map_err(|_| IdentityError::Io)?
        .ok_or(IdentityError::BindingBusy)?;
    capture_anthropic_binding_locked(&lock, base, slot)
}
pub fn capture_anthropic_binding_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    slot: AccountNum,
) -> Result<CapturedBinding, IdentityError> {
    if !lock.protects(base) {
        return Err(IdentityError::InvalidMetadata);
    }
    let pf = profiles::load(&profiles::profiles_path(base)).map_err(profiles_read_error)?;
    capture_with_profiles(base, slot, &pf)
}
pub fn binding_matches_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    expected: &CapturedBinding,
) -> Result<bool, IdentityError> {
    match capture_anthropic_binding_locked(lock, base, expected.slot) {
        Ok(current) => Ok(current == *expected),
        Err(IdentityError::MissingBinding) => Ok(false),
        Err(error) => Err(error),
    }
}
/// Compare custody while permitting canonical token rotation at the same UUID.
pub fn binding_custody_matches_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    expected: &CapturedBinding,
) -> Result<bool, IdentityError> {
    match capture_anthropic_binding_locked(lock, base, expected.slot()) {
        Ok(current) => Ok(current.namespace == expected.namespace
            && current.identity() == expected.identity()
            && current.context() == expected.context()
            && current.generation() == expected.generation()
            && current.legacy_email == expected.legacy_email),
        Err(IdentityError::MissingBinding) => Ok(false),
        Err(error) => Err(error),
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum PriorProvider {
    Anthropic(StoredAnthropicContext),
    Codex,
}
#[derive(Clone, PartialEq, Eq)]
struct PriorBinding {
    identity: IdentityId,
    provider: PriorProvider,
    metadata_version: [u8; 32],
    canonical_version: Option<CredentialVersion>,
}
impl fmt::Debug for PriorBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PriorBinding([REDACTED])")
    }
}
#[derive(Clone, PartialEq, Eq)]
struct IndependentLoginPrior {
    identity_label: Option<String>,
    bindings: Vec<IndependentProviderPrior>,
}
#[derive(Clone, PartialEq, Eq)]
enum IndependentProviderPrior {
    Gemini([u8; 32]),
    Native(crate::providers::catalog::Surface, [u8; 32]),
    ClaudeSettings([u8; 32]),
}
impl fmt::Debug for IndependentLoginPrior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IndependentLoginPrior([REDACTED])")
    }
}
fn optional_login_json(
    path: &Path,
    private: bool,
) -> Result<Option<serde_json::Value>, IdentityError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(IdentityError::Io),
        Ok(_) => read_json(path, private).map(Some),
    }
}
fn login_json_digest(value: &serde_json::Value) -> Result<[u8; 32], IdentityError> {
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| IdentityError::InvalidMetadata)?,
    );
    Ok(Sha256::digest(&*bytes).into())
}
// These are independent provider custody witnesses, never Anthropic proof.
fn capture_independent_login_prior(
    base: &Path,
    slot: AccountNum,
    pf: &ProfilesFile,
) -> Result<IndependentLoginPrior, IdentityError> {
    use crate::providers::{catalog::Surface, gemini::provisioning as gemini, native};
    let mut bindings = Vec::new();
    if let Some(value) = optional_login_json(&gemini::binding_path(base, slot), true)? {
        let binding: gemini::GeminiBinding =
            serde_json::from_value(value.clone()).map_err(|_| IdentityError::InvalidMetadata)?;
        if binding.v != gemini::BINDING_SCHEMA_VERSION {
            return Err(IdentityError::InvalidMetadata);
        }
        bindings.push(IndependentProviderPrior::Gemini(login_json_digest(&value)?));
    }
    for surface in [Surface::Kimi, Surface::Grok] {
        if let Some(value) = optional_login_json(&native::marker_path(base, slot, surface), true)? {
            let binding: native::NativeBinding = serde_json::from_value(value.clone())
                .map_err(|_| IdentityError::InvalidMetadata)?;
            if binding.v != native::NATIVE_BINDING_SCHEMA_VERSION
                || binding.surface != surface.as_str()
            {
                return Err(IdentityError::InvalidMetadata);
            }
            bindings.push(IndependentProviderPrior::Native(
                surface,
                login_json_digest(&value)?,
            ));
        }
    }
    let config = base.join(format!("config-{}", slot.get()));
    match std::fs::symlink_metadata(&config) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(IdentityError::InvalidMetadata);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(IdentityError::Io),
        _ => (),
    }
    let settings_path = config.join("settings.json");
    match std::fs::symlink_metadata(&settings_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(IdentityError::Io),
        Ok(_) => {
            let digest = read_json_with(&settings_path, false, |bytes| {
                let raw = std::str::from_utf8(bytes).map_err(|_| IdentityError::InvalidMetadata)?;
                // The existing guarded parser wipes complete/partial trees on
                // every exit. Hash borrowed fields; never clone token strings.
                crate::credentials::keychain::inspect_secret_json(raw, |settings| {
                    let object = settings.as_object().ok_or(IdentityError::InvalidMetadata)?;
                    let env = match object.get("env") {
                        Some(value) => {
                            Some(value.as_object().ok_or(IdentityError::InvalidMetadata)?)
                        }
                        None => None,
                    };
                    let relevant = |key: &str| {
                        key.starts_with("ANTHROPIC_")
                            || key.starts_with("CLAUDE_CODE_USE_")
                            || matches!(
                                key,
                                "CLOUD_ML_REGION"
                                    | "GOOGLE_APPLICATION_CREDENTIALS"
                                    | "AWS_REGION"
                                    | "AWS_BEARER_TOKEN_BEDROCK"
                            )
                    };
                    let mut entries = Vec::new();
                    for (scope, values) in [("root", Some(object)), ("env", env)] {
                        if let Some(values) = values {
                            for (key, value) in values.iter().filter(|(key, _)| relevant(key)) {
                                let value = value.as_str().ok_or(IdentityError::InvalidMetadata)?;
                                entries.push((scope, key.as_str(), value));
                            }
                        }
                    }
                    if entries.is_empty() {
                        return Ok(None);
                    }
                    entries.sort_unstable_by_key(|(scope, key, _)| (*scope, *key));
                    let mut digest = Sha256::new();
                    digest.update(b"csq-independent-claude-settings-v1\0");
                    for (scope, key, value) in entries {
                        for field in [scope, key, value] {
                            digest.update((field.len() as u64).to_be_bytes());
                            digest.update(field.as_bytes());
                        }
                    }
                    Ok(Some(<[u8; 32]>::from(digest.finalize())))
                })
                .ok_or(IdentityError::InvalidMetadata)?
            })?;
            if let Some(digest) = digest {
                bindings.push(IndependentProviderPrior::ClaudeSettings(digest));
            }
        }
    }
    Ok(IndependentLoginPrior {
        identity_label: pf.by_slot_identity.get(&slot.to_string()).cloned(),
        bindings,
    })
}
#[derive(Debug, Clone)]
pub struct LoginPrior {
    namespace: PathBuf,
    slot: AccountNum,
    generation: u64,
    binding: Option<PriorBinding>,
    independent: IndependentLoginPrior,
}
fn capture_prior_binding(
    base: &Path,
    slot: AccountNum,
    identity: IdentityId,
    pf: &ProfilesFile,
) -> Result<PriorBinding, IdentityError> {
    let metadata_path = identity_store::identity_json_path_for(base, identity);
    // A new login cannot safely guess custody for missing bound metadata.
    // Logout removes the explicit binding before a fresh verified login.
    if matches!(std::fs::symlink_metadata(&metadata_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(IdentityError::BoundIdentityMetadataMissing {
            account: slot.get(),
        });
    }
    let metadata = read_json(&metadata_path, true)?;
    let provider = match metadata.get("provider").and_then(|v| v.as_str()) {
        Some("anthropic") => {
            let context = read_stored_anthropic_context(base, identity)?;
            match &context {
                StoredAnthropicContext::Known(context) => {
                    validate_target_index(pf, Some(identity), Some(context), true)?;
                }
                StoredAnthropicContext::LegacyUnknown => {
                    validate_target_index(pf, Some(identity), None, false)?;
                }
            }
            PriorProvider::Anthropic(context)
        }
        Some("codex")
            if !pf
                .anthropic_contexts
                .iter()
                .any(|entry| entry.identity_uuid == identity) =>
        {
            PriorProvider::Codex
        }
        _ => return Err(IdentityError::InvalidMetadata),
    };
    let metadata_bytes =
        serde_json::to_vec(&metadata).map_err(|_| IdentityError::InvalidMetadata)?;
    let metadata_version: [u8; 32] = Sha256::digest(&metadata_bytes).into();
    let canonical_path = match &provider {
        PriorProvider::Anthropic(_) => identity_store::credentials_path_for(base, identity),
        PriorProvider::Codex => identity_store::credentials_codex_path_for(base, identity),
    };
    let canonical_version = match std::fs::symlink_metadata(&canonical_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(IdentityError::Io),
        Ok(_) => {
            let loaded = match load_anthropic_canonical(&canonical_path) {
                Ok(credential) => Some(credential),
                // A slot's OWN saved credential that is damaged (garbage, loose mode,
                // extra link, symlink) has nothing usable to protect, and refusing here
                // would lock the operator out of the very login that replaces it. It is
                // recorded as "no canonical" (`None`); a transient `SnapshotChanged` or an
                // I/O error still refuses. LEGACY priors only: a legacy slot's re-login
                // mints a NEW identity and never writes this file. A Known or Codex prior
                // keeps the rule that a malformed present canonical is never treated as
                // absent (`malformed_present_prior_never_treated_as_absent`).
                Err(
                    IdentityError::CredentialRefused
                    | IdentityError::UnsafePermissions
                    | IdentityError::MultipleLinks
                    | IdentityError::InvalidMetadata,
                ) if matches!(
                    provider,
                    PriorProvider::Anthropic(StoredAnthropicContext::LegacyUnknown)
                ) =>
                {
                    tracing::warn!(
                        error_kind = "anthropic_login_prior_canonical_unreadable",
                        "the slot's saved credential could not be read; the login replaces it"
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            match loaded {
                None => None,
                Some(credential) => Some(match (&provider, &credential) {
                    (PriorProvider::Anthropic(_), CredentialFile::Anthropic(creds)) => {
                        CredentialVersion::for_credentials(creds)?
                    }
                    (PriorProvider::Codex, CredentialFile::Codex(_)) => {
                        let bytes = zeroize::Zeroizing::new(
                            serde_json::to_vec(&credential)
                                .map_err(|_| IdentityError::CredentialRefused)?,
                        );
                        CredentialVersion(Sha256::digest(&*bytes).into())
                    }
                    _ => return Err(IdentityError::CredentialRefused),
                }),
            }
        }
    };
    Ok(PriorBinding {
        identity,
        provider,
        metadata_version,
        canonical_version,
    })
}
pub fn capture_login_prior(base: &Path, slot: AccountNum) -> Result<LoginPrior, IdentityError> {
    let lock = ProfilesFileLock::acquire_bounded(base)
        .map_err(|_| IdentityError::Io)?
        .ok_or(IdentityError::BindingBusy)?;
    let pf = profiles::load(&profiles::profiles_path(base)).map_err(profiles_read_error)?;
    let binding = pf
        .by_slot
        .get(&slot.to_string())
        .copied()
        .map(|identity| capture_prior_binding(base, slot, identity, &pf))
        .transpose()?;
    if !lock.protects(base) {
        return Err(IdentityError::InvalidMetadata);
    }
    let independent = capture_independent_login_prior(base, slot, &pf)?;
    Ok(LoginPrior {
        namespace: std::fs::canonicalize(base).map_err(|_| IdentityError::Io)?,
        slot,
        generation: pf
            .slot_binding_generations
            .get(&slot.to_string())
            .copied()
            .unwrap_or(0),
        binding,
        independent,
    })
}
fn login_prior_matches(
    base: &Path,
    slot: AccountNum,
    prior: &LoginPrior,
    pf: &ProfilesFile,
) -> Result<bool, IdentityError> {
    if capture_independent_login_prior(base, slot, pf)? != prior.independent {
        return Ok(false);
    }
    let current = pf
        .by_slot
        .get(&slot.to_string())
        .copied()
        .map(|identity| capture_prior_binding(base, slot, identity, pf))
        .transpose()?;
    Ok(match (&prior.binding, &current) {
        (None, None) => true,
        (Some(before), Some(now)) => login_prior_binding_matches(before, now),
        _ => false,
    })
}
fn login_prior_binding_matches(before: &PriorBinding, now: &PriorBinding) -> bool {
    // The daemon may upgrade the SAME UUID Legacy -> Known during the
    // browser wait; that rewrites the metadata and is not a rebind.
    let upgraded = matches!(
        (&before.provider, &now.provider),
        (
            PriorProvider::Anthropic(StoredAnthropicContext::LegacyUnknown),
            PriorProvider::Anthropic(StoredAnthropicContext::Known(_))
        )
    );
    before.identity == now.identity
        && (before.provider == now.provider || upgraded)
        && (before.metadata_version == now.metadata_version || upgraded)
        && matches!(
            (before.canonical_version, now.canonical_version),
            (None, None) | (Some(_), Some(_))
        )
}
pub struct CommittedAnthropicLogin {
    binding: CapturedBinding,
    independent: IndependentLoginPrior,
    mirror: Option<super::login::LoginMirrorContext>,
    fingerprint: Fingerprint,
}
impl fmt::Debug for CommittedAnthropicLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommittedAnthropicLogin([REDACTED])")
    }
}
impl CommittedAnthropicLogin {
    pub fn identity(&self) -> IdentityId {
        self.binding.identity
    }
    pub fn context(&self) -> &StoredAnthropicContext {
        &self.binding.context
    }
    pub fn email(&self) -> &str {
        match &self.binding.context {
            StoredAnthropicContext::Known(c) => c.email(),
            StoredAnthropicContext::LegacyUnknown => "unknown",
        }
    }
    pub fn binding(&self) -> &CapturedBinding {
        &self.binding
    }
    pub(crate) fn independent_matches_locked(
        &self,
        lock: &ProfilesFileLock,
        base: &Path,
    ) -> Result<bool, IdentityError> {
        if !lock.protects(base) || !self.binding.belongs_to(base) {
            return Err(IdentityError::InvalidMetadata);
        }
        let pf = profiles::load(&profiles::profiles_path(base)).map_err(profiles_read_error)?;
        Ok(capture_independent_login_prior(base, self.binding.slot(), &pf)? == self.independent)
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        CapturedBinding,
        Option<super::login::LoginMirrorContext>,
        Fingerprint,
    ) {
        (self.binding, self.mirror, self.fingerprint)
    }
}
pub fn commit_anthropic_login(
    base: &Path,
    slot: AccountNum,
    credential: &CredentialFile,
    expected: Option<&NativeContextExpectation>,
    prior: LoginPrior,
) -> Result<CommittedAnthropicLogin, IdentityError> {
    let incoming = credential
        .anthropic()
        .ok_or(IdentityError::CredentialRefused)?;
    let verified = verify_anthropic_context(incoming).map_err(|_| IdentityError::ProfileRefused)?;
    commit_verified_login(base, slot, incoming, verified, expected, prior)
}
pub fn commit_anthropic_login_sealed(
    base: &Path,
    slot: AccountNum,
    credential: &CredentialFile,
    expected: Option<&NativeContextExpectation>,
    prior: LoginPrior,
    seal: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<CommittedAnthropicLogin> {
    let incoming = credential
        .anthropic()
        .ok_or(IdentityError::CredentialRefused)?;
    let verified = verify_anthropic_context(incoming).map_err(|_| IdentityError::ProfileRefused)?;
    // Preserve the caller's typed cancellation error through the legacy identity
    // error boundary, so pre-seal refusal retains the caller's exit classification.
    let mut seal_error = None;
    let result =
        commit_verified_login_sealed(base, slot, incoming, verified, expected, prior, || {
            seal().map_err(|error| {
                seal_error = Some(error);
                anyhow::anyhow!("login publication refused")
            })
        });
    match seal_error {
        Some(error) => Err(error),
        None => result.map_err(anyhow::Error::from),
    }
}
/// Inject only the profile transport; validation, locking, seal placement and
/// publication are identical to the production sealed commit.
#[cfg(any(test, feature = "test-utils"))]
pub fn commit_anthropic_login_with_seal(
    base: &Path,
    slot: AccountNum,
    credential: &CredentialFile,
    http_get: &HttpGetFn,
    expected: Option<&NativeContextExpectation>,
    prior: LoginPrior,
    seal: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<CommittedAnthropicLogin> {
    let incoming = credential
        .anthropic()
        .ok_or(IdentityError::CredentialRefused)?;
    let verified = verify_anthropic_context_with(incoming, http_get)
        .map_err(|_| IdentityError::ProfileRefused)?;
    let mut seal_error = None;
    let result =
        commit_verified_login_sealed(base, slot, incoming, verified, expected, prior, || {
            seal().map_err(|error| {
                seal_error = Some(error);
                anyhow::anyhow!("login publication refused")
            })
        });
    match seal_error {
        Some(error) => Err(error),
        None => result.map_err(anyhow::Error::from),
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub fn commit_anthropic_login_with(
    base: &Path,
    slot: AccountNum,
    credential: &CredentialFile,
    http_get: &HttpGetFn,
    expected: Option<&NativeContextExpectation>,
    prior: LoginPrior,
) -> Result<CommittedAnthropicLogin, IdentityError> {
    let incoming = credential
        .anthropic()
        .ok_or(IdentityError::CredentialRefused)?;
    let verified = verify_anthropic_context_with(incoming, http_get)
        .map_err(|_| IdentityError::ProfileRefused)?;
    commit_verified_login(base, slot, incoming, verified, expected, prior)
}
/// A rescue record written BEFORE the profiles lock (D237 round-2 N4 / M4).
///
/// Drop semantics are the safety property: once written, the record is
/// removed only when this publication deliberately refuses the grant or a
/// later writer takes ownership of it. A profiles-lock failure, or any
/// I/O-class failure while the publication reads or writes supporting state,
/// calls [`PrelockLoginRescue::keep`] so the consumed grant stays durable for
/// adoption; a deliberate refusal removes it. The record's writer-liveness
/// sidecar (R3 sec M-A / corr L-7) is held by the record handle and releases
/// when the handle drops.
///
/// Refusal is the DEFAULT (ROOT ruling): the record carries `prelock: true`
/// and readers act on it only after a keep path wrote its kept marker. So a
/// refusal is durable even when its unlink fails, and a hard crash in the
/// middle of the publication loses the fresh grant — the previous canonical
/// is untouched and the user signs in again, which is the safe direction.
struct PrelockLoginRescue {
    path: Option<crate::credentials::file::PrelockRescue>,
    identity: Option<IdentityId>,
    keep: bool,
}

impl PrelockLoginRescue {
    fn none() -> Self {
        Self {
            path: None,
            identity: None,
            keep: false,
        }
    }

    /// Writes the pre-lock record for a re-login whose prior binding is
    /// Anthropic. Returns `none()` for a first login / non-Anthropic prior —
    /// there is no already-bound identity directory to rescue into.
    fn write(
        base: &Path,
        prior: &LoginPrior,
        incoming: &AnthropicCredentialFile,
        verified: &VerifiedAnthropicContext,
    ) -> Self {
        let Some(binding) = prior.binding.as_ref() else {
            return Self::none();
        };
        if !matches!(binding.provider, PriorProvider::Anthropic(_)) {
            return Self::none();
        }
        match crate::credentials::file::write_login_prelock_rescue(
            base,
            binding.identity,
            incoming,
            verified,
        ) {
            Some(record) => Self {
                path: Some(record),
                identity: Some(binding.identity),
                keep: false,
            },
            None => Self::none(),
        }
    }

    /// The run may not place the grant (profiles lock unavailable, or an
    /// I/O-class failure): the durable record must survive this unwind for
    /// the next tick's adoption.
    fn keep(&mut self) {
        self.keep = true;
    }

    /// Records an early return between [`Self::write`] and [`Self::take_for`]
    /// (R3 corr M-3).
    ///
    /// The record is the ONLY durable copy of a consumed login grant, and
    /// every `?` in that window used to drop it with `keep=false`, so a
    /// transient read failure destroyed the grant. A step that could not
    /// read or write the state it needs has decided nothing about the grant:
    /// retain it, and let the next adoption re-run every custody gate before
    /// installing.
    fn retain_on_failure<T>(
        &mut self,
        result: Result<T, IdentityError>,
    ) -> Result<T, IdentityError> {
        if result.is_err() {
            self.keep();
        }
        result
    }

    /// A custody-capture step's result: its typed semantic refusals
    /// (`BindingChanged`, `InvalidMetadata`, `InvalidContext`) remove the
    /// record, because adoption must not later install a grant this
    /// publication deliberately refused. Every other failure — the step
    /// could not read or prove the state — retains it (R3 corr M-3).
    fn retain_unless_refused<T>(
        &mut self,
        result: Result<T, IdentityError>,
    ) -> Result<T, IdentityError> {
        if let Err(error) = &result {
            if !matches!(
                error,
                IdentityError::BindingChanged
                    | IdentityError::InvalidMetadata
                    | IdentityError::InvalidContext
            ) {
                self.keep();
            }
        }
        result
    }

    /// Hands the record to a writer for `identity`, or durably refuses it
    /// when the resolved target is a different identity (the grant must not
    /// be installed at one identity the slot is not bound to). See
    /// `file::refuse_prelock_rescue` for the writer-liveness guard.
    fn take_for(
        &mut self,
        identity: IdentityId,
    ) -> Option<crate::credentials::file::PrelockRescue> {
        if self.identity != Some(identity) {
            crate::credentials::file::refuse_prelock_rescue(self.path.take());
            return None;
        }
        self.path.take()
    }
}

impl Drop for PrelockLoginRescue {
    fn drop(&mut self) {
        let record = self.path.take();
        if self.keep {
            // Kept for adoption: the kept marker is written BEFORE the
            // liveness guard drops; without it the record is refused.
            crate::credentials::file::keep_prelock_rescue(record);
        } else {
            crate::credentials::file::refuse_prelock_rescue(record);
        }
    }
}

fn commit_verified_login(
    base: &Path,
    slot: AccountNum,
    incoming: &AnthropicCredentialFile,
    verified: VerifiedAnthropicContext,
    expected: Option<&NativeContextExpectation>,
    prior: LoginPrior,
) -> Result<CommittedAnthropicLogin, IdentityError> {
    commit_verified_login_sealed(base, slot, incoming, verified, expected, prior, || Ok(()))
}
fn commit_verified_login_sealed(
    base: &Path,
    slot: AccountNum,
    incoming: &AnthropicCredentialFile,
    verified: VerifiedAnthropicContext,
    expected: Option<&NativeContextExpectation>,
    prior: LoginPrior,
    seal: impl FnOnce() -> anyhow::Result<()>,
) -> Result<CommittedAnthropicLogin, IdentityError> {
    if let Some(expected) = expected {
        check_native_expectation(expected, &verified)?;
    }
    // D237 round-2 corr N4 / security M4: the code exchange already consumed
    // the grant, and the profiles lock can be held for the whole COMMIT-class
    // budget by another publication's canonical wait. Rescue FIRST, before
    // ANY lock.
    let mut prelock_rescue = PrelockLoginRescue::write(base, &prior, incoming, &verified);
    let lock = match ProfilesFileLock::acquire_bounded(base)
        .map_err(|_| IdentityError::Io)
        .and_then(|lock| lock.ok_or(IdentityError::BindingBusy))
    {
        Ok(lock) => lock,
        Err(error) => {
            prelock_rescue.keep();
            return Err(error);
        }
    };
    publish_login_locked_rescued(
        &lock,
        base,
        slot,
        incoming,
        &verified,
        &prior,
        (&mut prelock_rescue, seal),
    )
}
fn publish_login_locked_rescued(
    lock: &ProfilesFileLock,
    base: &Path,
    slot: AccountNum,
    incoming: &AnthropicCredentialFile,
    verified: &VerifiedAnthropicContext,
    prior: &LoginPrior,
    publication: (&mut PrelockLoginRescue, impl FnOnce() -> anyhow::Result<()>),
) -> Result<CommittedAnthropicLogin, IdentityError> {
    let (prelock, seal) = publication;
    publish_login_locked_with_rescue(
        lock,
        base,
        slot,
        incoming,
        verified,
        prior,
        (profiles::save, seal),
        prelock,
    )
}
#[cfg(test)]
type LoginPrewriteMetadataHook = Box<dyn FnOnce()>;
#[cfg(test)]
std::thread_local! {
    // One-shot and thread-scoped: model a metadata mutation after the earlier
    // prior check without adding any production authority or callback.
    static LOGIN_PREWRITE_METADATA_HOOK: std::cell::RefCell<Option<LoginPrewriteMetadataHook>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn run_login_prewrite_metadata_hook() {
    let hook = LOGIN_PREWRITE_METADATA_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
std::thread_local! {
    // One-shot and thread-scoped: models a transient failure to READ
    // profiles.json at the publication's first read (R3 corr M-3). Real read
    // failures cannot be forced from a test without racing the shared
    // filesystem, and the hook adds no production authority.
    static PROFILES_LOAD_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn arm_profiles_load_fault() {
    PROFILES_LOAD_FAULT.with(|armed| armed.set(true));
}
#[cfg(test)]
fn take_profiles_load_fault() -> bool {
    PROFILES_LOAD_FAULT.with(|armed| armed.replace(false))
}

/// Reads `profiles.json` for the pre-lock publication.
///
/// Split out so the read failure has ONE site for the rescue disposition
/// (R3 corr M-3) and one test seam.
fn load_login_profiles(base: &Path) -> Result<ProfilesFile, crate::error::ConfigError> {
    #[cfg(test)]
    if take_profiles_load_fault() {
        // Model a transient read failure: the same ConfigError shape a real
        // reader returns, so the caller's mapping is exercised unchanged.
        return Err(crate::error::ConfigError::InvalidJson {
            path: profiles::profiles_path(base),
            reason: "injected_read_failure".to_string(),
        });
    }
    profiles::load(&profiles::profiles_path(base))
}

#[cfg(test)]
fn publish_login_locked_with<F>(
    lock: &ProfilesFileLock,
    base: &Path,
    slot: AccountNum,
    incoming: &AnthropicCredentialFile,
    verified: &VerifiedAnthropicContext,
    prior: &LoginPrior,
    publish: F,
) -> Result<CommittedAnthropicLogin, IdentityError>
where
    F: FnOnce(&Path, &ProfilesFile) -> Result<(), crate::error::ConfigError>,
{
    let mut prelock = PrelockLoginRescue::none();
    publish_login_locked_with_rescue(
        lock,
        base,
        slot,
        incoming,
        verified,
        prior,
        (publish, || Ok(())),
        &mut prelock,
    )
}

// The argument list is the publication contract (lock witness + target +
// verified grant + prior custody) plus the pre-lock rescue guard; splitting
// it would only move the same fields into a bundle struct.
#[allow(clippy::too_many_arguments)]
fn publish_login_locked_with_rescue<F, S>(
    lock: &ProfilesFileLock,
    base: &Path,
    slot: AccountNum,
    incoming: &AnthropicCredentialFile,
    verified: &VerifiedAnthropicContext,
    prior: &LoginPrior,
    publication: (F, S),
    prelock: &mut PrelockLoginRescue,
) -> Result<CommittedAnthropicLogin, IdentityError>
where
    F: FnOnce(&Path, &ProfilesFile) -> Result<(), crate::error::ConfigError>,
    S: FnOnce() -> anyhow::Result<()>,
{
    let (publish, seal) = publication;
    if !lock.protects(base)
        || std::fs::canonicalize(base).ok().as_ref() != Some(&prior.namespace)
        || prior.slot != slot
        || verified.version != CredentialVersion::for_credentials(incoming)?
    {
        return Err(IdentityError::InvalidMetadata);
    }
    // R3 corr M-3: a read failure decides nothing about the grant — retain
    // the rescue record for the next adoption.
    let mut pf =
        prelock.retain_on_failure(load_login_profiles(base).map_err(profiles_read_error))?;
    if pf
        .slot_binding_generations
        .get(&slot.to_string())
        .copied()
        .unwrap_or(0)
        != prior.generation
    {
        return Err(IdentityError::BindingChanged);
    }
    if !prelock.retain_unless_refused(login_prior_matches(base, slot, prior, &pf))? {
        return Err(IdentityError::BindingChanged);
    }
    // Read and validate the prior display email BEFORE any store or secret
    // writes. Use the same custody predicate as the prior check so a verified
    // same-UUID legacy upgrade does not become a post-write false refusal.
    let prior_oauth_email = match prior.binding.as_ref() {
        Some(binding) if matches!(&binding.provider, PriorProvider::Anthropic(_)) => {
            let current = prelock.retain_unless_refused(capture_prior_binding(
                base,
                slot,
                binding.identity,
                &pf,
            ))?;
            #[cfg(test)]
            run_login_prewrite_metadata_hook();
            let metadata = prelock.retain_on_failure(read_json(
                &identity_store::identity_json_path_for(base, binding.identity),
                true,
            ))?;
            let bytes =
                serde_json::to_vec(&metadata).map_err(|_| IdentityError::InvalidMetadata)?;
            let version: [u8; 32] = Sha256::digest(&bytes).into();
            if !login_prior_binding_matches(binding, &current)
                || version != current.metadata_version
            {
                return Err(IdentityError::BindingChanged);
            }
            metadata
                .get("email")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        }
        _ => None,
    };
    // Inspect every row for the incoming full tuple, including malformed
    // rows with ambiguous discriminators; unrelated damage remains untouched.
    let existing = validate_target_index(&pf, None, Some(verified.context()), false)?;
    let identity = existing.unwrap_or_else(IdentityId::new_v4);
    if existing.is_some()
        && prelock.retain_on_failure(read_stored_anthropic_context(base, identity))?
            != StoredAnthropicContext::Known(verified.context.clone())
    {
        return Err(IdentityError::InvalidMetadata);
    }
    // A schema-2 binary must refuse GC BEFORE the new reference channel exists.
    let sentinel = identity_store::store_version_path(base);
    if sentinel.exists() && crate::daemon::identity_mint::read_store_version_schema(base).is_none()
    {
        return Err(IdentityError::InvalidMetadata);
    }
    if crate::daemon::identity_mint::read_store_version_schema(base)
        .is_some_and(|v| v > crate::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT)
    {
        return Err(IdentityError::InvalidMetadata);
    }
    // Deliberate publication refusal must drop the pre-lock rescue as refused,
    // never retain it through the I/O-class rescue helpers. The public sealed
    // adapter preserves the caller's original typed error.
    seal().map_err(|_| IdentityError::CredentialRefused)?;
    prelock.retain_on_failure(
        crate::daemon::identity_mint::write_sentinel(&sentinel).map_err(|_| IdentityError::Io),
    )?;
    if existing.is_none() {
        let metadata = serde_json::json!({ "email": verified.context.email(), "provider": "anthropic",
            "account_uuid": verified.context.account_uuid(), "organization_uuid": verified.context.organization_uuid(),
            "created_at": crate::daemon::identity_mint::now_rfc3339(), "key_id": null });
        prelock.retain_on_failure(
            identity_store::write_anthropic_metadata_new(base, identity, &metadata)
                .map_err(|_| IdentityError::Io),
        )?;
    }
    let mirror = super::login::prepare_verified_login_mirror(
        base,
        slot,
        identity,
        &CredentialFile::Anthropic(incoming.clone()),
    );
    // D237 round-2 N4/M4: hand the pre-lock record over only when the
    // resolved target IS the identity it was written for; otherwise the
    // guard removes it and the target save writes its own record.
    let prelock_rescue = prelock.take_for(identity);
    crate::credentials::file::save_anthropic_login_target_locked(
        lock,
        base,
        slot,
        identity,
        incoming,
        verified,
        prelock_rescue,
    )
    .map_err(|error| login_identity_error(&error))?;
    let slot_key = slot.to_string();
    // Preserve a genuine v1 user rename in the same profiles publication.
    // An explicit later label wins; neither the incoming nor prior OAuth
    // email is a rename. Retained legacy metadata is used only to exclude
    // a display value, never as evidence of account ownership.
    let legacy_label = profiles::legacy_accounts_email_map(&pf)
        .remove(&slot_key)
        .filter(|label| {
            !pf.by_slot_label.contains_key(&slot_key)
                && !label.trim().is_empty()
                && label.len() <= 256
                && !label.chars().any(char::is_control)
                && !label.trim().eq_ignore_ascii_case(verified.context.email())
                && !prior_oauth_email
                    .as_ref()
                    .is_some_and(|email| label.trim().eq_ignore_ascii_case(email.trim()))
        });
    let label_changed = legacy_label.is_some();
    if let Some(label) = legacy_label {
        pf.by_slot_label.insert(slot_key.clone(), label);
    }
    let binding_changed = pf.by_slot.get(&slot_key).copied() != Some(identity);
    if binding_changed {
        let generation = prior
            .generation
            .checked_add(1)
            .ok_or(IdentityError::InvalidMetadata)?;
        // Owner directive 2026-10-11 (coordinator 32b912fa): this is the
        // production Anthropic re-login rebind — record the displaced uuid
        // in the slot's bounded binding history in THIS same publication.
        // A writer that bumps the generation without recording the
        // displacement silently kills the history channel for every real
        // re-login (the coordinator's lead, confirmed).
        match pf.by_slot.get(&slot_key).copied() {
            Some(displaced) => {
                profiles::record_binding_displacement(&mut pf, slot.get(), displaced)
            }
            // Review R3 M1 (second first-bind writer): a FIRST bind starts
            // with NO lineage — stale history under this key (a logout by
            // a pre-fix binary, a rollback that unbinds without clearing)
            // must not admit foreign identities at this slot.
            None => {
                let _ = pf.slot_binding_history.remove(&slot_key);
            }
        }
        pf.by_slot.insert(slot.to_string(), identity);
        pf.slot_binding_generations
            .insert(slot.to_string(), generation);
        if existing.is_none() {
            pf.anthropic_contexts
                .push(AnthropicContextEntry::new(verified.context(), identity));
        }
        pf.anthropic_contexts.sort_by_key(|entry| {
            (
                entry.email.clone(),
                entry.account_uuid,
                entry.organization_uuid,
            )
        });
    }
    if binding_changed || label_changed {
        // This publication never ADDS a legacy by_email entry — that map
        // stopped being the ownership index when `anthropic_contexts`
        // became the resolution source. The ONE by_email mutation it does
        // perform is a REMOVE: `record_binding_displacement` above purges
        // the displaced org-contexted uuid's stale entries, so no email
        // keeps resolving to a uuid this publication just retired.
        publish(&profiles::profiles_path(base), &pf)
            .map_err(|_| IdentityError::TargetAdvancedPublicationFailed)?;
    }
    let binding = capture_with_profiles(base, slot, &pf)?;
    // Ownership proof records only this exact grant, after the binding is published.
    // Failure is observable and leaves the committed identity intact; mirrors fail closed.
    if binding.credential_version() != verified.credential_version()
        || token_history::record_owner_verified_v2_locked(lock, base, &binding, verified)
            != token_history::OwnerVerifiedRecord::Written
    {
        tracing::warn!(
            error_kind = "anthropic_login_owner_proof_record_failed",
            "verified login ownership proof could not be recorded"
        );
    }
    Ok(CommittedAnthropicLogin {
        binding,
        independent: prior.independent.clone(),
        mirror,
        fingerprint: verified.fingerprint(),
    })
}
pub struct RefreshLineageWitness {
    identity: IdentityId,
    source: CredentialVersion,
    result: CredentialVersion,
}
impl fmt::Debug for RefreshLineageWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshLineageWitness([REDACTED])")
    }
}
impl RefreshLineageWitness {
    /// Test-only constructor: a witness for the EXACT (identity, source,
    /// result) triple. Feature-gated out of production builds
    /// (`rules/security.md` Rule 1 precedent); it grants no authority the
    /// production constructors do not.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_test(
        identity: IdentityId,
        source: CredentialVersion,
        result: CredentialVersion,
    ) -> Self {
        Self {
            identity,
            source,
            result,
        }
    }

    pub(crate) fn permits(
        &self,
        identity: IdentityId,
        source: CredentialVersion,
        result: CredentialVersion,
    ) -> bool {
        self.identity == identity && self.source == source && self.result == result
    }
}

// ── D237 round-2 H-c: persisted rescue source witnesses ─────────────────────
//
// A post-commit rescue record left behind by a lock timeout never ran the
// in-place writer's custody gate, so ADOPTION must re-run that gate rather
// than install on an expiry-only comparison (security R2-H1 / correctness
// N6). These types persist exactly the inputs the writers already hold.

/// Which in-place writer a rescue record substitutes for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueWitnessKind {
    /// `save_anthropic_lineage_canonical` — a rotated refresh pair.
    #[default]
    Refresh,
    /// `save_anthropic_login_target_locked` — an authorization-code grant.
    Login,
}

/// The captured context, persisted without the redacted wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescueKnownContext {
    pub email: String,
    pub account_uuid: Uuid,
    pub organization_uuid: Uuid,
}

/// SOURCE/RESULT inputs that let adoption re-run the writer's gates.
///
/// `source_version` is the exact canonical the writer captured before the
/// provider answered (refresh) or the verified grant version (login);
/// `result_version` is the version of the rescued payload being proposed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescueLineageWitness {
    #[serde(default)]
    pub kind: RescueWitnessKind,
    pub source_version: CredentialVersion,
    pub result_version: CredentialVersion,
    /// `None` = `StoredAnthropicContext::LegacyUnknown`.
    #[serde(default)]
    pub context: Option<RescueKnownContext>,
    #[serde(default)]
    pub legacy_email: Option<String>,
}

impl RescueLineageWitness {
    fn stored_context(&self) -> Result<StoredAnthropicContext, IdentityError> {
        match &self.context {
            None => Ok(StoredAnthropicContext::LegacyUnknown),
            Some(context) => Ok(StoredAnthropicContext::Known(AnthropicContext::new(
                &context.email,
                context.account_uuid,
                context.organization_uuid,
            )?)),
        }
    }
}

/// Builds the rescue witness for a refresh-lineage write.
pub(crate) fn rescue_lineage_witness_refresh(
    captured: &CapturedBinding,
    result: CredentialVersion,
) -> RescueLineageWitness {
    RescueLineageWitness {
        kind: RescueWitnessKind::Refresh,
        source_version: captured.credential_version(),
        result_version: result,
        context: match captured.context() {
            StoredAnthropicContext::Known(context) => Some(RescueKnownContext {
                email: context.email().to_string(),
                account_uuid: context.account_uuid(),
                organization_uuid: context.organization_uuid(),
            }),
            StoredAnthropicContext::LegacyUnknown => None,
        },
        legacy_email: captured.recorded_legacy_email().map(str::to_owned),
    }
}

/// Builds the rescue witness for a login-grant write.
pub(crate) fn rescue_lineage_witness_login(
    verified: &VerifiedAnthropicContext,
) -> RescueLineageWitness {
    RescueLineageWitness {
        kind: RescueWitnessKind::Login,
        source_version: verified.credential_version(),
        result_version: verified.credential_version(),
        context: Some(RescueKnownContext {
            email: verified.context().email().to_string(),
            account_uuid: verified.context().account_uuid(),
            organization_uuid: verified.context().organization_uuid(),
        }),
        legacy_email: None,
    }
}

/// What adoption should do with a rescue record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RescueGate {
    /// The writer's gate passes against the current canonical.
    Install,
    /// The canonical already holds this record's result.
    AlreadyInstalled,
    /// The writer's gate refuses, or its captured source no longer matches.
    Superseded,
}

/// Re-runs the in-place writer's custody gate for a rescue record.
///
/// `current` is the canonical read UNDER the canonical lock at adoption
/// time; `candidate` is the record's payload. This is deliberately the same
/// predicate set the in-place writers run — `RefreshLineageWitness::permits`
/// (`proof.permits`), [`refresh_context_matches`], and the login writer's
/// stored-context / freshness checks — so adoption can never install a pair
/// the writer would have refused.
pub(crate) fn rescue_source_gate(
    base: &Path,
    identity: IdentityId,
    witness: &RescueLineageWitness,
    current: Option<&AnthropicCredentialFile>,
    candidate: &AnthropicCredentialFile,
) -> Result<RescueGate, IdentityError> {
    let Some(current) = current else {
        return match witness.kind {
            // A refresh lineage needs its captured source canonical.
            RescueWitnessKind::Refresh => Ok(RescueGate::Superseded),
            // `save_anthropic_login_target_locked` refuses unless the stored
            // context equals the verified one, canonical or not: a grant for
            // another account is superseded, never installed. An unreadable
            // context is `Err`, so the record stays pending.
            RescueWitnessKind::Login => {
                if !login_payload_matches_witness(witness, candidate)? {
                    return Ok(RescueGate::Superseded);
                }
                if read_stored_anthropic_context(base, identity)? != witness.stored_context()? {
                    return Ok(RescueGate::Superseded);
                }
                rescue_store_schema_permits(base)?;
                if rescue_pair_held_elsewhere(base, identity, candidate)? {
                    return Ok(RescueGate::Superseded);
                }
                Ok(RescueGate::Install)
            }
        };
    };
    let current_version = CredentialVersion::for_credentials(current)?;
    let result_version = CredentialVersion::for_credentials(candidate)?;
    match witness.kind {
        RescueWitnessKind::Refresh => {
            let proof = RefreshLineageWitness {
                identity,
                source: witness.source_version,
                result: witness.result_version,
            };
            if proof.permits(identity, current_version, result_version) {
                let context = witness.stored_context()?;
                if refresh_context_matches_for(
                    base,
                    identity,
                    &context,
                    current_version,
                    witness.legacy_email.as_deref(),
                )? {
                    Ok(RescueGate::Install)
                } else {
                    Ok(RescueGate::Superseded)
                }
            } else if current_version == witness.result_version
                && result_version == witness.result_version
            {
                Ok(RescueGate::AlreadyInstalled)
            } else {
                // The canonical no longer holds the captured source (a newer
                // re-login or refresh landed): never revert it.
                Ok(RescueGate::Superseded)
            }
        }
        RescueWitnessKind::Login => {
            // The checks `save_anthropic_login_target_locked` runs.
            if result_version != witness.result_version {
                // sec LOW-3: the payload is not the grant the witness names.
                return Ok(RescueGate::Superseded);
            }
            if read_stored_anthropic_context(base, identity)? != witness.stored_context()? {
                return Ok(RescueGate::Superseded);
            }
            if current_version == witness.result_version && result_version == witness.result_version
            {
                return Ok(RescueGate::AlreadyInstalled);
            }
            if candidate.claude_ai_oauth.expires_at <= current.claude_ai_oauth.expires_at {
                // The existing canonical is at least as fresh as the rescued
                // grant; the writer would refuse the older grant.
                return Ok(RescueGate::Superseded);
            }
            rescue_store_schema_permits(base)?;
            if rescue_pair_held_elsewhere(base, identity, candidate)? {
                return Ok(RescueGate::Superseded);
            }
            Ok(RescueGate::Install)
        }
    }
}

/// sec LOW-3: whether a login payload IS the grant its witness names (the
/// writer requires `CredentialVersion(candidate) == verified version`).
/// `preserve_subscription_metadata` only backfills `subscription_type` /
/// `rate_limit_tier`, which [`CredentialVersion`] does not hash, so a
/// legitimate record always matches.
fn login_payload_matches_witness(
    witness: &RescueLineageWitness,
    candidate: &AnthropicCredentialFile,
) -> Result<bool, IdentityError> {
    Ok(CredentialVersion::for_credentials(candidate)? == witness.result_version)
}

/// sec MED-3: the login writer's one-grant-one-identity check, re-run at
/// adoption. `read_profiles_snapshot` takes NO lock (it is a bounded
/// read of `profiles.json`), so running it under the canonical lock cannot
/// invert the publication's profiles-then-canonical lock order. Adoption
/// knows no slot, so no binding is treated as "being replaced": every other
/// identity holding the pair, readable or not, keeps the record from
/// installing (`Err` = unreadable sibling = record stays pending).
fn rescue_pair_held_elsewhere(
    base: &Path,
    identity: IdentityId,
    candidate: &AnthropicCredentialFile,
) -> Result<bool, IdentityError> {
    let pf = read_profiles_snapshot(base)?;
    candidate_pair_held_elsewhere(base, &pf, identity, candidate)
}

/// The login publication's store-schema refusal, re-run before a login
/// rescue installs: a sentinel that exists but cannot be read, or a schema
/// newer than this binary, refuses (`Err`, so the record stays pending) —
/// an older binary must never write a canonical into a newer-schema store.
/// A sentinel whose presence cannot be determined refuses too.
///
/// Silent by design (corr L2): status and refresh readers reach it too, so
/// only the adoption path logs the refusal (`rescue_adopt_store_schema_refused`).
fn rescue_store_schema_permits(base: &Path) -> Result<(), IdentityError> {
    if rescue_store_schema_refused(base) {
        return Err(IdentityError::InvalidMetadata);
    }
    Ok(())
}

/// Whether the store schema refuses a login rescue install (see
/// `rescue_store_schema_permits`).
pub(crate) fn rescue_store_schema_refused(base: &Path) -> bool {
    let present = match std::fs::symlink_metadata(identity_store::store_version_path(base)) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    };
    let schema = crate::daemon::identity_mint::read_store_version_schema(base);
    (present && schema.is_none())
        || schema.is_some_and(|v| v > crate::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT)
}
/// Security and exact-canonical preflight, performed before a rotating request.
pub struct PreparedAnthropicRefresh {
    binding: CapturedBinding,
}
impl fmt::Debug for PreparedAnthropicRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedAnthropicRefresh([REDACTED])")
    }
}
pub fn prepare_anthropic_refresh(
    base: &Path,
    binding: &CapturedBinding,
) -> Result<PreparedAnthropicRefresh, crate::error::CredentialError> {
    if !binding.belongs_to(base) {
        return Err(credential_refusal());
    }
    crate::credentials::file::prepare_anthropic_refresh_directory(base, binding.identity())?;
    let path = identity_store::credentials_path_for(base, binding.identity());
    // Bounded acquisition. D237 round-2 H-b (correctness N2): a lock EXPIRY
    // here is PRE-COMMIT contention — nothing was consumed and the next tick
    // retries — so it carries its own typed refusal
    // (`CanonicalLockRefused`), distinct from the generic custody refusal
    // (`Corrupt { identity_authority_refused }`). Callers map the typed
    // variant to a SKIP; only genuine custody/content refusals stay terminal.
    let canonical_lock = path.with_extension("lock");
    let _canonical = match crate::platform::lock::lock_credential_file(&canonical_lock) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            return Err(crate::error::CredentialError::CanonicalLockRefused {
                path: canonical_lock,
                io_kind: std::io::ErrorKind::TimedOut,
            })
        }
        Err(error) => {
            return Err(crate::error::CredentialError::CanonicalLockRefused {
                path: canonical_lock,
                io_kind: crate::credentials::rescue::platform_error_kind(&error),
            })
        }
    };
    if identity_store::is_identity_removed(base, binding.identity())
        || !refresh_context_matches(base, binding).map_err(|_| credential_refusal())?
    {
        return Err(credential_refusal());
    }
    let current = load_anthropic_canonical(&path).map_err(|_| credential_refusal())?;
    if CredentialVersion::for_credentials(current.anthropic().ok_or_else(credential_refusal)?)
        .map_err(|_| credential_refusal())?
        != binding.credential_version()
    {
        return Err(credential_refusal());
    }
    Ok(PreparedAnthropicRefresh {
        binding: binding.clone(),
    })
}
pub fn refresh_captured_anthropic(
    prepared: &PreparedAnthropicRefresh,
    source: &AnthropicCredentialFile,
) -> Result<(AnthropicCredentialFile, RefreshLineageWitness), crate::error::OAuthError> {
    refresh_captured_anthropic_impl(prepared, source, crate::http::post_json_node)
}
/// Refresh with an injected transport.
///
/// Available in production as well as tests: `refresh::check::do_refresh`
/// wraps the injected closure to record whether the LOCAL transport failed,
/// which is what tells an unknown provider outcome apart from a provider
/// rejection (D237 ruling F). Production callers pass
/// `crate::http::post_json_node`, the same function
/// [`refresh_captured_anthropic`] uses.
pub fn refresh_captured_anthropic_with<F>(
    prepared: &PreparedAnthropicRefresh,
    source: &AnthropicCredentialFile,
    http_post: F,
) -> Result<(AnthropicCredentialFile, RefreshLineageWitness), crate::error::OAuthError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    refresh_captured_anthropic_impl(prepared, source, http_post)
}
fn refresh_captured_anthropic_impl<F>(
    prepared: &PreparedAnthropicRefresh,
    source: &AnthropicCredentialFile,
    http_post: F,
) -> Result<(AnthropicCredentialFile, RefreshLineageWitness), crate::error::OAuthError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    let captured = &prepared.binding;
    let source_version =
        CredentialVersion::for_credentials(source).map_err(|_| refresh_authority_refusal())?;
    if source_version != captured.credential_version {
        return Err(refresh_authority_refusal());
    }
    let refreshed =
        credentials::refresh::refresh_token(&CredentialFile::Anthropic(source.clone()), http_post)?;
    let refreshed = refreshed
        .anthropic()
        .ok_or_else(refresh_authority_refusal)?
        .clone();
    let result =
        CredentialVersion::for_credentials(&refreshed).map_err(|_| refresh_authority_refusal())?;
    Ok((
        refreshed,
        RefreshLineageWitness {
            identity: captured.identity,
            source: source_version,
            result,
        },
    ))
}
fn refresh_authority_refusal() -> crate::error::OAuthError {
    crate::error::OAuthError::Exchange("identity_authority_refused".into())
}
/// Login-specific refusals, told apart from the generic one by a fixed reason tag so the
/// publication owner can return a distinct [`IdentityError`] (`login_identity_error`).
/// The reason is `<tag>:<slot>`, the slot rendered by [`SlotKey`] (a number or the fixed
/// token `another slot`), so no key text from `profiles.json` is carried through.
const LOGIN_HELD_ELSEWHERE_REASON: &str = "login_credential_held_elsewhere";
const LOGIN_SIBLING_UNREADABLE_REASON: &str = "login_sibling_custody_unreadable";
pub(crate) fn login_held_elsewhere_refusal(holder: SlotKey) -> crate::error::CredentialError {
    crate::error::CredentialError::Corrupt {
        path: "anthropic-identity".into(),
        reason: format!("{LOGIN_HELD_ELSEWHERE_REASON}:{holder}"),
    }
}
pub(crate) fn login_sibling_unreadable_refusal(sibling: SlotKey) -> crate::error::CredentialError {
    crate::error::CredentialError::Corrupt {
        path: "anthropic-identity".into(),
        reason: format!("{LOGIN_SIBLING_UNREADABLE_REASON}:{sibling}"),
    }
}
/// Parse the `:<slot>` suffix back into a [`SlotKey`]; anything else is `another slot`.
fn login_reason_slot(reason: &str, tag: &str) -> Option<SlotKey> {
    let suffix = reason.strip_prefix(tag)?.strip_prefix(':')?;
    Some(SlotKey::from_key(suffix))
}
fn login_identity_error(error: &crate::error::CredentialError) -> IdentityError {
    match error {
        crate::error::CredentialError::Corrupt { reason, .. } => {
            if let Some(holder) = login_reason_slot(reason, LOGIN_HELD_ELSEWHERE_REASON) {
                IdentityError::LoginCredentialHeldElsewhere { holder }
            } else if let Some(sibling) = login_reason_slot(reason, LOGIN_SIBLING_UNREADABLE_REASON)
            {
                IdentityError::SiblingCustodyUnreadable { sibling }
            } else {
                IdentityError::CredentialRefused
            }
        }
        _ => IdentityError::CredentialRefused,
    }
}
pub(crate) fn credential_refusal() -> crate::error::CredentialError {
    crate::error::CredentialError::Corrupt {
        path: "anthropic-identity".into(),
        reason: "identity_authority_refused".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::file::{self, AnthropicWriteWitness, GuardedWriteOutcome};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }
    fn context(org: u128) -> AnthropicContext {
        AnthropicContext::new(
            "same@test.invalid",
            Uuid::from_u128(10),
            Uuid::from_u128(org),
        )
        .unwrap()
    }
    fn credential(tag: &str, expiry: u64) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: AccessToken::new(format!("fake-access-{tag}")),
                refresh_token: RefreshToken::new(format!("fake-refresh-{tag}")),
                expires_at: expiry,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }
    fn transport(expected: &CredentialFile, context: AnthropicContext) -> HttpGetFn {
        let expected_access = expected
            .anthropic()
            .unwrap()
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .to_owned();
        Arc::new(move |url, access, headers| {
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(access, expected_access);
            assert_eq!(headers, &[("anthropic-beta", "oauth-2025-04-20")]);
            Ok((
                200,
                serde_json::to_vec(&serde_json::json!({
                    "account":{"uuid":context.account_uuid(),"email":context.email()},
                    "organization":{"uuid":context.organization_uuid()},
                }))
                .unwrap(),
            ))
        })
    }
    fn commit(
        base: &Path,
        n: u16,
        creds: &CredentialFile,
        context: AnthropicContext,
    ) -> CommittedAnthropicLogin {
        let prior = capture_login_prior(base, slot(n)).unwrap();
        commit_anthropic_login_with(
            base,
            slot(n),
            creds,
            &transport(creds, context),
            None,
            prior,
        )
        .unwrap()
    }
    #[derive(Debug, thiserror::Error)]
    #[error("synthetic caller cancellation before seal")]
    struct FixtureSealRefusal;

    #[test]
    fn isolated_grant_seal_refusal_preserves_typed_error_and_prior_canonical() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path();
            let prior_creds = credential("prior-seal", 4_102_444_800_000);
            let receipt = commit(base, 2, &prior_creds, context(20));
            let identity = receipt.identity();
            crate::accounts::login::finalize_verified_login(base, slot(2), receipt).unwrap();
            let canonical = identity_store::credentials_path_for(base, identity);
            let prior_bytes = std::fs::read(&canonical).unwrap();
            let prior_profiles = std::fs::read(profiles::profiles_path(base)).unwrap();
            let mut grant =
                crate::accounts::credential_transaction::VendorLoginGrant::new(base).unwrap();
            let candidate = credential("refused-seal", 4_102_444_800_001);
            crate::credentials::save(&grant.config_dir().join(".credentials.json"), &candidate)
                .unwrap();
            let result = commit_anthropic_login_with_seal(
                base,
                slot(2),
                &candidate,
                &transport(&candidate, context(20)),
                None,
                capture_login_prior(base, slot(2)).unwrap(),
                || Err(anyhow::Error::new(FixtureSealRefusal)),
            );
            let error = result.expect_err("pre-seal caller refusal must refuse publication");
            assert!(error.downcast_ref::<FixtureSealRefusal>().is_some());
            grant.cleanup().unwrap();
            assert_eq!(std::fs::read(canonical).unwrap(), prior_bytes);
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                prior_profiles
            );
            assert_eq!(
                crate::accounts::markers::read_csq_account_uuid(&base.join("config-2")),
                Some(identity)
            );
        });
    }

    #[test]
    fn fresh_isolated_grant_finalizes_actual_canonical_marker_before_cleanup_error() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path();
            let mut grant =
                crate::accounts::credential_transaction::VendorLoginGrant::new(base).unwrap();
            let home = grant.config_dir().to_path_buf();
            let candidate = credential("fresh-seal", 4_102_444_800_000);
            crate::credentials::save(&home.join(".credentials.json"), &candidate).unwrap();
            let prior = capture_login_prior(base, slot(2)).unwrap();
            assert!(!base.join("config-2").exists());
            let receipt = commit_anthropic_login_with_seal(
                base,
                slot(2),
                &candidate,
                &transport(&candidate, context(20)),
                None,
                prior,
                || {
                    assert!(profiles::resolve_slot_to_uuid(base, 2).is_none());
                    assert!(!identity_store::store_version_path(base).exists());
                    assert!(!base.join("config-2/.csq-account").exists());
                    Ok(())
                },
            )
            .unwrap();
            let identity = receipt.identity();
            assert!(identity_store::credentials_path_for(base, identity).is_file());
            crate::accounts::login::finalize_verified_login(base, slot(2), receipt).unwrap();
            assert_eq!(profiles::resolve_slot_to_uuid(base, 2), Some(identity));
            assert_eq!(
                crate::accounts::markers::read_csq_account_uuid(&base.join("config-2")),
                Some(identity)
            );
            // Force a scoped cleanup observation failure after actual finalization.
            // Caller sequencing and committed-cancel outcome are tested by peers.
            std::fs::remove_dir_all(&home).unwrap();
            assert!(grant.cleanup().is_err());
            assert!(identity_store::credentials_path_for(base, identity).is_file());
            assert_eq!(
                crate::accounts::markers::read_csq_account_uuid(&base.join("config-2")),
                Some(identity)
            );
        });
    }

    fn canonical_version(base: &Path, id: IdentityId) -> CredentialVersion {
        CredentialVersion::for_credentials(
            file::load(&identity_store::credentials_path_for(base, id))
                .unwrap()
                .anthropic()
                .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn isolated_fresh_login_publishes_uuid_marker_in_new_canonical_home() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            let mut grant =
                crate::accounts::credential_transaction::VendorLoginGrant::new(dir.path()).unwrap();
            let creds = credential("isolated-finalizer", 4_102_444_800_000);
            crate::credentials::save(&grant.config_dir().join(".credentials.json"), &creds)
                .unwrap();
            let receipt = commit(dir.path(), 2, &creds, context(20));
            let identity = receipt.identity();
            assert!(!dir.path().join("config-2").exists());
            crate::accounts::login::finalize_verified_login(dir.path(), slot(2), receipt).unwrap();
            assert_eq!(
                crate::accounts::markers::read_csq_account_uuid(&dir.path().join("config-2")),
                Some(identity)
            );
            assert!(identity_store::credentials_path_for(dir.path(), identity).is_file());
            grant.cleanup().unwrap();
        });
    }

    #[test]
    fn sealed_prelock_refusal_discards_rescue_before_adoption() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            use crate::credentials::rescue;
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let committed = commit(
                base,
                1,
                &credential("initial-sealed-rescue", 100),
                context(20),
            );
            let id = committed.identity();
            let canonical = identity_store::credentials_path_for(base, id);
            let identity_dir = canonical.parent().unwrap();
            let old_bytes = std::fs::read(&canonical).unwrap();
            let old_profiles = std::fs::read(profiles::profiles_path(base)).unwrap();
            let incoming = credential("cancelled-sealed-rescue", 200);
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let mut seal_called = false;
            let result = commit_anthropic_login_with_seal(
                base,
                slot(1),
                &incoming,
                &transport(&incoming, context(20)),
                None,
                prior,
                || {
                    seal_called = true;
                    assert!(
                        rescue::rescue_record_pending(identity_dir).is_some(),
                        "SEALED_REFUSAL_RESCUE_EXISTS_BEFORE_SEAL"
                    );
                    Err(anyhow::Error::new(FixtureSealRefusal))
                },
            );
            let error =
                result.expect_err("deliberate pre-seal cancellation must refuse publication");
            assert!(seal_called);
            assert!(
                error.downcast_ref::<FixtureSealRefusal>().is_some(),
                "SEALED_REFUSAL_PRESERVES_TYPED_CANCELLATION"
            );
            assert!(
                rescue::rescue_record_pending(identity_dir).is_none(),
                "SEALED_REFUSAL_LEAVES_NO_PENDING_RESCUE"
            );
            assert!(
                !rescue::adopt_rescue_record(base, &id.to_string()).unwrap(),
                "SEALED_REFUSAL_CANNOT_BE_ADOPTED_LATER"
            );
            assert_eq!(std::fs::read(canonical).unwrap(), old_bytes);
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                old_profiles
            );
        });
    }

    #[test]
    fn sealed_postseal_canonical_lock_failure_keeps_rescue_then_adopts() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            use crate::credentials::rescue;
            use std::time::Duration;
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let committed = commit(base, 1, &credential("initial-postseal", 100), context(20));
            let id = committed.identity();
            let canonical = identity_store::credentials_path_for(base, id);
            let identity_dir = canonical.parent().unwrap();
            let old_bytes = std::fs::read(&canonical).unwrap();
            let incoming = credential("recoverable-postseal", 200);
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let mut holder = None;
            let mut seal_called = false;
            let budget = rescue::CommitBudgetOverrideGuard::install(Duration::from_millis(300));
            let result = commit_anthropic_login_with_seal(
                base,
                slot(1),
                &incoming,
                &transport(&incoming, context(20)),
                None,
                prior,
                || {
                    // Actual file contention begins only after every prior/identity
                    // check, ensuring this exercises POST-seal target-save rescue.
                    holder = Some(hold_lock_on_other_thread(&canonical.with_extension("lock")));
                    seal_called = true;
                    Ok(())
                },
            );
            drop(budget);
            let error =
                result.expect_err("actual post-seal canonical lock contention must refuse save");
            assert!(seal_called, "SEALED_POSTSEAL_REACHED_BEFORE_IO_FAILURE");
            assert!(error.downcast_ref::<FixtureSealRefusal>().is_none());
            let pending = rescue::rescue_record_pending(identity_dir)
                .expect("SEALED_POSTSEAL_IO_KEEPS_RESCUE");
            assert_eq!(pending.uuid, id.to_string());
            assert_eq!(std::fs::read(&canonical).unwrap(), old_bytes);
            drop(holder.take());
            assert!(
                rescue::adopt_rescue_record(base, &id.to_string()).unwrap(),
                "SEALED_POSTSEAL_IO_RESCUE_IS_RECOVERABLE"
            );
            let installed = file::load(&canonical).unwrap();
            assert_eq!(
                CredentialVersion::for_credentials(installed.anthropic().unwrap()).unwrap(),
                CredentialVersion::for_credentials(incoming.anthropic().unwrap()).unwrap()
            );
            assert!(rescue::rescue_record_pending(identity_dir).is_none());
        });
    }

    fn make_legacy(base: &Path, creds: &CredentialFile) -> IdentityId {
        let id = IdentityId::new_v4();
        crate::daemon::identity_mint::write_legacy_anthropic_metadata_fixture(
            base,
            id,
            "same@test.invalid",
        )
        .unwrap();
        // This fixture represents the legacy 0o755 namespace shape — a mode
        // production repairs to 0o700 (`prepare_anthropic_refresh_directory`
        // → `secure_dir`; see the sibling
        // `org_identity_regression_refresh_preflight_repairs_0755_before_rotating_http`)
        // — and pins it EXPLICITLY: `create_dir_all` alone leaves the mode to
        // the ambient umask, so the legacy-upgrade tests' mode assertions
        // would otherwise measure the runner's umask instead of the fixture.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                identity_store::identities_dir(base),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        file::save(&identity_store::credentials_path_for(base, id), creds).unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), id);
        pf.by_email.insert("same@test.invalid".into(), id);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        id
    }

    #[test]
    fn org_identity_regression_cross_email_login_excludes_prior_bare_oauth_label() {
        for known_prior in [false, true] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("old-label-account", 100);
            let old_id = if known_prior {
                commit(base, 1, &old, context(20)).identity()
            } else {
                make_legacy(base, &old)
            };
            let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            pf.set_profile(
                1,
                profiles::AccountProfile {
                    email: " Same@Test.Invalid ".into(),
                    method: "oauth".into(),
                    extra: Default::default(),
                },
            );
            profiles::save(&profiles::profiles_path(base), &pf).unwrap();
            let metadata = identity_store::identity_json_path_for(base, old_id);
            let canonical = identity_store::credentials_path_for(base, old_id);
            let metadata_before = std::fs::read(&metadata).unwrap();
            let canonical_before = std::fs::read(&canonical).unwrap();
            let incoming_context =
                AnthropicContext::new("new@test.invalid", Uuid::from_u128(11), Uuid::from_u128(21))
                    .unwrap();
            let fresh = commit(
                base,
                1,
                &credential("new-label-account", 200),
                incoming_context,
            );
            assert_ne!(fresh.identity(), old_id);
            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert!(
                !pf.by_slot_label.contains_key("1"),
                "a prior OAuth email is not a rename"
            );
            assert_eq!(pf.get_email(1), Some("new@test.invalid"));
            assert_eq!(std::fs::read(metadata).unwrap(), metadata_before);
            assert_eq!(std::fs::read(canonical).unwrap(), canonical_before);
        }
    }

    #[test]
    fn org_identity_regression_verified_publication_preserves_genuine_legacy_rename() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            1,
            profiles::AccountProfile {
                email: "Work account".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        let incoming = credential("legacy-rename", 200);
        let receipt = commit(base, 1, &incoming, context(20));
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(pf.by_slot.get("1"), Some(&receipt.identity()));
        assert_eq!(
            pf.by_slot_label.get("1").map(String::as_str),
            Some("Work account")
        );
        assert_eq!(pf.get_email(1), Some("Work account"));
        assert_eq!(
            canonical_version(base, receipt.identity()),
            CredentialVersion::for_credentials(incoming.anthropic().unwrap()).unwrap()
        );
    }

    #[test]
    fn org_identity_regression_verified_publication_preserves_explicit_label_precedence() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            1,
            profiles::AccountProfile {
                email: "Old legacy rename".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        pf.by_slot_label.insert("1".into(), "User set later".into());
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        let receipt = commit(base, 1, &credential("explicit-rename", 200), context(20));
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(pf.by_slot.get("1"), Some(&receipt.identity()));
        assert_eq!(
            pf.by_slot_label.get("1").map(String::as_str),
            Some("User set later")
        );
        assert_eq!(pf.get_email(1), Some("User set later"));
    }

    // Exercise the actual independent marker/settings writers. None mints a UUID.
    fn seed_independent_provider(base: &Path, mode: u8, changed: bool) -> Vec<PathBuf> {
        use crate::providers::{catalog::Surface, gemini::provisioning as gemini, native};
        match mode {
            0 => {
                gemini::write_binding(
                    base,
                    slot(1),
                    &gemini::GeminiBinding::new(
                        gemini::AuthMode::ApiKey,
                        if changed { "changed-model" } else { "auto" },
                    ),
                )
                .unwrap();
                if !changed {
                    let lock = ProfilesFileLock::acquire(base).unwrap();
                    profiles::set_slot_identity(
                        &lock,
                        base,
                        1,
                        &gemini::gemini_identity_label(slot(1), &gemini::AuthMode::ApiKey),
                    )
                    .unwrap();
                }
                vec![gemini::binding_path(base, slot(1))]
            }
            1 => {
                let surface = if changed {
                    Surface::Grok
                } else {
                    Surface::Kimi
                };
                native::write_binding(base, slot(1), surface).unwrap();
                if !changed {
                    let lock = ProfilesFileLock::acquire(base).unwrap();
                    profiles::set_slot_identity(&lock, base, 1, "kimi-1").unwrap();
                }
                vec![native::marker_path(base, slot(1), surface)]
            }
            2 => {
                crate::accounts::third_party::bind_provider_to_slot(
                    base,
                    "deepseek",
                    slot(1),
                    Some(if changed {
                        "fake-deepseek-winner-key"
                    } else {
                        "fake-deepseek-prior-key"
                    }),
                    None,
                )
                .unwrap();
                vec![base.join("config-1/settings.json")]
            }
            _ => panic!("unknown fixture provider"),
        }
    }

    #[test]
    fn org_identity_regression_independent_provider_prior_supports_verified_repurpose() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            for mode in 0..3 {
                let dir = TempDir::new().unwrap();
                let base = dir.path();
                let paths = seed_independent_provider(base, mode, false);
                let provider_bytes: Vec<_> =
                    paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
                let prior = capture_login_prior(base, slot(1)).unwrap();
                assert!(
                    prior.binding.is_none(),
                    "independent providers must not invent UUID custody"
                );
                assert!(!prior.independent.bindings.is_empty());
                let fresh = credential("independent-repurpose", 4102444800000);
                let receipt = commit_anthropic_login_with(
                    base,
                    slot(1),
                    &fresh,
                    &transport(&fresh, context(20)),
                    None,
                    prior,
                )
                .unwrap();
                for (path, bytes) in paths.iter().zip(&provider_bytes) {
                    assert_eq!(
                        std::fs::read(path).unwrap(),
                        *bytes,
                        "publication precedes provider cleanup"
                    );
                }
                assert_eq!(
                    read_stored_context(base, receipt.identity()).unwrap(),
                    StoredAnthropicContext::Known(context(20))
                );
                assert_eq!(
                    super::super::login::finalize_verified_login(base, slot(1), receipt).unwrap(),
                    "same@test.invalid"
                );
                let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
                assert!(!pf.by_slot_identity.contains_key("1"));
                assert!(
                    !crate::providers::gemini::provisioning::is_gemini_bound_slot(base, slot(1))
                );
                assert!(crate::providers::native::native_surface_for_slot(base, slot(1)).is_none());
                assert!(!crate::accounts::third_party::is_third_party_slot(base, slot(1)).unwrap());
            }
        });
    }

    #[test]
    fn org_identity_regression_independent_provider_winner_change_refuses_publication() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            for mode in 0..3 {
                let dir = TempDir::new().unwrap();
                let base = dir.path();
                seed_independent_provider(base, mode, false);
                let prior = capture_login_prior(base, slot(1)).unwrap();
                let label_before = prior.independent.identity_label.clone();
                let paths = seed_independent_provider(base, mode, true);
                let winner_bytes: Vec<_> =
                    paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
                let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
                assert_eq!(
                    profiles::load(&profiles::profiles_path(base))
                        .unwrap()
                        .by_slot_identity
                        .get("1")
                        .cloned(),
                    label_before
                );
                let fresh = credential("must-not-clobber-winner", 4102444800000);
                let outcome = commit_anthropic_login_with(
                    base,
                    slot(1),
                    &fresh,
                    &transport(&fresh, context(20)),
                    None,
                    prior,
                );
                assert!(matches!(outcome, Err(IdentityError::BindingChanged)));
                assert_eq!(
                    std::fs::read(profiles::profiles_path(base)).unwrap(),
                    profiles_before
                );
                for (path, bytes) in paths.iter().zip(winner_bytes) {
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                }
                assert!(
                    !base.join("identities").exists(),
                    "refusal must precede canonical publication"
                );
            }
        });
    }

    #[test]
    fn org_identity_regression_postcommit_provider_winner_refuses_finalizer_cleanup() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            for mode in 0..4 {
                let dir = TempDir::new().unwrap();
                let base = dir.path();
                let seed_mode = if mode == 3 { 0 } else { mode };
                let initial_paths = seed_independent_provider(base, seed_mode, false);
                let incoming = credential("committed-before-winner", 4102444800000);
                let receipt = commit(base, 1, &incoming, context(20));
                let identity = receipt.identity();
                let winner_paths = match mode {
                    0 | 1 => seed_independent_provider(base, mode, true),
                    2 => {
                        let lock = ProfilesFileLock::acquire(base).unwrap();
                        let path = base.join("config-1/settings.json");
                        let mut value: serde_json::Value =
                            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                        value["env"]["ANTHROPIC_AUTH_TOKEN"] =
                            serde_json::json!("fake-postcommit-winner-key");
                        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
                        drop(lock);
                        vec![path]
                    }
                    3 => {
                        let lock = ProfilesFileLock::acquire(base).unwrap();
                        profiles::set_slot_identity(&lock, base, 1, "postcommit-winner-label")
                            .unwrap();
                        initial_paths.clone()
                    }
                    _ => unreachable!(),
                };
                let winner_bytes: Vec<_> = winner_paths
                    .iter()
                    .map(|p| std::fs::read(p).unwrap())
                    .collect();
                let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
                let canonical = identity_store::credentials_path_for(base, identity);
                let canonical_before = std::fs::read(&canonical).unwrap();
                let metadata = identity_store::identity_json_path_for(base, identity);
                let metadata_before = std::fs::read(&metadata).unwrap();
                assert!(
                    super::super::login::finalize_verified_login(base, slot(1), receipt).is_err(),
                    "winner after commit must prevent cleanup"
                );
                assert_eq!(
                    std::fs::read(profiles::profiles_path(base)).unwrap(),
                    profiles_before
                );
                assert_eq!(std::fs::read(canonical).unwrap(), canonical_before);
                assert_eq!(std::fs::read(metadata).unwrap(), metadata_before);
                for (path, bytes) in winner_paths.iter().zip(winner_bytes) {
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                }
            }
        });
    }

    #[test]
    fn org_identity_regression_identical_gemini_marker_invalidates_finalizer_receipt() {
        use crate::providers::gemini::provisioning as gemini;
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            seed_independent_provider(base, 0, false);
            let exact_binding = gemini::read_binding(base, slot(1)).unwrap();
            let marker = gemini::binding_path(base, slot(1));
            let marker_before = std::fs::read(&marker).unwrap();
            let incoming = credential("before-identical-rekey", 4102444800000);
            let receipt = commit(base, 1, &incoming, context(20));
            let identity = receipt.identity();
            let committed_generation = receipt.binding().generation();
            // This is exactly the possible same-second rekey marker, without a
            // wall-clock assumption: the entire pre-captured binding is reused.
            gemini::write_binding(base, slot(1), &exact_binding).unwrap();
            assert_eq!(std::fs::read(&marker).unwrap(), marker_before);
            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert!(pf.slot_binding_generations["1"] > committed_generation);
            let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
            let canonical = identity_store::credentials_path_for(base, identity);
            let canonical_before = std::fs::read(&canonical).unwrap();
            let metadata = identity_store::identity_json_path_for(base, identity);
            let metadata_before = std::fs::read(&metadata).unwrap();
            assert!(super::super::login::finalize_verified_login(base, slot(1), receipt).is_err());
            assert_eq!(std::fs::read(&marker).unwrap(), marker_before);
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
            assert_eq!(std::fs::read(canonical).unwrap(), canonical_before);
            assert_eq!(std::fs::read(metadata).unwrap(), metadata_before);
        });
    }

    /// F5/L3 wiring: `finalize_verified_login` must end the target slot's refresh
    /// suppression itself. The sibling still shares the grant after the login, so the
    /// audit keeps reporting the slot suppressed, so only the `clear_on_login` call in the
    /// finalizer can lift it.
    #[test]
    fn org_identity_r5_finalize_verified_login_clears_the_slots_refresh_suppression() {
        use crate::accounts::refresh_token_audit as audit;
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let fresh = credential("login", 300);
            let receipt = commit(base, 2, &fresh, context(20));
            // A second slot (lower number, so it is the holder) shares the refresh grant.
            let sibling = IdentityId::new_v4();
            let pp = profiles::profiles_path(base);
            let mut pf = profiles::load(&pp).unwrap();
            pf.by_slot.insert("1".into(), sibling);
            profiles::save(&pp, &pf).unwrap();
            let path = identity_store::credentials_path_for(base, sibling);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
            crate::platform::fs::secure_dir(path.parent().unwrap()).unwrap();
            file::save(&path, &fresh).unwrap();
            audit::run_startup_audit(base);
            assert!(
                audit::is_refresh_suppressed(base, 2),
                "precondition: slot 2 is suppressed before its login finalizes"
            );
            assert_eq!(
                super::super::login::finalize_verified_login(base, slot(2), receipt).unwrap(),
                "same@test.invalid"
            );
            assert!(
                matches!(
                    audit::audit(base).slots.get(&2),
                    Some(audit::SlotState::Suppressed { .. })
                ),
                "the grant is still shared, so only clear_on_login can have lifted the entry"
            );
            assert!(
                !audit::is_refresh_suppressed(base, 2),
                "finalize_verified_login clears the logged-in slot's suppression"
            );
        });
    }

    #[test]
    fn org_identity_regression_gemini_vault_rekey_holds_profiles_through_publication() {
        use crate::platform::secret::{in_memory::InMemoryVault, SecretError, SlotKey, Vault};
        use crate::providers::gemini::{provisioning as gemini, SURFACE_GEMINI};
        use secrecy::{ExposeSecret, SecretString};
        struct CheckedVault {
            base: PathBuf,
            inner: InMemoryVault,
        }
        impl Vault for CheckedVault {
            fn set(&self, slot: SlotKey, key: &SecretString) -> Result<(), SecretError> {
                let base = &self.base;
                assert!(
                    crate::accounts::profiles_lock::on_other_thread(|| {
                        ProfilesFileLock::try_acquire(base).unwrap().is_none()
                    }),
                    "vault rotation must occur inside profiles authority"
                );
                self.inner.set(slot, key)
            }
            fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError> {
                self.inner.get(slot)
            }
            fn delete(&self, slot: SlotKey) -> Result<(), SecretError> {
                self.inner.delete(slot)
            }
            fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError> {
                self.inner.list_slots(surface)
            }
            fn backend_id(&self) -> &'static str {
                "in-memory"
            }
        }
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let vault = CheckedVault {
            base: base.to_owned(),
            inner: InMemoryVault::new(),
        };
        let address = SlotKey {
            surface: SURFACE_GEMINI,
            account: slot(1),
        };
        gemini::provision_api_key_via_vault(
            base,
            slot(1),
            &SecretString::new("fake-gemini-first-key".into()),
            &vault,
        )
        .unwrap();
        let first = profiles::load(&profiles::profiles_path(base)).unwrap();
        gemini::provision_api_key_via_vault(
            base,
            slot(1),
            &SecretString::new("fake-gemini-replacement-key".into()),
            &vault,
        )
        .unwrap();
        let current = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert!(current.slot_binding_generations["1"] > first.slot_binding_generations["1"]);
        assert_eq!(current.by_slot_identity["1"], first.by_slot_identity["1"]);
        assert_eq!(
            vault.get(address).unwrap().expose_secret(),
            "fake-gemini-replacement-key"
        );
        assert_eq!(
            gemini::read_binding(base, slot(1)).unwrap().auth,
            gemini::AuthMode::ApiKey
        );
        assert!(
            ProfilesFileLock::try_acquire(base).unwrap().is_some(),
            "transaction releases its lock"
        );
    }

    #[test]
    fn org_identity_regression_marker_publication_waits_for_profiles_authority() {
        use crate::providers::{catalog::Surface, gemini::provisioning as gemini, native};
        for gemini_writer in [false, true] {
            let dir = TempDir::new().unwrap();
            let base = dir.path().to_owned();
            let lock = ProfilesFileLock::acquire(&base).unwrap();
            let worker_base = base.clone();
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                if gemini_writer {
                    gemini::write_binding(
                        &worker_base,
                        slot(1),
                        &gemini::GeminiBinding::new(gemini::AuthMode::ApiKey, "auto"),
                    )
                    .unwrap();
                } else {
                    native::write_binding(&worker_base, slot(1), Surface::Kimi).unwrap();
                }
                done_tx.send(()).unwrap();
            });
            started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert!(matches!(
                done_rx.recv_timeout(std::time::Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            let marker = if gemini_writer {
                gemini::binding_path(&base, slot(1))
            } else {
                native::marker_path(&base, slot(1), Surface::Kimi)
            };
            assert!(
                !marker.exists(),
                "publication cannot cross held finalizer authority"
            );
            drop(lock);
            done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            worker.join().unwrap();
            assert!(marker.exists());
        }
    }

    #[test]
    fn org_identity_regression_independent_identity_label_change_refuses_publication() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_independent_provider(base, 0, false);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            profiles::set_slot_identity(&lock, base, 1, "changed-independent-identity").unwrap();
        }
        let before = std::fs::read(profiles::profiles_path(base)).unwrap();
        let fresh = credential("must-not-clobber-label", 4102444800000);
        assert!(matches!(
            commit_anthropic_login_with(
                base,
                slot(1),
                &fresh,
                &transport(&fresh, context(20)),
                None,
                prior
            ),
            Err(IdentityError::BindingChanged)
        ));
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            before
        );
    }

    #[test]
    fn org_identity_regression_malformed_independent_provider_never_treated_as_unbound() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let paths = seed_independent_provider(base, 0, false);
        std::fs::write(&paths[0], b"not-json").unwrap();
        let before = std::fs::read(profiles::profiles_path(base)).unwrap();
        assert!(capture_login_prior(base, slot(1)).is_err());
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            before
        );
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"not-json");
    }

    #[cfg(windows)]
    #[test]
    fn org_identity_regression_windows_equal_content_distinct_file_ids_and_hardlink_refusal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let first = tmp.path().join("first.json");
        let second = tmp.path().join("second.json");
        std::fs::write(&first, b"{}").unwrap();
        std::fs::write(&second, b"{}").unwrap();
        let a = std::fs::File::open(&first).unwrap();
        let b = std::fs::File::open(&second).unwrap();
        assert_ne!(
            windows_file_identity(&a).unwrap(),
            windows_file_identity(&b).unwrap()
        );
        std::fs::hard_link(&first, tmp.path().join("alias.json")).unwrap();
        assert!(windows_file_identity(&a).is_err());
        assert_eq!(std::fs::read(&first).unwrap(), b"{}");
    }

    #[test]
    fn org_identity_regression_complete_context_reuses_only_exact_tuple() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let a = credential("a", 100);
        let b = credential("b", 200);
        let c = credential("c", 300);
        let first = commit(base, 1, &a, context(20)).identity();
        let sibling = commit(base, 2, &b, context(21)).identity();
        assert_ne!(first, sibling);
        let reused = commit(base, 3, &c, context(20)).identity();
        assert_eq!(first, reused);
        assert_eq!(
            canonical_version(base, sibling),
            CredentialVersion::for_credentials(b.anthropic().unwrap()).unwrap()
        );
        assert_eq!(
            profiles::load(&profiles::profiles_path(base))
                .unwrap()
                .anthropic_contexts
                .len(),
            2
        );
        let lock = ProfilesFileLock::acquire(base).unwrap();
        let captured = capture_anthropic_binding_locked(&lock, base, slot(3)).unwrap();
        let history = token_history::read_owner_verified_v2_locked(&lock, base, &captured);
        assert!(
            history.contains(&token_history::fingerprint_from_credential_file(&c).unwrap()),
            "successful exact verified login must record its v2 proof"
        );
    }

    #[test]
    fn org_identity_regression_legacy_index_metadata_and_tokens_preserved() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("legacy", 100);
        let old_id = make_legacy(base, &old);
        let metadata_path = identity_store::identity_json_path_for(base, old_id);
        let token_path = identity_store::credentials_path_for(base, old_id);
        let before_metadata = std::fs::read(&metadata_path).unwrap();
        let before_tokens = std::fs::read(&token_path).unwrap();
        let fresh = commit(base, 1, &credential("known", 200), context(20));
        assert_ne!(fresh.identity(), old_id);
        assert_eq!(std::fs::read(metadata_path).unwrap(), before_metadata);
        assert_eq!(std::fs::read(token_path).unwrap(), before_tokens);
        assert_eq!(
            profiles::load(&profiles::profiles_path(base))
                .unwrap()
                .by_email
                .get("same@test.invalid"),
            Some(&old_id)
        );
        assert_eq!(
            read_stored_context(base, old_id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
        assert_eq!(
            crate::daemon::identity_mint::read_store_version_schema(base),
            Some(3)
        );
    }

    #[test]
    fn org_identity_regression_failed_publication_preserves_prior_binding_and_foreign_org() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("old", 100);
        let sibling = credential("sibling", 150);
        let old_id = commit(base, 1, &old, context(20)).identity();
        let other = commit(base, 2, &sibling, context(21)).identity();
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let before = std::fs::read(profiles::profiles_path(base)).unwrap();
        let candidate = credential("new-org", 200);
        let verified = verify_anthropic_context_with(
            candidate.anthropic().unwrap(),
            &transport(&candidate, context(22)),
        )
        .unwrap();
        let lock = ProfilesFileLock::acquire(base).unwrap();
        let outcome = publish_login_locked_with(
            &lock,
            base,
            slot(1),
            candidate.anthropic().unwrap(),
            &verified,
            &prior,
            |_, _| {
                Err(crate::error::ConfigError::InvalidJson {
                    path: "fixture".into(),
                    reason: "injected_publication_failure".into(),
                })
            },
        );
        assert!(matches!(
            outcome,
            Err(IdentityError::TargetAdvancedPublicationFailed)
        ));
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            before
        );
        assert_eq!(
            canonical_version(base, old_id),
            CredentialVersion::for_credentials(old.anthropic().unwrap()).unwrap()
        );
        assert_eq!(
            canonical_version(base, other),
            CredentialVersion::for_credentials(sibling.anthropic().unwrap()).unwrap()
        );
    }

    #[test]
    fn org_identity_regression_existing_target_advance_on_publication_failure_is_explicit() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let a = credential("a", 100);
        let b = credential("b", 150);
        let source = commit(base, 1, &a, context(20)).identity();
        let target = commit(base, 2, &b, context(21)).identity();
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let before = std::fs::read(profiles::profiles_path(base)).unwrap();
        let new = credential("advance", 200);
        let proof =
            verify_anthropic_context_with(new.anthropic().unwrap(), &transport(&new, context(21)))
                .unwrap();
        let lock = ProfilesFileLock::acquire(base).unwrap();
        let result = publish_login_locked_with(
            &lock,
            base,
            slot(1),
            new.anthropic().unwrap(),
            &proof,
            &prior,
            |_, _| {
                Err(crate::error::ConfigError::InvalidJson {
                    path: "fixture".into(),
                    reason: "injected_failure".into(),
                })
            },
        );
        assert!(matches!(
            result,
            Err(IdentityError::TargetAdvancedPublicationFailed)
        ));
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            before
        );
        assert_eq!(
            canonical_version(base, source),
            CredentialVersion::for_credentials(a.anthropic().unwrap()).unwrap()
        );
        assert_eq!(canonical_version(base, target), proof.credential_version());
    }

    #[test]
    fn org_identity_regression_missing_org_and_native_expectation_cannot_create_proof() {
        let dir = TempDir::new().unwrap();
        let creds = credential("unproven", 100);
        let incomplete: HttpGetFn = Arc::new(|_, _, _| {
            Ok((200,br#"{"account":{"email":"same@test.invalid","uuid":"00000000-0000-0000-0000-00000000000a"}}"#.to_vec()))
        });
        assert!(matches!(
            verify_anthropic_context_with(creds.anthropic().unwrap(), &incomplete),
            Err(ProfileCheckFailure::Unknown)
        ));
        let expected = NativeContextExpectation {
            context: context(21),
        };
        let prior = capture_login_prior(dir.path(), slot(1)).unwrap();
        assert!(matches!(
            commit_anthropic_login_with(
                dir.path(),
                slot(1),
                &creds,
                &transport(&creds, context(20)),
                Some(&expected),
                prior
            ),
            Err(IdentityError::InvalidContext)
        ));
        assert!(!profiles::profiles_path(dir.path()).exists());
    }

    #[test]
    fn org_identity_regression_captured_unbound_slot_and_aba_generation_refuse() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let creds = credential("a", 100);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let initial = commit(base, 1, &creds, context(20));
        let candidate = credential("b", 200);
        assert!(matches!(
            commit_anthropic_login_with(
                base,
                slot(1),
                &candidate,
                &transport(&candidate, context(21)),
                None,
                prior
            ),
            Err(IdentityError::BindingChanged)
        ));
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let lock = ProfilesFileLock::acquire(base).unwrap();
        profiles::remove_slot_mapping(&lock, base, 1).unwrap();
        // Reinstall the same UUID: generation must still distinguish the intervening unbind.
        profiles::add_identity_mapping(&lock, base, 1, "fixture-display", initial.identity())
            .unwrap();
        assert!(!binding_matches_locked(&lock, base, &captured).unwrap());
    }

    #[test]
    fn org_identity_regression_proof_wrong_pair_wrong_org_and_stale_anchor_refuse() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = credential("initial", 100);
        let original = commit(base, 1, &initial, context(20)).identity();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let a = credential("a", 200);
        let b = credential("b", 300);
        let proof =
            verify_anthropic_context_with(a.anthropic().unwrap(), &transport(&a, context(20)))
                .unwrap();
        assert!(file::save_anthropic_canonical_guarded(
            base,
            &captured,
            b.anthropic().unwrap(),
            AnthropicWriteWitness::Profile(&proof),
            None
        )
        .is_err());
        let foreign =
            verify_anthropic_context_with(a.anthropic().unwrap(), &transport(&a, context(21)))
                .unwrap();
        assert!(file::save_anthropic_canonical_guarded(
            base,
            &captured,
            a.anthropic().unwrap(),
            AnthropicWriteWitness::Profile(&foreign),
            None
        )
        .is_err());
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                a.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                a.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::BindingChanged
        );
        assert_eq!(
            canonical_version(base, original),
            proof.credential_version()
        );
    }

    #[test]
    fn org_identity_regression_legacy_refresh_rotates_only_own_uuid_without_upgrade() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let legacy = credential("legacy", 100);
        let id = make_legacy(base, &legacy);
        let canonical = identity_store::credentials_path_for(base, id);
        let before = std::fs::read(&canonical).unwrap();
        let metadata = identity_store::identity_json_path_for(base, id);
        let metadata_before = std::fs::read(&metadata).unwrap();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let calls = std::cell::Cell::new(0);
        let prepared = prepare_anthropic_refresh(base, &captured).unwrap();
        let (rotated, lineage) = refresh_captured_anthropic_with(&prepared, legacy.anthropic().unwrap(), |_, _| {
            calls.set(calls.get() + 1);
            Ok(br#"{"access_token":"fake-new-access","refresh_token":"fake-new-refresh","expires_in":3600}"#.to_vec())
        }).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                &rotated,
                AnthropicWriteWitness::RefreshLineage(&lineage),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_ne!(std::fs::read(canonical).unwrap(), before);
        assert!(profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .anthropic_contexts
            .is_empty());
        assert_eq!(std::fs::read(metadata).unwrap(), metadata_before);
        assert_eq!(
            read_stored_context(base, id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
    }

    #[test]
    fn org_identity_regression_known_refresh_preserves_transport_errors() {
        let dir = TempDir::new().unwrap();
        let creds = credential("known", 4102444800000);
        commit(dir.path(), 1, &creds, context(20));
        let captured = capture_anthropic_binding(dir.path(), slot(1)).unwrap();
        let prepared = prepare_anthropic_refresh(dir.path(), &captured).unwrap();
        let result =
            refresh_captured_anthropic_with(&prepared, creds.anthropic().unwrap(), |_, _| {
                Err("fake_transport_failure".into())
            });
        assert!(
            matches!(result, Err(crate::error::OAuthError::Exchange(message)) if message == "fake_transport_failure")
        );
    }

    #[test]
    fn org_identity_regression_legacy_email_diagnostic_is_negative_only_and_read_only() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let original = credential("legacy-recorded-email", 4102444800000);
        let identity = make_legacy(base, &original);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let metadata = identity_store::identity_json_path_for(base, identity);
        let canonical = identity_store::credentials_path_for(base, identity);
        let metadata_before = std::fs::read(&metadata).unwrap();
        let canonical_before = std::fs::read(&canonical).unwrap();
        let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
        for (email, expected) in [
            (" SAME@Test.Invalid ", OwnerVerdict::Unknown),
            ("different@test.invalid", OwnerVerdict::Mismatch),
        ] {
            let candidate = credential("complete-candidate-profile", 4102444800000);
            let context =
                AnthropicContext::new(email, Uuid::from_u128(11), Uuid::from_u128(21)).unwrap();
            let proof = verify_anthropic_context_with(
                candidate.anthropic().unwrap(),
                &transport(&candidate, context),
            )
            .unwrap();
            assert_eq!(
                compare_captured_legacy_email(base, &captured, &proof),
                expected
            );
            assert_eq!(
                compare_verified_owner(captured.context(), &proof),
                OwnerVerdict::Unknown,
                "legacy remains unproved even when diagnostic differs"
            );
            assert_eq!(std::fs::read(&metadata).unwrap(), metadata_before);
            assert_eq!(std::fs::read(&canonical).unwrap(), canonical_before);
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
        }
    }

    #[test]
    fn org_identity_regression_legacy_email_diagnostic_malformed_expected_stays_unknown() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let original = credential("legacy-malformed-expected", 4102444800000);
        let identity = make_legacy(base, &original);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("complete-different-profile", 4102444800000);
        let different = AnthropicContext::new(
            "different@test.invalid",
            Uuid::from_u128(11),
            Uuid::from_u128(21),
        )
        .unwrap();
        let proof = verify_anthropic_context_with(
            candidate.anthropic().unwrap(),
            &transport(&candidate, different),
        )
        .unwrap();
        let metadata = identity_store::identity_json_path_for(base, identity);
        let canonical = identity_store::credentials_path_for(base, identity);
        let canonical_before = std::fs::read(&canonical).unwrap();
        let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
        for expected in [
            serde_json::json!(""),
            serde_json::json!("unknown"),
            serde_json::json!("not-an-email"),
            serde_json::json!("bad\u{0007}@test.invalid"),
            serde_json::json!(7),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({"provider":"anthropic","email":expected,"created_at":"fixture","key_id":null})).unwrap();
            std::fs::write(&metadata, &bytes).unwrap();
            assert_eq!(
                compare_captured_legacy_email(base, &captured, &proof),
                OwnerVerdict::Unknown
            );
            assert_eq!(std::fs::read(&metadata).unwrap(), bytes);
        }
        std::fs::write(&metadata, b"not-json").unwrap();
        assert_eq!(
            compare_captured_legacy_email(base, &captured, &proof),
            OwnerVerdict::Unknown
        );
        assert_eq!(std::fs::read(&metadata).unwrap(), b"not-json");
        let foreign = TempDir::new().unwrap();
        assert_eq!(
            compare_captured_legacy_email(foreign.path(), &captured, &proof),
            OwnerVerdict::Unknown
        );
        assert_eq!(std::fs::read(&canonical).unwrap(), canonical_before);
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            profiles_before
        );
    }

    #[test]
    fn org_identity_regression_legacy_proof_unknown_and_raw_writers_refuse() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let legacy = credential("legacy", 100);
        let id = make_legacy(base, &legacy);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("new", 200);
        let proof = verify_anthropic_context_with(
            candidate.anthropic().unwrap(),
            &transport(&candidate, context(20)),
        )
        .unwrap();
        assert_eq!(
            compare_verified_owner(captured.context(), &proof),
            OwnerVerdict::Unknown
        );
        assert!(file::save_anthropic_canonical_guarded(
            base,
            &captured,
            candidate.anthropic().unwrap(),
            AnthropicWriteWitness::Profile(&proof),
            None
        )
        .is_err());
        assert!(file::save_canonical_for(base, slot(1), &candidate).is_err());
        assert_eq!(canonical_version(base, id), captured.credential_version());
    }

    #[test]
    fn org_identity_regression_missing_canonical_relogin_and_appearance_guard() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let first = credential("old", 100);
        let identity = commit(base, 1, &first, context(20)).identity();
        let path = identity_store::credentials_path_for(base, identity);
        std::fs::remove_file(&path).unwrap();
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let new = credential("new", 200);
        let restored = commit_anthropic_login_with(
            base,
            slot(1),
            &new,
            &transport(&new, context(20)),
            None,
            prior,
        )
        .unwrap();
        assert_eq!(restored.identity(), identity);
        std::fs::remove_file(&path).unwrap();
        let absent = capture_login_prior(base, slot(1)).unwrap();
        file::save(&path, &first).unwrap();
        assert!(matches!(
            commit_anthropic_login_with(
                base,
                slot(1),
                &new,
                &transport(&new, context(20)),
                None,
                absent
            ),
            Err(IdentityError::BindingChanged)
        ));
        assert_eq!(
            canonical_version(base, identity),
            CredentialVersion::for_credentials(first.anthropic().unwrap()).unwrap()
        );
    }

    #[test]
    fn org_identity_regression_codex_prior_is_explicit_and_preserved() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let identity = IdentityId::new_v4();
        identity_store::write_anthropic_metadata_new(
            base,
            identity,
            &serde_json::json!({"provider":"codex","email":"codex:fixture","created_at":"fixture"}),
        )
        .unwrap();
        let path = identity_store::identity_json_path_for(base, identity);
        let before = std::fs::read(&path).unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), identity);
        pf.by_email.insert("codex:fixture".into(), identity);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        let prior = capture_login_prior(base, slot(1)).unwrap();
        assert!(matches!(
            prior.binding.as_ref().unwrap().provider,
            PriorProvider::Codex
        ));
        let new = credential("anthropic", 200);
        let committed = commit_anthropic_login_with(
            base,
            slot(1),
            &new,
            &transport(&new, context(20)),
            None,
            prior,
        )
        .unwrap();
        assert_ne!(committed.identity(), identity);
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(
            profiles::load(&profiles::profiles_path(base))
                .unwrap()
                .by_email
                .get("codex:fixture"),
            Some(&identity)
        );
    }

    #[test]
    fn org_identity_regression_malformed_present_prior_never_treated_as_absent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let first = credential("old", 100);
        let identity = commit(base, 1, &first, context(20)).identity();
        let path = identity_store::credentials_path_for(base, identity);
        std::fs::write(&path, b"not-json").unwrap();
        assert!(capture_login_prior(base, slot(1)).is_err());
    }

    #[test]
    fn org_identity_regression_verified_finalizer_refuses_interleaved_rebind() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = commit(base, 1, &credential("a", 100), context(20));
        let marker = base.join("config-1/.csq-account");
        let _new = commit(base, 1, &credential("b", 200), context(21));
        assert!(crate::accounts::login::finalize_verified_login(base, slot(1), old).is_err());
        assert!(!marker.exists());
    }

    #[test]
    fn org_identity_regression_indexed_missing_metadata_never_remints_from_legacy_email() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let known = commit(base, 1, &credential("known", 100), context(20)).identity();
        let legacy = IdentityId::new_v4();
        let lock = ProfilesFileLock::acquire(base).unwrap();
        let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        pf.by_email.insert("same@test.invalid".into(), legacy);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        std::fs::remove_file(identity_store::identity_json_path_for(base, known)).unwrap();
        drop(lock);
        assert!(capture_login_prior(base, slot(1)).is_err());
        let after = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(after.by_slot.get("1"), Some(&known));
        assert_eq!(after.by_email.get("same@test.invalid"), Some(&legacy));
    }

    #[cfg(unix)]
    #[test]
    fn org_identity_regression_refresh_preflight_repairs_0755_before_rotating_http() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("legacy", 100);
        let id = commit(base, 1, &old, context(20)).identity();
        let identities = identity_store::identities_dir(base);
        let own = identity_store::identity_path(base, id);
        std::fs::set_permissions(&identities, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        assert_eq!(
            captured.context(),
            &StoredAnthropicContext::Known(context(20))
        );
        let prepared = prepare_anthropic_refresh(base, &captured).unwrap();
        let (fresh,lineage)=refresh_captured_anthropic_with(&prepared,old.anthropic().unwrap(),|_,body| {
            assert!(body.contains("fake-refresh-legacy"));
            assert_eq!(std::fs::metadata(&identities).unwrap().permissions().mode() & 0o777,0o700);
            assert_eq!(std::fs::metadata(&own).unwrap().permissions().mode() & 0o777,0o700);
            Ok(br#"{"access_token":"fake-rotated-access","refresh_token":"fake-rotated-refresh","expires_in":3600}"#.to_vec())
        }).unwrap();
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                &fresh,
                AnthropicWriteWitness::RefreshLineage(&lineage),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(
            canonical_version(base, id),
            CredentialVersion::for_credentials(&fresh).unwrap()
        );
    }

    #[test]
    fn org_identity_regression_rotation_rebind_retains_new_pair_at_original_uuid() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // Original expiry deliberately exceeds refreshed expiry: a rotating response is not timestamp-gated.
        let old = credential("old-rotating", 4102444800000);
        let original = commit(base, 1, &old, context(20)).identity();
        let other = credential("foreign", 4102444800001);
        let foreign = commit(base, 2, &other, context(21)).identity();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let prepared = prepare_anthropic_refresh(base, &captured).unwrap();
        let valid = std::cell::Cell::new(true);
        let (fresh,lineage)=refresh_captured_anthropic_with(&prepared,old.anthropic().unwrap(),|_,body| {
            assert!(valid.replace(false),"fake server rejects reuse of already rotated RT");
            assert!(body.contains("fake-refresh-old-rotating"));
            let lock=ProfilesFileLock::acquire(base).unwrap();profiles::swap_slot_mapping(&lock,base,1,2).unwrap();
            Ok(br#"{"access_token":"fake-new-after-rotation","refresh_token":"fake-new-rotated-RT","expires_in":3600}"#.to_vec())
        }).unwrap();
        assert!(
            !valid.get(),
            "old RT actually invalidated by the fixture server"
        );
        assert!(
            fresh.claude_ai_oauth.expires_at < old.anthropic().unwrap().claude_ai_oauth.expires_at
        );
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                &fresh,
                AnthropicWriteWitness::RefreshLineage(&lineage),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(
            canonical_version(base, original),
            CredentialVersion::for_credentials(&fresh).unwrap()
        );
        assert_eq!(
            canonical_version(base, foreign),
            CredentialVersion::for_credentials(other.anthropic().unwrap()).unwrap()
        );
        assert_eq!(profiles::resolve_slot_to_uuid(base, 1), Some(foreign));
        let lock = ProfilesFileLock::acquire(base).unwrap();
        assert!(!binding_custody_matches_locked(&lock, base, &captured).unwrap());
    }

    /// Owner directive 2026-10-11 (coordinator 32b912fa lead, confirmed):
    /// the PRODUCTION Anthropic re-login rebind must record the displaced
    /// uuid in `slot_binding_history` — this writer bumps the generation
    /// directly, so without the record the history channel would be dead
    /// for every real re-login (add_identity_mapping alone is not enough).
    #[test]
    fn production_login_rebind_records_binding_history() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let first_creds = credential("first", 4102444800000);
        let first = commit(base, 1, &first_creds, context(20)).identity();
        let second = commit(base, 1, &credential("second", 4102444800001), context(21)).identity();
        assert_ne!(first, second, "fixture must produce a genuine rebind");
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(pf.by_slot.get("1").copied(), Some(second));
        assert_eq!(pf.slot_binding_generations.get("1").copied(), Some(2));
        assert_eq!(
            pf.slot_binding_history.get("1"),
            Some(&vec![first]),
            "the production rebind path must record the displaced uuid"
        );

        // H1's prescribed end-to-end legs: A is ADMITTED for slot 1 (its
        // canonical fingerprint is carried as a retired binding), and a
        // retired identity of ANOTHER slot is refused. Read the state the
        // gate actually consumes — the writer and the reader meet here.
        let third_creds = credential("third", 4102444800002);
        commit(base, 2, &third_creds, context(22)).identity();
        commit(base, 2, &credential("fourth", 4102444800003), context(23)).identity();
        let bindings = crate::credentials::token_history::retired_bindings_for_slot(base, slot(1));
        assert_eq!(bindings.len(), 1, "exactly slot 1's one displaced identity");
        assert_eq!(
            bindings[0].canonical,
            crate::credentials::token_history::fingerprint_from_credential_file(&first_creds),
            "A's canonical fingerprint is what the gate admits (strong half)"
        );
        assert!(
            !bindings.iter().any(|b| b.canonical
                == crate::credentials::token_history::fingerprint_from_credential_file(
                    &third_creds
                )),
            "slot 2's retired identity must never appear among slot 1's bindings"
        );
    }

    /// Review R3 M1 (second first-bind writer): a FIRST bind through the
    /// production Anthropic publication must clear stale lineage — the
    /// same contract `add_identity_mapping` now carries. Stale entry = the
    /// pre-fix-logout / rollback-unbind shape review R3 M1 describes.
    #[test]
    fn production_login_first_bind_clears_stale_binding_history() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let stale = IdentityId::new_v4();
        let path = profiles::profiles_path(base);
        let mut pf = profiles::ProfilesFile::empty();
        pf.slot_binding_history.insert("3".into(), vec![stale]);
        profiles::save(&path, &pf).unwrap();

        let receipt = commit(base, 3, &credential("fresh", 4102444800000), context(30));

        let pf = profiles::load(&path).unwrap();
        assert_eq!(pf.by_slot.get("3").copied(), Some(receipt.identity()));
        assert_eq!(
            pf.slot_binding_history.get("3"),
            None,
            "a first bind must not inherit stale lineage from a pre-fix unbind \
             (review R3 M1)"
        );
    }

    #[test]
    fn org_identity_regression_same_custody_rotation_allows_prior_and_finalizer() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let original = credential("old", 100);
        let receipt = commit(base, 1, &original, context(20));
        let id = receipt.identity();
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let advance = credential("advanced", 200);
        let proof = verify_anthropic_context_with(
            advance.anthropic().unwrap(),
            &transport(&advance, context(20)),
        )
        .unwrap();
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                advance.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(
            crate::accounts::login::finalize_verified_login(base, slot(1), receipt).unwrap(),
            "same@test.invalid"
        );
        assert_eq!(canonical_version(base, id), proof.credential_version());
        assert!(
            token_history::read_history(base, id).contains(&proof.fingerprint()),
            "old receipt must not reset advanced canonical history to its old fingerprint"
        );
        let fresh = credential("login", 300);
        let committed = commit_anthropic_login_with(
            base,
            slot(1),
            &fresh,
            &transport(&fresh, context(20)),
            None,
            prior,
        )
        .unwrap();
        assert_eq!(committed.identity(), id);
    }

    #[test]
    fn org_identity_regression_rotated_pair_persists_with_corrupt_profiles() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("old", 100);
        let id = commit(base, 1, &old, context(20)).identity();
        let binding = capture_anthropic_binding(base, slot(1)).unwrap();
        assert_eq!(
            binding.context(),
            &StoredAnthropicContext::Known(context(20))
        );
        let prepared = prepare_anthropic_refresh(base, &binding).unwrap();
        let (fresh,proof)=refresh_captured_anthropic_with(&prepared,old.anthropic().unwrap(),|_,_|{
            std::fs::write(profiles::profiles_path(base),b"corrupt-after-rotation").unwrap();
            Ok(br#"{"access_token":"fake-rotated-a","refresh_token":"fake-rotated-r","expires_in":3600}"#.to_vec())
        }).unwrap();
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &binding,
                &fresh,
                AnthropicWriteWitness::RefreshLineage(&proof),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(
            canonical_version(base, id),
            CredentialVersion::for_credentials(&fresh).unwrap()
        );
    }

    #[test]
    fn org_identity_regression_invalid_context_debug_redacts_and_version_binds_expiry() {
        assert!(AnthropicContext::new("unknown", Uuid::from_u128(1), Uuid::from_u128(2)).is_err());
        assert!(
            AnthropicContext::new("valid@test.invalid", Uuid::nil(), Uuid::from_u128(2)).is_err()
        );
        let a = credential("SECRET-FIXTURE", 100);
        let b = credential("SECRET-FIXTURE", 101);
        let proof =
            verify_anthropic_context_with(a.anthropic().unwrap(), &transport(&a, context(20)))
                .unwrap();
        let formatted = format!(
            "{proof:?} {:?} {:?}",
            proof.context(),
            proof.credential_version()
        );
        assert!(formatted.contains("REDACTED"));
        assert!(!formatted.contains("SECRET-FIXTURE"));
        assert!(!formatted.contains("same@test.invalid"));
        assert_ne!(
            CredentialVersion::for_credentials(a.anthropic().unwrap()).unwrap(),
            CredentialVersion::for_credentials(b.anthropic().unwrap()).unwrap()
        );
    }
    #[test]
    fn org_identity_regression_legacy_own_uuid_candidate_cannot_promote_or_redirect() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("legacy-own", 100);
        let id = make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let metadata = std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap();
        let candidate = credential("legacy-candidate", 200);
        let verified = verify_anthropic_context_with(
            candidate.anthropic().unwrap(),
            &transport(&candidate, context(20)),
        )
        .unwrap();
        let own =
            verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, context(20)))
                .unwrap();
        let proof = legacy_own_uuid_proof(
            base,
            &captured,
            &verified,
            &own,
            candidate.anthropic().unwrap(),
        )
        .unwrap();
        assert_eq!(
            compare_verified_owner(captured.context(), &verified),
            OwnerVerdict::Unknown
        );
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::LegacyOwnUuid(&proof),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(profiles::resolve_slot_to_uuid(base, 1), Some(id));
        assert!(profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .anthropic_contexts
            .is_empty());
        assert_eq!(
            std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap(),
            metadata
        );
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::LegacyOwnUuid(&proof),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::BindingChanged
        );
    }

    #[test]
    fn org_identity_regression_legacy_daemon_upgrades_same_uuid_once_without_relogin() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("daemon-own", 100);
        let id = make_legacy(base, &old);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(base.join("identities"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
        let pf_before = profiles::load(&profiles::profiles_path(base)).unwrap();
        let canonical = std::fs::read(identity_store::credentials_path_for(base, id)).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let original = transport(&old, context(20));
        let http: HttpGetFn = Arc::new(move |u, t, h| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            original(u, t, h)
        });
        let mut verifier = crate::daemon::legacy_identity::LegacyVerifier::default();
        let now = std::time::Instant::now();
        let first = verifier.tick_with(base, 2, now, &http);
        assert_eq!((first.attempted, first.upgraded, first.refused), (1, 1, 0));
        assert_eq!(verifier.tick_with(base, 2, now, &http).attempted, 0);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(pf.by_slot, pf_before.by_slot);
        assert_eq!(pf.by_email, pf_before.by_email);
        assert_eq!(pf.anthropic_contexts.len(), 1);
        assert_eq!(pf.anthropic_contexts[0].identity_uuid, id);
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::Known(context(20))
        );
        assert_eq!(
            std::fs::read(identity_store::credentials_path_for(base, id)).unwrap(),
            canonical
        );
    }

    #[test]
    fn org_identity_regression_legacy_metadata_first_crash_repaired_without_http() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("crash-upgrade", 100);
        let id = make_legacy(base, &old);
        let proof =
            verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, context(20)))
                .unwrap();
        assert_eq!(
            upgrade_verified_legacy_identity_with(base, id, &proof, |_, _| Err(IdentityError::Io)),
            Err(IdentityError::Io)
        );
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::Known(context(20))
        );
        assert!(profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .anthropic_contexts
            .is_empty());
        let never: HttpGetFn = Arc::new(|_, _, _| panic!("metadata repair must not call HTTP"));
        let result = crate::daemon::legacy_identity::LegacyVerifier::default().tick_with(
            base,
            0,
            std::time::Instant::now(),
            &never,
        );
        assert_eq!(
            (result.attempted, result.repaired, result.refused),
            (0, 1, 0)
        );
        assert_eq!(
            capture_anthropic_binding(base, slot(1)).unwrap().identity(),
            id
        );
    }

    #[test]
    fn org_identity_regression_legacy_upgrade_collision_and_foreign_email_preserve_bytes() {
        for collision in [false, true] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            if collision {
                commit(base, 2, &credential("foreign-context", 300), context(20));
            }
            let old = credential("legacy-collision", 100);
            // Preserve the already-published foreign context while adding true legacy state.
            let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            let id = make_legacy(base, &old);
            pf.by_slot.insert("1".into(), id);
            profiles::save(&profiles::profiles_path(base), &pf).unwrap();
            let metadata = std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap();
            let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
            let observed = if collision {
                context(20)
            } else {
                AnthropicContext::new(
                    "foreign@test.invalid",
                    Uuid::from_u128(10),
                    Uuid::from_u128(20),
                )
                .unwrap()
            };
            let verified =
                verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, observed))
                    .unwrap();
            // An organization already held by another identity is refused as
            // shared-legacy (remedy: per-slot login); a foreign email stays invalid.
            assert_eq!(
                upgrade_verified_legacy_identity(base, id, &verified),
                Err(if collision {
                    IdentityError::SharedLegacyIdentity
                } else {
                    IdentityError::InvalidContext
                })
            );
            assert_eq!(
                std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap(),
                metadata
            );
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
            assert_eq!(
                read_stored_anthropic_context(base, id).unwrap(),
                StoredAnthropicContext::LegacyUnknown
            );
        }
    }

    #[test]
    fn org_identity_regression_legacy_upgrade_racing_rotation_refuses_stale_proof() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("old-upgrade", 100);
        let id = make_legacy(base, &old);
        let proof =
            verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, context(20)))
                .unwrap();
        let winner = credential("rotation-winner", 200);
        file::save(&identity_store::credentials_path_for(base, id), &winner).unwrap();
        assert_eq!(
            upgrade_verified_legacy_identity(base, id, &proof),
            Err(IdentityError::BindingChanged)
        );
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
        assert!(profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .anthropic_contexts
            .is_empty());
        assert_eq!(
            canonical_version(base, id),
            CredentialVersion::for_credentials(winner.anthropic().unwrap()).unwrap()
        );
    }

    #[test]
    fn org_identity_regression_legacy_upgrade_during_http_preserves_original_uuid_rotation() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("old-flight", 100);
        let id = make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let prepared = prepare_anthropic_refresh(base, &captured).unwrap();
        let (rotated,lineage)=refresh_captured_anthropic_with(&prepared,old.anthropic().unwrap(),|_,_| {
            let proof=verify_anthropic_context_with(old.anthropic().unwrap(),&transport(&old,context(20))).unwrap();
            upgrade_verified_legacy_identity(base,id,&proof).unwrap();
            Ok(br#"{"access_token":"fake-upgraded-access","refresh_token":"fake-upgraded-refresh","expires_in":3600}"#.to_vec())
        }).unwrap();
        assert!(refresh_context_matches(base, &captured).unwrap());
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                &rotated,
                AnthropicWriteWitness::RefreshLineage(&lineage),
                None
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
        assert_eq!(
            canonical_version(base, id),
            CredentialVersion::for_credentials(&rotated).unwrap()
        );
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::Known(context(20))
        );
    }

    #[test]
    fn org_identity_regression_legacy_verifier_budget_backoff_and_zero_budget() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let identities: Vec<_> = (1..=3)
            .map(|n| make_legacy(base, &credential(&format!("budget-{n}"), 100)))
            .collect();
        // make_legacy replaces the slot fixture each time. This budget test
        // needs three live bindings, matching the verifier's admission rule.
        let mut live_profiles = profiles::load(&profiles::profiles_path(base)).unwrap();
        for (index, identity) in identities.into_iter().enumerate() {
            live_profiles
                .by_slot
                .insert((index + 1).to_string(), identity);
        }
        profiles::save(&profiles::profiles_path(base), &live_profiles).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let http: HttpGetFn = Arc::new(move |_, _, _| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((429, vec![]))
        });
        let mut verifier = crate::daemon::legacy_identity::LegacyVerifier::default();
        let now = std::time::Instant::now();
        assert_eq!(verifier.tick_with(base, 0, now, &http).attempted, 0);
        assert_eq!(verifier.tick_with(base, 99, now, &http).attempted, 2);
        assert_eq!(verifier.tick_with(base, 99, now, &http).attempted, 1);
        assert_eq!(verifier.tick_with(base, 99, now, &http).attempted, 0);
        assert_eq!(
            verifier
                .tick_with(base, 99, now + std::time::Duration::from_secs(59), &http)
                .attempted,
            0
        );
        assert_eq!(
            verifier
                .tick_with(base, 99, now + std::time::Duration::from_secs(60), &http)
                .attempted,
            2
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 5);
    }
    #[test]
    fn org_identity_regression_legacy_index_publication_failure_restores_exact_metadata() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("publish-error", 100);
        let id = make_legacy(base, &old);
        let path = identity_store::identity_json_path_for(base, id);
        let before = std::fs::read(&path).unwrap();
        let profiles_path = profiles::profiles_path(base);
        let profiles_before = std::fs::read(&profiles_path).unwrap();
        let verified =
            verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, context(20)))
                .unwrap();
        assert_eq!(
            upgrade_verified_legacy_identity_with(base, id, &verified, |_, _| {
                std::fs::remove_file(&profiles_path).unwrap();
                std::fs::create_dir(&profiles_path).unwrap();
                Ok(())
            }),
            Err(IdentityError::Io)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
        std::fs::remove_dir(&profiles_path).unwrap();
        std::fs::write(&profiles_path, profiles_before).unwrap();
        assert!(profiles::load(&profiles_path)
            .unwrap()
            .anthropic_contexts
            .is_empty());
        assert_eq!(
            canonical_version(base, id),
            CredentialVersion::for_credentials(old.anthropic().unwrap()).unwrap()
        );
    }
    #[test]
    fn org_identity_regression_capture_is_bounded_and_locked_capture_preserves_legacy_custody() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("bounded-capture", 100);
        let id = make_legacy(base, &old);
        let lock = ProfilesFileLock::acquire(base).unwrap();
        assert_eq!(
            crate::accounts::profiles_lock::on_other_thread(|| capture_anthropic_binding(
                base,
                slot(1)
            )),
            Err(IdentityError::BindingBusy)
        );
        let captured = capture_anthropic_binding_locked(&lock, base, slot(1)).unwrap();
        assert_eq!(captured.identity(), id);
        assert_eq!(captured.recorded_legacy_email(), Some("same@test.invalid"));
        assert!(binding_matches_locked(&lock, base, &captured).unwrap());
        assert!(!format!("{captured:?}").contains("same@test.invalid"));
    }
    #[test]
    fn org_identity_regression_legacy_proof_cannot_authorize_foreign_uuid_or_email() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("proof-source", 100);
        let first = make_legacy(base, &old);
        let first_captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("proof-candidate", 200);
        let verified = verify_anthropic_context_with(
            candidate.anthropic().unwrap(),
            &transport(&candidate, context(20)),
        )
        .unwrap();
        let own =
            verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, context(20)))
                .unwrap();
        let proof = legacy_own_uuid_proof(
            base,
            &first_captured,
            &verified,
            &own,
            candidate.anthropic().unwrap(),
        )
        .unwrap();
        let second = make_legacy(base, &old);
        let second_captured = capture_anthropic_binding(base, slot(1)).unwrap();
        assert_ne!(first, second);
        assert!(!proof.permits(base, &second_captured, candidate.anthropic().unwrap()));
        let foreign = AnthropicContext::new(
            "foreign@test.invalid",
            Uuid::from_u128(10),
            Uuid::from_u128(20),
        )
        .unwrap();
        let foreign = verify_anthropic_context_with(
            candidate.anthropic().unwrap(),
            &transport(&candidate, foreign),
        )
        .unwrap();
        assert!(legacy_own_uuid_proof(
            base,
            &second_captured,
            &foreign,
            &own,
            candidate.anthropic().unwrap()
        )
        .is_err());
        assert_eq!(
            compare_captured_legacy_email(base, &second_captured, &foreign),
            OwnerVerdict::Mismatch
        );
        assert_eq!(
            canonical_version(base, first),
            first_captured.credential_version()
        );
        assert_eq!(
            canonical_version(base, second),
            second_captured.credential_version()
        );
        assert!(profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .anthropic_contexts
            .is_empty());
    }

    #[test]
    fn org_identity_regression_unproven_legacy_metadata_drift_is_not_refresh_lineage() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("drift-source", 100);
        let id = make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let path = identity_store::identity_json_path_for(base, id);
        let mut metadata = read_json(&path, true).unwrap();
        metadata["account_uuid"] = serde_json::json!(context(20).account_uuid());
        metadata["organization_uuid"] = serde_json::json!(context(20).organization_uuid());
        publish_metadata(&path, &metadata).unwrap();
        assert_eq!(
            refresh_context_matches(base, &captured),
            Err(IdentityError::InvalidMetadata)
        );
        assert_eq!(canonical_version(base, id), captured.credential_version());
    }
    fn unrelated_damaged_entries() -> Vec<AnthropicContextEntry> {
        let identity = IdentityId::new_v4();
        vec![
            AnthropicContextEntry {
                email: "not-an-email".into(),
                account_uuid: Uuid::from_u128(501),
                organization_uuid: Uuid::from_u128(502),
                identity_uuid: identity,
                extra: Default::default(),
            },
            AnthropicContextEntry {
                email: "foreign@test.invalid".into(),
                account_uuid: Uuid::from_u128(601),
                organization_uuid: Uuid::from_u128(602),
                identity_uuid: IdentityId::new_v4(),
                extra: Default::default(),
            },
        ]
    }

    #[test]
    fn org_identity_regression_foreign_index_damage_does_not_disable_healthy_capture_or_login() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("healthy-known", 100);
        let id = commit(base, 1, &old, context(20)).identity();
        let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        let mut damage = unrelated_damaged_entries();
        damage.push(damage[1].clone());
        pf.anthropic_contexts.extend(damage.clone());
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        assert_eq!(
            capture_anthropic_binding(base, slot(1)).unwrap().identity(),
            id
        );
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let new = credential("healthy-reuse", 200);
        assert_eq!(
            commit_anthropic_login_with(
                base,
                slot(1),
                &new,
                &transport(&new, context(20)),
                None,
                prior
            )
            .unwrap()
            .identity(),
            id
        );
        let fresh = commit(base, 2, &credential("healthy-new", 300), context(21));
        assert_ne!(fresh.identity(), id);
        let after = profiles::load(&profiles::profiles_path(base)).unwrap();
        for row in damage {
            assert_eq!(
                after
                    .anthropic_contexts
                    .iter()
                    .filter(|entry| *entry == &row)
                    .count(),
                pf.anthropic_contexts
                    .iter()
                    .filter(|entry| *entry == &row)
                    .count()
            );
        }
    }

    #[test]
    fn org_identity_regression_foreign_index_damage_does_not_disable_legacy_upgrade() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("healthy-legacy-upgrade", 100);
        let id = make_legacy(base, &old);
        let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        let mut damage = unrelated_damaged_entries();
        damage.push(damage[1].clone());
        pf.anthropic_contexts.extend(damage.clone());
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        assert_eq!(
            capture_anthropic_binding(base, slot(1)).unwrap().identity(),
            id
        );
        let proof =
            verify_anthropic_context_with(old.anthropic().unwrap(), &transport(&old, context(20)))
                .unwrap();
        upgrade_verified_legacy_identity(base, id, &proof).unwrap();
        let after = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(after.by_slot, pf.by_slot);
        assert_eq!(after.by_email, pf.by_email);
        assert_eq!(
            capture_anthropic_binding(base, slot(1)).unwrap().context(),
            &StoredAnthropicContext::Known(context(20))
        );
        for row in damage {
            assert_eq!(
                after
                    .anthropic_contexts
                    .iter()
                    .filter(|entry| *entry == &row)
                    .count(),
                pf.anthropic_contexts
                    .iter()
                    .filter(|entry| *entry == &row)
                    .count()
            );
        }
    }

    #[test]
    fn org_identity_regression_selected_duplicate_index_authority_refuses_capture_and_reuse() {
        for duplicate_context in [false, true] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("selected-duplicate", 100);
            let id = commit(base, 1, &old, context(20)).identity();
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            let mut duplicate = pf.anthropic_contexts[0].clone();
            if duplicate_context {
                duplicate.identity_uuid = IdentityId::new_v4();
            } else {
                duplicate.organization_uuid = Uuid::from_u128(21);
            }
            pf.anthropic_contexts.push(duplicate);
            profiles::save(&profiles::profiles_path(base), &pf).unwrap();
            let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
            let canonical_before =
                std::fs::read(identity_store::credentials_path_for(base, id)).unwrap();
            assert!(capture_anthropic_binding(base, slot(1)).is_err());
            assert!(capture_login_prior(base, slot(1)).is_err());
            let incoming = credential("duplicate-incoming", 200);
            assert!(commit_anthropic_login_with(
                base,
                slot(1),
                &incoming,
                &transport(&incoming, context(20)),
                None,
                prior
            )
            .is_err());
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
            assert_eq!(
                std::fs::read(identity_store::credentials_path_for(base, id)).unwrap(),
                canonical_before
            );
        }
    }

    #[test]
    fn org_identity_regression_ambiguous_target_index_row_refuses_upgrade_and_new_login() {
        for malformed_field in 0..3 {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("ambiguous-upgrade", 100);
            let id = make_legacy(base, &old);
            let mut row = AnthropicContextEntry::new(&context(20), IdentityId::new_v4());
            match malformed_field {
                0 => row.email = "not-an-email".into(),
                1 => row.account_uuid = Uuid::nil(),
                _ => row.organization_uuid = Uuid::nil(),
            }
            let mut pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            pf.anthropic_contexts.push(row);
            profiles::save(&profiles::profiles_path(base), &pf).unwrap();
            let metadata_before =
                std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap();
            let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
            let proof = verify_anthropic_context_with(
                old.anthropic().unwrap(),
                &transport(&old, context(20)),
            )
            .unwrap();
            assert!(upgrade_verified_legacy_identity(base, id, &proof).is_err());
            let prior = capture_login_prior(base, slot(2)).unwrap();
            let incoming = credential("ambiguous-new", 200);
            assert!(commit_anthropic_login_with(
                base,
                slot(2),
                &incoming,
                &transport(&incoming, context(20)),
                None,
                prior
            )
            .is_err());
            assert_eq!(
                std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap(),
                metadata_before
            );
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
        }
    }
    #[test]
    fn org_identity_regression_profiles_snapshot_missing_matches_empty_load() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        assert!(!profiles::profiles_path(base).exists());
        let bounded = read_profiles_snapshot(base).unwrap();
        let ordinary = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            serde_json::to_value(&bounded).unwrap(),
            serde_json::to_value(&ordinary).unwrap()
        );
        assert!(!profiles::profiles_path(base).exists());
        assert!(!base.join(".profiles.lock").exists());
    }

    #[test]
    fn org_identity_regression_profiles_snapshot_oversize_and_malformed_refuse() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let path = profiles::profiles_path(base);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for bytes in [vec![b' '; 1024 * 1024 + 1], b"{".to_vec(), b"  ".to_vec()] {
            std::fs::write(&path, &bytes).unwrap();
            assert!(
                read_profiles_snapshot(base).is_err(),
                "present invalid content must never become empty"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(!base.join(".profiles.lock").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn org_identity_regression_profiles_snapshot_symlink_and_dangling_refuse() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let path = profiles::profiles_path(base);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = base.join("snapshot-target.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_profiles_snapshot(base).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
        std::fs::remove_file(&target).unwrap();
        assert!(
            read_profiles_snapshot(base).is_err(),
            "dangling symlink is present unsafe state, not absence"
        );
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!base.join(".profiles.lock").exists());
    }

    #[test]
    fn org_identity_regression_profiles_snapshot_roundtrips_without_global_index_validation() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let mut expected = ProfilesFile::empty();
        expected.by_slot.insert("1".into(), IdentityId::new_v4());
        expected
            .by_slot_label
            .insert("1".into(), "Fixture label".into());
        expected.slot_binding_generations.insert("1".into(), 7);
        expected.extra.insert(
            "fixture_extension".into(),
            serde_json::json!({"preserve":true}),
        );
        // A snapshot does not decide whether an unrelated semantic row grants
        // authority. Target-specific validators perform that separate check.
        expected.anthropic_contexts = serde_json::from_value(serde_json::json!([{
            "email":"semantically-bad-row","account_uuid":Uuid::nil(),
            "organization_uuid":Uuid::nil(),"identity_uuid":IdentityId::new_v4()
        }]))
        .unwrap();
        profiles::save(&profiles::profiles_path(base), &expected).unwrap();
        let before = std::fs::read(profiles::profiles_path(base)).unwrap();
        let lock = ProfilesFileLock::acquire(base).unwrap();
        let actual = read_profiles_snapshot(base).unwrap();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            before
        );
        drop(lock);
    }

    #[test]
    fn org_identity_regression_context_row_extensions_survive_selected_and_foreign_roundtrip() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let selected = IdentityId::new_v4();
        let foreign = IdentityId::new_v4();
        let selected_context = context(11);
        let foreign_context = context(12);
        let mut original = serde_json::to_value(ProfilesFile::empty()).unwrap();
        original["by_slot"] = serde_json::json!({"1": selected});
        original["anthropic_contexts"] = serde_json::json!([
            {
                "email":selected_context.email(),
                "account_uuid":selected_context.account_uuid(),
                "organization_uuid":selected_context.organization_uuid(),
                "identity_uuid":selected,
                "future_selected_policy":{"retain":[true,7,"selected"]}
            },
            {
                "email":foreign_context.email(),
                "account_uuid":foreign_context.account_uuid(),
                "organization_uuid":foreign_context.organization_uuid(),
                "identity_uuid":foreign,
                "future_foreign_policy":{"retain":[null,"foreign"]}
            }
        ]);
        let path = profiles::profiles_path(base);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        let mut parsed = profiles::load(&path).unwrap();
        assert_eq!(parsed.by_slot.get("1"), Some(&selected));
        assert_eq!(
            parsed.anthropic_contexts[0].context().unwrap(),
            selected_context
        );
        assert_eq!(
            parsed.anthropic_contexts[1].context().unwrap(),
            foreign_context
        );
        assert_eq!(parsed.anthropic_contexts[0].extra.len(), 1);
        assert_eq!(parsed.anthropic_contexts[1].extra.len(), 1);
        parsed
            .by_slot_label
            .insert("1".into(), "Updated display label".into());
        profiles::save(&path, &parsed).unwrap();
        let actual: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            actual["anthropic_contexts"], original["anthropic_contexts"],
            "saving a selected-slot update must preserve both row extensions"
        );
        assert_eq!(actual["by_slot_label"]["1"], "Updated display label");
        let bounded = read_profiles_snapshot(base).unwrap();
        assert_eq!(
            serde_json::to_value(&bounded.anthropic_contexts).unwrap(),
            original["anthropic_contexts"]
        );
    }

    fn verified_for(cred: &CredentialFile, ctx: AnthropicContext) -> VerifiedAnthropicContext {
        verify_anthropic_context_with(cred.anthropic().unwrap(), &transport(cred, ctx)).unwrap()
    }
    #[test]
    fn org_identity_r2_legacy_adoption_requires_own_token_match() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r2-own", 100);
        make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r2-candidate", 200);
        let cand = verified_for(&candidate, context(20));
        // The identity's own token verified to a DIFFERENT organization: refuse.
        let own_other_org = verified_for(&old, context(21));
        assert!(legacy_own_uuid_proof(
            base,
            &captured,
            &cand,
            &own_other_org,
            candidate.anthropic().unwrap()
        )
        .is_err());
        // A "own" verification of some token that is not the captured canonical.
        let not_own = verified_for(&candidate, context(20));
        assert!(legacy_own_uuid_proof(
            base,
            &captured,
            &cand,
            &not_own,
            candidate.anthropic().unwrap()
        )
        .is_err());
        let own = verified_for(&old, context(20));
        assert!(legacy_own_uuid_proof(
            base,
            &captured,
            &cand,
            &own,
            candidate.anthropic().unwrap()
        )
        .is_ok());
    }
    #[test]
    fn org_identity_r2_shared_legacy_uuid_refuses_adoption_and_upgrade() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r2-shared", 100);
        let id = make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let own = verified_for(&old, context(20));
        let candidate = credential("r2-shared-candidate", 200);
        let cand = verified_for(&candidate, context(20));
        let proof =
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                .unwrap();
        let path = profiles::profiles_path(base);
        let mut pf = profiles::load(&path).unwrap();
        pf.by_slot.insert("2".into(), id);
        profiles::save(&path, &pf).unwrap();
        assert!(legacy_identity_is_shared(base, id).unwrap());
        // The write-time re-check (permits) sees the second slot too.
        assert!(!proof.permits(base, &captured, candidate.anthropic().unwrap()));
        assert_eq!(
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                .unwrap_err(),
            IdentityError::SharedLegacyIdentity
        );
        assert_eq!(
            upgrade_verified_legacy_identity(base, id, &own),
            Err(IdentityError::SharedLegacyIdentity)
        );
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
    }
    /// Legacy own-UUID adoption must apply the full-context index check the upgrade path
    /// already applies: a foreign row that MAY match the candidate's (email, account,
    /// organization) -- including a damaged row whose invalid field is a wildcard -- refuses
    /// the proof at mint time and again at write time (`permits`, under the caller's lock).
    #[test]
    fn org_identity_r2_legacy_adoption_refuses_foreign_row_that_may_match_context() {
        for malformed_field in 0..4 {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r2-wild", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r2-wild-candidate", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            // Healthy index: the proof is minted and permits the write (non-vacuity).
            let proof =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .unwrap();
            assert!(proof.permits(base, &captured, candidate.anthropic().unwrap()));
            let mut row = AnthropicContextEntry::new(&context(20), IdentityId::new_v4());
            match malformed_field {
                0 => row.email = "not-an-email".into(),
                1 => row.account_uuid = Uuid::nil(),
                2 => row.organization_uuid = Uuid::nil(),
                // Exact foreign Known row for the same complete context.
                _ => {}
            }
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap();
            pf.anthropic_contexts.push(row);
            profiles::save(&path, &pf).unwrap();
            // Write time: the already-minted proof no longer permits.
            assert!(
                !proof.permits(base, &captured, candidate.anthropic().unwrap()),
                "field {malformed_field}: permits must re-check the index"
            );
            // Mint time: no new proof is granted.
            assert!(
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .is_err(),
                "field {malformed_field}: proof minted despite a foreign matching row"
            );
            let before = std::fs::read(identity_store::credentials_path_for(base, id)).unwrap();
            assert!(file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::LegacyOwnUuid(&proof),
                None
            )
            .is_err());
            assert_eq!(
                std::fs::read(identity_store::credentials_path_for(base, id)).unwrap(),
                before,
                "field {malformed_field}: canonical must be untouched"
            );
        }
    }
    /// "Cannot read the index" refuses, at mint time, at write time and at the guarded
    /// writer, and a foreign row that CANNOT match the candidate's complete context
    /// (different organization) does not over-refuse. Both directions are asserted so
    /// the guard is shown to discriminate rather than to refuse everything.
    #[test]
    fn org_identity_r2_legacy_adoption_fails_closed_on_unreadable_index_only() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r2-unreadable", 100);
        let id = make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r2-unreadable-candidate", 200);
        let cand = verified_for(&candidate, context(20));
        let own = verified_for(&old, context(20));
        let path = profiles::profiles_path(base);
        let healthy = std::fs::read(&path).unwrap();
        // A foreign Known row for a DIFFERENT organization of the same email is no match.
        let mut pf = profiles::load(&path).unwrap();
        pf.anthropic_contexts.push(AnthropicContextEntry::new(
            &context(21),
            IdentityId::new_v4(),
        ));
        profiles::save(&path, &pf).unwrap();
        let proof =
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                .expect("an index row for another organization must not refuse adoption");
        assert!(proof.permits(base, &captured, candidate.anthropic().unwrap()));
        std::fs::write(&path, &healthy).unwrap();
        let proof =
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                .unwrap();
        assert!(proof.permits(base, &captured, candidate.anthropic().unwrap()));
        let before = std::fs::read(identity_store::credentials_path_for(base, id)).unwrap();
        for (label, unreadable) in [
            ("garbage", b"{ not json".to_vec()),
            ("blank", b"   \n".to_vec()),
        ] {
            std::fs::write(&path, &unreadable).unwrap();
            assert!(
                !proof.permits(base, &captured, candidate.anthropic().unwrap()),
                "{label}: permits must refuse when the index cannot be read"
            );
            assert!(
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .is_err(),
                "{label}: no proof may be minted when the index cannot be read"
            );
            assert!(
                file::save_anthropic_canonical_guarded(
                    base,
                    &captured,
                    candidate.anthropic().unwrap(),
                    AnthropicWriteWitness::LegacyOwnUuid(&proof),
                    None
                )
                .is_err(),
                "{label}: the guarded writer must refuse"
            );
            assert_eq!(
                std::fs::read(identity_store::credentials_path_for(base, id)).unwrap(),
                before,
                "{label}: canonical must be untouched"
            );
        }
    }
    /// A foreign row for the SAME account and organization is the same grant principal
    /// whatever email it records (a provider-side email change leaves stale-email rows),
    /// so it refuses legacy adoption and upgrade exactly as a full-context match does. A
    /// row that differs in account or organization does not.
    #[test]
    fn org_identity_regression_foreign_row_with_same_account_and_org_refuses_adoption_and_upgrade()
    {
        // (row email, account, organization, must refuse)
        let cases = [
            ("other@test.invalid", 10u128, 20u128, true),
            ("OTHER@test.invalid", 10, 20, true),
            ("other@test.invalid", 10, 21, false),
            ("other@test.invalid", 11, 20, false),
        ];
        for (email, account, org, refuses) in cases {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("n1-own", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("n1-cand", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            let early =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .unwrap();
            assert!(early.permits(base, &captured, candidate.anthropic().unwrap()));
            let foreign =
                AnthropicContext::new(email, Uuid::from_u128(account), Uuid::from_u128(org))
                    .unwrap();
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap();
            pf.anthropic_contexts
                .push(AnthropicContextEntry::new(&foreign, IdentityId::new_v4()));
            profiles::save(&path, &pf).unwrap();
            let label = format!("{email} acct={account} org={org}");
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            let permitted = early.permits(base, &captured, candidate.anthropic().unwrap());
            let metadata = std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap();
            let upgraded = upgrade_verified_legacy_identity(base, id, &own);
            if refuses {
                assert_eq!(
                    minted.unwrap_err(),
                    IdentityError::SharedLegacyIdentity,
                    "{label}"
                );
                assert!(!permitted, "{label}: permits must refuse");
                assert_eq!(
                    upgraded,
                    Err(IdentityError::SharedLegacyIdentity),
                    "{label}"
                );
                assert_eq!(
                    std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap(),
                    metadata,
                    "{label}: a refused upgrade leaves the metadata untouched"
                );
            } else {
                assert!(minted.is_ok(), "{label}: an unrelated row must not refuse");
                assert!(permitted, "{label}");
                assert_eq!(upgraded, Ok(()), "{label}");
            }
        }
    }
    /// Crash between an upgrade's metadata and index writes: the identity is Known with
    /// NO index row. The index-only checks cannot see it, so a legacy identity could take
    /// its context. The ambiguity check reads that sibling's metadata and refuses on a
    /// context that may collide, and fails CLOSED on metadata it cannot classify. A Known
    /// sibling of another organization, an absent identity.json and a non-Anthropic
    /// sibling do not refuse.
    #[test]
    fn org_identity_regression_known_sibling_without_index_row_refuses_legacy_mint_and_permits_but_upgrade_resolves(
    ) {
        let _tracing = tracing_lock();
        // (label, sibling context org, sibling metadata mutation, must refuse)
        let cases: [(&str, u128, &str, bool); 8] = [
            ("same context", 20, "keep", true),
            ("same account and org, other email", 20, "email", true),
            ("other organization", 21, "keep", false),
            ("unreadable metadata", 20, "garbage", true),
            ("absent identity.json", 20, "remove", false),
            ("non-Anthropic provider", 20, "codex", false),
            // r4 SEC-H1: another LEGACY identity recording the SAME email is ambiguous
            // authority (token equality cannot see a rotation lag); a different email is not.
            ("legacy sibling, same email", 20, "legacy", true),
            ("legacy sibling, other email", 20, "legacy_other", false),
        ];
        for (label, org, mutation, refuses) in cases {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("l1-own", 100);
            let id = make_legacy(base, &old);
            let sibling = commit(base, 2, &credential("l1-sibling", 100), context(org)).identity();
            // The crash shape: the sibling's metadata is Known, its index row is gone.
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap();
            pf.anthropic_contexts
                .retain(|entry| entry.identity_uuid != sibling);
            profiles::save(&path, &pf).unwrap();
            let metadata_path = identity_store::identity_json_path_for(base, sibling);
            let mut json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
            match mutation {
                "keep" => (),
                "email" => json["email"] = serde_json::json!("renamed@test.invalid"),
                "garbage" => std::fs::write(&metadata_path, b"{ not json").unwrap(),
                "remove" => std::fs::remove_file(&metadata_path).unwrap(),
                "codex" => json["provider"] = serde_json::json!("codex"),
                "legacy" | "legacy_other" => {
                    json.as_object_mut().unwrap().remove("account_uuid");
                    json.as_object_mut().unwrap().remove("organization_uuid");
                    if mutation == "legacy_other" {
                        json["email"] = serde_json::json!("other@test.invalid");
                    }
                }
                _ => unreachable!(),
            }
            if ["email", "codex", "legacy", "legacy_other"].contains(&mutation) {
                std::fs::write(&metadata_path, serde_json::to_vec(&json).unwrap()).unwrap();
            }
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("l1-cand", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            let metadata_before =
                std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap();
            let upgraded = upgrade_verified_legacy_identity(base, id, &own);
            if refuses {
                assert_eq!(
                    minted.unwrap_err(),
                    IdentityError::SharedLegacyIdentity,
                    "{label}"
                );
                if mutation == "legacy" {
                    // r5 F4: the metadata-only upgrade adopts no candidate and resolves a
                    // same-email legacy pair, so it is exempt from the same-email clause.
                    assert_eq!(upgraded, Ok(()), "{label}: upgrade is exempt");
                    assert_upgrade_recorded_own_context(base, id, &own, label);
                } else {
                    assert_eq!(
                        upgraded,
                        Err(IdentityError::SharedLegacyIdentity),
                        "{label}"
                    );
                    assert_eq!(
                        std::fs::read(identity_store::identity_json_path_for(base, id)).unwrap(),
                        metadata_before,
                        "{label}: a refused upgrade leaves the metadata untouched"
                    );
                }
            } else {
                assert!(minted.is_ok(), "{label}: must not refuse");
                assert_eq!(upgraded, Ok(()), "{label}: must not refuse");
            }
        }
    }
    /// A foreign row that MAY match but is DAMAGED (its recorded context does not parse)
    /// raises `DamagedContextIndexRow`, not `SharedLegacyIdentity`: login refuses on the
    /// same row, so the shared-identity remedy ("run csq login") would loop. A healthy
    /// foreign row keeps `SharedLegacyIdentity`.
    #[test]
    fn org_identity_regression_damaged_foreign_row_refuses_with_its_own_error() {
        for (label, damage, expected) in [
            ("bad email", 0, IdentityError::DamagedContextIndexRow),
            ("nil account", 1, IdentityError::DamagedContextIndexRow),
            ("nil organization", 2, IdentityError::DamagedContextIndexRow),
            ("healthy exact row", 3, IdentityError::SharedLegacyIdentity),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("dmg-own", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("dmg-cand", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            let mut row = AnthropicContextEntry::new(&context(20), IdentityId::new_v4());
            match damage {
                0 => row.email = "not-an-email".into(),
                1 => row.account_uuid = Uuid::nil(),
                2 => row.organization_uuid = Uuid::nil(),
                _ => (),
            }
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap();
            pf.anthropic_contexts.push(row);
            profiles::save(&path, &pf).unwrap();
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            assert_eq!(minted.unwrap_err(), expected, "{label}: mint");
            assert_eq!(
                upgrade_verified_legacy_identity(base, id, &own),
                Err(expected),
                "{label}: upgrade"
            );
        }
    }
    /// Bind a second LEGACY identity (no index row) to `slot_key`, holding `held`.
    ///
    /// The sibling records a DIFFERENT email than the fixtures' `same@test.invalid`, so it
    /// isolates the token comparison from the same-email ambiguity refusal (r4 SEC-H1).
    fn add_legacy_sibling(base: &Path, slot_key: &str, held: &CredentialFile) -> IdentityId {
        add_legacy_sibling_with_email(base, slot_key, "other@test.invalid", held)
    }
    fn add_legacy_sibling_with_email(
        base: &Path,
        slot_key: &str,
        email: &str,
        held: &CredentialFile,
    ) -> IdentityId {
        let sibling = IdentityId::new_v4();
        crate::daemon::identity_mint::write_legacy_anthropic_metadata_fixture(base, sibling, email)
            .unwrap();
        file::save(&identity_store::credentials_path_for(base, sibling), held).unwrap();
        let path = profiles::profiles_path(base);
        let mut pf = profiles::load(&path).unwrap();
        pf.by_slot.insert(slot_key.into(), sibling);
        profiles::save(&path, &pf).unwrap();
        sibling
    }
    /// Two identities must never hold one grant. Another bound identity's canonical
    /// credential that shares the candidate's refresh token OR access token refuses
    /// the legacy witness at mint and at write; a different pair does not.
    #[test]
    fn org_identity_regression_legacy_adoption_refuses_candidate_pair_held_by_another_identity() {
        // (sibling access, sibling refresh, must refuse): the candidate is
        // fake-access-r3-cand / fake-refresh-r3-cand.
        for (label, access, refresh, refuses) in [
            (
                "same refresh",
                "fake-access-sibling",
                "fake-refresh-r3-cand",
                true,
            ),
            (
                "same access",
                "fake-access-r3-cand",
                "fake-refresh-sibling",
                true,
            ),
            (
                "unrelated pair",
                "fake-access-sibling",
                "fake-refresh-sibling",
                false,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r3-own", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r3-cand", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            // Control: before any sibling exists the proof is minted and permits the write.
            let early =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .unwrap();
            assert!(early.permits(base, &captured, candidate.anthropic().unwrap()));
            let mut held = credential("r3-sibling", 150);
            let payload = &mut held.expect_anthropic_mut().claude_ai_oauth;
            payload.access_token = AccessToken::new(access.to_owned());
            payload.refresh_token = RefreshToken::new(refresh.to_owned());
            let sibling = add_legacy_sibling(base, "2", &held);
            let sibling_before =
                std::fs::read(identity_store::credentials_path_for(base, sibling)).unwrap();
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            // Write time: an already-minted proof sees a sibling bound after the mint.
            let permitted = early.permits(base, &captured, candidate.anthropic().unwrap());
            let before = std::fs::read(identity_store::credentials_path_for(base, id)).unwrap();
            if refuses {
                assert_eq!(
                    minted.unwrap_err(),
                    IdentityError::SharedLegacyIdentity,
                    "{label}: mint must refuse"
                );
                assert!(!permitted, "{label}: permits must refuse");
                assert!(
                    file::save_anthropic_canonical_guarded(
                        base,
                        &captured,
                        candidate.anthropic().unwrap(),
                        AnthropicWriteWitness::LegacyOwnUuid(&early),
                        None
                    )
                    .is_err(),
                    "{label}: the guarded writer must refuse"
                );
                assert_eq!(
                    std::fs::read(identity_store::credentials_path_for(base, id)).unwrap(),
                    before,
                    "{label}: canonical must be untouched"
                );
            } else {
                let proof = minted.expect("an unrelated pair must not refuse");
                assert!(
                    permitted && proof.permits(base, &captured, candidate.anthropic().unwrap())
                );
            }
            assert_eq!(
                std::fs::read(identity_store::credentials_path_for(base, sibling)).unwrap(),
                sibling_before,
                "{label}: the sibling's canonical is never touched"
            );
        }
    }
    /// The same rule on the Known-context writer: a verified context cannot rule out
    /// that a legacy identity's canonical holds the very pair being adopted.
    #[test]
    fn org_identity_regression_known_adoption_refuses_pair_held_by_a_legacy_identity() {
        for sibling_holds_pair in [false, true] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let target = commit(base, 1, &credential("r3-known", 100), context(20)).identity();
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r3-known-cand", 200);
            let proof = verified_for(&candidate, context(20));
            let mut held = credential("r3-legacy-sibling", 150);
            if sibling_holds_pair {
                held.expect_anthropic_mut().claude_ai_oauth.refresh_token =
                    RefreshToken::new("fake-refresh-r3-known-cand".to_owned());
            }
            let sibling = add_legacy_sibling(base, "2", &held);
            let sibling_before =
                std::fs::read(identity_store::credentials_path_for(base, sibling)).unwrap();
            let before = canonical_version(base, target);
            let outcome = file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            );
            if sibling_holds_pair {
                assert!(outcome.is_err(), "a held pair must be refused");
                assert_eq!(canonical_version(base, target), before);
            } else {
                assert_eq!(outcome.unwrap(), GuardedWriteOutcome::Written);
            }
            assert_eq!(
                std::fs::read(identity_store::credentials_path_for(base, sibling)).unwrap(),
                sibling_before
            );
        }
    }
    #[test]
    fn org_identity_r2_org_held_by_other_identity_refuses_legacy_upgrade() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r2-held", 100);
        let id = make_legacy(base, &old);
        commit(base, 2, &credential("r2-other", 100), context(20));
        let own = verified_for(&old, context(20));
        assert_eq!(
            upgrade_verified_legacy_identity(base, id, &own),
            Err(IdentityError::SharedLegacyIdentity)
        );
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::LegacyUnknown
        );
    }
    #[test]
    fn org_identity_r2_repair_refuses_known_identity_without_upgrade_marker() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("r2-known", 100), context(20)).identity();
        let path = profiles::profiles_path(base);
        let mut pf = profiles::load(&path).unwrap();
        pf.anthropic_contexts.clear();
        profiles::save(&path, &pf).unwrap();
        assert_eq!(
            repair_legacy_context_index(base, id),
            Err(IdentityError::InvalidMetadata)
        );
        assert!(profiles::load(&path).unwrap().anthropic_contexts.is_empty());
    }
    #[test]
    fn org_identity_r2_repair_and_upgrade_defer_on_busy_locks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r2-busy", 100);
        let id = make_legacy(base, &old);
        let own = verified_for(&old, context(20));
        let held = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        assert_eq!(
            upgrade_verified_legacy_identity(base, id, &own),
            Err(IdentityError::BindingBusy)
        );
        assert_eq!(
            repair_legacy_context_index(base, id),
            Ok(LegacyRepair::Deferred)
        );
        let http = transport(&old, context(20));
        let summary = crate::daemon::legacy_identity::LegacyVerifier::default().tick_with(
            base,
            2,
            std::time::Instant::now(),
            &http,
        );
        assert_eq!(
            (summary.deferred, summary.refused, summary.upgraded),
            (1, 0, 0)
        );
        drop(held);
        let canonical_path = identity_store::credentials_path_for(base, id).with_extension("lock");
        let canonical = crate::accounts::profiles_lock::HeldOnOtherThread::hold(move || {
            crate::platform::lock::lock_file(&canonical_path).unwrap()
        });
        assert_eq!(
            upgrade_verified_legacy_identity(base, id, &own),
            Err(IdentityError::BindingBusy)
        );
        assert_eq!(
            repair_legacy_context_index(base, id),
            Ok(LegacyRepair::Deferred)
        );
        drop(canonical);
        upgrade_verified_legacy_identity(base, id, &own).unwrap();
    }
    #[test]
    fn org_identity_r2_bound_slot_missing_identity_json_carries_remedy() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = make_legacy(base, &credential("r2-nometa", 100));
        std::fs::remove_file(identity_store::identity_json_path_for(base, id)).unwrap();
        let error = capture_login_prior(base, slot(1)).err().unwrap();
        assert_eq!(
            error,
            IdentityError::BoundIdentityMetadataMissing { account: 1 }
        );
        assert!(error.to_string().contains("csq logout 1"));
        assert!(error.to_string().contains("csq login 1"));
    }
    #[test]
    fn org_identity_r2_legacy_source_absent_or_removed_is_none_unreadable_refuses() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = make_legacy(base, &credential("r2-source", 100));
        assert!(legacy_verification_source(base, id).unwrap().is_some());
        let path = identity_store::credentials_path_for(base, id);
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"{not json").unwrap();
        assert!(legacy_verification_source(base, id).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(legacy_verification_source(base, id), Ok(None)));
        std::fs::write(&path, good).unwrap();
        identity_store::mark_identity_removed(base, id);
        assert!(matches!(legacy_verification_source(base, id), Ok(None)));
    }
    #[test]
    fn org_identity_r2_login_prior_survives_same_uuid_legacy_upgrade() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r2-prior", 100);
        let id = make_legacy(base, &old);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        upgrade_verified_legacy_identity(base, id, &verified_for(&old, context(20))).unwrap();
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert!(login_prior_matches(base, slot(1), &prior, &pf).unwrap());
    }

    #[test]
    fn org_identity_r3_malformed_legacy_email_has_working_verified_login_remedy() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r3-malformed-email", 4_102_444_800_000);
            let old_id = make_legacy(base, &old);
            let metadata_path = identity_store::identity_json_path_for(base, old_id);
            let canonical_path = identity_store::credentials_path_for(base, old_id);
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
            metadata["email"] = serde_json::json!("unparsable-legacy-email");
            std::fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
            let metadata_before = std::fs::read(&metadata_path).unwrap();
            let canonical_before = std::fs::read(&canonical_path).unwrap();
            let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
            assert_eq!(
                capture_anthropic_binding(base, slot(1)).err(),
                Some(IdentityError::LegacyEmailUnparseable)
            );
            assert_eq!(
                legacy_verification_source(base, old_id).err(),
                Some(IdentityError::LegacyEmailUnparseable)
            );
            assert!(IdentityError::LegacyEmailUnparseable
                .to_string()
                .contains("csq login N"));
            assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata_before);
            assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical_before);
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
            // The login prior grants no legacy email authority: a new exact
            // verified grant can replace this slot without merging the old UUID.
            let incoming = credential("r3-email-remedy", 4_102_444_800_001);
            let committed = commit(base, 1, &incoming, context(20));
            assert_ne!(committed.identity(), old_id);
            assert_eq!(
                committed.context(),
                &StoredAnthropicContext::Known(context(20))
            );
            assert_eq!(
                canonical_version(base, committed.identity()),
                CredentialVersion::for_credentials(incoming.anthropic().unwrap()).unwrap()
            );
            assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata_before);
            assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical_before);
        });
    }

    #[cfg(unix)]
    #[test]
    fn org_identity_r3d_profiles_capture_and_commit_keep_secure_reader_remedies() {
        use std::os::unix::fs::PermissionsExt;
        for hard_link in [false, true] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r3d-profiles-old", 4_102_444_800_000);
            make_legacy(base, &old);
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let path = profiles::profiles_path(base);
            if hard_link {
                std::fs::hard_link(&path, base.join("profiles-extra-link.json")).unwrap();
            } else {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            let expected = if hard_link {
                IdentityError::ProfilesMultipleLinks
            } else {
                IdentityError::ProfilesUnsafePermissions
            };
            let before = std::fs::read(&path).unwrap();
            assert_eq!(capture_login_prior(base, slot(1)).err(), Some(expected));
            let incoming = credential("r3d-profiles-incoming", 4_102_444_800_001);
            assert_eq!(
                commit_anthropic_login_with(
                    base,
                    slot(1),
                    &incoming,
                    &transport(&incoming, context(21)),
                    None,
                    prior
                )
                .err(),
                Some(expected)
            );
            let text = crate::accounts::login::LoginCommitOutcome::describe_error(&expected);
            assert!(text.contains("profiles.json"), "{text}");
            assert!(text.contains("trusted backup"), "{text}");
            assert!(!text.contains("csq logout"), "{text}");
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!identity_store::store_version_path(base).exists());
        }
    }

    #[test]
    fn org_identity_r3d_profiles_refusal_mapping_keeps_retry_and_sanitizes_details() {
        for (reason, expected) in [
            (
                "anthropic_identity_snapshot_changed: retry the operation",
                IdentityError::ProfilesSnapshotChanged,
            ),
            (
                "profiles_permissions_refused: fixed remedy",
                IdentityError::ProfilesUnsafePermissions,
            ),
            (
                "profiles_links_refused: fixed remedy",
                IdentityError::ProfilesMultipleLinks,
            ),
            (
                "untrusted fake parse detail SECRET-MARKER",
                IdentityError::ProfilesReadRefused,
            ),
        ] {
            let error = profiles_read_error(crate::error::ConfigError::InvalidJson {
                path: PathBuf::from("/fake/PRIVATE-MARKER"),
                reason: reason.into(),
            });
            assert_eq!(error, expected);
            let text = crate::accounts::login::LoginCommitOutcome::describe_error(&error);
            assert!(!text.contains("SECRET-MARKER"));
            assert!(!text.contains("PRIVATE-MARKER"));
            if error == IdentityError::ProfilesSnapshotChanged {
                assert!(text.contains("retry"), "{text}");
            }
        }
    }

    #[test]
    fn org_identity_r3d_unbound_legacy_upgrade_refuses_before_mutation() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r3d-unbound-upgrade", 4_102_444_800_000);
        let id = make_legacy(base, &old);
        let verified = verified_for(&old, context(20));
        let path = profiles::profiles_path(base);
        let mut pf = profiles::load(&path).unwrap();
        pf.by_slot.remove("1");
        assert!(pf.by_email.values().any(|bound| *bound == id));
        profiles::save(&path, &pf).unwrap();
        assert!(!identity_store::is_identity_removed(base, id));
        let metadata_path = identity_store::identity_json_path_for(base, id);
        let canonical_path = identity_store::credentials_path_for(base, id);
        let before = [
            std::fs::read(&path).unwrap(),
            std::fs::read(&metadata_path).unwrap(),
            std::fs::read(&canonical_path).unwrap(),
        ];
        #[cfg(unix)]
        let directory_mode = {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(base.join("identities"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755);
            mode
        };
        let metadata_writes = std::cell::Cell::new(0);
        assert_eq!(
            upgrade_verified_legacy_identity_with(base, id, &verified, |_, _| {
                metadata_writes.set(metadata_writes.get() + 1);
                Ok(())
            }),
            Err(IdentityError::BindingChanged)
        );
        assert_eq!(metadata_writes.get(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), before[0]);
        assert_eq!(std::fs::read(&metadata_path).unwrap(), before[1]);
        assert_eq!(std::fs::read(&canonical_path).unwrap(), before[2]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(base.join("identities"))
                    .unwrap()
                    .permissions()
                    .mode(),
                directory_mode
            );
        }
        // Restoring the real slot reference permits the same authenticated UUID
        // to upgrade; the retained email alias was never sufficient on its own.
        pf.by_slot.insert("1".into(), id);
        profiles::save(&path, &pf).unwrap();
        upgrade_verified_legacy_identity(base, id, &verified).unwrap();
        assert_eq!(
            read_stored_anthropic_context(base, id).unwrap(),
            StoredAnthropicContext::Known(context(20))
        );
        let after = profiles::load(&path).unwrap();
        assert_eq!(after.by_slot.get("1"), Some(&id));
        assert_eq!(after.anthropic_contexts.len(), 1);
        assert_eq!(after.anthropic_contexts[0].identity_uuid, id);
        assert_eq!(std::fs::read(&canonical_path).unwrap(), before[2]);
    }

    #[test]
    fn org_identity_r3_upgrade_marker_cannot_reindex_unbound_identity() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r3-unbound-repair", 4_102_444_800_000);
        let id = make_legacy(base, &old);
        upgrade_verified_legacy_identity(base, id, &verified_for(&old, context(20))).unwrap();
        let metadata_path = identity_store::identity_json_path_for(base, id);
        let metadata_before = std::fs::read(&metadata_path).unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&metadata_before).unwrap();
        assert!(metadata.get("legacy_upgrade_source_version").is_some());
        let path = profiles::profiles_path(base);
        let mut pf = profiles::load(&path).unwrap();
        pf.anthropic_contexts
            .retain(|entry| entry.identity_uuid != id);
        pf.by_slot.remove("1");
        profiles::save(&path, &pf).unwrap();
        let profiles_before = std::fs::read(&path).unwrap();
        let canonical_path = identity_store::credentials_path_for(base, id);
        let canonical_before = std::fs::read(&canonical_path).unwrap();
        assert_eq!(
            repair_legacy_context_index(base, id),
            Err(IdentityError::BindingChanged)
        );
        assert_eq!(std::fs::read(&path).unwrap(), profiles_before);
        assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata_before);
        assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical_before);
        // A real interrupted upgrade still bound to the same UUID remains
        // repairable: the retained marker alone is not sufficient authority.
        pf.by_slot.insert("1".into(), id);
        profiles::save(&path, &pf).unwrap();
        assert_eq!(
            repair_legacy_context_index(base, id),
            Ok(LegacyRepair::Repaired)
        );
        let repaired = profiles::load(&path).unwrap();
        assert_eq!(repaired.by_slot.get("1"), Some(&id));
        assert_eq!(repaired.anthropic_contexts.len(), 1);
        assert_eq!(repaired.anthropic_contexts[0].identity_uuid, id);
        assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata_before);
        assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical_before);
    }

    #[test]
    fn org_identity_r3_missing_bound_metadata_logout_then_login_recovers() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r3-missing-metadata", 4_102_444_800_000);
            let old_id = make_legacy(base, &old);
            // Real slot artifacts make the advertised public logout path
            // configured; there is no terminal or live keychain fixture.
            let config = base.join("config-1");
            std::fs::create_dir_all(&config).unwrap();
            file::save(&config.join(".credentials.json"), &old).unwrap();
            std::fs::write(config.join("settings.json"), b"{}").unwrap();
            crate::accounts::markers::write_csq_account(&config, old_id).unwrap();
            file::save(&base.join("credentials/1.json"), &old).unwrap();
            std::fs::remove_file(identity_store::identity_json_path_for(base, old_id)).unwrap();
            let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
            let canonical_path = identity_store::credentials_path_for(base, old_id);
            let canonical_before = std::fs::read(&canonical_path).unwrap();
            let expected = IdentityError::BoundIdentityMetadataMissing { account: 1 };
            assert_eq!(capture_login_prior(base, slot(1)).err(), Some(expected));
            assert_eq!(
                capture_anthropic_binding(base, slot(1)).err(),
                Some(expected)
            );
            assert!(expected.to_string().contains("csq logout 1"));
            assert!(expected.to_string().contains("csq login 1"));
            assert_eq!(
                std::fs::read(profiles::profiles_path(base)).unwrap(),
                profiles_before
            );
            assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical_before);
            crate::accounts::logout::logout_account(base, slot(1)).unwrap();
            assert!(identity_store::is_identity_removed(base, old_id));
            assert!(!profiles::load(&profiles::profiles_path(base))
                .unwrap()
                .by_slot
                .contains_key("1"));
            let incoming = credential("r3-after-logout", 4_102_444_800_001);
            let committed = commit(base, 1, &incoming, context(20));
            assert_ne!(committed.identity(), old_id);
            assert_eq!(
                committed.context(),
                &StoredAnthropicContext::Known(context(20))
            );
            assert_eq!(
                profiles::resolve_slot_to_uuid(base, 1),
                Some(committed.identity())
            );
            assert_eq!(
                canonical_version(base, committed.identity()),
                CredentialVersion::for_credentials(incoming.anthropic().unwrap()).unwrap()
            );
        });
    }

    fn browser_wait_upgrade_commit_case(incoming_org: u128) {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            // Far-future grants keep the real credential policy valid past 2100.
            let old = credential("r3-browser-old", 4_102_444_800_000);
            let old_id = make_legacy(base, &old);
            assert!(profiles::load(&profiles::profiles_path(base))
                .unwrap()
                .anthropic_contexts
                .is_empty());
            assert_eq!(
                read_stored_anthropic_context(base, old_id).unwrap(),
                StoredAnthropicContext::LegacyUnknown
            );
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let generation = prior.generation;
            // The actual daemon upgrade occurs after browser launch captured
            // its prior and before the incoming grant is verified/committed.
            upgrade_verified_legacy_identity(base, old_id, &verified_for(&old, context(20)))
                .unwrap();
            let old_metadata = identity_store::identity_json_path_for(base, old_id);
            let old_canonical = identity_store::credentials_path_for(base, old_id);
            let metadata_before = std::fs::read(&old_metadata).unwrap();
            let canonical_before = std::fs::read(&old_canonical).unwrap();
            let by_email_before = profiles::load(&profiles::profiles_path(base))
                .unwrap()
                .by_email;
            let incoming = credential("r3-browser-incoming", 4_102_444_800_001);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = calls.clone();
            let profile = transport(&incoming, context(incoming_org));
            let http: HttpGetFn = Arc::new(move |url, access, headers| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                profile(url, access, headers)
            });
            let committed =
                commit_anthropic_login_with(base, slot(1), &incoming, &http, None, prior)
                    .expect("authenticated same-UUID upgrade is not a browser login rebind");
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                committed.context(),
                &StoredAnthropicContext::Known(context(incoming_org))
            );
            assert_eq!(
                canonical_version(base, committed.identity()),
                CredentialVersion::for_credentials(incoming.anthropic().unwrap()).unwrap()
            );
            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert_eq!(pf.by_slot.get("1"), Some(&committed.identity()));
            assert_eq!(std::fs::read(&old_metadata).unwrap(), metadata_before);
            if incoming_org == 20 {
                assert_eq!(committed.identity(), old_id);
                assert_eq!(committed.binding().generation(), generation);
                assert_eq!(pf.anthropic_contexts.len(), 1);
                // No rebind: the publication still does not touch by_email.
                assert_eq!(pf.by_email, by_email_before);
            } else {
                assert_ne!(committed.identity(), old_id);
                assert_eq!(committed.binding().generation(), generation + 1);
                assert_eq!(pf.anthropic_contexts.len(), 2);
                // Rebinding slot 1 retires old_id, so the publication PURGES
                // old_id's stale by_email entry (owner-observed defect:
                // a retired uuid must not resolve from an email). It still
                // never ADDS an entry — by_email is not the ownership index.
                assert_eq!(
                    pf.by_email.get("same@test.invalid"),
                    None,
                    "the displaced identity's email entry must be purged, got {:?}",
                    pf.by_email.get("same@test.invalid")
                );
                assert!(
                    pf.by_email.values().all(|id| *id != old_id),
                    "no by_email entry may still point at the retired uuid"
                );
                assert_eq!(std::fs::read(&old_canonical).unwrap(), canonical_before);
                assert_eq!(
                    read_stored_anthropic_context(base, old_id).unwrap(),
                    StoredAnthropicContext::Known(context(20))
                );
            }
            let lock = ProfilesFileLock::acquire(base).unwrap();
            assert!(
                crate::credentials::token_history::read_owner_verified_v2_locked(
                    &lock,
                    base,
                    committed.binding()
                )
                .contains(
                    &crate::credentials::token_history::fingerprint_from_credential_file(
                        &incoming,
                    )
                    .unwrap()
                )
            );
        });
    }

    #[test]
    fn org_identity_r3_browser_wait_legacy_upgrade_same_org_commits_original_uuid() {
        browser_wait_upgrade_commit_case(20);
    }

    #[test]
    fn org_identity_r3_browser_wait_legacy_upgrade_other_org_commits_without_orphan() {
        browser_wait_upgrade_commit_case(21);
    }

    /// T3 (coordinator 0113baed): the production Anthropic publication is a
    /// rebind writer too, so a re-login that retires an ORG-CONTEXTED
    /// identity MUST purge that identity's stale `by_email` entry in the
    /// same publication — otherwise the email keeps resolving to the
    /// RETIRED uuid (a wrong claim on disk; email→identity resolution in
    /// production reads `anthropic_contexts`, not this index — see
    /// `record_binding_displacement`'s consumer census). That is the live
    /// shape the owner observed
    /// (a91640e6 was a Terrene-org sign-in), so the fixture is upgraded to
    /// the org-contexted shape before the rebind; a bare legacy prior is
    /// contract-protected and covered by
    /// `org_identity_regression_legacy_index_metadata_and_tokens_preserved`.
    #[test]
    fn org_identity_rebind_via_production_publication_purges_displaced_email_entry() {
        crate::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r3-purge-old", 4_102_444_800_000);
            let old_id = make_legacy(base, &old);
            assert_eq!(
                profiles::load(&profiles::profiles_path(base))
                    .unwrap()
                    .by_email
                    .get("same@test.invalid")
                    .copied(),
                Some(old_id),
                "precondition: the fixture seeds by_email → old_id"
            );
            // Org-contexted prior: exactly what a real org sign-in publishes,
            // and the discriminator the purge keys on.
            upgrade_verified_legacy_identity(base, old_id, &verified_for(&old, context(20)))
                .unwrap();
            assert!(
                profiles::load(&profiles::profiles_path(base))
                    .unwrap()
                    .anthropic_contexts
                    .iter()
                    .any(|entry| entry.identity_uuid == old_id),
                "precondition: old_id carries an org context after the upgrade"
            );

            // A different org uuid resolves to a different identity — a rebind.
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let generation = prior.generation;
            let incoming = credential("r3-purge-incoming", 4_102_444_800_001);
            let committed = commit_anthropic_login_with(
                base,
                slot(1),
                &incoming,
                &transport(&incoming, context(21)),
                None,
                prior,
            )
            .unwrap();
            assert_ne!(committed.identity(), old_id, "expected a rebind");
            assert_eq!(
                committed.binding().generation(),
                generation + 1,
                "a rebind advances the binding generation"
            );

            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert_eq!(pf.by_slot.get("1"), Some(&committed.identity()));
            assert_eq!(pf.slot_binding_history.get("1"), Some(&vec![old_id]));
            assert!(
                pf.by_email.get("same@test.invalid") != Some(&old_id),
                "the retired uuid must no longer resolve from its email"
            );
            assert!(
                pf.by_email.values().all(|id| *id != old_id),
                "no by_email entry may survive pointing at the retired uuid, \
                 got {:?}",
                pf.by_email
            );
        });
    }

    #[test]
    fn org_identity_r3_browser_wait_unauthorized_metadata_move_refuses_before_writes() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r3-metadata-old", 4_102_444_800_000);
        let old_id = make_legacy(base, &old);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let metadata_path = identity_store::identity_json_path_for(base, old_id);
        let original_metadata = std::fs::read(&metadata_path).unwrap();
        let mut metadata: serde_json::Value = serde_json::from_slice(&original_metadata).unwrap();
        metadata["unapproved_browser_change"] = serde_json::json!(true);
        let mutated_metadata = serde_json::to_vec(&metadata).unwrap();
        let profiles_before = std::fs::read(profiles::profiles_path(base)).unwrap();
        let canonical_path = identity_store::credentials_path_for(base, old_id);
        let canonical_before = std::fs::read(&canonical_path).unwrap();
        let identity_count = std::fs::read_dir(base.join("identities")).unwrap().count();
        // Earlier login_prior_matches and the pre-write capture must pass.
        // Mutate only between that capture and the second metadata read.
        let hook_count = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_count = hook_count.clone();
        let hook_path = metadata_path.clone();
        let hook_bytes = mutated_metadata.clone();
        LOGIN_PREWRITE_METADATA_HOOK.with(|hook| {
            assert!(hook
                .borrow_mut()
                .replace(Box::new(move || {
                    assert_eq!(std::fs::read(&hook_path).unwrap(), original_metadata);
                    observed_count.set(observed_count.get() + 1);
                    std::fs::write(&hook_path, &hook_bytes).unwrap();
                }))
                .is_none());
        });
        struct ResetHook;
        impl Drop for ResetHook {
            fn drop(&mut self) {
                LOGIN_PREWRITE_METADATA_HOOK.with(|hook| {
                    hook.borrow_mut().take();
                });
            }
        }
        let _reset_hook = ResetHook;
        let incoming = credential("r3-metadata-incoming", 4_102_444_800_001);
        let result = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(21)),
            None,
            prior,
        )
        .err();
        assert_eq!(
            hook_count.get(),
            1,
            "fixture must reach the new pre-write check"
        );
        assert_eq!(result, Some(IdentityError::BindingChanged));
        // Keep the external winner, without rolling it back or publishing the
        // incoming grant in any existing or new UUID.
        assert_eq!(std::fs::read(&metadata_path).unwrap(), mutated_metadata);
        assert_eq!(std::fs::read(&canonical_path).unwrap(), canonical_before);
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            profiles_before
        );
        assert_eq!(
            std::fs::read_dir(base.join("identities")).unwrap().count(),
            identity_count
        );
        assert!(!identity_store::store_version_path(base).exists());
    }

    // ── r4 fixes (orgident): rotation lag, unreadable sibling, login writer, fail-closed ──
    #[derive(Debug, Default)]
    struct Warn {
        level: Option<tracing::Level>,
        fields: std::collections::BTreeMap<String, String>,
    }
    impl tracing::field::Visit for Warn {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields.insert(field.name().into(), value.into());
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            self.fields
                .insert(field.name().into(), format!("{value:?}"));
        }
    }
    struct WarnCapture(Arc<std::sync::Mutex<Vec<Warn>>>);
    impl tracing::Subscriber for WarnCapture {
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
            let mut captured = Warn {
                level: Some(*event.metadata().level()),
                ..Warn::default()
            };
            event.record(&mut captured);
            self.0.lock().unwrap().push(captured);
        }
    }
    fn capture_warnings<T>(run: impl FnOnce() -> T) -> (T, Vec<Warn>) {
        let _guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(WarnCapture(events.clone()), || {
            tracing::callsite::rebuild_interest_cache();
            run()
        });
        let captured = std::mem::take(&mut *events.lock().unwrap());
        (out, captured)
    }
    /// Tests that reach the sibling-unreadable warning without capturing it hold the shared
    /// tracing lock too: their first hit could cache the callsite as disabled mid-capture.
    fn tracing_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
    fn held_with(tag: &str) -> CredentialFile {
        credential(tag, 150)
    }
    /// r6 sec L3: a successful upgrade must have recorded the identity's OWN verified
    /// context, in its metadata and in the index row, never a sibling's.
    fn assert_upgrade_recorded_own_context(
        base: &Path,
        id: IdentityId,
        own: &VerifiedAnthropicContext,
        label: &str,
    ) {
        assert_eq!(
            read_stored_anthropic_context(base, id),
            Ok(StoredAnthropicContext::Known(own.context().clone())),
            "{label}: metadata records the identity's own verified context"
        );
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        let rows: Vec<_> = pf
            .anthropic_contexts
            .iter()
            .filter(|row| row.identity_uuid == id)
            .collect();
        assert_eq!(rows.len(), 1, "{label}: exactly one index row");
        assert_eq!(
            rows[0].context().unwrap(),
            own.context().clone(),
            "{label}: the row carries the identity's own context"
        );
    }
    /// SEC-H1: exact token equality misses a CC-rotated pair. Y's saved file holds the
    /// OLD pair P, the candidate is the rotated P'; Y shares X's (normalised) legacy email.
    /// Adopting P' for X would later refuse Y's own live P', stranding the true owner. Same
    /// normalised email on another slot-bound legacy identity is ambiguous authority.
    #[test]
    fn org_identity_r4_rotation_lag_same_email_legacy_sibling_refuses_mint_and_permits_but_upgrade_resolves(
    ) {
        for (label, sibling_email, refuses) in [
            ("same email", "same@test.invalid", true),
            (
                "same email, other case and padding",
                "  SAME@Test.Invalid ",
                true,
            ),
            ("different email", "other@test.invalid", false),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r4-own", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r4-rotated", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            let early =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .unwrap();
            // Y holds the OLD pair P, never the rotated candidate: no token matches.
            let _y = add_legacy_sibling_with_email(
                base,
                "2",
                sibling_email,
                &held_with("r4-old-pair-of-y"),
            );
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            let permitted = early.permits(base, &captured, candidate.anthropic().unwrap());
            let upgraded = upgrade_verified_legacy_identity(base, id, &own);
            if refuses {
                assert_eq!(
                    minted.unwrap_err(),
                    IdentityError::SharedLegacyIdentity,
                    "{label}: mint"
                );
                assert!(!permitted, "{label}: permits");
                // r5 F4: the metadata-only upgrade adopts no candidate, so it is exempt.
                assert_eq!(upgraded, Ok(()), "{label}: upgrade is exempt");
            } else {
                assert!(minted.is_ok(), "{label}: must not refuse");
                assert!(permitted, "{label}: must permit");
                assert_eq!(upgraded, Ok(()), "{label}: must not refuse");
            }
            assert_upgrade_recorded_own_context(base, id, &own, label);
        }
    }
    /// r6 sec L3: when the F4 exemption is USED (a same-email legacy sibling stands and the
    /// upgrade proceeds anyway) a fixed-vocabulary warning names BOTH slots, so the operator
    /// can confirm which organization each slot should hold. A different-email sibling is
    /// no exemption and says nothing.
    #[test]
    fn org_identity_r6_f4_exemption_warns_naming_both_slots() {
        for (sibling_email, expect_warning) in [
            ("same@test.invalid", true),
            ("  SAME@Test.Invalid ", true),
            ("other@test.invalid", false),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r6-own", 100);
            let id = make_legacy(base, &old);
            let own = verified_for(&old, context(20));
            let _y = add_legacy_sibling_with_email(base, "2", sibling_email, &held_with("r6-y"));
            let (upgraded, warnings) =
                capture_warnings(|| upgrade_verified_legacy_identity(base, id, &own));
            assert_eq!(upgraded, Ok(()), "{sibling_email}");
            let hits: Vec<_> = warnings
                .iter()
                .filter(|w| {
                    w.fields.get("error_kind").map(String::as_str)
                        == Some("anthropic_legacy_upgrade_same_email_exemption")
                })
                .collect();
            if expect_warning {
                assert_eq!(hits.len(), 1, "{sibling_email}: {warnings:?}");
                assert_eq!(hits[0].level, Some(tracing::Level::WARN));
                assert_eq!(hits[0].fields.get("slot").unwrap(), "1");
                assert_eq!(hits[0].fields.get("sibling_slot").unwrap(), "2");
            } else {
                assert!(hits.is_empty(), "{sibling_email}: {warnings:?}");
            }
            for w in &warnings {
                let text = format!("{w:?}");
                assert!(
                    !text.contains("same@test.invalid") && !text.contains("r6-"),
                    "{text}"
                );
            }
        }
    }
    /// r7 item 6 (corr L-6): the exemption warning claims the upgrade records its own
    /// organization, so it is emitted only once the upgrade has committed.
    #[test]
    fn org_identity_r7_f4_exemption_warning_waits_for_the_upgrade_to_commit() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r7-own", 100);
        let id = make_legacy(base, &old);
        // Verified for a DIFFERENT credential version than the canonical: the upgrade
        // fails after the ambiguity check, with a same-email legacy sibling standing.
        let other = credential("r7-changed", 100);
        let own = verified_for(&other, context(20));
        let _y = add_legacy_sibling_with_email(base, "2", "same@test.invalid", &held_with("r7-y"));
        let (upgraded, warnings) =
            capture_warnings(|| upgrade_verified_legacy_identity(base, id, &own));
        assert!(upgraded.is_err(), "the upgrade must fail for this fixture");
        let hits = warnings
            .iter()
            .filter(|w| {
                w.fields.get("error_kind").map(String::as_str)
                    == Some("anthropic_legacy_upgrade_same_email_exemption")
            })
            .count();
        assert_eq!(hits, 0, "no commit, no claim: {warnings:?}");
    }
    /// A sibling whose recorded legacy email cannot be read cannot be ruled out: refuse.
    #[test]
    fn org_identity_r4_unparseable_legacy_sibling_email_refuses_adoption() {
        let _tracing = tracing_lock();
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r4-own-email", 100);
        make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r4-cand-email", 200);
        let cand = verified_for(&candidate, context(20));
        let own = verified_for(&old, context(20));
        let _y = add_legacy_sibling_with_email(base, "2", "not-an-email", &held_with("r4-y-email"));
        let minted =
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
        assert_eq!(minted.unwrap_err(), IdentityError::SharedLegacyIdentity);
    }
    /// The sibling-unreadable error is its own variant and tells the operator nothing
    /// about logging out the slot being adopted.
    #[test]
    fn org_identity_r4_sibling_unreadable_error_never_suggests_logout() {
        for error in [
            IdentityError::SiblingCustodyUnreadable {
                sibling: SlotKey::from_key("2"),
            },
            IdentityError::LoginCredentialHeldElsewhere {
                holder: SlotKey::from_key("2"),
            },
        ] {
            let text = error.to_string();
            assert!(!text.contains("logout"), "{text}");
        }
        assert!(IdentityError::SiblingCustodyUnreadable {
            sibling: SlotKey::from_key("2")
        }
        .to_string()
        .contains("sibling_custody_unreadable"));
    }
    #[cfg(unix)]
    fn damage_sibling_canonical(base: &Path, sibling: IdentityId, kind: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = identity_store::credentials_path_for(base, sibling);
        match kind {
            "garbage" => std::fs::write(&path, b"{ not json").unwrap(),
            // Valid JSON that parses as NO credential variant: the parseable-but-wrong-shape
            // case (distinct from "garbage" = invalid JSON). The comparison walk must refuse
            // it, never skip it — skipping is the fail-open the walk's Err arm exists to stop.
            "empty_object" => std::fs::write(&path, b"{}").unwrap(),
            "0644" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "0666" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap()
            }
            "symlink" => {
                let real = path.with_extension("real");
                std::fs::rename(&path, &real).unwrap();
                std::os::unix::fs::symlink(&real, &path).unwrap();
            }
            "nlink" => std::fs::hard_link(&path, path.with_extension("alias")).unwrap(),
            "oversize" => std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap(),
            _ => unreachable!(),
        }
    }
    /// CORR-M3 / SEC-H2 at every entry point: an unreadable sibling canonical refuses the
    /// mint, `permits` and the Known-context writer (fail closed), with a distinct error
    /// that is not a metadata fault of the slot being adopted. `0644` is the one ruled
    /// exception: the sibling is read for COMPARISON only, so a loose private-mode bit does
    /// not block adoption when the pairs differ (and still refuses when the pair is held).
    #[cfg(unix)]
    #[test]
    fn org_identity_r4_unreadable_sibling_canonical_refuses_mint_permits_and_known_writer() {
        let _tracing = tracing_lock();
        // (kind, sibling_holds_candidate_pair, expected)
        // expected: None = adoption proceeds; Some(err) = mint refuses with err.
        for (kind, holds_pair, expected) in [
            (
                "garbage",
                false,
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            (
                "empty_object",
                false,
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            (
                "symlink",
                false,
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            (
                "nlink",
                false,
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            (
                "oversize",
                false,
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            // Group/other-WRITABLE stays refused: only the private-mode test was dropped.
            (
                "0666",
                false,
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            // Comparison-readable: different pair is not held; the same pair still is.
            ("0644", false, None),
            ("0644", true, Some(IdentityError::SharedLegacyIdentity)),
        ] {
            let label = format!("{kind}/holds_pair={holds_pair}");
            // Legacy witness: mint + permits.
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r4u-own", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r4u-cand", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            let early =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                    .unwrap();
            let mut held = credential("r4u-sibling", 150);
            if holds_pair {
                held.expect_anthropic_mut().claude_ai_oauth.refresh_token =
                    RefreshToken::new("fake-refresh-r4u-cand".to_owned());
            }
            let sibling = add_legacy_sibling(base, "2", &held);
            damage_sibling_canonical(base, sibling, kind);
            let before = std::fs::read(identity_store::credentials_path_for(base, id)).unwrap();
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            let permitted = early.permits(base, &captured, candidate.anthropic().unwrap());
            match expected {
                Some(error) => {
                    assert_eq!(minted.unwrap_err(), error, "{label}: mint");
                    assert!(!permitted, "{label}: permits");
                    assert!(
                        file::save_anthropic_canonical_guarded(
                            base,
                            &captured,
                            candidate.anthropic().unwrap(),
                            AnthropicWriteWitness::LegacyOwnUuid(&early),
                            None
                        )
                        .is_err(),
                        "{label}: legacy writer"
                    );
                    assert_eq!(
                        std::fs::read(identity_store::credentials_path_for(base, id)).unwrap(),
                        before,
                        "{label}: canonical untouched"
                    );
                }
                None => {
                    assert!(minted.is_ok(), "{label}: mint must proceed");
                    assert!(permitted, "{label}: permits must proceed");
                }
            }
            // Known witness: the same sibling shapes at the Known-context writer.
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let target = commit(base, 1, &credential("r4u-known", 100), context(20)).identity();
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r4u-cand", 200);
            let proof = verified_for(&candidate, context(20));
            let sibling = add_legacy_sibling(base, "2", &held);
            damage_sibling_canonical(base, sibling, kind);
            let version_before = canonical_version(base, target);
            let outcome = file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            );
            if expected.is_some() {
                assert!(outcome.is_err(), "{label}: known writer must refuse");
                assert_eq!(canonical_version(base, target), version_before, "{label}");
            } else {
                assert_eq!(outcome.unwrap(), GuardedWriteOutcome::Written, "{label}");
            }
        }
    }
    /// A sibling canonical that cannot even be statted (here: its identity directory was
    /// replaced by a regular file, so the lookup fails with something other than NotFound)
    /// is not "absent": the Known-context writer refuses.
    #[cfg(unix)]
    #[test]
    fn org_identity_r4_known_writer_refuses_when_sibling_canonical_cannot_be_statted() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let target = commit(base, 1, &credential("r4s-known", 100), context(20)).identity();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r4s-cand", 200);
        let proof = verified_for(&candidate, context(20));
        let sibling = add_legacy_sibling(base, "2", &held_with("r4s-sib"));
        let sibling_dir = identity_store::credentials_path_for(base, sibling)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::remove_dir_all(&sibling_dir).unwrap();
        std::fs::write(&sibling_dir, b"not a directory").unwrap();
        let version_before = canonical_version(base, target);
        let (outcome, events) = capture_warnings(|| {
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            )
        });
        assert!(outcome.is_err());
        assert_eq!(canonical_version(base, target), version_before);
        assert!(events
            .iter()
            .any(|e| e.fields.get("error_kind").map(String::as_str)
                == Some("anthropic_sibling_canonical_unreadable")));
    }
    /// An unknown-provider sibling whose credentials.json has the Codex shape holds no
    /// Anthropic pair: it must NOT refuse (any of mint, permits, Known writer).
    #[test]
    fn org_identity_r4_unknown_provider_codex_shape_sibling_does_not_refuse() {
        let codex = br#"{"tokens":{"access_token":"fake-access-r4c-cand","refresh_token":"fake-refresh-r4c-cand"}}"#;
        let plant = |base: &Path| {
            let sibling = IdentityId::new_v4();
            let path = identity_store::credentials_path_for(base, sibling);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, codex).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let pf_path = profiles::profiles_path(base);
            let mut pf = profiles::load(&pf_path).unwrap();
            pf.by_slot.insert("2".into(), sibling);
            profiles::save(&pf_path, &pf).unwrap();
            assert_eq!(identity_store::read_identity_provider(base, sibling), None);
        };
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r4c-own", 100);
        make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r4c-cand", 200);
        let cand = verified_for(&candidate, context(20));
        let own = verified_for(&old, context(20));
        plant(base);
        let proof =
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
                .expect("a Codex-shaped sibling must not refuse the mint");
        assert!(proof.permits(base, &captured, candidate.anthropic().unwrap()));
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        commit(base, 1, &credential("r4c-known", 100), context(20));
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let proof = verified_for(&candidate, context(20));
        plant(base);
        assert_eq!(
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            )
            .unwrap(),
            GuardedWriteOutcome::Written
        );
    }
    /// SEC-L1: a sibling whose identity.json WRONGLY says `codex` while its credentials.json
    /// holds the Anthropic pair is still compared. The provider metadata is not authority
    /// for skipping a credential file.
    #[test]
    fn org_identity_r4_wrong_provider_metadata_does_not_hide_a_held_pair() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r4p-own", 100);
        make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r4p-cand", 200);
        let cand = verified_for(&candidate, context(20));
        let own = verified_for(&old, context(20));
        let mut held = credential("r4p-sibling", 150);
        held.expect_anthropic_mut().claude_ai_oauth.refresh_token =
            RefreshToken::new("fake-refresh-r4p-cand".to_owned());
        let sibling = add_legacy_sibling(base, "2", &held);
        let metadata = identity_store::identity_json_path_for(base, sibling);
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
        json["provider"] = serde_json::json!("codex");
        std::fs::write(&metadata, serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(
            identity_store::read_identity_provider(base, sibling).as_deref(),
            Some("codex")
        );
        let minted =
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
        assert_eq!(minted.unwrap_err(), IdentityError::SharedLegacyIdentity);
    }
    /// SEC-H2: the unreadable-sibling refusal emits a fixed-vocabulary warning naming the
    /// SIBLING slot on every arm — mint, the Known writer, and the known_unindexed
    /// metadata scan — and never a token or a logout remedy.
    #[test]
    fn org_identity_r4_unreadable_sibling_warns_with_sibling_slot_on_every_arm() {
        let assert_warns = |events: &[Warn], kind: &str, label: &str| {
            let hit: Vec<_> = events
                .iter()
                .filter(|e| e.fields.get("error_kind").map(String::as_str) == Some(kind))
                .collect();
            assert_eq!(
                hit.len(),
                1,
                "{label}: exactly one `{kind}` warning; captured {events:?}"
            );
            assert_eq!(hit[0].level, Some(tracing::Level::WARN), "{label}");
            assert_eq!(
                hit[0].fields.get("sibling_slot").map(String::as_str),
                Some("2"),
                "{label}: names the sibling slot"
            );
            let text = format!("{events:?}");
            assert!(!text.contains("fake-"), "{label}: no token bytes");
            assert!(!text.contains("logout"), "{label}: no logout remedy");
        };
        // Mint arm: sibling canonical is garbage.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r4w-own", 100);
        make_legacy(base, &old);
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r4w-cand", 200);
        let cand = verified_for(&candidate, context(20));
        let own = verified_for(&old, context(20));
        let sibling = add_legacy_sibling(base, "2", &held_with("r4w-sib"));
        std::fs::write(identity_store::credentials_path_for(base, sibling), b"{ x").unwrap();
        let (minted, events) = capture_warnings(|| {
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
        });
        assert_eq!(
            minted.unwrap_err(),
            IdentityError::SiblingCustodyUnreadable {
                sibling: SlotKey::from_key("2")
            }
        );
        assert_warns(&events, "anthropic_sibling_canonical_unreadable", "mint");
        // Known writer arm.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        commit(base, 1, &credential("r4w-known", 100), context(20));
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let proof = verified_for(&candidate, context(20));
        let sibling = add_legacy_sibling(base, "2", &held_with("r4w-sib2"));
        std::fs::write(identity_store::credentials_path_for(base, sibling), b"{ x").unwrap();
        let (outcome, events) = capture_warnings(|| {
            file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            )
        });
        assert!(outcome.is_err());
        assert_warns(&events, "anthropic_sibling_canonical_unreadable", "known");
        // known_unindexed arm: the sibling's identity.json is garbage.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old = credential("r4w-own3", 100);
        make_legacy(base, &old);
        let own = verified_for(&old, context(20));
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let sibling = add_legacy_sibling(base, "2", &held_with("r4w-sib3"));
        std::fs::write(
            identity_store::identity_json_path_for(base, sibling),
            b"{ not json",
        )
        .unwrap();
        let (minted, events) = capture_warnings(|| {
            legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap())
        });
        assert_eq!(minted.unwrap_err(), IdentityError::SharedLegacyIdentity);
        assert_warns(
            &events,
            "anthropic_sibling_metadata_unreadable",
            "unindexed",
        );
    }
    /// SEC-M1 / CORR-M1: the login writer, under the profiles lock, refuses a pair another
    /// identity's saved credential already holds, with a login-specific error, and an
    /// unreadable sibling refuses distinctly. A fresh pair publishes.
    #[test]
    fn org_identity_r4_login_writer_refuses_pair_held_by_another_identity() {
        let _tracing = tracing_lock();
        for (label, mode, expected) in [
            ("fresh pair", "fresh", None),
            (
                "pair held by a legacy sibling",
                "held",
                Some(IdentityError::LoginCredentialHeldElsewhere {
                    holder: SlotKey::from_key("2"),
                }),
            ),
            (
                "unreadable sibling",
                "garbage",
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
            (
                "empty-object sibling",
                "empty_object",
                Some(IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("2"),
                }),
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let incoming = credential("r4l-login", 300);
            let mut held = held_with("r4l-sibling");
            if mode == "held" {
                held.expect_anthropic_mut().claude_ai_oauth.access_token =
                    AccessToken::new("fake-access-r4l-login".to_owned());
            }
            let sibling = add_legacy_sibling(base, "2", &held);
            if mode == "garbage" {
                std::fs::write(identity_store::credentials_path_for(base, sibling), b"{ x")
                    .unwrap();
            }
            if mode == "empty_object" {
                std::fs::write(identity_store::credentials_path_for(base, sibling), b"{}").unwrap();
            }
            let sibling_before =
                std::fs::read(identity_store::credentials_path_for(base, sibling)).unwrap();
            let prior = capture_login_prior(base, slot(1)).unwrap();
            let result = commit_anthropic_login_with(
                base,
                slot(1),
                &incoming,
                &transport(&incoming, context(20)),
                None,
                prior,
            );
            match expected {
                None => {
                    result.unwrap_or_else(|e| panic!("{label}: {e}"));
                }
                Some(error) => {
                    assert_eq!(result.unwrap_err(), error, "{label}");
                    let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
                    assert!(!pf.by_slot.contains_key("1"), "{label}: slot 1 not bound");
                }
            }
            assert_eq!(
                std::fs::read(identity_store::credentials_path_for(base, sibling)).unwrap(),
                sibling_before,
                "{label}: sibling untouched"
            );
        }
    }

    /// Apply `damage` (custody damage on the target's prior canonical), capture the login
    /// prior, then commit the login.
    #[cfg(unix)]
    fn r5_login(
        base: &Path,
        n: u16,
        incoming: &CredentialFile,
        damage: impl FnOnce(),
    ) -> Result<CommittedAnthropicLogin, IdentityError> {
        damage();
        let prior = capture_login_prior(base, slot(n)).unwrap();
        commit_anthropic_login_with(
            base,
            slot(n),
            incoming,
            &transport(incoming, context(20)),
            None,
            prior,
        )
    }
    /// r5 H1 (i): the slot being logged in is about to REPLACE its prior binding, so that
    /// binding's own damaged canonical must not block the login that repairs it.
    #[cfg(unix)]
    #[test]
    fn org_identity_r5_h1_legacy_slot_with_damaged_own_canonical_relogs_in() {
        for kind in ["garbage", "0666", "nlink", "symlink"] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old_id = make_legacy(base, &credential("r5h1-old", 100));
            let incoming = credential("r5h1-login", 300);
            let committed = r5_login(base, 1, &incoming, || {
                damage_sibling_canonical(base, old_id, kind)
            })
            .unwrap_or_else(|e| panic!("{kind}: re-login must repair the slot: {e}"));
            let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
            assert_eq!(pf.by_slot.get("1"), Some(&committed.identity()), "{kind}");
            assert_ne!(
                committed.identity(),
                old_id,
                "{kind}: a new identity is minted"
            );
        }
    }
    /// r5 H1 (ii): a damaged OTHER sibling still refuses the login, and the error names
    /// THAT sibling's slot. An identity the target slot shares with another slot stays a
    /// sibling and is named by the OTHER slot.
    #[cfg(unix)]
    #[test]
    fn org_identity_r5_h1_damaged_other_sibling_still_refuses_and_names_its_slot() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old_id = make_legacy(base, &credential("r5h1b-old", 100));
        let other = add_legacy_sibling(base, "2", &held_with("r5h1b-other"));
        let incoming = credential("r5h1b-login", 300);
        assert_eq!(
            r5_login(base, 1, &incoming, || {
                damage_sibling_canonical(base, old_id, "garbage");
                damage_sibling_canonical(base, other, "garbage");
            })
            .unwrap_err(),
            IdentityError::SiblingCustodyUnreadable {
                sibling: SlotKey::from_key("2")
            }
        );
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(pf.by_slot.get("1"), Some(&old_id), "slot 1 not rebound");

        // Shared: slot 3 ALSO references the outgoing identity, so it is still a sibling,
        // named by slot 3 and never by the slot being logged in. `by_slot` is a HashMap
        // with a per-instance random order, so repeat to make a wrong choice near-certain
        // to show (each wrong pick is 1 in 2).
        for round in 0..16 {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old_id = make_legacy(base, &credential("r5h1c-old", 100));
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap();
            pf.by_slot.insert("3".into(), old_id);
            profiles::save(&path, &pf).unwrap();
            assert_eq!(
                r5_login(base, 1, &credential("r5h1c-login", 300), || {
                    damage_sibling_canonical(base, old_id, "garbage")
                })
                .unwrap_err(),
                IdentityError::SiblingCustodyUnreadable {
                    sibling: SlotKey::from_key("3")
                },
                "round {round}"
            );
        }
    }
    #[test]
    fn org_identity_r5_slot_key_prints_number_or_fixed_token() {
        for (key, shown, account) in [
            ("2", "2", Some(2u16)),
            ("01", "another slot", None),
            ("+2", "another slot", None),
            ("0", "another slot", None),
            ("not-a-slot\nforged", "another slot", None),
            ("", "another slot", None),
        ] {
            let k = SlotKey::from_key(key);
            assert_eq!(k.to_string(), shown, "{key:?}");
            assert_eq!(k.account().map(AccountNum::get), account, "{key:?}");
        }
    }
    /// r5 M1: the Profile (Known) witness refuses a slot-bound LegacyUnknown sibling with
    /// the same normalised email (rotation lag), and not one with a different email.
    #[test]
    fn org_identity_r5_m1_known_witness_refuses_same_email_legacy_sibling() {
        for (label, sibling_email, refuses) in [
            ("same email", "same@test.invalid", true),
            (
                "same email, other case and padding",
                "  SAME@Test.Invalid ",
                true,
            ),
            ("different email", "other@test.invalid", false),
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            commit(base, 1, &credential("r5m1-known", 100), context(20));
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            // Y holds the OLD pair, never the rotated candidate: no token matches.
            let _y = add_legacy_sibling_with_email(
                base,
                "2",
                sibling_email,
                &held_with("r5m1-old-pair-of-y"),
            );
            let candidate = credential("r5m1-rotated", 200);
            let proof = verified_for(&candidate, context(20));
            let outcome = file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            );
            assert_eq!(outcome.is_err(), refuses, "{label}: {outcome:?}");
        }
    }
    /// r5 M2: a SIBLING's identity.json is read for comparison only: a 0644 one is
    /// accepted (mode bits change nothing about the recorded email), a group-writable one
    /// is refused. Covers the legacy witness (mint + upgrade) and the Known witness.
    #[cfg(unix)]
    #[test]
    fn org_identity_r5_m2_sibling_metadata_is_read_for_comparison_not_custody() {
        use std::os::unix::fs::PermissionsExt;
        for (mode, refuses) in [(0o644u32, false), (0o664, true), (0o666, true)] {
            let label = format!("{mode:o}");
            // Legacy witness.
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let old = credential("r5m2-own", 100);
            let id = make_legacy(base, &old);
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let candidate = credential("r5m2-cand", 200);
            let cand = verified_for(&candidate, context(20));
            let own = verified_for(&old, context(20));
            let sibling = add_legacy_sibling(base, "2", &held_with("r5m2-sib"));
            std::fs::set_permissions(
                identity_store::identity_json_path_for(base, sibling),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            let minted =
                legacy_own_uuid_proof(base, &captured, &cand, &own, candidate.anthropic().unwrap());
            let upgraded = upgrade_verified_legacy_identity(base, id, &own);
            if refuses {
                assert_eq!(
                    minted.unwrap_err(),
                    IdentityError::SharedLegacyIdentity,
                    "{label}"
                );
                assert_eq!(
                    upgraded,
                    Err(IdentityError::SharedLegacyIdentity),
                    "{label}"
                );
            } else {
                assert!(minted.is_ok(), "{label}: mint {minted:?}");
                assert_eq!(upgraded, Ok(()), "{label}: upgrade");
            }
            // Known witness.
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            commit(base, 1, &credential("r5m2-known", 100), context(20));
            let captured = capture_anthropic_binding(base, slot(1)).unwrap();
            let sibling = add_legacy_sibling(base, "2", &held_with("r5m2-sib2"));
            std::fs::set_permissions(
                identity_store::identity_json_path_for(base, sibling),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            let proof = verified_for(&candidate, context(20));
            let outcome = file::save_anthropic_canonical_guarded(
                base,
                &captured,
                candidate.anthropic().unwrap(),
                AnthropicWriteWitness::Profile(&proof),
                None,
            );
            assert_eq!(outcome.is_err(), refuses, "{label}: known {outcome:?}");
        }
    }
    /// r5 F4: two legacy slots with the same email but different organizations are a
    /// legitimate pair. The metadata-only upgrade (it adopts no candidate) records each
    /// slot's organization and so resolves the ambiguity; the mint, which adopts a
    /// candidate credential, still refuses while the pair is ambiguous.
    #[test]
    fn org_identity_r5_f4_same_email_different_org_legacy_slots_upgrade_then_adopt() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let old_x = credential("r5f4-x", 100);
        let x = make_legacy(base, &old_x);
        let held_y = held_with("r5f4-y");
        let y = add_legacy_sibling_with_email(base, "2", "same@test.invalid", &held_y);
        let captured_x = capture_anthropic_binding(base, slot(1)).unwrap();
        let candidate = credential("r5f4-rot", 200);
        let cand = verified_for(&candidate, context(20));
        let own_x = verified_for(&old_x, context(20));
        // Mint keeps the same-email clause.
        assert_eq!(
            legacy_own_uuid_proof(
                base,
                &captured_x,
                &cand,
                &own_x,
                candidate.anthropic().unwrap()
            )
            .unwrap_err(),
            IdentityError::SharedLegacyIdentity,
            "mint"
        );
        // Upgrades are metadata-only and resolve it, one slot at a time.
        assert_eq!(
            upgrade_verified_legacy_identity(base, x, &own_x),
            Ok(()),
            "x"
        );
        let own_y = verified_for(&held_y, context(21));
        assert_eq!(
            upgrade_verified_legacy_identity(base, y, &own_y),
            Ok(()),
            "y"
        );
        // Now both are Known and the Known witness adopts.
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let proof = verified_for(&candidate, context(20));
        let outcome = file::save_anthropic_canonical_guarded(
            base,
            &captured,
            candidate.anthropic().unwrap(),
            AnthropicWriteWitness::Profile(&proof),
            None,
        );
        assert!(outcome.is_ok(), "adopt: {outcome:?}");
    }

    // ── D237 C1: post-commit rescue rows ────────────────────────────────

    /// Holds one lock file on another thread for the test's duration.
    /// A Windows named mutex is re-entrant for its HOLDING thread, so the
    /// contention probe must run elsewhere on every platform.
    fn hold_lock_on_other_thread(lock_path: &std::path::Path) -> ProfilesLockHolder {
        let lock_path = lock_path.to_path_buf();
        crate::accounts::profiles_lock::HeldOnOtherThread::hold(move || {
            crate::platform::lock::try_lock_file(&lock_path)
                .expect("try_lock_file")
                .expect("test must hold the canonical lock")
        })
    }

    type ProfilesLockHolder = crate::accounts::profiles_lock::HeldOnOtherThread;

    /// ROW 1 (Anthropic rotate): a post-HTTP save whose canonical lock stays
    /// held past the commit budget MUST NOT lose the rotated pair.
    ///
    /// RED mutation: delete the `write_post_commit_rescue` call in
    /// `save_anthropic_lineage_canonical` — the rescue record is then
    /// absent and this row panics on its `expect`.
    #[test]
    fn post_commit_anthropic_rotation_rescues_pair_then_adopts() {
        use crate::credentials::rescue;
        use std::time::Duration;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = credential("initial", 100);
        let committed = commit(base, 1, &initial, context(20));
        let id = committed.identity();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let prepared = prepare_anthropic_refresh(base, &captured).unwrap();
        let (rotated, lineage) = refresh_captured_anthropic_with(
            &prepared,
            initial.anthropic().unwrap(),
            |_, _| {
                Ok(br#"{"access_token":"fake-access-rotated","refresh_token":"fake-refresh-rotated","expires_in":3600}"#.to_vec())
            },
        )
        .unwrap();

        let canonical = identity_store::credentials_path_for(base, id);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let old_bytes = std::fs::read(&canonical).unwrap();
        let _holder = hold_lock_on_other_thread(&canonical.with_extension("lock"));
        let _budget = rescue::CommitBudgetOverrideGuard::install(Duration::from_millis(300));

        let error = file::save_anthropic_canonical_guarded(
            base,
            &captured,
            &rotated,
            AnthropicWriteWitness::RefreshLineage(&lineage),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                crate::error::CredentialError::CanonicalLockRefused { .. }
            ),
            "expiry must surface the typed commit-lock refusal: {error:?}"
        );

        // The pair is durable even though the canonical write did not land.
        let pending = rescue::rescue_record_pending(&identity_dir)
            .expect("the rotated pair must be durably rescued");
        assert!(!pending.is_unparseable());
        assert_eq!(pending.provider, "anthropic");
        assert_eq!(pending.uuid, id.to_string());
        assert_eq!(pending.schema, rescue::RESCUE_SCHEMA);
        let rescued: CredentialFile = serde_json::from_value(pending.payload).unwrap();
        assert_eq!(
            rescued
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-rotated"
        );
        // …and the canonical file still holds the PRE-rotation pair.
        assert_eq!(
            std::fs::read(&canonical).unwrap(),
            old_bytes,
            "a deferred save must leave the canonical untouched"
        );

        // The next tick's adoption installs the new pair and clears the record.
        drop(_holder);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        let installed = file::load(&canonical).unwrap();
        assert_eq!(
            installed
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-rotated"
        );
        assert!(
            rescue::rescue_record_pending(&identity_dir).is_none(),
            "adoption must remove the rescue record"
        );
    }

    /// ROW 3 (consumed login grant): `save_anthropic_login_target_locked`
    /// under contention past the commit budget leaves a rescue record, and
    /// adoption installs the freshly minted grant.
    ///
    /// RED mutation: delete the `write_post_commit_rescue` call in
    /// `save_anthropic_login_target_locked` — the row panics on its
    /// `expect`.
    #[test]
    fn post_commit_login_grant_rescues_then_adopts() {
        use crate::credentials::rescue;
        use std::time::Duration;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let committed = commit(base, 1, &credential("initial", 100), context(20));
        let id = committed.identity();
        let incoming = credential("fresh-login", 200);
        let verified = verify_anthropic_context_with(
            incoming.anthropic().unwrap(),
            &transport(&incoming, context(20)),
        )
        .unwrap();
        let canonical = identity_store::credentials_path_for(base, id);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let old_bytes = std::fs::read(&canonical).unwrap();
        let _holder = hold_lock_on_other_thread(&canonical.with_extension("lock"));
        let _budget = rescue::CommitBudgetOverrideGuard::install(Duration::from_millis(300));

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let error = file::save_anthropic_login_target_locked(
            &lock,
            base,
            slot(1),
            id,
            incoming.anthropic().unwrap(),
            &verified,
            None,
        )
        .unwrap_err();
        drop(lock);
        assert!(
            matches!(
                error,
                crate::error::CredentialError::CanonicalLockRefused { .. }
            ),
            "expiry must surface the typed commit-lock refusal: {error:?}"
        );

        let pending = rescue::rescue_record_pending(&identity_dir)
            .expect("the consumed login grant must be durably rescued");
        assert_eq!(pending.provider, "anthropic");
        assert_eq!(pending.uuid, id.to_string());
        let rescued: CredentialFile = serde_json::from_value(pending.payload).unwrap();
        assert_eq!(
            rescued
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-fresh-login"
        );
        assert_eq!(std::fs::read(&canonical).unwrap(), old_bytes);

        drop(_holder);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        let installed = file::load(&canonical).unwrap();
        assert_eq!(
            installed
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-fresh-login"
        );
        assert!(rescue::rescue_record_pending(&identity_dir).is_none());
    }

    /// RED with the former acquire/map-to-Io boundary: a real held lock
    /// must retain its busy diagnostic before login starts.
    #[test]
    fn capture_login_prior_profiles_lock_expiry_is_binding_busy() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let _holder = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        let _budget = crate::accounts::profiles_lock::ProfilesBudgetOverrideGuard::install(1);

        let error = capture_login_prior(base, slot(1)).unwrap_err();
        assert_eq!(error, IdentityError::BindingBusy);
        assert_eq!(error.to_string(), "anthropic_identity_profiles_busy");
    }

    #[test]
    fn capture_login_prior_profiles_parent_io_refusal_remains_io() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("not-a-directory");
        std::fs::write(&base, b"fixture").unwrap();
        let _budget = crate::accounts::profiles_lock::ProfilesBudgetOverrideGuard::install(1);

        let error = capture_login_prior(&base, slot(1)).unwrap_err();
        assert_eq!(error, IdentityError::Io);
        assert_eq!(error.to_string(), "anthropic_identity_io_refused");
    }

    // Unix opens the lock path as a file; a directory deterministically
    // exercises the real lock-file I/O failure rather than budget expiry.
    #[cfg(unix)]
    #[test]
    fn login_profiles_lock_file_io_refusal_remains_io() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let lock_path = ProfilesFileLock::lock_path(base);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::create_dir(&lock_path).unwrap();
        let _budget = crate::accounts::profiles_lock::ProfilesBudgetOverrideGuard::install(1);

        assert_eq!(
            capture_login_prior(base, slot(1)).unwrap_err(),
            IdentityError::Io
        );
        let incoming = credential("profiles-io-refusal", 100);
        let error = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        )
        .unwrap_err();
        assert_eq!(error, IdentityError::Io);
        assert_eq!(error.to_string(), "anthropic_identity_io_refused");
    }

    /// ROW N4 (profiles lock; D237 round-2 corr N4 / sec M4): a login whose
    /// profiles acquisition expires past the OLD 2 s bound no longer loses
    /// the consumed grant. The rescue is written BEFORE the profiles lock,
    /// so the grant stays durable and the next adoption installs it.
    ///
    /// RED mutation: move the rescue write back inside the target save (after
    /// the profiles acquire, as before this wave) — this row then finds no
    /// record and its `expect` panics.
    #[test]
    fn profiles_lock_expiry_keeps_the_consumed_login_grant_rescued() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let committed = commit(base, 1, &credential("initial", 100), context(20));
        let id = committed.identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();

        // Another publication holds the profiles lock past the OLD 2 s bound.
        let holder = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        // Keep the test fast: only the ATTEMPT COUNT is overridden.
        let budget = crate::accounts::profiles_lock::ProfilesBudgetOverrideGuard::install(3);
        let result = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        );
        drop(budget);
        let error = result.expect_err("profiles contention must refuse the publication");
        assert_eq!(error, IdentityError::BindingBusy);
        assert_eq!(error.to_string(), "anthropic_identity_profiles_busy");

        // The consumed grant is durable even though the publication failed.
        let canonical = identity_store::credentials_path_for(base, id);
        let identity_dir = canonical.parent().unwrap();
        let pending = rescue::rescue_record_pending(identity_dir)
            .expect("the consumed login grant must be rescued BEFORE the profiles lock");
        assert_eq!(pending.provider, "anthropic");
        let rescued: CredentialFile = serde_json::from_value(pending.payload).unwrap();
        assert_eq!(
            rescued
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-fresh-login"
        );

        // Once the lock frees, adoption installs the grant.
        drop(holder);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        let installed = file::load(&canonical).unwrap();
        assert_eq!(
            installed
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-fresh-login"
        );
        assert!(rescue::rescue_record_pending(identity_dir).is_none());
    }

    /// ROW 4 (PRE-COMMIT unchanged): `prepare_anthropic_refresh` still
    /// refuses inside the bounded 500 ms budget and writes NO rescue record.
    ///
    /// RED mutation: switch that preflight's acquisition to
    /// `rescue::lock_credential_file_commit` — the elapsed bound below then
    /// exceeds 5 s.
    #[test]
    fn pre_commit_prepare_refuses_within_the_bounded_budget_and_rescues_nothing() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let committed = commit(base, 1, &credential("initial", 100), context(20));
        let canonical = identity_store::credentials_path_for(base, committed.identity());
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let _holder = hold_lock_on_other_thread(&canonical.with_extension("lock"));

        let started = std::time::Instant::now();
        let error = prepare_anthropic_refresh(base, &captured).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(
                error,
                crate::error::CredentialError::CanonicalLockRefused {
                    io_kind: std::io::ErrorKind::TimedOut,
                    ..
                }
            ),
            "the preflight expiry carries its own typed PRE-COMMIT refusal \
             (D237 round-2 H-b), distinct from the custody refusal: {error:?}"
        );
        // The 500 ms budget, not the 30 s commit budget.
        assert!(
            elapsed
                >= crate::platform::lock::CREDENTIAL_LOCK_BUDGET
                    - crate::platform::lock::CREDENTIAL_LOCK_DELAY,
            "preflight returned before its bounded budget elapsed: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the PRE-COMMIT preflight must not use the long commit budget: {elapsed:?}"
        );
        assert!(
            rescue::rescue_record_pending(&identity_dir).is_none(),
            "a pre-commit refusal must never write a rescue record"
        );
    }

    /// R3 correctness M-3: an I/O-class failure between the pre-lock rescue
    /// write and its hand-over MUST retain the record. Only a deliberate
    /// refusal (binding changed / invalid metadata / stored-context
    /// mismatch) may remove the only durable copy of a consumed grant.
    ///
    /// RED mutation: restore the bare `?` at the profiles read (the record
    /// then drops with `keep=false`) — `rescue_record_pending` returns
    /// `None` and this row panics on its `expect`.
    #[test]
    fn r3_corr_m3_prelock_rescue_kept_on_io_error() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let committed = commit(base, 1, &credential("initial", 100), context(20));
        let id = committed.identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();

        // The publication's FIRST profiles read fails transiently.
        arm_profiles_load_fault();
        let result = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        );
        let error = result.expect_err("an unreadable profiles.json must refuse the publication");
        assert!(
            matches!(error, IdentityError::ProfilesReadRefused),
            "an injected read failure must surface as the READ refusal, never as a \
             deliberate one: {error:?}"
        );

        // The consumed grant survives for the next tick's adoption.
        let canonical = identity_store::credentials_path_for(base, id);
        let identity_dir = canonical.parent().unwrap();
        let pending = rescue::rescue_record_pending(identity_dir)
            .expect("R3 corr M-3: an I/O-class read failure must KEEP the pre-lock rescue record");
        assert_eq!(pending.provider, "anthropic");
        assert_eq!(pending.uuid, id.to_string());
        let rescued: CredentialFile = serde_json::from_value(pending.payload).unwrap();
        assert_eq!(
            rescued
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-fresh-login",
            "the kept record must hold the consumed login grant"
        );
        // Nothing was installed: the canonical still holds the prior pair.
        let installed = file::load(&canonical).unwrap();
        assert_eq!(
            installed
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "fake-access-initial"
        );
        // corr MED-2: KEPT, not merely pending — the marker exists and the
        // next adoption installs the grant.
        let record = only_record(base, id);
        assert!(
            record.with_extension("json.kept").exists(),
            "keep path wrote no marker"
        );
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    // ── Rescue refusal must be durable and adoption must keep writer parity ──
    //
    // Each row discriminates ONE mechanism; its doc names the mutation that
    // reds it. A PRE-LOCK record is refused by DEFAULT (no kept marker), so a
    // row that targets another mechanism uses a KEPT record or a post-lock
    // record to keep the default out of the way.

    fn canonical_access(base: &Path, id: IdentityId) -> Option<String> {
        let canonical = identity_store::credentials_path_for(base, id);
        if !canonical.exists() {
            return None;
        }
        Some(
            file::load(&canonical)
                .unwrap()
                .anthropic()
                .unwrap()
                .claude_ai_oauth
                .access_token
                .expose_secret()
                .to_string(),
        )
    }

    fn set_slot_generation(base: &Path, n: u16, generation: u64) {
        let path = profiles::profiles_path(base);
        let mut pf = profiles::load(&path).unwrap();
        pf.slot_binding_generations
            .insert(n.to_string(), generation);
        profiles::save(&path, &pf).unwrap();
    }

    fn slot_generation(base: &Path, n: u16) -> u64 {
        profiles::load(&profiles::profiles_path(base))
            .unwrap()
            .slot_binding_generations
            .get(&n.to_string())
            .copied()
            .unwrap_or(0)
    }

    fn write_store_schema(base: &Path, schema: u32) {
        std::fs::write(
            identity_store::store_version_path(base),
            format!("{{\"schema\":{schema}}}"),
        )
        .unwrap();
    }

    /// Writes an UNREFUSED pre-lock login record for `id`, returning the held
    /// handle (writer alive, not yet kept).
    fn prelock_record(
        base: &Path,
        id: IdentityId,
        incoming: &CredentialFile,
        ctx: AnthropicContext,
    ) -> file::PrelockRescue {
        file::write_login_prelock_rescue(
            base,
            id,
            incoming.anthropic().unwrap(),
            &verified_for(incoming, ctx),
        )
        .expect("the pre-lock record is written")
    }

    /// A pre-lock record whose publication KEPT it for adoption.
    fn kept_prelock_record(
        base: &Path,
        id: IdentityId,
        incoming: &CredentialFile,
        ctx: AnthropicContext,
    ) -> PathBuf {
        let handle = prelock_record(base, id, incoming, ctx);
        let path = handle.path.clone();
        file::keep_prelock_rescue(Some(handle));
        assert!(path.with_extension("json.kept").exists());
        path
    }

    /// A POST-lock login record (no kept-marker default), as the canonical
    /// writer writes it.
    fn post_lock_login_record(
        base: &Path,
        id: IdentityId,
        incoming: &CredentialFile,
        ctx: AnthropicContext,
    ) -> PathBuf {
        let verified = verified_for(incoming, ctx);
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        crate::credentials::rescue::write_rescue_record(
            &identity_dir,
            "anthropic",
            &id.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(incoming).unwrap(),
            &crate::credentials::rescue::RescueWitness::Anthropic(rescue_lineage_witness_login(
                &verified,
            )),
        )
        .unwrap()
    }

    fn quarantined(record: &Path) -> bool {
        record
            .parent()
            .unwrap()
            .join("quarantine")
            .join(record.file_name().unwrap())
            .exists()
    }

    fn dir_entry_names(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// Row 1 (HIGH, writer parity): with NO canonical, a KEPT login record
    /// whose witness context is another account's is quarantined, never
    /// installed.
    ///
    /// RED mutation: delete the stored-context check in the no-canonical
    /// Login arm of `rescue_source_gate`.
    #[test]
    fn rescue_refusal_row1_absent_canonical_foreign_context_never_installs() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = kept_prelock_record(base, id, &credential("foreign-login", 200), context(30));
        std::fs::remove_file(identity_store::credentials_path_for(base, id)).unwrap();

        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(matches!(adopted, Ok(false)), "got {adopted:?}");
        assert_eq!(
            canonical_access(base, id),
            None,
            "a foreign grant installed"
        );
        assert!(!record.exists());
        assert!(quarantined(&record));
    }

    /// Row 2 (corr M2): the login writer's policy gate refuses its own
    /// POST-lock record (unreadable canonical) and the unlink fails; the
    /// tombstone keeps adoption from installing it once the canonical reads.
    ///
    /// RED mutation: replace the `refuse_rescue_record` call in the gate's
    /// `Err` arm with the old best-effort `remove_rescue_record`.
    #[test]
    fn rescue_refusal_row2_login_gate_refusal_of_post_lock_record_survives_failed_unlink() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("fresh-login", 200);
        let verified = verified_for(&incoming, context(20));
        let canonical = identity_store::credentials_path_for(base, id);
        let original = std::fs::read(&canonical).unwrap();
        std::fs::write(&canonical, b"{not json").unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        let fault = rescue::refusal_faults::UnlinkFault::arm();
        let result = file::save_anthropic_login_target_locked(
            &lock,
            base,
            slot(1),
            id,
            incoming.anthropic().unwrap(),
            &verified,
            None,
        );
        drop(fault);
        drop(lock);
        assert!(
            result.is_err(),
            "an unreadable canonical refuses the login write"
        );
        std::fs::write(&canonical, &original).unwrap();

        let _ = rescue::adopt_rescue_record(base, &id.to_string());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial"),
            "adoption installed a grant the login gate refused"
        );
    }

    /// Row 3: a `BindingChanged` refusal whose tombstone AND unlink both fail
    /// stays refused: `PrelockLoginRescue`'s drop never keeps it.
    ///
    /// RED mutation: make the drop's refuse branch call
    /// `keep_prelock_rescue` (the record then carries a kept marker).
    #[test]
    fn rescue_refusal_row3_binding_changed_refusal_without_cleanup_stays_refused() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let generation = slot_generation(base, 1);
        set_slot_generation(base, 1, generation + 1);

        let unlink = rescue::refusal_faults::UnlinkFault::arm();
        let marker = rescue::refusal_faults::MarkerWriteFault::arm_tombstone_only(
            rescue::MarkerStage::Write,
        );
        let error = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        )
        .expect_err("a changed binding generation refuses the publication");
        drop(marker);
        drop(unlink);
        assert!(
            matches!(error, IdentityError::BindingChanged),
            "got {error:?}"
        );
        // The binding changing back does not resurrect the refused grant.
        set_slot_generation(base, 1, generation);

        let _ = rescue::adopt_rescue_record(base, &id.to_string());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial"),
            "adoption installed a grant the publication refused"
        );
    }

    /// Row 4 (writer parity, schema gate, canonical PRESENT): a kept login
    /// record stays pending while the store schema is newer than this
    /// binary, and adopts once it is current again.
    ///
    /// RED mutation: delete `rescue_store_schema_permits(base)?` in the
    /// canonical-present Login arm of `rescue_source_gate`.
    #[test]
    fn rescue_refusal_row4_present_canonical_newer_store_schema_stays_pending() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = kept_prelock_record(base, id, &credential("fresh-login", 200), context(20));
        let current = crate::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT;
        write_store_schema(base, current + 1);

        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(adopted.is_err(), "got {adopted:?}");
        assert!(record.exists(), "the record must stay pending");
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial")
        );

        write_store_schema(base, current);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    /// Row 5: an `InvalidContext` capture failure is a deliberate refusal
    /// (not a retained read failure): with no tombstone and no unlink, the
    /// record stays refused after the context is repaired.
    ///
    /// RED mutation: drop `IdentityError::InvalidContext` from
    /// `retain_unless_refused`'s refusal set (the record is then kept).
    #[test]
    fn rescue_refusal_row5_invalid_context_then_repaired_stays_refused() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let metadata_path = identity_store::identity_json_path_for(base, id);
        let original = std::fs::read(&metadata_path).unwrap();
        let mut corrupted: serde_json::Value = serde_json::from_slice(&original).unwrap();
        corrupted["account_uuid"] = serde_json::json!("not-a-uuid");
        std::fs::write(&metadata_path, serde_json::to_vec(&corrupted).unwrap()).unwrap();

        let unlink = rescue::refusal_faults::UnlinkFault::arm();
        let marker = rescue::refusal_faults::MarkerWriteFault::arm_tombstone_only(
            rescue::MarkerStage::Write,
        );
        let error = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        )
        .expect_err("an unparseable stored context refuses the publication");
        drop(marker);
        drop(unlink);
        assert!(
            matches!(error, IdentityError::InvalidContext),
            "got {error:?}"
        );
        std::fs::write(&metadata_path, &original).unwrap();

        let _ = rescue::adopt_rescue_record(base, &id.to_string());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial"),
            "a repaired context resurrected a refused grant"
        );
    }

    /// Row 6: account B re-logs into a slot bound to identity X (account A);
    /// `take_for` refuses X's pre-lock record and its cleanup fails. Even if
    /// X's stored context later reads as B's and nothing else holds B's
    /// grant, the record is never installed at X.
    ///
    /// RED mutation: make `take_for`'s mismatch branch call
    /// `keep_prelock_rescue` instead of `refuse_prelock_rescue`.
    #[test]
    fn rescue_refusal_row6_take_for_mismatch_refusal_stays_refused() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let x = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("other-account", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();

        let unlink = rescue::refusal_faults::UnlinkFault::arm();
        let marker = rescue::refusal_faults::MarkerWriteFault::arm_tombstone_only(
            rescue::MarkerStage::Write,
        );
        let committed = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(30)),
            None,
            prior,
        );
        drop(marker);
        drop(unlink);
        let y = committed
            .expect("account B binds to its own identity")
            .identity();
        assert_ne!(x, y);
        // Isolate the take_for refusal: make the context gate and the holder
        // check both pass for this record.
        let metadata_path = identity_store::identity_json_path_for(base, x);
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        metadata["organization_uuid"] = serde_json::json!(Uuid::from_u128(30).to_string());
        std::fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        std::fs::remove_file(identity_store::credentials_path_for(base, y)).unwrap();
        let x_canonical = identity_store::credentials_path_for(base, x);
        if x_canonical.exists() {
            std::fs::remove_file(&x_canonical).unwrap();
        }

        let _ = rescue::adopt_rescue_record(base, &x.to_string());
        assert_eq!(
            canonical_access(base, x),
            None,
            "account B's grant was installed into account A's identity"
        );
    }

    /// Row 7 (sec MED-2): a pre-lock refusal whose tombstone AND unlink both
    /// fail no longer holds the writer guard for the rest of the process, so
    /// a long-lived daemon or desktop never blocks the identity's refresh on
    /// it; adoption quarantines it.
    ///
    /// RED mutation: in `refuse_prelock_rescue`, `std::mem::forget` the
    /// writer guard instead of dropping it.
    #[test]
    fn rescue_refusal_row7_failed_prelock_cleanup_never_blocks_refresh() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        // No canonical: an unrefused same-account login record would install,
        // so it would block refresh.
        std::fs::remove_file(identity_store::credentials_path_for(base, id)).unwrap();
        let handle = prelock_record(base, id, &credential("fresh-login", 200), context(20));
        let record = handle.path.clone();
        {
            let _unlink = rescue::refusal_faults::UnlinkFault::arm();
            let _marker = rescue::refusal_faults::MarkerWriteFault::arm_tombstone_only(
                rescue::MarkerStage::Write,
            );
            file::refuse_prelock_rescue(Some(handle));
        }
        assert!(record.exists());
        assert!(!record.with_extension("json.refused").exists());
        assert!(!rescue::rescue_blocks_refresh(base, id), "refresh blocked");

        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(matches!(adopted, Ok(false)), "got {adopted:?}");
        assert_eq!(canonical_access(base, id), None);
        assert!(quarantined(&record));
    }

    /// Row 7b: a POST-lock record whose tombstone AND unlink both fail is a
    /// refusal that is not durable at all: `refuse_rescue_record` errs and
    /// raises the flag `csq login` reports (once).
    ///
    /// RED mutation: delete the `REFUSAL_NOT_DURABLE.store(..)` line.
    #[test]
    fn rescue_refusal_row7b_post_lock_refusal_not_durable_errs_and_flags() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = post_lock_login_record(base, id, &credential("fresh-login", 200), context(20));
        {
            let _unlink = rescue::refusal_faults::UnlinkFault::arm();
            let _marker = rescue::refusal_faults::MarkerWriteFault::arm_tombstone_only(
                rescue::MarkerStage::Write,
            );
            assert!(rescue::refuse_rescue_record(&record).is_err());
        }
        assert!(rescue::take_refusal_not_durable());
        assert!(!rescue::take_refusal_not_durable(), "the flag is read once");
    }

    /// Row 8 (§5a): a marker is 0o600, and its temp file is removed after a
    /// forced `secure_file` failure and a forced `atomic_replace` failure.
    #[test]
    fn rescue_refusal_row8_marker_write_follows_5a() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        for (n, stage) in [rescue::MarkerStage::Secure, rescue::MarkerStage::Replace]
            .into_iter()
            .enumerate()
        {
            let record = post_lock_login_record(
                base,
                id,
                &credential(&format!("stage-{n}"), 200),
                context(20),
            );
            {
                let _marker = rescue::refusal_faults::MarkerWriteFault::arm(stage);
                // The unlink still succeeds: the refusal is durable.
                rescue::refuse_rescue_record(&record).unwrap();
            }
            assert!(!record.exists());
            let leftovers: Vec<String> = dir_entry_names(&identity_dir)
                .into_iter()
                .filter(|name| name.contains(".tmp.") || name.ends_with(".refused"))
                .collect();
            assert!(leftovers.is_empty(), "{stage:?} left {leftovers:?}");
        }

        let record = post_lock_login_record(base, id, &credential("mode", 200), context(20));
        {
            let _unlink = rescue::refusal_faults::UnlinkFault::arm();
            rescue::refuse_rescue_record(&record).unwrap();
        }
        let tombstone = record.with_extension("json.refused");
        assert!(
            tombstone.exists(),
            "a failed unlink leaves the tombstone in place"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tombstone).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// Row 9 (guard-reader parity): a tombstone turns a record that would
    /// otherwise be UNADOPTABLE (no canonical, newer store schema) into one
    /// every reader classifies as adoption does: it does not block refresh,
    /// it is Adoptable, and adoption quarantines it.
    ///
    /// RED mutation: in `classify_records`, map `RefusalMark::Refused` to
    /// `record.is_self_resolving(..)` instead of `true`.
    #[test]
    fn rescue_refusal_row9_tombstoned_unadoptable_record_readers_agree_with_adoption() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = post_lock_login_record(base, id, &credential("fresh-login", 200), context(20));
        std::fs::remove_file(identity_store::credentials_path_for(base, id)).unwrap();
        write_store_schema(
            base,
            crate::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT + 1,
        );
        // Controls: untombstoned, the record blocks and is Unadoptable.
        assert!(rescue::rescue_blocks_refresh(base, id));
        assert!(matches!(
            rescue::rescue_pending_state(base, id),
            Some(rescue::RescuePendingState::Unadoptable)
        ));
        {
            let _unlink = rescue::refusal_faults::UnlinkFault::arm();
            rescue::refuse_rescue_record(&record).unwrap();
        }
        assert!(record.exists());
        assert!(!rescue::rescue_blocks_refresh(base, id));
        assert!(matches!(
            rescue::rescue_pending_state(base, id),
            Some(rescue::RescuePendingState::Adoptable)
        ));
        let rows = rescue::pending_rescues(base);
        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows[0].state,
            rescue::RescuePendingState::Adoptable
        ));

        assert!(matches!(
            rescue::adopt_rescue_record(base, &id.to_string()),
            Ok(false)
        ));
        assert_eq!(
            canonical_access(base, id),
            None,
            "a refused grant was installed"
        );
        assert!(quarantined(&record));
        assert!(!record.with_extension("json.refused").exists());
        assert!(rescue::rescue_pending_state(base, id).is_none());
    }

    /// Row 10: a refused pre-lock record leaves no `.json.writer` sidecar
    /// (and no other `rescue-*` file) behind once the record is gone.
    #[test]
    fn rescue_refusal_row10_refused_record_sidecar_is_removed() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        set_slot_generation(base, 1, slot_generation(base, 1) + 1);
        let error = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        )
        .expect_err("a changed binding generation refuses the publication");
        assert!(
            matches!(error, IdentityError::BindingChanged),
            "got {error:?}"
        );
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        let leftovers: Vec<String> = dir_entry_names(&identity_dir)
            .into_iter()
            .filter(|name| name.starts_with("rescue-"))
            .collect();
        assert!(leftovers.is_empty(), "refusal left {leftovers:?}");
    }

    /// Row 11: an UNREADABLE marker state never installs, in every reader:
    /// adoption leaves the record pending, refresh is blocked, and the state
    /// is Unadoptable.
    ///
    /// RED mutation: in `refusal_mark`, treat an unreadable marker as absent
    /// (`Err(_) => {}` for the tombstone, `Err(_) => RefusalMark::Absent` for
    /// the kept marker).
    #[test]
    fn rescue_refusal_row11_unreadable_marker_state_never_installs_in_any_reader() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = kept_prelock_record(base, id, &credential("fresh-login", 200), context(20));
        let fault = rescue::refusal_faults::MarkerReadFault::arm();
        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        let blocks = rescue::rescue_blocks_refresh(base, id);
        let state = rescue::rescue_pending_state(base, id);
        drop(fault);
        assert!(matches!(adopted, Ok(false)), "got {adopted:?}");
        assert!(record.exists(), "the record must stay pending");
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial")
        );
        assert!(blocks, "an unknown marker state must block refresh");
        assert!(
            matches!(state, Some(rescue::RescuePendingState::Unadoptable)),
            "{state:?}"
        );
    }

    /// Row 12 (kept-marker default): a pre-lock record whose writer died with
    /// no kept marker is quarantined; the same record KEPT is adopted.
    ///
    /// RED mutation: in `refusal_mark`, ignore `record.prelock` (treat every
    /// record as not defaulted).
    #[test]
    fn rescue_refusal_row12_unkept_prelock_record_is_quarantined_kept_one_adopts() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        // The writer crashed: the handle (and its guard) is gone, no marker.
        let crashed = prelock_record(base, id, &credential("crashed-login", 200), context(20));
        let crashed_path = crashed.path.clone();
        drop(crashed);
        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(matches!(adopted, Ok(false)), "got {adopted:?}");
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial")
        );
        assert!(quarantined(&crashed_path));

        kept_prelock_record(base, id, &credential("kept-login", 300), context(20));
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-kept-login")
        );
    }

    /// Row 13 (sec MED-3): a kept login record whose pair another identity
    /// already holds is superseded at adoption — one grant, one identity.
    ///
    /// RED mutation: delete the `rescue_pair_held_elsewhere` check in the
    /// canonical-present Login arm of `rescue_source_gate`.
    #[test]
    fn rescue_refusal_row13_pair_held_by_another_identity_never_installs() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let x = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let y = commit(base, 2, &credential("dup", 50), context(30)).identity();
        assert_ne!(x, y);
        let record = kept_prelock_record(base, x, &credential("dup", 200), context(20));

        let adopted = rescue::adopt_rescue_record(base, &x.to_string());
        assert!(matches!(adopted, Ok(false)), "got {adopted:?}");
        assert_eq!(
            canonical_access(base, x).as_deref(),
            Some("fake-access-initial")
        );
        assert!(quarantined(&record));
    }

    /// Row 14 (sec LOW-1 lead): the refresh-lineage writer finds its canonical
    /// UNREADABLE under the lock. That decides nothing about the rotated
    /// pair, whose old refresh token is already spent: the rescue record is
    /// retained, and adoption installs it once the canonical reads again.
    ///
    /// RED mutation: remove the record in the gate's `Unreadable` arm.
    #[test]
    fn rescue_refusal_row14_refresh_gate_unreadable_canonical_keeps_rotated_pair() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let initial = credential("initial", 100);
        let id = commit(base, 1, &initial, context(20)).identity();
        let captured = capture_anthropic_binding(base, slot(1)).unwrap();
        let prepared = prepare_anthropic_refresh(base, &captured).unwrap();
        let (rotated, lineage) = refresh_captured_anthropic_with(
            &prepared,
            initial.anthropic().unwrap(),
            |_, _| {
                Ok(br#"{"access_token":"fake-access-rotated","refresh_token":"fake-refresh-rotated","expires_in":3600}"#.to_vec())
            },
        )
        .unwrap();
        let canonical = identity_store::credentials_path_for(base, id);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        let original = std::fs::read(&canonical).unwrap();
        std::fs::write(&canonical, b"{not json").unwrap();

        let result = file::save_anthropic_canonical_guarded(
            base,
            &captured,
            &rotated,
            AnthropicWriteWitness::RefreshLineage(&lineage),
            None,
        );
        assert!(
            result.is_err(),
            "an unreadable canonical refuses the in-place write"
        );
        assert!(
            rescue::rescue_record_pending(&identity_dir).is_some(),
            "the rotated pair's only copy must be retained"
        );

        std::fs::write(&canonical, &original).unwrap();
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-rotated")
        );
    }

    /// Row 15 (writer parity, schema gate, NO canonical): a kept login record
    /// stays pending while the store schema is newer, and adopts once it is
    /// current.
    ///
    /// RED mutation: delete `rescue_store_schema_permits(base)?` in the
    /// no-canonical Login arm of `rescue_source_gate`.
    #[test]
    fn rescue_refusal_row15_absent_canonical_newer_store_schema_stays_pending() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = kept_prelock_record(base, id, &credential("fresh-login", 200), context(20));
        std::fs::remove_file(identity_store::credentials_path_for(base, id)).unwrap();
        let current = crate::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT;
        write_store_schema(base, current + 1);

        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(adopted.is_err(), "got {adopted:?}");
        assert!(record.exists(), "the record must stay pending");
        assert_eq!(canonical_access(base, id), None);

        write_store_schema(base, current);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    /// Row 16 (sec LOW-2): adoption sweeps markers and a free writer sidecar
    /// whose record is gone, and leaves a LIVE writer's sidecar alone.
    ///
    /// RED mutation: delete the `sweep_orphan_rescue_artifacts` call.
    #[test]
    fn rescue_refusal_row16_adoption_sweeps_orphan_artifacts() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        for name in [
            "rescue-orphan.json.refused",
            "rescue-orphan.json.kept",
            "rescue-orphan.json.writer",
        ] {
            std::fs::write(identity_dir.join(name), b"x").unwrap();
        }
        // A LIVE writer as `write_login_prelock_rescue` makes one: the sidecar
        // file created explicitly (Windows locks create no file), its lock
        // held on another thread (Windows locks are re-entrant per thread).
        let live = identity_dir.join("rescue-live.json.writer");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&live)
            .unwrap();
        let _held = crate::platform::lock::HeldOnOtherThread::hold(&live);

        let _ = rescue::adopt_rescue_record(base, &id.to_string());
        let left: Vec<String> = dir_entry_names(&identity_dir)
            .into_iter()
            .filter(|name| name.starts_with("rescue-"))
            .collect();
        assert_eq!(
            left,
            vec!["rescue-live.json.writer".to_string()],
            "{left:?}"
        );
    }

    /// The single pre-lock record in `id`'s directory.
    fn only_record(base: &Path, id: IdentityId) -> PathBuf {
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        let records: Vec<PathBuf> = dir_entry_names(&identity_dir)
            .into_iter()
            .filter(|name| name.starts_with("rescue-") && name.ends_with(".json"))
            .map(|name| identity_dir.join(name))
            .collect();
        assert_eq!(records.len(), 1, "{records:?}");
        records.into_iter().next().unwrap()
    }

    /// Row 17 (corr MED-2): a HANDED pre-lock record whose writer cannot take
    /// the canonical lock is KEPT (marker written), and adoption installs it.
    ///
    /// RED mutation: delete `keep_handed(..)` in the canonical-lock `Err` arm
    /// of `save_anthropic_login_target_locked`.
    #[test]
    fn rescue_refusal_row17_handed_record_kept_on_canonical_lock_timeout() {
        use crate::credentials::rescue;
        use std::time::Duration;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        let canonical = identity_store::credentials_path_for(base, id);
        let holder = hold_lock_on_other_thread(&canonical.with_extension("lock"));
        let budget = rescue::CommitBudgetOverrideGuard::install(Duration::from_millis(300));
        let result = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        );
        drop(budget);
        assert!(
            result.is_err(),
            "a held canonical lock defers the login write"
        );
        let record = only_record(base, id);
        assert!(
            record.with_extension("json.kept").exists(),
            "keep path wrote no marker"
        );

        drop(holder);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    /// Row 18 (corr MED-2 variant): the writer's holder scan cannot read a
    /// sibling canonical: the handed record is KEPT, and adoption installs it
    /// once the sibling reads again.
    ///
    /// RED mutation: delete `keep_prelock_rescue(..)` in the
    /// `SiblingCustodyUnreadable` arm.
    #[test]
    fn rescue_refusal_row18_handed_record_kept_on_unreadable_sibling() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let sibling = commit(base, 2, &credential("sibling", 100), context(30)).identity();
        let sibling_canonical = identity_store::credentials_path_for(base, sibling);
        let sibling_bytes = std::fs::read(&sibling_canonical).unwrap();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        std::fs::write(&sibling_canonical, b"{not json").unwrap();
        let result = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        );
        assert!(
            result.is_err(),
            "an unreadable sibling refuses the login write"
        );
        let record = only_record(base, id);
        assert!(
            record.with_extension("json.kept").exists(),
            "keep path wrote no marker"
        );

        std::fs::write(&sibling_canonical, &sibling_bytes).unwrap();
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    /// Row 19 (corr MED-1): the login writer's OWN stored-context read fails
    /// transiently: the handed record is KEPT, not refused, and adopts.
    ///
    /// RED mutation: route that read's `Err` to `discard_prelock_rescue`.
    #[test]
    fn rescue_refusal_row19_writer_context_read_fault_keeps_handed_record() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let incoming = credential("fresh-login", 200);
        let prior = capture_login_prior(base, slot(1)).unwrap();
        file::arm_writer_context_read_fault();
        let result = commit_anthropic_login_with(
            base,
            slot(1),
            &incoming,
            &transport(&incoming, context(20)),
            None,
            prior,
        );
        assert!(
            result.is_err(),
            "an unreadable stored context refuses the login write"
        );
        let record = only_record(base, id);
        assert!(
            record.with_extension("json.kept").exists(),
            "keep path wrote no marker"
        );
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    /// Row 20 (sec L-1): while the profiles store is held (a publication may
    /// be running its own holder scan), adoption leaves a login record
    /// pending instead of installing; it installs once the store is free.
    ///
    /// RED mutation: drop the `profiles_guard.is_none()` deferral.
    #[test]
    fn rescue_refusal_row20_login_adoption_defers_while_profiles_store_is_held() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let record = kept_prelock_record(base, id, &credential("fresh-login", 200), context(20));
        let holder = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        let adopted = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(matches!(adopted, Ok(false)), "got {adopted:?}");
        assert!(record.exists(), "the record must stay pending");
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-initial")
        );

        drop(holder);
        assert!(rescue::adopt_rescue_record(base, &id.to_string()).unwrap());
        assert_eq!(
            canonical_access(base, id).as_deref(),
            Some("fake-access-fresh-login")
        );
    }

    /// Row 21 (sec L-3): a planted DANGLING symlink named like a writer
    /// sidecar is unlinked by the sweep, and nothing is created at its target.
    #[cfg(unix)]
    #[test]
    fn rescue_refusal_row21_sweep_never_follows_a_planted_sidecar_symlink() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        let target = base.join("outside-target");
        let link = identity_dir.join("rescue-planted.json.writer");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let _ = rescue::adopt_rescue_record(base, &id.to_string());
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "the planted link is removed"
        );
        assert!(
            !target.exists(),
            "the sweep created a file through the link"
        );
    }

    /// Row 22 (sec L-4): a pre-lock record carries the DISTINCT pre-lock
    /// schema, which every reader older than the refusal default treats as
    /// unknown (quarantine), never as a v2 record to re-gate.
    ///
    /// RED mutation: write `RESCUE_SCHEMA` in `write_prelock_rescue_record`.
    #[test]
    fn rescue_refusal_row22_prelock_record_carries_its_own_schema() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let handle = prelock_record(base, id, &credential("fresh-login", 200), context(20));
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&handle.path).unwrap()).unwrap();
        assert_eq!(
            raw["schema"],
            serde_json::json!(rescue::RESCUE_SCHEMA_PRELOCK)
        );
        assert_ne!(rescue::RESCUE_SCHEMA_PRELOCK, rescue::RESCUE_SCHEMA);
        file::refuse_prelock_rescue(Some(handle));
    }

    /// Row 23 (corr LOW-3): a marker's orphaned §5a temp file
    /// (`<record>.json.tmp.<pid>.<n>`) is swept once its record is gone; a
    /// record-shaped temp name is not a marker temp and is left alone.
    ///
    /// RED mutation: make `orphan_artifact_record`'s temp branch return None.
    #[test]
    fn rescue_refusal_row23_sweep_removes_orphan_marker_temp_files() {
        use crate::credentials::rescue;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let id = commit(base, 1, &credential("initial", 100), context(20)).identity();
        let identity_dir = identity_store::credentials_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::write(identity_dir.join("rescue-orphan.json.tmp.123.4"), b"x").unwrap();
        std::fs::write(identity_dir.join("rescue-orphan.json.tmp.notpid.4"), b"x").unwrap();

        let _ = rescue::adopt_rescue_record(base, &id.to_string());
        let left: Vec<String> = dir_entry_names(&identity_dir)
            .into_iter()
            .filter(|name| name.starts_with("rescue-"))
            .collect();
        assert_eq!(
            left,
            vec!["rescue-orphan.json.tmp.notpid.4".to_string()],
            "{left:?}"
        );
    }
}

#[cfg(test)]
mod retained_writer_regression_tests {
    use super::*;

    #[test]
    fn metadata_temp_collision_preserves_foreign_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let tmp = dir.path().join("identity.tmp");
        std::fs::write(&path, b"old metadata").unwrap();
        std::fs::write(&tmp, b"foreign temporary entry").unwrap();
        assert!(matches!(
            publish_metadata_bytes_at(&path, b"{}", tmp.clone()),
            Err(IdentityError::Io)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"old metadata");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"foreign temporary entry");
    }
}
