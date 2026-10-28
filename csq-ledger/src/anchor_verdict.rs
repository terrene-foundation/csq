//! Authority-signed anchor verdicts for consumers that need a fresh,
//! tenant-bound decision rather than an unauthenticated JSON boolean.
//!
//! A verdict binds the exact inclusion-proof anchor (record id, leaf hash,
//! log index, and checkpoint commitment), the requesting tenant, a bounded
//! freshness window, and an authority-monotonic version.  The pre-image has a
//! separate domain from checkpoints and records, so a signature for one CSQ
//! protocol artifact cannot be replayed as another.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::signing::{derive_key_id, verify, ServerSigningKey};

/// Wire schema carried by every verdict.
pub const ANCHOR_VERDICT_SCHEMA: &str = "csq-ledger-anchor-verdict/v1";
/// Domain separator for Ed25519 verdict signatures.
const ANCHOR_VERDICT_DOMAIN: &str = "csq-ledger-anchor-verdict/v1";
/// Wire schema for durable, authority-signed revocations.
pub const ANCHOR_REVOCATION_SCHEMA: &str = "csq-ledger-anchor-revocation/v1";
/// Domain separator for Ed25519 revocation signatures.
const ANCHOR_REVOCATION_DOMAIN: &str = "csq-ledger-anchor-revocation/v1";
/// Wire schema for an externally durable, one-time verifier bootstrap.
pub const VERIFIER_BOOTSTRAP_SCHEMA: &str = "csq-ledger-verifier-bootstrap/v1";
/// Domain separator for verifier-bootstrap signatures.
const VERIFIER_BOOTSTRAP_DOMAIN: &str = "csq-ledger-verifier-bootstrap/v1";
/// A verdict is intentionally short lived so replay remains bounded.
pub const ANCHOR_VERDICT_TTL_SECS: i64 = 300;
/// Small clock skew allowance for a verifier that compares the signed issue time.
const MAX_FUTURE_ISSUED_AT_SECS: i64 = 30;
/// Tenant ids are identifiers, not free-form display data.
pub const MAX_TENANT_ID_BYTES: usize = 128;
/// Stable service namespace used to redeem exactly one replay-state bootstrap.
pub const MAX_VERIFIER_ID_BYTES: usize = 128;
/// A bootstrap response is only useful to the waiting client for a short window.
pub const VERIFIER_BOOTSTRAP_TTL_SECS: i64 = 300;

/// The authority's disposition for a verified log anchor.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorVerdictStatus {
    /// The anchor was inclusion-proof verified and has no signed revocation.
    Valid,
    /// The anchor was inclusion-proof verified but is explicitly revoked.
    Revoked,
}

impl AnchorVerdictStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Revoked => "revoked",
        }
    }
}

/// The inclusion-proof material the authority verifies before it signs a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAnchor {
    /// Immutable record id in the append-only log.
    pub anchor_id: String,
    /// RFC 6962 leaf hash of the canonical record bytes.
    pub leaf_hash: String,
    /// The anchor's assigned log index.
    pub log_index: u64,
    /// Tree size of the signed checkpoint that verified the inclusion proof.
    pub checkpoint_tree_size: u64,
    /// Root hash of the signed checkpoint that verified the inclusion proof.
    pub checkpoint_root_hash: String,
}

/// A fresh, CSQ-authority-signed answer about one verified anchor for one tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorVerdict {
    /// Stable schema identifier.
    pub schema: String,
    /// Exact verified anchor and checkpoint commitment.
    #[serde(flatten)]
    pub anchor: VerifiedAnchor,
    /// Tenant for which this verdict was issued.
    pub tenant_id: String,
    /// `valid` or `revoked`.
    pub status: AnchorVerdictStatus,
    /// RFC 3339 issue time, canonical UTC seconds precision.
    pub issued_at: String,
    /// RFC 3339 exclusive expiry time, canonical UTC seconds precision.
    pub expires_at: String,
    /// Globally monotonic authority version; consumers reject a lower version.
    pub version: u64,
    /// Authority key id clients pin out of band.
    pub signed_by_key_id: String,
    /// Authority public key (never private material).
    pub public_key: String,
    /// Ed25519 signature over the domain-separated verdict pre-image.
    pub signature: String,
}

/// A permanent, authority-signed revocation fact stored append-only by the ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorRevocation {
    /// Stable schema identifier.
    pub schema: String,
    /// Revoked immutable log record id.
    pub anchor_id: String,
    /// Tenant to which the revocation applies.
    pub tenant_id: String,
    /// RFC 3339 revocation time, canonical UTC seconds precision.
    pub revoked_at: String,
    /// Globally monotonic authority version.
    pub version: u64,
    /// Authority key id clients pin out of band.
    pub signed_by_key_id: String,
    /// Authority public key (never private material).
    pub public_key: String,
    /// Ed25519 signature over the domain-separated revocation pre-image.
    pub signature: String,
}

/// A durable, authority-signed redemption of a verifier's sole bootstrap.
///
/// The caller contributes a fresh challenge. Consumers verify that challenge
/// before creating local replay state, so a recorded successful response cannot
/// be replayed after that local state is deleted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifierBootstrap {
    /// Stable schema identifier.
    pub schema: String,
    /// Operator-provisioned, stable verifier namespace.
    pub verifier_id: String,
    /// Fresh client challenge, encoded as 32 lower-case random bytes in hex.
    pub challenge: String,
    /// Globally monotonic authority version.
    pub version: u64,
    /// Canonical UTC timestamp at redemption.
    pub issued_at: String,
    /// Canonical UTC expiry for the caller challenge-bound response.
    pub expires_at: String,
    /// Authority key id clients pin out of band.
    pub signed_by_key_id: String,
    /// Authority public key (never private material).
    pub public_key: String,
    /// Ed25519 signature over the domain-separated redemption pre-image.
    pub signature: String,
}

/// A reason a client must refuse an authority verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorVerdictError {
    /// The supplied schema is not the one this verifier understands.
    #[error("unsupported anchor verdict schema")]
    UnsupportedSchema,
    /// A signed field violated its canonical identifier constraints.
    #[error("invalid anchor verdict fields")]
    InvalidFields,
    /// The authority key did not match the client pin.
    #[error("anchor verdict authority key mismatch")]
    AuthorityKeyMismatch,
    /// The public key, key id, or signature could not be verified.
    #[error("invalid anchor verdict signature")]
    InvalidSignature,
    /// The verdict was for another anchor.
    #[error("anchor verdict bound to a different anchor")]
    AnchorMismatch,
    /// The verdict was for another tenant.
    #[error("anchor verdict bound to a different tenant")]
    TenantMismatch,
    /// The bootstrap receipt was minted for another verifier namespace.
    #[error("verifier bootstrap bound to a different verifier")]
    VerifierMismatch,
    /// The bootstrap receipt answers a different challenge than this request's.
    #[error("verifier bootstrap answers a different challenge")]
    ChallengeMismatch,
    /// A replayed verdict is no longer fresh.
    #[error("anchor verdict expired")]
    Expired,
    /// The authority claimed an implausibly future issue time.
    #[error("anchor verdict issued in the future")]
    IssuedInFuture,
    /// The signed freshness window is malformed or exceeds the protocol maximum.
    #[error("invalid anchor verdict freshness window")]
    InvalidFreshnessWindow,
    /// The verdict version is not greater than the client's accepted version.
    #[error("anchor verdict version rolled back")]
    SequenceRollback,
    /// A validly signed status still requires a consumer-side deny.
    #[error("anchor verdict revoked")]
    Revoked,
}

/// Schema tag for [`AnchorVerdictTrackerSnapshot`], so a future on-disk
/// format change is detectable (`from_snapshot` rejects an unrecognized
/// value) rather than silently mis-parsed into a tracker that accepts a
/// rolled-back version.
pub const ANCHOR_VERDICT_TRACKER_SNAPSHOT_SCHEMA: &str =
    "csq-ledger-anchor-verdict-tracker-snapshot/v1";

/// One `(anchor_id, tenant_id) -> highest accepted version` row of a
/// persisted [`AnchorVerdictTracker`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorVerdictTrackerEntry {
    /// The anchor half of the tracked key.
    pub anchor_id: String,
    /// The tenant half of the tracked key.
    pub tenant_id: String,
    /// Greatest version accepted so far for this `(anchor_id, tenant_id)` pair.
    pub highest_version: u64,
}

/// A durable, serializable snapshot of an [`AnchorVerdictTracker`]'s state.
///
/// `AnchorVerdictTracker::highest_versions` is keyed by a `(String, String)`
/// tuple. `serde_json` cannot serialize a tuple-keyed map as a JSON object —
/// object keys must be strings — so a bare `#[derive(Serialize)]` on the
/// tracker does NOT work; this flat, explicit-field row shape is the
/// serializable form the doc comment above tells callers to persist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorVerdictTrackerSnapshot {
    /// Stable schema identifier; [`AnchorVerdictTracker::from_snapshot`]
    /// rejects any other value rather than guessing at the row shape.
    pub schema: String,
    /// One row per `(anchor_id, tenant_id)` pair with its highest accepted
    /// version. Order is not significant.
    pub entries: Vec<AnchorVerdictTrackerEntry>,
}

/// Tracks the greatest accepted version per `(anchor, tenant)` pair.
///
/// Persist this state alongside the consumer's pinned authority key via
/// [`AnchorVerdictTracker::snapshot`] / [`AnchorVerdictTracker::from_snapshot`].
/// A process that discards it cannot detect rollback across restarts, so it
/// must fail closed until it reacquires a fresh authority verdict.
#[derive(Debug, Default)]
pub struct AnchorVerdictTracker {
    highest_versions: BTreeMap<(String, String), u64>,
}

impl AnchorVerdictTracker {
    /// Verifies a verdict and rejects any non-increasing version for the same
    /// anchor and tenant. Replaying an identical response is not an acceptance
    /// event; callers should retain the already-verified response until expiry.
    pub fn accept(
        &mut self,
        verdict: &AnchorVerdict,
        expected_anchor_id: &str,
        expected_tenant_id: &str,
        pinned_key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<AnchorVerdictStatus, AnchorVerdictError> {
        let key = (expected_anchor_id.to_owned(), expected_tenant_id.to_owned());
        let minimum_version = self.highest_versions.get(&key).copied();
        let status = verdict.verify_for(
            expected_anchor_id,
            expected_tenant_id,
            pinned_key_id,
            minimum_version,
            now,
        )?;
        self.highest_versions
            .entry(key)
            .and_modify(|highest| *highest = (*highest).max(verdict.version))
            .or_insert(verdict.version);
        Ok(status)
    }

    /// Returns the highest version accepted so far for `(anchor_id,
    /// tenant_id)`, or `None` if no verdict has been accepted for that pair.
    #[must_use]
    pub fn highest_version(&self, anchor_id: &str, tenant_id: &str) -> Option<u64> {
        self.highest_versions
            .get(&(anchor_id.to_owned(), tenant_id.to_owned()))
            .copied()
    }

    /// Serializes the tracker's current accept-state to a durable,
    /// JSON-serializable snapshot. Persist the result; restore it on the
    /// next process start via [`Self::from_snapshot`] before accepting any
    /// verdict, so a restart cannot reset rollback protection.
    #[must_use]
    pub fn snapshot(&self) -> AnchorVerdictTrackerSnapshot {
        AnchorVerdictTrackerSnapshot {
            schema: ANCHOR_VERDICT_TRACKER_SNAPSHOT_SCHEMA.to_owned(),
            entries: self
                .highest_versions
                .iter()
                .map(
                    |((anchor_id, tenant_id), highest_version)| AnchorVerdictTrackerEntry {
                        anchor_id: anchor_id.clone(),
                        tenant_id: tenant_id.clone(),
                        highest_version: *highest_version,
                    },
                )
                .collect(),
        }
    }

    /// Restores a tracker from a snapshot previously produced by
    /// [`Self::snapshot`]. Rejects a snapshot carrying any schema other than
    /// [`ANCHOR_VERDICT_TRACKER_SNAPSHOT_SCHEMA`] with
    /// [`AnchorVerdictError::UnsupportedSchema`] — a silently-accepted format
    /// change could restore a tracker that has forgotten a real high-water
    /// mark, which would let a replayed lower-version verdict pass again.
    pub fn from_snapshot(
        snapshot: AnchorVerdictTrackerSnapshot,
    ) -> Result<Self, AnchorVerdictError> {
        if snapshot.schema != ANCHOR_VERDICT_TRACKER_SNAPSHOT_SCHEMA {
            return Err(AnchorVerdictError::UnsupportedSchema);
        }
        let mut highest_versions = BTreeMap::new();
        for entry in snapshot.entries {
            highest_versions
                .entry((entry.anchor_id, entry.tenant_id))
                .and_modify(|highest: &mut u64| *highest = (*highest).max(entry.highest_version))
                .or_insert(entry.highest_version);
        }
        Ok(Self { highest_versions })
    }
}

/// Validates a tenant identifier before it enters a signed pre-image or disk log.
pub fn validate_tenant_id(tenant_id: &str) -> Result<(), AnchorVerdictError> {
    if tenant_id.is_empty() || tenant_id.len() > MAX_TENANT_ID_BYTES {
        return Err(AnchorVerdictError::InvalidFields);
    }
    if !tenant_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(AnchorVerdictError::InvalidFields);
    }
    Ok(())
}

/// Validates the stable service namespace before it enters authority storage.
pub fn validate_verifier_id(verifier_id: &str) -> Result<(), AnchorVerdictError> {
    if verifier_id.is_empty() || verifier_id.len() > MAX_VERIFIER_ID_BYTES {
        return Err(AnchorVerdictError::InvalidFields);
    }
    if !verifier_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(AnchorVerdictError::InvalidFields);
    }
    Ok(())
}

/// Validates the unpredictable request binding for one bootstrap redemption.
pub fn validate_bootstrap_challenge(challenge: &str) -> Result<(), AnchorVerdictError> {
    if !is_lower_hex(challenge, 64) {
        return Err(AnchorVerdictError::InvalidFields);
    }
    Ok(())
}

impl AnchorVerdict {
    /// Creates a short-lived signed verdict after the service has verified the
    /// record's inclusion proof against the bound checkpoint.
    pub fn sign(
        anchor: VerifiedAnchor,
        tenant_id: String,
        status: AnchorVerdictStatus,
        version: u64,
        issued_at: DateTime<Utc>,
        key: &ServerSigningKey,
    ) -> Result<Self, AnchorVerdictError> {
        validate_anchor(&anchor)?;
        validate_tenant_id(&tenant_id)?;
        let issued_at = timestamp(issued_at);
        let expires_at =
            timestamp(parse_timestamp(&issued_at)? + Duration::seconds(ANCHOR_VERDICT_TTL_SECS));
        let mut verdict = Self {
            schema: ANCHOR_VERDICT_SCHEMA.to_owned(),
            anchor,
            tenant_id,
            status,
            issued_at,
            expires_at,
            version,
            signed_by_key_id: key.key_id().to_owned(),
            public_key: hex::encode(key.public_key_bytes()),
            signature: String::new(),
        };
        verdict.signature = hex::encode(key.sign(&anchor_verdict_preimage(&verdict)?));
        Ok(verdict)
    }

    /// Checks signature, authority pin, expected binding, freshness, and
    /// monotonic version. `Ok(Revoked)` is cryptographically valid but MUST be
    /// treated as a deny by consumers.
    pub fn verify_for(
        &self,
        expected_anchor_id: &str,
        expected_tenant_id: &str,
        pinned_key_id: &str,
        minimum_version: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<AnchorVerdictStatus, AnchorVerdictError> {
        if self.schema != ANCHOR_VERDICT_SCHEMA {
            return Err(AnchorVerdictError::UnsupportedSchema);
        }
        validate_anchor(&self.anchor)?;
        validate_tenant_id(&self.tenant_id)?;
        if self.anchor.anchor_id != expected_anchor_id {
            return Err(AnchorVerdictError::AnchorMismatch);
        }
        if self.tenant_id != expected_tenant_id {
            return Err(AnchorVerdictError::TenantMismatch);
        }
        if self.signed_by_key_id != pinned_key_id {
            return Err(AnchorVerdictError::AuthorityKeyMismatch);
        }
        self.verify_signature_with_authority(pinned_key_id)?;
        let issued_at = parse_timestamp(&self.issued_at)?;
        let expires_at = parse_timestamp(&self.expires_at)?;
        let window = expires_at.signed_duration_since(issued_at);
        if window <= Duration::zero() || window > Duration::seconds(ANCHOR_VERDICT_TTL_SECS) {
            return Err(AnchorVerdictError::InvalidFreshnessWindow);
        }
        if issued_at > now + Duration::seconds(MAX_FUTURE_ISSUED_AT_SECS) {
            return Err(AnchorVerdictError::IssuedInFuture);
        }
        if now >= expires_at {
            return Err(AnchorVerdictError::Expired);
        }
        if minimum_version.is_some_and(|minimum| self.version <= minimum) {
            return Err(AnchorVerdictError::SequenceRollback);
        }
        Ok(self.status)
    }

    /// Verifies only the schema, structural fields, and authority signature.
    /// Storage recovery uses this path because persisted historical verdicts are
    /// expected to have expired by the next server start.
    pub fn verify_signature_with_authority(
        &self,
        expected_key_id: &str,
    ) -> Result<(), AnchorVerdictError> {
        if self.schema != ANCHOR_VERDICT_SCHEMA {
            return Err(AnchorVerdictError::UnsupportedSchema);
        }
        validate_anchor(&self.anchor)?;
        validate_tenant_id(&self.tenant_id)?;
        if self.signed_by_key_id != expected_key_id {
            return Err(AnchorVerdictError::AuthorityKeyMismatch);
        }
        verify_authority_signature(
            &self.signed_by_key_id,
            &self.public_key,
            &self.signature,
            &anchor_verdict_preimage(self)?,
        )
    }

    /// Verifies the verdict and turns a signed revoked status into a hard deny.
    pub fn ensure_servable(
        &self,
        expected_anchor_id: &str,
        expected_tenant_id: &str,
        pinned_key_id: &str,
        minimum_version: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<(), AnchorVerdictError> {
        match self.verify_for(
            expected_anchor_id,
            expected_tenant_id,
            pinned_key_id,
            minimum_version,
            now,
        )? {
            AnchorVerdictStatus::Valid => Ok(()),
            AnchorVerdictStatus::Revoked => Err(AnchorVerdictError::Revoked),
        }
    }
}

impl AnchorRevocation {
    /// Creates a permanent signed revocation fact for one tenant-bound anchor.
    pub fn sign(
        anchor_id: String,
        tenant_id: String,
        version: u64,
        revoked_at: DateTime<Utc>,
        key: &ServerSigningKey,
    ) -> Result<Self, AnchorVerdictError> {
        validate_anchor_id(&anchor_id)?;
        validate_tenant_id(&tenant_id)?;
        let mut revocation = Self {
            schema: ANCHOR_REVOCATION_SCHEMA.to_owned(),
            anchor_id,
            tenant_id,
            revoked_at: timestamp(revoked_at),
            version,
            signed_by_key_id: key.key_id().to_owned(),
            public_key: hex::encode(key.public_key_bytes()),
            signature: String::new(),
        };
        revocation.signature = hex::encode(key.sign(&anchor_revocation_preimage(&revocation)?));
        Ok(revocation)
    }

    /// Verifies the durable revocation against the expected CSQ authority key.
    pub fn verify_with_authority(&self, expected_key_id: &str) -> Result<(), AnchorVerdictError> {
        if self.schema != ANCHOR_REVOCATION_SCHEMA {
            return Err(AnchorVerdictError::UnsupportedSchema);
        }
        validate_anchor_id(&self.anchor_id)?;
        validate_tenant_id(&self.tenant_id)?;
        parse_timestamp(&self.revoked_at)?;
        if self.signed_by_key_id != expected_key_id {
            return Err(AnchorVerdictError::AuthorityKeyMismatch);
        }
        verify_authority_signature(
            &self.signed_by_key_id,
            &self.public_key,
            &self.signature,
            &anchor_revocation_preimage(self)?,
        )
    }
}

impl VerifierBootstrap {
    /// Signs one durable redemption for an exact verifier namespace and nonce.
    pub fn sign(
        verifier_id: String,
        challenge: String,
        version: u64,
        issued_at: DateTime<Utc>,
        key: &ServerSigningKey,
    ) -> Result<Self, AnchorVerdictError> {
        validate_verifier_id(&verifier_id)?;
        validate_bootstrap_challenge(&challenge)?;
        let issued_at = timestamp(issued_at);
        let expires_at = timestamp(
            parse_timestamp(&issued_at)? + Duration::seconds(VERIFIER_BOOTSTRAP_TTL_SECS),
        );
        let mut bootstrap = Self {
            schema: VERIFIER_BOOTSTRAP_SCHEMA.to_owned(),
            verifier_id,
            challenge,
            version,
            issued_at,
            expires_at,
            signed_by_key_id: key.key_id().to_owned(),
            public_key: hex::encode(key.public_key_bytes()),
            signature: String::new(),
        };
        bootstrap.signature = hex::encode(key.sign(&verifier_bootstrap_preimage(&bootstrap)?));
        Ok(bootstrap)
    }

    /// Verifies only the schema, structural fields, freshness-window SHAPE, and
    /// authority signature — deliberately NOT whether the window is currently
    /// open. Storage recovery uses this path: redemption records are durable by
    /// construction (that is what makes bootstrap one-time across a consumer
    /// deleting its local replay state), so every persisted record is expected
    /// to be far older than `VERIFIER_BOOTSTRAP_TTL_SECS` by the next server
    /// start. Adding a `now` check HERE would make the server fail to boot with
    /// `CorruptAuthorityAnchorState` as soon as any bootstrap aged past the TTL.
    ///
    /// Consumers deciding whether to ACCEPT a bootstrap MUST call
    /// [`Self::verify_for_redemption`] instead — this method alone cannot tell a
    /// live record from a long-expired one. Mirrors the same split
    /// `AnchorVerdict` draws between `verify_signature_with_authority` and
    /// `verify_for` — including the NAME, because the previous name
    /// (`verify_with_authority`) read as a complete acceptance check and was
    /// used as one.
    pub fn verify_signature_with_authority(
        &self,
        expected_key_id: &str,
    ) -> Result<(), AnchorVerdictError> {
        if self.schema != VERIFIER_BOOTSTRAP_SCHEMA {
            return Err(AnchorVerdictError::UnsupportedSchema);
        }
        validate_verifier_id(&self.verifier_id)?;
        validate_bootstrap_challenge(&self.challenge)?;
        parse_timestamp(&self.issued_at)?;
        let expires_at = parse_timestamp(&self.expires_at)?;
        let issued_at = parse_timestamp(&self.issued_at)?;
        if !(Duration::zero() < expires_at - issued_at
            && expires_at - issued_at <= Duration::seconds(VERIFIER_BOOTSTRAP_TTL_SECS))
        {
            return Err(AnchorVerdictError::InvalidFreshnessWindow);
        }
        if self.signed_by_key_id != expected_key_id {
            return Err(AnchorVerdictError::AuthorityKeyMismatch);
        }
        verify_authority_signature(
            &self.signed_by_key_id,
            &self.public_key,
            &self.signature,
            &verifier_bootstrap_preimage(self)?,
        )
    }

    /// Full acceptance check for a consumer redeeming a bootstrap — the
    /// bootstrap analogue of [`AnchorVerdict::verify_for`], and the ONLY method
    /// a consumer may decide on.
    ///
    /// [`Self::verify_signature_with_authority`] enforces NONE of the three
    /// bindings this design rests on: not that the receipt is still live, not
    /// that it is addressed to THIS verifier, and not that it answers THIS
    /// request's challenge. It only checks those fields are well-formed. So on
    /// its own it is fail-open by omission — any valid receipt from the pinned
    /// authority verifies, including one minted for a different `verifier_id`
    /// or the consumer's own receipt from months ago recovered from a proxy log
    /// or backup. A consumer that then creates fresh replay state believes it
    /// holds newly-minted bootstrap authority while its rollback floor is
    /// empty, which is precisely what the challenge and `expires_at` were added
    /// to prevent.
    ///
    /// The future-skew allowance matches `AnchorVerdict::verify_for` so a
    /// consumer whose clock trails the server's by a few seconds does not
    /// spuriously reject a just-issued record.
    pub fn verify_for_redemption(
        &self,
        expected_verifier_id: &str,
        expected_challenge: &str,
        pinned_key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AnchorVerdictError> {
        self.verify_signature_with_authority(pinned_key_id)?;
        if self.verifier_id != expected_verifier_id {
            return Err(AnchorVerdictError::VerifierMismatch);
        }
        // Constant-time: the challenge is the anti-replay secret binding this
        // receipt to this request, so it is compared without an early exit.
        if !constant_time_eq(self.challenge.as_bytes(), expected_challenge.as_bytes()) {
            return Err(AnchorVerdictError::ChallengeMismatch);
        }
        let issued_at = parse_timestamp(&self.issued_at)?;
        let expires_at = parse_timestamp(&self.expires_at)?;
        if issued_at > now + Duration::seconds(MAX_FUTURE_ISSUED_AT_SECS) {
            return Err(AnchorVerdictError::IssuedInFuture);
        }
        if now >= expires_at {
            return Err(AnchorVerdictError::Expired);
        }
        Ok(())
    }
}

/// Length-then-XOR-fold comparison with no early exit on the first differing
/// byte. `subtle` is deliberately not pulled in for one comparison; both inputs
/// here are 64-char lower-hex by construction, so the length branch leaks only
/// a well-formedness fact the caller already validated.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn anchor_verdict_preimage(verdict: &AnchorVerdict) -> Result<Vec<u8>, AnchorVerdictError> {
    validate_anchor(&verdict.anchor)?;
    validate_tenant_id(&verdict.tenant_id)?;
    Ok(format!(
        "{ANCHOR_VERDICT_DOMAIN}\nanchor_id={}\nleaf_hash={}\nlog_index={}\ncheckpoint_tree_size={}\ncheckpoint_root_hash={}\ntenant_id={}\nstatus={}\nissued_at={}\nexpires_at={}\nversion={}\n",
        verdict.anchor.anchor_id,
        verdict.anchor.leaf_hash,
        verdict.anchor.log_index,
        verdict.anchor.checkpoint_tree_size,
        verdict.anchor.checkpoint_root_hash,
        verdict.tenant_id,
        verdict.status.as_str(),
        verdict.issued_at,
        verdict.expires_at,
        verdict.version,
    )
    .into_bytes())
}

fn anchor_revocation_preimage(
    revocation: &AnchorRevocation,
) -> Result<Vec<u8>, AnchorVerdictError> {
    validate_anchor_id(&revocation.anchor_id)?;
    validate_tenant_id(&revocation.tenant_id)?;
    Ok(format!(
        "{ANCHOR_REVOCATION_DOMAIN}\nanchor_id={}\ntenant_id={}\nrevoked_at={}\nversion={}\n",
        revocation.anchor_id, revocation.tenant_id, revocation.revoked_at, revocation.version,
    )
    .into_bytes())
}

fn verifier_bootstrap_preimage(
    bootstrap: &VerifierBootstrap,
) -> Result<Vec<u8>, AnchorVerdictError> {
    validate_verifier_id(&bootstrap.verifier_id)?;
    validate_bootstrap_challenge(&bootstrap.challenge)?;
    Ok(format!(
        "{VERIFIER_BOOTSTRAP_DOMAIN}\nverifier_id={}\nchallenge={}\nissued_at={}\nexpires_at={}\nversion={}\n",
        bootstrap.verifier_id,
        bootstrap.challenge,
        bootstrap.issued_at,
        bootstrap.expires_at,
        bootstrap.version,
    )
    .into_bytes())
}

fn validate_anchor(anchor: &VerifiedAnchor) -> Result<(), AnchorVerdictError> {
    validate_anchor_id(&anchor.anchor_id)?;
    if !is_lower_hex(&anchor.leaf_hash, 64)
        || !is_lower_hex(&anchor.checkpoint_root_hash, 64)
        || anchor.checkpoint_tree_size == 0
        || anchor.log_index >= anchor.checkpoint_tree_size
    {
        return Err(AnchorVerdictError::InvalidFields);
    }
    Ok(())
}

fn validate_anchor_id(anchor_id: &str) -> Result<(), AnchorVerdictError> {
    if anchor_id.is_empty()
        || anchor_id.len() > 64
        || !anchor_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AnchorVerdictError::InvalidFields);
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, AnchorVerdictError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| AnchorVerdictError::InvalidFreshnessWindow)?;
    if timestamp(parsed) != value {
        return Err(AnchorVerdictError::InvalidFreshnessWindow);
    }
    Ok(parsed)
}

fn verify_authority_signature(
    key_id: &str,
    public_key: &str,
    signature: &str,
    preimage: &[u8],
) -> Result<(), AnchorVerdictError> {
    let public_key = hex::decode(public_key).map_err(|_| AnchorVerdictError::InvalidSignature)?;
    if public_key.len() != 32 {
        return Err(AnchorVerdictError::InvalidSignature);
    }
    let mut public_key_bytes = [0u8; 32];
    public_key_bytes.copy_from_slice(&public_key);
    if derive_key_id(&public_key_bytes) != key_id {
        return Err(AnchorVerdictError::InvalidSignature);
    }
    let signature = hex::decode(signature).map_err(|_| AnchorVerdictError::InvalidSignature)?;
    if signature.len() != 64 {
        return Err(AnchorVerdictError::InvalidSignature);
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&signature);
    if !verify(&public_key_bytes, preimage, &signature_bytes) {
        return Err(AnchorVerdictError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn key() -> ServerSigningKey {
        let dir = TempDir::new().unwrap();
        ServerSigningKey::load_or_generate(dir.path(), None).unwrap()
    }

    fn anchor() -> VerifiedAnchor {
        VerifiedAnchor {
            anchor_id: "01JCSQ0000000000000ANCHOR01".to_owned(),
            leaf_hash: "a".repeat(64),
            log_index: 4,
            checkpoint_tree_size: 5,
            checkpoint_root_hash: "b".repeat(64),
        }
    }

    fn verdict(status: AnchorVerdictStatus, version: u64, now: DateTime<Utc>) -> AnchorVerdict {
        let key = key();
        AnchorVerdict::sign(anchor(), "tenant-a".to_owned(), status, version, now, &key).unwrap()
    }

    #[test]
    fn forged_signature_is_refused() {
        let now = Utc::now();
        let mut signed = verdict(AnchorVerdictStatus::Valid, 1, now);
        let replacement = if signed.signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        signed.signature.replace_range(..1, replacement);
        assert_eq!(
            signed.verify_for(
                &anchor().anchor_id,
                "tenant-a",
                &signed.signed_by_key_id,
                None,
                now,
            ),
            Err(AnchorVerdictError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_anchor_or_tenant_is_refused_even_with_a_valid_signature() {
        let now = Utc::now();
        let signed = verdict(AnchorVerdictStatus::Valid, 1, now);
        assert_eq!(
            signed.verify_for(
                "another-anchor",
                "tenant-a",
                &signed.signed_by_key_id,
                None,
                now
            ),
            Err(AnchorVerdictError::AnchorMismatch)
        );
        assert_eq!(
            signed.verify_for(
                &anchor().anchor_id,
                "tenant-b",
                &signed.signed_by_key_id,
                None,
                now,
            ),
            Err(AnchorVerdictError::TenantMismatch)
        );
    }

    #[test]
    fn expired_verdict_is_refused() {
        let now = Utc::now();
        let signed = verdict(AnchorVerdictStatus::Valid, 1, now);
        assert_eq!(
            signed.verify_for(
                &anchor().anchor_id,
                "tenant-a",
                &signed.signed_by_key_id,
                None,
                now + Duration::seconds(ANCHOR_VERDICT_TTL_SECS),
            ),
            Err(AnchorVerdictError::Expired)
        );
    }

    #[test]
    fn sequence_rollback_is_refused() {
        let now = Utc::now();
        let signed = verdict(AnchorVerdictStatus::Valid, 4, now);
        assert_eq!(
            signed.verify_for(
                &anchor().anchor_id,
                "tenant-a",
                &signed.signed_by_key_id,
                Some(5),
                now,
            ),
            Err(AnchorVerdictError::SequenceRollback)
        );
        assert_eq!(
            signed.verify_for(
                &anchor().anchor_id,
                "tenant-a",
                &signed.signed_by_key_id,
                Some(4),
                now,
            ),
            Err(AnchorVerdictError::SequenceRollback),
            "an equal version could equivocate between valid and revoked"
        );
    }

    const VERIFIER: &str = "verifier-a";

    fn challenge() -> String {
        "c".repeat(64)
    }

    fn bootstrap(now: DateTime<Utc>) -> VerifierBootstrap {
        VerifierBootstrap::sign(VERIFIER.to_owned(), challenge(), 1, now, &key()).unwrap()
    }

    /// The two paths MUST disagree on a long-expired record, and that
    /// disagreement is the whole design: recovery accepts it, redemption does
    /// not. Asserting both directions on ONE record is what makes this a proof
    /// of the split rather than of either method alone.
    #[test]
    fn expired_bootstrap_is_recoverable_but_not_redeemable() {
        let issued = Utc::now();
        let signed = bootstrap(issued);
        let key_id = signed.signed_by_key_id.clone();
        let long_after = issued + Duration::seconds(VERIFIER_BOOTSTRAP_TTL_SECS * 10);

        assert_eq!(
            signed.verify_signature_with_authority(&key_id),
            Ok(()),
            "storage recovery MUST still accept a durable record after its \
             window closes — redemption records outlive their TTL by design, so \
             a `now` check here would fail the server's boot with \
             CorruptAuthorityAnchorState once any bootstrap aged past the TTL"
        );
        assert_eq!(
            signed.verify_for_redemption(VERIFIER, &challenge(), &key_id, long_after),
            Err(AnchorVerdictError::Expired),
            "a consumer MUST NOT accept a bootstrap whose signed window has closed"
        );
    }

    #[test]
    fn bootstrap_inside_its_window_is_redeemable() {
        let issued = Utc::now();
        let signed = bootstrap(issued);
        assert_eq!(
            signed.verify_for_redemption(
                VERIFIER,
                &challenge(),
                &signed.signed_by_key_id.clone(),
                issued
            ),
            Ok(())
        );
    }

    #[test]
    fn bootstrap_issued_beyond_the_skew_allowance_is_rejected() {
        let now = Utc::now();
        // Signed by a server whose clock runs far ahead of this consumer's.
        let signed = bootstrap(now + Duration::seconds(MAX_FUTURE_ISSUED_AT_SECS + 30));
        assert_eq!(
            signed.verify_for_redemption(
                VERIFIER,
                &challenge(),
                &signed.signed_by_key_id.clone(),
                now
            ),
            Err(AnchorVerdictError::IssuedInFuture)
        );
    }

    /// A receipt minted for someone else, replayed at me. Signature, authority
    /// pin and freshness all pass — only the verifier binding rejects it.
    #[test]
    fn bootstrap_for_another_verifier_is_refused() {
        let now = Utc::now();
        let signed = bootstrap(now);
        assert_eq!(
            signed.verify_for_redemption(
                "verifier-b",
                &challenge(),
                &signed.signed_by_key_id.clone(),
                now
            ),
            Err(AnchorVerdictError::VerifierMismatch)
        );
    }

    /// My own receipt from an earlier redemption, replayed against a NEW
    /// request. Everything passes except the challenge this request generated —
    /// which is the whole reason the challenge is in the signed pre-image.
    #[test]
    fn bootstrap_answering_a_different_challenge_is_refused() {
        let now = Utc::now();
        let signed = bootstrap(now);
        assert_eq!(
            signed.verify_for_redemption(
                VERIFIER,
                &"d".repeat(64),
                &signed.signed_by_key_id.clone(),
                now
            ),
            Err(AnchorVerdictError::ChallengeMismatch)
        );
    }

    #[test]
    fn revoked_verdict_is_signed_but_not_servable() {
        let now = Utc::now();
        let signed = verdict(AnchorVerdictStatus::Revoked, 2, now);
        assert_eq!(
            signed.ensure_servable(
                &anchor().anchor_id,
                "tenant-a",
                &signed.signed_by_key_id,
                None,
                now,
            ),
            Err(AnchorVerdictError::Revoked)
        );
    }

    /// `test tracker_snapshot_round_trips` (M2)
    ///
    /// The doc comment on `AnchorVerdictTracker` instructs consumers to
    /// persist it; before `snapshot`/`from_snapshot` existed there was no
    /// type a consumer could actually serialize (the map is keyed by a
    /// `(String, String)` tuple, which is not a valid JSON object key). This
    /// pins that the round trip preserves every tracked pair exactly.
    #[test]
    fn tracker_snapshot_round_trips() {
        let signing_key = key();
        let now = Utc::now();
        let mut tracker = AnchorVerdictTracker::default();

        let v1 = AnchorVerdict::sign(
            anchor(),
            "tenant-a".to_owned(),
            AnchorVerdictStatus::Valid,
            1,
            now,
            &signing_key,
        )
        .unwrap();
        tracker
            .accept(
                &v1,
                &anchor().anchor_id,
                "tenant-a",
                &v1.signed_by_key_id,
                now,
            )
            .unwrap();

        let mut other_anchor = anchor();
        other_anchor.anchor_id = "01JCSQ0000000000000ANCHOR02".to_owned();
        let v2 = AnchorVerdict::sign(
            other_anchor.clone(),
            "tenant-b".to_owned(),
            AnchorVerdictStatus::Valid,
            7,
            now,
            &signing_key,
        )
        .unwrap();
        tracker
            .accept(
                &v2,
                &other_anchor.anchor_id,
                "tenant-b",
                &v2.signed_by_key_id,
                now,
            )
            .unwrap();

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.schema, ANCHOR_VERDICT_TRACKER_SNAPSHOT_SCHEMA);
        assert_eq!(snapshot.entries.len(), 2, "one row per tracked pair");

        // The snapshot is itself ordinary JSON — the whole point.
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: AnchorVerdictTrackerSnapshot = serde_json::from_str(&json).unwrap();
        let restored = AnchorVerdictTracker::from_snapshot(parsed).unwrap();

        assert_eq!(
            restored.highest_version(&anchor().anchor_id, "tenant-a"),
            Some(1)
        );
        assert_eq!(
            restored.highest_version(&other_anchor.anchor_id, "tenant-b"),
            Some(7)
        );
        assert_eq!(
            restored.highest_version(&anchor().anchor_id, "tenant-nonexistent"),
            None
        );
    }

    /// `test restored_tracker_rejects_a_replayed_or_lower_version` (M2)
    ///
    /// The rollback protection `AnchorVerdictTracker` exists for is only real
    /// if it survives the restart it is meant to survive. Accept v1 then v2,
    /// snapshot, restore into a FRESH tracker (simulating a process restart),
    /// and confirm the restored tracker still refuses a replayed v2 and a
    /// lower v1 — exactly as the live tracker would — while a genuinely
    /// higher v3 is still accepted.
    #[test]
    fn restored_tracker_rejects_a_replayed_or_lower_version() {
        let signing_key = key();
        let now = Utc::now();
        let mut live = AnchorVerdictTracker::default();

        let v1 = AnchorVerdict::sign(
            anchor(),
            "tenant-a".to_owned(),
            AnchorVerdictStatus::Valid,
            1,
            now,
            &signing_key,
        )
        .unwrap();
        live.accept(
            &v1,
            &anchor().anchor_id,
            "tenant-a",
            &v1.signed_by_key_id,
            now,
        )
        .unwrap();
        let v2 = AnchorVerdict::sign(
            anchor(),
            "tenant-a".to_owned(),
            AnchorVerdictStatus::Valid,
            2,
            now,
            &signing_key,
        )
        .unwrap();
        live.accept(
            &v2,
            &anchor().anchor_id,
            "tenant-a",
            &v2.signed_by_key_id,
            now,
        )
        .unwrap();

        // Simulate a restart: serialize, drop `live`, restore into `restored`.
        let snapshot_json = serde_json::to_string(&live.snapshot()).unwrap();
        drop(live);
        let restored_snapshot: AnchorVerdictTrackerSnapshot =
            serde_json::from_str(&snapshot_json).unwrap();
        let mut restored = AnchorVerdictTracker::from_snapshot(restored_snapshot).unwrap();

        // A replay of the already-accepted v2 must still be refused.
        let v2_replay = AnchorVerdict::sign(
            anchor(),
            "tenant-a".to_owned(),
            AnchorVerdictStatus::Valid,
            2,
            now,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            restored.accept(
                &v2_replay,
                &anchor().anchor_id,
                "tenant-a",
                &v2_replay.signed_by_key_id,
                now,
            ),
            Err(AnchorVerdictError::SequenceRollback),
            "a restored tracker must still refuse a replay of the last accepted version"
        );

        // A rolled-back v1 (lower than the restored high-water mark) must
        // also be refused — this is the case a discarded (non-persisted)
        // tracker could never catch.
        let v1_rollback_attempt = AnchorVerdict::sign(
            anchor(),
            "tenant-a".to_owned(),
            AnchorVerdictStatus::Valid,
            1,
            now,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            restored.accept(
                &v1_rollback_attempt,
                &anchor().anchor_id,
                "tenant-a",
                &v1_rollback_attempt.signed_by_key_id,
                now,
            ),
            Err(AnchorVerdictError::SequenceRollback),
            "a restored tracker must refuse a version below its restored high-water mark"
        );

        // A genuinely fresh, higher version is still accepted normally.
        let v3 = AnchorVerdict::sign(
            anchor(),
            "tenant-a".to_owned(),
            AnchorVerdictStatus::Valid,
            3,
            now,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            restored.accept(
                &v3,
                &anchor().anchor_id,
                "tenant-a",
                &v3.signed_by_key_id,
                now
            ),
            Ok(AnchorVerdictStatus::Valid)
        );
        assert_eq!(
            restored.highest_version(&anchor().anchor_id, "tenant-a"),
            Some(3)
        );
    }

    /// `test tracker_snapshot_with_unrecognized_schema_is_rejected` (M2)
    ///
    /// A future format change to the persisted shape must fail loud rather
    /// than silently mis-parse into a tracker that has forgotten a real
    /// high-water mark.
    #[test]
    fn tracker_snapshot_with_unrecognized_schema_is_rejected() {
        let bogus = AnchorVerdictTrackerSnapshot {
            schema: "some-other-schema/v1".to_owned(),
            entries: vec![AnchorVerdictTrackerEntry {
                anchor_id: "a".to_owned(),
                tenant_id: "t".to_owned(),
                highest_version: 9,
            }],
        };
        assert!(matches!(
            AnchorVerdictTracker::from_snapshot(bogus),
            Err(AnchorVerdictError::UnsupportedSchema)
        ));
    }
}
