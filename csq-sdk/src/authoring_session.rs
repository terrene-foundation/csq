//! `csq.authoring_session.v1` — the governed authoring-session envelope (an internal ticket, S1).
//!
//! This module holds the wire SHAPE of a governed authoring session plus the
//! validation that governs it. It is the keystone the later authoring-session shards
//! build on: the intent turn, distillation, form-factor inference, session memory,
//! receipts, and capability advertisement are NOT here, by design — they attach to
//! this envelope additively (see [§ Additive extension](#additive-extension)).
//!
//! ## The five invariants
//!
//! Every authoring-session request AND response carries the same [`SessionBinding`],
//! which names five things:
//!
//! 1. **tenant identity** — [`SessionBinding::tenant_id`];
//! 2. **verified operator identity** — [`SessionBinding::operator`], an operator id
//!    plus the method and non-secret evidence handle by which it was verified;
//! 3. **session identity** — [`SessionBinding::session_id`];
//! 4. **request correlation-or-digest** — [`SessionBinding::correlation`], a closed
//!    two-armed choice so a caller that supplies no id still binds the turn to its
//!    content digest;
//! 5. **provider and regional-routing policy evidence** — [`SessionBinding::routing`],
//!    the provider, the region the turn would be served from, and the routing policy
//!    (by id and allowed-region set) that authorizes it.
//!
//! Both directions carry the SAME struct, so one validator
//! ([`SessionContext::admit`] for the request, [`SessionContext::accept_response`] for
//! the response) governs both and the two cannot drift apart.
//!
//! ## Fail-closed refusals
//!
//! [`SessionContext`] holds the authoritative facts established when the session was
//! opened. A binding is checked AGAINST it, never against itself, so a caller cannot
//! satisfy an invariant by restating its own claim:
//!
//! - a tenant that differs from the established session's ⇒ [`SdkErrorCode::TenantMismatch`];
//! - an operator id or session id that differs from the established session's ⇒
//!   [`SdkErrorCode::IdentityMismatch`];
//! - routing evidence that cites a different policy, restates a different allowed-region
//!   set, names a region outside it, or carries an EMPTY allowed set ⇒
//!   [`SdkErrorCode::RoutingDenied`]. The empty set refuses rather than admits, which is
//!   what makes an unpopulated policy a refusal instead of a blanket pass.
//!
//! ## Routing is checked before provider egress
//!
//! The ordering is enforced by types, not by comment: an egress call site takes an
//! [`EgressAuthorization`], whose only constructor is the private
//! `SessionContext::authorize_routing` reached through [`SessionContext::admit`].
//! [`EgressAuthorization`] has a private unit field, so no struct literal outside this
//! module — including in the later shards — can produce one without going through the
//! routing check. A caller holding one has, by construction, already passed it.
//!
//! ## Additive extension
//!
//! [`AuthoringSessionRequest`] and [`AuthoringSessionResponse`] are
//! `#[non_exhaustive]` and constructed through [`AuthoringSessionRequest::new`] /
//! [`AuthoringSessionResponse::new`]. A later shard adds its field as
//! `Option<T>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` plus a
//! `with_*` builder — a consumer pinned to `csq.authoring_session.v1` keeps parsing,
//! and the major does not bump (the contract-change policy in `crate`).
//!
//! ## Leak safety
//!
//! Every refusal message in this module is a fixed `&'static str` naming the CLASS of
//! mismatch. No tenant id, operator id, session id, correlation value, region, or
//! policy id is interpolated into an error, so an envelope emitted on refusal carries
//! no identity value (`rules/security.md` §2). The identifiers appear on the SUCCESS
//! path only, inside the payload the caller itself supplied.

use serde::{Deserialize, Serialize};

use crate::error::{SdkError, SdkErrorCode};

/// How an operator identity was verified.
///
/// `#[non_exhaustive]`: the vocabulary is closed at any given crate version but is
/// expected to gain members as csq gains verification channels. Sealing forces an
/// external `match` to carry a `_ =>` fallback; unit-variant construction is
/// unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationMethod {
    /// The operator was verified through an OAuth identity csq itself minted.
    OauthIdentity,
    /// The operator was verified by a signed assertion presented by the host.
    SignedAssertion,
}

impl VerificationMethod {
    /// The stable wire string for this method (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OauthIdentity => "oauth_identity",
            Self::SignedAssertion => "signed_assertion",
        }
    }
}

/// Invariant 2 — a **verified** operator identity: who, by what method, against what
/// evidence.
///
/// `evidence_id` is a non-secret HANDLE to the verification record (an audit record
/// id, an assertion id) — never the assertion itself, and never a token. It is
/// required to be non-empty by [`VerifiedOperator::validate`], which is what
/// distinguishes a verified identity from an asserted one on this DTO.
///
/// `#[non_exhaustive]`: construct via [`VerifiedOperator::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VerifiedOperator {
    /// The operator's stable identifier within the tenant.
    pub operator_id: String,
    /// The channel through which `operator_id` was verified.
    pub method: VerificationMethod,
    /// Non-secret handle to the verification evidence.
    pub evidence_id: String,
}

impl VerifiedOperator {
    /// Build a `VerifiedOperator` from its three always-present fields.
    #[must_use]
    pub fn new(
        operator_id: impl Into<String>,
        method: VerificationMethod,
        evidence_id: impl Into<String>,
    ) -> Self {
        Self {
            operator_id: operator_id.into(),
            method,
            evidence_id: evidence_id.into(),
        }
    }

    /// Structural check: both identifiers are present.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when `operator_id` or `evidence_id` is empty.
    /// An absent evidence handle is a refusal, not a downgrade to "asserted".
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.operator_id.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: operator id must not be empty",
            ));
        }
        if self.evidence_id.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: operator verification evidence id must not be empty",
            ));
        }
        Ok(())
    }
}

/// Invariant 4 — the turn's correlation: an id when the caller supplied one, otherwise
/// a digest of the turn's content.
///
/// Adjacently tagged on the wire (`{"kind":"id","value":"…"}`) so a consumer branches
/// on `kind` without positional parsing, and so a later shard can add a third arm
/// without reshaping the two that exist.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback; variant
/// construction is unaffected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequestCorrelation {
    /// A caller-supplied correlation id, echoed verbatim on the response.
    Id(String),
    /// A digest standing in for a correlation id the caller did not supply.
    Digest(String),
}

/// The longest correlation value this contract admits.
///
/// A bound, not a taste. Two outcomes have to stay separable: a legitimate
/// correlation — a request id (`"req-1"`), a UUID (36 bytes), or a hex content digest
/// (64 bytes for SHA-256, 128 for SHA-512) — and a value carrying something other than
/// an identity. 512 sits about 4x above the largest legitimate form and far below a
/// length at which echoing it into a receipt, a log line, or a store key is expensive.
/// It is deliberately the same bound as `authoring_memory`'s item id: both are
/// caller-supplied identifiers that this crate hands onward verbatim.
pub const CORRELATION_MAX_BYTES: usize = 512;

impl RequestCorrelation {
    /// The correlation's value, whichever arm carries it.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Id(v) | Self::Digest(v) => v,
        }
    }

    /// Structural check: the correlation carries a value, and one short enough to be
    /// an identifier.
    ///
    /// # Why a length bound and not just emptiness
    ///
    /// This value is chosen entirely by the caller and is echoed VERBATIM into
    /// artifacts that outlive the turn — most notably
    /// `crate::authoring_memory::MutationReceipt`, an attestation that is serialized
    /// and may be persisted or audited. Every other field of that receipt is derived
    /// by the gateway; this one is not, so it is the receipt's only fully
    /// caller-controlled surface. An identifier or a digest is tens of bytes; the
    /// bound admits those with orders of magnitude to spare and refuses a value being
    /// used as a smuggling channel or as a way to inflate a stored attestation.
    ///
    /// The bound is on BYTES, not chars, because that is what a store, a log line, and
    /// a wire payload actually pay for.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when the value is empty or exceeds
    /// [`CORRELATION_MAX_BYTES`].
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.value().is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: request correlation value must not be empty",
            ));
        }
        if self.value().len() > CORRELATION_MAX_BYTES {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: request correlation value is too long",
            ));
        }
        Ok(())
    }
}

/// The authoritative regional-routing policy for a session, held by
/// [`SessionContext`] — never by the caller's binding.
///
/// `#[non_exhaustive]`: construct via [`RoutingPolicy::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RoutingPolicy {
    /// Identifier of the policy that produced `allowed_regions`.
    pub policy_id: String,
    /// The regions this policy admits. An EMPTY set admits nothing.
    pub allowed_regions: Vec<String>,
}

impl RoutingPolicy {
    /// Build a `RoutingPolicy` from its two always-present fields.
    #[must_use]
    pub fn new(policy_id: impl Into<String>, allowed_regions: Vec<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            allowed_regions,
        }
    }
}

/// Invariant 5 — the provider and the regional-routing policy evidence the caller
/// presents for this turn.
///
/// The caller restates the policy it believes governs the turn; [`SessionContext`]
/// checks that restatement against the policy it actually holds. Restating a policy
/// is therefore not a way to widen it.
///
/// `#[non_exhaustive]`: construct via [`RoutingEvidence::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RoutingEvidence {
    /// The provider surface the turn would be served by (`"claude"`, …).
    pub provider: String,
    /// The region the turn would be served from.
    pub region: String,
    /// The routing policy the caller cites, restated in full.
    pub policy: RoutingPolicy,
}

impl RoutingEvidence {
    /// Build a `RoutingEvidence` from its three always-present fields.
    #[must_use]
    pub fn new(
        provider: impl Into<String>,
        region: impl Into<String>,
        policy: RoutingPolicy,
    ) -> Self {
        Self {
            provider: provider.into(),
            region: region.into(),
            policy,
        }
    }

    /// Structural check: provider and region are present.
    ///
    /// Whether the region is ADMITTED is not decided here — that comparison needs the
    /// authoritative policy and lives in `SessionContext::authorize_routing`.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when `provider` or `region` is empty.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.provider.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: routing provider must not be empty",
            ));
        }
        if self.region.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: routing region must not be empty",
            ));
        }
        Ok(())
    }
}

/// The five identity/routing invariants, carried identically on the request and the
/// response.
///
/// One struct in both directions is what lets one validator govern both; a
/// response-only mirror would be free to drift from the request shape it is supposed
/// to echo.
///
/// `#[non_exhaustive]`: construct via [`SessionBinding::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionBinding {
    /// Invariant 1 — the tenant this turn belongs to.
    pub tenant_id: String,
    /// Invariant 2 — the verified operator driving the turn.
    pub operator: VerifiedOperator,
    /// Invariant 3 — the authoring session this turn belongs to.
    pub session_id: String,
    /// Invariant 4 — the turn's correlation id or content digest.
    pub correlation: RequestCorrelation,
    /// Invariant 5 — provider and regional-routing policy evidence.
    pub routing: RoutingEvidence,
}

impl SessionBinding {
    /// Build a `SessionBinding` from its five always-present fields.
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        operator: VerifiedOperator,
        session_id: impl Into<String>,
        correlation: RequestCorrelation,
        routing: RoutingEvidence,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            operator,
            session_id: session_id.into(),
            correlation,
            routing,
        }
    }

    /// Structural check of all five invariants: each is present and non-empty.
    ///
    /// This is the SHAPE half only. Whether the values MATCH the established session
    /// is the [`SessionContext`] half, and a binding that passes here can still be
    /// refused there.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] naming the first absent invariant.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.tenant_id.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: tenant id must not be empty",
            ));
        }
        self.operator.validate()?;
        if self.session_id.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring session: session id must not be empty",
            ));
        }
        self.correlation.validate()?;
        self.routing.validate()
    }
}

/// Proof that the regional-routing policy check ran and PASSED.
///
/// The private `seal` field is what makes this a proof rather than a label: a struct
/// literal is only writable inside this module, so the sole way any other module —
/// including the later authoring-session shards — obtains one is
/// [`SessionContext::admit`], which returns it only after
/// `SessionContext::authorize_routing` has admitted the region. An egress call site
/// that takes an `EgressAuthorization` by value or reference therefore cannot be
/// reached with an unchecked route.
///
/// `#[non_exhaustive]` additionally seals it against a future public field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EgressAuthorization {
    provider: String,
    region: String,
    seal: (),
}

impl EgressAuthorization {
    /// The provider surface this authorization admits.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The region this authorization admits.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
}

/// The authoritative facts established when the authoring session was opened.
///
/// Every check compares a caller's [`SessionBinding`] against THIS, which is why a
/// caller restating its own claim cannot satisfy an invariant.
///
/// `#[non_exhaustive]`: construct via [`SessionContext::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionContext {
    /// The tenant the session was opened for.
    pub tenant_id: String,
    /// The operator id the session was opened by.
    pub operator_id: String,
    /// The session's own identifier.
    pub session_id: String,
    /// The regional-routing policy in force for this session.
    pub policy: RoutingPolicy,
}

impl SessionContext {
    /// Build a `SessionContext` from its four always-present fields.
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        operator_id: impl Into<String>,
        session_id: impl Into<String>,
        policy: RoutingPolicy,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            operator_id: operator_id.into(),
            session_id: session_id.into(),
            policy,
        }
    }

    /// Admit a request binding, returning the [`EgressAuthorization`] a later shard's
    /// provider call needs.
    ///
    /// Runs, in order: the binding's own shape check, tenant, identity/session, and
    /// finally routing. Routing is last but still strictly BEFORE any egress, because
    /// egress needs the value this function returns and there is no other constructor
    /// for it.
    ///
    /// # Errors
    /// - [`SdkErrorCode::InvalidInput`] — an invariant is absent (shape).
    /// - [`SdkErrorCode::TenantMismatch`] — the binding's tenant is not this session's.
    /// - [`SdkErrorCode::IdentityMismatch`] — the binding's operator or session id is
    ///   not this session's.
    /// - [`SdkErrorCode::RoutingDenied`] — the routing evidence cites a different
    ///   policy, restates a different allowed-region set, names a region outside it, or
    ///   the policy admits no region at all.
    pub fn admit(&self, binding: &SessionBinding) -> Result<EgressAuthorization, SdkError> {
        binding.validate()?;
        self.check_tenant(binding)?;
        self.check_identity(binding)?;
        self.authorize_routing(&binding.routing)
    }

    /// Validate a response binding against this session.
    ///
    /// Applies the SAME tenant and identity/session checks as [`Self::admit`], plus
    /// the correlation echo: a response whose correlation differs from the request's
    /// is not this request's response and is refused. Routing is not re-authorized
    /// here — the response direction performs no egress.
    ///
    /// # Errors
    /// - [`SdkErrorCode::InvalidInput`] — an invariant is absent (shape).
    /// - [`SdkErrorCode::TenantMismatch`] / [`SdkErrorCode::IdentityMismatch`] — as
    ///   [`Self::admit`].
    /// - [`SdkErrorCode::IdentityMismatch`] — the response does not echo the request's
    ///   correlation.
    pub fn accept_response(
        &self,
        request: &SessionBinding,
        response: &SessionBinding,
    ) -> Result<(), SdkError> {
        response.validate()?;
        self.check_tenant(response)?;
        self.check_identity(response)?;
        if response.correlation != request.correlation {
            return Err(SdkError::trusted(
                SdkErrorCode::IdentityMismatch,
                "authoring session: response does not echo the request correlation",
            ));
        }
        Ok(())
    }

    /// Invariant 1 — the binding's tenant is this session's tenant.
    fn check_tenant(&self, binding: &SessionBinding) -> Result<(), SdkError> {
        if binding.tenant_id == self.tenant_id {
            return Ok(());
        }
        Err(SdkError::trusted(
            SdkErrorCode::TenantMismatch,
            "authoring session: tenant identity does not match the established session",
        ))
    }

    /// Invariants 2 + 3 — the binding's verified operator and session id are this
    /// session's. Both map to one code: from a consumer's side the recovery is the
    /// same (re-establish the session), and splitting them would let a caller probe
    /// which half of the pair it guessed correctly.
    fn check_identity(&self, binding: &SessionBinding) -> Result<(), SdkError> {
        if binding.operator.operator_id == self.operator_id && binding.session_id == self.session_id
        {
            return Ok(());
        }
        Err(SdkError::trusted(
            SdkErrorCode::IdentityMismatch,
            "authoring session: verified operator identity does not match the established session",
        ))
    }

    /// Invariant 5 — the routing evidence is this session's policy, and the region it
    /// names is admitted by it.
    ///
    /// The only constructor of [`EgressAuthorization`].
    fn authorize_routing(
        &self,
        evidence: &RoutingEvidence,
    ) -> Result<EgressAuthorization, SdkError> {
        const DENIED: &str =
            "authoring session: regional routing is not permitted by the session policy";

        if self.policy.allowed_regions.is_empty()
            || evidence.policy.policy_id != self.policy.policy_id
            || evidence.policy.allowed_regions != self.policy.allowed_regions
            || !self
                .policy
                .allowed_regions
                .iter()
                .any(|r| r == &evidence.region)
        {
            return Err(SdkError::trusted(SdkErrorCode::RoutingDenied, DENIED));
        }

        Ok(EgressAuthorization {
            provider: evidence.provider.clone(),
            region: evidence.region.clone(),
            seal: (),
        })
    }
}

/// The `csq.authoring_session.v1` REQUEST payload.
///
/// Carries the [`SessionBinding`] and nothing else in S1: the intent turn,
/// distillation inputs, form-factor hints, and memory operations are later shards and
/// attach as optional fields (see the module's § Additive extension).
///
/// `#[non_exhaustive]`: construct via [`AuthoringSessionRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthoringSessionRequest {
    /// The five invariants for this turn.
    pub binding: SessionBinding,
}

impl AuthoringSessionRequest {
    /// Build a request payload around its binding.
    #[must_use]
    pub fn new(binding: SessionBinding) -> Self {
        Self { binding }
    }
}

/// The `csq.authoring_session.v1` RESPONSE payload.
///
/// Echoes the [`SessionBinding`] so a consumer can re-check all five invariants on the
/// value it received rather than trusting the transport. Everything a later shard
/// returns — receipts, distilled artifacts, memory read-backs — attaches additively.
///
/// `#[non_exhaustive]`: construct via [`AuthoringSessionResponse::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthoringSessionResponse {
    /// The five invariants, echoed from the request.
    pub binding: SessionBinding,
}

impl AuthoringSessionResponse {
    /// Build a response payload around its binding.
    #[must_use]
    pub fn new(binding: SessionBinding) -> Self {
        Self { binding }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, SCHEMA_AUTHORING_SESSION_V1};

    const TENANT: &str = "tenant-alpha";
    const OPERATOR: &str = "operator-7";
    const SESSION: &str = "sess-42";
    const POLICY: &str = "policy-eu-only";

    fn policy() -> RoutingPolicy {
        RoutingPolicy::new(POLICY, vec!["eu-west".to_string(), "eu-north".to_string()])
    }

    fn context() -> SessionContext {
        SessionContext::new(TENANT, OPERATOR, SESSION, policy())
    }

    fn binding() -> SessionBinding {
        SessionBinding::new(
            TENANT,
            VerifiedOperator::new(OPERATOR, VerificationMethod::OauthIdentity, "audit-rec-9"),
            SESSION,
            RequestCorrelation::Id("req-1".to_string()),
            RoutingEvidence::new("claude", "eu-west", policy()),
        )
    }

    // ── happy path ──────────────────────────────────────────────────────────────

    #[test]
    fn admit_returns_egress_authorization_for_a_matching_binding() {
        let auth = context()
            .admit(&binding())
            .expect("binding matches session");
        assert_eq!(auth.provider(), "claude");
        assert_eq!(auth.region(), "eu-west");
    }

    #[test]
    fn accept_response_admits_an_echoing_response() {
        let req = binding();
        context()
            .accept_response(&req, &req.clone())
            .expect("an exact echo is accepted");
    }

    // ── refusal 1: tenant mismatch ──────────────────────────────────────────────

    #[test]
    fn tenant_mismatch_is_refused_on_request_and_response() {
        let mut b = binding();
        b.tenant_id = "tenant-beta".to_string();

        let err = context().admit(&b).expect_err("foreign tenant is refused");
        assert_eq!(err.code, SdkErrorCode::TenantMismatch);

        let err = context()
            .accept_response(&binding(), &b)
            .expect_err("foreign tenant is refused on the response too");
        assert_eq!(err.code, SdkErrorCode::TenantMismatch);
    }

    // ── refusal 2: verified-identity / session mismatch ──────────────────────────

    #[test]
    fn verified_identity_or_session_mismatch_is_refused() {
        let mut wrong_operator = binding();
        wrong_operator.operator.operator_id = "operator-8".to_string();
        assert_eq!(
            context()
                .admit(&wrong_operator)
                .expect_err("foreign operator is refused")
                .code,
            SdkErrorCode::IdentityMismatch
        );

        let mut wrong_session = binding();
        wrong_session.session_id = "sess-43".to_string();
        assert_eq!(
            context()
                .admit(&wrong_session)
                .expect_err("foreign session is refused")
                .code,
            SdkErrorCode::IdentityMismatch
        );

        let mut wrong_correlation = binding();
        wrong_correlation.correlation = RequestCorrelation::Id("req-2".to_string());
        assert_eq!(
            context()
                .accept_response(&binding(), &wrong_correlation)
                .expect_err("a non-echoing correlation is refused")
                .code,
            SdkErrorCode::IdentityMismatch
        );
    }

    // ── refusal 3: disallowed regional routing ──────────────────────────────────

    #[test]
    fn disallowed_regional_routing_is_refused_and_yields_no_egress_authorization() {
        // (a) a region outside the policy
        let mut outside = binding();
        outside.routing.region = "us-east".to_string();
        assert_eq!(
            context()
                .admit(&outside)
                .expect_err("a region outside the policy is refused")
                .code,
            SdkErrorCode::RoutingDenied
        );

        // (b) evidence citing a different policy id
        let mut forged_id = binding();
        forged_id.routing.policy = RoutingPolicy::new("policy-global", policy().allowed_regions);
        assert_eq!(
            context()
                .admit(&forged_id)
                .expect_err("a foreign policy id is refused")
                .code,
            SdkErrorCode::RoutingDenied
        );

        // (c) evidence widening the allowed set under the session's own policy id
        let mut widened = binding();
        widened.routing.policy = RoutingPolicy::new(
            POLICY,
            vec![
                "eu-west".to_string(),
                "eu-north".to_string(),
                "us-east".to_string(),
            ],
        );
        widened.routing.region = "us-east".to_string();
        assert_eq!(
            context()
                .admit(&widened)
                .expect_err("restating a wider policy does not widen it")
                .code,
            SdkErrorCode::RoutingDenied
        );

        // (d) an empty policy admits nothing — fail closed, not open
        let empty = SessionContext::new(
            TENANT,
            OPERATOR,
            SESSION,
            RoutingPolicy::new(POLICY, vec![]),
        );
        let mut empty_evidence = binding();
        empty_evidence.routing.policy = RoutingPolicy::new(POLICY, vec![]);
        assert_eq!(
            empty
                .admit(&empty_evidence)
                .expect_err("an empty policy admits no region")
                .code,
            SdkErrorCode::RoutingDenied
        );
    }

    // ── shape validation ────────────────────────────────────────────────────────

    #[test]
    fn a_correlation_longer_than_the_bound_is_refused() {
        let over = RequestCorrelation::Id("x".repeat(CORRELATION_MAX_BYTES + 1));
        let err = over
            .validate()
            .expect_err("an over-long correlation is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        assert!(
            err.message.as_str().contains("too long"),
            "the refusal names the SIZE class, not emptiness: {}",
            err.message.as_str()
        );

        // The bound admits what it should — exactly at the limit, and every legitimate
        // form: a request id, a UUID, and a SHA-512 hex digest.
        RequestCorrelation::Id("x".repeat(CORRELATION_MAX_BYTES))
            .validate()
            .expect("exactly at the limit is admitted");
        RequestCorrelation::Id("req-1".to_string())
            .validate()
            .expect("a request id is admitted");
        RequestCorrelation::Digest("f".repeat(128))
            .validate()
            .expect("a SHA-512 hex digest is admitted");
    }

    #[test]
    fn an_over_long_correlation_is_refused_through_the_full_binding_gate() {
        // Reached via the gate a caller actually crosses, not just the leaf check —
        // this is the path that would otherwise clone the value into a receipt.
        let mut b = binding();
        b.correlation = RequestCorrelation::Id("x".repeat(CORRELATION_MAX_BYTES + 1));
        assert_eq!(
            context()
                .admit(&b)
                .expect_err("the binding is refused")
                .code,
            SdkErrorCode::InvalidInput
        );
    }

    #[test]
    fn absent_invariants_are_refused_as_invalid_input() {
        for mutate in [
            (|b: &mut SessionBinding| b.tenant_id.clear()) as fn(&mut SessionBinding),
            |b: &mut SessionBinding| b.operator.operator_id.clear(),
            |b: &mut SessionBinding| b.operator.evidence_id.clear(),
            |b: &mut SessionBinding| b.session_id.clear(),
            |b: &mut SessionBinding| b.correlation = RequestCorrelation::Digest(String::new()),
            |b: &mut SessionBinding| b.routing.provider.clear(),
            |b: &mut SessionBinding| b.routing.region.clear(),
        ] {
            let mut b = binding();
            mutate(&mut b);
            assert_eq!(
                context()
                    .admit(&b)
                    .expect_err("an absent invariant is refused")
                    .code,
                SdkErrorCode::InvalidInput
            );
        }
    }

    // ── leak safety ─────────────────────────────────────────────────────────────

    #[test]
    fn refusal_messages_carry_no_identity_or_routing_values() {
        let mut foreign = binding();
        foreign.tenant_id = "tenant-beta".to_string();
        foreign.operator.operator_id = "operator-8".to_string();
        foreign.session_id = "sess-43".to_string();
        foreign.routing.region = "us-east".to_string();

        for ctx_err in [
            context().admit(&foreign).unwrap_err(),
            context().accept_response(&binding(), &foreign).unwrap_err(),
        ] {
            let rendered = serde_json::to_string(&ctx_err).unwrap();
            for secret in [
                "tenant-beta",
                "operator-8",
                "sess-43",
                "us-east",
                TENANT,
                OPERATOR,
                SESSION,
                POLICY,
                "req-1",
                "audit-rec-9",
            ] {
                assert!(
                    !rendered.contains(secret),
                    "refusal message must not carry {secret}: {rendered}"
                );
            }
        }
    }

    // ── wire shape ──────────────────────────────────────────────────────────────

    #[test]
    fn request_and_response_round_trip_through_the_envelope() {
        let env = Envelope::success(
            SCHEMA_AUTHORING_SESSION_V1,
            Some("req-1".to_string()),
            AuthoringSessionRequest::new(binding()),
        );
        let line = env.to_line().unwrap();
        assert_eq!(
            line.matches('\n').count(),
            0,
            "the envelope serializes to one line: {line}"
        );

        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["schema"], "csq.authoring_session.v1");
        assert_eq!(v["ok"], true);
        // payload is flattened inline, not nested under "payload"
        assert!(v.get("payload").is_none());
        assert_eq!(v["binding"]["tenant_id"], TENANT);
        assert_eq!(v["binding"]["operator"]["method"], "oauth_identity");
        assert_eq!(v["binding"]["correlation"]["kind"], "id");
        assert_eq!(v["binding"]["correlation"]["value"], "req-1");
        assert_eq!(v["binding"]["routing"]["policy"]["policy_id"], POLICY);

        // and the payload deserializes back to the value that produced it
        let req = AuthoringSessionRequest::new(binding());
        let back: AuthoringSessionRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back, req);

        let resp = AuthoringSessionResponse::new(binding());
        let round: AuthoringSessionResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(round, resp);
    }

    #[test]
    fn verification_method_wire_strings_match_serialize() {
        for (method, wire) in [
            (VerificationMethod::OauthIdentity, "oauth_identity"),
            (VerificationMethod::SignedAssertion, "signed_assertion"),
        ] {
            assert_eq!(method.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&method).unwrap(),
                format!("\"{wire}\"")
            );
        }
    }

    #[test]
    fn a_refusal_emits_as_a_failure_envelope_with_no_payload() {
        let mut foreign = binding();
        foreign.tenant_id = "tenant-beta".to_string();
        let err = context().admit(&foreign).unwrap_err();

        let env: Envelope<AuthoringSessionResponse> =
            Envelope::failure(SCHEMA_AUTHORING_SESSION_V1, None, err);
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "tenant_mismatch");
        assert!(
            v.get("binding").is_none(),
            "a refusal carries no payload: {v}"
        );
    }
}
