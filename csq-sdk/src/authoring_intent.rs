//! `csq.authoring_intent.v1` — one turn of a governed multi-turn intent session
//! (an internal ticket, S2).
//!
//! This module carries a SINGLE turn of intent capture across the wire and governs
//! its continuation. It does not distil, infer a form factor, hold session memory, or
//! advertise a capability — those are later shards and attach to these DTOs
//! additively (see [§ Additive extension](#additive-extension)).
//!
//! ## Riding the S1 envelope
//!
//! Every turn — request AND response — carries the same
//! [`SessionBinding`] S1 defined, and every
//! turn is validated by the S1 validator rather than by a second copy of it here:
//! [`IntentTurnSequence::admit_turn`] delegates to
//! [`SessionContext::admit`](crate::authoring_session::SessionContext::admit) and
//! [`IntentTurnSequence::accept_turn_response`] delegates to
//! [`SessionContext::accept_response`](crate::authoring_session::SessionContext::accept_response).
//! The five invariants are therefore re-checked on turn 7 exactly as on turn 0, and
//! this module owns no copy of that logic that could drift from it.
//!
//! ## Egress still cannot be reached without authorization
//!
//! [`IntentTurnSequence::admit_turn`] returns an
//! [`EgressAuthorization`], and it
//! obtains one the only way anything can: from `SessionContext::admit`, whose private
//! constructor is reached only after the routing check passes. This module adds no
//! second path to one — it has no access to the sealed constructor either — so a
//! provider call site that takes an `EgressAuthorization` is as unreachable from an
//! unrouted intent turn as it is from an unrouted session turn.
//!
//! ## Worker utterance semantics are transported, never reinterpreted
//!
//! A [`WorkerUtterance`] is a transport, and two mechanisms make that structural
//! rather than a promise:
//!
//! 1. **No transform exists.** `WorkerUtterance`'s `text` is private with one
//!    constructor ([`WorkerUtterance::new`]) and one reader
//!    ([`WorkerUtterance::text`]). There is no setter, no `&mut` accessor, and no
//!    call to `trim`, `to_lowercase`, or any re-encoding anywhere in this module, so
//!    the bytes handed to `new` are the bytes `text()` and `Serialize` yield.
//! 2. **A response that altered it is REFUSED.**
//!    [`IntentTurnSequence::accept_turn_response`] compares the response's utterance
//!    to the request's for byte equality and returns
//!    [`SdkErrorCode::UtteranceAltered`] on any difference. A pipeline that
//!    normalized the worker's words between request and response cannot have its
//!    turn accepted.
//!
//! Emptiness is the ONLY property of an utterance this module judges: an empty
//! payload is not a turn at all (a structural refusal, [`SdkErrorCode::InvalidInput`]).
//! Whitespace, casing, punctuation, and script are the worker's, and are not this
//! module's to assess.
//!
//! ## Continuation is authoritative, not asserted
//!
//! Mirroring S1's stance that a caller restating its own claim cannot satisfy an
//! invariant: the request STATES its `turn_index`, and [`IntentTurnSequence`] — held
//! by the host, never by the caller — decides whether that is the turn the session is
//! actually waiting for. A replay of an accepted turn and a gap over a skipped one
//! are both [`SdkErrorCode::TurnOutOfSequence`].
//!
//! ## Additive extension
//!
//! [`IntentTurnRequest`], [`IntentTurnResponse`], and [`IntentTurn`] are
//! `#[non_exhaustive]` and constructed through their `new` functions. A later shard
//! adds its field as `Option<T>` with
//! `#[serde(default, skip_serializing_if = "Option::is_none")]` plus a `with_*`
//! builder — a consumer pinned to `csq.authoring_intent.v1` keeps parsing and the
//! major does not bump (the contract-change policy in `crate`). [`TurnDisposition`]
//! is `#[non_exhaustive]` for the same reason on the enum side.
//!
//! ## Leak safety
//!
//! Every refusal message here is a fixed `&'static str` naming the CLASS of refusal.
//! No tenant id, operator id, session id, region, policy id, turn index, or utterance
//! byte is interpolated into an error (`rules/security.md` §2). A caller recovering
//! from [`SdkErrorCode::TurnOutOfSequence`] reads
//! [`IntentTurnSequence::expected_index`] on its OWN cursor rather than parsing a
//! message, so the recovery path needs no value in the error either.

use serde::{Deserialize, Serialize};

use crate::authoring_session::{EgressAuthorization, SessionBinding, SessionContext};
use crate::error::{SdkError, SdkErrorCode};

/// What a worker said, transported verbatim.
///
/// The field is private with one constructor and one reader precisely so this type
/// can carry the no-transform guarantee described in the module's
/// § Worker utterance semantics: there is no API on this struct through which the
/// stored bytes can be altered after construction.
///
/// A newtype rather than a bare `String` so a later shard can attach per-utterance
/// metadata (a locale hint, an input modality) as an optional field without
/// reshaping every DTO that carries one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerUtterance {
    text: String,
}

impl WorkerUtterance {
    /// Wrap a worker's words for transport. The bytes are stored as given.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    /// The worker's words, byte-identical to what [`Self::new`] was given.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Structural check: the utterance carries content.
    ///
    /// Emptiness is the only property judged; see the module's
    /// § Worker utterance semantics for why whitespace and casing are not.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when the text is empty.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.text.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring intent: worker utterance must not be empty",
            ));
        }
        Ok(())
    }
}

/// One turn's position and content, carried identically on the request and the
/// response.
///
/// One struct in both directions is what makes the echo check a comparison of the
/// SAME type rather than a field-by-field reconciliation of two shapes that could
/// drift apart — the same reason S1 carries one `SessionBinding` both ways.
///
/// `#[non_exhaustive]`: construct via [`IntentTurn::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntentTurn {
    /// This turn's 0-based position in the session. Evidence the caller states;
    /// [`IntentTurnSequence`] decides whether it is the turn actually awaited.
    pub turn_index: u32,
    /// What the worker said on this turn.
    pub utterance: WorkerUtterance,
}

impl IntentTurn {
    /// Build a turn from its two always-present fields.
    #[must_use]
    pub fn new(turn_index: u32, utterance: WorkerUtterance) -> Self {
        Self {
            turn_index,
            utterance,
        }
    }

    /// Structural check of the turn's content.
    ///
    /// The SHAPE half only. Whether the turn is the one the session awaits is the
    /// [`IntentTurnSequence`] half, and a turn that passes here can still be refused
    /// there.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when the utterance is empty.
    pub fn validate(&self) -> Result<(), SdkError> {
        self.utterance.validate()
    }
}

/// Whether the session needs another turn after this one.
///
/// `#[non_exhaustive]`: the vocabulary is closed at any given crate version but a
/// later shard may add an arm (a distillation-ready disposition, say). Sealing forces
/// an external `match` to carry a `_ =>` fallback; unit-variant construction is
/// unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TurnDisposition {
    /// Intent is not yet captured; the response's `reply` is what to put to the
    /// worker next.
    NeedsMoreInput,
    /// The worker's intent is captured; no further turn is required to state it.
    IntentCaptured,
}

impl TurnDisposition {
    /// The stable wire string for this disposition (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeedsMoreInput => "needs_more_input",
            Self::IntentCaptured => "intent_captured",
        }
    }
}

/// The `csq.authoring_intent.v1` REQUEST payload — one turn of worker input under the
/// S1 binding.
///
/// `#[non_exhaustive]`: construct via [`IntentTurnRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntentTurnRequest {
    /// The five invariants for this turn, re-stated on every turn of the session.
    pub binding: SessionBinding,
    /// The turn itself.
    pub turn: IntentTurn,
}

impl IntentTurnRequest {
    /// Build a request payload from its binding and its turn.
    #[must_use]
    pub fn new(binding: SessionBinding, turn: IntentTurn) -> Self {
        Self { binding, turn }
    }

    /// Structural check of the turn this request carries.
    ///
    /// The binding's own shape is NOT checked here — it is checked by
    /// [`SessionContext::admit`](crate::authoring_session::SessionContext::admit),
    /// which [`IntentTurnSequence::admit_turn`] runs first, so there is exactly one
    /// implementation of that check.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when the utterance is empty.
    pub fn validate(&self) -> Result<(), SdkError> {
        self.turn.validate()
    }
}

/// The `csq.authoring_intent.v1` RESPONSE payload.
///
/// Echoes the binding (so a consumer can re-check all five invariants on the value it
/// received) AND the turn (so it can confirm the worker's words survived the round
/// trip unaltered), then adds this turn's outcome.
///
/// `#[non_exhaustive]`: construct via [`IntentTurnResponse::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntentTurnResponse {
    /// The five invariants, echoed from the request.
    pub binding: SessionBinding,
    /// The turn, echoed from the request — same index, byte-identical utterance.
    pub turn: IntentTurn,
    /// Whether the session needs another turn.
    pub disposition: TurnDisposition,
    /// What to put to the worker next. Model/system output, not worker text: per the
    /// crate's R5 it is caller-owned content that reaches stdout only through
    /// [`crate::emit`].
    pub reply: String,
}

impl IntentTurnResponse {
    /// Build a response payload from its four always-present fields.
    #[must_use]
    pub fn new(
        binding: SessionBinding,
        turn: IntentTurn,
        disposition: TurnDisposition,
        reply: impl Into<String>,
    ) -> Self {
        Self {
            binding,
            turn,
            disposition,
            reply: reply.into(),
        }
    }

    /// Structural check of the response's own content.
    ///
    /// Whether it echoes ITS REQUEST is a separate, relational check owned by
    /// [`IntentTurnSequence::accept_turn_response`] — this function sees only one
    /// side and cannot decide it.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when the echoed utterance is empty, or when the
    /// disposition is [`TurnDisposition::NeedsMoreInput`] with an empty `reply`: a
    /// turn that asks for more input while putting nothing to the worker cannot be
    /// continued by them.
    pub fn validate(&self) -> Result<(), SdkError> {
        self.turn.validate()?;
        if self.disposition == TurnDisposition::NeedsMoreInput && self.reply.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring intent: a turn needing more input must carry a reply",
            ));
        }
        Ok(())
    }
}

/// The host-held cursor over a multi-turn intent session.
///
/// Held by the party that established the session — never by the caller — which is
/// what makes a stated `turn_index` evidence rather than a decision.
///
/// The cursor advances on ONE event: a response accepted in full by
/// [`Self::accept_turn_response`]. That function's advance is its last statement and
/// every check before it exits with `?`, so a refused turn leaves the cursor where it
/// was and the same turn can be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentTurnSequence {
    next_index: u32,
}

impl IntentTurnSequence {
    /// A cursor for a session that has completed no turns; the first turn it awaits
    /// is index 0.
    #[must_use]
    pub const fn opening() -> Self {
        Self { next_index: 0 }
    }

    /// A cursor for a session being resumed from persisted state, awaiting
    /// `next_index`.
    #[must_use]
    pub const fn resuming(next_index: u32) -> Self {
        Self { next_index }
    }

    /// The turn index this session is waiting for.
    ///
    /// A caller recovering from [`SdkErrorCode::TurnOutOfSequence`] reads this rather
    /// than parsing the refusal message, which is what lets that message stay a fixed
    /// string carrying no session state.
    #[must_use]
    pub const fn expected_index(&self) -> u32 {
        self.next_index
    }

    /// Admit one intent turn, returning the [`EgressAuthorization`] a provider call
    /// needs.
    ///
    /// Runs, in order: the S1 governance gate ([`SessionContext::admit`] — shape,
    /// tenant, identity, routing), the turn's own shape, then continuation. The
    /// governance gate is first deliberately: a caller that fails tenant, identity,
    /// or routing is refused before any refusal that would distinguish an in-sequence
    /// turn index from an out-of-sequence one.
    ///
    /// The cursor is NOT advanced here — a turn is complete when its RESPONSE is
    /// accepted, so admitting a request that never returns leaves the session
    /// awaiting the same index.
    ///
    /// # Errors
    /// - [`SdkErrorCode::InvalidInput`] — an invariant or the utterance is absent.
    /// - [`SdkErrorCode::TenantMismatch`] / [`SdkErrorCode::IdentityMismatch`] /
    ///   [`SdkErrorCode::RoutingDenied`] — as
    ///   [`SessionContext::admit`](crate::authoring_session::SessionContext::admit).
    /// - [`SdkErrorCode::TurnOutOfSequence`] — the turn is not the one this session
    ///   awaits (a replay of an accepted turn, or a gap over a skipped one).
    pub fn admit_turn(
        &self,
        context: &SessionContext,
        request: &IntentTurnRequest,
    ) -> Result<EgressAuthorization, SdkError> {
        let authorization = context.admit(&request.binding)?;
        request.validate()?;
        self.check_index(request.turn.turn_index)?;
        Ok(authorization)
    }

    /// Accept one intent turn's response and advance the session.
    ///
    /// Runs, in order: the S1 response gate
    /// ([`SessionContext::accept_response`](crate::authoring_session::SessionContext::accept_response)
    /// — shape, tenant, identity, correlation echo), the response's own shape, that
    /// the pair is the turn this session awaits, the turn-index echo, and finally the
    /// utterance echo.
    ///
    /// On `Ok` the cursor has advanced by one and the session awaits the next index.
    ///
    /// # Errors
    /// - [`SdkErrorCode::InvalidInput`] — an invariant is absent, the echoed
    ///   utterance is empty, or a `NeedsMoreInput` turn carries no reply.
    /// - [`SdkErrorCode::TenantMismatch`] / [`SdkErrorCode::IdentityMismatch`] — as
    ///   `SessionContext::accept_response`, including a response that does not echo
    ///   the request's correlation.
    /// - [`SdkErrorCode::TurnOutOfSequence`] — the pair is not the turn this session
    ///   awaits, or the response is for a different turn than the request.
    /// - [`SdkErrorCode::UtteranceAltered`] — the response's utterance is not
    ///   byte-identical to the request's.
    /// - [`SdkErrorCode::Internal`] — the session's turn counter would overflow.
    pub fn accept_turn_response(
        &mut self,
        context: &SessionContext,
        request: &IntentTurnRequest,
        response: &IntentTurnResponse,
    ) -> Result<(), SdkError> {
        context.accept_response(&request.binding, &response.binding)?;
        response.validate()?;
        self.check_index(request.turn.turn_index)?;
        if response.turn.turn_index != request.turn.turn_index {
            return Err(SdkError::trusted(
                SdkErrorCode::TurnOutOfSequence,
                "authoring intent: response is for a different turn than the request",
            ));
        }
        if response.turn.utterance != request.turn.utterance {
            return Err(SdkError::trusted(
                SdkErrorCode::UtteranceAltered,
                "authoring intent: response did not reproduce the worker utterance",
            ));
        }
        self.next_index = self.next_index.checked_add(1).ok_or_else(|| {
            SdkError::trusted(
                SdkErrorCode::Internal,
                "authoring intent: session turn counter would overflow",
            )
        })?;
        Ok(())
    }

    /// The turn stated is the turn awaited.
    ///
    /// One refusal covers replay and gap alike: from a consumer's side the recovery
    /// is identical — resend at [`Self::expected_index`] — and distinguishing them
    /// would report how far a guess was from the session's actual position.
    fn check_index(&self, stated: u32) -> Result<(), SdkError> {
        if stated == self.next_index {
            return Ok(());
        }
        Err(SdkError::trusted(
            SdkErrorCode::TurnOutOfSequence,
            "authoring intent: turn does not continue the established session",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authoring_session::{
        RequestCorrelation, RoutingEvidence, RoutingPolicy, VerificationMethod, VerifiedOperator,
    };
    use crate::{Envelope, SCHEMA_AUTHORING_INTENT_V1};

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

    /// A binding whose every invariant matches [`context`], correlated to `correlation`.
    fn binding(correlation: &str) -> SessionBinding {
        SessionBinding::new(
            TENANT,
            VerifiedOperator::new(OPERATOR, VerificationMethod::OauthIdentity, "audit-rec-9"),
            SESSION,
            RequestCorrelation::Id(correlation.to_string()),
            RoutingEvidence::new("claude", "eu-west", policy()),
        )
    }

    fn request(index: u32, correlation: &str, text: &str) -> IntentTurnRequest {
        IntentTurnRequest::new(
            binding(correlation),
            IntentTurn::new(index, WorkerUtterance::new(text)),
        )
    }

    /// The response that faithfully echoes `request`.
    fn echo(request: &IntentTurnRequest) -> IntentTurnResponse {
        IntentTurnResponse::new(
            request.binding.clone(),
            request.turn.clone(),
            TurnDisposition::NeedsMoreInput,
            "which repository should this run against?",
        )
    }

    fn code(err: &SdkError) -> SdkErrorCode {
        err.code
    }

    // ── happy path: a turn admits, and its response advances the session ─────────

    #[test]
    fn admit_turn_returns_egress_authorization_for_the_awaited_turn() {
        let seq = IntentTurnSequence::opening();
        let auth = seq
            .admit_turn(&context(), &request(0, "req-0", "add a login page"))
            .expect("the first turn of an opening session is admitted");
        assert_eq!(auth.provider(), "claude");
        assert_eq!(auth.region(), "eu-west");
    }

    #[test]
    fn an_accepted_response_advances_the_session_to_the_next_turn() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        assert_eq!(seq.expected_index(), 0);

        let first = request(0, "req-0", "add a login page");
        seq.admit_turn(&ctx, &first).expect("turn 0 admits");
        seq.accept_turn_response(&ctx, &first, &echo(&first))
            .expect("a faithful echo is accepted");
        assert_eq!(seq.expected_index(), 1);

        let second = request(1, "req-1", "email and password, no SSO");
        seq.admit_turn(&ctx, &second)
            .expect("turn 1 continues the session");
    }

    // ── the five invariants are re-validated on EVERY turn, not just the first ──

    #[test]
    fn a_later_turn_from_another_tenant_is_refused() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let first = request(0, "req-0", "add a login page");
        seq.admit_turn(&ctx, &first).expect("turn 0 admits");
        seq.accept_turn_response(&ctx, &first, &echo(&first))
            .expect("turn 0 completes");

        let mut intruder = request(1, "req-1", "and export the user table");
        intruder.binding.tenant_id = "tenant-beta".to_string();
        let err = seq
            .admit_turn(&ctx, &intruder)
            .expect_err("turn 3 is governed exactly as turn 0");
        assert_eq!(code(&err), SdkErrorCode::TenantMismatch);
    }

    #[test]
    fn a_later_turn_routed_outside_the_policy_is_refused() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let first = request(0, "req-0", "add a login page");
        seq.admit_turn(&ctx, &first).expect("turn 0 admits");
        seq.accept_turn_response(&ctx, &first, &echo(&first))
            .expect("turn 0 completes");

        let mut strayed = request(1, "req-1", "and export the user table");
        strayed.binding.routing = RoutingEvidence::new("claude", "us-east", policy());
        let err = seq
            .admit_turn(&ctx, &strayed)
            .expect_err("a region outside the policy is refused on any turn");
        assert_eq!(code(&err), SdkErrorCode::RoutingDenied);
    }

    #[test]
    fn a_response_that_does_not_echo_the_correlation_is_refused() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let req = request(0, "req-0", "add a login page");
        let mut resp = echo(&req);
        resp.binding.correlation = RequestCorrelation::Id("req-99".to_string());
        let err = seq
            .accept_turn_response(&ctx, &req, &resp)
            .expect_err("the S1 correlation echo governs the intent turn too");
        assert_eq!(code(&err), SdkErrorCode::IdentityMismatch);
    }

    #[test]
    fn the_governance_gate_is_reported_ahead_of_the_sequence_gate() {
        // Both would refuse: wrong tenant AND an index the session does not await.
        // The governance verdict is the one returned, so a caller failing tenant
        // learns nothing about where the session actually stands.
        let seq = IntentTurnSequence::resuming(4);
        let mut both_wrong = request(0, "req-0", "add a login page");
        both_wrong.binding.tenant_id = "tenant-beta".to_string();
        let err = seq
            .admit_turn(&context(), &both_wrong)
            .expect_err("both gates would refuse");
        assert_eq!(code(&err), SdkErrorCode::TenantMismatch);
    }

    // ── continuation ────────────────────────────────────────────────────────────

    #[test]
    fn replaying_an_accepted_turn_is_refused() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let first = request(0, "req-0", "add a login page");
        seq.admit_turn(&ctx, &first).expect("turn 0 admits");
        seq.accept_turn_response(&ctx, &first, &echo(&first))
            .expect("turn 0 completes");

        let err = seq
            .admit_turn(&ctx, &first)
            .expect_err("turn 0 has already been accepted");
        assert_eq!(code(&err), SdkErrorCode::TurnOutOfSequence);
        assert_eq!(seq.expected_index(), 1);
    }

    #[test]
    fn skipping_a_turn_is_refused() {
        let err = IntentTurnSequence::opening()
            .admit_turn(&context(), &request(2, "req-2", "and add SSO"))
            .expect_err("the session awaits turn 0, not turn 2");
        assert_eq!(code(&err), SdkErrorCode::TurnOutOfSequence);
    }

    #[test]
    fn a_response_for_a_different_turn_than_its_request_is_refused() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let req = request(0, "req-0", "add a login page");
        let mut resp = echo(&req);
        resp.turn = IntentTurn::new(1, WorkerUtterance::new("add a login page"));
        let err = seq
            .accept_turn_response(&ctx, &req, &resp)
            .expect_err("the response addresses another turn");
        assert_eq!(code(&err), SdkErrorCode::TurnOutOfSequence);
    }

    #[test]
    fn a_refused_turn_leaves_the_cursor_where_it_was() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let req = request(0, "req-0", "add a login page");

        let mut altered = echo(&req);
        altered.turn = IntentTurn::new(0, WorkerUtterance::new("Add a login page."));
        seq.accept_turn_response(&ctx, &req, &altered)
            .expect_err("the altered echo is refused");
        assert_eq!(
            seq.expected_index(),
            0,
            "a refusal must not consume the turn"
        );

        // The same turn is retried and succeeds.
        seq.accept_turn_response(&ctx, &req, &echo(&req))
            .expect("the retried turn is accepted");
        assert_eq!(seq.expected_index(), 1);
    }

    #[test]
    fn a_session_at_the_counter_ceiling_refuses_rather_than_wrapping() {
        let ctx = context();
        let mut seq = IntentTurnSequence::resuming(u32::MAX);
        let req = request(u32::MAX, "req-max", "add a login page");
        let err = seq
            .accept_turn_response(&ctx, &req, &echo(&req))
            .expect_err("advancing past u32::MAX must refuse");
        assert_eq!(code(&err), SdkErrorCode::Internal);
        assert_eq!(seq.expected_index(), u32::MAX, "the cursor did not wrap");
    }

    // ── worker utterance semantics ───────────────────────────────────────────────

    #[test]
    fn an_altered_utterance_in_the_response_is_refused() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let req = request(0, "req-0", "  Add a Login Page  ");
        for tampered in [
            "Add a Login Page",       // trimmed
            "  add a login page  ",   // case-folded
            "  Add a Login Page  \n", // re-terminated
        ] {
            let mut resp = echo(&req);
            resp.turn = IntentTurn::new(0, WorkerUtterance::new(tampered));
            let err = seq
                .accept_turn_response(&ctx, &req, &resp)
                .expect_err("any normalization of the worker's words is refused");
            assert_eq!(code(&err), SdkErrorCode::UtteranceAltered);
        }
    }

    #[test]
    fn an_utterance_survives_construction_and_the_wire_byte_for_byte() {
        // Leading/trailing space, mixed case, an emoji, a combining mark, a tab, and
        // a newline: all preserved, none normalized.
        let raw = "  Añadir\tuna pági\u{0301}na de LOGIN 🔐\n";
        let utterance = WorkerUtterance::new(raw);
        assert_eq!(utterance.text(), raw);

        let json = serde_json::to_string(&utterance).expect("serializes");
        let back: WorkerUtterance = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back.text(), raw);
        assert_eq!(back, utterance);
    }

    #[test]
    fn an_empty_utterance_is_not_a_turn() {
        let err = IntentTurnSequence::opening()
            .admit_turn(&context(), &request(0, "req-0", ""))
            .expect_err("an empty utterance carries no turn");
        assert_eq!(code(&err), SdkErrorCode::InvalidInput);
    }

    #[test]
    fn a_turn_needing_more_input_must_carry_a_reply() {
        let ctx = context();
        let mut seq = IntentTurnSequence::opening();
        let req = request(0, "req-0", "add a login page");
        let mut mute = echo(&req);
        mute.reply = String::new();
        let err = seq
            .accept_turn_response(&ctx, &req, &mute)
            .expect_err("nothing was put to the worker to continue from");
        assert_eq!(code(&err), SdkErrorCode::InvalidInput);

        // The same emptiness is fine once intent is captured — there is nothing left
        // to ask.
        let mut done = echo(&req);
        done.disposition = TurnDisposition::IntentCaptured;
        done.reply = String::new();
        seq.accept_turn_response(&ctx, &req, &done)
            .expect("a captured turn need not ask anything further");
    }

    // ── leak safety ─────────────────────────────────────────────────────────────

    #[test]
    fn no_refusal_carries_an_identity_a_region_or_the_worker_text() {
        let ctx = SessionContext::new(
            "tenant-secret-9f3",
            "operator-secret-7a1",
            "sess-secret-4c2",
            RoutingPolicy::new("policy-secret-1b8", vec!["eu-west".to_string()]),
        );
        let secret_text = "utterance-secret-2e6";
        let secrets = [
            "tenant-secret-9f3",
            "operator-secret-7a1",
            "sess-secret-4c2",
            "policy-secret-1b8",
            secret_text,
            "us-east",
        ];

        let mut seq = IntentTurnSequence::resuming(3);
        let mut refusals: Vec<SdkError> = Vec::new();

        // one refusal per class this module can emit
        let intruder = request(3, "req-3", secret_text);
        refusals.push(seq.admit_turn(&ctx, &intruder).unwrap_err()); // TenantMismatch

        let mut strayed = request(3, "req-3", secret_text);
        strayed.binding.tenant_id = "tenant-secret-9f3".to_string();
        strayed.binding.operator = VerifiedOperator::new(
            "operator-secret-7a1",
            VerificationMethod::OauthIdentity,
            "e",
        );
        strayed.binding.session_id = "sess-secret-4c2".to_string();
        strayed.binding.routing = RoutingEvidence::new(
            "claude",
            "us-east",
            RoutingPolicy::new("policy-secret-1b8", vec!["eu-west".to_string()]),
        );
        refusals.push(seq.admit_turn(&ctx, &strayed).unwrap_err()); // RoutingDenied

        let mut lawful = strayed.clone();
        lawful.binding.routing = RoutingEvidence::new(
            "claude",
            "eu-west",
            RoutingPolicy::new("policy-secret-1b8", vec!["eu-west".to_string()]),
        );
        let mut out_of_sequence = lawful.clone();
        out_of_sequence.turn = IntentTurn::new(9, WorkerUtterance::new(secret_text));
        refusals.push(seq.admit_turn(&ctx, &out_of_sequence).unwrap_err()); // TurnOutOfSequence

        let mut tampered = echo(&lawful);
        tampered.turn = IntentTurn::new(3, WorkerUtterance::new("utterance-secret-2e6-EDITED"));
        refusals.push(
            seq.accept_turn_response(&ctx, &lawful, &tampered)
                .unwrap_err(),
        ); // UtteranceAltered

        let empty = IntentTurnRequest::new(
            lawful.binding.clone(),
            IntentTurn::new(3, WorkerUtterance::new("")),
        );
        refusals.push(seq.admit_turn(&ctx, &empty).unwrap_err()); // InvalidInput

        assert_eq!(refusals.len(), 5, "one refusal per class");
        for err in &refusals {
            let rendered = serde_json::to_string(err).expect("serializes");
            for secret in secrets {
                assert!(
                    !rendered.contains(secret),
                    "refusal leaked `{secret}`: {rendered}"
                );
            }
        }
    }

    // ── wire contract ───────────────────────────────────────────────────────────

    #[test]
    fn the_request_and_response_round_trip_under_the_intent_schema() {
        let req = request(0, "req-0", "add a login page");
        let resp = echo(&req);

        let req_json = serde_json::to_string(&req).expect("serializes");
        let req_back: IntentTurnRequest = serde_json::from_str(&req_json).expect("round-trips");
        assert_eq!(req_back, req);

        let resp_json = serde_json::to_string(&resp).expect("serializes");
        let resp_back: IntentTurnResponse = serde_json::from_str(&resp_json).expect("round-trips");
        assert_eq!(resp_back, resp);

        let env = Envelope::success(SCHEMA_AUTHORING_INTENT_V1, None, resp);
        let line = env.to_line().expect("envelope serializes");
        assert!(
            line.contains("\"schema\":\"csq.authoring_intent.v1\""),
            "{line}"
        );
        assert!(
            line.contains("\"disposition\":\"needs_more_input\""),
            "{line}"
        );
        assert!(
            line.ends_with('}'),
            "one line, no trailing newline in to_line"
        );
    }

    #[test]
    fn a_future_shards_added_field_does_not_break_a_v1_consumer() {
        // The additive-extension claim: a later shard's optional field appears as an
        // unknown key to a consumer pinned to this major, and must be ignored rather
        // than rejected.
        let mut value = serde_json::to_value(request(0, "req-0", "add a login page")).unwrap();
        value["distilled_intent"] = serde_json::json!({"summary": "login page"});
        value["form_factor"] = serde_json::json!("cli");
        let parsed: IntentTurnRequest =
            serde_json::from_value(value).expect("an added field must not break the major");
        assert_eq!(parsed.turn.utterance.text(), "add a login page");
    }

    #[test]
    fn turn_disposition_wire_strings_match_serialize() {
        for (disposition, wire) in [
            (TurnDisposition::NeedsMoreInput, "needs_more_input"),
            (TurnDisposition::IntentCaptured, "intent_captured"),
        ] {
            assert_eq!(disposition.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&disposition).unwrap(),
                format!("\"{wire}\"")
            );
        }
    }
}
