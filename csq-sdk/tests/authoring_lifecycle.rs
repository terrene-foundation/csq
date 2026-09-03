//! The executable integration path for the governed authoring lifecycle (an internal ticket).
//!
//! This file is a CONSUMER, not an in-crate test: it links `csq-sdk` from outside and
//! touches only the public API, so a path it can drive is a path a downstream host can
//! drive with the same imports. That is the acceptance criterion it exists to hold —
//! the lifecycle must be CALLABLE, not describable as a convention inside a prompt.
//!
//! [`governed_authoring_lifecycle_runs_end_to_end`] walks intent turn → distillation →
//! form-factor inference → memory read/edit/delete → deletion read-back in one
//! sequence, and the three refusal tests below show tenant, identity/session, and
//! regional-routing claims refused BEFORE any provider egress or store access.

use csq_sdk::{
    infer_form_factor, AuthoritativeState, DecisionOutcome, DecisionProcedure, DecisionStep,
    DeliveryFormFactor, DistillationRequest, DistillationResponse, Envelope, FormFactorSignal,
    FormFactorSignalKind, InMemorySessionMemory, IntentTurn, IntentTurnRequest, IntentTurnResponse,
    IntentTurnSequence, MemoryDeleteRequest, MemoryEditRequest, MemoryGateway, MemoryReadRequest,
    MemoryScope, RequestCorrelation, RoutingEvidence, RoutingPolicy, ScopeRead, SdkError,
    SdkErrorCode, SessionBinding, SessionContext, SessionMemoryStore, SessionTurn, StepTransition,
    TurnDisposition, TurnRole, VerificationMethod, VerifiedOperator, WorkerUtterance,
    SCHEMA_AUTHORING_MEMORY_V1,
};

const TENANT: &str = "tenant-alpha";
const OPERATOR: &str = "operator-7";
const SESSION: &str = "sess-42";
const POLICY: &str = "policy-eu-only";
const ITEM: &str = "brief-1";
const BRIEF: &str = "a login page with SSO";

fn policy() -> RoutingPolicy {
    RoutingPolicy::new(POLICY, vec!["eu-west".to_string(), "eu-north".to_string()])
}

/// The session as ESTABLISHED by the host. Every request below is checked against it.
fn context() -> SessionContext {
    SessionContext::new(TENANT, OPERATOR, SESSION, policy())
}

/// A binding whose five invariants all match [`context`].
fn binding(correlation: &str) -> SessionBinding {
    SessionBinding::new(
        TENANT,
        VerifiedOperator::new(OPERATOR, VerificationMethod::OauthIdentity, "audit-rec-9"),
        SESSION,
        RequestCorrelation::Id(correlation.to_string()),
        RoutingEvidence::new("claude", "eu-west", policy()),
    )
}

/// Wraps the shipped store and counts every call that REACHES it, so a refusal test
/// can assert the store was never touched rather than only that an `Err` came back.
#[derive(Default)]
struct CountingStore {
    inner: InMemorySessionMemory,
    touches: usize,
}

impl SessionMemoryStore for CountingStore {
    fn load(&mut self, scope: &MemoryScope, item_id: &str) -> Result<ScopeRead, SdkError> {
        self.touches += 1;
        self.inner.load(scope, item_id)
    }

    fn store(
        &mut self,
        scope: &MemoryScope,
        item_id: &str,
        expected_revision: Option<u64>,
        content: &str,
    ) -> Result<u64, SdkError> {
        self.touches += 1;
        self.inner.store(scope, item_id, expected_revision, content)
    }

    fn remove(
        &mut self,
        scope: &MemoryScope,
        item_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<u64, SdkError> {
        self.touches += 1;
        self.inner.remove(scope, item_id, expected_revision)
    }
}

// ── the whole lifecycle, in one sequence ────────────────────────────────────────

#[test]
fn governed_authoring_lifecycle_runs_end_to_end() {
    let ctx = context();
    let mut store = InMemorySessionMemory::new();

    // 1. Intent: the SDK owns the multi-turn loop; the host advances it.
    let mut session = IntentTurnSequence::opening();
    let turn_0 = IntentTurnRequest::new(
        binding("req-0"),
        IntentTurn::new(0, WorkerUtterance::new(BRIEF)),
    );
    let egress = session
        .admit_turn(&ctx, &turn_0)
        .expect("the opening turn of a matching session is admitted");
    assert_eq!(egress.provider(), "claude");
    assert_eq!(egress.region(), "eu-west");

    let reply = IntentTurnResponse::new(
        turn_0.binding.clone(),
        turn_0.turn.clone(),
        TurnDisposition::NeedsMoreInput,
        "which identity provider?",
    );
    session
        .accept_turn_response(&ctx, &turn_0, &reply)
        .expect("a faithfully echoing response advances the session");
    assert_eq!(session.expected_index(), 1, "the cursor advanced");

    // 2 + 3. Distillation and form-factor inference over the same bound session.
    let turns = vec![
        SessionTurn::new("turn-1", TurnRole::Operator, "sha256:aaaa"),
        SessionTurn::new("turn-2", TurnRole::Assistant, "sha256:bbbb"),
    ];
    let signals = vec![FormFactorSignal::new(
        "sig-1",
        FormFactorSignalKind::InvokedFromShell,
        vec!["turn-1".to_string()],
    )];
    let distill = DistillationRequest::new(binding("req-1"), turns, signals.clone());
    let admitted = distill
        .admit(&ctx)
        .expect("a matching binding admits the distillation");
    assert_eq!(admitted.authorization().region(), "eu-west");
    assert_eq!(
        admitted.form_factor().form_factor(),
        Some(DeliveryFormFactor::CommandLine),
        "a shell-invocation signal determines the command-line form factor"
    );

    let procedure = DecisionProcedure::new(
        "proc-1",
        "step-a",
        vec![DecisionStep::new(
            "step-a",
            "does the operator run it themselves?",
            "the session names a shell invocation",
            vec!["turn-1".to_string()],
            vec![DecisionOutcome::new(
                "yes",
                StepTransition::Terminal("ship-as-cli".to_string()),
            )],
        )],
    );
    DistillationResponse::new(binding("req-1"), procedure, infer_form_factor(&signals))
        .accept(&ctx, &distill)
        .expect("a well-formed distillation response over the same session is accepted");

    // 4. Memory: read an unheld key, write it, read it back, delete it.
    let mut memory = MemoryGateway::new(&ctx, &mut store);

    let before = memory
        .read(&MemoryReadRequest::new(binding("req-2"), ITEM))
        .expect("a matching binding admits the read");
    assert!(
        matches!(before.state(), AuthoritativeState::Absent(_)),
        "an unheld key reads as an anchored absence, not an error"
    );

    let edit = memory
        .edit(&MemoryEditRequest::new(binding("req-3"), ITEM, BRIEF))
        .expect("the write applies");
    let wrote_at = edit.receipt().applied_at_revision;
    assert!(
        matches!(edit.state(), AuthoritativeState::Present(_)),
        "the post-write read-back observes the item present"
    );

    let after = memory
        .read(&MemoryReadRequest::new(binding("req-4"), ITEM))
        .expect("a matching binding admits the read");
    match after.state() {
        AuthoritativeState::Present(item) => {
            assert_eq!(
                item.content.as_deref(),
                Some(BRIEF),
                "a read discloses content"
            );
            assert_eq!(
                item.revision, wrote_at,
                "read-back names the write's revision"
            );
        }
        other => panic!("expected the written item to be present, got {other:?}"),
    }

    // 5. Deletion read-back: the receipt attests the removal, the PROOF attests the
    //    key is empty. They are separate claims and both are asserted.
    let deleted = memory
        .delete(&MemoryDeleteRequest::new(binding("req-5"), ITEM).expecting_revision(wrote_at))
        .expect("a delete at the observed revision applies");
    let proof = deleted
        .proven_absent()
        .expect("the post-delete read-back proves the key empty");
    assert_eq!(proof.item_id(), ITEM);
    assert_eq!(
        proof.scope(),
        &MemoryScope::new(TENANT, SESSION),
        "the proof is anchored to the ESTABLISHED tenant and session"
    );
    assert!(
        proof.observed_at_revision() >= wrote_at,
        "the absence is anchored at or after the write it supersedes"
    );

    let gone = memory
        .read(&MemoryReadRequest::new(binding("req-6"), ITEM))
        .expect("a matching binding admits the read");
    assert!(
        matches!(gone.state(), AuthoritativeState::Absent(_)),
        "an independent read agrees the key is empty"
    );
}

// ── refusals, each BEFORE provider egress and before the store is reached ────────

/// A binding differing from [`context`] in exactly the named field, so the refusal
/// this produces can only be attributed to that field.
fn tenant_mismatch() -> SessionBinding {
    SessionBinding::new(
        "tenant-beta",
        VerifiedOperator::new(OPERATOR, VerificationMethod::OauthIdentity, "audit-rec-9"),
        SESSION,
        RequestCorrelation::Id("req-x".to_string()),
        RoutingEvidence::new("claude", "eu-west", policy()),
    )
}

fn session_mismatch() -> SessionBinding {
    SessionBinding::new(
        TENANT,
        VerifiedOperator::new(OPERATOR, VerificationMethod::OauthIdentity, "audit-rec-9"),
        "sess-99",
        RequestCorrelation::Id("req-x".to_string()),
        RoutingEvidence::new("claude", "eu-west", policy()),
    )
}

fn denied_region() -> SessionBinding {
    SessionBinding::new(
        TENANT,
        VerifiedOperator::new(OPERATOR, VerificationMethod::OauthIdentity, "audit-rec-9"),
        SESSION,
        RequestCorrelation::Id("req-x".to_string()),
        RoutingEvidence::new("claude", "us-east", policy()),
    )
}

#[test]
fn a_tenant_mismatch_is_refused_before_egress_and_before_the_store() {
    let ctx = context();

    // No EgressAuthorization exists on this path: its only constructor is `admit`,
    // and `admit` returned Err — so there is no value with which to call a provider.
    let err = ctx
        .admit(&tenant_mismatch())
        .expect_err("a foreign tenant is refused");
    assert_eq!(err.code, SdkErrorCode::TenantMismatch);

    let err = IntentTurnSequence::opening()
        .admit_turn(
            &ctx,
            &IntentTurnRequest::new(
                tenant_mismatch(),
                IntentTurn::new(0, WorkerUtterance::new(BRIEF)),
            ),
        )
        .expect_err("a foreign tenant is refused on the intent turn too");
    assert_eq!(err.code, SdkErrorCode::TenantMismatch);

    let mut store = CountingStore::default();
    let err = MemoryGateway::new(&ctx, &mut store)
        .read(&MemoryReadRequest::new(tenant_mismatch(), ITEM))
        .expect_err("a foreign tenant is refused on the memory read");
    assert_eq!(err.code, SdkErrorCode::TenantMismatch);
    assert_eq!(store.touches, 0, "the store was never reached");
}

#[test]
fn a_verified_identity_or_session_mismatch_is_refused_before_egress_and_the_store() {
    let ctx = context();

    let err = ctx
        .admit(&session_mismatch())
        .expect_err("another session's id is refused");
    assert_eq!(err.code, SdkErrorCode::IdentityMismatch);

    let err = DistillationRequest::new(
        session_mismatch(),
        vec![SessionTurn::new(
            "turn-1",
            TurnRole::Operator,
            "sha256:aaaa",
        )],
        vec![FormFactorSignal::new(
            "sig-1",
            FormFactorSignalKind::InvokedFromShell,
            vec!["turn-1".to_string()],
        )],
    )
    .admit(&ctx)
    .expect_err("another session's id is refused on distillation");
    assert_eq!(err.code, SdkErrorCode::IdentityMismatch);

    let mut store = CountingStore::default();
    let err = MemoryGateway::new(&ctx, &mut store)
        .edit(&MemoryEditRequest::new(session_mismatch(), ITEM, BRIEF))
        .expect_err("another session's id is refused on the memory edit");
    assert_eq!(err.code, SdkErrorCode::IdentityMismatch);
    assert_eq!(store.touches, 0, "no write reached the store");
}

#[test]
fn regional_routing_outside_the_policy_is_refused_before_egress_and_the_store() {
    let ctx = context();

    let err = ctx
        .admit(&denied_region())
        .expect_err("a region outside the policy is refused");
    assert_eq!(err.code, SdkErrorCode::RoutingDenied);

    let err = IntentTurnSequence::opening()
        .admit_turn(
            &ctx,
            &IntentTurnRequest::new(
                denied_region(),
                IntentTurn::new(0, WorkerUtterance::new(BRIEF)),
            ),
        )
        .expect_err("a region outside the policy is refused on the intent turn");
    assert_eq!(err.code, SdkErrorCode::RoutingDenied);

    let mut store = CountingStore::default();
    let err = MemoryGateway::new(&ctx, &mut store)
        .delete(&MemoryDeleteRequest::new(denied_region(), ITEM))
        .expect_err("a region outside the policy is refused on the memory delete");
    assert_eq!(err.code, SdkErrorCode::RoutingDenied);
    assert_eq!(store.touches, 0, "no removal reached the store");
}

// ── output hygiene ──────────────────────────────────────────────────────────────

/// A refusal renders as one `\n`-free JSON line under the memory schema, so the
/// diagnostic text a host logs to stderr can never be mistaken for, or concatenated
/// into, the envelope stream on stdout.
#[test]
fn a_refusal_renders_as_exactly_one_json_line_carrying_no_identity() {
    let err = context()
        .admit(&denied_region())
        .expect_err("a region outside the policy is refused");
    let line = Envelope::<()>::failure(SCHEMA_AUTHORING_MEMORY_V1, None, err)
        .to_line()
        .expect("a failure envelope serializes");

    assert!(!line.contains('\n'), "an envelope is a single line");
    let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(v["schema"], SCHEMA_AUTHORING_MEMORY_V1);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "routing_denied");
    for leak in [TENANT, OPERATOR, SESSION, "us-east", BRIEF] {
        assert!(
            !line.contains(leak),
            "the refusal must not carry {leak:?}: {line}"
        );
    }
}
