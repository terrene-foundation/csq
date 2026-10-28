//! Authoritative session memory for `csq.authoring_session.v1` (an internal ticket, S4).
//!
//! Read, edit, and delete over an authoring session's authoritative memory. Every
//! operation rides the S1 envelope: it re-validates all five identity/routing
//! invariants through [`SessionContext::admit`] before it touches the store, and the
//! store is reached only through a private helper that takes the
//! [`EgressAuthorization`] `admit` returns — a value NO module, including this one,
//! can construct any other way.
//!
//! ## The claim this module exists to keep separate
//!
//! "The delete request was accepted" and "the item is gone" are DIFFERENT claims, and
//! a caller must not be able to read the first as the second. Here they are carried by
//! different types, and only one of them can be minted by observation:
//!
//! | claim | type | who can mint it |
//! | --- | --- | --- |
//! | the mutation was admitted and applied at revision N | [`MutationReceipt`] | [`MemoryGateway`], after the store applied it |
//! | the key was OBSERVED to hold no item | [`AbsenceProof`] | [`MemoryGateway`], and only from an authoritative read that returned no record |
//!
//! [`AbsenceProof`]'s only field is PRIVATE, so a struct literal is writable only
//! inside this module, and this module writes exactly one — on the `Ok(None)` arm of
//! the authoritative read. That is the mechanism, not a convention: holding an
//! `AbsenceProof` means that literal executed, and it executes only when the store
//! answered the read and answered with no record.
//!
//! ## An absent read-back is not proof of deletion
//!
//! The naive shape for a read-back is `Option<Item>`, where `None` silently merges
//! three different facts: the store reported no item, the store could not be reached,
//! and nobody looked. [`AuthoritativeState`] refuses that merge — it has a third arm,
//! [`AuthoritativeState::Unobserved`], and a read-back that could not be performed
//! lands there rather than on [`AuthoritativeState::Absent`]. A caller asking
//! [`MutationOutcome::proven_absent`] gets `None` in that case, which is the correct
//! answer: nothing was proven.
//!
//! ## Producing versus parsing
//!
//! [`AuthoritativeState`] is `Serialize` but deliberately NOT `Deserialize`: a value
//! parsed from JSON was not observed by the parsing process, so allowing it to
//! deserialize into a proof-carrying type would forge exactly the proof the seal
//! protects. A consumer parses [`ReportedState`] instead, whose `Absent` arm carries
//! no proof and is honest about being a report. `reported_state_matches_authoritative`
//! (in this module's tests) asserts the two shapes agree on the wire for all three
//! arms, which is what keeps them from drifting.
//!
//! ## Leak safety
//!
//! Every refusal in this module is a fixed `&'static str` naming a CLASS: no tenant
//! id, session id, item id, revision, or memory content is interpolated into an error
//! (`rules/security.md` §2). A [`MutationReceipt`] names the item and the revision it
//! was applied at and carries NO content — a deletion receipt cannot echo what it
//! deleted. Content is disclosed on ONE path only, [`MemoryGateway::read`], where the
//! caller explicitly asked for it; a mutation's read-back reports presence without it.
//!
//! ## Additive extension
//!
//! Every DTO here is `#[non_exhaustive]` and built through a constructor, so S5 adds a
//! field as `Option<T>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`
//! plus a `with_*` builder and the `csq.authoring_session.v1` major does not bump (the
//! contract-change policy in `crate`). These payloads attach to S1's
//! `AuthoringSessionRequest` / `AuthoringSessionResponse`; they do NOT name a new
//! schema major of their own, and no capability is advertised for them here.

use serde::{Deserialize, Serialize};

use crate::authoring_session::{
    EgressAuthorization, RequestCorrelation, SessionBinding, SessionContext,
};
use crate::error::{SdkError, SdkErrorCode};

// ── scope + stored record ───────────────────────────────────────────────────────

/// The isolation scope a memory operation runs in.
///
/// [`MemoryGateway`] derives the scope it passes to a [`SessionMemoryStore`] from the
/// authoritative [`SessionContext`], never from the caller's [`SessionBinding`], so a
/// caller cannot widen its own reach by restating a different tenant. A scope built by
/// hand through [`MemoryScope::new`] carries no such guarantee — the enforcement point
/// is the gateway, and a caller that owns the store directly has bypassed it already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryScope {
    /// The tenant whose memory is addressed.
    pub tenant_id: String,
    /// The authoring session whose memory is addressed.
    pub session_id: String,
}

impl MemoryScope {
    /// Build a scope from its two always-present fields.
    #[must_use]
    pub fn new(tenant_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            session_id: session_id.into(),
        }
    }

    /// The scope the gateway will use for `context` — tenant and session as
    /// ESTABLISHED, not as claimed.
    #[must_use]
    pub fn of_session(context: &SessionContext) -> Self {
        Self::new(&context.tenant_id, &context.session_id)
    }
}

/// One authoritative memory record as the backing store holds it.
///
/// `#[non_exhaustive]`: construct via [`StoredRecord::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StoredRecord {
    /// The store revision this content was written at. Monotonic per scope.
    pub revision: u64,
    /// The item's content, as the operator authored it.
    pub content: String,
}

impl StoredRecord {
    /// Build a record from its two always-present fields.
    #[must_use]
    pub fn new(revision: u64, content: impl Into<String>) -> Self {
        Self {
            revision,
            content: content.into(),
        }
    }
}

/// One authoritative read of a key, and the scope revision it was read AT.
///
/// The two travel together because an [`AbsenceProof`] is exactly the conjunction of
/// them — "this key held no record, at this revision" — and a conjunction assembled
/// from two separate store calls is not one observation. Reading the record and the
/// watermark as one value is what lets an implementor make the pair atomic; with two
/// calls it cannot, whatever it does internally, because the gateway has already
/// interleaved them.
///
/// `#[non_exhaustive]`: construct via [`ScopeRead::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScopeRead {
    /// The record the key held, or `None` if the scope holds no such item.
    pub record: Option<StoredRecord>,
    /// The scope's revision watermark AT the moment `record` was determined.
    pub scope_revision: u64,
}

impl ScopeRead {
    /// Build a read result from its two always-present fields.
    #[must_use]
    pub const fn new(record: Option<StoredRecord>, scope_revision: u64) -> Self {
        Self {
            record,
            scope_revision,
        }
    }
}

/// The backing store for authoritative session memory.
///
/// This crate is the wire contract and owns no persistence; the APP supplies the
/// implementation (the daemon's session store). The governance — invariant
/// re-validation, routing-before-access, and the mandatory post-mutation read-back —
/// lives in [`MemoryGateway`] and is not delegated to the implementor, so a store that
/// merely reads and writes still yields governed outcomes.
///
/// An implementor MUST distinguish "no record" (`Ok(None)`) from "could not answer"
/// (`Err`). Collapsing the second into the first would let the gateway mint an
/// [`AbsenceProof`] for a read that never happened, which is the one thing the proof
/// exists to rule out.
///
/// # Store errors do not reach the wire
///
/// An implementor's error message is NOT forwarded. [`MemoryGateway`] re-wraps every
/// store error, preserving only its [`SdkErrorCode`] and substituting a fixed label of
/// this module's own — so a message built with [`SdkError::trusted`] (which skips
/// redaction by design) cannot carry an item id, revision, scope, or memory content
/// out through a refusal envelope. The `known` set is dropped for the same reason.
///
/// This is belt-and-braces, not a licence: an implementor SHOULD still keep its
/// messages free of content, because it cannot know that every future caller of its
/// store is this gateway. But the guarantee that a refusal from THIS surface is
/// content-free does not depend on it doing so.
pub trait SessionMemoryStore {
    /// Read the authoritative record for `item_id` together with the scope revision
    /// that read was taken at.
    ///
    /// [`ScopeRead::record`] is `None` when the scope holds no such item;
    /// [`ScopeRead::scope_revision`] is the watermark an observation of the scope is
    /// anchored to, and is what an [`AbsenceProof`] names. A key the scope does not
    /// hold has no revision of its own, which is why the watermark is returned
    /// unconditionally rather than derived from a record that may not exist.
    ///
    /// An implementor SHOULD determine both halves under whatever consistency
    /// mechanism it has (one snapshot, one transaction, one lock). The gateway cannot
    /// do this on its behalf: it is a single call precisely so that a concurrent
    /// writer has no window between the record and the watermark to land in.
    ///
    /// # Errors
    /// Any [`SdkError`] the store raises. An error means the question was NOT answered;
    /// it must not be used to signal absence. The gateway reports
    /// [`AuthoritativeState::Unobserved`] rather than minting a proof it cannot anchor.
    fn load(&mut self, scope: &MemoryScope, item_id: &str) -> Result<ScopeRead, SdkError>;

    /// Write `content` at `item_id`, returning the revision the write landed at.
    ///
    /// When `expected_revision` is `Some(n)`, the write applies only if the item is
    /// currently at revision `n`; otherwise the implementor returns
    /// [`SdkErrorCode::RevisionConflict`]. When it is `None` the write is an upsert.
    ///
    /// # Errors
    /// [`SdkErrorCode::RevisionConflict`] on a failed precondition, or any store error.
    fn store(
        &mut self,
        scope: &MemoryScope,
        item_id: &str,
        expected_revision: Option<u64>,
        content: &str,
    ) -> Result<u64, SdkError>;

    /// Remove `item_id`, returning the revision the removal landed at.
    ///
    /// Removal is idempotent: removing an item the scope does not hold succeeds and
    /// returns the scope's current revision watermark. `expected_revision` behaves as
    /// in [`Self::store`].
    ///
    /// # Errors
    /// [`SdkErrorCode::RevisionConflict`] on a failed precondition, or any store error.
    fn remove(
        &mut self,
        scope: &MemoryScope,
        item_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<u64, SdkError>;
}

// ── observed state ──────────────────────────────────────────────────────────────

/// Proof that an authoritative read ran against the store and returned no record.
///
/// Its single field is PRIVATE, which is what makes this a proof rather than a label:
/// a struct literal is writable only inside this module, and this module writes
/// exactly one — on the `Ok(None)` arm of `MemoryGateway::observe`. Every other path
/// (a record came back, the store errored, or the absence could not be anchored to a
/// revision) produces a different [`AuthoritativeState`] arm, so no code outside that
/// one arm can produce this type at all.
///
/// `Serialize` only, by design: a value recovered from JSON was not observed by the
/// process recovering it, so a `Deserialize` impl would manufacture the very proof the
/// private field protects. Consumers parse [`ReportedState`].
#[derive(Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AbsenceProof {
    scope: MemoryScope,
    item_id: String,
    observed_at_revision: u64,
}

impl AbsenceProof {
    /// The store revision at which the absence was observed.
    ///
    /// Absence is a fact about that revision. A later turn may re-create the item;
    /// this value is what lets a caller say WHEN the key was empty rather than that it
    /// is empty now.
    #[must_use]
    pub const fn observed_at_revision(&self) -> u64 {
        self.observed_at_revision
    }

    /// The scope the absence was observed in.
    ///
    /// Present so the proof names its subject. A proof naming neither scope nor item is
    /// a universal absence token: any absence, for any key, satisfies any question about
    /// any other key.
    #[must_use]
    pub const fn scope(&self) -> &MemoryScope {
        &self.scope
    }

    /// The item the absence was observed for.
    #[must_use]
    pub fn item_id(&self) -> &str {
        &self.item_id
    }
}

/// An item observed present by a read.
///
/// `content` is disclosed by [`MemoryGateway::read`] and withheld by a mutation's
/// read-back, so a delete that did not take effect reports presence without echoing
/// what it failed to delete.
///
/// `#[non_exhaustive]`: construct via [`ObservedItem::disclosed`] /
/// [`ObservedItem::undisclosed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ObservedItem {
    /// The item's identifier within the scope.
    pub item_id: String,
    /// The revision the observation saw.
    pub revision: u64,
    /// The item's content — present only on a read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl ObservedItem {
    /// An observation that discloses the item's content (the read path).
    #[must_use]
    pub fn disclosed(
        item_id: impl Into<String>,
        revision: u64,
        content: impl Into<String>,
    ) -> Self {
        Self {
            item_id: item_id.into(),
            revision,
            content: Some(content.into()),
        }
    }

    /// An observation that reports presence without content (a mutation read-back).
    #[must_use]
    pub fn undisclosed(item_id: impl Into<String>, revision: u64) -> Self {
        Self {
            item_id: item_id.into(),
            revision,
            content: None,
        }
    }
}

/// Why an authoritative read-back could not settle the question.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnobservedReason {
    /// The read-back was attempted and the store could not answer it.
    ReadBackFailed,
}

impl UnobservedReason {
    /// The stable wire string for this reason (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadBackFailed => "read_back_failed",
        }
    }
}

/// What an authoritative read OBSERVED about a key.
///
/// Three arms, because there are three facts and `Option` has room for two. The third
/// arm is what stops "the store could not answer" from being reported as "the item is
/// gone".
///
/// `Serialize` only — see [`AbsenceProof`]; consumers parse [`ReportedState`].
// NOT `Clone`, deliberately, and for the reason `AbsenceProof` is not: a cloneable
// `Absent` arm can be duplicated and attached to a different outcome, which is exactly
// the relocation the private field and the item-id guard exist to prevent. Consumers
// needing a copyable view parse `ReportedState`, which carries no proof.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthoritativeState {
    /// The read observed a record.
    Present(ObservedItem),
    /// The read ran and observed no record. Carries the proof.
    Absent(AbsenceProof),
    /// The read could not be performed. Carries no claim in either direction.
    Unobserved(UnobservedReason),
}

/// The consumer-side view of [`AuthoritativeState`], recovered from the wire.
///
/// Its `Absent` arm carries NO [`AbsenceProof`], which is the point: a state parsed
/// from JSON was observed by the emitting process, not by the parsing one, so it is a
/// REPORT of an observation and is typed as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReportedState {
    /// The emitter reported a record present.
    Present(ObservedItem),
    /// The emitter reported the key empty at `observed_at_revision`.
    Absent {
        /// The scope the emitter observed the absence in.
        scope: MemoryScope,
        /// The item the emitter observed absent.
        item_id: String,
        /// The revision the emitter observed the absence at.
        observed_at_revision: u64,
    },
    /// The emitter reported that it could not settle the question.
    Unobserved(UnobservedReason),
}

// ── receipts + outcomes ─────────────────────────────────────────────────────────

/// Which mutation a [`MutationReceipt`] attests to.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MemoryOperation {
    /// Content was written at the item.
    Edit,
    /// The item was removed.
    Delete,
}

impl MemoryOperation {
    /// The stable wire string for this operation (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Delete => "delete",
        }
    }
}

/// Attestation that a mutation was admitted and APPLIED.
///
/// A receipt states exactly this: the turn named by `correlation` passed all five
/// invariants, and the store applied `operation` to `item_id` at
/// `applied_at_revision`. It states nothing about the key's state now — a later turn
/// may have re-created a deleted item — and it carries no content, so a delete receipt
/// cannot echo what it deleted. The current state is [`MutationOutcome::state`], and
/// only that side can carry an [`AbsenceProof`].
///
/// `#[non_exhaustive]`: construct via [`MutationReceipt::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MutationReceipt {
    /// The item the mutation was applied to.
    pub item_id: String,
    /// Which mutation was applied.
    pub operation: MemoryOperation,
    /// The turn this mutation belongs to, echoed from the request's binding.
    pub correlation: RequestCorrelation,
    /// The store revision the mutation was applied at.
    pub applied_at_revision: u64,
}

impl MutationReceipt {
    /// Build a receipt from its four always-present fields.
    #[must_use]
    pub fn new(
        item_id: impl Into<String>,
        operation: MemoryOperation,
        correlation: RequestCorrelation,
        applied_at_revision: u64,
    ) -> Self {
        Self {
            item_id: item_id.into(),
            operation,
            correlation,
            applied_at_revision,
        }
    }
}

/// A mutation's receipt PLUS the authoritative post-state read back after it.
///
/// The two halves are reachable only through [`Self::receipt`] and [`Self::state`],
/// and neither type mentions the other's claim: the receipt has no "deleted" flag and
/// the state has no "accepted" flag. A caller that wants "is it gone" asks
/// [`Self::proven_absent`], which answers `Some` only for
/// [`AuthoritativeState::Absent`] — never for a read-back that failed.
///
/// `Serialize` only — its `state` carries an [`AbsenceProof`].
// Not `Clone` — it holds an `AuthoritativeState`; see that type.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MutationOutcome {
    /// What was applied.
    pub receipt: MutationReceipt,
    /// What the store held when read back immediately afterwards.
    ///
    /// PRIVATE deliberately, read through [`Self::state`]. A `pub` field lets a consumer
    /// overwrite an `Unobserved` or `Present` read-back with an `Absent` arm obtained
    /// elsewhere, which is the whole of what [`Self::proven_absent`] answers — the
    /// accessor is not a style preference, it is the seal.
    state: AuthoritativeState,
}

impl MutationOutcome {
    /// What was applied.
    #[must_use]
    pub const fn receipt(&self) -> &MutationReceipt {
        &self.receipt
    }

    /// What the read-back observed.
    #[must_use]
    pub const fn state(&self) -> &AuthoritativeState {
        &self.state
    }

    /// The absence proof, iff the read-back OBSERVED the key empty.
    ///
    /// `None` covers two different situations — the item is still present, and the
    /// read-back could not run — and in neither is deletion proven, which is why they
    /// share an answer here and are distinguishable through [`Self::state`].
    /// A proof whose subject is not this outcome's item answers NOTHING about it, so
    /// the item ids must agree. Without that guard a proof legitimately obtained by
    /// reading some other, unheld key satisfies this call for an item that is still
    /// present — the check is what makes the proof about THIS mutation.
    #[must_use]
    pub fn proven_absent(&self) -> Option<&AbsenceProof> {
        match &self.state {
            AuthoritativeState::Absent(proof) if proof.item_id() == self.receipt.item_id => {
                Some(proof)
            }
            _ => None,
        }
    }
}

/// The result of [`MemoryGateway::read`].
///
/// `Serialize` only — its `state` carries an [`AbsenceProof`].
// Not `Clone` — it holds an `AuthoritativeState`; see that type.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ReadOutcome {
    /// The item that was read.
    pub item_id: String,
    /// What the read observed. PRIVATE for the reason given on
    /// [`MutationOutcome::state`]; read it through [`Self::state`].
    state: AuthoritativeState,
}

impl ReadOutcome {
    /// What the read observed.
    ///
    /// This is the accessor [`Self::state`]'s field doc directs a consumer to; without
    /// it a read outcome was inspectable only by serializing the whole value.
    #[must_use]
    pub const fn state(&self) -> &AuthoritativeState {
        &self.state
    }
}

// ── request DTOs ────────────────────────────────────────────────────────────────

/// `csq.authoring_session.v1` — a memory READ turn.
///
/// `#[non_exhaustive]`: construct via [`MemoryReadRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryReadRequest {
    /// The five invariants for this turn.
    pub binding: SessionBinding,
    /// The item to read.
    pub item_id: String,
}

impl MemoryReadRequest {
    /// Build a read request from its two always-present fields.
    #[must_use]
    pub fn new(binding: SessionBinding, item_id: impl Into<String>) -> Self {
        Self {
            binding,
            item_id: item_id.into(),
        }
    }
}

/// `csq.authoring_session.v1` — a memory EDIT turn.
///
/// `#[non_exhaustive]`: construct via [`MemoryEditRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryEditRequest {
    /// The five invariants for this turn.
    pub binding: SessionBinding,
    /// The item to write.
    pub item_id: String,
    /// The revision the caller believes the item is at. `None` writes unconditionally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    /// The content to write.
    pub content: String,
}

impl MemoryEditRequest {
    /// Build an unconditional edit request.
    #[must_use]
    pub fn new(
        binding: SessionBinding,
        item_id: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            binding,
            item_id: item_id.into(),
            expected_revision: None,
            content: content.into(),
        }
    }

    /// Require the item to be at `revision` for the write to apply.
    #[must_use]
    pub fn expecting_revision(mut self, revision: u64) -> Self {
        self.expected_revision = Some(revision);
        self
    }
}

/// `csq.authoring_session.v1` — a memory DELETE turn.
///
/// `#[non_exhaustive]`: construct via [`MemoryDeleteRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryDeleteRequest {
    /// The five invariants for this turn.
    pub binding: SessionBinding,
    /// The item to remove.
    pub item_id: String,
    /// The revision the caller believes the item is at. `None` removes unconditionally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
}

impl MemoryDeleteRequest {
    /// Build an unconditional delete request.
    #[must_use]
    pub fn new(binding: SessionBinding, item_id: impl Into<String>) -> Self {
        Self {
            binding,
            item_id: item_id.into(),
            expected_revision: None,
        }
    }

    /// Require the item to be at `revision` for the removal to apply.
    #[must_use]
    pub fn expecting_revision(mut self, revision: u64) -> Self {
        self.expected_revision = Some(revision);
        self
    }
}

// ── the gateway ─────────────────────────────────────────────────────────────────

/// The only governed path to authoring-session memory.
///
/// Each operation runs, in this order: [`SessionContext::admit`] on the turn's
/// binding — which re-validates all five invariants against the ESTABLISHED session
/// and yields an [`EgressAuthorization`] — then the store, reached through a private
/// helper that takes that authorization by reference. Since
/// [`EgressAuthorization`]'s only constructor lives in `authoring_session` and is
/// private there, no code in this module can reach the store without having passed the
/// routing check; the ordering is a type requirement, not a review comment.
///
/// The scope handed to the store is [`MemoryScope::of_session`] over the gateway's
/// context, so the tenant and session addressed are the established ones even if the
/// caller's binding claimed otherwise — though a binding claiming otherwise is refused
/// by `admit` first.
pub struct MemoryGateway<'a, S: SessionMemoryStore> {
    context: &'a SessionContext,
    store: &'a mut S,
}

impl<'a, S: SessionMemoryStore> MemoryGateway<'a, S> {
    /// Bind a gateway to a session's authoritative context and its backing store.
    pub fn new(context: &'a SessionContext, store: &'a mut S) -> Self {
        Self { context, store }
    }

    /// Read an item, disclosing its content when present.
    ///
    /// # Errors
    /// Whatever [`SessionContext::admit`] refuses the binding with
    /// ([`SdkErrorCode::InvalidInput`], [`SdkErrorCode::TenantMismatch`],
    /// [`SdkErrorCode::IdentityMismatch`], [`SdkErrorCode::RoutingDenied`]), or
    /// [`SdkErrorCode::InvalidInput`] for an empty `item_id`. A store that cannot
    /// answer is NOT an error here — it is [`AuthoritativeState::Unobserved`].
    pub fn read(&mut self, request: &MemoryReadRequest) -> Result<ReadOutcome, SdkError> {
        let egress = self.context.admit(&request.binding)?;
        require_item_id(&request.item_id)?;
        let state = self.observe(&request.item_id, Disclosure::Content, &egress);
        Ok(ReadOutcome {
            item_id: request.item_id.clone(),
            state,
        })
    }

    /// Write content at an item, then read the result back authoritatively.
    ///
    /// # Errors
    /// As [`Self::read`], plus [`SdkErrorCode::RevisionConflict`] (or any store error)
    /// when the write itself does not apply. No receipt is produced for a mutation
    /// that did not apply.
    pub fn edit(&mut self, request: &MemoryEditRequest) -> Result<MutationOutcome, SdkError> {
        let egress = self.context.admit(&request.binding)?;
        require_item_id(&request.item_id)?;
        let applied_at_revision = self.apply_store(
            &request.item_id,
            request.expected_revision,
            &request.content,
            &egress,
        )?;
        let state = self.observe(&request.item_id, Disclosure::PresenceOnly, &egress);
        Ok(MutationOutcome {
            receipt: MutationReceipt::new(
                &request.item_id,
                MemoryOperation::Edit,
                request.binding.correlation.clone(),
                applied_at_revision,
            ),
            state,
        })
    }

    /// Remove an item, then read the key back authoritatively.
    ///
    /// The returned [`MutationOutcome`] separates the two claims: its receipt attests
    /// that the removal was applied, and only [`MutationOutcome::proven_absent`] — fed
    /// by the read-back below — attests that the key is empty.
    ///
    /// # Errors
    /// As [`Self::edit`].
    pub fn delete(&mut self, request: &MemoryDeleteRequest) -> Result<MutationOutcome, SdkError> {
        let egress = self.context.admit(&request.binding)?;
        require_item_id(&request.item_id)?;
        let applied_at_revision =
            self.apply_remove(&request.item_id, request.expected_revision, &egress)?;
        let state = self.observe(&request.item_id, Disclosure::PresenceOnly, &egress);
        Ok(MutationOutcome {
            receipt: MutationReceipt::new(
                &request.item_id,
                MemoryOperation::Delete,
                request.binding.correlation.clone(),
                applied_at_revision,
            ),
            state,
        })
    }

    /// Write, gated by the authorization the way [`Self::observe`] is.
    ///
    /// `_egress` is unused in the body and load-bearing in the signature. Before this
    /// helper existed the ordering held only by STATEMENT ORDER — `admit` happened to be
    /// first — so deleting that line left a mutation that still compiled, caught by tests
    /// alone. Now the type system carries it, and the module doc's claim that the store is
    /// reachable only through an authorization-taking helper is true of the MUTATING paths
    /// too, not just the read.
    fn apply_store(
        &mut self,
        item_id: &str,
        expected_revision: Option<u64>,
        content: &str,
        _egress: &EgressAuthorization,
    ) -> Result<u64, SdkError> {
        let scope = MemoryScope::of_session(self.context);
        self.store
            .store(&scope, item_id, expected_revision, content)
            .map_err(reclassify_store_error)
    }

    /// Remove, gated exactly as [`Self::apply_store`].
    fn apply_remove(
        &mut self,
        item_id: &str,
        expected_revision: Option<u64>,
        _egress: &EgressAuthorization,
    ) -> Result<u64, SdkError> {
        let scope = MemoryScope::of_session(self.context);
        self.store
            .remove(&scope, item_id, expected_revision)
            .map_err(reclassify_store_error)
    }

    /// The authoritative read, and the ONLY site that mints an [`AbsenceProof`].
    ///
    /// `_egress` is unused in the body and load-bearing in the signature: taking it
    /// makes reaching the store impossible without a value only
    /// [`SessionContext::admit`] can produce.
    fn observe(
        &mut self,
        item_id: &str,
        disclosure: Disclosure,
        _egress: &EgressAuthorization,
    ) -> AuthoritativeState {
        let scope = MemoryScope::of_session(self.context);
        match self.store.load(&scope, item_id) {
            Ok(read) => match read.record {
                Some(record) => AuthoritativeState::Present(match disclosure {
                    Disclosure::Content => {
                        ObservedItem::disclosed(item_id, record.revision, record.content)
                    }
                    Disclosure::PresenceOnly => ObservedItem::undisclosed(item_id, record.revision),
                }),
                // The ONLY AbsenceProof literal in this crate. It sits behind two
                // conditions, and they are now established by ONE store call: the store
                // answered the read, and it answered with no record; and that answer
                // carried the scope revision, so the proof names WHEN the key was empty.
                // An unanchorable absence is not a proof — and a pair of separately
                // anchored halves is not one observation.
                None => AuthoritativeState::Absent(AbsenceProof {
                    scope: scope.clone(),
                    item_id: item_id.to_owned(),
                    observed_at_revision: read.scope_revision,
                }),
            },
            Err(_) => AuthoritativeState::Unobserved(UnobservedReason::ReadBackFailed),
        }
    }
}

/// Whether an observation discloses content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disclosure {
    /// The read path: the caller asked for the item.
    Content,
    /// A mutation read-back: presence is the question, content is not disclosed.
    PresenceOnly,
}

/// Re-wrap a store-authored error so only its CLASS crosses the envelope.
///
/// The implementor's [`SdkErrorCode`] is preserved — that is the part a consumer
/// branches on, and [`SdkErrorCode::RevisionConflict`] in particular carries a
/// mechanical recovery. Everything the implementor WROTE is discarded: the message is
/// replaced with a fixed `&'static str` of this module's own, and any `known` set is
/// dropped.
///
/// # Why the message cannot be forwarded
///
/// [`SdkError::trusted`] skips redaction by design, so an implementor building
/// ``SdkError::trusted(RevisionConflict, format!("item {item_id} at rev {n}: {content}"))``
/// would put an item id and memory content on the same wire this module keeps
/// scrupulously clean (`rules/security.md` §2). Redaction would not save it either:
/// `csq-redact` catches secret-SHAPED tokens, and an item id or a memory body has no
/// shape to catch. Dropping the message is the only mechanism that holds for a store
/// this crate does not own.
fn reclassify_store_error(err: SdkError) -> SdkError {
    SdkError::trusted(
        err.code,
        match err.code {
            SdkErrorCode::RevisionConflict => {
                "authoring memory: the store refused the mutation — the item is not at the expected revision"
            }
            _ => "authoring memory: the store did not apply the mutation",
        },
    )
}

/// The longest item id this contract admits.
///
/// A bound, not a taste: `item_id` is caller-supplied and crosses into an
/// implementor's store as a key. 512 is far above any legitimate identifier and far
/// below a length that makes a key-space scan or a log line expensive.
const ITEM_ID_MAX_BYTES: usize = 512;

/// Structural check on the addressed item.
///
/// The refusal names the class only — no item id is interpolated (`security.md` §2).
///
/// # Why this constrains shape and not just emptiness
///
/// `csq-sdk` owns no persistence, so this value is handed to an implementor's store as
/// an opaque key — and the obvious implementation maps it to a path under the scope's
/// directory. `../../../other-tenant/brief-1` then walks straight out of the scope the
/// gateway derives from the authoritative `SessionContext`, bypassing the tenant
/// isolation every other part of this module enforces, one directory at a time.
///
/// Refusing the shape HERE is what makes that structural. A note in the trait's
/// contract would be a memory test taken by every future implementor, and the one who
/// fails it loses tenant isolation silently.
fn require_item_id(item_id: &str) -> Result<(), SdkError> {
    if item_id.is_empty() {
        return Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "authoring session memory: item id must not be empty",
        ));
    }
    if item_id.len() > ITEM_ID_MAX_BYTES {
        return Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "authoring session memory: item id is longer than the contract admits",
        ));
    }
    // Path separators and traversal, on both platform conventions. Also refuses control
    // characters and NUL, which are the log-injection and C-string-truncation shapes.
    if item_id.contains('/')
        || item_id.contains('\\')
        || item_id.split('/').any(|seg| seg == "..")
        || item_id.contains("..")
        || item_id.chars().any(char::is_control)
    {
        return Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "authoring session memory: item id must not contain a path separator, a \
             parent-directory reference, or a control character",
        ));
    }
    Ok(())
}

// ── the in-process store ────────────────────────────────────────────────────────

use std::collections::BTreeMap;

/// One scope's authoritative state: a monotonic revision watermark and the records
/// it currently holds.
#[derive(Debug, Default, Clone)]
struct ScopeState {
    revision: u64,
    items: BTreeMap<String, StoredRecord>,
}

/// A complete [`SessionMemoryStore`] whose durability is the LIFETIME OF THIS VALUE.
///
/// This is the store an embedding host gets for free, so the authoring lifecycle —
/// including the mutation receipts and the post-delete read-back that turn a deletion
/// into an [`AbsenceProof`] — is executable in this build with no persistence backend
/// to provision. It implements every method of the trait for real: revisions are
/// monotonic per scope, `expected_revision` preconditions are enforced and refused with
/// [`SdkErrorCode::RevisionConflict`], and `load` returns `Ok(None)` for a key the
/// scope does not hold while never collapsing an error into an absence (it cannot
/// fail, so the distinction the trait requires holds vacuously and correctly).
///
/// **Scope of the durability claim, per this type's mechanism:** state lives in the
/// `BTreeMap` below and is dropped with the value. It therefore survives exactly as
/// long as the process holds it — which spans an authoring session driven in-process,
/// and does NOT span separate processes or a restart. A host that needs memory to
/// outlive the process implements [`SessionMemoryStore`] over its own backend; the
/// gateway's governance is identical either way, because [`MemoryGateway`] performs
/// every invariant, routing, and read-back check itself and delegates only the raw
/// read and write. Cross-process durability is downstream hosting (an internal ticket's own
/// scope boundary), not a gap in this type.
///
/// Isolation is by `(tenant_id, session_id)`: two scopes never observe each other's
/// records or revisions, because every method resolves its `ScopeState` through the
/// scope key before touching anything.
#[derive(Debug, Default, Clone)]
pub struct InMemorySessionMemory {
    scopes: BTreeMap<(String, String), ScopeState>,
}

impl InMemorySessionMemory {
    /// An empty store holding no scopes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The state for `scope`, created empty on first use.
    fn scope_state(&mut self, scope: &MemoryScope) -> &mut ScopeState {
        self.scopes
            .entry((scope.tenant_id.clone(), scope.session_id.clone()))
            .or_default()
    }

    /// Enforce an `expected_revision` precondition against the item's CURRENT
    /// revision. An absent item satisfies no stated expectation, so a precondition
    /// naming a revision for a key the scope does not hold is a conflict.
    ///
    /// # Errors
    /// [`SdkErrorCode::RevisionConflict`] when the precondition does not hold. The
    /// message names neither the tenant, the session, the item, nor any content.
    fn check_precondition(
        state: &ScopeState,
        item_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<(), SdkError> {
        let Some(expected) = expected_revision else {
            return Ok(());
        };
        if state.items.get(item_id).map(|r| r.revision) == Some(expected) {
            Ok(())
        } else {
            Err(SdkError::trusted(
                SdkErrorCode::RevisionConflict,
                "authoring session memory: item is not at the expected revision",
            ))
        }
    }
}

impl SessionMemoryStore for InMemorySessionMemory {
    /// Both halves are read from the same `&mut` borrow of the scope's state, so no
    /// other caller can interleave between them — this implementor's atomicity is the
    /// borrow itself.
    fn load(&mut self, scope: &MemoryScope, item_id: &str) -> Result<ScopeRead, SdkError> {
        let state = self.scope_state(scope);
        Ok(ScopeRead::new(
            state.items.get(item_id).cloned(),
            state.revision,
        ))
    }

    fn store(
        &mut self,
        scope: &MemoryScope,
        item_id: &str,
        expected_revision: Option<u64>,
        content: &str,
    ) -> Result<u64, SdkError> {
        let state = self.scope_state(scope);
        Self::check_precondition(state, item_id, expected_revision)?;
        state.revision += 1;
        let revision = state.revision;
        state
            .items
            .insert(item_id.to_owned(), StoredRecord::new(revision, content));
        Ok(revision)
    }

    fn remove(
        &mut self,
        scope: &MemoryScope,
        item_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<u64, SdkError> {
        let state = self.scope_state(scope);
        Self::check_precondition(state, item_id, expected_revision)?;
        // The trait makes removal idempotent and specifies that removing a key the
        // scope does not hold returns the CURRENT watermark. Bumping here would move
        // the watermark for a no-op, so an unconditional delete of an absent key is
        // answered without a bump.
        if state.items.remove(item_id).is_none() {
            return Ok(state.revision);
        }
        state.revision += 1;
        Ok(state.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authoring_session::{
        RoutingEvidence, RoutingPolicy, VerificationMethod, VerifiedOperator,
    };
    use std::collections::HashMap;

    const TENANT: &str = "tenant-alpha";
    const OPERATOR: &str = "operator-7";
    const SESSION: &str = "sess-42";
    const POLICY: &str = "policy-eu-only";
    const ITEM: &str = "brief-1";
    const SECRET_CONTENT: &str = "the operator's authored brief body";

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

    /// A hermetic store with fault injection, so the three read-back outcomes
    /// (record / no record / cannot answer) are each reachable on demand.
    #[derive(Default)]
    struct FakeStore {
        items: HashMap<String, StoredRecord>,
        revision: u64,
        /// Scopes the store was actually asked about, in call order.
        seen_scopes: Vec<MemoryScope>,
        /// Number of `load` + `store` + `remove` calls that reached the store.
        touches: usize,
        fail_load: bool,
        /// The store can read the record but cannot determine the scope watermark, so
        /// it cannot answer at all — an absence it returned would be unanchorable.
        fail_revision: bool,
        /// Re-insert the item immediately after a `remove`, modelling a concurrent
        /// re-create between the mutation and its read-back.
        resurrect_on_remove: bool,
        /// The store refuses the mutation with an error whose message carries the item
        /// id and the memory content — built with `SdkError::trusted`, so redaction is
        /// skipped by design. A conforming implementor should not do this; the point is
        /// that the gateway's guarantee must not DEPEND on it not doing it.
        leak_through_store_error: bool,
        /// The scope's watermark advances on every read, modelling a concurrently
        /// written scope. Any anchor assembled from two separate calls disagrees with
        /// itself; one call cannot.
        bump_revision_per_read: bool,
    }

    impl FakeStore {
        fn with_item(content: &str) -> Self {
            let mut s = Self {
                revision: 4,
                ..Self::default()
            };
            s.items
                .insert(ITEM.to_string(), StoredRecord::new(4, content));
            s
        }
    }

    impl SessionMemoryStore for FakeStore {
        fn load(&mut self, scope: &MemoryScope, item_id: &str) -> Result<ScopeRead, SdkError> {
            self.touches += 1;
            self.seen_scopes.push(scope.clone());
            // Two distinct ways to be unable to answer, both now surfacing through the
            // one call: the record could not be read, or it could but the scope's
            // watermark could not be determined — and an absence with no watermark is
            // not anchorable, so it must not be reported as one.
            if self.fail_load || self.fail_revision {
                return Err(SdkError::trusted(SdkErrorCode::Internal, "store offline"));
            }
            if self.bump_revision_per_read {
                self.revision += 1;
            }
            Ok(ScopeRead::new(
                self.items.get(item_id).cloned(),
                self.revision,
            ))
        }

        fn store(
            &mut self,
            scope: &MemoryScope,
            item_id: &str,
            expected_revision: Option<u64>,
            content: &str,
        ) -> Result<u64, SdkError> {
            self.touches += 1;
            self.seen_scopes.push(scope.clone());
            if self.leak_through_store_error {
                return Err(SdkError::trusted(
                    SdkErrorCode::RevisionConflict,
                    format!("item {item_id} at rev {}: {content}", self.revision),
                ));
            }
            let current = self.items.get(item_id).map(|r| r.revision);
            if let Some(expected) = expected_revision {
                if current != Some(expected) {
                    return Err(SdkError::trusted(
                        SdkErrorCode::RevisionConflict,
                        "authoring session memory: item is not at the expected revision",
                    ));
                }
            }
            self.revision += 1;
            self.items.insert(
                item_id.to_string(),
                StoredRecord::new(self.revision, content),
            );
            Ok(self.revision)
        }

        fn remove(
            &mut self,
            scope: &MemoryScope,
            item_id: &str,
            expected_revision: Option<u64>,
        ) -> Result<u64, SdkError> {
            self.touches += 1;
            self.seen_scopes.push(scope.clone());
            if self.leak_through_store_error {
                return Err(SdkError::trusted(
                    SdkErrorCode::RevisionConflict,
                    format!("item {item_id} at rev {}", self.revision),
                ));
            }
            let current = self.items.get(item_id).map(|r| r.revision);
            if let Some(expected) = expected_revision {
                if current != Some(expected) {
                    return Err(SdkError::trusted(
                        SdkErrorCode::RevisionConflict,
                        "authoring session memory: item is not at the expected revision",
                    ));
                }
            }
            self.items.remove(item_id);
            self.revision += 1;
            if self.resurrect_on_remove {
                self.items.insert(
                    item_id.to_string(),
                    StoredRecord::new(self.revision, "recreated"),
                );
            }
            Ok(self.revision)
        }
    }

    // ── read ────────────────────────────────────────────────────────────────────

    #[test]
    fn read_discloses_content_for_a_present_item() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .read(&MemoryReadRequest::new(binding(), ITEM))
            .expect("binding matches session");
        match outcome.state {
            AuthoritativeState::Present(item) => {
                assert_eq!(item.revision, 4);
                assert_eq!(item.content.as_deref(), Some(SECRET_CONTENT));
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn read_of_an_unheld_key_is_absent_and_anchored_at_the_scope_revision() {
        let ctx = context();
        let mut store = FakeStore {
            revision: 9,
            ..FakeStore::default()
        };
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .read(&MemoryReadRequest::new(binding(), ITEM))
            .expect("binding matches session");
        match outcome.state {
            AuthoritativeState::Absent(proof) => assert_eq!(proof.observed_at_revision(), 9),
            other => panic!("expected Absent, got {other:?}"),
        }
    }

    // ── edit ────────────────────────────────────────────────────────────────────

    #[test]
    fn edit_returns_a_receipt_and_a_content_free_read_back() {
        let ctx = context();
        let mut store = FakeStore::with_item("old");
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .edit(&MemoryEditRequest::new(binding(), ITEM, SECRET_CONTENT))
            .expect("binding matches session");
        assert_eq!(outcome.receipt().operation, MemoryOperation::Edit);
        assert_eq!(outcome.receipt().applied_at_revision, 5);
        assert_eq!(
            outcome.receipt().correlation,
            RequestCorrelation::Id("req-1".to_string())
        );
        match outcome.state() {
            AuthoritativeState::Present(item) => {
                assert_eq!(item.revision, 5);
                assert!(
                    item.content.is_none(),
                    "a mutation read-back must not disclose content"
                );
            }
            other => panic!("expected Present, got {other:?}"),
        }
        assert!(outcome.proven_absent().is_none());
    }

    #[test]
    fn a_revision_conflict_refuses_the_mutation_and_produces_no_receipt() {
        let ctx = context();
        let mut store = FakeStore::with_item("old");
        let err = MemoryGateway::new(&ctx, &mut store)
            .edit(&MemoryEditRequest::new(binding(), ITEM, "new").expecting_revision(99))
            .expect_err("revision 99 is not the current revision");
        assert_eq!(err.code, SdkErrorCode::RevisionConflict);
        assert_eq!(
            store.items.get(ITEM).map(|r| r.content.as_str()),
            Some("old"),
            "a refused mutation must not have applied"
        );
    }

    // ── delete: the receipt / proof separation ──────────────────────────────────

    #[test]
    fn delete_read_back_proves_absence() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect("binding matches session");
        assert_eq!(outcome.receipt().operation, MemoryOperation::Delete);
        let proof = outcome
            .proven_absent()
            .expect("the read-back observed no record");
        assert_eq!(proof.observed_at_revision(), 5);
    }

    #[test]
    fn a_failed_read_back_is_unobserved_and_proves_nothing() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        store.fail_load = true;
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect("the mutation itself applied");
        assert_eq!(
            outcome.receipt().operation,
            MemoryOperation::Delete,
            "the receipt still attests the removal was applied"
        );
        assert!(
            matches!(
                outcome.state(),
                AuthoritativeState::Unobserved(UnobservedReason::ReadBackFailed)
            ),
            "a store that could not answer must not be reported as absence"
        );
        assert!(
            outcome.proven_absent().is_none(),
            "an unobserved read-back is NOT proof of deletion"
        );
    }

    // ── M2: a store's own message never reaches the wire ────────────────────────

    #[test]
    fn a_store_error_carrying_content_is_reclassified_to_its_code_alone() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        store.leak_through_store_error = true;

        let err = MemoryGateway::new(&ctx, &mut store)
            .edit(&MemoryEditRequest::new(binding(), ITEM, "new body"))
            .expect_err("the store refused the write");

        assert_eq!(
            err.code,
            SdkErrorCode::RevisionConflict,
            "the CLASS is preserved — it is what a consumer branches on"
        );
        let rendered = serde_json::to_string(&err).expect("the error serializes");
        assert!(
            !rendered.contains(ITEM),
            "the item id must not cross the envelope: {rendered}"
        );
        assert!(
            !rendered.contains("new body") && !rendered.contains(SECRET_CONTENT),
            "memory content must not cross the envelope: {rendered}"
        );
        assert!(
            rendered.contains("revision_conflict"),
            "the code still reaches the consumer: {rendered}"
        );
    }

    #[test]
    fn a_leaking_store_error_is_reclassified_on_the_delete_path_too() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        store.leak_through_store_error = true;

        let err = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect_err("the store refused the removal");

        let rendered = serde_json::to_string(&err).expect("the error serializes");
        assert!(
            !rendered.contains(ITEM),
            "delete is the sibling path and gets the same treatment: {rendered}"
        );
    }

    // ── L1: the absence anchor is ONE observation ───────────────────────────────

    #[test]
    fn an_absence_proof_is_anchored_at_the_revision_its_own_read_returned() {
        // The scope moves under every read. Assembling the anchor from a `load` and a
        // separate `revision` call would name a revision the read never saw; a single
        // call cannot disagree with itself.
        let ctx = context();
        let mut store = FakeStore {
            revision: 7,
            bump_revision_per_read: true,
            ..Default::default()
        };

        let outcome = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect("removing an absent key is idempotent");

        let proof = outcome
            .proven_absent()
            .expect("the read-back observed no record");
        // 7 -> 8 on the removal's own bump, then 8 -> 9 on the single read-back. The
        // proof names 9 because that is what the read that observed the absence
        // returned; there is no second call whose answer it could have named instead.
        assert_eq!(
            proof.observed_at_revision(),
            9,
            "the proof is anchored at the watermark its OWN read returned"
        );
    }

    #[test]
    fn one_read_back_reaches_the_store_exactly_once() {
        let ctx = context();
        let mut store = FakeStore::default();
        MemoryGateway::new(&ctx, &mut store)
            .read(&MemoryReadRequest::new(binding(), ITEM))
            .expect("the read is admitted");
        assert_eq!(
            store.touches, 1,
            "record and watermark arrive together; a second call is the window this \
             contract exists to close"
        );
    }

    #[test]
    fn an_unanchorable_absence_is_unobserved_rather_than_a_proof() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        store.fail_revision = true;
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect("the mutation itself applied");
        assert!(matches!(
            outcome.state(),
            AuthoritativeState::Unobserved(UnobservedReason::ReadBackFailed)
        ));
        assert!(outcome.proven_absent().is_none());
    }

    #[test]
    fn a_key_re_created_before_the_read_back_is_present_not_proven_absent() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        store.resurrect_on_remove = true;
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect("the mutation itself applied");
        match outcome.state() {
            AuthoritativeState::Present(item) => assert!(
                item.content.is_none(),
                "a delete read-back that finds the key occupied must not disclose its content"
            ),
            other => panic!("expected Present, got {other:?}"),
        }
        assert!(
            outcome.proven_absent().is_none(),
            "an applied removal does not by itself mean the key is empty"
        );
        let rendered = serde_json::to_string(&outcome).expect("outcome serializes");
        assert!(
            !rendered.contains("recreated"),
            "no memory content may reach a mutation outcome: {rendered}"
        );
    }

    #[test]
    fn a_delete_receipt_carries_no_content() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let outcome = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ITEM))
            .expect("binding matches session");
        let rendered = serde_json::to_string(&outcome).expect("outcome serializes");
        assert!(
            !rendered.contains(SECRET_CONTENT),
            "deleted content must not appear in the outcome: {rendered}"
        );
    }

    // ── refusals: the store is never reached ────────────────────────────────────

    #[test]
    fn a_tenant_mismatch_refuses_before_the_store_is_touched() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let mut b = binding();
        b.tenant_id = "tenant-beta".to_string();
        let err = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(b, ITEM))
            .expect_err("a foreign tenant is refused");
        assert_eq!(err.code, SdkErrorCode::TenantMismatch);
        assert_eq!(store.touches, 0, "a refused turn must not reach the store");
    }

    #[test]
    fn an_identity_mismatch_refuses_before_the_store_is_touched() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let mut b = binding();
        b.session_id = "sess-other".to_string();
        let err = MemoryGateway::new(&ctx, &mut store)
            .edit(&MemoryEditRequest::new(b, ITEM, "x"))
            .expect_err("a foreign session is refused");
        assert_eq!(err.code, SdkErrorCode::IdentityMismatch);
        assert_eq!(store.touches, 0);
    }

    #[test]
    fn a_denied_region_refuses_before_the_store_is_touched() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let mut b = binding();
        b.routing = RoutingEvidence::new("claude", "us-east", policy());
        let err = MemoryGateway::new(&ctx, &mut store)
            .read(&MemoryReadRequest::new(b, ITEM))
            .expect_err("a region outside the policy is refused");
        assert_eq!(err.code, SdkErrorCode::RoutingDenied);
        assert_eq!(store.touches, 0);
    }

    #[test]
    fn an_empty_item_id_refuses_before_the_store_is_touched() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let err = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ""))
            .expect_err("an empty item id is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        assert_eq!(store.touches, 0);
    }

    #[test]
    fn refusal_messages_name_no_identity_or_item_value() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        let mut b = binding();
        b.tenant_id = "tenant-beta".to_string();
        let tenant_err = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(b, ITEM))
            .expect_err("refused");
        let item_err = MemoryGateway::new(&ctx, &mut store)
            .delete(&MemoryDeleteRequest::new(binding(), ""))
            .expect_err("refused");
        for err in [&tenant_err, &item_err] {
            let rendered = serde_json::to_string(err).expect("error serializes");
            for leak in [TENANT, "tenant-beta", OPERATOR, SESSION, ITEM, POLICY] {
                assert!(
                    !rendered.contains(leak),
                    "refusal must not carry `{leak}`: {rendered}"
                );
            }
        }
    }

    #[test]
    fn every_verb_refuses_every_foreign_binding_before_touching_the_store() {
        // The refusal matrix is per-VERB: each of read/edit/delete calls `admit`
        // itself, so a bypass in one is invisible to a test that exercises another.
        type Mangle = fn(SessionBinding) -> SessionBinding;
        let foreign: [(&str, Mangle, SdkErrorCode); 3] = [
            (
                "tenant",
                |mut b| {
                    b.tenant_id = "tenant-beta".to_string();
                    b
                },
                SdkErrorCode::TenantMismatch,
            ),
            (
                "session",
                |mut b| {
                    b.session_id = "sess-other".to_string();
                    b
                },
                SdkErrorCode::IdentityMismatch,
            ),
            (
                "operator",
                |mut b| {
                    b.operator = VerifiedOperator::new(
                        "operator-other",
                        VerificationMethod::OauthIdentity,
                        "audit-rec-9",
                    );
                    b
                },
                SdkErrorCode::IdentityMismatch,
            ),
        ];
        let denied_region = |mut b: SessionBinding| {
            b.routing = RoutingEvidence::new("claude", "us-east", policy());
            b
        };

        for (label, mangle, code) in foreign.into_iter().chain([(
            "region",
            denied_region as Mangle,
            SdkErrorCode::RoutingDenied,
        )]) {
            let ctx = context();

            let mut store = FakeStore::with_item(SECRET_CONTENT);
            let err = MemoryGateway::new(&ctx, &mut store)
                .read(&MemoryReadRequest::new(mangle(binding()), ITEM))
                .expect_err("read must refuse a foreign binding");
            assert_eq!(err.code, code, "read/{label}");
            assert_eq!(store.touches, 0, "read/{label} reached the store");

            let mut store = FakeStore::with_item(SECRET_CONTENT);
            let err = MemoryGateway::new(&ctx, &mut store)
                .edit(&MemoryEditRequest::new(mangle(binding()), ITEM, "x"))
                .expect_err("edit must refuse a foreign binding");
            assert_eq!(err.code, code, "edit/{label}");
            assert_eq!(store.touches, 0, "edit/{label} reached the store");

            let mut store = FakeStore::with_item(SECRET_CONTENT);
            let err = MemoryGateway::new(&ctx, &mut store)
                .delete(&MemoryDeleteRequest::new(mangle(binding()), ITEM))
                .expect_err("delete must refuse a foreign binding");
            assert_eq!(err.code, code, "delete/{label}");
            assert_eq!(store.touches, 0, "delete/{label} reached the store");
        }
    }

    // ── scope is the session's, not the caller's ────────────────────────────────

    #[test]
    fn the_store_is_addressed_with_the_established_scope() {
        let ctx = context();
        let mut store = FakeStore::with_item(SECRET_CONTENT);
        MemoryGateway::new(&ctx, &mut store)
            .read(&MemoryReadRequest::new(binding(), ITEM))
            .expect("binding matches session");
        assert!(!store.seen_scopes.is_empty());
        for scope in &store.seen_scopes {
            assert_eq!(scope.tenant_id, TENANT);
            assert_eq!(scope.session_id, SESSION);
        }
        assert_eq!(
            MemoryScope::of_session(&ctx),
            MemoryScope::new(TENANT, SESSION)
        );
    }

    // ── wire shapes ─────────────────────────────────────────────────────────────

    /// M3 regression (security review of an internal ticket).
    ///
    /// `item_id` crosses into an implementor's store as an opaque key, and the obvious
    /// implementation maps it to a path under the scope directory. Each case below is a
    /// shape that would walk out of the scope the gateway derives from the authoritative
    /// context — refused here so no implementor has to remember to.
    #[test]
    fn an_item_id_that_could_escape_its_scope_is_refused() {
        for hostile in [
            "../../../other-tenant/brief-1",
            "..",
            "a/../../b",
            "nested/path",
            "windows\\path",
            "trailing/",
            "nul\u{0}byte",
            "newline\nid",
        ] {
            let err = require_item_id(hostile).expect_err("must refuse: {hostile}");
            assert_eq!(err.code, SdkErrorCode::InvalidInput, "for {hostile:?}");
            // The refusal names the class, never the value (`security.md` MUST-2).
            assert!(
                !format!("{:?}", err.message).contains(hostile),
                "refusal echoed the item id for {hostile:?}"
            );
        }

        let too_long = "x".repeat(ITEM_ID_MAX_BYTES + 1);
        assert!(
            require_item_id(&too_long).is_err(),
            "over-length must refuse"
        );

        // The bound admits what it should: a legitimate id, and exactly-at-the-limit.
        require_item_id(ITEM).expect("a plain item id is admitted");
        require_item_id(&"x".repeat(ITEM_ID_MAX_BYTES)).expect("exactly at the limit is admitted");
    }

    /// H1 regression (security review of an internal ticket).
    ///
    /// An `AbsenceProof` used to carry ONLY a revision — no scope, no item — and was
    /// `Clone`, while `MutationOutcome::state` was a `pub` field. Those three compose into
    /// a forgery: read any key the scope does not hold (an invented id costs nothing),
    /// keep the proof it hands back, and attach it to a mutation whose real read-back
    /// found the item still PRESENT. `proven_absent()` then answered `Some` for a record
    /// that was never deleted, and the forgery serialized byte-identically to a genuine
    /// outcome.
    ///
    /// Three things block it now; this pins the one that is not structural: the proof
    /// names its subject, `Clone` is gone so it cannot be relocated, and `proven_absent`
    /// refuses a proof whose item is not the receipt's.
    #[test]
    fn a_proof_for_another_item_does_not_prove_this_one_absent() {
        let outcome = MutationOutcome {
            receipt: MutationReceipt::new(
                ITEM,
                MemoryOperation::Delete,
                RequestCorrelation::Id("req-1".to_string()),
                9,
            ),
            // A proof legitimately obtained by observing a DIFFERENT, unheld key.
            state: AuthoritativeState::Absent(AbsenceProof {
                scope: MemoryScope::new(TENANT, SESSION),
                item_id: "some-other-key".to_owned(),
                observed_at_revision: 9,
            }),
        };
        assert!(
            outcome.proven_absent().is_none(),
            "a proof about another item must not prove THIS item absent"
        );

        let genuine = MutationOutcome {
            receipt: MutationReceipt::new(
                ITEM,
                MemoryOperation::Delete,
                RequestCorrelation::Id("req-1".to_string()),
                9,
            ),
            state: AuthoritativeState::Absent(AbsenceProof {
                scope: MemoryScope::new(TENANT, SESSION),
                item_id: ITEM.to_owned(),
                observed_at_revision: 9,
            }),
        };
        assert!(
            genuine.proven_absent().is_some(),
            "a proof about THIS item must still answer"
        );
    }

    #[test]
    fn reported_state_matches_authoritative_state_on_the_wire() {
        let states = [
            AuthoritativeState::Present(ObservedItem::disclosed(ITEM, 3, "body")),
            AuthoritativeState::Absent(AbsenceProof {
                scope: MemoryScope::new(TENANT, SESSION),
                item_id: ITEM.to_owned(),
                observed_at_revision: 7,
            }),
            AuthoritativeState::Unobserved(UnobservedReason::ReadBackFailed),
        ];
        let expected = [
            ReportedState::Present(ObservedItem::disclosed(ITEM, 3, "body")),
            ReportedState::Absent {
                scope: MemoryScope::new(TENANT, SESSION),
                item_id: ITEM.to_owned(),
                observed_at_revision: 7,
            },
            ReportedState::Unobserved(UnobservedReason::ReadBackFailed),
        ];
        for (state, want) in states.iter().zip(expected) {
            let json = serde_json::to_string(state).expect("authoritative state serializes");
            let got: ReportedState =
                serde_json::from_str(&json).expect("consumer parses the same bytes");
            assert_eq!(got, want, "shapes drifted for {json}");
        }
    }

    #[test]
    fn enum_wire_strings_match_serialize() {
        for (op, wire) in [
            (MemoryOperation::Edit, "edit"),
            (MemoryOperation::Delete, "delete"),
        ] {
            assert_eq!(op.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&op).expect("serializes"),
                format!("\"{wire}\"")
            );
        }
        assert_eq!(
            UnobservedReason::ReadBackFailed.as_str(),
            "read_back_failed"
        );
        assert_eq!(
            serde_json::to_string(&UnobservedReason::ReadBackFailed).expect("serializes"),
            "\"read_back_failed\""
        );
    }

    #[test]
    fn request_dtos_round_trip_and_omit_absent_optional_fields() {
        let edit = MemoryEditRequest::new(binding(), ITEM, "body");
        let json = serde_json::to_value(&edit).expect("serializes");
        assert!(
            json.get("expected_revision").is_none(),
            "an absent precondition must be omitted, not null: {json}"
        );
        let back: MemoryEditRequest = serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, edit);

        let del = MemoryDeleteRequest::new(binding(), ITEM).expecting_revision(4);
        let json = serde_json::to_value(&del).expect("serializes");
        assert_eq!(json["expected_revision"], serde_json::json!(4));
        let back: MemoryDeleteRequest = serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, del);

        let read = MemoryReadRequest::new(binding(), ITEM);
        let back: MemoryReadRequest =
            serde_json::from_value(serde_json::to_value(&read).expect("serializes"))
                .expect("round-trips");
        assert_eq!(back, read);
    }
}

#[cfg(test)]
mod in_memory_store_tests {
    use super::*;
    use crate::{
        RequestCorrelation, RoutingEvidence, RoutingPolicy, VerificationMethod, VerifiedOperator,
    };

    const TENANT: &str = "tenant-alpha";
    const SESSION: &str = "sess-42";
    const ITEM: &str = "brief-1";

    const OPERATOR: &str = "operator-7";

    fn scope() -> MemoryScope {
        MemoryScope::new(TENANT, SESSION)
    }

    fn policy() -> RoutingPolicy {
        RoutingPolicy::new("policy-eu-only", vec!["eu-west".to_string()])
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

    #[test]
    fn a_write_is_readable_and_lands_at_a_bumped_revision() {
        let mut store = InMemorySessionMemory::new();
        assert_eq!(store.load(&scope(), ITEM).unwrap().scope_revision, 0);
        let at = store.store(&scope(), ITEM, None, "body").unwrap();
        assert_eq!(at, 1, "the first write bumps the watermark to 1");
        let read = store.load(&scope(), ITEM).unwrap();
        assert_eq!(read.record, Some(StoredRecord::new(1, "body")));
        assert_eq!(
            read.scope_revision, 1,
            "the record and the watermark it was read at arrive together"
        );
    }

    #[test]
    fn an_unheld_key_is_no_record_never_an_error() {
        let mut store = InMemorySessionMemory::new();
        assert_eq!(store.load(&scope(), ITEM).unwrap().record, None);
    }

    #[test]
    fn a_stale_expected_revision_is_a_conflict_and_leaves_the_record_alone() {
        let mut store = InMemorySessionMemory::new();
        store.store(&scope(), ITEM, None, "first").unwrap();
        let err = store
            .store(&scope(), ITEM, Some(99), "second")
            .expect_err("a stale precondition is refused");
        assert_eq!(err.code, SdkErrorCode::RevisionConflict);
        assert_eq!(
            store.load(&scope(), ITEM).unwrap().record,
            Some(StoredRecord::new(1, "first")),
            "the refused write did not apply"
        );
    }

    #[test]
    fn a_precondition_on_a_key_the_scope_does_not_hold_is_a_conflict() {
        let mut store = InMemorySessionMemory::new();
        let err = store
            .store(&scope(), ITEM, Some(1), "body")
            .expect_err("an absent item satisfies no stated revision");
        assert_eq!(err.code, SdkErrorCode::RevisionConflict);
    }

    #[test]
    fn removing_a_held_key_bumps_the_watermark_and_removing_an_absent_one_does_not() {
        let mut store = InMemorySessionMemory::new();
        store.store(&scope(), ITEM, None, "body").unwrap();
        assert_eq!(store.remove(&scope(), ITEM, None).unwrap(), 2);
        assert_eq!(store.load(&scope(), ITEM).unwrap().record, None);
        assert_eq!(
            store.remove(&scope(), ITEM, None).unwrap(),
            2,
            "an idempotent no-op removal returns the CURRENT watermark, unbumped"
        );
    }

    #[test]
    fn two_scopes_never_observe_each_others_records_or_revisions() {
        let mut store = InMemorySessionMemory::new();
        let other = MemoryScope::new(TENANT, "sess-99");
        let foreign_tenant = MemoryScope::new("tenant-beta", SESSION);

        store.store(&scope(), ITEM, None, "alpha").unwrap();

        assert_eq!(store.load(&other, ITEM).unwrap().record, None);
        assert_eq!(store.load(&foreign_tenant, ITEM).unwrap().record, None);
        assert_eq!(store.load(&other, ITEM).unwrap().scope_revision, 0);
        assert_eq!(store.load(&foreign_tenant, ITEM).unwrap().scope_revision, 0);
        assert_eq!(store.load(&scope(), ITEM).unwrap().scope_revision, 1);
    }

    #[test]
    fn a_conflict_message_names_no_tenant_session_item_or_content() {
        let mut store = InMemorySessionMemory::new();
        let err = store
            .store(&scope(), ITEM, Some(7), "the operator's authored body")
            .expect_err("a stale precondition is refused");
        let rendered = format!("{}", err.message);
        for leak in [TENANT, SESSION, ITEM, "the operator's authored body"] {
            assert!(
                !rendered.contains(leak),
                "the conflict message must not carry {leak:?}: {rendered}"
            );
        }
    }

    #[test]
    fn the_gateway_drives_the_shipped_store_through_a_full_delete_read_back() {
        let ctx = context();
        let mut store = InMemorySessionMemory::new();
        let mut gateway = MemoryGateway::new(&ctx, &mut store);

        let wrote = gateway
            .edit(&MemoryEditRequest::new(binding(), ITEM, "body"))
            .expect("the write applies");
        let deleted = gateway
            .delete(
                &MemoryDeleteRequest::new(binding(), ITEM)
                    .expecting_revision(wrote.receipt().applied_at_revision),
            )
            .expect("a delete at the observed revision applies");
        assert!(
            deleted.proven_absent().is_some(),
            "the shipped store supports the deletion read-back, not just the fake"
        );
    }
}
