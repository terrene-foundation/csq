//! `csq.authoring_distill.v1` — distillation + form-factor inference over a bound
//! authoring session (an internal ticket, S3).
//!
//! Two outputs are derived from the SAME bound session, so both are governed by the
//! same five invariants:
//!
//! 1. **Distillation** — the session distilled into a [`DecisionProcedure`]: an
//!    explicit, inspectable graph of [`DecisionStep`]s, each naming the question it
//!    decides, the criterion that decides it, the outcomes it can reach, and the
//!    session turns it was distilled FROM. It is a structure, not prose, so a
//!    consumer can walk it, and a reviewer can trace every step back to its evidence.
//! 2. **Form-factor inference** — the delivery [`DeliveryFormFactor`] inferred from
//!    the [`FormFactorSignal`]s observed in that same session, via
//!    [`infer_form_factor`].
//!
//! ## Riding the S1 envelope
//!
//! [`DistillationRequest`] and [`DistillationResponse`] each carry a
//! [`SessionBinding`], and neither is validated by itself: [`DistillationRequest::admit`]
//! delegates the five invariants to [`SessionContext::admit`], and
//! [`DistillationResponse::accept`] delegates them to
//! [`SessionContext::accept_response`]. This module adds no second copy of those
//! checks, so it cannot drift from the envelope's.
//!
//! ## Egress ordering
//!
//! An [`AdmittedDistillation`] holds an [`EgressAuthorization`], whose only
//! constructor is private to the `authoring_session` module and is reached solely
//! through `SessionContext::admit`. `AdmittedDistillation` is `#[non_exhaustive]`
//! with private fields and its only constructor is [`DistillationRequest::admit`], so
//! outside this module no struct literal can produce one. A provider call site that
//! takes an `AdmittedDistillation` has, by that construction, already passed the
//! routing check.
//!
//! ## Undetermined is a state, not a default
//!
//! [`FormFactorInference`] is a two-armed closed enum. The
//! [`FormFactorInference::Undetermined`] arm is reached whenever the session's signals
//! do not converge on exactly one form factor — no signals at all, or signals implying
//! more than one. Three mechanisms keep a GUESS from reading as an inference:
//!
//! - no type in this module implements `Default`, so there is no form factor a value
//!   can acquire by being left unset;
//! - [`DeterminedFormFactor`] is `#[non_exhaustive]` and has no public constructor, so
//!   outside this crate it is obtainable only from [`infer_form_factor`] (which returns
//!   `Undetermined` unless the signals converge) or from deserialization;
//! - a DESERIALIZED inference is re-derived: [`DistillationResponse::accept`] re-runs
//!   [`infer_form_factor`] over the request's signals and refuses any response whose
//!   inference differs, with [`SdkErrorCode::InferenceUnsupported`].
//!
//! ## Additive extension
//!
//! Every DTO here is `#[non_exhaustive]` and built through a `new` constructor (except
//! [`DeterminedFormFactor`], deliberately — see above). A later shard adds its field as
//! `Option<T>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` plus a
//! `with_*` builder; a consumer pinned to `csq.authoring_distill.v1` keeps parsing and
//! the major does not bump (the contract-change policy in `crate`).
//!
//! ## Leak safety
//!
//! Every refusal in this module is a fixed `&'static str` naming the CLASS of defect.
//! No tenant id, operator id, session id, turn id, step id, or signal id is
//! interpolated into an error, so a refusal envelope carries no session content
//! (`rules/security.md` §2). That holds for BOTH directions and is the guarantee this
//! module actually makes.
//!
//! The PAYLOADS are not symmetric, and the difference matters to a consumer deciding
//! what it may log or forward:
//!
//! - a [`DistillationRequest`] carries its session turns as a `digest` handle rather
//!   than as turn text, so the request holds no authored content;
//! - a [`DistillationResponse`] DOES carry authored prose, by construction. Every
//!   [`DecisionStep`] in the distilled procedure has a `question` and a `criterion`,
//!   and those are distilled session content — producing them is the entire point of
//!   the operation. The response is content-BEARING, and a reader must not infer from
//!   the request's digest handles that a distillation response can be logged or
//!   forwarded as though it were content-free.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::authoring_session::{EgressAuthorization, SessionBinding, SessionContext};
use crate::error::{SdkError, SdkErrorCode};

// ── cardinality bounds ──────────────────────────────────────────────────────────
//
// Every collection below arrives from a caller and is validated by walking it. Without
// a bound, validation cost is a function of what the caller sent — and validation is
// what runs BEFORE the payload has been established as anything, so it is the one
// place a bound has to be unconditional rather than earned.
//
// A bound here is not a substitute for an envelope-level payload limit; `csq-sdk`'s
// `Envelope` is serialize-only (it emits, it does not parse), so nothing upstream of
// these checks bounds an inbound payload at all. These ARE the bound.
//
// Each is sized to keep two outcomes separable: the largest plausible legitimate value,
// and a value large enough that walking it is the point. Where the honest ceiling is
// another bound (a step cites turns; there are at most `MAX_SESSION_TURNS` of them),
// the same number is reused rather than invented.

/// The most session turns one distillation request may carry.
///
/// A long authoring session runs to hundreds of turns; 4096 is several times that and
/// far below a size at which a single linear pass is noticeable.
pub const MAX_SESSION_TURNS: usize = 4096;

/// The most form-factor signals one request may carry.
///
/// A signal is observed IN a turn, so the natural ceiling is one per turn.
pub const MAX_FORM_FACTOR_SIGNALS: usize = MAX_SESSION_TURNS;

/// The most steps one decision procedure may declare.
///
/// A distilled procedure is meant to be READ by a person. A thousand steps is already
/// far past legible; the bound exists for the machine, not the reader.
pub const MAX_DECISION_STEPS: usize = 1024;

/// The most branches out of a single decision step.
///
/// A step is one decision. Sixty-four branches is well beyond any decision a human
/// makes at one point in a procedure.
pub const MAX_STEP_OUTCOMES: usize = 64;

/// The most source turns a single step or signal may cite.
///
/// A citation names a turn, and the request carries at most `MAX_SESSION_TURNS` of
/// them — citing every turn in the session is the honest ceiling.
pub const MAX_SOURCE_TURN_CITATIONS: usize = MAX_SESSION_TURNS;

/// The most signals a determined inference may name as supporting it.
///
/// The supporting set is drawn from the request's signals, so it is bounded by them.
pub const MAX_SUPPORTING_SIGNALS: usize = MAX_FORM_FACTOR_SIGNALS;

/// Refuse when a caller-supplied collection exceeds its bound.
///
/// The refusal names the collection's CLASS and neither the offending count nor the
/// limit — consistent with every other refusal in this module (§ Leak safety), and
/// because a caller that sent the collection already knows how big it was.
fn bound(len: usize, max: usize, message: &'static str) -> Result<(), SdkError> {
    if len > max {
        return Err(refuse(message));
    }
    Ok(())
}

/// Who produced a turn in the authoring session.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback; unit-variant
/// construction is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TurnRole {
    /// The verified operator driving the session.
    Operator,
    /// The assistant surface responding within the session.
    Assistant,
}

impl TurnRole {
    /// The stable wire string for this role (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Assistant => "assistant",
        }
    }
}

/// One turn of the bound session, referenced by id and content DIGEST.
///
/// The turn's text is deliberately absent: distillation cites turns as evidence, and a
/// citation needs an identifier, not the content. Carrying the digest instead keeps
/// authored session content out of both the request payload and any refusal derived
/// from it.
///
/// `#[non_exhaustive]`: construct via [`SessionTurn::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionTurn {
    /// The turn's identifier within the session.
    pub turn_id: String,
    /// Who produced the turn.
    pub role: TurnRole,
    /// Digest of the turn's content — a handle, never the content.
    pub digest: String,
}

impl SessionTurn {
    /// Build a `SessionTurn` from its three always-present fields.
    #[must_use]
    pub fn new(turn_id: impl Into<String>, role: TurnRole, digest: impl Into<String>) -> Self {
        Self {
            turn_id: turn_id.into(),
            role,
            digest: digest.into(),
        }
    }

    /// Structural check: identifier and digest are present.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when `turn_id` or `digest` is empty.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.turn_id.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring distill: session turn id must not be empty",
            ));
        }
        if self.digest.is_empty() {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "authoring distill: session turn digest must not be empty",
            ));
        }
        Ok(())
    }
}

// ── the distilled decision procedure ─────────────────────────────────────────────

/// Where an outcome leads: to another step, or out of the procedure.
///
/// Adjacently tagged (`{"kind":"step","value":"…"}`) so a consumer branches on `kind`
/// without positional parsing, and a later shard can add a third arm without reshaping
/// these two.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum StepTransition {
    /// Continue at the named step. The target is required to resolve by
    /// [`DecisionProcedure::validate`].
    Step(String),
    /// Leave the procedure at the named terminal outcome.
    Terminal(String),
}

impl StepTransition {
    /// The target this transition names, whichever arm carries it.
    #[must_use]
    pub fn target(&self) -> &str {
        match self {
            Self::Step(v) | Self::Terminal(v) => v,
        }
    }
}

/// One branch out of a decision step.
///
/// `#[non_exhaustive]`: construct via [`DecisionOutcome::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecisionOutcome {
    /// The condition under which this branch is taken, in the step's own terms.
    pub label: String,
    /// Where the branch leads.
    pub transition: StepTransition,
}

impl DecisionOutcome {
    /// Build a `DecisionOutcome` from its two always-present fields.
    #[must_use]
    pub fn new(label: impl Into<String>, transition: StepTransition) -> Self {
        Self {
            label: label.into(),
            transition,
        }
    }
}

/// One decision in the distilled procedure: a question, the criterion that settles it,
/// the branches it can take, and the session turns it was distilled from.
///
/// `source_turns` is required to be non-empty by [`DecisionProcedure::validate`], and
/// every id in it must resolve to a turn the request declared. That pair is what makes
/// a step DISTILLED rather than invented: a step with no traceable evidence in the
/// bound session cannot pass validation.
///
/// `#[non_exhaustive]`: construct via [`DecisionStep::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecisionStep {
    /// The step's identifier, unique within the procedure.
    pub step_id: String,
    /// What this step decides.
    pub question: String,
    /// How it is decided — the rule a reader applies to pick an outcome.
    pub criterion: String,
    /// Ids of the session turns this step was distilled from.
    pub source_turns: Vec<String>,
    /// The branches out of this step.
    pub outcomes: Vec<DecisionOutcome>,
}

impl DecisionStep {
    /// Build a `DecisionStep` from its five always-present fields.
    #[must_use]
    pub fn new(
        step_id: impl Into<String>,
        question: impl Into<String>,
        criterion: impl Into<String>,
        source_turns: Vec<String>,
        outcomes: Vec<DecisionOutcome>,
    ) -> Self {
        Self {
            step_id: step_id.into(),
            question: question.into(),
            criterion: criterion.into(),
            source_turns,
            outcomes,
        }
    }
}

/// The session distilled into an explicit decision procedure.
///
/// `#[non_exhaustive]`: construct via [`DecisionProcedure::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecisionProcedure {
    /// The procedure's identifier.
    pub procedure_id: String,
    /// The step a reader starts at. Required to resolve by [`Self::validate`].
    pub entry_step: String,
    /// The steps, in authoring order. Order carries no semantics — `entry_step` plus
    /// the transitions do.
    pub steps: Vec<DecisionStep>,
}

impl DecisionProcedure {
    /// Build a `DecisionProcedure` from its three always-present fields.
    #[must_use]
    pub fn new(
        procedure_id: impl Into<String>,
        entry_step: impl Into<String>,
        steps: Vec<DecisionStep>,
    ) -> Self {
        Self {
            procedure_id: procedure_id.into(),
            entry_step: entry_step.into(),
            steps,
        }
    }

    /// Check the procedure's structure and its provenance against the session turns it
    /// claims to distil.
    ///
    /// Eight checks, all refusing rather than repairing: the procedure and entry are
    /// named; there is at least one step; each step names a question, a criterion, at
    /// least one source turn and at least one outcome, with non-empty labels and
    /// targets; step ids are unique; the entry resolves; every `Step` transition
    /// resolves; every cited source turn resolves to a declared turn; and every
    /// declared step is reachable from the entry.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] naming the CLASS of the first defect found. The
    /// offending identifier is deliberately not interpolated (module § Leak safety).
    pub fn validate(&self, turns: &[SessionTurn]) -> Result<(), SdkError> {
        if self.procedure_id.is_empty() {
            return Err(refuse("authoring distill: procedure id must not be empty"));
        }
        if self.entry_step.is_empty() {
            return Err(refuse(
                "authoring distill: procedure entry step must not be empty",
            ));
        }
        if self.steps.is_empty() {
            return Err(refuse(
                "authoring distill: a decision procedure must declare at least one step",
            ));
        }
        // Bound before walking: step count gates every loop below, and each of those
        // loops resolves ids against the request's turns.
        bound(
            self.steps.len(),
            MAX_DECISION_STEPS,
            "authoring distill: a decision procedure declares too many steps",
        )?;

        let turn_ids = turn_id_set(turns);
        // Built once, up front, so outcome-target resolution is a lookup rather than a
        // scan of every step per outcome. Declared-ness is a property of the step SET,
        // which is fully known before any outcome is examined.
        let mut step_ids: HashSet<&str> = HashSet::with_capacity(self.steps.len());
        for step in &self.steps {
            if !step_ids.insert(step.step_id.as_str()) {
                return Err(refuse(
                    "authoring distill: decision step ids must be unique within the procedure",
                ));
            }
        }

        for step in &self.steps {
            step_shape_is_valid(step)?;

            for turn_id in &step.source_turns {
                if !turn_ids.contains(turn_id.as_str()) {
                    return Err(refuse(
                        "authoring distill: decision step cites a turn absent from the session",
                    ));
                }
            }
            for outcome in &step.outcomes {
                if let StepTransition::Step(target) = &outcome.transition {
                    if !step_ids.contains(target.as_str()) {
                        return Err(refuse(
                            "authoring distill: decision outcome names an undeclared step",
                        ));
                    }
                }
            }
        }

        if !step_ids.contains(self.entry_step.as_str()) {
            return Err(refuse(
                "authoring distill: procedure entry step is not a declared step",
            ));
        }
        self.all_steps_reachable()
    }

    /// Every declared step is reachable from `entry_step` by some chain of `Step`
    /// transitions.
    ///
    /// Breadth-first from the entry; an unreachable step is dead procedure and is
    /// refused rather than pruned, because pruning would silently change what the
    /// distillation asserts. Called only after the entry and every transition target
    /// have been shown to resolve.
    fn all_steps_reachable(&self) -> Result<(), SdkError> {
        // `seen` is a set and the step lookup is a map: the previous shape used
        // `Vec::contains` for membership and a linear `find` for the lookup, so a
        // procedure of n steps cost O(n²) even though it is a plain graph walk.
        let by_id: std::collections::HashMap<&str, &DecisionStep> =
            self.steps.iter().map(|s| (s.step_id.as_str(), s)).collect();
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.steps.len());
        seen.insert(self.entry_step.as_str());
        let mut frontier: Vec<&str> = vec![self.entry_step.as_str()];

        while let Some(step_id) = frontier.pop() {
            let Some(step) = by_id.get(step_id) else {
                continue;
            };
            for outcome in &step.outcomes {
                if let StepTransition::Step(target) = &outcome.transition {
                    if seen.insert(target.as_str()) {
                        frontier.push(target.as_str());
                    }
                }
            }
        }

        if seen.len() == self.steps.len() {
            return Ok(());
        }
        Err(refuse(
            "authoring distill: every declared step must be reachable from the entry step",
        ))
    }
}

/// The set of turn ids a request declared, for resolving citations in one pass.
///
/// Every citation check in this module asks the same question — "is this id one of the
/// session's turns?" — and asked it by scanning the turn slice, once per citation.
fn turn_id_set(turns: &[SessionTurn]) -> HashSet<&str> {
    turns.iter().map(|t| t.turn_id.as_str()).collect()
}

/// Shape check for one step, split out to keep [`DecisionProcedure::validate`] within
/// one screen.
fn step_shape_is_valid(step: &DecisionStep) -> Result<(), SdkError> {
    if step.step_id.is_empty() {
        return Err(refuse(
            "authoring distill: decision step id must not be empty",
        ));
    }
    if step.question.is_empty() {
        return Err(refuse(
            "authoring distill: decision step must name the question it decides",
        ));
    }
    if step.criterion.is_empty() {
        return Err(refuse(
            "authoring distill: decision step must name the criterion that decides it",
        ));
    }
    bound(
        step.outcomes.len(),
        MAX_STEP_OUTCOMES,
        "authoring distill: decision step declares too many outcomes",
    )?;
    bound(
        step.source_turns.len(),
        MAX_SOURCE_TURN_CITATIONS,
        "authoring distill: decision step cites too many source turns",
    )?;
    if step.source_turns.is_empty() {
        return Err(refuse(
            "authoring distill: decision step must cite at least one source turn",
        ));
    }
    if step.source_turns.iter().any(String::is_empty) {
        return Err(refuse(
            "authoring distill: decision step source turn id must not be empty",
        ));
    }
    if step.outcomes.is_empty() {
        return Err(refuse(
            "authoring distill: decision step must declare at least one outcome",
        ));
    }
    for outcome in &step.outcomes {
        if outcome.label.is_empty() {
            return Err(refuse(
                "authoring distill: decision outcome label must not be empty",
            ));
        }
        if outcome.transition.target().is_empty() {
            return Err(refuse(
                "authoring distill: decision outcome transition target must not be empty",
            ));
        }
    }
    Ok(())
}

/// A fixed-vocabulary [`SdkErrorCode::InvalidInput`] refusal.
fn refuse(message: &'static str) -> SdkError {
    SdkError::trusted(SdkErrorCode::InvalidInput, message)
}

// ── form-factor inference ────────────────────────────────────────────────────────

/// How the authored artifact would be delivered.
///
/// `#[non_exhaustive]`: the vocabulary is closed at any given crate version but is
/// expected to grow; an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeliveryFormFactor {
    /// Run by an operator from a shell.
    CommandLine,
    /// Driven through a windowed, attended interface.
    DesktopApplication,
    /// Run unattended on a schedule or as a resident service.
    BackgroundService,
    /// Linked into a host process as a library.
    EmbeddedLibrary,
    /// Reached over the network as a remote API.
    HostedApi,
}

impl DeliveryFormFactor {
    /// The stable wire string for this form factor (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandLine => "command_line",
            Self::DesktopApplication => "desktop_application",
            Self::BackgroundService => "background_service",
            Self::EmbeddedLibrary => "embedded_library",
            Self::HostedApi => "hosted_api",
        }
    }
}

/// An observation from the bound session that bears on the delivery form factor.
///
/// The vocabulary is closed and each member implies exactly one
/// [`DeliveryFormFactor`] ([`Self::implies`]), so inference is a total function of the
/// signal set rather than a judgement call at the call site.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FormFactorSignalKind {
    /// The session described invoking the artifact from a shell.
    InvokedFromShell,
    /// The session described an attended, windowed interaction.
    WindowedInteraction,
    /// The session described unattended or scheduled operation.
    UnattendedSchedule,
    /// The session described linking the artifact into a host process.
    EmbeddedInHostProcess,
    /// The session described reaching the artifact over the network.
    RemoteApiCall,
}

impl FormFactorSignalKind {
    /// The single form factor this signal implies.
    #[must_use]
    pub const fn implies(self) -> DeliveryFormFactor {
        match self {
            Self::InvokedFromShell => DeliveryFormFactor::CommandLine,
            Self::WindowedInteraction => DeliveryFormFactor::DesktopApplication,
            Self::UnattendedSchedule => DeliveryFormFactor::BackgroundService,
            Self::EmbeddedInHostProcess => DeliveryFormFactor::EmbeddedLibrary,
            Self::RemoteApiCall => DeliveryFormFactor::HostedApi,
        }
    }

    /// The stable wire string for this signal kind (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvokedFromShell => "invoked_from_shell",
            Self::WindowedInteraction => "windowed_interaction",
            Self::UnattendedSchedule => "unattended_schedule",
            Self::EmbeddedInHostProcess => "embedded_in_host_process",
            Self::RemoteApiCall => "remote_api_call",
        }
    }
}

/// One form-factor signal, carrying its own provenance in the session.
///
/// `#[non_exhaustive]`: construct via [`FormFactorSignal::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FormFactorSignal {
    /// The signal's identifier, unique within the request.
    pub signal_id: String,
    /// What was observed.
    pub kind: FormFactorSignalKind,
    /// Ids of the session turns the signal was observed in.
    pub source_turns: Vec<String>,
}

impl FormFactorSignal {
    /// Build a `FormFactorSignal` from its three always-present fields.
    #[must_use]
    pub fn new(
        signal_id: impl Into<String>,
        kind: FormFactorSignalKind,
        source_turns: Vec<String>,
    ) -> Self {
        Self {
            signal_id: signal_id.into(),
            kind,
            source_turns,
        }
    }

    /// Structural check: the signal is named and carries at least one resolving source
    /// turn.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when the id is empty, no source turn is cited, or
    /// a cited turn is not among `turns`.
    pub fn validate(&self, turns: &[SessionTurn]) -> Result<(), SdkError> {
        self.validate_against(&turn_id_set(turns))
    }

    /// [`Self::validate`] against a turn-id set the caller already built.
    ///
    /// Exists so [`DistillationRequest::validate_shape`] builds the set ONCE for the
    /// whole request instead of once per signal; validating n signals against n turns
    /// was O(n²) string comparisons on a caller-supplied payload.
    fn validate_against(&self, turn_ids: &HashSet<&str>) -> Result<(), SdkError> {
        if self.signal_id.is_empty() {
            return Err(refuse(
                "authoring distill: form-factor signal id must not be empty",
            ));
        }
        if self.source_turns.is_empty() {
            return Err(refuse(
                "authoring distill: form-factor signal must cite at least one source turn",
            ));
        }
        bound(
            self.source_turns.len(),
            MAX_SOURCE_TURN_CITATIONS,
            "authoring distill: form-factor signal cites too many source turns",
        )?;
        for turn_id in &self.source_turns {
            if !turn_ids.contains(turn_id.as_str()) {
                return Err(refuse(
                    "authoring distill: form-factor signal cites a turn absent from the session",
                ));
            }
        }
        Ok(())
    }
}

/// Why a form factor could not be inferred.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UndeterminedReason {
    /// The session carried no form-factor signal at all.
    NoSignal,
    /// The session's signals implied more than one form factor.
    ConflictingSignals,
}

impl UndeterminedReason {
    /// The stable wire string for this reason (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSignal => "no_signal",
            Self::ConflictingSignals => "conflicting_signals",
        }
    }
}

/// A form factor the session's signals DID converge on, with the signals that carried
/// it.
///
/// Has no public constructor, deliberately: outside this crate a value of this type is
/// obtainable only from [`infer_form_factor`] — which yields it only when the signals
/// converge on exactly one form factor — or from deserialization, which
/// [`DistillationResponse::accept`] re-derives. `#[non_exhaustive]` is what closes the
/// struct-literal path that would otherwise reintroduce an unjustified constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeterminedFormFactor {
    /// The inferred form factor.
    pub form_factor: DeliveryFormFactor,
    /// Ids of the signals that implied it, in the order they were observed. Required
    /// to be non-empty by [`FormFactorInference::validate`].
    pub supporting_signals: Vec<String>,
}

/// The state in which the session's signals did NOT determine a form factor.
///
/// `#[non_exhaustive]`: construct via [`UndeterminedFormFactor::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UndeterminedFormFactor {
    /// Why the inference did not resolve.
    pub reason: UndeterminedReason,
    /// The form factors still in contention, in first-observed order. Empty for
    /// [`UndeterminedReason::NoSignal`]; two or more for
    /// [`UndeterminedReason::ConflictingSignals`].
    pub candidates: Vec<DeliveryFormFactor>,
}

impl UndeterminedFormFactor {
    /// Build an `UndeterminedFormFactor` from its two always-present fields.
    #[must_use]
    pub fn new(reason: UndeterminedReason, candidates: Vec<DeliveryFormFactor>) -> Self {
        Self { reason, candidates }
    }
}

/// The result of inferring a delivery form factor from a bound session.
///
/// Internally tagged (`{"state":"determined", …}`) so a consumer branches on `state`.
/// There is no third "assumed" or "default" arm and no `Default` impl: a value of this
/// type is either a form factor with the signals that implied it, or an explicit
/// account of why none was inferred.
///
/// `#[non_exhaustive]`: an external `match` carries a `_ =>` fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FormFactorInference {
    /// The signals converged on exactly one form factor.
    Determined(DeterminedFormFactor),
    /// The signals did not converge.
    Undetermined(UndeterminedFormFactor),
}

impl FormFactorInference {
    /// The inferred form factor, or `None` when the inference did not resolve.
    ///
    /// A consumer that wants a form factor and gets `None` has to decide what to do
    /// about it; there is no value here that stands in for one.
    #[must_use]
    pub fn form_factor(&self) -> Option<DeliveryFormFactor> {
        match self {
            Self::Determined(d) => Some(d.form_factor),
            Self::Undetermined(_) => None,
        }
    }

    /// Whether the inference resolved.
    #[must_use]
    pub fn is_determined(&self) -> bool {
        matches!(self, Self::Determined(_))
    }

    /// Structural check on a DESERIALIZED inference: each arm carries the evidence its
    /// own meaning requires.
    ///
    /// This is the shape half only. Whether the inference actually FOLLOWS from the
    /// session's signals is re-derived in [`DistillationResponse::accept`], and a value
    /// that passes here can still be refused there.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] when a determined inference names no supporting
    /// signal, a `NoSignal` refusal carries candidates, or a `ConflictingSignals`
    /// refusal carries fewer than two.
    pub fn validate(&self) -> Result<(), SdkError> {
        match self {
            Self::Determined(d) => {
                if d.supporting_signals.is_empty() {
                    return Err(refuse(
                        "authoring distill: a determined form factor must name the signals that implied it",
                    ));
                }
                bound(
                    d.supporting_signals.len(),
                    MAX_SUPPORTING_SIGNALS,
                    "authoring distill: a determined form factor names too many supporting signals",
                )?;
                if d.supporting_signals.iter().any(String::is_empty) {
                    return Err(refuse(
                        "authoring distill: supporting signal id must not be empty",
                    ));
                }
                Ok(())
            }
            Self::Undetermined(u) => match u.reason {
                UndeterminedReason::NoSignal if !u.candidates.is_empty() => Err(refuse(
                    "authoring distill: a no-signal inference must not name candidates",
                )),
                UndeterminedReason::ConflictingSignals if u.candidates.len() < 2 => Err(refuse(
                    "authoring distill: a conflicting-signals inference must name at least two candidates",
                )),
                _ => Ok(()),
            },
        }
    }
}

/// Infer the delivery form factor from the session's form-factor signals.
///
/// Total and deterministic over the signal set: the distinct form factors implied by
/// the signals are collected in first-observed order, and the count decides the arm —
/// zero implies [`UndeterminedReason::NoSignal`], one implies
/// [`FormFactorInference::Determined`], more than one implies
/// [`UndeterminedReason::ConflictingSignals`] with every contender named. There is no
/// tie-break, precedence order, or fallback, so a conflicting session cannot resolve to
/// one of its contenders by accident.
#[must_use]
pub fn infer_form_factor(signals: &[FormFactorSignal]) -> FormFactorInference {
    let mut candidates: Vec<DeliveryFormFactor> = Vec::new();
    for signal in signals {
        let implied = signal.kind.implies();
        if !candidates.contains(&implied) {
            candidates.push(implied);
        }
    }

    match candidates.len() {
        0 => FormFactorInference::Undetermined(UndeterminedFormFactor::new(
            UndeterminedReason::NoSignal,
            Vec::new(),
        )),
        1 => FormFactorInference::Determined(DeterminedFormFactor {
            form_factor: candidates[0],
            supporting_signals: signals.iter().map(|s| s.signal_id.clone()).collect(),
        }),
        _ => FormFactorInference::Undetermined(UndeterminedFormFactor::new(
            UndeterminedReason::ConflictingSignals,
            candidates,
        )),
    }
}

// ── the wire payloads ────────────────────────────────────────────────────────────

/// The `csq.authoring_distill.v1` REQUEST payload: the bound session, the turns to
/// distil, and the form-factor signals observed in them.
///
/// `#[non_exhaustive]`: construct via [`DistillationRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DistillationRequest {
    /// The five invariants for this turn, validated by [`SessionContext::admit`].
    pub binding: SessionBinding,
    /// The session turns available to distil. Both the procedure's step provenance and
    /// the signals' provenance are resolved against this set.
    pub turns: Vec<SessionTurn>,
    /// The form-factor signals observed in those turns.
    pub form_factor_signals: Vec<FormFactorSignal>,
}

impl DistillationRequest {
    /// Build a request payload from its three always-present fields.
    #[must_use]
    pub fn new(
        binding: SessionBinding,
        turns: Vec<SessionTurn>,
        form_factor_signals: Vec<FormFactorSignal>,
    ) -> Self {
        Self {
            binding,
            turns,
            form_factor_signals,
        }
    }

    /// Admit this request against the established session.
    ///
    /// Runs the payload's own shape check, then delegates all five invariants to
    /// [`SessionContext::admit`], then infers the form factor from the request's
    /// signals. The returned [`AdmittedDistillation`] carries the
    /// [`EgressAuthorization`] that call produced.
    ///
    /// # Errors
    /// - [`SdkErrorCode::InvalidInput`] — a turn or signal is malformed, turn or signal
    ///   ids collide, or a signal cites a turn the session did not carry.
    /// - [`SdkErrorCode::TenantMismatch`] / [`SdkErrorCode::IdentityMismatch`] /
    ///   [`SdkErrorCode::RoutingDenied`] — as [`SessionContext::admit`].
    pub fn admit(&self, context: &SessionContext) -> Result<AdmittedDistillation, SdkError> {
        // The governance gate runs FIRST, matching this module's own response direction
        // (`DistillationResponse::accept` admits before it validates) and the sibling
        // shards. Two reasons, and the second is why the ordering is load-bearing
        // rather than cosmetic:
        //
        // 1. a caller that fails tenant, identity, or routing learns only that, and
        //    nothing about how its payload was judged;
        // 2. payload validation walks caller-supplied collections. Running it first
        //    lets an unauthorized caller spend this process's time on a payload it was
        //    never entitled to submit. Bounded work is still work.
        let authorization = context.admit(&self.binding)?;
        self.validate_shape()?;
        Ok(AdmittedDistillation {
            authorization,
            inference: infer_form_factor(&self.form_factor_signals),
        })
    }

    /// Payload shape: turns present and uniquely identified, signals well-formed and
    /// uniquely identified.
    ///
    /// # Errors
    /// [`SdkErrorCode::InvalidInput`] naming the CLASS of the first defect.
    pub fn validate_shape(&self) -> Result<(), SdkError> {
        if self.turns.is_empty() {
            return Err(refuse(
                "authoring distill: a distillation request must carry at least one session turn",
            ));
        }
        // Both bounds are checked BEFORE either collection is walked, so an oversized
        // payload is refused on its length rather than on its content.
        bound(
            self.turns.len(),
            MAX_SESSION_TURNS,
            "authoring distill: a distillation request carries too many session turns",
        )?;
        bound(
            self.form_factor_signals.len(),
            MAX_FORM_FACTOR_SIGNALS,
            "authoring distill: a distillation request carries too many form-factor signals",
        )?;

        // Uniqueness by insertion into a set: `insert` returning false IS the duplicate,
        // so the check costs one pass rather than one scan of the prefix per element.
        let mut turn_ids: HashSet<&str> = HashSet::with_capacity(self.turns.len());
        for turn in &self.turns {
            turn.validate()?;
            if !turn_ids.insert(turn.turn_id.as_str()) {
                return Err(refuse(
                    "authoring distill: session turn ids must be unique within the request",
                ));
            }
        }

        let mut signal_ids: HashSet<&str> = HashSet::with_capacity(self.form_factor_signals.len());
        for signal in &self.form_factor_signals {
            signal.validate_against(&turn_ids)?;
            if !signal_ids.insert(signal.signal_id.as_str()) {
                return Err(refuse(
                    "authoring distill: form-factor signal ids must be unique within the request",
                ));
            }
        }
        Ok(())
    }
}

/// A [`DistillationRequest`] that passed every check, carrying the routing proof and
/// the form factor inferred from its signals.
///
/// Both fields are private and the type is `#[non_exhaustive]` with no public
/// constructor, so [`DistillationRequest::admit`] is the only way to obtain one — which
/// is what lets a downstream provider call site take this type as evidence that routing
/// was authorized first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmittedDistillation {
    authorization: EgressAuthorization,
    inference: FormFactorInference,
}

impl AdmittedDistillation {
    /// The routing proof produced by [`SessionContext::admit`].
    #[must_use]
    pub fn authorization(&self) -> &EgressAuthorization {
        &self.authorization
    }

    /// The form factor inferred from the request's signals — determined, or an explicit
    /// account of why not.
    #[must_use]
    pub fn form_factor(&self) -> &FormFactorInference {
        &self.inference
    }
}

/// The `csq.authoring_distill.v1` RESPONSE payload: the echoed binding, the distilled
/// decision procedure, and the form-factor inference.
///
/// `#[non_exhaustive]`: construct via [`DistillationResponse::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DistillationResponse {
    /// The five invariants, echoed from the request.
    pub binding: SessionBinding,
    /// The session distilled into an explicit decision procedure.
    pub procedure: DecisionProcedure,
    /// The delivery form factor inferred from the request's signals.
    pub form_factor: FormFactorInference,
}

impl DistillationResponse {
    /// Build a response payload from its three always-present fields.
    #[must_use]
    pub fn new(
        binding: SessionBinding,
        procedure: DecisionProcedure,
        form_factor: FormFactorInference,
    ) -> Self {
        Self {
            binding,
            procedure,
            form_factor,
        }
    }

    /// Accept this response against the established session and the request it answers.
    ///
    /// Four stages: the five invariants plus the correlation echo, delegated to
    /// [`SessionContext::accept_response`]; the procedure's structure and provenance
    /// against the request's turns; the inference's own shape; and finally the
    /// inference RE-DERIVED from the request's signals by [`infer_form_factor`] and
    /// compared. The last stage is why a response cannot assert a form factor the
    /// session's signals do not carry — the value is recomputed here rather than
    /// trusted.
    ///
    /// # Errors
    /// - [`SdkErrorCode::TenantMismatch`] / [`SdkErrorCode::IdentityMismatch`] — as
    ///   [`SessionContext::accept_response`], including a response that does not echo
    ///   the request's correlation.
    /// - [`SdkErrorCode::InvalidInput`] — the procedure or the inference is malformed,
    ///   or a step cites a turn the request did not carry.
    /// - [`SdkErrorCode::InferenceUnsupported`] — the response's form-factor inference
    ///   is not the one the request's signals imply.
    pub fn accept(
        &self,
        context: &SessionContext,
        request: &DistillationRequest,
    ) -> Result<(), SdkError> {
        context.accept_response(&request.binding, &self.binding)?;
        self.procedure.validate(&request.turns)?;
        self.form_factor.validate()?;

        if self.form_factor != infer_form_factor(&request.form_factor_signals) {
            return Err(SdkError::trusted(
                SdkErrorCode::InferenceUnsupported,
                "authoring distill: form-factor inference is not the one the session's signals imply",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authoring_session::{
        RequestCorrelation, RoutingEvidence, RoutingPolicy, VerificationMethod, VerifiedOperator,
    };

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

    fn turns() -> Vec<SessionTurn> {
        vec![
            SessionTurn::new("turn-1", TurnRole::Operator, "sha256:aaaa"),
            SessionTurn::new("turn-2", TurnRole::Assistant, "sha256:bbbb"),
        ]
    }

    fn shell_signal() -> FormFactorSignal {
        FormFactorSignal::new(
            "sig-1",
            FormFactorSignalKind::InvokedFromShell,
            vec!["turn-1".to_string()],
        )
    }

    fn windowed_signal() -> FormFactorSignal {
        FormFactorSignal::new(
            "sig-2",
            FormFactorSignalKind::WindowedInteraction,
            vec!["turn-2".to_string()],
        )
    }

    fn request() -> DistillationRequest {
        DistillationRequest::new(binding(), turns(), vec![shell_signal()])
    }

    /// Two steps: entry branches to `step-b` or leaves at a terminal; `step-b` leaves.
    fn procedure() -> DecisionProcedure {
        DecisionProcedure::new(
            "proc-1",
            "step-a",
            vec![
                DecisionStep::new(
                    "step-a",
                    "does the operator run it themselves?",
                    "the session names a shell invocation",
                    vec!["turn-1".to_string()],
                    vec![
                        DecisionOutcome::new("yes", StepTransition::Step("step-b".to_string())),
                        DecisionOutcome::new(
                            "no",
                            StepTransition::Terminal("needs-a-host".to_string()),
                        ),
                    ],
                ),
                DecisionStep::new(
                    "step-b",
                    "is the run attended?",
                    "the session names an interactive confirmation",
                    vec!["turn-2".to_string()],
                    vec![DecisionOutcome::new(
                        "attended",
                        StepTransition::Terminal("ship-as-cli".to_string()),
                    )],
                ),
            ],
        )
    }

    fn response() -> DistillationResponse {
        DistillationResponse::new(binding(), procedure(), infer_form_factor(&[shell_signal()]))
    }

    // ── M5: caller-supplied collections are bounded ─────────────────────────────

    /// `n` well-formed, uniquely-identified turns — a payload that is legitimate in
    /// every respect except its size, so only the bound can refuse it.
    fn many_turns(n: usize) -> Vec<SessionTurn> {
        (0..n)
            .map(|i| SessionTurn::new(format!("turn-{i}"), TurnRole::Operator, "sha256:aaaa"))
            .collect()
    }

    #[test]
    fn a_request_carrying_more_turns_than_the_bound_is_refused() {
        let over = DistillationRequest::new(binding(), many_turns(MAX_SESSION_TURNS + 1), vec![]);
        let err = over
            .admit(&context())
            .expect_err("an oversized turn list is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        assert!(
            err.message.as_str().contains("too many session turns"),
            "the refusal must name the SIZE class, not some other defect: {}",
            err.message.as_str()
        );

        // The bound admits what it should: exactly at the limit still passes, so the
        // refusal above is the SIZE and not some other property of a large payload.
        let at = DistillationRequest::new(binding(), many_turns(MAX_SESSION_TURNS), vec![]);
        at.admit(&context())
            .expect("exactly at the limit is admitted");
    }

    #[test]
    fn a_request_carrying_more_signals_than_the_bound_is_refused() {
        let signals: Vec<FormFactorSignal> = (0..=MAX_FORM_FACTOR_SIGNALS)
            .map(|i| {
                FormFactorSignal::new(
                    format!("sig-{i}"),
                    FormFactorSignalKind::InvokedFromShell,
                    vec!["turn-1".to_string()],
                )
            })
            .collect();
        let err = DistillationRequest::new(binding(), turns(), signals)
            .admit(&context())
            .expect_err("an oversized signal list is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        assert!(
            err.message
                .as_str()
                .contains("too many form-factor signals"),
            "the refusal must name the SIZE class: {}",
            err.message.as_str()
        );
    }

    #[test]
    fn a_signal_citing_more_source_turns_than_the_bound_is_refused() {
        let citations: Vec<String> = (0..=MAX_SOURCE_TURN_CITATIONS)
            .map(|i| format!("turn-{i}"))
            .collect();
        let signal =
            FormFactorSignal::new("sig-1", FormFactorSignalKind::InvokedFromShell, citations);
        let err = DistillationRequest::new(binding(), turns(), vec![signal])
            .admit(&context())
            .expect_err("an oversized citation list is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        // Every one of those citations also names a turn the session does not carry,
        // which refuses with the SAME code. Only the message separates the two, so
        // only the message can show the BOUND is what fired.
        assert!(
            err.message.as_str().contains("cites too many source turns"),
            "the bound must fire before citation resolution: {}",
            err.message.as_str()
        );
    }

    #[test]
    fn a_procedure_declaring_more_steps_than_the_bound_is_refused() {
        let steps: Vec<DecisionStep> = (0..=MAX_DECISION_STEPS)
            .map(|i| {
                DecisionStep::new(
                    format!("step-{i}"),
                    "q",
                    "c",
                    vec!["turn-1".to_string()],
                    vec![DecisionOutcome::new(
                        "out",
                        StepTransition::Terminal("done".to_string()),
                    )],
                )
            })
            .collect();
        let err = DecisionProcedure::new("proc-1", "step-0", steps)
            .validate(&turns())
            .expect_err("an oversized step list is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        // These steps are also unreachable from the entry, which refuses with the same
        // code; the message is what shows the bound fired first.
        assert!(
            err.message.as_str().contains("too many steps"),
            "the bound must fire before the reachability walk: {}",
            err.message.as_str()
        );
    }

    #[test]
    fn a_step_declaring_more_outcomes_than_the_bound_is_refused() {
        let outcomes: Vec<DecisionOutcome> = (0..=MAX_STEP_OUTCOMES)
            .map(|i| {
                DecisionOutcome::new(
                    format!("out-{i}"),
                    StepTransition::Terminal("done".to_string()),
                )
            })
            .collect();
        let proc = DecisionProcedure::new(
            "proc-1",
            "step-a",
            vec![DecisionStep::new(
                "step-a",
                "q",
                "c",
                vec!["turn-1".to_string()],
                outcomes,
            )],
        );
        let err = proc
            .validate(&turns())
            .expect_err("an oversized outcome list is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        assert!(
            err.message.as_str().contains("too many outcomes"),
            "the refusal must name the SIZE class: {}",
            err.message.as_str()
        );
    }

    #[test]
    fn a_step_citing_more_source_turns_than_the_bound_is_refused() {
        let citations: Vec<String> = (0..=MAX_SOURCE_TURN_CITATIONS)
            .map(|i| format!("turn-{i}"))
            .collect();
        let proc = DecisionProcedure::new(
            "proc-1",
            "step-a",
            vec![DecisionStep::new(
                "step-a",
                "q",
                "c",
                citations,
                vec![DecisionOutcome::new(
                    "out",
                    StepTransition::Terminal("done".to_string()),
                )],
            )],
        );
        let err = proc
            .validate(&turns())
            .expect_err("an oversized citation list is refused");
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
        assert!(
            err.message.as_str().contains("cites too many source turns"),
            "the bound must fire before citation resolution: {}",
            err.message.as_str()
        );
    }

    // ── L2: the governance gate runs before payload shape ───────────────────────

    #[test]
    fn the_governance_gate_is_reported_ahead_of_the_payload_shape_gate() {
        // Both would refuse: a foreign tenant AND a payload carrying no turn. The
        // governance verdict is the one returned, so a caller failing tenant learns
        // nothing about how its payload was judged. Named to match the sibling shard's
        // test of the same property (`authoring_intent`).
        let mut both_wrong = DistillationRequest::new(binding(), vec![], vec![]);
        both_wrong.binding.tenant_id = "tenant-beta".to_string();
        assert_eq!(
            both_wrong
                .admit(&context())
                .expect_err("both gates would refuse")
                .code,
            SdkErrorCode::TenantMismatch
        );
    }

    #[test]
    fn an_unauthorized_caller_cannot_reach_payload_validation_at_all() {
        // The same ordering stated as a cost property: an oversized payload from a
        // caller who fails routing is refused on the ROUTING, so the collections are
        // never walked.
        let mut foreign_region =
            DistillationRequest::new(binding(), many_turns(MAX_SESSION_TURNS + 1), vec![]);
        foreign_region.binding.routing = RoutingEvidence::new("claude", "us-east", policy());
        assert_eq!(
            foreign_region
                .admit(&context())
                .expect_err("a region outside the policy is refused")
                .code,
            SdkErrorCode::RoutingDenied,
            "routing is decided before the turn list is examined"
        );
    }

    // ── M4: the response is content-BEARING, and the doc says so ────────────────

    #[test]
    fn a_distillation_response_carries_distilled_prose_by_construction() {
        // Pins § Leak safety's corrected claim to observable behaviour: the REQUEST
        // holds digests only, the RESPONSE holds authored prose. If a later change made
        // the response content-free, this REDs and the doc paragraph is the thing to
        // revisit.
        let req = serde_json::to_string(&request()).expect("the request serializes");
        assert!(
            !req.contains("does the operator run it themselves?"),
            "the request carries digest handles, not turn text: {req}"
        );

        let resp = serde_json::to_string(&response()).expect("the response serializes");
        assert!(
            resp.contains("does the operator run it themselves?"),
            "the response's question is distilled prose: {resp}"
        );
        assert!(
            resp.contains("the session names a shell invocation"),
            "so is its criterion: {resp}"
        );
    }

    // ── happy path ──────────────────────────────────────────────────────────────

    #[test]
    fn admit_returns_routing_proof_and_the_inferred_form_factor() {
        let admitted = request()
            .admit(&context())
            .expect("binding matches session");
        assert_eq!(admitted.authorization().provider(), "claude");
        assert_eq!(admitted.authorization().region(), "eu-west");
        assert_eq!(
            admitted.form_factor().form_factor(),
            Some(DeliveryFormFactor::CommandLine)
        );
    }

    #[test]
    fn accept_admits_a_well_formed_response() {
        response()
            .accept(&context(), &request())
            .expect("a well-formed response over the same session is accepted");
    }

    // ── the envelope's five invariants govern this payload too ───────────────────

    #[test]
    fn admit_delegates_tenant_and_routing_refusals_to_the_envelope() {
        let mut foreign_tenant = request();
        foreign_tenant.binding.tenant_id = "tenant-beta".to_string();
        assert_eq!(
            foreign_tenant
                .admit(&context())
                .expect_err("foreign tenant is refused")
                .code,
            SdkErrorCode::TenantMismatch
        );

        let mut foreign_region = request();
        foreign_region.binding.routing = RoutingEvidence::new("claude", "us-east", policy());
        assert_eq!(
            foreign_region
                .admit(&context())
                .expect_err("a region outside the policy is refused")
                .code,
            SdkErrorCode::RoutingDenied
        );
    }

    #[test]
    fn accept_refuses_a_response_that_does_not_echo_the_correlation() {
        let mut resp = response();
        resp.binding.correlation = RequestCorrelation::Id("req-2".to_string());
        assert_eq!(
            resp.accept(&context(), &request())
                .expect_err("a non-echoing correlation is refused")
                .code,
            SdkErrorCode::IdentityMismatch
        );
    }

    // ── request shape ───────────────────────────────────────────────────────────

    #[test]
    fn request_shape_refusals_are_invalid_input() {
        let cases: Vec<(&str, DistillationRequest)> = vec![
            (
                "no turns",
                DistillationRequest::new(binding(), vec![], vec![]),
            ),
            (
                "duplicate turn id",
                DistillationRequest::new(
                    binding(),
                    vec![
                        SessionTurn::new("turn-1", TurnRole::Operator, "sha256:aaaa"),
                        SessionTurn::new("turn-1", TurnRole::Assistant, "sha256:bbbb"),
                    ],
                    vec![],
                ),
            ),
            (
                "empty turn digest",
                DistillationRequest::new(
                    binding(),
                    vec![SessionTurn::new("turn-1", TurnRole::Operator, "")],
                    vec![],
                ),
            ),
            (
                "signal cites an absent turn",
                DistillationRequest::new(
                    binding(),
                    turns(),
                    vec![FormFactorSignal::new(
                        "sig-1",
                        FormFactorSignalKind::InvokedFromShell,
                        vec!["turn-99".to_string()],
                    )],
                ),
            ),
            (
                "signal cites no turn",
                DistillationRequest::new(
                    binding(),
                    turns(),
                    vec![FormFactorSignal::new(
                        "sig-1",
                        FormFactorSignalKind::InvokedFromShell,
                        vec![],
                    )],
                ),
            ),
            (
                "duplicate signal id",
                DistillationRequest::new(
                    binding(),
                    turns(),
                    vec![
                        shell_signal(),
                        FormFactorSignal::new(
                            "sig-1",
                            FormFactorSignalKind::RemoteApiCall,
                            vec!["turn-2".to_string()],
                        ),
                    ],
                ),
            ),
        ];

        for (case, req) in cases {
            let err = req
                .admit(&context())
                .expect_err(&format!("{case} must be refused"));
            assert_eq!(err.code, SdkErrorCode::InvalidInput, "case: {case}");
        }
    }

    // ── procedure structure + provenance ────────────────────────────────────────

    #[test]
    fn procedure_structural_refusals_are_invalid_input() {
        let dangling = DecisionProcedure::new(
            "proc-1",
            "step-a",
            vec![DecisionStep::new(
                "step-a",
                "q",
                "c",
                vec!["turn-1".to_string()],
                vec![DecisionOutcome::new(
                    "yes",
                    StepTransition::Step("step-missing".to_string()),
                )],
            )],
        );

        let mut duplicate = procedure();
        duplicate.steps[1].step_id = "step-a".to_string();

        let mut unreachable = procedure();
        unreachable.steps[0].outcomes[0].transition = StepTransition::Terminal("stop".to_string());

        let mut foreign_turn = procedure();
        foreign_turn.steps[0].source_turns = vec!["turn-99".to_string()];

        let mut no_source = procedure();
        no_source.steps[0].source_turns = vec![];

        let mut no_outcome = procedure();
        no_outcome.steps[1].outcomes = vec![];

        let mut no_criterion = procedure();
        no_criterion.steps[0].criterion = String::new();

        let mut bad_entry = procedure();
        bad_entry.entry_step = "step-missing".to_string();

        let mut unnamed = procedure();
        unnamed.procedure_id = String::new();

        let empty = DecisionProcedure::new("proc-1", "step-a", vec![]);

        for (case, proc) in [
            ("dangling transition", dangling),
            ("duplicate step id", duplicate),
            ("unreachable step", unreachable),
            ("step cites an absent turn", foreign_turn),
            ("step cites no turn", no_source),
            ("step declares no outcome", no_outcome),
            ("step names no criterion", no_criterion),
            ("entry step is undeclared", bad_entry),
            ("procedure is unnamed", unnamed),
            ("procedure declares no step", empty),
        ] {
            let err = proc
                .validate(&turns())
                .expect_err(&format!("{case} must be refused"));
            assert_eq!(err.code, SdkErrorCode::InvalidInput, "case: {case}");
        }
    }

    #[test]
    fn a_cycle_between_steps_is_permitted() {
        // Looping back to re-ask a question is a legitimate procedure, so reachability
        // must not be implemented as acyclicity.
        let mut cyclic = procedure();
        cyclic.steps[1].outcomes[0].transition = StepTransition::Step("step-a".to_string());
        cyclic
            .validate(&turns())
            .expect("a cycle is reachable and legitimate");
    }

    // ── form-factor inference ───────────────────────────────────────────────────

    #[test]
    fn no_signal_is_undetermined_not_a_default_form_factor() {
        let inferred = infer_form_factor(&[]);
        assert!(!inferred.is_determined());
        assert_eq!(inferred.form_factor(), None);
        match inferred {
            FormFactorInference::Undetermined(u) => {
                assert_eq!(u.reason, UndeterminedReason::NoSignal);
                assert!(u.candidates.is_empty());
            }
            FormFactorInference::Determined(_) => panic!("no signal must not determine"),
        }
    }

    #[test]
    fn conflicting_signals_are_undetermined_and_name_every_candidate() {
        let inferred = infer_form_factor(&[shell_signal(), windowed_signal()]);
        assert_eq!(inferred.form_factor(), None);
        match inferred {
            FormFactorInference::Undetermined(u) => {
                assert_eq!(u.reason, UndeterminedReason::ConflictingSignals);
                assert_eq!(
                    u.candidates,
                    vec![
                        DeliveryFormFactor::CommandLine,
                        DeliveryFormFactor::DesktopApplication
                    ]
                );
            }
            FormFactorInference::Determined(_) => {
                panic!("conflicting signals must not resolve to one contender")
            }
        }
    }

    #[test]
    fn agreeing_signals_determine_and_name_their_support() {
        let second_shell = FormFactorSignal::new(
            "sig-3",
            FormFactorSignalKind::InvokedFromShell,
            vec!["turn-2".to_string()],
        );
        match infer_form_factor(&[shell_signal(), second_shell]) {
            FormFactorInference::Determined(d) => {
                assert_eq!(d.form_factor, DeliveryFormFactor::CommandLine);
                assert_eq!(d.supporting_signals, vec!["sig-1", "sig-3"]);
            }
            FormFactorInference::Undetermined(_) => panic!("agreeing signals determine"),
        }
    }

    #[test]
    fn every_signal_kind_implies_exactly_one_form_factor() {
        for (kind, expected) in [
            (
                FormFactorSignalKind::InvokedFromShell,
                DeliveryFormFactor::CommandLine,
            ),
            (
                FormFactorSignalKind::WindowedInteraction,
                DeliveryFormFactor::DesktopApplication,
            ),
            (
                FormFactorSignalKind::UnattendedSchedule,
                DeliveryFormFactor::BackgroundService,
            ),
            (
                FormFactorSignalKind::EmbeddedInHostProcess,
                DeliveryFormFactor::EmbeddedLibrary,
            ),
            (
                FormFactorSignalKind::RemoteApiCall,
                DeliveryFormFactor::HostedApi,
            ),
        ] {
            assert_eq!(kind.implies(), expected);
            let signal = FormFactorSignal::new("s", kind, vec!["turn-1".to_string()]);
            assert_eq!(
                infer_form_factor(&[signal]).form_factor(),
                Some(expected),
                "kind: {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn inference_shape_refusals_are_invalid_input() {
        let no_support = FormFactorInference::Determined(DeterminedFormFactor {
            form_factor: DeliveryFormFactor::CommandLine,
            supporting_signals: vec![],
        });
        let empty_support = FormFactorInference::Determined(DeterminedFormFactor {
            form_factor: DeliveryFormFactor::CommandLine,
            supporting_signals: vec![String::new()],
        });
        let no_signal_with_candidates =
            FormFactorInference::Undetermined(UndeterminedFormFactor::new(
                UndeterminedReason::NoSignal,
                vec![DeliveryFormFactor::CommandLine],
            ));
        let conflict_with_one = FormFactorInference::Undetermined(UndeterminedFormFactor::new(
            UndeterminedReason::ConflictingSignals,
            vec![DeliveryFormFactor::CommandLine],
        ));

        for (case, inference) in [
            ("determined with no supporting signal", no_support),
            ("determined with an empty signal id", empty_support),
            ("no-signal naming candidates", no_signal_with_candidates),
            ("conflict naming one candidate", conflict_with_one),
        ] {
            let err = inference
                .validate()
                .expect_err(&format!("{case} must be refused"));
            assert_eq!(err.code, SdkErrorCode::InvalidInput, "case: {case}");
        }
    }

    // ── a response cannot assert a form factor the session does not carry ────────

    #[test]
    fn a_form_factor_the_signals_do_not_imply_is_refused() {
        let mut resp = response();
        resp.form_factor = FormFactorInference::Determined(DeterminedFormFactor {
            form_factor: DeliveryFormFactor::HostedApi,
            supporting_signals: vec!["sig-1".to_string()],
        });
        assert_eq!(
            resp.accept(&context(), &request())
                .expect_err("a form factor the signals do not imply is refused")
                .code,
            SdkErrorCode::InferenceUnsupported
        );
    }

    #[test]
    fn a_determined_response_over_conflicting_signals_is_refused() {
        let conflicted =
            DistillationRequest::new(binding(), turns(), vec![shell_signal(), windowed_signal()]);
        let mut resp = response();
        // The request's signals conflict, so only Undetermined can be accepted here.
        resp.form_factor = FormFactorInference::Determined(DeterminedFormFactor {
            form_factor: DeliveryFormFactor::CommandLine,
            supporting_signals: vec!["sig-1".to_string()],
        });
        assert_eq!(
            resp.accept(&context(), &conflicted)
                .expect_err("a guess over conflicting signals is refused")
                .code,
            SdkErrorCode::InferenceUnsupported
        );

        resp.form_factor = infer_form_factor(&[shell_signal(), windowed_signal()]);
        resp.accept(&context(), &conflicted)
            .expect("the re-derived undetermined inference is accepted");
    }

    // ── wire shape ──────────────────────────────────────────────────────────────

    #[test]
    fn wire_shape_is_tagged_and_snake_case() {
        let determined = serde_json::to_value(infer_form_factor(&[shell_signal()])).unwrap();
        assert_eq!(determined["state"], "determined");
        assert_eq!(determined["form_factor"], "command_line");
        assert_eq!(
            determined["supporting_signals"],
            serde_json::json!(["sig-1"])
        );

        let undetermined = serde_json::to_value(infer_form_factor(&[])).unwrap();
        assert_eq!(undetermined["state"], "undetermined");
        assert_eq!(undetermined["reason"], "no_signal");

        let transition = serde_json::to_value(StepTransition::Step("step-b".to_string())).unwrap();
        assert_eq!(
            transition,
            serde_json::json!({"kind":"step","value":"step-b"})
        );

        let turn = serde_json::to_value(SessionTurn::new(
            "turn-1",
            TurnRole::Assistant,
            "sha256:bbbb",
        ))
        .unwrap();
        assert_eq!(turn["role"], "assistant");
    }

    #[test]
    fn enum_wire_strings_match_serialize() {
        for (rendered, wire) in [
            (
                serde_json::to_string(&TurnRole::Operator).unwrap(),
                TurnRole::Operator.as_str(),
            ),
            (
                serde_json::to_string(&DeliveryFormFactor::BackgroundService).unwrap(),
                DeliveryFormFactor::BackgroundService.as_str(),
            ),
            (
                serde_json::to_string(&FormFactorSignalKind::EmbeddedInHostProcess).unwrap(),
                FormFactorSignalKind::EmbeddedInHostProcess.as_str(),
            ),
            (
                serde_json::to_string(&UndeterminedReason::ConflictingSignals).unwrap(),
                UndeterminedReason::ConflictingSignals.as_str(),
            ),
        ] {
            assert_eq!(rendered, format!("\"{wire}\""));
        }
    }

    #[test]
    fn request_and_response_round_trip_through_json() {
        let req = request();
        let decoded: DistillationRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(decoded, req);

        let resp = response();
        let decoded: DistillationResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(decoded, resp);
        decoded
            .accept(&context(), &req)
            .expect("a round-tripped response is still accepted");
    }

    // ── leak safety ─────────────────────────────────────────────────────────────

    #[test]
    fn refusal_messages_carry_no_session_content() {
        let secrets = [TENANT, OPERATOR, SESSION, POLICY, "turn-99", "step-missing"];

        let mut foreign_turn = procedure();
        foreign_turn.steps[0].source_turns = vec!["turn-99".to_string()];

        let mut bad_entry = procedure();
        bad_entry.entry_step = "step-missing".to_string();

        let mut wrong_form_factor = response();
        wrong_form_factor.form_factor = FormFactorInference::Determined(DeterminedFormFactor {
            form_factor: DeliveryFormFactor::HostedApi,
            supporting_signals: vec!["sig-1".to_string()],
        });

        let messages = vec![
            foreign_turn.validate(&turns()).unwrap_err(),
            bad_entry.validate(&turns()).unwrap_err(),
            wrong_form_factor
                .accept(&context(), &request())
                .unwrap_err(),
            DistillationRequest::new(binding(), vec![], vec![])
                .admit(&context())
                .unwrap_err(),
        ];

        for err in messages {
            let rendered = serde_json::to_string(&err).unwrap();
            for secret in secrets {
                assert!(
                    !rendered.contains(secret),
                    "refusal must not carry `{secret}`: {rendered}"
                );
            }
        }
    }
}
