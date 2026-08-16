//! `csq-sdk` — the portable, edition-uniform envelope surface shared by every
//! `csq <op> --json`.
//!
//! This crate is the **public wire contract** (Apache-2.0, crates.io) that external
//! integrators parse. It holds the base envelope, the closed error/finish vocabularies,
//! the reusable completion body, the provider output adapters, the schema constants,
//! and the op payload DTOs (`CapabilitiesPayload`, `VerifyPayload` + its sub-DTOs). It
//! depends only on `csq-redact` (the redaction leaf) and serde — **zero** dependency on
//! csq-core, the daemon, credentials, or the moat.
//!
//! The APP (`csq-core` / the `csq` binary) owns everything that is not wire-shape:
//! the `EDITION` discriminant (passed IN to the payload DTOs, never a feature flag in
//! this crate) and the BUILDERS that map csq-core's internal audit types onto these
//! DTOs (`capabilities::build`, `build_verify_envelope`). This crate never reaches back
//! into csq-core.
//!
//! ## Cross-shard invariants (the foundation's guarantees)
//!
//! - **R1 — every envelope is a hand-authored DTO.** The [`envelope::Envelope`] wrapper
//!   and every payload struct are authored with explicit fields, never a blanket
//!   `#[derive(Serialize)]` on an internal type. Each field is auditable for
//!   edition-conditional presence and moat leakage.
//! - **R2 — errors carry a closed `code` + a `RedactedString` message.** See
//!   [`error::SdkError`] / [`error::SdkErrorCode`]. `code` is a fixed vocabulary a
//!   consumer branches on; `message` is redacted *by type* (via `csq-redact`), so no
//!   upstream token can reach stdout through it.
//! - **R3 — [`envelope::emit`] is the ONLY stdout writer.** It `serde_json`-serializes
//!   the whole envelope (control characters escaped → a completion's `text` cannot forge
//!   a second envelope line) and writes exactly one `\n`-terminated line. `schema` + `ok`
//!   are present on EVERY envelope; `error` is present iff the op could NOT produce a
//!   payload. A *value-or-nothing* op (`exec`) emits `ok:false` with an `error` and no
//!   payload; a *verdict* op (`verify`, `eval`) emits its payload regardless, so
//!   `ok:false` there carries the payload and no `error` (see [`envelope::Envelope::verdict`]).
//! - **R4 — [`envelope::FinishReason`] is a closed enum;** the raw provider token is
//!   preserved separately in `finish_reason_raw`.
//! - **R5 — a completion's `text` is caller-owned model output and is NOT redacted** —
//!   but it is only ever written through R3's choke point.

pub mod adapter;
pub mod capabilities;
pub mod envelope;
pub mod error;
pub mod verify;

pub use adapter::parse_claude_json;
pub use capabilities::{
    CapabilitiesPayload, ExecFeatures, Features, LoginFlow, ProviderLogin, ProviderSummary,
    ToolInfo,
};
pub use envelope::{emit, Completion, Envelope, FinishReason, Usage};
pub use error::{SdkError, SdkErrorCode};
pub use verify::{VerifyFailureDetail, VerifyKeyGap, VerifyPayload};

// ── Contract-change policy for every SCHEMA_* constant below (an internal ticket Track B) ──
//
// Each constant names a wire contract by MAJOR (`csq.<op>.vN`). Within a major,
// changes MUST be additive-only: a new optional field, a new enum variant a
// consumer can fall through on. A RENAME, REMOVAL, or RETYPE of an EXISTING
// field is a breaking change and MUST bump `N` to a new major — never silently
// reshape the payload under the same schema string. This is what lets a host's
// detection rule stay a single `starts_with` match on the major (e.g.
// `schema.starts_with("csq.status.v1")`) instead of a field-by-field probe.
// A field DERIVED from another value on the same payload (e.g. `csq doctor`'s
// `schema` string, derived from its numeric `schema_version`) MUST be computed
// from that value at one call site, never hand-written a second time — see
// `doctor_schema_string` in the `csq` binary for the worked example.

/// `csq exec --json` — a single spawn-capture completion (community, edition-uniform).
pub const SCHEMA_EXEC_V1: &str = "csq.exec.v1";

/// `csq sdk capabilities --json` — op discovery for the current build + edition.
pub const SCHEMA_CAPABILITIES_V1: &str = "csq.capabilities.v1";

/// `csq audit verify --json` — the chain-integrity verdict envelope (S2).
pub const SCHEMA_VERIFY_V1: &str = "csq.verify.v1";

/// `csq audit anchor --json` — reserved for S3 (hash-anchor); payload not coded here.
pub const SCHEMA_ANCHOR_V1: &str = "csq.anchor.v1";

/// `csq eval --json` — reserved for S4 (enterprise moat); payload not coded here.
pub const SCHEMA_EVAL_V1: &str = "csq.eval.v1";

/// `csq status --json` — the slot roster (id, label, quota windows, surface).
///
/// Before this schema existed the verb emitted a BARE top-level array, so a host
/// had nothing to feature-detect against: an added field was fine, but a rename
/// or retype was a silent break with no version to pin. The rows are unchanged;
/// they move under the envelope's payload.
pub const SCHEMA_STATUS_V1: &str = "csq.status.v1";

/// `csq listkeys --json` — bound 3P provider keys (fingerprinted, never raw).
///
/// Same bare-array history as [`SCHEMA_STATUS_V1`].
pub const SCHEMA_LISTKEYS_V1: &str = "csq.listkeys.v1";

/// `csq models list --json` — the model catalog for one provider or all.
///
/// Same bare-array history as [`SCHEMA_STATUS_V1`].
pub const SCHEMA_MODELS_V1: &str = "csq.models.v1";

/// `csq login --json` — a value-or-nothing op (an internal ticket): scoped today to the
/// fail-fast [`error::SdkErrorCode::InteractionRequired`] guard emitted BEFORE
/// any provider-specific login flow starts, when a non-headless-drivable flow is
/// attempted with no local TTY. The bulk of `csq login`'s human-facing progress
/// output (browser-open notices, device-code prompts) is unchanged text on
/// stdout/stderr — this schema does not (yet) envelope those.
pub const SCHEMA_LOGIN_V1: &str = "csq.login.v1";
