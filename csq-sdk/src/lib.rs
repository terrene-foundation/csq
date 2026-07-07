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
pub use capabilities::CapabilitiesPayload;
pub use envelope::{emit, Completion, Envelope, FinishReason, Usage};
pub use error::{SdkError, SdkErrorCode};
pub use verify::{VerifyFailureDetail, VerifyKeyGap, VerifyPayload};

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
