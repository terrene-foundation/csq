//! `sdk` — csq-core's re-export of the public `csq-sdk` wire contract, plus the
//! app-side builders.
//!
//! The wire types (envelope, error, completion, adapters, schema constants, payload
//! DTOs) live in the standalone `csq-sdk` crate (W2, `internal-design-docs`).
//! This module re-exports them at their historical path (`crate::sdk::*` /
//! `csq_core::sdk::*`) so every callsite — notably the `csq` CLI's `exec` / `audit` /
//! `sdk capabilities` subcommands — compiles unchanged. It adds the two things that are
//! NOT wire-shape and therefore stayed app-side:
//!
//! - [`EDITION`] — the `cfg(feature = "enterprise")` discriminant, passed INTO the DTOs
//!   (the public `csq-sdk` crate is edition-uniform and never feature-gates edition); and
//! - the builders ([`capabilities::build`], [`verify::build_verify_envelope`]) that map
//!   csq-core's internal audit types onto `csq-sdk`'s DTOs. csq-core depends on csq-sdk;
//!   csq-sdk never reaches back (the correct dependency direction).

pub mod capabilities;
pub mod verify;

// The wire contract — re-exported verbatim from the public `csq-sdk` crate.
pub use csq_sdk::{
    emit, parse_claude_json, CapabilitiesPayload, Completion, Envelope, FinishReason, SdkError,
    SdkErrorCode, Usage, VerifyFailureDetail, VerifyKeyGap, VerifyPayload, SCHEMA_ANCHOR_V1,
    SCHEMA_CAPABILITIES_V1, SCHEMA_EVAL_V1, SCHEMA_EXEC_V1, SCHEMA_VERIFY_V1,
};

// The app-side verify builder (maps the internal chain-verify result → the DTO).
pub use verify::build_verify_envelope;

/// The edition of this build, supplied to the SDK payload DTOs (`capabilities`,
/// `verify`) so a consumer distinguishes an op that is *absent-because-community* from
/// one that is *absent-because-unimplemented*.
///
/// `"enterprise"` when the `enterprise` Cargo feature is active (this repo's default
/// build), `"community"` otherwise (the Apache-2.0 fork). Per `rules/terrene-naming.md`.
/// This is the app's concern — `csq-sdk` itself is edition-uniform; edition is passed IN.
pub const EDITION: &str = if cfg!(feature = "enterprise") {
    "enterprise"
} else {
    "community"
};
