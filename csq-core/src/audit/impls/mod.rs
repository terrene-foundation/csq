//! Concrete implementations of the [`crate::audit::traits`] surface
//! that ship in csq-core.
//!
//! csq-core hosts ONLY implementations whose dependency footprint is
//! Apache 2.0 / Foundation-owned. The the enterprise edition-backed impls
//! (proprietary) live in the sibling `the enterprise seam crate`
//! crate, which is NOT a workspace member — maintainers build it
//! locally with `cargo check --manifest-path the enterprise seam crate/Cargo.toml`.
//! See `workspaces/csq-pact-eatp-adoption/todos/active/M01-trait-skeleton-csq-core-audit.md`
//! §"Acceptance criteria" amendment for the rationale.
//!
//! # Modules
//!
//! - [`noop`] — `NoopSink`, a `#[cfg(any(test, feature = "test-utils"))]`
//!   in-memory sink used by unit tests and the M01 type-check harness.
//!   Structurally cannot ship in a release binary (see audit-primitive
//!   grep in `M01-trait-skeleton-csq-core-audit.md`).
//! - [`sinks`] — M07 reference-impl catalog (each impl gated behind its
//!   own `--features <sink>-sink` flag). The `sinks` module itself is
//!   always compiled (zero-cost when no feature is active); the inner
//!   sink modules carry their own `#[cfg(feature = "...")]` guards.

/// Test-only `NoopSink`. Structurally excluded from release builds.
#[cfg(any(test, feature = "test-utils"))]
pub mod noop;

/// M07 reference-impl catalog. Each inner module is cfg-gated.
/// The module itself is always compiled; its contents are zero when
/// no sink feature is active.
pub mod sinks;

/// M10 `CsqLedgerSink` — the Foundation-owned csq-ledger reference impl.
/// Gated behind `--features csq-ledger-sink`; NOT on the default code path
/// (PRIMARY DIRECTIVE: csq-core stays local-only by default).
#[cfg(feature = "csq-ledger-sink")]
pub mod csq_ledger_sink;
