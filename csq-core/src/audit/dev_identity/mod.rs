//! M17 — Per-developer identity resolution (BE workstream).
//!
//! Implements the per-developer signing identity that signs provenance at the
//! csq↔loom seam. Per journal 0017 §3: RRPS devs share ONE model credential
//! (org-level GCP/Anthropic access), so the model credential signs NOTHING
//! and is NEVER identity. Provenance is signed with a per-developer key
//! resolved via one-time enrollment.
//!
//! # Module structure
//!
//! - [`enrollment`]: principal → Ed25519 key enrollment; on-disk pubkey-only
//!   table; private key in OS keychain (`csq-dev-signing-<principal>`).
//! - [`resolution`]: resolve claimed principal → `Enrolled{key,pubkey}` |
//!   `Unbacked`. NEVER returns the model credential.
//! - [`challenge`]: `prove_control` / `verify_control` (nonce-bound
//!   challenge-response).
//! - [`attest`]: `attest_authorship` — the single CRITICAL-2 call-site; issues
//!   CSPRNG nonce, resolves, proves-or-UNBACKED, returns `EatpActor`.
//! - [`error`]: `DevIdentityError` (all variants use fixed-vocabulary messages).
//!
//! # CRITICAL-2 invariant (from security-review.md)
//!
//! Resolution MUST fail-closed to UNBACKED. A missing/unresolvable per-dev
//! key produces a signed-as-UNBACKED record, NOT a record signed by the shared
//! model key dressed as identity. The shared model key is org-level model
//! access, never identity; signing provenance with it launders an
//! unattributable action into a falsely-attributed one.
//!
//! # Attribution granularity
//!
//! Default is `AccountablePrincipal` (works-council-safe for BetrVG §87(1)6).
//! `PerIndividual` requires explicit operator opt-in.

pub mod attest;
pub mod challenge;
pub mod enrollment;
pub mod error;
pub mod resolution;

// Public surface for M17.
pub use attest::attest_authorship;
pub use challenge::{prove_control, verify_control};
pub use enrollment::{
    enroll_developer, enrollment_path, unenroll_developer, DevEnrollment, EnrollmentTable,
    Granularity, Principal, DEV_SIGNING_SERVICE_PREFIX,
};
pub use error::DevIdentityError;
pub use resolution::{resolve_developer, DevResolution};
