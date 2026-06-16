//! M18 BE seam — loom↔csq provenance event ingest.
//!
//! This module implements the daemon-side IPC handler for F101-1 provenance
//! events emitted by loom. It is the implementation of the
//! `POST /api/provenance/anchor` route.
//!
//! ## Architecture
//!
//! ```text
//! IPC (Unix socket, SO_PEERCRED same-UID)
//!   └─ provenance_anchor_handler (server.rs)
//!        └─ ingest_provenance_event (seam/ingest.rs)
//!             ├─ SurfaceRegistry::load        — data-driven surface check
//!             ├─ validate_event               — F-SEAM-02 validate-before-link
//!             ├─ VersionRegistry::dispatch    — per-version decoder gate
//!             │   ├─ Rejected     → quarantine_event + seam_event_rejected
//!             │   ├─ UnknownVer   → park_unknown_version (no chain record)
//!             │   └─ KnownVer     → attest_authorship + ProvenanceAnchored
//!             └─ write_record_v2_signed       — single chain writer (HIGH-3)
//! ```
//!
//! ## Security properties
//!
//! - `received_bytes_hash = sha256(exact received bytes)` — F-SEAM-01(c).
//! - Malformed / frontier-rejected events NEVER reach the chain spine.
//! - Raw event body is NEVER persisted to the chain (HIGH-1).
//! - The production version dispatcher registers exactly the frozen F101-1
//!   `"1"` decode arm (M18-bind); unknown versions park visibly (ADR-B2).
//! - All custody writes (quarantine, pending) use the §5a tmp-cleanup pipeline.

pub mod capture_matrix;
pub mod decode;
pub mod envelope;
pub mod error;
pub mod frontier;
pub mod ingest;
pub mod precheck;
pub mod quarantine;
pub mod reconcile;
pub mod registry;

// Public API surface re-exported from seam.
pub use capture_matrix::{
    build_capture_matrix, emit_matrix_record, matrix_content_hash, read_last_hash,
    sidecar_dedup_key, write_last_hash,
};
pub use error::{RejectReason, SeamError};
pub use frontier::ValidatedEnvelope;
pub use ingest::{ingest_provenance_event, sweep_timed_out, IngestOutcome};
pub use registry::{DispatchOutcome, SurfaceRegistry, VersionRegistry};

// Test-only re-exports.
#[cfg(any(test, feature = "test-utils"))]
pub use ingest::ingest_provenance_event_with_test_registry;
