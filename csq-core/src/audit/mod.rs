//! Audit trail module — per-`csq run` JSONL record persistence and
//! sweep (spec 12 v1), plus the M01 trait abstraction layer for the
//! Phase-A `csq-pact-eatp-adoption` workspace (spec 12 §12.9).
//!
//! # v1 surface (spec 12 §12.3)
//!
//! [`persist::write_record`] is the ONLY function that writes under
//! `~/.claude/accounts/csq-runs/`. The [`sweep`] sub-module provides
//! the daemon-side GC tick (24h cadence, deletes >30d records).
//!
//! # M01 trait abstraction layer (spec 12 §12.9)
//!
//! Four csq-owned traits define the abstraction boundary between csq
//! and any concrete canonical-form + signing + storage substrate:
//!
//! - [`CanonicalForm`] — deterministic canonical serialization + SHA-256 hash
//! - [`SigningKey`] — key identity, sign (fallible), pubkey accessors
//! - [`LedgerEngine`] — local hash-chained append-only log (`&self`)
//! - [`LedgerSink`] — external anchor surface (async, exactly 3 methods)
//!
//! Per the M01 structural invariant, no vendor module paths appear
//! in [`traits`] or [`types`]; the the enterprise edition impls live in a sibling
//! `the enterprise seam crate` crate (is a workspace member, gated by the
//! `kailash-trust` feature of that crate).
//!
//! Supporting types in [`types`]: [`SignedRecord`] (custom Deserialize
//! enforces `kind == payload.kind()` + `deny_unknown_fields`),
//! [`RecordId`], [`KeyId`], [`Sha256Hex`], [`SinkName`], [`SinkId`],
//! [`RedactedString`], [`Ed25519Signature`], [`Ed25519PublicKey`],
//! [`SinkReceipt`], [`SinkError`] / [`LedgerError`] / [`SigningError`]
//! / [`IdError`] (all `#[non_exhaustive]`), [`EventKind`] (16 variants),
//! [`EventPayload`] (14 typed variants, includes `chain_id` for
//! cross-record consistency per M05).
//!
//! [`CanonicalForm`]: traits::CanonicalForm
//! [`SigningKey`]: traits::SigningKey
//! [`LedgerEngine`]: traits::LedgerEngine
//! [`LedgerSink`]: traits::LedgerSink
//! [`SignedRecord`]: types::SignedRecord
//! [`RecordId`]: types::RecordId
//! [`KeyId`]: types::KeyId
//! [`Sha256Hex`]: types::Sha256Hex
//! [`SinkName`]: types::SinkName
//! [`SinkId`]: types::SinkId
//! [`RedactedString`]: types::RedactedString
//! [`Ed25519Signature`]: types::Ed25519Signature
//! [`Ed25519PublicKey`]: types::Ed25519PublicKey
//! [`SinkReceipt`]: types::SinkReceipt
//! [`SinkError`]: types::SinkError
//! [`LedgerError`]: types::LedgerError
//! [`SigningError`]: types::SigningError
//! [`IdError`]: types::IdError
//! [`EventKind`]: types::EventKind
//! [`EventPayload`]: types::EventPayload

// `impls/mod.rs` is always compiled. The inner `noop` sub-module is
// test-gated; the `sinks` sub-module is gated per-feature.
// Prior to M07 the whole `impls/` dir was test-gated; M07 removes the
// outer gate so the cfg-gated reference-impl sinks can compile outside
// test builds when their feature flags are active.
pub mod impls;

// Re-export the `noop` surface under the test+test-utils gate so
// existing test callsites (`crate::audit::impls::noop::NoopSink`) are
// unchanged.
#[cfg(any(test, feature = "test-utils"))]
#[allow(unused_imports)]
pub use impls::noop;

/// M13b — Signed-when-possible emit helpers for lifecycle ops (account-swap,
/// logout, move-slot). Encodes the OD-2 signing posture from journal 0031.
pub mod op_emit;

/// M14 — External anchoring driver (spec 12 §12.18, spec 15 §15.12).
///
/// [`anchor::anchor_head`] commits the chain HEAD to an active [`LedgerSink`]
/// and records the outcome via `ReplicationAck` / `ReplicationFailed` events.
/// The daemon tokio loop lives in [`crate::daemon::anchor_task`]; this module
/// contains the pure, dependency-injected logic testable without a live daemon.
pub mod anchor;
/// M16 — signed export cutoff manifest (`CUTOFF.json`, spec 16 §16.14).
///
/// [`cutoff::build_cutoff_json`] builds and signs the chain-HEAD snapshot
/// `(latest_hash, latest_seq, latest_anchor_ref, export_ts)` that `csq audit
/// export` embeds in the bundle for export-time tamper-evidence.
pub mod cutoff;
/// CF1 / M08b — EATP audit-chain canonical-form **projection** (spec 12 §12.12.7).
///
/// A standalone encoder that reproduces the Foundation EATP governance
/// audit-chain canonical form (`terrene-foundation/kailash-py`
/// `AuditAnchor.compute_hash`) byte-for-byte. This is a projection for
/// EATP-relevant (loom↔csq seam) events — it does NOT replace csq's sovereign
/// session-custody [`SignedRecord`] chain. See the module docs and workspace
/// journals 0010 / 0017.
///
/// [`SignedRecord`]: types::SignedRecord
pub mod eatp_canonical;
/// M04 — local Ed25519 signing-key generation + OS keychain custody.
///
/// Provides [`key_custody::LocalSigningKey`] (implements [`traits::SigningKey`]),
/// idempotent key init ([`key_custody::audit_init`]), key rotation
/// ([`key_custody::rotate_key`]), and the `csq doctor` signing-key presence
/// check ([`key_custody::check_signing_key`]).
///
/// All keychain access goes through the `keyring` crate (cross-platform:
/// macOS Keychain, Linux Secret Service, Windows Credential Manager).
/// Per PRIMARY METHODOLOGICAL DIRECTIVE M04: `security-framework`,
/// `secret-service`, and `windows-rs` are BLOCKED in this module.
/// M09 — verifiable audit-bundle export (spec 16).
///
/// [`export::export_bundle`] packages the local chain into a self-contained,
/// cross-org-verifiable `.tar` bundle with an embedded `verify` script that
/// reproduces all chain checks with NO csq install required.
pub mod export;
/// M13 — F-LEDGER-02 orphan-intent detection (append-FIRST). Scans the
/// committed chain for INTENT records with no matching OUTCOME.
pub mod intent_scan;
pub mod key_custody;
pub mod persist;
/// M19b — chain-level session floor: a signed `CsqRun` record per `csq run`,
/// emitted daemon-side when a v1 run record is ingested. Idempotent via the M20
/// in-lock dedup index (`run:<run_id>`).
pub mod run_floor;
/// M07 — operator configuration for `LedgerSink` (audit.sink + per-sink
/// cadence). Compiles under ALL feature configurations; the cfg-gated
/// reference-impl sinks live in the `impls::sinks` sub-tree.
pub mod sink_config;
pub mod sweep;
pub mod traits;
/// M2 T2.5 — trust-plane conformance grading (enterprise edition only).
///
/// Classifies a verified audit chain against the the enterprise edition trust-plane
/// gradient (`Compatible`/`Conformant`/`Complete`). Surfaced in
/// `csq audit verify` and the `csq doctor` schema. The community edition has no
/// trust plane, so this module is `#[cfg(feature = "enterprise")]`.
#[cfg(feature = "enterprise")]
pub mod trust_grade;
pub mod types;
/// M05 — chain-integrity verifier (spec 12 §12.13).
///
/// [`verify::verify_chain`] walks the on-disk JSONL chain and verifies
/// hash-chain links, seq monotonicity, chain_id consistency, and Ed25519
/// signatures. Called at daemon startup (before socket bind) and by
/// `csq audit verify`.
pub mod verify;

/// M17 — per-developer identity resolution.
///
/// Resolves a claimed developer principal → per-dev Ed25519 key (in OS
/// keychain) or `Unbacked`. The `attest_authorship` function is the single
/// CRITICAL-2 call-site: it issues a CSPRNG nonce, proves key control via
/// challenge-response, and returns an `EatpActor` blob for `SignedRecord.actor`.
/// The model/chain signing key NEVER signs provenance.
pub mod dev_identity;

/// M18 BE — loom↔csq provenance seam.
///
/// Implements the `POST /api/provenance/anchor` IPC route. Validates inbound
/// F101-1 provenance events at the frontier (F-SEAM-02 validate-before-link),
/// parks unknown-version events in `.pending/provenance/`, and anchors
/// known-version events into the audit chain via M17 `attest_authorship` +
/// `write_record_v2_signed`. The production version dispatcher ships with
/// ZERO registered arms (ADR-B2: complete plugin system, no plugins installed).
pub mod seam;

/// M12 — Authority Registry for multi-sig own-ops.
///
/// Restricts accepted signer pubkeys for guarded op-classes (KeyRotate,
/// IdentityMint, ReleaseAuth) to an enrolled, op-class-scoped roster.
/// Closes the M11 Sybil-resistance gap: a sig-valid-but-unenrolled pubkey
/// contributes 0 to the threshold count post-activation (enterprise edition).
///
/// Community edition: no membership check (pure M11 behavior).
/// Enterprise edition: roster-backed membership enforcement after activation.
/// Fail closed on any enterprise misconfiguration.
pub mod authority;

/// M11 — Multi-sig authorization gate for high-impact own-ops.
///
/// Provides N-of-M Ed25519 signature collection over the canonical intent of
/// high-impact operations (KeyRotate, ReleaseAuth, IdentityMint) before the
/// record is written. The multi-sig proof lives in `SignedRecord.authority` and
/// is enforced by `verify_chain` for every record that carries it. Records with
/// `authority: None` are unaffected (backward compatible).
pub mod multi_sig;

/// `AuditHealth` — daemon-startup verify outcome, threaded into `RouterState`.
///
/// Stored in the daemon's shared state so audit-subsystem gates (anchor task,
/// emit IPC) and operator surfaces (doctor, daemon status) can consult it
/// without re-running chain verification. See spec 12 §12.13.5.
pub mod health;

// v1 re-exports — preserved for the spec 12 §12.3 write path.
pub use persist::{
    gen_run_id, write_record, AuditError, AuditRecord, Decision, ResultState, Surface,
};
// v2 re-exports — parallel write path (M02, spec 12 §12.2).
pub use anchor::scan_chain_for_anchor_outcome;
pub use intent_scan::{scan_orphan_intents, OrphanIntent, OrphanScanError};
pub use persist::{write_record_v2, write_record_v2_signed, AuditV2Error, ChainGenesis};
pub use sweep::{AuditSweepSnapshot, AuditSweeperHandle};

// M01 trait surface + supporting types. `NoopSink` is intentionally
// NOT re-exported — reachable only via `crate::audit::impls::noop::NoopSink`
// inside cfg-gated blocks.
pub use traits::{CanonicalForm, LedgerEngine, LedgerSink, SigningKey};
pub use types::{
    AccountLogoutPayload, AccountMovePayload, AccountSwapPayload, ArtifactLoadPayload,
    ChainContinuationPayload, ChainReGenesisPayload, CsqRunPayload, EatpActor, EatpAuthority,
    EatpTrust, Ed25519PublicKey, Ed25519Signature, EventKind, EventPayload, IdError,
    IdentityMintPayload, KeyId, KeyRotatePayload, LedgerError, ModelInvokePayload,
    OAuthRefreshPayload, OpOutcome, OpPhase, OutputCapturePayload, RecordId, RedactedString,
    ReleaseAuthPayload, ReplicationAckPayload, ReplicationFailedPayload, RotationReason, Sha256Hex,
    SignedRecord, SigningError, SinkDriftDetectedPayload, SinkError, SinkId, SinkName, SinkReceipt,
};
// M04 public surface — key custody operations.
pub use key_custody::{
    audit_init, check_signing_key, migrate_keys_to_file_store, repair_audit_chain, rotate_key,
    try_load_signing_key, write_roster_floor_to_keychain, ChainState, KeyCustodyError,
    KeyLoadOutcome, KeySlot, LocalSigningKey, MigrateOutcome, RepairOutcome, SigningKeyStatus,
    SERVICE_NAME as AUDIT_SIGNING_SERVICE_NAME,
};

// M2 T2.5 — trust-plane conformance grade (enterprise edition only).
#[cfg(feature = "enterprise")]
pub use trust_grade::{
    grade_for_audit_health, grade_for_verify_result, grade_from_signals, TrustPlaneGrade,
    TrustPlaneSignals,
};

// M08 — test-utils re-exports for the cross-impl canonical-form CI gate.
// `canonical_bytes_for` and `AUDIT_SCHEMA_VERSION` are pub(crate) in persist.rs
// to prevent accidental usage in production paths. The `_test` aliased variants
// are exposed under the `test-utils` feature gate so that the integration test
// `csq-core/tests/cross_impl_canonical_form.rs` can reach them.
#[cfg(any(test, feature = "test-utils"))]
pub use persist::{canonical_bytes_for_test, sha256_hex_test, AUDIT_SCHEMA_VERSION_TEST};

// M07 public surface — sink config + doctor snapshot.
pub use sink_config::{
    validate_sink_compiled_in, AuditSinkConfig, SinkCadenceConfig, SinkConfigError,
    SinkDoctorSnapshot,
};

// M05 public surface — chain-integrity verifier.
pub use verify::{
    exit_code_for_error, to_json_output, verify_chain, KeyGap, KeychainAnchorStatus,
    RosterFloorAnchorStatus, VerifyConfig, VerifyFailureDetail, VerifyJsonOutput, VerifySummary,
};

// AuditHealth — daemon-startup verify outcome.
pub use health::{clear_chain_broken, is_chain_broken, set_chain_broken, AuditHealth};

// M09 public surface — verifiable audit-bundle export.
pub use export::{export_bundle, ExportError, ExportSummary};

// M11 public surface — multi-sig own-ops gate.
pub use multi_sig::{
    authorize_op, resolve_edition, resolve_policy, verify_record_multi_sig, Edition,
    InMemorySignerSet, MultiSigError, MultiSigPolicy, SignerSet,
};

// CF1 / M08b public surface — EATP canonical-form projection.
pub use eatp_canonical::{
    EatpAuditAnchor, EatpCanonicalError, VerificationLevel, EATP_CANONICAL_FORM_SPEC_VERSION,
};

// M12 public surface — authority registry.
pub use authority::{
    resolve_registry, roster_path, save_roster, verify_signed_roster, AuthorityError,
    AuthorityGrant, AuthorityRegistry, EnrolledKey, LocalOperatorRegistry, OpClass, PactDefinition,
    Roster, RosterEntry, RosterFileRegistry, SignedRoster, SUPPORTED_ROSTER_FORMAT_VERSION,
};

// Test-utils re-exports from multi_sig (intent_hash for cross-crate test blob construction).
#[cfg(any(test, feature = "test-utils"))]
pub use multi_sig::intent_hash;
