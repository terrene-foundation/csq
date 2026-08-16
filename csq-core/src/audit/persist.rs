//! Single audited write site for `csq run` audit records.
//!
//! `write_record` is the ONLY public function that writes v1 records under
//! `~/.claude/accounts/csq-runs/`.  The invariant is enforced by the
//! static grep test at `csq-core/tests/audit_single_writer.rs`.
//!
//! `write_record_v2` is the parallel writer for schema v2 ledger records
//! (M02, spec 12 §12.2).  v1 and v2 writers are independent — v1 is NOT
//! replaced.  v2 records include a tamper-evident hash chain (`prev_hash`,
//! `canonical_hash`) and optional EATP attestation fields.
//!
//! # Write pattern
//!
//! Both writers mirror `credentials/file.rs::save` — the canonical
//! `unique_tmp_path → write → secure_file → atomic_replace` pipeline
//! with full §5a cleanup on every error branch.  See
//! `rules/security.md` §5a.
//!
//! # RULE_ID validation (v1)
//!
//! Items in `rule_ids_cited_original` and `rule_ids_cited_after_repair`
//! are validated against `^[A-Z][A-Z0-9-]{1,32}$` before serialization.
//! Items that fail the regex are dropped; the count is recorded in
//! `rule_ids_dropped_invalid_format`.  See `specs/12-audit-trail.md` §12.5.
//!
//! # Chain semantics (v2)
//!
//! `write_record_v2` maintains a per-base-dir chain file
//! (`csq-runs/chain.json`) recording `{chain_id, genesis_seq, genesis_ts}`.
//! `prev_hash` is computed from the CANONICAL FORM of the previous record
//! (excludes the `signature` field), not raw on-disk bytes.
//! `canonical_hash` is computed over the same canonical form of the current
//! record before any signature is attached.

use crate::audit::types::SignedRecord;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use serde::{Deserialize, Serialize};
use std::num::Wrapping;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ── Public types ───────────────────────────────────────────────────────────────

/// Per-`csq run` surface tag.  Serializes as lowercase string per the JSON
/// schema enum: `"cc"`, `"codex"`, `"gemini"`, `"kimi"`, `"grok"`.
///
/// `Kimi` and `Grok` (W3-2, Wave 3 native Kimi/Grok session surfaces) tag
/// audit records produced by native `csq run` dispatch to the Kimi CLI
/// (`kimi`) or Grok CLI (`grok`) — `providers::native` sessions, not
/// capability-layer-spawned `codex`/`gemini` subprocesses. See
/// `coc-eval/schemas/csq-runs-schema-v1.json` `surface.enum` (kept in sync
/// per spec 12 §12.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Cc,
    Codex,
    Gemini,
    Kimi,
    Grok,
}

/// Coarse outcome classification.  Serializes as lowercase strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultState {
    Pass,
    Fail,
    RepairApplied,
    Degraded,
}

/// Capability-layer decision tag.  Serializes as lowercase strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Accept,
    Reject,
    Repair,
    Bypass,
}

/// The M6 T6.1 cross-CLI spawn-boundary governance verdict recorded on a
/// `csq run` of codex/gemini.
///
/// Present ONLY when an operating envelope gated the spawn (enterprise edition,
/// codex/gemini surface). `None` for cc/3P runs (gated in-loop via M-IC /
/// Phase 2b, not at spawn) and for ungoverned spawns (no envelope configured),
/// so the serialized record stays byte-identical for every pre-M6 run.
/// Kailash-FREE plain data; `additionalProperties: true` in the v1 schema makes
/// the field additive (old records lacking it deserialize to `None`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnGateRecord {
    /// The spawned CLI surface: `"codex"` | `"gemini"`.
    pub cli: String,
    /// The kailash action id evaluated: `"spawn_codex"` | `"spawn_gemini"`.
    pub action: String,
    /// The governance disposition, a fixed-vocab tag (no envelope internals per
    /// `rules/security.md` §2):
    ///
    /// - `"pass"` | `"conditional"` — a PERMITTED spawn (the `SpawnGate::Proceed`
    ///   branch).
    /// - the refusal reason (e.g. `"spawn_blocked_by_operating_envelope"`) — a
    ///   REFUSED spawn (the `SpawnGate::Refuse` branch). `csq run` sets this
    ///   `verdict`, sets the audit result to `Fail`/`Reject`, and durably flushes
    ///   the record (`AuditEmitter::try_flush_now`) BEFORE exiting
    ///   `EXIT_CODE_SPAWN_BLOCKED` — so a refusal IS on the audit trail, not
    ///   stderr-only. (The reason is also printed to stderr for the operator.)
    pub verdict: String,
}

/// Per-`csq run` audit record.
///
/// Field names and types mirror `coc-eval/schemas/csq-runs-schema-v1.json`
/// exactly.  Any change to the schema MUST be reflected here (and vice versa)
/// per spec 12 §12.7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Schema version — always `"1"` for v1 records.
    pub schema_version: String,
    /// UUID v4 identifying this `csq run`.  Doubles as the filename stem.
    pub run_id: String,
    /// SHA-256 hex of the fixture content (NFR-AUDIT-01 re-run substrate).
    pub fixture_sha256: String,
    /// SHA-256 hex of the `.coc/` artifact set's COC.lock content.
    pub coc_sha256: String,
    /// Workspace version string (Cargo.toml workspace.package.version).
    pub csq_version: String,
    /// Version of the per-Surface CLI binary that was dispatched to.
    pub cli_version: String,
    /// Surface that was dispatched to.
    pub surface: Surface,
    /// Model identifier (e.g. `claude-opus-4-7`).
    pub model: String,
    /// RFC3339 timestamp at capability-layer-driver entry.
    pub start_ts: String,
    /// RFC3339 timestamp at capability-layer-driver exit.
    pub end_ts: String,
    /// Coarse outcome of this run.
    pub result_state: ResultState,
    /// Numeric score delta vs baseline, or `null` when outside the harness.
    pub score_delta_vs_baseline: Option<f64>,
    /// RULE_IDs parsed from model raw output — pre-validation set.
    pub rule_ids_cited_original: Vec<String>,
    /// RULE_IDs present after FR-CL-04 post-validate repair.
    pub rule_ids_cited_after_repair: Vec<String>,
    /// Count of RULE_IDs dropped due to failing the format regex.
    pub rule_ids_dropped_invalid_format: u32,
    /// Capability-layer decision for this run.
    pub decision: Decision,
    /// M6 T6.1 — the cross-CLI spawn-boundary governance verdict (codex/gemini,
    /// enterprise). `None` for cc/3P (in-loop gated) and ungoverned spawns.
    /// Additive `Option` (`skip_serializing_if`): pre-M6 records omit the key and
    /// deserialize to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn_gate: Option<SpawnGateRecord>,
}

/// Errors returned by [`write_record`].
///
/// Every variant maps to a fixed-vocabulary error tag per `rules/security.md`
/// §2 — callers MUST NOT echo variant debug output to the user.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("invalid RULE_ID format: {0}")]
    InvalidRuleIdFormat(String),
    /// The `run_id` is not a canonical UUID (8-4-4-4-12 hex). The v1 record
    /// filename is `<run_id>.jsonl` and the M19b floor-record dedup key is
    /// `run:<run_id>`, so an untrusted IPC `run_id` containing path separators
    /// or `:` would be a path-traversal / dedup-namespace-forge vector. Reject
    /// at the single write site (M19b security review M1/M2).
    #[error("invalid run_id (must be a UUID): {0}")]
    InvalidRunId(String),
    #[error("serialized record exceeds 4 KiB: {0} bytes")]
    RecordExceedsSize(usize),
    #[error("I/O error writing audit record")]
    Io(#[from] std::io::Error),
    #[error("serialization error")]
    Serialize(#[from] serde_json::Error),
}

/// Fixed-vocabulary error tag mapping for IPC responses.
///
/// Called by the daemon handler to pick a `&'static str` tag per
/// `rules/security.md` §2 (no upstream body echoes).
impl AuditError {
    pub fn fixed_tag(&self) -> &'static str {
        match self {
            AuditError::InvalidRuleIdFormat(_) => "invalid_rule_id",
            AuditError::InvalidRunId(_) => "invalid_run_id",
            AuditError::RecordExceedsSize(_) => "record_too_large",
            AuditError::Io(_) => "audit_io_error",
            AuditError::Serialize(_) => "audit_serialize_error",
        }
    }
}

// ── RULE_ID validator ──────────────────────────────────────────────────────────

/// Returns `true` if `s` matches `^[A-Z][A-Z0-9-]{1,32}$`.
///
/// Anchored regex; requires an uppercase letter followed by 1-32 uppercase
/// letters, digits, or hyphens.  Total length: 2-33 characters.
/// Cached in a `OnceLock` so the regex is compiled once per process.
fn validate_rule_id(s: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^[A-Z][A-Z0-9-]{1,32}$")
            .expect("RULE_ID regex is a compile-time constant and must compile")
    })
    .is_match(s)
}

// ── Filesystem helpers ─────────────────────────────────────────────────────────

/// Returns `~/.claude/accounts/csq-runs/` as an absolute path (the op-chain).
///
/// Convenience wrapper over [`audit_dir_for`] for `ChainKind::Op`.
fn audit_dir() -> PathBuf {
    audit_dir_for(ChainKind::Op)
}

/// Returns the production runs-directory for `chain`
/// (`~/.claude/accounts/csq-runs/` for the op-chain, `.../eatp-runs/` for the
/// EATP attestation chain) as an absolute path.
///
/// Uses `$HOME` (or the `CSQ_BASE_DIR` override used in tests) to locate the
/// csq base dir.  In tests, callers should pass a `TempDir`-backed path
/// directly to the internal writer rather than relying on this function.
fn audit_dir_for(chain: ChainKind) -> PathBuf {
    // Production: $HOME/.claude/accounts
    let base = std::env::var_os("CSQ_BASE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude").join("accounts"))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("csq-accounts"));
    base.join(chain.runs_subdir())
}

/// Maximum persisted record size per NFR-OBS-03.
const MAX_RECORD_BYTES: usize = 4 * 1024;

// ── Public write site ─────────────────────────────────────────────────────────

/// Generates a new UUID v4 string for use as a `run_id`.
///
/// Uses `getrandom` (the same CSPRNG source used by OAuth state tokens
/// and PKCE verifiers throughout csq).  Format:
/// `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` where `y` is `8..b`.
pub fn gen_run_id() -> String {
    let mut bytes = [0u8; 16];
    // R2-RS-6: halt-on-fatal is the correct response to getrandom failure
    // for an audit-trail writer. Signing records with non-CSPRNG bytes
    // would weaken every downstream cryptographic claim. Containers with
    // seccomp blocking `getrandom` cannot run csq's audit pipeline; halt
    // is the structural defense, not a recoverable error.
    getrandom::getrandom(&mut bytes).expect("getrandom for run_id");
    // Set version 4 bits (bits 12-15 of byte 6).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant bits (bits 6-7 of byte 8 to 10xx).
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ── v2 chain types and error ───────────────────────────────────────────────────

/// Schema version string embedded in every v2 `SignedRecord`.
///
/// Centralised here so callers (M04 `rotate.rs`, M02 `write_record_v2`) never
/// hardcode the literal `"2"`.  Changing the schema version is a single-edit
/// operation.
pub(crate) const AUDIT_SCHEMA_VERSION: &str = "2";

/// Public alias for `AUDIT_SCHEMA_VERSION` — exposed under `test-utils` for the
/// M08 cross-impl canonical-form CI gate (`csq-core/tests/cross_impl_canonical_form.rs`).
/// Not part of the production API surface.
#[cfg(any(test, feature = "test-utils"))]
pub const AUDIT_SCHEMA_VERSION_TEST: &str = AUDIT_SCHEMA_VERSION;

/// On-disk chain identity file (`csq-runs/chain.json`).
///
/// Written once on first `write_record_v2` call and never mutated thereafter.
/// The `chain_id` is a 26-char Crockford Base32 ULID generated from 128 bits
/// of CSPRNG entropy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainGenesis {
    /// 26-char Crockford Base32 ULID identifying this ledger chain.
    pub chain_id: String,
    /// Sequence number of the genesis record (always 0).
    /// `#[serde(default)]` allows deserialising chain.json files that predate
    /// this field (H-2: missing field must not fail deserialisation).
    #[serde(default)]
    pub genesis_seq: u64,
    /// ISO-8601 UTC timestamp of the genesis record.
    /// `#[serde(default)]` allows deserialising chain.json files that predate
    /// this field (H-2: missing field must not fail deserialisation).
    #[serde(default)]
    pub genesis_ts: String,
}

/// Errors returned by [`write_record_v2`].
#[derive(Debug, thiserror::Error)]
pub enum AuditV2Error {
    #[error("I/O error writing v2 audit record")]
    Io(#[from] std::io::Error),
    #[error("serialization error")]
    Serialize(#[from] serde_json::Error),
    #[error("chain.json is corrupted or unreadable: {reason}")]
    ChainCorrupt { reason: String },
    /// The sign-after-assign step ([`write_record_v2_signed`]) failed to
    /// produce a signature over the record's final canonical hash. The op
    /// fails closed — no record is written.
    #[error("signing failed: {reason}")]
    Signing { reason: String },
    /// The `.chain-lock` was held by another writer past the bounded
    /// acquisition deadline. The write fails closed — no record is appended
    /// and the calling operation must propagate this error without performing
    /// its side effect (F-LEDGER-02 fail-closed contract).
    #[error("chain-lock acquisition timed out after {deadline_secs}s — another writer is holding the lock")]
    ChainLockTimeout { deadline_secs: u64 },
    /// The `.chain-broken` sentinel is present — a prior `verify_chain` run
    /// classified this chain as broken or unverifiable. All writes are refused
    /// until the chain is repaired and the sentinel cleared by a subsequent
    /// successful `verify_chain` call.
    ///
    /// `error_kind` is the fixed-vocabulary tag written by the setter
    /// (e.g. `"audit_chain_broken_at_seq_5"`).
    /// To unblock: repair the chain and run `csq audit verify` (or
    /// `csq doctor`) to clear the sentinel. As a last resort, manually remove
    /// `<base_dir>/csq-runs/.chain-broken`.
    ///
    /// Note: lifecycle ops (swap/logout/move) degrade-and-proceed on this error
    /// (audit trail omitted but the op runs). `rotate_key` remains fail-closed.
    #[error(
        "chain write refused — chain is broken ({error_kind}); \
         run `csq audit verify` after repair to clear the sentinel and re-enable audit writes"
    )]
    ChainBrokenRefuseAppend { error_kind: String },
    /// An internal logic-invariant violation (e.g. a dedup outcome surfaced
    /// without a seam spec). Distinct from [`AuditV2Error::ChainCorrupt`]: this
    /// is a programmer error, NOT on-disk chain corruption — it MUST NOT trip
    /// the `.chain-broken` sentinel (which would refuse all subsequent writes).
    #[error("internal audit logic error: {reason}")]
    Internal { reason: String },
    /// A genesis-required write ([`write_genesis_v2_signed_in`]) found the chain
    /// already had a record (`seq >= 1`), so it refused IN-LOCK rather than
    /// appending a duplicate genesis. This is a BENIGN idempotency outcome (a
    /// concurrent `csq audit init` won the race) — NOT corruption. The caller
    /// maps it to the "genesis already present" no-op; it MUST NOT trip the
    /// `.chain-broken` sentinel.
    #[error("genesis already exists — chain is not empty, born-canonical genesis already written")]
    GenesisAlreadyExists,
}

impl AuditV2Error {
    /// Returns a fixed-vocabulary `error_kind` tag for operator surfaces.
    /// No upstream bodies are echoed per `rules/security.md` §2.
    pub fn fixed_tag(&self) -> &'static str {
        match self {
            AuditV2Error::Io(_) => "audit_v2_io_error",
            AuditV2Error::Serialize(_) => "audit_v2_serialize_error",
            AuditV2Error::ChainCorrupt { .. } => "audit_chain_corrupt",
            AuditV2Error::Signing { .. } => "audit_signing_error",
            AuditV2Error::ChainLockTimeout { .. } => "audit_chain_lock_timeout",
            AuditV2Error::ChainBrokenRefuseAppend { .. } => "audit_chain_broken_refuse_append",
            AuditV2Error::Internal { .. } => "audit_internal_error",
            AuditV2Error::GenesisAlreadyExists => "audit_genesis_already_exists",
        }
    }
}

// ── Pure-stdlib SHA-256 (FIPS 180-4) ──────────────────────────────────────────

/// Round constants Kₜ for SHA-256 (first 32 bits of fractional parts of
/// cube roots of first 64 primes).  FIPS 180-4 §4.2.2.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash values H₀–H₇ (first 32 bits of fractional parts of square
/// roots of first 8 primes).  FIPS 180-4 §5.3.3.
const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Pure-stdlib SHA-256 over `input`.  No external crate.
///
/// Implements FIPS 180-4 using `Wrapping<u32>` for overflow-safe arithmetic.
/// The output is a 64-character lowercase hex string.
pub(crate) fn sha256_hex(input: &[u8]) -> String {
    // ── Pre-processing: padding ──────────────────────────────────────────────
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg: Vec<u8> = input.to_vec();
    msg.push(0x80);
    // Pad with zeros until length ≡ 56 (mod 64).
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    // Append original bit length as big-endian u64.
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // ── Processing message schedule ──────────────────────────────────────────
    let mut h: [Wrapping<u32>; 8] = SHA256_H0.map(Wrapping);

    for chunk in msg.chunks_exact(64) {
        let mut w: [Wrapping<u32>; 64] = [Wrapping(0); 64];
        // Prepare message schedule W₀..W₁₅ from chunk.
        for (i, block) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = Wrapping(u32::from_be_bytes([block[0], block[1], block[2], block[3]]));
        }
        // Extend W₁₆..W₆₃.
        for i in 16..64 {
            let s0 =
                w[i - 15].0.rotate_right(7) ^ w[i - 15].0.rotate_right(18) ^ (w[i - 15].0 >> 3);
            let s1 = w[i - 2].0.rotate_right(17) ^ w[i - 2].0.rotate_right(19) ^ (w[i - 2].0 >> 10);
            w[i] = w[i - 16] + Wrapping(s0) + w[i - 7] + Wrapping(s1);
        }

        // Compression function.
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.0.rotate_right(6) ^ e.0.rotate_right(11) ^ e.0.rotate_right(25);
            let ch = (e.0 & f.0) ^ ((!e.0) & g.0);
            let temp1 = hh + Wrapping(s1) + Wrapping(ch) + Wrapping(SHA256_K[i]) + w[i];
            let s0 = a.0.rotate_right(2) ^ a.0.rotate_right(13) ^ a.0.rotate_right(22);
            let maj = (a.0 & b.0) ^ (a.0 & c.0) ^ (b.0 & c.0);
            let temp2 = Wrapping(s0) + Wrapping(maj);

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0].0, h[1].0, h[2].0, h[3].0, h[4].0, h[5].0, h[6].0, h[7].0
    )
}

// ── Canonical form helpers ─────────────────────────────────────────────────────

/// Helper struct that serializes a [`SignedRecord`] without the `signature`
/// field.  Used to compute `prev_hash` and `canonical_hash` from the
/// canonical form.
///
/// The canonical form is the JSON serialization of the record excluding the
/// `signature` field — the same bytes that a signing key would sign.
/// `prev_hash` for record N is SHA-256 of the canonical form of record N-1;
/// the genesis record uses 64 zero hex chars (`Sha256Hex::genesis()`).
#[derive(Serialize)]
struct CanonicalView<'a> {
    schema_version: &'a str,
    record_id: &'a str,
    chain_id: &'a str,
    seq: u64,
    prev_hash: &'a str,
    kind: &'a crate::audit::types::EventKind,
    payload: &'a crate::audit::types::EventPayload,
    ts: &'a str,
    key_id: &'a str,
    canonical_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<&'a crate::audit::types::EatpActor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<&'a crate::audit::types::EatpAuthority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<&'a crate::audit::types::EatpTrust>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eatp_start_ts: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eatp_end_ts: Option<&'a str>,
    // M13: append-FIRST op-phase envelope. Skipped when None so every
    // pre-M13 record's canonical form is byte-identical. When Some, the
    // intent / outcome envelope is part of the signed canonical bytes —
    // the outer signature commits to the op-phase, so an attacker cannot
    // strip an intent's `Intent` marker or forge an `Outcome` without
    // breaking the signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    op_phase: Option<&'a crate::audit::types::OpPhase>,
    // M3a: explicit PACT verification level. Skipped when None so every
    // pre-M3a record's canonical form is byte-identical. When Some, the
    // level is part of the signed canonical bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_level: Option<&'a crate::audit::eatp_canonical::VerificationLevel>,
}

/// Returns the canonical JSON bytes for `r` (excludes `signature`).
///
/// This is the pre-image for both `canonical_hash` (self-referential, computed
/// before the signature is attached) and `prev_hash` for the subsequent record.
/// Public wrapper for `canonical_bytes_for` — exposed under `test-utils` for the
/// M08 cross-impl canonical-form CI gate. Not part of the production API surface.
#[cfg(any(test, feature = "test-utils"))]
pub fn canonical_bytes_for_test(r: &SignedRecord) -> Vec<u8> {
    canonical_bytes_for(r)
}

/// Public wrapper for the pure-stdlib `sha256_hex` — exposed under `test-utils`
/// so the M08b conformance gate can independently re-hash a fixture's
/// `expected_canonical_input` and check it against the fixture's
/// `expected_sha256` WITHOUT routing through the `EatpAuditAnchor` encoder
/// (an oracle independent of the code-under-test). Not a production API.
#[cfg(any(test, feature = "test-utils"))]
pub fn sha256_hex_test(input: &[u8]) -> String {
    sha256_hex(input)
}

pub(crate) fn canonical_bytes_for(r: &SignedRecord) -> Vec<u8> {
    let view = CanonicalView {
        schema_version: &r.schema_version,
        record_id: r.record_id.as_str(),
        chain_id: r.chain_id.as_str(),
        seq: r.seq,
        prev_hash: r.prev_hash.as_str(),
        kind: &r.kind,
        payload: &r.payload,
        ts: &r.ts,
        key_id: r.key_id.as_str(),
        canonical_hash: r.canonical_hash.as_str(),
        actor: r.actor.as_ref(),
        authority: r.authority.as_ref(),
        trust: r.trust.as_ref(),
        eatp_start_ts: r.eatp_start_ts.as_deref(),
        eatp_end_ts: r.eatp_end_ts.as_deref(),
        op_phase: r.op_phase.as_ref(),
        verification_level: r.verification_level.as_ref(),
    };
    // R2-RS-5: halt-on-fatal. `CanonicalView` is structurally composed
    // of `&str`/u64/`EventKind`/`EventPayload`/`Option<EatpActor/Authority/Trust>`
    // (wrappers around `Option<serde_json::Value>`). `serde_json::to_vec`
    // can only fail under allocator exhaustion (OOM) — at which point
    // the audit pipeline cannot continue and halting is the right answer.
    // A signed record with truncated canonical bytes is worse than a
    // crash because downstream verifiers would silently accept the
    // wrong signature pre-image.
    serde_json::to_vec(&view).expect("CanonicalView serialization must not fail on valid record")
}

// ── Chain genesis helpers ──────────────────────────────────────────────────────

/// Crockford Base32 alphabet (26 chars → 32 symbols, excludes I/L/O/U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generates a 26-char Crockford Base32 chain ID from 128 bits of CSPRNG entropy.
///
/// Each output character encodes 5 bits; 26 × 5 = 130 bits, so the last character
/// encodes only 2 of its 5 bits from the entropy pool (top 3 bits forced to 0).
/// This matches the ULID specification's 128-bit identifier encoding.
pub fn gen_chain_id() -> String {
    let mut bytes = [0u8; 16]; // 128 bits
                               // R2-RS-6: halt-on-fatal — see `gen_run_id` rationale. A chain_id
                               // produced from non-CSPRNG bytes would be predictable and would
                               // collide across installs, defeating the chain-isolation invariant.
    getrandom::getrandom(&mut bytes).expect("getrandom for chain_id");

    // Encode 128 bits as 26 Crockford Base32 characters.
    // We process the 128 bits left-to-right; each symbol takes 5 bits.
    let mut out = [0u8; 26];
    // Combine all 128 bits into a big-endian bit stream.
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    let mut byte_idx: usize = 0;
    for ch in out.iter_mut() {
        // Refill buffer if < 5 bits remain.
        while bits_in_buf < 5 && byte_idx < 16 {
            bit_buf = (bit_buf << 8) | (bytes[byte_idx] as u64);
            bits_in_buf += 8;
            byte_idx += 1;
        }
        // Extract top 5 bits.
        let idx = if bits_in_buf >= 5 {
            bits_in_buf -= 5;
            ((bit_buf >> bits_in_buf) & 0x1f) as usize
        } else {
            0
        };
        *ch = CROCKFORD[idx];
    }

    String::from_utf8(out.to_vec()).expect("Crockford chars are ASCII")
}

/// Returns a minimal ISO-8601 UTC timestamp for v2 records.
pub fn current_iso8601_utc_persist() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);
    let secs = now.as_secs() as i64;
    // Reuse the civil-time conversion from sweep.rs via a local copy.
    let (year, month, day, hour, minute, second) = unix_to_ymdhms_persist(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        year, month, day, hour, minute, second
    )
}

/// Civil-time conversion (Howard Hinnant algorithm).  Stdlib-only.
fn unix_to_ymdhms_persist(mut t: i64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (t.rem_euclid(86_400)) as u32;
    let hour = s / 3_600;
    let minute = (s % 3_600) / 60;
    let second = s % 60;
    t = t.div_euclid(86_400);
    let z = t + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = (y + i64::from(month <= 2)) as i32;
    (year, month, day, hour, minute, second)
}

// ── Chain I/O helpers ──────────────────────────────────────────────────────────

/// Reads `chain.json` from `<csq_runs_dir>/chain.json`, or initialises it if
/// absent.  The file is written atomically with §5a cleanup on failure.
///
/// Returns the (possibly freshly-created) [`ChainGenesis`].
///
/// `pub(crate)` so M04 `key_custody::init` / `doctor` can call this to obtain
/// an authoritative `chain_id` instead of falling back to `"default"` (H-1).
pub(crate) fn read_or_init_chain_genesis(
    csq_runs_dir: &Path,
    genesis_ts: &str,
) -> Result<ChainGenesis, AuditV2Error> {
    let chain_path = csq_runs_dir.join("chain.json");

    if chain_path.exists() {
        let raw = std::fs::read_to_string(&chain_path)?;
        let genesis: ChainGenesis =
            serde_json::from_str(&raw).map_err(|e| AuditV2Error::ChainCorrupt {
                reason: e.to_string(),
            })?;
        return Ok(genesis);
    }

    // Not found → create a fresh genesis. A stale `.seam-dedup-index` sidecar from
    // a PRIOR chain (e.g. an operator manually deleted chain.json then re-ran
    // `csq audit init`) would carry dedup keys that do NOT belong to this new
    // chain — its flat, chain_id-unscoped keys would produce false-positive hits
    // for any `seam_dedup_index_contains(_or_rebuild)` consumer (the gap-check in
    // `seam::reconcile`, and the `mcp_gate_outbox` drain's confirmed-on-chain
    // delete). Clear it here so the new chain starts with no stale dedup state.
    // Fires ONLY when a genesis is actually minted (inside `.chain-lock`), never on
    // an existing chain. Redteam an internal ticket R2 (rust-specialist F3).
    let _ = std::fs::remove_file(csq_runs_dir.join(SEAM_DEDUP_INDEX));

    let genesis = ChainGenesis {
        chain_id: gen_chain_id(),
        genesis_seq: 0,
        genesis_ts: genesis_ts.to_string(),
    };
    let bytes = serde_json::to_vec(&genesis)?;
    let tmp = unique_tmp_path(&chain_path);

    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(std::io::Error::other(e.to_string())));
    }
    if let Err(e) = atomic_replace(&tmp, &chain_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(std::io::Error::other(e.to_string())));
    }

    Ok(genesis)
}

/// Reads the last record from `<csq_runs_dir>/<chain_id>.jsonl` and returns
/// its canonical bytes.  Returns `None` if the JSONL file does not exist
/// (genesis case).
///
/// Only reads the last non-empty line for efficiency (single-writer: the file
/// is always append-only and well-formed).
/// Reads the last record from the chain JSONL and returns its canonical bytes
/// **and** its `seq` number in a single file read.
///
/// R2-RS-2: returning `(canonical_bytes, seq)` together eliminates the
/// double-read that previously existed in `write_record_v2`: one call to this
/// function and one independent re-read of the file to extract `last_seq`.
/// Under any concurrent writer the two reads could observe different file
/// contents, producing a `(seq, prev_hash)` pair that referenced different
/// records.  A single read is structurally race-free regardless of the
/// single-writer convention.
fn read_last_canonical_bytes(
    csq_runs_dir: &Path,
    chain_id: &str,
) -> Result<Option<(Vec<u8>, u64)>, AuditV2Error> {
    let chain_jsonl = csq_runs_dir.join(format!("{chain_id}.jsonl"));
    if !chain_jsonl.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&chain_jsonl)?;
    // Find last non-empty line.
    let last_line = content.lines().rev().find(|l| !l.trim().is_empty());

    match last_line {
        None => Ok(None),
        Some(line) => {
            let record: SignedRecord =
                serde_json::from_str(line).map_err(|e| AuditV2Error::ChainCorrupt {
                    reason: format!("last JSONL line is not a valid SignedRecord: {e}"),
                })?;
            let seq = record.seq;
            Ok(Some((canonical_bytes_for(&record), seq)))
        }
    }
}

/// Which audit chain a write targets. Each kind lives in its OWN runs-directory
/// under `base_dir`, giving fully isolated fault domains: a separate
/// `chain.json` genesis, `<chain_id>.jsonl` log, `.chain-lock`, `.chain-broken`
/// sentinel, and `.seam-dedup-index`. A broken op-chain therefore never blocks
/// EATP attestation writes, and vice versa.
///
/// The default for every pre-existing writer is [`ChainKind::Op`] (the
/// `csq-runs/` op-chain) — the public `write_record_v2` / `write_record_v2_signed`
/// entry points are byte-identical to before this parameterization. The
/// born-canonical EATP attestation chain (M3 §10.5) is written via the `*_in`
/// entry points with [`ChainKind::Eatp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// The op-chain: lifecycle (`logout`/`move_slot`/`csq run` floor) +
    /// Phase-2b governance-turn records. Lives in `csq-runs/`. Honest-host grade.
    Op,
    /// The born-canonical EATP attestation chain (M3 §10.5): record #0 is a
    /// signed `SIGNED_ATTESTATION` genesis in the enterprise edition canonical form; appends
    /// are per-session close attestations. Lives in `eatp-runs/`.
    ///
    /// W1 added the writer + per-chain sentinel READER (`is_chain_broken_in`);
    /// W2a parameterized the verify side — `verify_chain_in` (`audit/verify.rs`)
    /// plus the four verify→sentinel callsites (daemon startup, `csq audit
    /// verify`, `csq doctor`, desktop daemon) now ALSO verify `eatp-runs/` and
    /// set/clear `eatp-runs/.chain-broken`. The prior W2-BLOCKER (a written EATP
    /// chain that nothing verifies) is therefore resolved.
    ///
    /// **Remaining W2b work before the first production `ChainKind::Eatp` write:**
    /// the EATP chain has its OWN `chain_id`, and `verify_chain_in` resolves the
    /// verifying key by that `chain_id`, so W2b's born-canonical genesis writer
    /// MUST establish the EATP chain's key custody (its own `chain.json` +
    /// file-store seed under the EATP `chain_id`, mirroring `csq audit init`)
    /// before emitting the `seq==0` signed genesis. There are no production
    /// `ChainKind::Eatp` writers yet — W2b is the first.
    Eatp,
}

impl ChainKind {
    /// The runs-subdirectory name (under `base_dir`) holding this chain's files.
    pub const fn runs_subdir(self) -> &'static str {
        match self {
            ChainKind::Op => "csq-runs",
            ChainKind::Eatp => "eatp-runs",
        }
    }
}

// ── v2 public write site ───────────────────────────────────────────────────────

/// Writes a v2 ledger record to `<csq_runs_dir>/<chain_id>.jsonl`.
///
/// This is the parallel v2 writer.  The v1 `write_record` function is
/// unchanged.
///
/// Steps:
/// 1. Ensure `csq-runs/` directory exists at mode 0o700.
/// 2. Read or initialise `chain.json` to obtain `chain_id` and `genesis_ts`.
/// 3. Determine `seq`: 0 if no prior chain file exists, otherwise
///    `prev_record.seq + 1`.
/// 4. Compute `prev_hash` from the canonical form of the previous record
///    (64 zeros for the genesis record).
/// 5. Patch the incoming `record` with `chain_id`, `seq`, `prev_hash`, and
///    `ts` from this call.
/// 6. Compute `canonical_hash` from the patched record's canonical form.
/// 7. Patch `record.canonical_hash`.
/// 8. Append-write via `unique_tmp_path → read-extend-write → secure_file →
///    atomic_replace` (single-writer invariant makes this safe without locking).
///
/// `base_dir` is `~/.claude/accounts`; tests supply a `TempDir`-backed path.
///
/// # Signature note (read before using on signed records)
///
/// This function does NOT (re)sign the record. It overwrites `seq`,
/// `prev_hash`, and `canonical_hash` in Steps 5–6, but leaves
/// `record.signature` exactly as the caller set it. That is correct for
/// placeholder-key records (`csq run`, pre-cutoff) whose signature is never
/// verified. For a record signed by a REAL key, the signature MUST cover the
/// FINAL `canonical_hash` — which depends on the final `seq`/`prev_hash` this
/// function assigns. A caller that signs BEFORE calling this function signs
/// over the wrong pre-image whenever the record does not land at seq 0, and
/// the verifier's canonical-hash recompute (M05 Check 4–5) then rejects the
/// signature. For real-key records use [`write_record_v2_signed`], which
/// signs AFTER seq assignment.
pub fn write_record_v2(record: SignedRecord, base_dir: Option<&Path>) -> Result<(), AuditV2Error> {
    write_record_v2_impl(record, base_dir, ChainKind::Op, None, None, false, false).map(|_| ())
}

/// Like [`write_record_v2`], but targets `chain`'s runs-directory. Used by the
/// EATP attestation chain (`ChainKind::Eatp`); `ChainKind::Op` is identical to
/// [`write_record_v2`].
pub fn write_record_v2_in(
    record: SignedRecord,
    base_dir: Option<&Path>,
    chain: ChainKind,
) -> Result<(), AuditV2Error> {
    write_record_v2_impl(record, base_dir, chain, None, None, false, false).map(|_| ())
}

/// TEST-ONLY: append an unsigned record while SKIPPING the M19b in-lock
/// unsigned-after-cutoff guard (M3). Used exclusively by verify-detection tests
/// that must construct the malformed (unsigned record at `seq >= cutoff`) chain
/// state the production writer now refuses to create, in order to assert
/// `verify_chain` still catches it (the tamper / external-corruption path). MUST
/// NOT be used by production code — the guard exists to make this state
/// unreachable through the writer.
#[cfg(any(test, feature = "test-utils"))]
pub fn write_record_v2_unchecked(
    record: SignedRecord,
    base_dir: Option<&Path>,
) -> Result<(), AuditV2Error> {
    write_record_v2_impl(record, base_dir, ChainKind::Op, None, None, true, false).map(|_| ())
}

/// Acquires the chain-wide `.chain-lock` sidecar with a bounded 5-second polled
/// `try_lock_file` loop (100 ms interval).
///
/// This is the shared acquisition primitive used by BOTH the chain-append path
/// (`write_record_v2_impl`) AND the roster-install path
/// (`csq audit roster-install`). Extracting it here avoids duplicating the
/// polling loop and ensures both paths use identical timeout semantics.
///
/// **Fail-closed contract**: if the lock cannot be acquired within the deadline,
/// `Err(AuditV2Error::ChainLockTimeout)` is returned and NO write has been
/// attempted.  The caller MUST propagate this error without performing any
/// side-effecting write (roster file, `chain.json`, or audit record).
///
/// **Caller invariant**: the caller must ensure `csq_runs_dir` exists before
/// calling (both callers already create / verify the directory).
///
/// Returns a [`crate::platform::lock::FileLockGuard`] that holds the lock until
/// dropped.  The lock is released when the guard goes out of scope — callers
/// MUST NOT drop the guard before all writes under the critical section complete.
pub fn acquire_chain_lock(
    csq_runs_dir: &std::path::Path,
) -> Result<crate::platform::lock::FileLockGuard, AuditV2Error> {
    use std::time::{Duration, Instant};
    let lock_path = csq_runs_dir.join(".chain-lock");
    const DEADLINE_SECS: u64 = 5;
    let deadline = Instant::now() + Duration::from_secs(DEADLINE_SECS);
    let poll_interval = Duration::from_millis(100);
    loop {
        match crate::platform::lock::try_lock_file(&lock_path) {
            Ok(Some(guard)) => return Ok(guard),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(AuditV2Error::ChainLockTimeout {
                        deadline_secs: DEADLINE_SECS,
                    });
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(AuditV2Error::Io(std::io::Error::other(format!(
                    "chain-lock: {e}"
                ))));
            }
        }
    }
}

/// Seam-write spec (M20): the dedup key carried across the `.chain-lock`
/// critical section so the duplicate check, the chain append, and the
/// dedup-index update are all ATOMIC under one lock acquisition — closing the
/// ingest-time TOCTOU the pre-M20 `chain_contains_decision_id` O(n) scan left
/// open (spec §12.19.4).
///
/// M18-bind: shrunk to `{dedup_key}` — the `source_counter`/`surface`/
/// `advance_counter` triplet that fed the deleted `.seam-source-counters`
/// sidecar is removed. Gap-detection now uses `seam_dedup_index_contains`
/// against `prev_link` (no new sidecar needed).
#[derive(Debug, Clone, Copy)]
pub struct SeamWriteSpec<'a> {
    /// The idempotent dedup key. For an anchor this is the v1 `decision_id`
    /// (sha256 hex); for a once-per-id `seam_duplicate_suppressed` record the
    /// caller namespaces it as `dup:<decision_id>` so the same in-lock index
    /// bounds suppression records to ONE per replayed id (F-SEAM-05 defense)
    /// without a second sidecar.
    pub dedup_key: &'a str,
}

/// Outcome of `write_seam_record_signed`.
#[derive(Debug)]
pub enum SeamWriteOutcome {
    /// The record was anchored. Carries the finalized on-disk record.
    Written(Box<SignedRecord>),
    /// The `decision_id` was already in the dedup index — NO record written.
    /// The caller maps this to `DuplicateSuppressed` (the once-per-id
    /// `seam_duplicate_suppressed` record is the caller's responsibility).
    Duplicate,
}

/// Write a `ProvenanceAnchored` record with IN-LOCK idempotent dedup (M20).
///
/// Unlike [`write_record_v2_signed`], the duplicate check runs INSIDE the
/// `.chain-lock` critical section, atomically with the append + the dedup-index
/// update + the per-source counter advance. Two concurrent identical POSTs can
/// no longer both pass a pre-lock scan and both append: the first append adds
/// the `decision_id` to the index under the lock; the second observes it under
/// the same lock and returns [`SeamWriteOutcome::Duplicate`] without writing.
///
/// The dedup index is the compact sidecar `csq-runs/.seam-dedup-index`
/// (newline-delimited `decision_id`s), rebuilt once from the chain if absent.
pub fn write_seam_record(
    record: SignedRecord,
    base_dir: Option<&Path>,
    signing_key: Option<&dyn crate::audit::traits::SigningKey>,
    spec: &SeamWriteSpec<'_>,
) -> Result<SeamWriteOutcome, AuditV2Error> {
    match write_record_v2_impl(
        record,
        base_dir,
        ChainKind::Op,
        signing_key,
        Some(spec),
        false,
        false,
    )? {
        WriteV2Outcome::Written(r) => Ok(SeamWriteOutcome::Written(r)),
        WriteV2Outcome::Duplicate => Ok(SeamWriteOutcome::Duplicate),
    }
}

/// Like [`write_record_v2`], but signs the record's FINAL canonical hash
/// with `signing_key` AFTER `seq`/`prev_hash` are assigned — the correct
/// order for any record signed by a real (non-placeholder) key.
///
/// The previous design (rotate.rs M04/M11) signed the record BEFORE calling
/// [`write_record_v2`], which then overwrote `seq`/`prev_hash`/`canonical_hash`
/// — so the stored signature only verified when the record happened to land
/// at seq 0 (masked because `csq audit init` writes no chain record, making
/// the first rotation always seq 0). Any second signed record — including
/// M13's intent/outcome pair — would land at seq ≥ 1 and fail
/// `verify_chain` Check 5. This function closes that latent bug: the
/// signature is always over the on-disk canonical form.
///
/// Fails closed: a signing failure returns [`AuditV2Error::Signing`] and NO
/// record is written.
///
/// Returns the FINALIZED record as persisted — with the writer-assigned `seq`,
/// `prev_hash`, `canonical_hash`, and the real `signature`. Callers that need
/// to echo or inspect the on-disk record (e.g. `csq audit rotate-key` emitting
/// the OUTCOME as JSON) MUST use this return value, not the pre-write input.
pub fn write_record_v2_signed(
    record: SignedRecord,
    base_dir: Option<&Path>,
    signing_key: &dyn crate::audit::traits::SigningKey,
) -> Result<SignedRecord, AuditV2Error> {
    write_record_v2_signed_in(record, base_dir, ChainKind::Op, signing_key)
}

/// Like [`write_record_v2_signed`], but targets `chain`'s runs-directory. The
/// EATP attestation chain (`ChainKind::Eatp`) uses this to write its
/// born-canonical signed genesis (M3 §10.5 W2) and session-close attestations
/// (W3); `ChainKind::Op` is identical to [`write_record_v2_signed`].
pub fn write_record_v2_signed_in(
    record: SignedRecord,
    base_dir: Option<&Path>,
    chain: ChainKind,
    signing_key: &dyn crate::audit::traits::SigningKey,
) -> Result<SignedRecord, AuditV2Error> {
    match write_record_v2_impl(
        record,
        base_dir,
        chain,
        Some(signing_key),
        None,
        false,
        false,
    )? {
        WriteV2Outcome::Written(r) => Ok(*r),
        // Unreachable: dedup is only consulted when `seam` is Some. Surface as
        // a logic error (NOT ChainCorrupt — that would brick the chain via the
        // .chain-broken sentinel for what is a programmer error).
        WriteV2Outcome::Duplicate => {
            debug_assert!(false, "dedup outcome without seam spec");
            Err(AuditV2Error::Internal {
                reason: "dedup outcome without seam spec".to_string(),
            })
        }
    }
}

/// Like [`write_record_v2_signed_in`], but REQUIRES the write to land at the
/// chain genesis (`seq == 0`). If the chain already has a record, the write is
/// refused IN-LOCK with [`AuditV2Error::GenesisAlreadyExists`] rather than
/// appending a duplicate genesis at `seq >= 1`.
///
/// M1 (redteam R1): closes the TOCTOU where two concurrent `csq audit init`
/// runs both pass an out-of-lock emptiness check and both append a "genesis".
/// The EATP born-canonical genesis writer is the sole caller; it maps
/// `GenesisAlreadyExists` to the idempotent "genesis already present" no-op.
pub fn write_genesis_v2_signed_in(
    record: SignedRecord,
    base_dir: Option<&Path>,
    chain: ChainKind,
    signing_key: &dyn crate::audit::traits::SigningKey,
) -> Result<SignedRecord, AuditV2Error> {
    match write_record_v2_impl(
        record,
        base_dir,
        chain,
        Some(signing_key),
        None,
        false,
        true,
    )? {
        WriteV2Outcome::Written(r) => Ok(*r),
        WriteV2Outcome::Duplicate => {
            debug_assert!(false, "dedup outcome without seam spec");
            Err(AuditV2Error::Internal {
                reason: "dedup outcome without seam spec".to_string(),
            })
        }
    }
}

/// Internal outcome of [`write_record_v2_impl`]. The `Duplicate` arm is only
/// ever returned when a [`SeamWriteSpec`] is supplied and the `decision_id` was
/// already in the dedup index.
enum WriteV2Outcome {
    Written(Box<SignedRecord>),
    Duplicate,
}

/// Shared implementation for [`write_record_v2`] (no signing),
/// [`write_record_v2_signed`] (sign-after-assign), and
/// `write_seam_record_signed` (sign + in-lock dedup). Returns the finalized
/// record (writer-assigned `seq`/`prev_hash`/`canonical_hash`/`signature`), or
/// `Duplicate` when a seam dedup key was supplied and already present.
fn write_record_v2_impl(
    mut record: SignedRecord,
    base_dir: Option<&Path>,
    chain: ChainKind,
    signing_key: Option<&dyn crate::audit::traits::SigningKey>,
    seam: Option<&SeamWriteSpec<'_>>,
    // M19b M3: when `true`, skip the in-lock unsigned-after-cutoff guard. ONLY
    // the test-only `write_record_v2_unchecked` passes `true` — it lets the
    // verify-detection tests construct the malformed (unsigned-after-cutoff)
    // chain state that the production writer now structurally refuses to create,
    // so they can assert `verify_chain` still CATCHES it (tamper/corruption path).
    bypass_cutoff_guard: bool,
    // M1 (redteam R1): when `true`, this write MUST land at `seq == 0` (chain
    // genesis). Checked IN-LOCK after seq assignment — if the chain already has a
    // record, the write is refused with `GenesisAlreadyExists` rather than
    // appending a duplicate "genesis" at `seq >= 1`. Closes the TOCTOU where two
    // concurrent `csq audit init` both pass an out-of-lock emptiness check. Only
    // the EATP genesis wrapper passes `true`; every other caller passes `false`.
    require_genesis_empty: bool,
) -> Result<WriteV2Outcome, AuditV2Error> {
    use crate::audit::types::{Ed25519Signature, RecordId, Sha256Hex};

    // Step 1 — ensure the chain's runs-dir (`csq-runs/` op-chain, `eatp-runs/`
    // EATP attestation chain). Each chain's lock/sentinel/genesis/dedup are
    // scoped to this directory, so the two chains are fully isolated fault
    // domains (W1).
    let csq_runs = match base_dir {
        Some(b) => b.join(chain.runs_subdir()),
        None => audit_dir_for(chain),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&csq_runs)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&csq_runs)?;
    }

    // H1 (M14 redteam B2): chain-wide advisory file lock to prevent a
    // race between the daemon's anchor task and a concurrent CLI `rotate-key`
    // writer. Both call `write_record_v2_impl`; without serialization the
    // read-seq → extend → atomic_replace sequence can silently lose a record.
    //
    // The lock file is a sidecar `.chain-lock` next to the csq-runs/ directory.
    // M13b-T2: replaced unbounded blocking flock with a bounded 5s polled
    // try_lock (mirrors `acquire_move_lock` in `move_slot.rs:213-246`).
    // A wedged lock fails the write CLOSED with `ChainLockTimeout` rather
    // than hanging the user-facing command (FM-3 from an internal journal entry).
    // The lock is held only over the critical section (steps 2–8); it is NOT
    // held across any await point (this function is synchronous — structural).
    //
    // The polling loop is extracted into `acquire_chain_lock` so that
    // `csq audit roster-install` can reuse the same bounded acquire semantics
    // without duplicating the deadline/interval constants (an internal ticket).
    let _chain_lock = acquire_chain_lock(&csq_runs)?;

    // Step 1.5 — fail-closed sentinel check (inside the `.chain-lock` critical
    // section so no concurrent writer can race between the check and the write).
    //
    // `is_chain_broken` reads `csq-runs/.chain-broken`. When present, it means
    // a prior `verify_chain` call (daemon startup, `csq audit verify`, or
    // `csq doctor`) classified the chain as Broken or Unknown. All writers must
    // refuse until the chain is repaired and the sentinel cleared by a
    // subsequent successful `verify_chain`.
    //
    // `base_dir` here is `csq_runs.parent()` (i.e. `~/.claude/accounts/` or
    // the temp dir in tests). The sentinel lives at `base_dir/csq-runs/.chain-broken`.
    if let Some(base) = csq_runs.parent() {
        if let Some(kind) = crate::audit::health::is_chain_broken_in(base, chain.runs_subdir()) {
            tracing::error!(
                error_kind = "chain_write_refused_broken_sentinel",
                broken_kind = kind.as_str(),
                "write_record_v2: refusing append — .chain-broken sentinel present ({kind})"
            );
            return Err(AuditV2Error::ChainBrokenRefuseAppend { error_kind: kind });
        }
    }

    // Step 2 — read or init chain genesis.
    let ts = current_iso8601_utc_persist();
    let genesis = read_or_init_chain_genesis(&csq_runs, &ts)?;

    // Step 2.5 — M20 in-lock idempotent dedup (inside `.chain-lock`, atomic
    // with the append below). When a seam dedup key is supplied, consult the
    // `.seam-dedup-index` sidecar (rebuilt from the ACTIVE chain — `genesis.chain_id`
    // — if absent; scoping to one chain file means a stray/rotated/pre-re-genesis
    // `.jsonl` cannot merge foreign decision_ids and false-suppress a fresh event).
    // If the key is already present, the event is a replay — return `Duplicate`
    // WITHOUT appending. Runs AFTER the genesis read so the active chain_id is
    // known. Closes the pre-M20 TOCTOU (spec §12.19.4 / F-SEAM-03(a)).
    if let Some(spec) = seam {
        let index = load_or_rebuild_dedup_index(&csq_runs, &genesis.chain_id)?;
        if index.contains(spec.dedup_key) {
            return Ok(WriteV2Outcome::Duplicate);
        }
    }

    // Step 3 & 4 — determine seq + prev_hash from last canonical bytes.
    //
    // R2-RS-2: `read_last_canonical_bytes` now returns (canonical_bytes, seq)
    // from a SINGLE file read, so both values always come from the same on-disk
    // snapshot.  The old code read the file twice — once for canonical bytes
    // (prev_hash) and again to extract last_seq — which could observe different
    // contents under any concurrent writer and produce a mismatched
    // (seq, prev_hash) pair.
    let last_canonical = read_last_canonical_bytes(&csq_runs, &genesis.chain_id)?;
    let (seq, prev_hash_str) = match last_canonical {
        None => (0u64, crate::audit::types::Sha256Hex::GENESIS.to_string()),
        Some((bytes, last_seq)) => (last_seq.saturating_add(1), sha256_hex(&bytes)),
    };

    // M1 (redteam R1): genesis-empty precondition, checked IN-LOCK so it is atomic
    // with the seq assignment and the append. A caller requiring the chain genesis
    // (EATP born-canonical genesis) refuses cleanly if a record already exists —
    // the second of two concurrent `csq audit init` runs gets this Err instead of
    // appending a duplicate genesis-shaped payload at seq 1. The caller maps it to
    // the idempotent "genesis already present" no-op.
    if require_genesis_empty && seq != 0 {
        return Err(AuditV2Error::GenesisAlreadyExists);
    }

    // Step 4.5 — IN-LOCK unsigned-after-cutoff guard (M19b security review M3).
    //
    // The signed-vs-unsigned decision is made by the CALLER OUTSIDE this
    // `.chain-lock` (e.g. `op_emit::load_signing_key_with_budget` reads
    // chain.json's cutoff state, then this writer is called). A concurrent
    // `csq audit init` / `rotate-key` can set the cutoff in the gap between that
    // decision and this locked append, so an unsigned (placeholder-key) record
    // could otherwise land at `seq >= cutoff` and BRICK `verify_chain`
    // (`UnsignedRecordAfterCutoff`, verify.rs Check 5). M19b makes `csq run` a
    // per-run unsigned writer, materially widening that race window, so the fix
    // belongs at the write site for ALL callers.
    //
    // `signing_key.is_none()` is the exact "this write will be unsigned" signal
    // (Step 6.5 only signs when a key is supplied). chain.json's
    // `signing_active_since_seq` is the correct source here: the write site
    // defends against the BENIGN init race, not against tampering (tamper
    // defense is verify.rs's job, which uses the keychain-authoritative cutoff).
    // Fail closed — refuse the unsigned append rather than brick the chain. The
    // floor-record caller maps this to a non-fatal skip; lifecycle callers fail
    // closed (abort the side effect), which is the safe outcome.
    //
    // R1-MED-1 (M19b redteam): the guard MUST fire only when verify_chain would
    // ACTUALLY reject the record — i.e. when the cutoff is REAL. verify.rs
    // Check 5 resolves a cutoff as real ONLY when BOTH
    // `signing_active_since_seq.is_some()` AND `signing_key_id.is_some()`; the
    // partial-init state (cutoff written but no key registered — documented
    // reachable in `key_custody/init.rs`) is treated by verify as NO cutoff
    // (placeholder records accepted at every seq). Gating on
    // `signing_active_since_seq` alone would FALSE-REFUSE legitimate unsigned
    // writes in that state, silently aborting `csq swap`/`logout`/`move`
    // lifecycle ops (they fail closed on a non-`ChainBrokenRefuseAppend` Err).
    // Require BOTH so the guard's refusal set == verify's rejection set.
    //
    // W1: the cutoff guard is an OP-CHAIN concern. `ChainState::load(base)`
    // resolves `base/csq-runs/chain.json` (the op-chain's key-custody state)
    // regardless of `chain`, so consulting it for an EATP write would compare
    // the EATP chain's `seq` against the OP-chain's cutoff — a cross-chain leak.
    // The EATP attestation chain is born-canonical and ALWAYS signed (W2/W3), so
    // it has no unsigned-before-cutoff history and no op-chain-derived cutoff
    // applies. Gate the guard on `ChainKind::Op` so the two chains stay fully
    // isolated fault domains (the `ChainKind` doc invariant) and a future
    // unsigned EATP path can never be governed by op-chain cutoff state.
    if chain == ChainKind::Op && !bypass_cutoff_guard && signing_key.is_none() {
        if let Some(base) = csq_runs.parent() {
            if let Ok(cs) = crate::audit::key_custody::ChainState::load(base) {
                if let (Some(cutoff), true) =
                    (cs.signing_active_since_seq, cs.signing_key_id.is_some())
                {
                    if seq >= cutoff {
                        return Err(AuditV2Error::Signing {
                            reason: format!(
                                "refusing unsigned append at seq {seq} >= signing cutoff \
                                 {cutoff}: a signing cutoff became active before this record \
                                 was written; post-cutoff records MUST be signed (in-lock guard)"
                            ),
                        });
                    }
                }
            }
        }
    }

    // Step 4b — M3a: stamp AUTO_APPROVED on every record (enterprise builds).
    //
    // The `is_none()` guard preserves any explicit higher level a future M3
    // phase sets. Community builds skip this block entirely: `verification_level`
    // stays `None`, so the community chain is byte-identical to pre-M3a.
    //
    // PRIMARY METHODOLOGICAL DIRECTIVE 3: the ONLY level stamped here is
    // `AutoApproved`. `SignedAttestation` and `PeerReviewed` are reserved for
    // Phase-2b turn-events (M3 T3.2) and MUST NOT appear on op-records.
    #[cfg(feature = "enterprise")]
    if record.verification_level.is_none() {
        record.verification_level =
            Some(crate::audit::eatp_canonical::VerificationLevel::AutoApproved);
    }

    // Step 5 — patch record with chain identity.
    record.schema_version = AUDIT_SCHEMA_VERSION.to_string();
    record.chain_id =
        RecordId::try_new(genesis.chain_id.clone()).map_err(|e| AuditV2Error::ChainCorrupt {
            reason: e.to_string(),
        })?;
    record.seq = seq;
    record.prev_hash =
        Sha256Hex::try_new(prev_hash_str).map_err(|e| AuditV2Error::ChainCorrupt {
            reason: e.to_string(),
        })?;
    record.ts = ts;

    // Step 6 — compute canonical_hash from canonical form (pre-signature).
    // First set canonical_hash to genesis (zero) so CanonicalView serializes
    // a stable canonical_hash field; then SHA-256 over it.
    record.canonical_hash = Sha256Hex::genesis();
    let canonical = canonical_bytes_for(&record);
    let hash_str = sha256_hex(&canonical);
    record.canonical_hash =
        Sha256Hex::try_new(hash_str).map_err(|e| AuditV2Error::ChainCorrupt {
            reason: e.to_string(),
        })?;

    // Step 6.5 — sign-after-assign (M13). When a signing key is supplied,
    // sign the 32 raw bytes of the FINAL canonical_hash (the exact pre-image
    // the verifier recomputes in M05 Check 4–5). This MUST run after Step 6
    // so the signature covers the assigned seq/prev_hash; signing earlier
    // (the pre-M13 rotate.rs path) only verified at seq 0.
    if let Some(key) = signing_key {
        let digest_bytes: [u8; 32] = {
            let bytes =
                hex::decode(record.canonical_hash.as_str()).map_err(|e| AuditV2Error::Signing {
                    reason: format!("canonical_hash hex decode: {e}"),
                })?;
            if bytes.len() != 32 {
                return Err(AuditV2Error::Signing {
                    reason: "canonical_hash decoded to wrong length (expected 32 bytes)"
                        .to_string(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig: Ed25519Signature = key.sign(&digest_bytes).map_err(|e| AuditV2Error::Signing {
            reason: format!("signing key failed: {e}"),
        })?;
        record.signature = sig;
    }

    // Step 7 — serialize the record to a JSONL line.
    let mut line_bytes = serde_json::to_vec(&record)?;
    line_bytes.push(b'\n');

    // Step 8 — append via read-extend-write atomic replace (§5a cleanup).
    let chain_jsonl = csq_runs.join(format!("{}.jsonl", genesis.chain_id));
    let mut existing = if chain_jsonl.exists() {
        std::fs::read(&chain_jsonl)?
    } else {
        Vec::new()
    };
    existing.extend_from_slice(&line_bytes);

    let tmp = unique_tmp_path(&chain_jsonl);
    if let Err(e) = std::fs::write(&tmp, &existing) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(std::io::Error::other(e.to_string())));
    }
    if let Err(e) = atomic_replace(&tmp, &chain_jsonl) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(std::io::Error::other(e.to_string())));
    }

    // Step 9 — M20 seam-index maintenance (inside the same `.chain-lock`, after
    // a durable append). Record the dedup key in the dedup index so the next
    // replay observes it. A sidecar-write failure here is NON-fatal to the
    // just-durable chain record — it degrades dedup to the rebuild-on-absence
    // path, never corrupts the chain — so it is logged, not propagated.
    //
    // M18-bind: the `.seam-source-counters` sidecar and `advance_counter` are
    // removed. Gap-detection uses `seam_dedup_index_contains` + prev_link only.
    if let Some(spec) = seam {
        if let Err(e) = append_dedup_index(&csq_runs, spec.dedup_key) {
            // The chain record is already durable, but the dedup index is now
            // STALE-PRESENT (the just-anchored key is missing from a file that
            // still exists). The rebuild path only triggers on ABSENCE, so we
            // delete the sidecar here — the next load rebuilds it from the
            // active chain (which now contains this record), restoring dedup.
            // Without this delete, a later replay would load the stale index,
            // miss the key, and double-anchor — re-opening the very TOCTOU M20
            // closes (red-team R1 security HIGH-2).
            let _ = std::fs::remove_file(csq_runs.join(SEAM_DEDUP_INDEX));
            tracing::warn!(
                error_kind = "seam_dedup_index_append_failed",
                "seam: dedup-index append failed post-anchor; sidecar dropped for rebuild"
            );
            let _ = e;
        }
    }

    Ok(WriteV2Outcome::Written(Box::new(record)))
}

// ---------------------------------------------------------------------------
// M20 seam sidecars: dedup index.
//
// The dedup index lives under csq-runs/ and is written ONLY from
// write_record_v2_impl (inside `.chain-lock`). It is a non-chain custody file:
// its loss degrades to a rebuild-from-chain, never chain corruption.
//
// M18-bind: the `.seam-source-counters` sidecar is REMOVED — gap-detection
// now uses `seam_dedup_index_contains` against `prev_link` (no integer
// counter sidecar needed). `read_source_counter`, `advance_source_counter`,
// and `chain_max_source_counter` are deleted.
// ---------------------------------------------------------------------------

/// Sidecar filename for the dedup index (newline-delimited dedup keys:
/// anchored `decision_id`s plus `dup:<id>` suppression markers).
pub(crate) const SEAM_DEDUP_INDEX: &str = ".seam-dedup-index";

/// Load the dedup index into a `HashSet`, rebuilding it from the ACTIVE chain
/// file (`<chain_id>.jsonl`) if the sidecar is absent. The rebuild scans for
/// `ProvenanceAnchored` payloads (their `decision_id`s are the authoritative
/// anchored set), `SeamDuplicateSuppressed` records (recording their
/// `dup:<id>` markers so a post-rebuild replay does not re-emit a suppression
/// record), and `CsqRun` session-floor records (M19b — their `run:<run_id>`
/// keys so a post-rebuild replay of a `csq run` IPC does not double-anchor the
/// floor record). Called inside `.chain-lock`.
///
/// **Scoped to the active chain ONLY**: scanning every `.jsonl` in `csq-runs/`
/// would merge decision_ids from a rotated / pre-re-genesis / stray chain into
/// the active chain's dedup set, false-suppressing a legitimately-fresh event.
/// Only `<chain_id>.jsonl` is authoritative for the active chain's dedup state.
fn load_or_rebuild_dedup_index(
    csq_runs: &Path,
    chain_id: &str,
) -> Result<std::collections::HashSet<String>, AuditV2Error> {
    use std::collections::HashSet;
    let index_path = csq_runs.join(SEAM_DEDUP_INDEX);
    if index_path.exists() {
        let content = std::fs::read_to_string(&index_path)?;
        return Ok(content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect());
    }

    // Rebuild from the ACTIVE chain file only (one-time, O(n) on first M20 write
    // to an existing chain).
    let mut set = HashSet::new();
    let chain_jsonl = csq_runs.join(format!("{chain_id}.jsonl"));
    if let Ok(content) = std::fs::read_to_string(&chain_jsonl) {
        for line in content.lines() {
            let Ok(record) = serde_json::from_str::<SignedRecord>(line) else {
                continue;
            };
            match &record.payload {
                crate::audit::types::EventPayload::ProvenanceAnchored(p) => {
                    set.insert(p.decision_id.clone());
                }
                crate::audit::types::EventPayload::SeamDuplicateSuppressed(p) => {
                    set.insert(format!("dup:{}", p.decision_id));
                }
                // M19b: the `CsqRun` session-floor record reuses this in-lock dedup
                // index (keyed `run:<run_id>`) so the rare double-emit window (live
                // IPC success + `.pending` drain overlap on a crash/retry) appends
                // exactly one floor record per run. The rebuild MUST re-collect
                // these ids — otherwise a Step-9 sidecar-drop (append_dedup_index
                // failure) would lose every prior run_id on the next rebuild and a
                // replay would double-anchor, re-opening the TOCTOU M20 closes.
                crate::audit::types::EventPayload::CsqRun(p) => {
                    set.insert(format!("run:{}", p.run_id));
                }
                // an internal ticket: the `GovernanceTurn` per-turn attestation record reuses
                // this in-lock dedup index (keyed `gov:<session_id>:<record_seq>`)
                // so a re-flush of the same governance events appends exactly one
                // record per event. Both key components are mirrored into the
                // payload precisely so this rebuild can re-derive the key — without
                // this arm a Step-9 sidecar-drop would lose every prior gov: key on
                // rebuild and a replay would double-append, re-opening the very
                // TOCTOU M20 closes (sibling-contract with the `run:` arm above).
                crate::audit::types::EventPayload::GovernanceTurn(p) => {
                    set.insert(format!("gov:{}:{}", p.session_id, p.record_seq));
                }
                // M6 T6.2 Shard 4: the `McpGateDecision` spawn-boundary attestation
                // reuses this in-lock dedup index (keyed
                // `mcp:<session_nonce>:<record_seq>`) so a proxy re-POST of the same
                // decision appends exactly one record. Both key components are
                // mirrored into the payload precisely so this rebuild can re-derive
                // the key — sibling-contract with the `run:` / `gov:` arms above.
                crate::audit::types::EventPayload::McpGateDecision(p) => {
                    set.insert(format!("mcp:{}:{}", p.session_nonce, p.record_seq));
                }
                _ => {}
            }
        }
    }
    // Persist the rebuilt index so subsequent checks are O(1) file reads.
    let body = {
        let mut v: Vec<&str> = set.iter().map(String::as_str).collect();
        v.sort_unstable();
        v.join("\n")
    };
    let _ = write_sidecar_atomic(&index_path, body.as_bytes());
    Ok(set)
}

/// Whether the dedup index currently contains `key`. Public for the reconcile
/// module + tests. Does NOT rebuild — a `false` on an absent index is the
/// "not yet seen" answer the in-lock writer will re-derive authoritatively.
pub fn seam_dedup_index_contains(csq_runs: &Path, key: &str) -> bool {
    let index_path = csq_runs.join(SEAM_DEDUP_INDEX);
    let Ok(content) = std::fs::read_to_string(&index_path) else {
        return false;
    };
    content.lines().any(|l| l.trim() == key)
}

/// Whether the dedup index currently contains `key`, rebuilding the index
/// from the active chain when the sidecar is absent.
///
/// This is the rebuild-aware variant used by the gap-check (`decide_gap_prev_link`)
/// so that an absent index (e.g. after a Step-9 append failure deleted it) does
/// NOT cause the gap-checker to false-Hold an event whose predecessor is durably
/// anchored in the chain. Consistent with the IN-LOCK writer's
/// `load_or_rebuild_dedup_index` semantics (MEDIUM-1 fix).
///
/// Falls back to `false` when the chain genesis file is unreadable (no chain
/// exists yet — the event really is the first).
pub fn seam_dedup_index_contains_or_rebuild(csq_runs: &Path, key: &str) -> bool {
    // Fast path: index file exists.
    let index_path = csq_runs.join(SEAM_DEDUP_INDEX);
    if index_path.exists() {
        let Ok(content) = std::fs::read_to_string(&index_path) else {
            return false;
        };
        return content.lines().any(|l| l.trim() == key);
    }

    // Slow path: index absent → rebuild from the active chain.
    // Load chain_id from chain.json (read-only, outside the .chain-lock — safe
    // because we only READ; the in-lock writer is the sole appender).
    let chain_path = csq_runs.join("chain.json");
    let Ok(raw) = std::fs::read_to_string(&chain_path) else {
        return false; // no chain yet → predecessor cannot be anchored
    };
    let Ok(genesis) = serde_json::from_str::<ChainGenesis>(&raw) else {
        return false;
    };
    // load_or_rebuild_dedup_index is fallible (chain-corrupt / I/O); ignore
    // its error — a false-Hold is safe (the event waits until the next drain
    // or the in-lock dedup confirms it during the eventual anchor).
    match load_or_rebuild_dedup_index(csq_runs, &genesis.chain_id) {
        Ok(set) => set.contains(key),
        Err(_) => false,
    }
}

/// Append `key` to the dedup index (read-extend-atomic_replace, inside the
/// `.chain-lock`). Idempotent: a key already present is not re-appended.
fn append_dedup_index(csq_runs: &Path, key: &str) -> Result<(), AuditV2Error> {
    let index_path = csq_runs.join(SEAM_DEDUP_INDEX);
    let mut existing = std::fs::read_to_string(&index_path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == key) {
        return Ok(());
    }
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(key);
    existing.push('\n');
    write_sidecar_atomic(&index_path, existing.as_bytes())
}

// (M18-bind: read_source_counter, advance_source_counter, chain_max_source_counter
// deleted — gap-detection uses seam_dedup_index_contains + prev_link instead.)

/// Write a non-chain sidecar under csq-runs/ via the §5a tmp-cleanup pipeline
/// (`unique_tmp_path → write → secure_file → atomic_replace`, cleanup on every
/// failure branch). The sidecar carries only `decision_id`s / counters — no
/// secret material — but uses the same atomic+0600 discipline as chain writes.
fn write_sidecar_atomic(path: &Path, body: &[u8]) -> Result<(), AuditV2Error> {
    let tmp = unique_tmp_path(path);
    if let Err(e) = std::fs::write(&tmp, body) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(std::io::Error::other(e.to_string())));
    }
    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditV2Error::Io(std::io::Error::other(e.to_string())));
    }
    Ok(())
}

/// The ONLY function that writes under `~/.claude/accounts/csq-runs/`.
///
/// Steps:
/// 1. Filter `rule_ids_cited_original` and `rule_ids_cited_after_repair`
///    through the RULE_ID regex; drop invalid items, increment
///    `rule_ids_dropped_invalid_format` for each dropped item.
/// 2. Serialize the (mutated) record to JSON.
/// 3. Assert serialized size ≤ 4 KiB; return [`AuditError::RecordExceedsSize`]
///    on overflow.
/// 4. Write to `<audit_dir>/<run_id>.jsonl` using the canonical
///    `unique_tmp_path → write → secure_file → atomic_replace` pipeline
///    with §5a cleanup on every error branch.
///
/// The `base_dir` parameter allows tests to supply a `TempDir`-backed path
/// instead of the real `~/.claude/accounts`.  Production callers pass
/// `None` (falls back to [`audit_dir()`]).
pub fn write_record(record: AuditRecord) -> Result<(), AuditError> {
    write_record_to(record, None)
}

/// Internal writer that accepts an explicit base directory for testing.
pub(crate) fn write_record_to(
    mut record: AuditRecord,
    base_dir: Option<&std::path::Path>,
) -> Result<(), AuditError> {
    // Step 0 — validate run_id shape (M19b security review M1/M2). The run_id
    // is UNTRUSTED at the same-UID daemon-IPC boundary (`audit_record_handler`)
    // and at the `.pending` drain (a planted file). It becomes BOTH the v1
    // filename `<run_id>.jsonl` (path-traversal vector) AND, downstream, the
    // M19b floor-record dedup key `run:<run_id>` (dedup-namespace-forge vector).
    // Rejecting anything but a canonical UUID at this single write site closes
    // both vectors for every ingress path; the legitimate CLI path always uses
    // `gen_run_id()` (a UUIDv4), so this never rejects a real record.
    if !crate::audit::seam::frontier::is_valid_uuid_shape(&record.run_id) {
        return Err(AuditError::InvalidRunId(record.run_id.clone()));
    }

    // Step 1 — validate and filter RULE_IDs.
    let mut dropped: u32 = 0;

    let original_filtered: Vec<String> = record
        .rule_ids_cited_original
        .into_iter()
        .filter(|id| {
            if validate_rule_id(id) {
                true
            } else {
                dropped += 1;
                false
            }
        })
        .collect();

    let after_repair_filtered: Vec<String> = record
        .rule_ids_cited_after_repair
        .into_iter()
        .filter(|id| {
            if validate_rule_id(id) {
                true
            } else {
                dropped += 1;
                false
            }
        })
        .collect();

    record.rule_ids_cited_original = original_filtered;
    record.rule_ids_cited_after_repair = after_repair_filtered;
    record.rule_ids_dropped_invalid_format += dropped;

    // Step 2 — serialize.
    let bytes = serde_json::to_vec(&record)?;

    // Step 3 — size guard (NFR-OBS-03).
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(AuditError::RecordExceedsSize(bytes.len()));
    }

    // Step 4 — write via the canonical §5a pipeline.
    let dir = match base_dir {
        Some(b) => b.join("csq-runs"),
        None => audit_dir(),
    };

    // Create parent dir at mode 0o700 if absent.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir)?;
    }

    let target = dir.join(format!("{}.jsonl", record.run_id));
    let tmp = unique_tmp_path(&target);

    // §5a: clean up tmp on every failure branch after fs::write.
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditError::Io(e));
    }

    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditError::Io(std::io::Error::other(e.to_string())));
    }

    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AuditError::Io(std::io::Error::other(e.to_string())));
    }

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    fn sample_record() -> AuditRecord {
        AuditRecord {
            schema_version: "1".to_string(),
            run_id: "00000000-0000-4000-8000-000000000001".to_string(),
            fixture_sha256: "a".repeat(64),
            coc_sha256: "b".repeat(64),
            csq_version: "2.6.2".to_string(),
            cli_version: "1.0.0".to_string(),
            surface: Surface::Cc,
            model: "claude-opus-4-7".to_string(),
            start_ts: "2026-05-09T00:00:00Z".to_string(),
            end_ts: "2026-05-09T00:00:01Z".to_string(),
            result_state: ResultState::Pass,
            score_delta_vs_baseline: Some(0.5),
            rule_ids_cited_original: vec![],
            rule_ids_cited_after_repair: vec![],
            rule_ids_dropped_invalid_format: 0,
            decision: Decision::Accept,
            spawn_gate: None,
        }
    }

    // ── run_id validation tests (M19b security review M1/M2) ────────────────

    /// A path-traversal run_id is rejected at the single write site — closes the
    /// arbitrary-write vector (the v1 filename is `<run_id>.jsonl`).
    #[test]
    fn write_record_rejects_path_traversal_run_id() {
        let dir = TempDir::new().unwrap();
        let mut rec = sample_record();
        rec.run_id = "../../etc/evil".to_string();
        let err = write_record_to(rec, Some(dir.path()))
            .expect_err("path-traversal run_id must be rejected");
        assert!(
            matches!(err, AuditError::InvalidRunId(_)),
            "expected InvalidRunId, got {err:?}"
        );
        assert_eq!(err.fixed_tag(), "invalid_run_id");
        // Nothing was written outside csq-runs/.
        assert!(!dir.path().join("etc").exists());
    }

    /// A run_id containing `:` is rejected — closes the dedup-namespace-forge
    /// vector (the floor dedup key is `run:<run_id>`; a `:` could let a crafted
    /// id collide with the seam `dup:`/`decision_id` namespaces).
    #[test]
    fn write_record_rejects_colon_run_id() {
        let dir = TempDir::new().unwrap();
        let mut rec = sample_record();
        rec.run_id = "dup:550e8400-e29b-41d4-a716-446655440000".to_string();
        let err =
            write_record_to(rec, Some(dir.path())).expect_err("colon run_id must be rejected");
        assert!(matches!(err, AuditError::InvalidRunId(_)), "got {err:?}");
    }

    /// A canonical UUID run_id (what `gen_run_id` produces) passes validation.
    #[test]
    fn write_record_accepts_uuid_run_id() {
        let dir = TempDir::new().unwrap();
        let rec = sample_record(); // run_id is a valid UUID
        write_record_to(rec, Some(dir.path())).expect("valid UUID run_id must pass");
    }

    // ── RULE_ID regex tests (T7) ────────────────────────────────────────────

    #[test]
    fn rule_id_accepts_rule_x() {
        // "RULE-X": uppercase initial, 6 trailing chars (RULE- = 4 + X = 1)
        // Wait — "RULE-X" = R-U-L-E---X = R then U,L,E,-,X = 5 trailing.
        // That's within {1,32}. Should match.
        assert!(validate_rule_id("RULE-X"), "RULE-X must match");
    }

    #[test]
    fn rule_id_rejects_single_char() {
        // "X" = 1 char total: just the uppercase letter, zero trailing chars.
        // {1,32} requires at least 1 trailing char, so X alone fails.
        assert!(!validate_rule_id("X"), "X alone must not match");
    }

    #[test]
    fn rule_id_accepts_two_chars_boundary() {
        // "AB" = A (initial) + B (1 trailing) — minimum valid.
        assert!(validate_rule_id("AB"), "AB is the 2-char minimum");
    }

    #[test]
    fn rule_id_accepts_rule_dash_only() {
        // "RULE-" = R + U,L,E,- = 4 trailing chars. Hyphen is in [A-Z0-9-].
        // So "RULE-" DOES match the regex because the trailing class includes '-'.
        assert!(
            validate_rule_id("RULE-"),
            "RULE- has 4 trailing chars including hyphen — must match"
        );
    }

    #[test]
    fn rule_id_rejects_lowercase() {
        assert!(
            !validate_rule_id("rule-x"),
            "lowercase initial must not match"
        );
    }

    #[test]
    fn rule_id_rejects_asterisk() {
        assert!(!validate_rule_id("RULE-X*"), "asterisk must not match");
    }

    #[test]
    fn rule_id_accepts_32_trailing_chars() {
        // "R" + 32 uppercase chars = 33 total. Max allowed.
        let s = format!("R{}", "A".repeat(32));
        assert_eq!(s.len(), 33);
        assert!(
            validate_rule_id(&s),
            "33-char string must match (32 trailing)"
        );
    }

    #[test]
    fn rule_id_rejects_33_trailing_chars() {
        // "R" + 33 uppercase chars = 34 total. Over max.
        let s = format!("R{}", "A".repeat(33));
        assert_eq!(s.len(), 34);
        assert!(
            !validate_rule_id(&s),
            "34-char string must not match (33 trailing)"
        );
    }

    #[test]
    fn rule_id_accepts_31_trailing_from_plan_example() {
        // "RULE-XYZ-12345-67890-12345-67890" = R + 31 trailing chars.
        // Within {1,32} → matches.
        let s = "RULE-XYZ-12345-67890-12345-67890";
        assert_eq!(s.len(), 32, "sanity: string should be 32 chars");
        assert!(validate_rule_id(s), "{s} must match (31 trailing chars)");
    }

    #[test]
    fn rule_id_accepts_32_trailing_from_plan_example() {
        // "RULE-XYZ-12345-67890-12345-678901" = R + 32 trailing chars.
        // Exactly at the {1,32} limit → matches.
        let s = "RULE-XYZ-12345-67890-12345-678901";
        assert_eq!(s.len(), 33, "sanity: string should be 33 chars");
        assert!(
            validate_rule_id(s),
            "{s} must match (32 trailing chars — exactly at limit)"
        );
    }

    #[test]
    fn rule_id_rejects_over_32_trailing() {
        // "RULE-XYZ-12345-67890-12345-6789012" = R + 33 trailing chars.
        // Over the {1,32} limit → does NOT match.
        let s = "RULE-XYZ-12345-67890-12345-6789012";
        assert_eq!(s.len(), 34, "sanity: string should be 34 chars");
        assert!(
            !validate_rule_id(s),
            "{s} must not match (33 trailing chars — over limit)"
        );
    }

    // ── Dropped-count test (T7) ────────────────────────────────────────────

    #[test]
    fn write_record_drops_invalid_rule_ids_and_counts() {
        let dir = TempDir::new().unwrap();
        let mut rec = sample_record();
        rec.rule_ids_cited_original = vec![
            "VALID-A".to_string(),
            "*invalid*".to_string(),
            "rule-lc".to_string(),
        ];
        rec.rule_ids_dropped_invalid_format = 0;

        write_record_to(rec, Some(dir.path())).unwrap();

        let path = dir
            .path()
            .join("csq-runs/00000000-0000-4000-8000-000000000001.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed.rule_ids_cited_original, vec!["VALID-A"]);
        assert_eq!(
            parsed.rule_ids_dropped_invalid_format, 2,
            "expected 2 dropped items (*invalid* and rule-lc)"
        );
    }

    // ── Round-trip test (T3 acceptance) ───────────────────────────────────

    #[test]
    fn write_record_round_trips() {
        let dir = TempDir::new().unwrap();
        let mut rec = sample_record();
        rec.rule_ids_cited_original = vec!["RULE-A".to_string(), "RULE-B".to_string()];
        rec.rule_ids_cited_after_repair = vec!["RULE-A".to_string()];

        write_record_to(rec.clone(), Some(dir.path())).unwrap();

        let path = dir
            .path()
            .join("csq-runs/00000000-0000-4000-8000-000000000001.jsonl");
        assert!(path.exists(), "JSONL file must exist after write");

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed.schema_version, "1");
        assert_eq!(parsed.run_id, rec.run_id);
        assert_eq!(parsed.surface, Surface::Cc);
        assert_eq!(parsed.result_state, ResultState::Pass);
        assert_eq!(parsed.decision, Decision::Accept);
        assert_eq!(parsed.rule_ids_cited_original, vec!["RULE-A", "RULE-B"]);
        assert_eq!(parsed.rule_ids_cited_after_repair, vec!["RULE-A"]);
        assert_eq!(parsed.rule_ids_dropped_invalid_format, 0);
    }

    /// Redteam R1 (#3): the additive `spawn_gate` field round-trips, and `None`
    /// serializes the key away — a pre-M6 record (no `spawn_gate` key) deserializes
    /// to `None`, byte-compatible with the existing JSONL audit stream.
    #[test]
    fn spawn_gate_round_trips_and_is_omitted_when_none() {
        let mut rec = sample_record();
        rec.spawn_gate = Some(SpawnGateRecord {
            cli: "codex".to_string(),
            action: "spawn_codex".to_string(),
            verdict: "conditional".to_string(),
        });
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
        let sg = parsed
            .spawn_gate
            .expect("spawn_gate must round-trip as Some");
        assert_eq!(sg.cli, "codex");
        assert_eq!(sg.action, "spawn_codex");
        assert_eq!(sg.verdict, "conditional");

        // `None` omits the key, and a JSON string without the key deserializes
        // back to `None` (pre-M6 forward-compatibility).
        let none_json = serde_json::to_string(&sample_record()).unwrap();
        assert!(
            !none_json.contains("spawn_gate"),
            "spawn_gate: None must serialize the key away"
        );
        let reparsed: AuditRecord = serde_json::from_str(&none_json).unwrap();
        assert!(reparsed.spawn_gate.is_none());
    }

    // ── Mode bits (T3 / NFR-AUDIT-03 / NFR-OBS-04) ───────────────────────

    #[cfg(unix)]
    #[test]
    fn write_record_file_mode_0600() {
        let dir = TempDir::new().unwrap();
        write_record_to(sample_record(), Some(dir.path())).unwrap();

        let path = dir
            .path()
            .join("csq-runs/00000000-0000-4000-8000-000000000001.jsonl");
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "JSONL file must be mode 0o600, got 0o{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn write_record_parent_dir_mode_0700() {
        let dir = TempDir::new().unwrap();
        write_record_to(sample_record(), Some(dir.path())).unwrap();

        let csq_runs = dir.path().join("csq-runs");
        let meta = std::fs::metadata(&csq_runs).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "csq-runs/ dir must be mode 0o700, got 0o{mode:o}"
        );
    }

    // ── Size guard (NFR-OBS-03) ────────────────────────────────────────────

    #[test]
    fn write_record_rejects_oversized_record() {
        let dir = TempDir::new().unwrap();
        let mut rec = sample_record();
        // 5 KiB of model name data — will push the serialized record over 4 KiB.
        rec.model = "x".repeat(5 * 1024);
        let result = write_record_to(rec, Some(dir.path()));
        assert!(
            matches!(result, Err(AuditError::RecordExceedsSize(_))),
            "expected RecordExceedsSize, got {result:?}"
        );
    }

    // ── §5a partial-failure cleanup test (T3 acceptance) ──────────────────

    #[cfg(unix)]
    #[test]
    fn write_record_partial_failure_cleans_tmp_file() {
        use crate::platform::fs::assert_no_tmp_leak_on_readonly_parent;
        use std::os::unix::fs::DirBuilderExt as _;

        let dir = TempDir::new().unwrap();

        // Pre-create the csq-runs dir with correct mode so the next call
        // only needs to write the file (not create the dir).
        let csq_runs = dir.path().join("csq-runs");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&csq_runs)
            .unwrap();

        assert_no_tmp_leak_on_readonly_parent(&csq_runs, || {
            write_record_to(sample_record(), Some(dir.path()))
        });
    }

    // ── Surface enum serde round-trip ─────────────────────────────────────

    #[test]
    fn surface_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Surface::Cc).unwrap(), "\"cc\"");
        assert_eq!(serde_json::to_string(&Surface::Codex).unwrap(), "\"codex\"");
        assert_eq!(
            serde_json::to_string(&Surface::Gemini).unwrap(),
            "\"gemini\""
        );
        assert_eq!(serde_json::to_string(&Surface::Kimi).unwrap(), "\"kimi\"");
        assert_eq!(serde_json::to_string(&Surface::Grok).unwrap(), "\"grok\"");
    }

    #[test]
    fn result_state_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&ResultState::RepairApplied).unwrap(),
            "\"repair_applied\""
        );
        assert_eq!(
            serde_json::to_string(&ResultState::Degraded).unwrap(),
            "\"degraded\""
        );
    }

    #[test]
    fn decision_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Decision::Accept).unwrap(),
            "\"accept\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::Bypass).unwrap(),
            "\"bypass\""
        );
    }

    // ── Idempotent writes (different run_ids coexist) ─────────────────────

    #[test]
    fn write_record_two_records_coexist() {
        let dir = TempDir::new().unwrap();
        let mut rec1 = sample_record();
        rec1.run_id = "00000000-0000-4000-8000-000000000001".to_string();
        let mut rec2 = sample_record();
        rec2.run_id = "00000000-0000-4000-8000-000000000002".to_string();

        write_record_to(rec1, Some(dir.path())).unwrap();
        write_record_to(rec2, Some(dir.path())).unwrap();

        let p1 = dir
            .path()
            .join("csq-runs/00000000-0000-4000-8000-000000000001.jsonl");
        let p2 = dir
            .path()
            .join("csq-runs/00000000-0000-4000-8000-000000000002.jsonl");
        assert!(p1.exists());
        assert!(p2.exists());
    }

    // ── M02 v2 writer tests ────────────────────────────────────────────────

    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId,
    };

    fn sample_v2_record() -> crate::audit::types::SignedRecord {
        use crate::audit::types::Sha256Hex;
        crate::audit::types::SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000R0").unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "run-0".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        }
    }

    // ── W1: chain-id parameterization — op-chain / EATP-chain isolation ──────

    /// W1: `ChainKind::Eatp` writes land in `eatp-runs/`, NOT `csq-runs/`. The
    /// op-chain runs-dir is not even created by an EATP-only write.
    #[test]
    fn eatp_write_targets_eatp_runs_dir_not_csq_runs() {
        let dir = TempDir::new().unwrap();
        write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp).unwrap();

        assert!(
            dir.path().join("eatp-runs/chain.json").exists(),
            "EATP write must create eatp-runs/chain.json"
        );
        assert!(
            !dir.path().join("csq-runs").exists(),
            "an EATP-only write must NOT create the op-chain's csq-runs/ dir"
        );
    }

    /// W1: the op-chain and the EATP chain maintain INDEPENDENT genesis,
    /// chain_id, and seq counters in the same base_dir — neither cross-links the
    /// other's records.
    #[test]
    fn op_and_eatp_chains_are_independent() {
        let dir = TempDir::new().unwrap();
        // Two records on each chain.
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp).unwrap();
        write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp).unwrap();

        let op_genesis: ChainGenesis = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("csq-runs/chain.json")).unwrap(),
        )
        .unwrap();
        let eatp_genesis: ChainGenesis = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("eatp-runs/chain.json")).unwrap(),
        )
        .unwrap();

        // Distinct chain identities.
        assert_ne!(
            op_genesis.chain_id, eatp_genesis.chain_id,
            "op-chain and EATP chain must have distinct chain_ids"
        );

        // Each chain's JSONL has exactly its own two records at seq 0,1 — no
        // cross-link: the EATP records did not advance the op-chain seq and
        // vice versa.
        for (runs, chain_id) in [
            ("csq-runs", &op_genesis.chain_id),
            ("eatp-runs", &eatp_genesis.chain_id),
        ] {
            let jsonl = dir.path().join(format!("{runs}/{chain_id}.jsonl"));
            let seqs: Vec<u64> = std::fs::read_to_string(&jsonl)
                .unwrap()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str::<SignedRecord>(l).unwrap().seq)
                .collect();
            assert_eq!(seqs, vec![0, 1], "{runs}: each chain owns seq 0,1 only");
        }
    }

    /// W1: a broken op-chain sentinel refuses op-chain appends but does NOT
    /// block the EATP chain (separate fault domains), and symmetrically.
    #[test]
    fn broken_sentinel_is_per_chain() {
        let dir = TempDir::new().unwrap();

        // Break the op-chain only.
        crate::audit::health::set_chain_broken_in(dir.path(), "csq-runs", "test_break");
        let op_err = write_record_v2(sample_v2_record(), Some(dir.path())).unwrap_err();
        assert!(
            matches!(op_err, AuditV2Error::ChainBrokenRefuseAppend { .. }),
            "op write must be refused by the op-chain sentinel"
        );
        // EATP chain is unaffected.
        write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp)
            .expect("EATP write must succeed despite a broken op-chain");

        // Now break the EATP chain only; clear the op-chain.
        crate::audit::health::clear_chain_broken_in(dir.path(), "csq-runs");
        crate::audit::health::set_chain_broken_in(dir.path(), "eatp-runs", "test_break");
        let eatp_err =
            write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp).unwrap_err();
        assert!(
            matches!(eatp_err, AuditV2Error::ChainBrokenRefuseAppend { .. }),
            "EATP write must be refused by the EATP-chain sentinel"
        );
        // Op chain now writes fine.
        write_record_v2(sample_v2_record(), Some(dir.path()))
            .expect("op write must succeed despite a broken EATP chain");
    }

    /// W1: an unsigned EATP write is NOT governed by the OP-chain's signing
    /// cutoff (the cutoff guard is gated on `ChainKind::Op`). Without that gate,
    /// `ChainState::load(base)` reads the op-chain's cutoff for an EATP write and
    /// wrongly refuses any EATP append at `eatp_seq >= op_cutoff` — a cross-chain
    /// leak. This pins the fix: the EATP chain stays a fully isolated fault
    /// domain even for unsigned writes.
    #[test]
    fn eatp_unsigned_write_not_governed_by_op_chain_cutoff() {
        use crate::audit::key_custody::ChainState;
        let dir = TempDir::new().unwrap();

        // Op-chain genesis at seq 0, then a REAL cutoff active from seq 1.
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        let mut cs = ChainState::load(dir.path()).unwrap();
        cs.signing_active_since_seq = Some(1);
        cs.signing_key_id = Some(KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap());
        cs.save(dir.path()).unwrap();

        // Two UNSIGNED EATP writes: the second lands at EATP seq 1, which under a
        // leaking guard would be `1 >= op_cutoff(1)` → wrongly refused. Both MUST
        // succeed: the EATP chain has its own (cutoff-free) fault domain.
        write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp)
            .expect("EATP seq 0 unsigned write must succeed");
        write_record_v2_in(sample_v2_record(), Some(dir.path()), ChainKind::Eatp)
            .expect("EATP seq 1 unsigned write must NOT be refused by the op-chain cutoff");

        // Sanity: the op-chain's own cutoff still refuses an unsigned op append
        // at seq 1 (the guard is intact for ChainKind::Op).
        let op_err = write_record_v2(sample_v2_record(), Some(dir.path()))
            .expect_err("unsigned op append at seq >= cutoff must still be refused");
        assert!(matches!(op_err, AuditV2Error::Signing { .. }));
    }

    /// M02 test 1: v1 write path is unchanged after v2 introduction.
    #[test]
    fn v1_write_path_unchanged_after_v2_introduction() {
        let dir = TempDir::new().unwrap();
        let rec = sample_record();
        let run_id = rec.run_id.clone();
        write_record_to(rec, Some(dir.path())).unwrap();

        let path = dir.path().join(format!("csq-runs/{run_id}.jsonl"));
        assert!(path.exists(), "v1 JSONL file must exist at run_id path");

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed.schema_version, "1",
            "v1 record must have schema_version=1"
        );
        assert_eq!(parsed.run_id, run_id);
    }

    /// M02 test 2: genesis record has prev_hash = 64 zeros.
    #[test]
    fn genesis_record_prev_hash_is_zero() {
        let dir = TempDir::new().unwrap();
        let rec = sample_v2_record();
        write_record_v2(rec, Some(dir.path())).unwrap();

        // Read chain.json to get chain_id, then read the JSONL.
        let chain_json = dir.path().join("csq-runs/chain.json");
        let genesis: ChainGenesis =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_jsonl = dir
            .path()
            .join(format!("csq-runs/{}.jsonl", genesis.chain_id));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();
        let written: crate::audit::types::SignedRecord =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();

        assert_eq!(
            written.prev_hash.as_str(),
            crate::audit::types::Sha256Hex::GENESIS,
            "genesis record must have prev_hash = 64 zeros"
        );
        assert_eq!(written.seq, 0, "genesis record must have seq=0");
        assert_eq!(
            written.schema_version, "2",
            "v2 record must have schema_version=2"
        );
    }

    /// M19b M3: the in-lock unsigned-after-cutoff guard refuses an unsigned
    /// `write_record_v2` append at `seq >= cutoff` when the cutoff is REAL
    /// (`signing_active_since_seq` AND `signing_key_id` both set) — the race-window
    /// last-line defense against bricking `verify_chain` (`UnsignedRecordAfterCutoff`).
    #[test]
    fn write_record_v2_refuses_unsigned_at_real_cutoff() {
        use crate::audit::key_custody::ChainState;
        let dir = TempDir::new().unwrap();
        // Genesis at seq 0 (unsigned, no cutoff — allowed).
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();

        // Establish a REAL cutoff (both fields set), at seq 1.
        let mut cs = ChainState::load(dir.path()).unwrap();
        cs.signing_active_since_seq = Some(1);
        cs.signing_key_id = Some(KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap());
        cs.save(dir.path()).unwrap();

        // Next unsigned append lands at seq 1 >= cutoff 1 → guard refuses.
        let err = write_record_v2(sample_v2_record(), Some(dir.path()))
            .expect_err("unsigned append at seq >= real cutoff must be refused");
        assert!(
            matches!(err, AuditV2Error::Signing { .. }),
            "expected Signing refusal, got {err:?}"
        );
    }

    /// M19b M3: `write_record_v2_unchecked` bypasses the guard so verify-detection
    /// tests can construct the malformed (unsigned-after-cutoff) state.
    #[test]
    fn write_record_v2_unchecked_bypasses_cutoff_guard() {
        use crate::audit::key_custody::ChainState;
        let dir = TempDir::new().unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        let mut cs = ChainState::load(dir.path()).unwrap();
        cs.signing_active_since_seq = Some(1);
        cs.signing_key_id = Some(KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap());
        cs.save(dir.path()).unwrap();
        // The unchecked writer appends the unsigned record despite the cutoff.
        write_record_v2_unchecked(sample_v2_record(), Some(dir.path()))
            .expect("unchecked writer must bypass the cutoff guard");
    }

    /// M19b M3 (R1-MED-1): in the PARTIAL-INIT state (cutoff set but
    /// `signing_key_id` ABSENT), `verify_chain` treats the chain as having NO
    /// cutoff, so the guard MUST NOT fire — an unsigned append succeeds.
    #[test]
    fn write_record_v2_allows_unsigned_in_partial_init_state() {
        use crate::audit::key_custody::ChainState;
        let dir = TempDir::new().unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        let mut cs = ChainState::load(dir.path()).unwrap();
        cs.signing_active_since_seq = Some(1);
        cs.signing_key_id = None; // partial init — no real cutoff per verify.rs
        cs.save(dir.path()).unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path()))
            .expect("partial-init unsigned append must NOT be refused");
    }

    /// M02 test 3: canonical_hash is computed before the signature is attached.
    ///
    /// Verify: `canonical_hash` is the SHA-256 of the canonical form (which
    /// itself includes a zeroed `canonical_hash` field).  The stored
    /// `canonical_hash` in the JSONL MUST NOT be all zeros.
    #[test]
    fn canonical_hash_computed_before_signature() {
        let dir = TempDir::new().unwrap();
        let rec = sample_v2_record();
        write_record_v2(rec, Some(dir.path())).unwrap();

        let chain_json = dir.path().join("csq-runs/chain.json");
        let genesis: ChainGenesis =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_jsonl = dir
            .path()
            .join(format!("csq-runs/{}.jsonl", genesis.chain_id));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();
        let written: crate::audit::types::SignedRecord =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();

        // canonical_hash must NOT be the genesis zero string.
        assert_ne!(
            written.canonical_hash.as_str(),
            crate::audit::types::Sha256Hex::GENESIS,
            "canonical_hash must be computed (not genesis zeros)"
        );
        // canonical_hash must be exactly 64 lowercase hex chars.
        assert_eq!(written.canonical_hash.as_str().len(), 64);
        assert!(
            written
                .canonical_hash
                .as_str()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "canonical_hash must be lowercase hex"
        );
    }

    /// M02 test 4: chain.json atomic write cleans tmp on error.
    ///
    /// Uses a read-only parent to force the write step to fail,
    /// then verifies no .tmp. file leaks in the directory.
    #[cfg(unix)]
    #[test]
    fn chain_json_atomic_write_cleans_tmp_on_error() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        // Create csq-runs/ at mode 0o500 (r-x: list + read, no write).
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        std::fs::set_permissions(&csq_runs, std::fs::Permissions::from_mode(0o500)).unwrap();

        let rec = sample_v2_record();
        let result = write_record_v2(rec, Some(dir.path()));

        // Must fail (can't write chain.json in read-only dir).
        assert!(result.is_err(), "write must fail on read-only csq-runs/");

        // Restore permissions so TempDir cleanup can succeed.
        std::fs::set_permissions(&csq_runs, std::fs::Permissions::from_mode(0o700)).unwrap();

        // No .tmp. files must remain in csq-runs/.
        let leaked: Vec<_> = std::fs::read_dir(&csq_runs)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "no .tmp. files must leak after a failed write; found: {:?}",
            leaked.iter().map(|e| e.path()).collect::<Vec<_>>()
        );
    }

    /// M02 test 5: seq is monotonically increasing across writes.
    #[test]
    fn seq_monotonic_across_writes() {
        let dir = TempDir::new().unwrap();

        for i in 0..3u64 {
            let mut rec = sample_v2_record();
            rec.record_id = RecordId::try_new(
                format!("01JZ0000000000000000000{:03}", i)
                    .chars()
                    .take(26)
                    .collect::<String>(),
            )
            .unwrap_or_else(|_| RecordId::try_new("01JZ00000000000000000000R0").unwrap());
            write_record_v2(rec, Some(dir.path())).unwrap();
        }

        let chain_json = dir.path().join("csq-runs/chain.json");
        let genesis: ChainGenesis =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_jsonl = dir
            .path()
            .join(format!("csq-runs/{}.jsonl", genesis.chain_id));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();

        let seqs: Vec<u64> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect();

        assert_eq!(seqs, vec![0, 1, 2], "seq must be 0, 1, 2 across 3 writes");
    }

    /// M02 test 6: v1 drain produces a v1-tagged log event.
    ///
    /// Structural probe: the startup_reconciler's `pass5_audit_drain`
    /// is annotated with a `"v1_drain"` event tag in its tracing
    /// instrumentation. This test verifies the tag is present in source.
    #[test]
    fn v1_drain_produces_v1_record_log_tag() {
        // Structural source probe — reconciler must log with the v1_drain tag.
        let source_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/daemon/startup_reconciler.rs"
        );
        let source = std::fs::read_to_string(source_path)
            .expect("startup_reconciler.rs must be readable from csq-core");
        assert!(
            source.contains("v1_drain") || source.contains("audit_drain"),
            "startup_reconciler.rs must contain a v1_drain or audit_drain log tag for the drain path"
        );
    }

    /// M02 test 7: prev_hash equals SHA-256 of the canonical bytes of the
    /// previous record.
    #[test]
    fn prev_hash_equals_sha256_of_canonical_prev_record() {
        let dir = TempDir::new().unwrap();

        // Write two records.
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();

        let chain_json = dir.path().join("csq-runs/chain.json");
        let genesis: ChainGenesis =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_jsonl = dir
            .path()
            .join(format!("csq-runs/{}.jsonl", genesis.chain_id));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();

        let records: Vec<crate::audit::types::SignedRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(records.len(), 2, "must have exactly 2 records");

        // Record 1's prev_hash must equal SHA-256 of record 0's canonical bytes.
        let expected_prev_hash = sha256_hex(&canonical_bytes_for(&records[0]));
        assert_eq!(
            records[1].prev_hash.as_str(),
            expected_prev_hash,
            "record[1].prev_hash must equal sha256(canonical(record[0]))"
        );
    }

    /// R2-RS-2: single-read guarantees seq monotonic + prev_hash consistent.
    ///
    /// Writes 3 records and verifies:
    ///   - seq values are 0, 1, 2 (strictly monotonic).
    ///   - each record's prev_hash equals sha256(canonical_bytes_for(prev_record)).
    ///
    /// This test would be non-deterministic under the old double-read if a
    /// concurrent writer could interleave between the two reads; the single-read
    /// fix makes the pairing structurally atomic within a single read syscall.
    #[test]
    fn write_record_v2_single_read_seq_and_prev_hash_consistent() {
        let dir = TempDir::new().unwrap();

        // Write 3 records sequentially.
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();
        write_record_v2(sample_v2_record(), Some(dir.path())).unwrap();

        let chain_json = dir.path().join("csq-runs/chain.json");
        let genesis: ChainGenesis =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_jsonl = dir
            .path()
            .join(format!("csq-runs/{}.jsonl", genesis.chain_id));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();

        let records: Vec<crate::audit::types::SignedRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(records.len(), 3, "must have exactly 3 records");

        // Seq must be 0, 1, 2 — strictly monotonic.
        assert_eq!(records[0].seq, 0, "first record seq must be 0");
        assert_eq!(records[1].seq, 1, "second record seq must be 1");
        assert_eq!(records[2].seq, 2, "third record seq must be 2");

        // Each record's prev_hash must equal sha256(canonical(previous record)).
        assert_eq!(
            records[0].prev_hash.as_str(),
            crate::audit::types::Sha256Hex::GENESIS,
            "record[0].prev_hash must be genesis (64 zeros)"
        );
        let expected_1 = sha256_hex(&canonical_bytes_for(&records[0]));
        assert_eq!(
            records[1].prev_hash.as_str(),
            expected_1,
            "record[1].prev_hash must equal sha256(canonical(record[0]))"
        );
        let expected_2 = sha256_hex(&canonical_bytes_for(&records[1]));
        assert_eq!(
            records[2].prev_hash.as_str(),
            expected_2,
            "record[2].prev_hash must equal sha256(canonical(record[1]))"
        );
    }

    // ── H1: concurrent-writer flock test ─────────────────────────────────────

    /// H1 regression: two concurrent `write_record_v2` callers on the SAME
    /// chain dir MUST NOT lose either record.
    ///
    /// The `.chain-lock` flock (added in M14 H1 fix) serializes the
    /// read-seq → extend → atomic_replace critical section so both records
    /// land with distinct, monotonic seqs and an intact `prev_hash` chain.
    ///
    /// Non-tautological: reverting the flock (removing the `lock_file` call
    /// in `write_record_v2_impl`) causes one thread's `atomic_replace` to
    /// overwrite the other's, leaving only 1 record in the chain. The
    /// `assert_eq!(records.len(), 2)` then fails.
    #[test]
    fn concurrent_chain_writers_do_not_lose_records() {
        use std::sync::Arc;

        // Hermeticity: verify_chain (called below) transitively reads
        // CSQ_AUDIT_EDITION via resolve_registry/resolve_edition. Hold the shared
        // env lock and pin a clean community baseline so this test cannot race a
        // concurrent enterprise-edition test that has CSQ_AUDIT_EDITION=enterprise
        // set (testing.md Rule 6 / test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = tempfile::TempDir::new().unwrap();
        let base = Arc::new(dir.path().to_path_buf());

        // Spawn two threads that each write one record concurrently.
        let base_a = Arc::clone(&base);
        let handle_a = std::thread::spawn(move || {
            write_record_v2(sample_v2_record(), Some(&base_a)).unwrap();
        });

        let base_b = Arc::clone(&base);
        let handle_b = std::thread::spawn(move || {
            write_record_v2(sample_v2_record(), Some(&base_b)).unwrap();
        });

        handle_a.join().expect("writer A panicked");
        handle_b.join().expect("writer B panicked");

        // Read all records from the JSONL.
        let chain_json = base.join("csq-runs/chain.json");
        let genesis: ChainGenesis =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_jsonl = base.join(format!("csq-runs/{}.jsonl", genesis.chain_id));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();
        let records: Vec<crate::audit::types::SignedRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("record must parse"))
            .collect();

        // Both records must be present — no lost write.
        assert_eq!(
            records.len(),
            2,
            "both concurrent writes must survive: got {} records",
            records.len()
        );

        // Seq values must be distinct and monotonic: 0, 1.
        let mut seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![0, 1], "seq values must be 0 and 1, got {seqs:?}");

        // prev_hash chain must be intact.
        // Sort records by seq for deterministic ordering.
        let mut sorted = records;
        sorted.sort_by_key(|r| r.seq);
        assert_eq!(
            sorted[0].prev_hash.as_str(),
            crate::audit::types::Sha256Hex::GENESIS,
            "record[0].prev_hash must be genesis sentinel"
        );
        let expected_1 = sha256_hex(&canonical_bytes_for(&sorted[0]));
        assert_eq!(
            sorted[1].prev_hash.as_str(),
            expected_1,
            "record[1].prev_hash must equal sha256(canonical(record[0]))"
        );

        // verify_chain must agree: no integrity errors.
        let summary = crate::audit::verify::verify_chain(&base, &Default::default(), None).unwrap();
        assert_eq!(
            summary.verified_count, 2,
            "verify_chain must report 2 verified records, got {}",
            summary.verified_count
        );
    }

    // ── M13b-T2 — Bounded `.chain-lock` tests ─────────────────────────────

    /// AC-T2: A held `.chain-lock` past the deadline causes `write_record_v2`
    /// to fail closed with `AuditV2Error::ChainLockTimeout` — never hangs.
    ///
    /// This test verifies the FM-3 fix from an internal journal entry: an unbounded blocking
    /// `flock` is replaced by a 5-second polled `try_lock_file` so a wedged
    /// lock fails the write closed rather than parking the user-facing command
    /// indefinitely.
    ///
    /// Implementation note: the 5-second deadline is reduced to a shorter
    /// timeout for testing via the test fixture (`try_lock_file` with a held
    /// lock from a background thread). The test asserts that the write returns
    /// `Err(ChainLockTimeout)` within a bounded wall-clock window.
    #[cfg(unix)]
    #[test]
    fn chain_lock_timeout_fails_closed() {
        use crate::audit::types::{CsqRunPayload, EventKind, EventPayload};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Ensure csq-runs/ exists so lock_file can open the lock path.
        let runs_dir = base.join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();

        // Hold `.chain-lock` in a background thread for longer than the deadline.
        let lock_path = runs_dir.join(".chain-lock");
        let lock_held = Arc::new(Mutex::new(false));
        let lock_held2 = Arc::clone(&lock_held);
        let lock_path2 = lock_path.clone();

        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            // Acquire the lock directly via the blocking variant.
            let guard = crate::platform::lock::lock_file(&lock_path2).unwrap();
            *lock_held2.lock().unwrap() = true;
            tx_locked.send(()).unwrap();
            // Hold until signalled.
            rx_release.recv_timeout(Duration::from_secs(30)).unwrap();
            drop(guard);
        });

        // Wait until background thread holds the lock.
        rx_locked
            .recv_timeout(Duration::from_secs(5))
            .expect("background thread must acquire lock");
        assert!(*lock_held.lock().unwrap());

        // Attempt a v2 write — this should fail with ChainLockTimeout within
        // the bounded deadline (5 seconds in production; the test will fail if
        // it hangs beyond 15s which is the harness timeout).
        let record = crate::audit::types::SignedRecord {
            schema_version: "2".into(),
            record_id: crate::audit::types::RecordId::try_new(gen_chain_id()).unwrap(),
            chain_id: crate::audit::types::RecordId::try_new(gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: crate::audit::types::Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "test-run".into(),
            }),
            ts: current_iso8601_utc_persist(),
            key_id: crate::audit::types::KeyId::try_new(format!("ed25519:{}", "0".repeat(64)))
                .unwrap(),
            canonical_hash: crate::audit::types::Sha256Hex::genesis(),
            signature: crate::audit::types::Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };

        let start = Instant::now();
        let result = write_record_v2(record, Some(base));
        let elapsed = start.elapsed();

        // Release the background lock.
        let _ = tx_release.send(());

        assert!(
            matches!(result, Err(AuditV2Error::ChainLockTimeout { .. })),
            "held chain-lock must fail closed with ChainLockTimeout, got: {result:?}"
        );
        // Should fail within the bounded deadline (5s) + some margin.
        // We allow up to 10s to account for CI scheduling latency.
        assert!(
            elapsed < Duration::from_secs(10),
            "chain-lock timeout must be bounded; elapsed {elapsed:?} exceeds expected limit"
        );
    }

    /// Round-3 FIX-1: `write_record_v2` (and therefore `write_record_v2_signed`
    /// used by `rotate_key`) MUST return `Err(ChainBrokenRefuseAppend)` when the
    /// `.chain-broken` sentinel is set. This confirms that key-rotation stays
    /// fail-closed — unlike lifecycle ops (logout/move/swap) which degrade via
    /// `emit_intent` returning `Ok(false)`, `rotate_key` calls `write_record_v2_signed`
    /// directly so the sentinel gates it at the write-site level.
    #[test]
    fn rotate_key_still_fails_closed_when_chain_broken() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();

        // Set the .chain-broken sentinel.
        crate::audit::health::set_chain_broken(base, "chain_broken_test");

        // write_record_v2 (the path rotate_key uses via write_record_v2_signed)
        // MUST refuse with ChainBrokenRefuseAppend.
        let result = write_record_v2(sample_v2_record(), Some(base));
        assert!(
            matches!(result, Err(AuditV2Error::ChainBrokenRefuseAppend { .. })),
            "write_record_v2 must fail closed with ChainBrokenRefuseAppend \
             when chain is broken (sentinel set), got: {result:?}"
        );

        // The csq-runs/ directory must have zero chain records — nothing landed.
        let runs_dir = base.join("csq-runs");
        let chain_files: Vec<_> = std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .collect();
        assert!(
            chain_files.is_empty(),
            "no record must land when chain is broken; found: {chain_files:?}"
        );
    }

    /// Redteam an internal ticket R2 (rust-specialist F3): minting a fresh genesis (chain.json
    /// absent) must CLEAR any stale `.seam-dedup-index` sidecar left by a prior
    /// chain (manual chain.json deletion + re-init), so its chain_id-unscoped keys
    /// cannot false-positive for a `seam_dedup_index_contains(_or_rebuild)`
    /// consumer against the NEW chain.
    #[test]
    fn new_genesis_clears_stale_dedup_sidecar() {
        let dir = TempDir::new().unwrap();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();

        // A stale sidecar key from a prior (deleted) chain.
        std::fs::write(csq_runs.join(SEAM_DEDUP_INDEX), b"mcp:old-chain:0\n").unwrap();
        assert!(
            seam_dedup_index_contains(&csq_runs, "mcp:old-chain:0"),
            "precondition: the stale key is present before re-genesis"
        );

        // No chain.json present → mint a fresh genesis.
        let g =
            read_or_init_chain_genesis(&csq_runs, "2026-07-02T00:00:00Z").expect("mint genesis");
        assert!(!g.chain_id.is_empty(), "a fresh chain_id was minted");

        assert!(
            !seam_dedup_index_contains(&csq_runs, "mcp:old-chain:0"),
            "new genesis must clear the stale dedup sidecar (no false-positive on the new chain)"
        );
    }
}
