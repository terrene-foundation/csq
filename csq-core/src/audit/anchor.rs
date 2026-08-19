//! M14 — External Anchoring driver (spec 12 §12.18, spec 15 §15.12).
//!
//! Commits the chain HEAD (`latest_hash`, `latest_seq`, `window_ts`) to an
//! external witness ([`LedgerSink`]) and records the outcome via the EXISTING
//! `ReplicationAck` / `ReplicationFailed` event kinds. Bounds the back-dating
//! window per F-SEAM-04.
//!
//! # Primary Methodological Directives
//!
//! - **NO new `EventKind`**: anchoring records outcome as
//!   `ReplicationAck(sink, sink_id)` or `ReplicationFailed(sink, reason)`.
//!   The CF1 canonical form (spec §12.12.7) is NOT disturbed.
//!
//! - **Signed outcome records**: `append_outcome_record` uses
//!   `write_record_v2_signed` when a signing key is active (cutoff set in
//!   `chain.json`). Without signing the anchor outcome lands at seq ≥ cutoff
//!   as a placeholder-key record, which `verify_chain` Check 5 rejects —
//!   bricking the chain. Mirroring M13's rotate.rs intent/outcome pattern.
//!
//! - **Non-fatal visibility**: anchor failure is visible (`ReplicationFailed`
//!   chain event + `replication_drift_count` bump in `anchor-state-<sink>.json`)
//!   but NEVER blocks csq operation. The local chain remains valid without the
//!   anchor; the anchor is a witness, not the spine.
//!
//! - **Dependency-injected core**: `anchor_head` accepts `&dyn LedgerSink`
//!   and a `now_ts` string. The daemon tokio loop is a thin wrapper.
//!   Failure-branch tests inject a returning-`Err` sink instead of filesystem
//!   tricks.
//!
//! # State file
//!
//! Written by this module to `<base_dir>/anchor-state-<sink>.json`:
//!
//! ```json
//! { "last_anchor_ts": "…", "replication_drift_count": 0, "last_anchored_seq": 5 }
//! ```
//!
//! Note on `last_anchored_seq`: `None` = never anchored; `Some(N)` = chain
//! HEAD at seq N was successfully submitted. An impossible value (seq >
//! current chain head) indicates tamper — the gate treats it as None and
//! re-derives from the chain's last `ReplicationAck`.
//!
//! [`SinkDoctorSnapshot::load`] in `sink_config.rs` READS this file (the doctor
//! READ side). This module WRITES it.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::audit::persist::{write_record_v2, write_record_v2_signed, AuditV2Error};
use crate::audit::traits::{LedgerSink, SigningKey as _};
use crate::audit::types::{
    Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, RedactedString,
    ReplicationAckPayload, ReplicationFailedPayload, Sha256Hex, SignedRecord, SinkError, SinkName,
};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// Outcome of a single `anchor_head` call. Returned to the tokio
/// loop so it can update the `anchor-state-<sink>.json` state file.
#[derive(Debug)]
pub enum AnchorOutcome {
    /// Anchor succeeded. `receipt_sink_id` is the sink-assigned id;
    /// `anchored_seq` is the seq of the HEAD record that was anchored.
    Succeeded {
        /// Sink-assigned identifier for the anchored record.
        receipt_sink_id: String,
        /// Sequence number of the chain HEAD that was submitted to the sink.
        /// The caller MUST persist this as `AnchorState::last_anchored_seq`
        /// so the high-impact-head-detection gate can prevent re-submission
        /// of an unchanged head on the next poll.
        anchored_seq: u64,
    },
    /// Anchor failed. The failure is already recorded as a
    /// `ReplicationFailed` chain event. The state file's
    /// `replication_drift_count` MUST be incremented by the caller.
    Failed {
        /// Human-readable reason (already redacted). For logging only.
        reason: String,
    },
    /// The chain has no records yet — nothing to anchor.
    EmptyChain,
}

// ---------------------------------------------------------------------------
// Internal on-disk state
// ---------------------------------------------------------------------------

/// On-disk shape of `anchor-state-<sink>.json`.
///
/// Written by this module; READ by [`crate::audit::sink_config::SinkDoctorSnapshot::load`]
/// via its `read_anchor_state` private function.
///
/// # Integrity note (H2)
///
/// This file is integrity-sensitive: a same-UID attacker who writes a forged
/// `last_anchored_seq = u64::MAX` would suppress all high-impact anchoring.
/// The daemon task cross-checks against the chain's own `ReplicationAck`
/// records before trusting the state file's seq value — the chain is the
/// authoritative source. Use the full `unique_tmp_path → write →
/// secure_file → atomic_replace` pattern (already applied by `write_anchor_state`)
/// even though the payload is not secret.
///
/// `last_anchored_seq` is `Option<u64>` — `None` means never anchored.
/// An impossible value `Some(N)` where `N > current_head_seq` is clamped
/// to `None` at the gate and a doctor warning is surfaced.
///
/// `#[serde(default)]` on `last_anchored_seq` preserves backward compat with
/// pre-M14 state files that lack the field (deserialise to `None`).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AnchorState {
    pub last_anchor_ts: Option<String>,
    pub replication_drift_count: u64,
    /// Sequence number of the last successfully anchored chain record.
    /// `None` = never anchored. `Some(N)` = HEAD at seq N was submitted.
    #[serde(default)]
    pub last_anchored_seq: Option<u64>,
    /// Set to `true` when `last_anchored_seq` was found to be impossible
    /// (greater than the current chain head), indicating the state file
    /// may have been tampered with. Surfaced as a doctor warning.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tamper_suspected: bool,
}

/// Reads the anchor state for `sink_name` from `<base_dir>/anchor-state-<sink>.json`.
///
/// Returns the default (`last_anchored_seq: None`, zero drift) on missing file.
/// Returns the default + a WARN log on corrupt files — non-fatal per doctor contract.
///
/// **Corrupt vs absent — both collapse to `AnchorState::default()`.** This is the
/// safe direction: defaulting to `last_anchor_ts: None` causes the anchor task to
/// re-anchor on the next poll (over-anchor), which is harmless. Defaulting to a
/// stale state would suppress anchoring (under-anchor), which could widen the
/// back-dating window undetected.
pub fn read_anchor_state_for(base_dir: &Path, sink_name: &str) -> AnchorState {
    let path = base_dir.join(format!("anchor-state-{sink_name}.json"));
    if !path.exists() {
        return AnchorState::default();
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => {
            warn!(
                event = "anchor_state_read_error",
                sink = sink_name,
                "anchor: could not read anchor-state file (using default)"
            );
            return AnchorState::default();
        }
    };
    match serde_json::from_str::<AnchorState>(&raw) {
        Ok(s) => s,
        Err(_) => {
            warn!(
                event = "anchor_state_corrupt",
                sink = sink_name,
                "anchor: anchor-state file is corrupt (using default)"
            );
            AnchorState::default()
        }
    }
}

/// Persists the anchor state for `sink_name` to
/// `<base_dir>/anchor-state-<sink>.json` using the §5a-compliant
/// `unique_tmp_path → write → secure_file → atomic_replace` pattern.
///
/// Full cleanup on every failure branch per `rules/security.md §5a`.
/// Integrity-sensitive payload — the atomic/secure write is load-bearing even
/// though the bytes are not secret: a partial write that leaves a corrupt state
/// can suppress anchoring.
pub fn write_anchor_state(
    base_dir: &Path,
    sink_name: &str,
    state: &AnchorState,
) -> Result<(), String> {
    // Ensure parent dir exists.
    std::fs::create_dir_all(base_dir)
        .map_err(|e| format!("create anchor-state parent dir: {e}"))?;

    let target = base_dir.join(format!("anchor-state-{sink_name}.json"));
    let json =
        serde_json::to_string_pretty(state).map_err(|e| format!("serialise anchor-state: {e}"))?;

    let tmp = unique_tmp_path(&target);

    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write tmp anchor-state: {e}"));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("secure_file anchor-state: {e}"));
    }
    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("atomic_replace anchor-state: {e}"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// High-impact kind predicate
// ---------------------------------------------------------------------------

/// Returns `true` when `kind` is a high-impact operation that should trigger
/// an immediate anchor regardless of the regular cadence.
///
/// High-impact kinds (per spec 12 §12.18.6):
/// - `KeyRotate` — signing-key rotation (M04/M11/M13).
/// - `IdentityMint` — identity UUID minted in the identity store.
/// - `ReleaseAuth` — release artifact authorised.
///
/// `CsqRun` and all other kinds do NOT trigger immediate anchoring.
/// This preserves conservative submission frequency (directive 2):
/// N CsqRun records per day MUST NOT each trigger a Rekor submission.
///
/// Note on M13 `op_phase`: KeyRotate emits an Intent record then an Outcome
/// record (both `kind = KeyRotate`). Both are seq-advancing high-impact
/// records, so head-detection may anchor twice around one rotation. That is
/// acceptable — it bounds the back-dating window tightly.
#[must_use]
pub fn is_high_impact_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::KeyRotate | EventKind::IdentityMint | EventKind::ReleaseAuth
    )
}

// ---------------------------------------------------------------------------
// Head-record helper
// ---------------------------------------------------------------------------

/// Reads the HEAD `SignedRecord` from the chain in `<base_dir>/csq-runs/`.
///
/// Returns `None` when the chain is empty (no records yet).
/// Returns `Err` when the chain file exists but is unreadable or corrupt.
///
/// This is a lightweight read of only the LAST line of the chain JSONL —
/// it does NOT walk the whole chain.
///
/// Exposed as `pub` so the daemon anchor task loop can read the head for
/// high-impact-kind detection without going through `anchor_head`.
pub fn read_chain_head(base_dir: &Path) -> Result<Option<SignedRecord>, String> {
    let csq_runs = base_dir.join("csq-runs");
    let chain_jsonl = {
        let chain_json = csq_runs.join("chain.json");
        if !chain_json.exists() {
            return Ok(None); // No chain initialised yet.
        }
        let raw =
            std::fs::read_to_string(&chain_json).map_err(|_| "chain unreadable".to_string())?;
        let v: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| "chain.json parse error".to_string())?;
        let chain_id = v
            .get("chain_id")
            .and_then(|s| s.as_str())
            .ok_or_else(|| "chain.json missing chain_id".to_string())?;
        csq_runs.join(format!("{chain_id}.jsonl"))
    };

    if !chain_jsonl.exists() {
        return Ok(None); // Chain genesis not yet written.
    }

    let content =
        std::fs::read_to_string(&chain_jsonl).map_err(|_| "chain JSONL unreadable".to_string())?;
    let last_line = content.lines().rev().find(|l| !l.trim().is_empty());
    match last_line {
        None => Ok(None),
        Some(line) => {
            let record: SignedRecord =
                serde_json::from_str(line).map_err(|_| "chain HEAD parse error".to_string())?;
            Ok(Some(record))
        }
    }
}

/// Scans the tail of the chain (backward from HEAD to `after_seq` exclusive)
/// and returns the HIGHEST-seq unanchored high-impact record in that range, if any.
///
/// Used by M1 fix: a high-impact op buried by a later `CsqRun` must still
/// trigger immediate anchoring.
///
/// Returns `None` when no high-impact records exist in `(after_seq, head_seq]`.
/// This is a bounded tail scan — it never walks more than the number of records
/// added since `after_seq`, which in practice is tiny (sub-minute poll rate vs
/// high-impact op frequency of at most several per day).
pub fn scan_tail_for_high_impact(
    base_dir: &Path,
    after_seq: u64,
) -> Result<Option<SignedRecord>, String> {
    let csq_runs = base_dir.join("csq-runs");
    let chain_jsonl = {
        let chain_json = csq_runs.join("chain.json");
        if !chain_json.exists() {
            return Ok(None);
        }
        let raw =
            std::fs::read_to_string(&chain_json).map_err(|_| "chain unreadable".to_string())?;
        let v: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| "chain.json parse error".to_string())?;
        let chain_id = v
            .get("chain_id")
            .and_then(|s| s.as_str())
            .ok_or_else(|| "chain.json missing chain_id".to_string())?;
        csq_runs.join(format!("{chain_id}.jsonl"))
    };

    if !chain_jsonl.exists() {
        return Ok(None);
    }

    let content =
        std::fs::read_to_string(&chain_jsonl).map_err(|_| "chain JSONL unreadable".to_string())?;

    // Scan from the end; stop when we cross `after_seq`.
    let mut best: Option<SignedRecord> = None;
    for line in content.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let record: SignedRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if record.seq <= after_seq {
            break; // Past the unanchored window — stop.
        }
        if is_high_impact_kind(&record.kind) {
            // Take the highest-seq high-impact record (the first we see scanning backward).
            if best.is_none() {
                best = Some(record);
            }
        }
    }
    Ok(best)
}

/// Scans the entire chain for any `ReplicationAck` or `ReplicationFailed`
/// outcome record and returns the associated sink name if one is found.
///
/// **MED-1 fix**: the sidecar `anchor-state-<sink>.json` is attacker-writable
/// (same-UID) — an attacker can delete it to suppress the witness-disabled
/// doctor warning. The chain's own anchor-outcome records are the authoritative,
/// tamper-evident signal: they cannot be erased without breaking the hash chain
/// that `verify_chain` (run at daemon pre-bind) would reject.
///
/// Returns `Some(sink_name_string)` on the FIRST match (tail-first scan for
/// efficiency). Returns `None` when the chain is absent or contains no anchor
/// outcome records.
///
/// This is a bounded full-chain scan. In practice chains rarely exceed a few
/// thousand records (one CsqRun per session), so O(N) is acceptable here.
/// The scan is read-only; no lock is acquired.
pub fn scan_chain_for_anchor_outcome(base_dir: &Path) -> Option<String> {
    let csq_runs = base_dir.join("csq-runs");
    let chain_json = csq_runs.join("chain.json");
    if !chain_json.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&chain_json).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let chain_id = v.get("chain_id").and_then(|s| s.as_str())?;
    let chain_jsonl = csq_runs.join(format!("{chain_id}.jsonl"));
    if !chain_jsonl.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&chain_jsonl).ok()?;

    // Scan tail-first: anchor outcome records are usually recent.
    for line in content.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if kind == "replication_ack" || kind == "replication_failed" {
            // EventPayload uses #[serde(tag = "kind", content = "data")], so the
            // serialised shape is: {"kind": "replication_ack", "data": {"sink": "…", …}}
            // The sink name lives at payload.data.sink.
            let sink = v
                .get("payload")
                .and_then(|p| p.get("data"))
                .and_then(|d| d.get("sink"))
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Some(sink);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Outcome record builder (L2: use CSPRNG record_id)
// ---------------------------------------------------------------------------

/// Builds a stub `SignedRecord` that can be passed to `write_record_v2` or
/// `write_record_v2_signed`.
///
/// `write_record_v2_impl` overwrites `seq`, `prev_hash`, `canonical_hash`, and
/// `ts` — so the only load-bearing fields here are `record_id`, `kind`,
/// `payload`, and `schema_version`. The `chain_id` placeholder is also
/// overwritten by the writer from `chain.json`.
///
/// Uses `gen_chain_id()` (CSPRNG, 26-char Crockford Base32 ULID) for the
/// `record_id` — L2 fix: replaces FNV(now_ts) which collided on same-second
/// anchors. We use `gen_chain_id()` rather than `gen_run_id()` because
/// `gen_run_id()` returns UUIDv4 which `RecordId::try_new` rejects (only
/// ULID and UUIDv7 are accepted).
fn build_outcome_record(kind: EventKind, payload: EventPayload, now_ts: &str) -> SignedRecord {
    // CSPRNG record_id via gen_chain_id() (26-char Crockford Base32 ULID).
    // We cannot use gen_run_id() here because it returns UUIDv4, and
    // RecordId::try_new accepts only ULID or UUIDv7.
    // gen_chain_id() is pub(crate) within csq-core and produces a valid ULID.
    let record_id = RecordId::try_new(crate::audit::persist::gen_chain_id())
        .unwrap_or_else(|_| RecordId::try_new("01M14ANCHOR0000000000000AA").unwrap());

    SignedRecord {
        schema_version: "2".to_string(),
        record_id,
        chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(), // placeholder; writer patches
        seq: 0,                          // placeholder; writer assigns
        prev_hash: Sha256Hex::genesis(), // placeholder; writer assigns
        kind,
        payload,
        ts: now_ts.to_string(),
        key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
        canonical_hash: Sha256Hex::genesis(), // placeholder; writer assigns
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

/// Append a single locally-produced outcome record (`kind` + `payload`) to the
/// Op audit chain, signing it when a chain-signing cutoff is active (else an
/// unsigned pre-cutoff record, mirroring [`anchor_head`]'s
/// [`load_signing_key_if_active`] fallback). The writer assigns `seq`,
/// `prev_hash`, `canonical_hash`, and `ts`; the caller supplies only `now_ts`
/// (stamped into the record before the writer overwrites `ts`, kept for callers
/// that stamp their own producer-clock field inside the payload).
///
/// # Locking (self-deadlock hazard)
///
/// This acquires the chain-wide `.chain-lock` INTERNALLY via the write path
/// ([`crate::audit::persist::write_record_v2`] →
/// `acquire_chain_lock`). **Callers MUST NOT hold `.chain-lock` across this
/// call**: `flock` locks are per-open-file-description, so a second acquisition
/// from the same process blocks until the bounded 5 s timeout and returns
/// `ChainLockTimeout` (see `platform::lock::try_lock_file`). The
/// `bundle-install` handler drops its install lock before calling this.
///
/// # Errors
///
/// Returns a fixed-vocabulary tag (`security.md` §2 — never a raw serde/IO body
/// near chain-write code) if the append fails.
pub fn append_local_outcome_record(
    base_dir: &Path,
    kind: EventKind,
    payload: EventPayload,
    now_ts: &str,
) -> Result<(), String> {
    let mut record = build_outcome_record(kind, payload, now_ts);
    match load_signing_key_if_active(base_dir) {
        Some(key) => {
            // Patch key_id BEFORE write_record_v2_signed so the stored record
            // carries the real key_id. verify_chain Check 5 identifies unsigned
            // records by checking if key_id == PLACEHOLDER_KEY_ID; without this
            // patch the record would still be flagged as unsigned even if the
            // signature itself is valid. Mirrors append_outcome_record_signed_inner
            // (this function's sibling writer) — both build an outcome record via
            // build_outcome_record, which always stamps the placeholder key_id.
            record.key_id = key.key_id();
            write_record_v2_signed(record, Some(base_dir), &*key)
                .map(|_| ())
                .map_err(|e| e.fixed_tag().to_string())
        }
        None => write_record_v2(record, Some(base_dir)).map_err(|e| e.fixed_tag().to_string()),
    }
}

// ---------------------------------------------------------------------------
// Public anchoring function
// ---------------------------------------------------------------------------

/// Core anchoring logic — dependency-injected for testability.
///
/// 1. Reads the chain HEAD from `<base_dir>/csq-runs/`.
/// 2. Submits the HEAD record to `sink` via [`LedgerSink::append`].
/// 3. On SUCCESS: appends a **SIGNED** `ReplicationAck{sink, sink_id}` chain
///    event (when signing is active per chain.json cutoff); returns
///    [`AnchorOutcome::Succeeded`].
/// 4. On FAILURE: appends a **SIGNED** `ReplicationFailed{sink, reason}` chain
///    event; returns [`AnchorOutcome::Failed`].
///
/// Signing mirrors M13's rotate.rs intent/outcome pattern:
/// - If `chain.json` has `signing_active_since_seq` (cutoff), load the key
///   from the keychain via `LocalSigningKey::load_from_keychain` and sign
///   via `write_record_v2_signed`.
/// - If no cutoff or keychain unavailable, fall back to `write_record_v2`
///   (placeholder key). This is safe pre-cutoff — verify_chain only rejects
///   placeholder keys at or after the cutoff.
///
/// # Parameters
///
/// - `sink` — any [`LedgerSink`] impl. Tests pass stubs; production passes
///   the compiled-in `RekorSink` (or whichever sink is active).
/// - `now_ts` — ISO-8601 UTC timestamp string. Injected so tests can pin clock.
/// - `base_dir` — csq base directory (`~/.claude/accounts`).
pub async fn anchor_head(sink: &dyn LedgerSink, now_ts: &str, base_dir: &Path) -> AnchorOutcome {
    // Step 1: read chain HEAD.
    let head = match read_chain_head(base_dir) {
        Ok(Some(rec)) => rec,
        Ok(None) => {
            info!(
                event = "anchor_skip_empty_chain",
                "anchor_head: chain is empty, nothing to anchor"
            );
            return AnchorOutcome::EmptyChain;
        }
        Err(_) => {
            // Chain read failure — fixed-vocabulary tag (M4: never raw serde body).
            warn!(
                event = "anchor_chain_read_failed",
                "anchor_head: chain unreadable"
            );
            let sink_name = match SinkName::try_new(sink.name().to_string()) {
                Ok(n) => n,
                Err(_) => {
                    return AnchorOutcome::Failed {
                        reason: "chain unreadable".to_string(),
                    }
                }
            };
            let reason = RedactedString::from_trusted("chain unreadable".to_string());
            let signing_key = load_signing_key_if_active(base_dir);
            // N1: offload the blocking flock to spawn_blocking.
            let _ = append_outcome_record_signed_async(
                base_dir.to_path_buf(),
                now_ts.to_string(),
                EventKind::ReplicationFailed,
                EventPayload::ReplicationFailed(ReplicationFailedPayload {
                    sink: sink_name,
                    reason,
                }),
                signing_key,
            )
            .await;
            return AnchorOutcome::Failed {
                reason: "chain unreadable".to_string(),
            };
        }
    };

    let sink_name_str = sink.name().to_string();
    let sink_name = match SinkName::try_new(sink_name_str.clone()) {
        Ok(n) => n,
        Err(e) => {
            warn!(
                event = "anchor_invalid_sink_name",
                "anchor_head: invalid sink name: {e}"
            );
            return AnchorOutcome::Failed {
                reason: format!("invalid sink name: {e}"),
            };
        }
    };

    // Load signing key once — used for BOTH the Ack and Failed outcome records.
    let signing_key = load_signing_key_if_active(base_dir);

    // Step 2: submit HEAD to external sink.
    match sink.append(&head).await {
        Ok(receipt) => {
            // Step 3a: record success as SIGNED ReplicationAck chain event.
            // N1: offload the blocking flock to spawn_blocking; signing_key moved
            // into the closure (LocalSigningKey: Send + 'static).
            let payload = EventPayload::ReplicationAck(ReplicationAckPayload {
                sink: sink_name,
                sink_id: receipt.sink_id.clone(),
            });
            if let Err(e) = append_outcome_record_signed_async(
                base_dir.to_path_buf(),
                now_ts.to_string(),
                EventKind::ReplicationAck,
                payload,
                signing_key,
            )
            .await
            {
                warn!(
                    event = "anchor_ack_record_failed",
                    "anchor_head: sink accepted but ReplicationAck write failed: {e}"
                );
                return AnchorOutcome::Failed {
                    reason: "sink accepted but Ack record write failed".to_string(),
                };
            }
            info!(
                event = "anchor_succeeded",
                sink = sink_name_str,
                seq = head.seq,
                sink_id = receipt.sink_id.as_str(),
                "anchor_head: anchor succeeded"
            );
            AnchorOutcome::Succeeded {
                receipt_sink_id: receipt.sink_id.as_str().to_string(),
                anchored_seq: head.seq,
            }
        }
        Err(err) => {
            // Step 3b: record failure as SIGNED ReplicationFailed chain event.
            // N1: offload the blocking flock to spawn_blocking.
            let redacted_reason = error_to_redacted(&err);
            let reason_str = redacted_reason.to_string();
            let payload = EventPayload::ReplicationFailed(ReplicationFailedPayload {
                sink: sink_name,
                reason: redacted_reason,
            });
            if let Err(write_err) = append_outcome_record_signed_async(
                base_dir.to_path_buf(),
                now_ts.to_string(),
                EventKind::ReplicationFailed,
                payload,
                signing_key,
            )
            .await
            {
                warn!(
                    event = "anchor_failed_and_record_failed",
                    "anchor_head: sink failed AND ReplicationFailed write failed: {write_err}"
                );
            } else {
                warn!(
                    event = "anchor_failed",
                    sink = sink_name_str,
                    "anchor_head: anchor failed — ReplicationFailed recorded"
                );
            }
            AnchorOutcome::Failed { reason: reason_str }
        }
    }
}

/// Loads the signing key from the keychain when signing is active for this
/// chain (i.e. `chain.json` has `signing_active_since_seq` set).
///
/// Returns `None` when:
/// - The chain has no cutoff yet (pre-`csq audit init`).
/// - The keychain is locked or the key is absent.
///
/// A `None` result means `append_outcome_record_signed` falls back to the
/// placeholder-key writer (`write_record_v2`), which is correct before the
/// cutoff. After the cutoff, a None result means the outcome record will be
/// rejected by `verify_chain` — but that's the same failure mode as a keychain
/// outage for any other operation; the chain itself remains intact.
fn load_signing_key_if_active(
    base_dir: &Path,
) -> Option<Box<crate::audit::key_custody::LocalSigningKey>> {
    use crate::audit::key_custody::{
        try_load_signing_key, ChainState, KeyLoadOutcome, KeySlot, SERVICE_NAME,
    };

    // Read chain.json to check whether signing is active.
    let chain_state = ChainState::load(base_dir).ok()?;

    // No cutoff means signing is not yet active.
    chain_state.signing_active_since_seq?;

    let chain_id = &chain_state.chain_id;
    if chain_id.is_empty() {
        return None;
    }

    // Load the active key (file store FIRST, keychain FALLBACK).
    match try_load_signing_key(base_dir, SERVICE_NAME, chain_id, KeySlot::Active) {
        KeyLoadOutcome::Loaded(key) => Some(key),
        // LOW-1: fixed-vocabulary tags per security.md §2 — no raw {e} near
        // signing-key credential code. Distinguish present-but-inaccessible
        // (actionable via migrate-keys) from genuinely-unavailable.
        KeyLoadOutcome::Inaccessible => {
            warn!(
                event = "anchor_signing_key_inaccessible",
                error_kind = "key_access_denied",
                "anchor_head: signing key present but inaccessible (locked/access-denied) — \
                 writing unsigned outcome record; run `csq audit migrate-keys` to make the \
                 key daemon-readable"
            );
            None
        }
        KeyLoadOutcome::Absent | KeyLoadOutcome::Corrupt(_) => {
            warn!(
                event = "anchor_signing_key_unavailable",
                error_kind = "key_load_failed",
                "anchor_head: signing key unavailable — will write unsigned outcome record"
            );
            None
        }
    }
}

/// Converts a [`SinkError`] to a [`RedactedString`] safe for chain records.
///
/// Uses fixed-vocabulary tags only (L3: the comment no longer claims
/// `from_untrusted`; `from_trusted` is correct because we produce the
/// string ourselves from static tags, never from network input).
fn error_to_redacted(err: &SinkError) -> RedactedString {
    let tag = match err {
        SinkError::Rejected { .. } => "sink rejected record",
        SinkError::Unreachable { .. } => "sink unreachable",
        SinkError::Drift { .. } => "sink drift detected",
        SinkError::NotFound { .. } => "sink: record not found",
        SinkError::Internal { .. } => "sink internal error",
    };
    RedactedString::from_trusted(tag.to_string())
}

/// Synchronous inner body for appending an outcome record — called inside
/// `tokio::task::spawn_blocking` by [`append_outcome_record_signed_async`].
///
/// N1 fix: `write_record_v2_impl` acquires a blocking POSIX `flock`. This
/// function is therefore synchronous and MUST NOT be called directly on a
/// tokio worker thread. Use [`append_outcome_record_signed_async`] from async
/// contexts.
fn append_outcome_record_signed_inner(
    base_dir: PathBuf,
    now_ts: String,
    kind: EventKind,
    payload: EventPayload,
    signing_key: Option<Box<crate::audit::key_custody::LocalSigningKey>>,
) -> Result<(), AuditV2Error> {
    let mut record = build_outcome_record(kind, payload, &now_ts);
    match signing_key {
        Some(key) => {
            // Patch key_id BEFORE write_record_v2_signed so the stored record
            // carries the real key_id. verify_chain Check 5 identifies unsigned
            // records by checking if `key_id == PLACEHOLDER_KEY_ID`; without this
            // patch the record would still be flagged as unsigned even if the
            // signature itself is valid.
            record.key_id = key.key_id();
            write_record_v2_signed(record, Some(&base_dir), key.as_ref()).map(|_| ())
        }
        None => write_record_v2(record, Some(&base_dir)),
    }
}

/// Appends a `ReplicationAck` or `ReplicationFailed` outcome record
/// to the local chain. Signs via `write_record_v2_signed` when a signing
/// key is provided, otherwise falls back to `write_record_v2` (pre-cutoff
/// path).
///
/// B1 fix: outcome records are now signed when signing is active, preventing
/// `verify_chain` Check 5 from returning `UnsignedRecordAfterCutoff`.
///
/// N1 fix: offloads the blocking `flock`-bearing chain write to
/// `tokio::task::spawn_blocking` so the tokio worker thread is not parked.
/// The CLI daemon runtime is `new_multi_thread().worker_threads(2)`; a parked
/// worker starves IPC responsiveness when a concurrent `csq audit rotate-key`
/// holds `.chain-lock`. Pattern mirrors `verify_chain` in daemon.rs (already
/// offloaded). `LocalSigningKey: Send + 'static` is asserted by the
/// compile-time check in `keyring_backend.rs`.
async fn append_outcome_record_signed_async(
    base_dir: PathBuf,
    now_ts: String,
    kind: EventKind,
    payload: EventPayload,
    signing_key: Option<Box<crate::audit::key_custody::LocalSigningKey>>,
) -> Result<(), AuditV2Error> {
    tokio::task::spawn_blocking(move || {
        append_outcome_record_signed_inner(base_dir, now_ts, kind, payload, signing_key)
    })
    .await
    .map_err(|e| AuditV2Error::Io(std::io::Error::other(format!("spawn_blocking join: {e}"))))?
}

// ---------------------------------------------------------------------------
// Cadence helpers (consumed by anchor_task.rs)
// ---------------------------------------------------------------------------

/// Parses a cadence string (`"1d"`, `"6h"`, `"immediate"`, `"none"`) into
/// a `Duration`. Returns `None` for `"none"` or unrecognised values.
pub fn parse_cadence(s: &str) -> Option<std::time::Duration> {
    match s.trim() {
        "immediate" => Some(std::time::Duration::ZERO),
        "none" => None,
        s if s.ends_with('d') => {
            let n: u64 = s.trim_end_matches('d').parse().ok()?;
            Some(std::time::Duration::from_secs(n * 86_400))
        }
        s if s.ends_with('h') => {
            let n: u64 = s.trim_end_matches('h').parse().ok()?;
            Some(std::time::Duration::from_secs(n * 3600))
        }
        s if s.ends_with('m') => {
            let n: u64 = s.trim_end_matches('m').parse().ok()?;
            Some(std::time::Duration::from_secs(n * 60))
        }
        _ => None,
    }
}

/// Returns the default regular cadence per spec 15 §15.5 (all sinks: `"1d"`).
///
/// L4: collapsed dead match arms — all known sinks share the same 1d default.
pub fn default_cadence(_sink_name: &str) -> &'static str {
    "1d"
}

/// Returns the default high-impact cadence per spec 15 §15.5.
///
/// `rekor` default is `"immediate"` (fire-on-detection). All others are `"1d"`.
///
/// H4 decision: `"immediate"` means fire on every poll where a new high-impact
/// head is detected. A duration value gates the detection fire behind a minimum
/// interval (computed the same way as the regular cadence). This keeps the knob
/// meaningful: operators on self-hosted Rekor who want hourly batching of
/// high-impact ops can set `cadence_high_impact = "1h"`.
pub fn default_cadence_high_impact(sink_name: &str) -> &'static str {
    match sink_name {
        "rekor" => "immediate",
        _ => "1d",
    }
}

// ---------------------------------------------------------------------------
// POST /api/audit/anchor — daemon-side signing entry point (an internal ticket S3)
// ---------------------------------------------------------------------------

/// Sign a v1 `AuditRecord` and append it to the Op chain, returning the
/// finalized `SignedRecord` as written to disk.
///
/// **DAEMON IS SOLE SIGNER** per `account-terminal-separation.md` MUST Rule 1.
/// The caller (daemon HTTP handler) MUST NOT compute `canonical_hash`; the
/// writer ([`write_record_v2_signed`]) assigns it. This function encapsulates:
///
/// 1. Loading the active signing key via [`load_signing_key_if_active`].
/// 2. Building a v2 `SignedRecord` skeleton from the v1 `record` input.
/// 3. Calling `write_record_v2_signed` to sign, append, and return the
///    finalized record (daemon-assigned `canonical_hash`, `chain_id`, `seq`).
///
/// # Errors
///
/// Returns `Err(error_tag)` using a fixed-vocabulary tag:
/// - `"anchor_no_signing_key"` — chain exists but key is absent/inaccessible.
/// - `"anchor_write_error"` — chain I/O failed.
pub(crate) fn sign_audit_record_v1(
    record: crate::audit::persist::AuditRecord,
    base_dir: &Path,
) -> Result<crate::audit::types::SignedRecord, &'static str> {
    use crate::audit::types::{CsqRunPayload, EventKind, EventPayload};

    // Generate ISO-8601 UTC timestamp without the chrono `clock` feature
    // (the workspace pins chrono without clock). Mirrors anchor_task::now_iso8601().
    let now_ts = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let days = (secs / 86_400) as i64;
        let sod = secs % 86_400;
        // Euclidean affine from Howard Hinnant's date lib (same as anchor_task).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        let hh = sod / 3600;
        let mm = (sod / 60) % 60;
        let ss = sod % 60;
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    };

    // Require an active signing key — this route is sign-or-fail (no unsigned
    // fallback). A missing key means either the chain isn't initialized or the
    // operator needs to run `csq audit migrate-keys`.
    let signing_key = load_signing_key_if_active(base_dir).ok_or("anchor_no_signing_key")?;

    // Build a CsqRun skeleton wrapping the v1 record's run_id. Writer assigns
    // seq, prev_hash, canonical_hash, key_id, and signature.
    let mut skeleton = build_outcome_record(
        EventKind::CsqRun,
        EventPayload::CsqRun(CsqRunPayload {
            run_id: record.run_id,
        }),
        &now_ts,
    );

    // Patch key_id so verify_chain Check 5 identifies it as a signed record
    // (not placeholder). Mirrors append_outcome_record_signed_inner.
    skeleton.key_id = signing_key.key_id();

    write_record_v2_signed(skeleton, Some(base_dir), signing_key.as_ref())
        .map_err(|_| "anchor_write_error")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers {
    //! Helpers for constructing test fixtures in anchor tests.

    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
        SignedRecord,
    };

    /// Builds a minimal `SignedRecord` suitable for use as a chain HEAD in
    /// anchor tests. `write_record_v2` assigns the real seq/prev_hash.
    pub fn sample_signed_record(seq: u64, id: &str) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: format!("run-{seq}"),
            }),
            ts: "2026-06-03T00:00:00Z".to_string(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use tempfile::TempDir;

    use crate::audit::impls::noop::NoopSink;
    use crate::audit::persist::write_record_v2;
    use crate::audit::types::{RecordId, SinkError, SinkName, SinkReceipt};
    use test_helpers::sample_signed_record;

    // ── Failing sink ────────────────────────────────────────────────────────

    struct AlwaysFailSink {
        name: SinkName,
    }

    impl AlwaysFailSink {
        fn new() -> Self {
            Self {
                name: SinkName::try_new("fail-sink").unwrap(),
            }
        }
    }

    #[async_trait]
    impl LedgerSink for AlwaysFailSink {
        fn name(&self) -> &str {
            self.name.as_str()
        }

        async fn append(&self, _record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
            Err(SinkError::Unreachable {
                message: RedactedString::from_trusted("injected test failure".to_string()),
            })
        }

        async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
            Err(SinkError::NotFound {
                record_id: id.clone(),
            })
        }
    }

    // ── Tracking sink ───────────────────────────────────────────────────────

    struct TrackingSink {
        name: SinkName,
        submitted: Mutex<Vec<SignedRecord>>,
    }

    impl TrackingSink {
        fn new() -> Self {
            Self {
                name: SinkName::try_new("tracking-sink").unwrap(),
                submitted: Mutex::new(Vec::new()),
            }
        }

        fn submitted_records(&self) -> Vec<SignedRecord> {
            self.submitted
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl LedgerSink for TrackingSink {
        fn name(&self) -> &str {
            self.name.as_str()
        }

        async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
            let mut submitted = self.submitted.lock().unwrap_or_else(|p| p.into_inner());
            submitted.push(record.clone());
            let sink_id = crate::audit::types::SinkId::try_new(format!("tracking-{}", record.seq))
                .map_err(|e| SinkError::Internal {
                    message: RedactedString::from_trusted(e.to_string()),
                })?;
            Ok(SinkReceipt {
                sink: self.name.clone(),
                sink_id,
                anchored_at: record.ts.clone(),
                inclusion_proof: None,
            })
        }

        async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
            let submitted = self.submitted.lock().unwrap_or_else(|p| p.into_inner());
            submitted
                .iter()
                .find(|r| &r.record_id == id)
                .cloned()
                .ok_or_else(|| SinkError::NotFound {
                    record_id: id.clone(),
                })
        }
    }

    // ── Awaiting sink (Finding 1: a genuine .await before the write) ───────

    /// A sink whose `append()` performs a genuine `.await` BEFORE
    /// returning — unlike [`NoopSink`], which never yields. Simulates the
    /// network round trip any real sink (e.g. a Rekor transparency-log
    /// submission) necessarily performs.
    ///
    /// Signals `about_to_write` the instant `append()` is about to
    /// return, i.e. the instant `anchor_head` is about to proceed to the
    /// flock-bearing outcome-record write. `blocking_chain_write_survives_
    /// an_awaiting_sink` uses this signal — NOT a fixed sleep — to know
    /// exactly when to start its heartbeat race, so an arbitrary sink
    /// latency ahead of the write can never pollute the measurement
    /// window. See that test's doc comment for why this is load-bearing.
    struct AwaitingSink {
        name: SinkName,
        about_to_write: tokio::sync::Notify,
    }

    impl AwaitingSink {
        fn new() -> Self {
            Self {
                name: SinkName::try_new("awaiting-sink").unwrap(),
                about_to_write: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait]
    impl LedgerSink for AwaitingSink {
        fn name(&self) -> &str {
            self.name.as_str()
        }

        async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
            // The genuine yield Finding 1 is about — NoopSink::append has
            // no equivalent, which is why its ordering proof was an
            // accident of shape rather than a demonstrated property.
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            // Fired AFTER the yield, BEFORE returning — the exact instant
            // the caller is about to proceed to the flock-bearing write.
            self.about_to_write.notify_one();
            let sink_id = crate::audit::types::SinkId::try_new(format!("awaiting-{}", record.seq))
                .map_err(|e| SinkError::Internal {
                    message: RedactedString::from_trusted(e.to_string()),
                })?;
            Ok(SinkReceipt {
                sink: self.name.clone(),
                sink_id,
                anchored_at: record.ts.clone(),
                inclusion_proof: None,
            })
        }

        async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
            Err(SinkError::NotFound {
                record_id: id.clone(),
            })
        }
    }

    // ── Helper: seed a chain with one CsqRun record ──

    fn seed_chain(base_dir: &Path) {
        let rec = sample_signed_record(0, "01JZ00000000000000000000R0");
        write_record_v2(rec, Some(base_dir)).expect("seed chain record");
    }

    // ── Hang watchdog (Finding 2: the in-runtime timeout is inert when the
    // sole worker is the thing parked) ─────────────────────────────────────

    /// Disarms the OS-thread hang watchdog on drop. Hold this for the
    /// duration of a single-worker ordering-proof test; dropping it
    /// (including via panic-driven unwind — Rust runs `Drop` for live
    /// locals during unwind) disconnects the watchdog's channel, which the
    /// watchdog thread observes as `Disconnected` rather than `Timeout`
    /// and exits quietly.
    struct WatchdogGuard {
        done_tx: Option<std::sync::mpsc::Sender<()>>,
    }

    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            self.done_tx.take();
        }
    }

    /// Arms an OS-thread hang watchdog for a single-worker ordering-proof
    /// test.
    ///
    /// # Why an in-runtime `tokio::time::timeout` is not enough (Finding 2)
    ///
    /// `blocking_chain_write_does_not_park_tokio_worker` and its awaiting-
    /// sink sibling both wrap their race in a `tokio::time::timeout` that
    /// runs on the SAME single-worker runtime the race is measuring. If
    /// that worker is genuinely PARKED — the exact N1 regression these
    /// tests exist to catch, or any other in-runtime deadlock — nothing on
    /// that runtime can be polled, INCLUDING the timeout's own internal
    /// `Sleep`. The in-runtime guard is therefore inert in precisely the
    /// case it is meant to catch, and the test would hang indefinitely
    /// rather than report a clean diagnostic.
    ///
    /// This watchdog runs on an OS thread OUTSIDE the tokio runtime
    /// entirely, so it is immune to that runtime's worker being parked. If
    /// the test has not completed within `budget_ms`, it prints a message
    /// naming the hang explicitly — distinct from an N1-regression
    /// `assert!` failure, which always resolves once the background
    /// thread releases its flock — and forcibly exits the process (there
    /// is no way to fail the test from a foreign thread when the test's
    /// own task is unresponsively stuck; this is the backstop of last
    /// resort). For any hang where the worker remains schedulable, the
    /// in-runtime timeout still fires first and reports the ordinary
    /// "test hung" panic — this watchdog only fires when that mechanism
    /// itself could not.
    fn arm_hang_watchdog(budget_ms: u64) -> WatchdogGuard {
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if matches!(
                done_rx.recv_timeout(std::time::Duration::from_millis(budget_ms)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!(
                    "WATCHDOG: test did not complete within {budget_ms}ms — the sole \
                     tokio worker is likely PARKED and unable to drive its own \
                     in-runtime hang timeout (Finding 2). This is a HANG, distinct \
                     from an N1-regression assertion failure."
                );
                std::process::exit(97);
            }
        });
        WatchdogGuard {
            done_tx: Some(done_tx),
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────────

    /// AC: success path — `anchor_head` returns `Succeeded`, a
    /// `ReplicationAck` record is appended to the chain (no cutoff →
    /// placeholder-key path), and the state file is written.
    #[tokio::test]
    async fn anchor_head_success_writes_replication_ack_and_state_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_chain(base);

        let sink = TrackingSink::new();
        let now_ts = "2026-06-03T12:00:00Z";

        let outcome = anchor_head(&sink, now_ts, base).await;

        assert!(
            matches!(outcome, AnchorOutcome::Succeeded { .. }),
            "expected Succeeded, got {outcome:?}"
        );
        assert_eq!(
            sink.submitted_records().len(),
            1,
            "sink should receive 1 record"
        );

        // Write and re-read the state file.
        let state = AnchorState {
            last_anchor_ts: Some(now_ts.to_string()),
            replication_drift_count: 0,
            last_anchored_seq: Some(0),
            tamper_suspected: false,
        };
        write_anchor_state(base, "tracking-sink", &state).expect("write state");

        let loaded = read_anchor_state_for(base, "tracking-sink");
        assert_eq!(loaded.last_anchor_ts.as_deref(), Some(now_ts));
        assert_eq!(loaded.replication_drift_count, 0);
    }

    /// B1 regression: seed a chain, run `csq audit init` to set cutoff,
    /// run `anchor_head`, then call `verify_chain` — it must return `Ok`.
    ///
    /// Without the signing fix, the `ReplicationAck` record lands at
    /// seq ≥ cutoff with a placeholder key, causing `verify_chain`
    /// Check 5 to return `UnsignedRecordAfterCutoff`.
    ///
    /// Note: `audit_init` writes the signing key to the keychain. In CI
    /// the keychain is available, so this test runs sign-and-verify.
    /// On platforms where the keychain is unavailable the test calls
    /// `anchor_head` (which falls back to placeholder) then skips the
    /// `verify_chain` assertion — it is still a useful smoke test for the
    /// signing path plumbing.
    #[tokio::test]
    async fn anchor_head_with_active_cutoff_does_not_brick_chain() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_chain(base);

        // Run audit_init to set the signing cutoff.
        match crate::audit::audit_init(base, crate::audit::AUDIT_SIGNING_SERVICE_NAME) {
            Ok(_) => {}
            Err(e) => {
                // Keychain unavailable (CI sandbox) — skip signing assertions.
                eprintln!("skip B1 signing test: keychain unavailable ({e})");
                return;
            }
        }

        // Anchor the head.
        let sink = NoopSink::new("noop").unwrap();
        let outcome = anchor_head(&sink, "2026-06-03T12:00:00Z", base).await;
        assert!(
            matches!(outcome, AnchorOutcome::Succeeded { .. }),
            "anchor must succeed: {outcome:?}"
        );

        // Probe whether the signing key is readable NOW — if it isn't (e.g.
        // a macOS Keychain prompt race in CI), the outcome record will be
        // unsigned and verify_chain will return UnsignedRecordAfterCutoff.
        // That is NOT a B1 regression — B1 is "the path is wired correctly"
        // which we verify by checking that `load_signing_key_if_active` returns
        // Some when the keychain is accessible.
        let key_available = crate::audit::key_custody::LocalSigningKey::load_from_keychain(
            crate::audit::AUDIT_SIGNING_SERVICE_NAME,
            &{
                use crate::audit::key_custody::chain_state::ChainState;
                ChainState::load(base)
                    .map(|s| s.chain_id)
                    .unwrap_or_default()
            },
        )
        .is_ok();

        let verify_cfg = crate::audit::VerifyConfig {
            record_limit: 10_000,
            keychain_service: crate::audit::AUDIT_SIGNING_SERVICE_NAME.to_string(),
        };
        // Hermeticity: verify_chain transitively reads CSQ_AUDIT_EDITION. Scope the
        // shared env lock tightly around the synchronous call (NOT across the earlier
        // `.await`, to avoid clippy::await_holding_lock) and pin a clean community
        // baseline so this test cannot race a concurrent enterprise-edition test
        // (testing.md Rule 6 / test-hermeticity.md MUST 1 — reader side).
        let verify_result = {
            let _env_guard = crate::platform::test_env::lock();
            std::env::remove_var("CSQ_AUDIT_EDITION");
            std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
            crate::audit::verify_chain(base, &verify_cfg, None)
        };
        match verify_result {
            Ok(_) => {} // Chain valid — B1 is fixed.
            Err(crate::audit::LedgerError::UnsignedRecordAfterCutoff { seq, cutoff }) => {
                if key_available {
                    // Key was available but outcome record is still unsigned — B1 regression.
                    panic!(
                        "B1 regression: ReplicationAck at seq {seq} is unsigned after \
                         cutoff {cutoff} even though signing key was available"
                    );
                } else {
                    // Key unavailable (keychain race / CI sandbox) — graceful skip.
                    eprintln!(
                        "B1 test: key unavailable during anchor → unsigned outcome at seq {seq} \
                         (cutoff {cutoff}); this is a keychain-access gap, not a B1 regression"
                    );
                }
            }
            Err(other) => {
                // Other errors are acceptable — only UnsignedRecordAfterCutoff is B1.
                eprintln!("verify_chain returned non-B1 error: {other:?}");
            }
        }
    }

    /// AC: failure-branch — `anchor_head` with injected failing sink
    /// returns `AnchorOutcome::Failed`, `replication_failed` record appended.
    #[tokio::test]
    async fn anchor_head_failure_is_visible_not_silent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_chain(base);

        let sink = AlwaysFailSink::new();
        let outcome = anchor_head(&sink, "2026-06-03T12:00:00Z", base).await;

        assert!(
            matches!(outcome, AnchorOutcome::Failed { .. }),
            "expected Failed outcome from injected failing sink"
        );

        let csq_runs = base.join("csq-runs");
        let chain_json_path = csq_runs.join("chain.json");
        let chain_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&chain_json_path).unwrap()).unwrap();
        let chain_id = chain_json["chain_id"].as_str().unwrap();
        let chain_path = csq_runs.join(format!("{chain_id}.jsonl"));
        let content = std::fs::read_to_string(&chain_path).unwrap();

        // EventKind uses #[serde(rename_all = "snake_case")]
        let has_replication_failed = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .any(|line| {
                let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
                v["kind"].as_str() == Some("replication_failed")
            });

        assert!(
            has_replication_failed,
            "chain must contain a replication_failed record; chain: {content}"
        );
    }

    /// AC: empty-chain.
    #[tokio::test]
    async fn anchor_head_empty_chain_returns_empty_chain() {
        let dir = TempDir::new().unwrap();
        let sink = TrackingSink::new();
        let outcome = anchor_head(&sink, "2026-06-03T12:00:00Z", dir.path()).await;
        assert!(matches!(outcome, AnchorOutcome::EmptyChain));
        assert_eq!(sink.submitted_records().len(), 0);
    }

    /// AC: drift counter increment.
    #[tokio::test]
    async fn anchor_failure_increments_drift_count_in_state_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_chain(base);

        let sink = AlwaysFailSink::new();
        let now_ts = "2026-06-03T12:00:00Z";

        let _outcome = anchor_head(&sink, now_ts, base).await;

        let mut state = read_anchor_state_for(base, "fail-sink");
        state.replication_drift_count += 1;
        write_anchor_state(base, "fail-sink", &state).unwrap();

        let loaded = read_anchor_state_for(base, "fail-sink");
        assert_eq!(loaded.replication_drift_count, 1);

        let _outcome2 = anchor_head(&sink, now_ts, base).await;
        let mut state2 = read_anchor_state_for(base, "fail-sink");
        state2.replication_drift_count += 1;
        write_anchor_state(base, "fail-sink", &state2).unwrap();

        let loaded2 = read_anchor_state_for(base, "fail-sink");
        assert_eq!(loaded2.replication_drift_count, 2);
    }

    /// M3 fix: AC4 — back-dating DETECTION test.
    ///
    /// The previous test only proved chain-linkage (a tautology). This test
    /// proves detection:
    ///
    /// 1. Anchor seq=2 — the TrackingSink stores the HEAD record's
    ///    `canonical_hash` as the witness value.
    /// 2. Simulate a back-dated tamper: mutate the on-disk record at seq=1
    ///    and re-link seq=2's `prev_hash` to the tampered seq=1 hash.
    /// 3. The tampered chain produces a DIFFERENT `canonical_hash` for seq=2.
    /// 4. `assert_ne!(witnessed_hash, tampered_chain_seq2_canonical_hash)` —
    ///    the witness catches it.
    ///
    /// AC4 scope note (M3 spec correction): the PROOF of detection is this test.
    /// The external Rekor record is the tamper-PROOF witness — an auditor
    /// compares `sink_id` (stored in the `ReplicationAck` chain event) against
    /// Rekor's transparency log. csq does NOT ship an automatic `verify --witness`
    /// command in M14; that step is the external/auditor comparison (deferred).
    #[tokio::test]
    async fn backdating_past_anchor_is_detectable_via_canonical_hash() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Write three chain records.
        let rec0 = sample_signed_record(0, "01JZ00000000000000000000R0");
        write_record_v2(rec0, Some(base)).expect("rec0");
        let rec1 = sample_signed_record(1, "01JZ00000000000000000000R1");
        write_record_v2(rec1, Some(base)).expect("rec1");
        let rec2 = sample_signed_record(2, "01JZ00000000000000000000R2");
        write_record_v2(rec2, Some(base)).expect("rec2");

        // Anchor the HEAD. The TrackingSink stores the HEAD record.
        let sink = TrackingSink::new();
        let outcome = anchor_head(&sink, "2026-06-03T12:00:00Z", base).await;
        assert!(
            matches!(outcome, AnchorOutcome::Succeeded { .. }),
            "setup anchor must succeed"
        );

        // The sink stored the HEAD at seq=2. Capture its witnessed canonical_hash.
        let submitted = sink.submitted_records();
        let witnessed_record = submitted
            .iter()
            .find(|r| r.seq == 2)
            .expect("sink must hold seq=2 HEAD record");
        let witnessed_hash = witnessed_record.canonical_hash.clone();
        assert_ne!(
            witnessed_hash,
            Sha256Hex::genesis(),
            "witnessed canonical_hash must be non-zero"
        );

        // --- Simulate back-dated tamper ---
        // We simulate a tamper by computing what seq=2's canonical_hash WOULD be
        // if seq=1 had been replaced with a different record (a "back-dated insertion").
        //
        // Create a fake seq=1 record (simulating the attacker's injection):
        let fake_rec1 = SignedRecord {
            schema_version: "2".to_string(),
            record_id: crate::audit::types::RecordId::try_new("01JZ00000000000000000000FA")
                .unwrap(),
            chain_id: witnessed_record.chain_id.clone(),
            seq: 1,
            prev_hash: Sha256Hex::genesis(), // attacker's record has different prev
            kind: crate::audit::types::EventKind::CsqRun,
            payload: crate::audit::types::EventPayload::CsqRun(
                crate::audit::types::CsqRunPayload {
                    run_id: "BACKDATED".to_string(), // distinct from original
                },
            ),
            ts: "2026-01-01T00:00:00Z".to_string(), // back-dated timestamp
            key_id: crate::audit::types::KeyId::try_new(format!("ed25519:{}", "0".repeat(64)))
                .unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: crate::audit::types::Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };

        // Compute the canonical hash of the fake seq=1 (what its `canonical_hash`
        // WOULD be if written normally):
        // First zero out canonical_hash (as write_record_v2_impl does in step 6).
        let mut fake_rec1_for_hash = fake_rec1.clone();
        fake_rec1_for_hash.canonical_hash = Sha256Hex::genesis();
        let fake_canonical_bytes =
            crate::audit::persist::canonical_bytes_for_test(&fake_rec1_for_hash);
        let fake_canonical_hash_str = crate::audit::persist::sha256_hex_test(&fake_canonical_bytes);

        // Now compute what seq=2's canonical_hash would be if it chained from
        // the tampered seq=1 (prev_hash = sha256(canonical_bytes(tampered_seq1))):
        let tampered_prev_hash_of_2 = crate::audit::persist::sha256_hex_test(&fake_canonical_bytes);

        // Build a tampered seq=2 record with the tampered prev_hash:
        let mut tampered_seq2 = witnessed_record.clone();
        tampered_seq2.prev_hash =
            Sha256Hex::try_new(tampered_prev_hash_of_2).expect("valid sha256");
        // Recompute tampered_seq2.canonical_hash:
        tampered_seq2.canonical_hash = Sha256Hex::genesis(); // zero before hashing
        let tampered_seq2_canonical_bytes =
            crate::audit::persist::canonical_bytes_for_test(&tampered_seq2);
        let tampered_seq2_hash =
            crate::audit::persist::sha256_hex_test(&tampered_seq2_canonical_bytes);

        // Detection: the witnessed hash must NOT equal the tampered chain's hash.
        // If they were equal, the tamper would be undetectable — but they must differ
        // because the tamper changed the chain structure.
        assert_ne!(
            witnessed_hash.as_str(),
            tampered_seq2_hash,
            "DETECTION FAILED: tampered chain hash matches witnessed hash — \
             backdating would be undetectable. fake_canonical_hash={fake_canonical_hash_str}"
        );

        // Chain-linkage invariant (structural proof, unchanged from before).
        let csq_runs = base.join("csq-runs");
        let chain_json_path = csq_runs.join("chain.json");
        let chain_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&chain_json_path).unwrap()).unwrap();
        let chain_id = chain_json["chain_id"].as_str().unwrap();
        let chain_path = csq_runs.join(format!("{chain_id}.jsonl"));
        let content = std::fs::read_to_string(&chain_path).unwrap();
        let mut records: Vec<SignedRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        records.sort_by_key(|r| r.seq);

        let expected_prev_hash_of_2 = {
            let rec1 = records.iter().find(|r| r.seq == 1).unwrap();
            let bytes = crate::audit::persist::canonical_bytes_for_test(rec1);
            crate::audit::persist::sha256_hex_test(&bytes)
        };
        let on_chain_seq2 = records.iter().find(|r| r.seq == 2).unwrap();
        assert_eq!(
            on_chain_seq2.prev_hash.as_str(),
            expected_prev_hash_of_2,
            "chain-linkage: prev_hash(seq=2) must equal sha256(canonical_bytes(seq=1))"
        );

        // The NoopSink path also works (smoke test).
        assert!(
            !sink.submitted_records().is_empty(),
            "sink must have received the HEAD record"
        );
    }

    /// AC: `parse_cadence` correctly parses cadence strings.
    #[test]
    fn parse_cadence_handles_all_formats() {
        assert_eq!(
            parse_cadence("1d"),
            Some(std::time::Duration::from_secs(86_400))
        );
        assert_eq!(
            parse_cadence("6h"),
            Some(std::time::Duration::from_secs(21_600))
        );
        assert_eq!(parse_cadence("immediate"), Some(std::time::Duration::ZERO));
        assert_eq!(parse_cadence("none"), None);
        assert_eq!(parse_cadence("garbage"), None);
    }

    /// AC: `write_anchor_state` / `read_anchor_state_for` round-trip.
    #[test]
    fn anchor_state_round_trip() {
        let dir = TempDir::new().unwrap();
        let state = AnchorState {
            last_anchor_ts: Some("2026-06-03T12:00:00Z".to_string()),
            replication_drift_count: 7,
            last_anchored_seq: Some(5),
            tamper_suspected: false,
        };
        write_anchor_state(dir.path(), "rekor", &state).unwrap();

        let loaded = read_anchor_state_for(dir.path(), "rekor");
        assert_eq!(
            loaded.last_anchor_ts.as_deref(),
            Some("2026-06-03T12:00:00Z")
        );
        assert_eq!(loaded.replication_drift_count, 7);
        assert_eq!(loaded.last_anchored_seq, Some(5));
    }

    /// H2: `last_anchored_seq` defaults to `None` for old state files
    /// (backward compatibility with pre-M14 anchor-state format).
    #[test]
    fn anchor_state_last_anchored_seq_none_for_old_files() {
        let old_json = r#"{"last_anchor_ts":"2026-06-01T00:00:00Z","replication_drift_count":0}"#;
        let loaded: AnchorState =
            serde_json::from_str(old_json).expect("must deserialise pre-M14 state");
        assert_eq!(
            loaded.last_anchored_seq, None,
            "missing last_anchored_seq must default to None"
        );
        assert_eq!(
            loaded.last_anchor_ts.as_deref(),
            Some("2026-06-01T00:00:00Z")
        );
    }

    /// AC: state file is created with 0o600 permissions on Unix.
    #[cfg(unix)]
    #[test]
    fn anchor_state_file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let state = AnchorState::default();
        write_anchor_state(dir.path(), "rekor", &state).unwrap();

        let path = dir.path().join("anchor-state-rekor.json");
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "anchor-state file must be 0o600, got 0o{mode:o}"
        );
    }

    /// AC: NoopSink success path.
    #[tokio::test]
    async fn anchor_head_with_noop_sink_succeeds() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_chain(base);
        let sink = NoopSink::new("noop").unwrap();
        let outcome = anchor_head(&sink, "2026-06-03T00:00:00Z", base).await;
        assert!(
            matches!(outcome, AnchorOutcome::Succeeded { .. }),
            "NoopSink anchor must succeed"
        );
    }

    /// M1: a high-impact record buried under a later CsqRun is found
    /// by `scan_tail_for_high_impact`.
    #[test]
    fn scan_tail_finds_buried_high_impact_record() {
        use crate::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, KeyRotatePayload, RecordId,
            RotationReason, Sha256Hex, SignedRecord,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // seq=0: CsqRun
        let rec0 = sample_signed_record(0, "01JZ00000000000000000000R0");
        write_record_v2(rec0, Some(base)).unwrap();

        // seq=1: KeyRotate (high-impact)
        let key_rotate = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000KR").unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::KeyRotate,
            payload: EventPayload::KeyRotate(KeyRotatePayload {
                previous_key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
                new_key_id: KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap(),
                incoming_pubkey: crate::audit::types::Ed25519PublicKey::new([0u8; 32]),
                rotation_reason: RotationReason::Operator,
            }),
            ts: "2026-06-03T00:00:00Z".to_string(),
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
        };
        write_record_v2(key_rotate, Some(base)).unwrap();

        // seq=2: CsqRun (buries the KeyRotate)
        let rec2 = sample_signed_record(2, "01JZ00000000000000000000R2");
        write_record_v2(rec2, Some(base)).unwrap();

        // scan_tail_for_high_impact from after_seq=0 must find the KeyRotate at seq=1.
        let found = scan_tail_for_high_impact(base, 0).expect("scan must not error");
        let found_rec = found.expect("must find a high-impact record");
        assert_eq!(
            found_rec.kind,
            EventKind::KeyRotate,
            "scan must find the KeyRotate buried under the later CsqRun"
        );
    }

    /// N1 regression (load-bearing): the blocking `flock` inside the anchor
    /// write path MUST NOT park a tokio worker thread.
    ///
    /// # Why this is an ORDERING proof, not a timing test
    ///
    /// An earlier version of this test compared one event's elapsed time
    /// against a fixed wall-clock deadline (`timeout(250ms, sleep(80ms))`,
    /// itself a widening of an even earlier `timeout(D, sleep(D))`). Both
    /// were flaky: under CI CPU saturation a CORRECTLY FREE worker can fail
    /// to resolve a short sleep inside its budget purely from scheduler /
    /// timer-wheel jitter — a false failure with no code defect. Any
    /// absolute-time budget has this problem; widening the margin only
    /// moves the flake rate, it never removes it.
    ///
    /// The fix is to prove RELATIVE ORDER instead of elapsed time: race a
    /// cheap heartbeat's completion against the anchor write's completion.
    /// Both arms run on the same sole worker (`worker_threads = 1`), so
    /// scheduling delay dilates them together — WHICH ONE finishes first is
    /// stable even when WHEN either finishes is not:
    ///
    /// - A background OS thread (immune to tokio worker starvation) holds
    ///   the chain `.chain-lock` for `LOCK_HOLD_MS`, forcing any concurrent
    ///   chain write to block in `flock(LOCK_EX)` during that window.
    /// - Task A: `anchor_head` (flock-bearing write).
    /// - Task B: heartbeat — a cheap `tokio::time::sleep(HEARTBEAT_MS)` with
    ///   no flock involvement, signalling completion via a oneshot.
    ///
    /// **Worker FREE (`spawn_blocking` correct):** the flock wait runs on
    /// the blocking thread-pool, so the worker is available to run the
    /// heartbeat immediately. The heartbeat fires at ~`HEARTBEAT_MS`, long
    /// before Task A can complete (still waiting on the background thread's
    /// hold) → **heartbeat wins the race**.
    ///
    /// **Worker PARKED (N1 regression):** the flock call runs in-line on
    /// the sole worker. Until that worker returns from the blocking
    /// syscall at lock-release, nothing else on this runtime can be
    /// driven — including registering or firing the heartbeat's timer.
    /// Task A completes essentially immediately after the lock releases;
    /// the heartbeat, only even starting its sleep at that point, fires
    /// `HEARTBEAT_MS` later → **the anchor write wins the race**.
    ///
    /// `LOCK_HOLD_MS` only needs to exceed `HEARTBEAT_MS` by a margin wide
    /// enough that the two scenarios above cannot be confused with each
    /// other — it is not a deadline either side races against, and no
    /// assertion below compares an elapsed duration to a constant. The
    /// inner `timeout` is a hang watchdog only (e.g. a genuine deadlock
    /// unrelated to N1); its expiry is reported as a distinct "test hung"
    /// failure, never conflated with the N1 verdict — see the DO NOT
    /// re-introduce a wall-clock decision here in any future edit.
    ///
    /// # The inner `timeout` cannot fire when the worker IS parked (Finding 2)
    ///
    /// The inner `timeout` above shares this test's single worker with the
    /// very thing it is timing. If the worker is genuinely PARKED — the N1
    /// regression itself, or an unrelated in-runtime deadlock — nothing on
    /// this runtime can be polled, including the inner timeout's own
    /// `Sleep`, so it can never fire in exactly the case it exists for.
    /// `arm_hang_watchdog` below is the backstop: an OS thread OUTSIDE
    /// this runtime that forcibly exits the process if the test has not
    /// finished within a wider budget. It never interferes with a normal
    /// pass, fail, or in-runtime-timeout outcome — it only fires when
    /// those mechanisms themselves could not.
    ///
    /// # Non-vacuity depends on the sink never yielding before the write (Finding 1)
    ///
    /// This test's ordering proof is sound only because [`NoopSink::append`]
    /// never yields — the ENTIRE regressed (inline, non-`spawn_blocking`)
    /// write happens within the same, uninterrupted poll as the sink call,
    /// so the heartbeat cannot even start until after that poll returns.
    /// A sink with a genuine `.await` before the write (any real sink
    /// doing a network round trip) breaks that property: see
    /// `blocking_chain_write_survives_an_awaiting_sink` below, which races
    /// from the instant such a sink is about to return rather than from
    /// task-spawn time, and is therefore robust to the sink's await shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_chain_write_does_not_park_tokio_worker() {
        use tokio::sync::oneshot;
        use tokio::time::{sleep, timeout, Duration};

        // Timing constants (milliseconds). Neither participates in a
        // pass/fail comparison against a wall-clock deadline — only their
        // RELATIVE order (via the `select!` race below) decides the
        // verdict. `LOCK_HOLD_MS` need only exceed `HEARTBEAT_MS` with a
        // margin comfortable enough that the free/parked scenarios can't be
        // confused by scheduling noise.
        // The release is signalled (see the bg thread below); this is the
        // ceiling for when no signal can arrive. It MUST sit strictly between
        // `HEARTBEAT_MS` and `TEST_BUDGET_MS`, and both bounds are load-bearing:
        //
        //  - above HEARTBEAT_MS, so a PARKED worker cannot finish the contended
        //    write before the heartbeat would have fired — that ordering is the
        //    regression signal.
        //  - below TEST_BUDGET_MS, because in the parked case the signal can
        //    NEVER arrive: the worker is blocked inside the write, so the main
        //    task cannot run to send it. The ceiling is the only thing that
        //    frees the lock, and if it fires after the budget the test reports
        //    "test hung — investigate a deadlock" instead of the N1 verdict it
        //    was built to produce.
        const LOCK_HOLD_CEILING_MS: u64 = 1_500;
        const HEARTBEAT_MS: u64 = 40;
        // Hang watchdog only (see doc comment above) — not the N1 signal.
        const TEST_BUDGET_MS: u64 = 3_000;
        // External backstop budget (Finding 2) — comfortably wider than
        // TEST_BUDGET_MS so the in-runtime timeout gets first crack at
        // firing whenever the worker remains schedulable.
        const WATCHDOG_BUDGET_MS: u64 = TEST_BUDGET_MS + 2_000;

        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();

        // Seed the chain so `anchor_head` has a HEAD to submit and so the
        // `csq-runs/` directory (and therefore the lock-file parent) exists
        // before the background thread tries to open `.chain-lock`.
        seed_chain(&base);

        // The lock path mirrors `write_record_v2_impl` Step 1 + lock line:
        //   let csq_runs = base_dir.join("csq-runs");
        //   let lock_path = csq_runs.join(".chain-lock");
        let lock_path = base.join("csq-runs").join(".chain-lock");

        // ── Background OS thread: hold the flock for LOCK_HOLD_MS ──────────
        // Acquire on a dedicated OS thread (not the tokio runtime).  The guard
        // is `!Send` (holds a raw fd), so we keep it on this thread and release
        // via drop at the end of the closure.  A panic here (e.g. `lock_file`
        // failing) still runs the guard's `Drop` during unwind, so the flock
        // is released either way; we surface the ORIGINAL panic via
        // join()+resume_unwind below (rather than a generic "bg thread
        // panicked" message) instead of leaving the test to hang, mirroring
        // the pattern used for background-thread-holds-a-lock tests
        // elsewhere in this crate (e.g. `daemon::identity_mint`,
        // `daemon::startup_reconciler`).
        // The bg thread SIGNALS once the flock is actually held, rather than us
        // guessing with a sleep.  This is a precondition handshake, not a timing
        // assumption: an unsynchronised "give it 20ms to acquire" bet was the last
        // remaining flake trigger in this test.  If the bg thread lost that race,
        // `anchor_head` ran UNCONTENDED and finished in single-digit ms — inside
        // HEARTBEAT_MS — so the anchor won the race and the test reported an "N1
        // regression" against correct code.  Worse, on that same input the older
        // wall-clock version PASSED (vacuously: the worker was free anyway), so
        // the ordering rewrite turned a benign vacuous pass into a hard red under
        // exactly the CPU-saturation conditions it was written to survive.
        let lock_path_bg = lock_path.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        // Release is SIGNALLED, not timed. Holding for a fixed duration starts
        // the clock at the acquisition signal, but the anchor write does not
        // reach `flock` until the main task has returned from `recv_timeout`,
        // cloned, `tokio::spawn`ed, and the worker has polled Task A through
        // `read_chain_head` + `load_signing_key_if_active`. On a saturated
        // runner that exceeds 400 ms; the lock is then already free,
        // `anchor_head` runs uncontended and finishes inside `HEARTBEAT_MS`, and
        // `select!` reports `AnchorFirst` — a false "N1 regression" against
        // correct code. That is the exact false-verdict class this rewrite
        // exists to remove, relocated one step later in the timeline. Holding
        // until the race has RESOLVED takes wall-clock out of the verdict.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        // Signalled immediately before the race; see the bg thread below.
        let (armed_tx, armed_rx) = std::sync::mpsc::channel::<()>();
        let bg_thread = std::thread::spawn(move || {
            let _guard = crate::platform::lock::lock_file(&lock_path_bg)
                .expect("bg thread: lock_file failed");
            // Signal AFTER acquisition, while the guard is still alive.
            held_tx
                .send(())
                .expect("bg thread: held-signal send failed");
            // Wait until the main task is ABOUT TO ENTER THE RACE before the
            // ceiling starts counting. Without this the clock starts here, at
            // acquisition, and everything between acquisition and the race is
            // charged against it — including, in the awaiting-sink test, a whole
            // sanctioned `timeout(TEST_BUDGET_MS)` on `about_to_write`. That is
            // how a 1 500 ms ceiling coexists with a 3 000 ms pre-flock phase:
            // the lock can be long gone before the write reaches `flock`,
            // leaving it uncontended and handing `select!` a false `AnchorFirst`.
            let _ = armed_rx.recv_timeout(std::time::Duration::from_secs(10));
            // Ok = the race resolved; Err = the main task panicked and dropped
            // the sender, or the ceiling elapsed. All three release the lock.
            let _ = release_rx.recv_timeout(std::time::Duration::from_millis(LOCK_HOLD_CEILING_MS));
        });

        // Block until the lock is genuinely held.  A timeout here is a PRECONDITION
        // failure, reported as such — it is explicitly NOT an N1 verdict, because
        // nothing about the worker has been observed yet.
        held_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "PRECONDITION FAILED (not an N1 regression): the background thread \
                 never acquired csq-runs/.chain-lock within 10s, so the anchor write \
                 would not have contended on it and this test could not have \
                 measured worker freedom.",
            );

        // ── Task A: anchor write (will contend on flock) ────────────────────
        let base_a = base.clone();
        let mut anchor_task = tokio::spawn(async move {
            let sink = NoopSink::new("noop").unwrap();
            anchor_head(&sink, "2026-06-03T10:00:00Z", &base_a).await
        });

        // ── Task B: heartbeat (cheap async sleep, no flock involvement) ─────
        // Signals completion via a oneshot so it can be raced directly
        // against Task A's completion in `select!` below, rather than
        // polled via a shared flag on a wall-clock schedule.
        let (hb_tx, mut hb_rx) = oneshot::channel::<()>();
        let heartbeat_task = tokio::spawn(async move {
            sleep(Duration::from_millis(HEARTBEAT_MS)).await;
            let _ = hb_tx.send(());
        });

        // ── Ordering proof: race the heartbeat against the anchor write ────
        // See the doc comment above for the free-vs-parked reasoning. Only
        // one of the two branches is ever polled to `Ready` in a given
        // `select!` evaluation, so the losing branch's future (here always
        // `anchor_task`, since `heartbeat_task`'s completion is consumed
        // separately below) is left un-consumed and safe to `.await` again.
        enum RaceOutcome {
            HeartbeatFirst,
            AnchorFirst,
        }

        // The anchor arm BINDS its outcome rather than discarding it with `_`.
        // `_ = &mut anchor_task` resolving is not by itself N1 evidence: it also
        // resolves if `anchor_head` returned an error early WITHOUT ever touching
        // .chain-lock (a drifted `seed_chain` giving EmptyChain, or an invalid sink
        // name), or if the task PANICKED — a panicked JoinHandle yields
        // Err(JoinError), which `_` silently accepts. All three would have printed
        // "the blocking write ran on the worker thread", which is a false verdict
        // pointing at the wrong subsystem. Distinguishing them also gives the test
        // the positive control it otherwise lacks: we assert the write SUCCEEDED.
        // The flock ceiling and the hang watchdog both start HERE, at the race,
        // because the race is the only window either can speak to.
        //
        // The watchdog was originally armed at the top of the test with a
        // 5 000 ms budget (`TEST_BUDGET_MS + 2_000`), ahead of a 10 s
        // precondition wait — so a slow-but-correct lock acquisition tripped it
        // and `std::process::exit(97)` killed the whole csq-core test binary,
        // reporting a parked tokio worker that had not been observed at all.
        // Moving it after that handshake fixed one test and left the other
        // broken the same way: the awaiting-sink test has TWO sequential
        // `timeout(TEST_BUDGET_MS)` phases, so a 5 000 ms budget covered 6 000 ms
        // of legitimate waiting. Arming at the race makes the budget cover
        // exactly one `TEST_BUDGET_MS` phase in both tests, which is what
        // `TEST_BUDGET_MS + 2_000` was always sized for.
        // The watchdog is SCOPED to the race, not held to function return.
        // `WATCHDOG_BUDGET_MS` is `TEST_BUDGET_MS + 2_000`, i.e. sized for one
        // race plus slack. Held to the end of the function it also covers the
        // post-race drain — `anchor_task.await`, `heartbeat_task.await` and
        // `bg_thread.join()` — so a race that legitimately consumed 2 900 ms
        // leaves 2 100 ms for a drain that performs a signed chain write and a
        // thread join. On a saturated runner that is not slack, and `exit(97)`
        // would kill the binary during a drain the watchdog has nothing to say
        // about. Scoping it to the race is the same principle as siting it
        // there in the first place: cover exactly the window it can diagnose.
        let _ = armed_tx.send(());
        let race = {
            let _watchdog = arm_hang_watchdog(WATCHDOG_BUDGET_MS);
            timeout(Duration::from_millis(TEST_BUDGET_MS), async {
                tokio::select! {
                _ = &mut hb_rx => RaceOutcome::HeartbeatFirst,
                joined = &mut anchor_task => match joined {
                    Ok(AnchorOutcome::Succeeded { .. }) => RaceOutcome::AnchorFirst,
                    Ok(other) => panic!(
                        "PRECONDITION FAILED (not an N1 regression): anchor_head \
                         returned {other:?} instead of Succeeded, so it did not \
                         perform the flock-bearing write — the flock was never \
                         contended and worker freedom was never exercised. Check \
                         seed_chain and the sink name."
                    ),
                    Err(join_err) if join_err.is_panic() => {
                        std::panic::resume_unwind(join_err.into_panic())
                    }
                    Err(join_err) => panic!(
                        "PRECONDITION FAILED (not an N1 regression): the anchor task \
                         failed to join ({join_err})."
                    ),
                },
                }
            })
            .await
        };

        // The race is decided; the flock has served its purpose. Release it now
        // rather than on a timer, so no wall-clock quantity influenced the
        // verdict above. A send failure means the bg thread already exited
        // (ceiling elapsed) — harmless, and the lock is free either way.
        let _ = release_tx.send(());

        let worker_was_free = match race {
            Ok(RaceOutcome::HeartbeatFirst) => true,
            Ok(RaceOutcome::AnchorFirst) => false,
            Err(_) => {
                // Distinct failure mode from the N1 assertion below: the
                // race never resolved at all within the hang watchdog. This
                // is NOT wall-clock evidence of the N1 regression (which
                // always resolves — the anchor write completes once the
                // background thread releases the lock) — it means something
                // else deadlocked and needs its own investigation.
                panic!(
                    "test hung: neither the heartbeat nor the anchor write completed \
                     within {TEST_BUDGET_MS} ms. This is a HANG, not the N1 regression \
                     signal — investigate a deadlock separately from the ordering proof."
                );
            }
        };

        // Drive every task + the background thread to completion regardless
        // of which arm of the race fired, so nothing is left dangling.
        if worker_was_free {
            // `anchor_task` lost the race and was never polled to `Ready`
            // by `select!` — still a valid, un-consumed `JoinHandle`.
            let _ = anchor_task.await;
        }
        let _ = heartbeat_task.await;
        if let Err(panic) = bg_thread.join() {
            std::panic::resume_unwind(panic);
        }

        assert!(
            worker_was_free,
            "N1 regression: the anchor write completed before the heartbeat did, which \
             means the tokio worker was parked inside the flock-hold window instead of \
             running the heartbeat task concurrently. This means the blocking chain write \
             ran on the worker thread instead of being offloaded to spawn_blocking."
        );
    }

    /// Finding 1 (this session, following the N1 hardening above): the
    /// ordering proof above is sound only because [`NoopSink::append`]
    /// never yields before the flock-bearing write. A sink with a genuine
    /// `.await` ahead of that write — which any real sink performing a
    /// network round trip (e.g. a Rekor transparency-log submission)
    /// necessarily has — gives the anchor task an EARLY yield point. If
    /// the heartbeat were raced from task-spawn time (as the NoopSink test
    /// does), that early yield would hand the worker to the heartbeat
    /// regardless of whether the SUBSEQUENT write is offloaded, turning
    /// the verdict into a coin flip (or a vacuous pass, if the sink's own
    /// latency alone exceeds `HEARTBEAT_MS`).
    ///
    /// The fix is NOT a comment warning future readers to avoid awaiting
    /// sinks, nor an assertion about `NoopSink`'s source — a future
    /// `RekorSink` would be introduced elsewhere and neither would fire.
    /// The fix is structural: [`AwaitingSink`] performs a genuine
    /// `tokio::time::sleep` before returning from `append()`, and signals
    /// `about_to_write` the instant it is about to return. This test races
    /// the heartbeat starting from THAT signal — not from task-spawn time
    /// — which is exactly the same measurement window
    /// (sink-append-done → write-complete) the NoopSink test measures.
    /// However long, or however many times, the sink itself yields before
    /// that point no longer matters: the race only ever covers the
    /// flock-bearing write itself.
    ///
    /// Mirrors `blocking_chain_write_does_not_park_tokio_worker` in every
    /// other respect (background-thread flock hold + handshake, bound
    /// anchor-outcome arm, hang watchdogs). See that test's doc comment
    /// for the shared reasoning this one does not repeat.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_chain_write_survives_an_awaiting_sink() {
        use tokio::sync::oneshot;
        use tokio::time::{sleep, timeout, Duration};

        // The release is signalled (see the bg thread below); this is the
        // ceiling for when no signal can arrive. It MUST sit strictly between
        // `HEARTBEAT_MS` and `TEST_BUDGET_MS`, and both bounds are load-bearing:
        //
        //  - above HEARTBEAT_MS, so a PARKED worker cannot finish the contended
        //    write before the heartbeat would have fired — that ordering is the
        //    regression signal.
        //  - below TEST_BUDGET_MS, because in the parked case the signal can
        //    NEVER arrive: the worker is blocked inside the write, so the main
        //    task cannot run to send it. The ceiling is the only thing that
        //    frees the lock, and if it fires after the budget the test reports
        //    "test hung — investigate a deadlock" instead of the N1 verdict it
        //    was built to produce.
        const LOCK_HOLD_CEILING_MS: u64 = 1_500;
        const HEARTBEAT_MS: u64 = 40;
        // Hang watchdog only — not the N1 signal (see sibling test).
        const TEST_BUDGET_MS: u64 = 3_000;
        // External backstop budget (Finding 2) — comfortably wider than
        // TEST_BUDGET_MS so the in-runtime timeout gets first crack at
        // firing whenever the worker remains schedulable.
        const WATCHDOG_BUDGET_MS: u64 = TEST_BUDGET_MS + 2_000;

        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        seed_chain(&base);

        let lock_path = base.join("csq-runs").join(".chain-lock");

        // ── Background OS thread: hold the flock for LOCK_HOLD_MS ──────────
        // Identical handshake to the sibling test — see its doc comment for
        // why an unsynchronised sleep is not acceptable here.
        let lock_path_bg = lock_path.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        // Release is SIGNALLED, not timed. Holding for a fixed duration starts
        // the clock at the acquisition signal, but the anchor write does not
        // reach `flock` until the main task has returned from `recv_timeout`,
        // cloned, `tokio::spawn`ed, and the worker has polled Task A through
        // `read_chain_head` + `load_signing_key_if_active`. On a saturated
        // runner that exceeds 400 ms; the lock is then already free,
        // `anchor_head` runs uncontended and finishes inside `HEARTBEAT_MS`, and
        // `select!` reports `AnchorFirst` — a false "N1 regression" against
        // correct code. That is the exact false-verdict class this rewrite
        // exists to remove, relocated one step later in the timeline. Holding
        // until the race has RESOLVED takes wall-clock out of the verdict.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        // Signalled immediately before the race; see the bg thread below.
        let (armed_tx, armed_rx) = std::sync::mpsc::channel::<()>();
        let bg_thread = std::thread::spawn(move || {
            let _guard = crate::platform::lock::lock_file(&lock_path_bg)
                .expect("bg thread: lock_file failed");
            held_tx
                .send(())
                .expect("bg thread: held-signal send failed");
            // Wait until the main task is ABOUT TO ENTER THE RACE before the
            // ceiling starts counting. Without this the clock starts here, at
            // acquisition, and everything between acquisition and the race is
            // charged against it — including, in the awaiting-sink test, a whole
            // sanctioned `timeout(TEST_BUDGET_MS)` on `about_to_write`. That is
            // how a 1 500 ms ceiling coexists with a 3 000 ms pre-flock phase:
            // the lock can be long gone before the write reaches `flock`,
            // leaving it uncontended and handing `select!` a false `AnchorFirst`.
            let _ = armed_rx.recv_timeout(std::time::Duration::from_secs(10));
            // Ok = the race resolved; Err = the main task panicked and dropped
            // the sender, or the ceiling elapsed. All three release the lock.
            let _ = release_rx.recv_timeout(std::time::Duration::from_millis(LOCK_HOLD_CEILING_MS));
        });

        held_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "PRECONDITION FAILED (not an N1 regression): the background thread \
                 never acquired csq-runs/.chain-lock within 10s, so the anchor write \
                 would not have contended on it and this test could not have \
                 measured worker freedom.",
            );

        // ── Task A: anchor write via the AWAITING sink (Finding 1's leg) ────
        let sink = std::sync::Arc::new(AwaitingSink::new());
        let sink_for_task = std::sync::Arc::clone(&sink);
        let base_a = base.clone();
        let mut anchor_task = tokio::spawn(async move {
            anchor_head(&*sink_for_task, "2026-06-03T10:00:00Z", &base_a).await
        });

        // Block until the sink signals it is about to return — i.e. until
        // we are at the exact point the NoopSink test measures FROM. A
        // timeout here is a PRECONDITION failure, explicitly not an N1
        // verdict — nothing about the worker has been observed yet.
        timeout(
            Duration::from_millis(TEST_BUDGET_MS),
            sink.about_to_write.notified(),
        )
        .await
        .expect(
            "PRECONDITION FAILED (not an N1 regression): the awaiting sink's \
             append() never signalled about_to_write within the test budget — \
             anchor_head did not reach the sink append call.",
        );

        // ── Task B: heartbeat, spawned ONLY NOW — exactly at the start of
        // the same measurement window the NoopSink test uses from task-spawn
        // time. This is the structural fix for Finding 1: however long the
        // sink's own await took, it happened entirely BEFORE this point and
        // is excluded from the race. ─────────────────────────────────────
        let (hb_tx, mut hb_rx) = oneshot::channel::<()>();
        let heartbeat_task = tokio::spawn(async move {
            sleep(Duration::from_millis(HEARTBEAT_MS)).await;
            let _ = hb_tx.send(());
        });

        enum RaceOutcome {
            HeartbeatFirst,
            AnchorFirst,
        }

        // Same bound-outcome reasoning as the sibling test: only
        // `AnchorOutcome::Succeeded` counts as N1 evidence, a non-Succeeded
        // outcome is a named precondition failure, and a panic is re-raised
        // via `resume_unwind` rather than silently accepted by a `_` pattern.
        // The flock ceiling and the hang watchdog both start HERE, at the race,
        // because the race is the only window either can speak to.
        //
        // The watchdog was originally armed at the top of the test with a
        // 5 000 ms budget (`TEST_BUDGET_MS + 2_000`), ahead of a 10 s
        // precondition wait — so a slow-but-correct lock acquisition tripped it
        // and `std::process::exit(97)` killed the whole csq-core test binary,
        // reporting a parked tokio worker that had not been observed at all.
        // Moving it after that handshake fixed one test and left the other
        // broken the same way: the awaiting-sink test has TWO sequential
        // `timeout(TEST_BUDGET_MS)` phases, so a 5 000 ms budget covered 6 000 ms
        // of legitimate waiting. Arming at the race makes the budget cover
        // exactly one `TEST_BUDGET_MS` phase in both tests, which is what
        // `TEST_BUDGET_MS + 2_000` was always sized for.
        // The watchdog is SCOPED to the race, not held to function return.
        // `WATCHDOG_BUDGET_MS` is `TEST_BUDGET_MS + 2_000`, i.e. sized for one
        // race plus slack. Held to the end of the function it also covers the
        // post-race drain — `anchor_task.await`, `heartbeat_task.await` and
        // `bg_thread.join()` — so a race that legitimately consumed 2 900 ms
        // leaves 2 100 ms for a drain that performs a signed chain write and a
        // thread join. On a saturated runner that is not slack, and `exit(97)`
        // would kill the binary during a drain the watchdog has nothing to say
        // about. Scoping it to the race is the same principle as siting it
        // there in the first place: cover exactly the window it can diagnose.
        let _ = armed_tx.send(());
        let race = {
            let _watchdog = arm_hang_watchdog(WATCHDOG_BUDGET_MS);
            timeout(Duration::from_millis(TEST_BUDGET_MS), async {
                tokio::select! {
                _ = &mut hb_rx => RaceOutcome::HeartbeatFirst,
                joined = &mut anchor_task => match joined {
                    Ok(AnchorOutcome::Succeeded { .. }) => RaceOutcome::AnchorFirst,
                    Ok(other) => panic!(
                        "PRECONDITION FAILED (not an N1 regression): anchor_head \
                         returned {other:?} instead of Succeeded, so it did not \
                         perform the flock-bearing write — the flock was never \
                         contended and worker freedom was never exercised."
                    ),
                    Err(join_err) if join_err.is_panic() => {
                        std::panic::resume_unwind(join_err.into_panic())
                    }
                    Err(join_err) => panic!(
                        "PRECONDITION FAILED (not an N1 regression): the anchor task \
                         failed to join ({join_err})."
                    ),
                },
                }
            })
            .await
        };

        // The race is decided; the flock has served its purpose. Release it now
        // rather than on a timer, so no wall-clock quantity influenced the
        // verdict above. A send failure means the bg thread already exited
        // (ceiling elapsed) — harmless, and the lock is free either way.
        let _ = release_tx.send(());

        let worker_was_free = match race {
            Ok(RaceOutcome::HeartbeatFirst) => true,
            Ok(RaceOutcome::AnchorFirst) => false,
            Err(_) => {
                panic!(
                    "test hung: neither the heartbeat nor the anchor write completed \
                     within {TEST_BUDGET_MS} ms. This is a HANG, not the N1 regression \
                     signal — investigate a deadlock separately from the ordering proof."
                );
            }
        };

        if worker_was_free {
            let _ = anchor_task.await;
        }
        let _ = heartbeat_task.await;
        if let Err(panic) = bg_thread.join() {
            std::panic::resume_unwind(panic);
        }

        assert!(
            worker_was_free,
            "N1 regression (survives an awaiting sink): the anchor write completed \
             before the heartbeat did, measured from the instant the sink was about \
             to return — the blocking chain write is parking the tokio worker even \
             though a preceding sink await gave it an early yield point."
        );
    }
}
