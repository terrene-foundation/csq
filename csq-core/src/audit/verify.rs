//! Chain-integrity verifier (M05, spec 12 §12.13).
//!
//! [`verify_chain`] walks every record in `<base_dir>/csq-runs/<chain_id>.jsonl`
//! and checks:
//!
//! 1. **Unbroken hash chain** — `record[n].prev_hash == sha256(canonical(record[n-1]))`.
//! 2. **Strictly-monotonic `seq`** — each record's `seq` is exactly `prev_seq + 1`.
//! 3. **Consistent `chain_id`** — every record's `chain_id` matches `chain.json`.
//! 4. **`canonical_hash` recomputed** — for every record the verifier recomputes
//!    `sha256(canonical_bytes_for(record_with_canonical_hash_set_to_genesis_sentinel))`
//!    and asserts it equals `record.canonical_hash` (R1-SEC-2 / R1-DEEP-7 fix).
//! 5. **Valid Ed25519 signature** — signature over the 32 raw bytes of the
//!    recomputed `canonical_hash` verified against the public key for
//!    `signing_key_id` read from the keychain via M04's [`LocalSigningKey`]
//!    (or the historical-key slot for rotated keys).
//!    Records with `seq < signing_active_since_seq` (or `None`) that carry
//!    the placeholder key are accepted without signature verification
//!    (pre-`csq audit init` migration concession). Records with
//!    `seq >= signing_active_since_seq` carrying the placeholder key are
//!    REJECTED with `LedgerError::UnsignedRecordAfterCutoff` (R1-DEEP-2 fix).
//!    The head record (newest) with signing active MUST carry a real signature
//!    (R1-SEC-1 fix — the prev_hash chain never covers the head).
//!
//! # Unified signing contract (R1-SEC-4 fix)
//!
//! Writer (`rotate.rs` / any future signing site) and verifier agree on:
//!
//! ```text
//! canonical_hash := sha256( canonical_bytes_for( record_with_canonical_hash := genesis_sentinel ) )
//! signature      := Ed25519_sign( privkey, <32 raw bytes of canonical_hash> )
//! ```
//!
//! Verification:
//! 1. Recompute `canonical_hash` from content; assert equals stored value.
//! 2. `verify_strict( pubkey, <32 raw bytes of recomputed canonical_hash>, signature )`.
//!
//! Signing the raw 32-byte digest (not the 64-char hex string) is the only
//! construction where the signature authenticates the record's actual content
//! rather than a textual representation of a hash.
//!
//! # Record-limit behaviour (R1-DEEP-3 fix)
//!
//! The `record_limit` bound is applied to the TAIL (newest records). All lines
//! are read into memory, the last `record_limit` non-v1 lines are selected, and
//! verification proceeds oldest-to-newest within that window. The head record
//! is always in the verified window. Records older than the limit are skipped
//! with a `audit_verify_limit_exceeded` WARN.
//!
//! # `--since` behaviour (R1-IR-1 fix)
//!
//! `since_seq` is accepted syntactically but is treated as `None` (verify all).
//! The previous implementation anchored the chain walk at an arbitrary seq,
//! causing the first surviving record to hit the genesis-seq-must-be-0 check
//! and return `IntegrityBroken`. Correct `--since` support requires loading the
//! record at `since_seq - 1` to seed `prev_hash`. That look-behind is deferred;
//! callers wishing partial verification should pass `None` and use `record_limit`
//! instead. The `since` parameter is accepted (not rejected) for forward-compat.
//!
//! v1 records (lines where parsing as [`SignedRecord`] fails and the raw JSON
//! contains `"schema_version":"1"`) are SKIPPED and counted in the
//! `skipped_v1_count` summary. A single summary log `audit_verify_skipped_v1_records_total`
//! is emitted (not one log per record). See spec 12 §12.13 For-Discussion #1 resolution.
//!
//! The verifier is called from:
//! - **Daemon startup** (M05 PRIMARY DIRECTIVE): before socket bind.
//! - **`csq audit verify` CLI** (M05): operator-facing chain health check.
//!
//! # Sentinel decision (per M05 directive)
//!
//! M05 does NOT introduce a persistent sentinel file for chain-broken state.
//! `verify_chain` runs at every daemon start and exits on failure — no
//! on-disk flag is needed because every start re-verifies. The
//! `sentinel-clearing-parity.md` rule is vacuously satisfied: no sentinel
//! is introduced, so there are no setter/clearer pairs to wire.

use crate::audit::authority::registry::{resolve_registry, AuthorityRegistry};
use crate::audit::key_custody::chain_state::ChainState;
use crate::audit::key_custody::keyring_backend::{
    is_keychain_access_error, load_embedded_cutoff, load_embedded_cutoff_file_first,
    try_load_signing_key, EmbeddedCutoff, KeyLoadOutcome,
};
use crate::audit::key_custody::KeyCustodyError;
use crate::audit::key_custody::{file_store, KeySlot};
use crate::audit::multi_sig::verify_record_multi_sig;
use crate::audit::persist::{canonical_bytes_for, sha256_hex, ChainKind};
use crate::audit::traits::SigningKey;
use crate::audit::types::{KeyId, LedgerError, RedactedString, Sha256Hex, SignedRecord};
use ed25519_dalek::{Signature, VerifyingKey};
use std::path::Path;
use tracing::{error, info, warn};

/// Placeholder key sentinel string — hoisted to a constant so string realloc
/// does not occur per record (R1-IR-4 fix).
const PLACEHOLDER_KEY_ID: &str = concat!(
    "ed25519:",
    "0000000000000000000000000000000000000000000000000000000000000000"
);

/// Configuration for a verification run.
///
/// Constructed by the daemon startup or `csq audit verify` CLI.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Maximum number of records to verify. Records beyond this limit are
    /// skipped. The limit applies to the TAIL (newest records); the head is
    /// always in the verified window (R1-DEEP-3 fix).
    ///
    /// Default: 10,000 (spec 12 §12.13 — sufficient for 30 days of daily csq use).
    pub record_limit: usize,
    /// Keychain service name (production: `csq-audit-signing`; tests: sandbox name).
    pub keychain_service: String,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            record_limit: 10_000,
            keychain_service: crate::audit::AUDIT_SIGNING_SERVICE_NAME.to_string(),
        }
    }
}

/// A contiguous run of records whose signatures were skipped because the
/// signing key that produced them is a historical (rotated-out) key no longer
/// present in the keychain.
///
/// Chain-linking checks (prev_hash / canonical_hash / seq-monotonic) are still
/// performed across and after the gap — only per-record signature verification
/// is skipped for these records. Insertion, reordering, or truncation of
/// historical records is therefore still detected.
///
/// Gaps are accumulated in [`VerifySummary::historical_key_gaps`] when the
/// missing key's ID differs from `chain.json`'s current active `signing_key_id`.
/// A missing *current* key still produces a fatal `LedgerError::KeyNotFound`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeyGap {
    /// The `key_id` that was required but not found in the keychain.
    pub key_id: String,
    /// Sequence number of the first record in this gap run.
    pub first_seq: u64,
    /// Sequence number of the last record in this gap run.
    pub last_seq: u64,
    /// Total number of records in this gap run.
    pub count: u64,
}

/// Summary returned by a successful (or partial) verification run.
#[derive(Debug, Clone, Default)]
pub struct VerifySummary {
    /// Number of v2 records that were chain-linked without error.
    ///
    /// This count includes historical-key gap records whose chain-linking
    /// (Checks 1-4: chain_id, seq, prev_hash, canonical_hash) was verified
    /// but whose Ed25519 signatures were skipped due to the rotated-out key
    /// being absent from the keychain. To compute the number of records that
    /// were BOTH chain-linked AND signature-verified, subtract the total
    /// `count` across all entries in `historical_key_gaps` from this field.
    pub verified_count: u64,
    /// Number of v1 records skipped (not v2 chain records).
    pub skipped_v1_count: u64,
    /// GH #910 — number of records that carried an `EventKind` this build does
    /// not know (written by a NEWER csq) and were verified OPAQUE-BUT-INTACT:
    /// their signature + hash-chain verified, but their typed payload semantics
    /// were deferred. These records ARE included in `verified_count` (they passed
    /// every integrity check); this field surfaces how many were opaque so
    /// operator/compliance surfaces can report "chain intact; N records newer
    /// than this reader" rather than silently under- or over-counting. `0` for a
    /// chain with no forward records — the common case.
    pub unknown_kind_count: u64,
    /// Number of records skipped because the record limit was reached
    /// (these are the oldest records, not the newest — limit applies to tail).
    pub limit_exceeded_count: u64,
    /// Highest verified sequence number (or 0 if no records exist).
    pub head_seq: u64,
    /// Historical (rotated-out) key gaps: signature verification was skipped
    /// for these records because the signing key is no longer in the keychain
    /// but is NOT the chain's current active key. Chain-linking was still
    /// verified end-to-end including across these gaps.
    ///
    /// Empty for a fully-verified chain. Non-empty indicates
    /// "verified-current-segment with historical gaps" status.
    pub historical_key_gaps: Vec<KeyGap>,
    /// Keychain integrity-anchor status for this run (DETECTOR, never fatal —
    /// see [`KeychainAnchorStatus`]). `Confirmed` = file/keychain agree;
    /// `Unconfirmed` = anchor not read+compared (keychain locked / absent /
    /// legacy — forge-resistance was file-only this run); `Mismatch` = file /
    /// keychain / chain.json disagree (possible tampering). Surfaced by
    /// `csq doctor` / `csq daemon status`; does NOT change `AuditHealth` or
    /// `is_operational()`.
    pub keychain_anchor: KeychainAnchorStatus,
    /// Keychain `roster_version_floor` anchor status for this run (DETECTOR,
    /// never fatal — see [`RosterFloorAnchorStatus`]).
    ///
    /// `Confirmed` = keychain and `chain.json` floors agree;
    /// `Unconfirmed` = no keychain entry, keychain locked, or no roster
    /// installed (floor is `None` in both sources — nothing to compare);
    /// `Mismatch` = keychain floor differs from `chain.json` floor (possible
    /// rollback attempt). Surfaced by `csq doctor`; NEVER changes
    /// `AuditHealth` or `is_operational()`.
    ///
    /// `None` when no roster is installed (`chain.json` `roster_version_floor`
    /// is `None`). Serialized as `null` / omitted in doctor output via
    /// `#[serde(skip_serializing_if = "Option::is_none")]` at the doctor layer.
    pub roster_floor_anchor: RosterFloorAnchorStatus,
    /// Whether `chain.json` carries a `roster_version_floor` at all — i.e.
    /// whether a roster has ever been installed. Consumers (doctor) gate the
    /// floor-anchor field on this so a no-roster install omits it instead of
    /// reporting a vacuous `confirmed` (default `false`).
    pub roster_floor_present: bool,
    /// M3a — cutoff-aware verification-levels-populated signal.
    ///
    /// `true` when the chain contains at least one record with an explicit
    /// `verification_level` AND all records after (and including) that first
    /// leveled record also carry a level. Pre-M3a records (no level) that form
    /// a contiguous prefix are exempt — the cutoff is the seq of the FIRST
    /// record that carries a level.
    ///
    /// Empty chains (`verified_count == 0`) and chains where no record has
    /// ever been leveled both return `false`.
    ///
    /// Sourced by `crate::audit::trust_grade::grade_for_verify_result` to
    /// advance the grade from `COMPATIBLE` → `CONFORMANT`.
    pub verification_levels_populated: bool,
    /// M3a — per-level record count (enterprise only).
    ///
    /// Maps canonical-string level names (`"AUTO_APPROVED"`, etc. — the
    /// UPPERCASE wire form emitted by `VerificationLevel::as_canonical_str`) to
    /// the number of records in this verification run that carry that level.
    /// Empty when no records carry a level (pre-M3a chains). Only populated
    /// by enterprise builds; the community build always leaves this empty.
    #[cfg(feature = "enterprise")]
    pub verification_level_summary: std::collections::BTreeMap<String, u64>,
}

/// Verifies the integrity of the on-disk chain under `base_dir`.
///
/// Returns `Ok(summary)` on clean verification; returns `Err(LedgerError)`
/// for any integrity violation. The first violation causes an early return —
/// no further records are checked after a failure.
///
/// # `base_dir`
///
/// This is `~/.claude/accounts` in production. `chain.json` is read from
/// `<base_dir>/csq-runs/chain.json`. If `chain.json` does not exist (no v2
/// records have been written yet), the function returns `Ok` with all counts
/// at zero — there is nothing to verify.
///
/// # `since_seq`
///
/// Currently treated as `None` regardless of the value passed. Correct
/// `--since` support requires a look-behind to anchor `prev_hash`; that is
/// deferred. See module-level doc.
///
/// Outcome of cross-checking the file-store seed against the OS keychain
/// integrity anchor during `verify_chain` Step-0.
///
/// # The keychain anchor is a DETECTOR, not a brick-gate
///
/// The signing seed lives in a 0o600 file the daemon reads non-interactively;
/// that same file is readable AND writable by any same-UID process. So the
/// file-mirror design does NOT make the signing key confidential against a
/// same-UID attacker — per the chain's pre-existing SEC-1 boundary, an attacker
/// who holds the live key forges regardless (and here the key is in the file).
/// The keychain — which a same-UID attacker can DELETE but cannot silently
/// REWRITE — is retained as a TAMPER DETECTOR: when readable, the file's
/// `(cutoff, key_id)` is cross-checked against it.
///
/// Per the chain owner's chosen posture (never-brick + optimistic-sign:
/// availability over realtime integrity), an anchor anomaly NEVER fails the
/// chain (no `Broken`, no durable `.chain-broken` sentinel — that is the brick
/// this whole change exists to eliminate). It is SURFACED instead: `Mismatch`
/// logs at ERROR and `csq doctor` shows a loud alarm. The ONLY remaining fatal
/// in this resolution is a corrupt FILE seed (genuine local seed damage,
/// recoverable via `csq audit repair`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeychainAnchorStatus {
    /// File and keychain were both read and AGREE on `(cutoff, key_id)` — full
    /// forge-detection coverage this run. (Also the N/A default for a chain
    /// with no signing key.)
    #[default]
    Confirmed,
    /// The keychain anchor could not be read+compared this run — locked /
    /// access-denied (the daemon's normal state), genuinely absent (`NoEntry` —
    /// file-only install, completed migration, OR a deleted anchor), or legacy
    /// bare-hex (no embedded cutoff). Forge-resistance was file-only this run.
    /// Run `csq audit migrate-keys` (interactive) to (re)establish the anchor.
    /// NON-fatal.
    Unconfirmed,
    /// The file and the keychain DISAGREE on `(cutoff, key_id)`, OR the keychain
    /// entry is corrupt/planted, OR chain.json disagrees with the seed. Possible
    /// tampering — surfaced loudly (ERROR log + `csq doctor` alarm) but NON-fatal
    /// (detector, not gate). The chain owner MUST investigate.
    Mismatch,
}

/// Keychain anchor status for the `roster_version_floor` field.
///
/// Mirrors [`KeychainAnchorStatus`] in semantics and serialization; separated
/// into its own type so callers can distinguish the two anchor surfaces via the
/// type system.
///
/// Written by the roster-install path (best-effort, non-fatal). Pre-existing
/// keychain entries that predate this field return `None` for
/// `EmbeddedCutoff::roster_version_floor`, which surfaces here as `Unconfirmed`.
///
/// # Detector — never bricks
///
/// `Mismatch` logs at ERROR and surfaces in `csq doctor`, but NEVER fails
/// `verify_chain`, never sets a sentinel, and never changes `AuditHealth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RosterFloorAnchorStatus {
    /// The keychain and `chain.json` both have a `roster_version_floor` value
    /// and they AGREE. Full rollback-detection coverage this run.
    ///
    /// Also used when both sources have `None` (no roster installed — nothing
    /// to disagree about).
    #[default]
    Confirmed,
    /// The keychain anchor could not be read this run (locked / absent /
    /// no entry / legacy), OR exactly one source has `None` and the other
    /// does not (partial install state). Rollback-detection is `chain.json`-only
    /// this run. NON-fatal.
    Unconfirmed,
    /// The keychain `roster_version_floor` EXISTS, is readable, and DISAGREES
    /// with `chain.json` `roster_version_floor`. Possible rollback of `chain.json`
    /// to a version that predates the installed roster. Surfaced loudly (ERROR log
    /// + `csq doctor` alarm) but NON-fatal (detector, not gate).
    Mismatch,
}

/// Resolve the authoritative signing cutoff from the FILE store (daemon-readable
/// primary) and report the keychain anchor status. READ-ONLY (spec §12.13.9).
///
/// Returns `(cutoff, anchor_status)`. The keychain anchor is a DETECTOR — see
/// [`KeychainAnchorStatus`]; anchor anomalies are reported via the status, never
/// as a fatal `Err`. The sole `Err` is a corrupt FILE seed (local damage).
#[allow(clippy::too_many_arguments)]
fn resolve_authoritative_cutoff(
    chain_id: &str,
    chain_json_key_id: &KeyId,
    chain_json_cutoff: Option<u64>,
    file_present: bool,
    file_ec: Result<Option<EmbeddedCutoff>, KeyCustodyError>,
    keychain_ec: Result<Option<EmbeddedCutoff>, KeyCustodyError>,
) -> Result<(Option<u64>, KeychainAnchorStatus), LedgerError> {
    use KeychainAnchorStatus::*;

    // Does an embedded cutoff agree with chain.json's (cutoff, key_id)?
    let agrees_with_chain_json = |ec: &EmbeddedCutoff| -> bool {
        chain_json_cutoff == Some(ec.signing_active_since_seq)
            && chain_json_key_id.as_str() == ec.signing_key_id
    };

    // A corrupt FILE seed (present but unparseable) is genuine LOCAL seed damage
    // (not a keychain-anchor anomaly) → fatal, recoverable via `csq audit repair`.
    let file_ec = match file_ec {
        Ok(opt) => opt,
        Err(_) => {
            return Err(LedgerError::Io {
                context: RedactedString::from_trusted(
                    "audit seed file is present but unreadable (corrupt) — run `csq audit repair`",
                ),
                source: std::io::Error::other("file seed present but not parseable"),
            });
        }
    };

    if file_present {
        match file_ec {
            // FILE present, new JSON → the daemon-readable PRIMARY seed source.
            Some(fec) => {
                // The file/chain.json disagreement is a half-written or tampered
                // state — flagged via Mismatch below.
                let chain_json_ok = agrees_with_chain_json(&fec);
                // Cutoff selection + anchor cross-check. Prefer the KEYCHAIN
                // cutoff when the keychain is READABLE: it is the un-writable
                // trustworthy source, so using it actively DEFEATS a
                // file/chain.json cutoff-raise (the placeholder records the
                // attacker re-opened are rejected at the real cutoff). Fall back
                // to the file cutoff only when the keychain is blocked/absent.
                let (cutoff, kc_status) = match keychain_ec {
                    Ok(Some(kec)) => {
                        // Prefer the keychain cutoff in BOTH directions safely: a
                        // keychain cutoff HIGHER than the file is unreachable
                        // through any legitimate write path (init writes both
                        // stores with the same cutoff; rotate copies it verbatim;
                        // the cutoff is immutable post-init), and an attacker
                        // cannot silently REWRITE the keychain (a planted entry
                        // surfaces as Ambiguous/BadEncoding → Mismatch). So
                        // "prefer keychain" only ever defeats a file-side raise.
                        let agree = fec.signing_active_since_seq == kec.signing_active_since_seq
                            && fec.signing_key_id == kec.signing_key_id;
                        (
                            Some(kec.signing_active_since_seq),
                            if agree { Confirmed } else { Mismatch },
                        )
                    }
                    // Legacy bare-hex keychain (no embedded cutoff) → use the
                    // file cutoff; anchor unconfirmed this run.
                    Ok(None) => (Some(fec.signing_active_since_seq), Unconfirmed),
                    // Keychain locked / access-denied (the daemon's normal
                    // state) → file cutoff; cross-check deferred (Unconfirmed).
                    Err(KeyCustodyError::Keychain(ref ke)) if is_keychain_access_error(ke) => {
                        (Some(fec.signing_active_since_seq), Unconfirmed)
                    }
                    // Keychain genuinely absent (NoEntry). Cannot distinguish a
                    // legitimate file-only install from an attacker who DELETED
                    // the anchor to downgrade trust → Unconfirmed (NOT a clean
                    // Confirmed — closes the silent-downgrade gap, Round-1 F1).
                    Err(KeyCustodyError::Keychain(keyring::Error::NoEntry)) => {
                        (Some(fec.signing_active_since_seq), Unconfirmed)
                    }
                    // Keychain present-but-corrupt/planted → tamper signal.
                    Err(_) => (Some(fec.signing_active_since_seq), Mismatch),
                };
                let status = if !chain_json_ok { Mismatch } else { kc_status };
                emit_anchor_status(chain_id, status);
                Ok((cutoff, status))
            }
            // FILE present but legacy bare-hex (no embedded cutoff). Use the
            // chain.json cutoff; anchor unconfirmed (no embedded value to anchor).
            None => {
                warn!(audit_cutoff_legacy_seed_no_embedded = true, chain_id = %chain_id,
                    "verify_chain: file seed is legacy bare-hex (pre-M-hardening) — \
                     using chain.json cutoff; re-run `csq audit init` to upgrade");
                Ok((chain_json_cutoff, Unconfirmed))
            }
        }
    } else {
        // FILE ABSENT (pre-migration install): the keychain is the only seed.
        match keychain_ec {
            Ok(Some(kec)) => {
                let status = if agrees_with_chain_json(&kec) {
                    Confirmed
                } else {
                    Mismatch
                };
                emit_anchor_status(chain_id, status);
                Ok((Some(kec.signing_active_since_seq), status))
            }
            Ok(None) => {
                warn!(audit_cutoff_legacy_seed_no_embedded = true, chain_id = %chain_id,
                    "verify_chain: keychain seed is legacy bare-hex (pre-M-hardening); \
                     using chain.json cutoff — re-run `csq audit init` to upgrade");
                Ok((chain_json_cutoff, Unconfirmed))
            }
            Err(KeyCustodyError::Keychain(ref ke)) if is_keychain_access_error(ke) => {
                // Locked/access-denied AND no file copy: defer to chain.json
                // (NOT fatal — the daemon-brick regression). Records signed by
                // the inaccessible key route to KeychainUnavailable per-record.
                warn!(audit_cutoff_keychain_unavailable = true, chain_id = %chain_id,
                    "verify_chain: keychain unavailable (locked/access-denied) and no file \
                     seed — using chain.json cutoff; tamper-check deferred");
                Ok((chain_json_cutoff, Unconfirmed))
            }
            Err(KeyCustodyError::Keychain(keyring::Error::NoEntry)) => {
                // Entry genuinely absent (pre-init). The per-record loop fails
                // closed (KeyNotFound) for any signed record referencing a gone key.
                Ok((chain_json_cutoff, Unconfirmed))
            }
            // Keychain present-but-corrupt/planted, with no file copy → tamper
            // signal (detector, non-fatal).
            Err(_) => {
                emit_anchor_status(chain_id, Mismatch);
                Ok((chain_json_cutoff, Mismatch))
            }
        }
    }
}

/// Emit the operator-facing log for a keychain anchor status (loud ERROR for a
/// Mismatch tamper signal; nothing for Confirmed/Unconfirmed which are surfaced
/// by `csq doctor` reading `VerifySummary::keychain_anchor`).
fn emit_anchor_status(chain_id: &str, status: KeychainAnchorStatus) {
    if status == KeychainAnchorStatus::Mismatch {
        error!(
            error_kind = "audit_keychain_anchor_mismatch",
            chain_id = %chain_id,
            "verify_chain: keychain integrity anchor MISMATCH — the file seed / chain.json \
             disagree with the keychain anchor (or the anchor is corrupt). Possible tampering. \
             The chain remains operational (detector, not gate); run `csq audit verify --full` \
             and investigate."
        );
    }
}

/// Emit the operator-facing log for a roster floor anchor status (loud ERROR
/// for a Mismatch tamper/rollback signal; nothing for Confirmed/Unconfirmed
/// which are surfaced by `csq doctor`).
fn emit_roster_floor_anchor_status(chain_id: &str, status: RosterFloorAnchorStatus) {
    if status == RosterFloorAnchorStatus::Mismatch {
        error!(
            error_kind = "audit_roster_floor_anchor_mismatch",
            chain_id = %chain_id,
            "verify_chain: roster_version_floor MISMATCH — keychain anchor disagrees with \
             chain.json. Possible rollback of chain.json to a version predating the installed \
             roster. The chain remains operational (detector, not gate); run `csq doctor` and \
             inspect `audit_roster_floor_anchor`; reinstalling the authentic roster \
             re-anchors the floor."
        );
    }
}

/// Compare `chain.json` roster_version_floor vs the keychain-anchored floor.
///
/// Returns the [`RosterFloorAnchorStatus`]:
/// - `Confirmed` when both agree (including both `None`).
/// - `Unconfirmed` when the keychain is unreadable or the keychain entry has no
///   `roster_version_floor` yet (pre-write).
/// - `Mismatch` when both are `Some` and they disagree.
///
/// Side-effect: emits an ERROR log on `Mismatch` via
/// [`emit_roster_floor_anchor_status`].
fn check_roster_floor_anchor(
    service: &str,
    chain_id: &str,
    chain_json_floor: Option<u64>,
) -> RosterFloorAnchorStatus {
    use RosterFloorAnchorStatus::*;

    // No roster installed: floor is None on both sides. No discrepancy possible.
    let Some(cj_floor) = chain_json_floor else {
        return Confirmed;
    };

    // Read the keychain entry for the active slot.
    let keychain_floor_opt: Option<u64> = match load_embedded_cutoff(service, chain_id) {
        Ok(Some(ec)) => ec.roster_version_floor,
        // Absent, legacy, or inaccessible: cannot compare → Unconfirmed.
        Ok(None) | Err(_) => {
            return Unconfirmed;
        }
    };

    match keychain_floor_opt {
        // Keychain entry exists but was written before this field was added:
        // no floor stored yet → Unconfirmed (not a mismatch).
        None => Unconfirmed,
        Some(kc_floor) => {
            let status = if kc_floor == cj_floor {
                Confirmed
            } else {
                Mismatch
            };
            emit_roster_floor_anchor_status(chain_id, status);
            status
        }
    }
}

/// M3a — per-record verification-level fold helper.
///
/// Updates the cutoff-aware fold accumulators for one verified record.
/// Called at every `summary.verified_count += 1` site in `verify_chain`
/// (including the three early-`continue` paths) so the fold is exhaustive.
///
/// `first_leveled_seq` tracks the seq of the first leveled record seen.
/// `levels_contiguous` flips to `false` if any post-cutoff record has
/// `verification_level == None`. The enterprise `verification_level_summary`
/// map is only updated when the `enterprise` feature is active.
#[inline]
fn m3a_fold_record(
    seq: u64,
    verification_level: Option<&crate::audit::eatp_canonical::VerificationLevel>,
    first_leveled_seq: &mut Option<u64>,
    levels_contiguous: &mut bool,
    #[cfg(feature = "enterprise")] level_summary: &mut std::collections::BTreeMap<String, u64>,
) {
    if let Some(level) = verification_level {
        if first_leveled_seq.is_none() {
            *first_leveled_seq = Some(seq);
        }
        #[cfg(feature = "enterprise")]
        {
            *level_summary
                .entry(level.as_canonical_str().to_string())
                .or_insert(0) += 1;
        }
        #[cfg(not(feature = "enterprise"))]
        {
            // Enterprise-only: silence unused-variable warning in community build.
            let _ = level;
        }
    } else if first_leveled_seq.is_some() {
        // Post-cutoff record with no level — breaks contiguity.
        *levels_contiguous = false;
    }
}

/// A parsed chain record for the per-record verification loop: either a fully
/// typed [`SignedRecord`] (known `EventKind`) or an [`OpaqueRecord`] whose
/// `EventKind` this binary does not recognize (GH #910 forward-compat). The loop
/// runs the SAME five integrity checks + multi-sig verification on both via
/// these accessors — only the payload SEMANTICS of an opaque record are
/// deferred, never a cryptographic check.
enum RecordView {
    Typed(Box<crate::audit::types::SignedRecord>),
    Opaque(Box<crate::audit::opaque::OpaqueRecord>),
}

impl RecordView {
    /// The raw `EventKind` tag string for an opaque record (for the operator
    /// WARN + `unknown_kind_count`); `None` for a typed record.
    fn opaque_kind(&self) -> Option<&str> {
        match self {
            RecordView::Opaque(o) => Some(&o.kind),
            RecordView::Typed(_) => None,
        }
    }
    fn seq(&self) -> u64 {
        match self {
            RecordView::Typed(r) => r.seq,
            RecordView::Opaque(o) => o.seq,
        }
    }
    fn chain_id_str(&self) -> &str {
        match self {
            RecordView::Typed(r) => r.chain_id.as_str(),
            RecordView::Opaque(o) => o.chain_id.as_str(),
        }
    }
    fn prev_hash(&self) -> &Sha256Hex {
        match self {
            RecordView::Typed(r) => &r.prev_hash,
            RecordView::Opaque(o) => &o.prev_hash,
        }
    }
    fn canonical_hash(&self) -> &Sha256Hex {
        match self {
            RecordView::Typed(r) => &r.canonical_hash,
            RecordView::Opaque(o) => &o.canonical_hash,
        }
    }
    fn key_id(&self) -> &KeyId {
        match self {
            RecordView::Typed(r) => &r.key_id,
            RecordView::Opaque(o) => &o.key_id,
        }
    }
    fn record_id(&self) -> &crate::audit::types::RecordId {
        match self {
            RecordView::Typed(r) => &r.record_id,
            RecordView::Opaque(o) => &o.record_id,
        }
    }
    fn signature_bytes(&self) -> [u8; 64] {
        match self {
            RecordView::Typed(r) => r.signature.0,
            RecordView::Opaque(o) => o.signature.0,
        }
    }
    /// Canonical bytes with the record's REAL stored `canonical_hash` — the
    /// pre-image for the NEXT record's `prev_hash` link (Check 3 seeding).
    fn canonical_bytes_link(&self) -> Vec<u8> {
        match self {
            RecordView::Typed(r) => canonical_bytes_for(r),
            RecordView::Opaque(o) => crate::audit::opaque::canonical_bytes_for_opaque_link(o),
        }
    }
    /// Canonical bytes with the genesis sentinel in the `canonical_hash`
    /// position — the Check-4 self-referential recompute pre-image.
    fn canonical_bytes_sentinel(&self) -> Vec<u8> {
        match self {
            RecordView::Typed(r) => {
                let mut record_for_hash = (**r).clone();
                record_for_hash.canonical_hash = Sha256Hex::genesis();
                canonical_bytes_for(&record_for_hash)
            }
            RecordView::Opaque(o) => crate::audit::opaque::canonical_bytes_for_opaque_check4(o),
        }
    }
    /// The PACT verification level for the M3a cutoff fold. Typed records carry
    /// it directly; opaque records carry it as a verbatim `RawValue` that is
    /// best-effort-parsed (a malformed level folds as `None`, never an error —
    /// the level is a summary annotation, not an integrity check).
    fn verification_level(&self) -> Option<crate::audit::eatp_canonical::VerificationLevel> {
        match self {
            RecordView::Typed(r) => r.verification_level,
            RecordView::Opaque(o) => o
                .verification_level
                .as_deref()
                .and_then(|rv| serde_json::from_str(rv.get()).ok()),
        }
    }
    /// Multi-sig authorization verification. Typed records run the full M11+M12
    /// check; opaque records run the pure-M11 inner-threshold check (op-class is
    /// unknowable — see [`crate::audit::multi_sig::verify_opaque_multi_sig`]).
    fn verify_multi_sig(
        &self,
        registry: Option<&dyn AuthorityRegistry>,
    ) -> Result<(), crate::audit::multi_sig::MultiSigError> {
        match self {
            RecordView::Typed(r) => verify_record_multi_sig(r, registry),
            RecordView::Opaque(o) => {
                // A structurally-broken authority blob fails closed (it cannot be
                // read to check the threshold). The verbatim blob is already
                // committed by the outer signature (Check 5), so this only rejects
                // a blob that is not even valid JSON.
                let authority = o.authority_value().map_err(|_| {
                    crate::audit::multi_sig::MultiSigError::MalformedAuthorityBlob(
                        "opaque record authority slot is not valid JSON",
                    )
                })?;
                crate::audit::multi_sig::verify_opaque_multi_sig(
                    o.chain_id.as_str(),
                    &o.kind,
                    &o.payload,
                    authority.as_ref(),
                )
            }
        }
    }
}

/// Verify the **op-chain** (`csq-runs/`). Convenience wrapper over
/// [`verify_chain_in`] with [`ChainKind::Op`] — byte-identical to the historical
/// `verify_chain` for every existing caller.
///
/// For the born-canonical EATP attestation chain (M3 §10.5) use
/// [`verify_chain_in`] with [`ChainKind::Eatp`].
pub fn verify_chain(
    base_dir: &Path,
    config: &VerifyConfig,
    since_seq: Option<u64>,
) -> Result<VerifySummary, LedgerError> {
    verify_chain_in(base_dir, config, since_seq, ChainKind::Op)
}

/// Verify the chain whose records live under `<base_dir>/<chain.runs_subdir()>/`
/// (`csq-runs/` for the op-chain, `eatp-runs/` for the born-canonical EATP
/// attestation chain — M3 §10.5 W1 chain-id parameterization).
///
/// Each chain is a fully isolated fault domain: its own `chain.json` genesis,
/// `<chain_id>.jsonl` log, and `.chain-broken` sentinel. The signing-key custody
/// resolution keys off the per-chain `chain_id` read from that chain's
/// `chain.json` (and `base_dir`), so verifying the EATP chain finds its own key
/// seed — provided the EATP genesis writer (W2b) established it under the EATP
/// `chain_id`. An absent chain (`chain.json` missing) is trivially clean.
///
/// W2a resolves the prior W2-BLOCKER: this verifier (and the four
/// verify→sentinel callsites — daemon startup, `csq audit verify`, `csq doctor`,
/// desktop daemon) now verify `eatp-runs/` too, so the first production EATP
/// write (W2b) lands onto a chain that IS verified end-to-end.
pub fn verify_chain_in(
    base_dir: &Path,
    config: &VerifyConfig,
    _since_seq: Option<u64>,
    chain: ChainKind,
) -> Result<VerifySummary, LedgerError> {
    let csq_runs = base_dir.join(chain.runs_subdir());
    let chain_json_path = csq_runs.join("chain.json");

    // No chain.json → no v2 records yet → trivially clean.
    if !chain_json_path.exists() {
        return Ok(VerifySummary::default());
    }

    // Load chain identity. Errors here indicate corruption (not absence).
    let chain_state =
        ChainState::load_in(base_dir, chain.runs_subdir()).map_err(|e| LedgerError::Io {
            context: RedactedString::from_trusted("chain.json load error"),
            source: std::io::Error::other(match e {
                KeyCustodyError::ChainIo(msg) => msg,
                KeyCustodyError::ChainParse(msg) => msg,
                other => other.to_string(),
            }),
        })?;

    // Also read the M02 genesis fields to get chain_id (M04 ChainState has chain_id).
    // chain_state.chain_id is the authoritative chain_id.
    let chain_id = &chain_state.chain_id;
    if chain_id.is_empty() {
        // Empty chain_id means chain.json exists but was written before M02
        // populated it. No v2 records can exist — trivially clean.
        return Ok(VerifySummary::default());
    }

    // ── M-hardening: resolve the authoritative signing cutoff (READ-ONLY) ─────
    //
    // `verify_chain` is a READ-ONLY path (daemon start + `csq audit verify`).
    // It MUST NOT write to the keychain.  All cutoff establishment and migration
    // is handled in write paths (`audit_init`, `rotate_key`).
    //
    // 4-state resolution:
    //
    // 1. Seed entry present, new JSON format → embedded cutoff AUTHORITATIVE.
    //    Cross-check vs chain.json cutoff AND signing_key_id.  Disagreement →
    //    `CutoffAnchorMismatch` (tamper signal).
    //
    // 2. Seed entry present, legacy bare-hex → no embedded cutoff.
    //    Use chain.json cutoff THIS run (TOFU-at-legacy: no trusted prior cutoff
    //    exists before M-hardening was introduced).  Warn but do NOT write.
    //
    // 3. Seed entry absent (pre-`audit init`) → no authoritative cutoff.
    //    Use chain.json (typically None → tolerate all placeholder records).
    //
    // 4. Keychain locked/access-denied (NOT NoEntry) → MUST NOT brick daemon.
    //    Use chain.json cutoff + warn `audit_cutoff_keychain_unavailable`;
    //    defer tamper-check to next unlocked run.  (deep-analyst HIGH: treating
    //    this as fatal caused daemon to refuse-to-start at boot on macOS when
    //    the Keychain is locked before first-user-unlock.)
    let (authoritative_cutoff, keychain_anchor): (Option<u64>, KeychainAnchorStatus) =
        if let Some(ref kid) = chain_state.signing_key_id {
            // FILE STORE is the daemon-readable PRIMARY; the OS KEYCHAIN is the
            // integrity ANCHOR (a DETECTOR — never fatal). Read both and
            // reconcile in `resolve_authoritative_cutoff`: the file supplies the
            // cutoff the daemon can always read non-interactively, and the
            // keychain — which a same-UID attacker can DELETE but cannot silently
            // REWRITE — is cross-checked when readable. An anchor anomaly is
            // SURFACED (status), never bricks the chain.
            let file_present = file_store::exists(base_dir, chain_id, KeySlot::Active);
            let file_ec = load_embedded_cutoff_file_first(base_dir, chain_id);
            let keychain_ec = load_embedded_cutoff(&config.keychain_service, chain_id);
            resolve_authoritative_cutoff(
                chain_id,
                kid,
                chain_state.signing_active_since_seq,
                file_present,
                file_ec,
                keychain_ec,
            )?
        } else {
            // No signing_key_id in chain.json: pre-`audit init`. Anchor N/A.
            // HIGH-2 guard: if chain.json has a cutoff but no signing_key_id,
            // that is an inconsistent state — reject it rather than silently
            // trusting the cutoff.
            if chain_state.signing_active_since_seq.is_some() {
                warn!(
                    audit_cutoff_inconsistent_state = true,
                    chain_id = %chain_id,
                    "verify_chain: chain.json has signing_active_since_seq but no \
                     signing_key_id — inconsistent state; treating as no cutoff"
                );
            }
            (None, KeychainAnchorStatus::Confirmed)
        };

    // ── M12: resolve authority registry (READ-ONLY) ────────────────────────────
    //
    // Construct the registry ONCE before the per-record loop. Fail closed on
    // enterprise misconfiguration (missing/corrupt/bad-sig/rolled-back roster
    // or missing root pubkey) — propagate as LedgerError BEFORE the loop so
    // the daemon refuses to start rather than silently accepting unenrolled sigs.
    //
    // verify_chain is READ-ONLY (spec 12 §12.13.9) — this does NOT write to
    // chain.json or the roster. The roster_activation_seq and roster_version_floor
    // are read here but only written by the roster-install WRITE path.
    let authority_registry =
        resolve_registry(base_dir, &chain_state).map_err(|e| LedgerError::Io {
            context: RedactedString::from_trusted(
                "authority registry load failed — enterprise roster misconfigured; \
                 daemon startup refused",
            ),
            source: std::io::Error::other(format!("{e}")),
        })?;

    // ── Roster floor anchor cross-check (DETECTOR, non-fatal) ────────────────
    //
    // Compare chain.json `roster_version_floor` with the keychain-anchored copy
    // (written best-effort by roster-install). A same-UID attacker can lower the
    // FS-side chain.json floor, but cannot silently rewrite the keychain entry —
    // so a Mismatch is a rollback-attempt signal.
    let roster_floor_present = chain_state.roster_version_floor.is_some();
    let roster_floor_anchor = check_roster_floor_anchor(
        &config.keychain_service,
        chain_id,
        chain_state.roster_version_floor,
    );

    let chain_jsonl_path = csq_runs.join(format!("{chain_id}.jsonl"));
    if !chain_jsonl_path.exists() {
        // chain.json exists but the JSONL file does not — genesis state, no
        // records to verify. Still carry the keychain anchor status computed in
        // Step-0 so a chain.json/keychain disagreement on a record-less chain is
        // not silently dropped.
        return Ok(VerifySummary {
            keychain_anchor,
            roster_floor_anchor,
            roster_floor_present,
            ..VerifySummary::default()
        });
    }

    let content = std::fs::read_to_string(&chain_jsonl_path).map_err(|e| LedgerError::Io {
        context: RedactedString::from_trusted("chain JSONL read error"),
        source: e,
    })?;

    // ── R1-DEEP-3 fix: collect ALL lines, then apply limit to TAIL ─────────────
    // Separate v1 lines (skipped) from v2 lines (to-be-verified) to correctly
    // apply the limit to the v2 tail. We track line indices so we can report
    // skipped-v1 counts accurately.
    let all_lines: Vec<&str> = content.lines().collect();

    // Classify lines: empty, v1, or v2.
    let mut skipped_v1_count: u64 = 0;
    let mut v2_lines: Vec<&str> = Vec::with_capacity(all_lines.len());

    for raw_line in &all_lines {
        if raw_line.trim().is_empty() {
            continue;
        }
        if raw_line.contains("\"schema_version\":\"1\"")
            || raw_line.contains("\"schema_version\": \"1\"")
        {
            // Skip v1 record — attempt parse to confirm; if it parses as v2
            // despite containing the v1 string, treat as v2. In practice
            // v1 records will not parse as SignedRecord.
            //
            // GH #910: a v2 record with a NEWER `EventKind` also fails the
            // `SignedRecord` parse but parses as an `OpaqueRecord` — and its
            // verbatim payload could legitimately CONTAIN the `"schema_version":
            // "1"` substring. Such a record MUST route to the opaque verify path,
            // not be dropped as a v1 skip (which would defeat forward-compat AND
            // break the next record's prev_hash link). So only skip as v1 when the
            // line is neither a v2 typed record NOR a v2 opaque record. A genuine
            // v1 record (a different `AuditRecord` shape — run_id, not the
            // SignedRecord fields) parses as neither, so it still skips correctly.
            if serde_json::from_str::<SignedRecord>(raw_line).is_err()
                && serde_json::from_str::<crate::audit::opaque::OpaqueRecord>(raw_line).is_err()
            {
                skipped_v1_count += 1;
                continue;
            }
        }
        v2_lines.push(raw_line);
    }

    // Apply limit to the TAIL: skip the oldest records if total v2 count exceeds limit.
    let limit_exceeded_count = if v2_lines.len() > config.record_limit {
        let excess = v2_lines.len() - config.record_limit;
        // Warn once with total count, not per record.
        warn!(
            total_records = v2_lines.len(),
            limit = config.record_limit,
            skipped = excess,
            "audit_verify_limit_exceeded: oldest records skipped, verifying tail only"
        );
        let skipped = excess as u64;
        v2_lines = v2_lines.split_off(excess); // keep the tail
        skipped
    } else {
        0
    };

    let mut summary = VerifySummary {
        skipped_v1_count,
        limit_exceeded_count,
        keychain_anchor,
        roster_floor_anchor,
        roster_floor_present,
        ..VerifySummary::default()
    };

    // Cache loaded public keys keyed by KeyId string to avoid repeated
    // keychain lookups for the same key across many records.
    // Also cache negative lookups — but distinguish historical-key gaps from
    // current-key-missing so crafted chains with many fake key_ids cannot
    // force O(records×rotations) keychain I/O (R1-SEC-6 / R1-IR-3 fix).
    //
    // Cache values:
    //   `Some(Some(pk))` — key present, pubkey bytes loaded
    //   `Some(None)` — key absent AND the current active key (fatal)
    //   `None` — not yet looked up
    //
    // Historical-gap negatives are tracked separately in `historical_gap_cache`
    // (key_id string → true) so repeated records with the same missing
    // historical key skip the keychain scan without returning a fatal error.
    //
    // R2-RS-4 (key_id cache bounded-key assessment): the cache IS bounded.
    // Every record is deserialized via `serde_json::from_str::<SignedRecord>`,
    // and `SignedRecord::key_id` is a `KeyId` newtype whose `Deserialize` impl
    // routes through `KeyId::try_new`.  `KeyId::try_new` enforces the shape
    // `"ed25519:<64-lowercase-hex>"` — exactly 72 characters, with no path
    // separators or control chars.  A crafted-unbounded-key_id attack is
    // therefore impossible: malformed key_ids are rejected at deserialize time
    // (the record is dropped as IntegrityBroken before reaching the cache).
    // No cache-size cap is needed; the bound is structural.
    let mut key_cache: std::collections::HashMap<String, Option<[u8; 32]>> =
        std::collections::HashMap::new();
    // Cache of key_ids confirmed to be historical (rotated-out) gaps.
    // Records using these keys skip signature verification but continue
    // chain-linking checks. This set is disjoint from `key_cache`'s
    // negative entries (those are for the current active key).
    let mut historical_gap_cache: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    let mut prev_canonical_bytes: Option<Vec<u8>> = None;
    let mut prev_seq: Option<u64> = None;
    // FIX-1 topology enforcement: track whether any record so far has been
    // signature-verified by a present key. Once true, a subsequent historical-key
    // gap record indicates tampering or an invalid rotation order (gaps must form
    // a contiguous PREFIX before any current-key-signed record).
    let mut seen_verified_signature: bool = false;
    // M3a — cutoff-aware verification-levels fold.
    // `first_leveled_seq`: the seq of the first record that carries a
    // `verification_level`; `None` if no leveled record has been seen yet.
    // `levels_contiguous`: false as soon as any post-cutoff record lacks a level.
    let mut first_leveled_seq: Option<u64> = None;
    let mut levels_contiguous: bool = true;

    for (verified_idx, raw_line) in v2_lines.iter().enumerate() {
        // Parse v2 record.
        // Parse: a fully typed record (known EventKind), or — GH #910 forward-
        // compat — an `OpaqueRecord` whose EventKind a NEWER writer added. A line
        // that is NEITHER a known record nor a well-formed forward record is
        // `IntegrityBroken`. Both variants run EVERY check below via `RecordView`
        // accessors; only an opaque record's typed payload SEMANTICS are deferred.
        let record: RecordView = match serde_json::from_str::<SignedRecord>(raw_line) {
            Ok(r) => RecordView::Typed(Box::new(r)),
            Err(_) => match serde_json::from_str::<crate::audit::opaque::OpaqueRecord>(raw_line) {
                Ok(o) => RecordView::Opaque(Box::new(o)),
                Err(_) => {
                    // Unrecognised format — treat as IntegrityBroken.
                    return Err(LedgerError::IntegrityBroken {
                        seq: prev_seq.map(|s| s + 1).unwrap_or(0),
                        reason: RedactedString::from_trusted(
                            "record is not valid JSON or unknown format",
                        ),
                    });
                }
            },
        };

        // GH #910: surface an unknown-kind record loudly and count it so tally
        // consumers stay honest. Counting here (before the checks) is safe: any
        // check failure returns `Err`, which discards `summary` — the count only
        // survives on a chain that verifies clean end-to-end.
        if let Some(unknown_kind) = record.opaque_kind() {
            summary.unknown_kind_count += 1;
            warn!(
                audit_verify_opaque_kind = true,
                kind = unknown_kind,
                seq = record.seq(),
                "verify_chain: record carries an EventKind this build does not know — \
                 verifying signature + hash-chain only (payload semantics deferred to a \
                 newer reader); NOT treated as tampered"
            );
        }

        // === Check 1: chain_id consistency ===
        if record.chain_id_str() != chain_id {
            return Err(LedgerError::IntegrityBroken {
                seq: record.seq(),
                reason: RedactedString::from_trusted("record chain_id does not match chain.json"),
            });
        }

        // === Check 2: strictly-monotonic seq ===
        // When applying the tail-only limit, the first record in the window
        // may not be seq 0. We only enforce the genesis-must-be-0 rule when
        // this is the first record in the ENTIRE chain (limit_exceeded_count
        // == 0 AND it's the first in the window).
        if let Some(ps) = prev_seq {
            if record.seq() != ps + 1 {
                return Err(LedgerError::IntegrityBroken {
                    seq: record.seq(),
                    reason: RedactedString::from_trusted(
                        "seq is not strictly monotonic (expected prev_seq + 1)",
                    ),
                });
            }
        } else if summary.limit_exceeded_count == 0 && verified_idx == 0 {
            // First record in the full walk; must be seq 0.
            if record.seq() != 0 {
                return Err(LedgerError::IntegrityBroken {
                    seq: record.seq(),
                    reason: RedactedString::from_trusted("first record seq must be 0 (genesis)"),
                });
            }
        }
        // When limit_exceeded_count > 0, we start mid-chain — no genesis check.

        // === Check 3: unbroken hash chain ===
        let expected_prev_hash = match prev_canonical_bytes.as_ref() {
            None => {
                if summary.limit_exceeded_count > 0 {
                    // Mid-chain start: we cannot verify the hash chain link for
                    // the first record in the tail window without loading the
                    // record immediately before it. Skip this check for the
                    // first record only.
                    // Seed prev_canonical_bytes so subsequent records CAN be checked.
                    prev_canonical_bytes = Some(record.canonical_bytes_link());
                    prev_seq = Some(record.seq());
                    summary.head_seq = record.seq();
                    summary.verified_count += 1;
                    // M3a: fold verification level.
                    m3a_fold_record(
                        record.seq(),
                        record.verification_level().as_ref(),
                        &mut first_leveled_seq,
                        &mut levels_contiguous,
                        #[cfg(feature = "enterprise")]
                        &mut summary.verification_level_summary,
                    );
                    continue;
                }
                Sha256Hex::GENESIS.to_string()
            }
            Some(bytes) => sha256_hex(bytes),
        };
        if record.prev_hash().as_str() != expected_prev_hash {
            // R2-RS-1: `expected_prev_hash` comes from our own `sha256_hex()`,
            // which always produces 64 lowercase hex chars — `try_new` cannot
            // fail on it. We avoid the round-trip to eliminate any silent
            // genesis downgrade on the diagnostic error path: if `try_new`
            // somehow failed we would emit the wrong `expected_prev` in the
            // error message, masking the real break point from the operator.
            let expected = Sha256Hex::try_new(&expected_prev_hash).map_err(|_| {
                LedgerError::IntegrityBroken {
                    seq: record.seq(),
                    reason: crate::audit::types::RedactedString::from_trusted(
                        "internal: sha256_hex produced malformed output",
                    ),
                }
            })?;
            return Err(LedgerError::ChainBroken {
                seq: record.seq(),
                expected_prev: expected,
                actual_prev: record.prev_hash().clone(),
            });
        }

        // === Check 4: canonical_hash recompute (R1-SEC-2 / R1-DEEP-7 fix) ===
        //
        // The canonical_hash field on the stored record MUST equal
        // sha256(canonical_bytes_for(record_with_canonical_hash := genesis_sentinel)).
        //
        // This is the same computation the WRITER performs (see persist.rs
        // write_record_v2 Steps 6-7 and rotate.rs Steps a-c): set
        // canonical_hash to the zero/genesis sentinel, compute the canonical
        // bytes, sha256 them, and store that hash. The verifier independently
        // recomputes and compares — an attacker who modifies any field of the
        // record (including canonical_hash itself) will produce a mismatch. For
        // an opaque record the same recompute runs over the verbatim payload
        // bytes (`OpaqueCanonicalView`), so a tampered unknown-kind record still
        // fails here — it is NOT waved through as intact.
        {
            let canonical_with_sentinel = record.canonical_bytes_sentinel();
            let expected_hash = sha256_hex(&canonical_with_sentinel);
            if record.canonical_hash().as_str() != expected_hash {
                return Err(LedgerError::IntegrityBroken {
                    seq: record.seq(),
                    reason: RedactedString::from_trusted(
                        "canonical_hash does not match recomputed value — record content may have been tampered",
                    ),
                });
            }
        }

        // === Check 5: Ed25519 signature (R1-SEC-4 + R1-DEEP-2 + R1-SEC-1 fixes) ===
        let key_id_str = record.key_id().as_str();
        let is_placeholder_key = key_id_str == PLACEHOLDER_KEY_ID;

        if is_placeholder_key {
            // M-hardening: use `authoritative_cutoff` (resolved from the keychain
            // seed entry above, NOT from chain.json directly) as the gate. This
            // applies to an opaque (unknown-kind) record too: an unsigned
            // placeholder record after the cutoff is rejected regardless of kind.
            if let Some(cutoff) = authoritative_cutoff {
                if record.seq() >= cutoff {
                    return Err(LedgerError::UnsignedRecordAfterCutoff {
                        seq: record.seq(),
                        cutoff,
                    });
                }
            }
            // Before cutoff or no cutoff: skip signature verification.
        } else {
            // Load the public key for this key_id (with positive + negative/gap cache).
            //
            // Three outcomes:
            //   (a) Key found → verify signature below.
            //   (b) Key missing + it IS the current active key → fatal KeyNotFound.
            //   (c) Key missing + it is a HISTORICAL (rotated-out) key →
            //       record the gap in summary, skip signature, continue
            //       chain-linking. This is the "verified-current-segment with
            //       historical gaps" degrade path (spec 12 §12.13.2).

            // Fast path: already confirmed as historical gap.
            if historical_gap_cache.contains(key_id_str) {
                // FIX-1: gaps must form a contiguous PREFIX before any
                // signature-verified record. A gap appearing after a
                // verified record is fatal (tampering or invalid rotation).
                if seen_verified_signature {
                    return Err(LedgerError::GapAfterVerifiedSegment {
                        gap_seq: record.seq(),
                        key_id: record.key_id().clone(),
                    });
                }

                // FIX-3: Coalesce only when same key AND contiguous (seq == last_seq + 1).
                // Non-contiguous same-key runs start a new KeyGap entry so that
                // `last_seq - first_seq + 1 == count` always holds.
                let merged = summary
                    .historical_key_gaps
                    .last_mut()
                    .filter(|g| g.key_id == key_id_str && record.seq() == g.last_seq + 1);
                if let Some(last_gap) = merged {
                    last_gap.last_seq = record.seq();
                    last_gap.count += 1;
                } else {
                    summary.historical_key_gaps.push(KeyGap {
                        key_id: key_id_str.to_string(),
                        first_seq: record.seq(),
                        last_seq: record.seq(),
                        count: 1,
                    });
                }
                // Chain-linking already verified above (Checks 1-4);
                // advance state and continue — signature skipped.
                prev_canonical_bytes = Some(record.canonical_bytes_link());
                prev_seq = Some(record.seq());
                summary.head_seq = record.seq();
                summary.verified_count += 1;
                // M3a: fold verification level.
                m3a_fold_record(
                    record.seq(),
                    record.verification_level().as_ref(),
                    &mut first_leveled_seq,
                    &mut levels_contiguous,
                    #[cfg(feature = "enterprise")]
                    &mut summary.verification_level_summary,
                );
                continue;
            }

            let pubkey_bytes = match key_cache.get(key_id_str) {
                Some(Some(pk)) => *pk,
                Some(None) => {
                    // Cached negative lookup: current active key is missing — fatal.
                    return Err(LedgerError::KeyNotFound {
                        key_id: record.key_id().clone(),
                    });
                }
                None => {
                    // Resolve the record's signing key. FILE STORE FIRST (always
                    // daemon-readable), OS keychain FALLBACK. Candidate slots are
                    // the active slot plus every historical slot up to
                    // rotation_count (chain_id-scoped — spec §12.11.1).
                    //
                    // CRITICAL — the conflation fix (an internal journal entry). Distinguish a
                    // keychain ACCESS error (present-but-blocked → TRANSIENT) from
                    // genuine ABSENCE. The pre-fix `Err(_) => continue` swallow
                    // collapsed both, so a present-but-ACL-blocked CURRENT key was
                    // misclassified as KeyNotFound/HistoricalKeyAtHead → Broken →
                    // durable `.chain-broken` sentinel → the daemon brick. The
                    // access path now routes to `KeychainUnavailable` →
                    // `AuditHealth::Unknown` (no durable sentinel).
                    let mut loaded_pk: Option<[u8; 32]> = None;
                    let mut saw_inaccessible = false;
                    let mut saw_corrupt: Option<String> = None;

                    let mut candidate_slots: Vec<KeySlot> = vec![KeySlot::Active];
                    for i in 0..=chain_state.rotation_count {
                        candidate_slots.push(KeySlot::Historical(i));
                    }

                    for slot in candidate_slots {
                        match try_load_signing_key(
                            base_dir,
                            &config.keychain_service,
                            chain_id,
                            slot,
                        ) {
                            KeyLoadOutcome::Loaded(key) if key.key_id().as_str() == key_id_str => {
                                loaded_pk = Some(key.public_key().0);
                                break;
                            }
                            // Loaded but a different key_id, or genuinely absent
                            // in this slot — keep searching.
                            KeyLoadOutcome::Loaded(_) | KeyLoadOutcome::Absent => continue,
                            // Present-but-inaccessible (locked / ACL-blocked):
                            // the key we need MIGHT live in this slot, so we
                            // cannot conclude absence. Remember and keep searching
                            // (another slot may hold a readable copy).
                            KeyLoadOutcome::Inaccessible => {
                                saw_inaccessible = true;
                                continue;
                            }
                            // Present-but-corrupt/planted seed — a tamper signal,
                            // NOT a transient lock. Remember; if no readable copy
                            // is found anywhere we fail closed.
                            KeyLoadOutcome::Corrupt(reason) => {
                                saw_corrupt.get_or_insert(reason);
                                continue;
                            }
                        }
                    }

                    match loaded_pk {
                        Some(pk) => {
                            key_cache.insert(key_id_str.to_string(), Some(pk));
                            pk
                        }
                        None => {
                            // A corrupt/planted seed takes precedence — fail
                            // closed (do NOT downgrade to a degrade or a
                            // transient). Preserves the present-but-unreadable →
                            // fatal posture of the Step-0 cutoff path.
                            if let Some(reason) = saw_corrupt {
                                return Err(LedgerError::Io {
                                    context: RedactedString::from_trusted(
                                        "audit signing seed is present but unreadable \
                                         (corrupt or planted entry) — failing closed",
                                    ),
                                    source: std::io::Error::other(reason),
                                });
                            }
                            // TRANSIENT: the key may be present but the store is
                            // locked / ACL-blocked right now. Do NOT cache a
                            // negative lookup (the block is not durable) and do
                            // NOT set the sentinel — route to KeychainUnavailable
                            // → AuditHealth::Unknown so the chain is DEFERRED, not
                            // bricked. Recovers on the next run that can read the
                            // store (interactive `csq audit verify`, or after
                            // `csq audit migrate-keys`).
                            if saw_inaccessible {
                                return Err(LedgerError::KeychainUnavailable {
                                    key_id: record.key_id().clone(),
                                });
                            }
                            // GENUINE ABSENCE: the key is in NEITHER the file
                            // store NOR the keychain, anywhere.
                            //
                            // Classify as HISTORICAL (degrade) only when ALL of:
                            //   1. chain.json has a current `signing_key_id`.
                            //   2. That current key_id DIFFERS from the record's key_id.
                            //
                            // If chain.json has no signing_key_id, we cannot
                            // distinguish a legitimate historical rotation from an
                            // entirely unknown key — fail closed to avoid
                            // inadvertently opening a gap for injected records.
                            let current_active_key_id: Option<&str> =
                                chain_state.signing_key_id.as_ref().map(|kid| kid.as_str());

                            let is_historical_rotated_out = match current_active_key_id {
                                Some(active) => active != key_id_str,
                                None => false, // no known current key — fail closed
                            };

                            if is_historical_rotated_out {
                                // FIX-1: gaps must form a contiguous PREFIX before any
                                // signature-verified record. A gap appearing after a
                                // verified record is fatal (tampering or invalid rotation).
                                if seen_verified_signature {
                                    return Err(LedgerError::GapAfterVerifiedSegment {
                                        gap_seq: record.seq(),
                                        key_id: record.key_id().clone(),
                                    });
                                }

                                // Historical (rotated-out) key whose seed was
                                // lost. Degrade: record the gap, skip signature
                                // verification for this and subsequent records
                                // with the same key_id, but continue all
                                // key-free chain-linking checks.
                                //
                                // Log once per distinct missing historical key_id
                                // (not once per record — avoids flooding the log).
                                warn!(
                                    audit_verify_historical_key_gap = true,
                                    key_id = key_id_str,
                                    seq = record.seq(),
                                    "verify_chain: historical signing key not found \
                                     in keychain — signature verification skipped for \
                                     records signed by this rotated-out key; \
                                     chain-linking verified across the gap"
                                );
                                historical_gap_cache.insert(key_id_str.to_string());
                                // FIX-3: First occurrence always pushes a new KeyGap entry.
                                summary.historical_key_gaps.push(KeyGap {
                                    key_id: key_id_str.to_string(),
                                    first_seq: record.seq(),
                                    last_seq: record.seq(),
                                    count: 1,
                                });
                                // Chain-linking already verified above (Checks 1-4);
                                // advance state and continue — signature skipped.
                                prev_canonical_bytes = Some(record.canonical_bytes_link());
                                prev_seq = Some(record.seq());
                                summary.head_seq = record.seq();
                                summary.verified_count += 1;
                                // M3a: fold verification level.
                                m3a_fold_record(
                                    record.seq(),
                                    record.verification_level().as_ref(),
                                    &mut first_leveled_seq,
                                    &mut levels_contiguous,
                                    #[cfg(feature = "enterprise")]
                                    &mut summary.verification_level_summary,
                                );
                                continue;
                            } else {
                                // Either the current active key is missing, or
                                // chain.json has no signing_key_id and the key
                                // is unclassifiable. Both are fatal: cache the
                                // negative lookup and fail closed.
                                key_cache.insert(key_id_str.to_string(), None);
                                return Err(LedgerError::KeyNotFound {
                                    key_id: record.key_id().clone(),
                                });
                            }
                        }
                    }
                }
            };

            // R1-SEC-4 fix: verify_strict over the 32 raw bytes of the
            // canonical_hash (not the 64-char hex string). The WRITER signs
            // sha256(canonical_bytes_for(record_with_real_hash)) which produces
            // 32 bytes; we re-derive those same 32 bytes here.
            //
            // canonical_hash has already been verified above (Check 4), so it
            // is safe to use as the signing pre-image basis.
            let canonical_hash_hex = record.canonical_hash().as_str();
            let digest_bytes =
                hex::decode(canonical_hash_hex).map_err(|_| LedgerError::IntegrityBroken {
                    seq: record.seq(),
                    reason: RedactedString::from_trusted(
                        "canonical_hash is not valid hex — cannot extract signing pre-image",
                    ),
                })?;
            if digest_bytes.len() != 32 {
                return Err(LedgerError::IntegrityBroken {
                    seq: record.seq(),
                    reason: RedactedString::from_trusted(
                        "canonical_hash decoded to wrong byte length (expected 32)",
                    ),
                });
            }

            let sig_bytes = record.signature_bytes();
            let verifying_key =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| LedgerError::Internal {
                    message: RedactedString::from_trusted("invalid public key bytes in keychain"),
                })?;
            let dalek_sig = Signature::from_bytes(&sig_bytes);
            if verifying_key
                .verify_strict(&digest_bytes, &dalek_sig)
                .is_err()
            {
                return Err(LedgerError::InvalidSignature {
                    record_id: record.record_id().clone(),
                    key_id: record.key_id().clone(),
                });
            }
            // FIX-1: signature successfully verified by a present key.
            // From this point, any subsequent historical-key gap record
            // indicates an invalid rotation topology (gaps must be a prefix).
            seen_verified_signature = true;
        }

        // === M11 + M12: multi-sig authority verification (ADDITIVE) ===
        //
        // Records with `authority: None` or whose authority blob does not carry
        // a `multi_sig` key return `Ok(())` immediately — backward compat for
        // all pre-M11 records. Records that DO carry a `multi_sig` blob must
        // pass the threshold check; a malformed or under-threshold blob is
        // rejected with `LedgerError::MultiSigInvalid`.
        //
        // M12: thread the registry (as `Option<&dyn AuthorityRegistry>`) so
        // `verify_record_multi_sig` can apply the membership check for guarded
        // op-classes post-activation. Community edition passes `None`.
        // For an opaque (unknown-kind) record this runs the pure-M11 inner
        // threshold check (op-class is unknowable → no M12 membership filter);
        // the outer signature (Check 5) already committed to the authority blob.
        let registry_ref: Option<&dyn AuthorityRegistry> = authority_registry.as_deref();
        if let Err(ms_err) = record.verify_multi_sig(registry_ref) {
            return Err(LedgerError::MultiSigInvalid {
                record_id: record.record_id().clone(),
                // OBS-2: route through `from_untrusted` (runs `redact_tokens`) rather
                // than `from_trusted`. Today every `MultiSigError` variant reachable
                // from `verify_record_multi_sig` carries only `&'static str` /
                // integers, so redaction is a no-op — but `MultiSigError` is
                // `#[non_exhaustive]`, and a future variant that interpolates dynamic
                // material would otherwise bypass redaction silently. Belt-and-suspenders.
                reason: RedactedString::from_untrusted(ms_err.to_string()),
            });
        }

        // Advance state.
        prev_canonical_bytes = Some(record.canonical_bytes_link());
        prev_seq = Some(record.seq());
        summary.head_seq = record.seq();
        summary.verified_count += 1;
        // M3a: fold verification level.
        m3a_fold_record(
            record.seq(),
            record.verification_level().as_ref(),
            &mut first_leveled_seq,
            &mut levels_contiguous,
            #[cfg(feature = "enterprise")]
            &mut summary.verification_level_summary,
        );
    }

    // M3a — populate the levels-populated signal from the fold accumulators.
    // `true` when at least one record carried a level AND no post-cutoff record
    // was missing one (contiguous from first-leveled onward).
    summary.verification_levels_populated = first_leveled_seq.is_some() && levels_contiguous;

    // Emit single v1-skip summary log (not one per record).
    if summary.skipped_v1_count > 0 {
        info!(
            audit_verify_skipped_v1_records_total = summary.skipped_v1_count,
            "v1 records skipped during chain verification (not chain-linked)"
        );
    }

    // FIX-1: HEAD-must-be-signed check.
    // The last record processed MUST have been signature-verified by a present
    // key. If the last record was a historical-key gap (signature skipped), the
    // chain has no tamper-evidence for its most-recent records. This is FATAL —
    // returning Ok with the head unverified would allow a forged tail.
    //
    // We track this by checking whether the last gap's `last_seq` equals the
    // current `head_seq`. If so, the HEAD was a gap record (unverified).
    if summary.verified_count > 0 {
        if let Some(last_gap) = summary.historical_key_gaps.last() {
            if last_gap.last_seq == summary.head_seq {
                // last_gap.key_id was already validated as a KeyId string when
                // it was inserted; try_new here is a formality to get the type.
                let key_id = KeyId::try_new(&last_gap.key_id).unwrap_or_else(|_|
                    // Unreachable: key_ids in gaps are always valid (they come
                    // from deserialized SignedRecord.key_id which is already KeyId).
                    KeyId::try_new(
                        "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .expect("static fallback KeyId is always valid"));
                return Err(LedgerError::HistoricalKeyAtHead {
                    head_seq: summary.head_seq,
                    key_id,
                });
            }
        }
    }

    Ok(summary)
}

/// JSON output shape for `csq audit verify --json`.
///
/// Per spec 12 §12.13: `{status, verified_count, skipped_v1_count, failure_detail?}`.
/// When `historical_key_gaps` is non-empty, `status` is `"partial_historical"` to
/// distinguish degraded-but-chain-linked from a clean `"ok"` verification.
#[derive(Debug, serde::Serialize)]
pub struct VerifyJsonOutput {
    /// Verification status:
    /// - `"ok"` — clean: all records chain-linked and signature-verified.
    /// - `"partial_historical"` — degraded: some records chain-linked but signature
    ///   verification skipped for a contiguous historical-key prefix.
    /// - `"integrity_failure"` — fatal: `ChainBroken` / `InvalidSignature` /
    ///   `IntegrityBroken` / `HistoricalKeyAtHead` / `GapAfterVerifiedSegment`.
    /// - `"partial"` — `KeyNotFound` (current active key genuinely absent) OR
    ///   `KeychainUnavailable` (key present but transiently unreadable — keychain
    ///   locked / access-denied). Both map to exit code 2.
    pub status: &'static str,
    /// Number of v2 records chain-linked without error (includes historical-key
    /// gap records whose chain-linking was verified but signatures were skipped).
    pub verified_count: u64,
    /// Number of v1 records skipped (not counted toward failures).
    pub skipped_v1_count: u64,
    /// GH #910 — number of records verified OPAQUE-BUT-INTACT because they carry
    /// an `EventKind` a NEWER csq added (signature + hash-chain verified; typed
    /// payload semantics deferred). Included in `verified_count`; surfaced here so
    /// a `--json` consumer sees "ok; N records newer than this reader" instead of
    /// a bare `"ok"`. Omitted when `0` (the common case) so the schema is
    /// byte-identical for chains with no forward records.
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub unknown_kind_count: u64,
    /// Historical-key gaps present when `status == "partial_historical"`.
    /// Omitted (not serialized) when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub historical_key_gaps: Vec<VerifyJsonKeyGap>,
    /// Typed failure detail when `status != "ok"` and `status != "partial_historical"`.
    /// `None` for clean and degraded-historical verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_detail: Option<VerifyFailureDetail>,
    /// M2 T2.5 — trust-plane conformance grade (`"COMPATIBLE"` / `"CONFORMANT"`
    /// / `"COMPLETE"`). **Enterprise edition only**: the community build always
    /// emits `None`, so `skip_serializing_if` omits the field entirely and the
    /// community `--json` schema is byte-identical. `None` (omitted) when the
    /// chain did not verify, or in any community build. See
    /// `crate::audit::trust_grade`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_plane_grade: Option<&'static str>,
    /// M3a — per-level record counts (`"AUTO_APPROVED"` → count, etc. — the
    /// UPPERCASE wire form from `VerificationLevel::as_canonical_str`).
    /// **Enterprise edition only**: community builds always emit `None` so
    /// `skip_serializing_if` omits the field entirely — community `--json`
    /// schema remains byte-identical. `None` (omitted) on verification
    /// failure or when no records carry a level (pre-M3a chains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_level_summary: Option<std::collections::BTreeMap<String, u64>>,
}

/// Compute the trust-plane grade wire string for a verify result.
///
/// Enterprise: delegates to [`crate::audit::grade_for_verify_result`] which
/// sources the real `verification_levels_populated` signal from the summary.
/// Community: always `None` (no trust plane — the field is omitted from
/// `--json`). This is the ONLY grade-computation site for
/// `csq audit verify --json`; the community arm references no enterprise
/// symbol, preserving the edition boundary.
fn trust_plane_grade_str(result: &Result<VerifySummary, LedgerError>) -> Option<&'static str> {
    #[cfg(feature = "enterprise")]
    {
        crate::audit::grade_for_verify_result(result).map(|g| g.as_str())
    }
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = result;
        None
    }
}

/// M3a — build the `verification_level_summary` field for `VerifyJsonOutput`.
///
/// Enterprise: returns the summary map from the verify result (empty map →
/// `None` so the field is omitted for pre-M3a chains). Community: always
/// `None` (field omitted, byte-identical schema).
fn verification_level_summary_for_output(
    result: &Result<VerifySummary, LedgerError>,
) -> Option<std::collections::BTreeMap<String, u64>> {
    #[cfg(feature = "enterprise")]
    {
        if let Ok(ref summary) = result {
            if !summary.verification_level_summary.is_empty() {
                return Some(summary.verification_level_summary.clone());
            }
        }
        None
    }
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = result;
        None
    }
}

/// One entry in the `historical_key_gaps` array of `VerifyJsonOutput`.
#[derive(Debug, serde::Serialize)]
pub struct VerifyJsonKeyGap {
    /// The `key_id` of the absent historical signing key.
    pub key_id: String,
    /// First sequence number in this contiguous gap run.
    pub first_seq: u64,
    /// Last sequence number in this contiguous gap run.
    pub last_seq: u64,
    /// Number of records in the gap (= `last_seq - first_seq + 1`).
    pub count: u64,
}

/// Typed failure detail for `csq audit verify --json`.
#[derive(Debug, serde::Serialize)]
pub struct VerifyFailureDetail {
    /// One of: `"chain_broken"`, `"invalid_signature"`, `"key_not_found"`,
    /// `"integrity_broken"`, `"io_error"`, `"internal"`,
    /// `"unsigned_record_after_cutoff"`.
    pub kind: &'static str,
    /// Human-readable description (fixed vocabulary — no token/path leakage).
    ///
    /// **Leak-safety invariant (redteam R1, security L1).** This field crosses the
    /// operator stdout boundary (`csq audit verify --json`, incl. the SDK
    /// `csq.verify.v1` envelope). Every arm of [`VerifyFailureDetail::from_ledger_error`]
    /// MUST interpolate ONLY (a) shape-validated identifiers (`KeyId` = `ed25519:<hex>`,
    /// `RecordId`, `Sha256Hex`, `u64` seqs) or (b) already-`RedactedString` sub-fields.
    /// A NEW `LedgerError` variant that carries a raw path / upstream body MUST route its
    /// message through `redact_tokens` (tokens) AND must not interpolate a `PathBuf`
    /// (username disclosure). The `_` fallback arm means an omitted arm is NOT a compile
    /// error — so this invariant is the reviewer's checklist, not a type guarantee.
    pub message: String,
}

impl VerifyFailureDetail {
    // `#[non_exhaustive]` on `LedgerError` requires a wildcard arm for
    // exhaustive matching even when all current variants are covered.
    #[allow(unreachable_patterns)]
    fn from_ledger_error(e: &LedgerError) -> Self {
        match e {
            LedgerError::ChainBroken {
                seq,
                expected_prev,
                actual_prev,
            } => Self {
                kind: "chain_broken",
                message: format!(
                    "chain break at seq {seq}: expected {expected_prev}, got {actual_prev}"
                ),
            },
            LedgerError::InvalidSignature { record_id, key_id } => Self {
                kind: "invalid_signature",
                message: format!("invalid signature for record {record_id} (key {key_id})"),
            },
            LedgerError::KeyNotFound { key_id } => Self {
                kind: "key_not_found",
                message: format!("signing key {key_id} not found in keychain"),
            },
            LedgerError::KeychainUnavailable { key_id } => Self {
                kind: "keychain_unavailable",
                message: format!(
                    "signing key {key_id} is present but temporarily inaccessible \
                     (credential store locked / access-denied) — verification deferred, \
                     not failed; retry interactively (`csq audit verify`) or run \
                     `csq audit migrate-keys` to make the key daemon-readable"
                ),
            },
            LedgerError::UnsignedRecordAfterCutoff { seq, cutoff } => Self {
                kind: "unsigned_record_after_cutoff",
                message: format!(
                    "unsigned record at seq {seq}: signing became mandatory at seq {cutoff}"
                ),
            },
            LedgerError::CutoffAnchorMismatch {
                chain_json_cutoff,
                keychain_cutoff,
            } => Self {
                kind: "cutoff_anchor_mismatch",
                message: format!(
                    "audit chain integrity failure: the signing cutoff in chain.json \
                     ({chain_json_cutoff:?}) disagrees with the authoritative value \
                     embedded in the keychain seed entry ({keychain_cutoff}) — this \
                     indicates tampering with chain.json. Run `csq audit verify --full` \
                     for diagnosis."
                ),
            },
            LedgerError::SigningKeyIdAnchorMismatch {
                chain_json_key_id,
                keychain_key_id,
            } => Self {
                kind: "signing_key_id_anchor_mismatch",
                message: format!(
                    "audit chain integrity failure: the signing key identifier in \
                     chain.json ({chain_json_key_id:?}) does not match the authoritative \
                     value embedded in the keychain seed entry ({keychain_key_id:?}) — \
                     this indicates tampering with chain.json. Run `csq audit verify \
                     --full` for diagnosis."
                ),
            },
            LedgerError::IntegrityBroken { seq, reason } => Self {
                kind: "integrity_broken",
                message: format!("integrity check failed at seq {seq}: {reason}"),
            },
            LedgerError::Io { context, .. } => Self {
                kind: "io_error",
                message: format!("storage io error: {context}"),
            },
            LedgerError::NotFound { seq } => Self {
                kind: "not_found",
                message: format!("sequence {seq} not found"),
            },
            LedgerError::Internal { message } => Self {
                kind: "internal",
                // R1-SEC-7 fix: route through fixed tag, not {message} which
                // could carry arbitrary error body in a future variant.
                message: format!(
                    "engine internal error: {}",
                    crate::error::redact_tokens(&message.to_string())
                ),
            },
            LedgerError::MultiSigInvalid { record_id, reason } => Self {
                kind: "multi_sig_invalid",
                message: format!(
                    "multi-sig verification failed for record {record_id}: {reason} — \
                     run `csq audit verify --full` for diagnosis"
                ),
            },
            LedgerError::HistoricalKeyAtHead { head_seq, .. } => Self {
                kind: "historical_key_at_head",
                message: format!(
                    "audit chain head (seq {head_seq}) is signed by a historical key \
                     absent from the keychain — the chain cannot be verified to the \
                     present; run `csq audit verify --full` for diagnosis"
                ),
            },
            LedgerError::GapAfterVerifiedSegment { gap_seq, .. } => Self {
                kind: "gap_after_verified_segment",
                message: format!(
                    "historical-key gap record at seq {gap_seq} appears after a \
                     signature-verified record — invalid rotation order or chain \
                     tampering; run `csq audit verify --full` for diagnosis"
                ),
            },
            _ => Self {
                kind: "unknown",
                // R1-SEC-7 fix: fixed tag, no raw {e} interpolation.
                message: "unclassified ledger error — run csq audit verify --full for diagnosis"
                    .to_string(),
            },
        }
    }
}

/// Exit code for `csq audit verify`:
/// - `0` = clean
/// - `1` = integrity failure (`ChainBroken`, `InvalidSignature`, `IntegrityBroken`,
///   `UnsignedRecordAfterCutoff`, `HistoricalKeyAtHead`, `GapAfterVerifiedSegment`,
///   and every other fatal variant via the `_` arm)
/// - `2` = partial (`KeyNotFound`, `KeychainUnavailable`)
pub fn exit_code_for_error(e: &LedgerError) -> i32 {
    match e {
        // 2 = partial / non-fatal: the chain is not proven clean but this is
        // NOT a hard integrity failure. `KeyNotFound` (key genuinely absent,
        // actionable via rotate-key) and `KeychainUnavailable` (key present but
        // transiently inaccessible, actionable via unlock / migrate-keys) both
        // signal "incomplete, not corrupt".
        LedgerError::KeyNotFound { .. } | LedgerError::KeychainUnavailable { .. } => 2,
        _ => 1,
    }
}

/// Builds the `VerifyJsonOutput` from a verification result.
/// `skip_serializing_if` predicate — omit a `u64` field from `--json` when zero
/// (keeps the common-case schema byte-identical).
fn u64_is_zero(n: &u64) -> bool {
    *n == 0
}

pub fn to_json_output(result: &Result<VerifySummary, LedgerError>) -> VerifyJsonOutput {
    match result {
        Ok(summary) if summary.historical_key_gaps.is_empty() => VerifyJsonOutput {
            status: "ok",
            verified_count: summary.verified_count,
            skipped_v1_count: summary.skipped_v1_count,
            unknown_kind_count: summary.unknown_kind_count,
            historical_key_gaps: Vec::new(),
            failure_detail: None,
            trust_plane_grade: trust_plane_grade_str(result),
            verification_level_summary: verification_level_summary_for_output(result),
        },
        Ok(summary) => {
            // Non-empty historical_key_gaps: chain-linked but degraded.
            let json_gaps = summary
                .historical_key_gaps
                .iter()
                .map(|g| VerifyJsonKeyGap {
                    key_id: g.key_id.clone(),
                    first_seq: g.first_seq,
                    last_seq: g.last_seq,
                    count: g.count,
                })
                .collect();
            VerifyJsonOutput {
                status: "partial_historical",
                verified_count: summary.verified_count,
                skipped_v1_count: summary.skipped_v1_count,
                unknown_kind_count: summary.unknown_kind_count,
                historical_key_gaps: json_gaps,
                failure_detail: None,
                trust_plane_grade: trust_plane_grade_str(result),
                verification_level_summary: verification_level_summary_for_output(result),
            }
        }
        Err(e) => {
            let status = match e {
                LedgerError::KeyNotFound { .. } | LedgerError::KeychainUnavailable { .. } => {
                    "partial"
                }
                _ => "integrity_failure",
            };
            VerifyJsonOutput {
                status,
                verified_count: 0,
                skipped_v1_count: 0,
                unknown_kind_count: 0,
                historical_key_gaps: Vec::new(),
                failure_detail: Some(VerifyFailureDetail::from_ledger_error(e)),
                // Err → chain did not verify → not gradeable → None (omitted).
                // (`trust_plane_grade_str` would also return None here; spelled
                // directly since the Err arm is unconditionally ungradeable.)
                trust_plane_grade: None,
                verification_level_summary: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::audit_init;
    use crate::audit::key_custody::keyring_backend::LocalSigningKey;
    use crate::audit::persist::{write_record_v2, write_record_v2_unchecked, AUDIT_SCHEMA_VERSION};
    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
        SignedRecord,
    };
    use tempfile::TempDir;

    // M2 T2.5 — trust-plane grade is wired into the `--json` output. Under the
    // enterprise edition a clean chain grades COMPATIBLE; the community build
    // omits the field entirely (serde `skip_serializing_if`), preserving the
    // byte-identical community schema.
    #[test]
    fn json_output_grade_for_ok_chain() {
        let result: Result<VerifySummary, LedgerError> = Ok(VerifySummary::default());
        let out = to_json_output(&result);
        #[cfg(feature = "enterprise")]
        assert_eq!(out.trust_plane_grade, Some("COMPATIBLE"));
        #[cfg(not(feature = "enterprise"))]
        assert_eq!(out.trust_plane_grade, None);
    }

    #[test]
    fn json_output_omits_grade_for_err_chain() {
        let key_id = KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap();
        let result: Result<VerifySummary, LedgerError> = Err(LedgerError::KeyNotFound { key_id });
        let out = to_json_output(&result);
        // Err is not gradeable in either edition → None → omitted from JSON.
        assert_eq!(out.trust_plane_grade, None);
        let json = serde_json::to_string(&out).unwrap();
        assert!(
            !json.contains("trust_plane_grade"),
            "an ungradeable chain must omit the field; got: {json}"
        );
    }

    fn sandbox_config(pid_suffix: u32) -> VerifyConfig {
        VerifyConfig {
            record_limit: 10_000,
            keychain_service: format!("csq-audit-signing-test-{pid_suffix}"),
        }
    }

    fn svc_name(tag: &str) -> String {
        format!("csq-audit-signing-test-{}-{}", std::process::id(), tag)
    }

    fn sample_v2_record(record_id_suffix: &str) -> SignedRecord {
        let rid = format!("01JZ0000000000000000000{}", record_id_suffix);
        let rid = if rid.len() >= 26 {
            rid[..26].to_string()
        } else {
            format!("{:0>26}", rid)
        };
        SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new(rid).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "test-run".to_string(),
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

    /// `test verify_integrity_detects_prev_hash_tamper`
    ///
    /// Write two v2 records via `write_record_v2`, then manually tamper with
    /// the second record's `prev_hash` on disk. Verify that `verify_chain`
    /// returns `LedgerError::ChainBroken`.
    #[test]
    fn verify_integrity_detects_prev_hash_tamper() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        write_record_v2(sample_v2_record("R0"), Some(base)).unwrap();
        write_record_v2(sample_v2_record("R1"), Some(base)).unwrap();

        let chain_json: crate::audit::persist::ChainGenesis = {
            let raw = std::fs::read_to_string(base.join("csq-runs/chain.json")).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        let jsonl_path = base
            .join("csq-runs")
            .join(format!("{}.jsonl", chain_json.chain_id));
        let content = std::fs::read_to_string(&jsonl_path).unwrap();

        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 records");
        let mut rec1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        rec1["prev_hash"] = serde_json::Value::String("f".repeat(64));
        let tampered = format!("{}\n{}\n", lines[0], rec1);
        std::fs::write(&jsonl_path, &tampered).unwrap();

        let cfg = sandbox_config(std::process::id());
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::ChainBroken { seq: 1, .. })),
            "expected ChainBroken at seq 1, got: {result:?}"
        );
    }

    /// `test verify_integrity_clean_chain_ok`
    ///
    /// Write three v2 records via `write_record_v2`. Verify that `verify_chain`
    /// returns `Ok` with `verified_count == 3`.
    #[test]
    fn verify_integrity_clean_chain_ok() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        write_record_v2(sample_v2_record("R0"), Some(base)).unwrap();
        write_record_v2(sample_v2_record("R1"), Some(base)).unwrap();
        write_record_v2(sample_v2_record("R2"), Some(base)).unwrap();

        let cfg = sandbox_config(std::process::id());
        let result = verify_chain(base, &cfg, None);
        match &result {
            Ok(summary) => {
                assert_eq!(summary.verified_count, 3, "expected 3 verified records");
                assert_eq!(summary.skipped_v1_count, 0);
            }
            Err(e) => panic!("expected Ok, got Err: {e:?}"),
        }
    }

    /// `test verify_integrity_empty_chain_ok`
    ///
    /// No `chain.json` → `verify_chain` returns `Ok` with all zeros.
    #[test]
    fn verify_integrity_empty_chain_ok() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = TempDir::new().unwrap();
        let cfg = sandbox_config(std::process::id());
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Ok(ref s) if s.verified_count == 0 && s.skipped_v1_count == 0),
            "expected Ok with all zeros, got: {result:?}"
        );
    }

    /// `test verify_integrity_detects_seq_gap`
    ///
    /// Write two v2 records, then manually set record[1].seq to 5.
    /// Verify that `verify_chain` returns `LedgerError::IntegrityBroken`.
    #[test]
    fn verify_integrity_detects_seq_gap() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        write_record_v2(sample_v2_record("R0"), Some(base)).unwrap();
        write_record_v2(sample_v2_record("R1"), Some(base)).unwrap();

        let chain_json: crate::audit::persist::ChainGenesis = {
            let raw = std::fs::read_to_string(base.join("csq-runs/chain.json")).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        let jsonl_path = base
            .join("csq-runs")
            .join(format!("{}.jsonl", chain_json.chain_id));
        let content = std::fs::read_to_string(&jsonl_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let mut rec1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        rec1["seq"] = serde_json::Value::Number(serde_json::Number::from(5u64));
        let tampered = format!("{}\n{}\n", lines[0], rec1);
        std::fs::write(&jsonl_path, &tampered).unwrap();

        let cfg = sandbox_config(std::process::id());
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::IntegrityBroken { .. })),
            "expected IntegrityBroken for seq gap, got: {result:?}"
        );
    }

    /// `test verify_integrity_skips_v1_records`
    ///
    /// Write a v1 JSONL line directly into the chain file, then a valid v2
    /// record. Verify that `verify_chain` returns Ok and `skipped_v1_count == 1`.
    #[test]
    fn verify_integrity_skips_v1_records() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        write_record_v2(sample_v2_record("R0"), Some(base)).unwrap();

        let chain_json: crate::audit::persist::ChainGenesis = {
            let raw = std::fs::read_to_string(base.join("csq-runs/chain.json")).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        let jsonl_path = base
            .join("csq-runs")
            .join(format!("{}.jsonl", chain_json.chain_id));

        let v2_content = std::fs::read_to_string(&jsonl_path).unwrap();
        let v1_line = r#"{"schema_version":"1","run_id":"test-run-v1","fixture_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","coc_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","csq_version":"1.0.0","cli_version":"1.0.0","surface":"cc","model":"claude-opus-4-7","start_ts":"2026-05-01T00:00:00Z","end_ts":"2026-05-01T00:00:01Z","result_state":"pass","score_delta_vs_baseline":null,"rule_ids_cited_original":[],"rule_ids_cited_after_repair":[],"rule_ids_dropped_invalid_format":0,"decision":"accept"}"#;
        let combined = format!("{v1_line}\n{v2_content}");
        std::fs::write(&jsonl_path, &combined).unwrap();

        let cfg = sandbox_config(std::process::id());
        let result = verify_chain(base, &cfg, None);
        match &result {
            Ok(summary) => {
                assert_eq!(summary.skipped_v1_count, 1, "expected 1 skipped v1 record");
                assert_eq!(summary.verified_count, 1, "expected 1 verified v2 record");
            }
            Err(e) => panic!("expected Ok, got Err: {e:?}"),
        }
    }

    /// `test verify_json_output_shape`
    ///
    /// Verify that `to_json_output` produces the expected fields for both
    /// success and failure cases.
    #[test]
    fn verify_json_output_shape() {
        let ok_summary = VerifySummary {
            verified_count: 42,
            skipped_v1_count: 3,
            limit_exceeded_count: 0,
            head_seq: 41,
            historical_key_gaps: Vec::new(),
            ..VerifySummary::default()
        };
        let ok_result: Result<VerifySummary, LedgerError> = Ok(ok_summary);
        let ok_json = to_json_output(&ok_result);
        assert_eq!(ok_json.status, "ok");
        assert_eq!(ok_json.verified_count, 42);
        assert_eq!(ok_json.skipped_v1_count, 3);
        assert!(ok_json.failure_detail.is_none());

        let json_str = serde_json::to_string(&ok_json).unwrap();
        assert!(json_str.contains("\"status\":\"ok\""));
        assert!(json_str.contains("\"verified_count\":42"));
        assert!(json_str.contains("\"skipped_v1_count\":3"));
        assert!(!json_str.contains("failure_detail"));

        let fail_result: Result<VerifySummary, LedgerError> = Err(LedgerError::ChainBroken {
            seq: 7,
            expected_prev: Sha256Hex::genesis(),
            actual_prev: Sha256Hex::try_new("f".repeat(64)).unwrap(),
        });
        let fail_json = to_json_output(&fail_result);
        assert_eq!(fail_json.status, "integrity_failure");
        assert!(fail_json.failure_detail.is_some());
        let detail = fail_json.failure_detail.unwrap();
        assert_eq!(detail.kind, "chain_broken");
        assert!(detail.message.contains("seq 7"));
    }

    /// `test verify_exit_codes`
    ///
    /// Check exit code mapping: integrity failure → 1, key not found → 2.
    #[test]
    fn verify_exit_codes() {
        let broken = LedgerError::ChainBroken {
            seq: 0,
            expected_prev: Sha256Hex::genesis(),
            actual_prev: Sha256Hex::genesis(),
        };
        assert_eq!(exit_code_for_error(&broken), 1);

        let key_not_found = LedgerError::KeyNotFound {
            key_id: KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).unwrap(),
        };
        assert_eq!(exit_code_for_error(&key_not_found), 2);
    }

    // ── R1 security tests (5 mandatory new tests) ──────────────────────────────

    /// Test 1 (R1-SEC-3 mandatory): `verify_chain_accepts_valid_signature`
    ///
    /// Mint a real Ed25519 key via audit_init, write a record via write_record_v2
    /// (which does NOT sign — placeholder key), then manually sign a record using
    /// LocalSigningKey per the unified contract and write it to disk. Assert
    /// verify_chain returns Ok.
    ///
    /// NOTE: write_record_v2 currently writes placeholder-key records.
    /// This test exercises the SIGNED path by building a properly-signed record
    /// directly and using a fresh chain with signing_active_since_seq set.
    #[test]
    fn verify_chain_accepts_valid_signature() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("accept_valid_sig");

        // Bootstrap chain.json with a valid chain_id.
        use crate::audit::key_custody::chain_state::ChainState;
        let chain_id = "01JZ00000000000000000000AA";
        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);

        // audit_init: generates key, sets signing_active_since_seq = 0
        // (fresh chain, no existing records).
        audit_init(base, &svc).expect("audit_init");

        // Load the key and chain state.
        let _chain_state = ChainState::load(base).expect("load chain_state");
        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        // Build a properly-signed v2 record per the unified contract:
        // (a) Set canonical_hash = genesis sentinel
        // (b) canonical_bytes_for(&record) → bytes
        // (c) sha256_hex(bytes) → real canonical_hash
        // (d) Set record.canonical_hash
        // (e) canonical_bytes_for(&record) → signing pre-image
        // (f) sha256 → 32 bytes
        // (g) sign

        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000BB").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "test-valid-sig".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
            canonical_hash: Sha256Hex::genesis(), // sentinel
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };

        // (b+c+d) compute real canonical_hash
        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();

        // (e+f+g) sign
        // Unified contract (R1-SEC-4): sign the 32 raw bytes of canonical_hash.
        let digest_bytes: [u8; 32] = {
            let bytes =
                hex::decode(record.canonical_hash.as_str()).expect("canonical_hash is valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig = signing_key.sign(&digest_bytes).expect("sign");
        record.signature = sig;

        // Write directly to the JSONL file.
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let line = serde_json::to_string(&record).unwrap() + "\n";
        std::fs::write(&jsonl_path, line.as_bytes()).unwrap();

        // Verify.
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Ok(ref s) if s.verified_count == 1),
            "verify_chain_accepts_valid_signature: expected Ok(1 verified), got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    // ── GH #910 — forward-compat opaque-record tests ─────────────────────────
    //
    // These build GENUINELY-SIGNED records whose `EventKind` this binary does
    // NOT know (as a NEWER writer would emit), then assert `verify_chain` treats
    // them as OPAQUE-BUT-INTACT (signature + hash-chain verified) rather than
    // `IntegrityBroken`. Tampered / bad-signature unknown records still fail.

    fn hex32(hex: &str) -> [u8; 32] {
        let b = hex::decode(hex).expect("valid hex");
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    }

    /// Seal a KNOWN record: compute its real `canonical_hash`, sign, and return
    /// its JSONL line. `record.canonical_hash` MUST be the genesis sentinel on
    /// entry (the Check-4 pre-image basis).
    fn seal_known(mut record: SignedRecord, signing_key: &LocalSigningKey) -> String {
        use crate::audit::persist::{canonical_bytes_for, sha256_hex};
        let sentinel = canonical_bytes_for(&record);
        record.canonical_hash = Sha256Hex::try_new(sha256_hex(&sentinel)).unwrap();
        record.signature = signing_key
            .sign(&hex32(record.canonical_hash.as_str()))
            .unwrap();
        serde_json::to_string(&record).unwrap()
    }

    /// Build a SIGNED record whose `EventKind` (`kind`) is UNKNOWN to this
    /// binary, exactly as a newer writer would produce it: the canonical hash is
    /// computed over the verbatim (opaque) canonical view and the Ed25519
    /// signature covers it. Returns the JSONL line (as a serde_json::Value so
    /// callers can tamper specific fields).
    fn build_signed_unknown(
        chain_id: &str,
        record_id: &str,
        seq: u64,
        prev_hash: &str,
        kind: &str,
        signing_key: &LocalSigningKey,
        authority: Option<serde_json::Value>,
    ) -> serde_json::Value {
        use crate::audit::opaque::{canonical_bytes_for_opaque_check4, OpaqueRecord};
        use crate::audit::persist::sha256_hex;
        let mut rec = serde_json::json!({
            "schema_version": "2",
            "record_id": record_id,
            "chain_id": chain_id,
            "seq": seq,
            "prev_hash": prev_hash,
            "kind": kind,
            "payload": { "kind": kind, "data": { "note": "future-payload", "n": 7 } },
            "ts": "2026-05-28T12:00:00+00:00",
            "key_id": signing_key.key_id().as_str(),
            "canonical_hash": Sha256Hex::GENESIS,
            "signature": "0".repeat(128),
        });
        if let Some(auth) = authority {
            rec["authority"] = auth;
        }
        // Recompute the canonical hash the way a kind-aware writer would (byte-
        // identical via OpaqueCanonicalView) and sign it.
        let opaque: OpaqueRecord = serde_json::from_value(rec.clone()).expect("opaque parse");
        let real_hash = sha256_hex(&canonical_bytes_for_opaque_check4(&opaque));
        rec["canonical_hash"] = serde_json::Value::String(real_hash.clone());
        let sig = signing_key.sign(&hex32(&real_hash)).unwrap();
        rec["signature"] = serde_json::to_value(sig).unwrap();
        rec
    }

    /// The canonical-link bytes of a sealed (real-hash) opaque record line — used
    /// to compute the NEXT record's `prev_hash`.
    fn opaque_link_hash(line: &serde_json::Value) -> String {
        use crate::audit::opaque::{canonical_bytes_for_opaque_link, OpaqueRecord};
        use crate::audit::persist::sha256_hex;
        let opaque: OpaqueRecord = serde_json::from_value(line.clone()).unwrap();
        sha256_hex(&canonical_bytes_for_opaque_link(&opaque))
    }

    fn setup_signed_chain(tag: &str, chain_id: &str) -> (TempDir, String, LocalSigningKey) {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = svc_name(tag);
        use crate::audit::key_custody::chain_state::ChainState;
        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(tmp.path(), &svc).expect("audit_init");
        let key = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load key");
        (tmp, svc, key)
    }

    fn write_jsonl(base: &Path, chain_id: &str, lines: &[String]) {
        let dir = base.join("csq-runs");
        std::fs::create_dir_all(&dir).unwrap();
        let body = lines.join("\n") + "\n";
        std::fs::write(dir.join(format!("{chain_id}.jsonl")), body).unwrap();
    }

    /// T1 / T14 — THE anti-brick test: a genesis record with an unknown
    /// EventKind + valid signature verifies OK (not IntegrityBroken), is counted
    /// in `verified_count`, and is surfaced via `unknown_kind_count`.
    #[test]
    fn verify_chain_accepts_unknown_kind_as_opaque_intact() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C01";
        let (tmp, svc, key) = setup_signed_chain("opaque_intact", chain_id);
        let rec = build_signed_unknown(
            chain_id,
            "01JZ0000000000000000000D01",
            0,
            Sha256Hex::GENESIS,
            "quantum_attestation_v9",
            &key,
            None,
        );
        write_jsonl(
            tmp.path(),
            chain_id,
            &[serde_json::to_string(&rec).unwrap()],
        );
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Ok(ref s) if s.verified_count == 1 && s.unknown_kind_count == 1),
            "expected Ok(verified=1, unknown_kind=1), got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// T2 — an unknown-kind record whose payload was tampered AFTER signing fails
    /// Check 4 (canonical_hash recompute) → IntegrityBroken. Proves the opaque
    /// path is NOT a tamper-blind pass-through.
    #[test]
    fn verify_chain_rejects_tampered_unknown_kind_payload() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C02";
        let (tmp, svc, key) = setup_signed_chain("opaque_tamper", chain_id);
        let rec = build_signed_unknown(
            chain_id,
            "01JZ0000000000000000000D02",
            0,
            Sha256Hex::GENESIS,
            "quantum_attestation_v9",
            &key,
            None,
        );
        // Tamper the payload bytes without recomputing canonical_hash/signature.
        let line =
            serde_json::to_string(&rec)
                .unwrap()
                .replacen("future-payload", "TAMPERD-paylod", 1);
        write_jsonl(tmp.path(), chain_id, &[line]);
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::IntegrityBroken { seq: 0, .. })),
            "tampered unknown-kind payload must be IntegrityBroken, got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// T3 — an unknown-kind record with a VALID canonical_hash but a WRONG
    /// signature fails Check 5 → InvalidSignature (not accepted as opaque-intact).
    #[test]
    fn verify_chain_rejects_unknown_kind_bad_signature() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C03";
        let (tmp, svc, key) = setup_signed_chain("opaque_badsig", chain_id);
        let mut rec = build_signed_unknown(
            chain_id,
            "01JZ0000000000000000000D03",
            0,
            Sha256Hex::GENESIS,
            "quantum_attestation_v9",
            &key,
            None,
        );
        // Replace the signature with a valid-hex-but-wrong 64-byte value.
        rec["signature"] = serde_json::Value::String("9".repeat(128));
        write_jsonl(
            tmp.path(),
            chain_id,
            &[serde_json::to_string(&rec).unwrap()],
        );
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::InvalidSignature { .. })),
            "wrong-signature unknown-kind record must be InvalidSignature, got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// T7 — a mixed chain known(0) → unknown(1) → known(2), all valid, verifies
    /// clean: seq stays monotonic, the prev_hash link across the opaque record
    /// holds (Check 3 on record 2 depends on the opaque record's link bytes),
    /// verified_count == 3, unknown_kind_count == 1, head_seq == 2.
    #[test]
    fn verify_chain_mixed_known_and_unknown_chain() {
        use crate::audit::persist::{canonical_bytes_for, sha256_hex};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C04";
        let (tmp, svc, key) = setup_signed_chain("opaque_mixed", chain_id);

        // Record 0 (known, genesis).
        let r0 = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01JZ0000000000000000000E00").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "r0".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: key.key_id().clone(),
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
        let l0 = seal_known(r0.clone(), &key);
        // Recompute r0's link hash for record 1's prev_hash.
        let r0_sealed: SignedRecord = serde_json::from_str(&l0).unwrap();
        let prev1 = sha256_hex(&canonical_bytes_for(&r0_sealed));

        // Record 1 (unknown kind).
        let u1 = build_signed_unknown(
            chain_id,
            "01JZ0000000000000000000E01",
            1,
            &prev1,
            "quantum_attestation_v9",
            &key,
            None,
        );
        let prev2 = opaque_link_hash(&u1);
        let l1 = serde_json::to_string(&u1).unwrap();

        // Record 2 (known again — its Check 3 depends on the opaque link bytes).
        let r2 = SignedRecord {
            record_id: RecordId::try_new("01JZ0000000000000000000E02").unwrap(),
            seq: 2,
            prev_hash: Sha256Hex::try_new(prev2).unwrap(),
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "r2".to_string(),
            }),
            canonical_hash: Sha256Hex::genesis(),
            ..r0
        };
        let l2 = seal_known(r2, &key);

        write_jsonl(tmp.path(), chain_id, &[l0, l1, l2]);
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Ok(ref s)
                if s.verified_count == 3 && s.unknown_kind_count == 1 && s.head_seq == 2),
            "mixed chain must verify clean (3 records, 1 opaque, head=2), got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// T16 — an unknown-kind record carrying a `multi_sig` authority blob with
    /// threshold > satisfied authorizations is rejected (`MultiSigInvalid`): the
    /// pure-M11 inner-threshold check runs on opaque records too, so a forged
    /// under-threshold blob cannot pass by being an unknown kind.
    #[test]
    fn verify_chain_opaque_under_threshold_multisig_rejected() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C05";
        let (tmp, svc, key) = setup_signed_chain("opaque_multisig", chain_id);
        // threshold 2, but zero authorizations → under threshold.
        let authority = serde_json::json!({
            "multi_sig": { "threshold": 2, "authorizations": [] }
        });
        let rec = build_signed_unknown(
            chain_id,
            "01JZ0000000000000000000D05",
            0,
            Sha256Hex::GENESIS,
            "quantum_guarded_op_v9",
            &key,
            Some(authority),
        );
        write_jsonl(
            tmp.path(),
            chain_id,
            &[serde_json::to_string(&rec).unwrap()],
        );
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::MultiSigInvalid { .. })),
            "opaque record with under-threshold multi_sig must be MultiSigInvalid, got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// T9 — an unknown-kind record signed with the PLACEHOLDER key AFTER the
    /// signing cutoff is rejected (`UnsignedRecordAfterCutoff`) exactly like a
    /// known unsigned record: the cutoff gate is kind-agnostic.
    #[test]
    fn verify_chain_rejects_unknown_kind_placeholder_after_cutoff() {
        use crate::audit::opaque::{canonical_bytes_for_opaque_check4, OpaqueRecord};
        use crate::audit::persist::sha256_hex;
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C06";
        let (tmp, svc, _key) = setup_signed_chain("opaque_placeholder", chain_id);
        // Build an unsigned (placeholder-key) unknown-kind record at seq 0 with a
        // VALID canonical_hash (so it fails at the cutoff gate, not Check 4).
        let placeholder = format!("ed25519:{}", "0".repeat(64));
        let mut rec = serde_json::json!({
            "schema_version": "2",
            "record_id": "01JZ0000000000000000000D06",
            "chain_id": chain_id,
            "seq": 0,
            "prev_hash": Sha256Hex::GENESIS,
            "kind": "quantum_attestation_v9",
            "payload": { "kind": "quantum_attestation_v9", "data": { "note": "x" } },
            "ts": "2026-05-28T12:00:00+00:00",
            "key_id": placeholder,
            "canonical_hash": Sha256Hex::GENESIS,
            "signature": "0".repeat(128),
        });
        let opaque: OpaqueRecord = serde_json::from_value(rec.clone()).unwrap();
        rec["canonical_hash"] =
            serde_json::Value::String(sha256_hex(&canonical_bytes_for_opaque_check4(&opaque)));
        write_jsonl(
            tmp.path(),
            chain_id,
            &[serde_json::to_string(&rec).unwrap()],
        );
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(
                result,
                Err(LedgerError::UnsignedRecordAfterCutoff { seq: 0, cutoff: 0 })
            ),
            "unsigned unknown-kind record after cutoff must be UnsignedRecordAfterCutoff, got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Redteam R1 (deep-analyst LOW): an unknown-kind record at the HEAD signed by
    /// a rotated-out (absent) key takes the historical-key-gap path and — because
    /// the gap is the head — is FATAL (`HistoricalKeyAtHead`), exactly like a typed
    /// record. Locks the gap logic against future accessor drift on the opaque path.
    #[test]
    fn verify_chain_opaque_record_head_via_historical_gap_is_fatal() {
        use crate::audit::opaque::{canonical_bytes_for_opaque_check4, OpaqueRecord};
        use crate::audit::persist::sha256_hex;
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C07";
        // audit_init records a CURRENT active key; the fabricated key below differs
        // from it (and from the placeholder), so it classifies as rotated-out.
        let (tmp, svc, _key) = setup_signed_chain("opaque_gap_head", chain_id);
        let fabricated = format!("ed25519:{}", "1".repeat(64));
        let mut rec = serde_json::json!({
            "schema_version": "2",
            "record_id": "01JZ0000000000000000000D07",
            "chain_id": chain_id,
            "seq": 0,
            "prev_hash": Sha256Hex::GENESIS,
            "kind": "quantum_attestation_v9",
            "payload": { "kind": "quantum_attestation_v9", "data": { "note": "x" } },
            "ts": "2026-05-28T12:00:00+00:00",
            "key_id": fabricated,
            "canonical_hash": Sha256Hex::GENESIS,
            // Valid-hex garbage sig: it is NEVER checked (the gap path skips the
            // signature), but must parse as an Ed25519Signature so the record is
            // an OpaqueRecord (not a corrupt line).
            "signature": "f".repeat(128),
        });
        let opaque: OpaqueRecord = serde_json::from_value(rec.clone()).unwrap();
        rec["canonical_hash"] =
            serde_json::Value::String(sha256_hex(&canonical_bytes_for_opaque_check4(&opaque)));
        write_jsonl(
            tmp.path(),
            chain_id,
            &[serde_json::to_string(&rec).unwrap()],
        );
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::HistoricalKeyAtHead { head_seq: 0, .. })),
            "opaque head record via historical-key gap must be HistoricalKeyAtHead, got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Redteam R1 (deep-analyst LOW): an opaque record as the FIRST record in the
    /// surviving window after the tail-limit drops earlier records exercises the
    /// mid-chain-start seed branch — its `canonical_bytes_link()` must seed
    /// `prev_canonical_bytes` so the NEXT (known) record's prev_hash link holds.
    #[test]
    fn verify_chain_opaque_record_first_under_tail_limit() {
        use crate::audit::persist::{canonical_bytes_for, sha256_hex};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C08";
        let (tmp, svc, key) = setup_signed_chain("opaque_tail_limit", chain_id);

        // r0 (known genesis) — will be DROPPED by the tail-limit.
        let r0 = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01JZ0000000000000000000E10").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "r0".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: key.key_id().clone(),
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
        let l0 = seal_known(r0.clone(), &key);
        let r0_sealed: SignedRecord = serde_json::from_str(&l0).unwrap();
        let prev1 = sha256_hex(&canonical_bytes_for(&r0_sealed));

        // u1 (opaque) — first in the surviving window; seeds via the opaque link.
        let u1 = build_signed_unknown(
            chain_id,
            "01JZ0000000000000000000E11",
            1,
            &prev1,
            "quantum_attestation_v9",
            &key,
            None,
        );
        let prev2 = opaque_link_hash(&u1);
        let l1 = serde_json::to_string(&u1).unwrap();

        // r2 (known) — its Check 3 depends on u1's seed being byte-correct.
        let r2 = SignedRecord {
            record_id: RecordId::try_new("01JZ0000000000000000000E12").unwrap(),
            seq: 2,
            prev_hash: Sha256Hex::try_new(prev2).unwrap(),
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "r2".to_string(),
            }),
            canonical_hash: Sha256Hex::genesis(),
            ..r0
        };
        let l2 = seal_known(r2, &key);

        write_jsonl(tmp.path(), chain_id, &[l0, l1, l2]);
        // record_limit = 2 drops r0; the window is [u1(opaque), r2]. u1 is the
        // first-in-window mid-chain seed; r2's prev_hash must link off it.
        let cfg = VerifyConfig {
            record_limit: 2,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Ok(ref s)
                if s.verified_count == 2 && s.unknown_kind_count == 1 && s.head_seq == 2
                    && s.limit_exceeded_count == 1),
            "opaque-first-under-tail-limit must verify clean (2 in window, 1 opaque, head=2), got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Redteam R1 (security L2): an opaque record whose VERBATIM payload contains
    /// the `"schema_version":"1"` substring must route to the opaque verify path,
    /// NOT be misclassified as a v1-skip (which would drop it silently and break
    /// the chain). The v1 classifier only skips a line that parses as NEITHER a
    /// typed nor an opaque v2 record.
    #[test]
    fn verify_chain_opaque_payload_with_v1_substring_not_skipped() {
        use crate::audit::opaque::{canonical_bytes_for_opaque_check4, OpaqueRecord};
        use crate::audit::persist::sha256_hex;
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let chain_id = "01JZ0000000000000000000C09";
        let (tmp, svc, key) = setup_signed_chain("opaque_v1_substr", chain_id);
        // The payload embeds the exact v1-classifier substring as a string VALUE.
        let mut rec = serde_json::json!({
            "schema_version": "2",
            "record_id": "01JZ0000000000000000000D09",
            "chain_id": chain_id,
            "seq": 0,
            "prev_hash": Sha256Hex::GENESIS,
            "kind": "quantum_attestation_v9",
            "payload": { "kind": "quantum_attestation_v9",
                         "data": { "note": "contains \"schema_version\":\"1\" inside" } },
            "ts": "2026-05-28T12:00:00+00:00",
            "key_id": key.key_id().as_str(),
            "canonical_hash": Sha256Hex::GENESIS,
            "signature": "0".repeat(128),
        });
        let opaque: OpaqueRecord = serde_json::from_value(rec.clone()).unwrap();
        let real_hash = sha256_hex(&canonical_bytes_for_opaque_check4(&opaque));
        rec["canonical_hash"] = serde_json::Value::String(real_hash.clone());
        rec["signature"] = serde_json::to_value(key.sign(&hex32(&real_hash)).unwrap()).unwrap();
        let line = serde_json::to_string(&rec).unwrap();
        assert!(
            line.contains("\\\"schema_version\\\":\\\"1\\\"")
                || line.contains("schema_version\":\"1"),
            "test line must actually contain the v1 substring (else it proves nothing)"
        );
        write_jsonl(tmp.path(), chain_id, &[line]);
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(tmp.path(), &cfg, None);
        assert!(
            matches!(result, Ok(ref s)
                if s.verified_count == 1 && s.unknown_kind_count == 1 && s.skipped_v1_count == 0),
            "opaque record with v1 substring in payload must verify as opaque (not v1-skipped), got: {result:?}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Redteam R1 (security L1): `to_json_output` surfaces `unknown_kind_count` in
    /// the `--json` verdict when non-zero, and omits it when zero (keeping the
    /// common-case schema byte-identical).
    #[test]
    fn to_json_output_surfaces_unknown_kind_count() {
        let with_opaque = VerifySummary {
            verified_count: 3,
            unknown_kind_count: 2,
            ..VerifySummary::default()
        };
        let out = to_json_output(&Ok(with_opaque));
        assert_eq!(out.status, "ok");
        assert_eq!(out.unknown_kind_count, 2);
        let json = serde_json::to_string(&out).unwrap();
        assert!(
            json.contains("\"unknown_kind_count\":2"),
            "non-zero unknown_kind_count must be present in --json: {json}"
        );

        let clean = VerifySummary {
            verified_count: 1,
            ..VerifySummary::default()
        };
        let clean_json = serde_json::to_string(&to_json_output(&Ok(clean))).unwrap();
        assert!(
            !clean_json.contains("unknown_kind_count"),
            "zero unknown_kind_count must be omitted from --json: {clean_json}"
        );
    }

    /// M3 §10.5 (W2a): `verify_chain_in(ChainKind::Eatp)` performs FULL
    /// signature + chain-linking verification on records under `eatp-runs/`,
    /// fully isolated from the op-chain under `csq-runs/`:
    /// - a valid EATP chain verifies clean via the `Eatp` selector;
    /// - the `Op` selector (and the `verify_chain` wrapper) does NOT see the
    ///   EATP records — it verifies only `csq-runs/`;
    /// - tampering the EATP JSONL is caught by the `Eatp` selector while the
    ///   op-chain still verifies clean (independent fault domains).
    ///
    /// Test artifice: the EATP chain here reuses the op-chain's `chain_id` + key
    /// seed so the existing `audit_init` bootstrap can stand up a verifiable
    /// chain WITHOUT W2b's per-EATP-chain key custody. W2a's surface is the
    /// verify-side subdir parameterization; the born-canonical genesis writer
    /// that gives the EATP chain its OWN `chain_id` + seed is W2b.
    #[test]
    fn verify_chain_in_eatp_verifies_and_is_isolated_from_op() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("eatp_verify_isolated");

        use crate::audit::key_custody::chain_state::ChainState;
        let chain_id = "01JZ00000000000000000000AA";
        ChainState::new(chain_id)
            .save(base)
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");
        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000BB").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "test-eatp-isolated".to_string(),
            }),
            ts: "2026-06-27T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
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
        let real_hash_hex = sha256_hex(&canonical_bytes_for(&record));
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();
        let digest_bytes: [u8; 32] = {
            let bytes = hex::decode(record.canonical_hash.as_str()).unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        record.signature = signing_key.sign(&digest_bytes).expect("sign");
        let line = serde_json::to_string(&record).unwrap() + "\n";

        // Write the SAME valid chain to BOTH subdirs (shared chain_id artifice).
        let op_runs = base.join("csq-runs");
        let eatp_runs = base.join("eatp-runs");
        std::fs::create_dir_all(&op_runs).unwrap();
        std::fs::create_dir_all(&eatp_runs).unwrap();
        std::fs::write(op_runs.join(format!("{chain_id}.jsonl")), line.as_bytes()).unwrap();
        std::fs::write(eatp_runs.join(format!("{chain_id}.jsonl")), line.as_bytes()).unwrap();
        // Mirror chain.json into eatp-runs/ so the Eatp selector loads identity.
        std::fs::copy(op_runs.join("chain.json"), eatp_runs.join("chain.json")).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };

        // Both selectors verify their own subdir clean.
        let op = verify_chain_in(base, &cfg, None, ChainKind::Op);
        assert!(
            matches!(op, Ok(ref s) if s.verified_count == 1),
            "Op selector verifies csq-runs/: {op:?}"
        );
        let eatp = verify_chain_in(base, &cfg, None, ChainKind::Eatp);
        assert!(
            matches!(eatp, Ok(ref s) if s.verified_count == 1),
            "Eatp selector verifies eatp-runs/: {eatp:?}"
        );
        // The `verify_chain` wrapper is the Op selector (delegation invariant).
        let wrapper = verify_chain(base, &cfg, None);
        assert!(matches!(wrapper, Ok(ref s) if s.verified_count == 1));

        // Tamper ONLY the EATP JSONL (flip a signature byte). The Eatp selector
        // must catch it; the op-chain remains clean (independent fault domains).
        let mut tampered = record.clone();
        let mut sig_bytes = *tampered.signature.as_bytes();
        sig_bytes[0] ^= 0x01;
        tampered.signature = Ed25519Signature::new(sig_bytes);
        let tampered_line = serde_json::to_string(&tampered).unwrap() + "\n";
        std::fs::write(
            eatp_runs.join(format!("{chain_id}.jsonl")),
            tampered_line.as_bytes(),
        )
        .unwrap();

        let eatp_after = verify_chain_in(base, &cfg, None, ChainKind::Eatp);
        assert!(
            matches!(eatp_after, Err(LedgerError::InvalidSignature { .. })),
            "Eatp selector catches the tampered EATP signature: {eatp_after:?}"
        );
        let op_after = verify_chain_in(base, &cfg, None, ChainKind::Op);
        assert!(
            matches!(op_after, Ok(ref s) if s.verified_count == 1),
            "op-chain unaffected by EATP tamper: {op_after:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Test 2 (R1-SEC-3 mandatory): `verify_chain_rejects_tampered_signature`
    ///
    /// Build and sign a record per the unified contract (same as test 1),
    /// then flip one byte of the signature. Assert InvalidSignature.
    #[test]
    fn verify_chain_rejects_tampered_signature() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("reject_tampered_sig");

        let chain_id = "01JZ00000000000000000000CC";
        use crate::audit::key_custody::chain_state::ChainState;
        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000DD").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "test-tampered-sig".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
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

        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();

        // Unified contract (R1-SEC-4): sign the 32 raw bytes of canonical_hash.
        let digest_bytes: [u8; 32] = {
            let bytes =
                hex::decode(record.canonical_hash.as_str()).expect("canonical_hash is valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig = signing_key.sign(&digest_bytes).expect("sign");
        record.signature = sig;

        // Tamper: flip first byte of signature.
        let mut sig_bytes = record.signature.0;
        sig_bytes[0] ^= 0xff;
        record.signature = crate::audit::types::Ed25519Signature::new(sig_bytes);

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let line = serde_json::to_string(&record).unwrap() + "\n";
        std::fs::write(&jsonl_path, line.as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::InvalidSignature { .. })),
            "verify_chain_rejects_tampered_signature: expected InvalidSignature, got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Test 3 (R1-SEC-3 mandatory): `verify_chain_rejects_tampered_payload_via_canonical_hash`
    ///
    /// Build and sign a record, write it, then mutate the payload field on
    /// disk while keeping the stored canonical_hash and signature unchanged.
    /// Assert IntegrityBroken (canonical_hash mismatch detected at Check 4).
    #[test]
    fn verify_chain_rejects_tampered_payload_via_canonical_hash() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("reject_tampered_payload");

        let chain_id = "01JZ00000000000000000000EE";
        use crate::audit::key_custody::chain_state::ChainState;
        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000FF").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "original-run-id".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
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

        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();

        // Unified contract (R1-SEC-4): sign the 32 raw bytes of canonical_hash.
        let digest_bytes: [u8; 32] = {
            let bytes =
                hex::decode(record.canonical_hash.as_str()).expect("canonical_hash is valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig = signing_key.sign(&digest_bytes).expect("sign");
        record.signature = sig;

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let good_line = serde_json::to_string(&record).unwrap();

        // Tamper: replace run_id in the JSON text (payload mutation).
        let tampered_line = good_line.replace("original-run-id", "attacker-injected-id");
        assert_ne!(
            tampered_line, good_line,
            "tamper must have changed the line"
        );
        std::fs::write(&jsonl_path, (tampered_line + "\n").as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::IntegrityBroken { .. })),
            "verify_chain_rejects_tampered_payload_via_canonical_hash: expected IntegrityBroken, got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Test 4 (R1-SEC-3 mandatory): `verify_chain_rejects_placeholder_key_after_cutoff`
    ///
    /// Write a placeholder-key record at seq >= signing_active_since_seq
    /// (cutoff = 0 means ALL records must be signed). Assert
    /// UnsignedRecordAfterCutoff.
    /// Test 4 (R1-SEC-3 mandatory): `verify_chain_rejects_placeholder_key_after_cutoff`
    ///
    /// Write a placeholder-key record at seq >= the authoritative cutoff.
    /// Cutoff = 0 means ALL records must be signed.
    ///
    /// M-hardening update: the cutoff is now read from the keychain seed entry
    /// (not directly from chain.json).  We use `audit_init` to establish the
    /// cutoff properly (writing the seed entry with embedded cutoff = 0), then
    /// write a placeholder record at seq 0 which falls AT the cutoff.
    /// Assert `UnsignedRecordAfterCutoff`.
    #[test]
    fn verify_chain_rejects_placeholder_key_after_cutoff() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("reject_placeholder_after_cutoff");

        let chain_id = "01JZ00000000000000000000GG";
        use crate::audit::key_custody::chain_state::ChainState;
        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);

        // audit_init: cutoff = 0 (fresh chain), writes seed entry with embedded
        // cutoff.  ALL subsequent records must be signed.
        audit_init(base, &svc).expect("audit_init");

        // Write a placeholder-key (unsigned) record via write_record_v2.
        // write_record_v2 uses the placeholder key; that record will be at seq 0.
        // M19b M3: the production writer now refuses unsigned-after-cutoff
        // appends, so seed the malformed state via the test-only unchecked writer
        // to assert verify_chain still CATCHES it (tamper/corruption path).
        write_record_v2_unchecked(sample_v2_record("GG"), Some(base)).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::UnsignedRecordAfterCutoff { seq: 0, cutoff: 0 })),
            "verify_chain_rejects_placeholder_key_after_cutoff: expected UnsignedRecordAfterCutoff at seq=0, got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Test 5 (R1-SEC-3 mandatory): `verify_chain_rejects_forged_head_record`
    ///
    /// The SEC-1 scenario: build a chain with signing active (cutoff=0),
    /// write a properly-signed record, then tamper ONLY the head record
    /// (newest) by replacing it with a placeholder-key version.
    /// Assert UnsignedRecordAfterCutoff (head tamper is detected).
    ///
    /// # Scope (R3-TDD-3 clarification)
    ///
    /// This test covers one **specific** head-forgery path:
    /// the head record is replaced with a **placeholder-key** (`ed25519:000…`)
    /// forged version so the `signing_active_since_seq` cutoff check fires
    /// (`UnsignedRecordAfterCutoff`).
    ///
    /// It does NOT cover:
    /// - Head record with a real key_id but a tampered/invalid signature →
    ///   covered by `verify_chain_rejects_tampered_signature`.
    /// - Head record whose key_id is absent from the keychain →
    ///   covered by `verify_chain_rejects_key_not_found` (R3-TDD-1).
    ///
    /// The name is cited in spec §12.13.8 and MUST NOT be renamed.
    /// Scope clarification is conveyed via this doc comment, not a rename.
    #[test]
    fn verify_chain_rejects_forged_head_record() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("reject_forged_head");

        let chain_id = "01JZ00000000000000000000HH";
        use crate::audit::key_custody::chain_state::ChainState;
        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init"); // sets cutoff = 0

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        // Build a properly-signed record at seq 0.
        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000KK").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "legit-run".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
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

        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();

        // Unified contract (R1-SEC-4): sign the 32 raw bytes of canonical_hash.
        let digest_bytes: [u8; 32] = {
            let bytes =
                hex::decode(record.canonical_hash.as_str()).expect("canonical_hash is valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig = signing_key.sign(&digest_bytes).expect("sign");
        record.signature = sig;

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let good_line = serde_json::to_string(&record).unwrap() + "\n";
        std::fs::write(&jsonl_path, good_line.as_bytes()).unwrap();

        // Verify the clean chain — must succeed.
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let clean_result = verify_chain(base, &cfg, None);
        assert!(
            clean_result.is_ok(),
            "clean chain must verify Ok before tampering: {clean_result:?}"
        );

        // Now forge the head: replace with a placeholder-key (attacker) version.
        let forged = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000JJ").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "attacker-controlled".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: {
                // Compute the correct canonical_hash for the forged content
                // so canonical_hash check passes; the placeholder-key cutoff
                // check will still fire.
                let mut forged_for_hash = SignedRecord {
                    schema_version: AUDIT_SCHEMA_VERSION.to_string(),
                    record_id: RecordId::try_new("01JZ00000000000000000000JJ").unwrap(),
                    chain_id: RecordId::try_new(chain_id).unwrap(),
                    seq: 0,
                    prev_hash: Sha256Hex::genesis(),
                    kind: EventKind::CsqRun,
                    payload: EventPayload::CsqRun(CsqRunPayload {
                        run_id: "attacker-controlled".to_string(),
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
                };
                forged_for_hash.canonical_hash = Sha256Hex::genesis();
                let bytes = canonical_bytes_for(&forged_for_hash);
                Sha256Hex::try_new(sha256_hex(&bytes)).unwrap()
            },
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };

        let forged_line = serde_json::to_string(&forged).unwrap() + "\n";
        std::fs::write(&jsonl_path, forged_line.as_bytes()).unwrap();

        // Verify the forged chain — must fail.
        let forged_result = verify_chain(base, &cfg, None);
        assert!(
            matches!(forged_result, Err(LedgerError::UnsignedRecordAfterCutoff { seq: 0, cutoff: 0 })),
            "verify_chain_rejects_forged_head_record: expected UnsignedRecordAfterCutoff, got: {forged_result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    // ── R3 fix-wave: integration tests for KeyNotFound + Internal ──────────

    /// R3-TDD-1: `verify_chain_rejects_key_not_found`
    ///
    /// Drives `verify_chain` to RETURN `LedgerError::KeyNotFound` via the
    /// **loaded-key-mismatch / never-stored path** (~line 445 of verify.rs).
    ///
    /// Covers both distinct `KeyNotFound` return sites:
    /// - Site 1 (~line 401): negative-cache hit on the second call.
    /// - Site 2 (~line 445): first call for this key_id — all account
    ///   candidates exhausted, nothing found → `None` inserted into cache.
    ///
    /// Arrangement: a record carries a well-formed `ed25519:<64hex>` key_id
    /// whose key was NEVER stored in the mock keychain. `signing_active_since_seq`
    /// is set to `Some(0)` so the record is inside the signed regime and
    /// signature verification is required. The canonical_hash is computed
    /// correctly so Check 4 passes; the test isolates the KeyNotFound path.
    #[test]
    fn verify_chain_rejects_key_not_found() {
        // Hold the shared env-test mutex: verify_chain calls resolve_edition()
        // which reads CSQ_AUDIT_EDITION. Without the lock, a concurrent test
        // setting CSQ_AUDIT_EDITION=enterprise can cause verify_chain to try
        // loading an enterprise roster (which doesn't exist here) and return
        // Io instead of KeyNotFound. Pre-existing data race surfaced by
        // M12 Round-2 test-ordering change.
        let _g = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("reject_key_not_found");

        // Bootstrap chain.json with signing_active_since_seq = Some(0) so
        // every record in the chain is in the signed regime.
        // Chain ID uses only valid Crockford Base32 chars (no I, L, O, U).
        let chain_id = "01JZ00000000000000000000MA";
        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");

        // Construct a key_id for a key that was NEVER stored in the keychain.
        // Shape: "ed25519:<64 lowercase hex chars>" — passes PLACEHOLDER check.
        let absent_key_id_str = format!("ed25519:{}", "ab".repeat(32));
        let absent_key_id = KeyId::try_new(absent_key_id_str.clone()).unwrap();

        // Build a record with correct canonical_hash (so Check 4 passes) but
        // referencing the absent key_id. The signature bytes are arbitrary
        // because we expect KeyNotFound before signature verification.
        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000MA").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "test-key-not-found".to_string(),
            }),
            ts: "2026-05-28T12:00:00+00:00".to_string(),
            key_id: absent_key_id.clone(),
            canonical_hash: Sha256Hex::genesis(), // sentinel; will be replaced below
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };

        // Compute real canonical_hash so Check 4 passes.
        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();

        // Write to disk — no keychain entry for absent_key_id.
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let line = serde_json::to_string(&record).unwrap() + "\n";
        std::fs::write(&jsonl_path, line.as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::KeyNotFound { ref key_id }) if key_id.as_str() == absent_key_id_str),
            "verify_chain_rejects_key_not_found: expected KeyNotFound with key_id={absent_key_id_str}, got: {result:?}"
        );

        // Second pass: exercises the negative-cache path (Site 1, ~line 401).
        // The negative-cache path fires within a SINGLE verify_chain call when
        // two consecutive records share the same absent key_id: record[0] hits
        // Site 2 (exhausted candidates → insert None into cache), record[1]
        // hits Site 1 (cache returns Some(None) → immediate KeyNotFound).
        // Use valid Crockford Base32 chars for the second record_id (no I/L/O/U).
        let mut record2 = SignedRecord {
            seq: 1,
            prev_hash: {
                let prev_bytes = canonical_bytes_for(&record);
                Sha256Hex::try_new(sha256_hex(&prev_bytes)).unwrap()
            },
            record_id: RecordId::try_new("01JZ00000000000000000000MB").unwrap(),
            ..record.clone()
        };
        // Recompute canonical_hash for record2.
        let canonical_with_sentinel2 = canonical_bytes_for(&record2);
        let real_hash_hex2 = sha256_hex(&canonical_with_sentinel2);
        record2.canonical_hash = Sha256Hex::try_new(real_hash_hex2).unwrap();

        let line2 = serde_json::to_string(&record2).unwrap() + "\n";
        let combined = serde_json::to_string(&record).unwrap() + "\n" + &line2;
        std::fs::write(&jsonl_path, combined.as_bytes()).unwrap();

        let result2 = verify_chain(base, &cfg, None);
        // record[0] hits Site 2 (absent → cache None), record[1] hits Site 1
        // (negative-cache). Either way: KeyNotFound at seq 0 is returned first.
        assert!(
            matches!(result2, Err(LedgerError::KeyNotFound { ref key_id }) if key_id.as_str() == absent_key_id_str),
            "verify_chain_rejects_key_not_found (cache path): expected KeyNotFound, got: {result2:?}"
        );
    }

    /// R3-TDD-2: `verify_chain_internal_path_unreachable_via_from_bytes`
    ///
    /// `LedgerError::Internal` at verify.rs ~line 479 is returned when
    /// `VerifyingKey::from_bytes(&pubkey_bytes)` fails.
    ///
    /// **Determination: NOT unit-testable via the mock keychain backend.**
    ///
    /// In ed25519-dalek v2 (`ed25519-dalek = { version = "2", ... }`),
    /// `VerifyingKey::from_bytes` accepts any `[u8; 32]` slice and returns
    /// `Ok(VerifyingKey)` unconditionally — it stores the raw bytes and defers
    /// curve-point decompression to the first `verify_strict` / `verify` call.
    /// There is no byte input that makes `from_bytes` return `Err` in v2.
    ///
    /// Consequently, storing an invalid-point pubkey in the mock keychain and
    /// calling `verify_chain` will reach `verify_strict`, not `from_bytes`,
    /// and will return `LedgerError::InvalidSignature` rather than `Internal`.
    ///
    /// The `Internal` variant guard is future-proof defensive code that would
    /// fire if: (a) ed25519-dalek is upgraded to a version that validates the
    /// curve point in `from_bytes`, or (b) the pubkey load path is refactored
    /// to use a stricter deserializer. Forcing a test against `Internal` today
    /// would require bypassing `LocalSigningKey`'s hex-decode + length checks
    /// (which already reject wrong-length inputs before reaching `from_bytes`)
    /// or mocking `VerifyingKey::from_bytes` itself (not possible without a
    /// mock-framework seam; the project intentionally avoids mockall).
    ///
    /// This test documents the analysis and asserts the CURRENT behavior:
    /// invalid-point pubkey bytes → `verify_strict` fails → `InvalidSignature`,
    /// not `Internal`.
    #[test]
    fn verify_chain_internal_path_unreachable_via_from_bytes() {
        // R3-TDD-2: Internal is only reachable if VerifyingKey::from_bytes
        // returns Err, which does not happen in ed25519-dalek v2 for any
        // [u8; 32] input — curve-point validation is deferred to verify_strict.
        // The path is not unit-testable without a mock-framework seam this
        // project does not use. The assertion below documents the invariant.

        // Demonstrate that from_bytes accepts all-zeros (invalid curve point).
        let all_zeros = [0u8; 32];
        let result = VerifyingKey::from_bytes(&all_zeros);
        assert!(
            result.is_ok(),
            "ed25519-dalek v2 from_bytes must accept any [u8;32] (deferred validation): got Err"
        );

        // Demonstrate that all-ones bytes are also accepted by from_bytes.
        let all_ones = [0xff_u8; 32];
        let result2 = VerifyingKey::from_bytes(&all_ones);
        assert!(
            result2.is_ok(),
            "ed25519-dalek v2 from_bytes must accept 0xff..ff bytes: got Err"
        );
    }

    // ── M-hardening tests ─────────────────────────────────────────────────────

    // ── ATTACK TEST B (C1 closure — LEAD) ────────────────────────────────────

    /// `test_verify_delete_seed_entry_fails_closed`
    ///
    /// ATTACK TEST B: an attacker DELETES the seed keychain entry to drop the
    /// embedded cutoff.  With a separate anchor, this used to enable TOFU
    /// re-laundering of the forged cutoff.  With co-location, deleting the seed
    /// entry removes BOTH the key and the cutoff simultaneously.
    ///
    /// Expected outcome: for any signed record, `verify_chain` returns
    /// `LedgerError::KeyNotFound` (no key to verify against).  For placeholder
    /// records, the cutoff is lost so they are tolerated — but the chain can
    /// only hold unsigned records, which means the attack re-opens the window
    /// to placeholder acceptance, which is the correct degradation mode
    /// (the attacker needed a signed chain to forge).
    ///
    /// CRITICAL INVARIANT: the verifier MUST NOT silently re-launder the
    /// forged chain.json cutoff as authoritative when the seed entry is absent.
    #[test]
    fn test_verify_delete_seed_entry_fails_closed() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("delete_seed_fails_closed");
        let chain_id = "01JZ00000000000000000000M2";
        use crate::audit::key_custody::chain_state::ChainState;
        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        // audit_init: cutoff=0, writes seed with embedded cutoff.
        audit_init(base, &svc).expect("audit_init");

        // Build a properly-signed record (not placeholder).
        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000M3").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "delete-seed-test".to_string(),
            }),
            ts: "2026-05-30T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
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
        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();
        let digest_bytes: [u8; 32] = {
            let bytes = hex::decode(record.canonical_hash.as_str()).unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig = signing_key.sign(&digest_bytes).expect("sign");
        record.signature = sig;

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        std::fs::write(
            &jsonl_path,
            (serde_json::to_string(&record).unwrap() + "\n").as_bytes(),
        )
        .unwrap();

        // Verify clean chain first.
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let clean = verify_chain(base, &cfg, None);
        assert!(
            clean.is_ok(),
            "clean chain with proper signature must verify OK before attack"
        );

        // ATTACK: delete the seed entry from BOTH stores (file + keychain).
        LocalSigningKey::delete_from_keychain(&svc, chain_id).expect("delete seed entry");
        file_store::delete(base, chain_id, KeySlot::Active).expect("delete seed file");

        // Now verify.  The key for this record is gone.
        // With co-location, the only way to get the cutoff is gone too.
        // Result: KeyNotFound (fails closed) — the signed record cannot be
        // verified and the verifier does NOT silently re-launder.
        let after_delete = verify_chain(base, &cfg, None);
        assert!(
            matches!(after_delete, Err(LedgerError::KeyNotFound { .. })),
            "test_verify_delete_seed_entry_fails_closed: after seed entry deleted, \
             verify_chain MUST return KeyNotFound (fails closed), NOT silently accept \
             the forged cutoff from chain.json. Got: {after_delete:?}"
        );
    }

    // ── Integrity-anchor reconciliation (file vs keychain) ─────────────────────
    //
    // These unit-test `resolve_authoritative_cutoff` directly — the
    // forge-resistance heart of the file-mirror + keychain-anchor design. They
    // simulate keychain access-errors / NoEntry / corrupt entries that the
    // in-memory mock keyring cannot produce through the live path.

    fn anchor_kid(hex_char: char) -> KeyId {
        KeyId::try_new(format!("ed25519:{}", String::from(hex_char).repeat(64))).unwrap()
    }

    fn anchor_ec(cutoff: u64, kid: &KeyId) -> EmbeddedCutoff {
        EmbeddedCutoff {
            signing_active_since_seq: cutoff,
            signing_key_id: kid.as_str().to_string(),
            roster_version_floor: None,
        }
    }

    fn kc_access_err() -> KeyCustodyError {
        KeyCustodyError::Keychain(keyring::Error::PlatformFailure(
            "errSecInteractionNotAllowed".to_string().into(),
        ))
    }

    use KeychainAnchorStatus::{Confirmed, Mismatch, Unconfirmed};

    /// File + keychain agree → `(cutoff, Confirmed)`, fully anchored.
    #[test]
    fn anchor_file_and_keychain_agree_ok() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(5),
            true,
            Ok(Some(anchor_ec(5, &kid))),
            Ok(Some(anchor_ec(5, &kid))),
        );
        assert_eq!(r.unwrap(), (Some(5), Confirmed));
    }

    /// File/keychain key_id DISAGREE → `Mismatch` (DETECTOR, non-fatal). The
    /// forge signal: an attacker rewrote the file seed (+ chain.json) but cannot
    /// rewrite the keychain anchor. Surfaced loudly, never bricks.
    #[test]
    fn anchor_file_keychain_keyid_disagree_is_mismatch_not_fatal() {
        let file_kid = anchor_kid('b'); // attacker's key in the file + chain.json
        let kc_kid = anchor_kid('a'); // genuine key still in the keychain
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &file_kid,
            Some(0),
            true,
            Ok(Some(anchor_ec(0, &file_kid))),
            Ok(Some(anchor_ec(0, &kc_kid))),
        );
        assert_eq!(
            r.unwrap(),
            (Some(0), Mismatch),
            "file/keychain key_id disagreement must surface as Mismatch (detector), not brick"
        );
    }

    /// File/keychain cutoffs DISAGREE → `Mismatch`, and the TRUSTWORTHY keychain
    /// cutoff (0) is used — actively DEFEATING the file/chain.json raise (to 9)
    /// when the keychain is readable.
    #[test]
    fn anchor_file_keychain_cutoff_disagree_uses_keychain_cutoff() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(9), // chain.json raised to match the file
            true,
            Ok(Some(anchor_ec(9, &kid))), // attacker raised the file cutoff
            Ok(Some(anchor_ec(0, &kid))), // keychain still holds the genuine cutoff
        );
        assert_eq!(
            r.unwrap(),
            (Some(0), Mismatch),
            "readable keychain cutoff (0) must win over the file/chain.json raise (9), and flag Mismatch"
        );
    }

    /// File present + keychain ACCESS-BLOCKED → `Unconfirmed` (cross-check
    /// deferred), file cutoff used. The legitimate non-interactive-daemon state
    /// — must NOT brick and must NOT report a clean Confirmed.
    #[test]
    fn anchor_file_present_keychain_blocked_is_unconfirmed() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(3),
            true,
            Ok(Some(anchor_ec(3, &kid))),
            Err(kc_access_err()),
        );
        assert_eq!(r.unwrap(), (Some(3), Unconfirmed));
    }

    /// File present + keychain genuinely absent (NoEntry) → `Unconfirmed`, NOT a
    /// clean Confirmed. This closes the silent-downgrade gap (Round-1 F1): an
    /// attacker who DELETES the keychain anchor to force NoEntry no longer gets a
    /// green "Verified+Confirmed" — the run is anchor-Unconfirmed and surfaced.
    #[test]
    fn anchor_file_present_keychain_noentry_is_unconfirmed_not_clean() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(3),
            true,
            Ok(Some(anchor_ec(3, &kid))),
            Err(KeyCustodyError::Keychain(keyring::Error::NoEntry)),
        );
        assert_eq!(
            r.unwrap(),
            (Some(3), Unconfirmed),
            "keychain NoEntry must be Unconfirmed (not silently Confirmed) — closes the delete-downgrade gap"
        );
    }

    /// File present + keychain present-but-CORRUPT (planted) → `Mismatch`
    /// (detector, non-fatal — surfaced loudly, the daemon stays operational).
    #[test]
    fn anchor_file_present_keychain_corrupt_is_mismatch() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(3),
            true,
            Ok(Some(anchor_ec(3, &kid))),
            Err(KeyCustodyError::Keychain(keyring::Error::BadEncoding(
                vec![0xff],
            ))),
        );
        assert_eq!(r.unwrap(), (Some(3), Mismatch));
    }

    /// File present but its cutoff disagrees with chain.json → `Mismatch`
    /// (detector). The file (primary) cutoff is used; the disagreement surfaces.
    #[test]
    fn anchor_file_disagrees_with_chain_json_is_mismatch() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(0), // chain.json says 0
            true,
            Ok(Some(anchor_ec(9, &kid))), // file says 9
            Err(KeyCustodyError::Keychain(keyring::Error::NoEntry)),
        );
        assert_eq!(r.unwrap(), (Some(9), Mismatch));
    }

    /// File ABSENT + keychain access-blocked → defer to chain.json cutoff
    /// (pre-migration brick fix), `Unconfirmed`. Not fatal.
    #[test]
    fn anchor_file_absent_keychain_blocked_uses_chain_json() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(7),
            false,
            Ok(None),
            Err(kc_access_err()),
        );
        assert_eq!(r.unwrap(), (Some(7), Unconfirmed));
    }

    /// File ABSENT + keychain present + agrees with chain.json → `Confirmed`
    /// (the keychain is the trustworthy authority). Pre-migration install.
    #[test]
    fn anchor_file_absent_keychain_present_ok() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(4),
            false,
            Ok(None),
            Ok(Some(anchor_ec(4, &kid))),
        );
        assert_eq!(r.unwrap(), (Some(4), Confirmed));
    }

    /// A corrupt FILE seed (present but unparseable) → fail closed regardless of
    /// the keychain.
    #[test]
    fn anchor_corrupt_file_is_fatal() {
        let kid = anchor_kid('a');
        let r = resolve_authoritative_cutoff(
            "CHAIN",
            &kid,
            Some(0),
            true,
            Err(KeyCustodyError::KeyCorrupt("bad json".to_string())),
            Ok(Some(anchor_ec(0, &kid))),
        );
        assert!(
            matches!(r, Err(LedgerError::Io { .. })),
            "a corrupt file seed must fail closed, got {r:?}"
        );
    }

    /// `KeychainUnavailable` maps to a transient/partial CLI surface (status
    /// "partial", exit 2, kind "keychain_unavailable") — NOT an integrity
    /// failure.
    #[test]
    fn keychain_unavailable_is_partial_not_integrity_failure() {
        let e = LedgerError::KeychainUnavailable {
            key_id: anchor_kid('a'),
        };
        assert_eq!(exit_code_for_error(&e), 2);
        let detail = VerifyFailureDetail::from_ledger_error(&e);
        assert_eq!(detail.kind, "keychain_unavailable");
        let json = to_json_output(&Err(e));
        assert_eq!(json.status, "partial");
    }

    /// End-to-end: a chain whose key lives ONLY in the file store (no keychain
    /// entry) verifies cleanly — proving the daemon-readable file primary works
    /// without any keychain access.
    #[test]
    fn file_only_custody_verifies_without_keychain() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("file_only_custody");
        let chain_id = "01JZ00000000000000000000F1";

        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let key = match try_load_signing_key(base, &svc, chain_id, KeySlot::Active) {
            KeyLoadOutcome::Loaded(k) => *k,
            other => panic!("expected Loaded, got {other:?}"),
        };

        // Delete ONLY the keychain copy — the file store keeps the seed.
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        assert!(
            file_store::exists(base, chain_id, KeySlot::Active),
            "file store must still hold the seed"
        );

        let rec0 = make_signed_record(chain_id, 0, Sha256Hex::genesis(), "F0", &key);
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::write(
            &jsonl_path,
            format!("{}\n", serde_json::to_string(&rec0).unwrap()),
        )
        .unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            result.is_ok(),
            "file-only custody must verify without a keychain entry, got {result:?}"
        );
    }

    // ── ATTACK TEST A ─────────────────────────────────────────────────────────

    /// `test_verify_raised_cutoff_in_chain_json_returns_anchor_mismatch`
    ///
    /// ATTACK TEST A: after audit_init writes the embedded cutoff into the seed
    /// entry, an attacker raises `chain.json`'s `signing_active_since_seq`.
    /// `verify_chain` reads the embedded cutoff from the keychain (authoritative)
    /// and compares — disagreement → `CutoffAnchorMismatch`.
    #[test]
    fn test_verify_raised_cutoff_in_chain_json_returns_anchor_mismatch() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("raised_cutoff_mismatch");
        let chain_id = "01JZ00000000000000000000M4";
        use crate::audit::key_custody::chain_state::ChainState;

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        // audit_init: cutoff=0, embedded in seed entry.
        audit_init(base, &svc).expect("audit_init");

        // Write a placeholder-key (unsigned) record at seq 0.
        // M19b M3: production writer refuses unsigned-after-cutoff; seed via the
        // test-only unchecked writer (tamper/corruption path verify must catch).
        write_record_v2_unchecked(sample_v2_record("M4"), Some(base)).unwrap();

        // ATTACK: raise chain.json signing_active_since_seq to 99 to re-open
        // placeholder-key acceptance below seq 99. The embedded cutoff in the
        // file + keychain stays at 0.
        let mut tampered = ChainState::load(base).expect("load");
        tampered.signing_active_since_seq = Some(99);
        tampered.save(base).expect("save tampered");

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        // DETECTOR-mode (file-mirror + keychain-anchor): the raise is DEFEATED,
        // not by a fatal CutoffAnchorMismatch, but because Step-0 uses the
        // TRUSTWORTHY readable keychain cutoff (0) — NOT chain.json's raised 99 —
        // so the placeholder record at seq 0 is rejected at the real cutoff
        // (UnsignedRecordAfterCutoff). The keychain anchor MISMATCH is also
        // surfaced (chain.json disagrees with the keychain), but the per-record
        // integrity check is the fatal arm here. Either way the attack fails.
        assert!(
            matches!(
                result,
                Err(LedgerError::UnsignedRecordAfterCutoff { seq: 0, cutoff: 0 })
            ),
            "raised-cutoff attack MUST be defeated: the trustworthy keychain cutoff (0) \
             is enforced, so the placeholder at seq 0 is rejected. Got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `test_verify_legacy_bare_hex_uses_chain_json_no_write`
    ///
    /// Legacy bare-hex seed entry (pre-M-hardening): no embedded cutoff.
    /// `verify_chain` falls back to chain.json + WARNs.
    /// Critically: verify MUST NOT write the keychain (read-only invariant).
    #[test]
    fn test_verify_legacy_bare_hex_uses_chain_json_no_write() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("legacy_bare_hex");
        let chain_id = "01JZ00000000000000000000M5";
        use crate::audit::key_custody::chain_state::ChainState;
        use crate::audit::key_custody::keyring_backend::load_embedded_cutoff;

        // Set up chain.json with a signing_key_id and cutoff.
        let mut state = ChainState::new(chain_id);
        // Simulate a legacy install: write chain.json fields but store a
        // bare-hex seed entry (pre-M-hardening format).
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).expect("getrandom");
        let bare_hex = hex::encode(seed_bytes);
        let entry = crate::audit::key_custody::keyring_entry(&svc, chain_id).expect("entry");
        entry.set_password(&bare_hex).expect("set bare-hex seed");

        // Load the key to get its key_id, set chain.json accordingly.
        let key = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load legacy key");
        state.signing_key_id = Some(key.key_id());
        state.pubkey = Some(key.public_key());
        state.signing_active_since_seq = Some(5);
        state.save(base).expect("save chain.json");

        // Write a placeholder record at seq 0 (below the cutoff of 5).
        write_record_v2(sample_v2_record("M5"), Some(base)).unwrap();

        // Snapshot the keychain state BEFORE verify_chain.
        let before_ec = load_embedded_cutoff(&svc, chain_id).expect("load before");
        assert!(before_ec.is_none(), "must start as legacy bare-hex");

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        // The placeholder record is at seq 0, cutoff is 5 → seq < cutoff → tolerated.
        assert!(
            result.is_ok(),
            "legacy install with placeholder below cutoff must verify OK. Got: {result:?}"
        );

        // INVARIANT: verify_chain MUST NOT write to the keychain.
        let after_ec = load_embedded_cutoff(&svc, chain_id).expect("load after");
        assert!(
            after_ec.is_none(),
            "verify_chain MUST NOT write the keychain (read-only invariant). \
             Legacy seed entry was upgraded after verify — BLOCKED."
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `test_verify_locked_keychain_uses_chain_json_not_fatal`
    ///
    /// Locked keychain (simulated via injecting a non-NoEntry keyring error):
    /// verify_chain MUST NOT fail the daemon. Uses chain.json cutoff + WARN.
    /// The mock keyring cannot simulate a locked-keychain error on get_password;
    /// instead we test the logic by calling with a service that has NO entry
    /// (NoEntry) for the signing key but chain.json has a key_id.
    /// (The locked-keychain path is identical to the NoEntry fall-through in
    /// the mock; the structural correctness is that neither path is fatal.)
    #[test]
    fn test_verify_absent_key_with_unsigned_records_tolerates_pre_cutoff() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("absent_key_pre_cutoff");
        let chain_id = "01JZ00000000000000000000M6";
        use crate::audit::key_custody::chain_state::ChainState;

        // Write chain.json with a signing_key_id and cutoff = 5.
        // DO NOT write a keychain entry (simulates locked or absent state).
        let fake_kid = KeyId::try_new(format!("ed25519:{}", "ab".repeat(32))).unwrap();
        let mut state = ChainState::new(chain_id);
        state.signing_key_id = Some(fake_kid.clone());
        state.signing_active_since_seq = Some(5);
        state.save(base).expect("save chain.json");

        // Write a placeholder record at seq 0 (below the cutoff of 5).
        write_record_v2(sample_v2_record("M6"), Some(base)).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        // The key is absent (NoEntry) → fall through to chain.json cutoff (5).
        // The placeholder record is at seq 0 < cutoff 5 → tolerated.
        // (For signed records, KeyNotFound would be returned — correct fail-closed.)
        assert!(
            result.is_ok(),
            "absent key with unsigned records below cutoff must verify OK \
             (not fatal). Got: {result:?}"
        );
    }

    /// `test_verify_init_writes_embedded_cutoff`
    ///
    /// After `audit_init`, the seed entry MUST be in new JSON format and
    /// contain the embedded cutoff that matches chain.json.
    #[test]
    fn test_verify_init_writes_embedded_cutoff() {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("init_embedded_cutoff");
        let chain_id = "01JZ00000000000000000000M7";
        use crate::audit::key_custody::chain_state::ChainState;
        use crate::audit::key_custody::keyring_backend::load_embedded_cutoff;

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);

        audit_init(base, &svc).expect("audit_init");

        let loaded = ChainState::load(base).expect("load chain.json");
        let chain_cutoff = loaded
            .signing_active_since_seq
            .expect("signing_active_since_seq must be set");
        let chain_kid = loaded
            .signing_key_id
            .as_ref()
            .expect("signing_key_id must be set");

        let ec = load_embedded_cutoff(&svc, chain_id)
            .expect("load_embedded_cutoff must not error")
            .expect("embedded cutoff must be present after audit_init");

        assert_eq!(
            ec.signing_active_since_seq, chain_cutoff,
            "embedded cutoff must match chain.json cutoff"
        );
        assert_eq!(
            ec.signing_key_id,
            chain_kid.as_str(),
            "embedded signing_key_id must match chain.json signing_key_id"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `test_verify_rotate_preserves_cutoff_and_consistency`
    ///
    /// After rotate_key, the new seed entry MUST have the same embedded cutoff
    /// as the outgoing key's entry, AND chain.json MUST also agree (MED-2).
    #[test]
    fn test_verify_rotate_preserves_cutoff_and_consistency() {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk). H-2 (review).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("rotate_preserves_cutoff");
        let chain_id = "01JZ00000000000000000000M8";
        use crate::audit::key_custody::chain_state::ChainState;
        use crate::audit::key_custody::keyring_backend::load_embedded_cutoff;
        use crate::audit::key_custody::rotate_key;
        use crate::audit::types::RotationReason;

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");

        audit_init(base, &svc).expect("audit_init");
        let pre_init = ChainState::load(base).expect("load pre-rotate");
        let original_cutoff = pre_init
            .signing_active_since_seq
            .expect("cutoff set after init");

        rotate_key(base, &svc, RotationReason::Operator).expect("rotate_key");

        // New seed entry must have same cutoff.
        let ec_after = load_embedded_cutoff(&svc, chain_id)
            .expect("load after rotate")
            .expect("must be new JSON format after rotate");
        assert_eq!(
            ec_after.signing_active_since_seq, original_cutoff,
            "rotate MUST NOT change the embedded cutoff"
        );

        // chain.json must also agree (MED-2).
        let post_rotate = ChainState::load(base).expect("load post-rotate");
        assert_eq!(
            post_rotate.signing_active_since_seq,
            Some(original_cutoff),
            "chain.json cutoff must remain consistent after rotate (MED-2)"
        );
        assert_eq!(
            post_rotate.signing_key_id.as_ref().map(|k| k.as_str()),
            Some(ec_after.signing_key_id.as_str()),
            "chain.json signing_key_id must match new embedded key_id after rotate"
        );

        // verify_chain must accept the chain (no CutoffAnchorMismatch).
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        // Chain has no records yet → Ok.
        let result = verify_chain(base, &cfg, None);
        assert!(
            result.is_ok(),
            "verify after rotate must succeed (no mismatch). Got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// `test_verify_chain_signing_key_id_tamper_returns_mismatch`
    ///
    /// An attacker alters chain.json's `signing_key_id` while leaving the
    /// embedded cutoff untouched. DETECTOR-mode: the verifier surfaces the
    /// disagreement as a NON-fatal `KeychainAnchorStatus::Mismatch` (loud ERROR +
    /// `csq doctor` alarm), not a fatal `*AnchorMismatch` — the keychain anchor
    /// never bricks the chain (never-brick + optimistic-sign posture).
    #[test]
    fn test_verify_chain_signing_key_id_tamper_returns_mismatch() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("kid_tamper");
        let chain_id = "01JZ00000000000000000000M9";
        use crate::audit::key_custody::chain_state::ChainState;

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        // Tamper: replace signing_key_id in chain.json with a different value.
        let mut tampered = ChainState::load(base).expect("load");
        tampered.signing_key_id =
            Some(KeyId::try_new(format!("ed25519:{}", "ff".repeat(32))).unwrap());
        tampered.save(base).expect("save tampered");

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        // DETECTOR-mode: the key_id tamper (chain.json disagrees with the
        // file/keychain seed) is SURFACED as `keychain_anchor == Mismatch`, not
        // a fatal error — the keychain anchor never bricks the chain (per the
        // never-brick + optimistic-sign posture). `csq doctor` shows the loud
        // anchor alarm. The chain itself has no records here, so it verifies Ok.
        match result {
            Ok(summary) => assert_eq!(
                summary.keychain_anchor,
                KeychainAnchorStatus::Mismatch,
                "key_id tamper must surface as a keychain-anchor Mismatch (detector)"
            ),
            other => panic!("key_id tamper must be a non-fatal Mismatch, got {other:?}"),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `test_verify_read_only_invariant`
    ///
    /// verify_chain is a read-only path.  For legacy bare-hex entries, it
    /// MUST NOT upgrade them to the new format.  Snapshot the entry before
    /// and after; assert identical bytes.
    #[test]
    fn test_verify_read_only_invariant() {
        // M12: verify_chain → resolve_registry reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("read_only_invariant");
        let chain_id = "01JZ00000000000000000000MA";
        use crate::audit::key_custody::chain_state::ChainState;

        // Write a legacy bare-hex seed entry.
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).expect("getrandom");
        let bare_hex = hex::encode(seed_bytes);
        let entry = crate::audit::key_custody::keyring_entry(&svc, chain_id).expect("entry");
        entry.set_password(&bare_hex).expect("set");

        let key = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load legacy key");
        let mut state = ChainState::new(chain_id);
        state.signing_key_id = Some(key.key_id());
        state.pubkey = Some(key.public_key());
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");

        // Write a record (placeholder — below any signed cutoff with no records).
        // For this test we just want to invoke verify_chain; no records needed.
        // The chain is empty → verify returns Ok trivially after reading chain.json.
        // But we still need a JSONL file so the function doesn't return early.
        // Write a placeholder record so the verifier walks the record loop.
        // M19b M3: production writer refuses unsigned-after-cutoff; seed via the
        // test-only unchecked writer (tamper/corruption path verify must catch).
        write_record_v2_unchecked(sample_v2_record("MA"), Some(base)).unwrap();

        // Snapshot keychain BEFORE.
        let before: String = crate::audit::key_custody::keyring_entry(&svc, chain_id)
            .unwrap()
            .get_password()
            .unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let _ = verify_chain(base, &cfg, None);

        // Snapshot AFTER.
        let after: String = crate::audit::key_custody::keyring_entry(&svc, chain_id)
            .unwrap()
            .get_password()
            .unwrap();

        assert_eq!(
            before, after,
            "verify_chain MUST NOT write to the keychain (read-only invariant). \
             Entry bytes changed after verify."
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    // ── M11 integration tests ────────────────────────────────────────────────

    /// AC-4 (verify path): a rotate record with a valid community 1-of-1
    /// multi-sig authority blob is ACCEPTED by verify_chain.
    ///
    /// This exercises the full round-trip:
    ///   rotate_key (authorize_op populates authority; M13 drains the INTENT
    ///     record and appends the OUTCOME record internally) →
    ///   verify_chain (outer signature + M11 multi-sig hook both pass for the
    ///     intent AND the outcome record).
    #[test]
    fn test_verify_chain_accepts_community_rotate_with_multi_sig_authority() {
        use crate::audit::key_custody::rotate_key;
        use crate::audit::types::RotationReason;

        // F-01: hold the env lock — resolve_policy() reads CSQ_AUDIT_EDITION
        // which the edition tests mutate. Without the lock these race and flake.
        let _guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FB2";
        let svc = svc_name("m11_verify_accept");

        use crate::audit::key_custody::chain_state::ChainState;
        ChainState::new(chain_id)
            .save(base)
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        // rotate_key now populates record.authority with a multi-sig blob.
        let (_new_key, rotate_record) =
            rotate_key(base, &svc, RotationReason::Operator).expect("rotate_key");

        // The rotate record carries an authority blob.
        assert!(
            rotate_record.authority.is_some(),
            "rotate record MUST carry an authority blob after M11 wiring"
        );
        let ms = &rotate_record.authority.as_ref().unwrap().0["multi_sig"];
        assert_eq!(
            ms["threshold"].as_u64(),
            Some(1),
            "community rotate must have threshold 1"
        );
        // M13: the returned record is the OUTCOME; rotate_key already wrote both
        // the INTENT and the OUTCOME to the chain. The test MUST NOT write again.
        assert!(
            matches!(
                rotate_record.op_phase,
                Some(crate::audit::types::OpPhase::Outcome { .. })
            ),
            "rotate_key returns the OUTCOME record"
        );

        // verify_chain must accept the chain (intent + outcome) — multi-sig hook
        // + outer signature both pass for each record.
        let config = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &config, None);
        assert!(
            result.is_ok(),
            "verify_chain MUST accept a community rotate (intent + outcome) with valid multi-sig authority: \
             {:?}",
            result.err()
        );

        let summary = result.unwrap();
        assert!(
            summary.verified_count >= 2,
            "both the intent and outcome rotate records must be verified, got {}",
            summary.verified_count
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// AC-6 (tamper via verify_chain path): a rotate record whose multi-sig
    /// inner authorization signature is tampered AFTER writing is REJECTED by
    /// verify_chain.
    ///
    /// The tamper modifies the authority blob's `authorizations[0].signature`.
    /// Since `canonical_hash` covers the authority slot (CanonicalView includes
    /// `authority`), tampering the authority blob changes the record's content
    /// hash — so verify_chain's Check 4 (canonical_hash recompute) fires BEFORE
    /// Check M11 (multi-sig hook). Both are defense-in-depth layers; the test
    /// asserts the record is rejected (by EITHER check) and that the multi-sig
    /// hook itself also rejects the tampered blob when tested in isolation
    /// (covered by `audit::multi_sig::verify::tests::test_verify_tampered_inner_signature_rejected`).
    ///
    /// Note: to exercise the multi-sig hook as the PRIMARY rejection path,
    /// would require an authority blob that (a) has a correct canonical_hash
    /// and outer signature (i.e. the signer signed the tampered blob) AND (b)
    /// has an invalid inner authorization. That is the scenario tested in
    /// `multi_sig::verify::tests::test_verify_tampered_inner_signature_rejected`
    /// (which assembles such a record directly). The on-disk tamper test here
    /// verifies the defense-in-depth: tamper is caught.
    #[test]
    fn test_verify_chain_rejects_tampered_multi_sig_inner_signature() {
        use crate::audit::key_custody::rotate_key;
        use crate::audit::types::RotationReason;

        // F-01: hold the env lock — resolve_policy() reads CSQ_AUDIT_EDITION.
        let _guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FB3";
        let svc = svc_name("m11_verify_tamper");

        use crate::audit::key_custody::chain_state::ChainState;
        ChainState::new(chain_id)
            .save(base)
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        // M13: rotate_key drains the KeyRotate INTENT (seq 0) and appends the
        // OUTCOME (seq 1) internally — both carry the multi_sig authority blob.
        // The test MUST NOT re-append the returned record (that would land a
        // third, signature-corrupt copy at seq 2 — its outer sig was made over
        // the seq-1 canonical_hash — and verify would fail on THAT record
        // regardless of the tamper below, making the tamper assertion dead).
        let (_new_key, _outcome) =
            rotate_key(base, &svc, RotationReason::Operator).expect("rotate_key");

        // Tamper: read the JSONL, find the rotate record, replace its inner
        // authorization signature with all-zero hex.
        let cs = ChainState::load(base).expect("load chain state");
        let jsonl_path = base.join("csq-runs").join(format!("{}.jsonl", cs.chain_id));
        let content = std::fs::read_to_string(&jsonl_path).expect("read jsonl");
        let tampered = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let mut v: serde_json::Value =
                    serde_json::from_str(line).expect("parse jsonl line");
                if v["kind"].as_str() == Some("key_rotate") {
                    // Tamper the inner authorization signature.
                    if let Some(auths) = v
                        .get_mut("authority")
                        .and_then(|a| a.get_mut("multi_sig"))
                        .and_then(|ms| ms.get_mut("authorizations"))
                        .and_then(|a| a.as_array_mut())
                    {
                        if let Some(first) = auths.first_mut() {
                            first["signature"] = serde_json::Value::String("00".repeat(64));
                        }
                    }
                }
                serde_json::to_string(&v).expect("serialize")
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&jsonl_path, tampered).expect("write tampered jsonl");

        let config = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &config, None);
        // The tamper MUST be detected. The canonical_hash check (Check 4) fires
        // before the multi-sig hook because canonical_hash covers the authority
        // slot — so IntegrityBroken is the expected variant here. MultiSigInvalid
        // would fire if Check 4 were bypassed (tested in isolation in
        // `multi_sig::verify::tests::test_verify_tampered_inner_signature_rejected`).
        assert!(
            result.is_err(),
            "verify_chain MUST reject a rotate record with a tampered authority blob"
        );
        match result.unwrap_err() {
            LedgerError::MultiSigInvalid { .. } => {
                // The multi-sig hook fired as the first detector — valid outcome.
            }
            LedgerError::IntegrityBroken { .. } => {
                // Check 4 (canonical_hash recompute) fired first — also valid
                // outcome; the tamper is caught by the outer signature layer.
            }
            LedgerError::InvalidSignature { .. } => {
                // Check 5 (Ed25519 outer signature) fired — also valid; the
                // canonical_hash changed so the outer sig fails.
            }
            other => panic!(
                "verify_chain must detect the tamper; expected MultiSigInvalid, \
                 IntegrityBroken, or InvalidSignature, got: {:?}",
                other
            ),
        }

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// SEC-4: verify_chain MUST reach the M11 hook and return
    /// `LedgerError::MultiSigInvalid` when:
    ///   - The outer canonical_hash is correctly computed (Check 4 passes).
    ///   - The outer Ed25519 signature is valid (Check 5 passes).
    ///   - The multi_sig authority blob is syntactically valid but under-threshold
    ///     (threshold=2, only 1 valid authorization → hook returns Err).
    ///
    /// This is the ONLY scenario where MultiSigInvalid is the actual rejection
    /// path — the existing tamper-on-disk test always trips Check 4 first
    /// (canonical_hash changes when the blob is tampered after write).
    ///
    /// Construction: build the record with a valid but under-threshold authority
    /// blob manually, then compute canonical_hash and sign with the real chain key
    /// so that Check 4 and Check 5 PASS, but Check M11 fires.
    #[test]
    fn test_verify_chain_rejects_under_threshold_multi_sig_returns_multi_sig_invalid() {
        use crate::audit::key_custody::chain_state::ChainState;
        use crate::audit::multi_sig::edition::MultiSigPolicy;
        use crate::audit::multi_sig::gate::authorize_op;
        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::traits::SigningKey as _;
        use crate::audit::types::{
            CsqRunPayload, EatpAuthority, Ed25519Signature, EventKind, EventPayload,
        };

        // F-01 note (corrected 2026-06-20): the original note claimed the lock was
        // "not needed" because authorize_op reads no env vars — but `verify_chain`
        // (called below at the SEC-4 assertion) ITSELF transitively reads
        // CSQ_AUDIT_EDITION via resolve_registry/resolve_edition, independent of
        // authorize_op. Without the lock this test races a concurrent
        // enterprise-edition test and fails closed on the missing roster. Hold the
        // shared env lock + pin a clean community baseline (testing.md Rule 6 /
        // test-hermeticity.md MUST 1b — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FB5";
        let svc = svc_name("sec4_multi_sig_invalid");

        // Bootstrap: audit_init creates the real chain key.
        ChainState::new(chain_id)
            .save(base)
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        // Build a valid 1-of-1 authority (using the chain key).
        let payload = EventPayload::CsqRun(CsqRunPayload {
            run_id: "sec4-test".to_string(),
        });
        let policy = MultiSigPolicy { threshold: 1 };
        let signers: &[&dyn crate::audit::traits::SigningKey] = &[&signing_key];
        let authority_1_of_1 =
            authorize_op(chain_id, &EventKind::CsqRun, &payload, signers, &policy)
                .expect("authorize_op must succeed");

        // Raise the threshold to 2 in the blob — now the single valid authorization
        // is under-threshold. The blob is syntactically valid (hex encodes, valid
        // Ed25519 pubkey and signature) so parsing passes; only the count check fails.
        let mut authority_under = authority_1_of_1;
        if let Some(ms) = authority_under.0.get_mut("multi_sig") {
            ms["threshold"] = serde_json::Value::Number(serde_json::Number::from(2u64));
            ms["roster_size"] = serde_json::Value::Number(serde_json::Number::from(2u64));
        }
        let authority = EatpAuthority(authority_under.0);

        // Build the record with the under-threshold authority blob.
        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FS0").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload,
            ts: "2026-06-02T12:00:00+00:00".to_string(),
            key_id: key_id.clone(),
            canonical_hash: Sha256Hex::genesis(), // sentinel — filled below
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: Some(authority),
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };

        // Compute real canonical_hash over the record INCLUDING the authority blob.
        // This is the key: the signer commits to the UNDER-THRESHOLD blob, so
        // Check 4 passes (canonical_hash matches) and Check 5 passes (outer sig
        // is valid over the real canonical_hash), but Check M11 fires because
        // threshold=2 > valid_count=1.
        let canonical_with_sentinel = canonical_bytes_for(&record);
        let real_hash_hex = sha256_hex(&canonical_with_sentinel);
        record.canonical_hash = Sha256Hex::try_new(real_hash_hex).unwrap();

        // Sign the 32 raw bytes of canonical_hash with the real chain key.
        let digest_bytes: [u8; 32] = {
            let bytes = hex::decode(record.canonical_hash.as_str()).expect("canonical_hash hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        let sig = signing_key.sign(&digest_bytes).expect("sign");
        record.signature = sig;

        // Write to disk.
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        std::fs::write(
            &jsonl_path,
            (serde_json::to_string(&record).unwrap() + "\n").as_bytes(),
        )
        .unwrap();

        // Verify. Check 4 and Check 5 MUST pass (we signed the exact blob).
        // The M11 hook MUST fire and return MultiSigInvalid.
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::MultiSigInvalid { .. })),
            "SEC-4: verify_chain MUST return MultiSigInvalid for a syntactically-valid \
             but under-threshold multi_sig blob whose outer signature passes. \
             Got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    // ── HIGH-4: enterprise resolve_registry integration tests ────────────────
    //
    // These tests exercise `resolve_registry` directly rather than `verify_chain`
    // with CSQ_AUDIT_EDITION=enterprise, because `verify_chain` also reads
    // the edition env var, and existing tests in this module that don't hold
    // `test_env::lock()` would race on that env var if we set it while holding
    // the lock. `resolve_registry` is the component `verify_chain` delegates to
    // for the enterprise path, so testing it directly is equivalent.

    /// HIGH-4 (a): enterprise `resolve_registry` + valid installed roster → Ok(Some).
    /// Proves the daemon-startup enterprise registry path accepts a valid roster.
    #[test]
    fn verify_chain_enterprise_valid_roster_grandfathered_records_ok() {
        use crate::audit::authority::{resolve_registry, save_roster, Roster, SignedRoster};
        use crate::audit::types::Ed25519PublicKey as CoreEd25519PK;
        use crate::platform::test_env;
        use ed25519_dalek::SigningKey as DalekSK;
        use std::collections::BTreeMap;

        let _g = test_env::lock();

        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        // Build and save a valid signed roster.
        let mut seed_root = [0u8; 32];
        getrandom::getrandom(&mut seed_root).unwrap();
        let root_sk = DalekSK::from_bytes(&seed_root);
        let root_pk = CoreEd25519PK(root_sk.verifying_key().to_bytes());

        let roster = Roster {
            format_version: 1,
            roster_version: 1,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries: BTreeMap::new(),
        };
        let roster_bytes = serde_json::to_vec(&roster).unwrap();
        use ed25519_dalek::Signer;
        let sig = root_sk.sign(&roster_bytes);
        let signed = SignedRoster {
            roster,
            roster_pubkey: root_pk,
            signature: crate::audit::types::Ed25519Signature::new(sig.to_bytes()),
        };
        save_roster(base, &signed).unwrap();

        // Build chain state with activation_seq=1 (grandfathers any seq=0 record).
        let mut chain = ChainState::new("verify-high4-a-chain");
        chain.roster_activation_seq = Some(1);
        chain.roster_version_floor = Some(1);

        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", hex::encode(root_pk.0));

        let result = resolve_registry(base, &chain);

        // Clean up env before assertion.
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        match result {
            Ok(Some(_)) => {} // pass — Some(registry) returned
            Ok(None) => panic!(
                "verify_chain_enterprise_valid_roster_grandfathered_records_ok: \
                 expected Some(registry), got None"
            ),
            Err(e) => panic!(
                "verify_chain_enterprise_valid_roster_grandfathered_records_ok: \
                 expected Ok(Some(registry)), got Err({e:?})"
            ),
        }
    }

    // ── Historical-key degrade tests ─────────────────────────────────────────

    /// Helper: build a properly-signed v2 record with the given chain_id, seq,
    /// prev_hash, and signing key.  Returns the record ready for JSON serialisation.
    fn make_signed_record(
        chain_id: &str,
        seq: u64,
        prev_hash: Sha256Hex,
        record_id_suffix: &str,
        signing_key: &LocalSigningKey,
    ) -> SignedRecord {
        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let rid = {
            let raw = format!("01JZ0000000000000000{record_id_suffix}");
            if raw.len() >= 26 {
                raw[..26].to_string()
            } else {
                format!("{:0>26}", raw)
            }
        };
        let mut record = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new(rid).unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq,
            prev_hash,
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: format!("test-run-{seq}"),
            }),
            ts: "2026-06-04T00:00:00+00:00".to_string(),
            key_id: signing_key.key_id(),
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

        let sentinel_bytes = canonical_bytes_for(&record);
        record.canonical_hash = Sha256Hex::try_new(sha256_hex(&sentinel_bytes)).unwrap();

        let digest: [u8; 32] = {
            let b = hex::decode(record.canonical_hash.as_str()).unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        };
        record.signature = signing_key.sign(&digest).unwrap();
        record
    }

    /// `missing_historical_key_degrades_not_fatal`
    ///
    /// Build a two-key chain:
    ///   - Segment A (seq 0-1): signed by key A (historical, rotated out, seed deleted).
    ///   - Segment B (seq 2):   signed by key B (current active, seed present).
    ///
    /// Delete key A from the keychain. Verify that `verify_chain` returns
    /// `Ok(summary)` with one `KeyGap` covering seq 0-1, and that the current
    /// segment (seq 2) was fully verified (verified_count == 3 total).
    ///
    /// This also exercises the daemon-disposition path: the result is `Ok`,
    /// so the daemon would proceed to socket bind.
    #[test]
    fn missing_historical_key_degrades_not_fatal() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("hist_key_degrade");

        let chain_id = "01JZ00000000000000000000H1";

        // Initialise chain state + key A.
        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save initial chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init key A");

        let key_a = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load key A");
        let key_a_id = key_a.key_id().as_str().to_string();

        // Write two records signed by key A.
        let rec0 = make_signed_record(chain_id, 0, Sha256Hex::genesis(), "A0", &key_a);
        let prev_hash_1 = {
            use crate::audit::persist::canonical_bytes_for;
            use crate::audit::persist::sha256_hex;
            Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&rec0))).unwrap()
        };
        let rec1 = make_signed_record(chain_id, 1, prev_hash_1, "A1", &key_a);

        // Simulate a rotation: rename the current slot to historical/0,
        // generate a fresh key B as the new active key.
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        let _ = file_store::delete(base, chain_id, KeySlot::Historical(0));
        // We want key A ABSENT from BOTH stores (simulating a lost seed): delete
        // the active slot from the keychain AND the file store so audit_init below
        // is not short-circuited by `exists_any` and re-mints a fresh key B.
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = file_store::delete(base, chain_id, KeySlot::Active);

        // Generate key B as the new active key (both stores now empty).
        audit_init(base, &svc).expect("re-init key B");
        let key_b = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load key B");
        let key_b_id = key_b.key_id().as_str().to_string();
        assert_ne!(key_a_id, key_b_id, "keys must differ");

        // Update chain.json: signing_key_id = key B, rotation_count = 1.
        let mut state2 = ChainState::load(base).expect("load chain state");
        state2.rotation_count = 1;
        // signing_key_id is already updated by audit_init above.
        state2.save(base).expect("save updated chain.json");

        // Write one record signed by key B (seq 2).
        let prev_hash_2 = {
            use crate::audit::persist::canonical_bytes_for;
            use crate::audit::persist::sha256_hex;
            Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&rec1))).unwrap()
        };
        let rec2 = make_signed_record(chain_id, 2, prev_hash_2, "B0", &key_b);

        // Write all three records to the JSONL file.
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let content = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&rec0).unwrap(),
            serde_json::to_string(&rec1).unwrap(),
            serde_json::to_string(&rec2).unwrap(),
        );
        std::fs::write(&jsonl_path, content.as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        match &result {
            Ok(summary) => {
                assert_eq!(
                    summary.verified_count, 3,
                    "missing_historical_key_degrades_not_fatal: \
                     expected verified_count=3, got {}",
                    summary.verified_count
                );
                assert_eq!(
                    summary.historical_key_gaps.len(),
                    1,
                    "missing_historical_key_degrades_not_fatal: \
                     expected 1 historical gap, got {:?}",
                    summary.historical_key_gaps
                );
                let gap = &summary.historical_key_gaps[0];
                assert_eq!(gap.key_id, key_a_id, "gap key_id must be key A");
                assert_eq!(gap.first_seq, 0, "gap first_seq must be 0");
                assert_eq!(gap.last_seq, 1, "gap last_seq must be 1");
                assert_eq!(gap.count, 2, "gap count must be 2");
            }
            Err(e) => {
                panic!("missing_historical_key_degrades_not_fatal: expected Ok, got Err({e:?})")
            }
        }

        // Daemon-disposition check: result is Ok → proceed to bind (not Err).
        assert!(result.is_ok(), "daemon would proceed to socket bind");

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `missing_current_key_stays_fatal`
    ///
    /// Build a single-key chain (seq 0-1) signed by the current active key,
    /// then delete the current key from the keychain. Verify that `verify_chain`
    /// returns `Err(LedgerError::KeyNotFound)`.
    #[test]
    fn missing_current_key_stays_fatal() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("missing_cur_key_fatal");

        let chain_id = "01JZ00000000000000000000H2";

        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let key = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");

        let rec0 = make_signed_record(chain_id, 0, Sha256Hex::genesis(), "C0", &key);
        let prev_hash_1 = {
            use crate::audit::persist::canonical_bytes_for;
            use crate::audit::persist::sha256_hex;
            Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&rec0))).unwrap()
        };
        let rec1 = make_signed_record(chain_id, 1, prev_hash_1, "C1", &key);

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let content = format!(
            "{}\n{}\n",
            serde_json::to_string(&rec0).unwrap(),
            serde_json::to_string(&rec1).unwrap(),
        );
        std::fs::write(&jsonl_path, content.as_bytes()).unwrap();

        // Delete the CURRENT (only) key from BOTH stores — not a historical
        // rotation, just genuinely gone.
        LocalSigningKey::delete_from_keychain(&svc, chain_id).expect("delete current key");
        file_store::delete(base, chain_id, KeySlot::Active).expect("delete current key file");

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::KeyNotFound { .. })),
            "missing_current_key_stays_fatal: expected KeyNotFound, got: {result:?}"
        );
    }

    /// `tamper_across_historical_gap_still_detected`
    ///
    /// Build a chain with a historical-key gap AND introduce a prev_hash break
    /// AFTER the gap (in the current-segment records). Verify that `verify_chain`
    /// still returns `Err(LedgerError::ChainBroken)`, proving chain-linking checks
    /// run end-to-end including across the historical gap.
    #[test]
    fn tamper_across_historical_gap_still_detected() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("tamper_across_gap");

        let chain_id = "01JZ00000000000000000000H3";

        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init key A");

        let key_a = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load key A");

        // Segment A: seq 0-1, signed by key A (historical, seed will be deleted).
        let rec0 = make_signed_record(chain_id, 0, Sha256Hex::genesis(), "T0", &key_a);
        let prev_hash_1 = {
            use crate::audit::persist::canonical_bytes_for;
            use crate::audit::persist::sha256_hex;
            Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&rec0))).unwrap()
        };
        let rec1 = make_signed_record(chain_id, 1, prev_hash_1, "T1", &key_a);

        // Delete key A (historical seed lost) from BOTH stores so audit_init
        // below re-mints a fresh key B instead of no-opping on `exists_any`.
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = file_store::delete(base, chain_id, KeySlot::Active);

        // Generate key B as the new active key (both stores now empty).
        audit_init(base, &svc).expect("re-init key B");
        let key_b = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load key B");

        // Update chain.json: rotation_count = 1.
        let mut state2 = ChainState::load(base).expect("load chain state");
        state2.rotation_count = 1;
        state2.save(base).expect("save updated chain.json");

        // Segment B: seq 2, but with a TAMPERED prev_hash (pointing at garbage).
        let tampered_prev = Sha256Hex::try_new("ee".repeat(32)).unwrap();
        let rec2_tampered = make_signed_record(chain_id, 2, tampered_prev, "T2", &key_b);

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let content = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&rec0).unwrap(),
            serde_json::to_string(&rec1).unwrap(),
            serde_json::to_string(&rec2_tampered).unwrap(),
        );
        std::fs::write(&jsonl_path, content.as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::ChainBroken { seq: 2, .. })),
            "tamper_across_historical_gap_still_detected: \
             expected ChainBroken at seq 2, got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `present_key_bad_signature_stays_fatal`
    ///
    /// Build a chain where the signing key IS present in the keychain but the
    /// stored signature for one record is corrupt. Verify that `verify_chain`
    /// returns `Err(LedgerError::InvalidSignature)` — NOT a historical-key gap.
    ///
    /// This confirms: degrade only fires for a MISSING key, not for a present
    /// key with a bad signature. The latter remains an integrity failure.
    #[test]
    fn present_key_bad_signature_stays_fatal() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("present_key_bad_sig");

        let chain_id = "01JZ00000000000000000000H4";

        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let key = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");

        let rec0 = make_signed_record(chain_id, 0, Sha256Hex::genesis(), "P0", &key);
        let prev_hash_1 = {
            use crate::audit::persist::canonical_bytes_for;
            use crate::audit::persist::sha256_hex;
            Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&rec0))).unwrap()
        };
        let mut rec1 = make_signed_record(chain_id, 1, prev_hash_1, "P1", &key);

        // Corrupt the signature on rec1: flip one byte.
        let mut sig_bytes = rec1.signature.0;
        sig_bytes[0] ^= 0xff;
        rec1.signature = crate::audit::types::Ed25519Signature::new(sig_bytes);

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let content = format!(
            "{}\n{}\n",
            serde_json::to_string(&rec0).unwrap(),
            serde_json::to_string(&rec1).unwrap(),
        );
        std::fs::write(&jsonl_path, content.as_bytes()).unwrap();

        // Key IS still present in the keychain.
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(result, Err(LedgerError::InvalidSignature { .. })),
            "present_key_bad_signature_stays_fatal: \
             expected InvalidSignature (not degrade), got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// HIGH-4 (b): enterprise `resolve_registry` + MISSING roster → Err(RosterMissing).
    /// Proves the daemon-startup enterprise path refuses to start without a roster.
    #[test]
    fn verify_chain_enterprise_missing_roster_fails_closed() {
        use crate::audit::authority::{resolve_registry, AuthorityError};
        use crate::platform::test_env;

        let _g = test_env::lock();

        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        // No roster on disk. Enterprise edition + root pubkey configured.
        let chain = ChainState::new("verify-high4-b-chain");

        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", "aa".repeat(32));

        let result = resolve_registry(base, &chain);

        // Clean up env before assertion.
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        match result {
            Err(AuthorityError::RosterMissing) => {} // pass
            Err(e) => panic!(
                "verify_chain_enterprise_missing_roster_fails_closed: \
                 expected RosterMissing, got Err({e:?})"
            ),
            Ok(_) => panic!(
                "verify_chain_enterprise_missing_roster_fails_closed: \
                 expected Err(RosterMissing), got Ok"
            ),
        }
    }

    // =========================================================================
    // FIX-1 topology enforcement tests
    // =========================================================================

    /// `forged_head_with_fabricated_absent_key_is_fatal`
    ///
    /// Scenario: a single-record chain where the ONLY record carries a
    /// fabricated key_id that is:
    ///   - NOT the placeholder key (so `UnsignedRecordAfterCutoff` does not fire)
    ///   - NOT the current active key in chain.json
    ///   - NOT present anywhere in the keychain
    ///
    /// Under the pre-FIX-1 code, this would classify as a "historical gap",
    /// skip signature verification, and return `Ok(summary)` — accepting a
    /// completely forged chain head.
    ///
    /// With FIX-1, the post-loop HEAD-must-be-signed check fires because
    /// the last gap's `last_seq == summary.head_seq`:
    /// → `Err(LedgerError::HistoricalKeyAtHead)`.
    ///
    /// This is the canonical forgery-hole closure test.
    #[test]
    fn forged_head_with_fabricated_absent_key_is_fatal() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("forged_head_absent_key");

        let chain_id = "01JZ00000000000000000000FA";

        // Initialise chain state + current key (key A). Key A will be the
        // "current active key" recorded in chain.json.
        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init key A");
        let key_a = LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load key A");
        let key_a_id = key_a.key_id().as_str().to_string();

        // Fabricate a distinct key_id that does not exist in the keychain and
        // is not key A (the current active key) and is not the placeholder.
        // Use a hex string of 1s to distinguish from the 0-repeat placeholder.
        let fabricated_key_id_str = format!("ed25519:{}", "1".repeat(64));
        let fabricated_key_id =
            KeyId::try_new(fabricated_key_id_str.clone()).expect("valid fabricated key_id");
        assert_ne!(
            fabricated_key_id_str, key_a_id,
            "fabricated key must differ from current"
        );

        // Build a forged record at seq 0 carrying the fabricated key_id.
        // Compute canonical_hash correctly (so Check 4 passes) but put garbage
        // in `signature` (sig check is what FIX-1 blocks, not chain-linking).
        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut forged = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000F0").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "forged-run".to_string(),
            }),
            ts: "2026-06-05T00:00:00+00:00".to_string(),
            key_id: fabricated_key_id,
            canonical_hash: Sha256Hex::genesis(), // sentinel — will be replaced
            signature: Ed25519Signature::new([0xFFu8; 64]), // garbage signature
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        // Compute the correct canonical_hash so Check 4 passes.
        let sentinel_bytes = canonical_bytes_for(&forged);
        forged.canonical_hash = Sha256Hex::try_new(sha256_hex(&sentinel_bytes)).unwrap();
        // (Re-apply the sentinel since canonical_hash changed.)
        let sentinel_bytes2 = {
            let mut r2 = forged.clone();
            r2.canonical_hash = Sha256Hex::genesis();
            canonical_bytes_for(&r2)
        };
        forged.canonical_hash = Sha256Hex::try_new(sha256_hex(&sentinel_bytes2)).unwrap();

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let line = serde_json::to_string(&forged).unwrap() + "\n";
        std::fs::write(&jsonl_path, line.as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(
                result,
                Err(LedgerError::HistoricalKeyAtHead { head_seq: 0, .. })
            ),
            "forged_head_with_fabricated_absent_key_is_fatal: \
             expected HistoricalKeyAtHead(head_seq=0), got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// `historical_gap_after_verified_record_is_fatal`
    ///
    /// Scenario: a two-record chain where:
    ///   - rec0 is signed by the CURRENT active key (present in keychain) →
    ///     `seen_verified_signature` becomes `true` after rec0.
    ///   - rec1 carries an absent non-current key_id (historical-gap topology).
    ///
    /// Under the pre-FIX-1 code, rec1 would classify as a historical gap (since
    /// its key_id differs from the current active key) and verify would return
    /// `Ok(summary)` — accepting a forged tail appended after the real last record.
    ///
    /// With FIX-1, the gap-after-verified-segment check fires for rec1:
    /// → `Err(LedgerError::GapAfterVerifiedSegment { gap_seq: 1, .. })`.
    #[test]
    fn historical_gap_after_verified_record_is_fatal() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name("gap_after_verified");

        let chain_id = "01JZ00000000000000000000GB";

        // Initialise chain state + current key.
        use crate::audit::key_custody::chain_state::ChainState;
        let mut state = ChainState::new(chain_id);
        state.signing_active_since_seq = Some(0);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");
        let current_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load current key");
        let current_key_id = current_key.key_id().as_str().to_string();

        // rec0: legitimately signed by the current active key.
        let rec0 = make_signed_record(chain_id, 0, Sha256Hex::genesis(), "GB00", &current_key);

        // rec1: forged record with a fabricated absent key_id (not current, not placeholder).
        let fabricated_key_id_str = format!("ed25519:{}", "2".repeat(64));
        assert_ne!(fabricated_key_id_str, current_key_id);
        let fabricated_key_id =
            KeyId::try_new(fabricated_key_id_str).expect("valid fabricated key_id");

        let prev_hash_1 = {
            use crate::audit::persist::{canonical_bytes_for, sha256_hex};
            Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&rec0))).unwrap()
        };

        use crate::audit::persist::{canonical_bytes_for, sha256_hex, AUDIT_SCHEMA_VERSION};
        use crate::audit::types::{CsqRunPayload, Ed25519Signature, EventKind, EventPayload};

        let mut forged_tail = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000G1").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 1,
            prev_hash: prev_hash_1.clone(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "forged-tail".to_string(),
            }),
            ts: "2026-06-05T00:00:00+00:00".to_string(),
            key_id: fabricated_key_id,
            canonical_hash: Sha256Hex::genesis(), // sentinel — will be replaced
            signature: Ed25519Signature::new([0xAAu8; 64]), // garbage signature
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        // Compute correct canonical_hash for the forged tail record.
        let sentinel_bytes = {
            let mut r = forged_tail.clone();
            r.canonical_hash = Sha256Hex::genesis();
            canonical_bytes_for(&r)
        };
        forged_tail.canonical_hash = Sha256Hex::try_new(sha256_hex(&sentinel_bytes)).unwrap();

        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        let content = format!(
            "{}\n{}\n",
            serde_json::to_string(&rec0).unwrap(),
            serde_json::to_string(&forged_tail).unwrap(),
        );
        std::fs::write(&jsonl_path, content.as_bytes()).unwrap();

        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            matches!(
                result,
                Err(LedgerError::GapAfterVerifiedSegment { gap_seq: 1, .. })
            ),
            "historical_gap_after_verified_record_is_fatal: \
             expected GapAfterVerifiedSegment(gap_seq=1), got: {result:?}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    // ── RosterFloorAnchorStatus detector tests (#694 item 2) ─────────────

    use crate::audit::key_custody::write_roster_floor_to_keychain;

    /// When no roster is installed (chain.json has no `roster_version_floor`),
    /// `check_roster_floor_anchor` returns `Confirmed` (the safe default).
    /// `verify_chain` therefore surfaces `Confirmed` for fresh installs.
    #[test]
    fn roster_floor_anchor_confirmed_when_no_roster_installed() {
        // Hermeticity: verify_chain (below) transitively reads CSQ_AUDIT_EDITION;
        // hold the shared env lock + pin a clean community baseline so this test
        // cannot race a concurrent enterprise-edition test (testing.md Rule 6 /
        // test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        // Arrange — init a chain without ever running `roster install`.
        let base = tempfile::TempDir::new().unwrap();
        let base = base.path();
        let svc = format!("csq-test-rfanchor-none-{}", std::process::id());
        let _ = crate::audit::key_custody::audit_init(base, &svc);
        let chain_id = crate::audit::key_custody::ChainState::load(base)
            .ok()
            .map(|cs| cs.chain_id.clone())
            .unwrap_or_default();

        // Act
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let summary = verify_chain(base, &cfg, None).expect("verify must succeed");

        // Assert — Confirmed because chain.json has no floor (no roster installed).
        assert_eq!(
            summary.roster_floor_anchor,
            RosterFloorAnchorStatus::Confirmed,
            "fresh install with no roster must yield Confirmed"
        );

        if !chain_id.is_empty() {
            let _ = LocalSigningKey::delete_from_keychain(&svc, &chain_id);
        }
    }

    /// When a roster is installed and the keychain entry has the matching floor,
    /// `verify_chain` yields `Confirmed`.
    #[test]
    fn roster_floor_anchor_confirmed_when_keychain_matches_chain_json() {
        use crate::audit::key_custody::{audit_init, ChainState};
        // Hermeticity: verify_chain (below) transitively reads CSQ_AUDIT_EDITION;
        // hold the shared env lock + pin a clean community baseline (testing.md
        // Rule 6 / test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Arrange — init chain, install a synthetic roster_version_floor into
        // chain.json, then write the matching floor into the keychain.
        let base = tempfile::TempDir::new().unwrap();
        let base = base.path();
        let svc = format!("csq-test-rfanchor-match-{}", std::process::id());
        let _ = audit_init(base, &svc);

        // Load chain state and plant a roster_version_floor.
        let mut chain = ChainState::load(base).expect("chain state must exist after audit_init");
        chain.roster_version_floor = Some(3);
        chain.save(base).expect("chain.save must succeed");

        // Write the SAME floor into the keychain anchor.
        write_roster_floor_to_keychain(base, &svc, &chain.chain_id, 3);

        // Act
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let summary = verify_chain(base, &cfg, None).expect("verify must succeed");

        // Assert
        assert_eq!(
            summary.roster_floor_anchor,
            RosterFloorAnchorStatus::Confirmed,
            "matching chain.json and keychain floors must yield Confirmed"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, &chain.chain_id);
    }

    /// When a roster is installed but the keychain entry has no floor (e.g.
    /// pre-#694 keychain entry), `verify_chain` yields `Unconfirmed` — the
    /// detection layer is chain.json-only for that installation.
    #[test]
    fn roster_floor_anchor_unconfirmed_when_keychain_has_no_floor() {
        use crate::audit::key_custody::{audit_init, ChainState};
        // Hermeticity: verify_chain (below) transitively reads CSQ_AUDIT_EDITION;
        // hold the shared env lock + pin a clean community baseline (testing.md
        // Rule 6 / test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Arrange — init chain, plant a floor in chain.json, but do NOT write
        // the floor into the keychain (simulating a pre-#694 keychain entry).
        let base = tempfile::TempDir::new().unwrap();
        let base = base.path();
        let svc = format!("csq-test-rfanchor-unconf-{}", std::process::id());
        let _ = audit_init(base, &svc);

        let mut chain = ChainState::load(base).expect("chain state must exist after audit_init");
        chain.roster_version_floor = Some(5);
        chain.save(base).expect("chain.save must succeed");
        // Note: no write_roster_floor_to_keychain call here.

        // Act
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let summary = verify_chain(base, &cfg, None).expect("verify must succeed");

        // Assert — keychain floor is None → Unconfirmed.
        assert_eq!(
            summary.roster_floor_anchor,
            RosterFloorAnchorStatus::Unconfirmed,
            "pre-#694 keychain entry (no floor field) must yield Unconfirmed"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, &chain.chain_id);
    }

    /// When the keychain-anchored floor DIFFERS from chain.json's floor, the
    /// detector returns `Mismatch` — indicating possible rollback tampering.
    /// This MUST NOT prevent `verify_chain` from returning `Ok` (non-fatal).
    #[test]
    fn roster_floor_anchor_mismatch_when_keychain_floor_differs() {
        use crate::audit::key_custody::{audit_init, ChainState};
        // Hermeticity: verify_chain (below) transitively reads CSQ_AUDIT_EDITION;
        // hold the shared env lock + pin a clean community baseline (testing.md
        // Rule 6 / test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Arrange — chain.json floor = 10, keychain anchor floor = 5.
        let base = tempfile::TempDir::new().unwrap();
        let base = base.path();
        let svc = format!("csq-test-rfanchor-mismatch-{}", std::process::id());
        let _ = audit_init(base, &svc);

        let mut chain = ChainState::load(base).expect("chain state must exist after audit_init");
        chain.roster_version_floor = Some(10);
        chain.save(base).expect("chain.save must succeed");

        // Write a DIFFERENT floor into the keychain (simulating an attacker
        // who rolled back chain.json but did not update the keychain).
        write_roster_floor_to_keychain(base, &svc, &chain.chain_id, 5);

        // Act — verify MUST return Ok (non-fatal DETECTOR, never bricks).
        let cfg = VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let result = verify_chain(base, &cfg, None);
        assert!(
            result.is_ok(),
            "Mismatch is non-fatal: verify_chain must return Ok; got: {result:?}"
        );

        // Assert — the summary carries the Mismatch verdict.
        let summary = result.unwrap();
        assert_eq!(
            summary.roster_floor_anchor,
            RosterFloorAnchorStatus::Mismatch,
            "differing chain.json (10) vs keychain (5) floors must yield Mismatch"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, &chain.chain_id);
    }

    // === M3a Acceptance Criterion Tests ===

    /// AC-1 — a `SignedRecord` with `verification_level: None` serialises to
    /// canonical bytes byte-identical to the same record before M3a (the new
    /// optional field must NOT appear in the canonical form when absent).
    #[test]
    fn signed_record_without_level_canonical_byte_identical() {
        use crate::audit::eatp_canonical::VerificationLevel;
        use crate::audit::persist::canonical_bytes_for_test;

        let base = sample_v2_record("AC1");
        // Record without a level (pre-M3a shape).
        let without_level = base.clone();
        // Record with a level set.
        let mut with_level = base.clone();
        with_level.verification_level = Some(VerificationLevel::AutoApproved);

        let bytes_without = canonical_bytes_for_test(&without_level);
        let bytes_with = canonical_bytes_for_test(&with_level);

        // The canonical bytes MUST differ — the level is signed.
        assert_ne!(
            bytes_without, bytes_with,
            "canonical bytes must differ when verification_level is set (level is signed)"
        );

        // The without-level canonical bytes must NOT contain the level — neither
        // the wire VALUE (`as_canonical_str` emits UPPERCASE "AUTO_APPROVED") nor
        // the field KEY ("verification_level"). The prior assertion checked the
        // lowercase "auto_approved", which the serializer never emits, so it was
        // vacuously true and could not catch a value-leak regression (redteam
        // R1 MED/NIT, 2026-06-17).
        let canonical_str = String::from_utf8_lossy(&bytes_without);
        assert!(
            !canonical_str.contains("AUTO_APPROVED"),
            "pre-M3a canonical form must not contain the level value: {canonical_str}"
        );
        assert!(
            !canonical_str.contains("verification_level"),
            "pre-M3a canonical form must not contain the verification_level key: {canonical_str}"
        );
    }

    /// AC-3 — cutoff-aware `verification_levels_populated` signal.
    /// Pre-M3a records (no level) followed by post-M3a records (with level)
    /// must set the signal only when all post-cutoff records carry a level.
    #[test]
    fn verification_levels_populated_cutoff_aware() {
        use crate::audit::eatp_canonical::VerificationLevel;

        // Drive the ACTUAL fold helper (`m3a_fold_record`) that verify_chain
        // runs per record, then apply the production predicate
        // (`first_leveled_seq.is_some() && levels_contiguous`). Prior version
        // asserted only against `VerifySummary::default()` / a hand-set bool, so
        // the load-bearing `levels_contiguous=false` gap branch had ZERO
        // coverage (redteam R1 MED, 2026-06-17). A real chain cannot reproduce
        // the gap because the enterprise writer always stamps; the gap is the
        // defensive downgrade/tamper case, so we drive the fold directly.
        //
        // `seqs`: (seq, has_level) tuples in chain order. Returns the predicate.
        fn fold(seqs: &[(u64, bool)]) -> bool {
            let mut first_leveled_seq: Option<u64> = None;
            let mut levels_contiguous = true;
            #[cfg(feature = "enterprise")]
            let mut summary_map = std::collections::BTreeMap::new();
            for &(seq, has_level) in seqs {
                let mut rec = sample_v2_record("AC3");
                rec.seq = seq;
                rec.verification_level = has_level.then_some(VerificationLevel::AutoApproved);
                m3a_fold_record(
                    rec.seq,
                    rec.verification_level.as_ref(),
                    &mut first_leveled_seq,
                    &mut levels_contiguous,
                    #[cfg(feature = "enterprise")]
                    &mut summary_map,
                );
            }
            first_leveled_seq.is_some() && levels_contiguous
        }

        // Case A — empty chain: no leveled record → false (no vacuous true).
        assert!(!fold(&[]), "empty chain → false");

        // Case B — all records leveled (post-M3a steady state) → true.
        assert!(
            fold(&[(0, true), (1, true), (2, true)]),
            "all leveled → CONFORMANT-eligible"
        );

        // Case C — legacy prefix (no level) then leveled-to-head: pre-cutoff
        // records are EXEMPT (they precede first_leveled_seq) → true.
        assert!(
            fold(&[(0, false), (1, false), (2, true), (3, true)]),
            "legacy prefix then leveled-to-head → true (legacy exempt)"
        );

        // Case D — THE load-bearing branch: leveled record then a later
        // unleveled record (gap / downgrade) → contiguity broken → false.
        assert!(
            !fold(&[(0, true), (1, true), (2, false)]),
            "post-cutoff gap (leveled then unleveled) → false"
        );

        // Case E — legacy-only chain (never leveled) → false (stays COMPATIBLE).
        assert!(
            !fold(&[(0, false), (1, false)]),
            "legacy-only chain → false"
        );
    }

    /// AC-7 — `grade_surface_always_includes_level_summary`.
    /// Enterprise: `to_json_output` on an Ok result that carries leveled
    /// records includes a non-None `verification_level_summary`.
    /// Community: `verification_level_summary` is always `None`.
    #[test]
    fn grade_surface_always_includes_level_summary() {
        // Build a summary with at least one leveled record.
        #[cfg(feature = "enterprise")]
        {
            use crate::audit::eatp_canonical::VerificationLevel;
            let mut summary = VerifySummary::default();
            summary.verification_level_summary.insert(
                VerificationLevel::AutoApproved
                    .as_canonical_str()
                    .to_string(),
                3,
            );
            let result: Result<VerifySummary, LedgerError> = Ok(summary);
            let out = to_json_output(&result);
            let map = out.verification_level_summary.expect(
                "enterprise: to_json_output with leveled summary must include level_summary",
            );
            assert_eq!(map.get("AUTO_APPROVED"), Some(&3));
        }

        // Community: even with verification_level_summary set, the field is
        // always None (edition boundary preserved).
        #[cfg(not(feature = "enterprise"))]
        {
            let summary = VerifySummary::default();
            let result: Result<VerifySummary, LedgerError> = Ok(summary);
            let out = to_json_output(&result);
            assert_eq!(
                out.verification_level_summary, None,
                "community: verification_level_summary must always be None"
            );
        }
    }

    /// AC-8 — `community_verify_json_omits_grade_surface`.
    /// Community build: `trust_plane_grade` and `verification_level_summary`
    /// are both `None` and therefore omitted from JSON serialisation.
    #[test]
    fn community_verify_json_omits_grade_surface() {
        let result: Result<VerifySummary, LedgerError> = Ok(VerifySummary::default());
        let out = to_json_output(&result);

        #[cfg(not(feature = "enterprise"))]
        {
            assert_eq!(
                out.trust_plane_grade, None,
                "community: trust_plane_grade must be None (omitted from JSON)"
            );
            assert_eq!(
                out.verification_level_summary, None,
                "community: verification_level_summary must be None (omitted from JSON)"
            );
            // Verify the JSON output does not contain either field key.
            let json = serde_json::to_string(&out).unwrap();
            assert!(
                !json.contains("trust_plane_grade"),
                "community JSON must not contain trust_plane_grade: {json}"
            );
            assert!(
                !json.contains("verification_level_summary"),
                "community JSON must not contain verification_level_summary: {json}"
            );
        }

        // Enterprise: fields ARE present (covered by other tests).
        #[cfg(feature = "enterprise")]
        {
            let _ = out; // avoid unused warning in enterprise build
        }
    }
}
