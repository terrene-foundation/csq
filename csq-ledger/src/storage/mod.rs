//! Append-only storage backend for csq-ledger (M10, PRIMARY DIRECTIVE 1 + 2).
//!
//! # Local file, not a database (PRIMARY DIRECTIVE 1)
//!
//! Storage is hand-rolled append-only segment files. No Postgres, SQLite,
//! RocksDB, or `sled`. An append-only transparency log is exactly the workload
//! file-backed storage handles best, and the milestone explicitly permits the
//! hand-rolled fallback when `sled` would add undesirable dep mass (it would —
//! ~15 transitive crates for a write-once workload). See spec 17 §17.4.
//!
//! # NEVER deletes or overwrites (PRIMARY DIRECTIVE 2)
//!
//! This module exposes NO `delete`, `truncate`, `compact`, `vacuum`, `wipe`,
//! `prune`, or `gc` operation. Once [`LedgerStore::append`] has returned, the
//! bytes that produced the inclusion proof are append-only forever from
//! csq-ledger's perspective. The audit primitive:
//!
//! ```bash
//! grep -rEn 'fn (delete|truncate|compact|vacuum|wipe|prune|gc)\b' \
//!   csq-ledger/src/storage/ --include='*.rs' | grep -v test
//! # Expected: 0 matches
//! ```
//!
//! is the structural enforcement. A future "compact" feature would silently
//! re-enable operator-side tamper, which is why the storage surface is
//! deliberately delete-free.
//!
//! # fsync before any operator-facing ack (PRIMARY DIRECTIVE 6)
//!
//! [`LedgerStore::append`] fsyncs BOTH the segment file (record bytes) AND the
//! segment directory (the rename / size-marker durability) before returning.
//! The server returns HTTP 200 only after `append` returns. There is NO
//! skip-fsync flag — fsync is unconditional.
//!
//! # On-disk layout
//!
//! ```text
//! <data_dir>/
//!   log/
//!     segment-00000000.jsonl   ← records 0..ROLL_THRESHOLD (one JSON object/line)
//!     segment-00000001.jsonl   ← records ROLL_THRESHOLD..2*ROLL_THRESHOLD
//!     ...
//!   leaves.bin                 ← append-only u32-prefixed leaf-hash log (32B each)
//!   tree_size                  ← ASCII decimal head-size marker (fsync'd last)
//!   anchors.jsonl              ← anchor receipts (append-only)
//!   anchor-verdict-version      ← durable monotonic authority-version counter (H2)
//!   anchor-revocations.jsonl   ← authority-signed revocation facts (append-only)
//!   signing-key.pem            ← server signing key (see signing.rs)
//! ```
//!
//! # Issued verdicts are not individually persisted (H2)
//!
//! An unauthenticated `GET /v1/log/entries/{id}?tenant_id=<anything>` reaches
//! [`LedgerStore::issue_anchor_verdict`]. Before this fix that call appended a
//! full signed-verdict line to `anchor-verdicts.jsonl` and fsync'd it, so any
//! caller — no prior relationship required, `tenant_id` is any 1-128 char
//! string — could drive an unbounded, durable, fsync'd disk append merely by
//! polling a read route. The two facts that actually need to survive a
//! restart are (a) the monotonic authority-version counter (so a version is
//! never reused or rolled back) and (b) the revocation set (so a revoked
//! anchor stays revoked). Neither requires persisting the ISSUED verdict
//! itself — it is already handed to the caller, who holds the only copy that
//! matters. `issue_anchor_verdict` now durably bumps the `anchor-verdict-version`
//! counter marker (one small fsync'd write, same shape as the `tree_size`
//! marker) instead of appending a growing JSONL line per request. Revocations
//! and verifier bootstraps are rare, authority-only writes (H3 moves them to
//! their own listener) and keep their own append-only JSONL files unchanged.
//!
//! A data directory created before this fix may still have a populated
//! `anchor-verdicts.jsonl`; recovery still reads it (read-only, never written
//! again) to fold its recorded versions into the counter, so upgrading an
//! existing deployment cannot roll the version back.
//!
//! `leaves.bin` is the recomputation source for the Merkle tree: 32 bytes per
//! leaf, in seq order. The segment files hold the authoritative record bytes
//! for `GET /v1/log/entries/{id}`.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
// `File` is used only by the `#[cfg(unix)]` directory-fsync in `fsync_dir`
// (Windows has no directory-fsync equivalent), so gate the import to match
// (else unused-imports on windows-latest under `-D warnings`).
#[cfg(unix)]
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use csq_core::audit::types::SignedRecord;

use crate::anchor_verdict::{
    AnchorRevocation, AnchorVerdict, AnchorVerdictError, AnchorVerdictStatus, VerifiedAnchor,
    VerifierBootstrap,
};
use crate::merkle::{self, Hash};
use crate::signing::ServerSigningKey;

/// Records per segment file before rolling to the next segment.
const ROLL_THRESHOLD: u64 = 10_000;

/// Filename for the durable authority-version counter marker (H2). Replaces a
/// full JSONL append per issued verdict: the version is the only durable
/// state an issued (non-revoked) verdict needs to leave behind, so a read
/// request no longer performs an unbounded, growing, fsync'd append. Same
/// on-disk shape as the `tree_size` marker (an ASCII decimal, fsync'd on
/// every write).
const ANCHOR_VERDICT_VERSION_MARKER: &str = "anchor-verdict-version";

/// Canonical leaf bytes for a record: the deterministic serde_json
/// serialization of the full `SignedRecord` (including signature).
///
/// The leaf commits to the CANONICAL RE-SERIALIZATION of the record, NOT the
/// exact wire bytes the submitter sent (rust-R6). The submit handler
/// deserializes the body into the typed `SignedRecord` and this function
/// re-serializes it; serde_json key-sorts object fields inside the EATP `Value`
/// payloads during that round-trip, so the leaf pre-image is the canonical form,
/// which may differ byte-for-byte from the submitted bytes (whitespace,
/// key order). That is sound because:
///
/// - The SAME function produces the leaf bytes for hashing here AND the bytes
///   stored to the segment (storage::append serializes once via
///   `serde_json::to_string`), so an inclusion proof and the persisted record
///   commit to identical bytes — Merkle integrity holds (the hashing and storage
///   pre-images are produced deterministically by the same serializer).
/// - csq's record signature is over `canonical_hash` (a content-derived digest,
///   the M05 unified-contract field), NOT over the wire bytes, so canonical
///   re-serialization (key reordering) does NOT invalidate the record signature.
///
/// Holding the full record (signature included) as the leaf pre-image means an
/// inclusion proof commits to the record's signature too — a verifier cannot
/// later swap the signature without invalidating the proof.
#[must_use]
pub fn canonical_leaf_bytes(record: &SignedRecord) -> Vec<u8> {
    // `serde_json::to_vec` over the typed struct is deterministic for our
    // schema: top-level field order is fixed by the struct definition, and
    // serde_json key-sorts nested `Value` object fields, so the output is a
    // single canonical encoding for a given record.
    serde_json::to_vec(record).expect("SignedRecord always serializes")
}

/// An error from the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Filesystem I/O failure. The message is a fixed-vocabulary description
    /// (no token/path leakage to operator surfaces).
    #[error("storage io error: {context}")]
    Io {
        /// Fixed-vocabulary context tag.
        context: &'static str,
        /// Underlying I/O error (for `#[source]` chaining; never surfaced raw
        /// to HTTP responses).
        #[source]
        source: std::io::Error,
    },
    /// A persisted segment line failed to parse as a `SignedRecord`. This is a
    /// corruption signal — the file was tampered with outside csq-ledger.
    #[error("corrupt segment record at seq {seq}")]
    CorruptRecord {
        /// The sequence number whose line failed to parse.
        seq: u64,
    },
    /// The on-disk `tree_size` marker disagrees with the recovered record
    /// count. Surfaced at startup so a torn write is loud, not silent.
    #[error("recovered {recovered} records but tree_size marker says {marker}")]
    SizeMarkerMismatch {
        /// Records actually recovered from segments.
        recovered: u64,
        /// The value read from the `tree_size` marker.
        marker: u64,
    },
    /// A durable authority verdict or revocation was malformed, forged, or
    /// reused an already-issued monotonic version. Startup refuses rather than
    /// silently dropping security state and serving a revoked anchor as valid.
    #[error("corrupt authority anchor state")]
    CorruptAuthorityAnchorState,
    /// The authority version space is exhausted, so a fresh verdict cannot be
    /// issued without risking a rollback.
    #[error("authority anchor version exhausted")]
    AuthorityVersionExhausted,
    /// A verifier namespace has already consumed its sole bootstrap authority.
    #[error("verifier bootstrap is already redeemed")]
    VerifierBootstrapAlreadyRedeemed,
}

impl StorageError {
    fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }
}

/// Append-only ledger store. Thread-safe via an internal `Mutex` guarding the
/// single-writer append path; reads take the same lock briefly to snapshot.
pub struct LedgerStore {
    data_dir: PathBuf,
    inner: Mutex<Inner>,
}

/// The mutable interior, guarded by [`LedgerStore::inner`].
struct Inner {
    /// All leaf hashes in seq order. The Merkle-tree recomputation source.
    leaves: Vec<Hash>,
    /// record_id → seq, for `GET /v1/log/entries/{id}` lookups.
    id_to_seq: HashMap<String, u64>,
    /// In-memory copy of every record by seq (segment-backed, recovered at
    /// startup). For an append-only log this is acceptable; the authoritative
    /// bytes are the segment files, this is the query cache.
    records: Vec<SignedRecord>,
    /// Anchor receipts appended via [`LedgerStore::record_anchor`].
    anchors: Vec<AnchorReceipt>,
    /// Latest permanent revocation fact per `(anchor_id, tenant_id)`.
    anchor_revocations: HashMap<(String, String), AnchorRevocation>,
    /// Greatest authority version issued so far, across the durable counter
    /// marker (H2), any legacy `anchor-verdicts.jsonl` entries recovered from
    /// a pre-H2 data directory, and the revocation / bootstrap logs.
    anchor_verdict_version: u64,
    /// Verifier namespaces that have consumed their one durable bootstrap.
    verifier_bootstrap_ids: HashSet<String>,
}

/// A stored anchor receipt: the sink's acknowledgement of a csq-ledger
/// checkpoint, surfaced via `GET /v1/checkpoint`'s `anchored_to` field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Sink name (e.g. `"rekor"`, `"s3"`).
    pub sink: String,
    /// Sink-assigned id for the anchored checkpoint.
    pub anchor_id: String,
    /// The tree size that was anchored.
    pub tree_size: u64,
    /// The root hash (hex) that was anchored.
    pub root_hash: String,
    /// RFC 3339 timestamp when the anchor was acknowledged.
    pub anchored_at: String,
    /// `true` when the anchor was witnessed ON TRUST — the sink returned NO
    /// inclusion proof, so csq-ledger has only the sink's word that the
    /// checkpoint was logged (security-L1). `false` when the sink returned an
    /// inclusion proof (e.g. Rekor). NOTE (M10): a returned proof is recorded as
    /// `unverified=false` on the basis of PRESENCE; cryptographic verification
    /// that the proof commits to this checkpoint's record_id/root is sink-
    /// dependent and deferred to Phase B. Defaults to `true` (the safe default —
    /// an old receipt without this field is treated as on-trust).
    #[serde(default = "default_unverified")]
    pub unverified: bool,
}

/// Serde default for [`AnchorReceipt::unverified`]: an old (pre-L1) receipt that
/// lacks the field is treated as on-trust (`true`) — fail safe.
fn default_unverified() -> bool {
    true
}

/// The result of an [`LedgerStore::append`] — the assigned seq plus the leaf
/// hash, enough for the server to build the submit response.
#[derive(Debug, Clone)]
pub struct AppendResult {
    /// The assigned log index (seq), starting at 0.
    pub log_index: u64,
    /// The leaf hash of the appended record.
    pub leaf_hash: Hash,
}

impl LedgerStore {
    /// Opens (or initializes) the store rooted at `data_dir`, pinning
    /// recovered authority verdict/revocation state to `authority_key_id` (the
    /// active server signing key). This is the ONLY way to open a store (`M3`
    /// — the prior unpinned `open()` recovered each authority artifact against
    /// its OWN embedded `signed_by_key_id` when no pin was supplied, so a
    /// locally planted, self-signed revocation or verdict file self-verified
    /// instead of being rejected as forged). Every caller, production and
    /// test, pins to a real signing key.
    ///
    /// Recovery reads every segment line, rebuilds the leaf-hash vector and the
    /// id→seq index, and cross-checks the count against the `tree_size` marker.
    /// This is the fsync-before-200 durability property's read side: every
    /// record that was acked (200'd) was fsync'd before the ack, so it is
    /// present in a segment and recovered here.
    pub fn open_with_authority(
        data_dir: impl AsRef<Path>,
        authority_key_id: &str,
    ) -> Result<Self, StorageError> {
        Self::open_inner(data_dir, authority_key_id)
    }

    fn open_inner(
        data_dir: impl AsRef<Path>,
        authority_key_id: &str,
    ) -> Result<Self, StorageError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let log_dir = data_dir.join("log");
        std::fs::create_dir_all(&log_dir).map_err(|e| StorageError::io("create log dir", e))?;
        secure_dir_best_effort(&data_dir);
        secure_dir_best_effort(&log_dir);

        let mut leaves: Vec<Hash> = Vec::new();
        let mut id_to_seq: HashMap<String, u64> = HashMap::new();
        let mut records: Vec<SignedRecord> = Vec::new();

        // ── Recover segments in order ────────────────────────────────────────
        //
        // Torn-trailing-line tolerance (deep-F1). Append is serialized under the
        // `Inner` Mutex (held across write → fsync segment → fsync dir → fsync
        // marker → return), and the server emits HTTP 200 only after `append`
        // returns Ok. So a line is fully written + fsync'd before the next
        // append's write begins, and the ONLY line that can ever be partially
        // written (torn) on a crash is the line of the in-flight append at crash
        // time — necessarily the FINAL non-empty line of the FINAL (highest-
        // index) segment. That append never returned Ok, so no 200 was sent and
        // no client received its inclusion proof. Such a torn never-acked tail is
        // NOT an acked record, so dropping it does not violate the append-only
        // invariant (which protects ACKED records).
        //
        // A parse failure on ANY line that is NOT the last non-empty line of the
        // last segment is genuine tamper (something rewrote the file out-of-band)
        // → fatal `CorruptRecord`.
        let mut seg_paths: Vec<(u64, PathBuf)> = Vec::new();
        {
            let mut seg_index = 0u64;
            loop {
                let seg_path = segment_path(&log_dir, seg_index);
                if !seg_path.exists() {
                    break;
                }
                seg_paths.push((seg_index, seg_path));
                seg_index += 1;
            }
        }
        let last_seg_index = seg_paths.len().checked_sub(1);
        for (pos, (_seg_index, seg_path)) in seg_paths.iter().enumerate() {
            let is_last_segment = Some(pos) == last_seg_index;
            let content = std::fs::read_to_string(seg_path)
                .map_err(|e| StorageError::io("open segment", e))?;
            // Track the byte offset at which each line's text starts, so a torn
            // trailing line can be truncated to the end of the last good line.
            let mut byte_offset: u64 = 0;
            // Byte offset of the end of the last successfully-parsed line
            // (including its trailing '\n'), used as the truncation point.
            let mut last_good_end: u64 = 0;
            for raw_line in content.split_inclusive('\n') {
                let line_start = byte_offset;
                byte_offset += raw_line.len() as u64;
                let line = raw_line.trim_end_matches('\n');
                if line.trim().is_empty() {
                    // Blank line: advance past it but keep last_good_end where it
                    // was (a blank line never carries a record).
                    if line.is_empty() {
                        last_good_end = byte_offset;
                    }
                    continue;
                }
                let seq = records.len() as u64;
                match serde_json::from_str::<SignedRecord>(line) {
                    Ok(record) => {
                        let leaf = merkle::hash_leaf(canonical_leaf_bytes(&record).as_slice());
                        id_to_seq.insert(record.record_id.as_str().to_string(), seq);
                        leaves.push(leaf);
                        records.push(record);
                        last_good_end = byte_offset;
                    }
                    Err(_) => {
                        // Is this the final non-empty line of the final segment?
                        // It is iff (a) we are in the last segment AND (b) no
                        // later non-empty line exists in this segment's remaining
                        // bytes. (No later segment exists by construction — this
                        // IS the last segment.)
                        let rest = &content[(line_start + raw_line.len() as u64) as usize..];
                        let has_later_nonempty = rest.lines().any(|l| !l.trim().is_empty());
                        if is_last_segment && !has_later_nonempty {
                            // Torn never-acked trailing line. Truncate the segment
                            // to the end of the last good line and continue
                            // startup. The marker cross-check below reconciles the
                            // size marker to the recovered count.
                            let f = OpenOptions::new()
                                .write(true)
                                .open(seg_path)
                                .map_err(|e| StorageError::io("open segment for truncate", e))?;
                            f.set_len(last_good_end)
                                .map_err(|e| StorageError::io("truncate torn segment", e))?;
                            f.sync_all()
                                .map_err(|e| StorageError::io("fsync truncated segment", e))?;
                            drop(f);
                            fsync_dir(&log_dir)?;
                            tracing::warn!(
                                recovered = records.len(),
                                "recovered {} records, discarded 1 torn never-acked trailing line",
                                records.len()
                            );
                            break;
                        }
                        // Mid-file corruption: genuine tamper → fatal.
                        return Err(StorageError::CorruptRecord { seq });
                    }
                }
            }
        }

        // Cross-check the tree_size marker (loud on torn writes).
        let marker_path = data_dir.join("tree_size");
        if marker_path.exists() {
            let raw = std::fs::read_to_string(&marker_path)
                .map_err(|e| StorageError::io("read tree_size marker", e))?;
            if let Ok(marker) = raw.trim().parse::<u64>() {
                let recovered = records.len() as u64;
                // The marker is written AFTER the segment fsync, so the marker
                // may legitimately be one BEHIND the recovered count if a crash
                // happened between segment-fsync and marker-write. The record
                // was durably written (it's in the segment) so we trust the
                // recovered count and rewrite the marker. The marker being
                // AHEAD of recovered records is the genuine corruption signal.
                if marker > recovered {
                    return Err(StorageError::SizeMarkerMismatch { recovered, marker });
                }
            }
        }

        // Recover anchors.
        let mut anchors: Vec<AnchorReceipt> = Vec::new();
        let anchors_path = data_dir.join("anchors.jsonl");
        if anchors_path.exists() {
            let raw = std::fs::read_to_string(&anchors_path)
                .map_err(|e| StorageError::io("read anchors", e))?;
            for line in raw.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(a) = serde_json::from_str::<AnchorReceipt>(line) {
                    anchors.push(a);
                }
            }
        }

        // Recover authority-issued verdict versions and permanent revocation
        // facts. Unlike optional anchor receipts, malformed authority state is
        // fatal: silently dropping it would turn a revoked anchor into valid.
        // Recovery is torn-tail tolerant (deep-F1, extended to the single-file
        // authority artifacts by `recover_authority_lines` — see its doc
        // comment for the safety argument); mid-file corruption stays fatal.
        //
        // `anchor-verdicts.jsonl` is a LEGACY artifact (H2): a data directory
        // created before H2 may still have entries here from the old
        // per-issued-verdict append path. Nothing APPENDS to this file
        // anymore — kept solely so upgrading an existing deployment cannot
        // roll the authority version backward — but recovery may still
        // truncate a torn trailing line left by a pre-H2 crash. A fresh H2+
        // deployment never creates this file, so the block is a no-op for it.
        let mut used_authority_versions = HashSet::new();
        let mut anchor_verdict_version = 0u64;
        let verdicts_path = data_dir.join("anchor-verdicts.jsonl");
        for verdict in recover_authority_lines::<AnchorVerdict>(&verdicts_path, "anchor-verdicts")?
        {
            verdict
                .verify_signature_with_authority(authority_key_id)
                .map_err(|_| StorageError::CorruptAuthorityAnchorState)?;
            if !used_authority_versions.insert(verdict.version) {
                return Err(StorageError::CorruptAuthorityAnchorState);
            }
            anchor_verdict_version = anchor_verdict_version.max(verdict.version);
        }

        // Recover the durable authority-version counter marker (H2): the
        // primary source for versions issued via `issue_anchor_verdict` going
        // forward, since that path no longer appends a full line per request.
        // `.max()` with the legacy-file result above and the revocation /
        // bootstrap logs below means whichever source recorded the highest
        // version wins, so the counter can only ever move forward across an
        // upgrade or a restart.
        let version_marker_path = data_dir.join(ANCHOR_VERDICT_VERSION_MARKER);
        if version_marker_path.exists() {
            let raw = std::fs::read_to_string(&version_marker_path)
                .map_err(|e| StorageError::io("read anchor verdict version marker", e))?;
            if let Ok(marker_version) = raw.trim().parse::<u64>() {
                anchor_verdict_version = anchor_verdict_version.max(marker_version);
            }
        }

        let revocations_path = data_dir.join("anchor-revocations.jsonl");
        let mut anchor_revocations = HashMap::new();
        for revocation in
            recover_authority_lines::<AnchorRevocation>(&revocations_path, "anchor-revocations")?
        {
            revocation
                .verify_with_authority(authority_key_id)
                .map_err(|_| StorageError::CorruptAuthorityAnchorState)?;
            if !used_authority_versions.insert(revocation.version) {
                return Err(StorageError::CorruptAuthorityAnchorState);
            }
            anchor_verdict_version = anchor_verdict_version.max(revocation.version);
            let key = (revocation.anchor_id.clone(), revocation.tenant_id.clone());
            anchor_revocations.insert(key, revocation);
        }

        let bootstraps_path = data_dir.join("verifier-bootstraps.jsonl");
        let mut verifier_bootstrap_ids = HashSet::new();
        for bootstrap in
            recover_authority_lines::<VerifierBootstrap>(&bootstraps_path, "verifier-bootstraps")?
        {
            // Signature-only BY DESIGN: redemption records are durable, so
            // every one recovered here is long past its freshness window.
            // See VerifierBootstrap::verify_signature_with_authority.
            bootstrap
                .verify_signature_with_authority(authority_key_id)
                .map_err(|_| StorageError::CorruptAuthorityAnchorState)?;
            if !used_authority_versions.insert(bootstrap.version)
                || !verifier_bootstrap_ids.insert(bootstrap.verifier_id.clone())
            {
                return Err(StorageError::CorruptAuthorityAnchorState);
            }
            anchor_verdict_version = anchor_verdict_version.max(bootstrap.version);
        }

        // Recovery invariant: one leaf hash per recovered record. The append
        // path pushes to `leaves` and `records` together under the Mutex, and a
        // poisoned-Mutex recovery (`unwrap_or_else(|p| p.into_inner())`) would
        // observe whatever the panicking writer left — this assert pins the
        // post-recovery state so a future change that desyncs the two vectors
        // (e.g. pushing a leaf before the record but panicking between) trips in
        // debug/test (rust-R1).
        debug_assert_eq!(
            leaves.len(),
            records.len(),
            "recovered leaf-hash count must equal recovered record count"
        );

        let store = Self {
            data_dir,
            inner: Mutex::new(Inner {
                leaves,
                id_to_seq,
                records,
                anchors,
                anchor_revocations,
                anchor_verdict_version,
                verifier_bootstrap_ids,
            }),
        };
        // Re-sync the size marker to the recovered count (idempotent).
        store.write_size_marker()?;
        Ok(store)
    }

    /// Appends `record` to the log, fsyncing the record bytes to disk BEFORE
    /// returning (PRIMARY DIRECTIVE 6). Returns the assigned log index + leaf.
    ///
    /// The durability sequence is:
    /// 1. Append the JSON line to the current segment file.
    /// 2. `file.sync_all()` — fsync the segment (data + metadata).
    /// 3. fsync the segment's parent directory (durably link the appended size).
    /// 4. Write + fsync the `tree_size` marker.
    /// 5. Update in-memory state and return.
    ///
    /// Only after step 5 does the caller (the server) emit HTTP 200. A crash at
    /// any point before step 2 returns means the record was NOT acked and is
    /// absent on recovery — the inclusion proof was never handed out.
    pub fn append(&self, record: SignedRecord) -> Result<AppendResult, StorageError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let seq = inner.records.len() as u64;
        let leaf = merkle::hash_leaf(canonical_leaf_bytes(&record).as_slice());

        // ── Step 1: append the JSON line to the current segment ──────────────
        let log_dir = self.data_dir.join("log");
        let seg_index = seq / ROLL_THRESHOLD;
        let seg_path = segment_path(&log_dir, seg_index);
        let line = serde_json::to_string(&record).expect("SignedRecord serializes") + "\n";

        let mut seg_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&seg_path)
            .map_err(|e| StorageError::io("open segment for append", e))?;
        seg_file
            .write_all(line.as_bytes())
            .map_err(|e| StorageError::io("write segment line", e))?;

        // ── Step 2: fsync the segment file (data durability) ─────────────────
        seg_file
            .sync_all()
            .map_err(|e| StorageError::io("fsync segment", e))?;

        // ── Step 3: fsync the segment directory (metadata durability) ────────
        fsync_dir(&log_dir)?;

        // ── Step 4: write + fsync the size marker ────────────────────────────
        write_and_fsync_marker(&self.data_dir, "tree_size", seq + 1)?;

        // ── Step 5: update in-memory state ───────────────────────────────────
        inner
            .id_to_seq
            .insert(record.record_id.as_str().to_string(), seq);
        inner.leaves.push(leaf);
        inner.records.push(record);

        Ok(AppendResult {
            log_index: seq,
            leaf_hash: leaf,
        })
    }

    /// Returns the record at `seq`, or `None` if `seq >= tree_size`.
    pub fn record_at(&self, seq: u64) -> Option<SignedRecord> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.records.get(seq as usize).cloned()
    }

    /// Returns the record with `record_id`, plus its seq, or `None`.
    pub fn record_by_id(&self, record_id: &str) -> Option<(u64, SignedRecord)> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let seq = *inner.id_to_seq.get(record_id)?;
        let record = inner.records.get(seq as usize)?.clone();
        Some((seq, record))
    }

    /// Current tree size (number of appended records).
    pub fn tree_size(&self) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.records.len() as u64
    }

    /// Snapshots the current leaf-hash vector (for Merkle computation).
    pub fn leaf_hashes(&self) -> Vec<Hash> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.leaves.clone()
    }

    /// Computes the current Merkle root over all leaves (RFC 6962).
    pub fn root_hash(&self) -> Hash {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        merkle::merkle_root(&inner.leaves)
    }

    /// Computes the inclusion proof for the leaf at `seq` in the current tree.
    pub fn inclusion_proof(&self, seq: u64) -> Option<Vec<Hash>> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        merkle::inclusion_proof(&inner.leaves, seq as usize)
    }

    /// Persists an anchor receipt (append-only) and caches it in memory.
    /// Surfaced via `GET /v1/checkpoint`'s `anchored_to` field.
    pub fn record_anchor(&self, anchor: AnchorReceipt) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let anchors_path = self.data_dir.join("anchors.jsonl");
        let line = serde_json::to_string(&anchor).expect("AnchorReceipt serializes") + "\n";
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&anchors_path)
            .map_err(|e| StorageError::io("open anchors for append", e))?;
        file.write_all(line.as_bytes())
            .map_err(|e| StorageError::io("write anchor", e))?;
        file.sync_all()
            .map_err(|e| StorageError::io("fsync anchors", e))?;
        fsync_dir(&self.data_dir)?;
        inner.anchors.push(anchor);
        Ok(())
    }

    /// Returns the most-recent anchor receipt, if any.
    pub fn latest_anchor(&self) -> Option<AnchorReceipt> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.anchors.last().cloned()
    }

    /// Returns whether an authority-signed permanent revocation exists for the
    /// exact `(anchor_id, tenant_id)` pair.
    pub fn is_anchor_revoked(&self, anchor_id: &str, tenant_id: &str) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .anchor_revocations
            .contains_key(&(anchor_id.to_owned(), tenant_id.to_owned()))
    }

    /// Issues one fresh authority-signed verdict and durably records ONLY the
    /// bumped version counter (H2 — see the module doc "Issued verdicts are
    /// not individually persisted"). The version is allocated while holding
    /// the storage mutex and the counter marker is fsync'd before return, so
    /// concurrent requests cannot reuse or roll back an issued version, and a
    /// caller cannot turn an unauthenticated read into an unbounded, growing,
    /// fsync'd disk append.
    /// The revocation status is resolved HERE, under the same lock acquisition
    /// that allocates the version — never passed in by the caller.
    ///
    /// A caller that reads `is_anchor_revoked` first and passes the answer down
    /// releases the lock between the read and the signature. A revoke landing
    /// in that window produces a `Valid` verdict carrying a HIGHER version than
    /// the revocation, and consumers are told to prefer the greatest version —
    /// so monotonic versioning does not merely fail to help, it actively
    /// selects the wrong answer and serves a revoked anchor as valid.
    pub fn issue_anchor_verdict(
        &self,
        anchor: VerifiedAnchor,
        tenant_id: String,
        issued_at: chrono::DateTime<chrono::Utc>,
        key: &ServerSigningKey,
    ) -> Result<AnchorVerdict, StorageError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let status = if inner
            .anchor_revocations
            .contains_key(&(anchor.anchor_id.clone(), tenant_id.clone()))
        {
            AnchorVerdictStatus::Revoked
        } else {
            AnchorVerdictStatus::Valid
        };
        let version = inner
            .anchor_verdict_version
            .checked_add(1)
            .ok_or(StorageError::AuthorityVersionExhausted)?;
        let verdict = AnchorVerdict::sign(anchor, tenant_id, status, version, issued_at, key)
            .map_err(map_anchor_verdict_error)?;
        // Durable state is the bumped counter ONLY — no per-verdict JSONL line.
        // This write+fsync happens before the verdict is returned, preserving
        // fsync-before-ack: once a caller has the verdict, `version` can never
        // be reissued, even across a crash immediately after this line.
        write_and_fsync_marker(&self.data_dir, ANCHOR_VERDICT_VERSION_MARKER, version)?;
        inner.anchor_verdict_version = version;
        Ok(verdict)
    }

    /// Creates and durably records an authority-signed permanent revocation.
    /// The server route that calls this is served from the dedicated
    /// AUTHORITY listener (H3, defaults to loopback-only — spec 17 §17.3), not
    /// the read/write listener.
    ///
    /// Idempotent on an already-revoked `(anchor_id, tenant_id)` pair (`L3`):
    /// returns the EXISTING revocation unchanged rather than allocating a new
    /// authority version and appending a new line. Without this, N calls
    /// against the same pair would durably write N lines and burn N versions
    /// for a fact that was already true after the first call — cheap to
    /// trigger accidentally (a retried request, a double-click) since the
    /// operation has no other side effect to detect duplication by.
    pub fn revoke_anchor(
        &self,
        anchor_id: String,
        tenant_id: String,
        revoked_at: chrono::DateTime<chrono::Utc>,
        key: &ServerSigningKey,
    ) -> Result<AnchorRevocation, StorageError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = inner
            .anchor_revocations
            .get(&(anchor_id.clone(), tenant_id.clone()))
        {
            return Ok(existing.clone());
        }
        let version = inner
            .anchor_verdict_version
            .checked_add(1)
            .ok_or(StorageError::AuthorityVersionExhausted)?;
        let revocation = AnchorRevocation::sign(anchor_id, tenant_id, version, revoked_at, key)
            .map_err(map_anchor_verdict_error)?;
        append_authority_line(
            &self.data_dir,
            "anchor-revocations.jsonl",
            &revocation,
            "open anchor revocations for append",
            "write anchor revocation",
            "fsync anchor revocations",
        )?;
        inner.anchor_verdict_version = version;
        inner.anchor_revocations.insert(
            (revocation.anchor_id.clone(), revocation.tenant_id.clone()),
            revocation.clone(),
        );
        Ok(revocation)
    }

    /// Atomically consumes a verifier namespace's only bootstrap authority.
    ///
    /// The receipt is append-only and fsync'd before it is returned. A local
    /// consumer that loses its replay state therefore cannot create a fresh
    /// state by reusing the same verifier identity.
    pub fn redeem_verifier_bootstrap(
        &self,
        verifier_id: String,
        challenge: String,
        issued_at: chrono::DateTime<chrono::Utc>,
        key: &ServerSigningKey,
    ) -> Result<VerifierBootstrap, StorageError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.verifier_bootstrap_ids.contains(&verifier_id) {
            return Err(StorageError::VerifierBootstrapAlreadyRedeemed);
        }
        let version = inner
            .anchor_verdict_version
            .checked_add(1)
            .ok_or(StorageError::AuthorityVersionExhausted)?;
        let bootstrap = VerifierBootstrap::sign(verifier_id, challenge, version, issued_at, key)
            .map_err(map_anchor_verdict_error)?;
        append_authority_line(
            &self.data_dir,
            "verifier-bootstraps.jsonl",
            &bootstrap,
            "open verifier bootstraps for append",
            "write verifier bootstrap",
            "fsync verifier bootstraps",
        )?;
        inner.anchor_verdict_version = version;
        inner
            .verifier_bootstrap_ids
            .insert(bootstrap.verifier_id.clone());
        Ok(bootstrap)
    }

    /// Rewrites the `tree_size` marker to the current recovered count.
    /// Used only at startup recovery to reconcile a marker that lagged a crash.
    fn write_size_marker(&self) -> Result<(), StorageError> {
        let size = self.tree_size();
        write_and_fsync_marker(&self.data_dir, "tree_size", size)
    }

    /// Returns the data directory root (for the signing-key path, etc.).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

fn map_anchor_verdict_error(_: AnchorVerdictError) -> StorageError {
    StorageError::CorruptAuthorityAnchorState
}

/// Appends an authority artifact and fsyncs both file and directory before its
/// in-memory version is advanced. These records carry no private key material.
///
/// `L2`: serialization failure is propagated as `CorruptAuthorityAnchorState`
/// rather than `.expect()`-panicking. Every caller of this function runs on a
/// request path (revoke, verifier-bootstrap redemption) in a trust crate — an
/// `expect` reachable from there turns a hypothetical future serialization gap
/// (e.g. a non-finite float, or a type change that adds a non-`Serialize`
/// field) into a process crash on an authority write, rather than a 500.
fn append_authority_line<T: serde::Serialize>(
    data_dir: &Path,
    filename: &str,
    value: &T,
    open_context: &'static str,
    write_context: &'static str,
    sync_context: &'static str,
) -> Result<(), StorageError> {
    let path = data_dir.join(filename);
    let line =
        serde_json::to_string(value).map_err(|_| StorageError::CorruptAuthorityAnchorState)? + "\n";
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| StorageError::io(open_context, e))?;
    file.write_all(line.as_bytes())
        .map_err(|e| StorageError::io(write_context, e))?;
    file.sync_all()
        .map_err(|e| StorageError::io(sync_context, e))?;
    fsync_dir(data_dir)
}

/// Recovers a single-file, single-writer JSONL authority artifact
/// (`anchor-verdicts.jsonl` [legacy], `anchor-revocations.jsonl`,
/// `verifier-bootstraps.jsonl`), tolerating a torn trailing line the same way
/// the segment-recovery loop above tolerates one (deep-F1) — this is that
/// loop's logic minus the multi-segment "which file is last" bookkeeping,
/// since here there is only ever one file.
///
/// Every one of these files is written exclusively through
/// [`append_authority_line`], which is single-writer-serialized under the
/// storage [`Mutex`] and only returns `Ok` after the write, the file sync,
/// and the parent-directory sync all complete. So a line that fails to parse
/// and has NO later non-empty line after it in the file can only be the
/// in-flight write of a crash that happened before that call ever returned —
/// no caller was ever acked for it, so discarding it does not violate the
/// append-only invariant (which protects ACKED facts). A parse failure on
/// any line that is NOT the final non-empty line means a later, fsync'd line
/// survived a crash this one didn't — genuine mid-file corruption — and
/// stays fatal.
///
/// Returns the parsed rows in file order. Returns an empty `Vec` if `path`
/// does not exist. Callers apply their own per-row authority checks
/// (signature verification, version-reuse detection) — this helper only
/// owns the torn-tail-safe parse.
fn recover_authority_lines<T: serde::de::DeserializeOwned>(
    path: &Path,
    kind: &'static str,
) -> Result<Vec<T>, StorageError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| StorageError::io("read authority artifact", e))?;
    let mut out: Vec<T> = Vec::new();
    let mut byte_offset: u64 = 0;
    let mut last_good_end: u64 = 0;
    let raw_lines: Vec<&str> = content.split_inclusive('\n').collect();
    for (idx, raw_line) in raw_lines.iter().enumerate() {
        byte_offset += raw_line.len() as u64;
        let line = raw_line.trim_end_matches('\n');
        if line.trim().is_empty() {
            // Blank line: advance past it but keep last_good_end where it was
            // unless it is a truly-empty line (mirrors the segment loop).
            if line.is_empty() {
                last_good_end = byte_offset;
            }
            continue;
        }
        match serde_json::from_str::<T>(line) {
            Ok(value) => {
                out.push(value);
                last_good_end = byte_offset;
            }
            Err(_) => {
                let has_later_nonempty = raw_lines[idx + 1..].iter().any(|l| !l.trim().is_empty());
                if has_later_nonempty {
                    return Err(StorageError::CorruptAuthorityAnchorState);
                }
                // Torn never-acked trailing line: truncate to the last good
                // line, fsync, warn, and return what recovered cleanly.
                let f = OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(|e| StorageError::io("open authority artifact for truncate", e))?;
                f.set_len(last_good_end)
                    .map_err(|e| StorageError::io("truncate torn authority artifact", e))?;
                f.sync_all()
                    .map_err(|e| StorageError::io("fsync truncated authority artifact", e))?;
                drop(f);
                if let Some(parent) = path.parent() {
                    fsync_dir(parent)?;
                }
                let recovered_count = out.len();
                tracing::warn!(
                    kind,
                    recovered = recovered_count,
                    "recovered {recovered_count} {kind} records, discarded 1 torn never-acked trailing line",
                );
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// Returns the segment file path for segment index `i`.
fn segment_path(log_dir: &Path, i: u64) -> PathBuf {
    log_dir.join(format!("segment-{i:08}.jsonl"))
}

/// Writes the decimal `value` to `<data_dir>/<filename>` and fsyncs it. Used
/// for both the `tree_size` marker and the `anchor-verdict-version` counter
/// marker (H2) — both are small, single-integer, crash-safe counters with the
/// identical durability shape (write → fsync file → fsync directory).
fn write_and_fsync_marker(data_dir: &Path, filename: &str, value: u64) -> Result<(), StorageError> {
    let marker_path = data_dir.join(filename);
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&marker_path)
        .map_err(|e| StorageError::io("open marker", e))?;
    f.write_all(value.to_string().as_bytes())
        .map_err(|e| StorageError::io("write marker", e))?;
    f.sync_all()
        .map_err(|e| StorageError::io("fsync marker", e))?;
    fsync_dir(data_dir)?;
    Ok(())
}

/// fsyncs a directory so a rename / new-file link is durable. On Unix this
/// opens the directory and calls `sync_all`. On non-Unix it is a best-effort
/// no-op (Windows has no directory-fsync equivalent; file `sync_all` suffices).
fn fsync_dir(dir: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        let f = File::open(dir).map_err(|e| StorageError::io("open dir for fsync", e))?;
        f.sync_all().map_err(|e| StorageError::io("fsync dir", e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Best-effort 0o700 on a directory (Unix). Mirrors csq-core's `secure_dir`
/// without taking a csq-core dependency on its private `platform::fs`.
fn secure_dir_best_effort(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

// NOTE (PRIMARY DIRECTIVE 2): there is intentionally NO delete / truncate /
// compact / vacuum / wipe / prune / gc function on this surface. The single
// `truncate(true)` above is on the SIZE MARKER (a non-record, recomputable
// counter), NOT on any record-bearing segment — record segments are
// append-only (`OpenOptions::append(true)`), never truncated. Adding any
// record-removal operation would re-open the operator-side tamper path the
// write-once invariant exists to close.

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::audit::types::{
        CsqRunPayload, EatpActor, EatpAuthority, EatpTrust, Ed25519Signature, EventKind,
        EventPayload, KeyId, RecordId, Sha256Hex, SignedRecord,
    };
    use tempfile::TempDir;

    /// Test helper: opens a store pinned to a freshly generated (or, on a
    /// reopen of the same `dir`, the already-persisted) authority key. `M3`
    /// removed the unauthenticated `LedgerStore::open` — a locally planted,
    /// self-signed authority artifact could recover under its OWN embedded
    /// key id when no pin was supplied, so a planted revocation or verdict
    /// self-verified. Every test now opens through `open_with_authority`, the
    /// same path production uses.
    fn open_store(dir: &std::path::Path) -> Result<LedgerStore, StorageError> {
        let key = ServerSigningKey::load_or_generate(dir, None).unwrap();
        LedgerStore::open_with_authority(dir, key.key_id())
    }

    fn sample(seq: u64, id_suffix: &str) -> SignedRecord {
        let rid = format!("01JZ0000000000000000000{id_suffix:0>3}");
        let rid = rid[..26].to_string();
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(rid).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: format!("run-{seq}"),
            }),
            ts: "2026-05-29T00:00:00+00:00".to_string(),
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

    /// `test storage_append_assigns_monotonic_seq`
    #[test]
    fn storage_append_assigns_monotonic_seq() {
        let dir = TempDir::new().unwrap();
        let store = open_store(dir.path()).unwrap();
        let r0 = store.append(sample(0, "A0")).unwrap();
        let r1 = store.append(sample(1, "A1")).unwrap();
        assert_eq!(r0.log_index, 0);
        assert_eq!(r1.log_index, 1);
        assert_eq!(store.tree_size(), 2);
    }

    /// `test storage_recovers_records_after_reopen`
    ///
    /// fsync-before-ack property: records appended (and acked) survive a
    /// process restart (simulated by dropping + reopening the store).
    #[test]
    fn storage_recovers_records_after_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let store = open_store(dir.path()).unwrap();
            for i in 0..5 {
                store.append(sample(i, &format!("B{i}"))).unwrap();
            }
            assert_eq!(store.tree_size(), 5);
        }
        // Reopen — simulates restart after a clean (or unclean) shutdown.
        let store = open_store(dir.path()).unwrap();
        assert_eq!(store.tree_size(), 5, "all acked records recovered");
        for i in 0..5 {
            assert!(
                store.record_at(i).is_some(),
                "record {i} present after reopen"
            );
        }
    }

    /// `test storage_record_by_id_round_trips`
    #[test]
    fn storage_record_by_id_round_trips() {
        let dir = TempDir::new().unwrap();
        let store = open_store(dir.path()).unwrap();
        let rec = sample(0, "C0");
        let id = rec.record_id.as_str().to_string();
        store.append(rec.clone()).unwrap();
        let (seq, fetched) = store.record_by_id(&id).expect("found");
        assert_eq!(seq, 0);
        assert_eq!(fetched, rec);
    }

    /// `test storage_root_and_proof_consistent_with_merkle`
    #[test]
    fn storage_root_and_proof_consistent_with_merkle() {
        let dir = TempDir::new().unwrap();
        let store = open_store(dir.path()).unwrap();
        for i in 0..7 {
            store.append(sample(i, &format!("D{i}"))).unwrap();
        }
        let root = store.root_hash();
        let leaves = store.leaf_hashes();
        for seq in 0..7u64 {
            let proof = store.inclusion_proof(seq).unwrap();
            assert!(
                merkle::verify_inclusion(&leaves[seq as usize], seq as usize, 7, &proof, &root),
                "stored inclusion proof verifies for seq {seq}"
            );
        }
    }

    /// `test storage_anchor_round_trips_after_reopen`
    #[test]
    fn storage_anchor_round_trips_after_reopen() {
        let dir = TempDir::new().unwrap();
        let anchor = AnchorReceipt {
            sink: "rekor".to_string(),
            anchor_id: "rekor-log-7".to_string(),
            tree_size: 3,
            root_hash: "ab".repeat(32),
            anchored_at: "2026-05-29T00:00:00+00:00".to_string(),
            unverified: false,
        };
        {
            let store = open_store(dir.path()).unwrap();
            store.append(sample(0, "E0")).unwrap();
            store.record_anchor(anchor.clone()).unwrap();
        }
        let store = open_store(dir.path()).unwrap();
        assert_eq!(store.latest_anchor(), Some(anchor));
    }

    /// `test authority_anchor_state_survives_restart_without_version_rollback`
    ///
    /// Authority-issued verdicts and revocations are security state, not an
    /// optional cache. Reopening with the active authority key must retain a
    /// revocation and allocate the next strictly-greater version.
    #[test]
    fn authority_anchor_state_survives_restart_without_version_rollback() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let (record_id, anchor) = {
            let store = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
            let record = sample(0, "J0");
            let record_id = record.record_id.as_str().to_owned();
            store.append(record).unwrap();
            let anchor = VerifiedAnchor {
                anchor_id: record_id.to_owned(),
                leaf_hash: hex::encode(store.leaf_hashes()[0]),
                log_index: 0,
                checkpoint_tree_size: store.tree_size(),
                checkpoint_root_hash: hex::encode(store.root_hash()),
            };
            let issued = store
                .issue_anchor_verdict(
                    anchor.clone(),
                    "tenant-a".to_owned(),
                    chrono::Utc::now(),
                    &key,
                )
                .unwrap();
            assert_eq!(issued.version, 1);
            assert_eq!(
                issued.status,
                AnchorVerdictStatus::Valid,
                "no revocation recorded yet, so the store must derive Valid"
            );
            let revocation = store
                .revoke_anchor(
                    record_id.clone(),
                    "tenant-a".to_owned(),
                    chrono::Utc::now(),
                    &key,
                )
                .unwrap();
            assert_eq!(revocation.version, 2);
            (record_id, anchor)
        };

        let reopened = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
        assert!(reopened.is_anchor_revoked(&record_id, "tenant-a"));
        let issued = reopened
            .issue_anchor_verdict(anchor, "tenant-a".to_owned(), chrono::Utc::now(), &key)
            .unwrap();
        assert_eq!(
            issued.version, 3,
            "restart must not reset authority version"
        );
        // The status is DERIVED under the version lock, not passed in — so this
        // also proves recovery restored the revocation into the derivation
        // path, which the old caller-supplied-status form could never show.
        assert_eq!(
            issued.status,
            AnchorVerdictStatus::Revoked,
            "a recovered revocation must make the next verdict Revoked"
        );
    }

    /// `test revoke_anchor_is_idempotent_and_does_not_burn_versions`
    ///
    /// L3: revoking the same `(anchor_id, tenant_id)` pair twice returns the
    /// IDENTICAL revocation (byte-for-byte, including signature) and does not
    /// allocate a second authority version — a naive re-revoke would burn a
    /// version and write a second durable line per replay.
    #[test]
    fn revoke_anchor_is_idempotent_and_does_not_burn_versions() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let store = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
        store.append(sample(0, "R30")).unwrap();

        let first = store
            .revoke_anchor(
                "01JZ0000000000000000000R30".to_owned(),
                "tenant-l3".to_owned(),
                chrono::Utc::now(),
                &key,
            )
            .unwrap();
        assert_eq!(first.version, 1);

        let second = store
            .revoke_anchor(
                "01JZ0000000000000000000R30".to_owned(),
                "tenant-l3".to_owned(),
                chrono::Utc::now(),
                &key,
            )
            .unwrap();
        assert_eq!(
            second, first,
            "a replayed revoke must return the identical existing fact"
        );
        assert_eq!(
            second.version, 1,
            "a replayed revoke must not burn a version"
        );

        // A DIFFERENT tenant for the SAME anchor is a distinct pair and still
        // allocates a fresh version — idempotency is per-pair, not per-anchor.
        let other_tenant = store
            .revoke_anchor(
                "01JZ0000000000000000000R30".to_owned(),
                "tenant-l3-other".to_owned(),
                chrono::Utc::now(),
                &key,
            )
            .unwrap();
        assert_eq!(other_tenant.version, 2);
    }

    /// `test issue_anchor_verdict_bumps_marker_not_a_growing_log`
    ///
    /// H2: issuing many verdicts never creates the legacy per-verdict JSONL
    /// file, and the version counter survives a restart via the durable
    /// marker alone (no revocation or bootstrap entry exists to recover it
    /// from — the marker is the ONLY durable trace).
    #[test]
    fn issue_anchor_verdict_bumps_marker_not_a_growing_log() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let record_id = "01JZ0000000000000000000H20".to_owned();
        let anchor = {
            let store = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
            store.append(sample(0, "H20")).unwrap();
            let anchor = VerifiedAnchor {
                anchor_id: record_id.clone(),
                leaf_hash: hex::encode(store.leaf_hashes()[0]),
                log_index: 0,
                checkpoint_tree_size: store.tree_size(),
                checkpoint_root_hash: hex::encode(store.root_hash()),
            };
            for _ in 0..10 {
                store
                    .issue_anchor_verdict(
                        anchor.clone(),
                        "tenant-h2".to_owned(),
                        chrono::Utc::now(),
                        &key,
                    )
                    .unwrap();
            }
            assert!(
                !dir.path().join("anchor-verdicts.jsonl").exists(),
                "H2: a fresh deployment must never create the legacy per-verdict log"
            );
            let marker = std::fs::read_to_string(dir.path().join(ANCHOR_VERDICT_VERSION_MARKER))
                .expect("counter marker must exist after issuing verdicts");
            assert_eq!(marker.trim(), "10", "marker holds the exact issued count");
            anchor
        };

        // Restart: the version must resume from 11, recovered ONLY from the
        // marker (no revocation/bootstrap log entry exists in this test).
        let reopened = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
        let issued = reopened
            .issue_anchor_verdict(anchor, "tenant-h2".to_owned(), chrono::Utc::now(), &key)
            .unwrap();
        assert_eq!(
            issued.version, 11,
            "restart must resume the counter from the durable marker alone"
        );
    }

    /// `test verifier_bootstrap_survives_restart_without_reset`
    ///
    /// A verifier bootstrap is an authority fact, not a cache. A local consumer
    /// must not regain bootstrap authority merely because it lost its own state.
    #[test]
    fn verifier_bootstrap_survives_restart_without_reset() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let verifier_id = "praxis.production.verdict-state".to_owned();
        {
            let store = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
            let receipt = store
                .redeem_verifier_bootstrap(
                    verifier_id.clone(),
                    "a".repeat(64),
                    chrono::Utc::now(),
                    &key,
                )
                .unwrap();
            assert_eq!(receipt.version, 1);
        }

        let reopened = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
        assert!(matches!(
            reopened.redeem_verifier_bootstrap(
                verifier_id,
                "b".repeat(64),
                chrono::Utc::now(),
                &key,
            ),
            Err(StorageError::VerifierBootstrapAlreadyRedeemed)
        ));
    }

    /// `test storage_segment_file_is_append_only_on_disk`
    ///
    /// Two appends produce a 2-line segment; the first line is byte-identical
    /// before and after the second append (no overwrite of prior records).
    #[test]
    fn storage_segment_file_is_append_only_on_disk() {
        let dir = TempDir::new().unwrap();
        let store = open_store(dir.path()).unwrap();
        store.append(sample(0, "F0")).unwrap();
        let seg = dir.path().join("log").join("segment-00000000.jsonl");
        let after_first = std::fs::read_to_string(&seg).unwrap();
        let first_line = after_first.lines().next().unwrap().to_string();
        store.append(sample(1, "F1")).unwrap();
        let after_second = std::fs::read_to_string(&seg).unwrap();
        assert_eq!(
            after_second.lines().next().unwrap(),
            first_line,
            "first record line must be unchanged after second append"
        );
        assert_eq!(after_second.lines().count(), 2);
    }

    /// `test storage_detects_corrupt_segment_record`
    ///
    /// MID-FILE corruption (a bad line that is NOT the last non-empty line of
    /// the last segment) is genuine tamper → fatal `CorruptRecord`. Here a valid
    /// record line FOLLOWS the corrupt one, so the corrupt line cannot be a
    /// never-acked torn tail (a later line was fsync'd after it). This is the
    /// regression guard for deep-F1's "mid-file stays fatal" boundary.
    #[test]
    fn storage_detects_corrupt_segment_record() {
        let dir = TempDir::new().unwrap();
        let good_line = {
            let store = open_store(dir.path()).unwrap();
            store.append(sample(0, "G0")).unwrap();
            let seg = dir.path().join("log").join("segment-00000000.jsonl");
            std::fs::read_to_string(&seg).unwrap().trim().to_string()
        };
        // Write a corrupt line FOLLOWED by a valid record line: the corrupt line
        // is now mid-file (a good line follows it), so it must be fatal.
        let seg = dir.path().join("log").join("segment-00000000.jsonl");
        std::fs::write(&seg, format!("{{not valid json}}\n{good_line}\n")).unwrap();
        let result = open_store(dir.path());
        assert!(
            matches!(result, Err(StorageError::CorruptRecord { seq: 0 })),
            "mid-file corruption (bad line with a valid line after) must be fatal"
        );
    }

    /// `test storage_tolerates_torn_trailing_line`
    ///
    /// deep-F1: a partial non-JSON tail with no newline appended to the active
    /// segment (simulating a crash mid-append, before the record was acked) is
    /// truncated on recovery — `LedgerStore::open_with_authority` succeeds with `tree_size == N`
    /// and the torn line dropped. The torn line was never 200'd, so no client
    /// holds an inclusion proof for it; dropping it does not violate the
    /// append-only invariant (which protects ACKED records).
    #[test]
    fn storage_tolerates_torn_trailing_line() {
        let dir = TempDir::new().unwrap();
        {
            let store = open_store(dir.path()).unwrap();
            for i in 0..5 {
                store.append(sample(i, &format!("H{i}"))).unwrap();
            }
            assert_eq!(store.tree_size(), 5);
        }
        // Append a partial non-JSON tail with NO trailing newline, exactly as a
        // crash mid-write would leave it.
        let seg = dir.path().join("log").join("segment-00000000.jsonl");
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(b"{\"schema_version\":\"2\",\"record_id\":\"01JZ")
                .unwrap();
        }
        // Recovery tolerates the torn tail: 5 records recovered, tail dropped.
        let store = open_store(dir.path()).expect("open tolerates torn tail");
        assert_eq!(store.tree_size(), 5, "all 5 acked records recovered");
        for i in 0..5u64 {
            assert!(store.record_at(i).is_some(), "record {i} present");
        }
        // The torn bytes were truncated off the segment on disk.
        let content = std::fs::read_to_string(&seg).unwrap();
        assert_eq!(
            content.lines().filter(|l| !l.trim().is_empty()).count(),
            5,
            "segment truncated to the 5 good lines"
        );
        // Re-opening again is a clean no-op (idempotent recovery).
        let store2 = open_store(dir.path()).expect("reopen clean");
        assert_eq!(store2.tree_size(), 5);
    }

    /// Shared harness for the M1 tests below (`recover_authority_lines`):
    /// seeds `filename` with exactly one durable, authority-signed line via
    /// `seed`, appends a torn (never-acked) trailing line and confirms
    /// recovery tolerates it — `check_after` asserts the one acked fact
    /// survived — then overwrites the file with a bad line FOLLOWED BY a
    /// good line (genuine mid-file corruption) and confirms recovery still
    /// refuses to start.
    fn torn_tail_tolerated_mid_file_fatal(
        filename: &str,
        seed: impl FnOnce(&LedgerStore, &ServerSigningKey, &std::path::Path),
        check_after: impl Fn(&LedgerStore, &ServerSigningKey),
    ) {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let path = dir.path().join(filename);
        {
            let store = LedgerStore::open_with_authority(dir.path(), key.key_id()).unwrap();
            seed(&store, &key, dir.path());
        }
        assert!(path.exists(), "{filename} must exist after the seed write");

        // --- torn tail: an in-flight write that crashed before it was acked ---
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"schema\":\"torn-in-flight-write-no-newline")
                .unwrap();
        }
        let reopened = LedgerStore::open_with_authority(dir.path(), key.key_id())
            .unwrap_or_else(|e| panic!("torn trailing line in {filename} must not be fatal: {e}"));
        check_after(&reopened, &key);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            content.lines().filter(|l| !l.trim().is_empty()).count(),
            1,
            "{filename} truncated to the 1 good line"
        );

        // --- mid-file corruption: a bad line with a good line after it ---
        let good_line = content.lines().next().unwrap().to_string();
        std::fs::write(&path, format!("{{not valid json}}\n{good_line}\n")).unwrap();
        let result = LedgerStore::open_with_authority(dir.path(), key.key_id());
        assert!(
            matches!(result, Err(StorageError::CorruptAuthorityAnchorState)),
            "mid-file corruption in {filename} must stay fatal"
        );
    }

    /// `test anchor_revocations_recovery_torn_tail_vs_mid_file` (M1)
    ///
    /// `anchor-revocations.jsonl` is written only via `append_authority_line`
    /// under the storage mutex, fsync'd before `revoke_anchor` returns — the
    /// same single-writer durability shape as the record-segment log. A torn
    /// trailing line can only be an in-flight write nobody was ever acked
    /// for, so recovery tolerates it; a bad line with a good line after it
    /// is genuine tamper and stays fatal.
    #[test]
    fn anchor_revocations_recovery_torn_tail_vs_mid_file() {
        torn_tail_tolerated_mid_file_fatal(
            "anchor-revocations.jsonl",
            |store, key, _dir| {
                store.append(sample(0, "TT1")).unwrap();
                store
                    .revoke_anchor(
                        "01JZ0000000000000000000TT1".to_owned(),
                        "tenant-torn".to_owned(),
                        chrono::Utc::now(),
                        key,
                    )
                    .unwrap();
            },
            |store, _key| {
                assert!(
                    store.is_anchor_revoked("01JZ0000000000000000000TT1", "tenant-torn"),
                    "the one acked revocation must survive recovery"
                );
            },
        );
    }

    /// `test verifier_bootstraps_recovery_torn_tail_vs_mid_file` (M1)
    ///
    /// Same durability shape as revocations (`append_authority_line`, same
    /// mutex, same fsync-before-return). A torn trailing bootstrap line is a
    /// never-acked in-flight write; a bad line with a good line after it is
    /// tamper.
    #[test]
    fn verifier_bootstraps_recovery_torn_tail_vs_mid_file() {
        torn_tail_tolerated_mid_file_fatal(
            "verifier-bootstraps.jsonl",
            |store, key, _dir| {
                store
                    .redeem_verifier_bootstrap(
                        "torn-verifier".to_owned(),
                        "a".repeat(64),
                        chrono::Utc::now(),
                        key,
                    )
                    .unwrap();
            },
            |store, key| {
                assert!(
                    matches!(
                        store.redeem_verifier_bootstrap(
                            "torn-verifier".to_owned(),
                            "b".repeat(64),
                            chrono::Utc::now(),
                            key,
                        ),
                        Err(StorageError::VerifierBootstrapAlreadyRedeemed)
                    ),
                    "the one acked bootstrap must survive recovery and stay redeemed"
                );
            },
        );
    }

    /// `test legacy_anchor_verdicts_recovery_torn_tail_vs_mid_file` (M1)
    ///
    /// `anchor-verdicts.jsonl` is the pre-H2 legacy artifact — nothing in the
    /// store API appends to it anymore, so it is seeded directly the way a
    /// pre-H2 deployment's crash would have left it. A torn trailing verdict
    /// line must not roll the recovered authority-version counter backward
    /// on restart; a bad line with a good line after it is tamper.
    #[test]
    fn legacy_anchor_verdicts_recovery_torn_tail_vs_mid_file() {
        torn_tail_tolerated_mid_file_fatal(
            "anchor-verdicts.jsonl",
            |store, key, dir| {
                store.append(sample(0, "TT2")).unwrap();
                let anchor = VerifiedAnchor {
                    anchor_id: "01JZ0000000000000000000TT2".to_owned(),
                    leaf_hash: hex::encode(store.leaf_hashes()[0]),
                    log_index: 0,
                    checkpoint_tree_size: store.tree_size(),
                    checkpoint_root_hash: hex::encode(store.root_hash()),
                };
                let verdict = AnchorVerdict::sign(
                    anchor,
                    "tenant-torn".to_owned(),
                    AnchorVerdictStatus::Valid,
                    1,
                    chrono::Utc::now(),
                    key,
                )
                .unwrap();
                let line = serde_json::to_string(&verdict).unwrap() + "\n";
                std::fs::write(dir.join("anchor-verdicts.jsonl"), line).unwrap();
            },
            |store, key| {
                // anchor-verdicts.jsonl folds only into the durable version
                // counter (H2); the next issued verdict proves the recovered
                // legacy line's version (1) was honored, not rolled back.
                let anchor = VerifiedAnchor {
                    anchor_id: "01JZ0000000000000000000TT2".to_owned(),
                    leaf_hash: hex::encode(store.leaf_hashes()[0]),
                    log_index: 0,
                    checkpoint_tree_size: store.tree_size(),
                    checkpoint_root_hash: hex::encode(store.root_hash()),
                };
                let issued = store
                    .issue_anchor_verdict(anchor, "tenant-torn".to_owned(), chrono::Utc::now(), key)
                    .unwrap();
                assert!(
                    issued.version > 1,
                    "recovered legacy verdict version must not roll back"
                );
            },
        );
    }

    /// `test canonical_leaf_bytes_handles_non_null_eatp_fields`
    ///
    /// rust-R3: pins the `.expect("SignedRecord always serializes")` infallibility
    /// claim. A record carrying non-null actor/authority/trust (each a
    /// `serde_json::Value` object) must serialize without panic, and the output
    /// must be deterministic across calls (serde_json key-sorts the nested
    /// object fields, so the canonical form is stable).
    #[test]
    fn canonical_leaf_bytes_handles_non_null_eatp_fields() {
        let mut rec = sample(0, "R3");
        // Build object Values with keys in NON-sorted order to exercise the
        // key-sorting path that produces the canonical form.
        rec.actor = Some(EatpActor(serde_json::json!({
            "role": "operator", "id": "actor-7", "agent": "csq"
        })));
        rec.authority = Some(EatpAuthority(serde_json::json!({
            "scope": "full", "envelope": "prod", "delegated_by": "root"
        })));
        rec.trust = Some(EatpTrust(serde_json::json!({
            "verified": true, "gradient": 3, "basis": "attestation"
        })));
        rec.eatp_start_ts = Some("2026-05-29T00:00:00+00:00".to_string());
        rec.eatp_end_ts = Some("2026-05-29T00:01:00+00:00".to_string());

        // Must not panic.
        let bytes_a = canonical_leaf_bytes(&rec);
        let bytes_b = canonical_leaf_bytes(&rec);
        assert!(!bytes_a.is_empty());
        assert_eq!(bytes_a, bytes_b, "canonical serialization is deterministic");

        // And the record round-trips through the store + recovery without panic.
        let dir = TempDir::new().unwrap();
        let store = open_store(dir.path()).unwrap();
        store.append(rec.clone()).unwrap();
        let reopened = open_store(dir.path()).unwrap();
        assert_eq!(reopened.tree_size(), 1);
        assert_eq!(reopened.record_at(0).unwrap(), rec);
    }
}
