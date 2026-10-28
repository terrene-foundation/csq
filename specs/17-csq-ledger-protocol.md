# Spec 17 — csq-ledger Transparency-Log Protocol

**Spec version:** 2
**Status:** Active

---

## §17.1 Scope

This spec governs the `csq-ledger` server: its HTTP/JSON routes and
request/response shapes, the checkpoint (signed tree head) contract, the RFC
6962 inclusion-proof format, the fsync-before-200 durability invariant, the
storage-no-delete invariant, the `--anchor-to-sink` configuration + cadence,
the write-once-storage recommendation + threat model, Docker deployment env
vars, and operator-monitoring guidance.

`csq-ledger` is a Foundation-owned, self-hostable transparency-log server. It
gives csq operators a Foundation-blessed external-anchoring target with no
Sigstore/AWS/Azure/GCP upstream dependency in the recommended path. It lives in
the `csq-ledger/` workspace crate (a distinct binary crate, NOT part of
`csq-core`).

Operator guide: `docs/audit-sinks/csq-ledger.md`.

---

## §17.2 Architecture invariants

These six invariants are load-bearing. Each has an audit primitive that
enforces it mechanically.

### §17.2.1 Storage is local-file, not a database

Storage is hand-rolled append-only segment files. A database backend
(Postgres / SQLite / RocksDB / `sled`) is BLOCKED. An append-only log is
exactly the workload file-backed storage handles best; pulling a database into
the dep tree widens the operator-deployment burden for no functional gain.
`sled` was considered as a default; it is NOT used because it adds ~15
transitive crates for a write-once workload that segment files handle natively.

```bash
grep -E '^(postgres|sqlx|diesel|rocksdb|rusqlite|tokio-postgres|sled)' csq-ledger/Cargo.toml
# Expected: 0 matches
```

### §17.2.2 Storage NEVER deletes or overwrites

The storage layer (`csq-ledger/src/storage/`) exposes NO delete, truncate,
compact, vacuum, wipe, prune, or gc operation. Once `POST /v1/log/entries` has
200'd a record, the bytes that produced its inclusion proof are append-only
forever from csq-ledger's perspective. (The lone `truncate(true)` in storage is
on the recomputable `tree_size` size marker, not on any record-bearing segment;
segments are opened append-only and never truncated.)

```bash
grep -rEn 'fn (delete|truncate|compact|vacuum|wipe|prune|gc)\b' \
  csq-ledger/src/storage/ --include='*.rs' | grep -v test
# Expected: 0 matches
```

### §17.2.3 anchor-to-sink reuses the LedgerSink trait

`--anchor-to-sink` defines NO new sink abstraction. It consumes
`csq_core::audit::traits::LedgerSink` (spec 15) and the reference-impl catalog.
The same `RekorSink` / `S3ObjectLockSink` / etc. power both operator-side csq
audit anchoring and csq-ledger-side checkpoint anchoring.

```bash
grep -rEn 'trait\s+\w*Sink\b' csq-ledger/src/ --include='*.rs'
# Expected: 0 matches (no new sink trait defined in csq-ledger)
```

### §17.2.4 No cross-witness gossip (future work)

This release ships a single-instance log + anchor-to-sink. Witness signatures,
gossip protocols, multi-witness checkpoint co-signing, and RFC 6962 cross-log
audits are future work (see §17.9).

### §17.2.5 axum, not tonic

The HTTP server uses `axum` (HTTP/JSON). `tonic` (gRPC) is BLOCKED for this
release. For the submit + query + checkpoint API, HTTP/JSON via `axum` is the
minimum-dep, maximum-ops-familiarity choice. gRPC is justified only when
cross-witness gossip lands.

```bash
grep -E '^tonic' csq-ledger/Cargo.toml
# Expected: 0 matches
```

### §17.2.6 fsync before 200

`POST /v1/log/entries` MUST fsync the new record's storage write to disk BEFORE
returning HTTP 200. The durability sequence in `LedgerStore::append`:

1. Append the JSON line to the current segment file.
2. `File::sync_all()` — fsync the segment (data + metadata).
3. fsync the segment's parent directory.
4. Write + fsync the `tree_size` size marker.
5. Return.

The submit handler awaits `append` before building the 200. There is NO
skip-fsync flag.

```bash
grep -n 'fsync\|sync_all\|sync_data' csq-ledger/src/server/submit.rs
# Expected: at least 1 match documenting the durability contract on the path
# between record write and HTTP 200. The actual sync_all lives in
# storage::LedgerStore::append, awaited by the handler before 200.
```

---

## §17.3 HTTP routes

No authentication in this release (operator fronts with a reverse proxy / VPN /
mTLS termination). All bodies are JSON.

### §17.3.1 POST /v1/log/entries

Submit a `SignedRecord`. The body is the `SignedRecord` JSON (validated by its
own `Deserialize`: ULID/UUIDv7 `record_id`, lowercase-hex fields,
kind/payload consistency, `deny_unknown_fields`). A malformed body is rejected
with 400 by the JSON extractor before durability is touched.

Returns (after fsync):

```json
{
  "inclusion_proof": ["<hex sibling hash>", ...],
  "log_index": <u64>,
  "checkpoint_at_submit": { ...Checkpoint... }
}
```

Submitting an already-logged `record_id` is idempotent: it returns the existing
record's proof + the current checkpoint without appending a second leaf.

On a durability failure (fsync error, disk full) the server returns HTTP 500
with `{"error":"durability_failure", ...}` and NO inclusion proof — the client
MUST NOT treat the record as logged.

### §17.3.2 GET /v1/log/entries/{id}

Retrieve a record by `record_id`. The id is a map key, never a filesystem path
(no traversal). Returns:

```json
{
  "record": { ...SignedRecord... },
  "log_index": <u64>,
  "inclusion_proof": ["<hex sibling hash>", ...],
  "checkpoint": { ...Checkpoint... }
}
```

The proof verifies against the CURRENT tree head (`checkpoint`). Unknown id →
404 `{"error":"not_found"}`.

### §17.3.3 GET /v1/checkpoint

The current signed tree head:

```json
{
  "tree_size": <u64>,
  "root_hash": "<64-hex>",
  "signed_by_key_id": "ed25519:<64-hex>",
  "public_key": "<64-hex 32-byte server public key>",
  "signature": "<128-hex 64-byte Ed25519 signature>",
  "anchored_to": {                 // present iff --anchor-to-sink configured
    "sink": "rekor",               // AND at least one anchor acknowledged
    "anchor_id": "rekor-log-7",
    "anchored_at": "<RFC 3339>",
    "unverified": false            // true = witnessed ON TRUST (sink returned
  }                                // no proof); false = sink returned a proof
}
```

The `anchored_to.unverified` flag lets a verifier distinguish a checkpoint
witnessed WITH an inclusion proof (`false`, e.g. Rekor) from one witnessed ON
TRUST (`true`, e.g. a WORM object store that only acks storage). The label is on
proof PRESENCE; cryptographic verification that the returned proof commits to
this checkpoint's record_id/root is sink-dependent and future work. The flag
defaults to `true` (fail-safe) when a stored receipt predates the field.

### §17.3.4 GET /v1/health

```json
{
  "status": "ok",
  "tree_size": <u64>,
  "signing_key_warning": "auto-generated signing key ..."  // present until
                                                            // CSQ_LEDGER_SIGNING_KEY_PATH is set
}
```

---

## §17.4 Storage layout

```text
<data_dir>/
  log/
    segment-00000000.jsonl   ← records 0..10000 (one JSON object per line)
    segment-00000001.jsonl   ← records 10000..20000
    ...
  tree_size                  ← ASCII decimal head-size marker (fsync'd last)
  anchors.jsonl              ← anchor receipts (append-only)
  signing-key.pem            ← server signing key (§17.6)
```

Records roll to a new segment every 10,000 records. Recovery at startup reads
every segment line in order, rebuilds the leaf-hash vector + the `record_id →
seq` index, and cross-checks the count against the `tree_size` marker. A marker
AHEAD of the recovered count is a corruption signal (`SizeMarkerMismatch`); a
marker BEHIND is tolerated and rewritten (a crash between segment-fsync and
marker-write — the record is durably in the segment, so the recovered count
wins).

A segment line that fails to parse as `SignedRecord` is normally a corruption
signal (`CorruptRecord`, fatal) — with ONE exception: the FINAL non-empty line
of the FINAL (highest-index) segment, when every prior line parsed cleanly. That
line is the only one that can ever be torn, because append is serialized under a
single-writer Mutex held across write → fsync-segment → fsync-dir → fsync-marker
→ return, and the server emits HTTP 200 only after `append` returns Ok. So a
torn final line belongs to an in-flight append that crashed before returning —
it was NEVER acked, no client holds its inclusion proof. Recovery truncates that
torn never-acked tail to the end of the last good line, emits a WARN
(`recovered N records, discarded 1 torn never-acked trailing line`), and
continues startup. This does NOT violate the append-only invariant (§17.2.2),
which protects ACKED records. A parse failure on any line that is NOT the last
line of the last segment (e.g. a valid line follows it) remains fatal
`CorruptRecord` — genuine out-of-band tamper.

---

## §17.5 RFC 6962 Merkle inclusion + consistency proofs

Inclusion proofs are RFC 6962-compatible Merkle audit paths, computed NATIVELY
on `sha2::Sha256` — there is no external transparency-log library dependency.
The construction (RFC 6962 §2.1):

- **Leaf hash:** `SHA-256(0x00 || leaf_bytes)` where `leaf_bytes` is the
  deterministic `serde_json` serialization of the full `SignedRecord` (signature
  included — an inclusion proof commits to the record's signature too). The
  pre-image is the CANONICAL RE-SERIALIZATION of the record, NOT the exact wire
  bytes the submitter sent: the submit handler deserializes the body
  into the typed `SignedRecord` and re-serializes it, and serde_json key-sorts
  nested `Value` object fields during that round-trip. This is sound because the
  SAME serializer produces both the leaf-hash pre-image and the bytes persisted
  to the segment (so the proof and the stored record commit to identical bytes),
  and because csq's record signature is over `canonical_hash` (a content-derived
  digest, the unified signing contract) — NOT over wire bytes — so key reordering
  does not invalidate the record signature.
- **Interior hash:** `SHA-256(0x01 || left || right)`.
- **Empty tree:** `SHA-256()` (hash of the empty string).
- **Split point:** for `n > 1`, `k` = largest power of two strictly less than
  `n`; `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`.

The `0x00`/`0x01` domain separation (RFC 6962 §2.1) defeats second-preimage
attacks (presenting an interior node as a leaf).

Implemented in `csq-ledger/src/merkle.rs`:

- `hash_leaf`, `hash_children`, `empty_root`, `merkle_root`.
- `inclusion_proof(leaves, m)` / `verify_inclusion(...)` — RFC 6962 §2.1.1
  audit path.
- `consistency_proof(leaves, m, n)` / `verify_consistency(...)` — RFC 6962
  §2.1.2 (proves the size-`m` tree is a prefix of the size-`n` tree:
  append-only consistency).

Today, `consistency_proof` / `verify_consistency` are a LIBRARY primitive only
— there is NO HTTP route that serves a consistency proof yet (a
`GET /v1/consistency?from=m&to=n` route is future work, see §17.9). The
primitive is shipped + test-vector-verified now so the future route is a thin
wrapper, not a new implementation.

The implementation is verified against the canonical RFC 6962 / Certificate
Transparency test vectors (empty-tree root, one-leaf root, the 8-leaf root, and
known path lengths), reproduced inline in the `merkle.rs` test module.

---

## §17.6 Checkpoint signing key

The server signs every checkpoint with its OWN Ed25519 key, distinct from the
csq CLIENT keys that sign individual audit records. The `KeyId` derivation
matches csq-core: `ed25519:<lowercase-hex-sha256(raw_32_byte_pubkey)>`.

### §17.6.1 Signature pre-image (deterministic)

```text
preimage := "csq-ledger-checkpoint/v1\n"
          || "tree_size=" || decimal(tree_size) || "\n"
          || "root_hash="  || hex(root_hash)    || "\n"
signature := Ed25519_sign(server_key, preimage_bytes)
```

The domain-separation prefix prevents a checkpoint signature from being
replayed as a record signature. The `anchored_to` field is NOT part of the
pre-image (it is metadata added after signing; a verifier checks the anchor
against the external sink independently).

### §17.6.2 First-boot key UX

When `CSQ_LEDGER_SIGNING_KEY_PATH` is unset, the server: (1) generates a random
Ed25519 keypair, (2) writes the private key to `<data_dir>/signing-key.pem` at
mode `0o600` (created with `0o600` from the start on Unix; partial-write
cleanup on any failure per the security spec §5a), and (3) logs a prominent WARN
to stderr AND surfaces it via `GET /v1/health` on every boot until
`CSQ_LEDGER_SIGNING_KEY_PATH` is explicitly set. Explicitly setting the env var
(even to the auto-generated file) is the operator's acknowledgement and clears
the WARN.

The key file is a self-contained PEM-style envelope wrapping the hex-encoded
32-byte seed (the `ed25519-dalek` `pem`/`pkcs8` feature is deliberately NOT
enabled, to avoid the pkcs8/der dep chain).

---

## §17.7 anchor-to-sink (Strengthening 1)

`csq-ledger --anchor-to-sink <name> --anchor-cadence <secs>` periodically
submits the signed checkpoint to a named sink (spec 15). Default cadence 86400
(1/day). The checkpoint is encoded as a `SignedRecord` of kind `ReleaseAuth`
(`release_tag = "csq-ledger-checkpoint-<tree_size>"`, `artifact_sha256 =
root_hash`, deterministic ULID-shaped `record_id` derived from the root) and
submitted via `LedgerSink::append`. The receipt is stored in `anchors.jsonl`
and surfaced via `GET /v1/checkpoint`'s `anchored_to` field.

Sink resolution (`anchor::resolve_sink`) maps the name to a reference impl behind
a per-sink feature flag (`anchor-rekor`, `anchor-s3`, `anchor-azure`,
`anchor-gcp`, each enabling the matching `csq-core/<name>-sink`). A name whose
feature was not compiled in fails loud (`SinkNotCompiledIn`), never a silent
no-op. csq-ledger ships with no default anchor target (no Sigstore-upstream
coupling).

---

## §17.8 Threat model + WORM storage (Strengthening 2)

The authoritative threat model is in `docs/audit-sinks/csq-ledger.md` §"Threat
model". Summary of the four defense layers:

| Layer | Adds defense against                           | Residual gap                           |
| ----- | ---------------------------------------------- | -------------------------------------- |
| 1     | External attackers (tamper-evidence)           | The operator who runs the server       |
| 2     | Operator-side storage deletion/rewrite (WORM)  | Operator full-log rewrite (no witness) |
| 3     | Operator-side full-log rewrite (anchor)        | Operator + sink-operator collusion     |
| 4     | Operator + single-sink collusion (future work) | Majority-of-witnesses compromise       |

A single-instance log is tamper-EVIDENT and tamper-RESISTANT to external
attackers, but cannot be tamper-PROOF against the operator who runs it (they
control binary + storage + clock + signing key). csq-ledger + WORM storage +
anchor-to-sink yields "tamper requires the operator to simultaneously rewrite
the WORM-locked storage AND rewrite the external sink's record" — compliance-
grade for SOC 2 / ISO 27001 / NIST SP 800-53 AU-9(3). WORM options: AWS S3
Object Lock (compliance mode), Azure Immutable Blob, GCP Bucket Lock +
retention, Linux `chattr +a`.

---

## §17.9 Out of scope (future work)

- **Cross-witness gossip** — ≥2 independent witnesses co-signing checkpoints
  (collusion resistance). Needs a witness protocol + ≥2 independent operators.
- **Multi-instance replication** — this release is one instance per operator.
- **Authn/authz** — operator fronts the server; built-in OIDC is future work.
- **Postgres/SQLite/RocksDB backend** — file-backed only (§17.2.1).
- **Web UI** — HTTP/JSON only.

---

## §17.10 CsqLedgerSink (csq-core side)

`CsqLedgerSink` (`csq-core/src/audit/impls/csq_ledger_sink.rs`, gated
`--features csq-ledger-sink`) is the `LedgerSink` impl that anchors a csq
audit chain TO a csq-ledger server: `append` POSTs to `/v1/log/entries`,
`verify_at` GETs from `/v1/log/entries/{id}`, `name` is `"csq-ledger"`. It is
NOT on the default csq-core code path (`csq-ledger-sink` is a feature flag, not
a default dep; the `reqwest` client is invoked only under the feature). It
passes the conformance harness (`ledger_sink_conformance_csq_ledger`) via an
in-memory mock transport. See spec 15 §15.4 for the catalog entry.

**Server-key pinning (current limitation).** `CsqLedgerSink` does NOT pin
the csq-ledger server's checkpoint signing key — it does not consume
`GET /v1/checkpoint` and discards the `checkpoint_at_submit` embedded in the
submit response. There is no configured expected `signed_by_key_id` today. A
MITM (or a swapped server behind the configured URL) returning a validly-shaped
response is therefore NOT detected by the sink itself. Operators MUST pin the
server OUT-OF-BAND: terminate with TLS to a known host (the recommended
deployment fronts the server with a reverse proxy / mTLS, §17.9) and/or verify
the `GET /v1/checkpoint` `signed_by_key_id` through a separate trusted channel.
Configurable in-sink pinning (an `expected_key_id` on `CsqLedgerConfig` + a
checkpoint-signature check per `append`) is future work.

---

## §17.11 Cross-references

- **Spec 12 — csq Audit Trail** (`12-audit-trail.md`): the local audit chain
  whose records csq-ledger logs; the unified signing contract (§12.10.8) the
  leaf-hash soundness argument relies on.
- **Spec 15 — LedgerSink Trait and Reference-Impl Catalog**
  (`15-ledgersink-trait-and-sinks.md`): the `LedgerSink` trait + catalog that
  `--anchor-to-sink` and `CsqLedgerSink` both consume.
- `csq-ledger/src/merkle.rs` — native RFC 6962 implementation + test vectors.
- `csq-ledger/src/storage/` — append-only segment store (no-delete invariant).
- `csq-ledger/src/server/submit.rs` — fsync-before-200 submit handler.
- `csq-ledger/src/signing.rs` — server checkpoint signing key + first-boot UX.
- `csq-ledger/src/anchor.rs` — anchor-to-sink (consumes the `LedgerSink` trait).
- `docs/audit-sinks/csq-ledger.md` — operator guide + authoritative threat model.

---

## Revisions

| Version | Change                           |
| ------- | -------------------------------- |
| 1       | Initial spec: csq-ledger server. |
| 2       | Cross-reference cleanup.         |
