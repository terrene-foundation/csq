# 12 csq Audit Trail

Spec version: 1.41.0 | Status: DRAFT | Governs: per-`csq run` audit-record schema (v1 JSONL + v2 chain-linked records), the single audited write site, the csq-cli emit/drain contract, retention and sweep, the audit-trait abstraction layer, local Ed25519 signing-key custody, chain-integrity verification at daemon start, the `csq audit verify` contract, the `.chain-broken` sentinel, the historical-key degrade path, and the verification-level gradient.

---

## 12.0 Scope

This spec defines csq's audit trail — the persisted JSONL records that capture per-`csq run` metadata sufficient to re-derive the harness invocation, plus the hash-linked, locally-signed chain those records form. It is the single source of truth for:

- The schema versions + field sets persisted under `~/.claude/accounts/csq-runs/`.
- The single audited write site that produces those records.
- The csq-cli emit contract (flush-on-`Drop` with timeout + `.pending/` fallback).
- Retention, drain, and sweep semantics (daemon scheduling lives in spec 04 § 4.2.8; semantic ownership stays here).
- The Ed25519 signing-key custody model, chain-integrity verification, and the `csq audit verify` / `csq doctor` surfaces.

When an implementation contradicts this spec, the spec wins.

## 12.1 Persisted-vs-ephemeral boundary

- **Persisted** to `~/.claude/accounts/csq-runs/`: metadata sufficient to re-run the harness invocation deterministically.

  **v1 required fields** (`schema_version: "1"`): `run_id`, `fixture_sha256`, `coc_sha256`, `csq_version`, `cli_version`, `surface`, `model`, `start_ts`, `end_ts`, `result_state`, `score_delta_vs_baseline`, `rule_ids_cited_original`, `rule_ids_cited_after_repair`, `rule_ids_dropped_invalid_format`, `decision`.

  **v2 required fields** (`schema_version: "2"`, in addition to all v1 fields): `record_id`, `kind`, `payload`, `prev_hash`, `canonical_hash`, `signature`, `signing_key_id`, `chain_id`, `seq`, `ts`. v2 records are chain-linked and locally signed (see §12.7–§12.13).

- **Ephemeral (in-memory only):** full prompt body, full model output body, intermediate repair drafts, MCP tool-call payloads.

JSON schemas for both versions are validated by downstream consumers; the authoritative Rust writers are `csq-core/src/audit/persist.rs::write_record` (v1) and `csq-core/src/audit/persist.rs::write_record_v2` (v2).

## 12.2 Single audited write site

Two public functions write audit records under `~/.claude/accounts/csq-runs/`: `write_record` (v1) and `write_record_v2` (v2). Both live in `csq-core/src/audit/persist.rs`. A second authorized write site is `csq-core/src/audit/key_custody/chain_state.rs`, which writes `signing_key_id` and `pubkey` into `csq-runs/chain.json` (the key-custody extension). No other code path writes audit records under that directory. The invariant is structurally enforced by:

1. **Module-API surface:** `persist.rs` exposes `pub fn write_record(record: AuditRecord) -> Result<(), AuditError>` (v1) and `pub fn write_record_v2(record: SignedRecord, base_dir: Option<&Path>) -> Result<(), AuditV2Error>` (v2). No other public function or constant in that module touches the filesystem. `chain_state.rs::ChainState::save` is the gated second write site for chain.json.
2. **Static grep test:** `csq-core/tests/audit_single_writer.rs` scans `csq-core/src`, `csq/src`, and the desktop backend source roots (missing dirs silently skipped). The detection is WRITE-OPERATION based, not file-membership based: a line is a violation only if it contains BOTH a `csq-runs/` / `chain.json` path reference AND a write-API token (`fs::write`, `File::create`, `OpenOptions`, `atomic_replace`, `secure_file`, `create_dir`) AND lives in a file outside the authorized-write allowlist. A write-operation model is required because a file-membership model would allowlist whole files, so a new WRITE added to an already-allowlisted READ-site would pass undetected. Read-only references (`read_to_string`, `File::open`, `read_dir`) in any file are unconditionally exempt. The allowlist distinguishes WRITE sites from READ sites:
   - **Authorized WRITE sites:** `audit/persist.rs` (v1 + v2 writers) + `audit/key_custody/chain_state.rs` (chain.json writer).
   - **Authorized READ/support sites:** `audit/mod.rs` (re-export), `audit/verify.rs` (chain verifier), `audit/sweep.rs` (deletes only), `audit/key_custody/{init,rotate,doctor,mod,keyring_backend}.rs` (call `chain_state::save` or are doc-only), `daemon/startup_reconciler.rs` (drain re-applies via `write_record`), `daemon/server.rs` (routes through `persist.rs`), `csq/src/cli/audit_emit.rs` (writes to `.pending/`), `csq/src/cli/trace_file.rs` (writes `.trace/` log files, NOT audit records), and the doc/import-only CLI modules.
   - Every non-allowlisted, non-test, non-comment match fails the test with message: `"FAIL: csq-runs/ write referenced outside authorized sites at <file>:<line>"`. A bare `assert!(false)` is BLOCKED; a descriptive `file:line` message is required.
   - `.pending/` and `.trace/` sub-path references are permitted for the listed emit/trace sites (they are inside `csq-runs/` but are not audit-record writers).
3. **Daemon drain inheritance:** the startup-drain pass (spec 04 § 4.2.8) MUST call `write_record` (v1) depending on the record's `schema_version`. Drain is a re-application, not a third parallel writer.

## 12.3 csq-cli emit contract

Each `csq run` instantiates an `AuditEmitter` in `csq/src/cli/audit_emit.rs`. On `Drop`, the emitter flushes the held record. A v2 `AuditEmitter` calls `write_record_v2` to produce a chain-linked record.

1. Issue a blocking `POST /api/audit/record` to `$base_dir/csq.sock` with a 100-millisecond total deadline (5 ms connect + 95 ms write + ack).
2. **Live-IPC happy path:** daemon returns 204; emitter discards the record from memory.
3. **Timeout / connect failure / 5xx:** emitter writes the record to `~/.claude/accounts/csq-runs/.pending/<run-id>.jsonl` (mode 0o600; parent 0o700) using the canonical `unique_tmp_path → write → secure_file → atomic_replace` pattern with partial-failure cleanup.
4. **`.pending/` write failure (fail-loud):** when the live-IPC POST AND the `.pending/` fallback write both fail, the emitter's behavior depends on which emit path is in use (see "Fail-loud split" below).

   The fail-loud remediation message (operator-facing, plain language):

   ```
   csq: audit record could not be written for operation "<operation>"
        The operation completed, but this event will not appear in your audit chain.
        Likely cause: disk full or permission error on ~/.claude/accounts/csq-runs/.pending/
        To continue without audit logging FOR THIS INVOCATION ONLY: re-run with --no-audit.
        To repair: ensure ~/.claude/accounts/csq-runs/.pending/ is writable and has space.
        To verify your chain integrity after the gap: csq audit verify
   ```

**Fail-loud split — `Drop`-vs-`try_flush_now` design boundary.** A `Drop` impl cannot return a `Result`, so a fail-loud guarantee CANNOT be surfaced from the `Drop` path. The emitter therefore splits its emit surface:

- **Fallible flush path (`AuditEmitter::try_flush_now`)** — every `csq run` exit path where csq still owns the exit code, i.e. immediately before any `cmd.exec()` (Unix process-image replacement) OR any `std::process::exit(...)` that runs AFTER an audit-emitting operation. These exits bypass `Drop`, so the flush MUST happen explicitly before them. The emitter returns `Err(AuditEmitError::PendingWriteFailed { operation, reason })`; the caller routes through `fail_loud_on_audit_write_failure` in `csq/src/cli/commands/run.rs`, which prints the message above to stderr and exits with code **3** (`EXIT_CODE_AUDIT_WRITE_FAILED`, distinct from `1` generic and `2` daemon-required) BEFORE the process image is replaced. The launched operation already completed; only the audit record was lost. The fallible-flush callers are the `exec_or_spawn` Inherit path and every `process::exit` inside the spawn-and-wait subpaths (`spawn_one_shot_with_post_validate`, `spawn_interactive_inherited`, `spawn_gemini_with_layer_dispatch`). Each such `process::exit` bypasses `Drop` — without an explicit pre-exit flush the owning `AuditEmitter` would never flush, losing the record with zero signal on every failed run.
- **Best-effort path (`Drop`)** — ONLY the spawn-and-wait SUCCESS teardown, where the child exited 0, no `process::exit` fired, and control reaches the post-spawn success block. `Drop` cannot return a `Result`, so it keeps the legacy fail-open posture: it emits the fixed-vocabulary `audit_emit_failed` tag at WARN (no body echoes) and drops the record. This is acceptable because the operation already completed AND csq has already returned a 0 exit code — there is no exit code left to own.

`try_flush_now` is idempotent: it `take()`s the held record, so once a fallible-flush subpath has flushed (and `process::exit`-ed), the record is `None` and the owner's `Drop` is a guaranteed no-op — no double-emit. The contract is implemented in `csq/src/cli/audit_emit.rs` (see its module-level "Fail-loud split" doc-comment).

**Per-invocation escape — `--no-audit` (no persistent config key).** There is NO persistent `audit.fail-loud` opt-out config key. The only escape is the per-invocation `csq run --no-audit` flag: it skips audit emission entirely for that one invocation (a `disabled` emitter holds no record, so every emit path is a no-op) and acknowledges the gap to the operator. A persistent flag would train operators to set-and-forget, defeating the audit guarantee; per-invocation acknowledgment keeps the gap visible at every occurrence.

The acknowledgement `csq: --no-audit set; this invocation's audit record will not be written.` MUST be emitted via **unconditional `eprintln!` to stderr** — it is NOT log-level-gated. The default `CSQ_LOG`/`RUST_LOG` filter is `warn`, which silently drops a `tracing::info!`; emitting only through `tracing` would make it invisible on every default-filter run. A mirrored `tracing::info!(event = "no_audit_set", …)` is SUPPLEMENTARY (for structured-log subscribers) and MUST NOT replace the unconditional stderr line. The wiring lives at `csq/src/cli/commands/run.rs`.

The 100 ms total deadline is the user-visible exit-latency floor under daemon contention. Lower starves real daemons under load; higher hangs `csq run` exit on a hung daemon. No per-route auth is needed — the Unix-socket peer-credential check is sufficient (see the security spec on daemon IPC).

## 12.4 RULE_ID format contract

The audit record splits citation into two fields:

- `rule_ids_cited_original` — RULE_IDs from the model's raw output.
- `rule_ids_cited_after_repair` — RULE_IDs present after post-validate repair.

Both fields contain strings matching:

```
^[A-Z][A-Z0-9-]{1,32}$
```

Anchored, starts with one uppercase letter, followed by 1-32 additional uppercase / digit / hyphen characters. Total length: 2-33 characters. Items failing the regex are dropped at write time (NOT carried as raw strings into the JSONL); the count of dropped items is recorded in `rule_ids_dropped_invalid_format`.

Rationale: RULE_IDs are content-bearing for compliance citation. An attacker injecting `; rm -rf ~` as a "RULE_ID" through a model-output channel could land that string in the persisted JSONL, where downstream tooling might parse it back. The regex fails closed. The pre/post split lets analysts compare "what the model claimed" vs "what survived validation."

## 12.5 Retention

- 30 days of retention.
- Daemon sweep runs every 24 hours per spec 04 § 4.2.8.
- Drain runs once per daemon start (NOT on the 24h tick).

## 12.6 Schema versioning

The `schema_version` field is a const string ("1" for v1, "2" for v2).

**v2 parallel writer:** `write_record_v2` is a separate function alongside the unchanged `write_record` (v1). v2 records are chain-linked and append to a single per-install JSONL chain file. v1 records written by the original `write_record` remain independent per-run files and are NOT rewritten.

**Chain genesis file (`chain.json`):** The first call to `write_record_v2` in an install generates a chain identity persisted at `~/.claude/accounts/csq-runs/chain.json` (mode 0o600, parent 0o700). Fields: `chain_id` (26-char Crockford Base32 string generated from 128-bit `getrandom`), `genesis_seq` (0), `genesis_ts` (ISO-8601 UTC). The file is written atomically with partial-failure cleanup.

**Genesis sentinel:** The genesis record (seq 0) uses `prev_hash = "0000…0000"` (64 zero hex characters = `Sha256Hex::GENESIS`). Every subsequent record's `prev_hash` is the SHA-256 of the CANONICAL FORM (all fields excluding `signature`) of the previous record. Canonical form is computed by `CanonicalView` (excludes the `signature` field from serde output) using a pure-stdlib SHA-256 implementation.

**`canonical_hash`:** Computed from the canonical form of the current record (excluding `signature`) BEFORE the signature is set. This is the pre-image the signing key signs over.

**Drain dispatch (startup reconciler and sweep):** `startup_reconciler.rs::pass5_audit_drain` dispatches on `schema_version` before applying a writer:

- `"1"` → drain v1 record via `write_record`; log `audit_drain_v1_record` structured tag.
- any other value → log `audit_drain_unknown_version` structured tag; **leave the file in `.pending/`**. MUST NOT delete or rewrite the file. (Lifecycle ops write directly to the committed chain via `write_record_v2`; they never pass through `.pending/`.)

**Chain-aware sweep:** The 30-day sweep (`audit::sweep::run_once`) MUST NOT age-delete any file whose `schema_version == "2"`. Deleting a chain-linked record breaks the chain for every subsequent record, causing `LedgerError::ChainBroken` on the next `verify_integrity`. The sweeper reads only the first 128 bytes of each candidate file to detect the `schema_version` before deciding to delete. A drain pass encountering an unknown `schema_version` MUST log `audit_drain_unknown_version` and leave the file in `.pending/`.

**v1 `surface` field accuracy:** The v1 `AuditRecord.surface` carries the ACTUAL dispatched surface (`cc` / `codex` / `gemini`), determined once in `csq/src/cli/commands/run.rs::handle` (via `surface_cli_for_slot`, mapped by `audit_surface_for`) BEFORE the record is constructed. Third-party slots dispatch through the Claude binary (network-layer redirect) and record `cc`.

**`run_id` validation:** `write_record_to` (the single v1 write site, reached by both the daemon `audit_record_handler` and the `.pending` reconciler drain) rejects any `run_id` that is not a canonical UUID (8-4-4-4-12 hex, via `seam::frontier::is_valid_uuid_shape`) with `AuditError::InvalidRunId` (fixed tag `invalid_run_id`). The `run_id` is untrusted at the same-UID daemon-IPC boundary and becomes BOTH the v1 filename `<run_id>.jsonl` (path-traversal vector) AND the floor-record dedup key `run:<run_id>` (dedup-namespace-forge vector); rejecting non-UUID shape at the single write site closes both for every ingress. The legitimate CLI path always uses `gen_run_id()` (a UUIDv4).

## 12.7 Trait abstraction layer

csq exposes a trait abstraction at `csq-core/src/audit/`. This section is the prose contract; the canonical files are `csq-core/src/audit/{traits,types}.rs`.

### 12.7.1 Trait surface (`csq-core/src/audit/traits.rs`)

Four traits define the abstraction boundary between csq's daemon / CLI surfaces and the underlying canonical-form + signing + storage providers:

| Trait                            | Methods                                | Async                   |
| -------------------------------- | -------------------------------------- | ----------------------- |
| `csq_core::audit::CanonicalForm` | `canonical_bytes`, `canonical_hash`    | no                      |
| `csq_core::audit::SigningKey`    | `key_id`, `public_key`, `sign`         | no                      |
| `csq_core::audit::LedgerEngine`  | `append`, `seq_at`, `verify_integrity` | no                      |
| `csq_core::audit::LedgerSink`    | `name`, `append`, `verify_at`          | **yes** (`async_trait`) |

`LedgerSink` is `Send + Sync + 'static` and uses `#[async_trait]` so the daemon can drive any sink through a `dyn LedgerSink` trait object. `LedgerSink` exposes EXACTLY three methods — every additional method is a place a sink impl can violate contract. The `LedgerSink` trait is the extension point for optional external anchoring; csq ships local-only by default, and operators opt in via the `audit.sink` config — see spec 15 (LedgerSink Trait and Reference-Impl Catalog).

### 12.7.2 Supporting types (`csq-core/src/audit/types.rs`)

| Type                                 | Purpose                                                                                                                                                          |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SignedRecord`                       | The on-disk schema-v2 record. Custom `Deserialize` enforces `deny_unknown_fields` + `kind == payload.kind()`.                                                    |
| `RecordId`                           | Validating newtype (accepts ULID or UUIDv7 — see §12.8.2; rejects CRLF/NUL/control/`/`/`\\`/`..`).                                                               |
| `KeyId`                              | Validating newtype shape `ed25519:[0-9a-f]{64}`.                                                                                                                 |
| `Sha256Hex`                          | Validating newtype — lowercase-only 64-hex SHA-256 digest. `Sha256Hex::GENESIS` const for the genesis sentinel.                                                  |
| `SinkName`                           | Validating newtype `[a-z0-9-]{1,64}` — defends `LedgerSink::name` against CRLF / log forgery.                                                                    |
| `SinkId`                             | Validating newtype `[A-Za-z0-9._:-]{1,256}` — sink-assigned record identifiers.                                                                                  |
| `RedactedString`                     | Wrapper whose only untrusted-source constructor routes through `error::redact_tokens` — structural defense for error messages.                                   |
| `Ed25519PublicKey`                   | Length-checked 32-byte wrapper; serde rejects wrong-length AND uppercase hex.                                                                                    |
| `Ed25519Signature`                   | Length-checked 64-byte wrapper; serde rejects wrong-length AND uppercase hex.                                                                                    |
| `SinkReceipt`                        | Receipt with typed `SinkName` + `SinkId` fields (no `pub String` attacker surfaces).                                                                             |
| `SinkError` (`#[non_exhaustive]`)    | Variants: `Rejected`, `Unreachable`, `Drift`, `NotFound`, `Internal`. All message fields are `RedactedString`.                                                   |
| `LedgerError` (`#[non_exhaustive]`)  | Variants: `ChainBroken{seq,expected_prev,actual_prev}`, `NotFound`, `IntegrityBroken`, `Io{context,source}`, `Internal`, plus the verifier variants in §12.10.2. |
| `SigningError` (`#[non_exhaustive]`) | Variants: `KeychainLocked`, `KeyRevoked{key_id}`, `Unavailable`, `Internal`. Returned by `SigningKey::sign`.                                                     |
| `IdError` (`#[non_exhaustive]`)      | Validation-failure error from every newtype constructor — `Empty`, `Length`, `Charset`, `Shape`.                                                                 |
| `EventKind`                          | Typed enum of session-custody event kinds. `ALL` const + compile-time variant-count assert.                                                                      |
| `EventPayload`                       | Typed enum paired 1-1 with `EventKind`. Per-variant struct fields use the validated newtypes above.                                                              |

The session-custody event kinds include `CsqRun` (per `csq run`), `OAuthRefresh`, `KeyRotate`, and the account-lifecycle kinds (`AccountSwap`, `AccountLogout`, `AccountMove`).

`EventPayload::kind()` returns the matching `EventKind`. `SignedRecord::kind` MUST equal `payload.kind()` — the consistency check is enforced AT DESERIALIZE TIME by the custom `Deserialize` impl on `SignedRecord`. A record with skewed kind/payload is rejected before deserialization succeeds.

`SignedRecord` carries a top-level `chain_id: RecordId` field for the cross-record consistency check. `SignedRecord.schema_version` is `String` (NOT `u32`) to preserve wire compatibility with the v1 `AuditRecord::schema_version: String`.

### 12.7.3 Structural invariants

The trait abstraction's load-bearing invariants:

1. **csq-owned surface.** `traits.rs` and `types.rs` define csq's own audit contract and depend only on csq-owned types and the standard library.

2. **`NoopSink` cannot ship in release binaries.** `csq-core/src/audit/impls/noop.rs::NoopSink` is gated `#[cfg(any(test, feature = "test-utils"))]`. The release pipeline builds with `--no-default-features --features cli`, which structurally excludes `test-utils`. `NoopSink` is NOT re-exported from `csq-core::audit`'s public surface — callers reach it only via the `crate::audit::impls::noop::NoopSink` path inside cfg-gated blocks.

3. **`#[serde(deny_unknown_fields)]` on `SignedRecord` and every payload struct.** Forged records with attacker-injected fields fail to deserialise. Verified by `audit::types::tests::signed_record_rejects_unknown_fields`.

4. **Fixed-length cryptographic newtypes — lowercase-hex-only.** `Ed25519PublicKey` and `Ed25519Signature` enforce 32-byte / 64-byte length AND reject uppercase hex at deserialise time. The uppercase rejection preserves the canonical-form contract (an uppercase-tolerant deserializer that re-serializes lowercase breaks signature verification on round-trips). Verified by `ed25519_public_key_rejects_uppercase_hex` / `ed25519_signature_rejects_wrong_length_hex`.

5. **Validating newtypes for every attacker-injectable string.** `RecordId`, `KeyId`, `Sha256Hex`, `SinkName`, `SinkId` all have private inner fields + `try_new` constructors + custom `Deserialize` routing through the validator. Rejects CRLF/NUL/control chars/path-traversal/wrong-charset at the trait surface — defends against path-traversal, header-injection, log-forgery, and confused-deputy failure modes. Verified by `record_id_rejects_path_traversal`, `record_id_rejects_crlf`, `key_id_rejects_uppercase_hex`, `sink_name_rejects_crlf`, `sink_id_rejects_control_chars`, and siblings.

6. **`kind == payload.kind()` consistency at deserialize time.** `SignedRecord`'s custom `Deserialize` rejects records with skewed top-level `kind` vs the payload's internal tag — closes the confused-deputy primitive where a verifier matching on `record.kind` would disagree with downstream code matching on `record.payload.kind()`. Verified by `signed_record_rejects_kind_payload_mismatch`.

7. **`RedactedString` structural redaction.** Error variants with operator-facing message fields carry `RedactedString`, whose only untrusted-source constructor routes through `error::redact_tokens`. Relying on "callers must redact" docstring discipline is the failure pattern; this newtype makes redaction the only constructable shape. Verified by `redacted_string_redacts_tokens`.

8. **All error enums are `#[non_exhaustive]`.** `SinkError`, `LedgerError`, `SigningError`, `IdError` can grow variants without breaking the public match surface.

9. **`AccountNum`-typed slot fields.** Every `slot` field in the payload structs is typed as `csq_core::types::AccountNum` (validated `1..=999`). Deserializing a `slot: 0` or `slot: 65535` from an audit payload is rejected at the type boundary.

10. **`LedgerEngine::append` takes `&self`.** Interior mutability lives inside the impl (single-writer invariant enforced internally). Daemon callers share `Arc<dyn LedgerEngine>` without an external `Mutex`, eliminating the "lock held across `.await`" anti-pattern. `SigningKey::sign` is FALLIBLE (`Result<Ed25519Signature, SigningError>`) so the keychain-backed impl can surface lock / revoke errors without panicking.

### 12.7.4 Cargo dependency

- `async-trait = "0.1"` — required for `LedgerSink`'s `dyn`-compatible async vtable.

## 12.8 v2 writer implementation notes

This section captures the load-bearing implementation decisions for `write_record_v2`.

### 12.8.1 SHA-256 implementation

`write_record_v2` uses a pure-stdlib SHA-256 (`std::num::Wrapping<u32>`, FIPS 180-4). No external crate (`sha2`, `ring`, etc.) is added. Rationale: `chain.json` is not a secret; the chain-integrity hash is a tamper-detection aid, not a cryptographic MAC. Adding a dep for SHA-256 would widen the attack surface for no gain. Tested by `prev_hash_equals_sha256_of_canonical_prev_record`.

### 12.8.2 `RecordId` format

`RecordId::try_new` accepts ONLY:

- **ULID:** 26-char Crockford Base32 string (`[0-9A-HJKMNP-TV-Z]{26}`, uppercase only — Crockford excludes I, L, O, U).
- **UUIDv7:** 36-char hyphenated UUID with version nibble `7` (`[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`).

### 12.8.3 Chain file layout

One chain per csq install: the genesis sidecar lives at `~/.claude/accounts/csq-runs/chain.json`; the chain JSONL appends to `~/.claude/accounts/csq-runs/<chain_id>.jsonl`. The filename encodes `chain_id` so a future multi-chain layout (one chain per provider surface) does not produce file collisions. Every v2 record in the chain carries its `chain_id` (matching `chain.json::chain_id`), `seq` (0-based monotonic counter), and `prev_hash` (SHA-256 of the canonical form of the previous record, or 64 zeros for seq 0).

The append uses an atomic read-extend-write pattern: read existing bytes, append new canonical bytes + newline, write back atomically. This is safe because `write_record_v2` is a single-writer function (§12.2). Multiple concurrent calls are not expected in the daemon architecture.

### 12.8.4 Verification-level gradient

The audit record's verification level uses a four-level gradient:

| Level           | Meaning                                                      |
| --------------- | ------------------------------------------------------------ |
| `AUTO_APPROVED` | The operation passed validation automatically; no hold.      |
| `FLAGGED`       | The operation completed but a check raised an advisory flag. |
| `HELD`          | The operation is held pending further review.                |
| `BLOCKED`       | The operation was blocked by a failed gate.                  |

The four levels are the complete gradient. The guard test `community_verification_level_is_four_levels` pins that the build cannot name or parse any level outside this set.

## 12.9 Local Ed25519 signing-key custody

csq signs its chain-linked records with a local Ed25519 key: a keypair generated on first `csq audit init` and used to sign `KeyRotate` events. The seed is stored under a **file-mirror + keychain-anchor** custody model — a 0o600 file store is the daemon-readable PRIMARY, and the OS keychain (via the `keyring` crate) is retained as an integrity anchor, a migration source, and a read fallback.

**Why the file store is primary:** the non-interactive daemon cannot answer the macOS keychain per-app-ACL prompt that fires when the running binary's code signature differs from the binary that created the keychain item — which happens on every rebuild. That prompt returns `errSecInteractionNotAllowed` (-25308) to a headless process, bricking the daemon's audit read path. The file store has no ACL and no prompt, so the daemon reads it non-interactively.

**Why the keychain is still load-bearing — as a DETECTOR.** The 0o600 file seed is same-UID-readable, so the signing key is not confidential against a same-UID attacker — an attacker who holds the live key forges regardless. The keychain's residual property is a same-UID write-asymmetry: an attacker with the user's UID can rewrite both `chain.json` and the file seed (both same-UID-writable under `csq-runs/`) and can DELETE the keychain item, but CANNOT silently REWRITE it — a planted or replaced entry either prompts or surfaces `keyring::Error::Ambiguous` / `BadEncoding`. So the keychain is retained as a delete-able-but-not-silently-rewrite-able tamper DETECTOR: when readable, the file's `(cutoff, key_id)` is cross-checked against it, and disagreement is surfaced (never fails the chain). The chosen posture is availability over real-time integrity (optimistic-sign, never-brick); the anchor detects anomalies, it does not block forgery.

### 12.9.1 Key generation and storage

- `csq audit init` (idempotent): generates a 32-byte CSPRNG seed via `getrandom::getrandom`, constructs an `ed25519-dalek` signing key, encodes the seed as lowercase hex (64-char ASCII) inside a `SeedEntryPayload` JSON (`{seed_hex, signing_active_since_seq, signing_key_id}`), and dual-writes that payload to BOTH stores. Lowercase hex is unambiguous across implementations and the embedded cutoff + key_id co-locate with the seed so deleting the seed destroys key + cutoff together (shared fate).
- **File store (PRIMARY, must succeed):** the payload is written to `<base>/csq-runs/keys/<chain_id>/active.json` (`0o600`); rotated-out keys go to `<base>/csq-runs/keys/<chain_id>/historical/<n>.json`, where `<n>` is the rotation count. Both parent directories are `0o700`. The on-disk slot is modeled by `KeySlot::{Active, Historical(u64)}` (`csq-core/src/audit/key_custody/file_store.rs`); the path is resolved by `seed_file_path`. Scoping the historical path under `keys/<chain_id>/historical/` fixes a multi-chain collision where two chains rotating to the same rotation count would otherwise collide.
- **Keychain (ANCHOR, best-effort):** the same payload is written under service `csq-audit-signing`, account `<chain_id>` via `keyring`. A keychain access-error during write is logged as a WARN and is non-fatal — the file write is the success condition.
- **Atomic write pipeline:** every file-seed write uses `unique_tmp_path → write → secure_file → atomic_replace` with `remove_file(&tmp)` on every failure branch. This pipeline lives in `file_store.rs`. The dual-write facade — `generate_and_store_dual`, `store_dual`, `preserve_dual`, `delete_dual` — is in `csq-core/src/audit/key_custody/keyring_backend.rs`.
- **File custody restores durable Linux custody.** The `keyring` crate is built with only `apple-native` + `windows-native` features, so its real OS-keychain backend ships ONLY on macOS and Windows; on Linux `keyring` falls back to an in-memory mock that does not persist between calls. The 0o600 file store persists on every platform, so Linux has durable on-disk custody.
- Seed bytes are held in `Zeroizing<[u8; 32]>` — zeroed on drop. The `DalekSigningKey` implements `ZeroizeOnDrop` natively.
- **keyring-directive scope:** all keychain I/O — and ONLY the keychain anchor / migration-source / read-fallback path — goes through `keyring`. `security-framework`, `secret-service`, and `windows-rs` MUST NOT be imported for signing-key custody. The file store is plain `std::fs` and does not touch any native keychain crate.

### 12.9.2 `KeyId` format

`"ed25519:<sha256_of_32_byte_pubkey_lowercase_hex>"` — 74-character string (`ed25519:` prefix + 64-char hex). SHA-256 is computed over the raw 32-byte compressed public key.

### 12.9.3 `chain.json` extension

The existing `chain.json` (if present) gains three optional fields:

| Field                      | Type                               | When present                 |
| -------------------------- | ---------------------------------- | ---------------------------- |
| `signing_key_id`           | `String`                           | After first `csq audit init` |
| `pubkey`                   | `String` (lowercase hex, 64 chars) | After first `csq audit init` |
| `signing_active_since_seq` | `u64`                              | After first `csq audit init` |

`signing_key_id`/`pubkey` are serialised with `skip_serializing_if = "Option::is_none"`. The `pubkey` deserialiser carries `#[serde(default)]` so loading a pre-signing `chain.json` returns `None` instead of a parse error.

`signing_active_since_seq` carries `#[serde(default)]` and records the chain `seq` at which signing became mandatory. The verifier treats any record with `seq >= authoritative_cutoff` carrying the all-zeros placeholder key as a tamper indicator (`UnsignedRecordAfterCutoff`). When no authoritative cutoff is available (pre-`audit init`), placeholder-key records are tolerated. `chain.json`'s `signing_active_since_seq` is ADVISORY only — the seed entry (file primary, keychain anchor) is authoritative. `chain.json` is attacker-writable; the file seed co-locates the cutoff with the key (shared fate), and when the keychain anchor is readable its trustworthy `(cutoff, key_id)` is PREFERRED over the file/chain.json — actively defeating a chain.json cutoff-raise. When the keychain is blocked/absent the file cutoff is used (a detector-Unconfirmed run, never a brick). See §12.9.4.

Every write of `chain.json` carrying these fields uses the `unique_tmp_path → write → secure_file → atomic_replace` pipeline with cleanup on every failure branch.

### 12.9.4 Co-located signing cutoff + file-vs-keychain cross-check

**Background.** `chain.json` lives at `<base_dir>/csq-runs/chain.json`, which is attacker-writable by a same-UID owner. Without the co-location below, a same-UID attacker could: (1) raise the `chain.json` cutoff, (2) insert unsigned placeholder records in the re-opened window, (3) delete a separable anchor item, causing the verifier to backfill the forged cutoff as authoritative.

**Fate-sharing (co-located payload).** The signing cutoff is stored INSIDE the seed payload (`SeedEntryPayload`: `{seed_hex, signing_active_since_seq, signing_key_id}`), so cutoff and key share fate: deleting the seed destroys both simultaneously, causing `verify_chain` to fail closed with `KeyNotFound` for records that reference the deleted key. There is no separable anchor item to target. The file seed (`active.json`) and the keychain anchor each hold the SAME single-file payload, so cutoff and key share fate in both stores.

**Write-asymmetry (the basis for DETECTION, not forge-resistance).** Fate-sharing protects against the delete-the-anchor attack. The keychain's separate property is a same-UID write-asymmetry: the file seed and `chain.json` are both same-UID-writable, and the keychain item is same-UID-DELETE-able, but it is NOT silently REWRITE-able. An attacker can forge the file seed (the 0o600 file is same-UID-readable, so the signing key is not confidential), but when the keychain anchor is readable it still witnesses the genuine `(cutoff, key_id)` and the verifier surfaces the disagreement as `KeychainAnchorStatus::Mismatch`. The keychain DETECTS anomalies — it does not block forgery. The disagreement is NEVER fatal: it is logged loudly and shown by `csq doctor`, but the chain stays operational.

**Seed entry payload format:**

```json
{"seed_hex":"<64-char lowercase hex>","signing_active_since_seq":<u64>,"signing_key_id":"<KeyId>"}
```

A legacy bare-hex format (bare 64-char hex string) is still accepted on read; it yields `None` from `load_embedded_cutoff` (treated as a legacy install).

**`csq audit init` behaviour:** computes the cutoff BEFORE the dual-write, then calls `generate_and_store_dual(base_dir, service, account, cutoff)` so the payload is written to the file store (PRIMARY, must succeed) and the keychain anchor (best-effort). On a `chain.json` save failure, `delete_dual` removes the seed from both stores.

**`csq audit rotate-key` behaviour:** reads the embedded cutoff from the outgoing seed (`load_embedded_cutoff`, file-first). A legacy bare-hex outgoing key warns `audit_cutoff_legacy_seed_no_embedded` and falls back to the `chain.json` cutoff. It preserves the outgoing seed to the historical slot via `preserve_dual`, then mints + dual-writes the incoming key via `store_dual`. If `chain.json::signing_active_since_seq` is `None`, it is set to the incoming cutoff before saving (prevents the next verify from self-inflicting a `KeychainAnchorStatus::Mismatch` from a chain.json-vs-seed disagreement). On a `chain.json` save failure, `delete_dual` removes the incoming key + historical slot from both stores.

**`verify_chain` cutoff resolution — file-primary, keychain-cutoff-preferred-when-readable, anchor cross-check as a DETECTOR (Step 0, READ-ONLY).** Resolution is implemented in `resolve_authoritative_cutoff` (`csq-core/src/audit/verify.rs`), which reads the FILE cutoff (primary), the KEYCHAIN cutoff (anchor), and `chain.json`'s `signing_active_since_seq` (advisory). It returns `(Option<u64>, KeychainAnchorStatus)` — never a fatal `Err` for any anchor anomaly:

```rust
pub enum KeychainAnchorStatus { Confirmed, Unconfirmed, Mismatch }
```

- **Confirmed** — file + keychain were both read and AGREE on `(cutoff, key_id)`. Full forge-detection coverage this run. (Also the N/A default for a chain with no signing key.)
- **Unconfirmed** — the keychain anchor could not be read+compared this run: locked / access-denied (the daemon's normal state), genuinely absent (a file-only install, a completed migration, OR an attacker who DELETED the anchor to downgrade trust), or legacy bare-hex. Forge-resistance was file-only this run; remediation is `csq audit migrate-keys` to (re)establish the anchor. NON-fatal.
- **Mismatch** — the file / keychain / chain.json DISAGREE on `(cutoff, key_id)`, OR the keychain entry is corrupt/planted. Possible tampering. Surfaced LOUDLY (an ERROR log via `emit_anchor_status`, `error_kind = "audit_keychain_anchor_mismatch"`, plus a `csq doctor` alarm line) but NON-fatal. The chain stays operational; the owner MUST investigate.

The resolution prefers the readable keychain cutoff (the un-rewritable source) to actively defeat a file/chain.json cutoff-raise — the placeholder records the attacker re-opened are rejected at the real cutoff via `UnsignedRecordAfterCutoff`. When the keychain is access-blocked or legacy bare-hex, the file cutoff is used with status `Unconfirmed`. A corrupt (present-but-unparseable) file seed is genuine local seed damage → the ONLY fatal in this resolution: `LedgerError::Io` (recoverable via `csq audit repair`).

**Integrity-vs-availability trade.** During a keychain-block window (`Unconfirmed`), the daemon signs and verifies optimistically with the FILE seed and does NOT fail closed — the run reports `Unconfirmed`, not a brick. Any `chain.json`-vs-keychain tampering is detected at the next keychain-readable verify (surfaced as `Mismatch`, still non-fatal). This is the deliberate posture: availability over real-time integrity, with the anchor as a loud detector rather than a gate.

**Implementation surface:**

- `csq-core/src/audit/key_custody/file_store.rs` — `KeySlot::{Active, Historical(u64)}`, `seed_file_path`, `store_payload` / `load_payload` (the atomic write pipeline lives here)
- `csq-core/src/audit/key_custody/keyring_backend.rs` — `SeedEntryPayload`, `EmbeddedCutoff`, `KeyLoadOutcome::{Loaded, Absent, Inaccessible, Corrupt}`, `try_load_signing_key` (file-first read), the `*_dual` facade, `is_keychain_access_error`
- `csq-core/src/audit/key_custody/init.rs` — computes the cutoff before the dual-write; save-failure rollback
- `csq-core/src/audit/key_custody/rotate.rs` — reads the embedded cutoff before rotate; dual-writes the incoming key + historical slot; chain.json sync
- `csq-core/src/audit/verify.rs` — `resolve_authoritative_cutoff` (Step 0), `KeychainAnchorStatus`, `emit_anchor_status`, `VerifySummary.keychain_anchor`; read-only invariant (writes neither store)

### 12.9.5 Key rotation contract

`csq audit rotate-key [--reason operator|policy|compromised]`:

1. Loads the active key (file-first; keychain fallback).
2. Copies its seed to a permanent historical slot keyed by its `KeyId` (retained for historical-record verification).
3. Generates a fresh keypair; dual-writes it after the outgoing seed is preserved.
4. Builds a `KeyRotate` `SignedRecord` signed by the outgoing key.
5. Writes the updated `chain.json` with the new `signing_key_id` + `pubkey`.

`RotationReason` enum values: `Operator` (default), `Policy`, `Compromised`, `Scheduled`.

### 12.9.6 `csq doctor` integration

The `DoctorReport` JSON carries a `signing_key` field:

```json
"signing_key": "present" | "absent" | "inaccessible"
```

Presence is resolved file-first via `try_load_signing_key` — `csq-core/src/audit/key_custody/doctor.rs::check_signing_key` maps `KeyLoadOutcome` to `SigningKeyStatus`:

- `Present { key_id }` — the active signing key loaded from the file store OR the keychain.
- `Absent` — neither store has the entry (pre-init or both cleared). Remediation: `csq audit init`.
- `Inaccessible` — the key is PRESENT but unreadable (locked / access-denied keychain entry). This is distinct from `Absent` because `csq audit init` would mint a SECOND key and is the WRONG remediation. The doctor recommends **`csq audit migrate-keys`** (copy the keychain key into the daemon-readable file store), NOT `audit init`.

`DoctorReport` also carries an `audit_keychain_anchor` field of type `csq_core::audit::KeychainAnchorStatus`, populated from the same `verify_chain` scan that produces `audit_chain_state` (it reads `VerifySummary::keychain_anchor`). Text-mode `csq doctor` prints an **`Audit anchor:`** line distinct from the chain / signing-key lines:

- `Confirmed` → `Audit anchor:  ✓ confirmed (file ↔ keychain agree)`
- `Unconfirmed` → `Audit anchor:  ⚠ UNCONFIRMED — keychain anchor not read this run (locked / absent); forge-resistance was file-only. Run \`csq audit migrate-keys\``
- `Mismatch` → `Audit anchor:  ✗ MISMATCH — file / keychain / chain.json disagree; possible tampering. Run \`csq audit verify --full\` and investigate`

The anchor is a DETECTOR axis SEPARATE from chain verification: it does NOT affect `AuditHealth` or `is_operational()` (a `Mismatch` is a loud alarm, not a `Broken` verdict).

### 12.9.7 Cargo dependencies

| Crate           | Version         | Feature flags                    | Purpose                                                          |
| --------------- | --------------- | -------------------------------- | ---------------------------------------------------------------- |
| `keyring`       | `3`             | `apple-native`, `windows-native` | Keychain anchor / migration source / read fallback (NOT primary) |
| `zeroize`       | `1`             | `derive`                         | `Zeroizing<[u8; 32]>` seed wrapper                               |
| `getrandom`     | `0.2`           | —                                | CSPRNG seed generation                                           |
| `ed25519-dalek` | already present | —                                | Ed25519 key generation and signing                               |
| `base64`        | already present | —                                | Key encoding for keychain storage                                |

**macOS ACL note — interactive paths only:** on macOS with the `apple-native` feature, a keychain write for a new service, or any keychain READ whose calling binary's code signature differs from the binary that created the item, triggers the system per-app-ACL dialog. Under the file-mirror model this prompt fires ONLY on the interactive write/migration paths — `csq audit init`, `csq audit rotate-key`, `csq audit migrate-keys` — where a TTY is present to answer it. The non-interactive daemon read path never touches the keychain on the hot path: it reads the 0o600 file store (no ACL, no prompt). `csq audit init` prints a one-line UX hint before the keyring call: `"macOS will prompt once to grant csq access to the keychain — this is expected."`

### 12.9.8 Operator recovery: migrate-keys + repair

Two operator commands recover a chain whose signing key is present-but-inaccessible (the daemon-brick condition the file store exists to prevent) or whose `.chain-broken` sentinel is stale.

**`csq audit migrate-keys`** (handler `handle_migrate_keys`; library `migrate_keys_to_file_store` in `csq-core/src/audit/key_custody/migrate.rs`): copies the active + historical signing seeds from the OS keychain INTO the 0o600 file store for the chain recorded in `chain.json`. Run interactively so the one-time keychain prompt can be granted. It is **additive — the keychain entries are NOT deleted** (they remain the integrity anchor + back-compat fallback), and idempotent. Returns `MigrateOutcome { active_migrated, active_already_present, historical_migrated: Vec<u64>, keychain_inaccessible, keychain_absent }`. This is the remediation `csq doctor` recommends for the `Inaccessible` signing-key state.

**`csq audit repair [--apply]`** (handler `handle_repair`; library `repair_audit_chain`): diagnoses the chain and returns `RepairOutcome`:

- `Healthy { sentinel_cleared }` — the chain verifies clean (or degraded-historical); any stale `.chain-broken` sentinel was cleared.
- `NeedsMigration` — the chain is unverifiable because the key is present-but-inaccessible. Repair refuses to reset; it recommends `csq audit migrate-keys`.
- `ResetRequired { reason }` — `--apply` absent: the chain is genuinely broken; reports what a reset would back up (dry-run).
- `ChainReset { backup_dir, reason }` — `--apply` present: the broken chain was backed up to `backup_dir` and the active chain state was reset so a fresh `csq audit init` starts clean.

CLI surface: `AuditCmd::{MigrateKeys, Repair { apply }}`.

## 12.10 Chain integrity verification at daemon start

The daemon inserts `audit::verify_chain` into its startup sequence AFTER the phase-4 gate check and BEFORE the socket bind. See spec 04 for the daemon-level sequencing contract; this section documents the verifier's error taxonomy, v1-skip behavior, and the `csq audit verify` CLI contract.

### 12.10.1 Pre-bind placement

The invariant is: a csq CLI client MUST NOT be able to connect to a daemon that has not yet verified its chain. `verify_chain` runs synchronously in a `tokio::task::spawn_blocking` wrapper inside the daemon's async startup loop, wrapped in `tokio::time::timeout` (default 5s, configurable via `CSQ_AUDIT_VERIFY_TIMEOUT_SECS`). The timeout produces a WARN log and proceeds to socket bind — slow verification is NOT an integrity failure.

### 12.10.2 Error taxonomy

Typed `LedgerError` variants are the canonical failure surface:

| Variant                                           | Trigger                                                                                                                                           | Daemon action                                                                                                                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ChainBroken { seq, expected_prev, actual_prev }` | `record[n].prev_hash != sha256(canonical(record[n-1]))`                                                                                           | `audit_chain_integrity_failure` ERROR log + stderr; sets `AuditHealth::Broken`; sets `.chain-broken` sentinel; proceeds to socket bind                                             |
| `InvalidSignature { record_id, key_id }`          | Ed25519 signature does not verify against the pubkey for `key_id`                                                                                 | same                                                                                                                                                                               |
| `KeyNotFound { key_id }`                          | Current **active** signing key GENUINELY ABSENT from both stores (file + keychain `NoEntry`); see §12.10.7 for the historical-key case            | `audit_current_key_not_found` ERROR log + stderr remediation naming `key_id`; sets `AuditHealth::Broken`; sets `.chain-broken`; proceeds to socket bind                            |
| `KeychainUnavailable { key_id }`                  | Active key is PRESENT but UNREADABLE — keychain access-error (locked / ACL-blocked) with no file copy; structurally distinct from genuine absence | maps to `AuditHealth::Unknown` (transient) — does NOT set the durable `.chain-broken` sentinel; gates the audit subsystem for this daemon's lifetime only; proceeds to socket bind |
| `IntegrityBroken { seq, reason }`                 | `seq` not monotonic, `chain_id` mismatch, or unrecognised record format                                                                           | `audit_chain_integrity_failure` ERROR log + stderr; sets `AuditHealth::Broken`; sets `.chain-broken`; proceeds to socket bind                                                      |
| `UnsignedRecordAfterCutoff { seq, cutoff }`       | placeholder key on a record with `seq >= authoritative_cutoff` (from the seed entry, §12.9.3); `cutoff` is the authoritative value                | `audit_chain_integrity_failure` ERROR log + stderr; sets `AuditHealth::Broken`; sets `.chain-broken`; proceeds to socket bind                                                      |

`KeychainUnavailable` is the access-vs-absence conflation fix: an access-error on a present key is transient (`Unknown`), whereas a genuine `NoEntry`/`KeyNotFound` is durable (`Broken`). Conflating them — treating a locked keychain as a missing key — would plant a durable `.chain-broken` sentinel on a recoverable condition. All variants are in `csq-core/src/audit/types.rs` (`LedgerError`, `#[non_exhaustive]`).

**Keychain integrity-anchor axis — a non-fatal DETECTOR, SEPARATE from this taxonomy.** `KeychainAnchorStatus` is NOT a `LedgerError` variant and NOT an `AuditHealth` value. The Step-0 cross-check (§12.9.4) produces a `KeychainAnchorStatus { Confirmed, Unconfirmed, Mismatch }` carried on `VerifySummary::keychain_anchor`. It NEVER fails the chain: a `Mismatch` is logged loudly via `emit_anchor_status` and surfaced by `csq doctor` / `csq daemon status`, but does NOT set `.chain-broken`, does NOT set `AuditHealth::Broken`, and does NOT affect `is_operational()`. The ONLY fatal outcome of Step-0 is a corrupt FILE seed (`LedgerError::Io`, recoverable via `csq audit repair`).

Stderr remediation messages:

- `ChainBroken` / `InvalidSignature`: "run `csq audit verify --full` for diagnosis. Repair tooling is forthcoming."
- `KeyNotFound` (current active key missing): "the current active signing key `<key_id>` is not in your keychain. New audit records cannot be verified. Run `csq audit init` to re-initialise signing, or restore the key from backup. Run `csq audit verify --full` for diagnosis."
- Keychain anchor `Mismatch`: emitted by `emit_anchor_status` at ERROR: "verify_chain: keychain integrity anchor MISMATCH — the file seed / chain.json disagree with the keychain anchor (or the anchor is corrupt). Possible tampering. The chain remains operational (detector, not gate); run `csq audit verify --full` and investigate." The chain is NOT failed and the daemon proceeds normally.

### 12.10.3 V1 record skip behavior

V1 records (JSON lines containing `"schema_version":"1"` that do not parse as `SignedRecord`) are NOT chain-linked and are skipped. A single summary log fires per verification run:

```
audit_verify_skipped_v1_records_total = <N>
```

NOT one log line per record. This avoids flooding the log for operators upgrading from a v1 install with many historical records.

### 12.10.4 Timeout and record-limit configuration

| Parameter    | Default   | How to override                                                                  |
| ------------ | --------- | -------------------------------------------------------------------------------- |
| Timeout      | 5 seconds | `CSQ_AUDIT_VERIFY_TIMEOUT_SECS` env var                                          |
| Record limit | 10,000    | `--audit-verify-limit N` on `csq daemon start`; `CSQ_AUDIT_VERIFY_LIMIT` env var |

The limit governs how many records from the **tail** (newest) are verified — the verifier keeps the last `N`, so the HEAD (most recent, highest-tamper-value record) is ALWAYS in the verified window. Records OLDER than the tail window produce `audit_verify_limit_exceeded` at WARN and are not verified (acceptable: oldest records are the lowest-value tamper target, and the head — the one an attacker would forge — is always checked). The limit of 10,000 is calibrated for 30 days of daily csq use.

### 12.10.5 `csq audit verify` CLI contract

**Command:** `csq audit verify [--full] [--since <ts>] [--json]`

**Flags:**

- `--full`: verify the entire chain (default: tail 1,000 records).
- `--since <ts>`: ISO-8601 timestamp filter — accepted for forward-compat but the implementation is a **no-op** (correct look-behind requires loading the predecessor record to seed the chain link and is not yet wired). The flag is retained for CLI-surface stability; it neither narrows nor errors verification today.
- `--json`: machine-parseable output.

**Exit codes:**

- `0` — clean (all verified records passed).
- `1` — integrity failure (`ChainBroken`, `InvalidSignature`, `IntegrityBroken`, `UnsignedRecordAfterCutoff`, I/O error).
- `2` — partial (`KeyNotFound` — signing key not found for historical records).

**Daemon-vs-CLI severity split (intentional):** the `csq audit verify` CLI treats `KeyNotFound` as exit-2 "partial" (the operator may have legitimately pruned an old key). The daemon distinguishes two sub-cases:

- **Historical (rotated-out) key missing** — `verify_chain` returns `Ok(summary)` with `summary.historical_key_gaps` populated. Chain-linking was verified end-to-end; only per-record signatures for those historical records were skipped. The daemon logs a WARN and proceeds to socket bind with `AuditHealth::Degraded`.
- **Current active key missing** — `verify_chain` returns `Err(LedgerError::KeyNotFound)`. The daemon logs `audit_current_key_not_found` ERROR, sets `AuditHealth::Broken`, and proceeds to socket bind (the audit subsystem is non-operational, but token-refresh and quota-polling are unaffected — see §12.10.6).
- **Chain corruption or invalid signature** — `verify_chain` returns a fatal `LedgerError` variant. The daemon logs the appropriate `error_kind`, sets `AuditHealth::Broken`, and proceeds to socket bind.

**`--json` output shape:**

```json
{
  "status": "ok" | "integrity_failure" | "partial",
  "verified_count": <u64>,
  "skipped_v1_count": <u64>,
  "failure_detail": {
    "kind": "chain_broken" | "invalid_signature" | "key_not_found" | "integrity_broken" | "io_error" | "internal",
    "message": "<human-readable string>"
  }
}
```

`failure_detail` is absent when `status == "ok"`.

### 12.10.6 Audit-verify decoupling — `AuditHealth` gating posture

`verify_chain` NEVER blocks daemon startup. Every outcome — including fatal errors and timeout — maps to an `AuditHealth` enum value stored in `RouterState`. Token-refresh and quota-polling ALWAYS proceed regardless of `AuditHealth`; only the audit subsystem itself is gated. The original coupling (refuse to start on a broken chain) was accidental — refusing to start never protected the on-disk chain (it is already corrupt or the key already gone before the daemon runs); it only made the daemon unavailable for all other subsystems during the operator's recovery window.

**`AuditHealth` enum** (`csq-core/src/audit/health.rs`):

| Variant                         | Source                                                                    | `is_operational()` |
| ------------------------------- | ------------------------------------------------------------------------- | ------------------ |
| `Verified`                      | `verify_chain` returns `Ok(summary)` with no gaps                         | `true`             |
| `Degraded { gaps }`             | `verify_chain` returns `Ok(summary)` with `historical_key_gaps` populated | `true`             |
| `Broken { error_kind, reason }` | `verify_chain` returns `Err(_)`                                           | `false`            |
| `Unknown { reason }`            | `verify_chain` task panicked or timed out                                 | `false`            |

**Audit-subsystem gates (`is_operational()` == `false` → closed):**

- **Anchor task** (CLI: `csq/src/cli/commands/daemon.rs`; desktop: `csq/src/desktop/daemon_supervisor.rs`): spawn is skipped when `!is_operational()`; log fires at ERROR.
- **`POST /api/audit/record`** (`csq-core/src/daemon/server.rs::audit_record_handler`): returns `503 Service Unavailable` with `{"error":"audit_chain_broken"}` when `!is_operational()`. The health check runs BEFORE body deserialization.
- **CLI-side `write_record_v2_impl`** (all direct writers): blocked at the write site via the `.chain-broken` sentinel (§12.10.8).

**`Degraded` is fully operational:** both anchor and emit run normally when `AuditHealth::Degraded`. The historical-key gaps are surfaced in `csq doctor` for operator awareness.

**`csq doctor` surface:** the `audit_chain_state` field reflects the classification from the same `verify_chain` call that populates `audit_historical_key_gaps`. JSON shape: `{ "status": "verified" | "degraded" | "broken" | "unknown", "error_kind": "...", "reason": "..." }` (the latter two present only for `broken` and `unknown`). Text-mode output includes an `Audit chain: ✓/⚠/✗` line next to the signing-key line. The separate keychain-anchor axis is surfaced via `audit_keychain_anchor` (§12.9.6) — a `Mismatch` is a loud alarm, never a `Broken` verdict.

**Desktop daemon supervisor** (`csq/src/desktop/daemon_supervisor.rs`): mirrors the CLI daemon's verify block — runs `verify_chain` in `spawn_blocking` before serving, applies the same timeout floor and record-limit defaults, maps outcomes to `AuditHealth`, sets/clears the `.chain-broken` sentinel, and gates anchor-task spawn on `is_operational()`.

**`CSQ_AUDIT_VERIFY_TIMEOUT_SECS` floor:** a value of `0` or an unparseable value MUST be treated as the default (5s), not as "skip verification." The minimum enforced floor is 1s.

**Start-time-only health:** `audit_health` in `RouterState` is a snapshot taken at daemon startup — it does NOT update continuously. Post-startup breakage is not reflected in the in-RAM `AuditHealth`. Post-startup protection uses two mechanisms: (1) the `.chain-broken` sentinel (§12.10.8), set by any subsequent `verify_chain` caller, and (2) the write-site gate in `write_record_v2_impl` that reads the sentinel before every append.

**`Unknown` is as serious as `Broken`:** when `verify_chain` times out or its `spawn_blocking` task panics, the daemon cannot confirm chain soundness — the outcome MUST be logged at ERROR (not WARN) and `eprintln!` fired, identical to `Broken`. The operator must run `csq audit verify --full` to recover.

### 12.10.7 Historical-key degrade path

**The problem.** Without this path, `verify_chain` returned `Err(LedgerError::KeyNotFound)` for ANY record whose signing key was absent — including records signed by a HISTORICAL (rotated-out) key whose seed was legitimately lost after multiple rotations. The daemon treated this as fatal and refused to bind, coupling an audit-hygiene condition to all daemon availability.

**The invariant.** A missing CURRENT active signing key is a genuine integrity gate failure: new appends cannot be verified, the chain's security posture is unknown. It stays fatal. A missing HISTORICAL signing key is an audit-hygiene gap: chain-linking (prev_hash / canonical_hash / seq-monotonic) is still verified end-to-end across the gap, and only per-record Ed25519 signatures for records signed by the absent historical key are skipped. Insertion, reordering, or truncation of historical records is still detected because the chain-linking checks run over all records including across the gap.

**Access-vs-absence distinction in the per-record loop.** The per-record check loads each record's key file-first via `try_load_signing_key`. A keychain ACCESS error (present key, locked/ACL-blocked, no file copy) routes to `LedgerError::KeychainUnavailable { key_id }` (transient, `AuditHealth::Unknown`, no `.chain-broken` sentinel) — it is NOT treated as absence.

**Classification for genuine absence.** A record's `key_id` is GENUINELY ABSENT when it is not found in the active slot for `chain_id`, not found in any `historical/{0..=rotation_count}` slot, and not the placeholder key. When a non-placeholder record's `key_id` is genuinely unresolvable:

1. Load `chain_state.signing_key_id` (the current active key recorded in `chain.json`).
2. If `Some(active_id)` AND `active_id != record.key_id` → **historical gap candidate**: proceed to the topology check.
3. If `Some(active_id)` AND `active_id == record.key_id` → **current key missing**: return `Err(LedgerError::KeyNotFound)` (fatal).
4. If `None` → **unclassifiable**: fail closed with `Err(LedgerError::KeyNotFound)`.

**Topology enforcement.** The degrade path (classifying a gap and skipping signature verification) is ONLY safe when historical-key records form a contiguous PREFIX followed by a current-key-signed SUFFIX through to the HEAD. Two invariants are enforced:

- **Invariant A — Gaps must be a contiguous prefix.** The forward walk tracks a `seen_verified_signature` flag. Once any record's signature is verified by a present key, the flag is set. If a subsequent record classifies as a historical-gap candidate while the flag is `true` → FATAL `LedgerError::GapAfterVerifiedSegment { gap_seq, key_id }`. A gap after a verified record indicates either chain tampering (a forged record appended after the rotation boundary) or an invalid rotation order.
- **Invariant B — The HEAD must be current-key-signed.** After the loop, if the last gap's `last_seq == summary.head_seq`, the most-recent record in the verified window was a gap (signature skipped) → FATAL `LedgerError::HistoricalKeyAtHead { head_seq, key_id }`. A chain whose head is unverified provides no tamper-evidence for its most-recent records.

**Why these invariants are sound.** `prev_hash` and `canonical_hash` are collision-resistant SHA-256. A forged record inserted BETWEEN two genuine records breaks the next genuine record's `prev_hash` check (`ChainBroken` — fatal). A forged tail appended AFTER the last genuine record is caught by Invariant B. A forged prefix replacing all old-key records is caught by Invariant A from the moment the first current-key record is reached. An attacker who holds the LIVE current signing key can sign genuine forgeries regardless — that is the pre-existing same-user trust boundary, not this hole.

**`VerifySummary` extension.** `VerifySummary` carries `historical_key_gaps: Vec<KeyGap>`. Each `KeyGap` records `{ key_id: String, first_seq: u64, last_seq: u64, count: u64 }`. Only contiguous same-key records are merged into a single `KeyGap`; `count == last_seq - first_seq + 1` always holds.

**Daemon disposition.** When `historical_key_gaps` is empty, the chain verified clean. When non-empty (Invariants A and B passed), the daemon logs `audit_verify_historical_key_gap` WARN per gap and proceeds to socket bind. The `KeyNotFound` Err arm only fires for the current active key missing.

**CLI / doctor surface.** `csq audit verify` prints `DEGRADED-AUDIT(historical)` with per-gap detail; `--json` reports status `"partial_historical"` with a `historical_key_gaps` array (omitted when empty). `csq doctor` surfaces any gaps as `audit_historical_key_gaps` (shape `[{ key_id, first_seq, last_seq, count }]`, omitted when empty).

**Verification disposition by condition.**

| Condition                                                      | Error                                    | Behavior                                                                        |
| -------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------- |
| `ChainBroken` (prev_hash mismatch)                             | `LedgerError::ChainBroken`               | Fatal — daemon refuses to serve the audit subsystem                             |
| `InvalidSignature` (key IS present, sig fails)                 | `LedgerError::InvalidSignature`          | Fatal — a present key with a bad signature is a tamper signal                   |
| `IntegrityBroken` (seq gap, chain_id mismatch, corrupt format) | `LedgerError::IntegrityBroken`           | Fatal                                                                           |
| `UnsignedRecordAfterCutoff` (placeholder after cutoff)         | `LedgerError::UnsignedRecordAfterCutoff` | Fatal                                                                           |
| Keychain anchor disagreement                                   | `KeychainAnchorStatus::Mismatch`         | **Non-fatal DETECTOR** — loud ERROR log + `csq doctor` alarm; chain operational |
| Current active key absent                                      | `LedgerError::KeyNotFound`               | Fatal — cannot verify new appends                                               |
| Historical rotated-out key absent                              | `Ok(summary)` with `historical_key_gaps` | **Non-fatal** — degrade; proceed                                                |
| Historical gap record appears AFTER a sig-verified record      | `LedgerError::GapAfterVerifiedSegment`   | Fatal — Invariant A: gaps must be a prefix                                      |
| Historical gap record is the chain HEAD                        | `LedgerError::HistoricalKeyAtHead`       | Fatal — Invariant B: HEAD must be current-key-signed                            |

### 12.10.8 Unified signing contract

The writer and verifier MUST sign/check the SAME pre-image, the verifier MUST recompute `canonical_hash` rather than trust it, and the signature MUST cover content-derived bytes. One contract that the writer (`key_custody/rotate.rs` and any v2 signer) and the verifier (`verify.rs`) BOTH implement:

```
canonical_hash := sha256( canonical_bytes_for( record with canonical_hash := Sha256Hex::genesis() sentinel ) )
signature      := Ed25519_sign( privkey, hex::decode(canonical_hash) )   // the 32 RAW hash bytes, NOT the 64-char hex string, NOT a second sha256
```

**Verification, per record:**

1. **Recompute** `canonical_hash` from the record's content (clone, set `canonical_hash` to the genesis sentinel, `sha256(canonical_bytes_for(clone))`) and assert it equals the stored `canonical_hash`. Any mutated field — including `canonical_hash` itself — is caught here.
2. **Signature gate by cutoff** (§12.9.3): a record with `seq >= authoritative_cutoff` carrying the all-zeros placeholder key → `UnsignedRecordAfterCutoff` (REJECT). Pre-cutoff or `None` → placeholder tolerated.
3. **Verify the signature** for non-placeholder records: `verify_strict(pubkey, hex::decode(recomputed canonical_hash), signature)`. Because step 1 already bound `canonical_hash` to content, the signature authenticates the record's contents — not a stale attacker-supplied hash.

**Why sign the hash bytes rather than the canonical bytes directly:** the 32-byte SHA-256 is a fixed-size, content-derived digest; signing it (after the verifier independently recomputes it from content in step 1) is equivalent in strength to signing the full canonical bytes while keeping the signed payload bounded. The load-bearing invariant is step 1 — the verifier never trusts the record's self-reported hash.

The cutoff gate reads the authoritative cutoff from the file seed / keychain anchor (§12.9.4) via the read-only Step-0 resolution before the record loop, not from `chain.json` directly. `verify_chain` MUST NOT write to the keychain on any code path; cutoff establishment and format migration are write-path responsibilities (`audit_init`, `rotate_key`).

Test coverage: `verify_chain_accepts_valid_signature`, `verify_chain_rejects_tampered_signature`, `verify_chain_rejects_tampered_payload_via_canonical_hash`, `verify_chain_rejects_placeholder_key_after_cutoff`, `verify_chain_rejects_forged_head_record`, `test_verify_read_only_invariant`, `test_verify_delete_seed_entry_fails_closed`.

### 12.10.9 `.chain-broken` sentinel

The daemon's `audit_health` is a startup snapshot; CLI-side writers (`write_record_v2_impl`, used by op-emit, key-rotation, anchor) bypass the daemon entirely and need an independent gate. The `.chain-broken` sentinel file (`csq-runs/.chain-broken`) is the cross-process mechanism.

**File location:** `<base_dir>/csq-runs/.chain-broken` — co-located with `.chain-lock`.

**Content:** the fixed-vocabulary `error_kind` string from `AuditHealth::Broken.error_kind` (e.g. `"audit_invalid_signature"`). Written via the atomic-write pattern (tmp → `secure_file(0o600)` → `atomic_replace`).

**Setters** — every `verify_chain` caller that classifies the chain as `Broken` MUST call `set_chain_broken(base_dir, error_kind)`. `Unknown` (timeout or `spawn_blocking` panic) MUST NOT set the sentinel — it is transient; setting a durable sentinel on a one-time timeout would permanently block lifecycle ops until the operator manually clears the file. Setter sites: `csq/src/cli/commands/daemon.rs`, `csq/src/cli/commands/audit.rs`, `csq/src/cli/commands/doctor.rs`, `csq/src/desktop/daemon_supervisor.rs`.

**Clearers** — every `verify_chain` caller that classifies the chain as `Verified` or `Degraded` MUST call `clear_chain_broken(base_dir)` (same four sites). `Unknown` MUST leave the sentinel unchanged. The in-RAM `AuditHealth::Unknown` still gates the daemon's IPC endpoint (`is_operational()` returns `false`) for the lifetime of that daemon process, providing in-process protection without the durable false-alarm lockout.

**Write-site gate:** `write_record_v2_impl` (`csq-core/src/audit/persist.rs`) reads `is_chain_broken(base_dir)` INSIDE the `.chain-lock` critical section (before seq assignment). If `Some(kind)` is returned, the write returns `AuditV2Error::ChainBrokenRefuseAppend { error_kind: kind }` immediately. An unreadable sentinel (permissions, I/O error) is treated as `Some("audit_sentinel_unreadable")` — fail-closed.

**`LedgerError::Io` routing:** `verify_chain` returns `Ok(default)` for a genuinely absent chain (no `csq-runs/` directory). An `Io` error therefore always means real corruption or permission failure — it maps to `AuditHealth::Broken`, not `Unknown`.

### 12.10.10 Implementation surface

- `csq-core/src/audit/verify.rs` — `verify_chain`, `VerifyConfig`, `VerifySummary`, `VerifyJsonOutput`, `exit_code_for_error`, `to_json_output`, `resolve_authoritative_cutoff`, `KeychainAnchorStatus`, `emit_anchor_status`
- `csq-core/src/audit/health.rs` — `AuditHealth`, `from_ledger_error`, `from_verify_result`, `set_chain_broken`, `clear_chain_broken`, `is_chain_broken`
- `csq-core/src/audit/persist.rs` — `write_record_v2_impl` sentinel gate; `AuditV2Error::ChainBrokenRefuseAppend`
- `csq-core/src/audit/types.rs` — `LedgerError` variants
- `csq-core/src/daemon/server.rs` — `RouterState::audit_health`; `audit_record_handler` health-first gate
- `csq/src/cli/commands/daemon.rs` — pre-bind wiring; sentinel set/clear; anchor gate
- `csq/src/cli/commands/audit.rs` — `handle_verify` handler; sentinel set/clear
- `csq/src/cli/commands/doctor.rs` — `check_audit_chain`; sentinel set/clear; text-mode audit-chain line
- `csq/src/desktop/daemon_supervisor.rs` — desktop verify block; sentinel set/clear; anchor gate
- `csq/src/cli/mod.rs` — `AuditCmd::Verify` variant + `DaemonCmd::Start.audit_verify_limit` flag

## 12.11 Cross-references

- **Spec 04 — csq Daemon Architecture** (`04-csq-daemon-architecture.md`): daemon startup sequencing, the verify-before-bind contract, sweep/drain scheduling (§4.2.8).
- **Spec 07 — Provider Surface Dispatch** (`07-provider-surface-dispatch.md`): the surface enum (`cc` / `codex` / `gemini`) recorded in the v1 `surface` field.
- **Spec 15 — LedgerSink Trait and Reference-Impl Catalog** (`15-ledgersink-trait-and-sinks.md`): the `LedgerSink` extension point for optional external anchoring, operator config (`audit.sink`, cadence), and the conformance harness.

## Revisions

- 1.41.0 — Current consolidated spec: v1 JSONL + v2 chain-linked records, single audited write site, csq-cli emit/drain contract, retention/sweep, the audit-trait abstraction layer, local Ed25519 signing-key custody (file-mirror + keychain-anchor DETECTOR), chain-integrity verification at daemon start, the `csq audit verify` / `csq doctor` surfaces, the `.chain-broken` sentinel, the historical-key degrade path, and the four-level verification gradient.
