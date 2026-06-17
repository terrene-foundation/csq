# Spec 15 — LedgerSink Trait and Reference-Impl Catalog

**Spec version:** 4
**Status:** Active

---

## §15.1 Scope

This spec governs the `LedgerSink` trait, the reference-impl catalog, operator configuration, the conformance harness, and the `csq doctor` sink surface. It is the authority on all external-anchoring behavior.

External anchoring is the optional mechanism by which csq replicates its local audit chain (spec 12) to an external, append-only witness — a transparency log or immutable object store — so that the chain's tamper-evidence does not rest on the operator's machine alone. csq ships local-only by default; external anchoring is strictly opt-in.

---

## §15.2 Trait Surface

`LedgerSink` is defined at `csq-core/src/audit/traits.rs`. It has **exactly three methods**:

```rust
#[async_trait]
pub trait LedgerSink: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError>;
    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError>;
}
```

Adding a 4th method is BLOCKED. Future capabilities land as sibling traits (`trait HealthCheckableSink: LedgerSink`, `trait BatchSink: LedgerSink`), not by widening this trait. Every additional method is a place a sink impl can violate contract.

### §15.2.1 Bounds

`Send + Sync + 'static` — required so the daemon can hold a sink behind `Arc<dyn LedgerSink>` and share it across tokio tasks without external locking.

### §15.2.2 Supporting Types

Types consumed by the trait surface are defined in `csq-core/src/audit/types.rs` (full contracts in spec 12 §12.7.2):

| Type           | Description                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------- |
| `SignedRecord` | The on-disk schema-v2 chain record (spec 12).                                                |
| `RecordId`     | Stable per-record identifier (ULID or UUIDv7).                                               |
| `SinkReceipt`  | Returned by `append` — carries `sink`, `sink_id`, `anchored_at`, optional `inclusion_proof`. |
| `SinkError`    | `#[non_exhaustive]` error enum: `Rejected`, `Unreachable`, `Drift`, `NotFound`, `Internal`.  |

---

## §15.3 Default Posture: Local-Only

**csq ships local-only by default.** No external sink is wired into the default build. The `audit.sink` config key defaults to `"none"`.

Operators opt in by:

1. Rebuilding with `--features <sink>-sink`.
2. Setting `csq audit config-sink <name>`.

---

## §15.4 Reference-Impl Catalog

| Impl                     | Feature flag      | Module                                        | Target substrate            |
| ------------------------ | ----------------- | --------------------------------------------- | --------------------------- |
| `RekorSink`              | `rekor-sink`      | `csq-core/src/audit/impls/sinks/rekor.rs`     | Sigstore Rekor              |
| `S3ObjectLockSink`       | `s3-sink`         | `csq-core/src/audit/impls/sinks/s3.rs`        | AWS S3 Object Lock          |
| `AzureImmutableBlobSink` | `azure-sink`      | `csq-core/src/audit/impls/sinks/azure.rs`     | Azure Immutable Blob        |
| `GcpBucketLockSink`      | `gcp-sink`        | `csq-core/src/audit/impls/sinks/gcp.rs`       | GCP Bucket Lock             |
| `AzureSqlLedgerSink`     | `azure-sql-sink`  | `csq-core/src/audit/impls/sinks/azure_sql.rs` | Azure SQL ledger tables     |
| `CsqLedgerSink`          | `csq-ledger-sink` | `csq-core/src/audit/impls/csq_ledger_sink.rs` | Foundation-owned csq-ledger |

### §15.4.1 CsqLedgerSink

`CsqLedgerSink` (gated `--features csq-ledger-sink`) anchors a csq audit chain
to a Foundation-owned `csq-ledger` transparency-log server: `append` POSTs the
`SignedRecord` to `/v1/log/entries`, `verify_at` GETs it from
`/v1/log/entries/{id}`, `name()` returns `"csq-ledger"`. It is NOT on the
default csq-core code path — `csq-ledger-sink` is a `[features]` flag (not a
default dependency), and the `reqwest` client it uses is invoked only under that
feature. It passes the conformance harness
(`ledger_sink_conformance_csq_ledger` in `csq-core/tests/sink_conformance.rs`)
via an in-memory mock transport.

The `csq-ledger` SERVER (the substrate this sink targets) is a separate
workspace crate; its full protocol — HTTP routes, RFC 6962 inclusion proofs,
signed checkpoints, fsync-before-200, write-once-storage invariant,
`--anchor-to-sink` strengthening, and threat model — is specified in
**spec 17 (csq-ledger Transparency-Log Protocol)**. Operator guide:
`docs/audit-sinks/csq-ledger.md`.

`csq-ledger` is the Foundation-blessed external-anchoring target: a
self-hostable, append-only transparency log with no Sigstore / AWS / Azure /
GCP upstream dependency in the recommended path. It is the canonical answer for
an operator who wants external anchoring without a cloud-provider account.

### §15.4.2 Mock Substrate Policy

Every reference impl uses an in-memory mock substrate rather than a live SDK in
its conformance test. This proves the trait contract (append/verify round-trip)
and the cfg-gating discipline in CI without cloud credentials. Operators harden
for production by replacing the mock with the SDK client as documented in
`docs/audit-sinks/<sink>.md`.

---

## §15.5 cfg-Gating Discipline

No external-sink crate appears on the default code path, and no external-sink
import appears outside its feature gate. This is enforced mechanically:

```bash
# No external-sink crate on the default code path:
grep -E '^(sigstore|sigstore-rekor|aws-sdk-s3|azure-storage|google-cloud-storage|tiberius)' \
  csq-core/Cargo.toml | grep -v 'optional = true'
# Expected: 0 matches

# No external-sink imports outside feature gates:
grep -rn 'use sigstore\|use aws_sdk_s3\|use azure_storage\|use google_cloud_storage\|use tiberius' \
  csq-core/src --include='*.rs'
# Expected: 0 matches outside #[cfg(feature = "...")] blocks

# No production NoopSink:
grep -rn 'NoopSink' csq-core/src --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v '#\[cfg(any(test'
# Expected: 0 production callsites (only noop.rs definitions and comments)
```

---

## §15.6 Operator Configuration

Configuration file: `~/.claude/accounts/audit-sink.json`

### §15.6.1 Keys

| Key                          | Type   | Default  | Description                                                  |
| ---------------------------- | ------ | -------- | ------------------------------------------------------------ |
| `sink`                       | string | `"none"` | Active sink name.                                            |
| `<sink>.cadence`             | string | varies   | Regular replication cadence (`"1d"`, `"6h"`, `"immediate"`). |
| `<sink>.cadence_high_impact` | string | varies   | Cadence for key rotation, release auth, etc.                 |
| `<sink>.fail_loud`           | bool   | `false`  | When `true`, sink failures block csq operations.             |

### §15.6.2 Per-Sink Cadence Defaults

| Sink        | cadence | cadence_high_impact |
| ----------- | ------- | ------------------- |
| `rekor`     | `1d`    | `immediate`         |
| `s3`        | `1d`    | `1d`                |
| `azure`     | `1d`    | `1d`                |
| `gcp`       | `1d`    | `1d`                |
| `azure-sql` | `1d`    | `1d`                |

Operator override: `csq audit config-cadence <sink> cadence <value>`

### §15.6.3 CLI Surface

```bash
csq audit config-sink             # print current sink
csq audit config-sink rekor       # set sink to rekor
csq audit config-sink none        # revert to local-only
csq audit config-cadence rekor cadence 6h
csq audit config-cadence rekor cadence-high-impact immediate
csq audit config-cadence rekor fail-loud true
```

### §15.6.4 Fail-Loud on Not-Compiled-In Sink

When an operator sets `audit.sink = <name>` for a sink whose feature flag was not compiled in, csq fails with the canonical error:

```
csq: requested sink '<name>' was not compiled into this build.
Rebuild with --features <name>-sink or install a csq release that includes it.
```

This is enforced at `csq audit config-sink` time, NOT at daemon start time, so operators get immediate feedback.

---

## §15.7 Conformance Harness

Location: `csq-core/tests/sink_conformance.rs`

Contract: every `LedgerSink` reference impl MUST pass `append(r); verify_at(r.id) == r` for every record `r` in the fixed 5-record corpus.

Running:

```bash
# Default (NoopSink conformance only):
cargo test --features csq-core/test-utils -p csq-core --test sink_conformance

# Rekor feature-on path:
cargo test --features csq-core/test-utils,csq-core/rekor-sink -p csq-core --test sink_conformance
```

New reference impls MUST land their feature flag wired into CI and a conformance test in `sink_conformance.rs`. The Tier-2 sinks (S3 / Azure Blob / GCP / Azure SQL) additionally carry per-sink retry-safety + failure-surfaced conformance assertions.

---

## §15.8 `csq doctor` Sink Surface

When `audit.sink != "none"`, `csq doctor` renders:

```
  Audit sink:    ✓ rekor — last anchor: 2026-05-29T00:00:00+00:00
```

With pending or drift events:

```
  Audit sink:    ⚠ rekor — last anchor: 2026-05-28T00:00:00+00:00 (pending: 3, drift: 0)
```

JSON shape (`csq doctor --json`):

```json
{
  "audit_sink": {
    "active_sink": "rekor",
    "last_anchor_ts": "2026-05-29T00:00:00+00:00",
    "pending_count": 0,
    "replication_drift_count": 0
  }
}
```

When `audit.sink = "none"` (default), the `audit_sink` field is absent from the JSON output.

---

## §15.9 Sink Failure Posture

**Sink failures NEVER block csq operations by default.** Each sink has its own `.pending-<sink>/` directory under `~/.claude/accounts/` that queues failed records for daemon drain.

Fail-loud is opt-in: `csq audit config-cadence <sink> fail-loud true`.

---

## §15.10 Multi-Sink Extension Path

One sink is active per install today. The `LedgerSink` trait surface is forward-compatible with a future `MultiSink` wrapper:

```rust
struct MultiSink {
    sinks: Vec<Box<dyn LedgerSink>>,
}
#[async_trait]
impl LedgerSink for MultiSink {
    fn name(&self) -> &str { "multi" }
    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        // broadcast to all sinks; collect receipts
    }
    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        // check all sinks; return first Ok or Drift if any disagree
    }
}
```

`MultiSink` is NOT built today. This section documents the extension path for a future milestone that ships it.

---

## §15.11 Anchor Driver

The periodic daemon task that anchors the chain head to the active sink lives at `csq-core/src/daemon/anchor_task.rs`. The pure anchoring logic lives at `csq-core/src/audit/anchor.rs`. Full contract documented in spec 12 §12.18.

Key invariants from this spec's perspective:

- Anchoring works by submitting the chain HEAD `SignedRecord` to the active `LedgerSink` via `append` — there is NO new `EventKind`; the HEAD's `canonical_hash` is the anchored hash and its `seq` is the anchored sequence. The anchor driver uses only `append` and `name` from the three-method surface (§15.2).
- The outcome is recorded back into the chain as a `replication_ack` (or `replication_failed`) record, and the anchor-attempt timestamp is recorded locally in `anchor-state-<sink>.json` (`last_anchor_ts`), NOT transmitted to the witness.
- The anchor driver reads cadence from `AuditSinkConfig.cadence_for(sink_name)` (§15.6.2).
- The `anchor-state-<sink>.json` state file's `last_anchor_ts` and `replication_drift_count` are the values surfaced by `csq doctor` (§15.8).
- Anchor failure is NEVER fail-loud by default — the `fail_loud` field in `SinkCadenceConfig` is an operator opt-in (§15.9). A failed anchor increments `replication_drift_count` (surfaced by `csq doctor`); silent discard is BLOCKED.

---

## §15.12 Cross-References

- **Spec 12 — csq Audit Trail** (`12-audit-trail.md`): the Tier-1 local hash chain this spec extends with Tier-2 external anchoring. §12.18 documents the anchor driver contract; §12.7 documents the trait abstraction layer.
- **Spec 16 — Audit Export Bundle** (`16-audit-export-bundle.md`): the self-contained verifiable bundle; the Rekor sink powers the bundle's `--rekor` entry-existence check.
- **Spec 17 — csq-ledger Transparency-Log Protocol** (`17-csq-ledger-protocol.md`): the Foundation-owned log server that `CsqLedgerSink` targets.
- `csq-core/src/audit/traits.rs` — `LedgerSink` trait definition.
- `csq-core/src/audit/sink_config.rs` — operator config layer.
- `csq-core/src/audit/anchor.rs` — pure anchoring logic + state-file writer.
- `csq-core/src/daemon/anchor_task.rs` — daemon tokio periodic loop.
- `csq-core/src/audit/impls/sinks/` — reference-impl catalog.
- `csq-core/tests/sink_conformance.rs` — conformance harness.
- `docs/audit-sinks/` — per-sink operator guides.

---

## Revisions

| Version | Change                                                                                                                                                                                                                                                                                                                |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1       | Initial spec: `LedgerSink` trait + reference impls.                                                                                                                                                                                                                                                                   |
| 2       | Anchor driver contract (§15.11).                                                                                                                                                                                                                                                                                      |
| 3       | `AzureSqlLedgerSink` (`azure-sql-sink`) added to the catalog (§15.4) + cadence table (§15.6.2) + config wiring (`RECOGNISED_SINK_NAMES`, `validate_sink_compiled_in`, `cadence_for`); per-sink retry-safety + failure-surfaced conformance assertions added for all Tier-2 sinks (S3 / Azure Blob / GCP / Azure SQL). |
| 4       | Cross-reference + section-numbering cleanup; anchor driver section renumbered to §15.11.                                                                                                                                                                                                                              |
