# csq-ledger — Foundation-Owned Transparency Log (operator guide)

`csq-ledger` is a self-hostable, Foundation-owned transparency-log server. It
gives csq operators a Foundation-blessed default for **external anchoring** of
their audit chain — no Sigstore/AWS/Azure/GCP upstream dependency required in
the recommended path. It stores `SignedRecord`s in an append-only log, serves
RFC 6962 Merkle inclusion proofs, and publishes a signed tree head
(checkpoint).

**csq-ledger is INTERNAL-ONLY.** It is never exposed to the public internet —
not directly, and not behind a reverse proxy either. Deploy it inside your own
trusted network, reachable only by the csq daemons and verifiers that live
there. This is enforced structurally, not left to a deployment note: revoke
and verifier-bootstrap redemption are served from a SEPARATE listener that
defaults to loopback-only (see "Two listeners" below).

This guide covers Docker deployment, environment variables, wiring csq to
anchor here, monitoring, the **threat model** (read this before deciding your
compliance posture), and the recommended write-once-storage deploy patterns.

Protocol authority: [`specs/17-csq-ledger-protocol.md`](../../specs/17-csq-ledger-protocol.md).

---

## What it is (and is not)

csq-ledger is a **single-instance** transparency log. It is:

- **Tamper-evident** — any mutation of a logged record breaks its inclusion
  proof against every checkpoint issued after it was logged.
- **Tamper-resistant against external attackers** — an attacker who does not
  control the server cannot forge a record into the log or alter one without
  detection.
- **Append-only by construction** — the storage layer exposes no delete,
  truncate, compact, vacuum, or garbage-collection operation. Once a submit
  returns HTTP 200, the bytes that produced the inclusion proof are append-only
  forever from csq-ledger's perspective.
- **Internal-only** — designed to run inside your trusted network, never on
  the public internet. There is no per-request authentication; the boundary is
  which listener a caller can reach, not an in-process check (see "Two
  listeners" below).

It is **NOT**, on its own:

- **Tamper-proof against the operator who runs it.** The operator controls the
  binary, the storage, the clock, and the signing key. A single-instance log
  cannot defend against the party who runs it — that requires the two
  strengthening layers below (WORM storage + anchor-to-sink), and ultimately
  cross-witness gossip (Phase B/C).

The **Threat model** section below states exactly what each layer defends
against. Treat it as load-bearing: deploying csq-ledger while believing it is
"tamper-proof" out of the box is the failure this document exists to prevent.

---

## Docker deployment

### Pull + run (single instance)

```bash
docker run -d \
  --name csq-ledger \
  -v /var/lib/csq-ledger:/data \
  -p 8080:8080 \
  ghcr.io/terrene-foundation/csq-ledger:latest

# Confirm it is serving:
curl http://localhost:8080/v1/health
# {"status":"ok","tree_size":0,"signing_key_warning":"auto-generated signing key ..."}
```

The published image is `ghcr.io/terrene-foundation/csq-ledger:<version>`
(GHCR). A future migration to a Foundation-owned registry
(`registry.terrene.foundation`) is a Foundation-ops decision; M10 ships against
GHCR.

**Only port 8080 (read/write) is published above — this is intentional.** The
authority listener binds `127.0.0.1:8081` by default; even publishing
`-p 8081:8081` would NOT make it reachable from the host, because a
loopback-bound process inside a container is only reachable from within that
container's own network namespace. To revoke or redeem a verifier bootstrap,
either `docker exec` into the container and call `127.0.0.1:8081` from there,
or explicitly set `CSQ_LEDGER_AUTHORITY_BIND=0.0.0.0`, publish `8081`, and put
your own network control (firewall, separate VLAN) in front of it.

### docker-compose

A minimal single-instance example ships at
[`csq-ledger/docker-compose.yml`](../../csq-ledger/docker-compose.yml):

```bash
docker compose -f csq-ledger/docker-compose.yml up -d
```

### Build locally

```bash
# From the workspace root (the build context must be the workspace root so the
# path-dependency on csq-core resolves):
docker build -f csq-ledger/Dockerfile -t csq-ledger:local .
```

The image is a multi-stage build: a Rust builder compiles the release binary,
then a `gcr.io/distroless/cc-debian12:nonroot` runtime carries only the binary
(no shell, no package manager — minimal attack surface). It runs as uid 65532
(`nonroot`); the mounted volume must be writable by that uid:

```bash
sudo chown -R 65532:65532 /var/lib/csq-ledger
```

---

## Environment variables

| Variable                      | Default               | Purpose                                                                                                         |
| ----------------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------- |
| `CSQ_LEDGER_DATA_DIR`         | `/var/lib/csq-ledger` | Data directory (segment files, size marker, anchors, signing key).                                              |
| `CSQ_LEDGER_PORT`             | `8080`                | TCP port for the READ/WRITE listener.                                                                           |
| `CSQ_LEDGER_BIND`             | `0.0.0.0`             | Bind address for the READ/WRITE listener. Reachable within your internal network; never expose it publicly.     |
| `CSQ_LEDGER_AUTHORITY_PORT`   | `8081`                | TCP port for the AUTHORITY listener (revoke, verifier-bootstraps).                                              |
| `CSQ_LEDGER_AUTHORITY_BIND`   | `127.0.0.1`           | Bind address for the AUTHORITY listener. Loopback-only by default — widening it is an explicit operator choice. |
| `CSQ_LEDGER_SIGNING_KEY_PATH` | _(unset)_             | Path to an operator-provisioned signing key. Setting it clears the first-boot WARN.                             |

CLI flags mirror the env vars (`--data-dir`, `--port`, `--bind`,
`--authority-port`, `--authority-bind`) plus the anchor flags
(`--anchor-to-sink`, `--anchor-cadence`).

### Two listeners: read/write and authority (H3)

csq-ledger binds and serves TWO independent HTTP listeners from one process:

- **Read/write** (`--bind`/`--port`) — submit, get-entry (+ tenant-bound
  verdict), checkpoint, health. Reachable wherever your internal network
  places it.
- **Authority** (`--authority-bind`/`--authority-port`) — revoke and
  verifier-bootstrap redemption ONLY, **loopback-only by default**. Revocation
  is permanent (there is no un-revoke), so any principal that can reach it can
  permanently deny any anchor for any tenant. The read/write listener's router
  never registers these two routes at all — a request to either on the
  read/write port gets a plain 404, not a permission check.

If you need to reach the authority listener from another host (e.g. a
dedicated revocation console), widen `--authority-bind` explicitly and put
your own network control (firewall rule, separate VLAN, bastion) in front of
it — that is additive to, not a substitute for, the listener split.

### First-boot signing key (read this)

On first boot with `CSQ_LEDGER_SIGNING_KEY_PATH` unset, csq-ledger:

1. Generates a random Ed25519 keypair.
2. Writes the private key to `<data_dir>/signing-key.pem` at mode `0o600`.
3. Logs a prominent WARN to stderr **and** surfaces it via `GET /v1/health`,
   **on every boot**, until `CSQ_LEDGER_SIGNING_KEY_PATH` is explicitly set.

```
WARN [csq-ledger] auto-generated signing key in use — BACK UP <data_dir>/signing-key.pem.
     If lost, checkpoints become unverifiable on restart and operator csq installs
     anchored to this ledger fail with KeyId mismatch. To use an operator-provisioned
     key (HSM, KMS, etc.), set CSQ_LEDGER_SIGNING_KEY_PATH and restart.
```

**Back up `signing-key.pem`.** If you lose it, every checkpoint this ledger ever
issued becomes unverifiable, and every csq install anchored here fails with a
KeyId mismatch. Once you have reviewed and backed up the key, set
`CSQ_LEDGER_SIGNING_KEY_PATH` (even pointing at the same auto-generated file) —
that explicit set is your acknowledgement, and it clears the WARN.

For higher assurance, provision the key from an HSM or KMS export and point
`CSQ_LEDGER_SIGNING_KEY_PATH` at it.

---

## HTTP API

| Listener   | Method | Path                                         | Purpose                                                                                                                                                                                                        |
| ---------- | ------ | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| read/write | POST   | `/v1/log/entries`                            | Submit a `SignedRecord`. Returns `{inclusion_proof, log_index, checkpoint_at_submit}` **after the record is fsync'd to disk**.                                                                                 |
| read/write | GET    | `/v1/log/entries/{id}`                       | Retrieve a record by `record_id` + its current inclusion proof. `?tenant_id=<id>` also returns a fresh Ed25519-signed anchor verdict bound to that record, tenant, checkpoint, expiry, and monotonic version.  |
| authority  | POST   | `/v1/log/entries/{id}/revoke?tenant_id=<id>` | Authority-only permanent revocation for a record/tenant pair. Returns a signed revocation; future tenant-bound verdicts deny. Idempotent: replaying it for an already-revoked pair returns the identical fact. |
| authority  | POST   | `/v1/log/verifier-bootstraps/{id}`           | Redeem one durable bootstrap for a verifier namespace. Body: a fresh 64-hex challenge; 201 returns its signed challenge-bound receipt and any later redemption returns 409.                                    |
| read/write | GET    | `/v1/checkpoint`                             | Current signed tree head: `{tree_size, root_hash, signed_by_key_id, public_key, signature, anchored_to?}`.                                                                                                     |
| read/write | GET    | `/v1/health`                                 | `{status, tree_size, signing_key_warning?}`.                                                                                                                                                                   |

There is **no per-request authentication** in this release. The access-control
boundary is which listener a caller can reach (see "Two listeners" above) —
csq-ledger is internal-only end to end, never fronted for public-internet
access. The server is the storage + proof primitive, not an internet-facing
access-control plane.

`POST /v1/log/entries/{id}/revoke` is served ONLY by the authority listener,
loopback-only by default. The service does not accept a caller-provided status
or private key. For `GET` verdicts, clients must pin `signed_by_key_id`,
verify the signature and binding to their expected record and tenant, require
a fresh `expires_at`, persist the greatest version they accepted, reject a
non-increasing version, and deny `status: "revoked"`.

`POST /v1/log/verifier-bootstraps/{id}` is served by the same authority
listener. A consumer that needs durable local replay tracking supplies a stable
operator-provisioned verifier id and a new random challenge for each attempt,
then creates its local state only after pin-verifying the matching signed 201
receipt. Once consumed, the CSQ-side append-only record returns 409 forever;
deleting every local consumer file cannot recreate bootstrap authority.

`POST /v1/log/entries` returns HTTP 200 **only after** the record's storage
write has been fsync'd to disk. If the server 200s, the record is durable: a
crash immediately afterward does not lose it. There is no flag to skip the
fsync.

---

## Wiring csq to anchor here

Build csq-core (or csq) with the `csq-ledger-sink` feature and point it at your
ledger:

```bash
# Rebuild csq with the csq-ledger sink compiled in:
cargo build --release -p csq --features cli,csq-core/csq-ledger-sink --no-default-features

# Configure csq to anchor to this ledger:
csq audit config-sink csq-ledger
csq config set audit.csq-ledger.url https://ledger.your-org.example
```

csq's daemon then anchors its audit records to your ledger via the M07
`LedgerSink` trait. Each anchored record gets an inclusion proof from the
ledger; csq stores the receipt alongside its local chain entry.

---

## Anchoring csq-ledger ITSELF to an external witness (Strengthening 1)

A single csq-ledger instance cannot defend against the operator who runs it
(see Threat model). To get tamper-resistance against the operator, configure
csq-ledger to anchor **its own checkpoint** to an external sink at a cadence:

```bash
# The binary must be built with the matching anchor feature, e.g.:
cargo build --release -p csq-ledger --features anchor-rekor

# Then run with the anchor flags:
csq-ledger --data-dir /var/lib/csq-ledger \
  --anchor-to-sink rekor \
  --anchor-cadence 86400        # seconds; default 86400 = 1/day
```

When configured, csq-ledger periodically submits its signed checkpoint to the
named M07 sink (`rekor`, `s3`, `azure`, `gcp`, or another csq-ledger instance
run by a different party). The sink's receipt is stored back in csq-ledger's
own log AND surfaced via `GET /v1/checkpoint`'s `anchored_to` field. **Operators
who want tamper-resistance against themselves MUST configure this.**

csq-ledger ships with **no default anchor target** — there is no
Sigstore-upstream coupling. You pick the witness that serves your compliance
posture. Three options, with no Foundation "blessed default" stamp on any one:

- **A public Sigstore Rekor instance** (`--anchor-to-sink rekor`) —
  operationally simplest; reintroduces some Sigstore-recommendation footprint.
- **An S3 Object Lock bucket you already operate** (`--anchor-to-sink s3`) —
  assumes you run AWS.
- **A second csq-ledger instance run by a peer organization** (auditor,
  customer, business partner) — a true cross-organizational witness, but
  requires coordination.

Cadence tradeoff: the default `1d` gives a 24-hour tamper-detection window
between routine anchors. Tighten it (e.g. `--anchor-cadence 3600` for hourly)
when your compliance requires a shorter window, at the cost of more external-
sink load.

**Anchor integrity labeling (`anchored_to.unverified`).** The `anchored_to`
object on `GET /v1/checkpoint` carries an `unverified` boolean (security-L1):

- `unverified: false` — the sink returned an **inclusion proof** (e.g. Rekor).
  The checkpoint was witnessed WITH proof.
- `unverified: true` — the sink returned **no proof**, only an acknowledgement
  (e.g. a WORM object store that confirms storage but issues no Merkle proof).
  The checkpoint was witnessed ON TRUST — you have the sink's word, not a proof.

In M10 this flag reflects proof PRESENCE only; csq-ledger does NOT yet
cryptographically verify that a returned proof commits to the anchored
checkpoint's record_id/root (that is Phase B, sink-dependent). An operator
relying on `unverified: false` for compliance should still independently verify
the proof against the sink until Phase-B verification ships. A stored receipt
that predates the flag is reported as `unverified: true` (fail-safe).

---

## Threat model

This is the load-bearing section. Each layer below names exactly what it
defends against and what it does **not**. Read all four before deciding your
deployment.

### Layer 1 — csq-ledger alone

**Defends against:** external attackers (anyone who does not control the
server). The log is tamper-evident: any mutation, deletion, or reordering of a
logged record breaks its RFC 6962 inclusion proof against every checkpoint
issued after it was logged. A submitter who receives a 200 receives a durable,
proof-backed commitment (fsync-before-200). Domain-separated leaf/interior
hashing (RFC 6962 §2.1) defeats second-preimage attacks.

**Does NOT defend against:** the operator who runs the server. The operator
controls the binary, the storage bytes, the system clock, and the signing key.
They can stop the server, edit the storage files at the filesystem level (the
write-once invariant is enforced by csq-ledger's code, not by the kernel), and
restart with a re-derived tree. A single-instance log structurally cannot
defend against its own operator.

### Layer 2 — csq-ledger + write-once (WORM) storage

**Adds defense against:** operator-side **deletion / rewrite of the storage**.
csq-ledger's storage layer never deletes or overwrites a record (the code has
no delete/truncate/compact/vacuum/wipe/prune/gc operation). But that is a code
invariant — an operator with root could still `rm` the segment files directly.
Mounting the data volume on **write-once media** moves the no-rewrite guarantee
from csq-ledger's code into the kernel / cloud provider, which the operator
cannot override even with root:

- **AWS S3 Object Lock (compliance mode)** — objects cannot be deleted or
  overwritten until the retention period expires, not even by the account root.
  Back the data volume with an S3-backed CSI driver in compliance mode.
- **Azure Immutable Blob Storage (time-based retention, locked policy)** — once
  the policy is locked, blobs are immutable for the retention window.
- **GCP Cloud Storage Bucket Lock + retention policy** — a locked retention
  policy prevents deletion/overwrite for the retention period.
- **On-prem Linux `chattr +a`** — the append-only attribute on the data
  directory's files prevents truncation/rewrite; only root can clear the
  attribute, so combine with a separate-admin-account control.

**Does NOT defend against:** an operator who **rewrites the whole log from
scratch** before anchoring it anywhere external. WORM stops in-place edits; it
does not stop "throw away everything and start a new clean log" if no external
party has witnessed the old one.

### Layer 3 — csq-ledger + WORM + anchor-to-sink

**Adds defense against:** operator-side **rewrite of the whole log**. When
csq-ledger anchors its signed checkpoint to an external sink the operator does
not control (a public Rekor instance, an S3 Object Lock bucket owned by a
different team, or a peer organization's csq-ledger), tampering now requires the
operator to **simultaneously**:

1. Rewrite the WORM-locked storage (which the cloud provider / kernel enforces
   against), AND
2. Rewrite the external sink's record of the csq-ledger checkpoint (which the
   operator does not control).

That combination is compliance-grade for **SOC 2 / ISO 27001 / NIST SP 800-53
AU-9(3)** (protection of audit information against unauthorized modification).

**Does NOT defend against:** **collusion** between the operator and the external
sink operator. If the same party controls both csq-ledger and the sink, the
external witness is not independent and the rewrite becomes possible again.

### Layer 4 — cross-witness gossip (Phase B/C — NOT in this release)

**Would add defense against:** operator + single-sink collusion, by requiring
**≥2 independent witnesses** to co-sign checkpoints (a majority-compromise
threshold). This needs a witness protocol design and at least two independent
witnesses operating — both are Phase B/C work and are explicitly **out of scope
for this release**. Do not deploy csq-ledger believing you have collusion
resistance today; you have Layers 1–3.

### Summary

| Layer | Adds defense against                         | Residual gap                           |
| ----- | -------------------------------------------- | -------------------------------------- |
| 1     | External attackers (tamper-evidence)         | The operator who runs the server       |
| 2     | Operator-side storage deletion/rewrite       | Operator full-log rewrite (no witness) |
| 3     | Operator-side full-log rewrite               | Operator + sink-operator collusion     |
| 4     | Operator + single-sink collusion (Phase B/C) | Majority-of-witnesses compromise       |

---

## Monitoring

- Poll `GET /v1/health` from your monitoring system. A non-200 or a stalled
  `tree_size` (when you expect anchoring traffic) is the alert signal.
- While `signing_key_warning` is present in the `/v1/health` body, the server is
  running on an unacknowledged auto-generated key — back it up and set
  `CSQ_LEDGER_SIGNING_KEY_PATH`.
- When `--anchor-to-sink` is configured, watch `GET /v1/checkpoint`'s
  `anchored_to` field: it should advance roughly every `--anchor-cadence`
  seconds. A stale `anchored_to.anchored_at` means anchoring is failing (check
  the sink's reachability and the server logs for `checkpoint anchor attempt
failed`).

---

## Cross-references

- [`specs/17-csq-ledger-protocol.md`](../../specs/17-csq-ledger-protocol.md) —
  the protocol authority (routes, checkpoint contract, RFC 6962 proof format,
  fsync-before-200 + no-delete invariants, anchor cadence, WORM recommendation).
- [`specs/15-ledgersink-trait-and-sinks.md`](../../specs/15-ledgersink-trait-and-sinks.md) —
  the `LedgerSink` trait `CsqLedgerSink` implements and that `--anchor-to-sink`
  consumes.
- [`docs/audit-sinks/rekor.md`](rekor.md),
  [`docs/audit-sinks/s3.md`](s3.md),
  [`docs/audit-sinks/azure.md`](azure.md),
  [`docs/audit-sinks/gcp.md`](gcp.md) — the M07 sinks usable as anchor targets.
