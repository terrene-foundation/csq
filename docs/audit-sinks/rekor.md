# Rekor Sink Operator Guide

**Feature flag:** `--features rekor-sink`
**Sink name:** `rekor`
**Target:** Sigstore Rekor transparency log (public instance or self-hosted)

## Overview

Rekor is an open-source, immutable tamper-evident audit log backed by a Merkle tree. Every submitted entry receives a log index and an inclusion proof. When configured as a csq audit sink, every `SignedRecord` from the local hash chain is anchored to Rekor at the configured cadence.

## Enabling

```bash
# Rebuild with the feature flag:
cargo build --release -p csq --features cli,rekor-sink --no-default-features

# Activate at runtime:
csq audit config-sink rekor
csq audit config-cadence rekor cadence 1d
csq audit config-cadence rekor cadence-high-impact immediate
```

## Default cadence (workspace-owner decision §5)

| Trigger          | Default     | Override key                      |
| ---------------- | ----------- | --------------------------------- |
| Regular interval | `1d`        | `audit.rekor.cadence`             |
| High-impact ops  | `immediate` | `audit.rekor.cadence-high-impact` |

High-impact operations: key rotation, release authorization.

## Production SDK integration

The M07 reference impl uses an in-memory mock substrate. To wire a live Rekor endpoint:

1. Add the optional dep to `csq-core/Cargo.toml` under `[dependencies]` (optional = true):
   ```toml
   sigstore = { version = "0.10", optional = true }
   sigstore-rekor = { version = "0.3", optional = true }
   ```
2. Add them to the `rekor-sink` feature:
   ```toml
   rekor-sink = ["dep:sigstore", "dep:sigstore-rekor"]
   ```
3. Replace the `store: Mutex<HashMap<...>>` in `RekorSink` with a
   `sigstore_rekor::RekorClient` and wire `append` / `verify_at` to
   `POST /api/v1/log/entries` and `GET /api/v1/log/entries/{uuid}`.

## Sink failure posture (default: non-blocking)

Sink failures do NOT block csq operations. Failed records queue to
`~/.claude/accounts/.pending-rekor/` for daemon drain. To make failures
block operations:

```bash
csq audit config-cadence rekor fail-loud true
```

## `csq doctor` output

When `audit.sink = rekor`, `csq doctor` renders:

```
  Audit sink:    ✓ rekor — last anchor: 2026-05-29T00:00:00+00:00
```

Pending or drift events surface as:

```
  Audit sink:    ⚠ rekor — last anchor: 2026-05-28T00:00:00+00:00 (pending: 3, drift: 0)
```
