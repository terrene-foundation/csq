# GCP Bucket Lock Sink Operator Guide

**Feature flag:** `--features gcp-sink`
**Sink name:** `gcp`
**Target:** GCP Cloud Storage with Bucket Lock and retention policy

## Overview

GCP Cloud Storage Bucket Lock locks a retention policy permanently, preventing reduction or removal. Combined with a retention period, it creates WORM-compliant storage for audit anchoring.

## Enabling

```bash
cargo build --release -p csq --features cli,gcp-sink --no-default-features
csq audit config-sink gcp
csq audit config-cadence gcp cadence 1d
```

## Bucket prerequisites

1. Create a bucket with uniform bucket-level access.
2. Set and lock a retention policy:
   ```bash
   gcloud storage buckets update gs://<bucket> \
     --retention-period=7y
   gcloud storage buckets update gs://<bucket> \
     --lock-retention-period
   ```
   Warning: locking is irreversible.

## IAM roles

Assign `roles/storage.objectCreator` and `roles/storage.objectViewer` to the service account.

## Object naming

`<chain_id>/<record_id>.json`

## Production SDK integration

Add `google-cloud-storage = { version = "0.20", optional = true }` and wire a `Client` in `GcpBucketLockSink`.

## Sink failure posture

Default: non-blocking. Override: `csq audit config-cadence gcp fail-loud true`.
