# Azure Immutable Blob Sink Operator Guide

**Feature flag:** `--features azure-sink`
**Sink name:** `azure`
**Target:** Azure Blob Storage with container-level immutability policy

## Overview

Azure Blob Storage supports time-based retention policies and legal holds at the container level. Once a policy is locked, blobs cannot be deleted or modified during the retention period.

## Enabling

```bash
cargo build --release -p csq --features cli,azure-sink --no-default-features
csq audit config-sink azure
csq audit config-cadence azure cadence 1d
```

## Container prerequisites

1. Create a storage account and container.
2. Apply a time-based immutability policy and lock it:
   ```bash
   az storage container immutability-policy create \
     --account-name <account> --container-name <container> \
     --period 2557
   az storage container immutability-policy lock \
     --account-name <account> --container-name <container> \
     --if-match <etag>
   ```

## Azure AD RBAC

Assign `Storage Blob Data Contributor` to the service principal running csq.

## Blob naming scheme

`<chain_id>/<record_id>.json`

## Production SDK integration

Add `azure-storage-blobs = { version = "0.20", optional = true }` and wire `BlobServiceClient` to the `AzureImmutableBlobSink` impl.

## Sink failure posture

Default: non-blocking. Override: `csq audit config-cadence azure fail-loud true`.
