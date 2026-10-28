# Azure SQL Ledger Sink Operator Guide

**Feature flag:** `--features azure-sql-sink`
**Sink name:** `azure-sql`
**Target:** Azure SQL Database ledger tables (cryptographically-verifiable append-only tables)

## Overview

Azure SQL Database **ledger tables** are append-only tables whose rows are
cryptographically hashed into a Merkle tree. The database periodically produces
a _digest_ the operator stores out-of-band; any later tampering with a committed
row breaks digest verification. This gives tamper-evidence at the database tier —
distinct from the object-storage WORM sinks (`s3` / `azure` / `gcp`), which make
the stored blob itself immutable.

A csq audit record is one row keyed by `record_id`; `verify_at` is a primary-key
`SELECT`.

## Enabling

```bash
cargo build --release -p csq --features cli,azure-sql-sink --no-default-features
csq audit config-sink azure-sql
csq audit config-cadence azure-sql cadence 1d
```

## Ledger-table prerequisites

1. Create the database and an **append-only ledger table**:
   ```sql
   CREATE TABLE audit_chain (
       record_id      VARCHAR(64)  NOT NULL PRIMARY KEY,
       chain_id       VARCHAR(64)  NOT NULL,
       seq            BIGINT       NOT NULL,
       canonical_hash CHAR(64)     NOT NULL,
       record_json    NVARCHAR(MAX) NOT NULL
   )
   WITH (LEDGER = ON (APPEND_ONLY = ON));
   ```
2. Configure **automatic digest storage** to an out-of-band location (e.g. an
   Azure Storage account with immutability, or Azure Confidential Ledger) so the
   digest the operator verifies against is itself tamper-evident.

## Azure AD auth + minimum grant

Authenticate via Azure AD (managed identity or service principal) and grant only
`INSERT` and `SELECT` on the ledger table — no `UPDATE`/`DELETE` (the
append-only ledger rejects them regardless, but least-privilege is defense in
depth).

## Digest export cadence

Ledger tamper-evidence depends on the operator periodically exporting and
independently storing the database digest (`sys.database_ledger_digest_locations`
/ `sp_verify_database_ledger`). Schedule digest export at least as often as the
csq anchor cadence and store each digest where it cannot be rewritten.

## Row scheme

`(record_id PK, chain_id, seq, canonical_hash, record_json)` — `record_json` is
the verbatim canonical-form `SignedRecord` line so `verify_at` reconstructs the
exact record csq appended.

## Production SDK integration

The shipped impl uses an in-memory mock substrate (spec 15 §15.4.2). Add
`tiberius = { version = "0.12", optional = true }` (the pure-Rust SQL Server
driver) and wire a connection pool to the `AzureSqlLedgerSink` impl: `append`
becomes an idempotent `MERGE` on the `record_id` primary key; `verify_at` becomes
a primary-key `SELECT`.

## Sink failure posture

Default: non-blocking. Override: `csq audit config-cadence azure-sql fail-loud true`.
