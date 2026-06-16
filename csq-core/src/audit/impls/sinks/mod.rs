//! M07 reference-impl catalog for [`crate::audit::traits::LedgerSink`].
//!
//! Each sink is `cfg`-gated behind an opt-in `--features <sink>-sink` flag.
//! None compile into the default build. Operators opt in by rebuilding csq
//! with the desired feature; the daemon then routes through the selected
//! sink at runtime.
//!
//! Per workspace-owner decision §5 (00-index.md) and the M07 PRIMARY
//! METHODOLOGICAL DIRECTIVE: external sinks are NEVER on the default
//! code path.
//!
//! # Sink catalog
//!
//! | Struct                    | Feature flag       | Target                            |
//! |---------------------------|--------------------|-----------------------------------|
//! | [`RekorSink`]             | `rekor-sink`       | Sigstore Rekor (public/self-host) |
//! | [`S3ObjectLockSink`]      | `s3-sink`          | AWS S3 Object Lock                |
//! | [`AzureImmutableBlobSink`]| `azure-sink`       | Azure Immutable Blob Storage      |
//! | [`GcpBucketLockSink`]     | `gcp-sink`         | GCP Cloud Storage Bucket Lock     |
//! | [`AzureSqlLedgerSink`]    | `azure-sql-sink`   | Azure SQL Database ledger tables  |
//!
//! `CsqLedgerSink` is reserved for M10 (feature flag `csq-ledger-sink`).
//! The feature flag is defined in Cargo.toml so the Cargo feature graph is
//! stable across M07→M10; the implementation body lands in M10.
//!
//! # Design note — mock substrates
//!
//! Each impl in this catalog uses an in-memory mock substrate rather than
//! a live SDK. This demonstrates the `LedgerSink` contract (append/verify
//! round-trip) and proves the cfg-gating discipline is sound.  Operators
//! harden for production by replacing the mock substrate with the real SDK
//! client; the trait surface is unchanged. See `docs/audit-sinks/` for the
//! per-sink operator guide.
//!
//! The pattern is the same as [`crate::audit::impls::noop::NoopSink`]
//! (which ships in test builds only).  Reference-impl sinks are gated on
//! feature flags rather than `#[cfg(test)]`; they may ship in release
//! binaries when the operator explicitly opts in.

#[cfg(feature = "azure-sink")]
pub mod azure;
#[cfg(feature = "azure-sql-sink")]
pub mod azure_sql;
#[cfg(feature = "gcp-sink")]
pub mod gcp;
#[cfg(feature = "rekor-sink")]
pub mod rekor;
#[cfg(feature = "s3-sink")]
pub mod s3;

#[cfg(feature = "azure-sink")]
pub use azure::AzureImmutableBlobSink;
#[cfg(feature = "azure-sql-sink")]
pub use azure_sql::AzureSqlLedgerSink;
#[cfg(feature = "gcp-sink")]
pub use gcp::GcpBucketLockSink;
#[cfg(feature = "rekor-sink")]
pub use rekor::RekorSink;
#[cfg(feature = "s3-sink")]
pub use s3::S3ObjectLockSink;
