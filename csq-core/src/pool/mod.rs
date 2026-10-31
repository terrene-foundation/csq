//! Community API-key custody, independent of account slots and Claude launch configuration.
mod env_file;
pub mod execution;
mod execution_ledger;
#[cfg(test)]
mod execution_ledger_tests;
mod execution_pricing;
mod execution_transport;
mod store;
mod types;
/// Hang guard for real waits in pool tests (handshakes, sockets, workers, custody
/// deadlines). Messages and the injected clock decide outcomes; this cap never does.
#[cfg(test)]
pub(crate) const REAL_WAIT_CAP: std::time::Duration = std::time::Duration::from_secs(300);
pub use execution::{execute, execute_with_deadline, PoolExecRequest};
pub(crate) use store::{ExecutionAdmission, LedgerIdentity, LedgerState};
pub use store::{Pool, RemovalSnapshot};
pub use types::{KeySource, PoolEntry, PoolName, PoolRow, Reset};

/// Fixed, non-secret startup recovery outcome. Deferred work remains durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartRecovery {
    NotNeeded,
    Recovered,
    Deferred,
}

pub type Result<T> = std::result::Result<T, PoolError>;

/// Fixed vocabulary: errors never contain a key, upstream body, or arbitrary path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    #[error("pool_invalid_name")]
    InvalidName,
    #[error("pool_invalid_provider")]
    InvalidProvider,
    #[error("pool_invalid_reset")]
    InvalidReset,
    #[error("pool_invalid_cap")]
    InvalidCap,
    #[error("pool_invalid_key")]
    InvalidKey,
    #[error("pool_manifest_invalid")]
    ManifestInvalid,
    #[error("pool_manifest_unavailable")]
    ManifestUnavailable,
    #[error("pool_manifest_write_unavailable")]
    ManifestWriteUnavailable,
    #[error("pool_env_file_invalid")]
    EnvFileInvalid,
    #[error("pool_env_file_unavailable")]
    EnvFileUnavailable,
    #[error("pool_key_missing")]
    KeyMissing,
    #[error("pool_name_exists")]
    NameExists,
    #[error("pool_store_unavailable")]
    StoreUnavailable,
    #[error("pool_custody_busy")]
    Busy,
    #[error("pool_ledger_identity_mismatch")]
    LedgerIdentityMismatch,
    #[error("pool_ledger_mirror_unavailable")]
    LedgerMirrorUnavailable,
    #[error("pool_unrelated_key_unavailable")]
    UnrelatedKeyUnavailable,
    #[error("pool_item_read_unavailable")]
    ItemReadUnavailable,
    #[error("pool_mutation_refused")]
    MutationRefused,
    #[error("pool_partial_failure_recovery_required")]
    RecoveryRequired,
    /// Wait for the writer; if it is the desktop, quit the csq app before recovery.
    #[error("pool_recovery_writer_alive")]
    RecoveryWriterAlive,
}

pub fn validate_key(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        Err(PoolError::InvalidKey)
    } else {
        Ok(())
    }
}
