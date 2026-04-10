use std::path::PathBuf;
use thiserror::Error;

/// Top-level error type for csq operations.
///
/// Used at CLI and Tauri command boundaries. Each variant wraps
/// a module-specific error for pattern matching.
#[derive(Error, Debug)]
pub enum CsqError {
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),

    #[error("platform error: {0}")]
    Platform(#[from] PlatformError),

    #[error("broker error: {0}")]
    Broker(#[from] BrokerError),

    #[error("oauth error: {0}")]
    OAuth(#[from] OAuthError),

    #[error("daemon error: {0}")]
    Daemon(#[from] DaemonError),

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Maps CsqError to a typed code string for Tauri IPC responses.
impl From<CsqError> for String {
    fn from(e: CsqError) -> String {
        match &e {
            CsqError::Credential(CredentialError::NotFound { .. }) => format!("NOT_FOUND: {e}"),
            CsqError::Credential(CredentialError::InvalidAccount(_)) => {
                format!("INVALID_INPUT: {e}")
            }
            CsqError::Broker(BrokerError::RefreshTokenInvalid { .. }) => {
                format!("LOGIN_REQUIRED: {e}")
            }
            CsqError::OAuth(OAuthError::StateMismatch) => format!("CSRF_ERROR: {e}"),
            _ => format!("INTERNAL_ERROR: {e}"),
        }
    }
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("credential file not found: {path}")]
    NotFound { path: PathBuf },

    #[error("corrupt credential file {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },

    #[error("invalid account number: {0}")]
    InvalidAccount(String),

    #[error("no credentials configured for account {0}")]
    NoCredentials(u16),

    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("lock contention on {path} (held by another process)")]
    LockContention { path: PathBuf },

    #[error("lock timeout after {timeout_ms}ms on {path}")]
    LockTimeout { path: PathBuf, timeout_ms: u64 },

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("process not found: PID {pid}")]
    ProcessNotFound { pid: u32 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("windows error: code {code}, {message}")]
    Win32 { code: u32, message: String },
}

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("refresh failed for account {account}: {reason}")]
    RefreshFailed { account: u16, reason: String },

    #[error("refresh token invalid for account {account} (re-login required)")]
    RefreshTokenInvalid { account: u16 },

    #[error("all siblings dead for account {account}")]
    AllSiblingsDead { account: u16 },

    #[error("recovery failed for account {account}: tried {tried} siblings")]
    RecoveryFailed { account: u16, tried: usize },
}

#[derive(Error, Debug)]
pub enum OAuthError {
    #[error("http error: {status} {body}")]
    Http { status: u16, body: String },

    #[error("state token expired (TTL {ttl_secs}s exceeded)")]
    StateExpired { ttl_secs: u64 },

    #[error("state token mismatch (CSRF)")]
    StateMismatch,

    #[error("PKCE verification failed")]
    PkceVerification,

    #[error("token exchange failed: {0}")]
    Exchange(String),
}

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("daemon not running (PID file: {pid_path})")]
    NotRunning { pid_path: PathBuf },

    #[error("daemon already running (PID {pid})")]
    AlreadyRunning { pid: u32 },

    #[error("socket connect failed: {path}")]
    SocketConnect { path: PathBuf },

    #[error("ipc timeout after {timeout_ms}ms")]
    IpcTimeout { timeout_ms: u64 },

    #[error("stale PID file (PID {pid} not alive)")]
    StalePidFile { pid: u32 },
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("profile not found: {name}")]
    ProfileNotFound { name: String },

    #[error("invalid JSON in {path}: {reason}")]
    InvalidJson { path: PathBuf, reason: String },

    #[error("settings merge conflict in {key}")]
    MergeConflict { key: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csq_error_display() {
        let err = CsqError::Credential(CredentialError::InvalidAccount("abc".to_string()));
        assert_eq!(
            format!("{err}"),
            "credential error: invalid account number: abc"
        );
    }

    #[test]
    fn csq_error_to_ipc_string() {
        let err = CsqError::Credential(CredentialError::InvalidAccount("0".to_string()));
        let s: String = err.into();
        assert!(s.starts_with("INVALID_INPUT:"));
    }

    #[test]
    fn broker_error_display() {
        let err = BrokerError::RefreshTokenInvalid { account: 3 };
        assert!(format!("{err}").contains("account 3"));
        assert!(format!("{err}").contains("re-login"));
    }

    #[test]
    fn credential_not_found_display() {
        let err = CredentialError::NotFound {
            path: PathBuf::from("/tmp/creds.json"),
        };
        assert!(format!("{err}").contains("/tmp/creds.json"));
    }
}
