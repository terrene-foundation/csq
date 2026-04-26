//! Encryption-at-rest primitive for Gemini API keys (PR-G2a).
//!
//! Gemini differs from Anthropic / Codex in two ways that matter for
//! credential handling:
//!
//! 1. **No OAuth lifecycle.** AI Studio API keys (`AIza*`) are
//!    long-lived, never auto-rotated, and revoked only by the user
//!    visiting `aistudio.google.com/apikey`. A quietly stolen key
//!    exfiltrates Gemini quota for weeks before the user notices the
//!    bill. There is no server-side `invalid_grant` backstop the way
//!    Anthropic refresh tokens have.
//! 2. **Vertex SA JSON** is signing material against the customer's
//!    GCP project — far worse than an API key if leaked.
//!
//! csq's existing same-user threat model is INADEQUATE here. This
//! module raises the bar: secrets at rest are protected by the
//! platform's native keychain when present, and refuse-to-operate
//! when not (with explicit `CSQ_SECRET_BACKEND=file` opt-in for
//! headless / WSL deployments).
//!
//! # Design source
//!
//! - `workspaces/gemini/02-plans/01-implementation-plan.md` PR-G2a
//! - rust-desktop-specialist + security-reviewer joint design (this
//!   session) reconciled where they conflicted in favor of the
//!   security-reviewer's tighter posture on auto-fallback
//! - `.claude/rules/security.md` §1, §2, §5 (no secrets in logs,
//!   atomic writes, fail-closed on backend hangs)
//!
//! # Sole ownership
//!
//! This module is sole-owned by Gemini per H8 in the plan — Codex
//! does NOT use it. Codex's auth artefact is a `CodexCredentialFile`
//! written via the existing `credentials/file.rs` + `secure_file`
//! pipeline. Adding `platform::secret` to Codex would change Codex's
//! threat model retroactively and is explicitly out of scope.

use crate::types::AccountNum;
use secrecy::SecretString;
use std::time::Duration;

pub mod audit;
pub mod file;
pub mod in_memory;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// Maximum time any single backend operation may block. The vault is
/// called from the daemon hot path (usage poller, spawn pre-flight)
/// and a hung D-Bus / locked-keychain prompt MUST NOT pin those
/// callers. Hard timeout at the trait boundary; backends honour it
/// via either their own async runtime ([`linux::SecretServiceVault`])
/// or the shared [`run_with_timeout`] helper ([`macos`] / [`windows`]).
pub const VAULT_OP_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs a synchronous backend operation on a dedicated worker thread
/// and returns its result, or [`SecretError::Timeout`] if the call
/// does not complete within [`VAULT_OP_TIMEOUT`]. The macOS Keychain
/// and Windows Credential Manager APIs are blocking syscalls with no
/// native timeout — the worker thread + bounded `recv_timeout`
/// pattern enforces the trait contract uniformly.
///
/// On timeout the worker thread continues to completion and is left
/// to detach naturally; the caller cannot wait on it without
/// reintroducing the original hang. For the few-times-per-process
/// vault call pattern this is acceptable. A genuinely hung backend
/// (LSA service stuck, login keychain unresponsive) is degenerate;
/// trading "occasional thread detach" for "daemon never hangs" is
/// the correct posture for a credential-handling primitive
/// (`security.md` §6 "fail-closed on Keychain/lock contention").
///
/// Compiled only on platforms whose backends actually call it
/// (`macos` and `windows`); the Linux backend uses its own tokio-
/// based `block_with_timeout` because the upstream crate is
/// async-only.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn run_with_timeout<F, T>(thread_name: &'static str, op: F) -> Result<T, SecretError>
where
    F: FnOnce() -> Result<T, SecretError> + Send + 'static,
    T: Send + 'static,
{
    use std::sync::mpsc;
    let (tx, rx) = mpsc::sync_channel::<Result<T, SecretError>>(1);
    std::thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            // `send` returns Err if the receiver dropped (timeout
            // path). We discard that error; the caller has already
            // surfaced `SecretError::Timeout`.
            let _ = tx.send(op());
        })
        .map_err(|e| SecretError::BackendUnavailable {
            reason: format!("vault worker thread spawn: {e}"),
        })?;
    match rx.recv_timeout(VAULT_OP_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SecretError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SecretError::BackendUnavailable {
            reason: "vault worker thread panicked before producing a result".into(),
        }),
    }
}

/// Logical identifier for a stored secret. csq is multi-account +
/// multi-surface; the (surface, account) pair is the addressable
/// unit. `surface` is a `&'static str` rather than the [`Surface`]
/// enum directly to keep `platform::secret` decoupled from the
/// catalog layer — but every value MUST originate from
/// [`Surface::as_str()`] (or the [`crate::providers::gemini::SURFACE_GEMINI`]
/// alias). The wire string and the enum stay in lock-step.
///
/// [`Surface`]: crate::providers::catalog::Surface
/// [`Surface::as_str()`]: crate::providers::catalog::Surface::as_str
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotKey {
    /// Surface tag — derived from [`Surface::as_str()`] on the
    /// matching enum variant. Today only Gemini is reachable
    /// (`Surface::Gemini.as_str() == "gemini"`); future surfaces with
    /// vault-backed secrets will pivot here without touching the
    /// `platform::secret` layer.
    ///
    /// [`Surface::as_str()`]: crate::providers::catalog::Surface::as_str
    pub surface: &'static str,
    /// Account slot (1..MAX_ACCOUNTS). The newtype already validates
    /// the range so backends can format it into native key names
    /// without further checks.
    pub account: AccountNum,
}

impl SlotKey {
    /// Renders the canonical native-keychain key string. macOS
    /// keychain `service` field, Linux Secret Service `attribute`,
    /// Windows Credential Manager `target_name` — same string on
    /// every platform so a future migration tool can correlate.
    ///
    /// Format: `csq.<surface>.<account>` — e.g. `csq.gemini.3`. The
    /// `csq.` prefix namespaces against unrelated keychain entries.
    pub fn native_name(&self) -> String {
        format!("csq.{}.{}", self.surface, self.account.get())
    }
}

/// Errors raised by [`Vault`] operations. Every variant maps to a
/// user-actionable IPC string via [`From<SecretError> for String`] —
/// per `rules/tauri-commands.md` §6, no opaque "secret error" tag is
/// acceptable. Reason fields are caller-supplied descriptive
/// strings, NOT upstream API bodies, so they do not pose a
/// token-leakage risk; the redactor is still defence-in-depth.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// No secret stored for the given slot. Distinct from
    /// `BackendUnavailable` so the UI can prompt provisioning rather
    /// than show a backend warning.
    #[error("no secret stored for {surface} slot {account}")]
    NotFound { surface: &'static str, account: u16 },
    /// The backend refused the operation explicitly (macOS user
    /// clicked "Deny" on the keychain prompt; Linux Secret Service
    /// access policy denied). Distinct from `Locked` so the UI text
    /// can prompt the right remediation.
    #[error("permission denied by secret backend: {reason}")]
    PermissionDenied { reason: String },
    /// Backend is reachable but the underlying store is locked
    /// (macOS login keychain not yet unlocked; Linux Secret Service
    /// collection auto-locked on screensaver). Caller may retry with
    /// backoff; csq daemon MUST NOT prompt for keychain unlock from
    /// background contexts (phishing-grade prompt).
    #[error("secret backend is locked")]
    Locked,
    /// macOS first-write requires user authorization (keychain
    /// prompt). Distinct from `PermissionDenied` because the user
    /// has not yet been asked — UI should prompt them to interact
    /// with the OS dialog.
    #[error("backend requires user authorization to proceed")]
    AuthorizationRequired,
    /// Native backend is not present on the host (Linux without
    /// Secret Service AND `CSQ_SECRET_BACKEND` not set to `file`;
    /// Windows daemon running as `LocalSystem` so DPAPI binding is
    /// the wrong scope). Refuse-to-operate posture per security
    /// review §3.
    #[error("secret backend unavailable: {reason}")]
    BackendUnavailable { reason: String },
    /// AEAD encryption failed — almost always indicates a logic bug
    /// (nonce reuse, key derivation failure). Distinct from I/O so
    /// the audit log entry classifies it differently.
    #[error("encryption failed: {reason}")]
    EncryptionFailed { reason: String },
    /// AEAD authentication tag mismatch on read — ciphertext was
    /// corrupted, the wrong passphrase was used, or the key
    /// derivation salt was tampered with. Caller MUST treat the
    /// stored secret as unrecoverable and prompt re-provisioning.
    #[error("decryption failed — stored secret is unrecoverable")]
    DecryptionFailed,
    /// Caller-supplied secret is rejected (empty, too long, fails
    /// shape validation done by the backend layer).
    #[error("invalid secret format: {reason}")]
    InvalidKey { reason: String },
    /// Backend exceeded [`VAULT_OP_TIMEOUT`]. Treated as transient
    /// by callers — usage poller backs off, spawn refuses with
    /// retry-after.
    #[error("secret backend operation timed out")]
    Timeout,
    /// Underlying I/O failure (file backend disk full, audit log
    /// write failure). The path is included so the user can
    /// diagnose; never includes the secret content.
    #[error("secret store I/O error at {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl SecretError {
    /// Fixed-vocabulary tag for structured logging — per
    /// `security.md` §2 every `warn!`/`error!` call near vault
    /// operations MUST use a tag, not `%e` formatting.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            SecretError::NotFound { .. } => "vault_not_found",
            SecretError::PermissionDenied { .. } => "vault_permission_denied",
            SecretError::Locked => "vault_locked",
            SecretError::AuthorizationRequired => "vault_authorization_required",
            SecretError::BackendUnavailable { .. } => "vault_backend_unavailable",
            SecretError::EncryptionFailed { .. } => "vault_encryption_failed",
            SecretError::DecryptionFailed => "vault_decryption_failed",
            SecretError::InvalidKey { .. } => "vault_invalid_key",
            SecretError::Timeout => "vault_timeout",
            SecretError::Io { .. } => "vault_io_error",
        }
    }
}

/// Encryption-at-rest primitive for per-slot secrets.
///
/// All methods MUST honour [`VAULT_OP_TIMEOUT`]. All methods that
/// surface secret material do so as [`SecretString`] so the value
/// cannot accidentally appear in `Debug` / `Display` / `Serialize`
/// output.
///
/// # Caching contract
///
/// Implementors MUST NOT cache *decrypted secret cleartext* across
/// calls — each `get` re-reads from the backing store and re-decrypts
/// so the cleartext window is bounded to the duration of a single
/// caller-held [`SecretString`]. Caching of *derived KDF master keys*
/// (e.g. the Argon2id-derived AES key in
/// [`file::FileVault`]) IS permitted: re-deriving on every call would
/// add ~700ms of CPU per vault op at the chosen cost parameters and
/// block the daemon hot path. The distinction is load-bearing — the
/// derived key is one step removed from the secret material, while
/// the cleartext is the secret itself.
pub trait Vault: Send + Sync {
    /// Stores `secret` at `slot`, overwriting any existing value.
    /// Atomic on every backend — partial writes are not observable
    /// to a concurrent reader.
    fn set(&self, slot: SlotKey, secret: &SecretString) -> Result<(), SecretError>;

    /// Reads the secret at `slot`, returning a fresh
    /// [`SecretString`]. The returned value is the caller's to drop;
    /// implementors do NOT retain a reference. Returns
    /// [`SecretError::NotFound`] if no secret was previously stored.
    fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError>;

    /// Removes the secret at `slot`. Idempotent: deleting a
    /// non-existent slot returns `Ok(())`, not `NotFound`. The
    /// distinction matters for cleanup paths that want to drop a
    /// slot without first checking existence.
    fn delete(&self, slot: SlotKey) -> Result<(), SecretError>;

    /// Enumerates the account numbers that have a secret stored
    /// under the given `surface`. Returns account numbers only —
    /// never returns secret material or any function of it (length,
    /// prefix, hash). The audit-log signature requires this tight
    /// invariant.
    fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError>;

    /// Backend identifier for audit logging and `csq doctor`
    /// diagnostics. e.g. `"macos-keychain"`, `"linux-file-aes"`,
    /// `"in-memory"`. NOT exposed via Tauri IPC — diagnostic only.
    fn backend_id(&self) -> &'static str;
}

/// Selects the right [`Vault`] implementation for the current
/// platform. Returns `BackendUnavailable` when the native primitive
/// is absent and the user has not opted into the file fallback via
/// `CSQ_SECRET_BACKEND=file`. Refuse-to-operate is the default per
/// security review §3 — silent fallback is BLOCKED.
///
/// Backend selection precedence:
///
/// 1. `CSQ_SECRET_BACKEND` env var (when set to `keychain`, `file`,
///    or `in-memory`) — explicit override for testing, headless
///    deploys, or the Linux file fallback.
/// 2. Compile-time platform default (macOS Keychain, Linux Secret
///    Service, Windows DPAPI).
/// 3. Refuse with `BackendUnavailable` if the platform default is
///    unreachable and no override is set.
///
/// `CSQ_SECRET_BACKEND=file` is honoured ONLY on Linux — macOS and
/// Windows have a native primitive and refusing here prevents an
/// attacker (or an over-eager systemd unit) from quietly downgrading
/// the threat model on a host that already has Keychain / DPAPI.
pub fn open_default_vault() -> Result<Box<dyn Vault>, SecretError> {
    let override_kind = std::env::var("CSQ_SECRET_BACKEND").ok();
    match override_kind.as_deref() {
        Some("in-memory") if cfg!(any(test, feature = "secret-in-memory")) => {
            Ok(Box::new(in_memory::InMemoryVault::new()))
        }
        Some(other) if !is_known_override(other) => Err(SecretError::BackendUnavailable {
            reason: format!("unknown CSQ_SECRET_BACKEND value: {other}"),
        }),
        // Known overrides (`auto`, `keychain`, `file`) and the unset
        // case all flow into the platform native dispatch, which
        // honours the override locally.
        _ => open_native_default(override_kind.as_deref()),
    }
}

/// True for env values we route to the platform dispatch. Anything
/// else gets a `BackendUnavailable` so a typo (`CSQ_SECRET_BACKEND=files`)
/// fails loudly rather than silently falling through.
fn is_known_override(value: &str) -> bool {
    matches!(value, "auto" | "keychain" | "file" | "in-memory")
}

#[cfg(target_os = "macos")]
fn open_native_default(override_kind: Option<&str>) -> Result<Box<dyn Vault>, SecretError> {
    match override_kind {
        Some("file") => Err(SecretError::BackendUnavailable {
            reason: "CSQ_SECRET_BACKEND=file is Linux-only — macOS uses the native Keychain".into(),
        }),
        // `auto`, `keychain`, or unset all route to the keychain.
        _ => Ok(Box::new(macos::MacosKeychainVault::new())),
    }
}

#[cfg(target_os = "linux")]
fn open_native_default(override_kind: Option<&str>) -> Result<Box<dyn Vault>, SecretError> {
    // The file fallback writes its store next to the rest of csq's
    // per-user state. `linux::open_linux_default` does the actual
    // dispatch + bus probe.
    let base_dir = default_base_dir();
    linux::open_linux_default(&base_dir, override_kind)
}

#[cfg(target_os = "windows")]
fn open_native_default(override_kind: Option<&str>) -> Result<Box<dyn Vault>, SecretError> {
    windows::open_windows_default(override_kind)
}

/// Resolves the canonical csq base dir (`~/.claude/accounts`) for the
/// file-vault store. Mirrors the convention used elsewhere in
/// `platform::fs`. Falls back to the system tempdir if `$HOME` is
/// unset — that is a degenerate environment but the file backend is
/// already user-opt-in so refusing to start would be punitive.
#[cfg(target_os = "linux")]
fn default_base_dir() -> std::path::PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".claude")
            .join("accounts");
    }
    std::env::temp_dir().join("csq-vault")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::catalog::Surface;
    use std::sync::Mutex;

    /// Surface tag for the only surface currently using the vault.
    /// Resolved from [`Surface::Gemini::as_str()`] so the test fixture
    /// pivots automatically if the wire string ever changes — no
    /// literal `"gemini"` survives in test code per PR-G2b.
    ///
    /// [`Surface::Gemini::as_str()`]: crate::providers::catalog::Surface::as_str
    const GEMINI: &str = Surface::Gemini.as_str();

    /// Serializes env-var manipulation across tests in this module.
    /// `cargo test` runs in parallel; reading and writing process
    /// env without coordination produces flaky failures where one
    /// test sees another's `CSQ_SECRET_BACKEND` value. Tests acquire
    /// `crate::platform::test_env::lock()` BEFORE this lock so every
    /// env-mutating test in the workspace serializes against every
    /// other (cross-module flakes only manifest when one test reads
    /// an env var another test mutates concurrently — the per-module
    /// lock alone does not catch that).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard restoring `CSQ_SECRET_BACKEND` on drop.
    struct EnvGuard {
        prev: Option<String>,
    }
    impl EnvGuard {
        fn capture() -> Self {
            Self {
                prev: std::env::var("CSQ_SECRET_BACKEND").ok(),
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("CSQ_SECRET_BACKEND", v),
                None => std::env::remove_var("CSQ_SECRET_BACKEND"),
            }
        }
    }

    fn slot(n: u16) -> SlotKey {
        SlotKey {
            surface: GEMINI,
            account: AccountNum::try_from(n).unwrap(),
        }
    }

    /// Anchors the SlotKey wire-string contract inside `platform::secret`.
    /// If `Surface::Gemini.as_str()` ever returns something other than
    /// `"gemini"`, every SlotKey-using test pivots through this const
    /// — but the persisted vault entries (`csq.gemini.<n>` keychain
    /// service names, `csq-surface=gemini` Linux attributes,
    /// `vault-audit.ndjson` `surface` field) DO NOT pivot. This test
    /// is the early-warning that a Surface rename is also a vault
    /// schema migration.
    #[test]
    fn gemini_const_matches_surface_enum_wire_name() {
        assert_eq!(GEMINI, "gemini");
        assert_eq!(GEMINI, Surface::Gemini.as_str());
    }

    #[test]
    fn slot_key_native_name_format() {
        assert_eq!(slot(3).native_name(), "csq.gemini.3");
        assert_eq!(slot(999).native_name(), "csq.gemini.999");
    }

    #[test]
    fn error_kind_tag_distinct_per_variant() {
        // Tags must be unique so log queries can disambiguate. This
        // catches accidental tag duplication when adding new
        // variants.
        let tags = [
            SecretError::NotFound {
                surface: GEMINI,
                account: 1,
            }
            .error_kind_tag(),
            SecretError::PermissionDenied { reason: "x".into() }.error_kind_tag(),
            SecretError::Locked.error_kind_tag(),
            SecretError::AuthorizationRequired.error_kind_tag(),
            SecretError::BackendUnavailable { reason: "x".into() }.error_kind_tag(),
            SecretError::EncryptionFailed { reason: "x".into() }.error_kind_tag(),
            SecretError::DecryptionFailed.error_kind_tag(),
            SecretError::InvalidKey { reason: "x".into() }.error_kind_tag(),
            SecretError::Timeout.error_kind_tag(),
            SecretError::Io {
                path: "/tmp/x".into(),
                source: std::io::Error::other("test"),
            }
            .error_kind_tag(),
        ];
        let unique: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len(), "tag collision: {tags:?}");
        // Every tag prefixed with "vault_" so log queries can
        // trivially filter to vault events.
        for t in tags {
            assert!(t.starts_with("vault_"), "missing vault_ prefix: {t}");
        }
    }

    #[test]
    fn error_display_messages_are_actionable() {
        // Per rules/tauri-commands.md §6 — every error variant must
        // produce a user-readable message, not "INTERNAL_ERROR".
        let cases = [
            SecretError::NotFound {
                surface: GEMINI,
                account: 1,
            }
            .to_string(),
            SecretError::Locked.to_string(),
            SecretError::AuthorizationRequired.to_string(),
            SecretError::Timeout.to_string(),
        ];
        for msg in cases {
            assert!(!msg.is_empty());
            assert!(!msg.to_ascii_lowercase().contains("internal_error"));
            assert!(!msg.to_ascii_lowercase().contains("unknown error"));
        }
    }

    #[test]
    fn open_default_vault_rejects_unknown_backend_value() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::set_var("CSQ_SECRET_BACKEND", "made-up-backend");
        let result = open_default_vault();
        assert!(matches!(
            result,
            Err(SecretError::BackendUnavailable { .. })
        ));
    }

    #[test]
    fn is_known_override_recognizes_documented_values() {
        for v in ["auto", "keychain", "file", "in-memory"] {
            assert!(is_known_override(v), "{v} must be a known override");
        }
        for v in ["", "Keychain", "files", "memory", "FILE"] {
            assert!(!is_known_override(v), "{v} must NOT be a known override");
        }
    }

    /// `CSQ_SECRET_BACKEND=file` MUST refuse on macOS — the user
    /// already has a Keychain and silently downgrading to a less
    /// protective backend would violate the security review §3
    /// "no silent fallback" rule. The error message MUST name the
    /// reason so the user can self-diagnose.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_refuses_file_override() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::set_var("CSQ_SECRET_BACKEND", "file");
        match open_default_vault() {
            Err(SecretError::BackendUnavailable { reason }) => {
                assert!(
                    reason.to_lowercase().contains("linux-only")
                        || reason.to_lowercase().contains("keychain"),
                    "reason must explain why the override is refused, got: {reason}"
                );
            }
            Err(other) => panic!("expected BackendUnavailable, got {other:?}"),
            Ok(_) => panic!("expected BackendUnavailable, got Ok"),
        }
    }

    /// macOS without any override (or with `keychain`/`auto`) MUST
    /// route to the Keychain backend and succeed. Smoke check that
    /// the dispatch wiring is intact — the keychain backend itself
    /// has gated live tests in macos.rs.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_returns_keychain_backend() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::remove_var("CSQ_SECRET_BACKEND");
        let v = open_default_vault().expect("macos default should not fail");
        assert_eq!(v.backend_id(), "macos-keychain");
    }

    /// `CSQ_SECRET_BACKEND=keychain` is a no-op alias on macOS.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_keychain_override_is_no_op() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::set_var("CSQ_SECRET_BACKEND", "keychain");
        let v = open_default_vault().expect("keychain override should map to native");
        assert_eq!(v.backend_id(), "macos-keychain");
    }

    /// Windows refuses `CSQ_SECRET_BACKEND=file` regardless of
    /// process posture — the file backend is Linux-only and DPAPI
    /// is the canonical Windows primitive.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_refuses_file_override() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::set_var("CSQ_SECRET_BACKEND", "file");
        match open_default_vault() {
            Err(SecretError::BackendUnavailable { reason }) => {
                assert!(
                    reason.to_lowercase().contains("linux-only"),
                    "reason must explain why file is refused on Windows, got: {reason}"
                );
            }
            Err(other) => panic!("expected BackendUnavailable, got {other:?}"),
            Ok(_) => panic!("expected BackendUnavailable, got Ok"),
        }
    }

    /// Windows default (unset env) returns the Credential Manager
    /// backend when the process is NOT running as `LocalSystem`. CI
    /// runners and developer workstations both run as a normal user,
    /// so this test path exercises the dispatch contract end-to-end.
    /// Skipped at runtime if `is_running_as_local_system` returns
    /// true (e.g. test harness launched by a SYSTEM service).
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_default_returns_credential_manager_when_not_system() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::remove_var("CSQ_SECRET_BACKEND");
        if windows::is_running_as_local_system() {
            // Skip — LocalSystem refusal is exercised by the
            // dedicated test below.
            return;
        }
        let v = open_default_vault().expect("Windows default should return CredentialVault");
        assert_eq!(v.backend_id(), "windows-credential-manager");
    }

    /// `unwrap_err` would not work on `Result<Box<dyn Vault>, ...>`
    /// because `Box<dyn Vault>` lacks `Debug`. Pattern-match instead.
    /// Asserts the unknown-value path explicitly to mirror the
    /// `is_known_override` test.
    #[test]
    fn open_default_vault_typo_surfaces_actionable_error() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::capture();
        std::env::set_var("CSQ_SECRET_BACKEND", "files");
        match open_default_vault() {
            Err(SecretError::BackendUnavailable { reason }) => {
                assert!(
                    reason.contains("files"),
                    "error must name the bad value so users can spot the typo, got: {reason}"
                );
            }
            Err(other) => panic!("expected BackendUnavailable, got {other:?}"),
            Ok(_) => panic!("expected BackendUnavailable, got Ok"),
        }
    }
}
