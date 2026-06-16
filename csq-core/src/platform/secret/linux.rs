//! Linux [`Vault`] backends — Secret Service via D-Bus (primary)
//! and the explicit AES-GCM file fallback (opt-in).
//!
//! # Backend selection
//!
//! `super::open_native_default` on Linux returns
//! [`SecretServiceVault`] when the D-Bus session bus is reachable and
//! a default collection exists. If the bus is missing (headless CI,
//! WSL with no systemd-user) the call surfaces
//! [`super::SecretError::BackendUnavailable`] rather than silently
//! degrading — per security review §3 there is no auto-fallback. The
//! user must opt into the file backend explicitly via
//! `CSQ_SECRET_BACKEND=file`.
//!
//! # Sync wrapper around an async crate
//!
//! The `secret-service` crate exposes only an async API. The
//! [`Vault`] trait is sync because it is called from both async
//! daemon paths and sync `csq-cli` paths. We bridge with a per-call
//! tokio runtime when no ambient runtime exists, or
//! `tokio::task::block_in_place` + the current `Handle` when called
//! from the daemon's multi-threaded runtime. Each operation is
//! wrapped in [`tokio::time::timeout`] honouring
//! [`super::VAULT_OP_TIMEOUT`] so a hung D-Bus broker cannot pin the
//! caller.

#![cfg(target_os = "linux")]

use super::{file::FileVault, SecretError, SlotKey, Vault, VAULT_OP_TIMEOUT};
use crate::types::AccountNum;
use secrecy::{ExposeSecret, SecretString};
use secret_service::{Collection, EncryptionType, Item, SecretService};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use tokio::runtime::Builder as RtBuilder;

/// Attribute key — the surface tag a slot belongs to. Values come
/// from [`crate::providers::catalog::Surface::as_str`]; today only
/// `Surface::Gemini.as_str() == "gemini"` is reachable (no other
/// surface uses the vault). Future surfaces serialize their own
/// tag here and the existing collection's search code partitions
/// by this attribute automatically.
const ATTR_SURFACE: &str = "csq-surface";
/// Attribute key — the account slot number rendered as decimal.
const ATTR_ACCOUNT: &str = "csq-account";
/// Attribute key — protocol-version marker so a future migration can
/// detect schema changes without re-deriving from scratch.
const ATTR_VERSION: &str = "csq-version";
/// Current attribute schema version. Bumping this requires a
/// migration step in the search path.
const SCHEMA_VERSION: &str = "1";
/// MIME type stored alongside each secret. Secret Service surfaces
/// this back to clients (e.g. `seahorse`); making it explicit avoids
/// the binary-default which renders as a hex blob in the GUI.
const SECRET_MIME: &str = "text/plain; charset=utf-8";

/// Secret Service-backed [`Vault`]. Stateless — every method is a
/// fresh D-Bus connect, per security review §3 ("no in-process
/// caching"). The connect cost is microseconds on a warm session
/// bus; for the few-times-per-process call pattern of csq, this
/// matches the macOS Keychain backend's shape.
pub struct SecretServiceVault;

impl SecretServiceVault {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecretServiceVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault for SecretServiceVault {
    fn set(&self, slot: SlotKey, secret: &SecretString) -> Result<(), SecretError> {
        if secret.expose_secret().is_empty() {
            return Err(SecretError::InvalidKey {
                reason: "secret must not be empty".into(),
            });
        }
        let bytes = secret.expose_secret().as_bytes().to_vec();
        block_with_timeout(async move {
            let service = connect_service().await?;
            let collection = open_default_collection(&service).await?;
            ensure_unlocked(&collection).await?;
            let attrs = attributes_for(slot);
            let label = label_for(slot);
            collection
                .create_item(
                    &label,
                    attrs.iter().map(|(k, v)| (*k, v.as_str())).collect(),
                    &bytes,
                    true, // replace existing
                    SECRET_MIME,
                )
                .await
                .map(|_item| ())
                .map_err(map_ss_error)
        })
    }

    fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError> {
        let surface_static = slot.surface;
        let account_value = slot.account.get();
        let bytes = block_with_timeout(async move {
            let service = connect_service().await?;
            let collection = open_default_collection(&service).await?;
            ensure_unlocked(&collection).await?;
            let attrs = attributes_for(slot);
            let items = collection
                .search_items(attrs.iter().map(|(k, v)| (*k, v.as_str())).collect())
                .await
                .map_err(map_ss_error)?;
            let Some(item) = items.into_iter().next() else {
                return Err(SecretError::NotFound {
                    surface: surface_static,
                    account: account_value,
                });
            };
            ensure_item_unlocked(&item).await?;
            item.get_secret().await.map_err(map_ss_error)
        })?;

        let s = String::from_utf8(bytes).map_err(|_| SecretError::DecryptionFailed)?;
        Ok(SecretString::new(s.into()))
    }

    fn delete(&self, slot: SlotKey) -> Result<(), SecretError> {
        block_with_timeout(async move {
            let service = connect_service().await?;
            let collection = open_default_collection(&service).await?;
            ensure_unlocked(&collection).await?;
            let attrs = attributes_for(slot);
            let items = collection
                .search_items(attrs.iter().map(|(k, v)| (*k, v.as_str())).collect())
                .await
                .map_err(map_ss_error)?;
            // Idempotent: delete-of-missing is OK.
            for item in items {
                item.delete().await.map_err(map_ss_error)?;
            }
            Ok(())
        })
    }

    fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError> {
        let surface_owned = surface.to_string();
        let mut nums = block_with_timeout(async move {
            let service = connect_service().await?;
            let collection = open_default_collection(&service).await?;
            ensure_unlocked(&collection).await?;
            let attrs: HashMap<&str, &str> = HashMap::from([
                (ATTR_SURFACE, surface_owned.as_str()),
                (ATTR_VERSION, SCHEMA_VERSION),
            ]);
            let items = collection.search_items(attrs).await.map_err(map_ss_error)?;
            let mut out: Vec<u16> = Vec::with_capacity(items.len());
            for item in items {
                let item_attrs = match item.get_attributes().await {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let Some(account_str) = item_attrs.get(ATTR_ACCOUNT) else {
                    continue;
                };
                if let Ok(n) = account_str.parse::<u16>() {
                    out.push(n);
                }
            }
            Ok(out)
        })?;

        // Convert + sort once we are out of the async block.
        nums.sort_unstable();
        nums.dedup();
        Ok(nums
            .into_iter()
            .filter_map(|n| AccountNum::try_from(n).ok())
            .collect())
    }

    fn backend_id(&self) -> &'static str {
        "linux-secret-service"
    }
}

// ── async helpers ─────────────────────────────────────────────────────

async fn connect_service() -> Result<SecretService<'static>, SecretError> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(map_ss_error)
}

async fn open_default_collection<'a>(
    service: &'a SecretService<'a>,
) -> Result<Collection<'a>, SecretError> {
    service.get_default_collection().await.map_err(map_ss_error)
}

/// Unlocks the collection if it is currently locked. The Secret
/// Service may surface a graphical PIN prompt here; that is acceptable
/// from `csq setkey` (interactive CLI) but the daemon's hot path
/// should never reach a locked collection because the user unlocked
/// at login. If the prompt fails we surface `Locked` rather than
/// blocking forever.
async fn ensure_unlocked<'a>(collection: &Collection<'a>) -> Result<(), SecretError> {
    match collection.is_locked().await {
        Ok(true) => collection.unlock().await.map_err(|e| match e {
            secret_service::Error::Prompt => SecretError::PermissionDenied {
                reason: "user denied collection unlock".into(),
            },
            other => map_ss_error(other),
        }),
        Ok(false) => Ok(()),
        Err(e) => Err(map_ss_error(e)),
    }
}

async fn ensure_item_unlocked<'a>(item: &Item<'a>) -> Result<(), SecretError> {
    match item.is_locked().await {
        Ok(true) => item.unlock().await.map_err(map_ss_error),
        Ok(false) => Ok(()),
        Err(e) => Err(map_ss_error(e)),
    }
}

fn attributes_for(slot: SlotKey) -> Vec<(&'static str, String)> {
    vec![
        (ATTR_SURFACE, slot.surface.to_string()),
        (ATTR_ACCOUNT, slot.account.get().to_string()),
        (ATTR_VERSION, SCHEMA_VERSION.to_string()),
    ]
}

fn label_for(slot: SlotKey) -> String {
    // Visible in seahorse / kwalletmanager. No secret material here —
    // just the slot identity.
    format!("csq {} account {}", slot.surface, slot.account.get())
}

/// Maps the crate's error enum to our [`SecretError`] taxonomy.
/// `secret-service::Error` is `#[non_exhaustive]`; the catch-all
/// `_` arm covers future variants without forcing a recompile when
/// the upstream adds one. Variant names checked against
/// `secret-service` v4.0.0 — see `<https://docs.rs/secret-service/4>`.
fn map_ss_error(e: secret_service::Error) -> SecretError {
    use secret_service::Error as E;
    match e {
        E::Locked => SecretError::Locked,
        E::Prompt => SecretError::AuthorizationRequired,
        // The crate uses `NoResult` for "no item matches the search
        // attributes" — but our get/list code already converts an
        // empty result vector into NotFound with the actual slot
        // identity, so this arm is reached only via odd code paths.
        // Fall through to BackendUnavailable to surface the
        // unexpected situation in the audit log.
        E::NoResult => SecretError::BackendUnavailable {
            reason: "secret-service returned no result on a path that should have surfaced \
                     NotFound earlier"
                .into(),
        },
        // `Crypto` carries a `&'static str` per v4.0.0 docs, but
        // we discard the inner value to insulate against signature
        // changes in future minor releases (the enum is
        // `#[non_exhaustive]`).
        E::Crypto(_) => SecretError::EncryptionFailed {
            reason: "secret-service session crypto failure".into(),
        },
        // Headless host: D-Bus session bus is reachable but no
        // backend (gnome-keyring / kwallet / KeePassXC) is providing
        // the org.freedesktop.secrets service.
        E::Unavailable => SecretError::BackendUnavailable {
            reason: "no Secret Service provider is registered on the session bus".into(),
        },
        // Zbus / D-Bus transport failures: bus down, broker not
        // reachable, malformed message. The error variants below all
        // map to BackendUnavailable because none of them are
        // actionable from the user's side beyond "the bus is gone".
        E::Zbus(zb) => SecretError::BackendUnavailable {
            reason: format!("dbus: {zb}"),
        },
        E::ZbusFdo(zb) => SecretError::BackendUnavailable {
            reason: format!("dbus-fdo: {zb}"),
        },
        E::Zvariant(zv) => SecretError::BackendUnavailable {
            reason: format!("dbus-zvariant: {zv}"),
        },
        // Catch-all for `#[non_exhaustive]` enum stability. Display
        // formatting is the only stable surface across crate
        // releases for variants we have not seen yet.
        _ => SecretError::BackendUnavailable {
            reason: "unrecognized secret-service error variant".into(),
        },
    }
}

// ── sync bridge ───────────────────────────────────────────────────────

/// Runs `fut` to completion under a fresh tokio runtime hosted on a
/// dedicated worker thread, honouring [`VAULT_OP_TIMEOUT`].
///
/// Earlier versions used `tokio::task::block_in_place` +
/// `Handle::block_on` when called from inside an ambient runtime, but
/// that pattern panics at runtime when the ambient runtime is
/// `current_thread` (e.g., `#[tokio::test]` defaults, any
/// `Runtime::new_current_thread().block_on(...)` site in the CLI).
/// Per security review H2, we sidestep the runtime-flavor minefield
/// entirely: every call spawns a short-lived OS thread, builds its
/// own `current_thread` runtime there, and joins on the result. The
/// thread spawn cost is microseconds; the call latency is dominated
/// by D-Bus IO; csq calls the vault a small constant number of times
/// per process so the absolute throughput cost is negligible.
///
/// This pattern is the standard "sync wrapper around an async-only
/// crate that may be called from async or sync contexts" — see e.g.
/// `keyring`'s same approach for the same crate.
fn block_with_timeout<F, T>(fut: F) -> Result<T, SecretError>
where
    F: Future<Output = Result<T, SecretError>> + Send + 'static,
    T: Send + 'static,
{
    let join = std::thread::Builder::new()
        .name("csq-vault-ss".into())
        .spawn(move || -> Result<T, SecretError> {
            let rt = RtBuilder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| SecretError::BackendUnavailable {
                    reason: format!("failed to build tokio runtime for vault op: {e}"),
                })?;
            rt.block_on(async move {
                match tokio::time::timeout(VAULT_OP_TIMEOUT, fut).await {
                    Ok(inner) => inner,
                    Err(_) => Err(SecretError::Timeout),
                }
            })
        })
        .map_err(|e| SecretError::BackendUnavailable {
            reason: format!("failed to spawn vault worker thread: {e}"),
        })?;
    join.join().map_err(|_| SecretError::BackendUnavailable {
        reason: "vault worker thread panicked".into(),
    })?
}

// ── factory ───────────────────────────────────────────────────────────

/// Linux backend selector called from
/// [`super::open_default_vault`]. Returns the explicit file backend
/// when the env override is set; otherwise probes Secret Service.
/// Refuses on probe failure rather than auto-fallback to the file
/// backend.
pub fn open_linux_default(
    base_dir: &Path,
    override_kind: Option<&str>,
) -> Result<Box<dyn Vault>, SecretError> {
    match override_kind {
        Some("file") => Ok(Box::new(FileVault::open(base_dir)?)),
        Some("keychain") | Some("auto") | None => {
            // Probe the bus before returning the vault so the
            // dispatch error message names "Secret Service" vs "file
            // backend" — without the probe, the first vault op would
            // surface BackendUnavailable later from inside a request
            // handler.
            block_with_timeout(async { connect_service().await.map(|_| ()) }).map_err(|e| {
                SecretError::BackendUnavailable {
                    reason: format!(
                        "Secret Service unavailable ({e}); \
                     set CSQ_SECRET_BACKEND=file plus CSQ_SECRET_PASSPHRASE \
                     to use the encrypted file fallback"
                    ),
                }
            })?;
            Ok(Box::new(SecretServiceVault::new()))
        }
        Some(other) => Err(SecretError::BackendUnavailable {
            reason: format!("unknown CSQ_SECRET_BACKEND value: {other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    //! Linux Secret Service tests touch the real session-bus broker
    //! and a real keychain collection. They are gated by both
    //! `#[cfg(target_os = "linux")]` (compile-time) and `#[ignore]`
    //! (runtime, opt-in via `cargo test -- --ignored`). Standard
    //! `cargo test --workspace` does NOT run them — they require a
    //! live D-Bus session bus and a default collection, which is not
    //! a guaranteed CI primitive.
    //!
    //! Run them locally on a Linux dev box before signing off
    //! PR-G2a.2 per the security-reviewer's gate.

    use super::*;
    use crate::types::AccountNum;

    fn slot(n: u16) -> SlotKey {
        SlotKey {
            surface: "gemini-test",
            account: AccountNum::try_from(n).unwrap(),
        }
    }

    /// RAII guard that deletes test slots on drop.
    struct ScopedSlot(SlotKey);
    impl Drop for ScopedSlot {
        fn drop(&mut self) {
            let v = SecretServiceVault::new();
            let _ = v.delete(self.0);
        }
    }

    #[test]
    #[ignore = "touches real Secret Service — run with --ignored"]
    fn live_set_get_round_trip() {
        let s = slot(900);
        let _g = ScopedSlot(s);
        let v = SecretServiceVault::new();
        v.set(s, &SecretString::new("AIzaTEST_LIVE_LINUX".into()))
            .expect("set");
        let got = v.get(s).expect("get");
        assert_eq!(got.expose_secret(), "AIzaTEST_LIVE_LINUX");
    }

    #[test]
    #[ignore = "touches real Secret Service — run with --ignored"]
    fn live_delete_idempotent() {
        let s = slot(901);
        let _g = ScopedSlot(s);
        let v = SecretServiceVault::new();
        v.delete(s).expect("delete on empty");
        v.set(s, &SecretString::new("x".into())).expect("set");
        v.delete(s).expect("delete after set");
        v.delete(s).expect("delete idempotent");
        assert!(matches!(v.get(s), Err(SecretError::NotFound { .. })));
    }

    #[test]
    #[ignore = "touches real Secret Service — run with --ignored"]
    fn live_list_slots_returns_account_numbers_only() {
        let v = SecretServiceVault::new();
        let s1 = slot(910);
        let s2 = slot(911);
        let _g1 = ScopedSlot(s1);
        let _g2 = ScopedSlot(s2);
        v.set(s1, &SecretString::new("a".into())).unwrap();
        v.set(s2, &SecretString::new("b".into())).unwrap();
        let listed: Vec<u16> = v
            .list_slots("gemini-test")
            .unwrap()
            .iter()
            .map(|a| a.get())
            .collect();
        assert!(listed.contains(&910));
        assert!(listed.contains(&911));
    }

    #[test]
    fn backend_id_is_linux_secret_service() {
        let v = SecretServiceVault::new();
        assert_eq!(v.backend_id(), "linux-secret-service");
    }

    #[test]
    fn empty_secret_rejected_at_set_without_dbus_call() {
        // Validation happens before D-Bus, so this test runs on every
        // Linux build without needing a session bus.
        let v = SecretServiceVault::new();
        let err = v
            .set(slot(1), &SecretString::new(String::new().into()))
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    #[test]
    fn attributes_include_csq_namespace() {
        let attrs = attributes_for(slot(7));
        assert!(attrs
            .iter()
            .any(|(k, v)| *k == ATTR_SURFACE && v == "gemini-test"));
        assert!(attrs.iter().any(|(k, v)| *k == ATTR_ACCOUNT && v == "7"));
        assert!(attrs
            .iter()
            .any(|(k, v)| *k == ATTR_VERSION && v == SCHEMA_VERSION));
    }

    #[test]
    fn label_is_human_readable() {
        let label = label_for(slot(3));
        assert!(label.contains("csq"));
        assert!(label.contains("3"));
    }
}
