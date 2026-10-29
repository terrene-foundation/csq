//! Desktop boundary for account-independent API-key custody.
//! No credential read command or secret-bearing return/event is exposed.
use csq_core::pool::{validate_key, KeySource, Pool, PoolName, PoolRow, RemovalSnapshot, Reset};
use secrecy::{ExposeSecret, SecretString};
use tauri::Manager;
use tauri::{Runtime, WebviewWindow};

/// Converts owned deserializer strings without shrinking their secret allocation.
pub struct PoolKey(SecretString);
fn key_from_owned_buffer(value: &mut zeroize::Zeroizing<String>) -> PoolKey {
    let key = PoolKey(SecretString::new(Box::<str>::from(value.as_str())));
    zeroize::Zeroize::zeroize(&mut **value);
    key
}
impl From<SecretString> for PoolKey {
    fn from(key: SecretString) -> Self {
        Self(key)
    }
}
impl<'de> serde::Deserialize<'de> for PoolKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PoolKey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an API key string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<PoolKey, E> {
                Ok(PoolKey(SecretString::new(Box::<str>::from(value))))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<PoolKey, E> {
                let mut value = zeroize::Zeroizing::new(value);
                Ok(key_from_owned_buffer(&mut value))
            }
        }
        deserializer.deserialize_string(Visitor)
    }
}

#[derive(Default)]
struct RemovalGate(std::sync::Arc<std::sync::atomic::AtomicBool>);
struct RemovalPermit(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl RemovalPermit {
    fn acquire(
        active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<std::sync::Arc<Self>, String> {
        active
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| "pool_custody_busy".to_owned())?;
        Ok(std::sync::Arc::new(Self(active)))
    }
}
impl Drop for RemovalPermit {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Native-derived invocation provenance, never a renderer-provided argument.
/// Tauri resolves request.url against the capability before dispatch (2.11.5,
/// webview/mod.rs). Missing Origin is legitimate for macOS postMessage IPC;
/// the resolved LOCAL ACL is mandatory even for that fallback.
pub struct PoolRequester {
    local_acl: bool,
    origin: Option<tauri::Url>,
    invalid_origin: bool,
}
impl<'a, R: Runtime> tauri::ipc::CommandArg<'a, R> for PoolRequester {
    fn from_command(item: tauri::ipc::CommandItem<'a, R>) -> Result<Self, tauri::ipc::InvokeError> {
        let origins = item.message.headers().get_all("origin");
        let mut values = origins.iter();
        let origin = values.next();
        let parsed = origin
            .and_then(|value| value.to_str().ok())
            .and_then(|value| tauri::Url::parse(value).ok());
        let invalid_origin = (origin.is_some() && parsed.is_none()) || values.next().is_some();
        Ok(Self {
            local_acl: item.acl.as_ref().is_some_and(|acl| {
                !acl.is_empty()
                    && acl.iter().all(|permission| {
                        permission.context == tauri::utils::acl::ExecutionContext::Local
                    })
            }),
            origin: parsed,
            invalid_origin,
        })
    }
}

fn require_origin(label: &str, url: &tauri::Url) -> Result<(), String> {
    let bundled = matches!(
        (url.scheme(), url.host_str(), url.port()),
        ("tauri", Some("localhost"), None) | ("http" | "https", Some("tauri.localhost"), None)
    );
    let development = cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("localhost")
        && url.port() == Some(5173);
    if label == "main"
        && url.username().is_empty()
        && url.password().is_none()
        && (bundled || development)
    {
        Ok(())
    } else {
        Err("pool_permission_denied".into())
    }
}
fn authorize<R: Runtime>(
    window: &WebviewWindow<R>,
    requester: &PoolRequester,
) -> Result<(), String> {
    if !requester.local_acl || requester.invalid_origin {
        return Err("pool_permission_denied".into());
    }
    let url = window
        .url()
        .map_err(|_| "pool_permission_denied".to_owned())?;
    require_origin(window.label(), &url)?;
    if let Some(origin) = &requester.origin {
        require_origin(window.label(), origin)?;
        if !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err("pool_permission_denied".into());
        }
    }
    Ok(())
}
fn canonical_pool<R: Runtime>(window: &WebviewWindow<R>) -> Result<Pool, String> {
    #[cfg(all(test, feature = "test-utils", unix))]
    if let Some(fixture) = window.try_state::<tests::Fixture>() {
        fixture
            .opens
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let vault =
            csq_core::platform::secret::file::FileVault::open_test(&fixture.base.join("vault"))
                .map_err(|_| "pool_base_unavailable".to_owned())?;
        return Ok(Pool::with_vault(&fixture.base, Box::new(vault)));
    }
    let _ = window;
    // Backend-owned configuration; the renderer cannot redirect this path.
    let base = crate::desktop::base_dir().ok_or_else(|| "pool_base_unavailable".to_owned())?;
    Ok(Pool::new(&base))
}
fn removal_message(snapshot: &RemovalSnapshot) -> String {
    let source = match snapshot.entry.source {
        KeySource::SecretStore => "stored key",
        KeySource::EnvFile => "env-file entry (the source file is kept)",
    };
    let cap = snapshot
        .entry
        .monthly_cap_usd
        .map_or_else(|| "not set".to_owned(), |cap| format!("USD {cap}"));
    format!(
        "Remove '{}' (provider: {}, source: {}, added: {}, monthly cap: {})? Stored key removal cannot be undone.",
        snapshot.entry.name.as_str(),
        snapshot.entry.provider,
        source,
        snapshot.entry.added_at,
        cap
    )
}
async fn confirm_removal<R: Runtime>(
    window: WebviewWindow<R>,
    message: String,
    permit: std::sync::Arc<RemovalPermit>,
) -> Result<bool, String> {
    #[cfg(all(test, feature = "test-utils", unix))]
    if let Some(fixture) = window.try_state::<tests::Fixture>() {
        *fixture.message.lock().unwrap() = Some(message);
        fixture
            .confirmations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _permit = permit;
        fixture.confirm_entered.notify_one();
        if fixture
            .pause_confirmation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            fixture.confirm_resume.notified().await;
        }
        let after_confirm = fixture.after_confirm.lock().unwrap().take();
        if let Some(operation) = after_confirm {
            operation();
        }
        return Ok(fixture.confirm.load(std::sync::atomic::Ordering::SeqCst));
    }
    blocking(move || {
        let _permit = permit;
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        Ok(window
            .dialog()
            .message(message)
            .title("Remove API key")
            .parent(&window)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Remove".into(),
                "Cancel".into(),
            ))
            .blocking_show())
    })
    .await
}
async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            tracing::error!(
                error_kind = "pool_worker_join_failed",
                panicked = error.is_panic()
            );
            "pool_worker_unavailable".to_owned()
        })?
}
fn add(
    pool: &Pool,
    name: &str,
    provider: &str,
    key: SecretString,
    reset: Option<Reset>,
    cap: Option<f64>,
) -> Result<(), String> {
    Pool::validate_add(name, provider, reset.as_ref(), cap).map_err(|e| e.to_string())?;
    validate_key(key.expose_secret()).map_err(|e| e.to_string())?;
    csq_core::credentials::keychain::with_interactive_keychain(|| {
        pool.add(name, provider, key, reset, cap)
            .map_err(|e| e.to_string())
    })
}
fn remove(pool: &Pool, snapshot: &RemovalSnapshot) -> Result<(), String> {
    csq_core::credentials::keychain::with_interactive_keychain(|| {
        pool.remove_if_unchanged(snapshot)
            .map_err(|e| e.to_string())
    })
}
fn set_reset(pool: &Pool, name: &str, reset: Option<Reset>) -> Result<(), String> {
    PoolName::new(name).map_err(|e| e.to_string())?;
    if let Some(value) = &reset {
        value.validate().map_err(|e| e.to_string())?;
    }
    pool.set_reset(name, reset).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn pool_list<R: Runtime>(
    window: WebviewWindow<R>,
    requester: PoolRequester,
) -> Result<Vec<PoolRow>, String> {
    authorize(&window, &requester)?;
    blocking(move || canonical_pool(&window)?.list().map_err(|e| e.to_string())).await
}
/// Creates one named entry. Retrying an already committed add returns pool_name_exists.
#[tauri::command]
pub async fn pool_add<R: Runtime>(
    window: WebviewWindow<R>,
    requester: PoolRequester,
    name: String,
    provider: String,
    key: PoolKey,
    reset: Option<Reset>,
    monthly_cap_usd: Option<f64>,
) -> Result<(), String> {
    authorize(&window, &requester)?;
    let key = key.0;
    Pool::validate_add(&name, &provider, reset.as_ref(), monthly_cap_usd)
        .map_err(|e| e.to_string())?;
    validate_key(key.expose_secret()).map_err(|e| e.to_string())?;
    blocking(move || {
        let _credential_write = crate::desktop::credential_writes::global().admit()?;
        add(
            &canonical_pool(&window)?,
            &name,
            &provider,
            key,
            reset,
            monthly_cap_usd,
        )
    })
    .await
}
/// Removes one named entry. Retrying a completed removal returns pool_key_missing.
#[tauri::command]
pub async fn pool_remove<R: Runtime>(
    window: WebviewWindow<R>,
    requester: PoolRequester,
    name: String,
) -> Result<(), String> {
    authorize(&window, &requester)?;
    PoolName::new(&name).map_err(|e| e.to_string())?;
    window.manage(RemovalGate::default());
    let permit = RemovalPermit::acquire(window.state::<RemovalGate>().0.clone())?;
    let snapshot_window = window.clone();
    let (pool, snapshot) = blocking(move || {
        let pool = canonical_pool(&snapshot_window)?;
        let snapshot = pool.removal_snapshot(&name).map_err(|e| e.to_string())?;
        Ok((pool, snapshot))
    })
    .await?;
    if !confirm_removal(window, removal_message(&snapshot), permit.clone()).await? {
        return Err("pool_removal_cancelled".into());
    }
    blocking(move || {
        let _permit = permit;
        let _credential_write = crate::desktop::credential_writes::global().admit()?;
        remove(&pool, &snapshot)
    })
    .await
}
/// Replaces reset metadata; repeated identical requests are idempotent.
#[tauri::command]
pub async fn pool_set_reset<R: Runtime>(
    window: WebviewWindow<R>,
    requester: PoolRequester,
    name: String,
    reset: Option<Reset>,
) -> Result<(), String> {
    authorize(&window, &requester)?;
    PoolName::new(&name).map_err(|e| e.to_string())?;
    if let Some(value) = &reset {
        value.validate().map_err(|e| e.to_string())?;
    }
    blocking(move || {
        let _credential_write = crate::desktop::credential_writes::global().admit()?;
        set_reset(&canonical_pool(&window)?, &name, reset)
    })
    .await
}

#[cfg(all(test, feature = "test-utils", unix))]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };
    use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime};
    pub(super) struct Fixture {
        pub base: PathBuf,
        pub opens: Arc<AtomicUsize>,
        pub confirmations: Arc<AtomicUsize>,
        pub confirm: AtomicBool,
        pub message: std::sync::Mutex<Option<String>>,
        pub pause_confirmation: AtomicBool,
        pub confirm_entered: tokio::sync::Notify,
        pub confirm_resume: tokio::sync::Notify,
        pub after_confirm: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    fn app(
        dir: &tempfile::TempDir,
        label: &str,
        confirm: bool,
    ) -> (
        tauri::App<MockRuntime>,
        WebviewWindow<MockRuntime>,
        Arc<AtomicUsize>,
    ) {
        let opens = Arc::new(AtomicUsize::new(0));
        let acl =
            serde_json::from_str(include_str!("../../../gen/schemas/acl-manifests.json")).unwrap();
        let capabilities =
            serde_json::from_str(include_str!("../../../gen/schemas/capabilities.json")).unwrap();
        let resolved = tauri::utils::acl::resolved::Resolved::resolve(
            &acl,
            capabilities,
            tauri::utils::platform::Target::current(),
        )
        .unwrap();
        let mut context = mock_context(noop_assets());
        *context.runtime_authority_mut() = tauri::runtime_authority!(acl, resolved);
        let app = mock_builder()
            .manage(Fixture {
                base: dir.path().to_owned(),
                opens: opens.clone(),
                confirmations: Arc::new(AtomicUsize::new(0)),
                confirm: AtomicBool::new(confirm),
                message: std::sync::Mutex::new(None),
                pause_confirmation: AtomicBool::new(false),
                confirm_entered: tokio::sync::Notify::new(),
                confirm_resume: tokio::sync::Notify::new(),
                after_confirm: std::sync::Mutex::new(None),
            })
            .invoke_handler(tauri::generate_handler![
                pool_list,
                pool_add,
                pool_remove,
                pool_set_reset
            ])
            .build(context)
            .unwrap();
        let window = tauri::WebviewWindowBuilder::new(
            &app,
            label,
            tauri::WebviewUrl::App("index.html".into()),
        )
        .build()
        .unwrap();
        (app, window, opens)
    }
    fn requester(allowed: bool) -> PoolRequester {
        PoolRequester {
            local_acl: allowed,
            origin: None,
            invalid_origin: false,
        }
    }
    fn ipc(
        window: &WebviewWindow<MockRuntime>,
        command: &str,
        body: serde_json::Value,
        origin: Option<&str>,
        url: &str,
    ) -> Result<tauri::ipc::InvokeResponseBody, serde_json::Value> {
        let mut headers = Default::default();
        if let Some(origin) = origin {
            headers = [("origin".parse().unwrap(), origin.parse().unwrap())]
                .into_iter()
                .collect();
        }
        get_ipc_response(
            window,
            tauri::webview::InvokeRequest {
                cmd: command.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: url.parse().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers,
                invoke_key: tauri::test::INVOKE_KEY.into(),
            },
        )
    }
    #[tokio::test]
    async fn pool_ipc_each_command_requires_authorization_before_custody() {
        let dir = tempfile::tempdir().unwrap();
        let (_app, window, opens) = app(&dir, "main", true);
        assert_eq!(
            pool_list(window.clone(), requester(false))
                .await
                .unwrap_err(),
            "pool_permission_denied"
        );
        assert_eq!(
            pool_add(
                window.clone(),
                requester(false),
                "entry".into(),
                "anthropic".into(),
                SecretString::from("synthetic".to_owned()).into(),
                None,
                None
            )
            .await
            .unwrap_err(),
            "pool_permission_denied"
        );
        assert_eq!(
            pool_remove(window.clone(), requester(false), "entry".into())
                .await
                .unwrap_err(),
            "pool_permission_denied"
        );
        assert_eq!(
            pool_set_reset(window, requester(false), "entry".into(), None)
                .await
                .unwrap_err(),
            "pool_permission_denied"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert!(!dir.path().join("pool").exists());
    }
    #[test]
    fn pool_ipc_native_acl_and_origin_enforce_frame_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let (app, window, opens) = app(&dir, "main", true);
        // macOS postMessage fallback has no default Origin: resolved LOCAL ACL authorizes it.
        assert!(ipc(
            &window,
            "pool_list",
            serde_json::json!({}),
            None,
            "tauri://localhost"
        )
        .is_ok());
        assert!(ipc(
            &window,
            "pool_list",
            serde_json::json!({}),
            Some("tauri://localhost"),
            "tauri://localhost"
        )
        .is_ok());
        for command in ["pool_list", "pool_add", "pool_remove", "pool_set_reset"] {
            let body = serde_json::json!({"name":"entry","provider":"anthropic","key":"synthetic","reset":null,"monthlyCapUsd":null});
            for origin in [
                "https://evil.example",
                "null",
                "tauri://localhost/path",
                "http://localhost:5174",
            ] {
                let before = opens.load(Ordering::SeqCst);
                assert_eq!(
                    ipc(
                        &window,
                        command,
                        body.clone(),
                        Some(origin),
                        "tauri://localhost"
                    )
                    .unwrap_err(),
                    serde_json::json!("pool_permission_denied")
                );
                assert_eq!(opens.load(Ordering::SeqCst), before);
            }
            let before = opens.load(Ordering::SeqCst);
            assert!(ipc(&window, command, body.clone(), None, "https://evil.example").is_err());
            let foreign = tauri::WebviewWindowBuilder::new(
                &app,
                format!("foreign-{command}"),
                Default::default(),
            )
            .build()
            .unwrap();
            assert!(ipc(&foreign, command, body, None, "tauri://localhost").is_err());
            assert_eq!(opens.load(Ordering::SeqCst), before);
        }
    }
    #[test]
    fn pool_ipc_fixture_roundtrip_returns_only_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let (_app, window, _) = app(&dir, "main", true);
        let secret = "synthetic-desktop-pool-fixture";
        ipc(&window, "pool_add", serde_json::json!({"name":"desktop","provider":"anthropic","key":secret,"reset":null,"monthlyCapUsd":10.0}), None, "tauri://localhost").unwrap();
        ipc(
            &window,
            "pool_set_reset",
            serde_json::json!({"name":"desktop","reset":{"day_of_month":5}}),
            None,
            "tauri://localhost",
        )
        .unwrap();
        let rows: serde_json::Value = ipc(
            &window,
            "pool_list",
            serde_json::json!({}),
            None,
            "tauri://localhost",
        )
        .unwrap()
        .deserialize()
        .unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["present"], true);
        assert_eq!(rows[0]["reset"]["day_of_month"], 5);
        let output = serde_json::to_string(&rows).unwrap();
        assert!(!output.contains(secret));
        assert!(!output.contains("secret_id"));
        ipc(
            &window,
            "pool_remove",
            serde_json::json!({"name":"desktop"}),
            None,
            "tauri://localhost",
        )
        .unwrap();
        let rows: serde_json::Value = ipc(
            &window,
            "pool_list",
            serde_json::json!({}),
            None,
            "tauri://localhost",
        )
        .unwrap()
        .deserialize()
        .unwrap();
        assert!(rows.as_array().unwrap().is_empty());
    }
    #[tokio::test]
    async fn pool_ipc_cancel_removal_preserves_backend_named_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (_app, window, opens) = app(&dir, "main", false);
        let pool = canonical_pool(&window).unwrap();
        pool.add("entry", "anthropic", "synthetic".into(), None, Some(37.5))
            .unwrap();
        opens.store(0, Ordering::SeqCst);
        assert_eq!(
            pool_remove(window.clone(), requester(true), "entry".into())
                .await
                .unwrap_err(),
            "pool_removal_cancelled"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(
            window
                .state::<Fixture>()
                .confirmations
                .load(Ordering::SeqCst),
            1
        );
        let message = window
            .state::<Fixture>()
            .message
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert!(message.contains("'entry'"));
        assert!(message.contains("anthropic"));
        assert!(message.contains("stored key"));
        let snapshot = pool.removal_snapshot("entry").unwrap();
        assert!(message.contains(&format!("added: {}", snapshot.entry.added_at)));
        assert!(message.contains("monthly cap: USD 37.5"));
        assert_eq!(pool.read_key("entry").unwrap().expose_secret(), "synthetic");
    }
    #[tokio::test]
    async fn pool_ipc_concurrent_remove_refuses_before_second_dialog() {
        let dir = tempfile::tempdir().unwrap();
        let (_app, window, opens) = app(&dir, "main", false);
        canonical_pool(&window)
            .unwrap()
            .add("entry", "anthropic", "synthetic".into(), None, None)
            .unwrap();
        opens.store(0, Ordering::SeqCst);
        let fixture = window.state::<Fixture>();
        fixture.pause_confirmation.store(true, Ordering::SeqCst);
        let first = pool_remove(window.clone(), requester(true), "entry".into());
        let second = async {
            fixture.confirm_entered.notified().await;
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                pool_remove(window.clone(), requester(true), "entry".into()),
            )
            .await;
            fixture.confirm_resume.notify_one();
            assert_eq!(
                result
                    .expect("single-flight must refuse without another dialog")
                    .unwrap_err(),
                "pool_custody_busy"
            );
        };
        let (result, ()) = tokio::join!(first, second);
        assert_eq!(result.unwrap_err(), "pool_removal_cancelled");
        assert_eq!(fixture.confirmations.load(Ordering::SeqCst), 1);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        let active = window.state::<RemovalGate>().0.clone();
        let first_dialog = RemovalPermit::acquire(active.clone()).unwrap();
        let worker = first_dialog.clone();
        drop(first_dialog);
        assert!(RemovalPermit::acquire(active.clone()).is_err());
        drop(worker);
        assert!(RemovalPermit::acquire(active).is_ok());
    }
    #[tokio::test]
    async fn pool_ipc_changed_entry_is_not_deleted_after_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let (_app, window, _) = app(&dir, "main", true);
        let pool = canonical_pool(&window).unwrap();
        pool.add("entry", "anthropic", "original".into(), None, None)
            .unwrap();
        *window.state::<Fixture>().after_confirm.lock().unwrap() = Some(Box::new(move || {
            pool.remove("entry").unwrap();
            pool.add("entry", "anthropic", "replacement".into(), None, None)
                .unwrap();
        }));
        assert_eq!(
            pool_remove(window.clone(), requester(true), "entry".into())
                .await
                .unwrap_err(),
            "pool_mutation_refused"
        );
        assert_eq!(
            canonical_pool(&window)
                .unwrap()
                .read_key("entry")
                .unwrap()
                .expose_secret(),
            "replacement"
        );
    }
    #[test]
    fn pool_ipc_owned_key_conversion_scrubs_without_shrinking() {
        let mut input = String::with_capacity(8192);
        input.push_str("synthetic-owned-buffer");
        let capacity = input.capacity();
        let pointer = input.as_ptr();
        let mut input = zeroize::Zeroizing::new(input);
        let key = key_from_owned_buffer(&mut input);
        assert_eq!(key.0.expose_secret(), "synthetic-owned-buffer");
        assert!(input.is_empty());
        assert_eq!(input.capacity(), capacity);
        assert_eq!(input.as_ptr(), pointer);
        let key: PoolKey = serde_json::from_value(serde_json::json!("synthetic-json-key")).unwrap();
        assert_eq!(key.0.expose_secret(), "synthetic-json-key");
    }
    #[test]
    fn pool_ipc_invalid_input_is_safe_and_does_not_create_custody() {
        let dir = tempfile::tempdir().unwrap();
        let (_app, window, opens) = app(&dir, "main", true);
        for (body, tag) in [
            (
                serde_json::json!({"name":"valid","provider":"anthropic","key":"synthetic\ncredential","reset":null,"monthlyCapUsd":null}),
                "pool_invalid_key",
            ),
            (
                serde_json::json!({"name":"valid","provider":"invalid-provider","key":"synthetic","reset":null,"monthlyCapUsd":null}),
                "pool_invalid_provider",
            ),
        ] {
            assert_eq!(
                ipc(&window, "pool_add", body, None, "tauri://localhost").unwrap_err(),
                serde_json::json!(tag)
            );
        }
        assert_eq!(
            ipc(
                &window,
                "pool_remove",
                serde_json::json!({"name":"../escape"}),
                None,
                "tauri://localhost"
            )
            .unwrap_err(),
            serde_json::json!("pool_invalid_name")
        );
        assert_eq!(
            ipc(
                &window,
                "pool_set_reset",
                serde_json::json!({"name":"valid","reset":{"day_of_month":31}}),
                None,
                "tauri://localhost"
            )
            .unwrap_err(),
            serde_json::json!("pool_invalid_reset")
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert!(!dir.path().join("pool").exists());
    }
    #[test]
    fn pool_ipc_acl_grants_match_production_registration() {
        let registration = include_str!("../mod.rs")
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .unwrap()
            .split("])")
            .next()
            .unwrap();
        let registered: std::collections::BTreeSet<_> = registration
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                line.starts_with("commands::").then(|| {
                    line.trim_end_matches(',')
                        .rsplit("::")
                        .next()
                        .unwrap()
                        .to_owned()
                })
            })
            .collect();
        let permission = include_str!("../../../permissions/legacy-main.toml");
        let list = permission.split("commands.allow = ").nth(1).unwrap();
        let mut granted: std::collections::BTreeSet<String> = serde_json::from_str(list).unwrap();
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../../../capabilities/default.json")).unwrap();
        assert_eq!(capability["windows"], serde_json::json!(["main"]));
        assert!(capability.get("remote").is_none());
        assert!(capability["permissions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("legacy-main")));
        for command in ["pool_list", "pool_add", "pool_remove", "pool_set_reset"] {
            assert!(capability["permissions"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(format!(
                    "allow-{}",
                    command.replace('_', "-")
                ))));
            assert!(granted.insert(command.into()));
        }
        assert_eq!(registered, granted);
    }
    // The shared capture lock must span the whole capture, awaits included;
    // tokio::test runs a current-thread runtime, so no other task here can
    // need it (clippy::await_holding_lock is about multi-task runtimes).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn pool_ipc_worker_panic_has_fixed_error_tag() {
        #[derive(Clone)]
        struct Writer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Writer(output.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _capture = csq_core::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        assert_eq!(
            blocking::<()>(|| panic!("synthetic panic payload"))
                .await
                .unwrap_err(),
            "pool_worker_unavailable"
        );
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("pool_worker_join_failed"));
        assert!(logs.contains("panicked=true"));
        assert!(!logs.contains("synthetic panic payload"));
    }
}
