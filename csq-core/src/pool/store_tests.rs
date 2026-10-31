use super::*;
use crate::platform::secret::file::FileVault;
use secrecy::ExposeSecret;

fn fixture() -> (tempfile::TempDir, Pool) {
    let dir = tempfile::tempdir().unwrap();
    let vault = FileVault::open_test(&dir.path().join("fixture-vault")).unwrap();
    let pool = Pool::with_vault(dir.path(), Box::new(vault));
    (dir, pool)
}
const SYNTHETIC: &str = "synthetic-pool-value-not-a-real-key";

#[derive(Clone)]
struct LossBeforeWriteVault {
    inner: std::sync::Arc<FileVault>,
    path: PathBuf,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl LossBeforeWriteVault {
    fn before_write(&self) {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            std::fs::remove_file(&self.path).unwrap();
        }
    }
}
impl Vault for LossBeforeWriteVault {
    fn named_store_present(&self) -> std::result::Result<bool, secret::SecretError> {
        self.inner.named_store_present()
    }
    fn set_named(
        &self,
        key: &NamedKey,
        secret: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        self.before_write();
        self.inner.set_named(key, secret)
    }
    fn set_named_existing(
        &self,
        key: &NamedKey,
        secret: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        self.before_write();
        self.inner.set_named_existing(key, secret)
    }
    fn get_named(&self, key: &NamedKey) -> std::result::Result<SecretString, secret::SecretError> {
        self.inner.get_named(key)
    }
    fn delete_named(&self, key: &NamedKey) -> std::result::Result<(), secret::SecretError> {
        self.inner.delete_named(key)
    }
    fn contains_named(&self, key: &NamedKey) -> std::result::Result<bool, secret::SecretError> {
        self.inner.contains_named(key)
    }
    fn set(
        &self,
        _: secret::SlotKey,
        _: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        panic!("fixture named-only")
    }
    fn get(&self, _: secret::SlotKey) -> std::result::Result<SecretString, secret::SecretError> {
        panic!("fixture named-only")
    }
    fn delete(&self, _: secret::SlotKey) -> std::result::Result<(), secret::SecretError> {
        panic!("fixture named-only")
    }
    fn list_slots(
        &self,
        _: &'static str,
    ) -> std::result::Result<Vec<crate::types::AccountNum>, secret::SecretError> {
        panic!("fixture named-only")
    }
    fn backend_id(&self) -> &'static str {
        self.inner.backend_id()
    }
}
fn loss_before_write_fixture() -> (tempfile::TempDir, Pool, LossBeforeWriteVault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = LossBeforeWriteVault {
        inner: std::sync::Arc::new(
            FileVault::open_test(&dir.path().join("fixture-vault")).unwrap(),
        ),
        path: dir.path().join("fixture-vault/pool-vault-store.json"),
        armed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let pool = Pool::with_vault(dir.path(), Box::new(vault.clone()));
    (dir, pool, vault)
}

#[test]
fn pool_add_losing_vault_after_presence_check_refuses_without_recreation() {
    let (dir, pool, vault) = loss_before_write_fixture();
    pool.add("a", "openai", SYNTHETIC.into(), None, Some(1.0))
        .unwrap();
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"b=synthetic-env-b\n").unwrap();
    pool.add_env_file(&env, &["b".into()], "openai", None, Some(1.0))
        .unwrap();
    vault.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        pool.add("c", "openai", "synthetic-native-c".into(), None, Some(1.0)),
        Err(PoolError::StoreUnavailable),
        "add must refuse when the native vault disappears at its writer"
    );
    assert!(
        !vault.path.try_exists().unwrap(),
        "refused add must not recreate the vault"
    );
    assert_eq!(pool.load().unwrap().entries.len(), 2);
    assert!(!pool.root.join("transaction.json").exists());
}

#[test]
fn pool_remove_backup_losing_vault_refuses_without_recreation() {
    let (_dir, pool, vault) = loss_before_write_fixture();
    pool.add("a", "openai", SYNTHETIC.into(), None, Some(1.0))
        .unwrap();
    pool.add("c", "openai", "synthetic-native-c".into(), None, Some(1.0))
        .unwrap();
    vault.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        pool.remove("a"),
        Err(PoolError::StoreUnavailable),
        "remove backup must refuse when the native vault disappears at its writer"
    );
    assert!(
        !vault.path.try_exists().unwrap(),
        "refused remove must not recreate the vault"
    );
    assert_eq!(pool.load().unwrap().entries.len(), 2);
    assert!(!pool.root.join("transaction.json").exists());
}

#[test]
fn pool_oversized_json_is_invalid_before_any_publication() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("manifest.json");
    let oversized = "x".repeat(MAX_MANIFEST_BYTES as usize + 1);
    assert_eq!(
        write_json(&destination, &oversized),
        Err(PoolError::ManifestInvalid),
        "oversized metadata is invalid, not a write failure"
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn pool_lost_native_vault_blocks_add_before_recreating_the_store() {
    let (dir, pool) = fixture();
    pool.add("a", "openai", SYNTHETIC.into(), None, Some(1.0))
        .unwrap();
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"b=synthetic-env-b\n").unwrap();
    pool.add_env_file(&env, &["b".into()], "openai", None, Some(1.0))
        .unwrap();
    let vault = dir.path().join("fixture-vault/pool-vault-store.json");
    std::fs::remove_file(&vault).unwrap();
    assert_eq!(
        pool.add("c", "openai", "synthetic-native-c".into(), None, Some(1.0)),
        Err(PoolError::StoreUnavailable),
        "a lost native store must refuse add before recreating it"
    );
    assert!(!vault.try_exists().unwrap());
    assert!(!pool.root.join("transaction.json").exists());
}

#[test]
fn pool_missing_vault_list_distinguishes_file_outage_from_missing_item() {
    let (dir, pool) = fixture();
    pool.add("a", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"b=synthetic-env-b\n").unwrap();
    pool.add_env_file(&env, &["b".into()], "openai", None, None)
        .unwrap();
    std::fs::remove_file(dir.path().join("fixture-vault/pool-vault-store.json")).unwrap();
    let rows = pool.list().unwrap();
    let native = rows
        .iter()
        .find(|row| row.entry.name.as_str() == "a")
        .unwrap();
    assert!(
        native.vault_file_missing,
        "listing must expose the missing vault file explicitly"
    );
    assert!(!native.present);
    let env = rows
        .iter()
        .find(|row| row.entry.name.as_str() == "b")
        .unwrap();
    assert!(env.present);
    assert!(!env.vault_file_missing);
    assert_eq!(
        serde_json::to_value(native).unwrap()["vault_file_missing"],
        true
    );
}

#[test]
fn pool_confirmed_missing_vault_allows_manifest_row_removal() {
    let (dir, pool) = fixture();
    pool.add("a", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    pool.add("c", "openai", "synthetic-native-c".into(), None, None)
        .unwrap();
    std::fs::remove_file(dir.path().join("fixture-vault/pool-vault-store.json")).unwrap();
    let snapshot = pool.removal_snapshot("a").unwrap();
    assert_eq!(
        pool.remove_if_unchanged_with_outcome(&snapshot),
        Ok(true),
        "confirmed absent vault must allow explicit removal of its manifest row"
    );
    assert_eq!(pool.remove_with_outcome("c"), Ok(true));
    assert!(pool.list().unwrap().is_empty());
    assert!(!pool.root.join("transaction.json").exists());
}

#[test]
fn pool_unreadable_native_vault_refuses_add_and_remove_as_store_wide() {
    let (dir, pool) = fixture();
    pool.add("a", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    std::fs::write(
        dir.path().join("fixture-vault/pool-vault-store.json"),
        b"invalid-json",
    )
    .unwrap();
    assert_eq!(
        pool.add("c", "openai", "synthetic-native-c".into(), None, None),
        Err(PoolError::StoreUnavailable)
    );
    assert_eq!(
        pool.remove("a"),
        Err(PoolError::StoreUnavailable),
        "an unreadable vault must refuse removal as a store-wide outage"
    );
    assert_eq!(pool.load().unwrap().entries.len(), 1);
}

#[test]
fn pool_file_custody_add_list_reset_read_remove_never_serializes_secret() {
    let (dir, pool) = fixture();
    pool.add(
        "credit.one",
        "anthropic",
        SYNTHETIC.into(),
        Some(Reset::Day { day_of_month: 7 }),
        Some(25.0),
    )
    .unwrap();
    let rows = pool.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].present);
    assert_eq!(rows[0].entry.name.as_str(), "credit.one");
    assert!(!serde_json::to_string(&rows).unwrap().contains(SYNTHETIC));
    for path in [
        dir.path().join("pool/manifest.json"),
        dir.path().join("fixture-vault/pool-vault-store.json"),
    ] {
        assert!(!std::fs::read_to_string(path).unwrap().contains(SYNTHETIC));
    }
    assert_eq!(
        pool.read_key("credit.one").unwrap().expose_secret(),
        SYNTHETIC
    );
    pool.set_reset(
        "credit.one",
        Some(Reset::Date {
            date: "2028-02-29".into(),
        }),
    )
    .unwrap();
    assert!(matches!(
        pool.list().unwrap()[0].entry.reset,
        Some(Reset::Date { .. })
    ));
    pool.set_reset("credit.one", None).unwrap();
    assert!(pool.list().unwrap()[0].entry.reset.is_none());
    pool.remove("credit.one").unwrap();
    assert!(pool.list().unwrap().is_empty());
    let vault = FileVault::open_test(&dir.path().join("fixture-vault")).unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("fixture-vault/pool-vault-store.json")).unwrap(),
    )
    .unwrap();
    assert!(body["named_entries"].as_array().is_none_or(Vec::is_empty));
    drop(vault);
}

#[test]
fn pool_invalid_metadata_and_duplicate_name_leave_committed_custody_unchanged() {
    let (dir, pool) = fixture();
    for name in ["", "name/escape", "space name", "é"] {
        assert!(PoolName::new(name).is_err());
    }
    assert!(PoolName::new(&"x".repeat(65)).is_err());
    assert!(PoolName::new("a.b-C_9").is_ok());
    for reset in [
        Reset::Day { day_of_month: 29 },
        Reset::Date {
            date: "2025-02-29".into(),
        },
    ] {
        assert_eq!(reset.validate(), Err(PoolError::InvalidReset));
    }
    assert_eq!(
        types::validate_options(None, Some(f64::NAN)),
        Err(PoolError::InvalidCap)
    );
    assert_eq!(
        types::validate_options(None, Some(-1.0)),
        Err(PoolError::InvalidCap)
    );
    assert_eq!(
        types::validate_provider("unknown-provider"),
        Err(PoolError::InvalidProvider)
    );
    for provider in ["claude", "codex", "grok", "gemini"] {
        assert_eq!(
            Pool::validate_add("one", provider, None, None),
            Err(PoolError::InvalidProvider)
        );
    }
    assert!(Pool::validate_add("one", "deepseek", None, None).is_ok());
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let before = std::fs::read(dir.path().join("pool/manifest.json")).unwrap();
    assert_eq!(
        pool.add("one", "openai", "other-synthetic-key".into(), None, None),
        Err(PoolError::NameExists)
    );
    assert_eq!(
        std::fs::read(dir.path().join("pool/manifest.json")).unwrap(),
        before
    );
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
}

#[test]
fn pool_env_file_is_literal_allowlisted_and_reread_per_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.env");
    crate::platform::fs::write_new_private_synced(
        &path,
        b"credit.one='synthetic-first'\nforeign=unadmitted\n",
    )
    .unwrap();
    let pool = Pool::new(dir.path());
    pool.add_env_file(&path, &["credit.one".into()], "anthropic", None, None)
        .unwrap();
    assert_eq!(pool.read_key("foreign").unwrap_err(), PoolError::KeyMissing);
    assert_eq!(
        pool.read_key("credit.one").unwrap().expose_secret(),
        "synthetic-first"
    );
    std::fs::write(
        &path,
        "export credit.one=synthetic-second\nforeign=unadmitted\n",
    )
    .unwrap();
    assert_eq!(
        pool.read_key("credit.one").unwrap().expose_secret(),
        "synthetic-second"
    );
    std::fs::write(&path, "credit.one=$(false)\n").unwrap();
    assert_eq!(
        pool.read_key("credit.one").unwrap().expose_secret(),
        "$(false)"
    );
    pool.remove("credit.one").unwrap();
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "credit.one=$(false)\n"
    );
}

#[test]
fn pool_presence_does_not_parse_value_and_ambiguous_admitted_values_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.env");
    crate::platform::fs::write_new_private_synced(&path, b"one=synthetic-initial\n").unwrap();
    let pool = Pool::new(dir.path());
    pool.add_env_file(&path, &["one".into()], "anthropic", None, None)
        .unwrap();
    // Admission now fingerprints a valid value. Listing still checks only
    // assignment presence after a later source edit makes its value invalid.
    std::fs::write(&path, b"one='unterminated\n").unwrap();
    assert!(pool.list().unwrap()[0].present);
    assert_eq!(pool.read_key("one").unwrap_err(), PoolError::EnvFileInvalid);
    std::fs::write(&path, "one=synthetic-one\none=synthetic-two\n").unwrap();
    assert_eq!(pool.read_key("one").unwrap_err(), PoolError::EnvFileInvalid);
}

#[test]
fn pool_corrupt_manifest_and_unknown_fields_fail_closed_without_overwrite() {
    let (dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let path = dir.path().join("pool/manifest.json");
    for text in [
        "{",
        "{\"version\":1,\"env_file\":null,\"entries\":[],\"unexpected\":true}",
    ] {
        std::fs::write(&path, text).unwrap();
        assert_eq!(pool.list().unwrap_err(), PoolError::ManifestInvalid);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}

#[test]
fn pool_recovery_restores_uncommitted_remove_and_cleans_committed_remove() {
    for committed in [false, true] {
        let (_dir, pool) = fixture();
        pool.add("one", "openai", SYNTHETIC.into(), None, None)
            .unwrap();
        let mut manifest = pool.load().unwrap();
        let row = manifest.entries[0].clone();
        let backup_id = fresh_id();
        pool.with_store(|v| {
            v.set_named(&key(&backup_id)?, &SecretString::from(SYNTHETIC))
                .unwrap();
            v.delete_named(&key(row.secret_id.as_ref().unwrap())?)
                .unwrap();
            Ok(())
        })
        .unwrap();
        if committed {
            manifest.entries.clear();
        } else {
            manifest.entries[0].remove_backup_id = Some(backup_id.clone());
        }
        pool.save(&manifest).unwrap();
        write_json(
            &pool.root.join("transaction.json"),
            &Journal::Remove {
                row,
                phase: Some(RemovePhase::OriginalDelete),
                backup_id,
                recovery_safe: true,
                backend_id: "linux-file-aes".into(),
                writer: Writer::current(),
            },
        )
        .unwrap();
        assert_eq!(pool.list().unwrap_err(), PoolError::RecoveryRequired);
        pool.recover_pending().unwrap();
        if committed {
            assert!(pool.list().unwrap().is_empty());
        } else {
            assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
        }
    }
}

#[test]
fn pool_uncertain_native_journal_refuses_replay_without_reading_or_deleting_keys() {
    let (_dir, pool) = fixture();
    pool.add("one", "anthropic", SYNTHETIC.into(), None, None)
        .unwrap();
    let row = pool.load().unwrap().entries[0].clone();
    write_json(
        &pool.root.join("transaction.json"),
        &Journal::Add {
            row,
            recovery_safe: false,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
    )
    .unwrap();
    assert_eq!(pool.list().unwrap_err(), PoolError::RecoveryRequired);
    assert!(pool.root.join("transaction.json").exists());
}

#[cfg(unix)]
#[test]
fn pool_custody_files_are_private_and_symlink_manifest_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (dir, pool) = fixture();
    pool.add("one", "anthropic", SYNTHETIC.into(), None, None)
        .unwrap();
    let path = dir.path().join("pool/manifest.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("pool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let target = dir.path().join("unrelated");
    std::fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    let prior = std::fs::read(&target).unwrap();
    assert_eq!(pool.list().unwrap_err(), PoolError::ManifestUnavailable);
    assert_eq!(std::fs::read(target).unwrap(), prior);
}

#[test]
#[ignore = "requires separate owner authorization: exactly one live reqwest Messages call"]
fn pool_operator_reqwest_probe_sends_one_minimal_messages_call() {
    let _env = crate::platform::test_env::lock();
    let base = std::env::var("CSQ_POOL_PROBE_BASE_DIR").expect("set explicit pool base");
    let name = std::env::var("CSQ_POOL_PROBE_NAME").expect("set explicit admitted name");
    let model = std::env::var("CSQ_POOL_PROBE_MODEL").expect("set explicit model");
    assert!(
        model.len() <= 128
            && model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)),
        "invalid model"
    );
    let pool = Pool::new(Path::new(&base));
    assert_eq!(
        pool.list()
            .unwrap()
            .iter()
            .find(|r| r.entry.name.as_str() == name)
            .unwrap()
            .entry
            .provider,
        "anthropic"
    );
    let key = pool.read_key(&name).expect("pool key unavailable");
    let status = crate::http::post_messages_status_once(&model, &key)
        .unwrap_or_else(|error| panic!("{}", crate::error::redact_tokens(&error)));
    println!("status={} model={}", status, model);
    assert!((200..300).contains(&status), "probe_http_refused");
}

#[derive(Clone)]
struct FaultVault {
    inner: std::sync::Arc<secret::in_memory::InMemoryVault>,
    fault: std::sync::Arc<std::sync::atomic::AtomicU8>,
    manifest: PathBuf,
    last_named: std::sync::Arc<std::sync::Mutex<Option<NamedKey>>>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    delete_fault: std::sync::Arc<std::sync::atomic::AtomicU8>,
    completed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Vault for FaultVault {
    fn backend_id(&self) -> &'static str {
        "fixture-native"
    }
    fn named_worker_state(&self, _: &NamedKey) -> secret::NamedWorkerState {
        if self.completed.load(std::sync::atomic::Ordering::SeqCst) {
            secret::NamedWorkerState::Completed
        } else {
            secret::NamedWorkerState::Unknown
        }
    }
    fn set_named(
        &self,
        name: &NamedKey,
        value: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_named.lock().unwrap() = Some(name.clone());
        match self.fault.swap(0, Ordering::SeqCst) {
            1 => Err(secret::SecretError::Locked),
            4 => Err(secret::SecretError::PermissionDenied {
                reason: "synthetic refusal".into(),
            }),
            5 => Err(secret::SecretError::AuthorizationRequired),
            2 => {
                self.inner.set_named(name, value)?;
                Err(secret::SecretError::NamedOutcomeUnknown)
            }
            3 => {
                self.inner.set_named(name, value)?;
                // The salt is already durable before the native mutation.
                // Replace that manifest with an irregular target to fail publication.
                std::fs::remove_file(&self.manifest).unwrap();
                std::fs::create_dir(&self.manifest).unwrap();
                Ok(())
            }
            _ => self.inner.set_named(name, value),
        }
    }
    fn get_named(&self, name: &NamedKey) -> std::result::Result<SecretString, secret::SecretError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get_named(name)
    }
    fn delete_named(&self, name: &NamedKey) -> std::result::Result<(), secret::SecretError> {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.delete_fault.swap(0, Ordering::SeqCst) {
            1 => Err(secret::SecretError::Locked),
            2 => {
                self.inner.delete_named(name)?;
                Err(secret::SecretError::NamedOutcomeUnknown)
            }
            _ => self.inner.delete_named(name),
        }
    }
    fn contains_named(&self, name: &NamedKey) -> std::result::Result<bool, secret::SecretError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fault.load(std::sync::atomic::Ordering::SeqCst) == 6 {
            return Err(secret::SecretError::Locked);
        }
        self.inner.contains_named(name)
    }
    fn set(
        &self,
        _: secret::SlotKey,
        _: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        panic!("slot API forbidden")
    }
    fn get(&self, _: secret::SlotKey) -> std::result::Result<SecretString, secret::SecretError> {
        panic!("slot API forbidden")
    }
    fn delete(&self, _: secret::SlotKey) -> std::result::Result<(), secret::SecretError> {
        panic!("slot API forbidden")
    }
    fn list_slots(
        &self,
        _: &'static str,
    ) -> std::result::Result<Vec<crate::types::AccountNum>, secret::SecretError> {
        panic!("slot API forbidden")
    }
}
fn fault_fixture(mode: u8) -> (tempfile::TempDir, Pool, FaultVault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = FaultVault {
        inner: std::sync::Arc::new(secret::in_memory::InMemoryVault::new()),
        fault: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(mode)),
        manifest: dir.path().join("pool/manifest.json"),
        last_named: std::sync::Arc::new(std::sync::Mutex::new(None)),
        calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        delete_fault: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
        completed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let pool = Pool::with_vault(dir.path(), Box::new(vault.clone()));
    (dir, pool, vault)
}
#[test]
fn pool_definite_locked_refusal_clears_journal_and_preserves_usability() {
    for mode in [1, 4, 5] {
        let (_dir, pool, _) = fault_fixture(mode);
        assert_eq!(
            pool.add("one", "openai", SYNTHETIC.into(), None, None),
            Err(PoolError::MutationRefused)
        );
        assert!(!pool.root.join("transaction.json").exists());
        assert!(pool.list().unwrap().is_empty());
        pool.add("one", "openai", SYNTHETIC.into(), None, None)
            .unwrap();
        assert!(pool.list().unwrap()[0].present);
    }
}
#[test]
fn pool_unknown_outcome_refuses_live_writer_then_recovers_dead_writer() {
    let (_dir, pool, vault) = fault_fixture(2);
    assert_eq!(
        pool.add("one", "openai", SYNTHETIC.into(), None, None),
        Err(PoolError::RecoveryRequired)
    );
    assert_eq!(pool.recover_pending(), Err(PoolError::RecoveryWriterAlive));
    let path = pool.root.join("transaction.json");
    let mut journal: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let id = match &mut journal {
        Journal::Add { row, writer, .. } => {
            writer.pid = 99_999_999;
            row.secret_id.clone().unwrap()
        }
        _ => panic!("add"),
    };
    assert!(vault.contains_named(&key(&id).unwrap()).unwrap());
    write_json(&path, &journal).unwrap();
    pool.recover_pending().unwrap();
    assert!(!vault.contains_named(&key(&id).unwrap()).unwrap());
    assert!(pool.list().unwrap().is_empty());
}
#[test]
fn pool_add_publication_failure_compensates_native_item_inline() {
    let (_dir, pool, vault) = fault_fixture(3);
    assert_eq!(
        pool.add("one", "openai", SYNTHETIC.into(), None, None),
        Err(PoolError::ManifestWriteUnavailable)
    );
    assert!(!pool.root.join("transaction.json").exists());
    let name = vault.last_named.lock().unwrap().clone().unwrap();
    assert!(!vault.contains_named(&name).unwrap());
    std::fs::remove_dir(pool.root.join("manifest.json")).unwrap();
    assert!(pool.list().unwrap().is_empty());
}
#[test]
fn pool_add_journal_recovery_distinguishes_committed_and_uncommitted() {
    let (_dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let row = pool.load().unwrap().entries[0].clone();
    let journal = Journal::Add {
        row: row.clone(),
        recovery_safe: true,
        backend_id: "linux-file-aes".into(),
        writer: Writer::current(),
    };
    write_json(&pool.root.join("transaction.json"), &journal).unwrap();
    pool.recover_pending().unwrap();
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
    pool.save(&Manifest::empty()).unwrap();
    write_json(&pool.root.join("transaction.json"), &journal).unwrap();
    pool.recover_pending().unwrap();
    pool.with_store(|v| {
        assert!(!v
            .contains_named(&key(row.secret_id.as_ref().unwrap())?)
            .unwrap());
        Ok(())
    })
    .unwrap();
}
#[test]
fn pool_journal_backend_and_cross_entry_ids_refuse_without_modifying_keys() {
    let (_dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    pool.add("two", "openai", "synthetic-second-key".into(), None, None)
        .unwrap();
    let manifest = pool.load().unwrap();
    let mut absent = manifest.entries[0].clone();
    absent.entry.name = PoolName::new("absent").unwrap();
    let mut noncanonical = manifest.entries[0].clone();
    noncanonical.entry.name = PoolName::new("noncanonical.absent").unwrap();
    noncanonical.secret_id = Some("ABCDEF0123456789ABCDEF0123456789".into());
    let journals = [
        Journal::Add {
            row: noncanonical,
            recovery_safe: true,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
        Journal::Add {
            row: manifest.entries[0].clone(),
            recovery_safe: true,
            backend_id: "wrong-backend".into(),
            writer: Writer::current(),
        },
        Journal::Add {
            row: absent,
            recovery_safe: true,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
        Journal::Remove {
            phase: None,
            row: manifest.entries[0].clone(),
            backup_id: manifest.entries[1].secret_id.clone().unwrap(),
            recovery_safe: true,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
    ];
    for journal in journals {
        write_json(&pool.root.join("transaction.json"), &journal).unwrap();
        assert_eq!(pool.recover_pending(), Err(PoolError::RecoveryRequired));
        pool.clear_journal().unwrap();
        assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
        assert_eq!(
            pool.read_key("two").unwrap().expose_secret(),
            "synthetic-second-key"
        );
    }
}
#[test]
fn pool_missing_item_presence_and_reset_unknown_fields_are_explicit() {
    let (_dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let row = pool.load().unwrap().entries[0].clone();
    pool.with_store(|v| {
        v.delete_named(&key(row.secret_id.as_ref().unwrap())?)
            .unwrap();
        Ok(())
    })
    .unwrap();
    write_json(
        &pool.root.join("transaction.json"),
        &Journal::Add {
            row: row.clone(),
            recovery_safe: true,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
    )
    .unwrap();
    pool.recover_pending().unwrap();
    assert!(!pool.list().unwrap()[0].present);
    pool.remove("one").unwrap();
    for input in [
        r#"{"day_of_month":1,"unknown":true}"#,
        r#"{"date":"2100-01-01","unknown":true}"#,
    ] {
        assert!(serde_json::from_str::<Reset>(input).is_err());
    }
}
#[cfg(unix)]
#[test]
fn pool_env_file_writable_source_is_refused_on_admission_and_every_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.env");
    std::fs::write(&path, "one=synthetic-value\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let pool = Pool::new(dir.path());
    assert_eq!(
        pool.add_env_file(&path, &["one".into()], "openai", None, None),
        Err(PoolError::EnvFileUnavailable)
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    pool.add_env_file(&path, &["one".into()], "openai", None, None)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert_eq!(
        pool.read_key("one").unwrap_err(),
        PoolError::EnvFileUnavailable
    );
    assert_eq!(pool.list().unwrap_err(), PoolError::EnvFileUnavailable);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(pool.list().unwrap()[0].present);
}
#[test]
fn pool_listing_is_all_or_nothing_when_one_source_is_unavailable() {
    let (dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let path = dir.path().join("keys.env");
    crate::platform::fs::write_new_private_synced(&path, b"two=synthetic-value\n").unwrap();
    pool.add_env_file(&path, &["two".into()], "openai", None, None)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(pool.list().unwrap_err(), PoolError::EnvFileUnavailable);
}

#[test]
fn pool_pending_journal_ordinary_operations_never_touch_vault_or_journal() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let journal = Journal::Add {
        row: pool.load().unwrap().entries[0].clone(),
        recovery_safe: true,
        backend_id: vault.backend_id().into(),
        writer: Writer::current(),
    };
    let path = pool.root.join("transaction.json");
    write_json(&path, &journal).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let calls = vault.calls.load(Ordering::SeqCst);
    assert_eq!(pool.list().unwrap_err(), PoolError::RecoveryRequired);
    assert_eq!(
        pool.set_reset("one", None),
        Err(PoolError::RecoveryRequired)
    );
    assert_eq!(
        pool.read_key("one").unwrap_err(),
        PoolError::RecoveryRequired
    );
    assert_eq!(vault.calls.load(Ordering::SeqCst), calls);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    pool.recover_pending().unwrap();
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
}

#[test]
fn pool_remove_recovery_preserves_original_against_planted_backup() {
    let (_dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let row = pool.load().unwrap().entries[0].clone();
    let backup_id = fresh_id();
    pool.with_store(|v| {
        v.set_named(&key(&backup_id)?, &SecretString::from("planted-different"))
            .unwrap();
        Ok(())
    })
    .unwrap();
    write_json(
        &pool.root.join("transaction.json"),
        &Journal::Remove {
            phase: Some(RemovePhase::OriginalDelete),
            row: row.clone(),
            backup_id: backup_id.clone(),
            recovery_safe: true,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
    )
    .unwrap();
    assert_eq!(pool.recover_pending(), Err(PoolError::RecoveryRequired));
    pool.with_store(|v| {
        assert_eq!(
            v.get_named(&key(row.secret_id.as_ref().unwrap())?)
                .unwrap()
                .expose_secret(),
            SYNTHETIC
        );
        Ok(())
    })
    .unwrap();
    std::fs::remove_file(pool.root.join("transaction.json")).unwrap();
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
    pool.with_store(|v| {
        assert!(v.contains_named(&key(&backup_id)?).unwrap());
        Ok(())
    })
    .unwrap();
}

#[test]
fn pool_writer_liveness_tolerates_jitter_and_refuses_unreadable_identity() {
    let writer = Writer {
        boot: current_boot(),
        pid: 123,
        started_at: Some("100".into()),
    };
    assert!(writer.possibly_alive_with(|_| true, |_| Some("101".into())));
    assert!(!writer.possibly_alive_with(|_| true, |_| Some("102".into())));
    assert!(writer.possibly_alive_with(|_| true, |_| None));
    assert!(writer.possibly_alive_with(|_| true, |_| Some("unreadable".into())));
    assert!(!writer.possibly_alive_with(|_| false, |_| panic!("dead PID does not need start")));
}

#[test]
fn pool_remove_confirmation_refuses_readded_secret_and_env_rows_without_deletes() {
    use std::sync::atomic::Ordering;
    let (dir, pool, vault) = fault_fixture(0);
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let snapshot = pool.removal_snapshot("one").unwrap();
    assert_eq!(snapshot.entry.name.as_str(), "one");
    pool.remove("one").unwrap();
    pool.add("one", "openai", "replacement-synthetic".into(), None, None)
        .unwrap();
    let calls = vault.calls.load(Ordering::SeqCst);
    assert_eq!(
        pool.remove_if_unchanged(&snapshot),
        Err(PoolError::MutationRefused)
    );
    assert_eq!(calls, vault.calls.load(Ordering::SeqCst));
    assert_eq!(
        pool.read_key("one").unwrap().expose_secret(),
        "replacement-synthetic"
    );
    let path = dir.path().join("fixture.env");
    crate::platform::fs::write_new_private_synced(&path, b"env.one=synthetic-env\n").unwrap();
    pool.add_env_file(&path, &["env.one".into()], "openai", None, None)
        .unwrap();
    let snapshot = pool.removal_snapshot("env.one").unwrap();
    let before = pool
        .load()
        .unwrap()
        .entries
        .iter()
        .find(|r| r.entry.name.as_str() == "env.one")
        .unwrap()
        .clone();
    pool.remove("env.one").unwrap();
    pool.add_env_file(&path, &["env.one".into()], "openai", None, None)
        .unwrap();
    // Force identical timestamp/metadata: only the persisted generation distinguishes ABA.
    let mut manifest = pool.load().unwrap();
    let replacement = manifest
        .entries
        .iter_mut()
        .find(|r| r.entry.name.as_str() == "env.one")
        .unwrap();
    replacement.entry = before.entry;
    pool.save(&manifest).unwrap();
    assert_eq!(
        pool.remove_if_unchanged(&snapshot),
        Err(PoolError::MutationRefused)
    );
    assert_eq!(
        pool.read_key("env.one").unwrap().expose_secret(),
        "synthetic-env"
    );
}

#[test]
fn pool_default_vault_override_is_scoped_and_nested_for_new_constructors() {
    let dir = tempfile::tempdir().unwrap();
    let first = std::sync::Arc::new(secret::in_memory::InMemoryVault::new());
    let second = std::sync::Arc::new(secret::in_memory::InMemoryVault::new());
    Pool::with_default_vault_for_test(first.clone(), || {
        let pool = Pool::new(dir.path());
        pool.add("one", "openai", SYNTHETIC.into(), None, None)
            .unwrap();
        assert_eq!(
            Pool::new(dir.path())
                .read_key("one")
                .unwrap()
                .expose_secret(),
            SYNTHETIC
        );
        Pool::with_default_vault_for_test(second, || {
            assert_eq!(
                Pool::new(dir.path()).read_key("one").unwrap_err(),
                PoolError::KeyMissing
            )
        });
        assert_eq!(
            Pool::new(dir.path())
                .read_key("one")
                .unwrap()
                .expose_secret(),
            SYNTHETIC
        );
    });
    assert!(DEFAULT_TEST_VAULT.with(|slot| slot.borrow().is_none()));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Pool::with_default_vault_for_test(first, || panic!("synthetic unwind"))
    }));
    assert!(panicked.is_err());
    assert!(DEFAULT_TEST_VAULT.with(|slot| slot.borrow().is_none()));
}

#[test]
fn pool_delete_faults_compensate_definite_refusal_and_preserve_unknown_journal() {
    use std::sync::atomic::Ordering;
    for fault in [1, 2] {
        let (_dir, pool, vault) = fault_fixture(0);
        pool.add("one", "openai", SYNTHETIC.into(), None, None)
            .unwrap();
        vault.delete_fault.store(fault, Ordering::SeqCst);
        if fault == 1 {
            assert_eq!(pool.remove("one"), Err(PoolError::MutationRefused));
            assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
            assert!(!pool.root.join("transaction.json").exists());
        } else {
            assert_eq!(pool.remove("one"), Err(PoolError::RecoveryRequired));
            let path = pool.root.join("transaction.json");
            let bytes = std::fs::read(&path).unwrap();
            let _ = bytes;
            pool.recover_pending().unwrap();
            assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
        }
    }
}

#[test]
fn pool_uncertain_native_add_keeps_durable_cleanup_for_late_completion() {
    let (_dir, pool, vault) = fault_fixture(2);
    assert_eq!(
        pool.add("one", "openai", SYNTHETIC.into(), None, None),
        Err(PoolError::RecoveryRequired)
    );
    let path = pool.root.join("transaction.json");
    let mut journal: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let id = match &mut journal {
        Journal::Add { row, writer, .. } => {
            writer.pid = 99_999_999;
            row.secret_id.clone().unwrap()
        }
        _ => unreachable!(),
    };
    write_json(&path, &journal).unwrap();
    pool.recover_pending().unwrap();
    assert!(pool.root.join("cleanup.json").exists());
    assert!(!vault.inner.contains_named(&key(&id).unwrap()).unwrap());
    // Simulate the external service completing its earlier create after recovery.
    vault
        .inner
        .set_named(&key(&id).unwrap(), &SecretString::from(SYNTHETIC))
        .unwrap();
    assert!(pool.list().unwrap().is_empty());
    pool.recover_pending().unwrap();
    assert!(!vault.inner.contains_named(&key(&id).unwrap()).unwrap());
    assert!(
        pool.root.join("cleanup.json").exists(),
        "no finite delay proves no later completion"
    );
}

#[test]
fn pool_uncertain_native_remove_never_restores_before_external_completion_proof() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let old_id = pool.load().unwrap().entries[0].secret_id.clone().unwrap();
    vault.delete_fault.store(2, Ordering::SeqCst);
    assert_eq!(pool.remove("one"), Err(PoolError::RecoveryRequired));
    pool.recover_pending().unwrap();
    let new_id = pool.load().unwrap().entries[0].secret_id.clone().unwrap();
    assert_ne!(old_id, new_id);
    // Late completion addresses the old ID and cannot erase the admitted backup.
    vault.inner.delete_named(&key(&old_id).unwrap()).unwrap();
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
}

#[test]
fn pool_completed_native_worker_allows_same_process_explicit_recovery() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(2);
    assert_eq!(
        pool.add("one", "openai", SYNTHETIC.into(), None, None),
        Err(PoolError::RecoveryRequired)
    );
    assert_eq!(pool.recover_pending(), Err(PoolError::RecoveryWriterAlive));
    vault.completed.store(true, Ordering::SeqCst);
    pool.recover_pending().unwrap();
    assert!(pool.list().unwrap().is_empty());
    assert!(
        !pool.root.join("cleanup.json").exists(),
        "observed native-call completion needs no late-create tombstone"
    );
}

#[test]
fn pool_recovery_unlocking_presence_survives_locked_metadata_check() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let row = pool.load().unwrap().entries[0].clone();
    let original = key(row.secret_id.as_ref().unwrap()).unwrap();
    let backup_id = fresh_id();
    vault
        .inner
        .set_named(&key(&backup_id).unwrap(), &SecretString::from(SYNTHETIC))
        .unwrap();
    vault.inner.delete_named(&original).unwrap();
    let mut manifest = pool.load().unwrap();
    manifest.entries[0].remove_backup_id = Some(backup_id.clone());
    pool.save(&manifest).unwrap();
    write_json(
        &pool.root.join("transaction.json"),
        &Journal::Remove {
            phase: Some(RemovePhase::OriginalDelete),
            row,
            backup_id,
            recovery_safe: true,
            backend_id: vault.backend_id().into(),
            writer: Writer::current(),
        },
    )
    .unwrap();
    vault.fault.store(6, Ordering::SeqCst);
    assert!(matches!(
        vault.contains_named(&original),
        Err(secret::SecretError::Locked)
    ));
    pool.recover_pending().unwrap();
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
    assert!(!pool.root.join("transaction.json").exists());
}

struct NativeFileFixture(FileVault);
impl Vault for NativeFileFixture {
    fn backend_id(&self) -> &'static str {
        "macos-keychain"
    }
    fn set_named(
        &self,
        k: &NamedKey,
        s: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        self.0.set_named(k, s)
    }
    fn set_named_existing(
        &self,
        k: &NamedKey,
        s: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        self.0.set_named_existing(k, s)
    }
    fn get_named(&self, k: &NamedKey) -> std::result::Result<SecretString, secret::SecretError> {
        self.0.get_named(k)
    }
    fn contains_named(&self, k: &NamedKey) -> std::result::Result<bool, secret::SecretError> {
        self.0.contains_named(k)
    }
    fn delete_named(&self, k: &NamedKey) -> std::result::Result<(), secret::SecretError> {
        self.0.delete_named(k)
    }
    fn set(
        &self,
        _: secret::SlotKey,
        _: &SecretString,
    ) -> std::result::Result<(), secret::SecretError> {
        panic!("fixture named-only")
    }
    fn get(&self, _: secret::SlotKey) -> std::result::Result<SecretString, secret::SecretError> {
        panic!("fixture named-only")
    }
    fn delete(&self, _: secret::SlotKey) -> std::result::Result<(), secret::SecretError> {
        panic!("fixture named-only")
    }
    fn list_slots(
        &self,
        _: &'static str,
    ) -> std::result::Result<Vec<crate::types::AccountNum>, secret::SecretError> {
        panic!("fixture named-only")
    }
}
fn native_file_pool(base: &Path) -> Pool {
    Pool::with_vault(
        base,
        Box::new(NativeFileFixture(
            FileVault::open_test(&base.join("native-fixture")).unwrap(),
        )),
    )
}
fn fixture_boot(time: u64) -> BootStamp {
    BootStamp {
        identity: format!("fixture:{time}"),
        started_at: time,
        uptime_ms: None,
    }
}
#[test]
#[ignore = "subprocess fixture entrypoint: invoked only with synthetic fixture paths by parent tests"]
fn pool_native_restart_child() {
    let base = PathBuf::from(std::env::var_os("CSQ_POOL_PHASE_FIXTURE").unwrap());
    TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(Some(fixture_boot(200))));
    let pool = native_file_pool(&base);
    if std::env::var("CSQ_POOL_PHASE_OPERATION").as_deref() == Ok("recover") {
        pool.recover_pending().unwrap();
    }
    if std::env::var("CSQ_POOL_PHASE_OPERATION").as_deref() == Ok("startup") {
        assert_eq!(
            pool.recover_after_restart().unwrap(),
            RestartRecovery::Recovered
        );
        assert!(!pool.root.join("transaction.json").exists());
    }
    let rows = pool.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(pool.read_key("one").unwrap().expose_secret(), SYNTHETIC);
    std::fs::write(base.join("child-completed"), b"verified-new-process").unwrap();
}
fn run_native_restart_matrix(operation: &str) {
    for crash in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let pool = native_file_pool(dir.path());
        pool.add("one", "openai", SYNTHETIC.into(), None, None)
            .unwrap();
        let mut manifest = pool.load().unwrap();
        let row = manifest.entries[0].clone();
        let original = row.secret_id.clone().unwrap();
        let backup_id = fresh_id();
        if crash >= 1 {
            pool.with_store(|v| {
                v.set_named(&key(&backup_id)?, &SecretString::from(SYNTHETIC))
                    .unwrap();
                Ok(())
            })
            .unwrap();
        }
        if crash >= 2 {
            manifest.entries[0].remove_backup_id = Some(backup_id.clone());
            pool.save(&manifest).unwrap();
        }
        let phase = if crash >= 3 {
            RemovePhase::OriginalDelete
        } else {
            RemovePhase::BackupWrite
        };
        if crash >= 4 {
            pool.with_store(|v| {
                v.delete_named(&key(&original)?).unwrap();
                Ok(())
            })
            .unwrap();
        }
        let mut writer = Writer::current();
        writer.boot = Some(fixture_boot(100)); // prior host boot, even if PID numerically reused
        write_json(
            &pool.root.join("transaction.json"),
            &Journal::Remove {
                row,
                phase: Some(phase),
                backup_id: backup_id.clone(),
                recovery_safe: false,
                backend_id: "macos-keychain".into(),
                writer,
            },
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .args([
                "pool::store::tests::pool_native_restart_child",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("CSQ_POOL_PHASE_FIXTURE", dir.path())
            .env("CSQ_POOL_PHASE_OPERATION", operation)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "crash={crash} operation={operation} child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored"));
        assert_eq!(
            std::fs::read(dir.path().join("child-completed")).unwrap(),
            b"verified-new-process"
        );
        let recovered = pool.load().unwrap();
        if crash >= 3 {
            assert_eq!(recovered.entries[0].secret_id.as_ref(), Some(&backup_id));
        } else {
            assert_eq!(recovered.entries[0].secret_id.as_ref(), Some(&original));
        }
        assert!(recovered.entries[0].remove_backup_id.is_none());
        assert!(!pool.root.join("transaction.json").exists());
    }
}
#[test]
fn pool_native_phase_crashes_auto_unlock_next_operation_in_new_process_after_reboot() {
    run_native_restart_matrix("next-operation");
}
#[test]
fn pool_native_phase_crashes_explicit_recovery_in_new_process_after_reboot() {
    run_native_restart_matrix("recover");
}
#[test]
fn pool_boot_proof_missing_unreadable_or_future_never_implicitly_recovers() {
    let (_dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    for previous in [None, Some(fixture_boot(200)), Some(fixture_boot(300))] {
        let mut writer = Writer::current();
        writer.boot = previous;
        write_json(
            &pool.root.join("transaction.json"),
            &Journal::Add {
                row: pool.load().unwrap().entries[0].clone(),
                recovery_safe: false,
                backend_id: "linux-file-aes".into(),
                writer,
            },
        )
        .unwrap();
        TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(Some(fixture_boot(200))));
        assert_eq!(pool.list().unwrap_err(), PoolError::RecoveryRequired);
    }
    TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(None));
    assert_eq!(pool.list().unwrap_err(), PoolError::RecoveryRequired);
    TEST_BOOT.with(|slot| *slot.borrow_mut() = None);
}
#[test]
fn pool_prior_boot_cleanup_prunes_only_after_successful_final_delete() {
    let (_dir, pool, vault) = fault_fixture(0);
    pool.custody().unwrap();
    let id = fresh_id();
    vault
        .inner
        .set_named(&key(&id).unwrap(), &SecretString::from(SYNTHETIC))
        .unwrap();
    write_json(
        &pool.root.join("cleanup.json"),
        &CleanupTombstones {
            boot: Some(fixture_boot(100)),
            backend_id: vault.backend_id().into(),
            ids: vec![id.clone()],
        },
    )
    .unwrap();
    TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(Some(fixture_boot(200))));
    pool.recover_pending().unwrap();
    assert!(!pool.root.join("cleanup.json").exists());
    assert!(!vault.inner.contains_named(&key(&id).unwrap()).unwrap());
    TEST_BOOT.with(|slot| *slot.borrow_mut() = None);
}

#[test]
fn pool_windows_supported_boot_property_parser_refuses_missing_malformed_and_oversize() {
    for input in [
        b"".as_slice(),
        b"garbage",
        b"-1",
        b"621355968000000000",
        b"621355967999999999",
        b"18446744073709551616",
    ] {
        assert!(parse_windows_boot(input).is_none());
    }
    assert!(parse_windows_boot(&[b'1'; 65]).is_none());
    let boot = parse_windows_boot(b"621355970000000000\r\n").unwrap();
    assert_eq!(boot.started_at, 200);
    assert_eq!(boot.identity, "windows-cim:621355970000000000");
}

#[test]
fn pool_missing_original_rejects_unadmitted_planted_backup_without_vault_operations() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let row = pool.load().unwrap().entries[0].clone();
    let original = key(row.secret_id.as_ref().unwrap()).unwrap();
    let backup_id = fresh_id();
    vault.inner.delete_named(&original).unwrap();
    vault
        .inner
        .set_named(
            &key(&backup_id).unwrap(),
            &SecretString::from("planted-substitution"),
        )
        .unwrap();
    write_json(
        &pool.root.join("transaction.json"),
        &Journal::Remove {
            row,
            phase: Some(RemovePhase::OriginalDelete),
            backup_id: backup_id.clone(),
            recovery_safe: true,
            backend_id: vault.backend_id().into(),
            writer: Writer::current(),
        },
    )
    .unwrap();
    let before = std::fs::read(pool.root.join("transaction.json")).unwrap();
    let calls = vault.calls.load(Ordering::SeqCst);
    assert_eq!(pool.recover_pending(), Err(PoolError::RecoveryRequired));
    assert_eq!(vault.calls.load(Ordering::SeqCst), calls);
    assert_eq!(
        std::fs::read(pool.root.join("transaction.json")).unwrap(),
        before
    );
    assert!(!vault.inner.contains_named(&original).unwrap());
    assert_eq!(
        vault
            .inner
            .get_named(&key(&backup_id).unwrap())
            .unwrap()
            .expose_secret(),
        "planted-substitution"
    );
}

#[test]
fn pool_windows_reboot_requires_monotonic_reset_and_changed_boot_property() {
    let stamp = |time: u64, uptime| BootStamp {
        identity: format!("windows-cim:{}", 621355968000000000 + time * 10000000),
        started_at: time,
        uptime_ms: uptime,
    };
    let original = stamp(100, Some(100000));
    // One live boot, wall clock shifted forward300s; monotonic uptime did not reset.
    assert!(!boot_is_advanced(&original, &stamp(400, Some(100001))));
    assert!(!boot_is_advanced(&original, &stamp(400, Some(100000))));
    assert!(boot_is_advanced(&original, &stamp(400, Some(1000))));
    assert!(boot_is_advanced(&original, &stamp(50, Some(1000))));
    assert!(!boot_is_advanced(&original, &stamp(100, Some(1000))));
    assert!(!boot_is_advanced(
        &stamp(100, None),
        &stamp(400, Some(1000))
    ));
    assert!(!boot_is_advanced(&original, &stamp(400, None)));
    // After restart the observed uptime may already exceed the old recorded uptime;
    // later checks in this boot cannot prove reset. Never promise eventual unlock.
    assert!(!boot_is_advanced(&original, &stamp(400, Some(200000))));
}
#[test]
fn pool_macos_boot_session_identity_prevents_same_boot_clock_shift_proof() {
    let stamp = |id: &str, time| BootStamp {
        identity: format!(
            "macos-session:{}",
            uuid::Uuid::from_u128(match id {
                "old-session" => 1,
                "new-session" => 2,
                _ => 3,
            })
        ),
        started_at: time,
        uptime_ms: None,
    };
    assert!(!boot_is_advanced(
        &stamp("same-session", 100),
        &stamp("same-session", 400)
    ));
    assert!(boot_is_advanced(
        &stamp("old-session", 100),
        &stamp("new-session", 400)
    ));
    assert!(boot_is_advanced(
        &stamp("old-session", 400),
        &stamp("new-session", 100)
    ));
}

#[test]
fn pool_malformed_kernel_boot_identity_never_establishes_reboot() {
    let make = |identity: &str| BootStamp {
        identity: identity.into(),
        started_at: 100,
        uptime_ms: Some(1),
    };
    for namespace in ["linux", "macos-session"] {
        let current = make(&format!("{namespace}:{}", uuid::Uuid::from_u128(2)));
        assert!(!boot_is_advanced(&make(&format!("{namespace}:")), &current));
        assert!(!boot_is_advanced(
            &make(&format!("{namespace}:garbage")),
            &current
        ));
        assert!(!boot_is_advanced(
            &make(&format!("{namespace}:{}", uuid::Uuid::nil())),
            &current
        ));
    }
    assert!(!boot_is_advanced(
        &make("windows-cim:garbage"),
        &make("windows-cim:621355978000000000")
    ));
}

#[test]
fn pool_native_phase_crashes_startup_unlock_in_new_process_after_reboot() {
    run_native_restart_matrix("startup");
}
#[test]
fn pool_startup_without_prior_boot_proof_never_opens_vault_or_mutates() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    assert_eq!(
        pool.recover_after_restart().unwrap(),
        RestartRecovery::NotNeeded
    );
    assert!(!pool.root.exists());
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    for old_boot in [None, Some(fixture_boot(200))] {
        let mut writer = Writer::current();
        writer.boot = old_boot;
        write_json(
            &pool.root.join("transaction.json"),
            &Journal::Add {
                row: pool.load().unwrap().entries[0].clone(),
                recovery_safe: false,
                backend_id: vault.backend_id().into(),
                writer,
            },
        )
        .unwrap();
        let before = std::fs::read(pool.root.join("transaction.json")).unwrap();
        vault.calls.store(0, Ordering::SeqCst);
        TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(Some(fixture_boot(200))));
        assert_eq!(
            pool.recover_after_restart().unwrap(),
            RestartRecovery::NotNeeded
        );
        assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            std::fs::read(pool.root.join("transaction.json")).unwrap(),
            before
        );
    }
    TEST_BOOT.with(|slot| *slot.borrow_mut() = None);
}
#[test]
fn pool_startup_prior_boot_cleanup_advances_one_item_and_defers_durably() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    pool.custody().unwrap();
    let ids = vec![fresh_id(), fresh_id(), fresh_id()];
    for id in &ids {
        vault
            .inner
            .set_named(&key(id).unwrap(), &SecretString::from(SYNTHETIC))
            .unwrap();
    }
    write_json(
        &pool.root.join("cleanup.json"),
        &CleanupTombstones {
            boot: Some(fixture_boot(100)),
            backend_id: vault.backend_id().into(),
            ids: ids.clone(),
        },
    )
    .unwrap();
    TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(Some(fixture_boot(200))));
    vault.calls.store(0, Ordering::SeqCst);
    assert_eq!(
        pool.recover_after_restart().unwrap(),
        RestartRecovery::Deferred
    );
    assert_eq!(vault.calls.load(Ordering::SeqCst), 1);
    let remaining: CleanupTombstones =
        serde_json::from_slice(&std::fs::read(pool.root.join("cleanup.json")).unwrap()).unwrap();
    assert_eq!(remaining.ids, ids[1..]);
    assert_eq!(
        pool.recover_after_restart().unwrap(),
        RestartRecovery::Deferred
    );
    assert_eq!(
        pool.recover_after_restart().unwrap(),
        RestartRecovery::Recovered
    );
    assert!(!pool.root.join("cleanup.json").exists());
    TEST_BOOT.with(|slot| *slot.borrow_mut() = None);
}

#[test]
fn pool_cleanup_cannot_delete_manifest_admitted_remove_backup() {
    use std::sync::atomic::Ordering;
    let (_dir, pool, vault) = fault_fixture(0);
    pool.add("one", "openai", SYNTHETIC.into(), None, None)
        .unwrap();
    let backup = fresh_id();
    vault
        .inner
        .set_named(&key(&backup).unwrap(), &SecretString::from(SYNTHETIC))
        .unwrap();
    let mut manifest = pool.load().unwrap();
    manifest.entries[0].remove_backup_id = Some(backup.clone());
    pool.save(&manifest).unwrap();
    write_json(
        &pool.root.join("cleanup.json"),
        &CleanupTombstones {
            boot: Some(fixture_boot(100)),
            backend_id: vault.backend_id().into(),
            ids: vec![backup.clone()],
        },
    )
    .unwrap();
    TEST_BOOT.with(|slot| *slot.borrow_mut() = Some(Some(fixture_boot(200))));
    vault.calls.store(0, Ordering::SeqCst);
    assert_eq!(
        pool.recover_after_restart(),
        Err(PoolError::RecoveryRequired)
    );
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
    assert!(vault.inner.contains_named(&key(&backup).unwrap()).unwrap());
    assert_eq!(
        pool.load().unwrap().entries[0].remove_backup_id,
        Some(backup)
    );
    assert!(pool.root.join("cleanup.json").exists());
    TEST_BOOT.with(|slot| *slot.borrow_mut() = None);
}
