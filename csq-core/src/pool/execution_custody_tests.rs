use super::*;
use crate::platform::secret::file::FileVault;
use secrecy::ExposeSecret;

const SYNTHETIC: &str = "synthetic-execution-custody-value";

fn fixture() -> (tempfile::TempDir, Pool) {
    let dir = tempfile::tempdir().unwrap();
    let vault = FileVault::open_test(&dir.path().join("fixture-vault")).unwrap();
    let pool = Pool::with_vault(dir.path(), Box::new(vault));
    (dir, pool)
}

fn add_secret(pool: &Pool, name: &str, provider: &str) {
    let value = if name == "one" {
        SYNTHETIC.to_owned()
    } else {
        format!("{SYNTHETIC}.{name}")
    };
    pool.add(name, provider, value.into(), None, Some(25.0))
        .unwrap();
}

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

type WarningFields = Vec<(String, String)>;
type WarningEvents = Vec<WarningFields>;

fn capture_warnings<T>(operation: impl FnOnce() -> T) -> (T, WarningEvents) {
    #[derive(Clone)]
    struct Capture(std::sync::Arc<std::sync::Mutex<WarningEvents>>);
    struct Fields(WarningFields);
    impl tracing::field::Visit for Fields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push((field.name().to_owned(), value.to_owned()));
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push((field.name().to_owned(), format!("{value:?}")));
        }
    }
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut fields = Fields(Vec::new());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let result = tracing::subscriber::with_default(Capture(events.clone()), operation);
    let warnings = events.lock().unwrap().clone();
    (result, warnings)
}

#[test]
fn execution_fingerprint_uses_hmac_sha256_known_answer() {
    assert_eq!(
        fingerprint::digest(
            "key",
            &SecretString::from("The quick brown fox jumps over the lazy dog")
        )
        .unwrap(),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );
}

#[test]
fn execution_ledger_anchor_persists_even_when_callback_returns_error() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let selected = candidate(&pool, "anthropic");
    let nested = pool
        .with_execution_key_bound(&selected, deadline(), |_, anchor, salt_id| {
            let value = anchor.as_mut().unwrap();
            assert_eq!(value.state, LedgerState::PendingInit);
            assert_eq!(value.salt_id, salt_id);
            value.state = LedgerState::Active;
            value.sequence = 7;
            Err::<(), _>("committed-before-error")
        })
        .map(|admission| admission.value)
        .unwrap();
    assert_eq!(nested, Err("committed-before-error"));
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        let value = anchor.as_mut().unwrap();
        assert_eq!(value.sequence, 7);
        assert_eq!(value.salt_id, salt_id);
        value.sequence = 8;
        Err::<(), _>("second-commit-before-error")
    })
    .unwrap()
    .unwrap_err();
    assert_eq!(pool.load().unwrap().ledger_identity.unwrap().sequence, 8);
}

#[test]
fn execution_ledger_anchor_refuses_rollback_rebinding_and_missing_or_changed_salt() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        let value = anchor.as_mut().unwrap();
        assert_eq!(value.salt_id, salt_id);
        value.state = LedgerState::Active;
        value.sequence = 9;
    })
    .unwrap();
    for erase in [false, true] {
        assert_eq!(
            pool.with_ledger_identity(deadline(), |anchor, _| {
                if erase {
                    *anchor = None;
                } else {
                    anchor.as_mut().unwrap().sequence = 8;
                }
            }),
            Err(PoolError::LedgerIdentityMismatch)
        );
        assert_eq!(pool.load().unwrap().ledger_identity.unwrap().sequence, 9);
    }
    let original = std::fs::read(pool.root.join("manifest.json")).unwrap();
    for changed in [false, true] {
        let mut body: serde_json::Value = serde_json::from_slice(&original).unwrap();
        if changed {
            body["fingerprint_salt"] = serde_json::Value::String("00".repeat(32));
        } else {
            body.as_object_mut().unwrap().remove("fingerprint_salt");
        }
        write_json(&pool.root.join("manifest.json"), &body).unwrap();
        assert_eq!(
            pool.with_ledger_identity(deadline(), |_, _| panic!("unbound salt reached ledger")),
            Err::<(), _>(PoolError::LedgerIdentityMismatch)
        );
    }
}

#[test]
fn execution_ledger_anchor_publication_lag_preserves_callback_error() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let (result, warnings) = capture_warnings(|| {
        pool.with_ledger_identity(deadline(), |anchor, salt_id| {
            let value = anchor.as_mut().unwrap();
            assert_eq!(value.salt_id, salt_id);
            value.state = LedgerState::Active;
            value.sequence = 1;
            std::fs::remove_file(pool.root.join("manifest.json")).unwrap();
            std::fs::create_dir(pool.root.join("manifest.json")).unwrap();
            Err::<(), _>("db-committed")
        })
    });
    assert_eq!(result, Ok(Err::<(), _>("db-committed")));
    assert_eq!(
        warnings,
        vec![vec![(
            "error_kind".to_owned(),
            "pool_ledger_mirror_lagging".to_owned()
        )]]
    );
}

#[test]
fn execution_admission_debug_redacts_arbitrary_callback_values() {
    let admission = ExecutionAdmission {
        value: SYNTHETIC.to_owned(),
        can_dispatch: true,
    };
    let debug = format!("{admission:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(SYNTHETIC));
}

#[test]
fn execution_active_mirror_lag_preserves_admission_and_rolls_forward_without_logging_values() {
    use super::super::execution_ledger::{BudgetLedger, ReserveResult};
    let (dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, Some(1.0))
        .unwrap();
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        BudgetLedger::with_bound(dir.path(), anchor, salt_id, |_| Ok(()))
    })
    .unwrap()
    .unwrap();
    let before = pool.load().unwrap().ledger_identity.unwrap();
    let selected = named_bound_candidate(&pool, "one");
    let now = chrono::DateTime::parse_from_rfc3339("2100-01-02T12:00:00Z")
        .unwrap()
        .timestamp();
    let (result, warnings) = capture_warnings(|| {
        Pool::with_ledger_mirror_failure_for_test(|| {
            pool.with_execution_key_bound(&selected, deadline(), |secret, anchor, salt_id| {
                BudgetLedger::with_bound(dir.path(), anchor, salt_id, |ledger| {
                    ledger.reserve(&selected, 500_000_000, now, now + 600)
                })
                .map(|held| (secret, held))
            })
        })
    });
    let admission = result.unwrap();
    assert!(admission.can_dispatch);
    let debug = format!("{admission:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(SYNTHETIC));
    assert!(!debug.contains(selected.fingerprint()));
    let (secret, held) = admission.value.unwrap();
    assert_eq!(secret.expose_secret(), SYNTHETIC);
    assert!(matches!(held, ReserveResult::Held(_)));
    assert_eq!(pool.load().unwrap().ledger_identity.unwrap(), before);
    assert_eq!(
        warnings,
        vec![vec![(
            "error_kind".to_owned(),
            "pool_ledger_mirror_lagging".to_owned()
        )]]
    );
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        BudgetLedger::with_bound(dir.path(), anchor, salt_id, |_| Ok(()))
    })
    .unwrap()
    .unwrap();
    assert!(pool.load().unwrap().ledger_identity.unwrap().sequence > before.sequence);
}

#[test]
fn execution_two_consecutive_mirror_failures_stop_until_a_durable_clear() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "openai");
    pool.with_ledger_identity(deadline(), |anchor, _| {
        let identity = anchor.as_mut().unwrap();
        identity.state = LedgerState::Active;
        identity.sequence = 1;
    })
    .unwrap();
    let selected = named_bound_candidate(&pool, "one");
    let advance = |_: SecretString, anchor: &mut Option<LedgerIdentity>, _: &str| {
        anchor.as_mut().unwrap().sequence += 1;
        "committed"
    };
    let first = Pool::with_ledger_mirror_failure_for_test(|| {
        pool.with_execution_key_bound(&selected, deadline(), advance)
    })
    .unwrap();
    assert!(
        first.can_dispatch,
        "one durably recorded mirror lag may dispatch"
    );
    assert!(pool.ledger_mirror_lag().unwrap().is_some());

    // A new Pool instance must observe the durable failure, not a process-local
    // counter. Its callback value is retained for definitely-unsent cleanup.
    let reopened = Pool::with_vault(
        dir.path(),
        Box::new(FileVault::open_test(&dir.path().join("fixture-vault")).unwrap()),
    );
    let second = Pool::with_ledger_mirror_failure_for_test(|| {
        reopened.with_execution_key_bound(&selected, deadline(), advance)
    })
    .unwrap();
    assert!(
        !second.can_dispatch,
        "a second consecutive failed mirror must stop dispatch"
    );
    assert_eq!(second.value, "committed");

    let successful = reopened
        .with_execution_key_bound(&selected, deadline(), advance)
        .unwrap();
    assert!(successful.can_dispatch);
    assert!(reopened.ledger_mirror_lag().unwrap().is_none());
    let after_clear = Pool::with_ledger_mirror_failure_for_test(|| {
        reopened.with_execution_key_bound(&selected, deadline(), advance)
    })
    .unwrap();
    assert!(
        after_clear.can_dispatch,
        "a durable successful publish clears the failure streak"
    );
}

#[test]
fn execution_unreadable_mirror_lag_state_refuses_admission() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "openai");
    pool.with_ledger_identity(deadline(), |anchor, _| {
        let identity = anchor.as_mut().unwrap();
        identity.state = LedgerState::Active;
        identity.sequence = 1;
    })
    .unwrap();
    std::fs::create_dir(pool.root.join("ledger-mirror-lag.json")).unwrap();
    let selected = named_bound_candidate(&pool, "one");
    let result = Pool::with_ledger_mirror_failure_for_test(|| {
        pool.with_execution_key_bound(&selected, deadline(), |_, anchor, _| {
            anchor.as_mut().unwrap().sequence += 1;
        })
    });
    assert_eq!(
        result.map(|admission| admission.can_dispatch),
        Err(PoolError::LedgerMirrorUnavailable),
        "unreadable lag state must not allow dispatch"
    );
}

#[test]
fn execution_missing_native_vault_is_store_wide_while_missing_item_is_local() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "openai");
    let vault_path = dir.path().join("fixture-vault/pool-vault-store.json");
    let original = std::fs::read(&vault_path).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&original).unwrap();
    body["named_entries"] = serde_json::json!([]);
    write_json(&vault_path, &body).unwrap();
    assert!(matches!(pool.read_key("one"), Err(PoolError::KeyMissing)));
    std::fs::write(&vault_path, &original).unwrap();
    std::fs::remove_file(&vault_path).unwrap();
    assert!(
        matches!(pool.read_key("one"), Err(PoolError::StoreUnavailable)),
        "a disappeared native vault is a store-wide outage, never a missing item"
    );
}

#[test]
fn execution_json_publication_failure_is_store_wide_not_a_semantic_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("manifest.json");
    std::fs::create_dir(&destination).unwrap();
    assert_eq!(
        write_json(&destination, &serde_json::json!({"fixture": "nonsecret"})),
        Err(PoolError::ManifestWriteUnavailable),
        "failed publication must stop every candidate, not skip a row"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn execution_manifest_permission_fault_restores_directory_and_scope_after_panic() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("manifest.json");
    let panicked = std::panic::catch_unwind(|| {
        Pool::with_manifest_write_failure_for_test(|| {
            let _mode = ManifestWriteModeGuard::for_path(&path).unwrap().unwrap();
            assert_eq!(
                std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
                0o500
            );
            panic!("synthetic permission-fault unwind");
        });
    });
    assert!(panicked.is_err());
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700,
        "directory mode must be restored even during unwind"
    );
    assert!(!FAIL_MANIFEST_WRITE.with(|slot| slot.get()));
    write_json(&path, &serde_json::json!({"fixture": "nonsecret"})).unwrap();
}

#[test]
fn execution_pending_anchor_publication_failure_prevents_the_reservation_callback() {
    struct FailBeforeInit {
        inner: FileVault,
        manifest: PathBuf,
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl Vault for FailBeforeInit {
        fn backend_id(&self) -> &'static str {
            self.inner.backend_id()
        }
        fn set_named(
            &self,
            name: &NamedKey,
            value: &SecretString,
        ) -> std::result::Result<(), secret::SecretError> {
            self.inner.set_named(name, value)
        }
        fn get_named(
            &self,
            name: &NamedKey,
        ) -> std::result::Result<SecretString, secret::SecretError> {
            let value = self.inner.get_named(name)?;
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                std::fs::remove_file(&self.manifest).unwrap();
                std::fs::create_dir(&self.manifest).unwrap();
            }
            Ok(value)
        }
        fn delete_named(&self, name: &NamedKey) -> std::result::Result<(), secret::SecretError> {
            self.inner.delete_named(name)
        }
        fn set(
            &self,
            _: secret::SlotKey,
            _: &SecretString,
        ) -> std::result::Result<(), secret::SecretError> {
            panic!("slot API forbidden")
        }
        fn get(
            &self,
            _: secret::SlotKey,
        ) -> std::result::Result<SecretString, secret::SecretError> {
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
    let dir = tempfile::tempdir().unwrap();
    let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pool = Pool::with_vault(
        dir.path(),
        Box::new(FailBeforeInit {
            inner: FileVault::open_test(&dir.path().join("fixture-vault")).unwrap(),
            manifest: dir.path().join("pool/manifest.json"),
            armed: armed.clone(),
        }),
    );
    add_secret(&pool, "one", "openai");
    let selected = named_bound_candidate(&pool, "one");
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        pool.with_execution_key_bound(&selected, deadline(), |_, _, _| panic!(
            "reservation began without a durable pending anchor"
        ))
        .map(|admission| admission.value),
        Err::<(), _>(PoolError::LedgerMirrorUnavailable)
    );
    assert!(!pool.root.join("execution-ledger.sqlite3").exists());
}

#[test]
fn execution_named_item_read_errors_are_distinct_from_ambiguous_vault_failures() {
    assert_eq!(
        named_read_error(secret::SecretError::NamedItemUnreadable),
        PoolError::ItemReadUnavailable
    );
    assert_eq!(
        secret::SecretError::NamedItemUnreadable.error_kind_tag(),
        "vault_named_item_unreadable"
    );
    for error in [
        secret::SecretError::DecryptionFailed,
        secret::SecretError::InvalidKey {
            reason: SYNTHETIC.into(),
        },
        secret::SecretError::PermissionDenied {
            reason: SYNTHETIC.into(),
        },
        secret::SecretError::Locked,
        secret::SecretError::AuthorizationRequired,
        secret::SecretError::BackendUnavailable {
            reason: SYNTHETIC.into(),
        },
        secret::SecretError::Timeout,
        secret::SecretError::Io {
            path: "synthetic-vault".into(),
            source: std::io::Error::other(SYNTHETIC),
        },
    ] {
        let mapped = named_read_error(error);
        assert_eq!(mapped, PoolError::StoreUnavailable);
        assert!(!mapped.to_string().contains(SYNTHETIC));
    }
}

#[test]
fn execution_malformed_named_nonce_skips_only_the_corrupt_file_vault_item() {
    let (dir, pool) = fixture();
    add_secret(&pool, "bad", "openai");
    add_secret(&pool, "healthy", "openai");
    let manifest = pool.load().unwrap();
    let id = manifest
        .entries
        .iter()
        .find(|row| row.entry.name.as_str() == "bad")
        .unwrap()
        .secret_id
        .as_deref()
        .unwrap();
    let bad_key = key(id).unwrap();
    let path = dir.path().join("fixture-vault/pool-vault-store.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (field, value) in [
        ("nonce", "invalid-base64!"),
        ("nonce", "AA=="),
        ("ciphertext", "invalid-base64!"),
        ("ciphertext", "AA=="),
    ] {
        let mut body = original.clone();
        let item = body["named_entries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["name"].as_str() == Some(bad_key.name()))
            .unwrap();
        item[field] = serde_json::Value::String(value.to_owned());
        write_json(&path, &body).unwrap();
        assert_eq!(
            pool.read_key("bad").unwrap_err(),
            PoolError::ItemReadUnavailable
        );
        assert_eq!(
            pool.read_key("healthy").unwrap().expose_secret(),
            format!("{SYNTHETIC}.healthy")
        );
        let bad = named_bound_candidate(&pool, "bad");
        assert_eq!(
            pool.with_execution_key_bound(&bad, deadline(), |_, _, _| panic!(
                "unreadable item reserved"
            ))
            .map(|admission| admission.value),
            Err::<(), _>(PoolError::ItemReadUnavailable)
        );
        let healthy = named_bound_candidate(&pool, "healthy");
        pool.with_execution_key_bound(&healthy, deadline(), |secret, _, _| {
            assert_eq!(secret.expose_secret(), format!("{SYNTHETIC}.healthy"))
        })
        .unwrap();
    }
}

#[test]
fn execution_file_vault_kdf_mismatch_remains_a_vault_wide_failure() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "openai");
    let path = dir.path().join("fixture-vault/pool-vault-store.json");
    let mut body: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    body["kdf"]["t_cost"] = serde_json::json!(2);
    write_json(&path, &body).unwrap();
    assert_eq!(
        pool.read_key("one").unwrap_err(),
        PoolError::StoreUnavailable
    );
}

#[test]
fn execution_deadline_expiry_refuses_even_uncontended_custody_before_callback() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let selected = candidate(&pool, "anthropic");
    let expired = std::time::Instant::now();
    assert_eq!(
        pool.execution_candidates_bound("anthropic", expired)
            .unwrap_err(),
        PoolError::Busy
    );
    assert_eq!(
        pool.with_execution_key_bound(&selected, expired, |_, _, _| panic!("expired callback"))
            .map(|admission| admission.value),
        Err::<(), _>(PoolError::Busy)
    );
    assert_eq!(
        pool.with_ledger_identity(expired, |_, _| panic!("expired ledger callback")),
        Err::<(), _>(PoolError::Busy)
    );
}

#[test]
#[ignore = "child fixture: invoked by execution_custody_waits_for_another_process_within_deadline with isolated paths and stdin release"]
fn execution_custody_holder_child() {
    use std::io::Read;
    let _env_guard = crate::platform::test_env::lock();
    let base = PathBuf::from(std::env::var_os("CSQ_EXEC_CUSTODY_FIXTURE").unwrap());
    let pool = Pool::with_vault(
        &base,
        Box::new(FileVault::open_test(&base.join("fixture-vault")).unwrap()),
    );
    let _guard = pool.custody().unwrap();
    std::fs::write(base.join("custody-held"), b"held").unwrap();
    let mut release = [0_u8];
    std::io::stdin().read_exact(&mut release).unwrap();
}

#[test]
fn execution_custody_waits_for_another_process_within_deadline() {
    use std::io::Write;
    use std::time::{Duration, Instant};
    let _env_guard = crate::platform::test_env::lock();
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env("HOME", dir.path())
        .env("CSQ_EXEC_CUSTODY_FIXTURE", dir.path());
    for name in [
        "PATH",
        "LANG",
        "LC_ALL",
        "TERM",
        "USER",
        "TMPDIR",
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .args([
            "pool::store::execution_custody_tests::execution_custody_holder_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let ready_deadline = deadline();
    while !dir.path().join("custody-held").exists() {
        assert!(
            Instant::now() < ready_deadline,
            "child failed to acquire isolated custody"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // Real time is the SUBJECT here, not an incidental dependency: this proves the
    // custody lock WAITS (real sleeps between real flock attempts) against a real
    // child process before refusing. The refusal cannot flip under load because the
    // child keeps the lock until it is told to release, which happens only after
    // this assertion; load can only lengthen the measured wait, and the floor
    // asserted below is a lower bound.
    let start = Instant::now();
    assert_eq!(
        pool.execution_candidates_bound("anthropic", start + Duration::from_millis(100))
            .unwrap_err(),
        PoolError::Busy
    );
    assert!(
        start.elapsed() >= Duration::from_millis(60),
        "custody refused immediately instead of waiting"
    );
    let mut release = child.stdin.take().unwrap();
    let release_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        release.write_all(b"x").unwrap();
    });
    let result = pool.execution_candidates_bound("anthropic", deadline());
    release_thread.join().unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn execution_duplicate_secret_is_refused_live_but_identity_follows_removed_renamed_key() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let before = pool
        .execution_candidates_bound("anthropic", deadline())
        .unwrap()
        .remove(0);
    assert_eq!(
        pool.add("duplicate", "anthropic", SYNTHETIC.into(), None, Some(25.0)),
        Err(PoolError::MutationRefused)
    );
    let env = dir.path().join("duplicate.env");
    fs::write_new_private_synced(&env, format!("env.one={SYNTHETIC}\n").as_bytes()).unwrap();
    assert_eq!(
        pool.add_env_file(&env, &["env.one".into()], "openai", None, None),
        Err(PoolError::MutationRefused)
    );
    assert!(!format!("{before:?}").contains(before.fingerprint()));
    pool.remove("one").unwrap();
    pool.add("renamed", "anthropic", SYNTHETIC.into(), None, Some(25.0))
        .unwrap();
    let after = pool
        .execution_candidates_bound("anthropic", deadline())
        .unwrap()
        .remove(0);
    assert_ne!(before.generation, after.generation);
    assert_eq!(before.fingerprint(), after.fingerprint());
    assert!(!std::fs::read_to_string(pool.root.join("manifest.json"))
        .unwrap()
        .contains(SYNTHETIC));
}

#[test]
fn execution_env_alias_refuses_and_unique_edit_refreshes_snapshot_before_reservation() {
    let (dir, pool) = fixture();
    add_secret(&pool, "stored", "anthropic");
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.one=synthetic-env-original\n").unwrap();
    pool.add_env_file(&env, &["env.one".into()], "openai", None, Some(25.0))
        .unwrap();
    let selected = pool
        .execution_candidates_bound("openai", deadline())
        .unwrap()
        .remove(0);
    std::fs::write(&env, format!("env.one={SYNTHETIC}.stored\n")).unwrap();
    assert_eq!(
        pool.with_execution_key_bound(&selected, deadline(), |_, _, _| panic!(
            "alias reached reservation"
        ))
        .map(|admission| admission.value),
        Err::<(), _>(PoolError::MutationRefused)
    );
    // A stale-snapshot refusal alone would mask missing duplicate guards: the
    // second selection must also refuse rather than dispatch the newly bound alias.
    let alias = pool
        .execution_candidates_bound("openai", deadline())
        .unwrap()
        .remove(0);
    assert_eq!(
        pool.with_execution_key_bound(&alias, deadline(), |_, _, _| panic!(
            "reselected alias reached reservation"
        ))
        .map(|admission| admission.value),
        Err::<(), _>(PoolError::MutationRefused)
    );
    std::fs::write(&env, b"env.one=synthetic-env-unique-replacement\n").unwrap();
    assert_eq!(
        pool.with_execution_key_bound(&selected, deadline(), |_, _, _| panic!(
            "stale fingerprint reserved"
        ))
        .map(|admission| admission.value),
        Err::<(), _>(PoolError::MutationRefused)
    );
    let refreshed = pool
        .execution_candidates_bound("openai", deadline())
        .unwrap()
        .remove(0);
    assert_ne!(selected.fingerprint(), refreshed.fingerprint());
    assert_ne!(selected.generation, refreshed.generation);
    pool.with_execution_key_bound(&refreshed, deadline(), |secret, _, _| {
        assert_eq!(secret.expose_secret(), "synthetic-env-unique-replacement")
    })
    .map(|admission| admission.value)
    .unwrap();
    pool.with_resolution_identity(
        &refreshed.entry.name,
        deadline(),
        |fingerprint, generation, _, _| {
            assert_eq!(fingerprint, refreshed.fingerprint());
            assert_eq!(generation, refreshed.generation);
        },
    )
    .unwrap();
}

fn bound_reserve(
    pool: &Pool,
    base: &Path,
    candidate: &ExecutionCandidate,
) -> super::super::execution_ledger::ReserveResult {
    use super::super::execution_ledger::BudgetLedger;
    // Far-future deterministic accounting time, after every fixture's admission.
    let now = chrono::DateTime::parse_from_rfc3339("2100-01-02T12:00:00Z")
        .unwrap()
        .timestamp();
    pool.with_execution_key_bound(candidate, deadline(), |_, anchor, salt_id| {
        BudgetLedger::with_bound(base, anchor, salt_id, |ledger| {
            ledger.reserve(candidate, 500_000_000, now, now + 600)
        })
    })
    .map(|admission| admission.value)
    .unwrap()
    .unwrap()
}

fn named_bound_candidate(pool: &Pool, name: &str) -> ExecutionCandidate {
    pool.execution_candidates_bound("openai", deadline())
        .unwrap()
        .into_iter()
        .find(|row| row.entry.name.as_str() == name)
        .unwrap()
}

#[test]
fn execution_env_rotation_reserves_twice_with_real_bound_ledger_and_retains_old_fingerprint_spend()
{
    use super::super::execution_ledger::ReserveResult;
    let (dir, pool) = fixture();
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.one=synthetic-first-real-ledger\n").unwrap();
    pool.add_env_file(&env, &["env.one".into()], "openai", None, Some(1.0))
        .unwrap();
    pool.add(
        "healthy",
        "openai",
        "synthetic-healthy-real-ledger".into(),
        None,
        Some(1.0),
    )
    .unwrap();
    let original = named_bound_candidate(&pool, "env.one");
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &original),
        ReserveResult::Held(_)
    ));
    std::fs::write(&env, b"env.one=synthetic-second-real-ledger\n").unwrap();
    assert_eq!(
        pool.with_execution_key_bound(&original, deadline(), |_, _, _| panic!(
            "stale rotation reserved"
        ))
        .map(|admission| admission.value),
        Err::<(), _>(PoolError::MutationRefused)
    );
    let rotated = named_bound_candidate(&pool, "env.one");
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &rotated),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &rotated),
        ReserveResult::Held(_)
    ));
    assert_ne!(original.generation, rotated.generation);
    let healthy = named_bound_candidate(&pool, "healthy");
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &healthy),
        ReserveResult::Held(_)
    ));
    std::fs::write(&env, b"env.one=synthetic-first-real-ledger\n").unwrap();
    assert_eq!(
        pool.with_execution_key_bound(&rotated, deadline(), |_, _, _| panic!(
            "stale carryback reserved"
        ))
        .map(|admission| admission.value),
        Err::<(), _>(PoolError::MutationRefused)
    );
    let returned = named_bound_candidate(&pool, "env.one");
    assert_ne!(returned.generation, original.generation);
    assert_ne!(returned.generation, rotated.generation);
    assert_eq!(returned.fingerprint(), original.fingerprint());
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &returned),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &returned),
        ReserveResult::InFlightBlocked
    ));
}

#[test]
fn execution_and_resolution_ignore_unreadable_unrelated_modern_env_rows() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.broken=synthetic-unrelated-value\n").unwrap();
    pool.add_env_file(&env, &["env.broken".into()], "openai", None, None)
        .unwrap();
    let selected = pool
        .execution_candidates_bound("anthropic", deadline())
        .unwrap()
        .remove(0);
    std::fs::remove_file(&env).unwrap();
    pool.with_execution_key_bound(&selected, deadline(), |secret, _, _| {
        assert_eq!(secret.expose_secret(), SYNTHETIC)
    })
    .map(|admission| admission.value)
    .unwrap();
    pool.with_resolution_identity(
        &selected.entry.name,
        deadline(),
        |fingerprint, generation, _, _| {
            assert_eq!(fingerprint, selected.fingerprint());
            assert_eq!(generation, selected.generation);
        },
    )
    .unwrap();
    pool.add(
        "new.healthy",
        "anthropic",
        "synthetic-new-healthy".into(),
        None,
        None,
    )
    .unwrap();
}

#[test]
fn execution_add_and_resolve_report_unrelated_legacy_source_failures_without_false_missing_name() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.broken=synthetic-unrelated-legacy\n").unwrap();
    pool.add_env_file(&env, &["env.broken".into()], "openai", None, None)
        .unwrap();
    let mut manifest = pool.load().unwrap();
    manifest.entries[1].fingerprint = None;
    pool.save(&manifest).unwrap();
    std::fs::write(&env, b"unadmitted=synthetic-other\n").unwrap();
    let before = std::fs::read(pool.root.join("manifest.json")).unwrap();
    assert_eq!(
        pool.with_resolution_identity(
            &PoolName::new("one").unwrap(),
            deadline(),
            |_, _, _, _| panic!("failed legacy migration reached resolution")
        ),
        Err::<(), _>(PoolError::UnrelatedKeyUnavailable)
    );
    assert_eq!(
        pool.add(
            "new.healthy",
            "anthropic",
            "synthetic-new-legacy-test".into(),
            None,
            None
        ),
        Err(PoolError::UnrelatedKeyUnavailable)
    );
    assert_eq!(
        std::fs::read(pool.root.join("manifest.json")).unwrap(),
        before
    );
}

#[test]
fn execution_bound_candidate_conversion_refuses_a_missing_fingerprint() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let mut row = pool.load().unwrap().entries.remove(0);
    row.fingerprint = None;
    assert!(matches!(
        ExecutionCandidate::from_stored(row),
        Err(PoolError::ManifestInvalid)
    ));
}

#[test]
fn execution_initial_identity_is_synced_before_callback_and_resumes_before_database_creation() {
    use super::super::execution_ledger::BudgetLedger;
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    assert!(pool.load().unwrap().ledger_identity.is_none());
    assert!(!pool.root.join("execution-ledger.sqlite3").exists());
    let mut pending_id = String::new();
    let stopped = pool
        .with_ledger_identity(deadline(), |anchor, salt_id| {
            let value = anchor.as_ref().unwrap();
            assert_eq!(value.state, LedgerState::PendingInit);
            assert_eq!(value.sequence, 0);
            assert_eq!(value.salt_id, salt_id);
            pending_id = value.id.clone();
            assert_eq!(pool.load().unwrap().ledger_identity.as_ref(), Some(value));
            assert!(!pool.root.join("execution-ledger.sqlite3").exists());
            Err::<(), _>("simulated-stop-before-database-create")
        })
        .unwrap();
    assert_eq!(stopped, Err("simulated-stop-before-database-create"));
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        BudgetLedger::with_bound(dir.path(), anchor, salt_id, |_| Ok(()))
    })
    .unwrap()
    .unwrap();
    let active = pool.load().unwrap().ledger_identity.unwrap();
    assert_eq!(active.id, pending_id);
    assert_eq!(active.state, LedgerState::Active);
}

#[test]
fn execution_pending_init_mirror_lag_preserves_reservation_for_unsent_cleanup() {
    use super::super::execution_ledger::{BudgetLedger, ReserveResult};
    let (dir, pool) = fixture();
    pool.add("one", "openai", SYNTHETIC.into(), None, Some(1.0))
        .unwrap();
    let selected = named_bound_candidate(&pool, "one");
    let now = chrono::DateTime::parse_from_rfc3339("2100-01-02T12:00:00Z")
        .unwrap()
        .timestamp();
    let mut pending_bytes = Vec::new();
    let mut pending_id = String::new();
    let stopped = pool.with_execution_key_bound(&selected, deadline(), |_, anchor, salt_id| {
        pending_bytes = std::fs::read(pool.root.join("manifest.json")).unwrap();
        pending_id = anchor.as_ref().unwrap().id.clone();
        let held = BudgetLedger::with_bound(dir.path(), anchor, salt_id, |ledger| {
            ledger.reserve(&selected, 500_000_000, now, now + 600)
        })
        .unwrap();
        assert!(matches!(&held, ReserveResult::Held(_)));
        assert_eq!(anchor.as_ref().unwrap().state, LedgerState::Active);
        std::fs::remove_file(pool.root.join("manifest.json")).unwrap();
        std::fs::create_dir(pool.root.join("manifest.json")).unwrap();
        held
    });
    let admission = stopped.unwrap();
    assert!(!admission.can_dispatch);
    let reservation = match admission.value {
        ReserveResult::Held(reservation) => reservation,
        _ => panic!("committed callback reservation was lost"),
    };
    std::fs::remove_dir(pool.root.join("manifest.json")).unwrap();
    fs::write_new_private_synced(&pool.root.join("manifest.json"), &pending_bytes).unwrap();
    assert_eq!(
        pool.load().unwrap().ledger_identity.unwrap().state,
        LedgerState::PendingInit
    );
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        BudgetLedger::with_bound(dir.path(), anchor, salt_id, |ledger| {
            ledger.release(&reservation)
        })
    })
    .unwrap()
    .unwrap();
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &selected),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &selected),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        bound_reserve(&pool, dir.path(), &selected),
        ReserveResult::InFlightBlocked
    ));
    let active = pool.load().unwrap().ledger_identity.unwrap();
    assert_eq!(active.id, pending_id);
    assert_eq!(active.state, LedgerState::Active);
    assert!(active.sequence >= 2);
}

#[test]
fn execution_legacy_anchor_defaults_active_and_refuses_transition_back_to_pending() {
    use super::super::execution_ledger::BudgetLedger;
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    pool.with_ledger_identity(deadline(), |anchor, salt_id| {
        BudgetLedger::with_bound(dir.path(), anchor, salt_id, |_| Ok(()))
    })
    .unwrap()
    .unwrap();
    let mut body: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pool.root.join("manifest.json")).unwrap()).unwrap();
    body["ledger_identity"]
        .as_object_mut()
        .unwrap()
        .remove("state");
    write_json(&pool.root.join("manifest.json"), &body).unwrap();
    assert_eq!(
        pool.load().unwrap().ledger_identity.unwrap().state,
        LedgerState::Active
    );
    assert_eq!(
        pool.with_ledger_identity(deadline(), |anchor, _| anchor.as_mut().unwrap().state =
            LedgerState::PendingInit),
        Err(PoolError::LedgerIdentityMismatch)
    );
}

#[test]
fn execution_legacy_fingerprint_migration_is_atomic_when_source_is_unreadable() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let mut body: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pool.root.join("manifest.json")).unwrap()).unwrap();
    body.as_object_mut().unwrap().remove("fingerprint_salt");
    for row in body["entries"].as_array_mut().unwrap() {
        row.as_object_mut().unwrap().remove("fingerprint");
    }
    write_json(&pool.root.join("manifest.json"), &body).unwrap();
    let before = std::fs::read(pool.root.join("manifest.json")).unwrap();
    break_vault(dir.path());
    assert_eq!(
        pool.execution_candidates_bound("anthropic", deadline())
            .unwrap_err(),
        PoolError::StoreUnavailable
    );
    assert_eq!(
        std::fs::read(pool.root.join("manifest.json")).unwrap(),
        before
    );
}

#[test]
fn execution_partial_legacy_migration_requires_reading_every_current_secret() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.one=synthetic-env-readable\n").unwrap();
    pool.add_env_file(&env, &["env.one".into()], "openai", None, None)
        .unwrap();
    let mut manifest = pool.load().unwrap();
    manifest.entries[1].fingerprint = None;
    pool.save(&manifest).unwrap();
    let before = std::fs::read(pool.root.join("manifest.json")).unwrap();
    break_vault(dir.path());
    assert_eq!(
        pool.execution_candidates_bound("openai", deadline())
            .unwrap_err(),
        PoolError::StoreUnavailable
    );
    assert_eq!(
        std::fs::read(pool.root.join("manifest.json")).unwrap(),
        before
    );
}

#[test]
fn execution_legacy_fingerprint_migration_persists_only_after_all_reads_and_duplicate_checks() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let mut legacy = pool.load().unwrap();
    legacy.fingerprint_salt = None;
    legacy.entries[0].fingerprint = None;
    pool.save(&legacy).unwrap();
    let migrated = pool
        .execution_candidates_bound("anthropic", deadline())
        .unwrap()
        .remove(0);
    assert_eq!(migrated.fingerprint().len(), 64);
    assert_eq!(
        pool.load().unwrap().entries[0].fingerprint.as_deref(),
        Some(migrated.fingerprint())
    );
    let mut duplicate = pool.load().unwrap();
    duplicate.fingerprint_salt = None;
    duplicate.entries[0].fingerprint = None;
    let mut row = duplicate.entries[0].clone();
    row.entry.name = PoolName::new("legacy-alias").unwrap();
    row.secret_id = Some(fresh_id());
    row.generation = Some(fresh_id());
    pool.with_store(|vault| {
        vault
            .set_named(
                &key(row.secret_id.as_deref().unwrap())?,
                &SecretString::from(SYNTHETIC),
            )
            .map_err(|_| PoolError::StoreUnavailable)
    })
    .unwrap();
    duplicate.entries.push(row);
    pool.save(&duplicate).unwrap();
    let before = std::fs::read(pool.root.join("manifest.json")).unwrap();
    assert_eq!(
        pool.execution_candidates_bound("anthropic", deadline())
            .unwrap_err(),
        PoolError::MutationRefused
    );
    assert_eq!(
        std::fs::read(pool.root.join("manifest.json")).unwrap(),
        before
    );
}

fn candidate(pool: &Pool, provider: &str) -> ExecutionCandidate {
    let mut rows = pool.execution_candidates(provider).unwrap();
    assert_eq!(rows.len(), 1);
    rows.remove(0)
}

fn break_vault(dir: &Path) {
    std::fs::write(
        dir.join("fixture-vault/pool-vault-store.json"),
        b"unreadable-synthetic-vault",
    )
    .unwrap();
}

#[test]
fn execution_candidates_filter_provider_without_reading_secret_payloads() {
    let (dir, pool) = fixture();
    add_secret(&pool, "anthropic.one", "anthropic");
    add_secret(&pool, "openai.one", "openai");
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.one=synthetic-env-value\n").unwrap();
    pool.add_env_file(&env, &["env.one".into()], "anthropic", None, None)
        .unwrap();
    // Vault metadata remains readable for the pool-wide health probe, while
    // every native payload and the env source are unreadable. Filtering must
    // not fetch/decrypt a selected key or read an env-file value.
    let vault_path = dir.path().join("fixture-vault/pool-vault-store.json");
    let mut vault: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vault_path).unwrap()).unwrap();
    for item in vault["named_entries"].as_array_mut().unwrap() {
        item["nonce"] = "invalid-base64".into();
        item["ciphertext"] = "invalid-base64".into();
    }
    std::fs::write(&vault_path, serde_json::to_vec(&vault).unwrap()).unwrap();
    std::fs::remove_file(&env).unwrap();
    let mut rows = pool.execution_candidates("anthropic").unwrap();
    rows.sort_by(|a, b| a.entry.name.as_str().cmp(b.entry.name.as_str()));
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].entry.name.as_str(), "anthropic.one");
    assert_eq!(rows[1].entry.name.as_str(), "env.one");
    for row in rows {
        assert_eq!(row.entry.provider, "anthropic");
        assert_eq!(row.generation.len(), 32);
        assert!(validate_id(&row.generation).is_ok());
    }
    assert_eq!(pool.execution_candidates("openai").unwrap().len(), 1);
    assert_eq!(
        pool.execution_candidates("not-a-provider").unwrap_err(),
        PoolError::InvalidProvider
    );
    assert_eq!(
        pool.read_key("anthropic.one").unwrap_err(),
        PoolError::ItemReadUnavailable
    );
    assert!(pool.read_key("env.one").is_err());
    break_vault(dir.path());
    assert_eq!(
        pool.execution_candidates("anthropic").unwrap_err(),
        PoolError::StoreUnavailable,
        "unreadable vault metadata must stop provider filtering pool-wide"
    );
}

#[test]
fn execution_candidates_distinguish_absent_manifest_from_configured_empty_pool() {
    let (_dir, pool) = fixture();
    assert_eq!(
        pool.execution_candidates("anthropic").unwrap_err(),
        PoolError::ManifestUnavailable
    );
    pool.save(&Manifest::empty()).unwrap();
    assert!(pool.execution_candidates("anthropic").unwrap().is_empty());
}

#[test]
fn execution_candidates_durably_backfill_legacy_generations_once_for_both_sources() {
    let (dir, pool) = fixture();
    add_secret(&pool, "stored.one", "anthropic");
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"env.one=synthetic-env-value\n").unwrap();
    pool.add_env_file(&env, &["env.one".into()], "anthropic", None, None)
        .unwrap();
    let mut legacy = pool.load().unwrap();
    for row in &mut legacy.entries {
        row.generation = None;
    }
    pool.save(&legacy).unwrap();
    let first = pool.execution_candidates("anthropic").unwrap();
    assert_eq!(first.len(), 2);
    assert_ne!(first[0].generation, first[1].generation);
    let persisted = pool.load().unwrap();
    for selected in &first {
        assert!(validate_id(&selected.generation).is_ok());
        let row = persisted
            .entries
            .iter()
            .find(|row| row.entry.name == selected.entry.name)
            .unwrap();
        assert_eq!(
            row.generation.as_deref(),
            Some(selected.generation.as_str())
        );
    }
    drop(pool);
    let reopened = Pool::with_vault(
        dir.path(),
        Box::new(FileVault::open_test(&dir.path().join("fixture-vault")).unwrap()),
    );
    let second = reopened.execution_candidates("anthropic").unwrap();
    for selected in first {
        let again = second
            .iter()
            .find(|row| row.entry.name == selected.entry.name)
            .unwrap();
        assert_eq!(again.entry, selected.entry);
        assert_eq!(again.generation, selected.generation);
    }
}

#[test]
fn execution_key_refuses_replaced_generation_even_with_identical_public_metadata() {
    for env_source in [false, true] {
        let (dir, pool) = fixture();
        let env = dir.path().join("fixture.env");
        if env_source {
            fs::write_new_private_synced(&env, b"one=synthetic-env-value\n").unwrap();
            pool.add_env_file(&env, &["one".into()], "anthropic", None, None)
                .unwrap();
        } else {
            add_secret(&pool, "one", "anthropic");
        }
        let selected = candidate(&pool, "anthropic");
        pool.remove("one").unwrap();
        if env_source {
            pool.add_env_file(&env, &["one".into()], "anthropic", None, None)
                .unwrap();
        } else {
            add_secret(&pool, "one", "anthropic");
        }
        let mut manifest = pool.load().unwrap();
        manifest.entries[0].entry = selected.entry.clone();
        assert_ne!(
            manifest.entries[0].generation.as_deref(),
            Some(selected.generation.as_str())
        );
        pool.save(&manifest).unwrap();
        assert_eq!(
            pool.with_execution_key(&selected, |_| panic!("stale generation reached closure")),
            Err::<(), _>(PoolError::MutationRefused)
        );
    }
}

#[test]
fn execution_key_checks_entire_public_entry_before_reading_unavailable_secret() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let selected = candidate(&pool, "anthropic");
    let original = pool.load().unwrap().entries[0].clone();
    break_vault(dir.path());
    let mut edits = Vec::new();
    let mut changed = original.entry.clone();
    changed.monthly_cap_usd = Some(1.0);
    edits.push(changed);
    let mut changed = original.entry.clone();
    changed.reset = Some(Reset::Day { day_of_month: 7 });
    edits.push(changed);
    let mut changed = original.entry.clone();
    changed.provider = "openai".into();
    edits.push(changed);
    let mut changed = original.entry.clone();
    changed.added_at = "2100-01-01T00:00:00Z".into();
    edits.push(changed);
    let mut changed = original.entry.clone();
    changed.source = KeySource::EnvFile;
    edits.push(changed);
    for entry in edits {
        let mut manifest = pool.load().unwrap();
        if entry.source == KeySource::EnvFile {
            manifest.env_file = Some(dir.path().join("missing-fixture.env"));
            manifest.entries[0].secret_id = None;
        }
        manifest.entries[0].entry = entry;
        pool.save(&manifest).unwrap();
        assert_eq!(
            pool.with_execution_key(&selected, |_| panic!("stale metadata reached closure")),
            Err::<(), _>(PoolError::MutationRefused)
        );
    }
    let mut manifest = pool.load().unwrap();
    manifest.entries[0] = original;
    pool.save(&manifest).unwrap();
    // The broken source is an actual failure when metadata matches.
    assert_eq!(
        pool.with_execution_key(&selected, |_| ()),
        Err(PoolError::StoreUnavailable)
    );
}

#[test]
fn execution_key_missing_row_never_invokes_reservation_closure() {
    let (_dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let selected = candidate(&pool, "anthropic");
    pool.remove("one").unwrap();
    assert_eq!(
        pool.with_execution_key(&selected, |_| panic!("removed row reached closure")),
        Err::<(), _>(PoolError::KeyMissing)
    );
}

#[test]
fn execution_key_reads_fresh_env_secret_for_each_request_and_refuses_unreadable_source() {
    let (dir, pool) = fixture();
    let env = dir.path().join("fixture.env");
    fs::write_new_private_synced(&env, b"one=synthetic-env-first\n").unwrap();
    pool.add_env_file(&env, &["one".into()], "anthropic", None, None)
        .unwrap();
    let selected = candidate(&pool, "anthropic");
    pool.with_execution_key(&selected, |secret| {
        assert_eq!(secret.expose_secret(), "synthetic-env-first");
    })
    .unwrap();
    std::fs::write(&env, b"one=synthetic-env-second\n").unwrap();
    pool.with_execution_key(&selected, |secret| {
        assert_eq!(secret.expose_secret(), "synthetic-env-second");
    })
    .unwrap();
    std::fs::remove_file(&env).unwrap();
    assert_eq!(
        pool.with_execution_key(&selected, |_| panic!("unreadable source reached closure")),
        Err::<(), _>(PoolError::EnvFileUnavailable)
    );
}

#[test]
fn execution_key_reservation_closure_holds_custody_and_return_releases_it() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let selected = candidate(&pool, "anthropic");
    let peer = Pool::with_vault(
        dir.path(),
        Box::new(FileVault::open_test(&dir.path().join("fixture-vault")).unwrap()),
    );
    let (secret, reservation) = pool
        .with_execution_key(&selected, |secret| {
            // A distinct thread also tests Windows' reentrant named mutex:
            // probing from this thread would wrongly succeed on that platform.
            std::thread::scope(|scope| {
                let contender = scope.spawn(|| peer.execution_candidates("anthropic"));
                assert_eq!(contender.join().unwrap().unwrap_err(), PoolError::Busy);
            });
            (secret, 17_u64)
        })
        .unwrap();
    assert_eq!(secret.expose_secret(), SYNTHETIC);
    assert_eq!(reservation, 17);
    assert_eq!(peer.execution_candidates("anthropic").unwrap().len(), 1);
    peer.set_reset("one", Some(Reset::Day { day_of_month: 7 }))
        .unwrap();
}

#[test]
fn execution_custody_refuses_unknown_same_boot_transaction_without_changing_it() {
    let (dir, pool) = fixture();
    add_secret(&pool, "one", "anthropic");
    let selected = candidate(&pool, "anthropic");
    write_json(
        &pool.root.join("transaction.json"),
        &Journal::Add {
            row: pool.load().unwrap().entries[0].clone(),
            recovery_safe: false,
            backend_id: "linux-file-aes".into(),
            writer: Writer::current(),
        },
    )
    .unwrap();
    let before = std::fs::read(pool.root.join("transaction.json")).unwrap();
    break_vault(dir.path());
    assert_eq!(
        pool.execution_candidates("anthropic").unwrap_err(),
        PoolError::RecoveryRequired
    );
    assert_eq!(
        pool.with_execution_key(&selected, |_| panic!("unknown custody reached closure")),
        Err::<(), _>(PoolError::RecoveryRequired)
    );
    assert_eq!(
        std::fs::read(pool.root.join("transaction.json")).unwrap(),
        before
    );
}
