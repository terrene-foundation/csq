//! Real SIGINT, actual scoped waiter, and real Codex first-write callback.
//! All auth bytes are synthetic; no browser, keychain, external HTTP or CLI lookup.
#![cfg(unix)]
#[path = "../src/login_cancel_guard.rs"]
mod login_cancel_guard;
#[path = "../src/login_child_custody.rs"]
mod login_child_custody;

use csq_core::types::AccountNum;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
const ENTRY: &str = "login_publication_signal_private_entry";
const ROLE: &str = "CSQ_PRIVATE_PUBLICATION_ROLE";
const ROOT: &str = "CSQ_PRIVATE_PUBLICATION_ROOT";
const MODE: &str = "CSQ_PRIVATE_PUBLICATION_MODE";
const BUDGET: Duration = Duration::from_secs(10);
const PRIOR_AUTH: &[u8] = b"PRIVATE_PRIOR_RAW_AUTH_UNCHANGED";
const PRIOR_CONFIG: &[u8] = b"model = \"gpt-fixture\"\nmodel_reasoning_effort = \"high\"\nunknown_secret = \"PRIVATE_MUST_NOT_COPY\"\n";
fn slot() -> AccountNum {
    AccountNum::try_from(1_u16).unwrap()
}
fn atomic(root: &Path, name: &str, bytes: &[u8]) {
    let mut file = tempfile::NamedTempFile::new_in(root).unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    file.persist(root.join(name)).unwrap();
}
fn until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + BUDGET;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
}
fn command(root: &Path, role: &str, mode: &str) -> Command {
    for dir in ["home", "base", "config", "bin", "tmp", "appdata", "local"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .args([
            ENTRY,
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .env(ROLE, role)
        .env(ROOT, root)
        .env(MODE, mode)
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("CSQ_BASE_DIR", root.join("base"))
        .env("CLAUDE_CONFIG_DIR", root.join("config"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("APPDATA", root.join("appdata"))
        .env("LOCALAPPDATA", root.join("local"))
        .env("TMPDIR", root.join("tmp"))
        .env("TMP", root.join("tmp"))
        .env("TEMP", root.join("tmp"))
        .env("PATH", root.join("bin"))
        .env("CSQ_SECRET_BACKEND", "in-memory")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(root.join(format!("{role}.stdout"))).unwrap())
        .stderr(std::fs::File::create(root.join(format!("{role}.stderr"))).unwrap());
    command
}
fn published(root: &Path) -> bool {
    let base = root.join("base");
    let Some(id) = csq_core::accounts::profiles::resolve_slot_to_uuid(&base, 1) else {
        return false;
    };
    let path = csq_core::accounts::identity_store::credentials_codex_path_for(&base, id);
    csq_core::credentials::load(&path)
        .ok()
        .and_then(|creds| creds.codex().cloned())
        .is_some_and(|creds| creds.tokens.account_id.as_deref() == Some("acct-synthetic"))
        && base.join("config-1/.csq-account").exists()
}
fn canonical_any(root: &Path) -> bool {
    let base = root.join("base");
    if csq_core::accounts::profiles::resolve_slot_to_uuid(&base, 1).is_some()
        || base.join("config-1/.csq-account").exists()
    {
        return true;
    }
    std::fs::read_dir(base.join("identities"))
        .ok()
        .is_some_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.path().join("credentials-codex.json").exists())
        })
}
fn assert_private_vendor_home(root: &Path, home: &Path) {
    let grant_root = std::fs::canonicalize(root.join("base"))
        .unwrap()
        .join(".login-grants");
    assert_eq!(home.parent(), Some(grant_root.as_path()));
    let name = home.file_name().unwrap().to_str().unwrap();
    let id = name.strip_prefix("grant-").unwrap();
    assert!(
        id.len() == 36
            && id
                .bytes()
                .enumerate()
                .all(|(i, c)| if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                })
    );
    let meta = std::fs::symlink_metadata(home).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}
fn vendor(root: &Path, mode: &str) -> ! {
    assert!(
        until(|| root.join("vendor-go").exists()),
        "private adoption release missing"
    );
    let config = PathBuf::from(std::env::var_os("CODEX_HOME").expect("actual child CODEX_HOME"));
    assert_private_vendor_home(root, &config);
    let prepared = std::fs::read_to_string(config.join("config.toml")).unwrap();
    assert!(
        prepared.contains("gpt-fixture")
            && prepared.contains("high")
            && prepared.contains("cli_auth_credentials_store")
            && prepared.contains("file")
            && !prepared.contains("PRIVATE_MUST_NOT_COPY")
            && !prepared.contains("unknown_secret"),
        "LOGIN_CLI_PRIVATE_CODEX_CONFIG_READ"
    );
    let auth = serde_json::json!({"auth_mode":"chatgpt", "OPENAI_API_KEY":null,
        "tokens":{"account_id":"acct-synthetic", "access_token":"eyJhbGciOiJIUzI1NiJ9.test-at.sig",
        "refresh_token":"rt_test", "id_token":"eyJhbGciOiJIUzI1NiJ9.test-id.sig"},
        "last_refresh":"2100-01-01T00:00:00Z"});
    atomic(
        &config,
        "auth.json",
        serde_json::to_string(&auth).unwrap().as_bytes(),
    );
    assert!(
        config.join("auth.json").is_file(),
        "LOGIN_CLI_PRIVATE_CODEX_AUTH_WRITE"
    );
    atomic(
        root,
        "vendor-home-proof",
        serde_json::to_string(&serde_json::json!({
        "home":config,"config_read":true,"auth_written":true}))
        .unwrap()
        .as_bytes(),
    );
    if mode == "oversize" || mode == "no-newline" {
        std::io::stdout()
            .write_all(&vec![b'x'; 64 * 1024 + 1])
            .unwrap();
        if mode == "oversize" {
            println!("\ntrailing private line");
        }
    } else {
        println!("\nPRIVATE_VENDOR_COMPLETE");
    }
    std::io::stdout().flush().unwrap();
    std::process::exit(0)
}
struct StubCustody {
    child: Arc<Mutex<Option<Arc<Mutex<Child>>>>>,
    root: PathBuf,
}
impl Drop for StubCustody {
    fn drop(&mut self) {
        let child = self.child.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(child) = child {
            atomic(&self.root, "vendor-go", b"cleanup");
            let mut child = child.lock().unwrap_or_else(|p| p.into_inner());
            let pid = child.id();
            let mut fallback = !self.root.join("actual-vendor-reap").exists();
            let status = match child.try_wait() {
                Ok(Some(status)) => status,
                _ => {
                    fallback = true;
                    let _ = child.kill();
                    child.wait().expect("actual retained stub wait")
                }
            };
            let confirmed = child.wait().expect("same original Child actual wait");
            assert_eq!(confirmed, status);
            atomic(
                &self.root,
                "stub-terminal",
                serde_json::to_string(&serde_json::json!({
                "pid":pid,"code":status.code(),"signal":status.signal(),"fallback":fallback}))
                .unwrap()
                .as_bytes(),
            );
        } else {
            atomic(&self.root, "stub-terminal", br#"{"no_vendor":true}"#);
        }
    }
}
fn driver(root: &Path, mode: &str) -> ! {
    let retained = Arc::new(Mutex::new(None));
    let custody = StubCustody {
        child: Arc::clone(&retained),
        root: root.to_path_buf(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        login_cancel_guard::with_cli_login_session(slot(), |guard| {
            let base = root.join("base");
            let login_lock = Arc::new(
                match csq_core::accounts::login_lock::AccountLoginLock::acquire(&base, slot())
                    .unwrap()
                {
                    csq_core::accounts::login_lock::AcquireOutcome::Acquired(lock) => lock,
                    _ => panic!("private account unexpectedly locked"),
                },
            );
            std::fs::create_dir_all(base.join("config-1")).unwrap();
            atomic(&base.join("config-1"), "auth.json", PRIOR_AUTH);
            atomic(&base.join("config-1"), "config.toml", PRIOR_CONFIG);
            let grant = Arc::new(Mutex::new(
                csq_core::accounts::credential_transaction::VendorLoginGrant::new(&base)?,
            ));
            let child_grant = Arc::clone(&grant);
            let child_lock = Arc::clone(&login_lock);
            let eof = Arc::new(Mutex::new(None));
            let gate = Arc::clone(&eof);
            let adopted = Arc::clone(&retained);
            let adopted_root = root.to_path_buf();
            let mut actual = None;
            let caller = std::thread::current().id();
            let mut callbacks = 0;
            let mut input = std::io::Cursor::new(Vec::<u8>::new());
            let mut output = Vec::new();
            let result = csq_core::providers::codex::login::perform_with_seal_and_grant(
                &base,
                slot(),
                (&mut input, &mut output),
                || csq_core::providers::codex::keychain::ProbeResult::Absent,
                || panic!("private Absent probe cannot purge keychain"),
                |config| {
                    assert_private_vendor_home(root, config);
                    let mut child = command(root, "vendor", mode);
                    child.env("CODEX_HOME", config).stdout(Stdio::piped());
                    let hooks = login_cancel_guard::PipedLoginTestHooks::new(
                        move || {
                            *gate.lock().unwrap() = Some(std::thread::current().id());
                        },
                        |observation| {
                            if let (Some(status), Some(joined)) = (
                                observation.reaped_status,
                                observation.reader_joined_thread_id,
                            ) {
                                actual = Some((observation.child_id, status, joined));
                            }
                        },
                    )
                    .with_adopted_child(move |child| {
                        *adopted.lock().unwrap() = Some(Arc::clone(&child));
                        let pid = child.lock().unwrap().id();
                        // SAFETY: original actual child is unreaped and gated at vendor-go.
                        assert_eq!(
                            unsafe { libc::getpgid(pid as libc::pid_t) },
                            pid as libc::pid_t
                        );
                        atomic(&adopted_root, "vendor-go", b"actual own group checked");
                    });
                    let receipt = login_cancel_guard::spawn_cli_piped_login_scoped_observed_receipt(
                        &mut child,
                        Duration::from_secs(30),
                        (Arc::clone(&child_grant), child_lock),
                        "Codex",
                        |_| {
                            assert_eq!(std::thread::current().id(), caller);
                            callbacks += 1;
                        },
                        |notice| login_cancel_guard::print_cli_notice(notice, slot()),
                        (hooks, guard),
                    );
                    if let Ok(receipt) = &receipt {
                        actual = Some((
                            receipt.child_id(),
                            receipt.reaped_status(),
                            receipt
                                .reader_joined_thread_id()
                                .expect("actual reader join"),
                        ));
                    }
                    if let Some((pid, status, joined)) = actual {
                        assert_eq!(Some(joined), *eof.lock().unwrap());
                        assert_ne!(joined, caller);
                        atomic(root, "actual-vendor-reap", serde_json::to_string(&serde_json::json!({
                            "pid":pid,"code":status.code(),"signal":status.signal(),"reader_joined":format!("{joined:?}"),"callbacks":callbacks})).unwrap().as_bytes());
                    }
                    login_cancel_guard::complete_vendor_grant(
                        &child_grant,
                        receipt.map(|receipt| receipt.reaped_status()),
                    )
                },
                (
                    || {
                        assert!(
                            root.join("actual-vendor-reap").exists(),
                            "seal requires actual child and reader receipts"
                        );
                        assert!(
                            matches!(
                                csq_core::accounts::login_lock::AccountLoginLock::acquire(
                                    &base,
                                    slot()
                                )
                                .unwrap(),
                                csq_core::accounts::login_lock::AcquireOutcome::Held { .. }
                            ),
                            "actual account lock must span publication"
                        );
                        atomic(root, "actual-lock-held-at-seal", b"held");
                        if mode == "post" {
                            guard.seal_publication()?;
                        }
                        if mode == "pre" || mode == "post" {
                            atomic(root, "seal-ready", mode.as_bytes());
                            assert!(until(|| guard.cancelled()), "actual SIGINT was not latched");
                            atomic(root, "actual-signal-latched", b"SIGINT");
                        }
                        if mode != "post" {
                            guard.seal_publication()?;
                        }
                        Ok(())
                    },
                    Arc::clone(&grant),
                ),
            );
            if result.is_ok() {
                guard.mark_publication_committed();
            }
            login_cancel_guard::cleanup_vendor_grant(&grant, result.map(|_| ()))
        })
    }));
    let (code, error) = match result {
        Ok(Ok(())) => (0, String::new()),
        Ok(Err(error)) => (
            login_cancel_guard::cli_error_exit_code(&error),
            format!("{error:#}"),
        ),
        Err(_) => (101, "private driver panic".to_owned()),
    };
    drop(custody); // durable actual stub wait precedes terminal driver receipt.
    let proof = serde_json::json!({"driver_pid":std::process::id(),"code":code,"error":error,
        "published":published(root),"canonical_any":canonical_any(root),
        "prior_auth_unchanged":std::fs::read(root.join("base/config-1/auth.json")).ok().as_deref() == Some(PRIOR_AUTH),
        "prior_config_unchanged":std::fs::read(root.join("base/config-1/config.toml")).ok().as_deref() == Some(PRIOR_CONFIG),
        "private_home_cleaned":std::fs::read(root.join("vendor-home-proof")).ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|proof| proof["home"].as_str().map(|home| !Path::new(home).exists())).unwrap_or(false),
        "lock_held_at_seal":root.join("actual-lock-held-at-seal").exists(),
        "signal_latched":root.join("actual-signal-latched").exists()});
    atomic(
        root,
        "driver-terminal",
        serde_json::to_string(&proof).unwrap().as_bytes(),
    );
    eprintln!("PUBLICATION_SIGNAL_DRIVER_RECEIPT: {proof}");
    std::process::exit(code)
}
#[test]
#[ignore = "private inert subprocess dispatcher, selected explicitly by parent test"]
fn login_publication_signal_private_entry() {
    let _environment = csq_core::platform::test_env::lock();
    // The explicit in-memory override must resolve before any grant creation,
    // cleanup or real canonical callback. A missing feature refuses here;
    // native platform keychains are never a test fallback.
    assert_eq!(
        csq_core::platform::secret::open_default_vault()
            .expect("LOGIN_PUBLICATION_HERMETIC_BACKEND: unavailable")
            .backend_id(),
        "in-memory",
        "LOGIN_PUBLICATION_HERMETIC_BACKEND"
    );
    let root = PathBuf::from(std::env::var_os(ROOT).expect("private root"));
    let mode = std::env::var(MODE).expect("private mode");
    match std::env::var(ROLE).as_deref() {
        Ok("vendor") => vendor(&root, &mode),
        Ok("driver") => driver(&root, &mode),
        _ => panic!("private role"),
    }
}
struct Driver {
    child: Option<Child>,
    root: Option<tempfile::TempDir>,
    pid: libc::pid_t,
    preserve: bool,
}
impl Driver {
    fn spawn(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut command = command(root.path(), "driver", mode);
        command.process_group(0);
        let child = command.spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        // SAFETY: this fresh actual Child is still retained and unreaped.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        Self {
            child: Some(child),
            root: Some(root),
            pid,
            preserve: false,
        }
    }
    fn root(&self) -> &Path {
        self.root.as_ref().unwrap().path()
    }
    fn signal_at_seal(&self) -> bool {
        if !until(|| {
            self.root().join("seal-ready").exists() || self.root().join("driver-terminal").exists()
        }) {
            return false;
        }
        if !self.root().join("seal-ready").exists() {
            return false;
        }
        assert!(self.root().join("actual-vendor-reap").exists());
        // SAFETY: only this retained, unreaped driver's own fresh group is signalled.
        assert_eq!(unsafe { libc::getpgid(self.pid) }, self.pid);
        assert_eq!(unsafe { libc::kill(-self.pid, libc::SIGINT) }, 0);
        true
    }
    fn finish(&mut self) -> Option<(ExitStatus, serde_json::Value)> {
        if !until(|| self.root().join("driver-terminal").exists()) {
            // Signal mutation can kill this driver AFTER actual vendor reap +
            // reader join. That receipt proves its sole finite stub is settled,
            // so this original driver Child may be actually reaped safely.
            if self.root().join("actual-vendor-reap").exists() {
                if let Ok(Some(actual)) = self.child.as_mut()?.try_wait() {
                    self.child.take();
                    self.preserve = true;
                    eprintln!(
                        "PUBLICATION_SIGNAL_ACTUAL_DRIVER_WAIT: pid={} code={:?} signal={:?}",
                        self.pid,
                        actual.code(),
                        actual.signal()
                    );
                    eprintln!("PUBLICATION_SIGNAL_DRIVER_STDERR_DIAGNOSTIC_ONLY");
                    eprintln!(
                        "{}",
                        std::fs::read_to_string(self.root().join("driver.stderr"))
                            .unwrap_or_default()
                    );
                    return Some((actual, serde_json::json!({"missing_terminal":true})));
                }
            }
            return None;
        }
        let proof: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.root().join("driver-terminal")).ok()?)
                .ok()?;
        if proof["driver_pid"] != self.pid {
            return None;
        }
        let status = self.child.as_mut()?.wait().ok()?;
        self.child.take();
        eprintln!(
            "PUBLICATION_SIGNAL_ACTUAL_DRIVER_WAIT: pid={} code={:?} signal={:?}",
            self.pid,
            status.code(),
            status.signal()
        );
        eprintln!(
            "{}",
            std::fs::read_to_string(self.root().join("driver.stderr")).unwrap_or_default()
        );
        Some((status, proof))
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        if self.child.is_some() {
            // Failure cleanup still signals only an unreaped test-owned driver;
            // its scoped handler owns actual vendor cleanup and receipt.
            // SAFETY: this actual Child reserves its original private group id.
            if unsafe { libc::getpgid(self.pid) } == self.pid {
                let _ = unsafe { libc::kill(-self.pid, libc::SIGINT) };
            }
            if self.finish().is_none() {
                let path = self.root.take().unwrap().keep();
                eprintln!("LOGIN_PUBLICATION_CUSTODY_UNKNOWN: owned driver terminal/reap proof absent: {}", path.display());
            }
        }
        if self.preserve {
            if let Some(root) = self.root.take() {
                eprintln!("LOGIN_PUBLICATION_CUSTODY_UNKNOWN: actual driver reaped; evidence retained: {}", root.keep().display());
            }
        }
    }
}
fn run(mode: &str, marker: &str) {
    let _environment = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn(mode);
    let signalled = if mode == "pre" || mode == "post" {
        driver.signal_at_seal()
    } else {
        false
    };
    let completed = driver.finish();
    let stub = std::fs::read(driver.root().join("stub-terminal"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let reap = std::fs::read(driver.root().join("actual-vendor-reap"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    assert!(
        stub.as_ref().is_some_and(|stub| stub["fallback"] == false
            && stub["pid"].as_u64().is_some_and(|pid| pid > 0)
            && stub["code"] == 0
            && stub["signal"].is_null())
            && reap
                .as_ref()
                .is_some_and(|reap| reap["pid"] == stub.as_ref().unwrap()["pid"]
                    && reap["code"] == 0
                    && reap["signal"].is_null()
                    && reap["reader_joined"].as_str().is_some()),
        "LOGIN_PUBLICATION_CUSTODY_UNKNOWN: actual original child/reader receipt absent"
    );
    let (status, proof) =
        completed.expect("LOGIN_PUBLICATION_CUSTODY_UNKNOWN: actual driver wait absent");
    let expected = match mode {
        "pre" => {
            proof["lock_held_at_seal"] == true
                && signalled
                && status.code() == Some(130)
                && proof["signal_latched"] == true
                && proof["published"] == false
                && proof["canonical_any"] == false
        }
        "post" => {
            proof["lock_held_at_seal"] == true
                && signalled
                && status.code() == Some(130)
                && proof["signal_latched"] == true
                && proof["published"] == true
                && proof["error"].as_str().is_some_and(|error| {
                    error.contains("WAS signed in") && error.contains("login_committed_cancelled")
                })
        }
        "control" => status.code() == Some(0) && proof["published"] == true,
        _ => {
            status.code() == Some(1)
                && proof["published"] == false
                && proof["canonical_any"] == false
        }
    };
    let home: serde_json::Value = serde_json::from_slice(
        &std::fs::read(driver.root().join("vendor-home-proof"))
            .expect("actual private env read/write receipt"),
    )
    .unwrap();
    let grant_root = std::fs::canonicalize(driver.root().join("base"))
        .unwrap()
        .join(".login-grants");
    assert!(
        home["config_read"] == true
            && home["auth_written"] == true
            && home["home"]
                .as_str()
                .is_some_and(|home| Path::new(home).parent() == Some(grant_root.as_path())),
        "LOGIN_CLI_ACTUAL_PRIVATE_CODEX_HOME_READ_WRITE"
    );
    let prior_preserved = mode == "post"
        || mode == "control"
        || (proof["prior_auth_unchanged"] == true && proof["prior_config_unchanged"] == true);
    assert!(
        expected && proof["private_home_cleaned"] == true && prior_preserved,
        "{marker}"
    );
}
#[test]
fn cli_real_sigint_before_core_seal_refuses_and_cleans() {
    run("pre", "LOGIN_CLI_REAL_SIGNAL_PRE_SEAL");
}
#[test]
fn cli_real_sigint_after_core_seal_publishes_and_reports_signed_in() {
    run("post", "LOGIN_CLI_REAL_SIGNAL_POST_SEAL");
}
#[test]
fn cli_core_publication_without_signal_is_unchanged() {
    run("control", "LOGIN_CLI_REAL_SIGNAL_NO_CANCEL_CONTROL");
}
#[test]
fn cli_actual_vendor_oversized_line_refuses_and_drains() {
    run("oversize", "LOGIN_CLI_ACTUAL_VENDOR_OVERSIZE");
}
#[test]
fn cli_actual_vendor_no_newline_refuses_and_drains() {
    run("no-newline", "LOGIN_CLI_ACTUAL_VENDOR_NO_NEWLINE");
}
