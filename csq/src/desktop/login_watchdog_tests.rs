// Source-only preparation. Controlled native test process, no vendor/login preamble.
use super::login_custody::{self, ChildKey, Drain, LoginProvider};
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::types::AccountNum;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DESKTOP_ENTRY: &str = "desktop::login_watchdog_tests::owned_desktop_vendor_entry";
const DESKTOP_ROLE: &str = "CSQ_PRIVATE_DESKTOP_VENDOR_ROLE";
const DESKTOP_ROOT: &str = "CSQ_PRIVATE_DESKTOP_VENDOR_ROOT";

fn publish_fixture_receipt(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| std::io::Error::other("private receipt parent absent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes.as_ref())?;
    temporary.flush()?;
    let temporary = temporary.into_temp_path(); // Close the writer before publication.
    temporary.persist(path).map_err(|error| error.error)
}

/// Publish a receipt under a name that must not already exist.
///
/// The liveness ping/ack transport uses this instead of replacing one fixed
/// name, because the peer spin-reads those names. On Windows a rename that
/// replaces a file the peer has open fails with `ERROR_ACCESS_DENIED` (os error
/// 5): measured on the train under a full parallel run, that error hit the
/// hold child's `ping-ack` publish (the child panicked, exit 101, and the
/// parent read a dead child as "unconfirmed cancel stopped it") and the
/// parent's own `ping` publish (the probe failed). A never-replaced name has no
/// open peer handle to collide with, and `persist_noclobber` makes reuse of a
/// name a loud `AlreadyExists` on every platform instead of a Windows-only race.
fn publish_new_fixture_receipt(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| std::io::Error::other("private receipt parent absent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes.as_ref())?;
    temporary.flush()?;
    let temporary = temporary.into_temp_path(); // Close the writer before publication.
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
}

/// Hold-child side of the liveness probe: answer the newest unanswered
/// `ping-<n>` with `ping-ack-<n>` carrying the exact nonce read. Returns
/// without acknowledging when the transport is not ready (the parent's bound
/// then reports an unconfirmed probe); it never panics on a transport error,
/// so such an error cannot terminate the child and masquerade as a stopped
/// one. An EMPTY published receipt still panics: publishing is atomic, so that
/// means real corruption, not a transport race.
fn answer_fresh_ping(root: &Path, acknowledged: &mut u64) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let fresh = entries
        .flatten()
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_prefix("ping-")?
                .parse::<u64>()
                .ok()
        })
        .filter(|sequence| *sequence > *acknowledged)
        .max();
    let Some(sequence) = fresh else {
        return;
    };
    let Ok(nonce) = std::fs::read(root.join(format!("ping-{sequence}"))) else {
        return;
    };
    assert!(
        !nonce.is_empty(),
        "DESKTOP_FIXTURE_RECEIPT_EMPTY: receipt=ping"
    );
    if publish_new_fixture_receipt(&root.join(format!("ping-ack-{sequence}")), &nonce).is_ok() {
        *acknowledged = sequence;
    }
}

#[cfg(all(unix, feature = "test-utils"))]
fn read_fixture_path_receipt(root: &Path, name: &'static str) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(root.join(name)).map_err(|error| {
        format!(
            "DESKTOP_FIXTURE_RECEIPT_IO: receipt={name}; kind={:?}; errno={:?}",
            error.kind(),
            error.raw_os_error()
        )
    })?;
    if text.is_empty() {
        return Err(format!("DESKTOP_FIXTURE_RECEIPT_EMPTY: receipt={name}"));
    }
    Ok(PathBuf::from(text))
}

// Diagnostics contain only fixed vocabulary, booleans and errno. Persist at the
// observation boundary; the outer case emits them only after its usual cleanup.
#[cfg(unix)]
fn record_case_diagnostic(value: serde_json::Value) -> Result<(), String> {
    let root =
        std::env::var_os(DESKTOP_ROOT).ok_or("DESKTOP_DIAGNOSTIC_IO: private case root absent")?;
    let root = PathBuf::from(root);
    publish_fixture_receipt(&root.join("case-stage.json"), value.to_string()).map_err(|error| {
        format!(
            "DESKTOP_DIAGNOSTIC_IO: kind={:?}; errno={:?}",
            error.kind(),
            error.raw_os_error()
        )
    })?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("case-diagnostic.jsonl"))
        .map_err(|error| {
            format!(
                "DESKTOP_DIAGNOSTIC_IO: kind={:?}; errno={:?}",
                error.kind(),
                error.raw_os_error()
            )
        })?;
    writeln!(file, "{value}").map_err(|error| {
        format!(
            "DESKTOP_DIAGNOSTIC_IO: kind={:?}; errno={:?}",
            error.kind(),
            error.raw_os_error()
        )
    })
}

#[cfg(all(unix, feature = "test-utils"))]
fn diagnostic_io<T>(result: Option<&std::io::Result<T>>) -> serde_json::Value {
    match result {
        None => serde_json::json!({"kind":"not_applicable","errno":null}),
        Some(Ok(_)) => serde_json::json!({"kind":"ok","errno":null}),
        Some(Err(error)) => {
            serde_json::json!({"kind":format!("{:?}",error.kind()),"errno":error.raw_os_error()})
        }
    }
}

#[cfg(all(unix, feature = "test-utils"))]
fn diagnostic_json<T>(result: Option<&Result<T, serde_json::Error>>) -> &'static str {
    match result {
        None => "not_observed",
        Some(Ok(_)) => "ok",
        Some(Err(error)) => match error.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        },
    }
}

struct DesktopFixture {
    sandbox: Option<tempfile::TempDir>,
    original: Option<Arc<Mutex<std::process::Child>>>,
    pid: Option<u32>,
    reaped: bool,
    sequence: u64,
}

impl DesktopFixture {
    fn new() -> std::io::Result<Self> {
        Self::with_sandbox(tempfile::tempdir()?)
    }
    #[cfg(all(unix, feature = "test-utils"))]
    fn new_short() -> std::io::Result<Self> {
        // Unix socket addresses are bounded even when the isolated runner's
        // TMPDIR is nested deeply. This exclusively owned 0700 root stays
        // alive through all actual Child and reader cleanup.
        Self::with_sandbox(
            tempfile::Builder::new()
                .prefix("cq-du-")
                .tempdir_in("/tmp")?,
        )
    }
    fn with_sandbox(sandbox: tempfile::TempDir) -> std::io::Result<Self> {
        for name in ["home", "base", "config", "tmp", "bin", "local", "appdata"] {
            std::fs::create_dir(sandbox.path().join(name))?;
        }
        Ok(Self {
            sandbox: Some(sandbox),
            original: None,
            pid: None,
            reaped: false,
            sequence: 0,
        })
    }

    fn root(&self) -> &Path {
        self.sandbox.as_ref().expect("private fixture").path()
    }

    fn command(&self, role: &str) -> std::io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .args([
                DESKTOP_ENTRY,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(self.root())
            .env(DESKTOP_ROLE, role)
            .env(DESKTOP_ROOT, self.root())
            .env("HOME", self.root().join("home"))
            .env("CSQ_HOME", self.root().join("home"))
            .env("USERPROFILE", self.root().join("home"))
            .env("CSQ_BASE_DIR", self.root().join("base"))
            .env("CLAUDE_CONFIG_DIR", self.root().join("config"))
            .env("XDG_CONFIG_HOME", self.root().join("config"))
            .env("LOCALAPPDATA", self.root().join("local"))
            .env("APPDATA", self.root().join("appdata"))
            .env("TMPDIR", self.root().join("tmp"))
            .env("TMP", self.root().join("tmp"))
            .env("TEMP", self.root().join("tmp"))
            .env("PATH", self.root().join("bin"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in ["SYSTEMROOT", "SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        Ok(command)
    }

    fn entry_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.root().join("entry-reached"))
            .ok()?
            .parse()
            .ok()
    }

    fn bind_original(&mut self, child: Arc<Mutex<std::process::Child>>) -> bool {
        let Ok(guard) = child.try_lock() else {
            return false;
        };
        let pid = guard.id();
        if self.entry_pid() != Some(pid) || !self.root().join("started").is_file() {
            return false;
        }
        drop(guard);
        self.original = Some(child);
        self.pid = Some(pid);
        true
    }

    fn live_original(&self) -> Option<bool> {
        let child = self.original.as_ref()?;
        let mut child = child.try_lock().ok()?;
        if self.pid != Some(child.id()) {
            return None;
        }
        child.try_wait().ok().map(|status| status.is_none())
    }

    fn ping_after_action(&mut self) -> bool {
        self.sequence += 1;
        let nonce = format!("private-desktop-ping-{}", self.sequence);
        let ping = self.root().join(format!("ping-{}", self.sequence));
        let ack = self.root().join(format!("ping-ack-{}", self.sequence));
        if publish_new_fixture_receipt(&ping, nonce.as_bytes()).is_err() {
            return false;
        }
        bounded(Duration::from_secs(3), || {
            std::fs::read(&ack).ok().as_deref() == Some(nonce.as_bytes())
        })
    }

    fn release(&self, code: i32) -> std::io::Result<()> {
        // Publish only a complete payload; the actual entry/parser is unchanged.
        let mut pending = tempfile::NamedTempFile::new_in(self.root())?;
        pending.write_all(code.to_string().as_bytes())?;
        pending.flush()?;
        pending
            .persist(self.root().join("release"))
            .map_err(|error| error.error)?;
        Ok(())
    }

    fn preserve_unknown(&mut self) {
        if let Some(sandbox) = self.sandbox.take() {
            eprintln!(
                "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: {}",
                sandbox.keep().display()
            );
        }
    }

    fn preserve_failed_case(&mut self) {
        if let Some(sandbox) = self.sandbox.take() {
            eprintln!(
                "DESKTOP_FAILED_CASE_EVIDENCE_ROOT: {}; original_reaped={}",
                sandbox.keep().display(),
                self.reaped
            );
        }
    }

    fn record_after_drain(&mut self) -> Option<ExitStatus> {
        let child = self.original.as_ref()?;
        let mut guard = child.try_lock().ok()?;
        if self.pid != Some(guard.id()) {
            return None;
        }
        let status = guard.try_wait().ok()??;
        // Only the same retained private Child, after its terminal/reap receipt.
        // Claude leaves stderr here; reader-owning adapters have already taken it.
        let stderr = guard.stderr.take();
        drop(guard);
        self.reaped = true;
        eprintln!(
            "PRIVATE_DESKTOP_CHILD_TERMINAL; pid={:?}; status={status:?}; stderr_available={}",
            self.pid,
            stderr.is_some()
        );
        if let Some(mut stderr) = stderr {
            let mut bytes = Vec::new();
            match stderr.read_to_end(&mut bytes) {
                Ok(_) => {
                    if let Err(error) =
                        std::fs::write(self.root().join("terminal-child-stderr"), &bytes)
                    {
                        eprintln!("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: private terminal stderr receipt write failed: {error}");
                    }
                    eprintln!("PRIVATE_DESKTOP_CHILD_STDERR_BEGIN; pid={:?}\n{}PRIVATE_DESKTOP_CHILD_STDERR_END", self.pid, String::from_utf8_lossy(&bytes));
                }
                Err(error) => eprintln!(
                    "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: private terminal stderr unavailable: {error}"
                ),
            }
        }
        Some(status)
    }
}

impl Drop for DesktopFixture {
    fn drop(&mut self) {
        if self.reaped {
            if std::thread::panicking() {
                self.preserve_failed_case();
            }
            return;
        }
        let Some(sandbox) = &self.sandbox else {
            return;
        };
        // Private fixture protocol only. Never signal or kill any PID.
        let _ =
            publish_fixture_receipt(&sandbox.path().join("cleanup"), b"owned fixture cleanup\n");
        let deadline = Instant::now() + Duration::from_secs(2);
        if let Some(child) = &self.original {
            while Instant::now() < deadline {
                if let Ok(mut child) = child.try_lock() {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        self.reaped = true;
                        break;
                    }
                }
                std::thread::yield_now();
            }
        }
        if !self.reaped {
            self.preserve_unknown();
        } else if std::thread::panicking() {
            self.preserve_failed_case();
        }
    }
}

#[test]
fn failed_case_retention_keeps_case_files_after_actual_unwind() {
    let _env_guard = csq_core::platform::test_env::lock();
    let outer = tempfile::tempdir().expect("retention control root");
    let mut fixture =
        DesktopFixture::with_sandbox(tempfile::tempdir_in(outer.path()).expect("failed case root"))
            .expect("failed case fixture");
    let root = fixture.root().to_path_buf();
    for (name, bytes) in [
        ("case.err", "synthetic stderr\n"),
        ("case-failure", "synthetic semantic RED\n"),
        ("case-stage.json", "{\"phase\":\"retention_control\"}\n"),
    ] {
        std::fs::write(root.join(name), bytes).expect("actual case file");
    }
    // Filesystem retention control only; no Child or native custody claim.
    fixture.reaped = true;
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _fixture = fixture;
        panic!("controlled case retention RED");
    }));
    assert!(failure.is_err());
    assert_eq!(
        std::fs::read_to_string(root.join("case.err")).unwrap(),
        "synthetic stderr\n"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("case-failure")).unwrap(),
        "synthetic semantic RED\n"
    );
    assert!(root.join("case-stage.json").is_file());

    let mut green =
        DesktopFixture::with_sandbox(tempfile::tempdir_in(outer.path()).expect("green case root"))
            .unwrap();
    let green_root = green.root().to_path_buf();
    green.reaped = true;
    drop(green);
    assert!(
        !green_root.exists(),
        "actual GREEN still releases its case root"
    );

    let mut unknown = DesktopFixture::with_sandbox(
        tempfile::tempdir_in(outer.path()).expect("unknown case root"),
    )
    .unwrap();
    let unknown_root = unknown.root().to_path_buf();
    std::fs::write(unknown_root.join("case-unknown"), b"synthetic unknown\n").unwrap();
    unknown.preserve_unknown();
    drop(unknown);
    assert_eq!(
        std::fs::read(unknown_root.join("case-unknown")).unwrap(),
        b"synthetic unknown\n"
    );
}

fn bounded(budget: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
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

#[test]
fn fixture_receipt_names_are_never_replaced() {
    let directory = tempfile::tempdir().expect("receipt root");
    let path = directory.path().join("receipt");
    publish_new_fixture_receipt(&path, b"first").expect("first publication");
    let error = publish_new_fixture_receipt(&path, b"second")
        .expect_err("a published receipt name must never be replaced");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).expect("first receipt"), b"first");
    assert_eq!(
        std::fs::read_dir(directory.path())
            .expect("receipt root")
            .count(),
        1,
        "a refused publication must not leave its temporary file behind"
    );
}

#[test]
fn liveness_probe_survives_a_peer_that_spin_reads_every_receipt() {
    use std::sync::atomic::{AtomicBool, Ordering};
    const ROUNDS: u64 = 100;
    let mut fixture = DesktopFixture::new().expect("probe fixture");
    // Filesystem transport only; no Child or custody claim is made here.
    fixture.reaped = true;
    let root = fixture.root().to_path_buf();
    let stop = Arc::new(AtomicBool::new(false));
    let answerer = {
        let (root, stop) = (root.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut acknowledged = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                answer_fresh_ping(&root, &mut acknowledged);
                std::thread::yield_now();
            }
        })
    };
    // The measured Windows race needs the peer to hold a receipt open at the
    // instant the other side publishes it; a hot reader makes that routine.
    let contender = {
        let (root, stop) = (root.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for round in 1..=ROUNDS {
                    let _ = std::fs::read(root.join(format!("ping-{round}")));
                    let _ = std::fs::read(root.join(format!("ping-ack-{round}")));
                }
                std::thread::yield_now();
            }
        })
    };
    let unanswered: Vec<u64> = (1..=ROUNDS)
        .filter(|_| !fixture.ping_after_action())
        .collect();
    stop.store(true, Ordering::Relaxed);
    answerer.join().expect("answering peer");
    contender.join().expect("contending reader");
    assert!(
        unanswered.is_empty(),
        "every liveness probe must be answered under contention; unanswered rounds: {unanswered:?}"
    );
}

#[test]
#[ignore = "fixture dispatcher; an owned subprocess supplies its explicit role"]
fn owned_desktop_vendor_entry() {
    #[cfg(all(unix, feature = "test-utils"))]
    if std::env::var(DESKTOP_ROLE).is_ok_and(|role| role.starts_with("case-handler-")) {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let role = std::env::var(DESKTOP_ROLE).unwrap();
            let root = PathBuf::from(std::env::var_os(DESKTOP_ROOT).unwrap());
            publish_fixture_receipt(&root.join("entry-reached"), std::process::id().to_string())
                .unwrap();
            publish_fixture_receipt(&root.join("started"), b"handler driver").unwrap();
            if role == "case-handler-codex-und" {
                run_handler_und_driver(&root)
            }
            if role == "case-handler-codex-setup-error" {
                run_handler_setup_error_driver(&root)
            }
            run_desktop_case_driver(&role, &root)
        });
        unreachable!();
    }
    let _env_guard = csq_core::platform::test_env::lock();
    let Some(role) = std::env::var_os(DESKTOP_ROLE) else {
        return;
    };
    let role = role.to_str().expect("private role");
    assert!(
        matches!(
            role,
            "hold"
                | "success"
                | "stdout-held"
                | "invalid-data-held"
                | "group-parent"
                | "group-child"
                | "handler-claude"
                | "handler-codex"
                | "handler-codex-und"
        ) || role.starts_with("case-")
    );
    let root = PathBuf::from(std::env::var_os(DESKTOP_ROOT).expect("private root"));
    for (key, name) in [
        ("HOME", "home"),
        ("CSQ_HOME", "home"),
        ("USERPROFILE", "home"),
        ("CSQ_BASE_DIR", "base"),
        ("CLAUDE_CONFIG_DIR", "config"),
        ("PATH", "bin"),
        ("TMPDIR", "tmp"),
        ("TMP", "tmp"),
        ("TEMP", "tmp"),
        ("LOCALAPPDATA", "local"),
        ("APPDATA", "appdata"),
    ] {
        assert_eq!(
            std::env::var_os(key).as_deref(),
            Some(root.join(name).as_os_str())
        );
    }
    #[cfg(unix)]
    if role == "group-child" {
        desktop_group_actor(&root, false);
    }
    publish_fixture_receipt(&root.join("entry-reached"), std::process::id().to_string())
        .expect("entry PID");
    publish_fixture_receipt(&root.join("started"), b"owned command entry\n").expect("started");
    if role.starts_with("case-") {
        run_desktop_case_driver(role, &root);
    }
    #[cfg(unix)]
    if role == "group-parent" {
        desktop_group_actor(&root, true);
    }
    if role == "invalid-data-held" {
        std::io::stdout()
            .write_all(&[0xff, b'\n'])
            .expect("private invalid UTF8");
        std::io::stdout().flush().expect("private invalid flush");
    }
    #[cfg(all(unix, feature = "test-utils"))]
    if role.starts_with("handler-") {
        handler_vendor_write(role, &root);
    }
    if role == "success" {
        std::fs::write(root.join("completed"), b"inert desktop transaction\n").expect("completed");
        std::process::exit(0);
    }
    // stdout/stderr intentionally remain open and silent. Codex/native real
    // reader/forwarder loops block before vendor wait without URL/browser activity.
    let mut acknowledged = 0_u64;
    loop {
        if root.join("cleanup").is_file() {
            std::process::exit(90);
        }
        answer_fresh_ping(&root, &mut acknowledged);
        if let Ok(code) = std::fs::read_to_string(root.join("release")) {
            let code = code.parse::<i32>().expect("private release code");
            assert!(matches!(code, 0 | 7));
            std::fs::write(root.join("completed"), b"inert desktop transaction\n")
                .expect("completed");
            std::io::stdout().flush().expect("fixture stdout flush");
            std::process::exit(code);
        }
        std::thread::yield_now();
    }
}

const RETAIN: &str =
    "dropping desktop observer must retain the exact live owned child and account lock";
const DRAIN_PENDING: &str =
    "desktop drain must remain pending while actual child or readers are live";
const CANCEL_FALSE: &str = "unconfirmed desktop cancel must never stop or clear owned child";
const CANCEL_TARGET: &str =
    "confirmed desktop cancel must stop only the exact selected owned child";
const EXIT_EARLY: &str = "desktop exit finalizer must wait for actual child and reader drain";
const LATE_ZERO: &str =
    "late desktop vendor zero must not authorize refused observer post callback";
type Observer = tokio::task::JoinHandle<Result<(), String>>;

fn account(value: u16) -> AccountNum {
    AccountNum::try_from(value).expect("private fixture account")
}
fn private_lock(root: &Path, value: u16) -> Result<Arc<AccountLoginLock>, String> {
    match AccountLoginLock::acquire(&root.join("base"), account(value)) {
        Ok(AcquireOutcome::Acquired(lock)) => Ok(Arc::new(lock)),
        _ => Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: private lock unavailable".into()),
    }
}
fn lock_held(root: &Path, value: u16) -> bool {
    matches!(
        AccountLoginLock::acquire(&root.join("base"), account(value)),
        Ok(AcquireOutcome::Held { .. })
    )
}
async fn until(budget: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::task::yield_now().await;
    }
}
async fn bind(fixture: &mut DesktopFixture, key: ChildKey) -> Result<(), String> {
    if !until(Duration::from_secs(10), || {
        fixture.entry_pid().is_some() && fixture.root().join("started").is_file()
    })
    .await
    {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: exact owned adapter entry absent".into());
    }
    if !until(Duration::from_secs(5), || {
        login_custody::global()
            .registered_child_for_test(&key)
            .is_some_and(|child| fixture.bind_original(child))
    })
    .await
    {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual adapter child identity unavailable; carrier hook required".into());
    }
    Ok(())
}
fn live_after_action(fixture: &mut DesktopFixture, semantic_marker: &str) -> Result<(), String> {
    match fixture.live_original() {
        Some(true) => {}
        Some(false) => {
            if semantic_marker == CANCEL_TARGET {
                eprintln!(
                    "{CANCEL_TARGET}; stage=unrelated_initial_terminal; pid={:?}; ping_sequence={}",
                    fixture.pid, fixture.sequence
                );
            }
            return Err(semantic_marker.into());
        }
        None => {
            return Err(
                "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: child handle observation unavailable".into(),
            )
        }
    }
    if !fixture.ping_after_action() {
        // The carrier can stop this exact child between the initial live
        // observation and its fresh acknowledgement. Require a terminal
        // receipt from the same retained Child before a semantic failure.
        return match fixture.live_original() {
            Some(false) => {
                if semantic_marker == CANCEL_TARGET {
                    eprintln!("{CANCEL_TARGET}; stage=unrelated_terminal_after_ping; pid={:?}; ping_sequence={}", fixture.pid, fixture.sequence);
                }
                Err(semantic_marker.into())
            }
            Some(true) | None => {
                Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: fresh child ping not observed".into())
            }
        };
    }
    Ok(())
}
async fn pending(drain: &Drain) -> Result<(), String> {
    let waiting = drain.wait();
    tokio::pin!(waiting);
    let is_pending =
        std::future::poll_fn(|cx| std::task::Poll::Ready(waiting.as_mut().poll(cx).is_pending()))
            .await;
    if is_pending {
        Ok(())
    } else {
        Err(DRAIN_PENDING.into())
    }
}
async fn drain_complete(drain: &Drain, fixture: &mut DesktopFixture) -> Result<ExitStatus, String> {
    tokio::time::timeout(Duration::from_secs(10), drain.wait())
        .await
        .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: drain not observed")??;
    fixture.record_after_drain().ok_or_else(|| {
        "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: original handle has no terminal receipt".into()
    })
}
async fn result(observer: &mut Observer) -> Result<Result<(), String>, String> {
    tokio::time::timeout(Duration::from_secs(5), observer)
        .await
        .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: adapter observation cap reached")?
        .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: adapter task failed".into())
}
fn start_claude(
    fixture: &DesktopFixture,
    slot: u16,
    timeout: Duration,
    post: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<Observer, String> {
    let command = fixture.command("hold").map_err(|e| e.to_string())?;
    let lock = private_lock(fixture.root(), slot)?;
    let key = ChildKey::new(LoginProvider::Claude, account(slot));
    login_custody::global().spawn_with_ticket(move |ticket| async move {
        let status = super::commands::claude_login_subprocess::desktop_vendor_status_registered_with_timeout(
            command, (ticket, lock), timeout, key,
        ).await?;
        if status.success() { post.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
        Ok(())
    })
}
async fn claude_case(drop_observer: bool, cancel: bool) -> Result<(), String> {
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let post = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let key = ChildKey::new(LoginProvider::Claude, account(1));
    let mut observer = start_claude(
        &fixture,
        1,
        if drop_observer || cancel {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(2)
        },
        Arc::clone(&post),
    )?;
    bind(&mut fixture, key).await?;
    if cancel {
        let operation_id = login_custody::global()
            .pending_logins()?
            .into_iter()
            .find(|row| row.provider == "claude" && row.account == 1)
            .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: owned operation identity unavailable")?
            .operation_id;
        let consent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let false_count = Arc::clone(&consent);
        let denied = login_custody::global()
            .cancel_child_with_confirmation(key, &operation_id, false, move || async move {
                false_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(true)
            })
            .await;
        if denied.as_ref().err().map(String::as_str) != Some("login_cancel_confirmation_required")
            || consent.load(std::sync::atomic::Ordering::SeqCst) != 0
        {
            return Err(CANCEL_FALSE.into());
        }
        let indexed = login_custody::global()
            .registered_child_for_test(&key)
            .is_some_and(|child| {
                fixture
                    .original
                    .as_ref()
                    .is_some_and(|owned| Arc::ptr_eq(&child, owned))
            });
        if !indexed {
            return Err(CANCEL_FALSE.into());
        }
        live_after_action(&mut fixture, CANCEL_FALSE)?;
        let stale_count = Arc::clone(&consent);
        let stale = login_custody::global()
            .cancel_child_with_confirmation(
                key,
                "stale-private-operation",
                true,
                move || async move {
                    stale_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(true)
                },
            )
            .await;
        if stale.as_ref().err().map(String::as_str) != Some("login_cancel_target_changed")
            || consent.load(std::sync::atomic::Ordering::SeqCst) != 0
        {
            return Err(CANCEL_FALSE.into());
        }
        live_after_action(&mut fixture, CANCEL_FALSE)?;
        let decline = login_custody::global()
            .cancel_child_with_confirmation(key, &operation_id, true, || async { Ok(false) })
            .await?;
        if decline {
            return Err(CANCEL_FALSE.into());
        }
        live_after_action(&mut fixture, CANCEL_FALSE)?;
        let mut unrelated = DesktopFixture::new().map_err(|e| e.to_string())?;
        let unrelated_post = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut unrelated_observer =
            start_claude(&unrelated, 2, Duration::from_secs(60), unrelated_post)?;
        bind(
            &mut unrelated,
            ChildKey::new(LoginProvider::Claude, account(2)),
        )
        .await?;
        if !login_custody::global()
            .cancel_child_with_confirmation(key, &operation_id, true, || async { Ok(true) })
            .await?
        {
            eprintln!("{CANCEL_TARGET}; stage=confirmed_cancel_returned_false; selected_pid={:?}; unrelated_pid={:?}", fixture.pid, unrelated.pid);
            return Err(CANCEL_TARGET.into());
        }
        if login_custody::global()
            .registered_child_for_test(&key)
            .is_some()
        {
            eprintln!("{CANCEL_TARGET}; stage=selected_registration_retained; selected_pid={:?}; unrelated_pid={:?}", fixture.pid, unrelated.pid);
            return Err(CANCEL_TARGET.into());
        }
        live_after_action(&mut unrelated, CANCEL_TARGET)?;
        let cancelled = result(&mut observer).await?;
        if cancelled.is_ok() || post.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            eprintln!("{CANCEL_TARGET}; stage=selected_observer_or_post; observer_ok={}; post={}; selected_pid={:?}; unrelated_pid={:?}", cancelled.is_ok(), post.load(std::sync::atomic::Ordering::SeqCst), fixture.pid, unrelated.pid);
            return Err(CANCEL_TARGET.into());
        }
        let drain = login_custody::global().close();
        pending(&drain).await?;
        unrelated.release(0).map_err(|e| e.to_string())?;
        result(&mut unrelated_observer).await??;
        let status = drain_complete(&drain, &mut fixture).await?;
        if status.success() {
            eprintln!("{CANCEL_TARGET}; stage=selected_terminal_success; selected_status={status:?}; selected_pid={:?}; unrelated_pid={:?}; selected_reaped={}", fixture.pid, unrelated.pid, fixture.reaped);
            return Err(CANCEL_TARGET.into());
        }
        let other = unrelated
            .record_after_drain()
            .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: unrelated child reap absent")?;
        if !other.success() {
            eprintln!("{CANCEL_TARGET}; stage=unrelated_terminal_nonzero; selected_status={status:?}; unrelated_status={other:?}; selected_pid={:?}; unrelated_pid={:?}; unrelated_reaped={}", fixture.pid, unrelated.pid, unrelated.reaped);
            return Err(CANCEL_TARGET.into());
        }
        drain.reopen()?;
        return Ok(());
    }
    if drop_observer {
        observer.abort();
        let joined = observer.await;
        if !joined.is_err_and(|error| error.is_cancelled()) {
            return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: observer abort not observed".into());
        }
    } else {
        let refusal = result(&mut observer)
            .await?
            .err()
            .ok_or("timeout must not authorize desktop post callback")?;
        if !refusal.contains("login_timeout_refused") {
            return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: wrong refusal receipt".into());
        }
    }
    live_after_action(&mut fixture, RETAIN)?;
    if !lock_held(fixture.root(), 1) {
        return Err(RETAIN.into());
    }
    let drain = login_custody::global().close();
    pending(&drain).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    let status = drain_complete(&drain, &mut fixture).await?;
    if !status.success() || post.load(std::sync::atomic::Ordering::SeqCst) != 0 {
        eprintln!("{LATE_ZERO}; stage=late_terminal_or_post; child_status={status:?}; post={}; pid={:?}; reaped={}", post.load(std::sync::atomic::Ordering::SeqCst), fixture.pid, fixture.reaped);
        return Err(LATE_ZERO.into());
    }
    drain.reopen()?;
    Ok(())
}

async fn native_case() -> Result<(), String> {
    use csq_core::providers::{catalog::Surface, native_login::login_native_with};
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture.command("stdout-held").map_err(|e| e.to_string())?;
    let base = fixture.root().join("base");
    let key = ChildKey::new(LoginProvider::Grok, account(3));
    let lock = private_lock(fixture.root(), 3)?;
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        Duration::from_secs(2),
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let worker_watchdog = watchdog.clone();
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        let worker = tokio::task::spawn_blocking(move || {
            let children: super::commands::NativeLoginChildren =
                Arc::new(Mutex::new(std::collections::HashMap::new()));
            let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
            login_native_with(
                &base,
                account(3),
                Surface::Grok,
                move |_, _, _, _| {
                    super::commands::native_vendor_with_command(
                        command,
                        "owned-private-native",
                        Surface::Grok,
                        &children,
                        &spawned,
                        worker_watchdog,
                        (ticket, lock),
                        key,
                    )
                },
                |_| {},
            )
            .map_err(|e| format!("{e:#}"))
        });
        super::commands::observe_desktop_login(worker, watchdog).await
    })?;
    bind(&mut fixture, key).await?;
    let refusal = result(&mut observer)
        .await?
        .err()
        .ok_or("native timeout must suppress post-wait finalization")?;
    if !refusal.contains("login_timeout_refused") {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: native refusal absent".into());
    }
    live_after_action(&mut fixture, RETAIN)?;
    if !lock_held(fixture.root(), 3) {
        return Err(RETAIN.into());
    }
    let drain = login_custody::global().close();
    pending(&drain).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    let status = drain_complete(&drain, &mut fixture).await?;
    if !status.success() {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: private native completion failed".into());
    }
    drain.reopen()?;
    Ok(())
}

#[cfg(unix)]
async fn codex_case(exit_request: bool) -> Result<(), String> {
    let app = tauri::test::mock_app();
    let handle = app.handle().clone();
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture.command("stdout-held").map_err(|e| e.to_string())?;
    let lock = private_lock(fixture.root(), 4)?;
    let key = ChildKey::new(LoginProvider::Codex, account(4));
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        if exit_request {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(2)
        },
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let worker_watchdog = watchdog.clone();
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        let worker = tokio::task::spawn_blocking(move || {
            let slot = Arc::new(Mutex::new(None));
            let mut on_code = |_| {};
            super::commands::codex_vendor_with_command(
                command,
                &mut on_code,
                &handle,
                &slot,
                worker_watchdog,
                (ticket, lock),
                key,
            )
            .map(|_| ())
            .map_err(|e| format!("{e:#}"))
        });
        super::commands::observe_desktop_login(worker, watchdog).await
    })?;
    bind(&mut fixture, key).await?;
    if exit_request {
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let final_code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
        let observed = Arc::clone(&finished);
        let code = Arc::clone(&final_code);
        login_custody::request_exit_with_finalizer(app.handle(), 17, move |value| {
            code.store(value, std::sync::atomic::Ordering::SeqCst);
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        if login_custody::global().admit().is_ok()
            || finished.load(std::sync::atomic::Ordering::SeqCst)
            || login_custody::global().exit_verified()
        {
            return Err(EXIT_EARLY.into());
        }
        live_after_action(&mut fixture, EXIT_EARLY)?;
        fixture.release(0).map_err(|e| e.to_string())?;
        result(&mut observer).await??;
        if !until(Duration::from_secs(10), || {
            finished.load(std::sync::atomic::Ordering::SeqCst)
        })
        .await
        {
            return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: exit finalizer unavailable".into());
        }
        if final_code.load(std::sync::atomic::Ordering::SeqCst) != 17
            || !login_custody::global().exit_verified()
        {
            return Err(EXIT_EARLY.into());
        }
        if !fixture
            .record_after_drain()
            .is_some_and(|status| status.success())
        {
            return Err(EXIT_EARLY.into());
        }
        return Ok(());
    }
    let refusal = result(&mut observer)
        .await?
        .err()
        .ok_or("Codex pre-wait reader timeout must refuse publication")?;
    if !refusal.contains("login_timeout_refused") {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: Codex refusal absent".into());
    }
    live_after_action(&mut fixture, RETAIN)?;
    if !lock_held(fixture.root(), 4) {
        return Err(RETAIN.into());
    }
    let drain = login_custody::global().close();
    pending(&drain).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    if !drain_complete(&drain, &mut fixture).await?.success() {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: Codex completion failed".into());
    }
    drain.reopen()?;
    Ok(())
}

fn run_desktop_case_driver(role: &str, root: &Path) -> ! {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("private desktop runtime");
    let (case_result, accounted) = runtime
        .block_on(async {
            let outcome = match role {
                #[cfg(all(unix, feature = "test-utils"))]
                role if role.starts_with("case-handler-") => handler_case(role).await,
                "case-claude-drop" => claude_case(true, false).await,
                "case-claude-timeout" => claude_case(false, false).await,
                "case-confirm-cancel" => claude_case(false, true).await,
                "case-native-reader" => native_case().await,
                "case-native-invalid" => native_invalid_case().await,
                #[cfg(unix)]
                "case-reservation" => reservation_case().await,
                #[cfg(unix)]
                "case-pub-finalized-before" => {
                    publication_after_reap_before_publication_case().await
                }
                "case-pub-before" => publication_case(false).await,
                "case-pub-after" => publication_case(true).await,
                #[cfg(unix)]
                "case-group-end" => group_end_case().await,
                #[cfg(unix)]
                "case-codex-reader" => codex_case(false).await,
                #[cfg(unix)]
                "case-exit-drain" => codex_case(true).await,
                #[cfg(unix)]
                "case-reader-finish" => reader_finish_tests::case_reader_finish().await,
                _ => Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: unsupported case role".into()),
            };
            #[cfg(unix)]
            if role == "case-group-end" {
                group_driver_diagnostic("group_driver_before_drain", None, outcome.is_err())?;
            }
            let drain = login_custody::global().close();
            let accounted = matches!(
                tokio::time::timeout(Duration::from_secs(10), drain.wait()).await,
                Ok(Ok(()))
            );
            #[cfg(unix)]
            if role == "case-group-end" {
                group_driver_diagnostic(
                    "group_driver_after_drain",
                    Some(accounted),
                    outcome.is_err(),
                )?;
            }
            Ok::<_, String>((outcome, accounted))
        })
        .unwrap_or_else(|error| (Err(error), false));
    if !accounted {
        std::fs::write(
            root.join("case-unknown"),
            b"actual desktop custody did not drain",
        )
        .expect("unknown receipt");
        // Preserve the actual owner; parent lifecycle controls this diagnostic group.
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }
    drop(runtime);
    match case_result {
        Ok(()) => {
            std::fs::write(
                root.join("case-completed"),
                b"actual adapter and guard drained\n",
            )
            .expect("case proof");
            std::process::exit(0)
        }
        Err(error) => {
            std::fs::write(root.join("case-failure"), error).expect("case failure");
            std::process::exit(8)
        }
    }
}

// Shared test custody: one independent Unix safety path owns WNOWAIT,
// group kill, actual reader joins, original reap and ESRCH observations.
#[cfg(unix)]
use crate::login_child_custody::test_case_custody::{CaseCustody, CaseWait};

#[cfg(not(unix))]
struct CaseWait {
    group_empty: bool,
    status: Option<ExitStatus>,
    timed_out: bool,
    detail: Option<String>,
}
fn spawn_owned_case(command: &mut Command) -> std::io::Result<std::process::Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command.spawn()
}

#[cfg(unix)]
fn wait_owned_case(fixture: &mut DesktopFixture, budget: Duration) -> CaseWait {
    let failed = |detail: &str| CaseWait {
        group_empty: false,
        status: None,
        readers_joined: false,
        timed_out: false,
        detail: Some(detail.into()),
    };
    let Some(original) = fixture.original.as_ref().map(Arc::clone) else {
        return failed("original case handle unavailable");
    };
    let Some(pid) = fixture.pid else {
        return failed("original case identity unavailable");
    };
    let mut custody = CaseCustody::from_shared(original, pid);
    let mut receipt = custody.wait(budget);
    if receipt.timed_out {
        receipt = custody.cleanup(Duration::from_secs(3));
        receipt.timed_out = true;
    }
    if receipt.status.is_some() {
        fixture.reaped = true;
    }
    receipt
}

#[cfg(not(unix))]
fn wait_owned_case(fixture: &mut DesktopFixture, budget: Duration) -> CaseWait {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = fixture.original.as_ref().and_then(|child| {
            child
                .try_lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok().flatten())
        }) {
            fixture.reaped = true;
            return CaseWait {
                group_empty: false,
                status: Some(status),
                timed_out: false,
                detail: None,
            };
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            {
                return stop_owned_case_after_bound(fixture);
            }
            #[cfg(not(unix))]
            {
                return CaseWait {
                    group_empty: false,
                    status: None,
                    timed_out: true,
                    detail: None,
                };
            }
        }
        std::thread::yield_now();
    }
}

fn case_process(role: &str) {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut fixture = DesktopFixture::new().expect("private case sandbox");
    let mut command = fixture.command(role).expect("private case command");
    command
        .stdout(std::fs::File::create(fixture.root().join("case.out")).expect("case stdout"))
        .stderr(std::fs::File::create(fixture.root().join("case.err")).expect("case stderr"));
    let child = spawn_owned_case(&mut command).expect("owned exact case entry");
    let pid = child.id();
    fixture.pid = Some(pid);
    fixture.original = Some(Arc::new(Mutex::new(child)));
    let waited = wait_owned_case(&mut fixture, Duration::from_secs(40));
    let last_recorded_stage = std::fs::File::open(fixture.root().join("case-stage.json"))
        .ok()
        .and_then(|file| {
            let mut bytes = Vec::new();
            file.take(8_193).read_to_end(&mut bytes).ok()?;
            (bytes.len() <= 8_192).then_some(bytes)
        })
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|record| {
            record["phase"]
                .as_str()
                .filter(|phase| {
                    phase.len() <= 80
                        && phase
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                })
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unavailable".into());
    if waited.status.is_some() {
        match std::fs::File::open(fixture.root().join("case-diagnostic.jsonl")) {
            Ok(file) => {
                let mut diagnostics = String::new();
                match file.take(65_537).read_to_string(&mut diagnostics) {
                    Ok(_) if diagnostics.len() <= 65_536 => {
                        for line in diagnostics.lines() {
                            eprintln!("DESKTOP_POST_CLEANUP_DIAGNOSTIC: case_reaped=true; nested_custody_proven=false; {line}");
                        }
                    }
                    Ok(_) => eprintln!("DESKTOP_DIAGNOSTIC_IO: kind=cap_exceeded; errno=none"),
                    Err(error) => eprintln!(
                        "DESKTOP_DIAGNOSTIC_IO: kind={:?}; errno={:?}",
                        error.kind(),
                        error.raw_os_error()
                    ),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "DESKTOP_DIAGNOSTIC_IO: kind={:?}; errno={:?}",
                error.kind(),
                error.raw_os_error()
            ),
        }
    }
    if waited.timed_out {
        use std::io::Read;
        if let Ok(file) = std::fs::File::open(fixture.root().join("case.err")) {
            let mut diagnostics = String::new();
            let _ = file.take(32_768).read_to_string(&mut diagnostics);
            for line in diagnostics
                .lines()
                .filter(|line| line.starts_with("DESKTOP_UND_"))
            {
                eprintln!("{line}");
            }
        }
    }
    let status = match (
        waited.status,
        waited.timed_out,
        waited.detail,
        waited.group_empty,
    ) {
        (Some(status), false, _, _) => status,
        (Some(status), true, detail, group_empty) => {
            if let Some(root) = fixture.sandbox.take() {
                eprintln!(
                    "DESKTOP_CASE_TIMEOUT_REAPED_ROOT: {}",
                    root.keep().display()
                );
            }
            panic!("DESKTOP_CASE_TIMEOUT_REAPED: original case {pid} reaped {status:?}; case_group_empty={group_empty}; last_recorded_stage={last_recorded_stage}; {detail:?}; nested fixture PGIDs not proven by case cleanup");
        }
        (None, _, None, _) => {
            fixture.preserve_unknown();
            panic!("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: case process unavailable");
        }
        (None, _, Some(detail), _) => {
            if let Some(root) = fixture.sandbox.take() {
                eprintln!(
                    "DESKTOP_CASE_CLEANUP_UNCONFIRMED_ROOT: {}",
                    root.keep().display()
                );
            }
            std::mem::forget(fixture.original.take());
            panic!("DESKTOP_CASE_CLEANUP_UNCONFIRMED: {detail}; original owned case retained for ROOT/Trestle");
        }
    };
    if fixture.entry_pid() != Some(pid) || !fixture.root().join("started").is_file() {
        panic!("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: exact case entry not reached");
    }
    let failure = std::fs::read_to_string(fixture.root().join("case-failure")).ok();
    if let Some(error) = failure.as_deref() {
        // Preserve the exact semantic marker/classifier. Surface only this
        // private synthetic case's stderr, where the failure stage was tagged.
        if error == CANCEL_TARGET
            || error == LATE_ZERO
            || error.starts_with("HANDLER_UND_RETAINS_SHARED_GRANT: ")
        {
            if let Ok(diagnostic) = std::fs::read_to_string(fixture.root().join("case.err")) {
                eprintln!("CANCEL_TARGET_OR_LATE_ZERO_PRIVATE_CASE_STDERR_BEGIN\n{diagnostic}CANCEL_TARGET_OR_LATE_ZERO_PRIVATE_CASE_STDERR_END");
            }
        }
        if [
            "receive-writer",
            "configure-receiver",
            "receiver-ready",
            "await-receiver-ready",
        ]
        .iter()
        .any(|phase| error.starts_with(&format!("DESKTOP_FIXTURE_SETUP: phase={phase};")))
        {
            if let Ok(diagnostic) = std::fs::read_to_string(fixture.root().join("case.err")) {
                for line in diagnostic
                    .lines()
                    .filter(|line| line.starts_with("DESKTOP_SCM_STEP:"))
                {
                    eprintln!("{line}");
                }
            }
        }
        match error {
            RETAIN
            | DRAIN_PENDING
            | CANCEL_FALSE
            | CANCEL_TARGET
            | EXIT_EARLY
            | LATE_ZERO
            | GROUP_END
            | NATIVE_INVALID
            | PUB_BEFORE
            | PUB_AFTER
            | RESERVED_BEFORE_SPAWN => {
                assert!(failure.is_none(), "{error}")
            }
            #[cfg(all(unix, feature = "test-utils"))]
            _ if error.starts_with("HANDLER_") => assert!(failure.is_none(), "{error}"),
            #[cfg(unix)]
            _ if error == reader_finish_tests::READER_FINISH => {
                assert!(failure.is_none(), "{error}")
            }
            _ => panic!("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: {error}"),
        }
    }
    assert_eq!(
        status.code(),
        Some(0),
        "actual adapter case process must finish cleanly"
    );
    assert!(
        fixture.root().join("case-completed").is_file(),
        "actual adapter/drain completion receipt required"
    );
}

#[test]
fn claude_observer_drop_retains_actual_child_and_lock() {
    case_process("case-claude-drop");
}
#[test]
fn claude_timeout_late_zero_never_reaches_post_callback() {
    case_process("case-claude-timeout");
}
#[test]
fn explicit_confirmation_stops_only_selected_owned_child_after_reap() {
    case_process("case-confirm-cancel");
}
#[test]
fn native_pre_wait_reader_timeout_keeps_actual_child_owned() {
    case_process("case-native-reader");
}
#[cfg(unix)]
#[test]
fn codex_pre_wait_readers_timeout_keeps_actual_child_owned() {
    case_process("case-codex-reader");
}
#[cfg(unix)]
#[test]
fn actual_codex_adapter_exit_request_drains_before_finalizer() {
    case_process("case-exit-drain");
}

#[cfg(unix)]
mod reader_finish_tests {
    include!("login_watchdog_reader_finish_tests.rs");
}

#[test]
fn instrument_empty_private_release_reaches_actual_parser_panic() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut fixture = DesktopFixture::new().expect("private instrument sandbox");
    // Deliberately model the old visible-create-before-write interval exactly.
    std::fs::File::create(fixture.root().join("release"))
        .expect("intentional empty old-protocol release");
    let child = fixture
        .command("hold")
        .expect("private instrument command")
        .spawn()
        .expect("private instrument actual entry");
    let pid = child.id();
    fixture.pid = Some(pid);
    fixture.original = Some(Arc::new(Mutex::new(child)));
    if !bounded(Duration::from_secs(10), || {
        fixture.live_original() == Some(false)
    }) {
        fixture.preserve_unknown();
        panic!("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: instrument actual parser terminal receipt absent");
    }
    assert_eq!(
        fixture.entry_pid(),
        Some(pid),
        "INSTRUMENT: exact child entry required"
    );
    assert!(
        fixture.root().join("started").is_file(),
        "INSTRUMENT: actual parser entry required"
    );
    let status = fixture
        .record_after_drain()
        .expect("INSTRUMENT: same-handle actual reap receipt");
    let stderr = std::fs::read_to_string(fixture.root().join("terminal-child-stderr"))
        .expect("INSTRUMENT: actual child stderr receipt");
    assert_eq!(
        status.code(),
        Some(101),
        "INSTRUMENT: actual Rust test entry must reject empty release"
    );
    assert!(
        stderr.contains("private release code") && stderr.contains("Empty"),
        "INSTRUMENT: actual empty-payload parser panic required: {stderr}"
    );
    assert!(
        !fixture.root().join("completed").exists(),
        "INSTRUMENT: empty release cannot complete"
    );
    eprintln!("INSTRUMENT_PRIVATE_EMPTY_RELEASE_PROVED; pid={pid}; status={status:?}; product_red_credit=false");
}

const GROUP_END: &str =
    "confirmed End must stop the actual vendor group and stdout-holding descendant";
const NATIVE_INVALID: &str =
    "native invalid UTF8 must refuse before actual raw stdout drain completes";
const PUB_BEFORE: &str =
    "cancel before first canonical seal must refuse actual late vendor success";
const PUB_AFTER: &str = "cancel after publication seal must finish actual owned finalization and report committed cancel";

#[tokio::test]
async fn overlong_operation_identity_refuses_before_lookup_or_consent() {
    let gate = login_custody::CredentialWrites::default();
    let confirmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&confirmed);
    let result = gate
        .cancel_provider_with_confirmation(
            LoginProvider::Claude,
            &"a".repeat(129),
            true,
            move || async move {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(true)
            },
        )
        .await;
    assert_eq!(
        result.err().as_deref(),
        Some("login_operation_id_invalid"),
        "overlong operation identity must be rejected before registry lookup"
    );
    assert!(!confirmed.load(std::sync::atomic::Ordering::SeqCst));
}
#[tokio::test]
async fn overflow_observer_returns_refusal_without_panicking() {
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        Duration::MAX,
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let worker = tokio::spawn(async { Ok::<_, String>(()) });
    let result = super::commands::observe_desktop_login(worker, watchdog).await;
    assert!(
        result.is_err(),
        "overflow observer must return a named refusal"
    );
}

async fn native_invalid_case() -> Result<(), String> {
    use csq_core::providers::catalog::Surface;
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture
        .command("invalid-data-held")
        .map_err(|e| e.to_string())?;
    let base = fixture.root().join("base");
    let lock = private_lock(fixture.root(), 8)?;
    let key = ChildKey::new(LoginProvider::Grok, account(8));
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        Duration::from_secs(60),
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let observed = watchdog.clone();
    let worker_watchdog = watchdog.clone();
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        let worker = tokio::task::spawn_blocking(move || {
            let children = Arc::new(Mutex::new(std::collections::HashMap::new()));
            let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
            csq_core::providers::native_login::login_native_with(
                &base,
                account(8),
                Surface::Grok,
                move |_, _, _, _| {
                    super::commands::native_vendor_with_command(
                        command,
                        "owned-private-native",
                        Surface::Grok,
                        &children,
                        &spawned,
                        worker_watchdog,
                        (ticket, lock),
                        key,
                    )
                },
                |_| {},
            )
            .map_err(|e| format!("{e:#}"))
        });
        super::commands::observe_desktop_login(worker, watchdog).await
    })?;
    bind(&mut fixture, key).await?;
    let refused_while_pipe_live = until(Duration::from_secs(2), || observed.is_refused()).await;
    let drain = login_custody::global().close();
    pending(&drain).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    let outcome = result(&mut observer).await?;
    let status = drain_complete(&drain, &mut fixture).await?;
    drain.reopen()?;
    if !refused_while_pipe_live || outcome.is_ok() || !status.success() {
        return Err(NATIVE_INVALID.into());
    }
    Ok(())
}

// Regression boundary: the actual inherited-stdio owner has reaped its Child
// and completed its reader-finalization gate, while the outer publication seal
// and lock are still held. Uses only APIs that exist before the product fix.
#[cfg(unix)]
async fn publication_after_reap_before_publication_case() -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const REACHED: &str = "LOGIN_CANCEL_AFTER_REAP_BEFORE_PUBLICATION_REACHED";
    const VERDICT: &str = "LOGIN_CANCEL_AFTER_REAP_BEFORE_PUBLICATION_CLEAN_REFUSAL";
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture.command("hold").map_err(|e| e.to_string())?;
    let key = ChildKey::new(LoginProvider::Claude, account(9));
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        Duration::from_secs(60),
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let observed_watchdog = watchdog.clone();
    let operation = login_custody::global().reserve_child(key, watchdog.clone())?;
    let worker_operation = Arc::clone(&operation);
    let operation_id = login_custody::global()
        .pending_logins()?
        .into_iter()
        .find(|row| row.account == 9)
        .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finalized publication operation absent")?
        .operation_id;
    let ready = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let seen_ready = Arc::clone(&ready);
    let finish = Arc::clone(&release);
    let committed = Arc::clone(&writes);
    let lock = private_lock(fixture.root(), 9)?;
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        let _outer_lock = lock;
        let _outer_ticket = ticket;
        let status = super::commands::claude_login_subprocess::desktop_vendor_status_impl(
            command,
            (Arc::clone(&_outer_ticket), Arc::clone(&_outer_lock)),
            watchdog,
            Arc::clone(&worker_operation),
            || Ok(()),
        )
        .await?;
        let (group, observation) = login_custody::global()
            .registered_observation_for_test(&key)
            .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finalized vendor observation absent")?;
        // This inherited-stdio adapter has no separate pipe-reader thread.
        // readers_joined is its real owner's completed finalization gate; no
        // new test flag or competing Child::try_wait supplies either proof.
        if !status.success()
            || !observation
                .reaped_status()
                .is_some_and(|actual| actual.success())
            || !group.readers_joined()
            || observation.custody_unresolved()
        {
            return Err(
                "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: vendor owner not positively finalized".into(),
            );
        }
        seen_ready.store(true, Ordering::SeqCst);
        if !until(Duration::from_secs(8), || finish.load(Ordering::SeqCst)).await {
            return Err(
                "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finalized prepublication release absent".into(),
            );
        }
        worker_operation
            .seal_publication()
            .map_err(|e| e.to_string())?;
        committed.fetch_add(1, Ordering::SeqCst);
        worker_operation.mark_committed()
    })?;
    bind(&mut fixture, key).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    if !until(Duration::from_secs(5), || ready.load(Ordering::SeqCst)).await {
        return Err(
            "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual finalized vendor boundary absent".into(),
        );
    }
    let (observed_group, registered_watchdog) = login_custody::global()
        .registered_observation_for_test(&key)
        .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: outer finalized vendor observation absent")?;
    let reaped_before_cancel = observed_watchdog
        .reaped_status()
        .is_some_and(|s| s.success())
        && registered_watchdog
            .reaped_status()
            .is_some_and(|s| s.success());
    let joined_before_cancel = observed_group.readers_joined();
    let exact_original = fixture.pid == Some(observed_group.id());
    let clean_before_cancel =
        !observed_watchdog.custody_unresolved() && !registered_watchdog.custody_unresolved();
    let unwritten_before_cancel = writes.load(Ordering::SeqCst) == 0;
    if !(reaped_before_cancel
        && joined_before_cancel
        && exact_original
        && clean_before_cancel
        && unwritten_before_cancel)
    {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finalized vendor evidence incomplete".into());
    }
    record_case_diagnostic(serde_json::json!({
        "phase":"cancel_after_reap_before_publication",
        "marker":REACHED,"original_pid":fixture.pid,"group_pid":observed_group.id(),
        "child_reaped":reaped_before_cancel,"reader_finalized":joined_before_cancel,
        "custody_unresolved":false,"publication":0
    }))?;
    eprintln!(
        "{REACHED}; actual_original_child_reaped=true; owner_readers_finalized=true; publication=0"
    );
    let mut cancel = Box::pin(login_custody::global().cancel_child_with_confirmation(
        key,
        &operation_id,
        true,
        || async { Ok(true) },
    ));
    let mut early = None;
    tokio::select! {
        outcome = &mut cancel => { early = Some(outcome); },
        _ = until(Duration::from_secs(2), || operation.cancellation_received()) => {},
    }
    let cancellation_latched = operation.cancellation_received();
    let drain = login_custody::global().close();
    let finalization_pending = pending(&drain).await.is_ok();
    let lock_retained = lock_held(fixture.root(), 9);
    // Even an immediate OLD unresolved result must not return before cleanup:
    // release the real owner, await refusal, drain and only then score it.
    release.store(true, Ordering::SeqCst);
    drop(operation);
    let outcome = result(&mut observer).await?;
    let cancellation = match early {
        Some(outcome) => outcome,
        None => tokio::time::timeout(Duration::from_secs(5), &mut cancel)
            .await
            .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finalized cancel completion absent")?,
    };
    let status = drain_complete(&drain, &mut fixture).await?;
    let registration_removed = login_custody::global()
        .registered_observation_for_test(&key)
        .is_none();
    let unresolved_after = observed_watchdog.custody_unresolved();
    let count = writes.load(Ordering::SeqCst);
    drain.reopen()?;
    let clean_cancel = matches!(&cancellation, Ok(true));
    let clean_refusal =
        matches!(&outcome, Err(error) if error.starts_with("login_cancelled_refused:"));
    record_case_diagnostic(serde_json::json!({
        "phase":"cancel_after_reap_before_publication_drained",
        "marker":VERDICT,"drained":true,"child_success":status.success(),
        "reader_finalized":observed_group.readers_joined(),"registration_removed":registration_removed,
        "cancellation":format!("{cancellation:?}"),"owner_result":format!("{outcome:?}"),
        "custody_unresolved":unresolved_after,"publication":count
    }))?;
    if !cancellation_latched
        || !finalization_pending
        || !lock_retained
        || !status.success()
        || !registration_removed
        || unresolved_after
        || !clean_cancel
        || !clean_refusal
        || count != 0
    {
        // Bare or qualified unresolved results remain semantic RED, never clean
        // cancellation. The independent unresolved-retention row is unchanged.
        return Err(format!("{VERDICT}; cancel={cancellation:?}; owner={outcome:?}; publication={count}; drained=true; unresolved={unresolved_after}"));
    }
    eprintln!("{VERDICT}; clean_cancel=true; refused=true; late_success_published=false; custody_drained=true");
    Ok(())
}
#[test]
#[cfg(unix)]
fn cancel_after_reap_before_publication_refuses_without_unresolved_custody() {
    case_process("case-pub-finalized-before");
}

async fn publication_case(after_seal: bool) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture.command("hold").map_err(|e| e.to_string())?;
    let key = ChildKey::new(LoginProvider::Claude, account(9));
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        Duration::from_secs(60),
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let operation = login_custody::global().reserve_child(key, watchdog.clone())?;
    let worker_operation = Arc::clone(&operation);
    let operation_id = login_custody::global()
        .pending_logins()?
        .into_iter()
        .find(|row| row.account == 9)
        .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: operation receipt absent")?
        .operation_id;
    let ready = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let seen_ready = Arc::clone(&ready);
    let finish = Arc::clone(&release);
    let committed = Arc::clone(&writes);
    let lock = private_lock(fixture.root(), 9)?;
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        // Mirror the real login's outer ownership through publication/finalization.
        let _outer_lock = lock;
        let _outer_ticket = ticket;
        let status = super::commands::claude_login_subprocess::desktop_vendor_status_impl(
            command,
            (Arc::clone(&_outer_ticket), Arc::clone(&_outer_lock)),
            watchdog,
            Arc::clone(&worker_operation),
            || Ok(()),
        )
        .await?;
        if !status.success() {
            return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: synthetic vendor failed".into());
        }
        if after_seal {
            worker_operation
                .seal_publication()
                .map_err(|e| e.to_string())?;
        }
        seen_ready.store(true, Ordering::SeqCst);
        if !until(Duration::from_secs(8), || finish.load(Ordering::SeqCst)).await {
            return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finalization release absent".into());
        }
        if !after_seal {
            worker_operation
                .seal_publication()
                .map_err(|e| e.to_string())?;
        }
        committed.fetch_add(1, Ordering::SeqCst);
        worker_operation.mark_committed()
    })?;
    bind(&mut fixture, key).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    if !until(Duration::from_secs(5), || ready.load(Ordering::SeqCst)).await {
        return Err(
            "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual vendor reap/precommit boundary absent".into(),
        );
    }
    let mut cancel = Box::pin(login_custody::global().cancel_child_with_confirmation(
        key,
        &operation_id,
        true,
        || async { Ok(true) },
    ));
    let mut early_cancellation = None;
    tokio::select! { outcome=&mut cancel=>{early_cancellation=Some(outcome);}, received=until(Duration::from_secs(2),||operation.cancellation_received())=>{if !received {return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: cancellation receipt absent".into());}} }
    let rejected_after_seal = early_cancellation.as_ref().is_some_and(|outcome| {
        outcome
            .as_ref()
            .is_err_and(|error| error == "login_already_completed")
    });
    if !operation.cancellation_received() && !rejected_after_seal {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: cancellation latch was not reached".into());
    }
    let drain = login_custody::global().close();
    pending(&drain).await?;
    if !lock_held(fixture.root(), 9) {
        return Err(
            "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual account lock released before finalization"
                .into(),
        );
    }
    release.store(true, Ordering::SeqCst);
    drop(operation);
    let outcome = result(&mut observer).await?;
    let cancellation = if let Some(outcome) = early_cancellation {
        outcome
    } else {
        tokio::time::timeout(Duration::from_secs(5), &mut cancel)
            .await
            .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: cancel completion absent")?
    };
    let cancelled = match cancellation {
        Ok(value) => value,
        Err(error) if error.starts_with("login_committed_cancelled:") => true,
        Err(error) if error == "login_already_completed" => false,
        Err(error) => return Err(error),
    };
    let status = drain_complete(&drain, &mut fixture).await?;
    drain.reopen()?;
    let marker = if after_seal { PUB_AFTER } else { PUB_BEFORE };
    if !cancelled || !status.success() {
        return Err(marker.into());
    }
    if after_seal {
        if writes.load(Ordering::SeqCst) != 1
            || !outcome.is_err_and(|e| e.starts_with("login_committed_cancelled:"))
        {
            return Err(marker.into());
        }
    } else if writes.load(Ordering::SeqCst) != 0 || outcome.is_ok() {
        return Err(marker.into());
    }
    Ok(())
}
#[test]
fn invalid_native_utf8_refuses_and_drains_actual_pipe() {
    case_process("case-native-invalid");
}
#[test]
fn cancellation_before_publication_refuses_actual_late_success() {
    case_process("case-pub-before");
}
#[test]
fn cancellation_after_publication_finishes_owned_finalization() {
    case_process("case-pub-after");
}

#[cfg(unix)]
mod desktop_descendant_identity {
    #[cfg(target_os = "linux")]
    pub(super) fn birth(pid: u32) -> std::io::Result<Option<String>> {
        let text = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let tail = text
            .rsplit_once(')')
            .ok_or_else(|| std::io::Error::other("invalid process stat"))?
            .1;
        let ticks = tail
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| std::io::Error::other("missing process birth"))?;
        Ok(Some(ticks.to_string()))
    }
    #[cfg(target_os = "macos")]
    pub(super) fn birth(pid: u32) -> std::io::Result<Option<String>> {
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            i32::try_from(pid).unwrap(),
        ];
        let mut bytes = [0_u8; 2048];
        let mut len = bytes.len();
        // SAFETY: initialized MIB and writable buffer; timeval is the documented
        // first kinfo_proc member. Read unaligned only after the length check.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                bytes.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        if len == 0 {
            return Ok(None);
        }
        if len < std::mem::size_of::<libc::timeval>() {
            return Err(std::io::Error::other("short process birth"));
        }
        // SAFETY: at least a timeval was written, whose fields are plain integers.
        let value = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::timeval>()) };
        if value.tv_sec == 0 {
            return Err(std::io::Error::other("zero process birth"));
        }
        Ok(Some(format!("{}:{}", value.tv_sec, value.tv_usec)))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn birth(_: u32) -> std::io::Result<Option<String>> {
        Err(std::io::Error::other("kernel process identity unsupported"))
    }
    pub(super) fn same_identity_gone(record: &serde_json::Value) -> bool {
        let pid = u32::try_from(record["pid"].as_u64().unwrap()).unwrap();
        match birth(pid) {
            Ok(None) => true,
            Ok(Some(current)) => current != record["birth"].as_str().unwrap(),
            Err(_) => false,
        }
    }
}

#[cfg(unix)]
fn desktop_group_actor(root: &Path, parent: bool) -> ! {
    // SAFETY: fixture-local disposition; no real sessions or host process IDs.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    let mut descendant = None;
    if parent {
        let mut command = Command::new(std::env::current_exe().expect("inert entry"));
        command
            .args([
                DESKTOP_ENTRY,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DESKTOP_ROLE, "group-child")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        descendant = Some(command.spawn().expect("actual private descendant"));
    } else {
        let record = serde_json::json!({"pid":std::process::id(),"birth":desktop_descendant_identity::birth(std::process::id()).expect("kernel birth").expect("live birth"),"ppid":unsafe{libc::getppid()},"pgid":unsafe{libc::getpgrp()}});
        publish_fixture_receipt(
            &root.join("descendant-ready"),
            serde_json::to_vec(&record).unwrap(),
        )
        .expect("private identity");
    }
    loop {
        if root.join("cleanup").exists() || root.join("release").exists() {
            if let Some(mut descendant) = descendant {
                let _ = descendant.wait();
            }
            std::process::exit(0);
        }
        std::thread::yield_now();
    }
}
#[cfg(unix)]
fn group_case_diagnostic(
    phase: &'static str,
    watchdog: &crate::login_child_custody::LoginWatchdog,
    group: Option<&crate::login_child_custody::group::GroupControl>,
) -> Result<(), String> {
    record_case_diagnostic(serde_json::json!({
        "phase":phase,
        "owner_reaped":watchdog.reaped_status().is_some(),
        "child_reaped":watchdog.reaped_status().is_some(),
        "reader_finalized":group.map(|group|group.readers_joined()),
        "custody_unresolved":watchdog.custody_unresolved(),
        "refusal":watchdog.refusal().map(|receipt| format!("{:?}",receipt.reason))
    }))
}
#[cfg(unix)]
fn group_driver_diagnostic(
    phase: &'static str,
    drained: Option<bool>,
    case_failed: bool,
) -> Result<(), String> {
    let observation = login_custody::global()
        .registered_observation_for_test(&ChildKey::new(LoginProvider::Codex, account(7)));
    record_case_diagnostic(serde_json::json!({
        "phase":phase,"driver_drained":drained,"case_failed":case_failed,"registration_present":observation.is_some(),
        "child_reaped":observation.as_ref().map(|(_,watchdog)|watchdog.reaped_status().is_some()),
        "reader_finalized":observation.as_ref().map(|(group,_)|group.readers_joined()),
        "custody_unresolved":observation.as_ref().map(|(_,watchdog)|watchdog.custody_unresolved())
    }))
}
#[cfg(unix)]
async fn group_end_case() -> Result<(), String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let app = tauri::test::mock_app();
    let handle = app.handle().clone();
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture.command("group-parent").map_err(|e| e.to_string())?;
    let key = ChildKey::new(LoginProvider::Codex, account(7));
    let lock = private_lock(fixture.root(), 7)?;
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        Duration::from_secs(60),
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let post = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&post);
    let diagnostic_watchdog = watchdog.clone();
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        let worker = tokio::task::spawn_blocking(move || {
            let slot = Arc::new(Mutex::new(None));
            let mut code = |_| {};
            let status = super::commands::codex_vendor_with_command(
                command,
                &mut code,
                &handle,
                &slot,
                watchdog,
                (ticket, lock),
                key,
            )
            .map_err(|e| e.to_string())?;
            if status.success() {
                observed.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        worker
            .await
            .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: group owner failed".to_string())?
    })?;
    group_case_diagnostic("group_before_bind", &diagnostic_watchdog, None)?;
    bind(&mut fixture, key).await?;
    let diagnostic_group = login_custody::global()
        .registered_observation_for_test(&key)
        .map(|(group, _)| group);
    group_case_diagnostic(
        "group_bound",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    group_case_diagnostic(
        "group_waitready_before",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    if !until(Duration::from_secs(5), || {
        fixture.root().join("descendant-ready").exists()
    })
    .await
    {
        group_case_diagnostic(
            "group_waitready_timeout",
            &diagnostic_watchdog,
            diagnostic_group.as_ref(),
        )?;
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: descendant not started".into());
    }
    group_case_diagnostic(
        "group_waitready_complete",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    group_case_diagnostic(
        "group_readJSON_before",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let record_bytes = match std::fs::read(fixture.root().join("descendant-ready")) {
        Ok(bytes) => bytes,
        Err(error) => {
            record_case_diagnostic(serde_json::json!({"phase":"group_readJSON_failed",
                "kind":format!("{:?}",error.kind()),"errno":error.raw_os_error()}))?;
            return Err("DESKTOP_FIXTURE_RECEIPT_IO: receipt=descendant-ready".into());
        }
    };
    if record_bytes.is_empty() {
        group_case_diagnostic(
            "group_readJSON_empty",
            &diagnostic_watchdog,
            diagnostic_group.as_ref(),
        )?;
        return Err("DESKTOP_FIXTURE_RECEIPT_EMPTY: receipt=descendant-ready".into());
    }
    group_case_diagnostic(
        "group_parseJSON_before",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let record: serde_json::Value = match serde_json::from_slice(&record_bytes) {
        Ok(record) => record,
        Err(error) => {
            record_case_diagnostic(serde_json::json!({"phase":"group_parseJSON_failed",
                "kind":format!("{:?}",error.classify()),"errno":null}))?;
            return Err("DESKTOP_FIXTURE_RECEIPT_JSON: receipt=descendant-ready".into());
        }
    };
    group_case_diagnostic(
        "group_PPID_validation_before",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    if record["ppid"].as_u64() != fixture.pid.map(u64::from) {
        group_case_diagnostic(
            "group_PPID_validation_failed",
            &diagnostic_watchdog,
            diagnostic_group.as_ref(),
        )?;
        return Err(
            "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: true vendor descendant relation absent".into(),
        );
    }
    let owned_vendor_group = record["pgid"].as_u64() == fixture.pid.map(u64::from);
    group_case_diagnostic(
        "descendant_ready",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let operation_id = login_custody::global()
        .pending_logins()?
        .into_iter()
        .find(|row| row.account == 7)
        .ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: group registration absent")?
        .operation_id;
    let mut end = Box::pin(login_custody::global().cancel_child_with_confirmation(
        key,
        &operation_id,
        true,
        || async { Ok(true) },
    ));
    group_case_diagnostic(
        "before_cancel",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let completed = tokio::time::timeout(Duration::from_secs(5), &mut end).await;
    let ended = matches!(&completed, Ok(Ok(true)));
    record_case_diagnostic(serde_json::json!({"phase":"group_after_confirmed_end",
        "completed":completed.is_ok(),"ended":ended,
        "result_error":matches!(&completed,Ok(Err(_))),
        "owner_reaped":diagnostic_watchdog.reaped_status().is_some(),
        "custody_unresolved":diagnostic_watchdog.custody_unresolved()}))?;
    let gone_before_cleanup = until(Duration::from_secs(2), || {
        desktop_descendant_identity::same_identity_gone(&record)
    })
    .await;
    record_case_diagnostic(
        serde_json::json!({"phase":"group_before_cooperative_cleanup",
        "gone_before_cleanup":gone_before_cleanup,"owned_vendor_group":owned_vendor_group}),
    )?;
    // Cooperative private fixture cleanup is unconditional, including a direct-child
    // mutant. It is not counted as successful group cancellation.
    publish_fixture_receipt(&fixture.root().join("cleanup"), b"owned fixture release")
        .map_err(|e| e.to_string())?;
    group_case_diagnostic(
        "group_after_cooperative_cleanup",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    if completed.is_err() {
        let _ = tokio::time::timeout(Duration::from_secs(8), &mut end)
            .await
            .map_err(|_| "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: group cleanup unknown")??;
    }
    group_case_diagnostic(
        "group_before_owner_result",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let outcome = result(&mut observer).await?;
    group_case_diagnostic(
        "group_after_owner_result",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let drain = login_custody::global().close();
    group_case_diagnostic(
        "group_before_drain",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    let status = drain_complete(&drain, &mut fixture).await?;
    group_case_diagnostic(
        "group_after_drain",
        &diagnostic_watchdog,
        diagnostic_group.as_ref(),
    )?;
    drain.reopen()?;
    if !until(Duration::from_secs(5), || {
        desktop_descendant_identity::same_identity_gone(&record)
    })
    .await
    {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: descendant kernel identity retained".into());
    }
    eprintln!("descendant reap: not observed (no subreaper on darwin)");
    if !owned_vendor_group
        || !ended
        || !gone_before_cleanup
        || outcome.is_ok()
        || status.success()
        || post.load(Ordering::SeqCst) != 0
    {
        return Err(GROUP_END.into());
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn confirmed_end_stops_actual_vendor_and_stdout_holding_descendant() {
    case_process("case-group-end");
}

const RESERVED_BEFORE_SPAWN: &str =
    "desktop operation must be reserved while actual Command spawn is still in pre-exec";
#[cfg(unix)]
async fn reservation_case() -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    struct Release(std::os::unix::net::UnixStream);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.write_all(b"x");
        }
    }
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let mut command = fixture.command("hold").map_err(|e| e.to_string())?;
    let (parent, child) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    parent.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut release = Release(parent);
    // SAFETY: the post-fork callback uses only async-signal-safe read/write on
    // its inherited private socket; no allocator, lock or provider operation.
    unsafe {
        command.pre_exec(move || {
            let fd = child.as_raw_fd();
            let byte = b"r";
            if libc::write(fd, byte.as_ptr().cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            let mut go = 0u8;
            if libc::read(fd, (&mut go as *mut u8).cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let lock = private_lock(fixture.root(), 12)?;
    let key = ChildKey::new(LoginProvider::Claude, account(12));
    let mut observer=login_custody::global().spawn_with_ticket(move|ticket|async move{
        let status=super::commands::claude_login_subprocess::desktop_vendor_status_registered_with_timeout(command,(ticket,lock),Duration::from_secs(60),key).await?;
        if status.success(){Ok(())}else{Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: reservation fixture failed".into())}
    })?;
    let mut byte = [0u8; 1];
    if !until(Duration::from_secs(5), || {
        matches!(release.0.read(&mut byte), Ok(1))
    })
    .await
    {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual pre-exec not reached".into());
    }
    let visible = login_custody::global()
        .pending_logins()?
        .iter()
        .any(|row| row.provider == "claude" && row.account == 12);
    let unattached = login_custody::global()
        .registered_child_for_test(&key)
        .is_none();
    release.0.write_all(b"x").map_err(|e| e.to_string())?;
    bind(&mut fixture, key).await?;
    let drain = login_custody::global().close();
    pending(&drain).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    result(&mut observer).await??;
    let status = drain_complete(&drain, &mut fixture).await?;
    drain.reopen()?;
    if !status.success() {
        return Err(
            "DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual reservation fixture reap failed".into(),
        );
    }
    if !visible || !unattached {
        return Err(RESERVED_BEFORE_SPAWN.into());
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn operation_is_reserved_before_actual_command_spawn_returns() {
    case_process("case-reservation");
}

#[cfg(all(unix, feature = "test-utils"))]
fn handler_vendor_write(role: &str, root: &Path) {
    let grant =
        PathBuf::from(std::env::var_os("CSQ_PRIVATE_GRANT").expect("injected actual vendor grant"));
    if role.starts_with("handler-codex") {
        publish_fixture_receipt(
            &root.join("actual-codex-home"),
            serde_json::to_vec(
                &std::env::var(csq_core::providers::codex::surface::HOME_ENV_VAR).ok(),
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(grant.join("auth.json"),serde_json::json!({"auth_mode":"chatgpt","OPENAI_API_KEY":null,
            "tokens":{"account_id":"desktop-handler-fixture","access_token":"eyJhbGciOiJIUzI1NiJ9.test-at.sig",
            "refresh_token":"fixture-handler-refresh","id_token":"eyJhbGciOiJIUzI1NiJ9.test-id.sig"},"last_refresh":"2026-04-22T00:00:00Z"}).to_string()).unwrap();
    } else {
        std::fs::write(grant.join(".credentials.json"),serde_json::json!({"claudeAiOauth":{
            "accessToken":"fixture-handler-access","refreshToken":"fixture-handler-refresh","expiresAt":4102444800000_u64,
            "scopes":["user:profile","user:inference"]}}).to_string()).unwrap();
        std::fs::write(grant.join(".claude.json"),serde_json::json!({"oauthAccount":{
            "emailAddress":"desktop-handler@test.invalid","accountUuid":"11111111-1111-4111-8111-111111111111",
            "organizationUuid":"22222222-2222-4222-8222-222222222222"}}).to_string()).unwrap();
        csq_core::platform::fs::secure_file(&grant.join(".claude.json")).unwrap();
        csq_core::platform::fs::secure_file(&grant.join(".credentials.json")).unwrap();
    }
    publish_fixture_receipt(
        &root.join("grant-written"),
        grant.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    if role == "handler-codex-und" {
        send_stdout_to_driver(root).expect("transfer actual captured stdout writer");
    }
}
#[cfg(all(unix, feature = "test-utils"))]
async fn handler_case(role: &str) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let claude = role.contains("claude");
    let late = role.ends_with("late");
    let end = role.ends_with("end");
    let after = role.ends_with("post");
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let base = fixture.root().join("base");
    let number = account(12);
    let prior_known = b"fixture-prior-known-slot-auth-unchanged";
    if !claude {
        csq_core::providers::codex::tos::acknowledge(&base).map_err(|e| e.to_string())?;
        std::fs::create_dir(base.join("config-12")).map_err(|e| e.to_string())?;
        std::fs::write(base.join("config-12/auth.json"), prior_known).map_err(|e| e.to_string())?;
        std::fs::write(
            base.join("config-12/config.toml"),
            b"model = \"fixture-model\"\n",
        )
        .map_err(|e| e.to_string())?;
        csq_core::platform::fs::secure_file(&base.join("config-12/auth.json"))
            .map_err(|e| e.to_string())?;
        csq_core::platform::fs::secure_file(&base.join("config-12/config.toml"))
            .map_err(|e| e.to_string())?;
    }
    let key = ChildKey::new(
        if claude {
            LoginProvider::Claude
        } else {
            LoginProvider::Codex
        },
        number,
    );
    let mut command = fixture
        .command(if claude {
            "handler-claude"
        } else {
            "handler-codex"
        })
        .map_err(|e| e.to_string())?;
    if claude {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let app = tauri::test::mock_app();
    let ready = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    struct Release(Arc<AtomicBool>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let release_guard = Release(Arc::clone(&release));
    let entered = Arc::clone(&ready);
    let released = Arc::clone(&release);
    let seal: Arc<dyn Fn(bool) + Send + Sync> = Arc::new(move |sealed| {
        if sealed == after {
            entered.store(true, Ordering::SeqCst);
            while !released.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
        }
    });
    let hooks = if late || end { None } else { Some(seal) };
    let timeout = if late {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(60)
    };
    let mut observer: Observer = if claude {
        let profile: csq_core::daemon::usage_poller::HttpGetFn = Arc::new(|url, token, _| {
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(token, "fixture-handler-access");
            Ok((200,serde_json::json!({"account":{"uuid":"11111111-1111-4111-8111-111111111111","email":"desktop-handler@test.invalid"},
                "organization":{"uuid":"22222222-2222-4222-8222-222222222222"}}).to_string().into_bytes()))
        });
        tokio::spawn(async move {
            super::commands::claude_login_subprocess::start_claude_login_owned(
                base,
                number,
                super::commands::claude_login_subprocess::ClaudeLoginIo::fixture(
                    command, timeout, profile, hooks,
                ),
            )
            .await
            .map(|_| ())
        })
    } else {
        let handle = app.handle().clone();
        let lock = match AccountLoginLock::acquire(&base, number).map_err(|e| e.to_string())? {
            AcquireOutcome::Acquired(lock) => lock,
            _ => return Err("fixture lock unavailable".into()),
        };
        tokio::spawn(async move {
            super::commands::complete_codex_login_owned(
                handle,
                Arc::new(Mutex::new(None)),
                base,
                number,
                lock,
                false,
                super::commands::CodexLoginIo::fixture(command, timeout, hooks),
                Arc::new(
                    super::login_custody::global()
                        .admit()
                        .expect("test login admission"),
                ),
            )
            .await
            .map(|_| ())
        })
    };
    bind(&mut fixture, key).await?;
    if !until(Duration::from_secs(5), || {
        fixture.root().join("grant-written").is_file()
    })
    .await
    {
        return Err("fixture actual token write absent".into());
    }
    // Defer even a malformed receipt verdict through the same actual cleanup.
    let grant_receipt = read_fixture_path_receipt(fixture.root(), "grant-written");
    let grant = grant_receipt.as_ref().ok();
    // Defer semantic assertions until the actual owner/readers are accounted,
    // including on the old known-path adapter baseline.
    let grant_root_read = std::fs::canonicalize(fixture.root().join("base/.login-grants"));
    let expected_grant_root = grant_root_read.as_ref().ok().cloned();
    let isolated_route = grant.is_some_and(|grant| {
        grant.parent() == expected_grant_root.as_deref()
            && grant
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("grant-"))
    });
    let prior_read =
        (!claude).then(|| std::fs::read(fixture.root().join("base/config-12/auth.json")));
    let prior_unchanged_after_write = claude
        || prior_read
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(Vec::as_slice)
            == Some(prior_known.as_slice());
    let home_match_read =
        (!claude).then(|| std::fs::read(fixture.root().join("actual-codex-home")));
    let home_match_parse = home_match_read
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|bytes| serde_json::from_slice::<Option<String>>(bytes));
    let actual_home_matches = claude
        || home_match_parse
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref)
            .is_some_and(|home| grant.is_some_and(|grant| Path::new(home) == grant));
    let home_root_read = (!claude).then(|| std::fs::read(fixture.root().join("actual-codex-home")));
    let home_root_parse = home_root_read
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|bytes| serde_json::from_slice::<Option<String>>(bytes));
    let actual_home_within_grant_root = claude
        || home_root_parse
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref)
            .is_some_and(|home| Path::new(home).parent() == expected_grant_root.as_deref());
    let lease_read = grant.map(|grant| std::fs::read(grant.join("lease.json")));
    let lease_parse = lease_read
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|bytes| serde_json::from_slice::<serde_json::Value>(bytes));
    let spawning_fence = lease_parse
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .is_some_and(|record| record["state"] == "Spawning");
    record_case_diagnostic(serde_json::json!({
        "phase":"handler_grant_snapshot","claude":claude,"late":late,"end":end,"after":after,
        "isolated_route":isolated_route,"spawning_fence":spawning_fence,
        "actual_home_matches":actual_home_matches,"actual_home_within_grant_root":actual_home_within_grant_root,
        "prior_unchanged_after_write":prior_unchanged_after_write,
        "grant_root_io":diagnostic_io(Some(&grant_root_read)),"prior_io":diagnostic_io(prior_read.as_ref()),
        "home_match_io":diagnostic_io(home_match_read.as_ref()),"home_match_parse":diagnostic_json(home_match_parse.as_ref()),
        "home_root_io":diagnostic_io(home_root_read.as_ref()),"home_root_parse":diagnostic_json(home_root_parse.as_ref()),
        "lease_io":diagnostic_io(lease_read.as_ref()),"lease_parse":diagnostic_json(lease_parse.as_ref())
    }))?;
    let operation_id = login_custody::global()
        .pending_logins()?
        .into_iter()
        .find(|row| row.account == 12)
        .ok_or("fixture actual operation absent")?
        .operation_id;
    let outcome;
    if late {
        outcome = result(&mut observer).await?;
        if outcome.is_ok() {
            return Err("HANDLER_LATE_ZERO_PERSISTENCE".into());
        }
        fixture.release(0).map_err(|e| e.to_string())?;
    } else {
        if !end {
            fixture.release(0).map_err(|e| e.to_string())?;
            if !until(Duration::from_secs(5), || ready.load(Ordering::SeqCst)).await {
                return Err("fixture actual canonical seal boundary absent".into());
            }
        }
        let id = operation_id.clone();
        let mut cancel = tokio::spawn(async move {
            login_custody::global()
                .cancel_child_with_confirmation(key, &id, true, || async { Ok(true) })
                .await
        });
        if !until(Duration::from_secs(3), || {
            login_custody::global().publication_cancelled_for_test(&key)
        })
        .await
        {
            return Err("fixture cancellation latch absent".into());
        }
        release.store(true, Ordering::SeqCst);
        outcome = result(&mut observer).await?;
        let cancelled = tokio::time::timeout(Duration::from_secs(8), &mut cancel)
            .await
            .map_err(|_| "fixture confirmed End completion absent")?
            .map_err(|e| e.to_string())?;
        if end && cancelled != Ok(true) {
            return Err("HANDLER_CONFIRMED_END_PERSISTENCE".into());
        }
    }
    drop(release_guard);
    let drain = login_custody::global().close();
    drain_complete(&drain, &mut fixture).await?;
    drain.reopen()?;
    let base = fixture.root().join("base");
    let uuid = csq_core::accounts::profiles::resolve_slot_to_uuid(&base, 12);
    let grant = grant_receipt?; // Named empty/IO error only after actual owner/readers drain.
    if !isolated_route
        || !spawning_fence
        || !actual_home_matches
        || !actual_home_within_grant_root
        || !prior_unchanged_after_write
    {
        return Err("HANDLER_PRIVATE_GRANT_CUSTODY".into());
    }
    if late || end || !after {
        let marker = if late {
            "HANDLER_LATE_ZERO_PERSISTENCE"
        } else if end {
            "HANDLER_CONFIRMED_END_PERSISTENCE"
        } else {
            "HANDLER_PRESEAL_CANONICAL"
        };
        let prior_unchanged = claude
            || std::fs::read(base.join("config-12/auth.json"))
                .ok()
                .as_deref()
                == Some(prior_known.as_slice());
        if !prior_unchanged
            || outcome.is_ok()
            || uuid.is_some()
            || base.join("config-12/.csq-account").exists()
            || grant
                .join(if claude {
                    ".credentials.json"
                } else {
                    "auth.json"
                })
                .exists()
        {
            return Err(marker.into());
        }
    } else {
        let Some(uuid) = uuid else {
            return Err("HANDLER_POSTSEAL_CANONICAL".into());
        };
        let canonical = base
            .join("identities")
            .join(uuid.to_string())
            .join(if claude {
                "credentials.json"
            } else {
                "credentials-codex.json"
            });
        if (!claude && base.join("config-12/auth.json").exists())
            || !outcome.is_err_and(|e| e.starts_with("login_committed_cancelled:"))
            || !canonical.is_file()
            || !base.join("config-12/.csq-account").is_file()
        {
            return Err("HANDLER_POSTSEAL_CANONICAL".into());
        }
    }
    Ok(())
}
#[cfg(all(unix, feature = "test-utils"))]
macro_rules! handler_row {
    ($name:ident,$role:literal) => {
        #[test]
        fn $name() {
            case_process($role);
        }
    };
}
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    claude_full_handler_late_zero_scrubs_vendor_grant,
    "case-handler-claude-late"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    codex_full_handler_late_zero_scrubs_vendor_grant,
    "case-handler-codex-late"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    claude_full_handler_confirmed_end_scrubs_written_grant,
    "case-handler-claude-end"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    codex_full_handler_confirmed_end_scrubs_written_grant,
    "case-handler-codex-end"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    claude_full_handler_preseal_cancel_has_no_canonical_write,
    "case-handler-claude-pre"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    codex_full_handler_preseal_cancel_has_no_canonical_write,
    "case-handler-codex-pre"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    claude_full_handler_postseal_cancel_finishes_canonical_write,
    "case-handler-claude-post"
);
#[cfg(all(unix, feature = "test-utils"))]
handler_row!(
    codex_full_handler_postseal_cancel_finishes_canonical_write,
    "case-handler-codex-post"
);

#[tokio::test]
async fn malformed_watchdog_metadata_refuses_without_observer_panic() {
    let gate = login_custody::CredentialWrites::default();
    let permit = gate.admit().unwrap();
    let (release, held) = std::sync::mpsc::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _ = held.recv();
        Ok::<_, String>(())
    });
    let observed = tokio::spawn(super::commands::observe_desktop_login(
        worker,
        crate::login_child_custody::LoginWatchdog::malformed_for_test(),
    ))
    .await;
    let drain = gate.close();
    let held_before_release = tokio::time::timeout(Duration::from_millis(20), drain.wait())
        .await
        .is_err();
    let _ = release.send(());
    tokio::time::timeout(Duration::from_secs(5), drain.wait())
        .await
        .expect("fixture actual owner release")
        .unwrap();
    assert!(
        held_before_release
            && matches!(observed,Ok(Err(error)) if error=="login_deadline_unavailable_refused"),
        "malformed watchdog metadata must refuse without panic and retain actual writer custody"
    );
}

#[cfg(all(unix, feature = "test-utils"))]
fn scm_error(step: &'static str, error: std::io::Error) -> std::io::Error {
    let errno = error
        .raw_os_error()
        .map_or_else(|| "none".to_owned(), |value| value.to_string());
    eprintln!("DESKTOP_SCM_STEP: role=receiver; step={step}; state=error; errno={errno}");
    error
}
#[cfg(all(unix, feature = "test-utils"))]
fn scm_sender_result<T>(
    root: &Path,
    step: &'static str,
    result: std::io::Result<T>,
    returned: Option<isize>,
) -> std::io::Result<T> {
    let state = if result.is_ok() { "ok" } else { "error" };
    let errno = result
        .as_ref()
        .err()
        .and_then(std::io::Error::raw_os_error)
        .map_or_else(|| "none".to_owned(), |value| value.to_string());
    let returned = returned.map_or_else(|| "none".to_owned(), |value| value.to_string());
    // This receipt contains only fixed tags and native integers, never argv,
    // paths, environment, auth bytes, or the vendor's diagnostic text.
    publish_fixture_receipt(
        &root.join("scm-send-status"),
        format!("{step} {state} {errno} {returned}\n"),
    )?;
    result
}
#[cfg(all(unix, feature = "test-utils"))]
fn scm_print_sender_result(root: &Path) -> Option<String> {
    let receipt = std::fs::File::open(root.join("scm-send-status")).and_then(|file| {
        let mut text = String::new();
        file.take(128).read_to_string(&mut text)?;
        Ok(text)
    });
    match receipt {
        Ok(text) => {
            let fields: Vec<_> = text.split_whitespace().collect();
            if let [step, state, errno, returned] = fields.as_slice() {
                if matches!(*step, "connect" | "await-receiver-ready" | "sendmsg")
                    && matches!(*state, "ok" | "error")
                    && (*errno == "none" || errno.parse::<i32>().is_ok())
                    && (*returned == "none" || returned.parse::<isize>().is_ok())
                    && (returned.parse::<isize>().ok().is_none_or(|count| count < 0)
                        || *errno == "none")
                {
                    eprintln!("DESKTOP_SCM_STEP: role=sender; step={step}; state={state}; errno={errno}; returned={returned}");
                    return if *step == "await-receiver-ready" && *state == "error" {
                        Some(desktop_setup_verdict(
                            "await-receiver-ready",
                            errno.parse().ok(),
                        ))
                    } else {
                        None
                    };
                }
            }
            eprintln!("DESKTOP_SCM_STEP: role=sender; step=receipt; state=invalid; errno=none");
        }
        Err(error) => {
            let errno = error
                .raw_os_error()
                .map_or_else(|| "none".to_owned(), |value| value.to_string());
            eprintln!(
                "DESKTOP_SCM_STEP: role=sender; step=receipt; state=unavailable; errno={errno}"
            );
        }
    }
    None
}
#[cfg(all(unix, feature = "test-utils"))]
fn send_stdout_to_driver(root: &Path) -> std::io::Result<()> {
    use std::os::unix::net::UnixStream;
    let mut socket = scm_sender_result(
        root,
        "connect",
        UnixStream::connect(root.join("captured-writer.sock")),
        None,
    )?;
    scm_sender_result(
        root,
        "await-receiver-ready",
        await_receiver_ready(&mut socket),
        None,
    )?;
    send_fixture_descriptor_record(&socket, libc::STDOUT_FILENO, Some(root))
}
#[cfg(all(unix, feature = "test-utils"))]
fn await_receiver_ready(socket: &mut std::os::unix::net::UnixStream) -> std::io::Result<()> {
    // Same connected peer stays open while the receiver configures its stream.
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut ready = [0_u8];
    socket.read_exact(&mut ready)?;
    if ready != *b"R" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private SCM receiver readiness byte invalid",
        ));
    }
    Ok(())
}
#[cfg(all(unix, feature = "test-utils"))]
fn send_fixture_descriptor(
    socket: &std::os::unix::net::UnixStream,
    descriptor: i32,
) -> std::io::Result<()> {
    send_fixture_descriptor_record(socket, descriptor, None)
}
#[cfg(all(unix, feature = "test-utils"))]
fn send_fixture_descriptor_record(
    socket: &std::os::unix::net::UnixStream,
    descriptor: i32,
    receipt: Option<&Path>,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut byte = [1_u8];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: initialized message references live aligned control/vector buffers;
    // SCM_RIGHTS duplicates this fixture's stdout, it never signals a process.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(std::io::Error::other("ancillary header unavailable"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), descriptor);
        let sent = libc::sendmsg(socket.as_raw_fd(), &message, 0);
        // Read errno only for a negative native return, before any diagnostic I/O.
        let result = if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else if sent == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "private SCM send wrote no byte",
            ))
        } else if sent != 1 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "private SCM send returned an invalid count",
            ))
        } else {
            Ok(())
        };
        if let Some(root) = receipt {
            scm_sender_result(root, "sendmsg", result, Some(sent))
        } else {
            result
        }
    }
}
#[cfg(all(unix, feature = "test-utils"))]
fn receive_captured_writer(
    socket: std::os::unix::net::UnixStream,
) -> std::io::Result<std::os::fd::OwnedFd> {
    receive_captured_writer_mode(socket, true)
}
#[cfg(all(unix, feature = "test-utils"))]
fn receive_captured_writer_mode(
    socket: std::os::unix::net::UnixStream,
    normalize: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    receive_captured_writer_raw(configure_captured_writer(socket, normalize)?)
}
#[cfg(all(unix, feature = "test-utils"))]
fn configure_captured_writer(
    socket: std::os::unix::net::UnixStream,
    normalize: bool,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    // Darwin's accepted stream can retain O_NONBLOCK from the listener. Keep
    // the existing normalization and bounded timeout; never retry the transfer.
    if normalize {
        socket
            .set_nonblocking(false)
            .map_err(|error| scm_error("normalize", error))?;
    }
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| scm_error("read-timeout", error))?;
    Ok(socket)
}
#[cfg(all(unix, feature = "test-utils"))]
fn receive_captured_writer_raw(
    socket: std::os::unix::net::UnixStream,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut byte = [0_u8];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: buffers are writable/aligned, ancillary sizes/types are checked
    // before the sole received descriptor is converted to one owning OwnedFd.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        let received = libc::recvmsg(socket.as_raw_fd(), &mut message, 0);
        if received < 0 {
            let error = std::io::Error::last_os_error();
            eprintln!(
                "DESKTOP_UND_RECVMSG: errno={:?}; accepted_flags={}",
                error.raw_os_error(),
                libc::fcntl(socket.as_raw_fd(), libc::F_GETFL)
            );
            eprintln!("DESKTOP_SCM_STEP: role=receiver; step=recvmsg; returned={received}; control_len={}; flags={}", message.msg_controllen, message.msg_flags);
            return Err(scm_error("recvmsg", error));
        }
        eprintln!("DESKTOP_SCM_STEP: role=receiver; step=recvmsg; state=ok; errno=none; returned={received}; control_len={}; flags={}", message.msg_controllen, message.msg_flags);
        if received == 0 {
            return Err(scm_error(
                "recvmsg-eof",
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "private SCM peer closed before descriptor transfer",
                ),
            ));
        }
        if received != 1 {
            return Err(scm_error(
                "recvmsg-count",
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "private SCM receive returned an invalid count",
                ),
            ));
        }
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || (*header).cmsg_len as usize
                != libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize
        {
            return Err(scm_error(
                "header",
                std::io::Error::other("fixture writer descriptor missing"),
            ));
        }
        let descriptor = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>());
        if descriptor < 0 {
            return Err(scm_error(
                "descriptor",
                std::io::Error::other("invalid fixture writer descriptor"),
            ));
        }
        let owned = std::os::fd::OwnedFd::from_raw_fd(descriptor);
        if libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return Err(scm_error("cloexec", std::io::Error::last_os_error()));
        }
        Ok(owned)
    }
}
#[cfg(all(unix, feature = "test-utils"))]
fn run_handler_und_driver(root: &Path) -> ! {
    run_handler_und_driver_with_setup(root, false)
}
#[cfg(all(unix, feature = "test-utils"))]
fn run_handler_setup_error_driver(root: &Path) -> ! {
    run_handler_und_driver_with_setup(root, true)
}
#[cfg(all(unix, feature = "test-utils"))]
fn run_handler_und_driver_with_setup(root: &Path, fail_holder_spawn: bool) -> ! {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("isolated UND runtime");
    let result = runtime.block_on(async {
        if fail_holder_spawn {
            handler_und_case_with_setup(true).await
        } else {
            handler_und_case().await
        }
    });
    if let Err(error) = &result {
        if error.starts_with("DESKTOP_FIXTURE_SETUP:") && error.contains("cleanup=unconfirmed") {
            std::fs::write(root.join("case-failure"), error).unwrap();
            // SETUP is already surfaced. Unproven actual custody still owns
            // its runtime; the original case handle remains the outer owner.
            loop {
                std::thread::park_timeout(Duration::from_secs(1));
            }
        }
    }
    if result
        .as_ref()
        .is_err_and(|error| error.starts_with("DESKTOP_FIXTURE_CUSTODY_UNKNOWN:"))
    {
        std::fs::write(root.join("case-unknown"), result.err().unwrap()).unwrap();
        // Missing actual cleanup proof is UNKNOWN; never exit over live custody.
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }
    drop(runtime);
    match result {
        Ok(proof) => {
            std::fs::write(root.join("full-handler-und-proof"), proof).unwrap();
            std::fs::write(root.join("case-completed"),b"actual fixture children reaped and actual adapter readers joined; retained K scope is driver process exit").unwrap();
            std::process::exit(0)
        }
        Err(error) => {
            std::fs::write(root.join("case-failure"), error).unwrap();
            std::process::exit(8)
        }
    }
}
#[cfg(all(unix, feature = "test-utils"))]
async fn handler_und_case() -> Result<String, String> {
    handler_und_case_with_setup(false).await
}
#[cfg(all(unix, feature = "test-utils"))]
fn desktop_setup_verdict(phase: &'static str, errno: Option<i32>) -> String {
    let phase = match phase {
        "fixture-root"
        | "base"
        | "socket"
        | "command"
        | "bind"
        | "accept-writer"
        | "configure-receiver"
        | "receiver-ready"
        | "await-receiver-ready"
        | "receive-writer"
        | "spawn-holder"
        | "holder-entry"
        | "reader-recovery"
        | "grant-receipt"
        | "operation-lookup" => phase,
        _ => "invalid-phase",
    };
    format!(
        "DESKTOP_FIXTURE_SETUP: phase={phase}; errno={}",
        errno
            .map(|errno| errno.to_string())
            .unwrap_or_else(|| "none".into())
    )
}
#[cfg(all(unix, feature = "test-utils"))]
async fn handler_und_case_with_setup(fail_holder_spawn: bool) -> Result<String, String> {
    use std::os::unix::{net::UnixListener, process::CommandExt};
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut vendor = DesktopFixture::new_short()
        .map_err(|e| desktop_setup_verdict("fixture-root", e.raw_os_error()))?;
    let mut holder = DesktopFixture::new_short()
        .map_err(|e| desktop_setup_verdict("fixture-root", e.raw_os_error()))?;
    let base = vendor.root().join("base");
    let slot = account(12);
    let key = ChildKey::new(LoginProvider::Codex, slot);
    let prior_auth = b"fixture-UND-prior-known-auth-identical";
    let prior_config = b"model = \"fixture-model\"\n";
    std::fs::create_dir(base.join("config-12"))
        .map_err(|e| desktop_setup_verdict("base", e.raw_os_error()))?;
    for (name, bytes) in [
        ("auth.json", prior_auth.as_slice()),
        ("config.toml", prior_config.as_slice()),
    ] {
        std::fs::write(base.join("config-12").join(name), bytes)
            .map_err(|e| desktop_setup_verdict("base", e.raw_os_error()))?;
        csq_core::platform::fs::secure_file(&base.join("config-12").join(name))
            .map_err(|_| desktop_setup_verdict("base", None))?;
    }
    csq_core::providers::codex::tos::acknowledge(&base)
        .map_err(|e| desktop_setup_verdict("base", e.raw_os_error()))?;
    let socket_path = vendor.root().join("captured-writer.sock");
    // The std address constructor checks this platform's actual SUN_LEN before any child exists.
    std::os::unix::net::SocketAddr::from_pathname(&socket_path)
        .map_err(|e| desktop_setup_verdict("socket", e.raw_os_error()))?;
    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| desktop_setup_verdict("socket", e.raw_os_error()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| desktop_setup_verdict("socket", e.raw_os_error()))?;
    let command = vendor
        .command("handler-codex-und")
        .map_err(|e| desktop_setup_verdict("command", e.raw_os_error()))?;
    let app = tauri::test::mock_app();
    let handle = app.handle().clone();
    let lock = match AccountLoginLock::acquire(&base, slot)
        .map_err(|e| desktop_setup_verdict("base", e.raw_os_error()))?
    {
        AcquireOutcome::Acquired(lock) => lock,
        _ => return Err(desktop_setup_verdict("base", None)),
    };
    let (join_tx, join_rx) = std::sync::mpsc::channel();
    let worker_base = base.clone();
    let mut observer: Observer = tokio::spawn(async move {
        super::commands::complete_codex_login_owned(
            handle,
            Arc::new(Mutex::new(None)),
            worker_base,
            slot,
            lock,
            false,
            super::commands::CodexLoginIo::fixture(command, Duration::from_secs(60), None)
                .with_reader_recovery(join_tx),
            Arc::new(
                super::login_custody::global()
                    .admit()
                    .expect("test login admission"),
            ),
        )
        .await
        .map(|_| ())
    });
    let mut recover = None;
    let mut cancellation = None;
    let mut owner_terminal = None;
    let mut observation_phase = "bind";
    let allowed = Arc::new(AtomicBool::new(false));
    let forced = Arc::new(AtomicBool::new(false));
    let finish = Arc::clone(&allowed);
    let fallback = Arc::clone(&forced);
    let vendor_root = vendor.root().to_path_buf();
    let holder_root = holder.root().to_path_buf();
    let controller = std::thread::spawn(move || {
        if !bounded(Duration::from_secs(12), || finish.load(Ordering::Acquire)) {
            fallback.store(true, Ordering::Release);
            let _ =
                publish_fixture_receipt(&holder_root.join("cleanup"), b"private writer cleanup");
            let _ =
                publish_fixture_receipt(&vendor_root.join("cleanup"), b"private vendor cleanup");
        }
    });
    // Every error below flows through actual fixture/process/reader cleanup.
    let observed:Result<(bool,String),String>=async {
        bind(&mut vendor,key).await.map_err(|_|desktop_setup_verdict("bind",None))?;
        let mut accepted=None;let mut accept_errno=None;observation_phase="accept-writer";
        let accepted_ready=until(Duration::from_secs(4),||match listener.accept(){Ok((socket,_))=>{accepted=Some(socket);true},Err(error)if error.kind()==std::io::ErrorKind::WouldBlock=>false,Err(error)=>{accept_errno=error.raw_os_error();true}}).await;
        if !accepted_ready||accepted.is_none(){return Err(desktop_setup_verdict("accept-writer",accept_errno));}
        observation_phase="configure-receiver";
        let mut receiver=configure_captured_writer(accepted.take().unwrap(),true).map_err(|e|desktop_setup_verdict("configure-receiver",e.raw_os_error()))?;
        observation_phase="receiver-ready";
        receiver.write_all(b"R").map_err(|e|desktop_setup_verdict("receiver-ready",e.raw_os_error()))?;
        observation_phase="receive-writer";
        let descriptor=receive_captured_writer_raw(receiver).map_err(|e|desktop_setup_verdict("receive-writer",e.raw_os_error()))?;
        observation_phase="spawn-holder";
        let mut command=holder.command("hold").map_err(|e|desktop_setup_verdict("spawn-holder",e.raw_os_error()))?;
        if fail_holder_spawn {
            // Real ENOENT from actual Command::spawn, after actual vendor entry
            // and descriptor receipt. No auth command/binary or synthetic errno.
            command=Command::new(holder.root().join("absent-private-holder-executable"));
            command.env_clear().current_dir(holder.root());
        }
        command.stdout(Stdio::from(descriptor)).stderr(Stdio::null()).process_group(0);
        let child=command.spawn().map_err(|e|desktop_setup_verdict("spawn-holder",e.raw_os_error()))?;drop(command);
        holder.pid=Some(child.id());holder.original=Some(Arc::new(Mutex::new(child)));
        if !until(Duration::from_secs(3),||holder.entry_pid()==holder.pid&&holder.root().join("started").exists()).await{return Err(desktop_setup_verdict("holder-entry",None));}
        observation_phase="reader-recovery";
        if !until(Duration::from_secs(3),||match join_rx.try_recv(){Ok(join)=>{recover=Some(join);true},Err(_)=>false}).await{return Err(desktop_setup_verdict("reader-recovery",None));}
        observation_phase="grant-receipt";
        let grant=read_fixture_path_receipt(vendor.root(),"grant-written")?;
        observation_phase="operation-lookup";
        let operation=login_custody::global().pending_logins().map_err(|_|desktop_setup_verdict("operation-lookup",None))?.into_iter().find(|row|row.account==12).ok_or_else(||desktop_setup_verdict("operation-lookup",None))?;
        observation_phase="observe-terminal";
        let id=operation.operation_id.clone();let began=Instant::now();
        cancellation=Some(tokio::spawn(async move{login_custody::global().cancel_child_with_confirmation(key,&id,true,||async{Ok(true)}).await}));
        let outcome=tokio::time::timeout(Duration::from_secs(7),&mut observer).await;
        let ui_refusal=match outcome {Ok(Ok(Err(error)))=>error,_=>String::new()};
        let mut terminal=None;
        if !until(Duration::from_secs(7),||match recover.as_ref().unwrap().terminal.try_recv(){Ok(receipt)=>{terminal=Some(receipt);true},Err(_)=>false}).await{return Err("fixture actual full-handler terminal custody receipt absent".into());}
        let (actual_und,refusal)=terminal.unwrap();owner_terminal=Some(actual_und);
        let cancel_terminal=if let Some(cancel)=cancellation.as_mut(){
            matches!(tokio::time::timeout(Duration::from_secs(2),cancel).await,Ok(Ok(Err(error))) if error==format!("login_group_custody_unresolved: {}",csq_core::cli_deps::sanitize::redact_display(format!("vendor_login_quarantined: <csq-base>/.login-grants/{}",grant.file_name().map(|name|name.to_string_lossy().into_owned()).unwrap_or_default()))))
        }else{false};
        let same_child=login_custody::global().registered_child_for_test(&key).zip(vendor.original.as_ref()).is_some_and(|(registered,original)|Arc::ptr_eq(&registered,original));
        let same_operation=login_custody::global().pending_logins()?.iter().any(|row|row.operation_id==operation.operation_id);
        let spawning=std::fs::read(grant.join("lease.json")).ok().and_then(|bytes|serde_json::from_slice::<serde_json::Value>(&bytes).ok()).is_some_and(|record|record["state"]=="Spawning");
        let prior=std::fs::read(base.join("config-12/auth.json")).ok().as_deref()==Some(prior_auth.as_slice()) && std::fs::read(base.join("config-12/config.toml")).ok().as_deref()==Some(prior_config.as_slice());
        let lock_retained=lock_held(vendor.root(),12);
        let active_holder=holder.live_original()==Some(true)&&holder.ping_after_action();
        // SAFETY: actual retained fixture identities; read-only group query.
        let different_group=unsafe{libc::getpgid(holder.pid.unwrap() as i32)}==holder.pid.unwrap() as i32 && holder.pid!=vendor.pid;
        let no_publish=csq_core::accounts::profiles::resolve_slot_to_uuid(&base,12).is_none()&&!base.join("config-12/.csq-account").exists();
        let grant_retained=grant.join("auth.json").is_file() && recover.as_ref().and_then(|recovery|recovery.grant.as_ref()).is_some_and(|grant|grant.upgrade().is_some());
        // an internal ticket R2-1: the quarantine names the grant relative to the accounts
        // base, never by its absolute path (Codex shares the core message).
        let path_named=grant.file_name().is_some_and(|name|refusal.contains(&format!("<csq-base>/.login-grants/{}",name.to_string_lossy())))&&!refusal.contains(grant.to_string_lossy().as_ref());
        let bounded_refusal=began.elapsed()>=crate::login_child_custody::group::STOP_DRAIN_BUDGET&&!forced.load(Ordering::Acquire)&&actual_und && refusal.contains("login_custody_UNDETERMINED") && ui_refusal.contains("refused");
        let drain=login_custody::global().close();let pending=tokio::time::timeout(Duration::from_millis(30),drain.wait()).await.is_err();
        let pass=cancel_terminal&&same_child&&same_operation&&spawning&&prior&&lock_retained&&active_holder&&different_group&&no_publish&&grant_retained&&path_named&&bounded_refusal&&pending;
        Ok((pass,format!("cancel_terminal={cancel_terminal}; same_actual_child={same_child}; same_operation={same_operation}; spawning={spawning}; prior={prior}; lock={lock_retained}; live_holder={active_holder}; separate_group={different_group}; no_publish={no_publish}; grant={grant_retained}; path={path_named}; bounded={bounded_refusal}; gate_pending={pending}")))
    }.await;
    eprintln!("DESKTOP_UND_OBSERVATION: phase={observation_phase}; result={observed:?}");
    let mut setup = observed
        .as_ref()
        .err()
        .filter(|error| error.starts_with("DESKTOP_FIXTURE_SETUP:"))
        .cloned();
    // An observation may fail before consuming the real recovery channel. Fetch
    // it during cleanup, rather than pretending absence means a failed reader.
    if recover.is_none() {
        let _ = until(Duration::from_secs(3), || match join_rx.try_recv() {
            Ok(receipt) => {
                recover = Some(receipt);
                true
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => true,
            Err(_) => false,
        })
        .await;
    }
    if setup.is_some() && cancellation.is_none() {
        if let Some(operation) = login_custody::global()
            .pending_logins()
            .unwrap_or_default()
            .into_iter()
            .find(|row| row.account == 12)
        {
            let id = operation.operation_id;
            cancellation = Some(tokio::spawn(async move {
                login_custody::global()
                    .cancel_child_with_confirmation(key, &id, true, || async { Ok(true) })
                    .await
            }));
            let _ = until(Duration::from_secs(2), || {
                login_custody::global().publication_cancelled_for_test(&key)
                    || login_custody::global()
                        .registered_child_for_test(&key)
                        .is_none()
            })
            .await;
        }
    }
    allowed.store(true, Ordering::Release);
    let _ = controller.join();
    // Setup never releases the token writer with exit0. Confirmed cancellation
    // latches first; the controlled nonzero release is a second publication fence.
    let _ = holder.release(if setup.is_some() { 7 } else { 0 });
    let _ = vendor.release(if setup.is_some() { 7 } else { 0 });
    let holder_existed = holder.original.is_some();
    let holder_status = if holder_existed {
        if !until(Duration::from_secs(3), || {
            holder.record_after_drain().is_some()
        })
        .await
        {
            if let Some(child) = &holder.original {
                if let Ok(mut child) = child.try_lock() {
                    let _ = child.kill();
                }
            }
            until(Duration::from_secs(2), || {
                holder.record_after_drain().is_some()
            })
            .await
        } else {
            true
        }
    } else {
        true
    };
    let reader_deadline = Instant::now() + Duration::from_secs(4);
    if owner_terminal.is_none() {
        if let Some(receipt) = recover.as_ref() {
            let _ = until(
                reader_deadline.saturating_duration_since(Instant::now()),
                || match receipt.terminal.try_recv() {
                    Ok((und, _)) => {
                        owner_terminal = Some(und);
                        true
                    }
                    Err(_) => false,
                },
            )
            .await;
        }
    }
    // Recovery can join retained readers only after the actual owner returned.
    // A normally finalized owner already joined its own handles; Weak then expires.
    let recovered = if owner_terminal == Some(true) {
        if let Some(receipt) = recover.take() {
            matches!(
                tokio::time::timeout(
                    reader_deadline.saturating_duration_since(Instant::now()),
                    tokio::task::spawn_blocking(receipt.finish)
                )
                .await,
                Ok(Ok(true))
            )
        } else {
            false
        }
    } else {
        false
    };
    // Never race the actual owner's wait/reap while it is still running.
    let vendor_status = if owner_terminal.is_some() {
        until(Duration::from_secs(3), || {
            vendor.record_after_drain().is_some()
        })
        .await
    } else {
        false
    };
    if let Some(cancel) = cancellation.take() {
        if !cancel.is_finished() {
            cancel.abort();
            let _ = cancel.await;
        }
    }
    if !observer.is_finished() {
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut observer).await;
    }
    let finalized_owner = owner_terminal == Some(false)
        && vendor_status
        && until(
            reader_deadline.saturating_duration_since(Instant::now()),
            || {
                login_custody::global()
                    .pending_logins()
                    .is_ok_and(|rows| !rows.iter().any(|row| row.account == 12))
                    && matches!(
                        AccountLoginLock::acquire(&base, slot),
                        Ok(AcquireOutcome::Acquired(_))
                    )
            },
        )
        .await;
    let reader_joined = recovered || finalized_owner;
    let no_publish = csq_core::accounts::profiles::resolve_slot_to_uuid(&base, 12).is_none()
        && !base.join("config-12/.csq-account").exists();
    eprintln!("DESKTOP_UND_CLEANUP: holder_reaped={holder_status}; readers_joined={reader_joined}; vendor_reaped={vendor_status}; owner_finalized={finalized_owner}; no_publication={no_publish}");
    if setup.is_some() {
        let sender_setup = scm_print_sender_result(vendor.root());
        if setup.as_ref().is_some_and(|error| {
            ["receive-writer", "configure-receiver", "receiver-ready"]
                .iter()
                .any(|phase| error.starts_with(&format!("DESKTOP_FIXTURE_SETUP: phase={phase};")))
        }) {
            if let Some(sender_setup) = sender_setup {
                setup = Some(sender_setup);
            }
        }
    }
    if !holder_status || !reader_joined || !vendor_status {
        holder.preserve_unknown();
        vendor.preserve_unknown();
        if let Some(setup) = setup {
            return Err(format!("{setup}; cleanup=unconfirmed; holder_reaped={holder_status}; readers_joined={reader_joined}; vendor_reaped={vendor_status}"));
        }
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: full-handler actual child/reader cleanup not verified".into());
    }
    if let Some(setup) = setup {
        return Err(format!("{setup}; cleanup=confirmed; vendor_reaped=true; holder={}; readers={}; no_publication={no_publish}",if holder_existed{"reaped"}else{"not-spawned"},if finalized_owner{"owner-finalized"}else{"recovery-joined"}));
    }
    let (pass, detail) = observed?;
    if !pass {
        let marker = if detail.contains("cancel_terminal=false") {
            "HANDLER_UND_CANCEL_TERMINAL_PATH"
        } else {
            "HANDLER_UND_RETAINS_SHARED_GRANT"
        };
        return Err(format!("{marker}: {detail}"));
    }
    Ok(format!("actual_vendor_reaped=true\nactual_sibling_reaped=true\nactual_adapter_readers_joined=true\nK_retention=isolated_driver_process_exit\n{detail}\n"))
}
#[cfg(all(unix, feature = "test-utils"))]
#[test]
fn codex_full_handler_missing_captured_eof_retains_shared_grant_and_prior_slot() {
    case_process("case-handler-codex-und");
}

#[cfg(unix)]
#[test]
fn stalled_owned_case_is_actually_reaped_after_case_bound() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut fixture = DesktopFixture::new().expect("private stalled case root");
    let mut command = fixture.command("hold").expect("exact inert stalled actor");
    // The actor has no descendants and performs only private file control.
    let child = spawn_owned_case(&mut command).expect("actual case spawn seam");
    drop(command);
    let pid = child.id();
    let original = Arc::new(Mutex::new(child));
    fixture.pid = Some(pid);
    fixture.original = Some(Arc::clone(&original));
    let entered = bounded(Duration::from_secs(3), || {
        fixture.entry_pid() == Some(pid) && fixture.root().join("started").exists()
    });
    let still_live = fixture.live_original() == Some(true);
    // SAFETY: read-only query of this actual retained unreaped fixture identity.
    let owns_group = unsafe { libc::getpgid(pid as i32) } == pid as i32;
    let waited = wait_owned_case(&mut fixture, Duration::from_millis(200));
    let reaped_by_bound = waited.timed_out && waited.status.is_some() && fixture.reaped;
    // OLD-flow safety cleanup is deliberately not credited as bound cleanup.
    let mut accounted = waited.status;
    if accounted.is_none() {
        if let Ok(mut child) = original.try_lock() {
            let _ = child.kill();
        }
        bounded(Duration::from_secs(3), || {
            accounted = original
                .try_lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok().flatten());
            accounted.is_some()
        });
    }
    if accounted.is_some() {
        fixture.reaped = true;
    } else {
        fixture.preserve_unknown();
        std::mem::forget(Arc::clone(&original));
        panic!(
            "DESKTOP_CASE_CLEANUP_UNCONFIRMED: actual controlled stalled actor could not be reaped"
        );
    }
    assert!(
        entered && still_live,
        "actual controlled stalled case entry must be reached before its bound"
    );
    assert!(
        owns_group && reaped_by_bound,
        "desktop case bound must terminate and reap the ORIGINAL owned case"
    );
    assert!(
        waited.group_empty,
        "desktop case bound must observe its owned PGID empty after actual reap"
    );
    // Typed same-Child terminal receipt, rather than an unrelated numeric PID probe.
    assert!(original.try_lock().unwrap().try_wait().unwrap().is_some());
}

#[cfg(all(unix, feature = "test-utils"))]
#[test]
fn actual_nonblocking_scm_receiver_reproduces_wouldblock_then_normalizes() {
    use std::os::{fd::AsRawFd, unix::net::UnixStream};
    let (sender, receiver) = UnixStream::pair().expect("owned SCM pair");
    receiver
        .set_nonblocking(true)
        .expect("actual nonblocking receiver");
    let negative = receive_captured_writer_mode(receiver.try_clone().unwrap(), false);
    let was_wouldblock = negative.as_ref().is_err_and(|error| {
        error.kind() == std::io::ErrorKind::WouldBlock && error.raw_os_error().is_some()
    });
    drop(negative);
    let (mut captured_reader, captured_writer) = UnixStream::pair().expect("owned captured writer");
    captured_reader
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let sent = send_fixture_descriptor(&sender, captured_writer.as_raw_fd());
    let normalized = receive_captured_writer(receiver.try_clone().unwrap());
    // SAFETY: a read-only flag query on this retained original descriptor.
    let blocking =
        unsafe { libc::fcntl(receiver.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK == 0;
    let mut transferred = false;
    if let Ok(descriptor) = normalized {
        let mut writer = std::fs::File::from(descriptor);
        if writer.write_all(b"scm-proof").is_ok() {
            let mut bytes = [0_u8; 9];
            transferred = captured_reader.read_exact(&mut bytes).is_ok() && &bytes == b"scm-proof";
        }
        drop(writer);
    }
    drop(captured_writer);
    drop(captured_reader);
    drop(sender);
    drop(receiver);
    // All descriptors close before causal assertions; no sleeps or child/threads.
    assert!(
        was_wouldblock,
        "actual nonblocking SCM receive must expose WouldBlock before normalization"
    );
    assert!(
        sent.is_ok() && blocking && transferred,
        "actual normalized SCM receiver must clear nonblocking and receive the owned writer"
    );
}
#[cfg(all(unix, feature = "test-utils"))]
#[test]
fn actual_holder_spawn_failure_surfaces_setup_phase_errno_after_cleanup() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut fixture = DesktopFixture::new().expect("private setup-error case root");
    let mut command = fixture
        .command("case-handler-codex-setup-error")
        .expect("isolated setup-error driver");
    command
        .stdout(std::fs::File::create(fixture.root().join("case.out")).unwrap())
        .stderr(std::fs::File::create(fixture.root().join("case.err")).unwrap());
    let child = spawn_owned_case(&mut command).expect("actual owned setup-error case");
    drop(command);
    let pid = child.id();
    fixture.pid = Some(pid);
    fixture.original = Some(Arc::new(Mutex::new(child)));
    let waited = wait_owned_case(&mut fixture, Duration::from_secs(40));
    let entered = fixture.entry_pid() == Some(pid) && fixture.root().join("started").is_file();
    let verdict = std::fs::read_to_string(fixture.root().join("case-failure")).unwrap_or_default();
    let diagnostic = std::fs::read_to_string(fixture.root().join("case.err")).unwrap_or_default();
    // OLD behavior parks after already reaping its controlled fixture processes.
    // The shared case helper kills/reaps that case before this assertion; require
    // its existing typed cleanup report so no live child is treated as accounted.
    let nested_accounted = verdict.contains("cleanup=confirmed")
        || diagnostic.contains(
            "DESKTOP_UND_CLEANUP: holder_reaped=true; readers_joined=false; vendor_reaped=true",
        );
    if waited.status.is_none()
        || !fixture.reaped
        || !nested_accounted
        || (waited.timed_out && !waited.group_empty)
    {
        fixture.preserve_unknown();
        std::mem::forget(fixture.original.take());
        panic!("DESKTOP_SETUP_CLEANUP_UNCONFIRMED: actual setup case or controlled nested children not accounted");
    }
    assert!(
        entered,
        "actual isolated setup-error case entry must be reached"
    );
    let expected = format!(
        "DESKTOP_FIXTURE_SETUP: phase=spawn-holder; errno={}",
        libc::ENOENT
    );
    assert!(
        !waited.timed_out
            && waited.status.is_some_and(|status| status.code() == Some(8))
            && verdict.starts_with(&expected)
            && verdict.contains("cleanup=confirmed")
            && verdict.contains("vendor_reaped=true")
            && verdict.contains("holder=not-spawned")
            && verdict.contains("no_publication=true")
            && !fixture.root().join("case-unknown").exists(),
        "actual setup failure must surface SETUP phase and syscall errno after owned cleanup"
    );
}

#[cfg(all(unix, feature = "test-utils"))]
#[test]
fn actual_scm_peer_eof_is_not_reported_as_stale_syscall_errno() {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().expect("owned EOF pair");
    let configured = configure_captured_writer(receiver, true);
    drop(sender); // Configuration ran while the actual peer was still open.
    let result = configured.and_then(receive_captured_writer_raw);
    let kind = result.as_ref().err().map(std::io::Error::kind);
    let errno = result.as_ref().err().and_then(std::io::Error::raw_os_error);
    drop(result); // Receiver and any unexpected delivered OwnedFd close first.
    assert!(
        kind == Some(std::io::ErrorKind::UnexpectedEof) && errno.is_none(),
        "actual SCM peer EOF must not report a stale syscall errno"
    );
}
