//! Actual `csq login` call sites against inert vendor executables.
//! Unix runtime; this file makes no native Windows runtime claim.
#![cfg(all(unix, feature = "test-utils"))]

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// All values are synthetic; no grant can authenticate or reach a real service.
const PRIOR_AUTH: &[u8] = br#"{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"account_id":"TEST_PRIOR","access_token":"TEST_PRIOR_ACCESS","refresh_token":"TEST_PRIOR_REFRESH","id_token":"TEST_PRIOR_ID"},"last_refresh":"2100-01-01T00:00:00Z"}"#;
const PRIOR_CONFIG: &[u8] = b"model = \"fixture-model\"\nmodel_reasoning_effort = \"high\"\ncli_auth_credentials_store = \"keyring\"\nprofile = \"DO-NOT-COPY\"\n[mcp_servers.fixture]\ncommand = \"DO-NOT-COPY\"\n";
const NEW_AUTH: &[u8] = br#"{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"account_id":"TEST_NEW","access_token":"TEST_NEW_ACCESS","refresh_token":"TEST_NEW_REFRESH","id_token":"TEST_NEW_ID"},"last_refresh":"2100-01-01T00:00:00Z"}"#;
fn backend_pin() -> &'static str {
    if cfg!(target_os = "linux") {
        "file"
    } else {
        "in-memory"
    }
}
fn backend_id() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux-file-aes"
    } else {
        "in-memory"
    }
}
fn pin_backend(command: &mut Command, root: &Path) {
    command.env("CSQ_SECRET_BACKEND", backend_pin());
    #[cfg(target_os = "linux")]
    command.env("CSQ_SECRET_PASSPHRASE_FILE", root.join("vault-passphrase"));
    #[cfg(not(target_os = "linux"))]
    let _ = root;
}
fn codex_grant_proof(root: &Path) {
    let supplied =
        PathBuf::from(std::env::var_os("CODEX_HOME").expect("actual csq supplied CODEX_HOME"));
    let home = std::fs::canonicalize(&supplied).unwrap();
    let expected = std::fs::canonicalize(root.join("base"))
        .unwrap()
        .join(".login-grants");
    assert_eq!(
        home.parent(),
        Some(expected.as_path()),
        "CODEX_GRANT_PRIVATE_HOME"
    );
    let name = home.file_name().unwrap().to_str().unwrap();
    assert!(
        name.strip_prefix("grant-").is_some_and(|id| id.len() == 36
            && id
                .bytes()
                .enumerate()
                .all(|(i, c)| if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                })),
        "CODEX_GRANT_UUID"
    );
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(home.join("config.toml")).unwrap()).unwrap();
    let table = config.as_table().unwrap();
    assert_eq!(table.len(), 3, "CODEX_GRANT_BENIGN_ALLOWLIST");
    assert_eq!(config["cli_auth_credentials_store"].as_str(), Some("file"));
    assert_eq!(config["model"].as_str(), Some("fixture-model"));
    assert_eq!(config["model_reasoning_effort"].as_str(), Some("high"));
    std::fs::write(home.join("auth.json"), NEW_AUTH).unwrap();
    let read_back = std::fs::read(home.join("auth.json")).unwrap();
    assert_eq!(read_back, NEW_AUTH);
    // No raw auth/config bytes leave the private vendor home in this receipt.
    atomic(
        root,
        "codex-grant-proof",
        &serde_json::to_vec(&serde_json::json!({
            "supplied_home": supplied, "read_home": home, "write_home": home,
            "generated_file_store": true, "benign_keys_only": true,
            "write_readback_identical": true, "auth_len": read_back.len()
        }))
        .unwrap(),
    );
}

const ENTRY: &str = "login_binary_fixture_entry";
const ROLE: &str = "CSQ_LOGIN_BINARY_FIXTURE_ROLE";
const ROOT: &str = "CSQ_LOGIN_BINARY_FIXTURE_ROOT";
/// Quick polls (ping, interrupt-forwarded and identity-gone checks) that only
/// observe a file the live fixture writes within one loop turn.
const BUDGET: Duration = Duration::from_secs(10);
/// The fixture's own enforced self-expiry (`fixture-expired` backstop below).
const FIXTURE_EXPIRY: Duration = Duration::from_secs(45);
/// `ready()` waits for process startup and fixture handshakes. Past
/// `FIXTURE_EXPIRY` the fixture has already abandoned the run, so waiting
/// longer cannot turn the row green; the bound sits at that enforced limit.
const READY_BOUND: Duration = FIXTURE_EXPIRY;
/// `finish()` waits for the child exit and the stdout EOF after an interrupt.
/// The fixture self-expires at `FIXTURE_EXPIRY`, which ends its stdout, so the
/// child cannot legitimately outlive that limit.
const FINISH_BOUND: Duration = FIXTURE_EXPIRY;
static INTERRUPTS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn ignore_interrupt(_: libc::c_int) {
    INTERRUPTS.fetch_add(1, Ordering::SeqCst);
}

fn poll(condition: impl FnMut() -> bool) -> bool {
    poll_within(BUDGET, condition)
}
fn poll_within(bound: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn atomic(root: &Path, name: &str, bytes: &[u8]) {
    let mut f = tempfile::NamedTempFile::new_in(root).unwrap();
    f.write_all(bytes).unwrap();
    f.persist(root.join(name)).unwrap();
}
fn disposition(ignore: bool) {
    // SAFETY: private fixture process; fully initialized sigaction and static
    // signal-safe callback. No signal state in the outer runner is changed.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = if ignore {
            ignore_interrupt as *const () as usize
        } else {
            libc::SIG_DFL
        };
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()),
            0
        );
    }
}
// Kernel start identity, never a bare PID liveness claim. Unexpected read
// errors remain UNKNOWN; only a missing process or different birth is GONE.
#[cfg(target_os = "linux")]
fn birth(pid: u32) -> std::io::Result<Option<String>> {
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
fn birth(pid: u32) -> std::io::Result<Option<String>> {
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
fn birth(_: u32) -> std::io::Result<Option<String>> {
    Err(std::io::Error::other("kernel process identity unsupported"))
}
fn same_identity_gone(record: &serde_json::Value) -> bool {
    let pid = u32::try_from(record["pid"].as_u64().unwrap()).unwrap();
    match birth(pid) {
        Ok(None) => true,
        Ok(Some(current)) => current != record["birth"].as_str().unwrap(),
        Err(_) => false,
    }
}

fn helper_command(root: &Path, role: &str) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.env_clear()
        .args([
            ENTRY,
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .env(ROOT, root)
        .env("HOME", root.join("home"))
        .env("CSQ_BASE_DIR", root.join("base"))
        .env("PATH", root.join("bin"))
        .env("TMPDIR", root.join("tmp"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    pin_backend(&mut c, root);
    c
}
struct OwnedFixtureChild(Option<Child>);
impl Drop for OwnedFixtureChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
#[ignore = "fixture dispatcher; only an owned subprocess supplies the required role"]
fn login_binary_fixture_entry() {
    let _env_guard = csq_core::platform::test_env::lock();
    let role = std::env::var(ROLE).expect("explicit private fixture role");
    let root = PathBuf::from(std::env::var_os(ROOT).expect("private root"));
    assert_eq!(
        PathBuf::from(std::env::var_os("HOME").unwrap()),
        root.join("home")
    );
    #[cfg(target_os = "linux")]
    {
        let file = PathBuf::from(std::env::var_os("CSQ_SECRET_PASSPHRASE_FILE").unwrap());
        assert_eq!(file, root.join("vault-passphrase"));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read(file).unwrap(),
            b"SYNTHETIC-LOGIN-BINARY-VAULT-ONLY\n"
        );
    }
    // Verify selected backend inside the actually execed fixture process.
    // open_default_vault refuses an unsupported pin instead of native fallback.
    let vault =
        csq_core::platform::secret::open_default_vault().expect("explicit synthetic backend");
    assert_eq!(vault.backend_id(), backend_id(), "LOGIN_BINARY_BACKEND_ID");
    atomic(
        &root,
        &format!("{role}-backend"),
        vault.backend_id().as_bytes(),
    );
    if role != "grandchild" && std::env::var_os("CODEX_HOME").is_some() {
        codex_grant_proof(&root);
    }
    let group = role == "vendor-group" || role == "grandchild";
    disposition(group);
    let mut lifeline = UnixStream::connect(root.join("ctl")).unwrap();
    lifeline.set_nonblocking(true).unwrap();
    let mut descendant = OwnedFixtureChild(None);
    if role == "vendor-group" {
        // This is an actual vendor child, hence a true grandchild of csq. It
        // inherits the vendor stdout descriptor and the vendor's process group.
        descendant.0 = Some(helper_command(&root, "grandchild").spawn().unwrap());
    } else {
        assert!(role == "vendor-default" || role == "grandchild");
    }
    let name = if role == "grandchild" {
        "grandchild"
    } else {
        "vendor"
    };
    // SAFETY: queries about this live fixture itself, not inferred target PIDs.
    let identity = serde_json::json!({"pid": std::process::id(),
        "pgid": unsafe { libc::getpgrp() }, "ppid": unsafe { libc::getppid() },
        "birth": birth(std::process::id()).unwrap().expect("live fixture birth identity")});
    atomic(
        &root,
        &format!("{name}-ready"),
        &serde_json::to_vec(&identity).unwrap(),
    );
    let deadline = Instant::now() + FIXTURE_EXPIRY;
    let mut seen = Vec::new();
    let mut interrupts = 0;
    loop {
        let count = INTERRUPTS.load(Ordering::SeqCst);
        if count != interrupts {
            atomic(
                &root,
                &format!("{name}-interrupt"),
                count.to_string().as_bytes(),
            );
            interrupts = count;
        }
        if let Ok(nonce) = std::fs::read(root.join("ping")) {
            if nonce != seen {
                atomic(&root, &format!("{name}-ping"), &nonce);
                seen = nonce;
            }
        }
        let mut byte = [0_u8; 1];
        let released = match lifeline.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                false
            }
            Err(_) => true,
        };
        if released || root.join("release").exists() || Instant::now() >= deadline {
            if Instant::now() >= deadline {
                atomic(&root, "fixture-expired", b"not a cleanup receipt");
            }
            atomic(&root, "release", b"cooperative fixture cleanup");
            if let Some(mut child) = descendant.0.take() {
                let status = child.wait().unwrap();
                atomic(&root, "grandchild-cooperative-reap", &serde_json::to_vec(&serde_json::json!({
                    "spawned_pid": child.id(), "reaped_pid": child.id(), "code": status.code(), "signal": status.signal()
                })).unwrap());
            }
            std::process::exit(0);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct BinaryLogin {
    sandbox: Option<tempfile::TempDir>,
    child: Option<Child>,
    input: Option<ChildStdin>,
    listener: UnixListener,
    lifelines: Vec<UnixStream>,
    stdout: Option<JoinHandle<Vec<u8>>>,
}
impl BinaryLogin {
    fn spawn(provider: &str, group: bool) -> Self {
        // Keep Unix socket below macOS's sockaddr_un bound, even when the host
        // TMPDIR is a long per-user path. Ownership lives until all Child waits.
        let sandbox = tempfile::Builder::new()
            .prefix("cq-l-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = sandbox.path();
        for name in ["home", "base", "bin", "tmp", "config", "appdata", "local"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut passphrase = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("vault-passphrase"))
                .unwrap();
            passphrase
                .write_all(b"SYNTHETIC-LOGIN-BINARY-VAULT-ONLY\n")
                .unwrap();
        }
        assert!(root.join("ctl").as_os_str().as_encoded_bytes().len() < 100);
        if provider == "codex" {
            let config = root.join("base/config-1");
            std::fs::create_dir(&config).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
            for (name, bytes) in [("auth.json", PRIOR_AUTH), ("config.toml", PRIOR_CONFIG)] {
                let path = config.join(name);
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let listener = UnixListener::bind(root.join("ctl")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let exe = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .replace('\'', "'\\''");
        for (name, version) in [
            ("claude", "2.0.0"),
            ("codex", "codex-cli 0.40.0"),
            ("kimi", "0.27.0"),
            ("grok", "grok 0.2.103"),
        ] {
            let script = format!("#!/bin/sh\ncase \"$1\" in --version|-V) printf '%s\\n' '{version}'; exit 0;; esac\nexec '{exe}' {ENTRY} --ignored --exact --nocapture --test-threads=1\n");
            let path = root.join("bin").join(name);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in ["open", "xdg-open"] {
            let path = root.join("bin").join(name);
            std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_csq"));
        command
            .env_clear()
            .current_dir(root)
            .args([
                "login",
                "1",
                "--provider",
                provider,
                "--ignore-cli-version",
                "--no-auto-update-cli",
            ])
            .env("HOME", root.join("home"))
            .env("CSQ_HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("CLAUDE_HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("APPDATA", root.join("appdata"))
            .env("LOCALAPPDATA", root.join("local"))
            .env("TMPDIR", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("PATH", root.join("bin"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
            .env("CSQ_TEST_BYPASS_TTY", "1")
            .env("CSQ_NO_TRACK_LATEST", "1")
            .env("CSQ_NO_AUTO_UPDATE_CLI", "1")
            .env("CSQ_LOGIN_TIMEOUT_SECS", "300")
            .env(
                ROLE,
                if group {
                    "vendor-group"
                } else {
                    "vendor-default"
                },
            )
            .env(ROOT, root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(root.join("csq.stderr")).unwrap())
            .process_group(0);
        pin_backend(&mut command, root);
        // Arm fallback Child ownership immediately after successful spawn,
        // before pipe extraction or reader-thread allocation can unwind.
        let mut owner = OwnedFixtureChild(Some(command.spawn().unwrap()));
        let input = owner.0.as_mut().unwrap().stdin.take();
        let mut output = owner.0.as_mut().unwrap().stdout.take().unwrap();
        let stdout_path = root.join("csq.stdout");
        let stdout = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).unwrap();
            std::fs::write(stdout_path, &bytes).unwrap();
            bytes
        });
        let mut this = Self {
            sandbox: Some(sandbox),
            child: owner.0.take(),
            input,
            listener,
            lifelines: Vec::new(),
            stdout: Some(stdout),
        };
        // The actual Codex prerequisite read receives Enter; keep the input
        // handle owned until cleanup rather than accidentally signal stdin EOF.
        this.input.as_mut().unwrap().write_all(b"\n").unwrap();
        this
    }
    fn root(&self) -> &Path {
        self.sandbox.as_ref().expect("private fixture root").path()
    }
    fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => self.lifelines.push(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("private lifeline accept: {e}"),
            }
        }
    }
    fn ready(&mut self, group: bool) -> bool {
        poll_within(READY_BOUND, || {
            self.accept();
            self.root().join("vendor-ready").exists()
                && (!group || self.root().join("grandchild-ready").exists())
                && self.lifelines.len() == if group { 2 } else { 1 }
        })
    }
    fn identity(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.root().join(format!("{name}-ready"))).unwrap())
            .unwrap()
    }
    fn interrupt(&self) {
        let child = self
            .child
            .as_ref()
            .expect("actual owned unreaped csq Child");
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        // SAFETY: signal only the PID from our still-owned, unreaped csq Child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    }
    fn ping(&self, group: bool) -> bool {
        let nonce = b"fresh-after-first-interrupt";
        atomic(self.root(), "ping", nonce);
        poll(|| {
            std::fs::read(self.root().join("vendor-ping"))
                .ok()
                .as_deref()
                == Some(nonce)
                && (!group
                    || std::fs::read(self.root().join("grandchild-ping"))
                        .ok()
                        .as_deref()
                        == Some(nonce))
        })
    }
    fn no_publication(&self) -> bool {
        let base = self.root().join("base");
        let profiles = base.join("profiles.json");
        if profiles.exists() {
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(profiles).unwrap()).unwrap();
            if !v["by_slot"]["1"].is_null() {
                return false;
            }
        }
        for dir in ["credentials", "identities"] {
            fn visit(path: &Path) -> bool {
                if !path.exists() {
                    return true;
                }
                for entry in std::fs::read_dir(path).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        if !visit(&path) {
                            return false;
                        }
                    } else if path.extension().is_some_and(|x| x == "json") {
                        return false;
                    }
                }
                true
            }
            if !visit(&base.join(dir)) {
                return false;
            }
        }
        true
    }
    fn finish(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        if !poll_within(FINISH_BOUND, || match child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                true
            }
            _ => false,
        }) {
            return None;
        }
        // Original actual Child is reaped here. Pipe EOF is a separate axis.
        self.child.take();
        self.input.take();
        if !poll_within(FINISH_BOUND, || {
            self.stdout
                .as_ref()
                .is_some_and(|reader| reader.is_finished())
        }) {
            return None;
        }
        self.stdout.take().unwrap().join().unwrap();
        status
    }
}
impl BinaryLogin {
    fn cleanup_owned(&mut self) {
        // Every failure path first closes the per-actor lifelines. The vendor
        // cooperatively reaps its actual child; no PID-only descendant kill.
        while let Ok((stream, _)) = self.listener.accept() {
            self.lifelines.push(stream);
        }
        for stream in self.lifelines.drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = std::fs::write(self.root().join("release"), b"owned controller cleanup");
        if let Some(child) = self.child.as_mut() {
            if !poll(|| child.try_wait().ok().flatten().is_some()) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        if let Some(reader) = self.stdout.take() {
            // The owned pipe must close after fixture lifeline cleanup. The
            // self-expiry is only a safety backstop, never a cleanup receipt.
            if !poll(|| reader.is_finished()) {
                // Keep ownership even on an outer assertion unwind. Joining
                // waits for the 45-second fixture backstop rather than silently
                // detaching this reader. It never makes a test row successful.
                eprintln!(
                    "BINARY_LOGIN_CLEANUP_UNKNOWN: actor cleanup did not produce bounded EOF"
                );
            }
            let _ = reader.join();
        }
    }
}

impl Drop for BinaryLogin {
    fn drop(&mut self) {
        self.cleanup_owned();
        if std::thread::panicking() {
            let kept = self.sandbox.take().unwrap().keep();
            eprintln!("BINARY_LOGIN_FAILED_CASE_RETAINED {}", kept.display());
        }
    }
}

#[test]
fn failed_binary_case_keeps_stderr_after_actual_unwind() {
    let sandbox = tempfile::Builder::new()
        .prefix("cq-l-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = sandbox.path().to_path_buf();
    std::fs::write(root.join("csq.stderr"), b"synthetic captured child failure").unwrap();
    let listener = UnixListener::bind(root.join("ctl")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _login = BinaryLogin {
            sandbox: Some(sandbox),
            child: None,
            input: None,
            listener,
            lifelines: Vec::new(),
            stdout: None,
        };
        panic!("synthetic binary checklist failure");
    }));
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(root.join("csq.stderr")).unwrap(),
        b"synthetic captured child failure"
    );
    std::fs::remove_dir_all(root).unwrap();
}

fn exercise(provider: &str, group: bool) {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut login = BinaryLogin::spawn(provider, group);
    let mut checks = Vec::new();
    let ready = login.ready(group);
    checks.push(("BINARY_LOGIN_CALLSITE_REACHED", ready));
    let mut vendor = None;
    let mut descendant = None;
    if ready {
        let identity = login.identity("vendor");
        checks.push((
            "BINARY_LOGIN_OWN_VENDOR_GROUP",
            identity["pgid"] == identity["pid"],
        ));
        vendor = Some(identity);
        if group {
            let child = login.identity("grandchild");
            checks.push((
                "BINARY_LOGIN_TRUE_VENDOR_DESCENDANT",
                child["ppid"] == vendor.as_ref().unwrap()["pid"]
                    && child["pgid"] == vendor.as_ref().unwrap()["pgid"],
            ));
            descendant = Some(child);
        }
        login.interrupt();
        if group {
            checks.push((
                "BINARY_LOGIN_FIRST_INTERRUPT_FORWARDED",
                poll(|| {
                    login.root().join("vendor-interrupt").exists()
                        && login.root().join("grandchild-interrupt").exists()
                }),
            ));
            checks.push((
                "BINARY_LOGIN_FIRST_INTERRUPT_MUST_NOT_KILL",
                login.ping(true) && login.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            ));
            checks.push(("BINARY_LOGIN_NO_EARLY_PUBLICATION", login.no_publication()));
            eprintln!("BINARY_LOGIN_SECOND_INTERRUPT_REQUESTED provider={provider}");
            login.interrupt();
        }
    }
    let status = login.finish();
    checks.push((
        "BINARY_LOGIN_ACTUAL_EXIT130_AND_EOF",
        status.is_some_and(|s| s.code() == Some(130)),
    ));
    checks.push(("BINARY_LOGIN_NO_PUBLICATION", login.no_publication()));
    checks.push((
        "BINARY_LOGIN_VENDOR_IDENTITY_GONE",
        vendor
            .as_ref()
            .is_some_and(|id| poll(|| same_identity_gone(id))),
    ));
    if let Some(id) = &descendant {
        checks.push((
            "BINARY_LOGIN_DESCENDANT_IDENTITY_GONE",
            poll(|| same_identity_gone(id)),
        ));
    }
    // Cleanup is complete before any observation is turned into a test verdict.
    login.cleanup_owned();
    checks.push((
        "BINARY_LOGIN_NO_PUBLICATION_AFTER_CLEANUP",
        login.no_publication(),
    ));
    checks.push((
        "BINARY_LOGIN_FIXTURE_EXPIRY_IS_NOT_CLEANUP",
        !login.root().join("fixture-expired").exists(),
    ));
    let role = if group {
        "vendor-group"
    } else {
        "vendor-default"
    };
    checks.push((
        "LOGIN_BINARY_BACKEND_ID",
        std::fs::read(login.root().join(format!("{role}-backend")))
            .ok()
            .as_deref()
            == Some(backend_id().as_bytes()),
    ));
    if provider == "codex" {
        checks.push((
            "CODEX_PRIOR_AUTH_BYTE_IDENTICAL",
            std::fs::read(login.root().join("base/config-1/auth.json"))
                .ok()
                .as_deref()
                == Some(PRIOR_AUTH),
        ));
        checks.push((
            "CODEX_PRIOR_CONFIG_BYTE_IDENTICAL",
            std::fs::read(login.root().join("base/config-1/config.toml"))
                .ok()
                .as_deref()
                == Some(PRIOR_CONFIG),
        ));
        let proof = std::fs::read(login.root().join("codex-grant-proof"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        checks.push((
            "CODEX_ACTUAL_PRIVATE_GRANT_READ_WRITE",
            proof.as_ref().is_some_and(|p| {
                p["generated_file_store"] == true
                    && p["benign_keys_only"] == true
                    && p["write_readback_identical"] == true
                    && p["supplied_home"] == p["read_home"]
                    && p["read_home"] == p["write_home"]
                    && p["auth_len"] == NEW_AUTH.len()
            }),
        ));
        if let Some(proof) = proof {
            eprintln!("CODEX_ACTUAL_GRANT_RECEIPT {proof}");
        }
    } else if provider == "kimi-cli" || provider == "grok" {
        eprintln!("native auth: UNVERIFIED (lifecycle-only synthetic vendor)");
    }
    let failures: Vec<_> = checks
        .iter()
        .filter(|(_, value)| !value)
        .map(|(name, _)| *name)
        .collect();
    // Actual child/reader cleanup above precedes scoring. Keep the sandbox
    // through the assertion so an unwind preserves the original evidence.
    let stderr = if failures.is_empty() {
        String::new()
    } else {
        std::fs::read_to_string(login.root().join("csq.stderr"))
            .unwrap_or_else(|error| format!("child stderr unavailable: {error}"))
    };
    assert!(
        failures.is_empty(),
        "{provider} group={group}: {failures:?}\nactual child stderr:\n{stderr}"
    );
    drop(login);
    if descendant.is_some() {
        eprintln!("descendant reap: not observed (no subreaper on darwin)");
    }
    eprintln!("BINARY_LOGIN_CAUSAL_RECEIPT provider={provider} group={group} direct_child_reaped=true reader_eof=true exit=130 publication=0");
}

#[test]
fn claude_binary_ctrlc_maps130_without_publication() {
    exercise("claude", false);
}
#[test]
fn codex_binary_ctrlc_maps130_without_publication() {
    exercise("codex", false);
}
#[test]
fn kimi_binary_ctrlc_maps130_without_publication() {
    exercise("kimi-cli", false);
}
#[test]
fn grok_binary_ctrlc_maps130_without_publication() {
    exercise("grok", false);
}
#[test]
fn claude_binary_second_ctrlc_ends_vendor_and_true_grandchild() {
    exercise("claude", true);
}
#[test]
fn codex_binary_second_ctrlc_ends_vendor_and_true_grandchild() {
    exercise("codex", true);
}
#[test]
fn kimi_binary_second_ctrlc_ends_vendor_and_true_grandchild() {
    exercise("kimi-cli", true);
}
#[test]
fn grok_binary_second_ctrlc_ends_vendor_and_true_grandchild() {
    exercise("grok", true);
}
