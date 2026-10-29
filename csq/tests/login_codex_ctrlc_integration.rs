//! Actual Codex core perform_with + shared CLI piped waiter, private inputs only.
//! All rows bind actual original Child/status, real reader join and live PGID.
//! Each driver preserves a harmless prior SIGINT handler so the compiled
//! handler-removal mutant retains its real vendor reaper on Linux AND Darwin.
//! These rows do not prove prevention of raw SIG_DFL parent death.
#![cfg(unix)]

#[path = "../src/login_cancel_guard.rs"]
mod login_cancel_guard;
#[path = "../src/login_child_custody.rs"]
mod login_child_custody;

use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::types::AccountNum;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ENTRY: &str = "login_codex_ctrlc_private_entry";
const ROLE: &str = "CSQ_PRIVATE_CODEX_CTRLC_ROLE";
const ROOT: &str = "CSQ_PRIVATE_CODEX_CTRLC_ROOT";
const NOTICE: &str = "Cancelling — waiting for Codex login to exit";
const DEFAULT_ASSERTION: &str = "LOGIN_CODEX_CTRLC_DEFAULT_REAP_JOIN_CANCEL130";
const RETAIN_ASSERTION: &str = "LOGIN_CODEX_CTRLC_RETAIN_LOCK_PING";
const LATE_ASSERTION: &str = "LOGIN_CODEX_CTRLC_LATE_ZERO_NO_POST";
const CONTROL_ASSERTION: &str = "LOGIN_CODEX_CTRLC_NO_CANCEL_PUBLISH_ONCE";
// These are failure/cleanup budgets, never scheduler-speed success assertions.
// Every successful transition requires its causal marker or fresh nonce.
// HANG GUARD, not a pacing assumption: success always needs its causal marker;
// this only bounds a genuinely wedged run. Sized for a sustained host io stall (an internal ticket).
const BUDGET: Duration = Duration::from_secs(180);
const PGID_ASSERTION: &str = "LOGIN_CODEX_CTRLC_OWNED_VENDOR_PGID";
const REAP_ASSERTION: &str = "LOGIN_CODEX_CTRLC_ACTUAL_CHILD_REAP";
const JOIN_ASSERTION: &str = "LOGIN_CODEX_CTRLC_READER_JOIN";
const CALLBACK_ASSERTION: &str = "LOGIN_CODEX_CTRLC_CALLBACK_CALLER_THREAD";
const OPEN_ASSERTION: &str = "LOGIN_CODEX_CTRLC_OPEN_STDOUT_RETAIN_NO_PUBLISH";
const OPEN_CUSTODY_ASSERTION: &str = "LOGIN_CODEX_CTRLC_OPEN_STDOUT_TIMEOUT_CUSTODY";
const OPEN_FINAL_ASSERTION: &str = "LOGIN_CODEX_CTRLC_OPEN_STDOUT_FINAL_REFUSAL";
static LIVE_OWNED_SIDECARS: AtomicUsize = AtomicUsize::new(0);
const URL_LINE: &str = "https://fixture.invalid/device-auth";

static PRIOR_SIGNALS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn prior_sigint(_: libc::c_int) {
    PRIOR_SIGNALS.fetch_add(1, Ordering::SeqCst);
}

fn atomic_write(root: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.persist(root.join(name)).map_err(|error| error.error)?;
    Ok(())
}

fn poll(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + BUDGET;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn selected_command(root: &Path, role: &str) -> std::io::Result<Command> {
    for relative in ["home", "base", "config", "bin", "tmp", "appdata", "local"] {
        std::fs::create_dir_all(root.join(relative))?;
    }
    atomic_write(root, "user-config.toml", b"# isolated test input\n")?;
    let mut command = Command::new(std::env::current_exe()?);
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
        .env("HOME", root.join("home"))
        .env("CSQ_HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("CSQ_BASE_DIR", root.join("base"))
        .env("CLAUDE_CONFIG_DIR", root.join("config"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("APPDATA", root.join("appdata"))
        .env("LOCALAPPDATA", root.join("local"))
        .env("TMPDIR", root.join("tmp"))
        .env("TEMP", root.join("tmp"))
        .env("TMP", root.join("tmp"))
        .env("PATH", root.join("bin"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("CODEX_USER_CONFIG", root.join("user-config.toml"))
        .env("CSQ_SECRET_BACKEND", "in-memory")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(root.join(format!("{role}.stdout")))?)
        .stderr(std::fs::File::create(root.join(format!("{role}.stderr")))?);
    Ok(command)
}

fn account() -> AccountNum {
    AccountNum::try_from(1_u16).expect("private fixture slot")
}

fn held(root: &Path) -> bool {
    matches!(
        AccountLoginLock::acquire(&root.join("base"), account()),
        Ok(AcquireOutcome::Held { .. })
    )
}

fn install_prior(default: bool) {
    // SAFETY: private fixture process only; initialized mask and a static
    // signal-safe atomic-only callback (or POSIX SIG_DFL) form the full action.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = if default {
        libc::SIG_DFL
    } else {
        prior_sigint as *const () as usize
    };
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: action owns the writable signal mask.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: the complete initialized action is installed in this fixture;
    // no signal state in the outer test runner is modified.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) },
        0
    );
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

fn write_synthetic_auth(root: &Path) {
    let config = PathBuf::from(std::env::var_os("CODEX_HOME").unwrap());
    assert_private_vendor_home(root, &config);
    // Mirror the existing CodexCredentialFile login fixture; synthetic strings
    // never authenticate anything and no upstream request is made.
    let body = serde_json::json!({
        "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
        "tokens": {"account_id": "TEST-INPUT-codex-custody",
            "access_token": "eyJhbGciOiJIUzI1NiJ9.test-at.sig",
            "refresh_token": "rt_TEST_INPUT_ONLY",
            "id_token": "eyJhbGciOiJIUzI1NiJ9.test-id.sig"},
        "last_refresh": "2100-01-01T00:00:00Z"
    });
    atomic_write(
        &config,
        "auth.json",
        serde_json::to_string(&body).unwrap().as_bytes(),
    )
    .unwrap();
}

// SCM_RIGHTS duplicates the actual vendor's stdout write descriptor into
// its driver's controller. The directly owned sidecar is a SIBLING, never an
// orphan/grandchild. Every reported descriptor is immediately made an OwnedFd.
fn send_stdout_fd(stream: &UnixStream) -> std::io::Result<()> {
    let mut byte = *b"F";
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: the zeroed msghdr is fully initialized with valid owned buffers.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // SAFETY: size describes one RawFd; the aligned control buffer is larger.
    message.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) } as _;
    assert!(message.msg_controllen as usize <= std::mem::size_of_val(&control));
    // SAFETY: header/data fall within the initialized aligned control buffer;
    // stdout remains open in this vendor for the complete sendmsg syscall.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), libc::STDOUT_FILENO);
        if libc::sendmsg(stream.as_raw_fd(), &message, 0) != 1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// Bounded readiness wait that never touches socket options, so it behaves the
// same whether or not the peer has already closed. EINTR retries against the
// one fixed deadline; expiry is an explicit TimedOut, never a silent pass.
fn wait_readable(stream: &UnixStream, budget: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = libc::c_int::try_from(remaining.as_millis()).unwrap_or(libc::c_int::MAX);
        let mut pollfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd for a socket `stream` keeps open.
        let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "private descriptor transfer not readable within budget",
            ));
        }
        if pollfd.revents & libc::POLLNVAL != 0 {
            return Err(std::io::Error::other(
                "private descriptor transfer socket invalid",
            ));
        }
        // POLLIN or POLLHUP/POLLERR: recvmsg now returns without blocking and
        // reports queued data, EOF (0 bytes), or the socket error itself.
        return Ok(());
    }
}

fn receive_stdout_fd(stream: &UnixStream) -> std::io::Result<OwnedFd> {
    // Accepted sockets may retain nonblocking state on some Unix platforms.
    // Normalize explicitly so the bounded readiness wait below governs this
    // transfer instead of an immediate WouldBlock before the sender runs.
    stream.set_nonblocking(false)?;
    // Bound the wait with poll(2), NOT SO_RCVTIMEO. The sender drops its end
    // immediately after sendmsg; once that close lands, darwin's sosetopt
    // refuses every setsockopt on the disconnected socket with EINVAL even
    // though the byte and SCM_RIGHTS descriptor are still queued. poll reports
    // the queued data (POLLIN, with POLLHUP) and recvmsg still delivers it.
    wait_readable(stream, BUDGET)?;
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: initialized writable message buffers live throughout recvmsg.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    // Allocate capacity before receiving descriptors, so taking ownership of
    // every possible reported RawFd needs no allocation after recvmsg.
    let mut descriptors = Vec::<OwnedFd>::with_capacity(
        std::mem::size_of_val(&control) / std::mem::size_of::<RawFd>(),
    );
    // SAFETY: valid socket and writable initialized message buffers.
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: libc's CMSG walkers delimit kernel-produced ancillary messages.
    // Own ALL returned SCM_RIGHTS descriptors before checking payload shape,
    // so every subsequent error/panic closes every delivered descriptor.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let payload =
                    ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                for index in 0..payload / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header)
                            .add(index * std::mem::size_of::<RawFd>())
                            .cast::<RawFd>(),
                    );
                    if fd >= 0 {
                        descriptors.push(OwnedFd::from_raw_fd(fd));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received != 1
        || byte != *b"F"
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || descriptors.len() != 1
    {
        return Err(std::io::Error::other(
            "invalid private stdout descriptor transfer",
        ));
    }
    let fd = descriptors.pop().unwrap();
    // SAFETY: fd is now exclusively owned; mark it close-on-exec before any
    // sidecar spawn. Command's explicit stdout mapping duplicates it to fd 1.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

// This fixture owns a clone of the ORIGINAL adopted std::process::Child.
// Cleanup never targets an inferred PID. Normal publication evidence remains
// the production owner's typed receipt; any fixture fallback is explicit UND.
#[derive(Clone)]
enum FixtureVendorPhase {
    BeforeHelper,
    NoVendorBeforeSpawn,
    SpawnAttemptStarted,
    NotSpawned,
    Adopted(Arc<Mutex<Child>>),
}

#[cfg(all(test, unix))]
fn record_exited_child_lease(
    root: &Path,
    phase: &Mutex<FixtureVendorPhase>,
    observation: login_cancel_guard::PipedLoginObservation,
) {
    let FixtureVendorPhase::Adopted(child) = phase.lock().unwrap().clone() else {
        panic!("private WNOWAIT observation requires the actual adopted child");
    };
    let child = child.lock().unwrap();
    assert_eq!(child.id(), observation.child_id);
    if !login_child_custody::group::observe_owned_unreaped_for_test(&child)
        .expect("private original-child WNOWAIT observation")
    {
        return;
    }
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: the exact owned Child was observed exited with WNOWAIT above;
    // its unreaped leader still reserves this private group's numeric identity.
    let pgid = unsafe { libc::getpgid(pid) };
    // Capture errno before any other operation can replace it.
    let pgid_errno = if pgid == -1 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    assert_eq!(
        pgid, pid,
        "private exited leader getpgid errno={pgid_errno:?}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        pgid == -1 && pgid_errno == Some(libc::ESRCH),
        "private exited leader getpgid={pgid}, errno={pgid_errno:?}"
    );
    let proof = serde_json::json!({
        "child_id": child.id(), "exited_wnowait": true, "pgid": pgid,
        "pgid_errno": pgid_errno,
        "reaped_pid": serde_json::Value::Null,
        "reader_is_finished": observation.reader_is_finished,
        "reader_joined_thread": observation.reader_joined_thread_id.map(|id| format!("{id:?}")),
    });
    drop(child);
    atomic_write(
        root,
        "exited-child-lease",
        serde_json::to_string(&proof).unwrap().as_bytes(),
    )
    .unwrap();
}

#[derive(Clone)]
struct FixtureAbort {
    requested: Arc<AtomicBool>,
    root: PathBuf,
}
impl FixtureAbort {
    fn release_all(&self) {
        self.requested.store(true, Ordering::SeqCst);
        for (name, bytes) in [
            ("release", b"0".as_slice()),
            ("reader-release", b"cleanup".as_slice()),
            ("holder-release", b"cleanup".as_slice()),
            ("sidecar-stop", b"cleanup".as_slice()),
        ] {
            let _ = atomic_write(&self.root, name, bytes);
        }
    }
}
struct CallbackUnwind(FixtureAbort);
impl Drop for CallbackUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.release_all();
        }
    }
}

struct FixtureVendorCustody {
    phase: Arc<Mutex<FixtureVendorPhase>>,
    operation_finished: Arc<AtomicBool>,
    abort: FixtureAbort,
    thread: Option<std::thread::JoinHandle<std::io::Result<serde_json::Value>>>,
}
impl FixtureVendorCustody {
    fn new(root: &Path) -> Self {
        let phase = Arc::new(Mutex::new(FixtureVendorPhase::BeforeHelper));
        let operation_finished = Arc::new(AtomicBool::new(false));
        let abort = FixtureAbort {
            requested: Arc::new(AtomicBool::new(false)),
            root: root.to_path_buf(),
        };
        let worker_phase = Arc::clone(&phase);
        let finished = Arc::clone(&operation_finished);
        let worker_abort = abort.clone();
        let thread = std::thread::spawn(move || -> std::io::Result<serde_json::Value> {
            let mut adopted_at = None;
            loop {
                let phase = worker_phase
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                let aborting = worker_abort.requested.load(Ordering::SeqCst)
                    || worker_abort.root.join("finish").exists();
                let done = finished.load(Ordering::SeqCst);
                match phase {
                    FixtureVendorPhase::Adopted(child) => {
                        let since = *adopted_at.get_or_insert_with(Instant::now);
                        let expired = since.elapsed() >= BUDGET * 3;
                        if !done && !aborting && !expired {
                            std::thread::yield_now();
                            continue;
                        }
                        // On normal helper return the same actual Child has
                        // already been reaped by OwnedLoginChild. This wait
                        // reads that Child's cached REAL status. On fallback
                        // the retained original handle is killed/waited here.
                        let mut actual = None;
                        if done {
                            let mut child = child
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            actual = child.try_wait().ok().flatten();
                        }
                        let mut used_fallback = false;
                        if actual.is_none() {
                            used_fallback = true;
                            worker_abort.release_all();
                            let _ = poll(|| {
                                let mut child = child
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                match child.try_wait() {
                                    Ok(Some(status)) => {
                                        actual = Some(status);
                                        true
                                    }
                                    _ => false,
                                }
                            });
                        }
                        let mut child = child
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let original_pid = child.id();
                        let status = match actual {
                            Some(status) => status,
                            None => {
                                let _ = child.kill();
                                child.wait()?
                            }
                        };
                        // Call wait on the SAME retained handle even if a
                        // previous actual try_wait populated its cached status.
                        let confirmed = child.wait()?;
                        if confirmed != status {
                            return Err(std::io::Error::other(
                                "same Child status disagrees during fixture cleanup",
                            ));
                        }
                        drop(child);
                        let proof = serde_json::json!({"kind": "ACTUAL_OWNED_STUB_WAIT", "driver_pid": std::process::id(),
                            "original_pid": original_pid, "reaped_pid": original_pid,
                            "code": status.code(), "signal": status.signal(), "fallback_used": used_fallback,
                            "cleanup_reaper": if used_fallback { "fixture_original_handle_fallback" } else { "production_owner_cached_actual_status" }});
                        atomic_write(
                            &worker_abort.root,
                            "vendor-cleanup-terminal",
                            serde_json::to_string(&proof).unwrap().as_bytes(),
                        )?;
                        return Ok(proof);
                    }
                    FixtureVendorPhase::BeforeHelper
                    | FixtureVendorPhase::NoVendorBeforeSpawn
                    | FixtureVendorPhase::NotSpawned => {
                        // Initial absence is NOT terminal while helper is live.
                        if done {
                            let proof = serde_json::json!({"kind": "NO_VENDOR_SPAWNED", "driver_pid": std::process::id(),
                                "fallback_used": false, "terminal_after_helper_scope": true,
                                "spawn_phase": match phase { FixtureVendorPhase::BeforeHelper => "BeforeHelper", FixtureVendorPhase::NoVendorBeforeSpawn => "NoVendorBeforeSpawn", FixtureVendorPhase::NotSpawned => "NotSpawned", _ => unreachable!() }});
                            atomic_write(
                                &worker_abort.root,
                                "vendor-cleanup-terminal",
                                serde_json::to_string(&proof).unwrap().as_bytes(),
                            )?;
                            return Ok(proof);
                        }
                    }
                    FixtureVendorPhase::SpawnAttemptStarted => {
                        // Started is NOT absence proof. Actual command.spawn
                        // must report Err or immediately deliver its adopted
                        // actual Child. Never manufacture a terminal receipt.
                    }
                }
                std::thread::yield_now();
            }
        });
        Self {
            phase,
            operation_finished,
            abort,
            thread: Some(thread),
        }
    }
    fn operation_finished(&self) {
        self.operation_finished.store(true, Ordering::SeqCst);
    }
    fn finish(&mut self) -> std::io::Result<serde_json::Value> {
        self.operation_finished();
        self.thread
            .take()
            .expect("one actual fixture controller join")
            .join()
            .map_err(|_| std::io::Error::other("original Child cleanup controller panicked"))?
    }
}
impl Drop for FixtureVendorCustody {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.abort.release_all();
            self.operation_finished();
            match thread.join() { Ok(Ok(_)) => {}, Ok(Err(error)) => eprintln!("LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: actual stub cleanup controller error: {error}"), Err(_) => eprintln!("LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: actual stub cleanup controller panicked") }
        }
    }
}

struct OwnedSidecar {
    child: Option<Child>,
    root: PathBuf,
    original_pid: u32,
}
impl OwnedSidecar {
    fn record(&mut self, status: ExitStatus, cleanup_killed: bool) {
        self.child.take();
        let old = LIVE_OWNED_SIDECARS.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(old, 1, "exactly one directly owned sidecar must be reaped");
        let receipt = serde_json::json!({"original_pid": self.original_pid,
            "reaped_pid": self.original_pid, "code": status.code(), "signal": status.signal(),
            "cleanup_killed": cleanup_killed, "live_owned_sidecars": LIVE_OWNED_SIDECARS.load(Ordering::SeqCst)});
        atomic_write(
            &self.root,
            "holder-reaped",
            serde_json::to_string(&receipt).unwrap().as_bytes(),
        )
        .unwrap();
    }
    fn reap(&mut self) -> std::io::Result<()> {
        let mut status = None;
        let observed = poll(|| match self.child.as_mut().unwrap().try_wait() {
            Ok(Some(actual)) => {
                status = Some(actual);
                true
            }
            _ => false,
        });
        if observed {
            self.record(status.unwrap(), false);
            return Ok(());
        }
        // Explicitly approved fixture cleanup acts on the retained original
        // sidecar Child, never a bare/reused PID or the production vendor.
        let child = self.child.as_mut().unwrap();
        let _ = child.kill();
        let actual = child.wait()?;
        self.record(actual, true);
        Ok(())
    }
}
impl Drop for OwnedSidecar {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            match child.wait() {
                Ok(actual) => self.record(actual, true),
                Err(error) => eprintln!(
                    "LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: owned sidecar actual reap failed: {error}"
                ),
            }
        }
    }
}

struct SidecarController {
    root: PathBuf,
    thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    // Drop joins the controller before this owned short socket directory drops.
    _socket_dir: tempfile::TempDir,
    holder_created: Arc<AtomicBool>,
}
impl SidecarController {
    fn start(root: &Path, force_long_socket: bool) -> std::io::Result<Self> {
        // The leg's TMPDIR/root may exceed sockaddr_un path capacity. This
        // randomized test-owned directory has a short explicit Unix path.
        let socket_dir = tempfile::Builder::new()
            .prefix("csq-fd-")
            .tempdir_in("/tmp")?;
        let socket_path = socket_dir.path().join(if force_long_socket {
            "s".repeat(120)
        } else {
            "s".to_owned()
        });
        let path_bytes = socket_path.as_os_str().as_bytes().len();
        if !force_long_socket {
            assert!(
                path_bytes < 100,
                "LOGIN_CODEX_CTRLC_SHORT_SOCKET_PATH_LENGTH"
            );
        }
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                // Capture the ACTUAL public bind error; raw errno may be None
                // when std rejects the path before calling the kernel.
                let proof = serde_json::json!({"operation": "UnixListener::bind",
                    "driver_pid": std::process::id(), "socket_path_bytes": path_bytes,
                    "raw_os_error": error.raw_os_error(), "error_kind": format!("{:?}", error.kind()),
                    "error": error.to_string(), "forced_long_socket": force_long_socket});
                atomic_write(
                    root,
                    "socket-bind-error",
                    serde_json::to_string(&proof).unwrap().as_bytes(),
                )?;
                return Err(error);
            }
        };
        atomic_write(
            root,
            "stdout-sidecar-path",
            socket_path
                .to_str()
                .expect("ASCII private socket path")
                .as_bytes(),
        )?;
        listener.set_nonblocking(true)?;
        let owned_root = root.to_path_buf();
        let holder_created = Arc::new(AtomicBool::new(false));
        let worker_created = Arc::clone(&holder_created);
        let thread = std::thread::Builder::new()
            .name("private-stdout-sidecar".to_owned())
            .spawn(move || -> std::io::Result<()> {
                let mut accepted = None;
                if !poll(|| {
                    if owned_root.join("sidecar-stop").exists() {
                        return true;
                    }
                    if let Ok((stream, _)) = listener.accept() {
                        accepted = Some(stream);
                        return true;
                    }
                    false
                }) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "private descriptor sender did not connect",
                    ));
                }
                let Some(stream) = accepted else {
                    return Ok(());
                };
                let fd = receive_stdout_fd(&stream)?;
                drop(stream);
                let mut command = selected_command(&owned_root, "stdout-sidecar")?;
                command.stdout(Stdio::from(fd));
                let holder_root = owned_root.clone();
                let child = command.spawn()?;
                let original_pid = child.id();
                let mut holder = OwnedSidecar {
                    child: Some(child),
                    root: holder_root,
                    original_pid,
                };
                worker_created.store(true, Ordering::SeqCst);
                LIVE_OWNED_SIDECARS.fetch_add(1, Ordering::SeqCst);
                // Command retains its Stdio; drop it so ONLY vendor and actual
                // sidecar own write ends, and sidecar exit can deliver genuine EOF.
                drop(command);
                let deadline = Instant::now() + BUDGET * 3;
                while !owned_root.join("holder-release").exists() && Instant::now() < deadline {
                    std::thread::yield_now();
                }
                if !owned_root.join("holder-release").exists() {
                    atomic_write(&owned_root, "holder-release", b"bounded fixture cleanup")?;
                }
                holder.reap()
            })?;
        Ok(Self {
            root: root.to_path_buf(),
            thread: Some(thread),
            _socket_dir: socket_dir,
            holder_created,
        })
    }
    fn finish(&mut self) -> std::io::Result<()> {
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !self.holder_created.load(Ordering::SeqCst) {
                // Actual controller thread has terminated; its explicit spawn
                // phase never adopted a holder. This is not PID absence.
                let proof = serde_json::json!({"kind": "NO_HOLDER_SPAWNED", "driver_pid": std::process::id(), "controller_joined": true});
                atomic_write(
                    &self.root,
                    "holder-cleanup-terminal",
                    serde_json::to_string(&proof).unwrap().as_bytes(),
                )?;
            }
            result.map_err(|_| std::io::Error::other("private sidecar controller panicked"))??;
        }
        Ok(())
    }
}
impl Drop for SidecarController {
    fn drop(&mut self) {
        let _ = atomic_write(&self.root, "holder-release", b"RAII cleanup");
        let _ = atomic_write(&self.root, "reader-release", b"RAII cleanup");
        let _ = atomic_write(&self.root, "sidecar-stop", b"RAII cleanup");
        if let Err(error) = self.finish() {
            eprintln!("LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: controller join: {error}");
        }
    }
}

fn run_stdout_sidecar(root: &Path) -> ! {
    // No stdout writes: merely keep the inherited actual pipe descriptor open.
    // The parent controller owns the sole actual sidecar Child handle.
    atomic_write(
        root,
        "holder-ready",
        std::process::id().to_string().as_bytes(),
    )
    .unwrap();
    let mut previous = Vec::new();
    loop {
        if let Ok(nonce) = std::fs::read(root.join("holder-ping")) {
            if nonce != previous {
                atomic_write(root, "holder-ping-ack", &nonce).unwrap();
                previous = nonce;
            }
        }
        if root.join("holder-release").exists() {
            std::process::exit(0);
        }
        std::thread::yield_now();
    }
}

fn run_vendor(root: &Path, ignore: bool, hold_stdout: bool, ignore_release: bool) -> ! {
    // SAFETY: this is only the owned private vendor process; the complete
    // disposition is initialized before publishing its readiness marker.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = if ignore { libc::SIG_IGN } else { libc::SIG_DFL };
    // SAFETY: action owns the writable mask.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: initialized action, private fixture process only.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) },
        0
    );
    // Separate libtest's partial progress line from the actual URL payload.
    println!("\n{URL_LINE}");
    println!("TEST-INPUT device code: ABCD-EFGH");
    std::io::stdout().flush().unwrap();
    if hold_stdout {
        let socket_path = PathBuf::from(
            std::fs::read_to_string(root.join("stdout-sidecar-path"))
                .expect("atomic explicit private socket path"),
        );
        assert!(socket_path.is_absolute());
        let stream = UnixStream::connect(&socket_path).unwrap();
        send_stdout_fd(&stream).unwrap();
        drop(stream);
        assert!(
            poll(|| root.join("holder-ready").exists()),
            "owned sidecar did not take stdout descriptor"
        );
    }
    // Exit lifeline: the kernel closes this write end when the vendor exits.
    let _life = std::fs::OpenOptions::new()
        .write(true)
        .open(root.join("vendor-life"))
        .unwrap();
    atomic_write(
        root,
        "vendor-ready",
        std::process::id().to_string().as_bytes(),
    )
    .unwrap();
    let mut seen = Vec::new();
    loop {
        if let Ok(nonce) = std::fs::read(root.join("ping")) {
            if nonce != seen {
                atomic_write(root, "ping-ack", &nonce).unwrap();
                seen = nonce;
            }
        }
        if let Ok(release) = std::fs::read_to_string(root.join("release")) {
            if ignore_release {
                std::thread::yield_now();
                continue;
            }
            let code = release.parse::<i32>().expect("atomic private release code");
            assert_eq!(code, 0);
            write_synthetic_auth(root);
            atomic_write(root, "vendor-completed", b"0").unwrap();
            std::process::exit(code);
        }
        std::thread::yield_now();
    }
}

fn canonical_present(root: &Path) -> bool {
    let base = root.join("base");
    csq_core::accounts::profiles::resolve_slot_to_uuid(&base, 1).is_some()
        || base.join("config-1/.csq-account").exists()
}

fn canonical_valid(root: &Path) -> bool {
    let base = root.join("base");
    let Some(uuid) = csq_core::accounts::profiles::resolve_slot_to_uuid(&base, 1) else {
        return false;
    };
    let path = csq_core::accounts::identity_store::credentials_codex_path_for(&base, uuid);
    csq_core::credentials::load(&path)
        .ok()
        .and_then(|creds| creds.codex().cloned())
        .is_some_and(|creds| creds.tokens.account_id.as_deref() == Some("TEST-INPUT-codex-custody"))
        && base.join("config-1/.csq-account").exists()
}

fn run_driver_body(root: &Path, role: &str, custody: &FixtureVendorCustody) -> i32 {
    install_prior(false);
    let fd_mode = role == "driver-fd" || role == "driver-fd-long";
    let mut sidecar = if fd_mode {
        match SidecarController::start(root, role == "driver-fd-long") {
            Ok(controller) => Some(controller),
            Err(error) => {
                // start's fallible setup precedes its controller thread and
                // every vendor/holder spawn. This is a terminal phase proof,
                // never an inference from missing PID/receipt files.
                let proof = serde_json::json!({"kind": "NO_VENDOR_SPAWNED",
                    "stage": "sidecar_setup_before_helper", "driver_pid": std::process::id(),
                    "error": error.to_string()});
                atomic_write(
                    root,
                    "driver-setup-terminal",
                    serde_json::to_string(&proof).unwrap().as_bytes(),
                )
                .unwrap();
                panic!("private sidecar setup failed before any vendor spawn: {error}");
            }
        }
    } else {
        None
    };
    let cleanup_root = root.to_path_buf();
    // EOF independently releases the actual inert vendor and reader gate;
    // production remains the only Child reaper and actual JoinHandle owner.
    let _cleanup = std::thread::spawn(move || {
        let mut byte = [0_u8; 1];
        loop {
            match std::io::Read::read(&mut std::io::stdin(), &mut byte) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => {
                    for (name, bytes) in [
                        ("release", b"0".as_slice()),
                        ("reader-release", b"done".as_slice()),
                        ("holder-release", b"EOF".as_slice()),
                        ("sidecar-stop", b"EOF".as_slice()),
                        ("finish", b"EOF".as_slice()),
                    ] {
                        atomic_write(&cleanup_root, name, bytes).unwrap();
                    }
                    break;
                }
                Ok(_) => {}
            }
        }
    });
    let lock = match AccountLoginLock::acquire(&root.join("base"), account()).unwrap() {
        AcquireOutcome::Acquired(lock) => lock,
        _ => panic!("private fixture account lock unexpectedly held"),
    };
    assert!(!canonical_present(root));
    let vendor_role = if fd_mode {
        "vendor-fd"
    } else if role == "driver-fallback-timeout" {
        "vendor-stubborn"
    } else if role == "driver-default" {
        "vendor-default"
    } else {
        "vendor-ignore"
    };
    let mut command = selected_command(root, vendor_role).unwrap();
    command.stdout(Stdio::piped());
    if role == "driver-spawn-error" {
        command = Command::new(root.join("bin/absent-private-fixture-executable"));
        command.env_clear().stdout(Stdio::piped());
    }
    let caller_thread = std::thread::current().id();
    let mut callback_count = 0_usize;
    let mut url_callbacks = 0_usize;
    let mut actual_receipt = None;
    let phase_for_spawn = Arc::clone(&custody.phase);
    let phase_for_adopt = Arc::clone(&custody.phase);
    let phase_for_observe = Arc::clone(&custody.phase);
    let callback_abort = custody.abort.clone();
    let gate_abort = custody.abort.clone();
    let gate_root = root.to_path_buf();
    let mut input = std::io::Cursor::new(Vec::<u8>::new());
    // Match the production call: StdoutLock stays held across perform_with.
    // Callback asserts caller-thread execution BEFORE recursively teeing stdout.
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let result = csq_core::providers::codex::login::perform_with(
        &root.join("base"),
        account(),
        &mut input,
        &mut writer,
        || csq_core::providers::codex::keychain::ProbeResult::Absent,
        || panic!("private Absent probe must never purge a real keychain"),
        |config_dir| {
            assert_private_vendor_home(root, config_dir);
            command.env("CODEX_HOME", config_dir);
            let timeout = if fd_mode {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(300)
            };
            let on_line = |line: String| {
                let _on_unwind = CallbackUnwind(callback_abort.clone());
                assert_eq!(
                    std::thread::current().id(),
                    caller_thread,
                    "{CALLBACK_ASSERTION}"
                );
                if role == "driver-callback-unwind" {
                    atomic_write(
                        root,
                        "callback-unwind-entered",
                        b"actual calling-thread callback panic",
                    )
                    .unwrap();
                    panic!("private actual callback unwind control");
                }
                callback_count += 1;
                println!("{line}");
                if line == URL_LINE {
                    url_callbacks += 1;
                    atomic_write(root, "callback-ready", b"URL observed on calling thread")
                        .unwrap();
                }
            };
            let notice = |event: login_child_custody::TimeoutNotice| {
                let _on_unwind = CallbackUnwind(callback_abort.clone());
                if fd_mode {
                    atomic_write(root, "timeout-notice", event.tag().as_bytes()).unwrap();
                }
            };
            let gate = move || {
                let _on_unwind = CallbackUnwind(gate_abort);
                let reader_id = format!("{:?}", std::thread::current().id());
                atomic_write(&gate_root, "reader-eof-held", reader_id.as_bytes()).unwrap();
                assert!(
                    poll(|| gate_root.join("reader-release").exists()),
                    "private real-reader EOF gate not released"
                );
            };
            let hooks = login_cancel_guard::PipedLoginTestHooks::new(gate, |observation| {
                let _on_unwind = CallbackUnwind(callback_abort.clone());
                if fd_mode
                    && observation.reaped_status.is_none()
                    && !observation.reader_is_finished
                    && observation.reader_joined_thread_id.is_none()
                {
                    record_exited_child_lease(root, &phase_for_observe, observation);
                }
                if let Some(status) = observation.reaped_status {
                    actual_receipt = Some((
                        observation.child_id,
                        status,
                        observation.reader_joined_thread_id,
                    ));
                }
            })
            .with_spawn_outcome(move |outcome| {
                let phase = match outcome {
                    login_cancel_guard::PipedLoginSpawnOutcome::NoVendorBeforeSpawn => {
                        FixtureVendorPhase::NoVendorBeforeSpawn
                    }
                    login_cancel_guard::PipedLoginSpawnOutcome::SpawnAttemptStarted => {
                        FixtureVendorPhase::SpawnAttemptStarted
                    }
                    login_cancel_guard::PipedLoginSpawnOutcome::NotSpawned => {
                        FixtureVendorPhase::NotSpawned
                    }
                };
                *phase_for_spawn
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = phase;
            })
            .with_adopted_child(move |child| {
                // Store the actual Arc FIRST. No IO or fallible setup precedes it.
                *phase_for_adopt
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    FixtureVendorPhase::Adopted(child);
            });
            let result = login_cancel_guard::spawn_cli_piped_login_observed_receipt(
                &mut command,
                timeout,
                lock,
                "Codex",
                on_line,
                notice,
                hooks,
            );
            match result {
                Ok(receipt) => {
                    let status = receipt.reaped_status();
                    actual_receipt = Some((
                        receipt.child_id(),
                        status,
                        receipt.reader_joined_thread_id(),
                    ));
                    Ok(status)
                }
                Err(error) => {
                    if let Some(cancelled) =
                        error.downcast_ref::<login_cancel_guard::CliLoginCancelled>()
                    {
                        if let (Some(pid), Some(status)) =
                            (cancelled.child_id(), cancelled.reaped_status())
                        {
                            actual_receipt =
                                Some((pid, status, cancelled.reader_joined_thread_id()));
                        }
                    }
                    Err(error)
                }
            }
        },
    );
    custody.operation_finished();
    if fd_mode {
        // Actual perform_with has returned here. A join-removal mutant must
        // expose real early return/publication, not just a waiter attempt.
        atomic_write(
            root,
            "core-returned",
            if result.is_ok() {
                b"published"
            } else {
                b"refused"
            },
        )
        .unwrap();
        if let Some(controller) = sidecar.as_mut() {
            controller.finish().unwrap();
        }
    }
    let exit = result
        .as_ref()
        .err()
        .map(login_cancel_guard::cli_error_exit_code)
        .unwrap_or(0);
    let mut publications = 0_usize;
    let mut inert_post = || {
        publications += 1;
        atomic_write(root, "post-called", publications.to_string().as_bytes()).unwrap();
    };
    if result.is_ok() {
        inert_post();
    }
    let vendor_pid: u32 = std::fs::read_to_string(root.join("vendor-ready"))
        .unwrap()
        .parse()
        .unwrap();
    let (reaped_pid, code, signal, reader_joined) = match actual_receipt {
        Some((pid, status, joined)) => (
            Some(pid),
            status.code(),
            status.signal(),
            joined.map(|id| format!("{id:?}")),
        ),
        None => (None, None, None, None),
    };
    let receipt = serde_json::json!({
        "vendor_pid": vendor_pid, "reaped_pid": reaped_pid,
        "vendor_code": code, "vendor_signal": signal,
        "reader_joined_thread": reader_joined,
        "caller_thread": format!("{caller_thread:?}"),
        "callback_count": callback_count, "url_callbacks": url_callbacks,
        "exit": exit, "publication": publications,
        "canonical_present": canonical_present(root), "canonical_valid": canonical_valid(root),
        "live_owned_sidecars": LIVE_OWNED_SIDECARS.load(Ordering::SeqCst),
        "prior_signals_at_return": PRIOR_SIGNALS.load(Ordering::SeqCst),
    });
    atomic_write(
        root,
        "reaped-receipt",
        serde_json::to_string(&receipt).unwrap().as_bytes(),
    )
    .unwrap();
    drop(writer);
    let deadline = Instant::now() + BUDGET;
    loop {
        if root.join("finish").exists() {
            return exit;
        }
        assert!(
            Instant::now() < deadline,
            "private fixture controller never finished"
        );
        std::thread::yield_now();
    }
}

fn run_driver(root: &Path, role: &str) -> ! {
    let mut custody = FixtureVendorCustody::new(root);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_driver_body(root, role, &custody)
    }));
    if result.is_err() {
        custody.abort.release_all();
    }
    let vendor = custody
        .finish()
        .expect("original inert Child custody must finish before driver exit");
    let holder = if role != "driver-fd" && role != "driver-fd-long" {
        serde_json::json!({"kind": "NO_HOLDER_REQUESTED"})
    } else if let Ok(bytes) = std::fs::read(root.join("holder-reaped")) {
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .expect("atomic actual holder wait proof")
    } else if let Ok(bytes) = std::fs::read(root.join("holder-cleanup-terminal")) {
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("atomic no-holder terminal")
    } else if root.join("driver-setup-terminal").exists() {
        // SidecarController.start failed before starting its controller thread.
        serde_json::json!({"kind": "NO_HOLDER_SPAWNED", "driver_pid": std::process::id(), "stage": "sidecar_setup_before_thread"})
    } else {
        panic!("LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: holder terminal proof unavailable");
    };
    let fallback = vendor["fallback_used"] == true || holder["cleanup_killed"] == true;
    let terminal = serde_json::json!({"driver_pid": std::process::id(), "vendor": vendor, "holder": holder, "fallback_used": fallback});
    atomic_write(
        root,
        "driver-custody-terminal",
        serde_json::to_string(&terminal).unwrap().as_bytes(),
    )
    .unwrap();
    std::process::exit(match &result {
        Ok(exit) if !fallback => *exit,
        _ => 101,
    });
}

#[test]
#[ignore = "fixture dispatcher; invoked only by an owned subprocess with explicit role"]
fn login_codex_ctrlc_private_entry() {
    let _env_guard = csq_core::platform::test_env::lock();
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let role = role.to_str().expect("private fixture role");
    let root = PathBuf::from(std::env::var_os(ROOT).expect("private fixture root"));
    for (key, relative) in [
        ("HOME", "home"),
        ("CSQ_HOME", "home"),
        ("USERPROFILE", "home"),
        ("CSQ_BASE_DIR", "base"),
        ("CLAUDE_CONFIG_DIR", "config"),
        ("XDG_CONFIG_HOME", "config"),
        ("PATH", "bin"),
        ("TMPDIR", "tmp"),
        ("TEMP", "tmp"),
        ("TMP", "tmp"),
        ("APPDATA", "appdata"),
        ("LOCALAPPDATA", "local"),
        ("CODEX_USER_CONFIG", "user-config.toml"),
    ] {
        assert_eq!(
            std::env::var_os(key).as_deref(),
            Some(root.join(relative).as_os_str())
        );
    }
    assert_eq!(
        std::env::var("CSQ_SECRET_BACKEND").as_deref(),
        Ok("in-memory")
    );
    if role.starts_with("vendor-") {
        let home = PathBuf::from(std::env::var_os("CODEX_HOME").unwrap());
        assert_private_vendor_home(&root, &home);
    } else {
        assert!(std::env::var_os("CODEX_HOME").is_none());
    }
    match role {
        "vendor-default" => run_vendor(&root, false, false, false),
        "vendor-ignore" => run_vendor(&root, true, false, false),
        "vendor-fd" => run_vendor(&root, true, true, false),
        "vendor-stubborn" => run_vendor(&root, true, false, true),
        "stdout-sidecar" => run_stdout_sidecar(&root),
        "driver-default"
        | "driver-ignore"
        | "driver-control"
        | "driver-fd"
        | "driver-fd-long"
        | "driver-spawn-error"
        | "driver-callback-unwind"
        | "driver-fallback-timeout" => run_driver(&root, role),
        _ => panic!("unrecognized private fixture role"),
    }
}

/// SIGCONT on drop, so a panic while the driver is stopped never strands it.
struct StoppedDriver(libc::pid_t);
impl Drop for StoppedDriver {
    fn drop(&mut self) {
        // SAFETY: the pid is this test's own still-owned, unreaped driver.
        unsafe { libc::kill(self.0, libc::SIGCONT) };
    }
}

struct Driver {
    child: Option<Child>,
    input: Option<ChildStdin>,
    sandbox: Option<tempfile::TempDir>,
    pid: libc::pid_t,
    pgid_custody: bool,
    role: &'static str,
    logs_forwarded: bool,
    vendor_pid: Option<u32>,
    life: Option<std::fs::File>,
    preserve_sandbox: bool,
}

impl Driver {
    fn spawn(role: &'static str) -> Self {
        let sandbox = tempfile::tempdir().unwrap();
        let life_path = sandbox.path().join("vendor-life");
        let life_c = std::ffi::CString::new(life_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path inside this test's private sandbox.
        assert_eq!(unsafe { libc::mkfifo(life_c.as_ptr(), 0o600) }, 0);
        let life = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&life_path)
            .unwrap();
        let mut command = selected_command(sandbox.path(), role).unwrap();
        command.process_group(0).stdin(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let fixture = Self {
            child: Some(child),
            input,
            sandbox: Some(sandbox),
            pid,
            pgid_custody: true,
            role,
            logs_forwarded: false,
            vendor_pid: None,
            life: Some(life),
            preserve_sandbox: false,
        };
        // A fresh actual Child remains UNREAPED until cleanup completes.
        // getpgid binds the only terminal-signal target to its owned group.
        // SAFETY: pid came from this still-owned, unreaped Child. Query only.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        fixture
    }

    /// Freeze the driver (waitid(WSTOPPED|WNOWAIT) proves it stopped) so signals sent
    /// next are only pending: the 200ms production pump cannot act on them
    /// before the test has ordered the vendor's exit.
    fn stop(&self) -> StoppedDriver {
        assert!(self.pgid_custody);
        let guard = StoppedDriver(self.pid);
        // SAFETY: only this unreaped private driver PID is targeted.
        assert_eq!(unsafe { libc::kill(self.pid, libc::SIGSTOP) }, 0);
        // SAFETY: waitid with WNOWAIT only observes the state change and never
        // reaps: Child keeps sole ownership of the exit status, so a driver that
        // already died stays a zombie instead of being reaped before the guard's
        // SIGCONT (no PID-reuse window).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(
            info.si_code,
            libc::CLD_STOPPED,
            "driver exited instead of stopping"
        );
        guard
    }
    /// True once the kernel closed the vendor's FIFO write end: the vendor
    /// process exited. An event, not a duration; valid only after ready().
    fn vendor_exited(&self) -> bool {
        use std::io::Read;
        let mut byte = [0_u8; 1];
        let mut life = self.life.as_ref().unwrap();
        matches!(life.read(&mut byte), Ok(0))
    }
    fn root(&self) -> &Path {
        self.sandbox.as_ref().unwrap().path()
    }
    fn ready(&mut self) -> bool {
        if !poll(|| {
            self.root().join("vendor-ready").exists()
                || self.no_vendor_setup_terminal()
                || self.root().join("driver-custody-terminal").exists()
        }) {
            return false;
        }
        if self.no_vendor_setup_terminal() || !self.root().join("vendor-ready").exists() {
            return false;
        }
        let vendor_pid = std::fs::read_to_string(self.root().join("vendor-ready"))
            .expect("atomic selected vendor identity")
            .parse::<u32>()
            .expect("vendor PID");
        self.vendor_pid = Some(vendor_pid);
        self.assert_live_vendor_group();
        poll(|| self.root().join("callback-ready").exists())
    }
    fn assert_live_vendor_group(&self) {
        assert!(self.pgid_custody, "{PGID_ASSERTION}");
        let vendor_pid =
            libc::pid_t::try_from(self.vendor_pid.expect("actual ready vendor PID")).unwrap();
        // SAFETY: before any signal/release, the selected inert vendor remains
        // live under this unreaped driver. The typed reap later binds the same
        // PID to the production owner's original Child handle.
        assert_eq!(
            unsafe { libc::getpgid(vendor_pid) },
            vendor_pid,
            "{PGID_ASSERTION}"
        );
    }
    fn actual_reap_matches_spawn(&self, receipt: &serde_json::Value) -> bool {
        if std::fs::read(self.root().join("vendor-cleanup-terminal"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|proof| proof["fallback_used"] == true)
        {
            return false;
        }
        let expected_pid = self.vendor_pid.or_else(|| {
            std::fs::read_to_string(self.root().join("vendor-ready"))
                .ok()?
                .parse::<u32>()
                .ok()
        });
        expected_pid.is_some_and(|pid| receipt["vendor_pid"] == pid && receipt["reaped_pid"] == pid)
            && (receipt["vendor_code"].as_i64().is_some()
                != receipt["vendor_signal"].as_i64().is_some())
    }
    fn signal_group(&self) {
        self.assert_live_vendor_group();
        assert!(self.pgid_custody);
        // SAFETY: actual Child group leader stays unreaped; process_group(0)
        // created this fresh group and only these two private fixtures join it.
        assert_eq!(unsafe { libc::getpgid(self.pid) }, self.pid);
        // SAFETY: the checked group remains in our custody until cleanup.
        assert_eq!(unsafe { libc::kill(-self.pid, libc::SIGINT) }, 0);
    }
    fn notices(&self, role: &str) -> usize {
        std::fs::read_to_string(self.root().join(format!("{role}.stderr")))
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == NOTICE)
            .count()
    }
    fn ping(&self, nonce: &[u8]) -> bool {
        atomic_write(self.root(), "ping", nonce).unwrap();
        poll(|| std::fs::read(self.root().join("ping-ack")).ok().as_deref() == Some(nonce))
    }
    fn release(&self) {
        atomic_write(self.root(), "release", b"0").unwrap();
    }
    fn release_reader(&self) {
        atomic_write(self.root(), "reader-release", b"done").unwrap();
    }
    fn eof_held(&self) -> bool {
        poll(|| self.root().join("reader-eof-held").exists())
            && !self.root().join("reaped-receipt").exists()
            && held(self.root())
            && !canonical_present(self.root())
            && !self.root().join("post-called").exists()
    }
    fn actual_reader_join(&self, receipt: &serde_json::Value) -> bool {
        let reader_id = std::fs::read_to_string(self.root().join("reader-eof-held")).ok();
        reader_id
            .as_deref()
            .is_some_and(|id| receipt["reader_joined_thread"] == id)
            && receipt["reader_joined_thread"] != receipt["caller_thread"]
            && receipt["callback_count"]
                .as_u64()
                .is_some_and(|count| count >= 1)
            && receipt["url_callbacks"] == 1
            && std::fs::read_to_string(self.root().join(format!("{}.stdout", self.role)))
                .unwrap_or_default()
                .lines()
                .filter(|line| *line == URL_LINE)
                .count()
                == 1
    }

    fn receipt(&self) -> Option<serde_json::Value> {
        if !poll(|| self.root().join("reaped-receipt").exists()) {
            return None;
        }
        Some(
            serde_json::from_slice(&std::fs::read(self.root().join("reaped-receipt")).unwrap())
                .unwrap(),
        )
    }
    fn no_vendor_setup_terminal(&self) -> bool {
        std::fs::read(self.root().join("driver-setup-terminal"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|proof| {
                proof["kind"] == "NO_VENDOR_SPAWNED"
                    && proof["stage"] == "sidecar_setup_before_helper"
                    && proof["driver_pid"] == self.pid
            })
    }
    fn forward_driver_stderr(&mut self) {
        if self.logs_forwarded {
            return;
        }
        // Diagnostics do not certify a vendor/holder/driver reap.
        eprintln!("LOGIN_CODEX_CTRLC_DRIVER_STDERR_DIAGNOSTIC_ONLY");
        match std::fs::read_to_string(self.root().join(format!("{}.stderr", self.role))) {
            Ok(stderr) => {
                eprint!("{stderr}");
                self.logs_forwarded = true;
            }
            Err(error) => eprintln!("private driver stderr unavailable: {error}"),
        }
    }
    fn finish_and_reap(&mut self) -> Option<ExitStatus> {
        // Do NOT poll/reap the group leader before the sole vendor reaper has
        // returned. Atomic cooperative release is bounded even in the mutant.
        self.release();
        self.release_reader();
        atomic_write(self.root(), "holder-release", b"cleanup").unwrap();
        atomic_write(self.root(), "sidecar-stop", b"cleanup").unwrap();
        atomic_write(
            self.root(),
            "finish",
            b"finish and actually drain original handles",
        )
        .unwrap();
        self.input.take();
        let cleanup_deadline = Instant::now() + BUDGET * 3;
        while !self.root().join("driver-custody-terminal").exists() {
            if Instant::now() >= cleanup_deadline {
                return None;
            }
            std::thread::yield_now();
        }
        let terminal: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.root().join("driver-custody-terminal")).ok()?,
        )
        .ok()?;
        if terminal["driver_pid"] != self.pid {
            return None;
        }
        let vendor = &terminal["vendor"];
        let no_vendor = vendor["kind"] == "NO_VENDOR_SPAWNED";
        let actual_vendor = vendor["kind"] == "ACTUAL_OWNED_STUB_WAIT"
            && vendor["original_pid"] == vendor["reaped_pid"]
            && vendor["original_pid"].as_u64().is_some()
            && (vendor["code"].as_i64().is_some() != vendor["signal"].as_i64().is_some());
        if !no_vendor && !actual_vendor {
            return None;
        }
        let holder = &terminal["holder"];
        let no_holder =
            holder["kind"] == "NO_HOLDER_REQUESTED" || holder["kind"] == "NO_HOLDER_SPAWNED";
        let actual_holder = holder["original_pid"] == holder["reaped_pid"]
            && holder["original_pid"].as_u64().is_some()
            && holder["live_owned_sidecars"] == 0
            && (holder["code"].as_i64().is_some() != holder["signal"].as_i64().is_some());
        if !no_holder && !actual_holder {
            return None;
        }
        self.preserve_sandbox = no_vendor || terminal["fallback_used"] == true;
        // The body scope actually joined its holder controller and original
        // stub-handle cleanup controller before publishing this terminal.
        self.pgid_custody = false;
        self.input.take();
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        if !poll(|| match child.try_wait() {
            Ok(Some(actual)) => {
                status = Some(actual);
                true
            }
            Ok(None) => false,
            Err(_) => false,
        }) {
            // Only reached after explicit NO_VENDOR_SPAWNED or actual vendor
            // and holder reap proof: this original inert driver owns no child.
            let _ = child.kill();
            status = Some(child.wait().ok()?);
        }
        let actual = status?;
        self.child.take();
        let proof = serde_json::json!({"driver_pid": self.pid, "actual_code": actual.code(),
            "actual_signal": actual.signal(), "child_terminal_kind": if no_vendor { "NO_VENDOR_SPAWNED" } else { "ACTUAL_VENDOR_REAP" }, "custody": terminal});
        atomic_write(
            self.root(),
            "driver-reaped-proof",
            serde_json::to_string(&proof).unwrap().as_bytes(),
        )
        .unwrap();
        eprintln!("LOGIN_CODEX_CTRLC_DRIVER_REAP_RECEIPT: {proof}");
        if let Ok(bytes) = std::fs::read(self.root().join("socket-bind-error")) {
            if let Ok(error) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                eprintln!("LOGIN_CODEX_CTRLC_ACTUAL_SOCKET_BIND_ERROR: {error}");
            }
        }
        self.forward_driver_stderr();
        if terminal["fallback_used"] == true {
            eprintln!("LOGIN_CODEX_CTRLC_FIXTURE_FALLBACK_REAP_NO_PRODUCTION_CREDIT: fixture fallback actually reaped original handle; no normal production-reap credit");
        }
        Some(actual)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Close first so the independent private EOF lifeline also handles
        // unwinds; the fixture's production owner still performs the reap.
        self.input.take();
        if self.child.is_some() && self.finish_and_reap().is_none() {
            // Never turn PID absence into reap evidence or kill an unowned
            // orphan. Preserve private receipts on an unmeasurable cleanup.
            self.forward_driver_stderr();
            let root = self.sandbox.take().unwrap().keep();
            eprintln!(
                "LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: actual driver/vendor cleanup not proved: {}",
                root.display()
            );
        } else if self.preserve_sandbox {
            let root = self.sandbox.take().unwrap().keep();
            eprintln!("LOGIN_CODEX_CTRLC_PRIVATE_EVIDENCE_PRESERVED: actual driver and child custody receipts retained: {}", root.display());
        }
    }
}

fn actual_cancel_receipt(receipt: &serde_json::Value, signal: Option<i32>) -> bool {
    receipt["exit"] == 130
        && receipt["publication"] == 0
        && receipt["reaped_pid"] == receipt["vendor_pid"]
        && receipt["reaped_pid"].as_u64().is_some()
        && if let Some(signal) = signal {
            receipt["vendor_signal"] == signal && receipt["vendor_code"].is_null()
        } else {
            receipt["vendor_code"] == 0 && receipt["vendor_signal"].is_null()
        }
}

#[test]
fn login_codex_ctrlc_default_sigint_reaps_joins_cancel130_no_publish() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-default");
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let eof_held = ready && driver.eof_held();
    driver.release_reader();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let joined = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reader_join(r));
    let notices = driver.notices("driver-default");
    let status = driver.finish_and_reap();
    assert!(reaped, "{REAP_ASSERTION}");
    assert!(eof_held && joined, "{JOIN_ASSERTION}");
    assert!(
        ready
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, Some(libc::SIGINT))
                    && r["canonical_present"] == false
                    && r["canonical_valid"] == false)
            && status.is_some_and(|status| status.code() == Some(130))
            && notices == 1,
        "{DEFAULT_ASSERTION}"
    );
}

#[test]
fn login_codex_ctrlc_ignored_sigint_retains_lock_until_late_zero_reap() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-ignore");
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let cancelled = ready && poll(|| driver.notices("driver-ignore") > 0);
    let retained = cancelled
        && held(driver.root())
        && driver.ping(b"after-cancel-1")
        && !driver.root().join("reaped-receipt").exists();
    // The second interrupt is the product's explicit second-Ctrl-C kill
    // escalation, acted on by the 200ms pump. Deliver it while the driver is
    // stopped (a further SIGINT would coalesce into the same single pending
    // signal), release the vendor and wait for its ACTUAL exit before SIGCONT:
    // the late-zero outcome no longer depends on pump latency (an internal ticket). Lock
    // retention is asserted before the stop and again after the reap; nothing
    // is sampled while the driver is frozen, where no check could fail.
    let repeated = retained && {
        let stopped = driver.stop();
        driver.signal_group();
        driver.release();
        let exited = poll(|| driver.vendor_exited());
        drop(stopped);
        exited
    };
    driver.release();
    let eof_held = driver.eof_held();
    driver.release_reader();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let joined = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reader_join(r));
    let completed = driver.root().join("vendor-completed").exists();
    let notices = driver.notices("driver-ignore");
    let status = driver.finish_and_reap();
    assert!(reaped, "{REAP_ASSERTION}");
    assert!(eof_held && joined, "{JOIN_ASSERTION}");
    assert!(retained && repeated, "{RETAIN_ASSERTION}");
    assert!(
        completed
            && notices == 1
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, None)
                    && r["canonical_present"] == false
                    && r["canonical_valid"] == false)
            && status.is_some_and(|status| status.code() == Some(130)),
        "{LATE_ASSERTION}"
    );
}

#[test]
fn login_codex_ctrlc_no_cancel_actual_zero_publishes_once() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-control");
    let ready = driver.ready();
    let live = ready && held(driver.root()) && driver.ping(b"before-release-control");
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let eof_held = driver.eof_held();
    driver.release_reader();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let joined = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reader_join(r));
    let completed = driver.root().join("vendor-completed").exists();
    let post = std::fs::read(driver.root().join("post-called")).ok();
    let notices = driver.notices("driver-control");
    let status = driver.finish_and_reap();
    assert!(reaped, "{REAP_ASSERTION}");
    assert!(eof_held && joined, "{JOIN_ASSERTION}");
    assert!(
        live && completed
            && post.as_deref() == Some(b"1")
            && notices == 0
            && receipt.is_some_and(|r| r["exit"] == 0
                && r["publication"] == 1
                && r["vendor_code"] == 0
                && r["vendor_signal"].is_null()
                && r["canonical_present"] == true
                && r["canonical_valid"] == true)
            && status.is_some_and(|status| status.code() == Some(0)),
        "{CONTROL_ASSERTION}"
    );
}

#[test]
fn login_codex_ctrlc_owned_sidecar_open_stdout_retains_until_reap_join() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-fd");
    let ready = driver.ready();
    if driver.no_vendor_setup_terminal() {
        let actual_driver = driver.finish_and_reap();
        assert!(
            actual_driver.is_some(),
            "LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: setup driver actual reap unavailable"
        );
        panic!("LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: setup failed with NO_VENDOR_SPAWNED; actual driver reap recorded");
    }
    let holder_pid = std::fs::read_to_string(driver.root().join("holder-ready"))
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let holder_pgid = holder_pid.is_some_and(|pid| {
        // SAFETY: this is the fixture's direct, still-owned live sidecar.
        (unsafe { libc::getpgid(libc::pid_t::try_from(pid).unwrap()) }) == driver.pid
    });
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let exit_lease = if poll(|| driver.root().join("exited-child-lease").exists()) {
        Some(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(driver.root().join("exited-child-lease")).unwrap(),
            )
            .unwrap(),
        )
    } else {
        None
    };
    let original_exited_unreaped = exit_lease.as_ref().is_some_and(|proof| {
        let platform_pgid = (cfg!(target_os = "linux")
            && proof["pgid"] == proof["child_id"]
            && proof["pgid_errno"].is_null())
            || (cfg!(target_os = "macos")
                && proof["pgid"] == -1
                && proof["pgid_errno"] == libc::ESRCH);
        Some(proof["child_id"].as_u64().unwrap_or(0) as u32) == driver.vendor_pid
            && proof["exited_wnowait"] == true
            && platform_pgid
            && proof["reaped_pid"].is_null()
            && proof["reader_is_finished"] == false
            && proof["reader_joined_thread"].is_null()
    });
    let timeout = poll(|| {
        driver.root().join("timeout-notice").exists()
            || driver.root().join("core-returned").exists()
    });
    atomic_write(
        driver.root(),
        "holder-ping",
        b"live-fd-owner-after-original-exit",
    )
    .unwrap();
    let ping = poll(|| {
        std::fs::read(driver.root().join("holder-ping-ack"))
            .ok()
            .as_deref()
            == Some(b"live-fd-owner-after-original-exit")
    });
    let early_return_or_publication =
        driver.root().join("core-returned").exists() || canonical_present(driver.root());
    let open_retained = ready
        && holder_pgid
        && original_exited_unreaped
        && timeout
        && ping
        && held(driver.root())
        && !canonical_present(driver.root())
        && !driver.root().join("core-returned").exists()
        && !driver.root().join("reader-eof-held").exists()
        && std::fs::read(driver.root().join("timeout-notice"))
            .ok()
            .as_deref()
            == Some(b"login_timeout_refused");
    atomic_write(
        driver.root(),
        "holder-release",
        b"cooperative close actual stdout write FD",
    )
    .unwrap();
    let eof = poll(|| driver.root().join("reader-eof-held").exists());
    driver.release_reader();
    let receipt = driver.receipt();
    let joined = receipt
        .as_ref()
        .is_some_and(|proof| driver.actual_reader_join(proof));
    let reaped = receipt
        .as_ref()
        .is_some_and(|proof| driver.actual_reap_matches_spawn(proof));
    let holder = std::fs::read(driver.root().join("holder-reaped"))
        .ok()
        .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
    let holder_reaped = holder.as_ref().is_some_and(|proof| {
        proof["original_pid"].as_u64() == holder_pid.map(u64::from)
            && proof["reaped_pid"] == proof["original_pid"]
            && proof["code"] == 0
            && proof["signal"].is_null()
            && proof["cleanup_killed"] == false
            && proof["live_owned_sidecars"] == 0
    });
    let status = driver.finish_and_reap();
    // The accepted named RED requires actual early core return/publication.
    // An equivalent-safe gate mutation blocked by Drop cannot trigger it.
    assert!(
        ready
            && holder_pgid
            && original_exited_unreaped
            && ping
            && reaped
            && holder_reaped
            && status.is_some(),
        "LOGIN_CODEX_CTRLC_CUSTODY_UNKNOWN: fourth-row FD ownership/reap measurement unavailable"
    );
    assert!(!early_return_or_publication, "{OPEN_ASSERTION}");
    assert!(open_retained, "{OPEN_CUSTODY_ASSERTION}");
    assert!(reaped && holder_reaped, "{REAP_ASSERTION}");
    eprintln!("SIBLING typed reap: {}", holder.as_ref().unwrap());
    assert!(eof && joined, "{JOIN_ASSERTION}");
    assert!(
        receipt.is_some_and(|proof| proof["exit"] == 1
            && proof["publication"] == 0
            && proof["vendor_code"] == 0
            && proof["vendor_signal"].is_null()
            && proof["canonical_present"] == false
            && proof["canonical_valid"] == false
            && proof["live_owned_sidecars"] == 0)
            && status.is_some_and(|actual| actual.code() == Some(1)),
        "{OPEN_FINAL_ASSERTION}"
    );
}

#[test]
fn login_codex_ctrlc_forced_long_socket_bind_error_proves_no_spawn_and_driver_reap() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-fd-long");
    let ready = driver.ready();
    let actual = driver.finish_and_reap();
    let bind = std::fs::read(driver.root().join("socket-bind-error"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let wait = std::fs::read(driver.root().join("driver-reaped-proof"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    assert!(
        !ready
            && actual.is_some_and(|status| status.code() == Some(101))
            && bind.is_some_and(|proof| proof["operation"] == "UnixListener::bind"
                && proof["forced_long_socket"] == true
                && proof["driver_pid"] == driver.pid
                && proof["socket_path_bytes"]
                    .as_u64()
                    .is_some_and(|bytes| bytes >= 100)
                && proof["error_kind"]
                    .as_str()
                    .is_some_and(|kind| !kind.is_empty())
                && proof["error"]
                    .as_str()
                    .is_some_and(|error| !error.is_empty())
                && (proof["raw_os_error"].is_null() || proof["raw_os_error"].as_i64().is_some()))
            && wait.is_some_and(|proof| proof["driver_pid"] == driver.pid
                && proof["actual_code"] == 101
                && proof["actual_signal"].is_null()
                && proof["child_terminal_kind"] == "NO_VENDOR_SPAWNED"
                && proof["custody"]["vendor"]["kind"] == "NO_VENDOR_SPAWNED"
                && proof["custody"]["holder"]["kind"] == "NO_HOLDER_SPAWNED"
                && proof["custody"]["fallback_used"] == false),
        "LOGIN_CODEX_CTRLC_FORCED_LONG_BIND_ERROR_REAP"
    );
}

fn durable_driver_proof(driver: &Driver) -> Option<serde_json::Value> {
    std::fs::read(driver.root().join("driver-reaped-proof"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

#[test]
fn login_codex_ctrlc_actual_spawn_error_proves_no_vendor_and_driver_reap() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-spawn-error");
    let ready = driver.ready();
    let actual = driver.finish_and_reap();
    assert!(
        !ready
            && actual.is_some_and(|status| status.code() == Some(101))
            && durable_driver_proof(&driver).is_some_and(|proof| proof["driver_pid"] == driver.pid
                && proof["custody"]["vendor"]["kind"] == "NO_VENDOR_SPAWNED"
                && proof["custody"]["vendor"]["spawn_phase"] == "NotSpawned"
                && proof["custody"]["holder"]["kind"] == "NO_HOLDER_REQUESTED"
                && proof["custody"]["fallback_used"] == false),
        "LOGIN_CODEX_CTRLC_ACTUAL_SPAWN_ERROR_REAP"
    );
}

#[test]
fn login_codex_ctrlc_actual_callback_unwind_reaps_original_stub_and_driver() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-callback-unwind");
    // The callback may unwind/reap before a live-PGID readiness query.
    // This control requires its actual callback-entry marker, not readiness.
    let entered = poll(|| driver.root().join("callback-unwind-entered").exists());
    let actual = driver.finish_and_reap();
    assert!(
        actual.is_some_and(|status| status.code() == Some(101))
            && entered
            && durable_driver_proof(&driver).is_some_and(|proof| proof["driver_pid"] == driver.pid
                && proof["custody"]["vendor"]["kind"] == "ACTUAL_OWNED_STUB_WAIT"
                && proof["custody"]["vendor"]["original_pid"]
                    .as_u64()
                    .is_some()
                && proof["custody"]["vendor"]["original_pid"]
                    == proof["custody"]["vendor"]["reaped_pid"]
                && (proof["custody"]["vendor"]["code"].as_i64().is_some()
                    != proof["custody"]["vendor"]["signal"].as_i64().is_some())
                && proof["custody"]["holder"]["kind"] == "NO_HOLDER_REQUESTED"),
        "LOGIN_CODEX_CTRLC_ACTUAL_CALLBACK_UNWIND_REAP"
    );
}

#[test]
fn login_codex_ctrlc_actual_stubborn_stub_fallback_kill_wait_is_not_production_credit() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-fallback-timeout");
    let ready = driver.ready();
    let pid = driver.vendor_pid;
    let actual = driver.finish_and_reap();
    assert!(
        ready
            && actual.is_some_and(|status| status.code() == Some(101))
            && durable_driver_proof(&driver).is_some_and(|proof| proof["driver_pid"] == driver.pid
                && proof["custody"]["vendor"]["kind"] == "ACTUAL_OWNED_STUB_WAIT"
                && proof["custody"]["vendor"]["original_pid"].as_u64() == pid.map(u64::from)
                && proof["custody"]["vendor"]["original_pid"]
                    == proof["custody"]["vendor"]["reaped_pid"]
                && proof["custody"]["vendor"]["signal"] == libc::SIGKILL
                && proof["custody"]["vendor"]["code"].is_null()
                && proof["custody"]["vendor"]["fallback_used"] == true
                && proof["custody"]["vendor"]["cleanup_reaper"]
                    == "fixture_original_handle_fallback"
                && proof["custody"]["fallback_used"] == true),
        "LOGIN_CODEX_CTRLC_ACTUAL_STUB_FALLBACK_KILL_WAIT_UND"
    );
}

#[test]
fn login_codex_ctrlc_fd_transport_normalizes_nonblocking_before_actual_receive() {
    let _env_guard = csq_core::platform::test_env::lock();
    let (receiver, sender) = UnixStream::pair().expect("private actual Unix socketpair");
    receiver.set_nonblocking(true).unwrap();
    let receiver = Arc::new(receiver);
    // SAFETY: receiver owns this live socket for the complete control.
    let initial_flags = unsafe { libc::fcntl(receiver.as_raw_fd(), libc::F_GETFL) };
    assert!(
        initial_flags >= 0 && initial_flags & libc::O_NONBLOCK != 0,
        "LOGIN_CODEX_CTRLC_FD_TRANSPORT_NONBLOCKING_SETUP"
    );
    let observed_receiver = Arc::clone(&receiver);
    let sender = std::thread::Builder::new()
        .name("private-fd-transport-control".to_owned())
        .spawn(move || -> std::io::Result<()> {
            // This is a causal barrier, not a scheduler-speed assertion: only
            // the actual receiver helper may clear this descriptor's flag.
            if !poll(|| {
                // SAFETY: observed_receiver keeps this exact socket alive.
                let flags = unsafe { libc::fcntl(observed_receiver.as_raw_fd(), libc::F_GETFL) };
                flags >= 0 && flags & libc::O_NONBLOCK == 0
            }) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "actual receiver never became blocking",
                ));
            }
            send_stdout_fd(&sender)
        })
        .expect("private actual FD sender thread");
    // Always join the actual sender before making a result assertion, including
    // a failing receive. Every delivered descriptor is owned and drops here.
    let received = receive_stdout_fd(&receiver);
    let sent = sender.join();
    let descriptor_is_cloexec = received.as_ref().is_ok_and(|fd| {
        // SAFETY: this actual received descriptor remains owned by received.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        flags >= 0 && flags & libc::FD_CLOEXEC != 0
    });
    assert!(
        received.is_ok() && matches!(sent, Ok(Ok(()))) && descriptor_is_cloexec,
        "LOGIN_CODEX_CTRLC_FD_TRANSPORT_BLOCKING_RECEIVE"
    );
}

#[test]
fn login_codex_ctrlc_fd_transport_receives_after_sender_already_closed() {
    // The production-shaped vendor sends its descriptor and drops the socket
    // at once; under load that close can land before the controller's receive
    // runs. darwin then refuses setsockopt on the disconnected socket (EINVAL)
    // although the byte and SCM_RIGHTS descriptor are still queued. Forcing
    // that interleaving deterministically: the receive must still succeed.
    let _env_guard = csq_core::platform::test_env::lock();
    let (receiver, sender) = UnixStream::pair().expect("private actual Unix socketpair");
    send_stdout_fd(&sender).expect("private actual descriptor send");
    drop(sender);
    let received = receive_stdout_fd(&receiver);
    let descriptor_is_cloexec = received.as_ref().is_ok_and(|fd| {
        // SAFETY: this actual received descriptor remains owned by received.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        flags >= 0 && flags & libc::FD_CLOEXEC != 0
    });
    assert!(
        descriptor_is_cloexec,
        "LOGIN_CODEX_CTRLC_FD_TRANSPORT_PEER_CLOSED_RECEIVE: {:?}",
        received.as_ref().err()
    );
}
