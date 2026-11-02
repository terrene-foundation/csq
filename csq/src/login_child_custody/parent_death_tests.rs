//! Inert production-spawn parent-death probe. No credential or real vendor entry.
//! macOS/Linux only: Windows Job parent-death behavior is not measured here.
use crate::login_child_custody::group;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const ENTRY: &str = "login_child_custody::tests::parent_death_tests::private_parent_death_actor";
const ROLE: &str = "CSQ_PRIVATE_PARENT_DEATH_ROLE";
const ROOT: &str = "CSQ_PRIVATE_PARENT_DEATH_ROOT";
const TOKEN: &str = "CSQ_PRIVATE_PARENT_DEATH_TOKEN";
const UNKNOWN: &str = "PARENT_DEATH_OBSERVATION_UNDETERMINED";
// Startup and cleanup each have 5s; observation allows 2s for native death/EOF.
// Actors remain live for 30s without a release, leaving >=18s beyond that path.
const SETUP: Duration = Duration::from_secs(5);
const OBSERVE: Duration = Duration::from_secs(2);
const SAFETY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Identity {
    role: String,
    token: String,
    pid: u32,
    parent: u32,
    group: i32,
    birth: String,
}

#[cfg(target_os = "linux")]
fn birth(pid: u32) -> io::Result<Option<String>> {
    let text = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let tail = text
        .rsplit_once(')')
        .ok_or_else(|| io::Error::other(UNKNOWN))?
        .1;
    Ok(Some(
        tail.split_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::other(UNKNOWN))?
            .to_owned(),
    ))
}

#[cfg(target_os = "macos")]
fn birth(pid: u32) -> io::Result<Option<String>> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        i32::try_from(pid).map_err(|_| io::Error::other(UNKNOWN))?,
    ];
    let mut bytes = [0_u8; 2048];
    let mut len = bytes.len();
    // SAFETY: initialized exact-PID read-only query, with a writable buffer.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if len == 0 {
        return Ok(None);
    }
    if len < std::mem::size_of::<libc::timeval>() {
        return Err(io::Error::other(UNKNOWN));
    }
    // SAFETY: sysctl wrote at least the initial process-start timeval.
    let start = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::timeval>()) };
    if start.tv_sec == 0 {
        return Err(io::Error::other(UNKNOWN));
    }
    Ok(Some(format!("{}:{}", start.tv_sec, start.tv_usec)))
}

fn gone(identity: &Identity) -> io::Result<bool> {
    Ok(birth(identity.pid)?.is_none_or(|current| current != identity.birth))
}

fn command(root: &Path, token: &str, role: &str) -> io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .env_clear()
        .args([
            ENTRY,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .env(ROLE, role)
        .env(ROOT, root)
        .env(TOKEN, token)
        .env("HOME", root.join("home"))
        .env("CSQ_BASE_DIR", root.join("base"))
        .env("PATH", root.join("bin"))
        .env("TMPDIR", root.join("tmp"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("CSQ_SECRET_BACKEND", "in-memory")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Ok(command)
}

fn send_identity(stream: &mut UnixStream, identity: &Identity) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(identity)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)
}

fn line(stream: &mut BufReader<UnixStream>) -> io::Result<String> {
    let mut text = String::new();
    if stream.read_line(&mut text)? == 0 || !text.ends_with('\n') {
        return Err(io::Error::other(UNKNOWN));
    }
    Ok(text)
}

struct Peer {
    identity: Identity,
    stream: BufReader<UnixStream>,
}
impl Peer {
    fn alive_challenge(&mut self) -> io::Result<bool> {
        self.stream.get_mut().write_all(b"P")?;
        let current: Identity = serde_json::from_str(&line(&mut self.stream)?)?;
        if current != self.identity {
            return Err(io::Error::other(UNKNOWN));
        }
        gone(&self.identity).map(|gone| !gone)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    ExitedAndEof,
    Survived { vendor: bool, descendant: bool },
    Undetermined,
}

// Native lookup errors, missing EOF, and unauthenticated/no challenge response
// cannot certify either death or a survivor. The caller must fail UNKNOWN.
fn classify(
    vendor_gone: io::Result<bool>,
    descendant_gone: io::Result<bool>,
    eof: io::Result<bool>,
    vendor_alive: io::Result<bool>,
    descendant_alive: io::Result<bool>,
) -> Observation {
    match (vendor_gone, descendant_gone, eof) {
        (Ok(true), Ok(true), Ok(true)) => Observation::ExitedAndEof,
        (Ok(vg), Ok(dg), Ok(_)) => match (vendor_alive, descendant_alive) {
            (Ok(v), Ok(d)) if (!vg && v) || (!dg && d) => Observation::Survived {
                vendor: !vg && v,
                descendant: !dg && d,
            },
            _ => Observation::Undetermined,
        },
        _ => Observation::Undetermined,
    }
}

struct Fixture {
    sandbox: Option<tempfile::TempDir>,
    root: PathBuf,
    listener: UnixListener,
    token: String,
    owner: Option<Child>,
    stdout: Option<ChildStdout>,
    eof: bool,
    peers: Vec<Peer>,
    cleaned: bool,
}
impl Fixture {
    fn start() -> io::Result<Self> {
        let sandbox = tempfile::Builder::new()
            .prefix("csq-pd-")
            .tempdir_in("/tmp")?;
        for name in ["home", "base", "bin", "tmp"] {
            std::fs::create_dir(sandbox.path().join(name))?;
        }
        let token = format!(
            "FAKETEST_{}",
            sandbox
                .path()
                .file_name()
                .ok_or_else(|| io::Error::other(UNKNOWN))?
                .to_string_lossy()
        );
        let listener = UnixListener::bind(sandbox.path().join("control"))?;
        listener.set_nonblocking(true)?;
        let root = sandbox.path().to_path_buf();
        let mut fixture = Self {
            sandbox: Some(sandbox),
            root,
            listener,
            token,
            owner: None,
            stdout: None,
            eof: false,
            peers: Vec::new(),
            cleaned: false,
        };
        let mut cmd = command(&fixture.root, &fixture.token, "owner")?;
        cmd.stdout(Stdio::piped())
            .stderr(std::fs::File::create(fixture.root.join("stderr"))?);
        // Install the original Child immediately, before any fallible setup.
        fixture.owner = Some(cmd.spawn()?);
        fixture.stdout = fixture.owner.as_mut().and_then(|child| child.stdout.take());
        let fd = fixture
            .stdout
            .as_ref()
            .ok_or_else(|| io::Error::other(UNKNOWN))?
            .as_raw_fd();
        // SAFETY: fcntl changes only this retained pipe read descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + SETUP;
        while fixture.peers.len() < 3 && Instant::now() < deadline {
            match fixture.listener.accept() {
                Ok((stream, _)) => {
                    // Darwin inherits the nonblocking listener flag on accept;
                    // actor handshakes use bounded blocking reads on all Unix.
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
                    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
                    let mut stream = BufReader::new(stream);
                    let identity: Identity = serde_json::from_str(&line(&mut stream)?)?;
                    if identity.token != fixture.token
                        || !["owner", "vendor", "descendant"].contains(&identity.role.as_str())
                        || fixture
                            .peers
                            .iter()
                            .any(|peer| peer.identity.role == identity.role)
                    {
                        return Err(io::Error::other(UNKNOWN));
                    }
                    fixture.peers.push(Peer { identity, stream });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error),
            }
        }
        let owner_pid = fixture
            .owner
            .as_ref()
            .ok_or_else(|| io::Error::other(UNKNOWN))?
            .id();
        let owner = fixture.identity("owner")?;
        let vendor = fixture.identity("vendor")?;
        let descendant = fixture.identity("descendant")?;
        if owner.pid != owner_pid
            || vendor.parent != owner.pid
            || descendant.parent != vendor.pid
            || vendor.group != i32::try_from(vendor.pid).map_err(|_| io::Error::other(UNKNOWN))?
            || descendant.group != vendor.group
            || gone(&owner)?
            || gone(&vendor)?
            || gone(&descendant)?
        {
            return Err(io::Error::other(UNKNOWN));
        }
        if line(&mut fixture.peer("owner")?.stream)? != format!("SPAWN {}\n", vendor.pid) {
            return Err(io::Error::other(UNKNOWN));
        }
        // The real owner may be crashed only after authenticated topology ack.
        fixture.peer("owner")?.stream.get_mut().write_all(b"A")?;
        if line(&mut fixture.peer("owner")?.stream)? != "ARMED\n"
            || !fixture.peer("vendor")?.alive_challenge()?
            || !fixture.peer("descendant")?.alive_challenge()?
            || fixture.drain()?
        {
            return Err(io::Error::other(UNKNOWN));
        }
        eprintln!(
            "PARENT_DEATH_TOPOLOGY: owner_pid={} owner_parent={} owner_pgid={} owner_birth={}; vendor_pid={} vendor_parent={} vendor_pgid={} vendor_birth={}; descendant_pid={} descendant_parent={} descendant_pgid={} descendant_birth={}; captured_eof=false",
            owner.pid, owner.parent, owner.group, owner.birth,
            vendor.pid, vendor.parent, vendor.group, vendor.birth,
            descendant.pid, descendant.parent, descendant.group, descendant.birth,
        );
        Ok(fixture)
    }
    fn peer(&mut self, role: &str) -> io::Result<&mut Peer> {
        self.peers
            .iter_mut()
            .find(|peer| peer.identity.role == role)
            .ok_or_else(|| io::Error::other(UNKNOWN))
    }
    fn identity(&mut self, role: &str) -> io::Result<Identity> {
        Ok(self.peer(role)?.identity.clone())
    }
    fn drain(&mut self) -> io::Result<bool> {
        if self.eof {
            return Ok(true);
        }
        let mut bytes = [0_u8; 4096];
        let stdout = self
            .stdout
            .as_mut()
            .ok_or_else(|| io::Error::other(UNKNOWN))?;
        loop {
            match stdout.read(&mut bytes) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(true);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    fn finish_owner(&mut self, crash: bool) -> io::Result<()> {
        if crash {
            // The only external termination: actual owned original Child,
            // never a remembered PID or PGID, and SIGKILL produces no crash dialog.
            self.owner
                .as_mut()
                .ok_or_else(|| io::Error::other(UNKNOWN))?
                .kill()?;
        } else {
            self.peer("owner")?.stream.get_mut().write_all(b"K")?;
        }
        let deadline = Instant::now() + SETUP;
        while Instant::now() < deadline {
            if let Some(status) = self
                .owner
                .as_mut()
                .ok_or_else(|| io::Error::other(UNKNOWN))?
                .try_wait()?
            {
                if (crash && status.signal() == Some(libc::SIGKILL)) || (!crash && status.success())
                {
                    eprintln!("PARENT_DEATH_OWNER_REAP: crash={crash}; actual_status={status:?}");
                    return Ok(());
                }
                return Err(io::Error::other(UNKNOWN));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(io::Error::other(UNKNOWN))
    }
    fn observe(&mut self) -> io::Result<Observation> {
        let vendor = self.identity("vendor")?;
        let descendant = self.identity("descendant")?;
        let deadline = Instant::now() + OBSERVE;
        loop {
            let vg = gone(&vendor);
            let dg = gone(&descendant);
            let eof = self.drain();
            if vg.as_ref().is_ok_and(|gone| *gone)
                && dg.as_ref().is_ok_and(|gone| *gone)
                && eof.as_ref().is_ok_and(|eof| *eof)
            {
                return Ok(Observation::ExitedAndEof);
            }
            if Instant::now() >= deadline {
                let va = if vg.as_ref().is_ok_and(|gone| *gone) {
                    Ok(false)
                } else {
                    self.peer("vendor")?.alive_challenge()
                };
                let da = if dg.as_ref().is_ok_and(|gone| *gone) {
                    Ok(false)
                } else {
                    self.peer("descendant")?.alive_challenge()
                };
                return Ok(classify(vg, dg, eof, va, da));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        // Independent release channel survives owner death. The marker covers
        // actors not yet accepted during a setup failure; it never names a PID.
        std::fs::write(self.root.join("release"), b"release")?;
        for peer in &mut self.peers {
            let _ = peer.stream.get_mut().write_all(b"E");
        }
        if let Some(owner) = self.owner.as_mut() {
            if owner.try_wait()?.is_none() {
                owner.kill()?;
            }
        }
        let deadline = Instant::now() + SETUP;
        loop {
            let reaped = match self.owner.as_mut() {
                Some(owner) => owner.try_wait()?.is_some(),
                None => true,
            };
            let gone = self.peers.iter().try_fold(true, |all, peer| {
                Ok::<_, io::Error>(gone(&peer.identity)? && all)
            })?;
            let eof = if self.stdout.is_some() {
                self.drain()?
            } else {
                true
            };
            if reaped && gone && eof {
                self.cleaned = true;
                eprintln!("PARENT_DEATH_PRIVATE_CLEANUP: actual_owner_reaped=true; bound_actors_gone=true; captured_eof=true; numeric_signals=false");
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(UNKNOWN));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            // Keep the release channel reachable if native accounting fails.
            // Actor deadlines remain a final independent bound, never PASS.
            if let Some(sandbox) = self.sandbox.take() {
                let _ = sandbox.keep();
            }
            eprintln!("{UNKNOWN}: private cleanup incomplete: {error}");
        }
    }
}

fn actor() -> io::Result<()> {
    let root = PathBuf::from(std::env::var_os(ROOT).ok_or_else(|| io::Error::other(UNKNOWN))?);
    let role = std::env::var(ROLE).map_err(|_| io::Error::other(UNKNOWN))?;
    let token = std::env::var(TOKEN).map_err(|_| io::Error::other(UNKNOWN))?;
    if std::env::var_os("HOME").as_deref() != Some(root.join("home").as_os_str())
        || std::env::var_os("CSQ_BASE_DIR").as_deref() != Some(root.join("base").as_os_str())
        || std::env::var("CSQ_SECRET_BACKEND").as_deref() != Ok("in-memory")
    {
        return Err(io::Error::other(UNKNOWN));
    }
    let mut stream = UnixStream::connect(root.join("control"))?;
    stream.set_read_timeout(Some(Duration::from_millis(20)))?;
    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
    let pid = std::process::id();
    let identity = Identity {
        role: role.clone(),
        token: token.clone(),
        pid,
        // SAFETY: read-only queries of this live inert process itself.
        parent: unsafe { libc::getppid() } as u32,
        group: unsafe { libc::getpgrp() },
        birth: birth(pid)?.ok_or_else(|| io::Error::other(UNKNOWN))?,
    };
    send_identity(&mut stream, &identity)?;
    let mut child = None;
    let mut production_group = None;
    match role.as_str() {
        "owner" => {
            let mut cmd = command(&root, &token, "vendor")?;
            let (spawned, group) = group::spawn(&mut cmd, group::StdinPolicy::Null)?;
            writeln!(stream, "SPAWN {}", spawned.id())?;
            child = Some(spawned);
            production_group = Some(group);
        }
        "vendor" => {
            child = Some(command(&root, &token, "descendant")?.spawn()?);
        }
        "descendant" => {}
        _ => return Err(io::Error::other(UNKNOWN)),
    }
    let deadline = Instant::now() + SAFETY;
    let mut armed = false;
    while Instant::now() < deadline && !root.join("release").exists() {
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => match byte[0] {
                b'P' => send_identity(&mut stream, &identity)?,
                b'A' if role == "owner" => {
                    armed = true;
                    stream.write_all(b"ARMED\n")?;
                }
                b'K' if role == "owner" && armed => {
                    let group = production_group
                        .as_ref()
                        .ok_or_else(|| io::Error::other(UNKNOWN))?;
                    group.check_wait_lease()?;
                    group.signal(group::GroupSignal::Kill)?;
                    let until = Instant::now() + SETUP;
                    while Instant::now() < until {
                        if group
                            .try_reap(
                                child.as_mut().ok_or_else(|| io::Error::other(UNKNOWN))?,
                                true,
                            )?
                            .is_some()
                        {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    return Err(io::Error::other(UNKNOWN));
                }
                b'E' => break,
                _ => return Err(io::Error::other(UNKNOWN)),
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    // Cooperative actor shutdown only. A descendant is never targeted by a
    // remembered identity; the vendor reaps only its own actual Child handle.
    if let Some(mut child) = child {
        let until = Instant::now() + SETUP;
        while Instant::now() < until {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        return Err(io::Error::other(UNKNOWN));
    }
    Ok(())
}

#[test]
#[ignore = "private inert owner/vendor/descendant dispatcher; invoked only by isolated self-exec"]
fn private_parent_death_actor() {
    let _environment = csq_core::platform::test_env::lock();
    if let Err(error) = actor() {
        eprintln!("{UNKNOWN}: actor: {error}");
        std::process::exit(2);
    }
}

fn case(crash: bool) -> Observation {
    let _environment = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::start().unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
    let result = fixture.finish_owner(crash).and_then(|()| fixture.observe());
    // Observe before private cleanup; otherwise cleanup could manufacture PASS.
    eprintln!("PARENT_DEATH_BEFORE_PRIVATE_CLEANUP: crash={crash}; observation={result:?}");
    let cleanup = fixture.cleanup();
    assert!(cleanup.is_ok(), "{UNKNOWN}: cleanup: {cleanup:?}");
    result.unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"))
}

#[test]
fn crash_matrix_unix_vendor_survives_parent_kill_until_guardian() {
    // an internal ticket shard A records the measured Linux/macOS residual. The desired
    // completion assertion and causal RED receipts remain in the handoff.
    // Shard B must change this contract to verified exit, never skip UNKNOWN.
    assert_eq!(
        case(true),
        Observation::Survived {
            vendor: true,
            descendant: true
        },
        "PARENT_DEATH_CURRENT_UNIX_RESIDUAL_CHANGED_OR_UNDETERMINED"
    );
}

#[test]
fn live_owner_explicit_group_cleanup_terminates_vendor_and_descendant() {
    assert_eq!(
        case(false),
        Observation::ExitedAndEof,
        "{UNKNOWN}: ordinary owned cleanup"
    );
}

#[test]
fn parent_death_oracle_requires_available_identity_and_eof_evidence() {
    assert_eq!(
        classify(Ok(true), Ok(true), Ok(true), Ok(false), Ok(false)),
        Observation::ExitedAndEof
    );
    assert_eq!(
        classify(Ok(false), Ok(false), Ok(false), Ok(true), Ok(true)),
        Observation::Survived {
            vendor: true,
            descendant: true
        }
    );
    for observation in [
        classify(
            Err(io::Error::other("unavailable")),
            Ok(true),
            Ok(true),
            Ok(false),
            Ok(false),
        ),
        classify(Ok(true), Ok(true), Ok(false), Ok(false), Ok(false)),
        classify(
            Ok(false),
            Ok(false),
            Ok(false),
            Err(io::Error::other("unauthenticated")),
            Ok(true),
        ),
    ] {
        assert_eq!(observation, Observation::Undetermined);
    }
}
