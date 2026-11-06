//! Per-relay local control transport (spec 34 §34.3.1).
//!
//! Socket admission binds one bounded frame and kernel-bound peer to its
//! original lease, then delegates owner provenance to the command verifier.
//! That opaque admission grants neither Idle nor a state/writer bypass. No
//! connection thread owns a PTY descriptor. Replies use a bounded channel, so
//! handing the worker a reply performs no socket I/O on the byte loop.

use super::owner::{AuthorizedOwnerCommand, OwnerAuthError, OwnerVerifier, WireOwnerCommand};
use super::state::SlashCmd;
use super::types::{CliKind, InjectOutcome, SessionIdentity};
use crate::sdk::SdkErrorCode;
use std::fmt;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET: &str = ".csq-relay.sock";
pub const MAX_LINE: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 4;
const IO_BOUND: Duration = Duration::from_secs(2);
const CANCEL_TICK: Duration = Duration::from_millis(25);
const ACCEPT_IDLE: Duration = Duration::from_millis(250);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(10);
const UNDETERMINED_FRAME: &[u8] = b"{\"outcome\":\"undetermined\"}";
static BIND_MASK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
#[repr(usize)]
enum FailureTag {
    ForeignUid,
    PeerCredentials,
    PeerStartUnreadable,
    PeerIdentityChanged,
    ConnectionCap,
    Accept,
    Spawn,
    Serve,
    QueueFull,
    ReauthMismatch,
    Expired,
}

impl FailureTag {
    const ALL: [Self; 11] = [
        Self::ForeignUid,
        Self::PeerCredentials,
        Self::PeerStartUnreadable,
        Self::PeerIdentityChanged,
        Self::ConnectionCap,
        Self::Accept,
        Self::Spawn,
        Self::Serve,
        Self::QueueFull,
        Self::ReauthMismatch,
        Self::Expired,
    ];

    const fn wire(self) -> &'static str {
        match self {
            Self::ForeignUid => "relay_control_foreign_uid",
            Self::PeerCredentials => "relay_control_peer_credentials",
            Self::PeerStartUnreadable => "relay_control_peer_start_unreadable",
            Self::PeerIdentityChanged => "relay_control_peer_identity_changed",
            Self::ConnectionCap => "relay_control_connection_cap",
            Self::Accept => "relay_control_accept_failed",
            Self::Spawn => "relay_control_spawn_failed",
            Self::Serve => "relay_control_serve_failed",
            Self::QueueFull => "relay_control_queue_full",
            Self::ReauthMismatch => "relay_control_reauth_mismatch",
            Self::Expired => "relay_control_request_expired",
        }
    }
}

struct DiagnosticLimiter {
    last: [Option<Instant>; FailureTag::ALL.len()],
    suppressed: [u64; FailureTag::ALL.len()],
}

impl DiagnosticLimiter {
    const fn new() -> Self {
        Self {
            last: [None; FailureTag::ALL.len()],
            suppressed: [0; FailureTag::ALL.len()],
        }
    }

    fn record(&mut self, tag: FailureTag, now: Instant) -> Option<u64> {
        let index = tag as usize;
        if self.last[index]
            .is_some_and(|last| now.saturating_duration_since(last) < DIAGNOSTIC_INTERVAL)
        {
            self.suppressed[index] = self.suppressed[index].saturating_add(1);
            return None;
        }
        self.last[index] = Some(now);
        Some(std::mem::take(&mut self.suppressed[index]))
    }
}

static DIAGNOSTICS: Mutex<DiagnosticLimiter> = Mutex::new(DiagnosticLimiter::new());

fn diagnostic(tag: FailureTag) {
    let count = DIAGNOSTICS
        .lock()
        .ok()
        .and_then(|mut limiter| limiter.record(tag, Instant::now()));
    if let Some(suppressed) = count {
        emit_diagnostic(tag, suppressed);
    }
}

fn emit_diagnostic(tag: FailureTag, suppressed: u64) {
    // Closed tags and counters only: no path, identity, payload or OS error.
    tracing::warn!(event = tag.wire(), suppressed, "relay control refusal");
}

fn refusal(kind: io::ErrorKind, tag: &'static str) -> io::Error {
    io::Error::new(kind, tag)
}

fn denied() -> io::Error {
    refusal(io::ErrorKind::PermissionDenied, "relay_control_peer")
}

/// A write window with permanent revocation. A clamp owns a child cancellation
/// node: parent loss propagates downward, but a write cutoff never kills the
/// original request's still-live reply channel.
#[derive(Clone)]
pub(in crate::relay) struct RequestLease {
    node: Arc<LeaseNode>,
}

struct LeaseNode {
    deadline: Instant,
    cancelled: AtomicBool,
    parent: Option<Arc<LeaseNode>>,
}

impl RequestLease {
    fn new(deadline: Instant) -> Self {
        Self {
            node: Arc::new(LeaseNode {
                deadline,
                cancelled: AtomicBool::new(false),
                parent: None,
            }),
        }
    }

    pub(in crate::relay) fn deadline(&self) -> Instant {
        self.node.deadline
    }

    pub(in crate::relay) fn is_expired(&self) -> bool {
        let now = Instant::now();
        let mut node = Some(&self.node);
        while let Some(current) = node {
            if now >= current.deadline {
                current.cancelled.store(true, Ordering::Release);
            }
            if current.cancelled.load(Ordering::Acquire) {
                return true;
            }
            node = current.parent.as_ref();
        }
        false
    }

    pub(in crate::relay) fn clamp(&self, earlier: Instant) -> Self {
        Self {
            node: Arc::new(LeaseNode {
                deadline: self.deadline().min(earlier),
                cancelled: AtomicBool::new(false),
                parent: Some(Arc::clone(&self.node)),
            }),
        }
    }

    pub(in crate::relay) fn revoke(&self) {
        self.node.cancelled.store(true, Ordering::Release);
    }
}

/// Revokes queued/in-flight authority on every worker exit, including unwind.
struct CancelLease(RequestLease);

impl Drop for CancelLease {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

/// One bounded frame. The peer identity is evidence for a later authorization
/// check; same UID alone does not authorize a command.
pub struct ControlRequest {
    peer: SessionIdentity,
    line: Vec<u8>,
    reply: mpsc::SyncSender<Vec<u8>>,
    lease: RequestLease,
    /// Immutable identity of the lease received with this line. Never on wire.
    origin: Arc<LeaseNode>,
}

impl ControlRequest {
    #[must_use]
    pub const fn peer(&self) -> SessionIdentity {
        self.peer
    }

    #[must_use]
    pub fn line(&self) -> &[u8] {
        &self.line
    }

    /// Re-read the incarnation after the caller's authorization chain walk.
    #[must_use]
    pub fn peer_is_live(&self) -> bool {
        peer_is_live(self.peer)
    }

    /// The full read, queue and answer lifetime shares the worker's deadline.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.lease.is_expired()
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "production owner command cells remain closed")
    )]
    pub(in crate::relay) fn lease(&self) -> RequestLease {
        self.lease.clone()
    }

    #[cfg(test)]
    pub(crate) fn for_test(peer: SessionIdentity, line: Vec<u8>, deadline: Instant) -> Self {
        Self::for_test_with_lease(peer, line, RequestLease::new(deadline))
    }

    #[cfg(test)]
    pub(in crate::relay) fn for_test_with_lease(
        peer: SessionIdentity,
        line: Vec<u8>,
        lease: RequestLease,
    ) -> Self {
        let (reply, _receiver) = mpsc::sync_channel(1);
        Self {
            peer,
            line,
            reply,
            origin: Arc::clone(&lease.node),
            lease,
        }
    }

    #[cfg(test)]
    pub(in crate::relay) fn with_lease_from_for_test(mut self, donor: &Self) -> Self {
        self.lease = donor.lease.clone();
        self
    }

    /// Consume one received line and its original lease. Neither raw owner
    /// provenance nor a separately cloned lease can construct an admission.
    pub(in crate::relay) fn admit_owner(
        self,
        verifier: &mut OwnerVerifier,
        cli: CliKind,
        now_ms: Option<u64>,
    ) -> Result<(OwnerAdmission, ReplyHandle), AdmissionRefusal> {
        let admitted = (|| {
            if !Arc::ptr_eq(&self.origin, &self.lease.node) {
                return Err(InjectOutcome::Refused(SdkErrorCode::NotAuthorized));
            }
            if self.is_expired() {
                return Err(InjectOutcome::Refused(SdkErrorCode::RequestExpired));
            }
            if !self.peer_is_live() {
                return Err(InjectOutcome::Undetermined);
            }
            if self.is_expired() {
                return Err(InjectOutcome::Refused(SdkErrorCode::RequestExpired));
            }
            if cli == CliKind::Codex {
                return Err(InjectOutcome::Refused(SdkErrorCode::InputRejected));
            }
            let wire = serde_json::from_slice::<WireOwnerCommand>(&self.line)
                .map_err(|_| InjectOutcome::Refused(SdkErrorCode::NotAuthorized))?;
            let owner = verifier.verify(wire, now_ms).map_err(owner_refusal)?;
            verifier.revalidate(&owner, now_ms).map_err(owner_refusal)?;
            if !self.peer_is_live() {
                return Err(InjectOutcome::Undetermined);
            }
            let lease = self.lease.clamp(owner.deadline());
            if lease.is_expired() {
                return Err(InjectOutcome::Refused(SdkErrorCode::RequestExpired));
            }
            Ok(OwnerAdmission { owner, lease })
        })();
        let reply = self.into_reply();
        match admitted {
            Ok(admission) => Ok((admission, reply)),
            Err(outcome) => Err(AdmissionRefusal { outcome, reply }),
        }
    }

    fn into_reply(self) -> ReplyHandle {
        ReplyHandle {
            peer: self.peer,
            reply: self.reply,
            lease: RequestLease { node: self.origin },
        }
    }

    /// Hand a JSON response to the connection worker without waiting for I/O.
    /// Consuming the request permits at most one response.
    pub fn reply(self, json: &[u8]) -> io::Result<()> {
        self.into_reply().reply(json)
    }
}

/// Opaque, single-use provenance and write lease from the same received frame.
#[must_use = "consume the request admission or explicitly abandon it"]
pub(in crate::relay) struct OwnerAdmission {
    owner: AuthorizedOwnerCommand,
    lease: RequestLease,
}

impl OwnerAdmission {
    pub(in crate::relay) fn command(&self) -> SlashCmd {
        self.owner.command()
    }

    pub(in crate::relay) fn into_parts(self) -> (AuthorizedOwnerCommand, RequestLease) {
        (self.owner, self.lease)
    }
}

impl fmt::Debug for OwnerAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerAdmission(<bound>)")
    }
}

/// Original reply ownership; a shorter child write cutoff cannot renew or
/// revoke this root window. Dropping it grants no new writing authority.
#[must_use = "retain the original reply handle until the request terminates"]
pub(in crate::relay) struct ReplyHandle {
    peer: SessionIdentity,
    reply: mpsc::SyncSender<Vec<u8>>,
    lease: RequestLease,
}

impl ReplyHandle {
    pub(in crate::relay) fn peer_is_live(&self) -> bool {
        peer_is_live(self.peer)
    }

    pub(in crate::relay) fn is_expired(&self) -> bool {
        self.lease.is_expired()
    }

    pub(in crate::relay) fn reply(self, json: &[u8]) -> io::Result<()> {
        if self.is_expired() {
            diagnostic(FailureTag::Expired);
            return Err(refusal(
                io::ErrorKind::TimedOut,
                "relay_control_request_expired",
            ));
        }
        let json = json.strip_suffix(b"\n").unwrap_or(json);
        validate_line(json)?;
        self.reply
            .try_send(json.to_vec())
            .map_err(|_| refusal(io::ErrorKind::BrokenPipe, "relay_control_reply_unavailable"))
    }
}

impl fmt::Debug for ReplyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplyHandle(<original-window>)")
    }
}

#[must_use = "a refused admission retains its original reply handle"]
pub(in crate::relay) struct AdmissionRefusal {
    outcome: InjectOutcome,
    reply: ReplyHandle,
}

impl AdmissionRefusal {
    pub(in crate::relay) fn into_parts(self) -> (InjectOutcome, ReplyHandle) {
        (self.outcome, self.reply)
    }
}

impl fmt::Debug for AdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdmissionRefusal(<closed-outcome>)")
    }
}

fn peer_is_live(peer: SessionIdentity) -> bool {
    match super::pty::process_identity_start(peer.pid) {
        Some(start) if start == peer.started_at => true,
        Some(_) => {
            diagnostic(FailureTag::PeerIdentityChanged);
            false
        }
        None => {
            diagnostic(FailureTag::PeerStartUnreadable);
            false
        }
    }
}

fn owner_refusal(error: OwnerAuthError) -> InjectOutcome {
    InjectOutcome::Refused(match error {
        OwnerAuthError::Disabled => SdkErrorCode::DisabledByOperator,
        OwnerAuthError::Expired => SdkErrorCode::RequestExpired,
        OwnerAuthError::ClockUnavailable
        | OwnerAuthError::GenerationUnavailable
        | OwnerAuthError::Invalid
        | OwnerAuthError::Replay => SdkErrorCode::NotAuthorized,
    })
}

/// Owns the socket and the accept thread. Drop wakes accept, cancels connection
/// I/O at its next bounded poll, joins its workers, then checks inode ownership
/// before unlinking. Only a same-UID socket proved stale by ECONNREFUSED is
/// recoverable; existing non-sockets, live endpoints and unknown probes refuse.
pub struct ControlServer {
    path: PathBuf,
    incoming: mpsc::Receiver<ControlRequest>,
    stop: Arc<AtomicBool>,
    wake: UnixStream,
    accept: Option<JoinHandle<()>>,
    owned: SocketOwner,
}

impl ControlServer {
    pub fn bind(handle_dir: &Path) -> io::Result<Self> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(refusal(
                io::ErrorKind::Unsupported,
                "relay_control_platform",
            ));
        }
        let dir = private_dir(handle_dir)?;
        let path = handle_dir.join(SOCKET);
        socket_path(&path)?;
        recover_stale_socket(&path, &dir, |p| {
            connect(p, Instant::now() + IO_BOUND, &AtomicBool::new(false)).map(drop)
        })?;
        let listener = bind_private(&path, |p| UnixListener::bind(p))?;
        let meta = fs::symlink_metadata(&path)?;
        // The path must still name a socket owned by this uid before chmod.
        // SAFETY: geteuid has no arguments.
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            return Err(denied());
        }
        let owned = SocketOwner {
            path: path.clone(),
            dir,
            dev: meta.dev(),
            ino: meta.ino(),
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        if !same_object(&private_dir(handle_dir)?, &owned.dir) || !owned.matches() {
            return Err(denied());
        }
        listener.set_nonblocking(true)?;
        let (wake, wake_read) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        wake_read.set_nonblocking(true)?;
        no_sigpipe(&wake)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (send, incoming) = mpsc::sync_channel(MAX_CONNECTIONS);
        let thread_stop = stop.clone();
        let accept = thread::Builder::new()
            .name("relay-control".into())
            .spawn(move || {
                accept_loop(listener, wake_read, send, thread_stop);
            })
            .inspect_err(|_| {
                diagnostic(FailureTag::Spawn);
            })?;
        Ok(Self {
            path,
            incoming,
            stop,
            wake,
            accept: Some(accept),
            owned,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Called by the relay loop; no connection wait or socket read occurs here.
    pub fn try_recv(&self) -> Result<ControlRequest, mpsc::TryRecvError> {
        self.incoming.try_recv()
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = send_bytes(
            &self.wake,
            b"x",
            Instant::now() + CANCEL_TICK,
            &AtomicBool::new(false),
        );
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        // SocketOwner drops after every thread that could use the socket.
        let _ = &self.owned;
    }
}

struct SocketOwner {
    path: PathBuf,
    dir: Metadata,
    dev: u64,
    ino: u64,
}

impl SocketOwner {
    fn matches(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.file_type().is_socket() && m.dev() == self.dev && m.ino() == self.ino
                // SAFETY: geteuid has no arguments.
                && m.uid() == unsafe { libc::geteuid() }
        })
    }
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        if self
            .path
            .parent()
            .and_then(|p| private_dir(p).ok())
            .is_some_and(|m| same_object(&m, &self.dir))
            && self.matches()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn same_object(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn private_dir(path: &Path) -> io::Result<Metadata> {
    let m = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments.
    if !path.is_absolute()
        || !m.is_dir()
        || m.mode() & 0o7777 != 0o700
        || m.uid() != unsafe { libc::geteuid() }
    {
        return Err(denied());
    }
    Ok(m)
}

fn socket_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().as_bytes().len() >= 104 || path.as_os_str().as_bytes().contains(&0) {
        return Err(refusal(io::ErrorKind::InvalidInput, "relay_control_path"));
    }
    Ok(())
}

fn recover_stale_socket<F>(path: &Path, dir: &Metadata, probe: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let before = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // SAFETY: geteuid has no arguments.
    let uid = unsafe { libc::geteuid() };
    let collision = || refusal(io::ErrorKind::AlreadyExists, "relay_control_path_exists");
    if !before.file_type().is_socket() || before.uid() != uid {
        return Err(collision());
    }
    match probe(path) {
        Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => {}
        _ => return Err(collision()),
    }
    // A failed probe grants no deletion authority by itself. Re-read the
    // private directory and exact socket object immediately before unlink.
    let parent = path.parent().ok_or_else(collision)?;
    let current_dir = private_dir(parent)?;
    let current = fs::symlink_metadata(path)?;
    if !same_object(&current_dir, dir)
        || !same_object(&current, &before)
        || !current.file_type().is_socket()
        || current.uid() != uid
    {
        return Err(collision());
    }
    fs::remove_file(path)
}

fn bind_private<F>(path: &Path, bind: F) -> io::Result<UnixListener>
where
    F: FnOnce(&Path) -> io::Result<UnixListener>,
{
    // umask is process-global. This serializes relay binds; unrelated creators
    // may observe the briefly restrictive mask. No process-wide coordination
    // with foreign umask writers is claimed.
    let _lock = BIND_MASK.lock().map_err(|_| denied())?;
    struct RestoreMask(libc::mode_t);
    impl Drop for RestoreMask {
        fn drop(&mut self) {
            // SAFETY: restore the value returned by our preceding umask call.
            unsafe { libc::umask(self.0) };
        }
    }
    // SAFETY: umask has no pointer arguments; the guard restores on unwind too.
    let _mask = RestoreMask(unsafe { libc::umask(0o077) });
    bind(path)
}

fn accept_loop(
    listener: UnixListener,
    wake: UnixStream,
    send: mpsc::SyncSender<ControlRequest>,
    stop: Arc<AtomicBool>,
) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Acquire) {
        for i in (0..workers.len()).rev() {
            if workers[i].is_finished() && workers.swap_remove(i).join().is_err() {
                diagnostic(FailureTag::Serve);
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: fds is a valid writable array for the specified length.
        let ready = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as _,
                ACCEPT_IDLE.as_millis() as _,
            )
        };
        if ready < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                diagnostic(FailureTag::Accept);
                accept_backoff(&wake, &stop);
            }
            continue;
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            diagnostic(FailureTag::Accept);
            accept_backoff(&wake, &stop);
            continue;
        }
        if ready == 0 || fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        let Ok(accepted_at) = unix_seconds() else {
            diagnostic(FailureTag::PeerStartUnreadable);
            accept_backoff(&wake, &stop);
            continue;
        };
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) => {
                if !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    diagnostic(FailureTag::Accept);
                    accept_backoff(&wake, &stop);
                }
                continue;
            }
        };
        if workers.len() >= MAX_CONNECTIONS {
            diagnostic(FailureTag::ConnectionCap);
            continue;
        }
        // UID, PID and start are obtained before any payload read.
        let Ok(peer) = authenticate_peer_at(&stream, accepted_at) else {
            continue;
        };
        if stream
            .set_nonblocking(true)
            .and_then(|()| no_sigpipe(&stream))
            .is_err()
        {
            diagnostic(FailureTag::Serve);
            continue;
        }
        let send = send.clone();
        let stopped = stop.clone();
        if let Ok(worker) = thread::Builder::new()
            .name("relay-control-peer".into())
            .spawn(move || {
                if serve_one(stream, peer, send, &stopped).is_err() {
                    diagnostic(FailureTag::Serve);
                }
            })
        {
            workers.push(worker);
        } else {
            diagnostic(FailureTag::Spawn);
            accept_backoff(&wake, &stop);
        }
    }
    stop.store(true, Ordering::Release);
    for worker in workers {
        if worker.join().is_err() {
            diagnostic(FailureTag::Serve);
        }
    }
}

fn accept_backoff(wake: &UnixStream, stop: &AtomicBool) {
    if !stop.load(Ordering::Acquire) {
        let _ = wait_fd(
            wake.as_raw_fd(),
            libc::POLLIN,
            Instant::now() + ACCEPT_BACKOFF,
            stop,
        );
    }
}

fn serve_one(
    stream: UnixStream,
    peer: SessionIdentity,
    send: mpsc::SyncSender<ControlRequest>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let end = Instant::now() + IO_BOUND;
    serve_until(stream, peer, send, stop, end)
}

fn serve_until(
    mut stream: UnixStream,
    peer: SessionIdentity,
    send: mpsc::SyncSender<ControlRequest>,
    stop: &AtomicBool,
    end: Instant,
) -> io::Result<()> {
    // Also covers direct socket-pair worker tests, which bypass accept setup.
    no_sigpipe(&stream)?;
    let line = read_line(&mut stream, end, stop)?;
    // Re-read after transport work. The loop rechecks after its own chain walk.
    reauthenticate(&stream, peer, end, stop)?;
    remaining(end, stop)?;
    let (reply, answer) = mpsc::sync_channel(1);
    let lease = RequestLease::new(end);
    let _cancel_on_exit = CancelLease(lease.clone());
    send.try_send(ControlRequest {
        peer,
        line,
        reply,
        origin: Arc::clone(&lease.node),
        lease,
    })
    .map_err(|_| {
        diagnostic(FailureTag::QueueFull);
        refusal(io::ErrorKind::WouldBlock, "relay_control_queue_full")
    })?;
    loop {
        remaining(end, stop)?;
        if peer_disconnected(&stream)? {
            return Err(refusal(
                io::ErrorKind::BrokenPipe,
                "relay_control_peer_closed",
            ));
        }
        match answer.recv_timeout(CANCEL_TICK.min(end.saturating_duration_since(Instant::now()))) {
            Ok(json) => return send_frame(&stream, &json, end, stop),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

/// Check full close without consuming a byte or mistaking a write-half-close
/// for loss of the reply receiver. Darwin can omit HUP for a zero event mask,
/// so every tick probes whether the peer can receive. The empty send adds no
/// wire bytes; the Linux HUP path remains separate.
fn peer_disconnected(stream: &UnixStream) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    // SAFETY: one initialized writable pollfd; a zero timeout cannot block.
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(error)
        };
    }
    if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Ok(true);
    }
    #[cfg(not(target_os = "macos"))]
    if poll.revents & libc::POLLHUP == 0 {
        return Ok(false);
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the socket is live and the empty slice is valid for length
        // zero. SO_NOSIGPIPE was set before admission; MSG_DONTWAIT bounds this
        // probe even if the direct caller has not made the socket nonblocking.
        let sent = unsafe {
            libc::send(
                stream.as_raw_fd(),
                b"".as_ptr().cast(),
                0,
                libc::MSG_DONTWAIT,
            )
        };
        if sent >= 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EPIPE | libc::ECONNRESET | libc::ENOTCONN) => Ok(true),
            Some(libc::EINTR | libc::EAGAIN) => Ok(false),
            _ => Err(error),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(true)
    }
}

fn reauthenticate(
    stream: &UnixStream,
    peer: SessionIdentity,
    end: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    if authenticate_peer(stream).is_ok_and(|current| current == peer) {
        return Ok(());
    }
    diagnostic(FailureTag::ReauthMismatch);
    let _ = send_frame(stream, UNDETERMINED_FRAME, end, stop);
    Err(denied())
}

fn authenticate_peer(stream: &UnixStream) -> io::Result<SessionIdentity> {
    authenticate_peer_at(stream, unix_seconds()?)
}

fn unix_seconds() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| denied())
}

fn authenticate_peer_at(stream: &UnixStream, accepted_at: u64) -> io::Result<SessionIdentity> {
    let (pid, uid) = peer_credentials(stream).inspect_err(|_| {
        diagnostic(FailureTag::PeerCredentials);
    })?;
    // SAFETY: geteuid has no arguments.
    require_uid(uid, unsafe { libc::geteuid() })?;
    let started_at = bracketed_peer_start(
        pid,
        accepted_at,
        super::pty::process_identity_start,
        crate::sessions::process_start_time,
    )?;
    Ok(SessionIdentity { pid, started_at })
}

fn bracketed_peer_start(
    pid: u32,
    accepted_at: u64,
    identity: impl Fn(u32) -> Option<u64>,
    seconds: impl Fn(u32) -> Option<u64>,
) -> io::Result<u64> {
    let before = identity(pid);
    let seconds = seconds(pid);
    let after = identity(pid);
    let (Some(before), Some(seconds), Some(after)) = (before, seconds, after) else {
        diagnostic(FailureTag::PeerStartUnreadable);
        return Err(denied());
    };
    if before == 0 || before != after || seconds == 0 || seconds > accepted_at.saturating_add(1) {
        diagnostic(FailureTag::PeerIdentityChanged);
        return Err(denied());
    }
    Ok(before)
}

fn require_uid(peer: libc::uid_t, ours: libc::uid_t) -> io::Result<()> {
    if peer == ours {
        Ok(())
    } else {
        diagnostic(FailureTag::ForeignUid);
        Err(denied())
    }
}

// The daemon helpers are private and accept tokio streams. These use the same
// kernel UID facilities, with PID and returned-length checks added for relay
// identity. Tests check this implementation against a native same-process
// socket and inject a foreign UID value; they do not call the daemon helper or
// establish daemon-helper parity under a real cross-UID connection.
#[cfg(target_os = "linux")]
fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, libc::uid_t)> {
    // SAFETY: ucred is plain data; getsockopt receives its exact size.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    // SAFETY: connected socket and valid writable out-pointers.
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if r != 0 || len as usize != std::mem::size_of_val(&cred) {
        return Err(denied());
    }
    Ok((
        u32::try_from(cred.pid)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(denied)?,
        cred.uid,
    ))
}

#[cfg(target_os = "macos")]
fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, libc::uid_t)> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: connected socket and valid writable uid/gid output slots.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(denied());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
    // SAFETY: connected socket and valid writable pid/length output slots.
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast(),
            &mut len,
        )
    };
    if r != 0 || len as usize != std::mem::size_of_val(&pid) {
        return Err(denied());
    }
    Ok((
        u32::try_from(pid)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(denied)?,
        uid,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_credentials(_stream: &UnixStream) -> io::Result<(u32, libc::uid_t)> {
    Err(denied())
}

fn no_sigpipe(stream: &UnixStream) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let yes: libc::c_int = 1;
        // SAFETY: valid socket and initialized integer option value.
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                std::ptr::addr_of!(yes).cast(),
                std::mem::size_of_val(&yes) as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let _ = stream;
    Ok(())
}

fn remaining(end: Instant, stop: &AtomicBool) -> io::Result<Duration> {
    if stop.load(Ordering::Acquire) {
        return Err(refusal(io::ErrorKind::Interrupted, "relay_control_stopped"));
    }
    let left = end.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(refusal(io::ErrorKind::TimedOut, "relay_control_timeout"));
    }
    Ok(left)
}

fn wait_fd(fd: RawFd, event: libc::c_short, end: Instant, stop: &AtomicBool) -> io::Result<()> {
    loop {
        let left = remaining(end, stop)?.min(CANCEL_TICK);
        let mut pfd = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        // SAFETY: a single initialized writable pollfd.
        let r = unsafe { libc::poll(&mut pfd, 1, left.as_millis().max(1) as _) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        } else if r > 0 {
            if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(refusal(io::ErrorKind::BrokenPipe, "relay_control_socket"));
            }
            return Ok(());
        }
    }
}

fn validate_line(json: &[u8]) -> io::Result<()> {
    if json.is_empty()
        || json.len() > MAX_LINE
        || json.contains(&b'\n')
        || serde_json::from_slice::<serde_json::Value>(json).is_err()
    {
        return Err(refusal(io::ErrorKind::InvalidData, "relay_control_frame"));
    }
    Ok(())
}

fn read_line(stream: &mut UnixStream, end: Instant, stop: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_LINE + 1);
    let mut buf = [0u8; 1024];
    loop {
        wait_fd(stream.as_raw_fd(), libc::POLLIN, end, stop)?;
        match stream.read(&mut buf) {
            Ok(0) => return Err(refusal(io::ErrorKind::UnexpectedEof, "relay_control_eof")),
            Ok(n) => {
                if out.len() + n > MAX_LINE + 1 {
                    return Err(refusal(
                        io::ErrorKind::InvalidData,
                        "relay_control_too_large",
                    ));
                }
                out.extend_from_slice(&buf[..n]);
                if let Some(pos) = out.iter().position(|b| *b == b'\n') {
                    if pos + 1 != out.len() {
                        return Err(refusal(
                            io::ErrorKind::InvalidData,
                            "relay_control_extra_frame",
                        ));
                    }
                    out.truncate(pos);
                    validate_line(&out)?;
                    return Ok(out);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}

fn send_bytes(
    stream: &UnixStream,
    mut bytes: &[u8],
    end: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        wait_fd(stream.as_raw_fd(), libc::POLLOUT, end, stop)?;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        // SAFETY: bytes is valid for its length and stream owns the socket.
        let n = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                flags,
            )
        };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n == 0 {
            return Err(refusal(
                io::ErrorKind::WriteZero,
                "relay_control_write_zero",
            ));
        } else {
            let e = io::Error::last_os_error();
            if !matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn send_frame(stream: &UnixStream, json: &[u8], end: Instant, stop: &AtomicBool) -> io::Result<()> {
    send_bytes(stream, json, end, stop)?;
    send_bytes(stream, b"\n", end, stop)
}

/// Connect with an absolute deadline, authenticate the recorded server PID and
/// exact start time, then exchange one JSON line. No payload is sent before
/// server authentication. The metadata supplying `server` is the caller's
/// responsibility and must be bound to the target relay record.
pub fn request(path: &Path, server: SessionIdentity, json: &[u8]) -> io::Result<Vec<u8>> {
    let json = json.strip_suffix(b"\n").unwrap_or(json);
    validate_line(json)?;
    socket_path(path)?;
    let m = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments.
    if !m.file_type().is_socket()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
    {
        return Err(denied());
    }
    let stop = AtomicBool::new(false);
    let end = Instant::now() + IO_BOUND;
    let mut stream = connect(path, end, &stop)?;
    if authenticate_peer(&stream)? != server {
        return Err(denied());
    }
    send_frame(&stream, json, end, &stop)?;
    let answer = read_line(&mut stream, end, &stop)?;
    // The connected endpoint was authenticated before sending; its accepted
    // socket cannot be redirected to another listener. On macOS LOCAL_PEERPID
    // returns ENOTCONN after the worker closes its endpoint, including after a
    // complete response. Recheck the retained process incarnation rather than
    // asking a disconnected socket for credentials it no longer exposes.
    require_server_incarnation(server)?;
    Ok(answer)
}

fn require_server_incarnation(server: SessionIdentity) -> io::Result<()> {
    if super::pty::process_identity_start(server.pid) != Some(server.started_at) {
        diagnostic(FailureTag::PeerIdentityChanged);
        return Err(refusal(
            io::ErrorKind::PermissionDenied,
            "relay_control_server_incarnation",
        ));
    }
    Ok(())
}

fn connect(path: &Path, end: Instant, stop: &AtomicBool) -> io::Result<UnixStream> {
    // SAFETY: socket returns a new owned fd or -1, checked immediately.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly created uniquely owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: fcntl acts on our owned fd; fixed flags require no pointer.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(raw, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_un is plain data; socket_path has checked length/NUL.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (dst, src) in addr.sun_path.iter_mut().zip(path.as_os_str().as_bytes()) {
        *dst = *src as _;
    }
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = std::mem::size_of_val(&addr) as _;
    }
    // SAFETY: addr has the platform sockaddr_un layout and initialized length.
    let r = unsafe {
        libc::connect(
            raw,
            std::ptr::addr_of!(addr).cast(),
            std::mem::size_of_val(&addr) as _,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
        // A completed refused connect can poll as POLLERR. Read SO_ERROR in
        // that case so stale recovery sees the actual ECONNREFUSED, while a
        // timeout/cancellation or an indeterminate fd still refuses recovery.
        match wait_fd(raw, libc::POLLOUT, end, stop) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
            Err(error) => return Err(error),
        }
        let mut error: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&error) as libc::socklen_t;
        // SAFETY: valid socket and writable option result slots.
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                std::ptr::addr_of_mut!(error).cast(),
                &mut len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
    }
    let stream = UnixStream::from(fd);
    no_sigpipe(&stream)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::owner::{mint, OwnerCommand, OwnerCommandFields};
    use std::io::Write;

    const OWNER_NOW: u64 = 1_000_000;
    const OWNER_KEY: [u8; 32] = [0x53; 32];

    fn owner_fixture() -> (OwnerVerifier, Vec<u8>) {
        let relay = me();
        let mut verifier = OwnerVerifier::new(
            zeroize::Zeroizing::new(OWNER_KEY),
            SessionIdentity {
                pid: if relay.pid == 1 { 2 } else { 1 },
                started_at: 1,
            },
            relay,
        )
        .unwrap();
        verifier.set_clock_for_test(Arc::new(|| Some(OWNER_NOW)));
        let target = verifier.target();
        let wire = mint(
            OwnerCommandFields {
                version: 1,
                target_pid: target.pid,
                target_started_at: target.started_at,
                relay_pid: relay.pid,
                relay_started_at: relay.started_at,
                generation: verifier.generation(),
                update_id: 7,
                issued_at_ms: OWNER_NOW,
                expires_at_ms: OWNER_NOW + 30_000,
                command: OwnerCommand::Clear,
            },
            &OWNER_KEY,
        )
        .unwrap();
        (verifier, serde_json::to_vec(&wire).unwrap())
    }

    #[test]
    fn admitted_child_revocation_preserves_original_reply_handle() {
        let (mut verifier, line) = owner_fixture();
        let (reply, answer) = mpsc::sync_channel(1);
        let mut request =
            ControlRequest::for_test(me(), line, Instant::now() + Duration::from_secs(30));
        request.reply = reply;
        let (admission, reply) = request
            .admit_owner(&mut verifier, CliKind::Claude, Some(OWNER_NOW))
            .unwrap();
        assert_eq!(admission.command(), SlashCmd::Clear);
        let (_owner, child) = admission.into_parts();
        child.revoke();
        assert!(child.is_expired());
        assert!(reply.peer_is_live());
        assert!(
            !reply.is_expired(),
            "ADMITTED_WRITE_REVOCATION_MUST_KEEP_ORIGINAL_REPLY_WINDOW"
        );
        let frame = br#"{"outcome":"refused","error":{"code":"request_expired"}}"#;
        reply.reply(frame).unwrap();
        assert_eq!(answer.recv_timeout(IO_BOUND).unwrap(), frame);
    }

    #[test]
    fn swapped_admission_refusal_keeps_original_expired_reply_window() {
        let (mut verifier, line) = owner_fixture();
        let expired = ControlRequest::for_test(me(), line.clone(), Instant::now());
        let donor = ControlRequest::for_test(me(), line, Instant::now() + Duration::from_secs(30));
        let refused = expired
            .with_lease_from_for_test(&donor)
            .admit_owner(&mut verifier, CliKind::Claude, Some(OWNER_NOW))
            .unwrap_err();
        let (outcome, reply) = refused.into_parts();
        assert_eq!(outcome, InjectOutcome::Refused(SdkErrorCode::NotAuthorized));
        assert!(
            reply.is_expired(),
            "SWAPPED_REPLY_MUST_KEEP_ORIGINAL_FRAME_WINDOW"
        );
        assert!(!donor.is_expired());
        assert_eq!(
            reply.reply(b"{}").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn admission_and_reply_debug_never_expose_owner_mac() {
        let (mut verifier, line) = owner_fixture();
        let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
        let mac = value["mac"].as_str().unwrap();
        let request =
            ControlRequest::for_test(me(), line.clone(), Instant::now() + Duration::from_secs(30));
        let (admission, reply) = request
            .admit_owner(&mut verifier, CliKind::Claude, Some(OWNER_NOW))
            .unwrap();
        for rendered in [format!("{admission:?}"), format!("{reply:?}")] {
            assert!(
                !rendered.contains(mac),
                "bound authority debug must omit bearer MAC"
            );
        }
        let request = ControlRequest::for_test(me(), line, Instant::now());
        let refused = request
            .admit_owner(&mut verifier, CliKind::Claude, Some(OWNER_NOW))
            .unwrap_err();
        assert!(!format!("{refused:?}").contains(mac));
    }

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("rc-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn me() -> SessionIdentity {
        let pid = std::process::id();
        SessionIdentity {
            pid,
            started_at: super::super::pty::process_identity_start(pid).unwrap(),
        }
    }

    // How long a test waits to OBSERVE server-thread work on a raw socket: the
    // accept loop queuing a request, or closing a peer it drops or shuts down.
    // Under full-suite sign-off load that work can take longer than the
    // production IO_BOUND; a passing run returns as soon as the event lands,
    // and a server that never acts still fails, as a TimedOut error.
    const PEER_OBSERVE_BOUND: Duration = Duration::from_secs(15);

    // A peer can already be closed by the time accept returns. On Darwin,
    // configuring SO_RCVTIMEO on that endpoint can fail with EINVAL. Poll plus
    // one MSG_DONTWAIT recv bounds observation without reconfiguring it.
    fn bounded_peer_read(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<usize> {
        wait_fd(
            stream.as_raw_fd(),
            libc::POLLIN,
            Instant::now() + PEER_OBSERVE_BOUND,
            &AtomicBool::new(false),
        )?;
        // SAFETY: the socket and writable slice remain live for this recv.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    #[test]
    fn private_socket_round_trip_binds_kernel_peer_and_nonblocking_reply() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let server = ControlServer::bind(dir.path()).unwrap();
        assert_eq!(
            fs::symlink_metadata(server.path()).unwrap().mode() & 0o777,
            0o600
        );
        let path = server.path().to_owned();
        let client = thread::spawn(move || request(&path, me(), br#"{"command":"clear"}"#));
        let req = server.incoming.recv_timeout(IO_BOUND).unwrap();
        assert_eq!(req.peer(), me());
        assert!(req.peer_is_live());
        assert_eq!(req.line(), br#"{"command":"clear"}"#);
        req.reply(b"{\"outcome\":\"refused\"}\n").unwrap();
        assert_eq!(client.join().unwrap().unwrap(), br#"{"outcome":"refused"}"#);
        let path = server.path().to_owned();
        drop(server);
        assert!(!path.exists());
    }

    #[test]
    fn server_identity_mismatch_sends_no_payload() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let path = dir.path().join(SOCKET);
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut wrong = me();
        wrong.started_at += 1;
        let client = thread::spawn(move || request(&path, wrong, br#"{"secret":"fixture"}"#));
        let (stream, _) = listener.accept().unwrap();
        // Join the client BEFORE reading: once it has refused the server and
        // dropped its end, anything it sent is already buffered here and the
        // read returns at once, so the result no longer depends on the client
        // thread being scheduled inside the read's IO bound (it timed out
        // under sign-off load). A client that sent the payload still fails
        // the zero-bytes assertion below.
        assert_eq!(
            client.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut bytes = [0u8; 32];
        assert_eq!(
            bounded_peer_read(&stream, &mut bytes).unwrap(),
            0,
            "wrong server must receive zero payload bytes"
        );
    }

    #[test]
    fn uid_screen_matches_kernel_and_refuses_foreign_value() {
        // Exact production predicate; a native socket pair also checks that
        // the kernel credentials agree with the daemon's same-effective-UID rule.
        let (a, _b) = UnixStream::pair().unwrap();
        let (pid, uid) = peer_credentials(&a).unwrap();
        assert_eq!(pid, std::process::id());
        // SAFETY: geteuid has no arguments.
        let ours = unsafe { libc::geteuid() };
        assert_eq!(uid, ours);
        assert!(require_uid(uid, ours).is_ok());
        assert_eq!(
            require_uid(ours.wrapping_add(1), ours).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn directory_symlink_mode_and_preexisting_paths_refuse_without_unlink() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(ControlServer::bind(&link).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ControlServer::bind(dir.path()).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join(SOCKET);
        fs::write(&path, b"foreign").unwrap();
        assert!(ControlServer::bind(dir.path()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"foreign");
        fs::remove_file(&path).unwrap();
        let live = UnixListener::bind(&path).unwrap();
        let ino = fs::symlink_metadata(&path).unwrap().ino();
        assert!(ControlServer::bind(dir.path()).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), ino);
        drop(live);
        // The in-process listener may have been inherited by a concurrent
        // spawn elsewhere; build the stale socket where no fd can leak.
        fs::remove_file(&path).unwrap();
        make_stale_socket(&path);
        let recovered =
            ControlServer::bind(dir.path()).expect("same-UID refused socket must recover");
        assert_eq!(
            fs::symlink_metadata(recovered.path()).unwrap().mode() & 0o777,
            0o600
        );
    }

    /// Builds the `sockaddr_un` for `path` (allocation-free afterwards, so a
    /// forked child can use it between `fork` and `_exit`).
    fn sockaddr_for(path: &Path) -> (libc::sockaddr_un, libc::socklen_t) {
        // SAFETY: sockaddr_un is plain data; all-zero is a valid value.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() < addr.sun_path.len());
        for (slot, b) in addr.sun_path.iter_mut().zip(bytes) {
            *slot = *b as libc::c_char;
        }
        (
            addr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    }

    /// A forked child that owns the ONLY listening fd for `path`. The test
    /// process never holds it, so a concurrent fork+exec elsewhere in the
    /// process cannot inherit a copy that outlives the holder.
    struct ListenerHolder {
        pid: libc::pid_t,
    }

    impl ListenerHolder {
        /// Returns once the child has bound AND listened (a byte on a pipe
        /// says so; no sleeping).
        fn spawn(path: &Path) -> Self {
            let (addr, len) = sockaddr_for(path);
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: fds is a valid 2-element out array.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let (ready_r, ready_w) = (fds[0], fds[1]);
            // SAFETY: fork in a multithreaded process; the child restricts
            // itself to async-signal-safe calls and never returns.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // SAFETY: socket/bind/listen/write/pause/_exit are all
                // async-signal-safe; nothing allocates.
                unsafe {
                    libc::close(ready_r);
                    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                    let ok = fd >= 0
                        && libc::bind(fd, (&raw const addr).cast(), len) == 0
                        && libc::listen(fd, 1) == 0;
                    if ok {
                        let byte = 1u8;
                        libc::write(ready_w, (&raw const byte).cast(), 1);
                        loop {
                            libc::pause();
                        }
                    }
                    libc::_exit(1);
                }
            }
            // SAFETY: closing our copy of the write end; reading one byte
            // into a valid buffer; closing the read end.
            let got = unsafe {
                libc::close(ready_w);
                let mut byte = 0u8;
                let n = libc::read(ready_r, (&raw mut byte).cast(), 1);
                libc::close(ready_r);
                n
            };
            assert_eq!(got, 1, "listener child failed before listening");
            ListenerHolder { pid }
        }

        /// Kills and reaps the holder, releasing the only listening fd.
        fn release(self) {
            let mut status = 0;
            // SAFETY: pid is our child; status is a valid out-pointer.
            unsafe {
                assert_eq!(libc::kill(self.pid, libc::SIGKILL), 0);
                assert_eq!(libc::waitpid(self.pid, &mut status, 0), self.pid);
            }
            assert!(libc::WIFSIGNALED(status));
        }
    }

    /// Reproduces what a sibling test's concurrent spawn does: a child
    /// forked from THIS process that stays in its fork-to-exec window
    /// (blocked in `pre_exec`) and so keeps a copy of every fd the process
    /// held at fork time. `ready` returns once the fork has happened;
    /// `release` lets the child exec and die.
    struct ExecWindowForker {
        gate_w: libc::c_int,
        thread: std::thread::JoinHandle<std::process::Child>,
    }

    impl ExecWindowForker {
        fn start() -> Self {
            use std::os::unix::process::CommandExt;
            let mut ready = [0 as libc::c_int; 2];
            let mut gate = [0 as libc::c_int; 2];
            // SAFETY: valid 2-element out arrays; CLOEXEC on the parent ends.
            unsafe {
                assert_eq!(libc::pipe(ready.as_mut_ptr()), 0);
                assert_eq!(libc::pipe(gate.as_mut_ptr()), 0);
                libc::fcntl(ready[0], libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(gate[1], libc::F_SETFD, libc::FD_CLOEXEC);
            }
            let (ready_r, ready_w, gate_r, gate_w) = (ready[0], ready[1], gate[0], gate[1]);
            let thread = std::thread::spawn(move || {
                let mut cmd = std::process::Command::new("sleep");
                cmd.arg("60");
                // SAFETY: write and read are async-signal-safe; the closure
                // touches no other memory.
                unsafe {
                    cmd.pre_exec(move || {
                        let byte = 1u8;
                        libc::write(ready_w, (&raw const byte).cast(), 1);
                        let mut got = 0u8;
                        libc::read(gate_r, (&raw mut got).cast(), 1);
                        Ok(())
                    });
                }
                cmd.spawn().unwrap()
            });
            // Block until the forked child is inside its exec window.
            // SAFETY: valid buffer; fds are ours.
            unsafe {
                let mut byte = 0u8;
                assert_eq!(libc::read(ready_r, (&raw mut byte).cast(), 1), 1);
                libc::close(ready_r);
                libc::close(ready_w);
                libc::close(gate_r);
            }
            ExecWindowForker { gate_w, thread }
        }

        /// Lets the child exec, then kills and reaps it.
        fn finish(self) {
            let byte = 1u8;
            // SAFETY: gate_w is ours; one byte from a valid buffer.
            unsafe {
                libc::write(self.gate_w, (&raw const byte).cast(), 1);
                libc::close(self.gate_w);
            }
            let mut child = self.thread.join().unwrap();
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    /// Leaves a stale (listener-less) socket inode at `path` without ever
    /// holding the listening fd in this process: a forked child binds and
    /// `_exit`s, and the parent reaps it. A sibling test's concurrent
    /// fork+exec therefore cannot inherit a copy that would keep the socket
    /// answering connect() after the "stale" step.
    fn make_stale_socket(path: &Path) {
        // Everything allocating happens BEFORE fork; the child only calls
        // async-signal-safe libc functions.
        let (addr, len) = sockaddr_for(path);
        // SAFETY: fork in a multithreaded process; the child below restricts
        // itself to async-signal-safe calls and ends with _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // SAFETY: socket/bind/listen/_exit are async-signal-safe.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                let ok = fd >= 0
                    && libc::bind(fd, (&raw const addr).cast(), len) == 0
                    && libc::listen(fd, 1) == 0;
                libc::_exit(if ok { 0 } else { 1 });
            }
        }
        let mut status = 0;
        // SAFETY: pid is our child; status is a valid out-pointer.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_socket());
    }

    /// Mechanism: a listener copy held by another process keeps the socket
    /// answering, so a bind that refuses is the correct fail-safe; once every
    /// holder is gone it recovers. The listener lives ONLY in a forked child,
    /// so no concurrent spawn in this process can pin a stray copy and break
    /// the recovery step; `ExecWindowForker` proves that by deliberately
    /// forking while the holder runs.
    #[test]
    fn inherited_listener_copy_is_live_until_the_child_releases_it() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let path = dir.path().join(SOCKET);
        let holder = ListenerHolder::spawn(&path);
        let forker = ExecWindowForker::start();
        let refused = ControlServer::bind(dir.path());
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists),
            "a socket a child still listens on must not be reclaimed"
        );
        holder.release();
        forker.finish();
        ControlServer::bind(dir.path()).expect("recovers once no process listens");
    }

    #[test]
    fn cleanup_does_not_unlink_replacement_inode() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let server = ControlServer::bind(dir.path()).unwrap();
        let path = server.path().to_owned();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        drop(server);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }

    #[test]
    fn absolute_deadline_and_size_cap_reject_slow_or_oversized_frames() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.write_all(b"{").unwrap();
        let stop = AtomicBool::new(false);
        let end = Instant::now() + Duration::from_millis(30);
        assert_eq!(
            read_line(&mut reader, end, &stop).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop((reader, writer));
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let mut huge = Vec::with_capacity(MAX_LINE + 4);
        huge.push(b'"');
        huge.extend(std::iter::repeat_n(b'x', MAX_LINE));
        huge.extend_from_slice(b"\"\n");
        no_sigpipe(&writer).unwrap();
        let sender = thread::spawn(move || writer.write_all(&huge));
        assert_eq!(
            read_line(&mut reader, Instant::now() + IO_BOUND, &stop)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        sender.join().unwrap().unwrap();
        assert!(validate_line(b"{}\n{}").is_err());
        assert!(validate_line(b"not-json").is_err());
    }

    #[test]
    fn expired_deadline_refuses_even_ready_complete_frame() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.write_all(b"{}\n").unwrap();
        let stop = AtomicBool::new(false);
        assert_eq!(
            read_line(&mut reader, Instant::now(), &stop)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut,
            "expired deadline must refuse ready input"
        );
    }

    #[test]
    fn slow_connection_does_not_block_another_request_and_shutdown_cancels_it() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let server = ControlServer::bind(dir.path()).unwrap();
        let mut slow = UnixStream::connect(server.path()).unwrap();
        slow.write_all(b"{").unwrap();
        let path = server.path().to_owned();
        let client = thread::spawn(move || request(&path, me(), b"{}"));
        let req = server.incoming.recv_timeout(IO_BOUND).unwrap();
        req.reply(b"{}").unwrap();
        assert_eq!(client.join().unwrap().unwrap(), b"{}");
        drop(server);
        let mut b = [0u8; 1];
        match bounded_peer_read(&slow, &mut b) {
            Ok(n) => assert_eq!(n, 0, "shutdown must close the slow peer"),
            Err(error) => assert!(matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            )),
        }
    }

    #[test]
    fn bounded_request_queue_refuses_overflow() {
        let (a, mut b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.write_all(b"{}\n").unwrap();
        let (send, _recv) = mpsc::sync_channel(0);
        let stop = AtomicBool::new(false);
        assert_eq!(
            serve_one(a, me(), send, &stop).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn connection_cap_drops_fifth_while_four_replies_are_pending() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let server = ControlServer::bind(dir.path()).unwrap();
        let mut clients = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let mut client = UnixStream::connect(server.path()).unwrap();
            client.write_all(b"{}\n").unwrap();
            pending.push(server.incoming.recv_timeout(PEER_OBSERVE_BOUND).unwrap());
            clients.push(client);
        }
        let mut fifth = UnixStream::connect(server.path()).unwrap();
        if let Err(error) = fifth.write_all(b"{}\n") {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ));
        }
        assert!(
            matches!(
                server.incoming.recv_timeout(IO_BOUND / 4),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "fifth complete request must not be admitted"
        );
        let mut byte = [0u8; 1];
        match bounded_peer_read(&fifth, &mut byte) {
            Ok(n) => assert_eq!(n, 0, "fifth connection must be dropped before read"),
            Err(error) => assert!(matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            )),
        }
        assert!(matches!(server.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(pending);
        drop(clients);
        drop(server);
    }

    #[test]
    fn accepted_peer_start_cannot_postdate_acceptance() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let start = crate::sessions::process_start_time(me().pid).unwrap();
        assert!(authenticate_peer_at(&socket, start.saturating_sub(2)).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn orderly_close_loses_peer_pid_but_preserves_verified_server_incarnation() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let server = me();
        assert_eq!(authenticate_peer(&receiver).unwrap(), server);
        sender.write_all(b"{}\n").unwrap();
        drop(sender);
        assert_eq!(
            read_line(
                &mut receiver,
                Instant::now() + IO_BOUND,
                &AtomicBool::new(false),
            )
            .unwrap(),
            b"{}"
        );
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: receiver owns the socket; pid and len are writable outputs.
        let result = unsafe {
            libc::getsockopt(
                receiver.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                std::ptr::addr_of_mut!(pid).cast(),
                &mut len,
            )
        };
        assert_eq!(
            result, -1,
            "closed peer must no longer expose LOCAL_PEERPID"
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOTCONN)
        );
        assert!(require_server_incarnation(server).is_ok());
        let mut replaced = server;
        replaced.started_at += 1;
        assert_eq!(
            require_server_incarnation(replaced).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
        );
    }

    #[test]
    fn stale_socket_requires_explicit_refusal_and_preserves_unknown_probes() {
        let _env = crate::platform::test_env::lock();
        let dir = fixture();
        let path = dir.path().join(SOCKET);
        make_stale_socket(&path);
        let original = fs::symlink_metadata(&path).unwrap();
        for result in [
            Ok(()),
            Err(refusal(io::ErrorKind::TimedOut, "fixture_unknown")),
        ] {
            assert!(
                recover_stale_socket(&path, &private_dir(dir.path()).unwrap(), |_| result).is_err(),
                "only explicit connection refusal may reclaim a socket"
            );
            assert!(same_object(
                &original,
                &fs::symlink_metadata(&path).unwrap()
            ));
        }
        let recovered =
            ControlServer::bind(dir.path()).expect("stale same-UID socket must be recovered");
        let client = UnixStream::connect(recovered.path()).unwrap();
        drop(client);
    }

    #[test]
    fn stale_socket_rechecks_directory_and_inode_before_unlink() {
        let _env = crate::platform::test_env::lock();
        let root = fixture();
        let dir = root.path().join("handle");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(SOCKET);
        drop(UnixListener::bind(&path).unwrap());
        let dir_meta = private_dir(&dir).unwrap();
        assert!(
            recover_stale_socket(&path, &dir_meta, |p| {
                fs::remove_file(p)?;
                fs::write(p, b"foreign replacement")?;
                Err(io::Error::from_raw_os_error(libc::ECONNREFUSED))
            })
            .is_err(),
            "replacement inode must not grant unlink authority"
        );
        assert_eq!(fs::read(&path).unwrap(), b"foreign replacement");
        fs::remove_file(&path).unwrap();
        drop(UnixListener::bind(&path).unwrap());
        let parked = root.path().join("parked");
        let mut replacement_listener = None;
        assert!(
            recover_stale_socket(&path, &dir_meta, |p| {
                fs::rename(&dir, &parked)?;
                fs::create_dir(&dir)?;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                replacement_listener = Some(UnixListener::bind(p)?);
                Err(io::Error::from_raw_os_error(libc::ECONNREFUSED))
            })
            .is_err(),
            "replacement directory must not grant unlink authority"
        );
        assert!(path.exists());
        assert!(parked.join(SOCKET).exists());
        drop(replacement_listener);
    }

    #[test]
    fn expired_control_request_refuses_reply_before_queueing() {
        let req = ControlRequest::for_test(me(), b"{}".to_vec(), Instant::now());
        assert!(
            req.is_expired(),
            "request deadline must be visible to the loop before authorization"
        );
        assert_eq!(
            req.reply(b"{}").unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "expired request must not enqueue a reply"
        );
    }

    #[test]
    fn request_lease_clamp_never_extends_and_revokes_only_write_descendants() {
        let now = Instant::now();
        let end = now + Duration::from_secs(30);
        let req = ControlRequest::for_test(me(), b"{}".to_vec(), end);
        let original = req.lease();
        let earlier = now + Duration::from_secs(10);
        let shortened = original.clamp(earlier);
        assert_eq!(shortened.deadline(), earlier);
        assert_eq!(shortened.clamp(end).deadline(), earlier);
        assert_eq!(original.clamp(end + IO_BOUND).deadline(), end);
        assert!(!original.is_expired());
        assert!(!shortened.is_expired());

        let expired = shortened.clamp(now);
        let sibling = expired.clone();
        let descendant = sibling.clamp(end);
        assert!(
            expired.is_expired(),
            "exclusive cutoff must revoke the lease"
        );
        assert!(
            sibling.is_expired(),
            "a sibling cannot resume after revocation"
        );
        assert!(
            descendant.is_expired(),
            "child leases cannot escape parent loss"
        );
        assert!(
            !req.is_expired(),
            "R1_M4: a write cutoff must leave the reply authority alive"
        );
        assert!(!original.clamp(end).is_expired());
        shortened.revoke();
        assert!(shortened.clamp(end).is_expired());
        assert!(!req.is_expired());
    }

    #[test]
    fn test_request_dropped_reply_receiver_does_not_cancel_lease() {
        let end = Instant::now() + Duration::from_secs(30);
        let req = ControlRequest::for_test(me(), b"{}".to_vec(), end);
        assert_eq!(req.lease().deadline(), end);
        assert!(!req.is_expired());
        assert_eq!(
            req.reply(b"{}").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe,
            "test helper's dropped receiver is not a worker cancellation"
        );
    }

    #[test]
    fn worker_stop_revokes_queued_lease_before_original_deadline() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.write_all(b"{}\n").unwrap();
        let (send, recv) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let end = Instant::now() + Duration::from_secs(30);
        let worker = thread::spawn(move || serve_until(worker, me(), send, &worker_stop, end));
        let req = recv.recv_timeout(IO_BOUND).unwrap();
        let lease = req.lease();
        assert!(!lease.is_expired());
        stop.store(true, Ordering::Release);
        assert!(worker.join().unwrap().is_err());
        assert!(
            Instant::now() < end,
            "worker stop must not await the cutoff"
        );
        assert!(
            lease.is_expired(),
            "worker exit must revoke queued authority"
        );
        assert!(req.is_expired());
    }

    #[test]
    fn clamped_write_expiry_still_allows_honest_reply_in_original_window() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.set_nonblocking(true).unwrap();
        caller.write_all(b"{}\n").unwrap();
        let (send, recv) = mpsc::sync_channel(1);
        let end = Instant::now() + Duration::from_secs(30);
        let worker =
            thread::spawn(move || serve_until(worker, me(), send, &AtomicBool::new(false), end));
        let req = recv.recv_timeout(IO_BOUND).unwrap();
        let write_lease = req.lease().clamp(Instant::now());
        assert!(write_lease.is_expired());
        assert!(
            !req.is_expired(),
            "R1_M4: write expiry must not revoke the reply window"
        );
        let frame = br#"{"outcome":"refused","error":{"code":"request_expired"}}"#;
        req.reply(frame).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(
            read_line(
                &mut caller,
                Instant::now() + IO_BOUND,
                &AtomicBool::new(false)
            )
            .unwrap(),
            frame,
            "R1_M4: an honest expired-write refusal must reach the still-connected caller"
        );
    }

    #[test]
    fn queued_client_full_disconnect_revokes_lease_before_original_deadline() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.write_all(b"{}\n").unwrap();
        let (send, recv) = mpsc::sync_channel(1);
        let (done, finished) = mpsc::sync_channel(1);
        let (release, keep_alive) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let end = Instant::now() + Duration::from_secs(30);
        let worker = thread::spawn(move || {
            let result = serve_until(worker, me(), send, &worker_stop, end);
            let _ = done.send(());
            // Keep the thread alive until the caller records revocation. Its
            // eventual exit/join must not supply the observation under test.
            // Dropping release during unwind also unblocks this receive.
            let _ = keep_alive.recv();
            result
        });
        let queued = recv.recv_timeout(IO_BOUND);
        let lease = queued.as_ref().ok().map(ControlRequest::lease);
        let initially_live = lease.as_ref().is_some_and(|lease| !lease.is_expired());
        drop(caller);
        let disconnected = finished.recv_timeout(IO_BOUND);
        let revoked_before_cleanup = lease.as_ref().is_some_and(RequestLease::is_expired);
        let before_original_deadline = Instant::now() < end;
        // Capture above, then always release/reap before any assertion. Even a
        // mutant that leaks the lease or ignores disconnect gets safe cleanup.
        stop.store(true, Ordering::Release);
        let _ = release.send(());
        let terminal = worker.join();
        assert!(
            queued.is_ok(),
            "the full-close fixture must admit one request"
        );
        assert!(initially_live, "the queued lease must initially be live");
        assert!(disconnected.is_ok(), "R1_M3_FULL_DISCONNECT_REVOKES: worker must observe full close before the original deadline");
        assert!(before_original_deadline);
        assert!(
            revoked_before_cleanup,
            "R2_M3_REVOCATION_BEFORE_CLEANUP: full close must revoke the live queued lease before stop, thread exit or join"
        );
        assert!(
            matches!(terminal, Ok(Err(_))),
            "full close must end the worker with a transport refusal"
        );
    }

    #[test]
    fn queued_client_write_half_close_preserves_reply_receiver() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.set_nonblocking(true).unwrap();
        let probe = worker.try_clone().unwrap();
        caller.write_all(b"{}\n").unwrap();
        let (send, recv) = mpsc::sync_channel(1);
        let end = Instant::now() + IO_BOUND;
        let worker =
            thread::spawn(move || serve_until(worker, me(), send, &AtomicBool::new(false), end));
        let req = recv.recv_timeout(IO_BOUND).unwrap();
        caller.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            !peer_disconnected(&probe).unwrap(),
            "R1_M3_HALF_CLOSE: a peer still receiving replies must retain authority"
        );
        drop(probe);
        req.reply(b"{}").unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(
            read_line(
                &mut caller,
                Instant::now() + IO_BOUND,
                &AtomicBool::new(false)
            )
            .unwrap(),
            b"{}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_hangup_probe_distinguishes_full_and_half_close_without_wire_bytes() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.set_nonblocking(true).unwrap();
        no_sigpipe(&worker).unwrap();
        caller.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            !peer_disconnected(&worker).unwrap(),
            "R1_M3_DARWIN_HALF_CLOSE: a live reply receiver must survive the probe"
        );
        let mut byte = [0u8; 1];
        assert!(
            matches!(caller.read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "R1_M3_ZERO_PROBE_NO_PAYLOAD: the disconnect probe must add no wire byte"
        );
        drop(caller);
        assert!(
            peer_disconnected(&worker).unwrap(),
            "R1_M3_DARWIN_FULL_CLOSE: full close must be distinguished without a deadline wait"
        );
    }

    #[test]
    fn serve_lifecycle_reuses_one_absolute_deadline() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.write_all(b"{}\n").unwrap();
        let (send, recv) = mpsc::sync_channel(1);
        let end = Instant::now() + IO_BOUND;
        let worker =
            thread::spawn(move || serve_until(worker, me(), send, &AtomicBool::new(false), end));
        let req = recv.recv_timeout(IO_BOUND).unwrap();
        assert_eq!(
            req.lease().deadline(),
            end,
            "queue must carry the original read deadline"
        );
        assert!(!req.is_expired());
        let lease = req.lease();
        req.reply(b"{}").unwrap();
        worker.join().unwrap().unwrap();
        assert!(
            lease.is_expired(),
            "successful worker exit also ends authority"
        );
    }

    #[test]
    fn reauth_mismatch_returns_fixed_undetermined_and_never_queues() {
        let (worker, mut caller) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        caller.set_nonblocking(true).unwrap();
        no_sigpipe(&worker).unwrap();
        caller.write_all(b"{}\n").unwrap();
        let (send, recv) = mpsc::sync_channel(1);
        let mut wrong = me();
        wrong.started_at += 1;
        assert_eq!(
            serve_one(worker, wrong, send, &AtomicBool::new(false))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            read_line(
                &mut caller,
                Instant::now() + IO_BOUND,
                &AtomicBool::new(false)
            )
            .is_ok_and(|frame| frame == UNDETERMINED_FRAME),
            "identity mismatch must best-effort return the closed undetermined frame"
        );
        assert!(
            matches!(recv.try_recv(), Err(mpsc::TryRecvError::Disconnected)),
            "reauth mismatch must never enqueue a command"
        );
    }

    #[test]
    fn peer_chronology_is_bracketed_by_exact_identity_and_allows_only_one_second() {
        use std::cell::Cell;
        assert_eq!(
            bracketed_peer_start(1, 10, |_| Some(123), |_| Some(11)).unwrap(),
            123
        );
        assert!(
            bracketed_peer_start(1, 10, |_| Some(123), |_| Some(12)).is_err(),
            "peer chronology must not allow more than one second"
        );
        let reads = Cell::new(0);
        assert!(
            bracketed_peer_start(
                1,
                10,
                |_| {
                    let n = reads.get();
                    reads.set(n + 1);
                    Some(123 + n)
                },
                |_| Some(10)
            )
            .is_err(),
            "exact identity must bracket the seconds reading"
        );
        assert!(bracketed_peer_start(1, 10, |_| None, |_| Some(10)).is_err());
    }

    #[test]
    fn accept_failure_backoff_waits_and_idle_poll_is_not_a_reap_spin() {
        let (wake, mut writer) = UnixStream::pair().unwrap();
        let start = Instant::now();
        accept_backoff(&wake, &AtomicBool::new(false));
        assert!(
            start.elapsed() >= ACCEPT_BACKOFF,
            "accept failure must enforce backoff"
        );
        assert!(
            ACCEPT_IDLE >= Duration::from_millis(250),
            "idle worker reap must not poll every 25ms"
        );
        writer.write_all(b"x").unwrap();
        assert!(
            wait_fd(
                wake.as_raw_fd(),
                libc::POLLIN,
                Instant::now() + ACCEPT_BACKOFF,
                &AtomicBool::new(false)
            )
            .is_ok(),
            "wake descriptor must interrupt the idle/backoff poll"
        );
    }

    #[derive(Default)]
    struct DiagnosticFields {
        names: Vec<String>,
        tag: Option<String>,
        suppressed: Option<u64>,
    }

    impl tracing::field::Visit for DiagnosticFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.names.push(field.name().to_owned());
            if field.name() == "event" {
                self.tag = Some(value.to_owned());
            }
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.names.push(field.name().to_owned());
            if field.name() == "suppressed" {
                self.suppressed = Some(value);
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, _: &dyn std::fmt::Debug) {
            self.names.push(field.name().to_owned());
        }
    }

    struct DiagnosticCapture(Arc<Mutex<Vec<DiagnosticFields>>>);

    impl tracing::Subscriber for DiagnosticCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = DiagnosticFields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields);
        }
    }

    #[test]
    fn refusal_diagnostics_are_closed_vocabulary_and_rate_limited() {
        let _capture = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut limiter = DiagnosticLimiter::new();
        let now = Instant::now();
        for tag in FailureTag::ALL {
            assert_eq!(limiter.record(tag, now), Some(0));
            assert_eq!(
                limiter.record(tag, now),
                None,
                "repeated refusal must be rate limited"
            );
            assert_eq!(
                limiter.record(tag, now + DIAGNOSTIC_INTERVAL),
                Some(1),
                "next emission must report suppressed refusals"
            );
        }
        let captured = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(DiagnosticCapture(captured.clone()), || {
            tracing::callsite::rebuild_interest_cache();
            for tag in FailureTag::ALL {
                emit_diagnostic(tag, 7);
            }
        });
        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.len(),
            FailureTag::ALL.len(),
            "every closed refusal tag must emit"
        );
        for (event, tag) in captured.iter().zip(FailureTag::ALL) {
            assert_eq!(event.tag.as_deref(), Some(tag.wire()));
            assert_eq!(event.suppressed, Some(7));
            let mut names = event.names.clone();
            names.sort();
            assert_eq!(
                names,
                ["event", "message", "suppressed"],
                "diagnostic must contain only fixed tag, message and counter"
            );
        }
    }

    #[test]
    fn restrictive_mask_covers_bind_before_chmod_and_restores_on_error() {
        let _mask = crate::platform::test_env::UmaskGuard::pin(0);
        let dir = fixture();
        let path = dir.path().join(SOCKET);
        let listener = bind_private(&path, |p| {
            let listener = UnixListener::bind(p)?;
            assert_eq!(
                fs::symlink_metadata(p)?.mode() & 0o777,
                0o700,
                "socket creation must already be private before explicit chmod"
            );
            Ok(listener)
        })
        .unwrap();
        assert!(bind_private(&path, |p| UnixListener::bind(p)).is_err());
        // SAFETY: test owns the process-global env/umask lock through UmaskGuard.
        let mask = unsafe { libc::umask(0) };
        assert_eq!(mask, 0, "failed bind must restore the entering mask");
        drop(listener);
    }
}
