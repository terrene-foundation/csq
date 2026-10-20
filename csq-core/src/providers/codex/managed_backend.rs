//! Private transport to the native Codex server owning a terminal's threads.
//!
//! Codex 0.160.1 uses WebSocket JSON-RPC over its Unix socket (`/rpc`). An
//! embedded TUI cannot be attached externally. The supervisor launches the
//! native server, attaches its TUI using `--remote`, and owns both lifetimes.
//! This module never resumes an unloaded thread or manufactures a user prompt.
//! `thread/queue/start` selects an existing durable notice on the owning server.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DIRECTORY: &str = ".csq-native";
const SOCKET: &str = "rpc.sock";
const BINDING: &str = ".csq-native-backend.json";
const MAX_MESSAGE: usize = 1024 * 1024;
const MAX_BINDING: u64 = 16 * 1024;

/// Exact launch incarnation, independent of the recipient TUI process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LauncherIdentity {
    pub pid: u32,
    pub started_exact: u64,
}

impl LauncherIdentity {
    pub fn capture(pid: u32) -> io::Result<Self> {
        let started_exact = crate::sessions::ancestor_start(pid)
            .ok_or_else(|| refused("native backend launch identity unavailable"))?;
        Ok(Self { pid, started_exact })
    }

    pub fn verify(&self) -> io::Result<()> {
        if crate::sessions::ancestor_start(self.pid) != Some(self.started_exact) {
            return Err(refused("native backend launch incarnation changed"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ManagedBackendPlan {
    handle_dir: PathBuf,
    sqlite_home: PathBuf,
    socket_path: PathBuf,
}

/// Persisted endpoint identity. A backend PID is not a recipient session PID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendBinding {
    schema_version: u32,
    handle_dir: PathBuf,
    sqlite_home: PathBuf,
    socket_path: PathBuf,
    pub launcher: LauncherIdentity,
    pub native: LauncherIdentity,
    socket_device: u64,
    socket_inode: u64,
    handle_device: u64,
    handle_inode: u64,
    recipient: Option<LauncherIdentity>,
}

impl BackendBinding {
    /// Publish only after the actual TUI has spawned. The backend and recipient
    /// identities are separate; a backend alone does not authorize delivery.
    #[cfg(unix)]
    pub fn publish_recipient(&mut self, recipient: &LauncherIdentity) -> io::Result<()> {
        self.launcher.verify()?;
        self.native.verify()?;
        recipient.verify()?;
        self.recipient = Some(recipient.clone());
        let identity = directory_identity(&self.handle_dir)?;
        if identity != (self.handle_device, self.handle_inode) {
            return Err(refused("native handle incarnation changed"));
        }
        write_binding(&self.handle_dir.join(BINDING), self)
    }

    fn verify_live(&self, expected_recipient: &LauncherIdentity) -> io::Result<()> {
        if self.recipient.as_ref() != Some(expected_recipient) {
            return Err(refused("native backend belongs to another recipient"));
        }
        self.launcher.verify()?;
        self.native.verify()?;
        self.recipient
            .as_ref()
            .ok_or_else(|| refused("native recipient is not bound"))?
            .verify()
    }

    /// Removes only this retired incarnation's marker and socket. The
    /// supervisor must first stop and reap its native backend, not just its TUI.
    #[cfg(unix)]
    pub fn retire_after_exit(&self) -> io::Result<()> {
        if crate::sessions::ancestor_start(self.native.pid) == Some(self.native.started_exact) {
            return Err(refused("cannot retire a live native backend"));
        }
        if is_configured(&self.handle_dir)
            && read_binding(&self.handle_dir, &self.sqlite_home)? != *self
        {
            return Err(refused("native binding belongs to another incarnation"));
        }
        match socket_metadata(&self.socket_path) {
            Ok(identity) if identity == (self.socket_device, self.socket_inode) => {
                let physical = physical_socket_path(&self.socket_path)?;
                if physical != self.socket_path {
                    std::fs::remove_file(physical)?;
                }
                std::fs::remove_file(&self.socket_path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(refused("cannot retire a replaced native socket")),
            Err(error) => return Err(error),
        }
        match std::fs::remove_file(self.handle_dir.join(BINDING)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl ManagedBackendPlan {
    /// Creates only this handle's private runtime directory. Existing sockets
    /// are refused; the owner must first finish the previous backend lifetime.
    #[cfg(unix)]
    pub fn prepare(handle_dir: &Path, sqlite_home: &Path) -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        validate_owned_handle(handle_dir)?;
        let handle_dir = handle_dir.canonicalize()?;
        let sqlite_home = sqlite_home.canonicalize()?;
        let directory = handle_dir.join(DIRECTORY);
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        validate_private_directory(&directory)?;
        let socket_path = directory.join(SOCKET);
        use std::os::unix::ffi::OsStrExt;
        if socket_path.as_os_str().as_bytes().len() >= native_socket_path_limit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native socket path too long",
            ));
        }
        if std::fs::symlink_metadata(&socket_path).is_ok() {
            return Err(refused("native backend socket already exists"));
        }
        Ok(Self {
            handle_dir,
            sqlite_home,
            socket_path,
        })
    }

    pub fn sqlite_home(&self) -> &Path {
        &self.sqlite_home
    }

    pub fn endpoint_url(&self) -> String {
        format!("unix://{}", self.socket_path.display())
    }

    /// Only native global configuration overrides belong on the backend. TUI
    /// resume, prompt, terminal and interaction flags stay on the TUI command.
    pub fn backend_argv(&self, global_config_overrides: &[OsString]) -> io::Result<Vec<OsString>> {
        if !global_config_overrides.len().is_multiple_of(2)
            || global_config_overrides
                .as_chunks::<2>()
                .0
                .iter()
                .any(|pair| (pair[0] != "-c" && pair[0] != "--config") || pair[1].is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backend accepts only global configuration pairs",
            ));
        }
        let mut argv = global_config_overrides.to_vec();
        // StateRuntime is process-scoped. Pin the supervisor's selected account
        // after all inherited overrides so the published binding describes it.
        let sqlite = self.sqlite_home.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "native state path is not UTF-8",
            )
        })?;
        argv.extend([
            OsString::from("-c"),
            OsString::from(format!("sqlite_home={}", serde_json::json!(sqlite))),
        ]);
        argv.extend([
            OsString::from("app-server"),
            OsString::from("--listen"),
            OsString::from(self.endpoint_url()),
        ]);
        Ok(argv)
    }

    #[cfg(unix)]
    pub fn publish_binding(
        &self,
        launcher: &LauncherIdentity,
        timeout: Duration,
    ) -> io::Result<BackendBinding> {
        let deadline = deadline(timeout)?;
        launcher.verify()?;
        let (stream, native_pid, device, inode) =
            connect_checked(&self.socket_path, None, deadline)?;
        if native_pid != launcher.pid
            && !super::ancestry::ancestor_chain(
                native_pid,
                super::ancestry::DEFAULT_ANCESTOR_CHAIN_BOUND,
            )
            .contains(&launcher.pid)
        {
            return Err(refused(
                "native socket peer is outside the launched backend",
            ));
        }
        let native = LauncherIdentity::capture(native_pid)?;
        let mut client = RpcClient::initialize(stream, &self.handle_dir, deadline)?;
        client.close();
        launcher.verify()?;
        native.verify()?;
        let (handle_device, handle_inode) = directory_identity(&self.handle_dir)?;
        let binding = BackendBinding {
            schema_version: 1,
            handle_dir: self.handle_dir.clone(),
            sqlite_home: self.sqlite_home.clone(),
            socket_path: self.socket_path.clone(),
            launcher: launcher.clone(),
            native,
            socket_device: device,
            socket_inode: inode,
            handle_device,
            handle_inode,
            recipient: None,
        };
        Ok(binding)
    }
}

#[cfg(unix)]
fn native_socket_path_limit() -> usize {
    // SAFETY: sockaddr_un is a plain C address structure; zero initialization
    // is valid and lets us inspect the platform's fixed-size sun_path field.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_path.len()
}

fn deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .filter(|_| !timeout.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid native RPC timeout"))
}

/// Presence includes malformed or unreadable markers: callers must refuse a
/// configured backend failure instead of silently launching a second server.
pub fn is_configured(handle_dir: &Path) -> bool {
    !matches!(
        std::fs::symlink_metadata(handle_dir.join(BINDING)),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    )
}

/// Caller proof minted only by this module after authenticating the owning
/// backend and validating its bound native TUI through csq's existing target
/// checks. Native internal threads retain their existing process-level identity.
#[derive(Debug)]
pub struct ManagedCaller {
    recipient: LauncherIdentity,
    native: LauncherIdentity,
    started_at: u64,
    handle_dir: PathBuf,
}

impl ManagedCaller {
    pub fn recipient(&self) -> &LauncherIdentity {
        &self.recipient
    }
    pub fn native(&self) -> &LauncherIdentity {
        &self.native
    }
    pub fn started_at(&self) -> u64 {
        self.started_at
    }
    pub fn handle_dir(&self) -> &Path {
        &self.handle_dir
    }
}

/// A remote TUI executes tools in the native server. Only that exact server's
/// descendants can use its private binding to assume the bound TUI identity.
/// A direct TUI child returns None and uses the ordinary ancestor resolver.
#[cfg(unix)]
pub fn resolve_managed_caller(
    handle: &Path,
    timeout: Duration,
) -> io::Result<Option<ManagedCaller>> {
    resolve_managed_caller_with(
        handle,
        timeout,
        &|native| {
            native.verify()?;
            crate::sessions::codex_launch_for_pid(native.pid)
                .and_then(|launch| launch.sqlite_home)
                .ok_or_else(|| refused("native backend account provenance unavailable"))
        },
        &|native| {
            prove_backend_caller_ancestry(
                native,
                &crate::sessions::ancestor_path_of_current,
                &crate::sessions::is_session_hop,
            )
        },
        &validate_bound_recipient,
    )
}

#[cfg(unix)]
fn prove_backend_caller_ancestry(
    native: &LauncherIdentity,
    ancestry: &dyn Fn(u32) -> Option<Option<crate::sessions::AncestorHops>>,
    hop: &dyn Fn(u32, u64) -> Option<bool>,
) -> io::Result<Option<crate::sessions::AncestorHops>> {
    native.verify()?;
    let Some(path) = ancestry(native.pid) else {
        return Err(refused("managed caller ancestry unreadable"));
    };
    let Some(path) = path else {
        return Ok(None);
    };
    for (pid, start) in &path {
        match hop(*pid, *start) {
            Some(false) => {}
            Some(true) => return Err(refused("managed caller contains a nearer CLI session")),
            None => return Err(refused("managed caller hop unreadable or changed")),
        }
    }
    native.verify()?;
    Ok(Some(path))
}

#[cfg(unix)]
fn validate_bound_recipient(
    binding: &BackendBinding,
    recipient: &LauncherIdentity,
) -> io::Result<u64> {
    use crate::sessions;
    let (info, exact) =
        sessions::session_info_exact_for_pid_kind(sessions::CliKind::Codex, recipient.pid)
            .map_err(|_| refused("managed TUI identity unreadable"))?
            .ok_or_else(|| refused("managed recipient is not a native TUI session"))?;
    let started = info
        .started_at
        .ok_or_else(|| refused("managed TUI start unavailable"))?;
    if exact != recipient.started_exact || info.config_dir.canonicalize()? != binding.handle_dir {
        return Err(refused("managed TUI handle or incarnation changed"));
    }
    let launch = sessions::codex_launch_for_session(recipient.pid, started, exact)
        .ok_or_else(|| refused("managed TUI launch provenance unavailable"))?;
    let accounts = binding
        .handle_dir
        .parent()
        .ok_or_else(|| refused("managed handle account root unavailable"))?;
    let target = sessions::wake_target_ok(accounts, recipient.pid, &binding.handle_dir, &launch)
        .ok_or_else(|| refused("managed TUI is not the supervisor's own launch"))?;
    if !target.still_live() || target.sqlite_home() != binding.sqlite_home {
        return Err(refused("managed TUI account or launch changed"));
    }
    recipient.verify()?;
    Ok(started)
}

#[cfg(unix)]
fn resolve_managed_caller_with(
    handle: &Path,
    timeout: Duration,
    native_sqlite: &dyn Fn(&LauncherIdentity) -> io::Result<PathBuf>,
    ancestry: &dyn Fn(&LauncherIdentity) -> io::Result<Option<crate::sessions::AncestorHops>>,
    recipient_check: &dyn Fn(&BackendBinding, &LauncherIdentity) -> io::Result<u64>,
) -> io::Result<Option<ManagedCaller>> {
    let deadline = deadline(timeout)?;
    let initial = read_binding_record(handle)?;
    let recipient = initial
        .recipient
        .clone()
        .ok_or_else(|| refused("managed recipient not published"))?;
    initial.verify_live(&recipient)?;
    let sqlite = native_sqlite(&initial.native)?;
    let binding = read_binding(handle, &sqlite)?;
    if binding != initial {
        return Err(refused("managed caller binding changed"));
    }
    let before = ancestry(&binding.native)?;
    let (stream, _, _, _) = connect_checked(&binding.socket_path, Some(&binding), deadline)?;
    let mut client = RpcClient::initialize(stream, &binding.handle_dir, deadline)?;
    client.close();
    binding.verify_live(&recipient)?;
    if read_binding(handle, &sqlite)? != binding || ancestry(&binding.native)? != before {
        return Err(refused(
            "managed caller provenance changed during authentication",
        ));
    }
    let Some(_) = before else {
        return Ok(None);
    };
    let started_at = recipient_check(&binding, &recipient)?;
    binding.verify_live(&recipient)?;
    if ancestry(&binding.native)? != before || read_binding(handle, &sqlite)? != binding {
        return Err(refused("managed caller provenance changed before mint"));
    }
    if recipient_check(&binding, &recipient)? != started_at {
        return Err(refused("managed recipient changed before mint"));
    }
    Ok(Some(ManagedCaller {
        recipient,
        native: binding.native,
        started_at,
        handle_dir: binding.handle_dir,
    }))
}

/// Enqueues only csq's fixed wake notice using the native owning service.
#[cfg(unix)]
pub fn enqueue_notice(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    thread_id: &str,
    unread: usize,
    timeout: Duration,
) -> io::Result<String> {
    enqueue_summary(
        handle_dir,
        expected_sqlite_home,
        expected_recipient,
        thread_id,
        &crate::messaging::store::PendingNotice::count_only(unread),
        timeout,
    )
}

/// Enqueue a safely framed stored summary through the native owning service.
#[cfg(unix)]
pub fn enqueue_summary(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    thread_id: &str,
    summary: &crate::messaging::store::PendingNotice,
    timeout: Duration,
) -> io::Result<String> {
    validate_id(thread_id)?;
    let deadline = deadline(timeout)?;
    let binding = read_binding(handle_dir, expected_sqlite_home)?;
    binding.verify_live(expected_recipient)?;
    let (stream, _, _, _) = connect_checked(&binding.socket_path, Some(&binding), deadline)?;
    let mut client = RpcClient::initialize(stream, &binding.handle_dir, deadline)?;
    binding.verify_live(expected_recipient)?;
    let message_id = uuid::Uuid::new_v4().to_string();
    let response = client.request("thread/queue/add", serde_json::json!({
        "threadId":thread_id,
        "input":[{"type":"text","text":crate::messaging::frame::render_preview_notice(summary),"textElements":[]}],
        "clientUserMessageId":message_id,
    }))?;
    let item = response
        .get("queuedSubmission")
        .ok_or_else(|| protocol("native queue add omitted submission"))?;
    if item
        .get("clientUserMessageId")
        .and_then(serde_json::Value::as_str)
        != Some(message_id.as_str())
    {
        return Err(protocol(
            "native queue add returned another message identity",
        ));
    }
    let id = item
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| protocol("native queue add omitted item identity"))?;
    validate_id(id)?;
    let id = id.to_owned();
    client.close();
    Ok(id)
}

/// Remove only a caller-proven csq item whose native stored input still equals
/// the fixed notice for that generation. Already consumed items return false;
/// this operation never interrupts a turn or deletes arbitrary queue contents.
#[cfg(unix)]
pub fn delete_notice(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    thread_id: &str,
    item_id: &str,
    unread: usize,
    timeout: Duration,
) -> io::Result<bool> {
    validate_id(thread_id)?;
    validate_id(item_id)?;
    let deadline = deadline(timeout)?;
    let binding = read_binding(handle_dir, expected_sqlite_home)?;
    binding.verify_live(expected_recipient)?;
    let (stream, _, _, _) = connect_checked(&binding.socket_path, Some(&binding), deadline)?;
    let mut client = RpcClient::initialize(stream, &binding.handle_dir, deadline)?;
    let expected = crate::messaging::wake::notice(unread);
    let mut cursor = None::<String>;
    let mut total = 0usize;
    loop {
        let page = client.request(
            "thread/queue/list",
            serde_json::json!({"threadId":thread_id,"cursor":cursor,"limit":128}),
        )?;
        let items = page
            .get("data")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| protocol("native queue list omitted items"))?;
        total += items.len();
        if total > 1024 {
            return Err(protocol("native queue list exceeded bound"));
        }
        if let Some(item) = items
            .iter()
            .find(|item| item.get("id").and_then(serde_json::Value::as_str) == Some(item_id))
        {
            let input = item
                .get("input")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| protocol("native queue item omitted input"))?;
            if input.len() != 1
                || input[0].get("type").and_then(serde_json::Value::as_str) != Some("text")
                || input[0].get("text").and_then(serde_json::Value::as_str)
                    != Some(expected.as_str())
            {
                return Err(refused("native queued item is not the expected csq notice"));
            }
            binding.verify_live(expected_recipient)?;
            client.request(
                "thread/queue/delete",
                serde_json::json!({"threadId":thread_id,"queuedSubmissionId":item_id}),
            )?;
            client.close();
            return Ok(true);
        }
        match page.get("nextCursor") {
            None | Some(serde_json::Value::Null) => {
                client.close();
                return Ok(false);
            }
            Some(serde_json::Value::String(next))
                if !next.is_empty() && Some(next) != cursor.as_ref() =>
            {
                cursor = Some(next.clone())
            }
            _ => return Err(protocol("native queue list cursor did not advance")),
        }
    }
}

/// Whether a start must re-prove the target is idle and accepting direct
/// input. The child-completion path requires it: its wake exists precisely for
/// an idle parent. The interrupted-turn live path does NOT: that RPC exists to
/// start where automatic queue dispatch skips Interrupted, so its admission
/// stays exactly as it was before the child-wake lane.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StartAdmission {
    RequireIdle,
    AdmitAnyStatus,
}

/// Starts precisely an already-enqueued item. No queue/add, turn/start, resume,
/// credential RPC or fabricated message is sent by this operation.
#[cfg(unix)]
pub fn start_existing_queue_item(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    thread_id: &str,
    item_id: &str,
    admission: StartAdmission,
    timeout: Duration,
) -> io::Result<String> {
    validate_id(thread_id)?;
    validate_id(item_id)?;
    let deadline = deadline(timeout)?;
    let binding = read_binding(handle_dir, expected_sqlite_home)?;
    binding.verify_live(expected_recipient)?;
    let (stream, _, _, _) = connect_checked(&binding.socket_path, Some(&binding), deadline)?;
    let mut client = RpcClient::initialize(stream, &binding.handle_dir, deadline)?;
    binding.verify_live(expected_recipient)?;
    if admission == StartAdmission::RequireIdle {
        // FRESH, under the caller's wake lock: the target thread must be idle
        // and accepting direct input at the moment of the start. Refusing is
        // fail-safe: the notice stays queued and the next trigger re-validates.
        let target = read_thread(&mut client, thread_id)?;
        if status_of(&target).as_deref() != Some(crate::providers::codex::child_wake::STATUS_IDLE)
            || can_accept_direct_input(&target) != Some(true)
        {
            client.close();
            return Err(refused(
                "native queue start refused: thread is not idle and accepting direct input",
            ));
        }
    }
    let response = client.request(
        "thread/queue/start",
        serde_json::json!({
            "threadId": thread_id, "queuedSubmissionId": item_id
        }),
    )?;
    let turn_id = response
        .get("turn")
        .and_then(|turn| turn.get("id"))
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| protocol("native queue start returned no turn identity"))?
        .to_owned();
    client.close();
    Ok(turn_id)
}

fn validate_id(id: &str) -> io::Result<()> {
    uuid::Uuid::parse_str(id).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid native queue identity")
    })?;
    Ok(())
}

/// Reads metadata for currently loaded threads from the owning native manager,
/// never filesystem recency. `includeTurns=false` avoids transcript retrieval.
#[cfg(unix)]
pub fn loaded_thread_metadata(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    timeout: Duration,
) -> io::Result<Vec<serde_json::Value>> {
    let deadline = deadline(timeout)?;
    let binding = read_binding(handle_dir, expected_sqlite_home)?;
    binding.verify_live(expected_recipient)?;
    let (stream, _, _, _) = connect_checked(&binding.socket_path, Some(&binding), deadline)?;
    let mut client = RpcClient::initialize(stream, &binding.handle_dir, deadline)?;
    let threads = loaded_threads_with(&mut client)?;
    binding.verify_live(expected_recipient)?;
    client.close();
    Ok(threads)
}

#[cfg(unix)]
fn loaded_threads_with(client: &mut RpcClient<'_>) -> io::Result<Vec<serde_json::Value>> {
    let mut threads = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor = None::<String>;
    loop {
        let page = client.request(
            "thread/loaded/list",
            serde_json::json!({"cursor":cursor,"limit":128}),
        )?;
        let ids = page
            .get("data")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| protocol("native loaded list omitted identities"))?;
        for id in ids {
            let id = id
                .as_str()
                .ok_or_else(|| protocol("invalid loaded thread identity"))?;
            validate_id(id)?;
            if !seen.insert(id.to_owned()) || seen.len() > 1024 {
                return Err(protocol(
                    "native loaded list repeated or exceeded identities",
                ));
            }
            let result = client.request(
                "thread/read",
                serde_json::json!({"threadId":id,"includeTurns":false}),
            )?;
            let thread = result
                .get("thread")
                .filter(|thread| thread.get("id").and_then(serde_json::Value::as_str) == Some(id))
                .ok_or_else(|| protocol("native thread metadata identity mismatch"))?;
            threads.push(thread.clone());
        }
        match page.get("nextCursor") {
            None | Some(serde_json::Value::Null) => break,
            Some(serde_json::Value::String(next))
                if !next.is_empty() && Some(next) != cursor.as_ref() =>
            {
                cursor = Some(next.clone())
            }
            _ => return Err(protocol("native loaded list cursor did not advance")),
        }
    }
    Ok(threads)
}

/// A handle-specific backend must have exactly one native CLI root. Spawned
/// agents carry structured `source: {subAgent: ...}` and are not candidates.
pub fn unique_loaded_cli_thread(threads: &[serde_json::Value]) -> io::Result<String> {
    let mut candidates = threads.iter().filter(|thread| {
        (thread.get("source").and_then(serde_json::Value::as_str) == Some("cli")
            || (thread.get("source").and_then(serde_json::Value::as_str) == Some("vscode")
                && thread
                    .get("threadSource")
                    .and_then(serde_json::Value::as_str)
                    == Some("user")))
            && thread
                .get("parentThreadId")
                .is_some_and(serde_json::Value::is_null)
            && matches!(
                thread
                    .get("status")
                    .and_then(|status| status.get("type"))
                    .and_then(serde_json::Value::as_str),
                Some("idle" | "active" | "systemError")
            )
            && thread
                .get("canAcceptDirectInput")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
    });
    let first = candidates
        .next()
        .ok_or_else(|| protocol("native CLI main thread is not loaded"))?;
    if candidates.next().is_some() {
        return Err(protocol("native CLI main thread is ambiguous"));
    }
    let id = first
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| protocol("native CLI main thread omitted identity"))?;
    validate_id(id)?;
    Ok(id.to_owned())
}

#[cfg(unix)]
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(100);
#[cfg(unix)]
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(5);
/// At most one reconnect warning per this interval while the backend is down.
#[cfg(unix)]
const RECONNECT_WARN_EVERY: Duration = Duration::from_secs(60);

/// Everything the watcher needs from its owner, below the connection layer.
#[cfg(unix)]
struct WatchCtx<'a> {
    main_thread: &'a dyn Fn() -> Option<String>,
    queued_item: &'a dyn Fn() -> Option<String>,
    start: &'a dyn Fn(&str, &str) -> io::Result<String>,
    stop: &'a dyn Fn() -> bool,
}

/// Subscribe to the owning native app-server's server-initiated notifications
/// and start a queued notice when a subagent thread finishes while the main
/// thread is idle.
///
/// The app-server PUSHES `thread/*` and `turn/*` notifications over the bound
/// socket csq already holds (codex-cli 0.163.0's protocol table), so this
/// watcher never polls thread state on a timer. Each notification that names a
/// CHILD thread triggers an authoritative `thread/read`, because the payload
/// shape is not a stable contract; a notification naming the supervised main
/// is skipped (main's status is read only on a child edge).
///
/// FAIL CLOSED: an unknown status, a thread not parented to the supervised
/// main thread, a busy main thread, an unreadable queue, or no queued item
/// produces no action. Starts are deduped on `(child, item)`.
///
/// Fail-closed and never silent:
/// - every connection failure, watcher error and deadline expiry is logged at
///   `warn` with a fixed vocabulary (no path, thread or message text), and the
///   watcher reconnects with bounded backoff while the supervisor lives;
/// - the handshake has its own bound (`RPC_HANDSHAKE_TIMEOUT`), never the
///   supervisor-lifetime total;
/// - notifications are coalesced per thread under a hard cap; an overflow
///   resyncs once from authoritative `thread/loaded/list` metadata;
/// - a start is deduped on `(child, item)`, so a duplicate notification cannot
///   start twice while a LATER completion with a new item still wakes.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn watch_child_completions(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    main_thread: &dyn Fn() -> Option<String>,
    queued_item: &dyn Fn() -> Option<String>,
    start: &dyn Fn(&str, &str) -> io::Result<String>,
    stop: &dyn Fn() -> bool,
    total: Duration,
    slice: Duration,
) -> io::Result<()> {
    let deadline = deadline(total)?;
    let slice = if slice.is_zero() {
        Duration::from_millis(1)
    } else {
        slice
    };
    let ctx = WatchCtx {
        main_thread,
        queued_item,
        start,
        stop,
    };
    let mut tracker = crate::providers::codex::child_wake::ChildWakeTracker::default();
    let mut started: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut seeded = false;
    let mut backoff = RECONNECT_BACKOFF_MIN;
    // A down backend is warned about at most once per minute: the watcher may
    // live for 12 hours, and one warn every 5 s is noise, not signal.
    let mut last_warn: Option<Instant> = None;
    loop {
        if stop() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            tracing::warn!(event = "child_wake", outcome = "deadline_reached");
            return Ok(());
        }
        let outcome = connect_and_watch(
            handle_dir,
            expected_sqlite_home,
            expected_recipient,
            &ctx,
            &mut tracker,
            &mut started,
            &mut seeded,
            &mut backoff,
            deadline,
            slice,
        );
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) => {
                if stop() {
                    // A stop that interrupted a request is a clean stop, not a
                    // deadline expiry.
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    tracing::warn!(
                        event = "child_wake",
                        outcome = "deadline_reached",
                        error_kind = %error.kind()
                    );
                    return Ok(());
                }
                let due = last_warn.is_none_or(|at| at.elapsed() >= RECONNECT_WARN_EVERY);
                if due {
                    last_warn = Some(Instant::now());
                    tracing::warn!(
                        event = "child_wake",
                        outcome = "reconnect",
                        error_kind = %error.kind()
                    );
                } else {
                    tracing::debug!(
                        event = "child_wake",
                        outcome = "reconnect",
                        error_kind = %error.kind()
                    );
                }
                if backoff_sleep(backoff, stop, deadline) {
                    return Ok(());
                }
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
            }
        }
    }
}

/// Sleep in short steps so the stop flag and the total deadline are honored.
/// Returns true when the watcher must stop.
#[cfg(unix)]
fn backoff_sleep(mut wait: Duration, stop: &dyn Fn() -> bool, deadline: Instant) -> bool {
    while !wait.is_zero() {
        if stop() || Instant::now() >= deadline {
            return true;
        }
        let step = wait.min(Duration::from_millis(50));
        std::thread::sleep(step);
        wait -= step;
    }
    false
}

/// One connection's lifetime. `Ok(())` means the stop flag fired; `Err` is a
/// transport/backend failure the caller retries with backoff.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn connect_and_watch(
    handle_dir: &Path,
    expected_sqlite_home: &Path,
    expected_recipient: &LauncherIdentity,
    ctx: &WatchCtx<'_>,
    tracker: &mut crate::providers::codex::child_wake::ChildWakeTracker,
    started: &mut std::collections::HashSet<(String, String)>,
    seeded: &mut bool,
    backoff: &mut Duration,
    deadline: Instant,
    slice: Duration,
) -> io::Result<()> {
    let binding = read_binding(handle_dir, expected_sqlite_home)?;
    binding.verify_live(expected_recipient)?;
    let (stream, _, _, _) = connect_checked(&binding.socket_path, Some(&binding), deadline)?;
    let mut client = RpcClient::initialize_watch(stream, &binding.handle_dir, deadline, ctx.stop)?;
    client.set_slice(slice);
    if !*seeded {
        // Seed so a child that was ALREADY active before we subscribed still
        // produces an edge on its first idle observation.
        let loaded = match loaded_threads_with(&mut client) {
            Ok(loaded) => loaded,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                client.close();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        for thread in loaded {
            if (ctx.stop)() {
                client.close();
                return Ok(());
            }
            if let (Some(id), Some(status)) = (thread_id_of(&thread), status_of(&thread)) {
                tracker.seed(&id, &status);
            }
        }
        *seeded = true;
    } else {
        // A reconnect or overflow: observe authoritative statuses through the
        // same edge machinery. A child last seen ACTIVE that finished while
        // the connection was down still produces its edge here.
        match resync_threads(&mut client, ctx, tracker, started) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                client.close();
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    // The connection is healthy through the seed: the next reconnect starts
    // from the minimum backoff again instead of the last failure's maximum.
    *backoff = RECONNECT_BACKOFF_MIN;
    binding.verify_live(expected_recipient)?;
    loop {
        if (ctx.stop)() {
            client.close();
            return Ok(());
        }
        let event = match client.next_event() {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                client.close();
                return Ok(());
            }
            Err(error) => {
                client.close();
                return Err(error);
            }
        };
        match event {
            WakeEvent::Idle => continue,
            WakeEvent::Resync => {
                tracing::warn!(event = "child_wake", outcome = "notification_overflow");
                resync_threads(&mut client, ctx, tracker, started)?;
            }
            WakeEvent::Notification(thread) => {
                // The supervised main is never a child candidate, and its own
                // notifications do not need a read: main's status is only
                // needed on a child edge, where `consider_thread` re-reads it.
                if (ctx.main_thread)().as_deref() == Some(thread.as_str()) {
                    continue;
                }
                match read_thread(&mut client, &thread) {
                    Ok(metadata) => {
                        match consider_thread(&mut client, ctx, tracker, started, &metadata) {
                            Ok(()) => {}
                            // A server REJECTION of one request (a closed thread,
                            // an unknown turn id) is that request's problem; the
                            // connection stays usable.
                            Err(error) if request_rejected(&error) => {
                                tracing::debug!(
                                    event = "child_wake",
                                    outcome = "request_rejected",
                                    error_kind = %error.kind()
                                );
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) if request_rejected(&error) => {
                        tracing::debug!(
                            event = "child_wake",
                            outcome = "request_rejected",
                            error_kind = %error.kind()
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

/// True for an error that is a verdict on ONE request, not on the transport.
/// Such a request is skipped; the connection continues.
#[cfg(unix)]
fn request_rejected(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Other
            | io::ErrorKind::InvalidData
            | io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
    )
}

/// Re-derive every loaded thread's status through the edge machinery, which
/// is how a completion lost to a disconnect or a buffer overflow is recovered.
#[cfg(unix)]
fn resync_threads(
    client: &mut RpcClient<'_>,
    ctx: &WatchCtx<'_>,
    tracker: &mut crate::providers::codex::child_wake::ChildWakeTracker,
    started: &mut std::collections::HashSet<(String, String)>,
) -> io::Result<()> {
    for thread in loaded_threads_with(client)? {
        if (ctx.stop)() {
            return Ok(());
        }
        match consider_thread(client, ctx, tracker, started, &thread) {
            Ok(()) => {}
            Err(error) if request_rejected(&error) => {
                tracing::debug!(
                    event = "child_wake",
                    outcome = "request_rejected",
                    error_kind = %error.kind()
                );
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Observe one thread's metadata and, on an `active -> idle` edge for a child
/// of the supervised main thread with the main idle and the recorded notice
/// queued, start exactly that item once.
#[cfg(unix)]
fn consider_thread(
    client: &mut RpcClient<'_>,
    ctx: &WatchCtx<'_>,
    tracker: &mut crate::providers::codex::child_wake::ChildWakeTracker,
    started: &mut std::collections::HashSet<(String, String)>,
    metadata: &serde_json::Value,
) -> io::Result<()> {
    use crate::providers::codex::child_wake::STATUS_IDLE;
    let Some(thread) = thread_id_of(metadata) else {
        return Ok(());
    };
    let Some(status) = status_of(metadata) else {
        return Ok(());
    };
    let edge = tracker.observe(&thread, &status);
    let Some(main) = (ctx.main_thread)() else {
        return Ok(());
    };
    if uuid::Uuid::parse_str(&main).is_err() || thread == main {
        return Ok(());
    }
    if !edge || parent_of(metadata).as_deref() != Some(main.as_str()) {
        return Ok(());
    }
    let main_meta = read_thread(client, &main)?;
    if status_of(&main_meta).as_deref() != Some(STATUS_IDLE)
        || can_accept_direct_input(&main_meta) != Some(true)
    {
        return Ok(());
    }
    // Only the wake path's OWN recorded notice is started: the queue may hold
    // user-submitted prompts, which must never be started early.
    let Some(item) = (ctx.queued_item)() else {
        return Ok(());
    };
    if uuid::Uuid::parse_str(&item).is_err() || started.contains(&(thread.clone(), item.clone())) {
        return Ok(());
    }
    if !item_is_queued(client, &main, &item)? {
        return Ok(());
    }
    if (ctx.stop)() {
        return Ok(());
    }
    match (ctx.start)(&main, &item) {
        Ok(_turn) => {
            started.insert((thread, item));
            tracing::debug!(event = "child_wake", outcome = "started");
        }
        Err(error) => {
            tracing::warn!(
                event = "child_wake",
                outcome = "start_failed",
                error_kind = %error.kind()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn notification_thread_id(value: &serde_json::Value) -> Option<String> {
    let params = value.get("params")?;
    let candidate = params
        .get("threadId")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            params
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| params.get("id").and_then(serde_json::Value::as_str))?;
    uuid::Uuid::parse_str(candidate)
        .ok()
        .map(|_| candidate.to_owned())
}

#[cfg(unix)]
fn thread_id_of(thread: &serde_json::Value) -> Option<String> {
    thread
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

#[cfg(unix)]
fn status_of(thread: &serde_json::Value) -> Option<String> {
    thread
        .get("status")
        .and_then(|status| status.get("type"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

#[cfg(unix)]
fn parent_of(thread: &serde_json::Value) -> Option<String> {
    thread
        .get("parentThreadId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

#[cfg(unix)]
fn can_accept_direct_input(thread: &serde_json::Value) -> Option<bool> {
    thread
        .get("canAcceptDirectInput")
        .and_then(serde_json::Value::as_bool)
}

#[cfg(unix)]
fn read_thread(client: &mut RpcClient<'_>, id: &str) -> io::Result<serde_json::Value> {
    let result = client.request(
        "thread/read",
        serde_json::json!({"threadId":id,"includeTurns":false}),
    )?;
    result
        .get("thread")
        .filter(|thread| thread.get("id").and_then(serde_json::Value::as_str) == Some(id))
        .cloned()
        .ok_or_else(|| protocol("native thread metadata identity mismatch"))
}

#[cfg(unix)]
fn item_is_queued(client: &mut RpcClient<'_>, thread: &str, item: &str) -> io::Result<bool> {
    let mut cursor = None::<String>;
    let mut seen = 0usize;
    loop {
        let page = client.request(
            "thread/queue/list",
            serde_json::json!({"threadId":thread,"cursor":cursor,"limit":128}),
        )?;
        let items = page
            .get("data")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| protocol("native queue list omitted items"))?;
        seen += items.len();
        if seen > 1024 {
            return Err(protocol("native queue list exceeded bound"));
        }
        if items
            .iter()
            .any(|candidate| candidate.get("id").and_then(serde_json::Value::as_str) == Some(item))
        {
            return Ok(true);
        }
        match page.get("nextCursor") {
            None | Some(serde_json::Value::Null) => return Ok(false),
            Some(serde_json::Value::String(next))
                if !next.is_empty() && Some(next) != cursor.as_ref() =>
            {
                cursor = Some(next.clone())
            }
            _ => return Err(protocol("native queue list cursor did not advance")),
        }
    }
}

/// Existing csq handle directories are 0755. They must be owned and cannot
/// admit other writers; only our new runtime directory requires private 0700.
#[cfg(unix)]
fn validate_owned_handle(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and cannot fail.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(refused("native handle is not an owned directory"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(refused("native runtime directory is not private and owned"));
    }
    Ok(())
}

#[cfg(unix)]
fn socket_metadata(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    validate_private_directory(
        path.parent()
            .ok_or_else(|| refused("missing socket parent"))?,
    )?;
    let metadata = std::fs::symlink_metadata(physical_socket_path(path)?)?;
    // SAFETY: geteuid has no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(refused("native socket is not private and owned"));
    }
    Ok((metadata.dev(), metadata.ino()))
}

/// Native 0.160.1 advertises a per-handle symlink to the reserved host socket
/// root. Accept only its exact SHA-256-derived alias; arbitrary symlinks remain
/// refused. This mirrors native protected_socket_path/daemon_directory.
#[cfg(unix)]
fn physical_socket_path(path: &Path) -> io::Result<PathBuf> {
    use sha2::Digest;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_symlink() {
        return Ok(path.to_path_buf());
    }
    // SAFETY: geteuid has no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid {
        return Err(refused("native rendezvous alias has another owner"));
    }
    let directory = std::fs::canonicalize("/tmp")?.join(format!("codex-daemon-{uid}"));
    validate_private_directory(&directory)?;
    let hash = sha2::Sha256::digest(path.as_os_str().as_bytes());
    let expected = directory.join(format!("{hash:x}"));
    if std::fs::read_link(path)? != expected {
        return Err(refused("native rendezvous alias has an unexpected target"));
    }
    Ok(expected)
}

#[cfg(unix)]
fn connect_checked(
    path: &Path,
    binding: Option<&BackendBinding>,
    deadline: Instant,
) -> io::Result<(std::os::unix::net::UnixStream, u32, u64, u64)> {
    let before = socket_metadata(path)?;
    let stream = connect_bounded(path, deadline)?;
    let peer = peer_identity(&stream)?;
    let after = socket_metadata(path)?;
    if before != after
        || binding.is_some_and(|binding| {
            peer != binding.native.pid || before != (binding.socket_device, binding.socket_inode)
        })
    {
        return Err(refused("native endpoint identity changed"));
    }
    Ok((stream, peer, before.0, before.1))
}

#[cfg(unix)]
fn connect_bounded(path: &Path, deadline: Instant) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: socket returns an owned descriptor or -1, with no borrowed memory.
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    let raw = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly owned descriptor and is transferred exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Darwin has no atomic SOCK_CLOEXEC; mark the newly created descriptor
    // immediately, before connecting or returning it to any caller.
    // SAFETY: fcntl acts on our newly owned descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl acts on the live owned socket descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_un is a plain C address structure; zero initialization
    // supplies the terminator and padding before the bounded path is copied.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    #[cfg(target_os = "macos")]
    {
        address.sun_len = std::mem::size_of_val(&address) as u8;
    }
    // SAFETY: address is a fully initialized sockaddr_un, and its exact size
    // bounds the C function's read. The descriptor stays owned throughout.
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            // EAGAIN on an overloaded local listener is refused rather than
            // falling back to an unbounded blocking connect.
            return Err(error);
        }
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "native connect deadline elapsed")
                })?;
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: pollfd is one live descriptor slot; poll reads/writes only
            // that slot and is bounded by the remaining absolute deadline.
            let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native connect deadline elapsed",
                ));
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let mut error: libc::c_int = 0;
            let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
            // SAFETY: correctly sized SO_ERROR and size output slots.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    std::ptr::addr_of_mut!(error).cast(),
                    &mut size,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
    }
    // SAFETY: ownership of the connected descriptor moves into UnixStream.
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd.into_raw_fd()) };
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(unix)]
fn peer_identity(stream: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: geteuid has no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: connected socket fd and valid output pointers.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != me {
            return Err(refused("native endpoint peer UID mismatch"));
        }
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: getsockopt receives correctly sized pid and length slots.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                std::ptr::addr_of_mut!(pid).cast(),
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of_val(&pid)
        {
            return Err(refused("native endpoint peer PID unavailable"));
        }
        u32::try_from(pid)
            .ok()
            .filter(|pid| *pid != 0)
            .ok_or_else(|| refused("invalid native peer PID"))
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: ucred is plain data and getsockopt fills its bounded buffer.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of_val(&cred)
            || cred.uid != me
        {
            return Err(refused("native endpoint peer identity unavailable"));
        }
        u32::try_from(cred.pid)
            .ok()
            .filter(|pid| *pid != 0)
            .ok_or_else(|| refused("invalid native peer PID"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (fd, me);
        Err(refused("native endpoint peer validation unsupported"))
    }
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    validate_owned_handle(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn write_binding(path: &Path, binding: &BackendBinding) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = crate::platform::fs::unique_tmp_path(path);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        let bytes = serde_json::to_vec(binding)
            .map_err(|_| protocol("native binding serialization failed"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        crate::platform::fs::atomic_replace(&tmp, path).map_err(io::Error::other)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn read_binding(handle: &Path, sqlite: &Path) -> io::Result<BackendBinding> {
    let binding = read_binding_record(handle)?;
    if binding.sqlite_home != sqlite.canonicalize()? {
        return Err(refused("native backend account binding changed"));
    }
    Ok(binding)
}

#[cfg(unix)]
fn read_binding_record(handle: &Path) -> io::Result<BackendBinding> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    validate_owned_handle(handle)?;
    let handle = handle.canonicalize()?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(handle.join(BINDING))?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != me
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_BINDING
    {
        return Err(refused("invalid native backend binding file"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_BINDING + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BINDING {
        return Err(refused("native binding grew beyond limit"));
    }
    let binding: BackendBinding =
        serde_json::from_slice(&bytes).map_err(|_| protocol("invalid native backend binding"))?;
    if binding.schema_version != 1
        || directory_identity(&handle)? != (binding.handle_device, binding.handle_inode)
        || binding.handle_dir != handle
        || binding.socket_path != handle.join(DIRECTORY).join(SOCKET)
    {
        return Err(refused("native backend account or handle binding changed"));
    }
    Ok(binding)
}

/// Absolute bound on ONE request/response exchange for the WATCHER's client.
/// Interleaved notifications do not extend it: it is a deadline, not a
/// per-read idle bound.
#[cfg(unix)]
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Bound on the watcher's WebSocket handshake plus `initialize`, never the
/// supervisor-lifetime total.
#[cfg(unix)]
const RPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard cap on buffered notification THREAD IDENTITIES. An overflow drops the
/// buffer and asks for ONE authoritative resync instead of growing without
/// bound while the main thread is busy.
#[cfg(unix)]
const MAX_PENDING_NOTIFICATIONS: usize = 256;

#[cfg(unix)]
struct RpcClient<'a> {
    socket: tungstenite::WebSocket<DeadlineStream>,
    /// Unique request-id prefix. A late reply to an abandoned request carries
    /// an id that can never match a later request, so it is discarded instead
    /// of being read as that request's answer.
    nonce: String,
    next_id: u64,
    /// Thread ids with a buffered notification, in arrival order. Only the
    /// IDENTITY is kept: the watcher re-reads the thread anyway, so buffering
    /// a payload would only multiply memory by the message size.
    pending: std::collections::VecDeque<String>,
    pending_set: std::collections::HashSet<String>,
    /// The buffer overflowed: the watcher resyncs once from authoritative
    /// `thread/loaded/list` metadata.
    resync: bool,
    /// A timed-out exchange leaves a reply in flight. The connection is no
    /// longer trustworthy and is dropped rather than reused.
    poisoned: bool,
    /// Watcher-only: the absolute per-exchange and handshake caps. The
    /// live-send and queue RPCs keep their caller's pre-fix budgets.
    exchange_cap: Option<Duration>,
    /// Watcher-only cancellation gate, checked between reads so a streaming
    /// server cannot hold the watcher past its stop flag.
    stop: Option<&'a dyn Fn() -> bool>,
}

/// One thing the watcher must act on.
#[cfg(unix)]
enum WakeEvent {
    /// A notification naming this thread.
    Notification(String),
    /// The buffer overflowed; re-read every loaded thread once.
    Resync,
    /// Nothing actionable was read (a skipped notification, a stray response,
    /// or a refused server request). The watcher re-checks its stop flag.
    Idle,
}

#[cfg(unix)]
fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "watcher stopped")
}

#[cfg(unix)]
impl<'a> RpcClient<'a> {
    /// A plain client: pre-fix behaviour, bounded only by the caller's
    /// deadline. Used by every existing RPC caller.
    fn initialize(
        stream: std::os::unix::net::UnixStream,
        handle: &Path,
        deadline: Instant,
    ) -> io::Result<Self> {
        Self::initialize_with(stream, handle, deadline, None, None, None)
    }

    /// The watcher's client: absolute exchange/handshake caps and a
    /// cancellation gate that is honoured between reads.
    fn initialize_watch(
        stream: std::os::unix::net::UnixStream,
        handle: &Path,
        deadline: Instant,
        stop: &'a dyn Fn() -> bool,
    ) -> io::Result<Self> {
        Self::initialize_with(
            stream,
            handle,
            deadline,
            Some(RPC_REQUEST_TIMEOUT),
            Some(RPC_HANDSHAKE_TIMEOUT),
            Some(stop),
        )
    }

    fn initialize_with(
        stream: std::os::unix::net::UnixStream,
        handle: &Path,
        deadline: Instant,
        exchange_cap: Option<Duration>,
        handshake_cap: Option<Duration>,
        stop: Option<&'a dyn Fn() -> bool>,
    ) -> io::Result<Self> {
        // The HANDSHAKE gets its own absolute bound when the caller asks for
        // one; the caller's total bounds the session from here on.
        let handshake_deadline =
            handshake_cap.map_or(deadline, |cap| deadline.min(Instant::now() + cap));
        let stream = DeadlineStream {
            stream,
            deadline: handshake_deadline,
            slice: exchange_cap,
        };
        stream.check()?;
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let (socket, _) =
            tungstenite::client::client_with_config("ws://localhost/rpc", stream, Some(config))
                .map_err(|_| protocol("native WebSocket handshake failed"))?;
        let mut client = Self {
            socket,
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            next_id: 0,
            pending: std::collections::VecDeque::new(),
            pending_set: std::collections::HashSet::new(),
            resync: false,
            poisoned: false,
            exchange_cap,
            stop,
        };
        let result = client.request(
            "initialize",
            serde_json::json!({
                "clientInfo": {"name":"csq-messaging", "version":env!("CARGO_PKG_VERSION")},
                "capabilities": {"experimentalApi":true}
            }),
        )?;
        let home = result
            .get("codexHome")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| protocol("native initialize omitted home identity"))?;
        if Path::new(home).canonicalize()? != handle {
            return Err(refused("native server belongs to another handle"));
        }
        client.send(serde_json::json!({"method":"initialized"}))?;
        client.socket.get_mut().deadline = deadline;
        Ok(client)
    }

    fn stopped(&self) -> bool {
        self.stop.is_some_and(|stop| stop())
    }

    fn send(&mut self, value: serde_json::Value) -> io::Result<()> {
        self.socket.get_ref().check()?;
        self.socket
            .send(tungstenite::Message::Text(value.to_string().into()))
            .map_err(|_| protocol("native RPC write failed"))
    }

    /// One request/response exchange. A client configured with an exchange cap
    /// gets an ABSOLUTE bound (`now + cap`), so interleaved notifications
    /// cannot extend it; the watcher's stop flag is honoured between reads.
    /// A timeout POISONS the connection: the reply may still arrive later and
    /// must never be read as the answer to a subsequent request.
    fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> io::Result<serde_json::Value> {
        if self.poisoned {
            return Err(protocol(
                "native RPC connection is unusable after a timeout",
            ));
        }
        if self.stopped() {
            return Err(stopped());
        }
        self.next_id += 1;
        let id = format!("{}-{}", self.nonce, self.next_id);
        let saved_deadline = self.socket.get_mut().deadline;
        let saved_slice = self.socket.get_mut().slice;
        if let Some(cap) = self.exchange_cap {
            self.socket.get_mut().deadline = saved_deadline.min(Instant::now() + cap);
            self.socket.get_mut().slice = None;
        }
        let result = self
            .send(serde_json::json!({"id":id,"method":method,"params":params}))
            .and_then(|()| self.await_response(&id));
        self.socket.get_mut().deadline = saved_deadline;
        self.socket.get_mut().slice = saved_slice;
        if result.as_ref().err().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
        }) {
            self.poisoned = true;
        }
        result
    }

    fn await_response(&mut self, id: &str) -> io::Result<serde_json::Value> {
        loop {
            if self.stopped() {
                return Err(stopped());
            }
            let message = match self.socket.read() {
                Ok(message) => message,
                // WouldBlock is the transport's idle bound; TimedOut is the
                // deadline (the caller's total, or this exchange's cap).
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native RPC response unavailable in time",
                    ))
                }
                Err(_) => return Err(protocol("native RPC response unavailable")),
            };
            let tungstenite::Message::Text(text) = message else {
                if matches!(message, tungstenite::Message::Close(_)) {
                    return Err(protocol("native RPC connection closed"));
                }
                continue;
            };
            let response: serde_json::Value =
                serde_json::from_str(&text).map_err(|_| protocol("invalid native RPC envelope"))?;
            if response.get("id").and_then(serde_json::Value::as_str) == Some(id) {
                if let Some(error) = response.get("error") {
                    let code = error
                        .get("code")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0);
                    return Err(io::Error::other(format!(
                        "native RPC rejected request (code {code})"
                    )));
                }
                return response
                    .get("result")
                    .cloned()
                    .ok_or_else(|| protocol("native RPC response omitted result"));
            }
            // This client never accepts server-initiated approval/tool requests.
            if response.get("method").is_some() && response.get("id").is_some() {
                self.send(serde_json::json!({"id":response["id"],"error":{"code":-32601,"message":"Unsupported client request"}}))?;
                continue;
            }
            if response.get("method").is_some() {
                self.buffer_notification(response);
                continue;
            }
            // A reply to a DIFFERENT request (one this client abandoned after
            // its timeout): discard it. Unique ids make this unambiguous.
        }
    }

    /// Keep only the IDENTITY of thread/* and turn/* notifications, one per
    /// thread, up to a hard cap. Overflow drops the buffer and asks for one
    /// resync: a lost completion is recovered from authoritative metadata.
    fn buffer_notification(&mut self, value: serde_json::Value) {
        let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
            return;
        };
        if !(method.starts_with("thread/") || method.starts_with("turn/")) {
            return;
        }
        let Some(thread) = notification_thread_id(&value) else {
            return;
        };
        // A second notification for a thread already buffered adds no
        // information: the watcher re-reads the thread regardless.
        if self.pending_set.contains(&thread) {
            return;
        }
        if self.pending.len() >= MAX_PENDING_NOTIFICATIONS {
            self.pending.clear();
            self.pending_set.clear();
            self.resync = true;
            return;
        }
        self.pending_set.insert(thread.clone());
        self.pending.push_back(thread);
    }

    /// Bound each blocking notification read to `slice` while the total
    /// deadline still applies, so a watcher can check its stop flag without
    /// polling state. Requests temporarily use their own absolute bound.
    fn set_slice(&mut self, slice: Duration) {
        self.socket.get_mut().slice = Some(slice);
    }

    /// Next event: a buffered thread identity, a resync request, one newly
    /// read notification, or `Ok(None)` when the read slice elapsed. Performs
    /// at most ONE read, so the caller re-checks its stop flag between reads.
    fn next_event(&mut self) -> io::Result<Option<WakeEvent>> {
        if self.resync {
            self.resync = false;
            return Ok(Some(WakeEvent::Resync));
        }
        if let Some(thread) = self.pending.pop_front() {
            self.pending_set.remove(&thread);
            return Ok(Some(WakeEvent::Notification(thread)));
        }
        if self.poisoned {
            return Err(protocol(
                "native RPC connection is unusable after a timeout",
            ));
        }
        if self.stopped() {
            return Err(stopped());
        }
        let message = match self.socket.read() {
            Ok(message) => message,
            // The notification slice elapsed. (The TOTAL deadline is reported
            // as TimedOut by `DeadlineStream::check` and must end the watcher,
            // never be mistaken for an idle slice.)
            Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None)
            }
            Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native RPC deadline elapsed",
                ))
            }
            Err(_) => return Err(protocol("native RPC response unavailable")),
        };
        let tungstenite::Message::Text(text) = message else {
            if matches!(message, tungstenite::Message::Close(_)) {
                return Err(protocol("native RPC connection closed"));
            }
            return Ok(Some(WakeEvent::Idle));
        };
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| protocol("invalid native RPC envelope"))?;
        if value.get("method").is_none() {
            return Ok(Some(WakeEvent::Idle));
        }
        if value.get("id").is_some() {
            self.send(serde_json::json!({"id":value["id"],"error":{"code":-32601,"message":"Unsupported client request"}}))?;
            return Ok(Some(WakeEvent::Idle));
        }
        let method = value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !(method.starts_with("thread/") || method.starts_with("turn/")) {
            return Ok(Some(WakeEvent::Idle));
        }
        match notification_thread_id(&value) {
            Some(thread) => Ok(Some(WakeEvent::Notification(thread))),
            None => Ok(Some(WakeEvent::Idle)),
        }
    }

    fn close(&mut self) {
        if self.socket.get_ref().check().is_ok() {
            let _ = self.socket.close(None);
        }
    }
}

/// Every underlying syscall receives the remaining absolute budget. A peer
/// trickling an HTTP header or a partial WebSocket frame cannot reset it.
#[cfg(unix)]
struct DeadlineStream {
    stream: std::os::unix::net::UnixStream,
    deadline: Instant,
    /// Optional bound on ONE blocking read, shorter than the total deadline.
    /// A watcher uses it to re-check its stop flag between slices; the total
    /// deadline still bounds the whole lifetime.
    slice: Option<Duration>,
}

#[cfg(unix)]
impl DeadlineStream {
    fn check(&self) -> io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "native RPC deadline elapsed")
            })?;
        let wait = self.slice.map_or(remaining, |slice| remaining.min(slice));
        self.stream.set_read_timeout(Some(wait))?;
        self.stream.set_write_timeout(Some(wait))
    }
}

#[cfg(unix)]
impl io::Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        io::Read::read(&mut self.stream, buffer)
    }
}

#[cfg(unix)]
impl io::Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check()?;
        io::Write::write(&mut self.stream, buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        io::Write::flush(&mut self.stream)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};

    const MAIN: &str = "01a0f6f5-1ba8-7202-94c4-bb7233a1f783";
    const ITEM: &str = "01a11624-fed4-71e1-b2a0-cbceaf8db0ff";

    fn plan() -> (tempfile::TempDir, ManagedBackendPlan) {
        // Unix-domain sockets have a small platform path limit. Use the shared
        // short-root fixture so the plan is valid under long workspace/TMPDIR
        // paths and the root is private at creation.
        let temp = crate::testing::socket_fixture::short_root("csq-").unwrap();
        let sqlite = temp.path().join("state");
        std::fs::create_dir(&sqlite).unwrap();
        let plan = ManagedBackendPlan::prepare(temp.path(), &sqlite).unwrap();
        (temp, plan)
    }

    fn test_listener(plan: &ManagedBackendPlan) -> UnixListener {
        let listener = UnixListener::bind(&plan.socket_path).unwrap();
        std::fs::set_permissions(&plan.socket_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        listener
    }

    fn receive(socket: &mut tungstenite::WebSocket<UnixStream>) -> serde_json::Value {
        loop {
            if let tungstenite::Message::Text(text) = socket.read().unwrap() {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    /// Accepts connections until one sends a request, dropping "probe"
    /// connections that complete the handshake and then close without one (the
    /// binding publication's connection, or any stray client). The probe is
    /// identified by OBSERVED BEHAVIOUR, not by accept ordinal: keying on the
    /// ordinal assumes the client's connect sequence maps 1:1 onto accepts, so
    /// one extra or reordered connection makes the server drop a live RPC
    /// socket (observed on darwin as "native RPC write failed").
    fn next_request(
        listener: &UnixListener,
        home: &Path,
    ) -> (tungstenite::WebSocket<UnixStream>, serde_json::Value) {
        loop {
            let mut socket = initialized(listener, home);
            match socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    return (socket, serde_json::from_str(&text).unwrap());
                }
                // A probe closes after the handshake: either a Close frame or
                // the read error that follows it. Neither carries a request.
                Ok(_) | Err(_) => continue,
            }
        }
    }

    fn initialized(listener: &UnixListener, home: &Path) -> tungstenite::WebSocket<UnixStream> {
        let stream = listener.accept().unwrap().0;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        let request = receive(&mut socket);
        assert_eq!(request["method"], "initialize");
        assert_eq!(request["params"]["capabilities"]["experimentalApi"], true);
        socket
            .send(tungstenite::Message::Text(
                json!({"id":request["id"], "result":{"codexHome":home}})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        assert_eq!(receive(&mut socket)["method"], "initialized");
        socket
    }

    #[test]
    fn launch_rejects_tui_options_and_pins_account_state() {
        let (_temp, plan) = plan();
        assert!(plan.backend_argv(&["resume".into(), MAIN.into()]).is_err());
        let argv = plan
            .backend_argv(&["-c".into(), "model=\"example\"".into()])
            .unwrap();
        assert_eq!(argv[0], "-c");
        assert_eq!(
            argv[3],
            format!("sqlite_home={}", json!(plan.sqlite_home.to_str().unwrap())).as_str()
        );
        assert_eq!(argv[4], "app-server");
        assert_eq!(argv[5], "--listen");
        assert_eq!(argv[6], plan.endpoint_url().as_str());
    }

    #[test]
    fn private_runtime_rejects_symlink_and_existing_endpoint() {
        let (temp, plan) = plan();
        let _listener = test_listener(&plan);
        assert!(ManagedBackendPlan::prepare(temp.path(), &plan.sqlite_home).is_err());
        let alias = temp.path().join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(ManagedBackendPlan::prepare(&alias, &plan.sqlite_home).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_accepts_socket_paths_below_linux_sun_path_limit() {
        use std::os::unix::ffi::OsStrExt;

        // Unix-domain sockets have a small platform path limit. Keep this
        // fixture root short so tests remain valid when the checkout lives
        // under a long CI workspace path or TMPDIR.
        let temp = tempfile::Builder::new()
            .prefix("csq")
            .tempdir_in("/tmp")
            .unwrap();
        let base = temp.path().canonicalize().unwrap();
        let target_len = native_socket_path_limit() - 2;
        let fixed_suffix = format!("/{DIRECTORY}/{SOCKET}");
        let component_len = target_len
            .checked_sub(base.as_os_str().as_bytes().len())
            .and_then(|length| length.checked_sub(1))
            .and_then(|length| length.checked_sub(fixed_suffix.len()))
            .expect("temp path must leave room for a long handle component");
        let handle_dir = base.join("h".repeat(component_len));
        std::fs::create_dir(&handle_dir).unwrap();
        let sqlite_home = handle_dir.join("state");
        std::fs::create_dir(&sqlite_home).unwrap();

        let plan = ManagedBackendPlan::prepare(&handle_dir, &sqlite_home).unwrap();
        assert_eq!(plan.socket_path.as_os_str().as_bytes().len(), target_len);
    }

    #[test]
    fn native_metadata_identifies_cli_root_and_refuses_ambiguity() {
        let root = json!({"id":MAIN,"source":"cli","parentThreadId":null,"status":{"type":"idle"},"canAcceptDirectInput":true});
        let child =
            json!({"id":ITEM,"source":{"subAgent":{"threadSpawn":{}}},"status":{"type":"idle"}});
        assert_eq!(
            unique_loaded_cli_thread(&[child, root.clone()]).unwrap(),
            MAIN
        );
        assert!(unique_loaded_cli_thread(&[root.clone(), root]).is_err());
        assert!(unique_loaded_cli_thread(&[json!({"id":MAIN,"source":"cli"})]).is_err());
    }

    // A real UDS/WebSocket protocol fixture, not a simulated native consumer.
    // The IDs and preceding Interrupted incident are recorded CR6 identities;
    // the oracle checks exact native queue/start routing without queue/add or
    // turn/start. Native model execution remains outside this fixture's scope.
    #[test]
    fn recorded_interrupted_item_starts_through_bound_native_queue_rpc() {
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/codex-0.160.1-interrupted-resume.json"
        ))
        .unwrap();
        assert_eq!(recorded["prior_native_event"]["reason"], "interrupted");
        assert_eq!(
            recorded["send"]["receipt_delivery"],
            "codex_queued_unverified"
        );
        assert_eq!(
            recorded["regression_oracle"]["queue_start_must_use_existing_item_id"],
            true
        );
        let main = recorded["target"]["thread_id"].as_str().unwrap().to_owned();
        let item = recorded["native_queue_observation"]["item"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let server_main = main.clone();
        let server_item = item.clone();
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, request) = next_request(&listener, &home);
            assert_eq!(request["method"], "thread/queue/start");
            assert_eq!(
                request["params"],
                json!({"threadId":server_main,"queuedSubmissionId":server_item})
            );
            assert!(request["params"].get("input").is_none());
            socket.send(tungstenite::Message::Text(json!({"id":request["id"],"result":{"turn":{"id":"native-turn","status":"inProgress"}}}).to_string().into())).unwrap();
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&launcher, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&LauncherIdentity::capture(std::process::id()).unwrap())
            .unwrap();
        assert_eq!(
            start_existing_queue_item(
                &plan.handle_dir,
                &plan.sqlite_home,
                &launcher,
                &main,
                &item,
                StartAdmission::AdmitAnyStatus,
                Duration::from_secs(3)
            )
            .unwrap(),
            "native-turn"
        );
        server.join().unwrap();
    }

    #[test]
    fn binding_refuses_account_swap_and_replaced_socket() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            drop(initialized(&listener, &home));
        });
        plan.publish_binding(
            &LauncherIdentity::capture(std::process::id()).unwrap(),
            Duration::from_secs(3),
        )
        .unwrap()
        .publish_recipient(&LauncherIdentity::capture(std::process::id()).unwrap())
        .unwrap();
        server.join().unwrap();
        let mut foreign = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let foreign_identity = LauncherIdentity::capture(foreign.id()).unwrap();
        let refused_foreign = start_existing_queue_item(
            &plan.handle_dir,
            &plan.sqlite_home,
            &foreign_identity,
            MAIN,
            ITEM,
            StartAdmission::AdmitAnyStatus,
            Duration::from_millis(100),
        )
        .is_err();
        foreign.kill().unwrap();
        foreign.wait().unwrap();
        assert!(
            refused_foreign,
            "another genuinely live recipient must be refused before RPC"
        );
        let another = plan.handle_dir.join("another-state");
        std::fs::create_dir(&another).unwrap();
        assert!(read_binding(&plan.handle_dir, &another).is_err());
        std::fs::remove_file(&plan.socket_path).unwrap();
        let _replacement = test_listener(&plan);
        assert!(start_existing_queue_item(
            &plan.handle_dir,
            &plan.sqlite_home,
            &LauncherIdentity::capture(std::process::id()).unwrap(),
            MAIN,
            ITEM,
            StartAdmission::AdmitAnyStatus,
            Duration::from_millis(100)
        )
        .is_err());
    }

    #[test]
    fn stalled_native_handshake_has_deadline() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let server = std::thread::spawn(move || {
            let stream = listener.accept().unwrap().0;
            let mut byte = [0];
            use std::io::Read;
            let _ = stream.take(1).read(&mut byte);
            std::thread::sleep(Duration::from_millis(150));
        });
        let start = Instant::now();
        assert!(plan
            .publish_binding(
                &LauncherIdentity::capture(std::process::id()).unwrap(),
                Duration::from_millis(30)
            )
            .is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn stalled_loaded_thread_list_obeys_one_rpc_deadline() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            // Held open without a reply: the client must hit its own deadline.
            let (_socket, request) = next_request(&listener, &home);
            assert_eq!(request["method"], "thread/loaded/list");
            std::thread::sleep(Duration::from_millis(200));
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&launcher, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&launcher).unwrap();

        let started = Instant::now();
        let result = loaded_thread_metadata(
            &plan.handle_dir,
            &plan.sqlite_home,
            &launcher,
            Duration::from_millis(50),
        );
        assert!(result.is_err(), "a stalled list must refuse metadata");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the list RPC exceeded its absolute deadline: {:?}",
            started.elapsed()
        );
        server.join().unwrap();
    }

    #[test]
    fn trickled_handshake_obeys_total_deadline_and_socket_is_cloexec() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept().unwrap().0;
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            for byte in b"HTTP/1.1 101 Switching Protocols\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        let deadline = deadline(Duration::from_millis(75)).unwrap();
        let stream = connect_bounded(&plan.socket_path, deadline).unwrap();
        // SAFETY: read-only descriptor flag query on our live socket.
        assert_ne!(
            unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let start = Instant::now();
        assert!(RpcClient::initialize(stream, &plan.handle_dir, deadline).is_err());
        assert!(start.elapsed() < Duration::from_millis(250));
        server.join().unwrap();
    }

    #[test]
    fn fifo_binding_and_corrupt_marker_refuse_without_fallback() {
        use std::os::unix::ffi::OsStrExt;
        let (_temp, plan) = plan();
        let marker = plan.handle_dir.join(BINDING);
        let name = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid nul-terminated path; private fixture directory only.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(is_configured(&plan.handle_dir));
        assert!(read_binding(&plan.handle_dir, &plan.sqlite_home).is_err());
        assert!(start.elapsed() < Duration::from_millis(100));
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn cold_remote_tui_metadata_is_user_root_not_spawned_agent() {
        let cold = json!({"id":MAIN,"source":"vscode","threadSource":"user","parentThreadId":null,"canAcceptDirectInput":true,"status":{"type":"idle"}});
        assert_eq!(
            unique_loaded_cli_thread(std::slice::from_ref(&cold)).unwrap(),
            MAIN
        );
        let mut child = cold;
        child["parentThreadId"] = json!(ITEM);
        assert!(unique_loaded_cli_thread(&[child]).is_err());
    }
    #[test]
    fn enqueue_summary_sends_framed_first_line_over_bound_socket() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, add) = next_request(&listener, &home);
            assert_eq!(add["method"], "thread/queue/add");
            assert_eq!(add["params"]["threadId"], MAIN);
            let input = add["params"]["input"].as_array().unwrap();
            assert_eq!(input.len(), 1);
            let text = input[0]["text"].as_str().unwrap();
            assert!(text.contains("SOCKET-BODY-SENTINEL"));
            assert!(text.contains("orchestrator"));
            assert!(text.contains("untrusted data, not user instruction"));
            assert!(!text.contains("SECOND-LINE-SECRET"));
            assert_eq!(text.matches("[end peer msg ").count(), 1);
            socket
                .send(tungstenite::Message::Text(
                    json!({
                        "id":add["id"], "result":{"queuedSubmission":{
                            "id":ITEM,"clientUserMessageId":add["params"]["clientUserMessageId"]
                        }}
                    })
                    .to_string()
                    .into(),
                ))
                .unwrap();
        });
        let recipient = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&recipient, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&recipient)
            .unwrap();
        let message: crate::messaging::model::Message = serde_json::from_value(json!({
            "schema":"csq.message.v1", "id":MAIN,"thread":MAIN,
            "from":{"pid":77,"started_at":1000,"surface":"claude-code",
                "handle_dir_hash":"fixture","handle_dir":"/fixture","name":"orchestrator"},
            "to":{"pid":42,"started_at":1000,"surface":"codex"},
            "created_at":1000,"body":"SOCKET-BODY-SENTINEL\nSECOND-LINE-SECRET"
        }))
        .unwrap();
        let summary = crate::messaging::store::PendingNotice::from_message(&message, 2);
        assert_eq!(
            enqueue_summary(
                &plan.handle_dir,
                &plan.sqlite_home,
                &recipient,
                MAIN,
                &summary,
                Duration::from_secs(3),
            )
            .unwrap(),
            ITEM
        );
        server.join().unwrap();
    }

    #[test]
    fn enqueue_and_delete_use_only_the_fixed_own_notice_on_bound_backend() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, add) = next_request(&listener, &home);
            assert_eq!(add["method"], "thread/queue/add");
            assert_eq!(add["params"]["threadId"], MAIN);
            assert_eq!(
                add["params"]["input"],
                json!([{"type":"text","text":crate::messaging::wake::notice(2),"textElements":[]} ])
            );
            socket.send(tungstenite::Message::Text(json!({"id":add["id"],"result":{"queuedSubmission":{"id":ITEM,"clientUserMessageId":add["params"]["clientUserMessageId"]}}}).to_string().into())).unwrap();
            drop(socket);
            let (mut socket, list) = next_request(&listener, &home);
            assert_eq!(list["method"], "thread/queue/list");
            socket.send(tungstenite::Message::Text(json!({"id":list["id"],"result":{"data":[{"id":ITEM,"input":add["params"]["input"]}],"nextCursor":null}}).to_string().into())).unwrap();
            let delete = receive(&mut socket);
            assert_eq!(delete["method"], "thread/queue/delete");
            assert_eq!(
                delete["params"],
                json!({"threadId":MAIN,"queuedSubmissionId":ITEM})
            );
            socket
                .send(tungstenite::Message::Text(
                    json!({"id":delete["id"],"result":{}}).to_string().into(),
                ))
                .unwrap();
        });
        let recipient = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&recipient, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&recipient)
            .unwrap();
        assert_eq!(
            enqueue_notice(
                &plan.handle_dir,
                &plan.sqlite_home,
                &recipient,
                MAIN,
                2,
                Duration::from_secs(3)
            )
            .unwrap(),
            ITEM
        );
        assert!(delete_notice(
            &plan.handle_dir,
            &plan.sqlite_home,
            &recipient,
            MAIN,
            ITEM,
            2,
            Duration::from_secs(3)
        )
        .unwrap());
        server.join().unwrap();
    }

    /// An extra connection that completes the handshake and closes — a stray
    /// client, a reordered probe, a client retry — must not shift which
    /// connection the fake server treats as the queue RPC. The probe is
    /// identified by having sent no request, so the shift is impossible by
    /// construction; a positional fixture reddened on darwin with the enqueue's
    /// socket dropped ("native RPC write failed").
    #[test]
    fn a_stray_handshake_connection_cannot_shift_the_queue_rpc_connection() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, add) = next_request(&listener, &home);
            assert_eq!(add["method"], "thread/queue/add");
            send_result(
                &mut socket,
                add["id"].clone(),
                json!({"queuedSubmission":{"id":ITEM,"clientUserMessageId":add["params"]["clientUserMessageId"]}}),
            );
            drop(socket);
            let (mut socket, list) = next_request(&listener, &home);
            assert_eq!(list["method"], "thread/queue/list");
            send_result(
                &mut socket,
                list["id"].clone(),
                json!({"data":[{"id":ITEM,"input":add["params"]["input"]}],"nextCursor":null}),
            );
            let delete = receive(&mut socket);
            assert_eq!(delete["method"], "thread/queue/delete");
            send_result(&mut socket, delete["id"].clone(), json!({}));
        });
        let recipient = LauncherIdentity::capture(std::process::id()).unwrap();
        // The stray completes the same handshake a probe does, then closes.
        let stray = std::os::unix::net::UnixStream::connect(&plan.socket_path).unwrap();
        let (mut stray, _) = tungstenite::client("ws://localhost/rpc", stray).unwrap();
        stray
            .send(tungstenite::Message::Text(
                json!({"id":0,"method":"initialize","params":{"capabilities":{"experimentalApi":true}}})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        // The handshake reply is `{"id":..,"result":..}` — no `method` field.
        assert_eq!(
            receive(&mut stray)["id"],
            0,
            "the stray's initialize must be answered"
        );
        stray
            .send(tungstenite::Message::Text(
                json!({"method":"initialized"}).to_string().into(),
            ))
            .unwrap();
        drop(stray);
        plan.publish_binding(&recipient, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&recipient)
            .unwrap();
        assert_eq!(
            enqueue_notice(
                &plan.handle_dir,
                &plan.sqlite_home,
                &recipient,
                MAIN,
                2,
                Duration::from_secs(3)
            )
            .unwrap(),
            ITEM
        );
        assert!(delete_notice(
            &plan.handle_dir,
            &plan.sqlite_home,
            &recipient,
            MAIN,
            ITEM,
            2,
            Duration::from_secs(3)
        )
        .unwrap());
        server.join().unwrap();
    }

    #[test]
    fn delete_refuses_an_exact_item_whose_input_is_not_our_notice() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, list) = next_request(&listener, &home);
            assert_eq!(list["method"], "thread/queue/list");
            socket.send(tungstenite::Message::Text(json!({"id":list["id"],"result":{"data":[{"id":ITEM,"input":[{"type":"text","text":"user-owned message"}]}],"nextCursor":null}}).to_string().into())).unwrap();
            if let Ok(tungstenite::Message::Text(text)) = socket.read() {
                panic!("a refused user item must send no delete request: {text}");
            }
        });
        let recipient = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&recipient, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&recipient)
            .unwrap();
        assert!(delete_notice(
            &plan.handle_dir,
            &plan.sqlite_home,
            &recipient,
            MAIN,
            ITEM,
            1,
            Duration::from_secs(3)
        )
        .is_err());
        server.join().unwrap();
    }
    /// Real private UDS/authenticated peer and live process incarnations with
    /// recorded role metadata supplied to the pure recipient proof boundary.
    /// This tests mapping; the stand-in is not a native Codex consumer.
    #[test]
    fn private_recorded_backend_caller_maps_to_bound_tui_and_refuses_other_owners() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = ChildGuard(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let recipient = LauncherIdentity::capture(child.0.id()).unwrap();
        let started = crate::sessions::process_start_time(recipient.pid).unwrap();
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            drop(initialized(&listener, &home));
            drop(initialized(&listener, &home));
        });
        let native = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&native, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&recipient).unwrap();
        let record = json!({"kind":"private-recorded-process-binding-fixture","backend":native,"recipient":recipient,"handleDevice":binding.handle_device,"handleInode":binding.handle_inode});
        assert_eq!(record["recipient"]["pid"], child.0.id());
        let mapped = resolve_managed_caller_with(
            &plan.handle_dir,
            Duration::from_secs(3),
            &|_| Ok(plan.sqlite_home.clone()),
            &|identity| {
                assert_eq!(identity, &native);
                prove_backend_caller_ancestry(identity, &|_| Some(Some(vec![])), &|_, _| {
                    Some(false)
                })
            },
            &|bound, identity| {
                assert_eq!(identity, &recipient);
                assert_eq!(bound.handle_dir, plan.handle_dir);
                assert_eq!(bound.sqlite_home, plan.sqlite_home);
                Ok(started)
            },
        )
        .unwrap()
        .unwrap();
        server.join().unwrap();
        assert_eq!(mapped.recipient(), &recipient);
        assert_ne!(mapped.recipient(), mapped.native());
        let row: crate::sessions::SessionInfo = serde_json::from_value(json!({"pid":recipient.pid,"cwd":plan.handle_dir,"config_dir":plan.handle_dir,"started_at":started})).unwrap();
        let resolved =
            crate::sessions::mapped_caller_from_listing(&mapped, std::slice::from_ref(&row))
                .unwrap();
        assert_eq!(resolved.pid(), recipient.pid);
        assert!(resolved.verified().is_ok());
        assert!(crate::sessions::mapped_caller_from_listing(&mapped, &[]).is_err());
        let mut other = row.clone();
        other.pid = native.pid + 1000;
        other.started_at = None;
        assert!(
            crate::sessions::mapped_caller_from_listing(&mapped, &[row.clone(), other]).is_err()
        );
        let mut unknown = row.clone();
        unknown.config_dir = plan.handle_dir.join("missing-alias");
        assert!(
            crate::sessions::mapped_caller_from_listing(&mapped, &[row.clone(), unknown]).is_err()
        );
        let mut stale = binding.clone();
        stale.recipient.as_mut().unwrap().started_exact += 1;
        write_binding(&plan.handle_dir.join(BINDING), &stale).unwrap();
        assert!(resolve_managed_caller_with(
            &plan.handle_dir,
            Duration::from_millis(100),
            &|_| Ok(plan.sqlite_home.clone()),
            &|_| Ok(Some(vec![])),
            &|_, _| Ok(started)
        )
        .is_err());
        write_binding(&plan.handle_dir.join(BINDING), &binding).unwrap();
        std::fs::write(plan.handle_dir.join(BINDING), b"corrupt").unwrap();
        assert!(is_configured(&plan.handle_dir));
        assert!(resolve_managed_caller(&plan.handle_dir, Duration::from_millis(100)).is_err());
    }

    #[test]
    fn managed_backend_caller_rejects_nested_cli_unreadable_and_recycled_hops() {
        let native = LauncherIdentity::capture(std::process::id()).unwrap();
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/codex-0.160.1-interrupted-resume.json"
        ))
        .unwrap();
        let pid = recorded["target"]["pid"].as_u64().unwrap() as u32;
        let start = recorded["target"]["started_at"].as_u64().unwrap();
        let ancestry = |_: u32| Some(Some(vec![(pid, start)]));
        assert!(prove_backend_caller_ancestry(&native, &ancestry, &|_, _| Some(true)).is_err());
        assert!(prove_backend_caller_ancestry(&native, &ancestry, &|_, _| None).is_err());
        assert!(prove_backend_caller_ancestry(&native, &|_| None, &|_, _| Some(false)).is_err());
        assert_eq!(
            prove_backend_caller_ancestry(&native, &|_| Some(None), &|_, _| Some(false)).unwrap(),
            None
        );
        let mut recycled = native;
        recycled.started_exact += 1;
        assert!(prove_backend_caller_ancestry(&recycled, &ancestry, &|_, _| Some(false)).is_err());
    }

    // ── child-completion wake (native subscription) ──────────────────────

    const CHILD_A: &str = "01a11624-fed4-71e1-b2a0-cbceaf8db0ff";
    const CHILD_B: &str = "01a11625-bbbb-71e1-b2a0-cbceaf8db0ff";
    const FOREIGN: &str = "01a11626-cccc-71e1-b2a0-cbceaf8db0ff";
    const TURN: &str = "01a11627-dddd-71e1-b2a0-cbceaf8db0ff";
    const ITEM2: &str = "01a11628-eeee-71e1-b2a0-cbceaf8db0ff";

    fn thread_meta(
        id: &str,
        parent: Option<&str>,
        status: &str,
        can_accept: bool,
    ) -> serde_json::Value {
        json!({
            "id": id,
            "source": if parent.is_some() {
                json!({"subAgent":{"threadSpawn":{}}})
            } else {
                json!("cli")
            },
            "parentThreadId": parent,
            "status": {"type": status},
            "canAcceptDirectInput": can_accept,
        })
    }

    /// Hold the connection open until the CLIENT closes it. A fixture that
    /// returns right after a reply drops the socket, and under full-suite load
    /// the peer can observe EOF before the last frame is consumed.
    fn wait_for_client_close(socket: &mut tungstenite::WebSocket<UnixStream>) {
        let _ = socket
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(3)));
        let _ = socket.read();
    }

    fn send_result(
        socket: &mut tungstenite::WebSocket<UnixStream>,
        id: serde_json::Value,
        result: serde_json::Value,
    ) {
        socket
            .send(tungstenite::Message::Text(
                json!({"id": id, "result": result}).to_string().into(),
            ))
            .unwrap();
    }

    /// Accept with a bound so a watcher that never connects cannot hang the
    /// fixture. The listener is switched to non-blocking once.
    fn accept_bounded(listener: &UnixListener, bound: Duration) -> Option<UnixStream> {
        let _ = listener.set_nonblocking(true);
        let deadline = Instant::now() + bound;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return Some(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return None,
            }
        }
    }

    fn initialized_bounded(
        listener: &UnixListener,
        home: &Path,
        bound: Duration,
    ) -> Option<tungstenite::WebSocket<UnixStream>> {
        let stream = accept_bounded(listener, bound)?;
        // BSD/macOS accept() INHERITS O_NONBLOCK from the listener (Linux does
        // not). The handshake below is blocking, so clear it explicitly.
        stream.set_nonblocking(false).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .ok()?;
        let mut socket = tungstenite::accept(stream).ok()?;
        let request = receive(&mut socket);
        if request["method"] != "initialize" {
            return None;
        }
        socket
            .send(tungstenite::Message::Text(
                json!({"id":request["id"], "result":{"codexHome": home}})
                    .to_string()
                    .into(),
            ))
            .ok()?;
        Some(socket)
    }

    /// Fake owning app-server: one publish connection, one watcher connection.
    /// The seed reads return the child ACTIVE; every later read returns IDLE.
    /// After the seed reads, the scripted completion notifications are pushed.
    fn serve_child_watch(
        listener: UnixListener,
        home: PathBuf,
        main_status: &'static str,
        children: Vec<(&'static str, Option<&'static str>)>,
        queue: Vec<&'static str>,
        notifications: Vec<&'static str>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let publish = initialized_bounded(&listener, &home, Duration::from_secs(3));
            let mut socket = match initialized_bounded(&listener, &home, Duration::from_secs(3)) {
                Some(socket) => socket,
                None => return,
            };
            drop(publish);
            let mut ids: Vec<String> = vec![MAIN.to_owned()];
            ids.extend(children.iter().map(|(id, _)| (*id).to_owned()));
            let seed_reads = ids.len();
            let mut reads = 0usize;
            let mut sent = false;
            loop {
                let message = match socket.read() {
                    Ok(tungstenite::Message::Text(text)) => text,
                    Ok(_) => continue,
                    Err(_) => break,
                };
                let request: serde_json::Value = match serde_json::from_str(&message) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let Some(method) = request.get("method").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                // A client notification ("initialized") has no id.
                let Some(id) = request.get("id").cloned() else {
                    continue;
                };
                let seeding = reads < seed_reads;
                match method {
                    "thread/loaded/list" => {
                        let data: Vec<serde_json::Value> = ids.iter().map(|id| json!(id)).collect();
                        send_result(&mut socket, id, json!({"data": data, "nextCursor": null}));
                    }
                    "thread/read" => {
                        let tid = request["params"]["threadId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        let value = if tid == MAIN {
                            thread_meta(MAIN, None, main_status, true)
                        } else if let Some((child, parent)) =
                            children.iter().find(|(id, _)| *id == tid)
                        {
                            let status = if seeding { "active" } else { "idle" };
                            thread_meta(child, *parent, status, false)
                        } else {
                            thread_meta(&tid, None, "idle", false)
                        };
                        send_result(&mut socket, id, json!({"thread": value}));
                        reads += 1;
                        if reads >= seed_reads && !sent {
                            sent = true;
                            for child in &notifications {
                                socket
                                    .send(tungstenite::Message::Text(
                                        json!({"method":"turn/completed","params":{"threadId": child}})
                                            .to_string()
                                            .into(),
                                    ))
                                    .unwrap();
                            }
                        }
                    }
                    "thread/queue/list" => {
                        let data: Vec<serde_json::Value> =
                            queue.iter().map(|id| json!({"id": id})).collect();
                        send_result(&mut socket, id, json!({"data": data, "nextCursor": null}));
                    }
                    _ => send_result(&mut socket, id, json!({})),
                }
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn run_child_watch(
        plan: &ManagedBackendPlan,
        listener: UnixListener,
        main_status: &'static str,
        children: Vec<(&'static str, Option<&'static str>)>,
        queue: Vec<&'static str>,
        expected: Option<&'static str>,
        notifications: Vec<&'static str>,
        wait: Duration,
    ) -> Vec<(String, String)> {
        let home = plan.handle_dir.clone();
        let server = serve_child_watch(listener, home, main_status, children, queue, notifications);
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&launcher, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&launcher).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = stop.clone();
        let dir = plan.handle_dir.clone();
        let sqlite = plan.sqlite_home.clone();
        let watcher_launcher = launcher.clone();
        let watcher = std::thread::spawn(move || {
            let main_of = || Some(MAIN.to_owned());
            let queued_item = || expected.map(str::to_owned);
            let start = |thread: &str, item: &str| -> io::Result<String> {
                let _ = tx.send((thread.to_owned(), item.to_owned()));
                Ok(TURN.to_owned())
            };
            let stopped = || stop_flag.load(std::sync::atomic::Ordering::SeqCst);
            watch_child_completions(
                &dir,
                &sqlite,
                &watcher_launcher,
                &main_of,
                &queued_item,
                &start,
                &stopped,
                Duration::from_secs(30),
                Duration::from_millis(25),
            )
        });
        std::thread::sleep(wait);
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let outcome = watcher.join().unwrap();
        assert!(outcome.is_ok(), "watcher must stop cleanly: {outcome:?}");
        let _ = server.join();
        let mut rows = Vec::new();
        while let Ok(row) = rx.try_recv() {
            rows.push(row);
        }
        rows
    }

    #[test]
    fn child_completion_while_idle_starts_exactly_once() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let starts = run_child_watch(
            &plan,
            listener,
            "idle",
            vec![(CHILD_A, Some(MAIN))],
            vec![ITEM],
            Some(ITEM),
            vec![CHILD_A, CHILD_A],
            Duration::from_millis(1500),
        );
        assert_eq!(
            starts,
            vec![(MAIN.to_owned(), ITEM.to_owned())],
            "one child, one start, duplicates deduped"
        );
    }

    #[test]
    fn child_completion_while_main_busy_starts_nothing() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let starts = run_child_watch(
            &plan,
            listener,
            "active",
            vec![(CHILD_A, Some(MAIN))],
            vec![ITEM],
            Some(ITEM),
            vec![CHILD_A],
            Duration::from_millis(1200),
        );
        assert!(
            starts.is_empty(),
            "a busy main thread must not be started: {starts:?}"
        );
    }

    #[test]
    fn foreign_thread_completion_starts_nothing() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let starts = run_child_watch(
            &plan,
            listener,
            "idle",
            vec![(CHILD_A, Some(FOREIGN)), (CHILD_B, None)],
            vec![ITEM],
            Some(ITEM),
            vec![CHILD_A, CHILD_B],
            Duration::from_millis(1200),
        );
        assert!(
            starts.is_empty(),
            "only a thread parented to the supervised main may wake it: {starts:?}"
        );
    }

    #[test]
    fn two_children_each_start_once_with_no_double_start() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let starts = run_child_watch(
            &plan,
            listener,
            "idle",
            vec![(CHILD_A, Some(MAIN)), (CHILD_B, Some(MAIN))],
            vec![ITEM],
            Some(ITEM),
            vec![CHILD_A, CHILD_B, CHILD_A],
            Duration::from_millis(1500),
        );
        assert_eq!(starts.len(), 2, "one start per child: {starts:?}");
        assert!(starts
            .iter()
            .all(|(thread, item)| thread == MAIN && item == ITEM));
    }

    // ── scripted app-server (R1 fix-wave rows) ───────────────────────────

    #[derive(Clone, Default)]
    struct WatchScript {
        main_status: std::sync::Arc<std::sync::Mutex<String>>,
        /// Status returned only by the SEED read for MAIN (else `main_status`).
        main_seed: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        /// When set, MAIN's metadata carries this `parentThreadId` (a
        /// self-parented main makes the main exclusion the ONLY rejector).
        main_parent: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        main_can_accept: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
        /// Live status per thread id, returned by every non-seed `thread/read`.
        statuses: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
        /// Per-thread status returned by successive non-seed reads, consumed
        /// before `statuses`.
        sequence: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>>,
        parents:
            std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Option<String>>>>,
        queue: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        /// Notifications the test pushes; the server sends and clears them.
        outbox: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        /// One-shot delay per method name.
        delays: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Duration>>>,
        reads: std::sync::Arc<std::sync::Mutex<usize>>,
        loaded_lists: std::sync::Arc<std::sync::Mutex<usize>>,
    }

    impl WatchScript {
        fn thread_ids(&self) -> Vec<String> {
            let mut ids: Vec<String> = vec![MAIN.to_owned()];
            ids.extend(self.statuses.lock().unwrap().keys().cloned());
            ids
        }
    }

    fn serve_scripted(
        listener: UnixListener,
        home: PathBuf,
        script: WatchScript,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let publish = initialized_bounded(&listener, &home, Duration::from_secs(3));
            let mut socket = match initialized_bounded(&listener, &home, Duration::from_secs(3)) {
                Some(socket) => socket,
                None => return,
            };
            drop(publish);
            let seed_reads = script.thread_ids().len();
            // Wake periodically so notifications the test stages AFTER the
            // watcher went idle still reach it.
            socket
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(25)))
                .unwrap();
            loop {
                let pending: Vec<String> = script.outbox.lock().unwrap().drain(..).collect();
                for child in pending {
                    if socket
                        .send(tungstenite::Message::Text(
                            json!({"method":"turn/completed","params":{"threadId": child}})
                                .to_string()
                                .into(),
                        ))
                        .is_err()
                    {
                        return;
                    }
                }
                let message = match socket.read() {
                    Ok(tungstenite::Message::Text(text)) => text,
                    Ok(_) => continue,
                    Err(tungstenite::Error::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue
                    }
                    Err(_) => break,
                };
                let request: serde_json::Value = match serde_json::from_str(&message) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let Some(method) = request.get("method").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(id) = request.get("id").cloned() else {
                    continue;
                };
                let delay = script.delays.lock().unwrap().remove(method);
                if let Some(delay) = delay {
                    std::thread::sleep(delay);
                }
                match method {
                    "thread/loaded/list" => {
                        *script.loaded_lists.lock().unwrap() += 1;
                        let data: Vec<serde_json::Value> = script
                            .thread_ids()
                            .into_iter()
                            .map(|id| json!(id))
                            .collect();
                        send_result(&mut socket, id, json!({"data": data, "nextCursor": null}));
                    }
                    "thread/read" => {
                        let tid = request["params"]["threadId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        let seed = {
                            let mut reads = script.reads.lock().unwrap();
                            *reads += 1;
                            *reads <= seed_reads
                        };
                        let value = if tid == MAIN {
                            let status =
                                if seed {
                                    script.main_seed.lock().unwrap().clone().unwrap_or_else(|| {
                                        script.main_status.lock().unwrap().clone()
                                    })
                                } else {
                                    script.main_status.lock().unwrap().clone()
                                };
                            let parent = script.main_parent.lock().unwrap().clone();
                            let can_accept = script.main_can_accept.lock().unwrap().unwrap_or(true);
                            thread_meta(MAIN, parent.as_deref(), &status, can_accept)
                        } else {
                            let parent =
                                script.parents.lock().unwrap().get(&tid).cloned().flatten();
                            let status =
                                if seed {
                                    "active".to_owned()
                                } else if let Some(next) =
                                    script.sequence.lock().unwrap().get_mut(&tid).and_then(
                                        |queue| {
                                            if queue.is_empty() {
                                                None
                                            } else {
                                                Some(queue.remove(0))
                                            }
                                        },
                                    )
                                {
                                    next
                                } else {
                                    script
                                        .statuses
                                        .lock()
                                        .unwrap()
                                        .get(&tid)
                                        .cloned()
                                        .unwrap_or_else(|| "idle".to_owned())
                                };
                            thread_meta(&tid, parent.as_deref(), &status, false)
                        };
                        send_result(&mut socket, id, json!({"thread": value}));
                    }
                    "thread/queue/list" => {
                        let data: Vec<serde_json::Value> = script
                            .queue
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|id| json!({"id": id}))
                            .collect();
                        send_result(&mut socket, id, json!({"data": data, "nextCursor": null}));
                    }
                    _ => send_result(&mut socket, id, json!({})),
                }
            }
        })
    }

    struct ScriptedRun {
        starts: Vec<(String, String)>,
        script: WatchScript,
    }

    /// Drive the watcher against a scripted server.
    fn run_scripted(
        plan: &ManagedBackendPlan,
        listener: UnixListener,
        script: WatchScript,
        expected: Option<&'static str>,
        wait: Duration,
    ) -> ScriptedRun {
        let home = plan.handle_dir.clone();
        let server = serve_scripted(listener, home, script.clone());
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&launcher, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&launcher).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let dir = plan.handle_dir.clone();
        let sqlite = plan.sqlite_home.clone();
        let owner = launcher.clone();
        let watcher = std::thread::spawn(move || {
            let main_of = || Some(MAIN.to_owned());
            let queued_item = || expected.map(str::to_owned);
            let start = |thread: &str, item: &str| -> io::Result<String> {
                let _ = tx.send((thread.to_owned(), item.to_owned()));
                Ok(TURN.to_owned())
            };
            let stopped = || flag.load(std::sync::atomic::Ordering::SeqCst);
            watch_child_completions(
                &dir,
                &sqlite,
                &owner,
                &main_of,
                &queued_item,
                &start,
                &stopped,
                Duration::from_secs(30),
                Duration::from_millis(25),
            )
        });
        std::thread::sleep(wait);
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let outcome = watcher.join().unwrap();
        assert!(outcome.is_ok(), "watcher must stop cleanly: {outcome:?}");
        let _ = server.join();
        let mut starts = Vec::new();
        while let Ok(row) = rx.try_recv() {
            starts.push(row);
        }
        ScriptedRun { starts, script }
    }

    fn child_in(
        script: &WatchScript,
        id: &'static str,
        parent: Option<&'static str>,
        status: &str,
    ) {
        script
            .statuses
            .lock()
            .unwrap()
            .insert(id.to_owned(), status.to_owned());
        script
            .parents
            .lock()
            .unwrap()
            .insert(id.to_owned(), parent.map(str::to_owned));
    }

    /// A seed read delayed past the 25 ms notification slice must not kill the
    /// watcher: requests keep their own bound.
    #[test]
    fn fixwave_slow_response_past_the_slice_does_not_kill_the_watcher() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let script = WatchScript::default();
        *script.main_status.lock().unwrap() = "idle".to_owned();
        child_in(&script, CHILD_A, Some(MAIN), "idle");
        script.queue.lock().unwrap().push(ITEM.to_owned());
        script
            .delays
            .lock()
            .unwrap()
            .insert("thread/read".to_owned(), Duration::from_millis(300));
        script.outbox.lock().unwrap().push(CHILD_A.to_owned());
        let run = run_scripted(
            &plan,
            listener,
            script,
            Some(ITEM),
            Duration::from_millis(2000),
        );
        assert_eq!(
            run.starts,
            vec![(MAIN.to_owned(), ITEM.to_owned())],
            "a slow response must not kill the watcher"
        );
    }

    /// The supervised main is never a child candidate. The fixture makes the
    /// MAIN EXCLUSION the only rejector: the main is self-parented (so the
    /// parent check passes) and its seed read says `active` while its live
    /// read says `idle` (so the edge fires). Removing the exclusion starts a
    /// turn; with it, nothing starts. A flood forces the authoritative resync,
    /// which is where loaded threads (main included) are re-examined.
    #[test]
    fn fixwave_r2_main_is_never_a_child_candidate() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let script = WatchScript::default();
        *script.main_status.lock().unwrap() = "idle".to_owned();
        *script.main_seed.lock().unwrap() = Some("active".to_owned());
        *script.main_parent.lock().unwrap() = Some(MAIN.to_owned());
        script.queue.lock().unwrap().push(ITEM.to_owned());
        {
            let mut outbox = script.outbox.lock().unwrap();
            for n in 0..300u128 {
                outbox.push(
                    uuid::Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0000 + n)
                        .to_string(),
                );
            }
        }
        let run = run_scripted(
            &plan,
            listener,
            script,
            Some(ITEM),
            Duration::from_millis(3000),
        );
        assert!(
            run.starts.is_empty(),
            "the main thread must never wake itself: {:?}",
            run.starts
        );
    }

    /// A main that reports idle but `canAcceptDirectInput: false` starts
    /// nothing: the notice would not be taken.
    #[test]
    fn fixwave_main_not_accepting_direct_input_starts_nothing() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let script = WatchScript::default();
        *script.main_status.lock().unwrap() = "idle".to_owned();
        *script.main_can_accept.lock().unwrap() = Some(false);
        child_in(&script, CHILD_A, Some(MAIN), "idle");
        script.queue.lock().unwrap().push(ITEM.to_owned());
        script.outbox.lock().unwrap().push(CHILD_A.to_owned());
        let run = run_scripted(
            &plan,
            listener,
            script,
            Some(ITEM),
            Duration::from_millis(1500),
        );
        assert!(
            run.starts.is_empty(),
            "a non-accepting main starts nothing: {:?}",
            run.starts
        );
    }

    /// A second notice plus a second completion of the SAME child must wake
    /// again: dedupe is on (child, item), never on child alone.
    #[test]
    fn fixwave_second_notice_from_the_same_child_wakes_again() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let script = WatchScript::default();
        *script.main_status.lock().unwrap() = "idle".to_owned();
        // Seed reads report ACTIVE; the first live read reports IDLE (edge).
        child_in(&script, CHILD_A, Some(MAIN), "idle");
        script.queue.lock().unwrap().push(ITEM.to_owned());
        script.outbox.lock().unwrap().push(CHILD_A.to_owned());
        let home = plan.handle_dir.clone();
        let server = serve_scripted(listener, home, script.clone());
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&launcher, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&launcher).unwrap();
        let current = std::sync::Arc::new(std::sync::Mutex::new(ITEM.to_owned()));
        let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let dir = plan.handle_dir.clone();
        let sqlite = plan.sqlite_home.clone();
        let owner = launcher.clone();
        let watcher_item = current.clone();
        let watcher = std::thread::spawn(move || {
            let main_of = || Some(MAIN.to_owned());
            let queued_item = || Some(watcher_item.lock().unwrap().clone());
            let start = |thread: &str, item: &str| -> io::Result<String> {
                let _ = tx.send((thread.to_owned(), item.to_owned()));
                Ok(TURN.to_owned())
            };
            let stopped = || flag.load(std::sync::atomic::Ordering::SeqCst);
            watch_child_completions(
                &dir,
                &sqlite,
                &owner,
                &main_of,
                &queued_item,
                &start,
                &stopped,
                Duration::from_secs(30),
                Duration::from_millis(25),
            )
        });
        let first = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("first start");
        assert_eq!(first, (MAIN.to_owned(), ITEM.to_owned()));
        {
            let mut queue = script.queue.lock().unwrap();
            queue.clear();
            queue.push(ITEM2.to_owned());
        }
        *current.lock().unwrap() = ITEM2.to_owned();
        // Two reads: idle->active, then active->idle. The second is the edge.
        script.sequence.lock().unwrap().insert(
            CHILD_A.to_owned(),
            vec!["active".to_owned(), "idle".to_owned()],
        );
        script.outbox.lock().unwrap().push(CHILD_A.to_owned());
        script.outbox.lock().unwrap().push(CHILD_A.to_owned());
        let second = rx.recv_timeout(Duration::from_secs(3)).ok();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = watcher.join();
        let _ = server.join();
        assert_eq!(
            second,
            Some((MAIN.to_owned(), ITEM2.to_owned())),
            "a new notice plus a new completion must wake again"
        );
    }

    /// A flood of notifications across many threads while the watcher is busy
    /// in requests must overflow the bounded buffer, trigger ONE resync via
    /// thread/loaded/list, and leave the watcher working.
    #[test]
    fn fixwave_notification_flood_resyncs_and_keeps_watching() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let script = WatchScript::default();
        *script.main_status.lock().unwrap() = "idle".to_owned();
        child_in(&script, CHILD_A, Some(MAIN), "idle");
        script.queue.lock().unwrap().push(ITEM.to_owned());
        {
            let mut outbox = script.outbox.lock().unwrap();
            for n in 0..300u128 {
                outbox.push(
                    uuid::Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0000 + n)
                        .to_string(),
                );
            }
        }
        script.outbox.lock().unwrap().push(CHILD_A.to_owned());
        let before = *script.loaded_lists.lock().unwrap();
        let run = run_scripted(
            &plan,
            listener,
            script,
            Some(ITEM),
            Duration::from_millis(2500),
        );
        let after = *run.script.loaded_lists.lock().unwrap();
        assert!(
            after >= before + 2,
            "a flood must trigger a resync (seed + resync >= 2): before={before} after={after}"
        );
        assert_eq!(
            run.starts,
            vec![(MAIN.to_owned(), ITEM.to_owned())],
            "the watcher must keep working after a resync"
        );
    }

    /// An EXISTING RPC caller (queue/add) keeps its pre-fix budget: a reply
    /// slower than the watcher's 2 s exchange cap must still be reported.
    #[test]
    fn fixwave_r2_slow_queue_add_still_queues() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            // Connection 1 is the binding publication's handshake.
            let _publish = initialized(&listener, &home);
            let mut socket = initialized(&listener, &home);
            let request = receive(&mut socket);
            assert_eq!(request["method"], "thread/queue/add");
            std::thread::sleep(Duration::from_millis(2500));
            let message_id = request["params"]["clientUserMessageId"].clone();
            send_result(
                &mut socket,
                request["id"].clone(),
                json!({"queuedSubmission":{"id":ITEM,"clientUserMessageId":message_id}}),
            );
            wait_for_client_close(&mut socket);
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&launcher, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&launcher)
            .unwrap();
        let summary = crate::messaging::store::PendingNotice::count_only(1);
        let queued = enqueue_summary(
            &plan.handle_dir,
            &plan.sqlite_home,
            &launcher,
            MAIN,
            &summary,
            Duration::from_secs(6),
        );
        let _ = server.join();
        assert_eq!(queued.unwrap(), ITEM, "a slow queue/add must still queue");
    }

    /// A streaming server plus a withheld reply must not hold the watcher: a
    /// stop is honoured between reads, so the join has a real bound.
    #[test]
    fn fixwave_r2_watcher_stops_during_a_stream() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream_stop = server_stop.clone();
        let server = std::thread::spawn(move || {
            let _publish = initialized(&listener, &home);
            let mut socket = initialized(&listener, &home);
            socket
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let mut seeded = false;
            while !stream_stop.load(std::sync::atomic::Ordering::SeqCst) {
                // The stream: an item event every read window.
                let _ = socket.send(tungstenite::Message::Text(
                    json!({"method":"item/delta","params":{"threadId":MAIN}})
                        .to_string()
                        .into(),
                ));
                match socket.read() {
                    Ok(tungstenite::Message::Text(text)) => {
                        let request: serde_json::Value =
                            serde_json::from_str(&text).unwrap_or_default();
                        let Some(method) =
                            request.get("method").and_then(serde_json::Value::as_str)
                        else {
                            continue;
                        };
                        let Some(id) = request.get("id").cloned() else {
                            continue;
                        };
                        match method {
                            "thread/loaded/list" => send_result(
                                &mut socket,
                                id,
                                json!({"data":[MAIN, CHILD_A], "nextCursor": null}),
                            ),
                            "thread/read" if !seeded => {
                                seeded = true;
                                let tid =
                                    request["params"]["threadId"].as_str().unwrap_or_default();
                                let value = if tid == MAIN {
                                    thread_meta(MAIN, None, "idle", true)
                                } else {
                                    thread_meta(tid, Some(MAIN), "active", false)
                                };
                                send_result(&mut socket, id, json!({"thread": value}));
                            }
                            _ => {}
                        }
                        if seeded {
                            // Trigger ONE read the server will never answer.
                            let _ = socket.send(tungstenite::Message::Text(
                                json!({"method":"turn/completed",
                                       "params":{"threadId":CHILD_A}})
                                .to_string()
                                .into(),
                            ));
                        }
                    }
                    Ok(_) => continue,
                    Err(tungstenite::Error::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => return,
                }
            }
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&launcher, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&launcher).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let dir = plan.handle_dir.clone();
        let sqlite = plan.sqlite_home.clone();
        let owner = launcher.clone();
        let watcher = std::thread::spawn(move || {
            let main_of = || Some(MAIN.to_owned());
            let queued_item = || Some(ITEM.to_owned());
            let start = |_thread: &str, _item: &str| -> io::Result<String> { Ok(TURN.to_owned()) };
            let stopped = || flag.load(std::sync::atomic::Ordering::SeqCst);
            watch_child_completions(
                &dir,
                &sqlite,
                &owner,
                &main_of,
                &queued_item,
                &start,
                &stopped,
                Duration::from_secs(30),
                Duration::from_millis(25),
            )
        });
        // Let the seed and the withheld read happen, then stop.
        std::thread::sleep(Duration::from_millis(1200));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let bound = Instant::now() + Duration::from_secs(4);
        while !watcher.is_finished() && Instant::now() < bound {
            std::thread::sleep(Duration::from_millis(20));
        }
        let finished = watcher.is_finished();
        server_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = server.join();
        if finished {
            let _ = watcher.join();
        }
        assert!(
            finished,
            "a stop must end the watcher within its bound even while the server streams"
        );
    }

    /// Lay down a binding and drive one start against `status`, returning the
    /// result and whether the server ever saw `thread/queue/start`.
    fn run_start_with_status(
        status: &str,
        admission: StartAdmission,
    ) -> (io::Result<String>, bool) {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let status = status.to_owned();
        let seen_start = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = seen_start.clone();
        let server = std::thread::spawn(move || {
            let _publish = initialized(&listener, &home);
            let mut socket = initialized(&listener, &home);
            socket
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(600)))
                .unwrap();
            loop {
                match socket.read() {
                    Ok(tungstenite::Message::Text(text)) => {
                        let request: serde_json::Value =
                            serde_json::from_str(&text).unwrap_or_default();
                        let method = request
                            .get("method")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default();
                        let Some(id) = request.get("id").cloned() else {
                            continue;
                        };
                        match method {
                            "thread/read" => send_result(
                                &mut socket,
                                id,
                                json!({"thread": thread_meta(MAIN, None, &status, true)}),
                            ),
                            "thread/queue/start" => {
                                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                                send_result(&mut socket, id, json!({"turn":{"id":TURN}}));
                                wait_for_client_close(&mut socket);
                                return;
                            }
                            _ => {}
                        }
                    }
                    Ok(_) => continue,
                    Err(_) => return,
                }
            }
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&launcher, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&launcher)
            .unwrap();
        let result = start_existing_queue_item(
            &plan.handle_dir,
            &plan.sqlite_home,
            &launcher,
            MAIN,
            ITEM,
            admission,
            Duration::from_secs(3),
        );
        let _ = server.join();
        (result, seen_start.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[test]
    fn fixwave_r2_start_refuses_a_busy_thread() {
        let (result, saw_start) = run_start_with_status("busy", StartAdmission::RequireIdle);
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "a busy thread must be refused"
        );
        assert!(!saw_start, "no queue/start may be issued for a busy thread");
    }

    /// The interrupted-turn live path admits ANY status: a non-idle main is
    /// started, and no idle probe is made at all.
    #[test]
    fn fixwave_r2_admit_any_status_starts_a_busy_main() {
        let (result, saw_start) =
            run_start_with_status("interrupted", StartAdmission::AdmitAnyStatus);
        assert_eq!(result.unwrap(), TURN);
        assert!(saw_start);
    }

    /// A reply whose id is not the request in flight is discarded.
    #[test]
    fn fixwave_r2_stray_reply_discarded() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = std::thread::spawn(move || {
            let _publish = initialized(&listener, &home);
            let mut socket = initialized(&listener, &home);
            let request = receive(&mut socket);
            assert_eq!(request["method"], "thread/read");
            send_result(
                &mut socket,
                json!("not-this-request"),
                json!({"thread": {"id": CHILD_A}}),
            );
            send_result(
                &mut socket,
                request["id"].clone(),
                json!({"thread": thread_meta(MAIN, None, "idle", true)}),
            );
            wait_for_client_close(&mut socket);
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&launcher, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&launcher)
            .unwrap();
        let binding = read_binding(&plan.handle_dir, &plan.sqlite_home).unwrap();
        let (stream, _, _, _) = connect_checked(
            &binding.socket_path,
            Some(&binding),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let mut client = RpcClient::initialize(
            stream,
            &binding.handle_dir,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let thread = read_thread(&mut client, MAIN).unwrap();
        let _ = server.join();
        assert_eq!(thread_id_of(&thread).as_deref(), Some(MAIN));
    }

    /// A timed-out exchange poisons the connection: the late reply can never
    /// be read as the answer to a later request, so the next call fails fast
    /// instead of waiting on the wire.
    #[test]
    fn fixwave_r2_timeout_poisons_the_connection() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream_stop = server_stop.clone();
        let server = std::thread::spawn(move || {
            let _publish = initialized(&listener, &home);
            let mut socket = initialized(&listener, &home);
            socket
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            while !stream_stop.load(std::sync::atomic::Ordering::SeqCst) {
                match socket.read() {
                    Ok(_) => {}
                    Err(tungstenite::Error::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => return,
                }
            }
        });
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        plan.publish_binding(&launcher, Duration::from_secs(3))
            .unwrap()
            .publish_recipient(&launcher)
            .unwrap();
        let binding = read_binding(&plan.handle_dir, &plan.sqlite_home).unwrap();
        let (stream, _, _, _) = connect_checked(
            &binding.socket_path,
            Some(&binding),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        let never = || false;
        let mut client = RpcClient::initialize_watch(
            stream,
            &binding.handle_dir,
            Instant::now() + Duration::from_secs(30),
            &never,
        )
        .unwrap();
        let first = client.request(
            "thread/read",
            json!({"threadId": MAIN, "includeTurns": false}),
        );
        assert_eq!(first.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let started = Instant::now();
        let second = client.request(
            "thread/read",
            json!({"threadId": MAIN, "includeTurns": false}),
        );
        assert_eq!(second.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a poisoned connection fails fast"
        );
        server_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = server.join();
    }

    #[test]
    fn watcher_returns_at_its_total_deadline_without_spinning() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let home = plan.handle_dir.clone();
        let server = serve_child_watch(listener, home, "idle", vec![], vec![ITEM], vec![]);
        let launcher = LauncherIdentity::capture(std::process::id()).unwrap();
        let mut binding = plan
            .publish_binding(&launcher, Duration::from_secs(3))
            .unwrap();
        binding.publish_recipient(&launcher).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let dir = plan.handle_dir.clone();
        let sqlite = plan.sqlite_home.clone();
        let owner = launcher.clone();
        let watcher = std::thread::spawn(move || {
            let main_of = || Some(MAIN.to_owned());
            let queued_item = || Some(ITEM.to_owned());
            let start = |_thread: &str, _item: &str| Ok(TURN.to_owned());
            let stopped = || flag.load(std::sync::atomic::Ordering::SeqCst);
            watch_child_completions(
                &dir,
                &sqlite,
                &owner,
                &main_of,
                &queued_item,
                &start,
                &stopped,
                Duration::from_millis(800),
                Duration::from_millis(20),
            )
        });
        std::thread::sleep(Duration::from_millis(2500));
        let finished = watcher.is_finished();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let outcome = watcher.join().unwrap();
        let _ = server.join();
        assert!(
            finished,
            "the watcher must return at its total deadline instead of spinning"
        );
        assert!(outcome.is_ok(), "deadline stop is clean: {outcome:?}");
    }

    #[test]
    fn recorded_item_absent_from_queue_starts_nothing() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let starts = run_child_watch(
            &plan,
            listener,
            "idle",
            vec![(CHILD_A, Some(MAIN))],
            vec![],
            Some(ITEM),
            vec![CHILD_A],
            Duration::from_millis(1200),
        );
        assert!(
            starts.is_empty(),
            "an already-consumed notice must not be started: {starts:?}"
        );
    }

    #[test]
    fn no_recorded_item_starts_nothing() {
        let (_temp, plan) = plan();
        let listener = test_listener(&plan);
        let starts = run_child_watch(
            &plan,
            listener,
            "idle",
            vec![(CHILD_A, Some(MAIN))],
            vec![ITEM],
            None,
            vec![CHILD_A],
            Duration::from_millis(1200),
        );
        assert!(
            starts.is_empty(),
            "a queue holding a user message must never be started early: {starts:?}"
        );
    }
}
