// Standalone Linux libtest: root supplies two actually built native CLI images.
// An owned Codex-shaped ELF is a resolver fixture, not a real Codex client/model.
#[cfg(not(target_os = "linux"))]
compile_error!("native MCP exec fixture requires Linux /proc and ELF images");

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
const META: &str = "com.terrene.csq/mcp-image-v1";

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing native prerequisite {name}"))
}
fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn executable_copy(source: &Path, target: &Path) {
    fs::copy(source, target).unwrap();
    fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
}
fn image(name: &str) -> PathBuf {
    let path = PathBuf::from(required(name));
    assert!(path.is_absolute(), "native image must be absolute");
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    fs::canonicalize(path).unwrap()
}
fn revision(name: &str) -> String {
    let value = required(name);
    assert!(matches!(value.len(), 40 | 64));
    assert!(value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    value
}
fn isolated(command: &mut Command, root: &Path) {
    command.env_clear().current_dir(root);
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "CSQ_HOME",
        "CLAUDE_HOME",
    ] {
        command.env(key, root.join("home"));
    }
    for key in ["TMPDIR", "TMP", "TEMP"] {
        command.env(key, root.join("tmp"));
    }
    command.env("CSQ_BASE_DIR", root.join("base"));
    command.env("CODEX_HOME", root.join("handle"));
    command.env("XDG_CACHE_HOME", root.join("cache"));
    command.env("XDG_CONFIG_HOME", root.join("config"));
    command.env("PATH", root.join("bin"));
    command.env("LANG", "C").env("LC_ALL", "C");
}
fn process_identity(pid: u32) -> (u32, u64) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let (_, tail) = stat.rsplit_once(')').unwrap();
    let fields: Vec<_> = tail.split_whitespace().collect();
    (fields[1].parse().unwrap(), fields[19].parse().unwrap())
}
fn file_identity(path: &Path) -> Value {
    let m = File::open(path).unwrap().metadata().unwrap();
    json!({"dev":m.dev(), "ino":m.ino(), "size":m.size(),
        "mtime_sec":m.mtime(), "mtime_nsec":m.mtime_nsec(),
        "ctime_sec":m.ctime(), "ctime_nsec":m.ctime_nsec()})
}
struct OwnedGroup {
    owner: Child,
    rpc: UnixStream,
    finished: bool,
}
impl Drop for OwnedGroup {
    fn drop(&mut self) {
        let _ = self.rpc.shutdown(Shutdown::Both);
        // The unreaped group leader reserves its PID; only our spawned group is killed.
        if !self.finished {
            unsafe {
                kill(-(self.owner.id() as i32), 9);
            }
            let _ = self.owner.wait();
        }
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn response(reader: &mut BufReader<UnixStream>) -> Value {
    let mut bytes = Vec::new();
    reader.take(65537).read_until(b'\n', &mut bytes).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 65536 && bytes.ends_with(b"\n"));
    serde_json::from_slice(&bytes).unwrap()
}
fn request(id: u64, method: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "method":method,
        "params":{"protocolVersion":"2024-11-05"}})
}
fn report(response: &Value) -> &Value {
    assert!(
        response.get("error").is_none(),
        "native RPC error: {response}"
    );
    let report = &response["result"]["_meta"][META];
    assert!(
        report.is_object(),
        "actual native image metadata is required"
    );
    report
}
fn assert_report(value: &Value, rev: &str, owner: u32, handle: &Path) -> (u32, u64) {
    assert_eq!(value["schema"], "csq.mcp_image.v1");
    assert_eq!(value["platform"], "linux");
    assert_eq!(value["build"]["revision"], rev);
    assert_eq!(value["build"]["source_state"], "clean");
    assert_eq!(value["build"]["availability"], "available");
    let pid = u32::try_from(value["child"]["pid"].as_u64().unwrap()).unwrap();
    let start = value["child"]["start_exact"].as_u64().unwrap();
    assert_ne!(pid, owner);
    assert_eq!(process_identity(pid), (owner, start));
    assert_eq!(value["session"]["pid"], owner);
    assert_eq!(value["session"]["start_exact"], process_identity(owner).1);
    assert!(value["session"]["started_at"].as_u64().unwrap() > 0);
    assert_eq!(value["session"]["surface"], "codex");
    let canonical = fs::canonicalize(handle).unwrap();
    let digest = format!(
        "{:x}",
        Sha256::digest(
            canonical
                .to_str()
                .expect("owned handle must be UTF-8")
                .as_bytes()
        )
    );
    assert_eq!(value["session"]["handle_sha256"], digest);
    assert_eq!(value["loaded"]["kind"], "linux_proc_exe");
    assert_eq!(
        value["loaded"]["identity"],
        file_identity(Path::new(&format!("/proc/{pid}/exe")))
    );
    (pid, start)
}
fn assert_publication(handle: &Path, report: &Value, pid: u32, start: u64) {
    let directory = handle.join(".csq-mcp-images");
    let mut bytes = Vec::new();
    File::open(directory.join(format!("{pid}-{start}.json")))
        .unwrap()
        .take(4097)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 4096);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), *report);
    let finals: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    assert_eq!(finals.len(), 1, "one stable native PID/start report slot");
}

#[test]
fn native_owned_parent() {
    assert_eq!(required("CSQ_NATIVE_OWNER_ROLE"), "1");
    let root = PathBuf::from(required("CSQ_NATIVE_OWNER_ROOT"));
    assert_eq!(
        fs::read_to_string("/proc/self/comm").unwrap().trim(),
        "codex"
    );
    // libtest output stays in the owner log; stdin is the dedicated RPC socket.
    let socket = unsafe { File::from_raw_fd(0) };
    let mut command = Command::new(root.join("bin/csq"));
    isolated(&mut command, &root);
    command.arg("mcp-messaging");
    command.stdin(Stdio::from(socket.try_clone().unwrap()));
    command.stdout(Stdio::from(socket));
    command.stderr(Stdio::from(File::create(root.join("mcp.stderr")).unwrap()));
    let mut child = OwnedChild(command.spawn().unwrap());
    drop(command);
    assert!(child.0.wait().unwrap().success(), "native MCP child failed");
}

#[test]
fn native_mcp_image_same_pid_exec() {
    let a = image("CSQ_NATIVE_IMAGE_A");
    let b = image("CSQ_NATIVE_IMAGE_B");
    let rev_a = revision("CSQ_NATIVE_REVISION_A");
    let rev_b = revision("CSQ_NATIVE_REVISION_B");
    assert_ne!(
        rev_a, rev_b,
        "two distinct actually compiled image revisions required"
    );
    let parent = fs::canonicalize(required("CSQ_NATIVE_EXEC_TMP")).unwrap();
    assert!(parent.is_dir());
    let temp = tempfile::Builder::new()
        .prefix("csq-native-exec-")
        .tempdir_in(parent)
        .unwrap();
    let root = temp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["home", "tmp", "base", "handle", "cache", "config", "bin"] {
        private_dir(&root.join(name));
    }
    let watched = root.join("bin/csq");
    executable_copy(&a, &watched);
    let owner_image = root.join("bin/codex");
    executable_copy(&std::env::current_exe().unwrap(), &owner_image);
    let (rpc, inherited) = UnixStream::pair().unwrap();
    rpc.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    rpc.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut command = Command::new(owner_image);
    isolated(&mut command, root);
    command
        .arg("--exact")
        .arg("native_owned_parent")
        .arg("--nocapture");
    command
        .env("CSQ_NATIVE_OWNER_ROLE", "1")
        .env("CSQ_NATIVE_OWNER_ROOT", root);
    command
        .process_group(0)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(inherited)));
    let log = File::create(root.join("owner.log")).unwrap();
    command
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    let mut owned = OwnedGroup {
        owner: command.spawn().unwrap(),
        rpc,
        finished: false,
    };
    drop(command);
    let owner = owned.owner.id();
    assert_eq!(
        fs::read_to_string(format!("/proc/{owner}/comm"))
            .unwrap()
            .trim(),
        "codex"
    );
    let mut reader = BufReader::new(owned.rpc.try_clone().unwrap());
    writeln!(owned.rpc, "{}", request(0, "initialize")).unwrap();
    owned.rpc.flush().unwrap();
    let initial = response(&mut reader);
    assert_eq!(initial["id"], 0);
    let first = report(&initial).clone();
    let (pid, start) = assert_report(&first, &rev_a, owner, &root.join("handle"));
    assert_publication(&root.join("handle"), &first, pid, start);
    let next = root.join("bin/.csq-next");
    executable_copy(&b, &next);
    fs::rename(next, &watched).unwrap();
    // One write queues all requests. No timing or synthetic in-flight gate is claimed.
    let batch = [
        request(1, "ping"),
        request(2, "initialize"),
        request(3, "tools/list"),
    ]
    .map(|v| format!("{v}\n"))
    .concat();
    owned.rpc.write_all(batch.as_bytes()).unwrap();
    owned.rpc.flush().unwrap();
    let mut replies = Vec::new();
    let mut notifications = 0;
    for _ in 0..4 {
        let value = response(&mut reader);
        if value.get("id").is_some() {
            assert!(value.get("error").is_none(), "queued RPC failed: {value}");
            replies.push(value);
        } else {
            assert_eq!(value["method"], "notifications/tools/list_changed");
            notifications += 1;
        }
    }
    assert_eq!(notifications, 1);
    assert_eq!(
        replies
            .iter()
            .map(|v| v["id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let second = report(&replies[1]);
    assert_eq!(
        assert_report(second, &rev_b, owner, &root.join("handle")),
        (pid, start)
    );
    assert_eq!(second["session"], first["session"]);
    for field in ["edition", "version", "target"] {
        assert_eq!(second["build"][field], first["build"][field]);
    }
    assert_ne!(second["loaded"]["identity"], first["loaded"]["identity"]);
    assert_eq!(second["loaded"]["identity"], file_identity(&watched));
    assert_publication(&root.join("handle"), second, pid, start);
    let mut tools: Vec<_> = replies[2]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    tools.sort_unstable();
    assert_eq!(
        tools,
        ["ack", "inbox", "list_sessions", "reply", "send", "set_name"]
    );
    // EOF completes the stream: any duplicate or extra output fails, not just its prefix.
    owned.rpc.shutdown(Shutdown::Write).unwrap();
    let mut extra = [0_u8; 1];
    assert_eq!(
        reader.read(&mut extra).unwrap(),
        0,
        "unexpected additional native output"
    );
    let status = owned.owner.wait().unwrap();
    owned.finished = true;
    assert!(status.success(), "owned native parent failed");
}
