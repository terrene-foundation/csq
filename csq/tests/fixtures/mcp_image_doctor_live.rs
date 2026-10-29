// Standalone Linux libtest: root supplies one actually built N2-capable CLI image.
// An owned Codex-shaped ELF is a resolver fixture, not a real Codex client/model.
#[cfg(not(target_os = "linux"))]
compile_error!("native MCP exec fixture requires Linux /proc and ELF images");

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
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
    command.env("PATH", root.join("empty-path"));
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

fn wait_child(child: &mut Child, deadline: Instant) -> std::process::ExitStatus {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "owned subprocess deadline exceeded"
        );
        std::thread::yield_now();
    }
}
fn bounded_file(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(131073)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 131072, "doctor output exceeds fixture bound");
    bytes
}
fn doctor(root: &Path, json: bool, deadline: Instant) {
    let stem = if json { "doctor-json" } else { "doctor-text" };
    let mut command = Command::new(root.join("home/.local/bin/csq"));
    isolated(&mut command, root);
    command.arg("doctor");
    if json {
        command.arg("--json");
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(
        File::create(root.join(format!("{stem}.stdout"))).unwrap(),
    ));
    command.stderr(Stdio::from(
        File::create(root.join(format!("{stem}.stderr"))).unwrap(),
    ));
    let mut child = OwnedChild(command.spawn().unwrap());
    drop(command);
    assert!(
        wait_child(&mut child.0, deadline).success(),
        "actual doctor failed"
    );
}
#[test]
fn native_doctor_owned_parent() {
    assert_eq!(required("CSQ_NATIVE_DOCTOR_OWNER_ROLE"), "1");
    let root = PathBuf::from(required("CSQ_NATIVE_DOCTOR_OWNER_ROOT"));
    let deadline = Instant::now() + Duration::from_secs(50);
    assert_eq!(
        fs::read_to_string("/proc/self/comm").unwrap().trim(),
        "codex"
    );
    let socket = unsafe { File::from_raw_fd(0) };
    let mut command = Command::new(root.join("home/.local/bin/csq"));
    isolated(&mut command, &root);
    command
        .arg("mcp-messaging")
        .stdin(Stdio::from(socket.try_clone().unwrap()));
    command.stdout(Stdio::from(socket));
    command.stderr(Stdio::from(File::create(root.join("mcp.stderr")).unwrap()));
    let mut child = OwnedChild(command.spawn().unwrap());
    drop(command);
    let mut control = UnixStream::connect(root.join("control.sock")).unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    control
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut start = [0; 7];
    control.read_exact(&mut start).unwrap();
    assert_eq!(&start, b"doctor\n");
    doctor(&root, true, deadline);
    doctor(&root, false, deadline);
    control.write_all(b"done\n").unwrap();
    assert!(
        wait_child(&mut child.0, deadline).success(),
        "native MCP failed"
    );
}
#[test]
fn native_doctor_live_mcp_json_and_text() {
    let native = image("CSQ_NATIVE_IMAGE_A");
    let rev = revision("CSQ_NATIVE_REVISION_A");
    let parent = fs::canonicalize(required("CSQ_NATIVE_EXEC_TMP")).unwrap();
    assert!(parent.is_dir());
    let temp = tempfile::Builder::new()
        .prefix("csq-native-doctor-")
        .tempdir_in(parent)
        .unwrap();
    let root = temp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "home",
        "tmp",
        "base",
        "handle",
        "cache",
        "config",
        "owner",
        "empty-path",
        "home/.local",
        "home/.local/bin",
    ] {
        private_dir(&root.join(name));
    }
    // Ordinary fresh cache suppresses community update HTTP; no provider/probe bypass.
    File::create(root.join("base/.csq-update-check")).unwrap();
    let installed = root.join("home/.local/bin/csq");
    executable_copy(&native, &installed);
    let owner_image = root.join("owner/codex");
    executable_copy(&std::env::current_exe().unwrap(), &owner_image);
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (rpc, inherited) = UnixStream::pair().unwrap();
    rpc.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    rpc.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut command = Command::new(owner_image);
    isolated(&mut command, root);
    command.args(["--exact", "native_doctor_owned_parent", "--nocapture"]);
    command
        .env("CSQ_NATIVE_DOCTOR_OWNER_ROLE", "1")
        .env("CSQ_NATIVE_DOCTOR_OWNER_ROOT", root);
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
    let initial_report = report(&initial);
    let (pid, start) = assert_report(initial_report, &rev, owner, &root.join("handle"));
    let installed_identity = file_identity(&installed);
    assert_eq!(initial_report["loaded"]["identity"], installed_identity);
    let published = root.join(format!("handle/.csq-mcp-images/{pid}-{start}.json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&bounded_file(&published)).unwrap(),
        *initial_report
    );
    let mut control = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "owner control connection deadline"
                );
                std::thread::yield_now();
            }
            Err(e) => panic!("owner control connection: {e}"),
        }
    };
    control
        .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .unwrap();
    control
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    control.write_all(b"doctor\n").unwrap();
    let mut done = [0; 5];
    control.read_exact(&mut done).unwrap();
    assert_eq!(&done, b"done\n");
    let json_bytes = bounded_file(&root.join("doctor-json.stdout"));
    assert_eq!(json_bytes.iter().filter(|b| **b == b'\n').count(), 1);
    let value: Value = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(value["schema"], "csq.doctor.v35");
    assert_eq!(value["schema_version"], 35);
    assert_eq!(value["cli_shim"]["check_status"], "current");
    assert_eq!(value["cli_shim"]["managed_plist_allowed"], true);
    let rows = value["mcp_images"]["rows"].as_array().unwrap();
    let matching: Vec<_> = rows
        .iter()
        .filter(|r| r["child"]["pid"] == pid && r["child"]["start_exact"] == start)
        .collect();
    assert_eq!(matching.len(), 1, "exact live owned child row required");
    let row = matching[0];
    assert_eq!(row["state"], "same_image", "undetermined is a failure");
    assert_eq!(row["reason"], "none");
    for field in ["child", "session", "build"] {
        assert_eq!(row[field], initial_report[field]);
    }
    assert_eq!(row["reported_loaded"], initial_report["loaded"]);
    assert_eq!(row["observed_loaded"], installed_identity);
    assert_eq!(row["installed"], installed_identity);
    let coverage = value["mcp_images"]["coverage"].as_str().unwrap();
    assert!(matches!(coverage, "complete" | "limited" | "unavailable"));
    let text = String::from_utf8(bounded_file(&root.join("doctor-text.stdout"))).unwrap();
    assert!(
        text.lines()
            .any(|line| line == format!("MCP executable-file identity: coverage {coverage}"))
    );
    assert_eq!(
        text.lines()
            .filter(|line| *line == format!("  child {pid}: same_image (none)"))
            .count(),
        1
    );
    assert_report(initial_report, &rev, owner, &root.join("handle"));
    assert_eq!(file_identity(&installed), installed_identity);
    writeln!(owned.rpc, "{}", request(1, "ping")).unwrap();
    owned.rpc.flush().unwrap();
    let ping = response(&mut reader);
    assert_eq!(ping["id"], 1);
    assert!(ping.get("error").is_none());
    owned.rpc.shutdown(Shutdown::Write).unwrap();
    let mut extra = [0; 1];
    assert_eq!(
        reader.read(&mut extra).unwrap(),
        0,
        "no trailing RPC output"
    );
    let status = wait_child(&mut owned.owner, deadline);
    owned.finished = true;
    assert!(status.success(), "owned native doctor/MCP helper failed");
}
