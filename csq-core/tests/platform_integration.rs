//! Integration tests for the platform abstraction layer.
//!
//! These tests exercise cross-process locking, atomic writes under
//! contention, and process lifecycle detection.

use csq_core::platform::fs::{atomic_replace, secure_file};
use csq_core::platform::lock::{lock_file, try_lock_file};
use csq_core::platform::process::{is_cc_command, is_pid_alive};
use std::fs;
use tempfile::TempDir;

// ── Cross-process file locking ────────────────────────────────────────

#[cfg(unix)]
fn perl_try_flock(lock_path: &std::path::Path) -> String {
    use std::process::Command;

    // Use perl for cross-process flock testing — available on both macOS and Linux.
    let output = Command::new("perl")
        .arg("-e")
        .arg(format!(
            r#"use Fcntl qw(:flock); open(my $fh, ">", "{}") or die "open: $!"; if (flock($fh, LOCK_EX|LOCK_NB)) {{ print "acquired\n" }} else {{ print "blocked\n" }}"#,
            lock_path.display()
        ))
        .output()
        .expect("perl should be available");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(unix)]
#[test]
fn cross_process_lock_contention() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("cross.lock");

    // Acquire the lock in this process
    let _guard = lock_file(&lock_path).unwrap();

    // Spawn a child (via perl) that tries a non-blocking flock on the same file
    let result = perl_try_flock(&lock_path);
    assert_eq!(result, "blocked", "child should not acquire the lock");
}

#[cfg(unix)]
#[test]
fn lock_released_after_drop_allows_child() {
    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("release.lock");

    // Acquire and immediately release
    {
        let _guard = lock_file(&lock_path).unwrap();
    }

    // Child should now acquire it
    let result = perl_try_flock(&lock_path);
    assert_eq!(result, "acquired", "child should acquire after drop");
}

#[cfg(unix)]
#[test]
fn try_lock_returns_none_when_held_cross_process() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let dir = TempDir::new().unwrap();
    let lock_path = dir.path().join("try_lock.lock");

    // Spawn a child that holds a flock and signals readiness via stdout
    let mut child = Command::new("perl")
        .arg("-e")
        .arg(format!(
            r#"use Fcntl qw(:flock); open(my $fh, ">", "{}") or die "open: $!"; flock($fh, LOCK_EX) or die "flock: $!"; print "locked\n"; STDOUT->flush(); sleep 30;"#,
            lock_path.display()
        ))
        .stdout(Stdio::piped())
        .spawn()
        .expect("perl should be available");

    // Wait for child to signal it holds the lock
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "locked");

    // Now try_lock_file should return None since the child holds the lock
    let result = try_lock_file(&lock_path).unwrap();
    assert!(
        result.is_none(),
        "try_lock_file should return None when lock is held by another process"
    );

    // Clean up
    child.kill().unwrap();
    child.wait().unwrap();
}

// ── Atomic writes under contention ────────────────────────────────────

#[test]
fn atomic_replace_no_partial_reads() {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let dir = TempDir::new().unwrap();
    let target = dir.path().join("contended.txt");
    fs::write(&target, "initial_value").unwrap();

    let target_arc = Arc::new(target.clone());
    let dir_path = Arc::new(dir.path().to_path_buf());
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Writer threads: continuously replace the file
    let writer_handles: Vec<_> = (0..4)
        .map(|i| {
            let target = Arc::clone(&target_arc);
            let dir_path = Arc::clone(&dir_path);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut iter = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let payload = format!("w{i}_{iter:08}");
                    let tmp = dir_path.join(format!("wr_{i}_{iter}.tmp"));
                    fs::write(&tmp, &payload).unwrap();
                    let _ = atomic_replace(&tmp, &target);
                    iter += 1;
                }
            })
        })
        .collect();

    // Reader thread: continuously reads the file and checks for partial content
    let reader_target = Arc::clone(&target_arc);
    let reader_stop = Arc::clone(&stop);
    let reader = thread::spawn(move || {
        let mut reads = 0u64;
        while !reader_stop.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(content) = fs::read_to_string(&*reader_target) {
                // Content must be well-formed: either "initial_value" or "wN_NNNNNNNN"
                assert!(
                    content == "initial_value" || (content.starts_with('w') && content.len() >= 4),
                    "partial read detected: {content:?}"
                );
                reads += 1;
            }
        }
        reads
    });

    thread::sleep(Duration::from_millis(500));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);

    for h in writer_handles {
        h.join().unwrap();
    }
    let reads = reader.join().unwrap();
    assert!(reads > 0, "reader should have completed at least one read");
}

// ── Secure file permissions ───────────────────────────────────────────

#[cfg(unix)]
#[test]
fn secure_file_integration() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("creds.json");
    fs::write(&path, r#"{"token": "secret"}"#).unwrap();

    // Default might be 0o644
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    secure_file(&path).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ── Process lifecycle ─────────────────────────────────────────────────

#[test]
fn spawn_detect_kill_verify() {
    use std::process::Command;

    // Spawn a long-running process
    let mut child = Command::new("sleep").arg("60").spawn().unwrap();

    let pid = child.id();
    assert!(is_pid_alive(pid), "spawned process should be alive");

    // Kill it
    child.kill().unwrap();
    child.wait().unwrap();

    // Give the OS a moment to reap
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!is_pid_alive(pid), "killed process should be dead");
}

// ── CC command detection (exhaustive) ─────────────────────────────────

#[test]
fn cc_command_detection_exhaustive() {
    // Positive matches
    let positives = [
        "claude",
        "Claude",
        "/usr/local/bin/claude",
        "/opt/homebrew/bin/claude",
        "/home/user/.local/bin/claude",
        "C:\\Users\\jack\\AppData\\Local\\claude.exe",
        "node /usr/local/bin/claude",
        "node.exe C:\\Users\\jack\\AppData\\claude",
        "node /home/user/.nvm/versions/node/v20.11.0/bin/claude",
        "node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js",
    ];
    for cmd in &positives {
        assert!(is_cc_command(cmd), "should match: {cmd}");
    }

    // Negative matches
    let negatives = [
        "/bin/bash",
        "zsh",
        "vim",
        "python3",
        "node server.js",
        "node index.js",
        "",
        "claudette", // different tool
    ];
    for cmd in &negatives {
        assert!(!is_cc_command(cmd), "should not match: {cmd}");
    }
}
