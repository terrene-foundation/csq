//! R2-LOW-2 — Cross-process serialization of `profiles.json` writes.
//!
//! Two subprocesses each acquire `ProfilesFileLock` and call
//! `profiles::add_identity_mapping` concurrently (one waits for the lock while
//! the other holds it). After both complete, `profiles.json` MUST contain
//! both rows — no lost-update.
//!
//! # Subprocess protocol
//!
//! The test binary detects `PROFILES_LOCK_SUBPROCESS_MODE=1` in its env and
//! runs as a writer helper instead of a test. The helper:
//!   1. Acquires `ProfilesFileLock` on the base dir.
//!   2. Calls `profiles::add_identity_mapping`.
//!   3. Exits 0 on success, 1 on error.
//!
//! The parent test spawns two such subprocesses simultaneously and waits for
//! both to finish.

use csq_core::accounts::identity_store::IdentityId;
use csq_core::accounts::profiles;
use csq_core::accounts::profiles_lock::ProfilesFileLock;
use std::process::Command;
use tempfile::TempDir;

// ── Subprocess mode ───────────────────────────────────────────────────────

/// Entry point invoked by subprocess instances. Reads env vars to know which
/// slot/email/uuid to write, acquires the lock, and calls add_identity_mapping.
///
/// Env vars:
///   PROFILES_LOCK_SUBPROCESS_MODE=1
///   SUBPROCESS_BASE_DIR=<path>
///   SUBPROCESS_SLOT=<u16>
///   SUBPROCESS_EMAIL=<str>
///   SUBPROCESS_UUID=<uuid str>
fn maybe_run_as_subprocess() -> Option<()> {
    if std::env::var("PROFILES_LOCK_SUBPROCESS_MODE").as_deref() != Ok("1") {
        return None;
    }

    let base_dir = std::env::var("SUBPROCESS_BASE_DIR").expect("SUBPROCESS_BASE_DIR required");
    let base_dir = std::path::PathBuf::from(&base_dir);
    let slot: u16 = std::env::var("SUBPROCESS_SLOT")
        .expect("SUBPROCESS_SLOT required")
        .parse()
        .expect("SUBPROCESS_SLOT must be u16");
    let email = std::env::var("SUBPROCESS_EMAIL").expect("SUBPROCESS_EMAIL required");
    let uuid_str = std::env::var("SUBPROCESS_UUID").expect("SUBPROCESS_UUID required");
    let uuid: IdentityId = uuid_str
        .parse()
        .expect("SUBPROCESS_UUID must be a valid uuid");

    let lock = ProfilesFileLock::acquire(&base_dir).expect("acquire lock");
    profiles::add_identity_mapping(&lock, &base_dir, slot, &email, uuid)
        .expect("add_identity_mapping must succeed");

    eprintln!("[subprocess slot={slot}] wrote mapping {email} -> {uuid}");
    std::process::exit(0);
}

// ── Clean subprocess command helper ───────────────────────────────────────

/// Spawns the test binary in subprocess mode. Follows testing.md Rule 4a:
/// env_clear() + stdlib whitelist + only the explicitly required vars.
fn spawn_writer(
    base_dir: &std::path::Path,
    slot: u16,
    email: &str,
    uuid: IdentityId,
) -> std::process::Child {
    let exe = std::env::current_exe().expect("current_exe must be resolvable");
    let mut cmd = Command::new(&exe);
    cmd.env_clear();

    // Re-inject stdlib whitelist per testing.md Rule 4a.
    for k in ["HOME", "PATH", "LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }

    // Subprocess protocol env vars.
    cmd.env("PROFILES_LOCK_SUBPROCESS_MODE", "1");
    cmd.env("SUBPROCESS_BASE_DIR", base_dir);
    cmd.env("SUBPROCESS_SLOT", slot.to_string());
    cmd.env("SUBPROCESS_EMAIL", email);
    cmd.env("SUBPROCESS_UUID", uuid.to_string());

    // Pass --test-threads=1 to avoid the subprocess re-running all tests.
    // The subprocess will detect mode=1 early and exit before any test runs.
    cmd.arg("--test-threads=1");

    cmd.spawn().expect("subprocess spawn must succeed")
}

// ── Test ──────────────────────────────────────────────────────────────────

/// Checks for subprocess mode at startup, before any test framework code runs.
/// Called from the first test that needs it; harmless no-op if not in subprocess mode.
fn ensure_subprocess_checked() {
    // If we're running as a subprocess writer, execute and exit.
    if maybe_run_as_subprocess().is_some() {
        // Never reached — maybe_run_as_subprocess() calls process::exit
        unreachable!()
    }
}

#[cfg(unix)]
#[test]
fn profiles_lock_cross_process_both_rows_survive() {
    // Ensure subprocess mode is handled before test logic.
    ensure_subprocess_checked();

    // Arrange: fresh base dir with profiles.json absent.
    let dir = TempDir::new().unwrap();
    let base = dir.path().to_path_buf();
    // Create the accounts directory structure.
    std::fs::create_dir_all(&base).unwrap();

    let uuid1 = IdentityId::new_v4();
    let uuid2 = IdentityId::new_v4();

    // Act: spawn both writers simultaneously — they race on the lock.
    // The first to acquire writes, the second blocks until the first releases.
    let mut child1 = spawn_writer(&base, 1, "alice@example.com", uuid1);
    let mut child2 = spawn_writer(&base, 2, "bob@example.com", uuid2);

    let status1 = child1.wait().expect("child1 must exit");
    let status2 = child2.wait().expect("child2 must exit");

    // Assert: both subprocesses succeeded.
    assert!(
        status1.success(),
        "subprocess 1 (alice) must exit 0; got {:?}",
        status1
    );
    assert!(
        status2.success(),
        "subprocess 2 (bob) must exit 0; got {:?}",
        status2
    );

    // Assert: profiles.json contains BOTH rows — no lost-update.
    let profiles_path = profiles::profiles_path(&base);
    let loaded = profiles::load(&profiles_path).expect("profiles.json must load");

    assert!(
        loaded.by_email.contains_key("alice@example.com"),
        "alice@example.com must be in by_email after concurrent writes; got: {:?}",
        loaded.by_email.keys().collect::<Vec<_>>()
    );
    assert!(
        loaded.by_email.contains_key("bob@example.com"),
        "bob@example.com must be in by_email after concurrent writes; got: {:?}",
        loaded.by_email.keys().collect::<Vec<_>>()
    );
    assert!(
        loaded.by_slot.contains_key("1"),
        "slot 1 must be in by_slot; got: {:?}",
        loaded.by_slot.keys().collect::<Vec<_>>()
    );
    assert!(
        loaded.by_slot.contains_key("2"),
        "slot 2 must be in by_slot; got: {:?}",
        loaded.by_slot.keys().collect::<Vec<_>>()
    );

    // Assert: the UUID values are the correct ones (no UUID churn / mix-up).
    assert_eq!(
        loaded.by_email["alice@example.com"], uuid1,
        "alice's uuid must match uuid1"
    );
    assert_eq!(
        loaded.by_email["bob@example.com"], uuid2,
        "bob's uuid must match uuid2"
    );
}
