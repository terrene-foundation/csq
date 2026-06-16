//! Integration test — PR-C0 / OPEN-C03 follow-up.
//!
//! The handle-dir model for `Surface::Codex` links `term-<pid>/sessions →
//! config-<N>/codex-sessions/` so that transcript rollouts persist across
//! handle-dir churn. The daemon sweep (`sweep_dead_handles`) removes dead
//! `term-<pid>/` dirs; these tests assert the sweep unlinks the symlink
//! WITHOUT walking into the target (which would delete the user's persisted
//! Codex history).
//!
//! Journal 0006 already proved the basic case via the existing image-cache
//! regression test (`csq-core/src/session/handle_dir.rs:sweep_handles_image_cache_symlink`).
//! This file covers the Codex-specific edge cases identified in the journal's
//! "Decision impact" section:
//!
//! - Broken symlink (target already deleted at sweep time)
//! - Symlink-to-symlink chain (two-hop resolution)
//! - Codex-filename context (exercises the exact `sessions/` name the spec
//!   mandates, not the generic image-cache case)

#![cfg(unix)]

use csq_core::session::handle_dir::sweep_dead_handles;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

/// Plant a dead handle-dir `term-999990` in `base` whose `sessions` entry is
/// a symlink to `codex_sessions`. The handle-dir's `.live-pid` marker points
/// at PID 999_990 which is never alive.
fn setup_dead_handle_with_sessions_symlink(
    base: &std::path::Path,
    codex_sessions: &std::path::Path,
) -> std::path::PathBuf {
    let dead = base.join("term-999990");
    fs::create_dir_all(&dead).unwrap();
    symlink(codex_sessions, dead.join("sessions")).unwrap();
    fs::write(dead.join(".live-pid"), "999990").unwrap();
    dead
}

/// Sweep-safe: a Codex-style `sessions` symlink inside a dead handle dir is
/// unlinked, but the real `codex_sessions/` directory — and its contents —
/// survive.
#[test]
fn sweep_unlinks_codex_sessions_symlink_without_walking_target() {
    // Arrange
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let claude_home = base.join(".claude");
    fs::create_dir_all(&claude_home).unwrap();

    // The persistent Codex sessions directory (lives in config-<N>/).
    let config_n = base.join("config-5");
    let codex_sessions = config_n.join("codex-sessions");
    fs::create_dir_all(&codex_sessions).unwrap();
    let sentinel = codex_sessions.join("rollout-2100-01-01.jsonl");
    fs::write(&sentinel, b"PERSISTED_TRANSCRIPT_MUST_SURVIVE").unwrap();

    // The dead handle-dir with a `sessions` symlink into codex_sessions.
    let dead = setup_dead_handle_with_sessions_symlink(base, &codex_sessions);

    // Act
    let removed = sweep_dead_handles(base, Some(&claude_home));

    // Assert
    assert_eq!(removed, 1);
    assert!(!dead.exists(), "dead handle dir should be swept");
    assert!(
        codex_sessions.exists(),
        "persistent codex_sessions dir must survive the sweep"
    );
    assert!(
        sentinel.exists(),
        "persistent transcript file must survive the sweep"
    );
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"PERSISTED_TRANSCRIPT_MUST_SURVIVE",
        "persisted transcript contents must not be mutated"
    );
}

/// Broken symlink (target deleted before sweep) does not panic or fail the
/// sweep; the dead handle dir is still removed and no error is propagated.
#[test]
fn sweep_tolerates_broken_codex_sessions_symlink() {
    // Arrange
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let claude_home = base.join(".claude");
    fs::create_dir_all(&claude_home).unwrap();

    // Create target, symlink to it, then DELETE the target before sweep.
    let config_n = base.join("config-6");
    let codex_sessions = config_n.join("codex-sessions");
    fs::create_dir_all(&codex_sessions).unwrap();
    let dead = setup_dead_handle_with_sessions_symlink(base, &codex_sessions);

    // Delete the target — the symlink inside `dead` now dangles.
    fs::remove_dir_all(&codex_sessions).unwrap();
    assert!(!codex_sessions.exists());
    // The dangling symlink still exists as a link itself, though
    // `symlink_metadata` will work and `metadata` will not.
    assert!(dead.join("sessions").symlink_metadata().is_ok());
    assert!(dead.join("sessions").metadata().is_err());

    // Act
    let removed = sweep_dead_handles(base, Some(&claude_home));

    // Assert
    assert_eq!(removed, 1);
    assert!(!dead.exists(), "dead handle dir should be swept");
}

/// Symlink chain (`sessions → intermediate → codex_sessions`) still does not
/// walk to the terminal target — the sweep unlinks only the first hop.
#[test]
fn sweep_does_not_walk_symlink_chain() {
    // Arrange
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let claude_home = base.join(".claude");
    fs::create_dir_all(&claude_home).unwrap();

    // The persistent target.
    let config_n = base.join("config-7");
    let codex_sessions = config_n.join("codex-sessions");
    fs::create_dir_all(&codex_sessions).unwrap();
    let sentinel = codex_sessions.join("chain-sentinel.jsonl");
    fs::write(&sentinel, b"TERMINAL_TARGET_MUST_SURVIVE").unwrap();

    // Intermediate symlink.
    let intermediate = base.join("config-7").join("codex-sessions-alias");
    symlink(&codex_sessions, &intermediate).unwrap();

    // Dead handle-dir whose `sessions` points at the intermediate.
    let dead = base.join("term-999991");
    fs::create_dir_all(&dead).unwrap();
    symlink(&intermediate, dead.join("sessions")).unwrap();
    fs::write(dead.join(".live-pid"), "999991").unwrap();

    // Act
    let removed = sweep_dead_handles(base, Some(&claude_home));

    // Assert
    assert_eq!(removed, 1);
    assert!(!dead.exists(), "dead handle dir should be swept");
    assert!(intermediate.exists(), "intermediate symlink must survive");
    assert!(
        codex_sessions.exists(),
        "terminal target directory must survive"
    );
    assert!(sentinel.exists(), "terminal target contents must survive");
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"TERMINAL_TARGET_MUST_SURVIVE"
    );
}

/// Sweep processes a handle-dir whose `sessions` symlink points OUTSIDE the
/// base dir — the external target must survive. This exercises the defence
/// against a scenario where a user has (or a misconfiguration creates) a
/// handle-dir sessions pointer at e.g. `~/.codex/sessions/` directly.
#[test]
fn sweep_does_not_delete_external_symlink_target() {
    // Arrange
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let claude_home = base.join(".claude");
    fs::create_dir_all(&claude_home).unwrap();

    // An "external" target living outside `base` (simulated: sibling TempDir).
    let external = TempDir::new().unwrap();
    let external_sessions = external.path().join("user-codex-sessions");
    fs::create_dir_all(&external_sessions).unwrap();
    let sentinel = external_sessions.join("user-data.jsonl");
    fs::write(&sentinel, b"EXTERNAL_DATA_MUST_SURVIVE").unwrap();

    let dead = setup_dead_handle_with_sessions_symlink(base, &external_sessions);

    // Act
    let removed = sweep_dead_handles(base, Some(&claude_home));

    // Assert
    assert_eq!(removed, 1);
    assert!(!dead.exists(), "dead handle dir should be swept");
    assert!(
        external_sessions.exists(),
        "external symlink target must survive"
    );
    assert!(sentinel.exists(), "external user data must survive");
    assert_eq!(fs::read(&sentinel).unwrap(), b"EXTERNAL_DATA_MUST_SURVIVE");
}
