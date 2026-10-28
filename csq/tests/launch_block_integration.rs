//! orgident r7 item 9: new launches into a slot whose sign-in is shared are refused.
//!
//! Every test drives the real `csq` binary against a hermetic base dir whose
//! `refresh-suppressed.json` was produced by the real startup audit (two slots holding
//! one refresh grant). `env_clear()` plus a sandbox HOME keep the operator's keychain and
//! live sessions out of reach (`rules/test-hermeticity.md`).

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use csq_core::accounts::launch_block::{self, fixture};
use tempfile::TempDir;

#[path = "common/mod.rs"]
mod common;
use common::csq_bin;

fn sandbox_home() -> PathBuf {
    static H: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    H.get_or_init(|| TempDir::new().expect("sandbox home"))
        .path()
        .to_path_buf()
}

fn empty_path() -> PathBuf {
    static H: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    H.get_or_init(|| TempDir::new().expect("empty path dir"))
        .path()
        .to_path_buf()
}

fn csq(base: &Path) -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear()
        .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
        .env("HOME", sandbox_home())
        .env("CSQ_HOME", sandbox_home())
        .env("CLAUDE_HOME", sandbox_home())
        .env("CSQ_BASE_DIR", base);
    // An EMPTY PATH: a run that is not refused must fail at "claude not installed", never
    // start a real Claude Code.
    cmd.env("PATH", empty_path());
    for k in ["LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd
}

fn text(o: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// One entry of [`tree`]: what a write of any kind would change.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    /// A directory and its unix mode: a created (even empty) directory or a mode change shows.
    Dir { mode: u32 },
    /// A non-directory, its unix mode, its mtime and its bytes (a symlink's bytes are its target
    /// and its mtime the link's own): a same-bytes rewrite of any file shows through the mtime.
    /// Only the mtime is recorded; atime and ctime move on reads and metadata-only events.
    File {
        mode: u32,
        mtime: std::time::SystemTime,
        bytes: Vec<u8>,
    },
}

/// Every directory and every non-directory under `root`, with its unix mode and (for a
/// non-directory) its mtime and bytes: a created file or directory, a content change, a
/// same-bytes rewrite, or a permission change makes the map differ.
fn tree(root: &Path) -> BTreeMap<PathBuf, Node> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, Node>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let mode = meta.permissions().mode();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            if meta.is_dir() {
                out.insert(rel, Node::Dir { mode });
                walk(&path, root, out);
            } else {
                let bytes = if meta.file_type().is_symlink() {
                    std::fs::read_link(&path)
                        .unwrap()
                        .into_os_string()
                        .into_encoded_bytes()
                } else {
                    std::fs::read(&path).unwrap()
                };
                let mtime = meta.modified().unwrap();
                out.insert(rel, Node::File { mode, mtime, bytes });
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// The update-check stamp's mtime: the seed below relies on the background update check
/// leaving a fresh stamp alone, so every refused verb asserts that it did.
fn update_stamp_mtime(base: &Path) -> std::time::SystemTime {
    std::fs::metadata(base.join(".csq-update-check"))
        .and_then(|m| m.modified())
        .expect("seeded update-check stamp")
}

fn seeded() -> TempDir {
    let base = TempDir::new().unwrap();
    fixture::seed_shared_grant(base.path(), 1, 2);
    // Seed a FRESH update-check stamp. `run`/`exec`/`swap` pass through the CLI
    // entry, which spawns the background update check, and a stale cache makes that
    // thread touch `.csq-update-check` BEFORE dispatch by design (update/mod.rs
    // writes the backoff stamp before the network call so a rate-limited GitHub
    // cannot keep the cache stale forever). That stamp is an always-on startup
    // write, not a launch side effect; seeding it fresh (mtime within the 24h TTL,
    // empty contents — the same shape csq/tests/fixtures/mcp_image_doctor_live.rs
    // uses) keeps the "a refused <verb> writes nothing" assertions about the
    // launch path itself.
    std::fs::File::create(base.path().join(".csq-update-check")).unwrap();
    base
}

/// Non-vacuity of [`tree`] for the "writes nothing" assertions: a same-bytes, same-mode rewrite
/// of a seeded file (not only the update stamp) must make the snapshot differ.
/// Falsifier: a `Node::File` without the mtime compares equal after this rewrite.
#[test]
fn tree_sees_a_same_bytes_rewrite_of_any_seeded_file() {
    let base = seeded();
    let before = tree(base.path());
    let (rel, path) = before
        .iter()
        .find_map(|(rel, node)| {
            let path = base.path().join(rel);
            (matches!(node, Node::File { .. })
                && rel != Path::new(".csq-update-check")
                && !std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink())
            .then(|| (rel.clone(), path))
        })
        .expect("fixture: the seed holds a regular file besides the update stamp");
    let bytes = std::fs::read(&path).unwrap();
    let old_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::fs::write(&path, &bytes).unwrap();
    // Pin the new mtime one hour away from the old one, so the rewrite is visible whatever the
    // filesystem's timestamp granularity.
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(old_mtime + std::time::Duration::from_secs(3600))
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "fixture: same bytes");
    let after = tree(base.path());
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>(),
        "fixture: no entry created or removed"
    );
    assert_ne!(
        after.get(&rel),
        before.get(&rel),
        "a same-bytes rewrite of {} must show in the snapshot",
        rel.display()
    );
}

#[test]
fn run_refuses_a_suppressed_slot_before_any_launch_side_effect() {
    let base = seeded();
    let before = tree(base.path());
    let stamp = update_stamp_mtime(base.path());
    let out = csq(base.path()).args(["run", "2"]).output().unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "run must fail: {said}");
    assert!(said.contains(&launch_block::refusal_message(2)), "{said}");
    assert!(
        !base.path().join(".csq-launch.log").exists(),
        "a refused launch must not reach the launch log"
    );
    assert_eq!(tree(base.path()), before, "a refused run writes nothing");
    assert_eq!(
        update_stamp_mtime(base.path()),
        stamp,
        "a refused run leaves the update-check stamp untouched"
    );
}

#[test]
fn run_is_not_refused_for_the_holder_slot() {
    let base = seeded();
    let out = csq(base.path()).args(["run", "1"]).output().unwrap();
    let said = text(&out);
    assert!(
        !said.contains("shares its sign-in"),
        "the holder keeps the grant and may launch: {said}"
    );
}

#[test]
fn swap_refuses_a_suppressed_slot_before_any_credential_or_marker_write() {
    let base = seeded();
    let before = tree(base.path());
    let stamp = update_stamp_mtime(base.path());
    let out = csq(base.path()).args(["swap", "2"]).output().unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "swap must fail: {said}");
    assert!(said.contains(&launch_block::refusal_message(2)), "{said}");
    assert!(!base.path().join(".csq-launch.log").exists(), "{said}");
    assert_eq!(tree(base.path()), before, "a refused swap writes nothing");
    assert_eq!(
        update_stamp_mtime(base.path()),
        stamp,
        "a refused swap leaves the update-check stamp untouched"
    );
}

#[test]
fn run_and_swap_stop_refusing_once_login_clears_the_suppression() {
    let base = seeded();
    fixture::simulate_login(base.path(), 2);
    for args in [["run", "2"], ["swap", "2"]] {
        let out = csq(base.path()).args(args).output().unwrap();
        let said = text(&out);
        assert!(
            !said.contains("shares its sign-in"),
            "{args:?} must not be refused after the login: {said}"
        );
    }
}

fn terminal_on_slot(base: &Path, slot: u16) -> PathBuf {
    let handle = base.join("term-424242");
    std::fs::create_dir_all(&handle).unwrap();
    std::fs::write(handle.join(".csq-account"), slot.to_string()).unwrap();
    handle
}

#[test]
fn statusline_of_a_terminal_on_a_suppressed_slot_shows_the_fixed_warning() {
    let base = seeded();
    let handle = terminal_on_slot(base.path(), 2);
    let out = csq(base.path())
        .arg("statusline")
        .env("CLAUDE_CONFIG_DIR", &handle)
        .output()
        .unwrap();
    let said = text(&out);
    assert!(said.contains(&launch_block::status_warning(2)), "{said}");
}

#[test]
fn statusline_of_the_holder_and_of_a_cleared_slot_shows_no_warning() {
    let base = seeded();
    let holder = terminal_on_slot(base.path(), 1);
    let out = csq(base.path())
        .arg("statusline")
        .env("CLAUDE_CONFIG_DIR", &holder)
        .output()
        .unwrap();
    assert!(!text(&out).contains("sign-in shared"), "{}", text(&out));

    fixture::simulate_login(base.path(), 2);
    let cleared = terminal_on_slot(base.path(), 2);
    let out = csq(base.path())
        .arg("statusline")
        .env("CLAUDE_CONFIG_DIR", &cleared)
        .output()
        .unwrap();
    assert!(!text(&out).contains("sign-in shared"), "{}", text(&out));
}

// ── csq exec (the other path that starts a fresh Claude Code) ────────────────

#[test]
fn exec_refuses_a_suppressed_slot_before_any_handle_dir_or_spawn() {
    let base = seeded();
    let before = tree(base.path());
    let stamp = update_stamp_mtime(base.path());
    let out = csq(base.path())
        .args(["exec", "--slot", "2", "hello"])
        .output()
        .unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "exec must fail: {said}");
    assert!(said.contains(&launch_block::refusal_message(2)), "{said}");
    assert_eq!(tree(base.path()), before, "a refused exec writes nothing");
    assert_eq!(
        update_stamp_mtime(base.path()),
        stamp,
        "a refused exec leaves the update-check stamp untouched"
    );
}

#[test]
fn exec_by_provider_never_auto_picks_a_refused_slot() {
    let base = seeded();
    let out = csq(base.path())
        .args(["exec", "--provider", "claude", "hello"])
        .output()
        .unwrap();
    let said = text(&out);
    assert!(
        !said.contains("shares its sign-in"),
        "the holder slot is the eligible pick: {said}"
    );

    fixture::destroy_suppression_state(base.path());
    let out = csq(base.path())
        .args(["exec", "--provider", "claude", "hello"])
        .output()
        .unwrap();
    assert!(
        text(&out).contains(&launch_block::damaged_message()),
        "every Anthropic slot refused while the record is unknown: {}",
        text(&out)
    );
}

#[test]
fn exec_stops_refusing_once_login_clears_the_suppression() {
    let base = seeded();
    fixture::simulate_login(base.path(), 2);
    let out = csq(base.path())
        .args(["exec", "--slot", "2", "hello"])
        .output()
        .unwrap();
    assert!(!text(&out).contains("shares its sign-in"), "{}", text(&out));
}

// ── fail-closed while the suppression record is unknown ─────────────────────

#[test]
fn run_and_swap_refuse_every_anthropic_slot_while_the_record_is_unknown_then_per_slot_login() {
    let base = seeded();
    fixture::bind(base.path(), 3, "launch-block-distinct-three");
    fixture::destroy_suppression_state(base.path());
    let damaged = launch_block::damaged_message();
    for args in [["run", "3"], ["swap", "3"], ["run", "1"]] {
        let out = csq(base.path()).args(args).output().unwrap();
        assert!(text(&out).contains(&damaged), "{args:?}: {}", text(&out));
    }
    assert_eq!(
        std::fs::read(base.path().join("refresh-suppressed.json")).unwrap(),
        b"garbage",
        "the damaged record is never rewritten or removed"
    );
    // `csq login 2` frees slot 2 only.
    fixture::simulate_login(base.path(), 2);
    let out = csq(base.path()).args(["run", "2"]).output().unwrap();
    assert!(
        !text(&out).contains(&damaged),
        "slot 2 was re-verified: {}",
        text(&out)
    );
    let out = csq(base.path()).args(["run", "3"]).output().unwrap();
    assert!(text(&out).contains(&damaged), "{}", text(&out));
}

#[test]
fn an_absent_record_does_not_block_a_fresh_install() {
    let base = TempDir::new().unwrap();
    fixture::bind(base.path(), 3, "launch-block-distinct-three");
    let out = csq(base.path()).args(["run", "3"]).output().unwrap();
    let said = text(&out);
    assert!(!said.contains(&launch_block::damaged_message()), "{said}");
    assert!(!said.contains("shares its sign-in"), "{said}");
}

#[test]
fn statusline_shows_the_fixed_damaged_warning_for_an_unverified_anthropic_slot() {
    let base = seeded();
    fixture::bind(base.path(), 3, "launch-block-distinct-three");
    fixture::destroy_suppression_state(base.path());
    let handle = terminal_on_slot(base.path(), 3);
    let out = csq(base.path())
        .arg("statusline")
        .env("CLAUDE_CONFIG_DIR", &handle)
        .output()
        .unwrap();
    assert!(
        text(&out).contains(&launch_block::status_damaged()),
        "{}",
        text(&out)
    );
}
