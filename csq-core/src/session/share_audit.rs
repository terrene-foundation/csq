//! Detects handle-dir state that SHOULD be shared across terminals but is not.
//!
//! # The failure this exists to catch
//!
//! A handle dir is provisioned from an ALLOWLIST of items to symlink back to
//! `config-N`. Anything not on that list becomes a real file inside `term-<pid>` and is
//! destroyed with the handle dir. The default is therefore per-terminal, and the list is
//! maintained by hand against an upstream CLI nobody here controls.
//!
//! That list goes stale by construction. ClaudeCode's grew to 35 entries — every one
//! added AFTER a feature broke, which is what a reactive list looks like. Codex's stayed
//! at five and missed `state_<N>.sqlite`, where codex-cli keeps conversation NAMES: on a
//! maintainer host 2026-08-19, three live handle dirs held 35M + 35M + 7.1M of separate
//! metadata, so a thread named in one terminal read as unnamed in the next.
//!
//! Fixing that instance does not close the class. The next capability an upstream CLI
//! adds is unshared again, silently, and the first symptom is a user noticing something
//! they cannot name. **This module is the detector: it does not know what the CLI will
//! add, but it can see that a real file appeared where a symlink was expected.**
//!
//! # Why a positive allowlist
//!
//! The check is inverted relative to provisioning: everything in a handle dir is
//! expected to be a SYMLINK, except a small, enumerable set that is deliberately
//! per-terminal. A denylist of known-bad names would have to predict what the CLI adds,
//! which is the assumption that failed in the first place
//! (`cc-artifact-construction.md` Rule 10).

use std::path::{Path, PathBuf};

/// Entries that are LEGITIMATELY per-terminal and must not be reported.
///
/// A POSITIVE allowlist, and every entry is justified from the code that writes it — not
/// from a guess about what looks unimportant. A detector that cries wolf is one operators
/// learn to override (`tooling-self-verification.md` Rule 5), and this one reports on a
/// surface where most entries are legitimately real.
///
/// - `log` / `logs` / `tmp` — codex-cli's per-session log and scratch dirs; the sweeper
///   removes them with the handle dir.
/// - `settings.json` — materialized as a real file ON PURPOSE by
///   `materialize_handle_settings`, which deep-merges per-slot config. A symlink here
///   would leak one slot's merged settings into every other.
/// - `.claude.json` — same, via `materialize_handle_claude_json`.
/// - `.live-pid` / `.live-cc-pid` — per-handle liveness sentinels; the logout guard and
///   the orphan GC both read them to decide whether a handle is alive. Sharing them
///   would make every terminal claim one PID.
/// - `.swap-lock` / `.swap.lock` — the two distinct swap locks. A lock shared across
///   terminals is not a lock.
/// - `.last-cleanup` / `.last-update-result.json` — per-terminal bookkeeping written by
///   the upstream CLI; nothing reads them across terminals.
/// - `.csq*` — csq's own per-handle markers.
/// - `*.swap-tmp` — the atomic swap's staging name, transient by construction.
const EXPECTED_PER_TERMINAL: &[&str] = &[
    "log",
    "logs",
    "tmp",
    "settings.json",
    ".claude.json",
    ".live-pid",
    ".live-cc-pid",
    ".swap-lock",
    ".swap.lock",
    ".last-cleanup",
    ".last-update-result.json",
];

/// One handle-dir entry that is real state where a share was expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsharedEntry {
    /// The handle dir holding it, e.g. `term-49305`.
    pub handle_dir: String,
    /// The entry's name within that handle dir, e.g. `state_5.sqlite`.
    pub name: String,
    /// Bytes it occupies. State that is merely large is not necessarily important, but
    /// size is what makes a silent split legible in a report.
    pub bytes: u64,
}

/// Whether `name` is deliberately per-terminal.
fn is_expected_per_terminal(name: &str) -> bool {
    if EXPECTED_PER_TERMINAL.contains(&name) {
        return true;
    }
    // csq's own per-handle bookkeeping, and the atomic swap's staging name.
    name.starts_with(".csq") || name.ends_with(".swap-tmp")
}

/// Recursive size of `p`, or its own length when it is a file.
///
/// Best-effort: an unreadable subtree contributes what was readable rather than failing
/// the audit. A size is context for a human, never the verdict — the verdict is that the
/// entry is real at all.
fn size_of(p: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    if !meta.is_dir() {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(p) else {
        return 0;
    };
    entries.flatten().map(|e| size_of(&e.path())).sum()
}

/// Audit every handle dir under `accounts_dir` for state that is not shared.
///
/// Returns entries that are REAL files or directories where a symlink into `config-N`
/// was expected. An empty result means every handle dir holds only symlinks plus the
/// deliberately-ephemeral set.
///
/// Symlinks are never reported — including a BROKEN one. A dangling link is a different
/// defect (a target that moved), and conflating the two would make this report say two
/// things at once.
#[must_use]
pub fn unshared_handle_dir_state(accounts_dir: &Path) -> Vec<UnsharedEntry> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(accounts_dir) else {
        return found;
    };

    for entry in entries.flatten() {
        let handle = entry.path();
        let Some(handle_name) = handle.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !handle_name.starts_with("term-") {
            continue;
        }
        let Ok(inner) = std::fs::read_dir(&handle) else {
            continue;
        };
        for item in inner.flatten() {
            let path = item.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if is_expected_per_terminal(name) {
                continue;
            }
            // A symlink is shared by definition — that is the whole mechanism.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            found.push(UnsharedEntry {
                handle_dir: handle_name.to_string(),
                name: name.to_string(),
                bytes: size_of(&path),
            });
        }
    }
    found.sort_by(|a, b| {
        a.handle_dir
            .cmp(&b.handle_dir)
            .then_with(|| a.name.cmp(&b.name))
    });
    found
}

/// The same audit, reported as one line per distinct entry NAME across handle dirs.
///
/// A split shows up as the same name in several handle dirs, so grouping by name is what
/// makes "three terminals each hold their own `state_5.sqlite`" legible rather than three
/// unrelated-looking rows.
#[must_use]
pub fn unshared_state_by_name(accounts_dir: &Path) -> Vec<(String, Vec<UnsharedEntry>)> {
    let mut by_name: std::collections::BTreeMap<String, Vec<UnsharedEntry>> =
        std::collections::BTreeMap::new();
    for e in unshared_handle_dir_state(accounts_dir) {
        by_name.entry(e.name.clone()).or_default().push(e);
    }
    by_name.into_iter().collect()
}

/// Convenience: the accounts dir under a csq base.
#[must_use]
pub fn accounts_dir(base: &Path) -> PathBuf {
    base.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a handle dir with `symlinked` pointing into config-N and `real` as files.
    fn handle(base: &Path, name: &str, symlinked: &[&str], real: &[&str]) {
        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for s in symlinked {
            let target = config.join(s);
            std::fs::write(&target, b"x").unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, dir.join(s)).unwrap();
        }
        for r in real {
            std::fs::write(dir.join(r), b"realstate").unwrap();
        }
    }

    #[test]
    fn a_fully_symlinked_handle_dir_is_clean() {
        let t = TempDir::new().unwrap();
        handle(t.path(), "term-1", &["sessions", "auth.json"], &[]);
        assert!(unshared_handle_dir_state(t.path()).is_empty());
    }

    /// The reported bug: real state where a share was expected.
    #[test]
    fn a_real_state_file_is_reported() {
        let t = TempDir::new().unwrap();
        handle(t.path(), "term-1", &["sessions"], &["state_5.sqlite"]);
        let found = unshared_handle_dir_state(t.path());
        assert_eq!(found.len(), 1, "got {found:?}");
        assert_eq!(found[0].name, "state_5.sqlite");
        assert_eq!(found[0].handle_dir, "term-1");
        assert!(found[0].bytes > 0);
    }

    /// The detector must not depend on the file's NAME — that is the whole point. A
    /// capability nobody has written yet is caught because it is REAL, not because it
    /// was predicted.
    #[test]
    fn an_unknown_future_state_file_is_reported_too() {
        let t = TempDir::new().unwrap();
        handle(
            t.path(),
            "term-1",
            &[],
            &["something_nobody_has_added_yet.db"],
        );
        let found = unshared_handle_dir_state(t.path());
        assert_eq!(found.len(), 1, "an unpredicted name must still be caught");
    }

    #[test]
    fn deliberately_ephemeral_entries_are_not_reported() {
        let t = TempDir::new().unwrap();
        let dir = t.path().join("term-1");
        std::fs::create_dir_all(dir.join("log")).unwrap();
        std::fs::write(dir.join(".csq-account"), b"1").unwrap();
        std::fs::write(dir.join("sessions.swap-tmp"), b"x").unwrap();
        // Materialized-on-purpose real files, and the liveness/lock markers.
        std::fs::write(dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(dir.join(".claude.json"), b"{}").unwrap();
        std::fs::write(dir.join(".live-pid"), b"1").unwrap();
        std::fs::write(dir.join(".swap-lock"), b"").unwrap();
        assert!(
            unshared_handle_dir_state(t.path()).is_empty(),
            "log/, .csq-*, and *.swap-tmp are per-terminal by design"
        );
    }

    /// The shape that makes a split legible: one name, several terminals.
    #[test]
    fn the_same_name_across_terminals_groups_into_one_finding() {
        let t = TempDir::new().unwrap();
        handle(t.path(), "term-1", &[], &["state_5.sqlite"]);
        handle(t.path(), "term-2", &[], &["state_5.sqlite"]);
        handle(t.path(), "term-3", &[], &["state_5.sqlite"]);
        let grouped = unshared_state_by_name(t.path());
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].0, "state_5.sqlite");
        assert_eq!(grouped[0].1.len(), 3, "all three terminals must appear");
    }

    #[test]
    fn non_handle_directories_are_ignored() {
        let t = TempDir::new().unwrap();
        std::fs::create_dir_all(t.path().join("config-1")).unwrap();
        std::fs::write(t.path().join("config-1/state_5.sqlite"), b"x").unwrap();
        assert!(
            unshared_handle_dir_state(t.path()).is_empty(),
            "config-N is the SHARE target; real state there is correct"
        );
    }

    /// A broken symlink is a different defect and must not be reported here.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_not_reported_as_unshared() {
        let t = TempDir::new().unwrap();
        let dir = t.path().join("term-1");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(t.path().join("config-1/gone"), dir.join("sessions")).unwrap();
        assert!(
            unshared_handle_dir_state(t.path()).is_empty(),
            "a dangling link is a moved target, not unshared state"
        );
    }
}
