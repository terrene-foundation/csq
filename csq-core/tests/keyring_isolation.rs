//! Keychain-isolation invariant: `keyring::Entry::new` has exactly ONE
//! callsite in workspace source — the `keyring_entry` chokepoint at
//! `csq-core/src/audit/key_custody/mod.rs` — which installs the process-global
//! in-memory mock store under `cfg(test)` / the `test-utils` feature before
//! any entry is created.
//!
//! ## Why this invariant exists
//!
//! Origin: 2026-06-11 keychain prompt-spam incident. Eight test-bearing files
//! transitively reached the OS keyring with the production service name
//! (`csq-audit-signing`) without installing the mock: the `csq` crate's test
//! binaries (swap, audit, desktop commands) could never install it (the helper
//! was gated `#[cfg(test)]` inside csq-core), and five csq-core test modules
//! raced on whether a mock-installing test happened to run first. Every cargo
//! test rebuild produces unsigned test binaries, and each real-keychain access
//! from an unsigned binary triggers a macOS authorization prompt ("unknown")
//! — one per access, spamming the operator.
//!
//! The structural fix is allowlist-shaped (per `cc-artifacts.md` Rule 10):
//! ONE constructor that self-arms the mock, and this scanner flagging any
//! future direct `keyring::Entry::new` callsite — instead of an enumerated
//! list of test modules that each remember to call `init_mock_keyring()`.

use std::fs;
use std::path::{Path, PathBuf};

const NEEDLE: &str = "keyring::Entry::new(";
const CHOKEPOINT_SUFFIX: &str = "csq-core/src/audit/key_custody/mod.rs";

fn collect_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    collect_recursive(root, &mut result);
    result
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // missing optional path — silently skip
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "target" || name_str == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_recursive(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn keyring_entry_new_only_in_chokepoint() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("workspace root");

    let mut offenders: Vec<String> = Vec::new();
    let mut chokepoint_hits = 0usize;

    for src_root in ["csq-core/src", "csq/src"] {
        for file in collect_rs_files(&workspace_root.join(src_root)) {
            let content = match fs::read_to_string(&file) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let hits = content.matches(NEEDLE).count();
            if hits == 0 {
                continue;
            }
            let normalized = file.to_string_lossy().replace('\\', "/");
            if normalized.ends_with(CHOKEPOINT_SUFFIX) {
                chokepoint_hits += hits;
            } else {
                offenders.push(format!("{normalized}: {hits} direct callsite(s)"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "direct `keyring::Entry::new` callsites found outside the \
         `key_custody::keyring_entry` chokepoint — route them through the \
         chokepoint so the test-utils mock keyring covers them (keychain \
         prompt-spam class, 2026-06-11):\n{}",
        offenders.join("\n")
    );
    assert_eq!(
        chokepoint_hits, 1,
        "expected exactly one `keyring::Entry::new` inside the chokepoint \
         (found {chokepoint_hits}) — the wrapper itself must be the sole \
         constructor"
    );
}
