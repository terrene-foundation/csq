//! PR-G2a "lint" gate (per implementation plan §PR-G2a "Lint" line):
//!
//! > Lint: ban direct `Command::new("gemini")` outside `spawn_gemini`
//!
//! Implemented as a workspace-wide grep over `.rs` source files. Any
//! match for `Command::new("gemini")` outside
//! `csq-core/src/providers/gemini/spawn.rs` (the sole sanctioned
//! spawn site) fails the test.
//!
//! # Why this exists
//!
//! Per security review §5 ("argv / env / log / IPC / NDJSON leak
//! inventory"): every gemini-cli invocation MUST go through
//! `spawn_gemini` so the env_clear + allowlist + .env scan + EP1
//! drift detector + RLIMIT_CORE pre-exec all fire as a unit. A bare
//! `Command::new("gemini")` skips every one of those defences. This
//! test is the structural enforcement.
//!
//! # Why not a clippy lint
//!
//! Clippy can't reason about string-literal arguments to
//! `Command::new`. A custom lint via `dylint` would work but adds a
//! build-time dependency for one rule. A grep test is shorter,
//! faster, and lives in the same repo as the rule.

use std::path::Path;

const SANCTIONED_FILE: &str = "csq-core/src/providers/gemini/spawn.rs";
const FORBIDDEN_PATTERN: &str = "Command::new(\"gemini\")";

#[test]
fn no_direct_gemini_command_new_outside_sanctioned_file() {
    // Walk the workspace root from the test binary's working dir.
    // Cargo runs integration tests with CWD = the package root
    // (csq-core/), so go up one level to reach the workspace.
    let workspace_root = std::env::current_dir()
        .expect("cwd")
        .parent()
        .expect("workspace root above csq-core")
        .to_path_buf();

    let mut violations: Vec<String> = Vec::new();
    walk_rs_files(
        &workspace_root,
        &workspace_root,
        &mut |rel_path, content| {
            // Skip the sanctioned file itself.
            if rel_path == Path::new(SANCTIONED_FILE) {
                return;
            }
            // Skip this very test file — its docstring quotes the
            // forbidden pattern by necessity to document it.
            if rel_path.ends_with("no_direct_gemini_spawn.rs") {
                return;
            }
            // Skip target/ build outputs and node_modules/.
            let path_str = rel_path.to_string_lossy();
            if path_str.starts_with("target/")
                || path_str.contains("/target/")
                || path_str.contains("/node_modules/")
                || path_str.contains("/.git/")
            {
                return;
            }
            for (lineno, line) in content.lines().enumerate() {
                if line.contains(FORBIDDEN_PATTERN) {
                    violations.push(format!(
                        "{}:{}: {}",
                        rel_path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        },
    );

    assert!(
        violations.is_empty(),
        "Direct Command::new(\"gemini\") found outside {SANCTIONED_FILE}.\n\
         All gemini-cli spawns MUST go through providers::gemini::spawn::spawn_gemini\n\
         so env_clear + allowlist + .env scan + EP1 drift detector all fire as a unit.\n\n\
         Violations:\n  {}",
        violations.join("\n  ")
    );
}

/// Walks `.rs` files under `root`, calling `cb(relative_path, content)`
/// for each. Avoids hidden dirs (`.git/`, `.cargo/`) and `target/`.
fn walk_rs_files(base: &Path, current: &Path, cb: &mut dyn FnMut(&Path, &str)) {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Skip hidden, target, node_modules.
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_rs_files(base, &path, cb);
        } else if ft.is_file() && name.ends_with(".rs") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                cb(rel, &content);
            }
        }
    }
}
