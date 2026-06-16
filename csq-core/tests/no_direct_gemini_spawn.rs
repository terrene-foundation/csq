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
//! `spawn_gemini` so the env_clear + allowlist + .env scan +
//! settings drift reassertion + RLIMIT_CORE pre-exec all fire as a
//! unit. A bare `Command::new("gemini")` skips every one of those
//! defences. This test is the structural enforcement. (Earlier
//! revisions framed the settings drift step as the "EP1 drift
//! detector" of a 7-layer ToS guard — that framing was retracted
//! in journal 0048.)
//!
//! # Why not a clippy lint
//!
//! Clippy can't reason about string-literal arguments to
//! `Command::new`. A custom lint via `dylint` would work but adds a
//! build-time dependency for one rule. A grep test is shorter,
//! faster, and lives in the same repo as the rule.

use std::path::Path;

/// Files where direct `Command::new("gemini")` invocations are
/// allowed because they run their own well-defined defense pipeline:
///
/// - `spawn.rs` — CC-session spawn pipeline (env_clear + allowlist +
///   .env scan + settings drift reassertion + RLIMIT_CORE pre-exec).
/// - `oauth_login.rs` — Code Assist OAuth login shell-out (Stage 2 of
///   journal 0048). Different security posture from a CC-session
///   spawn: inherits the user's env so their default browser opens,
///   no .env scan (not a CC session), no settings drift (no handle
///   dir). Defense is "delegate to reference client" — gemini-cli
///   owns the OAuth flow, csq just spawns it and waits.
const SANCTIONED_FILES: &[&str] = &[
    "csq-core/src/providers/gemini/spawn.rs",
    "csq-core/src/providers/gemini/oauth_login.rs",
];
/// Both forms of "spawn the gemini binary" must be banned outside the
/// sanctioned files. The literal-string form is the obvious one; the
/// constant form is what real callers use (per the existing sanctioned
/// sites — both spawn.rs:execute_plan and oauth_login::perform invoke
/// `Command::new(GEMINI_CLI_BINARY)`). A redteam round-1 finding
/// (security + intermediate review, both CRITICAL) noted that the
/// single-pattern form would not catch the constant form, defeating
/// the lint.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "Command::new(\"gemini\")",
    "Command::new(GEMINI_CLI_BINARY)",
];

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
            // Skip any sanctioned file.
            if SANCTIONED_FILES.iter().any(|s| rel_path == Path::new(s)) {
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
                for pat in FORBIDDEN_PATTERNS {
                    if line.contains(pat) {
                        violations.push(format!(
                            "{}:{}: {}",
                            rel_path.display(),
                            lineno + 1,
                            line.trim()
                        ));
                    }
                }
            }
        },
    );

    assert!(
        violations.is_empty(),
        "Direct Command::new(\"gemini\") or Command::new(GEMINI_CLI_BINARY) found outside\n\
         sanctioned files {SANCTIONED_FILES:?}.\n\
         CC-session spawns MUST go through providers::gemini::spawn::spawn_gemini so\n\
         env_clear + allowlist + .env scan + settings drift reassertion all fire as a\n\
         unit. OAuth login spawns live in providers::gemini::oauth_login::perform.\n\
         Any other gemini-cli invocation is a review failure.\n\n\
         Violations:\n  {}",
        violations.join("\n  ")
    );
}

/// Positive test: the lint actually fires on a synthesized violator.
/// Without this, a regression that breaks the matcher (e.g., the
/// pattern array becomes empty) would silently pass with zero
/// violations forever. This test injects content into the same scanner
/// and asserts the violation IS detected — defense in depth against
/// the round-1 finding "lint test asserts only the negative."
#[test]
fn lint_actually_fires_on_synthesized_violator() {
    let content_literal = "let mut cmd = Command::new(\"gemini\");\ncmd.arg(\"foo\");";
    let content_const = "let mut cmd = Command::new(GEMINI_CLI_BINARY);\ncmd.arg(\"bar\");";
    let content_clean = "let s = \"this string mentions Command::new but no gemini\";\n";

    let mut hits: Vec<String> = Vec::new();
    for (label, content) in [
        ("violator-literal", content_literal),
        ("violator-const", content_const),
        ("clean", content_clean),
    ] {
        for (lineno, line) in content.lines().enumerate() {
            for pat in FORBIDDEN_PATTERNS {
                if line.contains(pat) {
                    hits.push(format!("{}:{}: {}", label, lineno + 1, line.trim()));
                }
            }
        }
    }
    assert_eq!(
        hits.len(),
        2,
        "expected exactly 2 hits (literal + const), got: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.starts_with("violator-literal:")),
        "literal form must be detected: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.starts_with("violator-const:")),
        "constant form must be detected: {hits:?}"
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
