//! FR-FMT-06 read-only invariant: csq MUST NOT write under `.coc/` from
//! production code paths. Test-fixture writes (inside `#[cfg(test)]` modules
//! or under `tests/`) are EXEMPT — they create synthetic `.coc/` trees in
//! tempdirs to exercise the loader, not the user's working tree.
//!
//! Note on the parse cache: the cache lives at `<workspace_root>/.cache/`
//! — OUTSIDE `.coc/` — per `csq-core/src/coc/integrity.rs::cache_dir`,
//! ratified in PR-CA9 design 08:151 + an internal journal entry §7. `<workspace>/.cache/`
//! is a sibling of `.coc/`, not a subdirectory of it, so cache writes
//! trivially satisfy this read-only invariant without needing a special
//! exemption: no source line that writes the cache mentions `.coc/`.
//! The `CACHE_EXEMPTION` constant below is reserved for the contingency
//! where a future revision relocates the cache inside `.coc/`; if that
//! never lands, the constant becomes safe to delete.
//!
//! Implementation: walk every `.rs` source file under `csq-core/src` and
//! `csq-cli/src`. Track brace depth across `#[cfg(test)]` mod boundaries
//! to skip lines inside them. For lines OUTSIDE `cfg(test)`, reject any
//! `.coc` reference paired with a write API call (unless the
//! `CACHE_EXEMPTION` substring appears on the same line — currently
//! vestigial; see note above).
//!
//! Spec authority: `specs/09-unified-coc-artifact-standard.md` §9.10 +
//! `specs/10-capability-layer-architecture.md` §10.9.4. an internal ticket tracks
//! the spec-text amendment that aligned §10.9.2 + §10.9.4 with the
//! `<workspace_root>/.cache/` implementation.

use std::fs;
use std::path::{Path, PathBuf};

const WRITE_APIS: &[&str] = &[
    "fs::write",
    "fs::create_dir",
    "tokio::fs::write",
    "OpenOptions::new",
    "OpenOptions::create",
    "File::create",
    "File::create_new",
    "File::options",
];

const CACHE_EXEMPTION: &str = ".coc/.cache";

#[test]
fn coc_directory_is_read_only_in_csq_core_and_cli() {
    let csq_core = workspace_root().join("csq-core/src");
    let csq_cli = workspace_root().join("csq-cli/src");

    let mut violations = Vec::new();
    walk_rs(&csq_core, &mut violations);
    walk_rs(&csq_cli, &mut violations);

    if !violations.is_empty() {
        let summary = violations
            .iter()
            .map(|v| format!("  {}:{} → `{}`", v.path.display(), v.line_num, v.snippet))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("FR-FMT-06 violation: write call site under `.coc/` (spec 09 §9.10):\n{summary}");
    }
}

struct Violation {
    path: PathBuf,
    line_num: usize,
    snippet: String,
}

fn walk_rs(dir: &Path, violations: &mut Vec<Violation>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, violations);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scan_file(&path, &content, violations);
    }
}

/// Scan one source file. Track which line ranges are inside a
/// `#[cfg(test)]` module — a coarse line-by-line state machine that opens
/// when we see `#[cfg(test)]` immediately followed by `mod` (with any
/// whitespace between, including newlines), and closes when the module's
/// brace count returns to zero.
fn scan_file(path: &Path, content: &str, violations: &mut Vec<Violation>) {
    let mut in_cfg_test = false;
    let mut brace_depth: i32 = 0;
    let mut pending_cfg_test = false;
    // True while we are between `#[cfg(test)]` and the opening `{`.
    let mut waiting_for_open_brace = false;

    for (idx, line) in content.lines().enumerate() {
        let stripped = line.trim_start();

        // Detect `#[cfg(test)]` annotations attached to a `mod` declaration.
        if stripped.contains("#[cfg(test)]") {
            pending_cfg_test = true;
        }
        if pending_cfg_test && stripped.starts_with("mod ") {
            waiting_for_open_brace = true;
            pending_cfg_test = false;
        }

        // Brace counting (rough — comments + strings can confuse this, but
        // for csq's source this is sufficient because the lines we'd flag
        // never live inside an unbalanced string literal).
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;

        if waiting_for_open_brace {
            if opens > 0 {
                in_cfg_test = true;
                brace_depth = opens - closes;
                waiting_for_open_brace = false;
                continue; // skip the `mod tests {` line itself
            }
            continue;
        }

        if in_cfg_test {
            brace_depth += opens - closes;
            if brace_depth <= 0 {
                in_cfg_test = false;
                brace_depth = 0;
            }
            continue;
        }

        // We are NOT inside a #[cfg(test)] module.
        if let Some(v) = check_line(path, idx + 1, line) {
            violations.push(v);
        }
    }
}

fn check_line(path: &Path, line_num: usize, line: &str) -> Option<Violation> {
    if !line.contains(".coc") {
        return None;
    }
    if line.contains(CACHE_EXEMPTION) {
        return None;
    }
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
        return None;
    }
    let mentions_write = WRITE_APIS.iter().any(|api| line.contains(api));
    if !mentions_write {
        return None;
    }
    Some(Violation {
        path: path.to_path_buf(),
        line_num,
        snippet: line.trim().to_string(),
    })
}

fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR set by cargo");
    manifest_dir.parent().unwrap().to_path_buf()
}
