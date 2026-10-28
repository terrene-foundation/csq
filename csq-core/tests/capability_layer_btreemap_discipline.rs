//! Spec 10 §10.3.5 — determinism by `BTreeMap`/`BTreeSet` in the
//! capability layer. Concretely: HashMap and HashSet MUST NOT appear
//! anywhere under `csq-core/src/capability_layer/`. The cross-process
//! determinism property holds by type construction, not by per-call
//! sort discipline (which is easy to forget).
//!
//! This static-grep test mirrors the FR-FMT-06 read-only invariant
//! test (see `coc_readonly.rs`) — it walks every `.rs` source file
//! in the capability_layer module and rejects any line that
//! references the banned types in *production* code. Doc-comments
//! and `//!` module headers that NAME these types when explaining
//! the discipline are exempt; the exemption is detected by
//! line-leading `///` or `//!` markers (after whitespace).
//!
//! Why a test rather than a clippy lint: the workspace has 215+
//! existing HashMap/HashSet uses outside `capability_layer/` and
//! `coc/`, so a project-wide `disallowed-types` clippy config would
//! require an `#[allow]` per call-site. Spec 10 §10.3.5 names the
//! lint as workspace-scoped to capability_layer; this test
//! materializes it without disturbing the rest of the codebase.

use std::fs;
use std::path::{Path, PathBuf};

const BANNED: &[&str] = &["HashMap", "HashSet"];

#[test]
fn capability_layer_uses_btreemap_and_btreeset_only() {
    let dir = workspace_root().join("csq-core/src/capability_layer");
    assert!(
        dir.is_dir(),
        "capability_layer dir missing at {}",
        dir.display()
    );

    let mut violations = Vec::new();
    walk_rs(&dir, &mut violations);

    if !violations.is_empty() {
        let summary = violations
            .iter()
            .map(|v| format!("  {}:{} → `{}`", v.path.display(), v.line_num, v.line))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "spec 10 §10.3.5 BTreeMap discipline violated — \
             HashMap/HashSet found in capability_layer/:\n{summary}"
        );
    }
}

struct Violation {
    path: PathBuf,
    line_num: usize,
    line: String,
}

fn walk_rs(dir: &Path, violations: &mut Vec<Violation>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, violations);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            scan_file(&path, violations);
        }
    }
}

fn scan_file(path: &Path, violations: &mut Vec<Violation>) {
    let content = fs::read_to_string(path).unwrap();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        // Doc-comments + module-header comments are exempt — they
        // legitimately NAME the banned types when documenting why
        // they're banned.
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        // Inline `//` comments are exempt only AFTER the first non-
        // comment code on the line. We strip the trailing comment
        // and scan the rest.
        let scannable = match trimmed.find("//") {
            Some(pos) => &trimmed[..pos],
            None => trimmed,
        };
        for banned in BANNED {
            if scannable.contains(banned) {
                violations.push(Violation {
                    path: path.to_path_buf(),
                    line_num: idx + 1,
                    line: trimmed.to_string(),
                });
            }
        }
    }
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at csq-core; one level up is the
    // workspace root.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    PathBuf::from(manifest).parent().unwrap().to_path_buf()
}
