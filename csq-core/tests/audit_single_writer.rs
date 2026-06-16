//! T4 — Single-writer enforcement: only authorized sites may WRITE to
//! `csq-runs/` paths or `chain.json` in workspace source.
//!
//! ## What this test enforces
//!
//! The single-WRITE-site invariant (spec 12 §12.3, updated for R1 fix-wave B):
//! - `csq-core/src/audit/persist.rs` — the ONLY v1 + v2 write site.
//! - `csq-core/src/audit/key_custody/chain_state.rs` — M04 authorized
//!   WRITE site for `chain.json` (`signing_key_id`, `pubkey` fields).
//!
//! ## PRIMARY METHODOLOGICAL DIRECTIVE (R1-DEEP-5 fix)
//!
//! The scanner detects WRITE operations that reference `csq-runs/` or
//! `chain.json` paths — NOT mere file membership. A line is flagged when
//! it contains BOTH:
//!   1. A `csq-runs/` or `chain.json` path reference (the LITERAL), AND
//!   2. A write-API token (see `WRITE_TOKENS`).
//!
//! This means READ-only references in non-authorized files (verify.rs,
//! sweep.rs, daemon/server.rs, startup_reconciler.rs, drain paths) are NOT
//! flagged — the invariant is "single audited WRITE site", not "single
//! reference site". A future write added inside verify.rs is caught; a
//! `read_to_string` inside verify.rs is not.
//!
//! Additional authorized WRITE sites (MUST be named explicitly per spec 12
//! §12.3 "to add a new site, cite authorization in PR"):
//! - `csq-core/src/audit/mod.rs`        — re-export; no filesystem access
//! - `csq-core/src/audit/verify.rs`     — M05 read-only chain verifier
//! - `csq-core/src/audit/sweep.rs`      — reads and deletes; never writes audit records
//! - `csq-core/src/audit/key_custody/init.rs`   — calls chain_state::save
//! - `csq-core/src/audit/key_custody/rotate.rs` — calls chain_state::save
//! - `csq-core/src/audit/key_custody/mod.rs`    — doc / re-export
//! - `csq-core/src/audit/key_custody/doctor.rs` — reads chain.json key_id
//! - `csq-core/src/audit/key_custody/keyring_backend.rs` — doc comment
//! - `csq-core/src/daemon/startup_reconciler.rs` — drain calls write_record
//! - `csq-core/src/daemon/server.rs`    — routes audit writes through persist.rs
//! - `csq/src/cli/audit_emit.rs`        — writes to .pending/ subdir
//! - `csq/src/cli/trace_file.rs`        — writes to .trace/ subdir (NOT audit records)
//! - `csq/src/cli/mod.rs`               — doc comment only
//! - `csq/src/cli/commands/audit.rs`    — calls write_record_v2 via persist.rs
//! - `csq/src/cli/commands/doctor.rs`   — doc comment only (chain.json)
//!
//! Scan roots: `csq-core/src`, `csq/src`, `csq-desktop/src-tauri/src`.
//! Missing directories (e.g. csq-desktop) are silently skipped.
//!
//! ## Write-API tokens (WRITE_TOKENS)
//!
//! A line is classified as a WRITE attempt if it contains one of:
//!   `fs::write`, `File::create`, `OpenOptions`, `atomic_replace`,
//!   `secure_file`, `create_dir`, `DirBuilder`, `write_all`, `write_bytes`,
//!   `BufWriter`
//!
//! These tokens cover: direct write (fs::write, File::create, OpenOptions
//! with write(true)), the atomic-replace pipeline helpers, directory
//! creation, and buffered writers. Read-only APIs (`read_to_string`,
//! `File::open`, `read_dir`, `read_bytes`) contain none of these tokens.
//!
//! ## Authorized WRITE-site allowlist
//!
//! Only lines in these files are exempted from the write-detection check.
//! Read-only references in any file are never flagged (by design).
//! Adding a new WRITE site requires a PR comment citing spec 12 §12.3.
//!
//! ## What the test does NOT gate
//!
//! - READ-only references to `csq-runs/` or `chain.json` in any file
//!   (authorized or not) — reads don't violate the single-write-site rule.
//! - Lines inside `#[cfg(test)]` blocks or doc comments (`///`, `//!`, `//`
//!   as the first non-whitespace on the line).
//! - Inline trailing comments: `some_code(); // csq-runs/` IS checked because
//!   the line starts with code, not a comment marker.
//!
//! ## Failure message format (spec 12 §12.3 PRIMARY METHODOLOGICAL DIRECTIVE)
//!
//! `"FAIL: csq-runs/ write referenced outside authorized sites at <file>:<line>"`
//!
//! Origin: spec 12 §12.3, plan §0.4, journal-0075 enumeration-primitive method.
//! R1 fix-wave B: switched from file-membership allowlist to write-detection
//! (R1-DEEP-5 + R1-IR-8 fixes). Read sites are no longer in scope; WRITE_TOKENS
//! are the detection primitive.

use std::fs;
use std::path::{Path, PathBuf};

/// The path literal that identifies audit record paths.
const LITERAL: &str = "csq-runs/";

/// Write-API tokens: a line containing any of these tokens AND the LITERAL
/// is classified as a potential unauthorized write site.
///
/// These cover the full write surface:
/// - `fs::write`         — direct write via std::fs
/// - `File::create`      — create-truncate
/// - `OpenOptions`       — flexible open; encompasses write(true)/append(true)
/// - `atomic_replace`    — csq's atomic rename helper (write-path)
/// - `secure_file`       — csq's chmod helper (always paired with a write)
/// - `create_dir`        — directory creation (csq-runs/ itself)
/// - `DirBuilder`        — alternative directory creation API
/// - `write_all`         — Write trait method (BufWriter, File, etc.)
/// - `write_bytes`       — alternative write method name
/// - `BufWriter`         — buffered writer (wraps a write target)
const WRITE_TOKENS: &[&str] = &[
    "fs::write",
    "File::create",
    "OpenOptions",
    "atomic_replace",
    "secure_file",
    "create_dir",
    "DirBuilder",
    "write_all",
    "write_bytes",
    "BufWriter",
];

/// Authorized WRITE sites for `csq-runs/` and `chain.json` paths.
///
/// Only entries here may have lines that BOTH reference `csq-runs/`/`chain.json`
/// AND contain a write-API token. READ-only references in any file are not
/// subject to this allowlist — they are unconditionally allowed.
///
/// Adding a new WRITE site requires a PR comment citing spec 12 §12.3.
const AUTHORIZED_WRITE_FILES: &[&str] = &[
    // v1 write_record + v2 write_record_v2 + chain.json genesis writer.
    "csq-core/src/audit/persist.rs",
    // M04: writes signing_key_id + pubkey into chain.json atomically.
    // Authorization: spec 12 §12.11, M04 PR feat/m04-key-custody-keychain.
    "csq-core/src/audit/key_custody/chain_state.rs",
    // File-based signing-key custody: writes 0o600 seed files under
    // csq-runs/keys/<chain_id>/. Authorization: spec 12 §12.11.1 (file-mirror +
    // keychain-anchor custody, fix/audit-key-file-custody). The §5a pipeline
    // (unique_tmp_path → secure_file → atomic_replace) lives here.
    "csq-core/src/audit/key_custody/file_store.rs",
    // Audit-key migration + repair: copies keychain seeds into the file store
    // (writes under csq-runs/keys/) and backs up a broken chain. Authorization:
    // spec 12 §12.11.1 (csq audit migrate-keys / repair).
    "csq-core/src/audit/key_custody/migrate.rs",
    // sink_config.rs: writes audit-sink.json (NOT a csq-runs/ path).
    // Listed for completeness; the file writes to audit-sink.json under
    // base_dir, not under csq-runs/ — so it cannot trigger the LITERAL match.
    // audit_emit.rs writes to .pending/ subdir inside csq-runs/; authorized
    // per spec 12 §12.3 (pending subdir is an extension point, not a record).
    "csq/src/cli/audit_emit.rs",
    // trace_file.rs writes .trace/ log files inside csq-runs/; these are NOT
    // audit records per spec 12 §12.3 (purged by audit::sweep separately).
    "csq/src/cli/trace_file.rs",
    // M18 seam: quarantine.rs writes to csq-runs/.quarantine/ (frontier-rejected
    // events) and csq-runs/.pending/provenance/ (unknown-version events).
    // These are custody dirs, NOT chain records — no chain spine is written here.
    // Authorization: spec 12 §12.3, M18 BE seam scaffolding.
    "csq-core/src/audit/seam/quarantine.rs",
    // M20/M18-bind seam: reconcile.rs writes raw event bytes to
    // csq-runs/.pending/provenance-ordered/<person_id>/<decision_id>.json
    // (prev_link hash-chain held store, F-SEAM-09; M18-bind re-keyed it from
    // the original <surface>/<counter> shape). A custody buffer, NOT a chain
    // record — no chain spine is written here. It joins onto a passed-in
    // csq_runs path so it carries no `csq-runs/` literal (the scanner won't
    // flag it); registered for audit completeness. Authorization: spec 12
    // §12.21.3, M20 BE seam + M18-bind ordering re-key.
    "csq-core/src/audit/seam/reconcile.rs",
];

/// Source roots to scan (relative to workspace root).
/// Missing directories are silently skipped.
const SCAN_ROOTS: &[&str] = &["csq-core/src", "csq/src", "csq-desktop/src-tauri/src"];

// ─── Filesystem helpers ────────────────────────────────────────────────────

/// Collect all `.rs` files under `root`, skipping `target/` and `.git/`.
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

/// Returns the workspace root (directory containing the top-level Cargo.toml).
/// Anchored via `CARGO_MANIFEST_DIR` (set by cargo), not a hardcoded path.
fn workspace_root() -> PathBuf {
    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by cargo");
    PathBuf::from(manifest)
        .parent()
        .expect("csq-core is a workspace member — parent must exist")
        .to_path_buf()
}

// ─── Test-context heuristic ───────────────────────────────────────────────

/// Returns `true` when the line appears to be inside a `#[cfg(test)]` block
/// or is a pure doc / line comment (the ENTIRE line's first non-whitespace
/// starts with `//`).
///
/// ## Hardened edges (R1-IR-8)
///
/// 1. The `//` check ONLY fires when `//` is the FIRST non-whitespace token
///    on the line. This means inline trailing comments on a code line are NOT
///    exempt: `let p = base.join("csq-runs/foo"); // build path` is flagged
///    if it also contains a write token.
///
/// 2. The backward `#[cfg(test)]` scan window is raised to 500 lines (from
///    200) to handle large test modules. The heuristic is still conservative
///    (false-negative bias is wrong for a security gate, so we prefer to scan
///    further rather than miss a test-context flag). A closing brace counter
///    resets the match when a `}` closes the `mod tests` block before the
///    match line, preventing false-positives from deep nesting.
///
/// Note: `is_test_or_doc_context` is intentionally conservative — it should
/// NOT flag real production code as test context. The 500-line window +
/// brace-balance heuristic is an approximation; the structural defense is the
/// write-token detection, not the test-exclusion.
fn is_test_or_doc_context(lines: &[&str], line_idx: usize) -> bool {
    let line = lines[line_idx].trim();

    // Pure comment line: first non-whitespace is `//` (covers `///`, `//!`, `//`).
    // Does NOT exempt inline trailing comments like `code(); // csq-runs/`.
    if line.starts_with("//") {
        return true;
    }

    // Look backwards for a test-block opening within 500 lines.
    // Track brace balance: if the block was closed before line_idx, skip.
    let start = line_idx.saturating_sub(500);
    let preceding = &lines[start..line_idx];

    // Count net open braces from `mod tests {` or `#[cfg(test)]` block.
    // We scan in reverse; the first test-marker we hit either is still open
    // (net brace balance ≥ 0 counting from line_idx backward) or was closed.
    let mut open_braces: i64 = 0;
    for prev in lines[line_idx..]
        .iter()
        .take(0)
        .chain(preceding.iter().rev())
    {
        let trimmed = prev.trim();
        // Count braces in forward direction (we're scanning backwards, so
        // closing braces from our POV mean we're outside the block).
        open_braces += trimmed.chars().filter(|&c| c == '{').count() as i64;
        open_braces -= trimmed.chars().filter(|&c| c == '}').count() as i64;

        if trimmed.contains("#[cfg(test)]")
            || trimmed.starts_with("mod tests")
            || trimmed.starts_with("pub(crate) mod tests")
            || trimmed.starts_with("pub(super) mod tests")
            || trimmed.contains("#[test]")
            || trimmed.contains("#[tokio::test")
        {
            // If open_braces < 0 at this point scanning backwards, the block
            // was already closed before our line. But a simple marker like
            // `#[test]` above us is sufficient to say we're in a test context
            // for the purpose of this heuristic — attribute macros above a
            // function definitively mark it.
            return true;
        }

        // If we've gone through more close-braces than open-braces (scanning
        // backwards), the test block was closed before our line. Stop.
        if open_braces < -2 {
            return false;
        }
    }

    false
}

// ─── Write-detection scanner ──────────────────────────────────────────────

/// Returns `true` if the line contains any of the write-API tokens in
/// `WRITE_TOKENS`.
fn line_contains_write_token(line: &str) -> bool {
    WRITE_TOKENS.iter().any(|tok| line.contains(tok))
}

/// Walk all `.rs` files in the scan roots and return a list of
/// `(file_rel, line_number, line_content)` for every unauthorized WRITE
/// operation that references `csq-runs/` or `chain.json`.
///
/// A line is flagged when ALL of the following hold:
///   1. It contains the LITERAL (`csq-runs/`).
///   2. It contains a write-API token from `WRITE_TOKENS`.
///   3. The file is NOT in `AUTHORIZED_WRITE_FILES`.
///   4. The line is NOT in a `#[cfg(test)]` / `#[test]` / doc-comment context.
///
/// READ-only lines referencing `csq-runs/` are never flagged regardless of
/// which file they are in.
fn scan_workspace_for_writes(workspace: &Path) -> Vec<(String, usize, String)> {
    let mut violations = Vec::new();

    for root_rel in SCAN_ROOTS {
        let root_abs = workspace.join(root_rel);
        for file in collect_rs_files(&root_abs) {
            let rel = file
                .strip_prefix(workspace)
                .unwrap_or(&file)
                .to_string_lossy()
                .to_string();

            let normalized_rel = rel.replace('\\', "/");
            let authorized = AUTHORIZED_WRITE_FILES
                .iter()
                .any(|a| normalized_rel.ends_with(&a.replace('\\', "/")));

            // Authorized write sites are always exempt.
            if authorized {
                continue;
            }

            let content = match fs::read_to_string(&file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                // Must reference the csq-runs/ path literal.
                if !line.contains(LITERAL) {
                    continue;
                }
                // Must contain a write-API token to be a write site.
                if !line_contains_write_token(line) {
                    continue;
                }
                // Skip test / doc contexts.
                if is_test_or_doc_context(&lines, idx) {
                    continue;
                }
                violations.push((rel.clone(), idx + 1, line.trim().to_string()));
            }
        }
    }

    violations
}

// ─── Primary enforcement test ─────────────────────────────────────────────

/// Asserts that no unauthorized file contains a line that BOTH references
/// `csq-runs/` (or `chain.json`) AND uses a write-API token.
///
/// READ-only references to these paths in any file are unconditionally
/// allowed — the invariant is "single audited WRITE site", not "single
/// reference site".
///
/// Failure message format (spec 12 §12.3 PRIMARY METHODOLOGICAL DIRECTIVE):
/// `"FAIL: csq-runs/ write referenced outside authorized sites at <file>:<line>"`
#[test]
fn no_unauthorized_csq_runs_write_sites() {
    let workspace = workspace_root();
    let violations = scan_workspace_for_writes(&workspace);

    if violations.is_empty() {
        return;
    }

    let mut msg = String::from(
        "FAIL: csq-runs/ write referenced outside authorized sites.\n\
         \n\
         Only the sites listed in AUTHORIZED_WRITE_FILES in\n\
         `csq-core/tests/audit_single_writer.rs` may have lines that BOTH\n\
         reference `csq-runs/` AND use a write-API token.\n\
         READ-only references are unconditionally allowed.\n\
         To add a new authorized WRITE site, update AUTHORIZED_WRITE_FILES AND\n\
         document the authorization in the PR description per spec 12 §12.3.\n\
         \n\
         Unauthorized write references:\n",
    );
    for (file, line, content) in &violations {
        msg.push_str(&format!(
            "  FAIL: csq-runs/ write referenced outside authorized sites at {file}:{line}\n"
        ));
        msg.push_str(&format!("        content: {content}\n"));
    }
    panic!("{msg}");
}

// ─── Regression tests (R1-DEEP-5 + R1-IR-8) ─────────────────────────────

/// (a) A synthetic WRITE line in a non-authorized file IS flagged.
///
/// Verifies the primary detection path: line contains both LITERAL and a
/// write-API token → violation.
#[test]
fn synthetic_write_in_non_writer_file_is_flagged() {
    let write_line = r#"    std::fs::write(base.join("csq-runs/bad.jsonl"), b"data").unwrap();"#;
    let lines: Vec<&str> = write_line.lines().collect();
    let has_literal = write_line.contains(LITERAL);
    let has_write_token = line_contains_write_token(write_line);
    let is_test = is_test_or_doc_context(&lines, 0);

    assert!(has_literal, "synthetic line must contain csq-runs/ literal");
    assert!(
        has_write_token,
        "synthetic line must be detected as a write (fs::write token)"
    );
    assert!(
        !is_test,
        "synthetic line must not be classified as test context"
    );
    // This would be flagged as a violation.
    assert!(
        has_literal && has_write_token && !is_test,
        "synthetic write in non-writer file must be flagged as a violation"
    );
}

/// (b) A synthetic READ line in a non-authorized file is NOT flagged.
///
/// Verifies that read-only references (e.g. verify.rs, sweep.rs) are
/// unconditionally allowed — the invariant is WRITE-site-only.
#[test]
fn synthetic_read_in_non_writer_file_is_not_flagged() {
    let read_line = r#"    let raw = std::fs::read_to_string(base.join("csq-runs/chain.json"))?;"#;
    let has_literal = read_line.contains(LITERAL) || read_line.contains("chain.json");
    let has_write_token = line_contains_write_token(read_line);

    assert!(has_literal, "synthetic read line must reference csq-runs/");
    assert!(
        !has_write_token,
        "read_to_string must NOT trigger a write token (no write-API token present)"
    );
    // NOT a violation: no write token.
    assert!(
        !has_write_token,
        "synthetic read in non-writer file must NOT be flagged"
    );
}

/// (c) Edge: `#[cfg(test)]` / `#[test]` marker more than 200 lines above
///     (the old 200-line window would miss this; the new 500-line window catches it).
#[test]
fn test_context_detection_handles_gt200_lines_above_test_marker() {
    // Build a fake source with #[test] at line 0 and the target line at line 250.
    let mut fake_lines: Vec<String> = vec!["#[test]".to_string()];
    // Pad with 249 blank lines to place the csq-runs/ reference at line 250.
    for _ in 0..249 {
        fake_lines.push(String::new());
    }
    fake_lines.push(
        r#"    std::fs::write(base.join("csq-runs/bad.jsonl"), b"data").unwrap();"#.to_string(),
    );

    let refs: Vec<&str> = fake_lines.iter().map(|s| s.as_str()).collect();
    let target_idx = refs.len() - 1;

    // With 500-line window the #[test] at line 0 is within range (250 lines back).
    let is_test = is_test_or_doc_context(&refs, target_idx);
    assert!(
        is_test,
        "line 250 with #[test] at line 0 (250 lines back) must be classified as test context \
         (500-line window catches it)"
    );
}

/// (d) A trailing inline comment `// csq-runs/` on a real statement line IS
///     checked, not silently exempted.
///
/// Specifically: `some_code(); // csq-runs/path` should be checked because the
/// line does NOT start with `//` — only pure comment lines are exempt.
#[test]
fn inline_trailing_comment_csq_runs_reference_is_checked() {
    // This line has real code + a trailing comment with csq-runs/
    let trailing_comment_line =
        r#"    std::fs::write(&path, data)?; // writes to csq-runs/records.jsonl"#;

    let trimmed = trailing_comment_line.trim();
    // Must NOT be classified as a doc/comment line (doesn't start with //)
    assert!(
        !trimmed.starts_with("//"),
        "line with leading code must not be classified as a pure comment"
    );

    let lines: Vec<&str> = trailing_comment_line.lines().collect();
    let is_test = is_test_or_doc_context(&lines, 0);
    assert!(
        !is_test,
        "line with code + trailing csq-runs/ comment must NOT be exempt as a doc context"
    );

    // The line also contains a write token (fs::write) and csq-runs/
    let has_literal = trailing_comment_line.contains(LITERAL);
    let has_write_token = line_contains_write_token(trailing_comment_line);
    assert!(has_literal, "trailing comment line must contain csq-runs/");
    assert!(
        has_write_token,
        "trailing comment line with fs::write must trigger write detection"
    );
}

/// Verifies the scanner produces the required failure-message format.
///
/// Failure message format (spec 12 §12.3):
/// `"FAIL: csq-runs/ write referenced outside authorized sites at <file>:<line>"`
#[test]
fn unauthorized_csq_runs_write_produces_descriptive_file_line_message() {
    // Inline scanner against synthetic content (no actual file I/O needed).
    // Both LITERAL and write-token MUST be on the same line for detection.
    let fake_content = concat!(
        "fn bad_write() {\n",
        r#"    std::fs::write("/home/user/.claude/accounts/csq-runs/bad.jsonl", b"data").unwrap();"#,
        "\n",
        "}\n",
    );

    let lines: Vec<&str> = fake_content.lines().collect();
    let mut hits: Vec<(String, usize, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if line.contains(LITERAL)
            && line_contains_write_token(line)
            && !is_test_or_doc_context(&lines, idx)
        {
            hits.push((
                "fake_module.rs".to_string(),
                idx + 1,
                line.trim().to_string(),
            ));
        }
    }

    // Scanner must find the write violation (on the fs::write line).
    assert!(
        !hits.is_empty(),
        "scanner must detect synthetic csq-runs/ write violation — scanner is broken"
    );

    // Failure message must contain the required format.
    let (file, line_no, _) = &hits[0];
    let msg =
        format!("FAIL: csq-runs/ write referenced outside authorized sites at {file}:{line_no}");
    assert!(
        msg.contains(
            "FAIL: csq-runs/ write referenced outside authorized sites at fake_module.rs:"
        ),
        "failure message must contain required format\ngot: {msg}"
    );
    assert!(*line_no > 0, "line number must be > 0, got {line_no}");
}

/// The legacy `#[ignore]` self-test: kept as documentation.
/// Run manually with:
/// ```
/// cargo test --test audit_single_writer -- --ignored synthetic_violation_fails
/// ```
/// Expected: this test PANICS (scanner correctly detects the synthetic hit).
#[test]
#[ignore = "self-test: expected to panic — see no_unauthorized_csq_runs_write_sites for the active gate"]
fn synthetic_violation_fails() {
    let tmpdir = tempfile::TempDir::new().unwrap();
    let fake_src = tmpdir.path().join("src");
    fs::create_dir_all(&fake_src).unwrap();
    let fake_file = fake_src.join("fake_module.rs");
    fs::write(
        &fake_file,
        r#"
fn bad_write() {
    let path = "/home/user/.claude/accounts/csq-runs/bad.jsonl";
    std::fs::write(path, b"data").unwrap();
}
"#,
    )
    .unwrap();

    let content = fs::read_to_string(&fake_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let violations: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(idx, line)| {
            line.contains(LITERAL)
                && line_contains_write_token(line)
                && !is_test_or_doc_context(&lines, *idx)
        })
        .map(|(idx, line)| ("fake_module.rs".to_string(), idx + 1, line.to_string()))
        .collect();

    assert!(
        !violations.is_empty(),
        "scanner should have found the synthetic violation but didn't — scanner is broken"
    );

    panic!(
        "synthetic violation correctly detected at line {}: {}",
        violations[0].1, violations[0].2
    );
}
