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
//! `csq/src`. Track brace depth across `#[cfg(test)]` mod boundaries
//! to skip lines inside them. For lines OUTSIDE `cfg(test)`, reject any
//! `.coc` reference paired with a write API call **within a small line
//! window** (unless the `CACHE_EXEMPTION` substring appears in that window
//! — currently vestigial; see note above).
//!
//! # Why the walk roots are asserted, not merely walked
//!
//! Until 2026-07-27 this test walked `csq-cli/src`, a directory that has not
//! existed since the CLI crate was renamed to `csq/`. `walk_rs` treated an
//! unreadable directory as "nothing to scan" and returned, so the test passed
//! while **126 `.coc` references in `csq/src` went unscanned**. The guard was
//! green and half-blind for the entire period.
//!
//! That is the failure class in `.claude/rules/tooling-self-verification.md`
//! Rule 1 — a success signal not conditional on the operation having happened.
//! The fix is structural: `assert_walk_root` fails loudly if a root is missing,
//! so a future rename breaks this test instead of silently narrowing it.
//!
//! # Non-vacuity
//!
//! `.claude/rules/tooling-self-verification.md` Rule 3 requires a guard to be
//! proven capable of failing, separately from its own verdict. The
//! `detects_*` tests below plant each violation shape against the scanner and
//! assert it fires. Widening `WRITE_APIS` without those tests would itself be
//! an unproven change.
//!
//! Spec authority: `specs/09-unified-coc-artifact-standard.md` §9.10 +
//! `specs/10-capability-layer-architecture.md` §10.9.4. an internal ticket tracks
//! the spec-text amendment that aligned §10.9.2 + §10.9.4 with the
//! `<workspace_root>/.cache/` implementation.

use std::fs;
use std::path::{Path, PathBuf};

/// Every std/tokio API that can CREATE, MODIFY, MOVE, or REMOVE a path.
///
/// A read-only invariant is not only about `write` — `remove_dir_all` on
/// `.coc/` destroys the policy just as effectively as rewriting it, and
/// `rename`/`symlink` substitute it. The pre-2026-07-27 list covered only the
/// create/write third of the surface.
const WRITE_APIS: &[&str] = &[
    // create / write
    "fs::write",
    "fs::create_dir",
    "tokio::fs::write",
    "OpenOptions::new",
    "OpenOptions::create",
    "File::create",
    "File::create_new",
    "File::options",
    // remove
    "fs::remove_file",
    "fs::remove_dir",
    "fs::remove_dir_all",
    "tokio::fs::remove_file",
    "tokio::fs::remove_dir",
    "tokio::fs::remove_dir_all",
    // move / substitute
    "fs::rename",
    "tokio::fs::rename",
    "fs::copy",
    "tokio::fs::copy",
    "fs::hard_link",
    "os::unix::fs::symlink",
    "symlink_file",
    "symlink_dir",
    // permissions
    "fs::set_permissions",
    "set_readonly",
    // csq's own atomic-write helpers — these bypass the bare std names above
    "atomic_replace",
    "secure_file",
];

const CACHE_EXEMPTION: &str = ".coc/.cache";

/// How many consecutive non-`cfg(test)` source lines are considered together
/// when pairing a `.coc` mention with a write API.
///
/// Rationale for the value, per `tooling-self-verification.md` Rule 3 — the two
/// outcomes this must separate.
///
/// TOO SMALL (1, the pre-2026-07-27 behaviour) misses the overwhelmingly common
/// rustfmt output shape, where a call exceeding 100 columns is split so the API
/// and its path argument land on different lines:
///
/// ```text
/// fs::write(
///     coc_dir.join("rules/x.md"),
///     body,
/// )?;
/// ```
///
/// That is a 3-line span between `fs::write` and `.coc`.
///
/// TOO LARGE (say 20) pairs a `.coc` mention in one statement with an unrelated
/// write several statements later, producing false positives — and per
/// `tooling-self-verification.md` Rule 5 an audit primitive that cries wolf is
/// one nobody runs.
///
/// 6 covers a split call plus a doc line or attribute between them, and is far
/// below the distance at which unrelated statements begin colliding. Measured
/// on the current tree: 0 violations at 6, and the `detects_split_line_write`
/// non-vacuity test fails if the window is reduced to 1.
const WINDOW_LINES: usize = 6;

#[test]
fn coc_directory_is_read_only_in_csq_core_and_cli() {
    let csq_core = workspace_root().join("csq-core/src");
    let csq_cli = workspace_root().join("csq/src");

    assert_walk_root(&csq_core);
    assert_walk_root(&csq_cli);

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
    // Non-test, non-comment lines, in order, with their 1-based line numbers.
    // The window pass runs over this rather than over raw content so that
    // `cfg(test)` bodies and comments cannot pad a window into a false pair.
    let mut eligible: Vec<(usize, String)> = Vec::new();

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

        // We are NOT inside a #[cfg(test)] module. Comment-only lines carry no
        // behaviour, so they are excluded from the window entirely rather than
        // occupying a slot in it.
        if stripped.starts_with("//") {
            continue;
        }
        eligible.push((idx + 1, line.to_string()));
    }

    scan_window(path, &eligible, violations);
}

/// Pair each write-API call site with any `.coc` mention within
/// [`WINDOW_LINES`] eligible lines in EITHER direction.
///
/// Both directions are required. rustfmt splits a long call so the API precedes
/// its path argument (`fs::write(\n    coc_dir.join(..),`), while a
/// let-bound path precedes its use (`let p = base.join(".coc");\n fs::write(p,`).
/// A one-directional scan misses exactly half of the real shapes.
fn scan_window(path: &Path, eligible: &[(usize, String)], violations: &mut Vec<Violation>) {
    for (i, (line_num, line)) in eligible.iter().enumerate() {
        if !WRITE_APIS.iter().any(|api| line.contains(api)) {
            continue;
        }
        // An import names a write API without calling one.
        if line.trim_start().starts_with("use ") {
            continue;
        }

        let lo = i.saturating_sub(WINDOW_LINES);
        let hi = (i + WINDOW_LINES + 1).min(eligible.len());
        let window = &eligible[lo..hi];

        // The cache exemption is evaluated over the whole window, not the
        // single line, so a split `.coc/.cache` call is still exempt.
        if window.iter().any(|(_, l)| l.contains(CACHE_EXEMPTION)) {
            continue;
        }
        if !window.iter().any(|(_, l)| mentions_coc_path(l)) {
            continue;
        }

        violations.push(Violation {
            path: path.to_path_buf(),
            line_num: *line_num,
            snippet: line.trim().to_string(),
        });
    }
}

/// True when the line references the `.coc` **directory**, as opposed to merely
/// containing the three characters `coc` after a dot.
///
/// A bare `line.contains(".coc")` produced three distinct false-positive shapes
/// on the real tree when the widened matcher first ran (2026-07-27):
///
/// * `summary.coc_trust_orphans_removed += 1;` — a struct field access
/// * `handle_dir_abs.join("rules.coc-staging")` — a sibling staging dir whose
///   name merely ends in `.coc-staging`
/// * `use crate::platform::fs::secure_file;` — an import, handled separately
///
/// A real `.coc` path reference is always followed by a path separator or a
/// string terminator. Requiring that keeps the gate credible: per
/// `.claude/rules/tooling-self-verification.md` Rule 5, an audit primitive with
/// a high false-positive rate is one nobody runs, and acting on its output
/// unread produces pointless changes that bury the real findings.
fn mentions_coc_path(line: &str) -> bool {
    line.match_indices(".coc").any(|(idx, _)| {
        match line[idx + ".coc".len()..].chars().next() {
            // `.coc/rules`, `".coc"`, `'.coc'`, `.coc` then `)` / `,` / EOL.
            Some('/') | Some('"') | Some('\'') | Some(')') | Some(',') | None => true,
            // `.coc_trust`, `.coc-staging`, `.cocoa` — not the directory.
            Some(_) => false,
        }
    })
}

/// Fail loudly when a walk root is missing.
///
/// This is the structural fix for the 2026-07-27 finding: `walk_rs` treats an
/// unreadable directory as "nothing to scan", so a renamed crate silently
/// narrowed this guard's coverage to half the tree while it kept reporting
/// green. A missing root is a broken guard, not an empty one.
fn assert_walk_root(dir: &Path) {
    assert!(
        dir.is_dir(),
        "coc_readonly walk root does not exist: {}\n\
         The guard scans nothing under a missing root, so this test would pass \
         while the invariant went unchecked. If a crate was renamed or moved, \
         update the roots in `coc_directory_is_read_only_in_csq_core_and_cli`.",
        dir.display()
    );
}

fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR set by cargo");
    manifest_dir.parent().unwrap().to_path_buf()
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-vacuity proofs.
//
// `.claude/rules/tooling-self-verification.md` Rule 3: proving a guard PASSES
// is not proving it CAN FAIL. Each test below plants one violation shape and
// asserts the scanner fires; the negative tests pin the false-positive
// boundary, because an audit primitive that cries wolf is one nobody runs
// (same rule, Rule 5).
//
// These are the reason the WRITE_APIS widening and the window are trustworthy.
// Delete any single planted case and its test fails.
// ─────────────────────────────────────────────────────────────────────────────

/// Run the scanner over synthetic source and return the flagged line numbers.
fn scan(src: &str) -> Vec<usize> {
    let mut violations = Vec::new();
    scan_file(Path::new("synthetic.rs"), src, &mut violations);
    violations.iter().map(|v| v.line_num).collect()
}

#[test]
fn detects_same_line_write() {
    let hits = scan("fn f() {\n    fs::write(root.join(\".coc/rules/x.md\"), b\"\")?;\n}\n");
    assert_eq!(hits, vec![2], "same-line write under .coc must be flagged");
}

#[test]
fn detects_split_line_write() {
    // The rustfmt shape: API and path on different lines. This is what the
    // pre-2026-07-27 same-line matcher could not see.
    let src = "fn f() {\n    \
               fs::write(\n        \
               coc_dir.join(\".coc/rules/x.md\"),\n        \
               body,\n    \
               )?;\n}\n";
    assert_eq!(
        scan(src),
        vec![2],
        "split-line write under .coc must be flagged; if this fails, WINDOW_LINES is too small"
    );
}

#[test]
fn detects_write_after_let_bound_coc_path() {
    // The other direction: path bound first, written several lines later.
    let src = "fn f() {\n    \
               let target = base.join(\".coc\").join(\"rules\");\n    \
               let body = render();\n    \
               fs::create_dir(&target)?;\n}\n";
    assert_eq!(
        scan(src),
        vec![4],
        "backward-window pairing must be flagged"
    );
}

#[test]
fn detects_removal_apis() {
    // Destroying the policy is as much a violation as rewriting it — the
    // pre-2026-07-27 WRITE_APIS list covered none of these.
    for api in [
        "fs::remove_dir_all",
        "fs::remove_file",
        "fs::rename",
        "fs::copy",
        "fs::set_permissions",
    ] {
        let src = format!("fn f() {{\n    {api}(root.join(\".coc\"))?;\n}}\n");
        assert_eq!(
            scan(&src),
            vec![2],
            "`{api}` under .coc must be flagged — it mutates the policy tree"
        );
    }
}

#[test]
fn honours_cache_exemption() {
    let src = "fn f() {\n    fs::write(root.join(\".coc/.cache/parse.json\"), b\"\")?;\n}\n";
    assert!(
        scan(src).is_empty(),
        "the reserved .coc/.cache exemption must suppress the finding"
    );
}

#[test]
fn skips_cfg_test_modules() {
    let src = "fn prod() {}\n\
               #[cfg(test)]\n\
               mod tests {\n    \
               fn t() {\n        \
               fs::create_dir(dir.join(\".coc\")).unwrap();\n    \
               }\n\
               }\n";
    assert!(
        scan(src).is_empty(),
        "test-fixture writes build synthetic trees in tempdirs and are exempt"
    );
}

#[test]
fn skips_comment_lines() {
    let src = "fn f() {\n    // fs::write(root.join(\".coc\"), b\"\")?;\n}\n";
    assert!(
        scan(src).is_empty(),
        "a commented-out call is not a call; flagging it is the cry-wolf failure"
    );
}

#[test]
fn window_does_not_pair_distant_lines() {
    // Upper bound on WINDOW_LINES: an unrelated write far below a `.coc`
    // mention must NOT pair. Anything that flags here is a false positive.
    let mut src = String::from("fn f() {\n    let p = base.join(\".coc\");\n");
    for i in 0..12 {
        src.push_str(&format!("    let unrelated_{i} = compute({i});\n"));
    }
    src.push_str("    fs::write(other_path, body)?;\n}\n");
    // 12 filler lines exceeds WINDOW_LINES=6 in both directions.
    assert!(
        scan(&src).is_empty(),
        "distant write must not pair with a far-away .coc mention"
    );
}

#[test]
fn does_not_match_coc_lookalikes() {
    // The three real shapes that the first widened matcher wrongly flagged on
    // this tree. Each is a legitimate non-`.coc/` construct.
    for line in [
        "    summary.coc_trust_orphans_removed += 1;",
        "    let tmp = handle_dir_abs.join(\"rules.coc-staging\");",
        "    let p = base.join(\".cocoa\");",
    ] {
        assert!(
            !mentions_coc_path(line),
            "must not treat a `.coc` lookalike as the .coc directory: {line}"
        );
    }
    // …and the shapes that ARE the directory must still match.
    for line in [
        "    root.join(\".coc/rules/x.md\")",
        "    base.join(\".coc\")",
        "    let d = \".coc\";",
    ] {
        assert!(
            mentions_coc_path(line),
            "must recognise a genuine .coc path reference: {line}"
        );
    }
}

#[test]
fn use_statement_is_not_a_call() {
    let src = "use crate::platform::fs::secure_file;\n\
               fn f() {\n    \
               let p = root.join(\".coc\");\n\
               }\n";
    assert!(
        scan(src).is_empty(),
        "an import naming a write API is not a call site"
    );
}

#[test]
#[should_panic(expected = "walk root does not exist")]
fn missing_walk_root_fails_loudly() {
    // The 2026-07-27 regression itself: a renamed crate made a root vanish and
    // the guard silently scanned nothing. This asserts it now breaks instead.
    assert_walk_root(&workspace_root().join("csq-cli/src"));
}
