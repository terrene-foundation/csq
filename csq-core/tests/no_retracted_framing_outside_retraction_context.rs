//! Eradication-CI lint: any match for a retracted-policy phrase MUST
//! be wrapped in retraction context (the ±N-line neighborhood, where
//! N = `NEIGHBORHOOD_HALF_WINDOW`, contains an explicit retraction
//! keyword). A bare match — a doc comment, an error message, a skill
//! table, a test assertion — that asserts the retracted policy as
//! live truth FAILS this test.
//!
//! # Why this exists
//!
//! Journal 0049 §"Process improvement" (csq-as-cli workspace, 2026-
//! 05-06) identified that single-line eradication greps cannot
//! distinguish retraction context from live framing. The Gemini
//! Stage 1 retraction (journal 0048) initially shipped four artifacts
//! that still asserted the retracted EP1-EP7 / "7-layer ToS guard"
//! policy as live truth, despite the WIP commit's verification grep
//! returning "only intentional retraction comments remain". /redteam
//! rounds 3 + 4 caught and fixed all four.
//!
//! This test is the durable fix: a tree-walker that runs on every
//! CI build, finds every match for the retracted phrases, and only
//! tolerates matches whose neighborhood explicitly says "retracted",
//! "Earlier revisions", "now-retracted", "framing was wrong",
//! "framing correction", or appears in a legacy-event drainer code
//! path tagged `tos_guard_tripped` (the v1→v2 schema migration in
//! `daemon/usage_poller/gemini.rs` is intentional, not enforcement).
//!
//! # Adding a new retraction
//!
//! When a future session retracts another piece of csq policy, append
//! to `RETRACTED_PHRASES` and run this test locally. Any match
//! lacking retraction context will fail — exactly the early-warning
//! signal future retraction sessions need.
//!
//! # Why not a clippy lint
//!
//! Clippy operates on Rust syntax trees; the retracted phrases live
//! across `.rs`, `.md`, `.svelte`, `.ts`, `.json` and per-skill
//! `SKILL.md` files. A workspace-wide grep test catches all of them
//! with zero plugin infrastructure. Pattern follows
//! `csq-core/tests/no_direct_gemini_spawn.rs`.

use std::path::{Path, PathBuf};

/// File extensions to scan. Add as needed when retractions touch
/// new file types.
const SCANNED_EXTENSIONS: &[&str] = &["rs", "md", "svelte", "ts", "tsx", "js", "json"];

/// Top-level paths walked by the test. `target/`, `node_modules/`,
/// `.git/` are excluded by `walk_files` regardless of inclusion here.
const SCANNED_ROOTS: &[&str] = &[
    "csq-core/src",
    "csq-cli/src",
    "csq-desktop/src",
    "csq-desktop/src-tauri/src",
    "csq-core/tests",
    "csq-cli/tests",
    "specs",
    ".claude",
];

/// Files explicitly skipped because they contain retracted phrases as
/// the SUBJECT of the file (this test, journal entries documenting
/// the retraction). Matched against the workspace-relative path.
const SKIP_FILES_EXACT: &[&str] =
    &["csq-core/tests/no_retracted_framing_outside_retraction_context.rs"];

/// Path prefixes to skip — entire directory trees that legitimately
/// document the retracted policy in full (journal entries OWN the
/// historical record; release notes for already-published versions
/// preserve historical accuracy). Matched as path prefixes.
const SKIP_PREFIXES: &[&str] = &[
    "workspaces/",    // every journal entry; the retraction lives there
    "journal/",       // root-level journal
    "docs/releases/", // released release notes are historical
    // Persistent agent git worktrees under `.claude/worktrees/<id>/`
    // check out other branches whose content is historical from main's
    // perspective. Treat them like extra `workspaces/` siblings — the
    // retraction lives in main, so any branch that predates it is
    // legitimately allowed to contain pre-retraction framing.
    ".claude/worktrees/",
];

/// Each retraction is a (phrase-pattern, retraction-keyword-set)
/// pair. A match for `phrase` is tolerated only if the
/// ±`NEIGHBORHOOD_HALF_WINDOW`-line neighborhood contains at least
/// one of the `keywords`.
struct RetractedPhrase {
    /// The exact substring to grep for. Case-sensitive.
    phrase: &'static str,
    /// Retraction-context keywords; presence of ANY one in the
    /// neighborhood marks the match as historical context, not
    /// live framing.
    keywords: &'static [&'static str],
}

/// Retracted phrases to scan for. Append entries here when new
/// retractions land. The keyword sets are deliberately broad — false-
/// positive tolerance is fine, false-negative (missing a live framing)
/// is the failure mode this test prevents.
const RETRACTED_PHRASES: &[RetractedPhrase] = &[
    // Journal 0048: Gemini ToS-driven defense framing retracted.
    RetractedPhrase {
        phrase: "EP1-EP7",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "7-layer",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "tos_guard",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS_PLUS_LEGACY,
    },
    RetractedPhrase {
        phrase: "active enforcement",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "permanent ban",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "C-CR1",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "kill-on-OAuth",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "first offence",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "first offense",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
    RetractedPhrase {
        phrase: "recertification",
        keywords: GEMINI_TOS_RETRACTION_KEYWORDS,
    },
];

/// Retraction keywords for journal-0048-class retractions (the
/// Gemini OAuth restriction lift).
const GEMINI_TOS_RETRACTION_KEYWORDS: &[&str] = &[
    "retracted",
    "now-retracted",
    "Earlier revisions",
    "earlier revisions",
    "was wrong",
    "framing correction",
    "journal 0048",
    "journal 0049",
    "Retracted:",
    "RETRACTED",
    "Stage 2 of journal 0048",
];

/// Same as above plus the legacy-drainer tag — `tos_guard_tripped`
/// envelopes are intentionally drained and dropped silently in
/// `daemon/usage_poller/gemini.rs` per the v1→v2 schema migration.
const GEMINI_TOS_RETRACTION_KEYWORDS_PLUS_LEGACY: &[&str] = &[
    "retracted",
    "now-retracted",
    "Earlier revisions",
    "earlier revisions",
    "was wrong",
    "framing correction",
    "journal 0048",
    "journal 0049",
    "Retracted:",
    "RETRACTED",
    "Stage 2 of journal 0048",
    "tos_guard_tripped",
    "legacy",
    "v1 →",
    "v1→",
    "v1 -> v2",
    "v1->v2",
    "v1 included",
];

#[test]
fn no_retracted_phrase_lives_outside_retraction_context() {
    let workspace_root = std::env::current_dir()
        .expect("cwd")
        .parent()
        .expect("workspace root above csq-core")
        .to_path_buf();

    let mut violations: Vec<String> = Vec::new();

    for root in SCANNED_ROOTS {
        let root_path = workspace_root.join(root);
        if !root_path.exists() {
            continue;
        }
        walk_files(&workspace_root, &root_path, &mut |rel_path, content| {
            if should_skip(rel_path) {
                return;
            }
            scan_content(rel_path, content, &mut violations);
        });
    }

    assert!(
        violations.is_empty(),
        "Retracted-policy phrases asserted as live truth (no retraction \
         keyword in surrounding neighborhood). Each violation is a doc \
         comment, error message, skill row, or test assertion that future \
         agents would read as current policy.\n\n\
         Fix: either (a) wrap the phrase in explicit retraction context \
         (e.g. \"Earlier revisions framed this as ... — that framing was \
         retracted in journal 0048\"), or (b) delete the phrase entirely \
         if no longer needed.\n\n\
         If you intentionally added a phrase that should bypass this \
         check (e.g. a new retracted-policy framework documented in a \
         fresh journal entry), append the journal number to the \
         RETRACTED_PHRASES keyword set in this test file.\n\n\
         Violations:\n  {}",
        violations.join("\n  ")
    );
}

/// Half-window size in lines. The neighborhood is `[idx - WINDOW,
/// idx + WINDOW]` (inclusive), so a window of 3 means a 7-line
/// strip total. Sized to span typical multi-line Rust doc-comment
/// blocks (`///` continuation runs of 4-7 lines) and Markdown
/// paragraphs without bleeding into unrelated content.
const NEIGHBORHOOD_HALF_WINDOW: usize = 3;

fn scan_content(rel_path: &Path, content: &str, violations: &mut Vec<String>) {
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        for retracted in RETRACTED_PHRASES {
            if !line.contains(retracted.phrase) {
                continue;
            }
            let lo = idx.saturating_sub(NEIGHBORHOOD_HALF_WINDOW);
            let hi = (idx + NEIGHBORHOOD_HALF_WINDOW + 1).min(lines.len());
            let neighborhood = lines[lo..hi].join("\n");

            let has_retraction_context = retracted
                .keywords
                .iter()
                .any(|kw| neighborhood.contains(kw));

            if !has_retraction_context {
                violations.push(format!(
                    "{}:{}: phrase=\"{}\"  line={}",
                    rel_path.display(),
                    idx + 1,
                    retracted.phrase,
                    line.trim(),
                ));
            }
        }
    }
}

fn should_skip(rel_path: &Path) -> bool {
    // Normalize Windows backslash path separators to forward slash so
    // SKIP_FILES_EXACT + SKIP_PREFIXES (which are authored as POSIX-
    // style paths) match on Windows CI runners. Without this, the
    // self-skip ("csq-core/tests/no_retracted_framing_outside_retraction_context.rs")
    // fails byte-equality against the Windows path
    // ("csq-core/tests\\no_retracted_framing_outside_retraction_context.rs"),
    // and the test file scans itself — every retracted-phrase string
    // literal in `RETRACTED_PHRASES` then registers as a violation.
    // Origin: pre-existing Windows-only CI failure observed
    // 2026-05-07; fixed during /autonomize this session.
    let path_str = rel_path.to_string_lossy().replace('\\', "/");
    if SKIP_FILES_EXACT.iter().any(|p| path_str == *p) {
        return true;
    }
    if SKIP_PREFIXES.iter().any(|p| path_str.starts_with(p)) {
        return true;
    }
    false
}

/// Walks the file tree under `current`, calling `cb(workspace_relative_path, content)`
/// for each file whose extension is in `SCANNED_EXTENSIONS`. Skips
/// hidden dirs, `target/`, and `node_modules/`.
fn walk_files(base: &Path, current: &Path, cb: &mut dyn FnMut(&Path, &str)) {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Skip hidden, target, node_modules. (Note: `.claude/` is
        // explicitly listed in SCANNED_ROOTS; we walk INTO it from
        // its root entry, but skip other dot-dirs inside.)
        if name == "target" || name == "node_modules" {
            continue;
        }
        // Allow `.claude` only when it's the entry whose parent is
        // the workspace root — i.e., we're at depth 1 under base.
        if name.starts_with('.') && name != ".claude" {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_files(base, &path, cb);
        } else if ft.is_file() {
            let ext_ok = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| SCANNED_EXTENSIONS.contains(&e))
                .unwrap_or(false);
            if !ext_ok {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                let rel: PathBuf = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                cb(&rel, &content);
            }
        }
    }
}
