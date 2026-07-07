//! Edition-INVARIANT guard for the capability-layer MCP gate (T-M4.6).
//!
//! The pre-spawn capability-layer pipeline — including `mcp_gate` — MUST stay
//! kailash-FREE in BOTH editions. The enterprise PACT MCP-action policy
//! (`csq_trust_contract::mcp_baseline_verdict`, spec 25 §25.9) is a DISTINCT
//! daemon-gate contract surface and MUST NOT couple into this pre-spawn pipeline
//! (spec 10 §10.8.5) — the two MCP surfaces share no code.
//!
//! This guard is edition-INVARIANT (no `#[cfg]`): a leak would be AUTHORED in the
//! enterprise source-of-truth build (e.g. a `use csq_trust_contract::…` added to a
//! capability-layer file), so a community-only `#[cfg(not(feature = "enterprise"))]`
//! guard would never run where the leak originates. The scan reads its OWN crate
//! source via `CARGO_MANIFEST_DIR` — hermetic: no `$HOME`, no subprocess, no
//! process-env (`rules/test-hermeticity.md`).
//!
//! # Detection: import/PATH context, not comment-stripping
//!
//! A real coupling to the moat surface is a Rust path: `use csq_trust_contract::X;`,
//! `use crate::phase2b::Y;`, an inline `csq_trust_contract::Foo` reference, or a glob
//! `use …::*;`. So a forbidden token counts as a hit ONLY when it appears in
//! IMPORT/PATH context — adjacent (same line) to a `::` path separator, or
//! immediately after the `use` keyword (see [`token_in_path_context`]). Prose that
//! mentions a token as FREE TEXT — a doc comment ("this stays `kailash`-free", "the
//! phase2b tree") or a string/char literal ("http://x", `'"'`, a JSON fixture) — is
//! NOT `::`-adjacent, so it never matches. This needs NO comment/string/char/raw
//! lexing, which is the point: an earlier comment-stripping design desynced its
//! string-parity state machine on char literals (`'"'`, `b'"'`) and raw strings
//! already present in the tree, which could hide a real `use` behind a phantom
//! comment (a false-NEGATIVE; redteam R2, an internal journal entry) — exactly that failure this
//! removes.
//!
//! This is a FAST TRIPWIRE for the common forms, NOT an exhaustive lexer. It catches
//! direct / qualified / glob imports, inline `::`-paths, visibility-modified bare
//! uses (`pub(crate) use kailash;`), and `use csq_trust_contract as tc;` whole-crate
//! renames (the token sits right after `use`). It does NOT catch a grouped
//! module-segment alias (`use crate::{phase2b as p};`), an `extern crate` (legacy;
//! csq is edition 2021), a macro-generated path, or a coupling authored OUTSIDE
//! `src/capability_layer`. Those are deferred to the AUTHORITATIVE backstop — the
//! COMMUNITY BUILD:
//!
//! - A `crate::phase2b` reach (any form, aliased or not) is a community compile error
//!   because `phase2b` is a `#[cfg(enterprise)]` moat module ABSENT in the community
//!   edition.
//! - A `csq_trust_contract` coupling (any form) is a community compile error because
//!   the crate is enterprise-feature-gated and not compiled in the community edition.
//!   (`scripts/check-edition-leak.sh`'s `cargo tree` does NOT help here:
//!   `csq_trust_contract` is kailash-FREE, so it adds no kailash/eatp dependency edge
//!   to flag. cargo-tree catches a kailash/eatp DEP; this scan + the community compile
//!   catch a trust-contract SOURCE coupling.)
//!
//! The residual false-POSITIVE is rare and SAFE: a doc comment that literally shows
//! example `module::path` import code reds CI and prompts a human.
//!
//! NOTE on `kailash`/`eatp`: csq-core has NO kailash dependency (only the
//! `the enterprise seam crate` seam does), so a capability-layer `use kailash_governance::…`
//! cannot compile in EITHER edition — these are defensive placeholders, and the
//! cargo-tree dep-edge check is the real defense if csq-core ever gains a kailash dep.
//! The live, fireable catches are `csq_trust_contract`, `csq_audit_kailash`, `phase2b`.

use std::path::{Path, PathBuf};

/// Tokens whose appearance in capability-layer IMPORT/PATH context means the
/// kailash-free pre-spawn pipeline has coupled to the enterprise seam /
/// trust-contract.
///
/// - **Live crate-name + moat-path tokens (load-bearing):** `csq_trust_contract`
///   and `csq_audit_kailash` catch a direct import; `phase2b` catches a bare-name
///   re-export reach into the moat tree (csq-core re-exports trust-contract types
///   under bare names there, e.g. `pub use csq_trust_contract::CanonicalProjector;`
///   in `phase2b/governance_audit.rs`, so `use crate::phase2b::…::CanonicalProjector`
///   carries no crate-name token but IS a moat reach). These three are the fireable
///   structural catch.
/// - **Defensive crate-name tokens:** `kailash`, `eatp` — csq-core has no kailash
///   dependency (only the seam does), so a capability-layer `use kailash_*::…` cannot
///   compile here; these fire on no real coupling and the cargo-tree dep-edge check is
///   the real defense if csq-core ever gains a kailash dep (see the module doc).
/// - **Symbol tokens (convenience):** the specific T-M4.6 enterprise symbols — NOT
///   exhaustive. Any bare use of one of these requires an accompanying `use …::`
///   import that a crate-name / `phase2b` token already catches.
const FORBIDDEN: &[&str] = &[
    // Crate-name + moat-path tokens — the load-bearing structural catch.
    "kailash",
    "eatp",
    "csq_trust_contract",
    "csq_audit_kailash",
    "phase2b",
    // Convenience symbol tokens (T-M4.6 substrate; not exhaustive).
    "EnvelopeVerdict",
    "ActionGovernor",
    "mcp_baseline_verdict",
    "mcp_verdict",
    "McpPolicy",
    "NEVER_DELEGATED",
    "SessionAction",
];

/// `true` iff `tok` occurs in `src` as a whole identifier in IMPORT/PATH context:
/// same-line adjacent to `::`, or immediately after the `use` keyword. Prose and
/// string/char literals (free-text mentions) are NOT `::`-adjacent, so they never
/// match — no comment or string lexing is required. Every `use …::` / `::`-path /
/// `use <tok>` form IS detected; the module doc enumerates the forms this does NOT
/// detect (a grouped module-segment alias, `extern crate`, a macro path) and their
/// community-compile backstop. Whole-identifier boundaries prevent a substring match
/// (e.g. `kailash` inside `kailash_learning`).
fn token_in_path_context(src: &str, tok: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(rel) = src[from..].find(tok) {
        let start = from + rel;
        let end = start + tok.len();
        from = start + 1;

        // Whole-identifier boundary — reject a substring of a larger identifier.
        let before = src[..start].chars().next_back();
        let after = src[end..].chars().next();
        if before.is_some_and(&is_ident) || after.is_some_and(&is_ident) {
            continue;
        }

        // `tok::` or `::tok` on the SAME line — trim only spaces/tabs, never a
        // newline, so a prose mention at a line's end immediately followed by a
        // `::`-path on the NEXT line cannot spuriously match. rustfmt never
        // line-splits a `::` path segment, so same-line loses no real coupling.
        if src[end..].trim_start_matches([' ', '\t']).starts_with("::") {
            return true;
        }
        if src[..start].trim_end_matches([' ', '\t']).ends_with("::") {
            return true;
        }
        // `use tok` (a bare-crate import, e.g. `use kailash;`) — the token is
        // immediately preceded by the `use` keyword as the last word, covering any
        // visibility modifier (`pub use`, `pub(crate) use`, `pub(super) use`)
        // without false-matching an identifier that merely ends in "use"
        // (`misuse`, `excuse`).
        let line_start = src[..start].rfind('\n').map_or(0, |n| n + 1);
        if src[line_start..start].split_whitespace().last() == Some("use") {
            return true;
        }
    }
    false
}

/// The forbidden tokens present in `src` (import/path context). Empty = clean. The
/// shared primitive both tests below use, so the `mcp_gate` kailash-free assertion
/// and the whole-tree scan apply the identical rule.
fn forbidden_hits(src: &str) -> Vec<&'static str> {
    FORBIDDEN
        .iter()
        .copied()
        .filter(|t| token_in_path_context(src, t))
        .collect()
}

/// Recursively collect every `*.rs` file under `dir`.
fn rs_files(dir: &Path, acc: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rs_files(&path, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            acc.push(path);
        }
    }
}

/// The pre-spawn capability-layer source references no kailash / enterprise-seam /
/// trust-contract symbol, and does not reach into the moat `phase2b` tree (in
/// import/path context). A `use csq_trust_contract::…`, a kailash path, or a
/// `use crate::phase2b::…` added to any capability-layer file fails here — the
/// structural defense that the community MCP gate never gains a kailash dependency,
/// enforced in BOTH editions (spec 10 §10.8.5). See the module doc for the scan's
/// scope and the authoritative cargo-tree / community-compile backstops.
#[test]
fn capability_layer_source_references_no_kailash_symbol() {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/capability_layer"));
    assert!(
        root.is_dir(),
        "capability_layer source dir must exist at {}",
        root.display()
    );
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "expected .rs files under {}",
        root.display()
    );

    let mut violations = Vec::new();
    for f in &files {
        let src =
            std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
        for tok in forbidden_hits(&src) {
            // Report the first line where the token is in PATH context (not a mere
            // substring), so the message points at the real coupling, not a prose
            // mention earlier in the file. Path-context is same-line, so this
            // matches the whole-file scan's logic exactly.
            let line = src
                .lines()
                .enumerate()
                .find(|(_, l)| token_in_path_context(l, tok))
                .map(|(n, _)| n + 1)
                .unwrap_or(0);
            violations.push(format!(
                "{}:{line} references forbidden token `{tok}`",
                f.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "the pre-spawn capability-layer pipeline must stay kailash-free in BOTH \
         editions (spec 10 §10.8.5); the enterprise PACT MCP policy \
         (csq_trust_contract::mcp_baseline_verdict, spec 25 §25.9) is a distinct \
         daemon-gate surface and must not couple here. Found:\n{}",
        violations.join("\n")
    );
}

/// The `mcp_gate` stage is present AND its source is kailash-free — the test name's
/// two claims are BOTH asserted in the body (not delegated to the sibling
/// whole-tree scan), so the name is honest on its own: if the whole-tree scan were
/// ever deleted or its root drifted, this test still independently verifies the
/// `mcp_gate` file itself carries no forbidden path.
#[test]
fn mcp_gate_stage_present_and_kailash_free() {
    // Present.
    assert_eq!(csq_core::capability_layer::mcp_gate::STAGE, "mcp_gate");
    // Kailash-free — assert the mcp_gate source itself, independent of the sibling.
    let mcp_gate_rs = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/capability_layer/mcp_gate.rs"
    ));
    let src = std::fs::read_to_string(&mcp_gate_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", mcp_gate_rs.display()));
    let hits = forbidden_hits(&src);
    assert!(
        hits.is_empty(),
        "mcp_gate.rs must reference no kailash / seam / trust-contract / phase2b \
         path; found: {hits:?}"
    );
}

/// Pins the load-bearing contract of [`token_in_path_context`]: a real import is
/// NEVER missed (no false-NEGATIVE — the anti-leak direction), and the char-literal
/// / raw-string / prose constructs that desynced the previous comment-stripping
/// design (and that LIVE in the scanned tree — `find('"')` in logging.rs, `b'"'` in
/// struct_out.rs) produce NO hit. This is the regression test the earlier design
/// lacked, which let the desync blind spot ship (redteam R2, an internal journal entry).
#[test]
fn path_context_catches_imports_but_not_prose_or_literals() {
    // (1) Real imports in CODE → caught (the anti-leak property).
    assert!(
        forbidden_hits("use csq_trust_contract::EnvelopeVerdict;").contains(&"csq_trust_contract")
    );
    // `kailash` is a synthetic FORM assertion — no bare `kailash` crate exists (the
    // real moat crates are `kailash_*`, and csq-core has no kailash dep at all); this
    // pins the scanner's path-context logic, not a reachable coupling.
    assert!(forbidden_hits("use kailash::keys::TrustKeyPair;").contains(&"kailash"));
    assert!(forbidden_hits("use eatp;").contains(&"eatp")); // bare-crate import
    assert!(forbidden_hits("pub(crate) use kailash;").contains(&"kailash")); // visibility-modified bare use
                                                                             // `use <crate> as <alias>;` whole-crate rename — the token sits right after `use`
                                                                             // (R3-1A): the live csq_trust_contract coupling form, caught regardless of a
                                                                             // leading visibility modifier or a `#[cfg(feature = "enterprise")]` attribute.
    assert!(
        forbidden_hits("pub(crate) use csq_trust_contract as tc;").contains(&"csq_trust_contract")
    );
    assert!(
        forbidden_hits("#[cfg(feature = \"enterprise\")] use csq_trust_contract as tc;")
            .contains(&"csq_trust_contract")
    );
    assert!(
        forbidden_hits("let g: csq_trust_contract::ActionGovernor = todo!();")
            .contains(&"csq_trust_contract")
    );
    assert!(forbidden_hits("use csq_trust_contract::*;").contains(&"csq_trust_contract")); // glob
                                                                                           // (2) R1 fix: bare-name re-export reach into the moat tree → caught via `phase2b`.
    assert!(
        forbidden_hits("use crate::phase2b::governance_audit::CanonicalProjector;")
            .contains(&"phase2b"),
        "a bare-name re-export reach into the moat phase2b tree must trip `phase2b`"
    );
    // (3) R2 regression — the live-in-tree char-literal / raw-string / prose
    //     constructs that broke the old stripper must produce NO hit:
    assert!(
        forbidden_hits(r#"if remaining.find('"') == Some(0) { /* phase2b */ }"#).is_empty(),
        "a `'\"'` char literal + a `phase2b` block comment must not desync into a hit"
    );
    assert!(
        forbidden_hits(r####"let q = b'"'; // mentioning phase2b and kailash in prose"####)
            .is_empty(),
        "a `b'\"'` byte-char literal + prose in a `//` comment must not produce a hit"
    );
    assert!(
        forbidden_hits(r####"let j = r#"{"kailash": "phase2b"}"#;"####).is_empty(),
        "forbidden words as raw-string JSON data (not `::`-paths) must not hit"
    );
    // (4) THE adversarial leak-hide case from R2: a char literal + an unbalanced
    //     `/*` inside a string preceding a REAL moat import. The old stripper hid
    //     the `use`; path-context still surfaces it (no comment lexing to desync).
    let adversarial =
        "let q = '\"';\nlet s = \"/* phase2b\";\nuse crate::phase2b::Real;\nlet t = \"*/\";";
    assert!(
        forbidden_hits(adversarial).contains(&"phase2b"),
        "the R2 leak-hide construct must NOT hide the real `use crate::phase2b::Real;`"
    );
    // (5) Prose mentions (non-`::`) are NOT hits — doc comments may name the boundary.
    assert!(
        forbidden_hits("//! this stage stays kailash-free, separate from phase2b\n").is_empty()
    );
    assert!(
        forbidden_hits("// the SessionAction / EnvelopeVerdict enums live elsewhere\n").is_empty()
    );
    // (6) Whole-identifier boundary — a forbidden token as a substring is not a hit.
    assert!(forbidden_hits("use crate::kailash_learning::Foo;").is_empty()); // `kailash` ⊂ `kailash_learning`
                                                                             // An identifier ending in "use" (misuse/excuse) before a bare token is NOT a `use` import.
    assert!(forbidden_hits("let misuse = 0; let _ = kailash;").is_empty());
    // (7) Clean capability-layer code → no hits.
    assert!(forbidden_hits("use crate::capability_layer::state::PreSpawnState;").is_empty());
    // (8) DOCUMENTED blind spot (R3-1): a grouped module-segment alias is NOT a
    //     source-scan hit — the module doc defers it to the community-compile
    //     backstop (`phase2b` is a `#[cfg(enterprise)]` module absent in community,
    //     so this is a community compile error). This assertion pins the boundary:
    //     if a future change makes the scanner catch it, this test flips and the doc
    //     must be updated to match.
    assert!(forbidden_hits("use crate::{phase2b as p};").is_empty());
}
