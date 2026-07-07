//! M2 T2.7 — community-edition purity guard.
//!
//! `csq-ledger` is the community (Apache-2.0, Terrene Foundation-owned),
//! self-contained transparency-log server. It MUST stay free of the proprietary
//! the enterprise edition / `eatp` crates — the enterprise edition's attestation depth lives
//! behind the `the enterprise seam crate` seam, never in the community ledger
//! (`rules/independence.md` dog/tail model; spec 18 edition seam).
//!
//! # Why an import guard and not a bare-word grep
//!
//! T2.7's literal acceptance criterion was `grep -r 'kailash' csq-ledger/src
//! returns 0`. The bare word trips on the three doc-comments that *document the
//! absence* of the dependency (`lib.rs`, `merkle.rs`, `Cargo.toml`) — removing
//! those valuable comments to satisfy a crude grep would be strictly worse. The
//! real invariant is **no kailash/eatp import or path in the code** — which this
//! test enforces precisely, ignoring comments. The structural backstop is
//! `csq-ledger/Cargo.toml`: it declares no kailash/eatp dependency, so any
//! `use kailash::` / `eatp::` would fail to compile regardless of this test.

use std::fs;
use std::path::Path;

/// Tokens that indicate a real the enterprise edition / eatp *usage* (import or path),
/// distinct from an English-prose mention in a comment.
const FORBIDDEN: &[&str] = &["use kailash", "kailash::", "kailash_", "use eatp", "eatp::"];

#[test]
fn csq_ledger_source_has_no_kailash_or_eatp_usage() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan_dir(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "csq-ledger (community edition) must stay kailash/eatp-free; found {} usage(s):\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}

fn scan_dir(dir: &Path, offenders: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read csq-ledger src dir") {
        let path = entry.expect("read dir entry").path();
        if path.is_dir() {
            scan_dir(&path, offenders);
        } else if path.extension().is_some_and(|e| e == "rs") {
            scan_file(&path, offenders);
        }
    }
}

fn scan_file(path: &Path, offenders: &mut Vec<String>) {
    let text = fs::read_to_string(path).expect("read .rs file");
    for (idx, line) in text.lines().enumerate() {
        // Strip the line comment: the ONLY legitimate "kailash"/"eatp" mentions
        // are doc-comments (`//!` / `///`) documenting the absence of the dep.
        // `split("//").next()` keeps just the code portion before any comment.
        let code = line.split("//").next().unwrap_or("");
        if let Some(tok) = FORBIDDEN.iter().find(|t| code.contains(**t)) {
            offenders.push(format!(
                "{}:{}: `{tok}` in `{}`",
                path.display(),
                idx + 1,
                line.trim()
            ));
        }
    }
}

/// The authoritative structural backstop: csq-ledger's `Cargo.toml` MUST NOT
/// declare a `kailash*` / `eatp` dependency. This is immune to source
/// comment-parsing — if no such dependency is declared, `use kailash::` /
/// `eatp::` cannot compile regardless of what the source scan sees. We assert it
/// explicitly so the test OWNS the invariant rather than merely echoing it
/// (security-reviewer LOW-1, an internal journal entry).
#[test]
fn csq_ledger_cargo_toml_declares_no_kailash_or_eatp_dependency() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = fs::read_to_string(&manifest).expect("read csq-ledger Cargo.toml");
    let mut offenders = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        // Strip TOML `#` comments — the manifest documents the absence of the
        // dep in a comment, which must not trip the scan.
        let code = line.split('#').next().unwrap_or("").trim();
        // A dependency declaration is `<name> = ...` or `<name>.workspace`.
        // Match a kailash*/eatp crate name at the start of a dep line.
        let is_dep_decl = code
            .split(['=', '.', ' '])
            .next()
            .map(|name| {
                let n = name.trim();
                n == "eatp" || n.starts_with("kailash")
            })
            .unwrap_or(false);
        if is_dep_decl && (code.contains('=') || code.contains(".workspace")) {
            offenders.push(format!("Cargo.toml:{}: `{}`", idx + 1, line.trim()));
        }
    }
    assert!(
        offenders.is_empty(),
        "csq-ledger Cargo.toml must declare no kailash/eatp dependency; found:\n{}",
        offenders.join("\n")
    );
}
