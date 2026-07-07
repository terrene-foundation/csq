//! Codex slot binding predicates — surface-agnostic-equivalent of
//! `gemini/provisioning.rs:300-320`. Codex bindings live at
//! `credentials/codex-<N>.json` via `canonical_path_for(.., Surface::Codex)`.

use crate::credentials::file::{canonical_path_for, load as cred_load};
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

/// Returns the canonical credential-file path for a Codex slot.
pub fn binding_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    canonical_path_for(base_dir, slot, Surface::Codex)
}

/// Whether `slot` has a Codex credential file on disk. Single
/// `symlink_metadata` syscall — no JSON parse. Treats a dangling symlink
/// as "bound" (same posture as `is_gemini_bound_slot` / FR-CLI-05; refusing
/// a setkey against a dangling link is safer because the link can later
/// be repaired). MUST use `symlink_metadata`, NOT `Path::exists` (which
/// follows symlinks and treats dangling links as absent — wrong posture).
pub fn is_codex_bound_slot(base_dir: &Path, slot: AccountNum) -> bool {
    std::fs::symlink_metadata(binding_path(base_dir, slot)).is_ok()
}

/// True iff slot has a spawn-admissible Codex credential file
/// (`is_codex_bound_slot`) whose payload does NOT parse via
/// `credentials::file::load` (corrupt JSON, IO error, or other
/// `CredentialError` variant). Single definition shared by
/// `csq probe --all` (#515 / mirror #514). NOT called from
/// `probe_slot` — that path reads the credential once and matches the
/// Result directly (read-once invariant; see synthesis §"Note on
/// read-once invariant").
pub fn is_codex_corrupt_bound(base_dir: &Path, slot: AccountNum) -> bool {
    is_codex_bound_slot(base_dir, slot) && cred_load(&binding_path(base_dir, slot)).is_err()
}

/// True iff `credentials/codex-<slot>.json` exists (i.e.
/// `is_codex_bound_slot(base, slot)` is `true`) AND the file parses
/// successfully via `credentials::file::load` BUT the parsed
/// `CredentialFile` does NOT carry a Codex variant
/// (`cf.codex().is_none()`).
///
/// Distinguishes the **wrong-variant** case (operator wrote an
/// Anthropic-shape `claudeAiOauth` payload to a Codex-prefixed
/// path; an internal ticket) from the **corrupt** case (`is_codex_corrupt_bound`;
/// #515). Today's `CredentialFile` parser is 2-variant untagged
/// (Anthropic + Codex) at `csq-core/src/credentials/mod.rs:38-48`;
/// a wrong-variant `Ok(cf)` therefore always means `cf` is the
/// Anthropic variant. The two predicates are mutually exclusive
/// per-load-Result by Rust's type system (Result is one-of) — pinned
/// by the regression test below.
pub fn is_codex_wrong_variant_bound(base_dir: &Path, slot: AccountNum) -> bool {
    if !is_codex_bound_slot(base_dir, slot) {
        return false;
    }
    match cred_load(&binding_path(base_dir, slot)) {
        Ok(cf) => cf.codex().is_none(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn write_valid_codex(dir: &Path, n: u16) {
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some(format!("uuid-{n}")),
                access_token: format!("eyJ.codex-{n}.sig"),
                refresh_token: Some(format!("rt_{n}")),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        let path = binding_path(dir, slot(n));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::credentials::file::save(&path, &creds).unwrap();
    }

    fn write_corrupt_codex(dir: &Path, n: u16) {
        let path = binding_path(dir, slot(n));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not valid json").unwrap();
    }

    fn write_wrong_variant_codex(dir: &Path, n: u16) {
        // Anthropic-shape payload at the Codex-prefixed path. Synthetic-token
        // discipline per security.md §2 + 03-security-review.md §3.4:
        // - accessToken: "sk-ant-oat01-x" — live OAuth prefix + 1-char synthetic
        //   suffix (well under 20-char synthetic budget).
        // - refreshToken: "rt" — synthetic.
        // - expiresAt: 4102444800000 — project-canonical year-2100 ms literal
        //   (feedback_no_test_timebombs).
        let path = binding_path(dir, slot(n));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"rt","expiresAt":4102444800000,"scopes":[]}}"#,
        )
        .unwrap();
    }

    #[test]
    fn is_codex_bound_slot_returns_false_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!is_codex_bound_slot(dir.path(), slot(5)));
    }

    #[test]
    fn is_codex_bound_slot_returns_true_after_write() {
        let dir = TempDir::new().unwrap();
        write_valid_codex(dir.path(), 5);
        assert!(is_codex_bound_slot(dir.path(), slot(5)));
    }

    #[test]
    fn is_codex_corrupt_bound_returns_false_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!is_codex_corrupt_bound(dir.path(), slot(5)));
    }

    #[test]
    fn is_codex_corrupt_bound_returns_false_for_valid_binding() {
        let dir = TempDir::new().unwrap();
        write_valid_codex(dir.path(), 5);
        assert!(!is_codex_corrupt_bound(dir.path(), slot(5)));
    }

    #[test]
    fn is_codex_corrupt_bound_returns_true_for_corrupt_binding() {
        let dir = TempDir::new().unwrap();
        write_corrupt_codex(dir.path(), 5);
        assert!(is_codex_corrupt_bound(dir.path(), slot(5)));
    }

    #[test]
    fn is_codex_corrupt_and_wrong_variant_are_mutually_exclusive() {
        // Four reachable file states for a single slot. At most ONE of
        // (is_codex_corrupt_bound, is_codex_wrong_variant_bound) returns true
        // per state — pins ADR-2's mutually-exclusive-by-type-system claim
        // and defends FM-3 (predicate mutual-exclusivity inversion).

        // (1) Corrupt file: not-JSON → load returns Err.
        let dir = TempDir::new().unwrap();
        write_corrupt_codex(dir.path(), 1);
        assert!(is_codex_corrupt_bound(dir.path(), slot(1)));
        assert!(!is_codex_wrong_variant_bound(dir.path(), slot(1)));

        // (2) Wrong-variant file: Anthropic shape at Codex path.
        let dir = TempDir::new().unwrap();
        write_wrong_variant_codex(dir.path(), 2);
        assert!(!is_codex_corrupt_bound(dir.path(), slot(2)));
        assert!(is_codex_wrong_variant_bound(dir.path(), slot(2)));

        // (3) Valid Codex file: load Ok, cf.codex() is_some.
        let dir = TempDir::new().unwrap();
        write_valid_codex(dir.path(), 3);
        assert!(!is_codex_corrupt_bound(dir.path(), slot(3)));
        assert!(!is_codex_wrong_variant_bound(dir.path(), slot(3)));

        // (4) Unbound: no codex-<N>.json on disk.
        let dir = TempDir::new().unwrap();
        assert!(!is_codex_corrupt_bound(dir.path(), slot(4)));
        assert!(!is_codex_wrong_variant_bound(dir.path(), slot(4)));
    }
}
