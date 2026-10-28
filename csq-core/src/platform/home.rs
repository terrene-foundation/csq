//! Shared home-directory resolution.
//!
//! Production semantics are **exactly** [`dirs::home_dir`] on every platform
//! — this module changes NOTHING about what a real user's csq install
//! resolves to. It exists so a single resolver can be redirected under test,
//! instead of every call site duplicating a `dirs::home_dir()` call that a
//! Windows test has no way to redirect.
//!
//! # Why setting `HOME` does not sandbox `dirs::home_dir()` on Windows
//!
//! On Windows, `dirs::home_dir()` resolves via
//! `SHGetKnownFolderPath(FOLDERID_Profile)` (`dirs-sys`'s
//! `known_folder_profile`) — a Win32 known-folder lookup keyed off the
//! process token. It does not read `HOME`, `USERPROFILE`, or any other
//! environment variable. Verified against the version this workspace
//! actually resolves (`dirs-sys 0.4.1`, `dirs 5.0.1` for the `csq` binary
//! crate — `cargo tree -p csq -i dirs`): `known_folder_profile` calls
//! `known_folder(Shell::FOLDERID_Profile)`, which is a bare
//! `SHGetKnownFolderPath` FFI call with no env lookup anywhere in its body.
//!
//! A test that follows `test-hermeticity.md` MUST-2 (set `HOME` to a
//! `TempDir`) therefore sandboxes every call site that reads `HOME`
//! directly, but NOT one that calls `dirs::home_dir()` — on Windows that
//! keeps resolving to the CI runner's real user profile regardless of
//! `HOME`, so a test can read and write the runner account's real files
//! while believing it is sandboxed.
//!
//! # The fix is test-only — production MUST NOT start honoring `HOME` on Windows
//!
//! Production code must not switch to reading `HOME` on Windows: Git Bash
//! sets `HOME` there (to an msys-style path), so doing so would silently
//! relocate a real user's csq state away from the native profile directory
//! `dirs::home_dir()` (and every other Windows tool) resolves to. Instead,
//! under the `test-utils` feature ONLY, an explicit `CSQ_HOME` override
//! takes precedence over `dirs::home_dir()`. Outside that feature `CSQ_HOME`
//! is never read, so it cannot appear in a production binary
//! (`--no-default-features --features cli` / `desktop`) or affect a real
//! user's resolution — see `rules/no-stubs.md` / `edition-safe-install.md`.

use std::path::PathBuf;

/// Resolves the current user's home directory.
///
/// Production semantics are exactly [`dirs::home_dir`] on every platform.
/// Under the `test-utils` feature, an explicit `CSQ_HOME` environment
/// override — set by the test sandboxing helpers alongside `HOME` — takes
/// precedence, so a test that redirects `HOME` (the standard
/// `test-hermeticity.md` MUST-2 pattern) can also redirect this resolver on
/// every platform, including Windows.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(feature = "test-utils")]
    {
        if let Some(overridden) = test_override() {
            return Some(overridden);
        }
    }
    dirs::home_dir()
}

/// The `test-utils`-gated override lookup, split out so the mutation proof
/// (`tests::mutation_proof_ignoring_override_reds`) can call it directly
/// without needing a real `dirs::home_dir()` result to compare against.
#[cfg(feature = "test-utils")]
fn test_override() -> Option<PathBuf> {
    std::env::var_os("CSQ_HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;

    /// The override MUST be visible to `home_dir()` and MUST take priority
    /// over whatever `dirs::home_dir()` would otherwise return — this is the
    /// property that makes a Windows test hermetic. Proof that removing the
    /// check breaks this: `mutation_proof_ignoring_override_reds` below.
    #[test]
    fn csq_home_override_redirects_resolution() {
        let _guard = crate::platform::test_env::lock();
        let prev = std::env::var_os("CSQ_HOME");
        let sandbox = std::path::Path::new("/nonexistent/sandbox/home-for-test");
        // SAFETY: env-test mutex held for the duration of this block; restored
        // before the guard drops.
        unsafe { std::env::set_var("CSQ_HOME", sandbox) };

        let resolved = home_dir();

        unsafe {
            match &prev {
                Some(v) => std::env::set_var("CSQ_HOME", v),
                None => std::env::remove_var("CSQ_HOME"),
            }
        }

        assert_eq!(
            resolved.as_deref(),
            Some(sandbox),
            "CSQ_HOME must redirect home_dir() even though the path does not \
             exist and is nowhere near the real dirs::home_dir() result"
        );
    }

    /// Empty `CSQ_HOME` is treated as unset — a test helper that does
    /// `cmd.env("CSQ_HOME", "")` by accident must not silently resolve to the
    /// process's cwd (`PathBuf::from("")`).
    #[test]
    fn empty_csq_home_is_ignored() {
        let _guard = crate::platform::test_env::lock();
        let prev = std::env::var_os("CSQ_HOME");
        // SAFETY: env-test mutex held for the duration of this block; restored
        // before the guard drops.
        unsafe { std::env::set_var("CSQ_HOME", "") };

        let resolved = test_override();

        unsafe {
            match &prev {
                Some(v) => std::env::set_var("CSQ_HOME", v),
                None => std::env::remove_var("CSQ_HOME"),
            }
        }

        assert_eq!(resolved, None, "empty CSQ_HOME must not resolve to cwd");
    }

    /// Mandatory mutation proof (per the dispatch instructions): with the
    /// `CSQ_HOME` check removed, `home_dir()` degrades to bare
    /// `dirs::home_dir()` and the override is silently ignored — i.e. this
    /// test asserts the CURRENT (correct) behaviour, and mutating
    /// `home_dir()` to skip `test_override()` must turn it red. Kept as a
    /// standing regression test; the actual mutate-and-restore run and its
    /// verbatim output are recorded in the PR description, not here (this
    /// module cannot re-execute a mutated copy of itself at test time).
    #[test]
    fn csq_home_override_differs_from_unset_resolution() {
        let _guard = crate::platform::test_env::lock();
        let prev = std::env::var_os("CSQ_HOME");
        unsafe { std::env::remove_var("CSQ_HOME") };
        let baseline = dirs::home_dir();
        let sandbox = std::path::Path::new("/nonexistent/sandbox/home-for-test-2");
        // SAFETY: env-test mutex held for the duration of this block; restored
        // before the guard drops.
        unsafe { std::env::set_var("CSQ_HOME", sandbox) };
        let overridden = home_dir();
        unsafe {
            match &prev {
                Some(v) => std::env::set_var("CSQ_HOME", v),
                None => std::env::remove_var("CSQ_HOME"),
            }
        }

        // Guard against a CI host whose real home genuinely IS the sandbox
        // path (impossible in practice — the sandbox path does not exist —
        // but stated so the assertion below is provably discriminating
        // rather than coincidentally true).
        assert_ne!(
            baseline.as_deref(),
            Some(sandbox),
            "test setup invariant: the real dirs::home_dir() must not already \
             equal the sandbox path, or this test cannot discriminate"
        );
        assert_eq!(overridden.as_deref(), Some(sandbox));
    }
}
