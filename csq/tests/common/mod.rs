//! Shared test-binary path resolution for `csq/tests/*_integration.rs`.
//!
//! Extracted from `cli_deps_install_integration.rs` (see `git show 6ce7bd56`),
//! which fixed this logic in ONE file and reported the remaining eight as
//! carrying the same latent defect rather than fixing them blind. This module
//! is that follow-up: one copy, adopted by all nine integration-test files
//! that previously duplicated it.
//!
//! Included via `#[path = "common/mod.rs"] mod common;` (not `mod common;`
//! from a `tests/common.rs` file) because each file under `tests/` compiles
//! as its own separate test-binary crate — there is no shared-crate mechanism
//! across them, so this file is textually included by every adopter rather
//! than linked once.
//!
//! Not every adopter calls every function here (e.g. only
//! `cli_deps_install_integration.rs` needs [`stub_cli_bin`]), so every item is
//! `#[allow(dead_code)]` — each inclusion compiles as its own crate and an
//! unused item would otherwise warn in every file that doesn't happen to call
//! it.
//!
//! ## Which fallback is actually load-bearing (verified 2026-09-13)
//!
//! Migrating exposed a nuance the original fix's commit message did not have
//! the evidence to state: `CARGO_BIN_EXE_csq` DOES resolve via
//! `std::env::var` at runtime for [`csq_bin`], because `csq` is a `[[bin]]`
//! in the SAME package as these tests — Cargo passes it as a real env var to
//! the test process, not only via the compile-time `env!` macro. Reproduced
//! directly: with `target/debug/csq` renamed aside and `CARGO_TARGET_DIR`
//! redirected, all 8 non-install adopters (which call only [`csq_bin`])
//! still passed 100% — the manifest-relative fallback was never reached.
//!
//! `CARGO_BIN_EXE_stub-cli` does NOT resolve the same way, because `stub-cli`
//! is declared in `csq-core`'s `Cargo.toml` — a DIFFERENT package — and
//! cross-package binary env vars require the unstable `-Zbindeps` feature.
//! [`stub_cli_bin`]'s fallback is therefore the one that is genuinely
//! exercised in practice, and the one the original defect lived in.
//! Reproduced: `cli_deps_install_integration.rs` at its pre-extraction
//! content, same parked-binary + redirected-`CARGO_TARGET_DIR` configuration,
//! scored 21 passed / 4 FAILED (`<path>/stub-cli: No such file or
//! directory`) — identical to the 2026-09-13 commit's own numbers. The
//! migrated, common-module version of the same file, identical
//! configuration, scored 25 passed / 0 failed.
//!
//! [`csq_bin`]'s fallback stays in place as real defense-in-depth (a
//! differently-shaped Cargo invocation, or a future Cargo version, could stop
//! setting the env var), but it is not the path that was ever observed to
//! fail.

use std::path::PathBuf;

/// The `<target>/debug` directory THIS test binary was built into.
///
/// Derived from `current_exe()` — an integration-test binary lives at
/// `<target>/debug/deps/<name>-<hash>`, so two parents up is `<target>/debug`
/// under ANY `CARGO_TARGET_DIR`.
///
/// WHY NOT the manifest-relative `<workspace>/target/debug` this used to build:
/// that path is fixed to the workspace root and does not follow
/// `CARGO_TARGET_DIR`, so it was correct only by ACCIDENT — in the main checkout
/// `<workspace>/target/debug/` happens to be populated, so the wrong path still
/// resolved to a real binary. In a git worktree with a cargo target-dir slot
/// (`scripts/worktree-new.sh` assigns one, redirecting builds to
/// `~/.cache/csq-worktree-target/slot-N`) that directory does not exist, and
/// four tests in `cli_deps_install_integration.rs` failed with
/// `<worktree>/target/debug/stub-cli: No such file or directory`.
///
/// Measured 2026-09-13 (`cli_deps_install_integration.rs`, pre-extraction):
/// 25/25 pass in the main checkout, 21/25 in a slot-assigned worktree.
/// Reproduced in the main checkout by parking `target/debug/stub-cli` aside —
/// the same 4 fail. That is the falsifying instrument: the accident, removed.
///
/// This matters beyond the inconvenience. Agents work in worktrees, so a full
/// `cargo test --workspace` there shows red they did not cause, and the natural
/// response is to narrow scope. A gate that is unreliable in the environment it
/// runs in trains people to work around it (`tooling-self-verification.md`
/// Rule 5).
///
/// NOTE on `CARGO_BIN_EXE_<name>`: Cargo sets it at COMPILE time for `env!`, not
/// at run time, so the `std::env::var` lookups in [`csq_bin`] / [`stub_cli_bin`]
/// never hit and this path is always the one taken. Left in place as a
/// no-cost override hook.
#[allow(dead_code)]
pub fn target_debug_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .and_then(|deps| deps.parent())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("target")
                .join("debug")
        })
}

/// Path to the built `csq` binary, resolved from the REAL target dir (see
/// [`target_debug_dir`]), not a manifest-relative guess.
#[allow(dead_code)]
pub fn csq_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_csq") {
        return PathBuf::from(p);
    }
    target_debug_dir().join("csq")
}

/// Path to the `stub-cli` test-fixture binary (`csq-core/tests/bin/stub_cli.rs`),
/// resolved the same way as [`csq_bin`].
#[allow(dead_code)]
#[cfg(unix)]
pub fn stub_cli_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_stub-cli") {
        return PathBuf::from(p);
    }
    let path = target_debug_dir().join("stub-cli");
    // `stub-cli` is a csq-core `[[bin]]`; a `-p csq` test run does not build it.
    // Without this check a missing binary surfaces as an unrelated-looking
    // failure deep inside a stub script ("stub-cli: No such file or directory",
    // exit 126), which has been misread as a real product regression.
    assert!(
        path.is_file(),
        "stub-cli is not built at {}; run `cargo build -p csq-core --bin stub-cli \
         --features test-utils` into the same CARGO_TARGET_DIR first",
        path.display()
    );
    path
}
