//! Desktop→CLI shim refresh.
//!
//! The desktop app and the terminal CLI are the SAME single binary (per the
//! an internal workspace work), but they are installed by two independent channels:
//! the desktop `.app` is auto-updated by the Tauri updater, while the CLI at
//! `~/.local/bin/csq` is installed once by `install.sh` and never touched by a
//! desktop update. After a desktop auto-update the in-process daemon (running
//! the new bundle code) and the terminal CLI drift to different versions and
//! trip the version-skew guard on `csq run` / `login` / `status` / `doctor`.
//!
//! [`ensure_cli_shim`] closes that gap: on desktop launch it refreshes the CLI
//! binary so it is byte-identical to the running bundle.
//!
//! Two mechanisms are DELIBERATELY avoided:
//!
//! - **`cp`**: attaches `com.apple.provenance` on macOS → Gatekeeper SIGKILL
//!   (csq discovery `cp_provenance_gatekeeper_sigkill`). We write a fresh temp
//!   file then `atomic_replace` (rename) instead — the same primitive the
//!   in-place updater uses (`update/apply.rs`).
//! - **symlink into the `.app`**: `mode::detect` canonicalizes `current_exe()`,
//!   which resolves a symlink back into `…/Contents/MacOS/csq`, sees
//!   `/Contents/MacOS/`, and launches DESKTOP mode — so `csq` typed in a
//!   terminal would open the WebView app instead of the CLI. A real-file copy
//!   keeps `current_exe()` at the CLI path so CLI mode is selected correctly.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Outcome of [`ensure_cli_shim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimOutcome {
    /// Target did not exist; created it.
    Installed,
    /// Target existed as a regular file but differed from the source; replaced.
    Updated,
    /// Target was a symlink (or other non-regular file) — CLI-breaking under
    /// `mode::detect` — replaced with a real-file copy.
    ReplacedNonRegular,
    /// Target already byte-identical to the source; nothing to do.
    NoOp,
    /// Target resolves to the same file as the source (e.g. the bundle exe is
    /// itself on PATH); refused to copy onto self.
    SkippedSameFile,
}

/// Refresh `target` to a byte-identical real-file copy of `source` (the running
/// desktop binary). Idempotent: a no-op when already current. Best-effort
/// caller-facing (the desktop wiring logs failures non-fatally).
pub fn ensure_cli_shim(source: &Path, target: &Path) -> Result<ShimOutcome> {
    let link_meta = std::fs::symlink_metadata(target);
    let is_symlink = link_meta
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let exists = link_meta.is_ok();

    // Never copy onto ourselves (e.g. the bundle exe is itself on PATH and the
    // target resolves to the source). Apply the self-copy guard ONLY for
    // regular-file targets: a SYMLINK at the CLI path — even one pointing at the
    // source — MUST be replaced, because `mode::detect` canonicalizes it back
    // into the bundle and launches Desktop mode for a terminal `csq`.
    if !is_symlink {
        if let (Ok(s), Ok(t)) = (source.canonicalize(), target.canonicalize()) {
            if s == t {
                return Ok(ShimOutcome::SkippedSameFile);
            }
        }
    }

    let outcome = if !exists {
        ShimOutcome::Installed
    } else if is_symlink {
        // A symlink target breaks `csq` in the terminal (mode::detect resolves
        // it into the bundle → Desktop mode). Always replace it with a real copy.
        ShimOutcome::ReplacedNonRegular
    } else if files_identical(source, target).unwrap_or(false) {
        return Ok(ShimOutcome::NoOp);
    } else {
        ShimOutcome::Updated
    };

    let bytes = std::fs::read(source)
        .with_context(|| format!("read source binary {}", source.display()))?;
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // Write a fresh temp file + atomic_replace (rename) — NEVER `cp`
    // (provenance/Gatekeeper) and NEVER a symlink (mode::detect canonicalize trap).
    let tmp = crate::platform::fs::unique_tmp_path(target);
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write temp shim {}", tmp.display()));
    }
    if let Err(e) = set_executable(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("chmod 0o755 {}", tmp.display()));
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "atomic replace of {} failed: {e}",
            target.display()
        ));
    }
    Ok(outcome)
}

/// Resolve the *source* binary the shim copies from, given the running
/// executable (`current_exe()`).
///
/// On the enterprise macOS build the running binary is `…/Contents/MacOS/csq`,
/// which is signed `--deep` as the bundle's **main** executable — its signature
/// is bound to `Contents/Info.plist` + the sealed-resources envelope. Copied to
/// a standalone path (`~/.local/bin/csq`), that bundle-bound signature is invalid
/// (`invalid Info.plist`), so a hardened-runtime Gatekeeper exec SIGKILLs the CLI
/// (exit 137) — GH an internal ticket. The provenance xattr the copy also picks up is
/// incidental; the broken signature is the load-bearing cause.
///
/// The enterprise signing runbook (`docs/release-signing.md` §2a) ships a
/// **standalone-signed** copy of the same binary at `…/Contents/Helpers/csq-cli`
/// — signed WITHOUT bundle binding, so its signature stays valid at any path.
/// When that helper is present we copy IT; the copied file is then a real,
/// standalone-valid binary that runs in the terminal and (being byte-stable)
/// makes [`ensure_cli_shim`]'s identity check a clean no-op on later launches
/// (no re-sign churn, no recurrence loop).
///
/// Fallback (no helper present — the community ad-hoc build, which does NOT
/// exhibit an internal ticket, or any non-bundle layout): return `current_exe` unchanged, i.e.
/// today's behavior.
pub fn resolve_shim_source(current_exe: &Path) -> PathBuf {
    // The helper sits at `…/Contents/Helpers/csq-cli`, sibling to the running
    // exe's `…/Contents/MacOS/` directory. Only look for it when the running exe
    // is under a `Contents/MacOS/` bundle layout.
    if let Some(macos_dir) = current_exe.parent() {
        if macos_dir.file_name().and_then(|n| n.to_str()) == Some("MacOS") {
            if let Some(contents_dir) = macos_dir.parent() {
                let helper = contents_dir.join("Helpers").join("csq-cli");
                // The `is_file()` → later `read()` (in `ensure_cli_shim`) gap is a
                // TOCTOU window, but it is bounded by the same-user / in-bundle
                // threat model: swapping `Contents/Helpers/csq-cli` requires write
                // access inside the running, Gatekeeper-validated `.app` bundle —
                // a strictly larger compromise this code neither creates nor widens.
                if helper.is_file() {
                    return helper;
                }
            }
        }
    }
    current_exe.to_path_buf()
}

/// Resolve the CLI shim target: `~/.local/bin/csq` (the canonical `install.sh`
/// location) whenever anything already sits there, else the on-PATH `csq` when
/// it is OUTSIDE an app bundle / AppImage, else `~/.local/bin/csq` as the
/// create-path. Returns `None` only when no home directory resolves and no
/// suitable on-PATH `csq` exists.
///
/// **The canonical location outranks the `$PATH` hit, and that ordering is
/// load-bearing.** This function answers "which csq installation must this app
/// keep in sync with the bundle" — NOT "which csq would a subprocess get". The
/// desktop app resolves the second question through a `$PATH` it seeds itself
/// in `augment_subprocess_path`, which prepends `/opt/homebrew/bin`,
/// `/opt/homebrew/sbin` and `/usr/local/bin` AHEAD of `~/.local/bin`. That
/// ordering is right for locating third-party CLIs (claude / codex / gemini)
/// and wrong for choosing which csq to overwrite. Scope of the claim: the
/// augmentation SKIPS any entry already on the inherited `PATH`, so on a host
/// where both locations are already present in the operator's own order this is
/// a no-op for them and `~/.local/bin` can win. Under the launch context that
/// motivates the augmentation at all — Finder/Dock, i.e. the system-default
/// `PATH`, which carries neither — the prepend applies in full and
/// [`crate::cli_deps::install_path::find_in_path`] returns the homebrew copy,
/// while the operator's own interactive shell runs the `~/.local/bin` one. The shim refresh then keeps a binary nobody runs current
/// and lets the binary everybody runs drift — producing exactly the
/// daemon-vs-CLI version skew the refresh exists to prevent (see this module's
/// header). Measured on the maintainer host 2026-09-12: `.app` 2.18.0 and
/// `/opt/homebrew/bin/csq` byte-identical at 2.18.0 (so the refresh was a
/// silent `NoOp`) against `~/.local/bin/csq` 2.19.0, daemon spawning from the
/// stale path.
///
/// Existence — not regular-file-ness — is the test, because a SYMLINK at the
/// canonical path is precisely the `mode::detect` trap [`ensure_cli_shim`]
/// exists to replace ([`ShimOutcome::ReplacedNonRegular`]). Skipping a symlink
/// here would route the refresh to some other path and leave the trap in place.
pub fn resolve_shim_target() -> Option<PathBuf> {
    // `crate::platform::home::home_dir()`: exactly `dirs::home_dir()` in
    // production (test-hermeticity.md Windows hole fix — see that module's
    // doc comment). Previously this read `$HOME` directly, which returned
    // `None` on native Windows outside Git Bash (no `HOME` set) even though
    // every other call site in csq resolved the profile dir via `dirs`.
    let canonical =
        crate::platform::home::home_dir().map(|home| home.join(".local").join("bin").join("csq"));
    let canonical_occupied = canonical.as_ref().is_some_and(|c| canonical_is_occupied(c));
    resolve_shim_target_from(
        canonical,
        canonical_occupied,
        crate::cli_deps::install_path::find_in_path("csq"),
    )
}

/// Is a REPLACEABLE thing sitting at the canonical CLI path?
///
/// `symlink_metadata` and NOT `metadata`, and the difference is load-bearing
/// for exactly one input: a DANGLING symlink. `metadata()` follows the link,
/// fails to stat the missing referent, and reports the path as free — so the
/// refresh would route to the `$PATH` hit and leave the dangling link in place.
/// That link is the `mode::detect` canonicalize trap: a `csq` there resolves
/// into the bundle and runs the terminal CLI in Desktop mode.
/// [`ensure_cli_shim`] exists to replace it ([`ShimOutcome::ReplacedNonRegular`]),
/// and can only do so if this predicate reports it occupied.
///
/// A DIRECTORY is excluded, and that exclusion is not cosmetic. This path does
/// not only receive the shim copy — `resolve_managed_daemon_exe` falls through
/// to [`resolve_shim_target`] whenever `current_exe()` is inside the bundle,
/// which is every Finder launch, so it also becomes the launchd plist's
/// `ProgramArguments[0]`. Claiming a directory here would make `ensure_cli_shim`
/// fail with a non-fatal warn (recoverable) AND point the managed daemon's exec
/// at a directory (not recoverable — the daemon can never start). Treating it as
/// unoccupied instead falls through to the `$PATH` hit, which at worst refreshes
/// a different real binary.
///
/// Extracted from [`resolve_shim_target`] so the predicate PRODUCTION uses is
/// the one under test — a test that recomputes `symlink_metadata` itself proves
/// a std-library fact and leaves this line unpinned.
fn canonical_is_occupied(path: &Path) -> bool {
    match path.symlink_metadata() {
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// [`resolve_shim_target`]'s decision, with its two environment reads
/// (`$HOME`, `$PATH`) injected.
///
/// Split out so the PRECEDENCE is testable without mutating process-global
/// environment — `test-hermeticity.md` forbids the `$HOME`/`$PATH` swap this
/// would otherwise need, and an env-locked test would serialize against every
/// other test in the crate. Same extraction the sibling
/// `version_output_is_enterprise` took in the desktop crate.
fn resolve_shim_target_from(
    canonical: Option<PathBuf>,
    canonical_occupied: bool,
    path_hit: Option<PathBuf>,
) -> Option<PathBuf> {
    if canonical_occupied {
        if let Some(canonical) = canonical {
            return Some(canonical);
        }
    }
    if let Some(p) = path_hit {
        let s = p.to_string_lossy();
        // Skip a PATH hit inside the desktop bundle / AppImage — copying onto or
        // next to the bundle is wrong; fall through to ~/.local/bin.
        let in_bundle =
            s.contains("/Contents/MacOS/") || s.contains(".app/") || s.contains(".AppImage");
        if !in_bundle {
            return Some(p);
        }
    }
    canonical
}

/// True iff both files exist with identical length AND identical bytes. Length
/// is checked first so a differently-sized build short-circuits without reading
/// the full binary.
fn files_identical(a: &Path, b: &Path) -> Result<bool> {
    let (ma, mb) = (std::fs::metadata(a)?, std::fs::metadata(b)?);
    if ma.len() != mb.len() {
        return Ok(false);
    }
    Ok(std::fs::read(a)? == std::fs::read(b)?)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("set 0o755 on {}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_exe(path: &Path, content: &[u8]) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn installs_when_target_missing() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"binary-v2");
        let target = dir.path().join(".local/bin/csq");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::Installed);
        assert_eq!(std::fs::read(&target).unwrap(), b"binary-v2");
        // Real file, NOT a symlink (mode::detect canonicalize trap defense).
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn updates_when_target_stale() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"binary-v2-longer");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"binary-v1");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::Updated);
        assert_eq!(std::fs::read(&target).unwrap(), b"binary-v2-longer");
    }

    #[test]
    fn noop_when_already_identical() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"same-bytes");
        let target = dir.path().join(".local/bin/csq");
        write_exe(&target, b"same-bytes");

        let outcome = ensure_cli_shim(&src, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::NoOp);
    }

    #[cfg(unix)]
    #[test]
    fn replaces_symlink_target_with_real_copy() {
        // A prior (buggy) symlink install must be replaced by a real file —
        // otherwise mode::detect canonicalizes into the bundle and launches
        // Desktop mode for a terminal `csq`.
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("App.app/Contents/MacOS/csq");
        write_exe(&bundle, b"bundle-bytes");
        let target = dir.path().join(".local/bin/csq");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&bundle, &target).unwrap();
        assert!(std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());

        let outcome = ensure_cli_shim(&bundle, &target).unwrap();
        assert_eq!(outcome, ShimOutcome::ReplacedNonRegular);
        // Now a real file, not a symlink.
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"bundle-bytes");
    }

    #[test]
    fn skips_when_target_is_source() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"self");
        let outcome = ensure_cli_shim(&src, &src).unwrap();
        assert_eq!(outcome, ShimOutcome::SkippedSameFile);
    }

    #[test]
    fn shim_source_prefers_standalone_helper_when_present() {
        // Simulate a bundle layout: …/Contents/MacOS/csq (running) +
        // …/Contents/Helpers/csq-cli (standalone-signed helper, an internal ticket).
        let dir = TempDir::new().unwrap();
        let macos = dir.path().join("Code Squad Q.app/Contents/MacOS/csq");
        write_exe(&macos, b"bundle-main-deep-signed");
        let helper = dir.path().join("Code Squad Q.app/Contents/Helpers/csq-cli");
        write_exe(&helper, b"standalone-signed");

        assert_eq!(resolve_shim_source(&macos), helper);
    }

    #[test]
    fn shim_source_falls_back_to_exe_when_helper_absent() {
        // Bundle layout but NO helper (community ad-hoc build / pre-an internal ticket-fix).
        let dir = TempDir::new().unwrap();
        let macos = dir.path().join("App.app/Contents/MacOS/csq");
        write_exe(&macos, b"bundle-main");
        // No Contents/Helpers/csq-cli.
        assert_eq!(resolve_shim_source(&macos), macos);
    }

    #[test]
    fn shim_source_falls_back_outside_bundle_layout() {
        // A plain on-PATH binary (Linux, dev cargo build, /usr/local/bin) — no
        // Contents/MacOS/ ancestry, so the helper probe never fires.
        let dir = TempDir::new().unwrap();
        let exe = dir.path().join("usr/local/bin/csq");
        write_exe(&exe, b"plain");
        // Even a stray Helpers dir elsewhere must NOT be picked up.
        assert_eq!(resolve_shim_source(&exe), exe);
    }

    #[test]
    fn shim_source_ignores_helper_that_is_a_directory() {
        // A `csq-cli` that is a directory (not a regular file) must be skipped —
        // `is_file()` guards the copy source.
        let dir = TempDir::new().unwrap();
        let macos = dir.path().join("App.app/Contents/MacOS/csq");
        write_exe(&macos, b"main");
        std::fs::create_dir_all(dir.path().join("App.app/Contents/Helpers/csq-cli")).unwrap();
        assert_eq!(resolve_shim_source(&macos), macos);
    }

    // ── resolve_shim_target precedence ────────────────────────────────
    //
    // Each of these RUNS on every platform: the decision is exercised through
    // `resolve_shim_target_from`, whose inputs are injected, so no case depends
    // on the host actually carrying a `/opt/homebrew/bin/csq`.

    /// The regression that motivated the change. A host with BOTH a homebrew
    /// `csq` (which the desktop app's own `augment_subprocess_path` ranks first
    /// on `$PATH`) and the canonical `~/.local/bin/csq` must refresh the
    /// CANONICAL one — the binary the operator's shell actually runs.
    ///
    /// Falsifying result, named up front: before the fix this returned
    /// `/opt/homebrew/bin/csq`, i.e. the `path_hit`.
    #[test]
    fn shim_target_prefers_canonical_over_path_hit() {
        let canonical = PathBuf::from("/home/u/.local/bin/csq");
        let got = resolve_shim_target_from(
            Some(canonical.clone()),
            true,
            Some(PathBuf::from("/opt/homebrew/bin/csq")),
        );
        assert_eq!(got, Some(canonical));
    }

    /// The canonical path is only preferred when something is THERE. A host
    /// that installed csq solely to `/usr/local/bin` keeps that target, so the
    /// fix does not strand single-location installs.
    #[test]
    fn shim_target_falls_back_to_path_hit_when_canonical_absent() {
        let hit = PathBuf::from("/usr/local/bin/csq");
        let got = resolve_shim_target_from(
            Some(PathBuf::from("/home/u/.local/bin/csq")),
            false,
            Some(hit.clone()),
        );
        assert_eq!(got, Some(hit));
    }

    /// A `$PATH` hit INSIDE the bundle is still skipped — copying onto or next
    /// to the running `.app` is wrong — and the canonical create-path is used.
    #[test]
    fn shim_target_skips_in_bundle_path_hit() {
        let canonical = PathBuf::from("/home/u/.local/bin/csq");
        for hit in [
            "/Applications/Code Squad Q.app/Contents/MacOS/csq",
            "/opt/x/csq.AppImage",
        ] {
            let got =
                resolve_shim_target_from(Some(canonical.clone()), false, Some(PathBuf::from(hit)));
            assert_eq!(got, Some(canonical.clone()), "hit {hit}");
        }
    }

    /// With no home AND only an in-bundle `$PATH` hit there is no legitimate
    /// target — the caller must skip the refresh rather than guess.
    #[test]
    fn shim_target_is_none_without_home_or_usable_path_hit() {
        let got = resolve_shim_target_from(
            None,
            false,
            Some(PathBuf::from(
                "/Applications/Code Squad Q.app/Contents/MacOS/csq",
            )),
        );
        assert_eq!(got, None);
    }

    /// `canonical_is_occupied` over all four on-disk shapes, calling the
    /// function PRODUCTION calls rather than recomputing the predicate here.
    ///
    /// The DANGLING-symlink row is the one that discriminates. Falsifying
    /// result, named up front: swap `symlink_metadata` for `metadata` in
    /// `canonical_is_occupied` and that row flips to `false` — the refresh
    /// would then route to the `$PATH` hit and leave a `mode::detect` trap
    /// symlink at the canonical path. The other three rows survive that
    /// mutation, which is precisely why testing only them proves nothing.
    #[cfg(unix)]
    #[test]
    fn canonical_is_occupied_covers_every_on_disk_shape() {
        let dir = TempDir::new().unwrap();

        let regular = dir.path().join("regular");
        write_exe(&regular, b"bin");
        assert!(canonical_is_occupied(&regular), "regular file is occupied");

        let referent = dir.path().join("referent");
        write_exe(&referent, b"bin");
        let live_link = dir.path().join("live-link");
        std::os::unix::fs::symlink(&referent, &live_link).unwrap();
        assert!(
            canonical_is_occupied(&live_link),
            "symlink to an existing file is occupied"
        );

        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("gone"), &dangling).unwrap();
        assert!(
            canonical_is_occupied(&dangling),
            "a DANGLING symlink is still occupied — metadata() would say otherwise, \
             and ensure_cli_shim must be routed here to replace the mode::detect trap"
        );

        let a_directory = dir.path().join("a-directory");
        std::fs::create_dir_all(&a_directory).unwrap();
        assert!(
            !canonical_is_occupied(&a_directory),
            "a DIRECTORY must NOT count as occupied — this path also becomes the \
             launchd plist's ProgramArguments[0] via resolve_managed_daemon_exe, and a \
             directory there is a daemon that can never exec"
        );

        assert!(
            !canonical_is_occupied(&dir.path().join("absent")),
            "nothing there is not occupied"
        );
    }

    /// A symlink at the canonical path still wins the precedence decision, so
    /// `ensure_cli_shim` is routed at it and can replace it.
    #[cfg(unix)]
    #[test]
    fn shim_target_treats_canonical_symlink_as_occupied() {
        let dir = TempDir::new().unwrap();
        let canonical = dir.path().join(".local/bin/csq");
        std::fs::create_dir_all(canonical.parent().unwrap()).unwrap();
        let bundle = dir.path().join("Bundle.app/Contents/MacOS/csq");
        write_exe(&bundle, b"bundle");
        std::os::unix::fs::symlink(&bundle, &canonical).unwrap();

        let got = resolve_shim_target_from(
            Some(canonical.clone()),
            canonical_is_occupied(&canonical),
            Some(PathBuf::from("/opt/homebrew/bin/csq")),
        );
        assert_eq!(got, Some(canonical));
    }

    #[cfg(unix)]
    #[test]
    fn shim_target_is_executable_0755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("bundle/csq");
        write_exe(&src, b"x");
        let target = dir.path().join(".local/bin/csq");
        ensure_cli_shim(&src, &target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "shim must be executable");
    }
}
