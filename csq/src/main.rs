//! csq — single-binary dispatcher.
//!
//! Detects the runtime mode (CLI vs desktop) and routes to the appropriate
//! entry point. Mode detection logic lives in `mode.rs`. Mode bodies live in
//! `cli/` and `desktop/`, both gated by Cargo features so a `--features cli`
//! release strips Tauri/WebView entirely (and vice versa).

#![cfg_attr(
    all(feature = "desktop", not(any(feature = "cli", debug_assertions))),
    windows_subsystem = "windows"
)]

mod mode;

#[cfg(feature = "cli")]
mod cli;

#[cfg(feature = "desktop")]
mod desktop;

/// The edition this binary was BUILT as — a compile-time, unspoofable const
/// driven by the `enterprise` Cargo feature. This is the "which edition did I
/// install" signal, surfaced in `csq --version`, `csq doctor`, and the desktop
/// header badge. It is DISTINCT from the runtime audit dialect selected by
/// `CSQ_AUDIT_EDITION` (`csq_core::audit::multi_sig::Edition`): that env var
/// picks the 4-level vs 6-level audit grammar at run time, whereas this reflects
/// what was actually compiled. Names per `rules/terrene-naming.md`: community =
/// `csq`, enterprise = `csq-ee`; the invoked command stays `csq` for both.
/// Defined at the crate root (not under the feature-gated `cli`/`desktop`
/// modules) so both surfaces can read it in any feature combination.
#[cfg(feature = "enterprise")]
pub(crate) const BUILD_EDITION: &str = "enterprise";
#[cfg(not(feature = "enterprise"))]
pub(crate) const BUILD_EDITION: &str = "community";

/// Human-readable edition label, e.g. `Enterprise (csq-ee)` / `Community (csq)`.
pub(crate) fn edition_label() -> &'static str {
    match BUILD_EDITION {
        "enterprise" => "Enterprise (csq-ee)",
        _ => "Community (csq)",
    }
}

/// `--version` string carrying the edition suffix, e.g. `2.16.2 (community)`.
/// `concat!(env!(...), ...)` resolves at compile time to a single `&'static str`.
#[cfg(feature = "enterprise")]
pub(crate) const VERSION_LINE: &str = concat!(env!("CARGO_PKG_VERSION"), " (enterprise)");
#[cfg(not(feature = "enterprise"))]
pub(crate) const VERSION_LINE: &str = concat!(env!("CARGO_PKG_VERSION"), " (community)");

fn main() {
    match mode::detect() {
        mode::Mode::Cli => {
            #[cfg(feature = "cli")]
            {
                if let Err(e) = cli::run() {
                    eprintln!("Error: {e:?}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "cli"))]
            {
                eprintln!(
                    "csq: CLI mode requested but this binary was built without --features cli"
                );
                std::process::exit(2);
            }
        }
        mode::Mode::Desktop => {
            #[cfg(feature = "desktop")]
            desktop::run();
            #[cfg(not(feature = "desktop"))]
            {
                eprintln!(
                    "csq: desktop mode requested but this binary was built without --features desktop"
                );
                std::process::exit(2);
            }
        }
    }
}
