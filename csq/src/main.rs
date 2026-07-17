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
    // #1011 headless self-test short-circuit. The self-test lives at the top of
    // `desktop::run()`, but `mode::detect()` only resolves `Desktop` from the
    // `.app` bundle sentinel / `--desktop` — so `--self-test` on a raw binary
    // would otherwise route to CLI and never reach it. Route to `desktop::run()`
    // directly whenever the self-test is requested, so the flag reliably works on
    // every desktop-feature build (the bundled binary AND a plain `cargo build`).
    #[cfg(feature = "desktop")]
    {
        // `--self-test` is honored ONLY as the sole argument (not `.any(argv)`,
        // which would misfire if a future flag or a `csq://` deep-link argv merely
        // contained the token — R1 LOW-1). The env path stays precise.
        let argv: Vec<String> = std::env::args().collect();
        if std::env::var("CSQ_DESKTOP_SELFTEST").as_deref() == Ok("1")
            || (argv.len() == 2 && argv[1] == "--self-test")
        {
            desktop::run(); // runs the self-test block at its top, then exits
            return;
        }
    }

    match mode::detect() {
        mode::Mode::Cli => {
            #[cfg(feature = "cli")]
            {
                // clap builds and renders the ENTIRE subcommand tree recursively on
                // any parse (including `--help`). csq's tree is large; on Windows the
                // default 1 MiB main-thread stack overflows during that recursion
                // (`STATUS_STACK_OVERFLOW` on e.g. `csq run --help` — surfaced by
                // an internal ticket adding roster subcommands), while macOS/Linux (8 MiB
                // default) are fine. Run the CLI on a thread with a generous stack —
                // the canonical remedy (rustc/cargo do the same). Applies on every
                // platform for uniform headroom; the join propagates the exit code.
                let code = std::thread::Builder::new()
                    .name("csq-cli".into())
                    .stack_size(32 * 1024 * 1024)
                    .spawn(|| match cli::run() {
                        Ok(()) => 0,
                        Err(e) => {
                            eprintln!("Error: {e:?}");
                            1
                        }
                    })
                    .expect("failed to spawn csq-cli worker thread")
                    .join()
                    .unwrap_or(101); // panic hook already printed the message
                std::process::exit(code);
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
