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
