//! `csq update` — check and install newer csq releases from GitHub.
//!
//! ### Subcommands
//!
//! - `csq update check` — check GitHub Releases for a newer version and
//!   print a notice. No changes made to the binary.
//!
//! - `csq update install` — check for a newer version, download it,
//!   verify SHA256 checksum and Ed25519 signature, and atomically
//!   replace the current binary. Only proceeds if both verification
//!   steps pass.
//!
//! ### Version comparison
//!
//! Rolls a minimal comparator that handles `MAJOR.MINOR.PATCH[-tag]`
//! by splitting on `.` and parsing each component as u32. Pre-
//! release tags (`2.0.0-alpha.1`) are compared lexicographically
//! after the numeric components, matching semver spec closely
//! enough for csq's linear release cadence.

use anyhow::{Context, Result};
use csq_core::update::github::compare_versions;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runs `csq update check`. Prints the result to stdout.
pub fn check() -> Result<()> {
    eprintln!("Checking for csq updates…");

    let info = csq_core::update::check_for_update().context("failed to check for updates")?;

    match info {
        Some(update) => {
            let ordering = compare_versions(&update.version, CURRENT_VERSION);
            if ordering == std::cmp::Ordering::Greater {
                println!(
                    "A newer version of csq is available: {} → {}",
                    CURRENT_VERSION, update.version
                );
                println!("  Release notes: {}", update.html_url);
                println!();
                println!("To upgrade:");
                println!("  csq update install   (downloads, verifies, and replaces this binary)");
                println!("  brew upgrade csq     (if installed via Homebrew)");
                println!("  Download manually:   {}", update.html_url);
            } else {
                println!("csq {} is up to date.", CURRENT_VERSION);
            }
        }
        None => {
            println!("csq {} is up to date.", CURRENT_VERSION);
        }
    }
    Ok(())
}

/// Runs `csq update install`.
///
/// 1. Checks GitHub Releases for a newer version.
/// 2. If none exists, reports "already up to date" and exits.
/// 3. If a newer version exists, downloads the binary, verifies the
///    SHA256 checksum and Ed25519 signature, and atomically replaces
///    the current binary.
/// 4. Prompts the user for confirmation before replacing.
///
/// # Security
///
/// The update is refused unless both the SHA256 checksum and the
/// Ed25519 signature (against the pinned Foundation release key) pass.
/// See `csq_core::update::verify` for the verification logic.
pub fn install() -> Result<()> {
    // C1: Refuse to install when the release signing key is still the
    // placeholder test key. Anyone who reads the source can derive
    // the corresponding private key and sign a malicious binary.
    if csq_core::update::verify::is_placeholder_key() {
        anyhow::bail!(
            "csq update install is not available yet — the release signing key \
             has not been configured. Use `csq update check` to see if a newer \
             version exists, then download it manually from the GitHub Releases page."
        );
    }

    eprintln!("Checking for csq updates…");

    let info = csq_core::update::check_for_update().context("failed to check for updates")?;

    let info = match info {
        None => {
            println!("csq {} is already up to date.", CURRENT_VERSION);
            return Ok(());
        }
        Some(i) => i,
    };

    println!(
        "csq {} is available (current: {}).",
        info.version, CURRENT_VERSION
    );
    println!("Release notes: {}", info.html_url);
    println!();
    print!("Download and install? [y/N] ");
    // Flush stdout before waiting for input.
    use std::io::Write;
    std::io::stdout()
        .flush()
        .context("failed to flush stdout")?;

    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .context("failed to read user input")?;

    if !response.trim().eq_ignore_ascii_case("y") {
        println!("Update cancelled.");
        return Ok(());
    }

    csq_core::update::download_and_apply(&info).context("update failed")?;

    println!("Restart csq to use v{}.", info.version);
    Ok(())
}

// Version comparison tests live in csq-core/src/update/github.rs alongside
// the canonical compare_versions implementation.
