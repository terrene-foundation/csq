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
use serde::Deserialize;

const GITHUB_API_LATEST: &str =
    "https://api.github.com/repos/terrene-foundation/csq/releases/latest";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Subset of the GitHub Releases API response we care about.
#[derive(Debug, Deserialize)]
struct LatestRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: String,
}

/// Runs `csq update check`. Prints the result to stdout.
pub fn check() -> Result<()> {
    eprintln!("Checking for csq updates…");
    let release = fetch_latest_release().context("failed to fetch latest release from GitHub")?;
    let latest = release.tag_name.trim_start_matches('v').to_string();
    let ordering = compare_versions(&latest, CURRENT_VERSION);
    match ordering {
        std::cmp::Ordering::Greater => {
            println!(
                "A newer version of csq is available: {} → {}",
                CURRENT_VERSION, latest
            );
            println!("  Release notes: {}", release.html_url);
            if !release.body.trim().is_empty() {
                // Show the first non-empty line of the release body
                // as a one-line summary. Full notes are at html_url.
                if let Some(first_line) = release.body.lines().find(|l| !l.trim().is_empty()) {
                    println!("  Summary: {}", first_line.trim());
                }
            }
            println!();
            println!("To upgrade:");
            println!("  csq update install   (downloads, verifies, and replaces this binary)");
            println!("  brew upgrade csq     (if installed via Homebrew)");
            println!("  Download manually:   {}", release.html_url);
        }
        std::cmp::Ordering::Equal => {
            println!("csq {} is up to date.", CURRENT_VERSION);
        }
        std::cmp::Ordering::Less => {
            // Current is AHEAD of latest release — this happens on
            // dev builds. Don't alarm the user.
            println!(
                "csq {} is ahead of the latest published release ({}).",
                CURRENT_VERSION, latest
            );
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

/// Fetches `GET /repos/.../releases/latest` from the GitHub API.
///
/// Returns a 15-second-timeout-bound blocking call so the CLI
/// doesn't hang on a network partition. No auth header — the
/// unauthenticated GitHub API has a 60 req/hour per-IP rate limit
/// which is fine for a once-in-a-while update check.
fn fetch_latest_release() -> Result<LatestRelease> {
    // Custom User-Agent is required by GitHub API for non-browser
    // clients; they 403 any request without one.
    let ua = format!("csq/{}", CURRENT_VERSION);
    let body = csq_core::http::get_with_headers(
        GITHUB_API_LATEST,
        &[
            ("User-Agent", ua.as_str()),
            ("Accept", "application/vnd.github+json"),
        ],
    )
    .map_err(|e| anyhow::anyhow!("HTTP request to GitHub failed: {e}"))?;
    let release: LatestRelease =
        serde_json::from_slice(&body).context("could not parse GitHub API response")?;
    Ok(release)
}

/// Compares two semver-ish version strings.
///
/// Algorithm:
/// - Split each on `-` into (numeric_part, prerelease_part).
/// - Parse the numeric part as a `.`-separated list of u32s. Pad
///   shorter lists with zeros so `1.2` and `1.2.0` compare equal.
/// - Compare numeric lists element-wise. Different → return.
/// - If numeric parts are equal:
///   - Neither has a prerelease → equal.
///   - Only one has a prerelease → the one WITHOUT is greater
///     (semver spec: `1.0.0 > 1.0.0-alpha`).
///   - Both have prereleases → compare them lexicographically.
///
/// Good enough for csq's linear release cadence. Does not handle
/// build metadata (`+build.123`) because we don't use it.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_num, a_pre) = split_version(a);
    let (b_num, b_pre) = split_version(b);

    // Compare numeric parts element-wise with zero-padding.
    let max_len = std::cmp::max(a_num.len(), b_num.len());
    for i in 0..max_len {
        let an = a_num.get(i).copied().unwrap_or(0);
        let bn = b_num.get(i).copied().unwrap_or(0);
        match an.cmp(&bn) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    // Numeric parts are equal — now compare prereleases.
    match (a_pre, b_pre) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater, // 1.0.0 > 1.0.0-alpha
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(a), Some(b)) => a.cmp(&b),
    }
}

/// Splits `"2.0.0-alpha.1"` into `([2, 0, 0], Some("alpha.1"))`.
/// Non-numeric components in the main part are treated as 0 so a
/// bogus tag doesn't crash the comparison.
fn split_version(v: &str) -> (Vec<u32>, Option<String>) {
    let (main, pre) = match v.split_once('-') {
        Some((m, p)) => (m, Some(p.to_string())),
        None => (v, None),
    };
    let nums: Vec<u32> = main.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    (nums, pre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn compare_basic_greater() {
        assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("2.0.0", "1.99.99"), Ordering::Greater);
        assert_eq!(compare_versions("1.10.0", "1.9.0"), Ordering::Greater);
    }

    #[test]
    fn compare_basic_less() {
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("1.9.0", "1.10.0"), Ordering::Less);
    }

    #[test]
    fn compare_equal() {
        assert_eq!(compare_versions("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn compare_different_length_numeric() {
        // "1.2" and "1.2.0" compare equal after zero-padding.
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.2.0.0", "1.2"), Ordering::Equal);
    }

    #[test]
    fn compare_prerelease_vs_release() {
        // Semver: 1.0.0 > 1.0.0-alpha
        assert_eq!(compare_versions("1.0.0", "1.0.0-alpha"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0-alpha", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn compare_two_prereleases() {
        // Lexicographic within the pre tag.
        assert_eq!(
            compare_versions("2.0.0-alpha", "2.0.0-beta"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("2.0.0-alpha.2", "2.0.0-alpha.10"),
            Ordering::Greater // lexicographic: "2" > "10" because "2" > "1"
        );
    }

    #[test]
    fn compare_version_with_v_prefix() {
        // The caller is responsible for stripping `v`; test
        // fixtures here use bare numeric versions.
        // Just confirm strip_prefix works as expected at the call
        // site by simulating the path.
        let raw = "v2.0.0-alpha.1";
        let stripped = raw.trim_start_matches('v');
        assert_eq!(stripped, "2.0.0-alpha.1");
    }

    #[test]
    fn compare_bogus_version_does_not_panic() {
        // Non-numeric component → treated as 0, still compares.
        assert_eq!(compare_versions("garbage", "1.0.0"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "garbage"), Ordering::Greater);
    }
}
