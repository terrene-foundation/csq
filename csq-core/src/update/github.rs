//! GitHub Releases API client for csq self-update.
//!
//! Fetches the latest release metadata from the GitHub Releases API,
//! finds the asset matching the current platform, and returns an
//! `UpdateInfo` struct the apply module uses to download and verify.
//!
//! ### Security
//!
//! - HTTPS-only (inherited from `crate::http`).
//! - No authentication header — unauthenticated GitHub API has a
//!   60 req/hour per-IP rate limit, adequate for update checks.
//! - No release data is treated as trusted until `verify.rs` confirms
//!   the Ed25519 signature and SHA256 checksum.
//! - All URLs parsed from the API response are validated to be HTTPS
//!   before being returned.
//!
//! ### Platform naming
//!
//! GitHub release assets are named `csq-{os}-{arch}[.exe]` where:
//! - `os`   = `macos` | `linux` | `windows`
//! - `arch` = `aarch64` | `x86_64`
//!
//! The `.sig` file for each binary is `csq-{os}-{arch}.sig` (no `.exe`
//! suffix for either, even on Windows).

use anyhow::{Context, Result};
use serde::Deserialize;

/// GitHub Releases listing endpoint. We DO NOT use `/releases/latest`
/// because that endpoint excludes prereleases — for csq in
/// `2.0.0-alpha.*` state it returns `v1.1.0` (the Python-era line)
/// and `check_latest_version` would permanently report "up to date"
/// even when a new alpha exists.
///
/// We also DO NOT trust the server ordering of `/releases`. Observed
/// behavior on the live API: the list is ordered roughly by an
/// internal `updated_at`, NOT by `published_at` or `created_at`, so
/// a release whose assets finished uploading in a second pass floats
/// to the top ahead of a chronologically later release. Client-side
/// sort by proper semver is the only reliable answer.
///
/// `per_page=30` comfortably covers the last month of alpha churn
/// without pagination, keeping the update check a single HTTPS
/// round-trip.
const GITHUB_API_RELEASES: &str =
    "https://api.github.com/repos/terrene-foundation/csq/releases?per_page=30";

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Metadata for an available update, returned by `check_latest_version`.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    /// Version string without leading `v` (e.g. `"2.1.0"`).
    pub version: String,
    /// HTTPS URL to download the binary asset (e.g. the `.tar.gz` or bare binary).
    pub download_url: String,
    /// HTTPS URL to the `.sig` file (Ed25519 signature over the binary bytes).
    pub signature_url: String,
    /// HTTPS URL to the `SHA256SUMS` file listing `{hash}  {filename}` pairs.
    pub checksum_url: String,
    /// Human-readable HTML page for the release (shown in update notices).
    pub html_url: String,
}

/// Subset of the GitHub Releases API response we care about.
#[derive(Debug, Deserialize)]
struct LatestRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<ReleaseAsset>,
    /// `true` if this release is marked as a draft. Drafts must not
    /// be considered by auto-update — they are unfinished and their
    /// assets may be rewritten.
    #[serde(default)]
    draft: bool,
}

/// One entry in `release.assets`.
#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

/// Checks GitHub Releases for a version newer than the current binary.
///
/// Returns `Ok(Some(info))` if a newer release exists and assets for the
/// current platform are present. Returns `Ok(None)` if already up to date
/// or the release has no assets for this platform.
///
/// The `http_get` parameter is an injectable transport so tests can supply
/// canned responses without a live network connection:
///
/// ```rust,ignore
/// // Production:
/// let info = check_latest_version(|url, headers| {
///     crate::http::get_with_headers(url, headers)
/// })?;
///
/// // Test:
/// let info = check_latest_version(|_url, _headers| {
///     Ok(FAKE_GITHUB_JSON.to_vec())
/// })?;
/// ```
pub fn check_latest_version<F>(http_get: F) -> Result<Option<UpdateInfo>>
where
    F: Fn(&str, &[(&str, &str)]) -> Result<Vec<u8>, String>,
{
    let ua = format!("csq/{CURRENT_VERSION}");
    let body = http_get(
        GITHUB_API_RELEASES,
        &[
            ("User-Agent", ua.as_str()),
            ("Accept", "application/vnd.github+json"),
            ("X-GitHub-Api-Version", "2022-11-28"),
        ],
    )
    .map_err(|e| anyhow::anyhow!("GitHub API request failed: {e}"))?;

    let mut releases: Vec<LatestRelease> =
        serde_json::from_slice(&body).context("failed to parse GitHub API response")?;

    // Filter out drafts — they can be rewritten and their assets are
    // not stable. Prereleases are KEPT because csq ships as
    // `2.0.0-alpha.*` and the user opts in via semver ordering.
    releases.retain(|r| !r.draft);

    // Client-side sort by semver, descending. Server-side order is
    // NOT reliable — observed live on the csq repo: `/releases`
    // returned `alpha.9` before `alpha.11` even though `alpha.11`
    // has a later `created_at` AND `published_at`. GitHub appears
    // to sort by an internal `updated_at` that jumps around when
    // assets are uploaded in a second pass.
    releases.sort_by(|a, b| {
        let av = a.tag_name.trim_start_matches('v');
        let bv = b.tag_name.trim_start_matches('v');
        compare_versions(bv, av) // reverse: b vs a = descending
    });

    let release = match releases.into_iter().next() {
        Some(r) => r,
        None => return Ok(None),
    };

    let latest_version = release.tag_name.trim_start_matches('v').to_string();

    // If the latest is not strictly greater, nothing to do.
    if compare_versions(&latest_version, CURRENT_VERSION) != std::cmp::Ordering::Greater {
        return Ok(None);
    }

    let platform_stem = current_platform_stem();
    let binary_name = binary_asset_name(&platform_stem);
    let sig_name = format!("{platform_stem}.sig");
    // The checksum file is a single file covering all platform binaries.
    let checksum_name = "SHA256SUMS";

    let find_asset = |name: &str| -> Option<String> {
        release
            .assets
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.browser_download_url.clone())
    };

    let download_url = match find_asset(&binary_name) {
        Some(u) => u,
        None => return Ok(None), // no asset for this platform — cannot update
    };
    let signature_url = match find_asset(&sig_name) {
        Some(u) => u,
        None => return Ok(None), // no signature — refuse to update without verification
    };
    let checksum_url = match find_asset(checksum_name) {
        Some(u) => u,
        None => return Ok(None), // no checksum — refuse to update without verification
    };

    // Validate all URLs are HTTPS before returning.
    for url in [&download_url, &signature_url, &checksum_url] {
        if !url.starts_with("https://") {
            return Err(anyhow::anyhow!(
                "GitHub returned a non-HTTPS download URL — refusing to proceed"
            ));
        }
    }

    Ok(Some(UpdateInfo {
        version: latest_version,
        download_url,
        signature_url,
        checksum_url,
        html_url: release.html_url,
    }))
}

/// Returns the platform stem used in release asset names.
///
/// Format: `csq-{os}-{arch}` where:
/// - os   = `macos` | `linux` | `windows`
/// - arch = `aarch64` | `x86_64`
pub fn current_platform_stem() -> String {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    format!("csq-{os}-{arch}")
}

/// Returns the binary asset filename for the given platform stem.
///
/// On Windows the binary has a `.exe` extension; on all other platforms it
/// is bare (no extension).
pub fn binary_asset_name(stem: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

/// Compares two semver-ish version strings using the same algorithm as
/// `csq-cli::commands::update::compare_versions`.
///
/// Returns `Greater` if `a > b`, `Less` if `a < b`, `Equal` if equal.
///
/// - Splits each on `-` into (numeric_part, prerelease_part).
/// - Numeric parts compared element-wise (zero-padded).
/// - A release (`1.0.0`) is greater than a prerelease (`1.0.0-alpha`).
/// - Two prereleases compared lexicographically.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_num, a_pre) = split_version(a);
    let (b_num, b_pre) = split_version(b);

    let max_len = std::cmp::max(a_num.len(), b_num.len());
    for i in 0..max_len {
        let an = a_num.get(i).copied().unwrap_or(0);
        let bn = b_num.get(i).copied().unwrap_or(0);
        match an.cmp(&bn) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    // Prerelease comparison, per the SemVer 2.0.0 spec section 11:
    //
    //   - A version without a prerelease has HIGHER precedence than
    //     the same version with one (`1.0.0 > 1.0.0-alpha`).
    //   - Precedence for two prereleases is determined by comparing
    //     dot-separated identifiers left to right:
    //       * Numeric identifiers compare numerically.
    //       * String identifiers compare lexicographically (ASCII).
    //       * Numeric identifiers are always lower precedence than
    //         non-numeric identifiers (`1.0.0-alpha.1 < 1.0.0-alpha.beta`).
    //     A prerelease with fewer fields has LOWER precedence if all
    //     preceding fields are equal (`1.0.0-alpha < 1.0.0-alpha.1`).
    //
    // Alpha.9/10/11 live-bug: the old implementation used plain
    // `String::cmp` on the prerelease suffix, so `"alpha.11"` sorted
    // BEFORE `"alpha.9"` because `'1' < '9'` lexicographically. That
    // made `csq update install` refuse every double-digit alpha as a
    // "downgrade". The per-segment compare below handles it correctly.
    match (a_pre, b_pre) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(a), Some(b)) => compare_prerelease(&a, &b),
    }
}

/// Compares two prerelease suffixes per SemVer 2.0.0 section 11.
fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    let a_ids: Vec<&str> = a.split('.').collect();
    let b_ids: Vec<&str> = b.split('.').collect();

    let min_len = std::cmp::min(a_ids.len(), b_ids.len());
    for i in 0..min_len {
        let ai = a_ids[i];
        let bi = b_ids[i];
        let a_num = ai.parse::<u64>().ok();
        let b_num = bi.parse::<u64>().ok();
        let ord = match (a_num, b_num) {
            (Some(an), Some(bn)) => an.cmp(&bn),
            // Numeric identifiers ALWAYS have lower precedence than
            // non-numeric identifiers.
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => ai.cmp(bi),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    // All shared identifiers compare equal; longer prerelease wins
    // (has higher precedence) per SemVer: `1.0.0-alpha < 1.0.0-alpha.1`.
    a_ids.len().cmp(&b_ids.len())
}

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

    // Minimal canned GitHub API response with all assets present.
    // Now wrapped in a one-element array because check_latest_version
    // fetches `/releases?per_page=30` and expects a JSON array.
    fn fake_release_json(version: &str, platform_stem: &str) -> Vec<u8> {
        serde_json::Value::Array(vec![fake_release_value(version, platform_stem)])
            .to_string()
            .into_bytes()
    }

    fn fake_release_value(version: &str, platform_stem: &str) -> serde_json::Value {
        let binary_name = binary_asset_name(platform_stem);
        let sig_name = format!("{platform_stem}.sig");
        let base =
            format!("https://github.com/terrene-foundation/csq/releases/download/v{version}");
        serde_json::json!({
            "tag_name": format!("v{version}"),
            "html_url": format!("https://github.com/terrene-foundation/csq/releases/tag/v{version}"),
            "draft": false,
            "assets": [
                {
                    "name": binary_name,
                    "browser_download_url": format!("{base}/{binary_name}")
                },
                {
                    "name": sig_name,
                    "browser_download_url": format!("{base}/{sig_name}")
                },
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": format!("{base}/SHA256SUMS")
                }
            ]
        })
    }

    /// Wraps a bare release JSON object (single release) in an array,
    /// for the tests that were written before the endpoint switch and
    /// need a minimal shim rather than a full rewrite.
    fn wrap_in_array(release: serde_json::Value) -> Vec<u8> {
        serde_json::Value::Array(vec![release])
            .to_string()
            .into_bytes()
    }

    #[test]
    fn check_latest_returns_update_info_when_newer() {
        // Arrange: a release newer than the compile-time version
        let stem = current_platform_stem();
        let new_version = "999.0.0"; // guaranteed newer than any real version
        let json = fake_release_json(new_version, &stem);

        // Act
        let result = check_latest_version(|_url, _headers| Ok(json.clone()));

        // Assert
        let info = result.unwrap().expect("should return Some when newer");
        assert_eq!(info.version, new_version);
        assert!(info.download_url.starts_with("https://"));
        assert!(info.signature_url.contains(".sig"));
        assert!(info.checksum_url.contains("SHA256SUMS"));
    }

    #[test]
    fn check_latest_returns_none_when_up_to_date() {
        // Arrange: same version as current
        let stem = current_platform_stem();
        let json = fake_release_json(CURRENT_VERSION, &stem);

        // Act
        let result = check_latest_version(|_url, _headers| Ok(json.clone()));

        // Assert
        assert!(
            result.unwrap().is_none(),
            "should return None when up to date"
        );
    }

    #[test]
    fn check_latest_returns_none_when_no_platform_asset() {
        // Arrange: newer version but only assets for a different platform
        let json = wrap_in_array(serde_json::json!({
            "tag_name": "v999.0.0",
            "html_url": "https://github.com/terrene-foundation/csq/releases/tag/v999.0.0",
            "draft": false,
            "assets": [
                {
                    "name": "csq-other-platform",
                    "browser_download_url": "https://github.com/example/csq-other-platform"
                }
            ]
        }));

        // Act
        let result = check_latest_version(|_url, _headers| Ok(json.clone()));

        // Assert
        assert!(
            result.unwrap().is_none(),
            "should return None when platform asset missing"
        );
    }

    #[test]
    fn check_latest_returns_none_when_sig_missing() {
        // Arrange: binary present but no .sig — must refuse without signature
        let stem = current_platform_stem();
        let binary_name = binary_asset_name(&stem);
        let json = wrap_in_array(serde_json::json!({
            "tag_name": "v999.0.0",
            "html_url": "https://github.com/terrene-foundation/csq/releases/tag/v999.0.0",
            "draft": false,
            "assets": [
                {
                    "name": binary_name,
                    "browser_download_url": format!("https://github.com/terrene-foundation/csq/releases/download/v999.0.0/{binary_name}")
                },
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://github.com/terrene-foundation/csq/releases/download/v999.0.0/SHA256SUMS"
                }
            ]
        }));

        // Act
        let result = check_latest_version(|_url, _headers| Ok(json.clone()));

        // Assert
        assert!(
            result.unwrap().is_none(),
            "should return None when .sig is missing"
        );
    }

    #[test]
    fn check_latest_rejects_http_download_url() {
        // Arrange: GitHub returns an HTTP (non-HTTPS) URL — must be rejected
        let stem = current_platform_stem();
        let binary_name = binary_asset_name(&stem);
        let sig_name = format!("{stem}.sig");
        let json = wrap_in_array(serde_json::json!({
            "tag_name": "v999.0.0",
            "html_url": "https://github.com/terrene-foundation/csq/releases/tag/v999.0.0",
            "draft": false,
            "assets": [
                {
                    "name": binary_name,
                    "browser_download_url": format!("http://github.com/download/{binary_name}")
                },
                {
                    "name": sig_name,
                    "browser_download_url": format!("https://github.com/download/{sig_name}")
                },
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://github.com/download/SHA256SUMS"
                }
            ]
        }));

        // Act
        let result = check_latest_version(|_url, _headers| Ok(json.clone()));

        // Assert
        assert!(result.is_err(), "must reject HTTP download URLs");
        assert!(
            result.unwrap_err().to_string().contains("non-HTTPS"),
            "error must mention HTTPS"
        );
    }

    #[test]
    fn check_latest_propagates_transport_error() {
        // Arrange: HTTP transport fails
        let result = check_latest_version(|_url, _headers| Err("connection failed".into()));

        // Assert
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("GitHub API request failed"));
    }

    #[test]
    fn check_latest_errors_on_malformed_json() {
        // Act
        let result = check_latest_version(|_url, _headers| Ok(b"not json".to_vec()));

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn check_latest_returns_none_when_checksum_missing() {
        // Arrange: binary + sig present but no SHA256SUMS
        let stem = current_platform_stem();
        let binary_name = binary_asset_name(&stem);
        let sig_name = format!("{stem}.sig");
        let json = wrap_in_array(serde_json::json!({
            "tag_name": "v999.0.0",
            "html_url": "https://github.com/terrene-foundation/csq/releases/tag/v999.0.0",
            "draft": false,
            "assets": [
                {
                    "name": binary_name,
                    "browser_download_url": format!("https://github.com/terrene-foundation/csq/releases/download/v999.0.0/{binary_name}")
                },
                {
                    "name": sig_name,
                    "browser_download_url": format!("https://github.com/terrene-foundation/csq/releases/download/v999.0.0/{sig_name}")
                }
            ]
        }));

        // Act
        let result = check_latest_version(|_url, _headers| Ok(json.clone()));

        // Assert
        assert!(
            result.unwrap().is_none(),
            "should return None when SHA256SUMS is missing"
        );
    }

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
    fn compare_double_digit_alpha_numeric_order() {
        // The alpha.9/10/11 bug: old code used lexicographic string
        // compare on the prerelease suffix, so "alpha.11" sorted
        // BEFORE "alpha.9" and csq update rejected every double-digit
        // alpha as a downgrade. New code parses each dot-segment as
        // a number where possible and compares numerically.
        assert_eq!(
            compare_versions("2.0.0-alpha.11", "2.0.0-alpha.9"),
            Ordering::Greater,
            "alpha.11 MUST be greater than alpha.9"
        );
        assert_eq!(
            compare_versions("2.0.0-alpha.10", "2.0.0-alpha.9"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("2.0.0-alpha.9", "2.0.0-alpha.11"),
            Ordering::Less,
            "alpha.9 MUST be less than alpha.11"
        );
        assert_eq!(
            compare_versions("2.0.0-alpha.100", "2.0.0-alpha.99"),
            Ordering::Greater,
            "triple-digit alpha must beat double-digit"
        );
    }

    #[test]
    fn compare_prerelease_semver_spec_rules() {
        // SemVer 2.0.0 section 11: numeric < non-numeric in
        // per-segment compare; fewer segments < more segments when
        // prefix matches.
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-alpha.1"),
            Ordering::Less,
            "shorter prerelease has lower precedence"
        );
        assert_eq!(
            compare_versions("1.0.0-alpha.1", "1.0.0-alpha.beta"),
            Ordering::Less,
            "numeric identifier < non-numeric identifier"
        );
        assert_eq!(
            compare_versions("1.0.0-beta", "1.0.0-alpha"),
            Ordering::Greater,
            "beta > alpha lexicographically"
        );
    }

    #[test]
    fn check_latest_picks_highest_semver_from_unsorted_list() {
        // Regression for the live bug: GitHub `/releases` returned
        // alpha.9 BEFORE alpha.11 in server order. check_latest_version
        // must client-side sort and pick the highest. Uses 999.x.x
        // prereleases so the selected one is always newer than the
        // current compile-time version regardless of what release
        // this test runs on.
        let stem = current_platform_stem();
        let json = serde_json::Value::Array(vec![
            fake_release_value("999.0.0-alpha.9", &stem),
            fake_release_value("999.0.0-alpha.11", &stem),
            fake_release_value("999.0.0-alpha.10", &stem),
            fake_release_value("998.0.0", &stem),
        ])
        .to_string()
        .into_bytes();

        let info = check_latest_version(|_url, _headers| Ok(json.clone()))
            .unwrap()
            .expect("should return Some when a newer release exists");

        assert_eq!(
            info.version, "999.0.0-alpha.11",
            "client-side sort must pick alpha.11 even though the server \
             returned alpha.9 first (and even though alpha.11 < alpha.9 \
             under the pre-fix lexicographic compare)"
        );
    }

    #[test]
    fn check_latest_ignores_v1_x_stable_when_current_is_alpha() {
        // GitHub's /releases/latest endpoint returns v1.1.0 because
        // all 2.0.0-alpha.* are prereleases. We deliberately do NOT
        // hit /releases/latest. This test simulates the list response
        // to ensure a later alpha beats v1.1.0 in the semver sort.
        let stem = current_platform_stem();
        let json = serde_json::Value::Array(vec![
            fake_release_value("1.1.0", &stem),
            fake_release_value("999.0.0-alpha.1", &stem),
        ])
        .to_string()
        .into_bytes();

        let info = check_latest_version(|_url, _headers| Ok(json.clone()))
            .unwrap()
            .expect("should return Some when a newer prerelease exists");

        // 999.0.0-alpha.1 is strictly greater than any 2.x; 1.1.0
        // would only win under `/releases/latest`-semantics we no
        // longer use.
        assert_eq!(info.version, "999.0.0-alpha.1");
    }

    #[test]
    fn check_latest_skips_draft_releases() {
        let stem = current_platform_stem();
        let mut draft = fake_release_value("999.9.9", &stem);
        draft["draft"] = serde_json::Value::Bool(true);
        let json =
            serde_json::Value::Array(vec![draft, fake_release_value("999.0.0-alpha.1", &stem)])
                .to_string()
                .into_bytes();

        let info = check_latest_version(|_url, _headers| Ok(json.clone()))
            .unwrap()
            .expect("should find the non-draft release");

        assert_eq!(
            info.version, "999.0.0-alpha.1",
            "drafts must be excluded even if they have a higher version"
        );
    }

    #[test]
    fn check_latest_returns_none_when_all_older() {
        // Every release in the list is older than the current version.
        // This is the normal "up to date" path.
        let stem = current_platform_stem();
        let json = serde_json::Value::Array(vec![
            fake_release_value("0.0.1", &stem),
            fake_release_value("0.0.2", &stem),
        ])
        .to_string()
        .into_bytes();

        assert!(check_latest_version(|_url, _headers| Ok(json.clone()))
            .unwrap()
            .is_none());
    }

    #[test]
    fn compare_prerelease_vs_release() {
        assert_eq!(compare_versions("1.0.0", "1.0.0-alpha"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0-alpha", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn current_platform_stem_is_valid() {
        // Just confirm the function runs and returns something reasonable.
        let stem = current_platform_stem();
        assert!(
            stem.starts_with("csq-"),
            "stem must start with csq-: {stem}"
        );
        assert!(
            stem.contains("aarch64") || stem.contains("x86_64"),
            "stem must contain arch: {stem}"
        );
    }
}
