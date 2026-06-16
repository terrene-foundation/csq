//! csq self-update version checker.
//!
//! Fetches the static `latest.json` manifest (the same one the Tauri desktop
//! updater uses — a CDN-served release **asset**, NOT the GitHub REST API),
//! reads its `version`, and — when newer — CONSTRUCTS the CLI's download /
//! signature / checksum URLs from that version. Returns an `UpdateInfo` the
//! apply module uses to download and verify.
//!
//! ### Why not the REST API
//!
//! `api.github.com/repos/.../releases` is rate-limited to 60 req/hour per IP
//! unauthenticated — shared across every csq instance behind one egress IP and
//! trivially exhausted at scale. Release-asset downloads (`releases/download/`)
//! are CDN-served and not subject to that limit, so the whole flow scales to
//! unlimited users. See [`GITHUB_LATEST_JSON`].
//!
//! ### Security
//!
//! - HTTPS-only (inherited from `crate::http`); constructed URLs are HTTPS by
//!   construction (the `releases/download/...` base is hardcoded).
//! - No release data is treated as trusted until `verify.rs` confirms the
//!   Ed25519 signature and SHA256 checksum.
//!
//! ### Platform naming
//!
//! GitHub release assets are named `csq-{os}-{arch}[.exe]` where:
//! - `os`   = `macos` | `linux` | `windows`
//! - `arch` = `aarch64` | `x86_64`
//!
//! The `.sig` file for each binary is `csq-{os}-{arch}.sig` (no `.exe`
//! suffix for either, even on Windows).

use crate::http::FullResponse;
use anyhow::{Context, Result};
use serde::Deserialize;

/// The version manifest the update checker reads. This is the SAME
/// `latest.json` the Tauri desktop updater consumes — a static release
/// **asset** (the rolling `updater-manifest` release whose only asset is
/// `latest.json`, repointed at the freshest version on every release).
///
/// **Why an asset, not the REST API (the load-bearing scaling decision):**
/// the previous implementation fetched `api.github.com/repos/.../releases`,
/// which is rate-limited to **60 requests/hour per IP for unauthenticated
/// callers**. That limit is shared across every csq instance behind one
/// egress IP (a single user's many terminals + daemon + desktop app, or an
/// entire office/VPN/NAT), so it is trivially and permanently exhausted at
/// scale. A release **asset** download (`releases/download/...`) is served
/// from GitHub's CDN (`release-assets.githubusercontent.com`) and is NOT
/// subject to the REST-API rate limit — it scales to unlimited users. We
/// fetch only `version` from the manifest and CONSTRUCT the CLI asset URLs
/// from it (see `RELEASE_DOWNLOAD_BASE`), so the whole update flow is
/// API-free. The `updater-manifest` rolling tag (not `/releases/latest/`)
/// tracks the freshest version regardless of prerelease flags — matching the
/// prior include-prereleases behavior and the desktop updater's primary
/// endpoint.
const GITHUB_LATEST_JSON: &str =
    "https://github.com/terrene-foundation/csq/releases/download/updater-manifest/latest.json";

/// Base for constructing CLI release-asset URLs from a version tag — also a
/// CDN-served `releases/download/...` path, never the REST API.
const RELEASE_DOWNLOAD_BASE: &str = "https://github.com/terrene-foundation/csq/releases/download";

/// Base for the human-readable release page (shown in update notices).
const RELEASE_TAG_BASE: &str = "https://github.com/terrene-foundation/csq/releases/tag";

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

/// The subset of `latest.json` (the Tauri-updater manifest) we read. Only
/// `version` is needed — the CLI asset URLs are constructed from it. Other
/// keys (`pub_date`, `platforms` — which point at the DESKTOP bundles with
/// minisign signatures, irrelevant to the CLI's Ed25519 verify) are ignored.
#[derive(Debug, Deserialize)]
struct LatestManifest {
    version: String,
}

/// Checks the static `latest.json` manifest for a version newer than the
/// running binary, and constructs the CLI asset URLs for it.
///
/// Returns `Ok(Some(info))` if the manifest's `version` is strictly greater
/// than `CURRENT_VERSION`, `Ok(None)` if already up to date, and `Err` on a
/// transport/parse failure or a non-2xx manifest fetch.
///
/// **No GitHub REST API is used** — the manifest and the constructed asset
/// URLs are all CDN-served release assets (see [`GITHUB_LATEST_JSON`]),
/// immune to the 60/hour unauthenticated API rate limit. The download URLs
/// are constructed from the manifest `version` + the deterministic release-
/// asset naming, so no asset enumeration is needed; the actual download +
/// Ed25519/SHA256 verification (in `apply.rs` / `verify.rs`) is unchanged and
/// fails closed if a constructed URL 404s.
///
/// The `http_get` parameter is an injectable transport returning
/// `(status, headers, body)`. Tests supply a canned `latest.json` body.
pub fn check_latest_version<F>(http_get: F) -> Result<Option<UpdateInfo>>
where
    F: Fn(&str, &[(&str, &str)]) -> Result<FullResponse, String>,
{
    let ua = format!("csq/{CURRENT_VERSION}");
    let (status, _headers, body) = http_get(GITHUB_LATEST_JSON, &[("User-Agent", ua.as_str())])
        .map_err(|e| anyhow::anyhow!("update manifest request failed: {e}"))?;

    // Non-2xx: the manifest is a CDN asset (not the rate-limited REST API), so
    // a failure here is a missing/transient asset, not a quota issue. Surface
    // the status; the redacted body tail aids diagnosis without leaking tokens.
    if status / 100 != 2 {
        let tail = crate::error::redact_tokens(&String::from_utf8_lossy(&body));
        let tail: String = tail.chars().take(120).collect();
        anyhow::bail!("update manifest fetch failed (HTTP {status}): {tail}");
    }

    let manifest: LatestManifest =
        serde_json::from_slice(&body).context("failed to parse update manifest (latest.json)")?;
    let latest_version = manifest.version.trim_start_matches('v').to_string();

    // If the manifest is not strictly newer, nothing to do.
    if compare_versions(&latest_version, CURRENT_VERSION) != std::cmp::Ordering::Greater {
        return Ok(None);
    }

    // Construct the CLI asset URLs from the version tag (all CDN-served
    // `releases/download/...` paths — no API). The release pipeline publishes
    // the CLI binary, its `.sig`, and `SHA256SUMS` for every release under the
    // `v{version}` tag; `apply.rs` verifies + fails closed if any 404s.
    let platform_stem = current_platform_stem();
    let binary_name = binary_asset_name(&platform_stem);
    let tag_base = format!("{RELEASE_DOWNLOAD_BASE}/v{latest_version}");

    Ok(Some(UpdateInfo {
        download_url: format!("{tag_base}/{binary_name}"),
        signature_url: format!("{tag_base}/{platform_stem}.sig"),
        checksum_url: format!("{tag_base}/SHA256SUMS"),
        html_url: format!("{RELEASE_TAG_BASE}/v{latest_version}"),
        version: latest_version,
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
    use std::collections::HashMap;

    /// A canned `latest.json` body (the Tauri-updater manifest) with the given
    /// version. Only `version` is read by `check_latest_version`; `platforms`
    /// is included for realism (the CLI ignores it).
    fn fake_manifest(version: &str) -> Vec<u8> {
        serde_json::json!({
            "version": version,
            "pub_date": "2026-01-01T00:00:00Z",
            "platforms": {
                "darwin-aarch64": {"signature": "x", "url": "https://example/x"}
            }
        })
        .to_string()
        .into_bytes()
    }

    /// Wrap a body as a 200 OK response with empty headers.
    fn ok_200(body: Vec<u8>) -> Result<FullResponse, String> {
        Ok((200, HashMap::new(), body))
    }

    #[test]
    fn check_latest_returns_update_info_when_newer() {
        // A manifest version newer than the compile-time version yields Some,
        // with all asset URLs CONSTRUCTED from the version (no enumeration).
        let new_version = "999.0.0"; // guaranteed newer than any real version
        let json = fake_manifest(new_version);
        let info = check_latest_version(|_url, _h| ok_200(json.clone()))
            .unwrap()
            .expect("should return Some when newer");

        assert_eq!(info.version, new_version);
        let stem = current_platform_stem();
        let binary = binary_asset_name(&stem);
        assert_eq!(
            info.download_url,
            format!(
                "https://github.com/terrene-foundation/csq/releases/download/v999.0.0/{binary}"
            )
        );
        assert_eq!(
            info.signature_url,
            format!(
                "https://github.com/terrene-foundation/csq/releases/download/v999.0.0/{stem}.sig"
            )
        );
        assert!(info.checksum_url.ends_with("/v999.0.0/SHA256SUMS"));
        assert!(info.html_url.ends_with("/releases/tag/v999.0.0"));
    }

    /// The scaling guarantee (regression): every URL the checker emits is a
    /// CDN release-asset path — NEVER the rate-limited `api.github.com` REST
    /// API. This is the whole point of the latest.json switch.
    #[test]
    fn check_latest_never_touches_the_rest_api() {
        let json = fake_manifest("999.0.0");
        // The transport MUST be called only with the CDN manifest URL.
        let info = check_latest_version(|url, _h| {
            assert!(
                url.starts_with("https://github.com/terrene-foundation/csq/releases/download/"),
                "update check must hit the release-asset CDN, not the API; got {url}"
            );
            assert!(
                !url.contains("api.github.com"),
                "must NOT use the REST API: {url}"
            );
            ok_200(json.clone())
        })
        .unwrap()
        .expect("Some when newer");
        for u in [
            &info.download_url,
            &info.signature_url,
            &info.checksum_url,
            &info.html_url,
        ] {
            assert!(u.starts_with("https://"), "all URLs https: {u}");
            assert!(!u.contains("api.github.com"), "no API URL: {u}");
        }
    }

    #[test]
    fn check_latest_returns_none_when_up_to_date() {
        let json = fake_manifest(CURRENT_VERSION);
        assert!(check_latest_version(|_url, _h| ok_200(json.clone()))
            .unwrap()
            .is_none());
    }

    #[test]
    fn check_latest_returns_none_when_manifest_older() {
        let json = fake_manifest("0.0.1");
        assert!(check_latest_version(|_url, _h| ok_200(json.clone()))
            .unwrap()
            .is_none());
    }

    /// Manifest version may be prefixed with `v`; the checker strips it and
    /// the semver compare (alpha ordering) still governs.
    #[test]
    fn check_latest_handles_prerelease_and_v_prefix() {
        let json = fake_manifest("v999.0.0-alpha.11");
        let info = check_latest_version(|_url, _h| ok_200(json.clone()))
            .unwrap()
            .expect("alpha newer than current");
        assert_eq!(info.version, "999.0.0-alpha.11");
        assert!(info.download_url.contains("/v999.0.0-alpha.11/"));
    }

    #[test]
    fn check_latest_propagates_transport_error() {
        let result = check_latest_version(|_url, _h| Err("connection failed".into()));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("update manifest request failed"));
    }

    #[test]
    fn check_latest_errors_on_malformed_manifest() {
        // 200 OK but body is not the expected JSON object → parse error.
        let result = check_latest_version(|_url, _h| ok_200(b"not json".to_vec()));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("parse update manifest"));
    }

    #[test]
    fn check_latest_errors_on_non_2xx_manifest_fetch() {
        // A 404 on the manifest asset (e.g. updater-manifest tag missing) is a
        // surfaced error, NOT a silent up-to-date — and names the status.
        let result =
            check_latest_version(|_url, _h| Ok((404, HashMap::new(), b"Not Found".to_vec())));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("404"));
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
