//! Codex models catalog — bundled cold-start + 1.5s live fetch + cache.
//!
//! The desktop `ChangeModelModal` for a Codex-surface slot needs a
//! list of valid model ids the user can pick without typing. Three
//! layered sources, consulted in this order by [`list_models`]:
//!
//! 1. **On-disk cache** (`accounts/codex-models-cache.json`). If present
//!    and not older than [`CACHE_TTL_SECS`], returned immediately. The
//!    cache record carries its own timestamp so the UI can render a
//!    "Cached Nm ago" hint.
//! 2. **Live fetch** via Node transport to
//!    `https://chatgpt.com/backend-api/codex/models` with a
//!    [`LIVE_FETCH_TIMEOUT_MS`] cap. Success rewrites the cache.
//! 3. **Bundled cold-start list** if both of the above fail. Returned
//!    with `source == Bundled` so the UI can warn the user that the
//!    list may be stale.
//!
//! Design invariant: the returned `Vec<String>` is **never empty** on
//! any path. A "no models" return from the upstream is itself a cache
//! miss and is treated as a live failure.
//!
//! This module is consumed by the `list_codex_models` Tauri command
//! in PR-C8. The CLI does not call it directly — `csq models switch
//! codex <id> --force` already has a different escape hatch (FR-CLI-04
//! via `--force` per PR-C7), and the curated CLI catalog is
//! deliberately minimal.

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Filename relative to `base_dir`. Co-located with other
/// account-scope caches (e.g. `quota.json`).
pub const MODELS_CACHE_FILENAME: &str = "codex-models-cache.json";

/// How long a cached `models` payload is trusted before the modal
/// refetches. Mirrors the behavior of a reasonable "hot cache" — a
/// Codex subscription's model list changes on the order of days
/// (when OpenAI promotes a model from preview to GA), so 1 hour is a
/// compromise between responsiveness and not hammering the endpoint.
pub const CACHE_TTL_SECS: u64 = 3_600;

/// Hard cap on the live fetch roundtrip. Anything past this falls
/// through to the cache-or-bundled path. Matches the 1.5s ceiling
/// from the PR-C8 plan ("1.5s fetch `chatgpt.com/backend-api/codex/models`").
pub const LIVE_FETCH_TIMEOUT_MS: u64 = 1_500;

/// Bundled cold-start model list. Consulted only when both the cache
/// AND the live fetch fail. Kept deliberately short: the provider's
/// `default_model` (per catalog) plus the two most likely
/// alternatives a real user would recognize. A fresh `csq` install
/// without a prior Codex login will show these; as soon as the first
/// live fetch succeeds, the on-disk cache supersedes them.
///
/// The entries are `(id, label)` pairs — the `id` is what gets
/// written to `config.toml`; the `label` is the UI dropdown text.
pub const BUNDLED_MODELS: &[(&str, &str)] = &[
    ("gpt-5.4", "gpt-5.4 (default)"),
    ("gpt-5-codex", "gpt-5-codex"),
    ("gpt-5", "gpt-5"),
];

/// One row in the UI picker. Small on purpose — anything more than
/// id+label belongs in a separate view that is not safe to cache
/// on disk (e.g. subscription-tier gating).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexModel {
    pub id: String,
    pub label: String,
}

/// Where the [`CodexModelList`] was sourced. Lets the UI render a
/// "Cached Nm ago" vs "Live" vs "Cold-start (offline)" hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelSource {
    Live,
    Cached,
    Bundled,
}

/// Result of [`list_models`]. IPC-safe — no tokens, no user PII.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexModelList {
    pub models: Vec<CodexModel>,
    pub source: ModelSource,
    /// Unix epoch seconds at which the payload was captured.
    /// For `Bundled`, always 0 (the bundle has no timestamp).
    pub fetched_at: u64,
}

/// Returns the absolute path to the on-disk cache.
pub fn cache_path(base_dir: &Path) -> PathBuf {
    base_dir.join(MODELS_CACHE_FILENAME)
}

/// Reads and validates the on-disk cache. Returns `Some(list)` iff
/// the file exists AND parses as a `CodexModelList` AND its
/// `fetched_at` timestamp is within [`CACHE_TTL_SECS`] of `now`.
pub fn read_cache(base_dir: &Path, now: u64) -> Option<CodexModelList> {
    let raw = std::fs::read_to_string(cache_path(base_dir)).ok()?;
    let parsed: CodexModelList = serde_json::from_str(&raw).ok()?;
    if parsed.models.is_empty() {
        return None;
    }
    if now.saturating_sub(parsed.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(CodexModelList {
        source: ModelSource::Cached,
        ..parsed
    })
}

/// Atomically writes `list` to the cache path. Permissions flipped
/// to 0o600 for uniformity with other account-scope caches.
pub fn write_cache(base_dir: &Path, list: &CodexModelList) -> std::io::Result<()> {
    let json =
        serde_json::to_string_pretty(list).map_err(|e| std::io::Error::other(e.to_string()))?;
    let target = cache_path(base_dir);
    let tmp = unique_tmp_path(&target);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(e.to_string()));
    }
    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(e.to_string()));
    }
    Ok(())
}

/// Returns the bundled cold-start list. The `source` is
/// [`ModelSource::Bundled`] and `fetched_at` is 0.
pub fn bundled() -> CodexModelList {
    CodexModelList {
        models: BUNDLED_MODELS
            .iter()
            .map(|(id, label)| CodexModel {
                id: (*id).to_string(),
                label: (*label).to_string(),
            })
            .collect(),
        source: ModelSource::Bundled,
        fetched_at: 0,
    }
}

/// Parses the `backend-api/codex/models` response body into a
/// `CodexModelList`. The response shape is documented-by-observation
/// (see journal 0010 for `wham/usage`; `codex/models` parallel shape):
/// `{"models": [{"id": "...", "display_name": "..."}, ...]}`. Unknown
/// fields are ignored via `#[serde(default)]`. Rejection on empty
/// models array is deliberate — an empty list from the upstream is
/// indistinguishable from a bogus-session response and MUST fall
/// through to cache/bundled.
pub fn parse_response(body: &[u8], now: u64) -> Result<CodexModelList, String> {
    #[derive(Deserialize)]
    struct RawModel {
        id: String,
        #[serde(default)]
        display_name: Option<String>,
    }
    #[derive(Deserialize)]
    struct RawList {
        #[serde(default)]
        models: Vec<RawModel>,
    }

    let raw: RawList = serde_json::from_slice(body).map_err(|e| format!("parse models: {e}"))?;
    if raw.models.is_empty() {
        return Err("upstream returned empty models array".into());
    }
    let models = raw
        .models
        .into_iter()
        .map(|m| CodexModel {
            label: m.display_name.unwrap_or_else(|| m.id.clone()),
            id: m.id,
        })
        .collect::<Vec<_>>();
    Ok(CodexModelList {
        models,
        source: ModelSource::Live,
        fetched_at: now,
    })
}

/// Orchestrator for [`list_models`] consumed by the Tauri command.
/// DI-injected so tests can feed pre-canned bytes without spawning
/// Node.
///
/// * `cache_lookup` — returns a fresh cached list or `None`.
/// * `fetcher` — consults the upstream. Returns `Ok(bytes)` on HTTP
///   200, any other outcome is an error string. Implementations use
///   `crate::http::get_bearer_node` in production.
/// * `cache_writer` — persists a freshly fetched list. Errors are
///   swallowed — a write failure must not abort the UI flow.
/// * `now` — unix epoch seconds, injected for deterministic tests.
pub fn list_models_with<F, C, W>(
    cache_lookup: C,
    fetcher: F,
    cache_writer: W,
    now: u64,
) -> CodexModelList
where
    C: FnOnce() -> Option<CodexModelList>,
    F: FnOnce() -> Result<Vec<u8>, String>,
    W: FnOnce(&CodexModelList),
{
    if let Some(c) = cache_lookup() {
        return c;
    }
    match fetcher() {
        Ok(bytes) => match parse_response(&bytes, now) {
            Ok(list) => {
                cache_writer(&list);
                list
            }
            Err(_) => bundled(),
        },
        Err(_) => bundled(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn bundled_is_never_empty() {
        let b = bundled();
        assert!(!b.models.is_empty(), "bundled cold-start MUST NOT be empty");
        assert_eq!(b.source, ModelSource::Bundled);
    }

    #[test]
    fn bundled_leads_with_provider_default() {
        // The catalog's `default_model` is `gpt-5.4` — the bundled
        // list's first entry must match so users see the default
        // pre-selected in the dropdown.
        let b = bundled();
        assert_eq!(b.models[0].id, "gpt-5.4");
        let default_model = crate::providers::get_provider("codex")
            .unwrap()
            .default_model;
        assert_eq!(
            b.models[0].id, default_model,
            "bundled lead must match catalog default"
        );
    }

    #[test]
    fn parse_response_handles_minimal_shape() {
        let body = br#"{"models":[{"id":"gpt-5.4","display_name":"GPT 5.4"},{"id":"gpt-5"}]}"#;
        let list = parse_response(body, 1_000).unwrap();
        assert_eq!(list.models.len(), 2);
        assert_eq!(list.models[0].id, "gpt-5.4");
        assert_eq!(list.models[0].label, "GPT 5.4");
        assert_eq!(list.models[1].id, "gpt-5");
        assert_eq!(list.models[1].label, "gpt-5", "label falls back to id");
        assert_eq!(list.source, ModelSource::Live);
        assert_eq!(list.fetched_at, 1_000);
    }

    #[test]
    fn parse_response_rejects_empty_models_array() {
        let body = br#"{"models":[]}"#;
        assert!(parse_response(body, 0).is_err());
    }

    #[test]
    fn parse_response_rejects_invalid_json() {
        assert!(parse_response(b"not json", 0).is_err());
    }

    #[test]
    fn parse_response_tolerates_unknown_fields() {
        let body = br#"{"models":[{"id":"x","display_name":"X","canary":true}],"meta":{"v":2}}"#;
        let list = parse_response(body, 0).unwrap();
        assert_eq!(list.models.len(), 1);
    }

    #[test]
    fn read_cache_returns_none_when_missing() {
        let dir = TempDir::new().unwrap();
        assert!(read_cache(dir.path(), 0).is_none());
    }

    #[test]
    fn write_then_read_cache_round_trips() {
        let dir = TempDir::new().unwrap();
        let list = CodexModelList {
            models: vec![CodexModel {
                id: "gpt-x".into(),
                label: "GPT X".into(),
            }],
            source: ModelSource::Live,
            fetched_at: 1_000,
        };
        write_cache(dir.path(), &list).unwrap();
        let roundtrip = read_cache(dir.path(), 1_050).unwrap();
        assert_eq!(roundtrip.models, list.models);
        assert_eq!(
            roundtrip.source,
            ModelSource::Cached,
            "source always flips to Cached on read"
        );
        assert_eq!(roundtrip.fetched_at, 1_000);
    }

    #[test]
    fn read_cache_returns_none_when_stale() {
        let dir = TempDir::new().unwrap();
        let list = CodexModelList {
            models: vec![CodexModel {
                id: "gpt-x".into(),
                label: "gpt-x".into(),
            }],
            source: ModelSource::Live,
            fetched_at: 1_000,
        };
        write_cache(dir.path(), &list).unwrap();
        let now = 1_000 + CACHE_TTL_SECS + 1;
        assert!(read_cache(dir.path(), now).is_none());
    }

    #[test]
    fn read_cache_returns_none_when_models_empty() {
        let dir = TempDir::new().unwrap();
        let list = CodexModelList {
            models: vec![],
            source: ModelSource::Live,
            fetched_at: 1_000,
        };
        write_cache(dir.path(), &list).unwrap();
        assert!(
            read_cache(dir.path(), 1_050).is_none(),
            "empty cache is not a valid list"
        );
    }

    #[test]
    fn list_models_prefers_cache_hit() {
        let cached = CodexModelList {
            models: vec![CodexModel {
                id: "gpt-cached".into(),
                label: "gpt-cached".into(),
            }],
            source: ModelSource::Cached,
            fetched_at: 500,
        };
        let fetch_called = std::cell::Cell::new(false);
        let write_called = std::cell::Cell::new(false);
        let out = list_models_with(
            || Some(cached.clone()),
            || {
                fetch_called.set(true);
                Err("should not run".into())
            },
            |_| write_called.set(true),
            1_000,
        );
        assert_eq!(out, cached);
        assert!(!fetch_called.get(), "fetch must NOT run on cache hit");
        assert!(!write_called.get(), "cache write must NOT run on cache hit");
    }

    #[test]
    fn list_models_fetches_and_caches_on_miss() {
        let write_calls = std::cell::Cell::new(0);
        let body = br#"{"models":[{"id":"a"},{"id":"b"}]}"#.to_vec();
        let out = list_models_with(
            || None,
            move || Ok(body.clone()),
            |_| write_calls.set(write_calls.get() + 1),
            42,
        );
        assert_eq!(out.models.len(), 2);
        assert_eq!(out.source, ModelSource::Live);
        assert_eq!(out.fetched_at, 42);
        assert_eq!(write_calls.get(), 1, "live fetch must persist to cache");
    }

    #[test]
    fn list_models_falls_back_to_bundled_on_fetch_error() {
        let write_calls = std::cell::Cell::new(0);
        let out = list_models_with(
            || None,
            || Err("network exploded".into()),
            |_| write_calls.set(write_calls.get() + 1),
            0,
        );
        assert_eq!(out.source, ModelSource::Bundled);
        assert!(!out.models.is_empty());
        assert_eq!(
            write_calls.get(),
            0,
            "bundled fallback must NOT overwrite the cache"
        );
    }

    #[test]
    fn list_models_falls_back_to_bundled_on_parse_error() {
        let out = list_models_with(
            || None,
            || Ok(b"not json".to_vec()),
            |_| panic!("no cache write on parse error"),
            0,
        );
        assert_eq!(out.source, ModelSource::Bundled);
        assert!(!out.models.is_empty());
    }

    #[test]
    fn list_models_never_returns_empty_list() {
        // The invariant the desktop UI depends on.
        let a = list_models_with(|| None, || Err("x".into()), |_| {}, 0);
        assert!(!a.models.is_empty());

        let b = list_models_with(|| None, || Ok(b"{}".to_vec()), |_| {}, 0);
        assert!(!b.models.is_empty());

        let c = list_models_with(|| None, || Ok(br#"{"models":[]}"#.to_vec()), |_| {}, 0);
        assert!(!c.models.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cache_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let list = CodexModelList {
            models: vec![CodexModel {
                id: "x".into(),
                label: "x".into(),
            }],
            source: ModelSource::Live,
            fetched_at: 1,
        };
        write_cache(dir.path(), &list).unwrap();
        let mode = std::fs::metadata(cache_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
