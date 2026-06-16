//! Codex models catalog — bundled cold-start + 1.5s live fetch + codex-cli probe + cache.
//!
//! The desktop `ChangeModelModal` for a Codex-surface slot needs a
//! list of valid model ids the user can pick without typing. Four
//! layered sources, consulted in this order by [`list_models`]:
//!
//! 1. **On-disk cache** (`accounts/codex-models-cache.json`). If present
//!    and not older than [`CACHE_TTL_SECS`], returned immediately. The
//!    cache record carries its own timestamp so the UI can render a
//!    "Cached Nm ago" hint.
//! 2. **Live HTTP fetch** via Node transport to
//!    `https://chatgpt.com/backend-api/codex/models` with a
//!    [`LIVE_FETCH_TIMEOUT_MS`] cap. Success rewrites the cache.
//! 3. **codex-cli probe** via `codex debug models` subprocess.
//!    The codex-cli binary ships with a frozen catalog snapshot
//!    that matches what its TUI shows; probing it gives accurate
//!    ordering + display names without requiring an authenticated
//!    HTTP fetch. Used as the offline / no-codex-account fallback.
//!    Cached on success.
//! 4. **Bundled cold-start list** if all of the above fail. Returned
//!    with `source == Bundled` so the UI can warn the user that the
//!    list may be stale.
//!
//! Design invariant: the returned `Vec<String>` is **never empty** on
//! any path. A "no models" return from any upstream is itself a cache
//! miss and is treated as a fetch failure that falls through to the
//! next tier.
//!
//! This module is consumed by the `list_codex_models` Tauri command
//! in PR-C8. The CLI does not call it directly — `csq models switch
//! codex <id> --force` already has a different escape hatch (FR-CLI-04
//! via `--force` per PR-C7), and the curated CLI catalog is
//! deliberately minimal.
//!
//! The codex-cli probe was added 2026-05-07 per `/autonomize` item 2
//! (operator request: "dynamic fetch from codex-cli, not hardcoded").
//! `codex debug models` emits JSON with `slug` / `display_name` /
//! `priority` / `visibility` — same structural shape this module's
//! parser expects, with a small adapter for the field-name variation
//! (`slug` vs `id`).

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

/// Bundled cold-start model list. Consulted only when the cache,
/// the live HTTP fetch, AND the codex-cli probe all fail. Kept
/// deliberately short: the provider's `default_model` (per catalog)
/// plus the two most likely alternatives a real user would recognize.
/// A fresh `csq` install on a machine with no codex-cli installed
/// AND no network will show these; as soon as either the live HTTP
/// fetch or the codex-cli probe succeeds, the on-disk cache
/// supersedes them.
///
/// The entries are `(id, label)` pairs — the `id` is what gets
/// written to `config.toml`; the `label` is the UI dropdown text.
///
/// First entry MUST equal the catalog's `default_model` so the
/// dropdown pre-selects the same model `csq run` would write to a
/// fresh slot's `config.toml`. The other entries are sorted by
/// codex-cli's `priority` field as observed at csq build time — they
/// drift over time but the codex-cli probe (when available) is the
/// dynamic source of truth so this drift is bounded by "what a fresh
/// install with no codex-cli sees on day 1."
///
/// Last refreshed 2026-05-11 from upstream tooltip ("GPT-5.5 is now available
/// in Codex... our strongest agentic coding model yet"). The 2026-05-07
/// refresh against codex-cli 0.128.0 had 5.4 as default; OpenAI promoted 5.5
/// to default between then and now. v2.7.1 patch.
pub const BUNDLED_MODELS: &[(&str, &str)] = &[
    ("gpt-5.5", "GPT-5.5 (default)"),
    ("gpt-5.4", "GPT-5.4"),
    ("gpt-5.3-codex", "gpt-5.3-codex"),
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
/// "Cached Nm ago" vs "Live" vs "From codex-cli" vs "Cold-start
/// (offline)" hint. Variants ordered by freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelSource {
    /// HTTP fetch against `chatgpt.com/backend-api/codex/models`.
    Live,
    /// On-disk cache hit (any prior source).
    Cached,
    /// `codex debug models` subprocess probe — codex-cli's frozen
    /// catalog snapshot. Used when the HTTP path is unavailable
    /// (offline, no Codex account, throttled).
    CodexCli,
    /// In-binary cold-start list. Drift-prone; only shown when no
    /// other source is available.
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

/// Parses the `codex debug models` JSON output into a
/// `CodexModelList`. Distinct from `parse_response` because the
/// codex-cli output uses `slug` (not `id`) for the model identifier
/// and adds `priority` + `visibility` fields. We:
///
/// - filter to `visibility == "list"` so hidden / removed models
///   don't appear in the dropdown
/// - sort ascending by `priority` so the codex-cli's recommended
///   model (priority 0) leads the dropdown
/// - map `display_name` → label, falling back to `slug` if missing
///
/// Origin: /autonomize item 2 (2026-05-07) — operator request to
/// dynamically fetch the model list from codex-cli rather than
/// trusting the bundled snapshot. `codex debug models` is the
/// authoritative source codex-cli's TUI uses for its own picker.
pub fn parse_codex_cli_models(stdout: &[u8], now: u64) -> Result<CodexModelList, String> {
    #[derive(Deserialize)]
    struct CliModel {
        slug: String,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        priority: i64,
        #[serde(default = "default_visibility")]
        visibility: String,
    }
    fn default_visibility() -> String {
        "hidden".to_string()
    }
    #[derive(Deserialize)]
    struct CliPayload {
        #[serde(default)]
        models: Vec<CliModel>,
    }

    let raw: CliPayload = serde_json::from_slice(stdout)
        .map_err(|e| format!("parse codex debug models output: {e}"))?;
    let mut visible: Vec<CliModel> = raw
        .models
        .into_iter()
        .filter(|m| m.visibility == "list")
        .collect();
    if visible.is_empty() {
        return Err("codex debug models returned no list-visible entries".into());
    }
    visible.sort_by_key(|m| m.priority);
    let models = visible
        .into_iter()
        .map(|m| CodexModel {
            label: m.display_name.unwrap_or_else(|| m.slug.clone()),
            id: m.slug,
        })
        .collect::<Vec<_>>();
    Ok(CodexModelList {
        models,
        source: ModelSource::CodexCli,
        fetched_at: now,
    })
}

/// Orchestrator for [`list_models`] consumed by the Tauri command.
/// DI-injected so tests can feed pre-canned bytes without spawning
/// Node OR codex-cli.
///
/// Tier order:
///
/// 1. `cache_lookup` — returns a fresh cached list or `None`.
/// 2. `http_fetcher` — consults `chatgpt.com/backend-api/codex/models`.
///    Returns `Ok(bytes)` on HTTP 200, error string otherwise.
/// 3. `cli_probe` — runs `codex debug models` subprocess. Returns
///    `Ok(stdout_bytes)` on exit 0 + parseable JSON, error otherwise.
/// 4. `bundled()` — last-resort cold-start list.
///
/// `cache_writer` persists a freshly fetched list (from either tier
/// 2 or tier 3). Errors are swallowed — a write failure must not
/// abort the UI flow. `now` is unix epoch seconds, injected for
/// deterministic tests.
pub fn list_models_with<C, F, P, W>(
    cache_lookup: C,
    http_fetcher: F,
    cli_probe: P,
    cache_writer: W,
    now: u64,
) -> CodexModelList
where
    C: FnOnce() -> Option<CodexModelList>,
    F: FnOnce() -> Result<Vec<u8>, String>,
    P: FnOnce() -> Result<Vec<u8>, String>,
    W: FnOnce(&CodexModelList),
{
    if let Some(c) = cache_lookup() {
        return c;
    }
    if let Ok(bytes) = http_fetcher() {
        if let Ok(list) = parse_response(&bytes, now) {
            cache_writer(&list);
            return list;
        }
    }
    if let Ok(stdout) = cli_probe() {
        if let Ok(list) = parse_codex_cli_models(&stdout, now) {
            cache_writer(&list);
            return list;
        }
    }
    bundled()
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
        // The catalog's `default_model` is `gpt-5.5` (v2.7.1+) — the bundled
        // list's first entry must match so users see the default
        // pre-selected in the dropdown.
        let b = bundled();
        assert_eq!(b.models[0].id, "gpt-5.5");
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
        let cli_called = std::cell::Cell::new(false);
        let write_called = std::cell::Cell::new(false);
        let out = list_models_with(
            || Some(cached.clone()),
            || {
                fetch_called.set(true);
                Err("should not run".into())
            },
            || {
                cli_called.set(true);
                Err("should not run".into())
            },
            |_| write_called.set(true),
            1_000,
        );
        assert_eq!(out, cached);
        assert!(!fetch_called.get(), "HTTP fetch must NOT run on cache hit");
        assert!(!cli_called.get(), "CLI probe must NOT run on cache hit");
        assert!(!write_called.get(), "cache write must NOT run on cache hit");
    }

    #[test]
    fn list_models_fetches_and_caches_on_miss() {
        let write_calls = std::cell::Cell::new(0);
        let body = br#"{"models":[{"id":"a"},{"id":"b"}]}"#.to_vec();
        let cli_called = std::cell::Cell::new(false);
        let out = list_models_with(
            || None,
            move || Ok(body.clone()),
            || {
                cli_called.set(true);
                Err("should not run".into())
            },
            |_| write_calls.set(write_calls.get() + 1),
            42,
        );
        assert_eq!(out.models.len(), 2);
        assert_eq!(out.source, ModelSource::Live);
        assert_eq!(out.fetched_at, 42);
        assert_eq!(write_calls.get(), 1, "live fetch must persist to cache");
        assert!(
            !cli_called.get(),
            "CLI probe must NOT run when HTTP succeeds"
        );
    }

    #[test]
    fn list_models_falls_through_to_cli_probe_on_http_failure() {
        // codex debug models output shape: `slug` not `id`,
        // `priority` for ordering, `visibility=list` for filter.
        let cli_stdout = br#"{"models":[
            {"slug":"gpt-5.5","display_name":"GPT-5.5","priority":0,"visibility":"list"},
            {"slug":"gpt-5.4","display_name":"gpt-5.4","priority":2,"visibility":"list"},
            {"slug":"gpt-hidden","display_name":"hidden","priority":99,"visibility":"hidden"}
        ]}"#
        .to_vec();
        let write_calls = std::cell::Cell::new(0);
        let out = list_models_with(
            || None,
            || Err("HTTP exploded".into()),
            move || Ok(cli_stdout.clone()),
            |_| write_calls.set(write_calls.get() + 1),
            123,
        );
        assert_eq!(out.source, ModelSource::CodexCli);
        assert_eq!(out.fetched_at, 123);
        assert_eq!(out.models.len(), 2, "hidden visibility must be filtered");
        assert_eq!(out.models[0].id, "gpt-5.5", "priority=0 must lead");
        assert_eq!(out.models[1].id, "gpt-5.4");
        assert_eq!(
            write_calls.get(),
            1,
            "CLI probe success must persist to cache"
        );
    }

    #[test]
    fn list_models_falls_back_to_bundled_when_all_tiers_fail() {
        let write_calls = std::cell::Cell::new(0);
        let out = list_models_with(
            || None,
            || Err("network exploded".into()),
            || Err("codex-cli not installed".into()),
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
    fn list_models_falls_back_to_bundled_on_http_parse_error_and_cli_failure() {
        let out = list_models_with(
            || None,
            || Ok(b"not json".to_vec()),
            || Err("codex-cli unavailable".into()),
            |_| panic!("no cache write on parse error"),
            0,
        );
        assert_eq!(out.source, ModelSource::Bundled);
        assert!(!out.models.is_empty());
    }

    #[test]
    fn list_models_falls_through_http_parse_error_to_cli_probe() {
        // HTTP returns garbage; codex-cli probe succeeds. The cli
        // probe MUST be consulted — bundled is only the final tier.
        let cli_stdout =
            br#"{"models":[{"slug":"x","display_name":"X","priority":0,"visibility":"list"}]}"#
                .to_vec();
        let out = list_models_with(
            || None,
            || Ok(b"not json".to_vec()),
            move || Ok(cli_stdout.clone()),
            |_| {},
            10,
        );
        assert_eq!(out.source, ModelSource::CodexCli);
        assert_eq!(out.models.len(), 1);
        assert_eq!(out.models[0].id, "x");
    }

    #[test]
    fn list_models_never_returns_empty_list() {
        // The invariant the desktop UI depends on. Test all four tiers:
        // empty cache → empty HTTP → empty CLI → bundled (non-empty).
        let a = list_models_with(|| None, || Err("x".into()), || Err("y".into()), |_| {}, 0);
        assert!(!a.models.is_empty());

        let b = list_models_with(
            || None,
            || Ok(b"{}".to_vec()),
            || Err("y".into()),
            |_| {},
            0,
        );
        assert!(!b.models.is_empty());

        let c = list_models_with(
            || None,
            || Ok(br#"{"models":[]}"#.to_vec()),
            || Err("y".into()),
            |_| {},
            0,
        );
        assert!(!c.models.is_empty());

        // CLI probe returns empty visibility=list set → still falls
        // through to bundled.
        let d = list_models_with(
            || None,
            || Err("x".into()),
            || Ok(br#"{"models":[{"slug":"x","visibility":"hidden","priority":0}]}"#.to_vec()),
            |_| {},
            0,
        );
        assert!(!d.models.is_empty());
        assert_eq!(d.source, ModelSource::Bundled);
    }

    #[test]
    fn parse_codex_cli_models_filters_hidden_visibility() {
        let stdout = br#"{"models":[
            {"slug":"a","display_name":"A","priority":1,"visibility":"list"},
            {"slug":"b","display_name":"B","priority":0,"visibility":"hidden"},
            {"slug":"c","priority":2,"visibility":"list"}
        ]}"#;
        let list = parse_codex_cli_models(stdout, 100).unwrap();
        assert_eq!(list.models.len(), 2);
        // Sorted by priority — `a` has priority=1, `c` has priority=2.
        assert_eq!(list.models[0].id, "a");
        assert_eq!(list.models[0].label, "A");
        assert_eq!(list.models[1].id, "c");
        assert_eq!(
            list.models[1].label, "c",
            "label falls back to slug when display_name absent"
        );
        assert_eq!(list.source, ModelSource::CodexCli);
        assert_eq!(list.fetched_at, 100);
    }

    #[test]
    fn parse_codex_cli_models_rejects_only_hidden() {
        let stdout = br#"{"models":[{"slug":"a","priority":0,"visibility":"hidden"}]}"#;
        assert!(parse_codex_cli_models(stdout, 0).is_err());
    }

    #[test]
    fn parse_codex_cli_models_rejects_invalid_json() {
        assert!(parse_codex_cli_models(b"not json", 0).is_err());
    }

    #[test]
    fn parse_codex_cli_models_handles_real_codex_cli_shape() {
        // Real `codex debug models` output (codex-cli 0.128.0) has
        // many additional fields per model — `description`,
        // `default_reasoning_level`, `supported_reasoning_levels`,
        // `shell_type`, `supported_in_api`, `availability_nux`,
        // `base_instructions`, etc. The parser ignores unknown fields
        // via the default behavior of `#[serde(default)]` on optional
        // ones; this regression test pins that.
        let stdout = br#"{"models":[
            {
                "slug":"gpt-5.5",
                "display_name":"GPT-5.5",
                "description":"Frontier model.",
                "default_reasoning_level":"medium",
                "shell_type":"shell_command",
                "visibility":"list",
                "supported_in_api":true,
                "priority":0,
                "extra_unknown_field":42
            }
        ]}"#;
        let list = parse_codex_cli_models(stdout, 0).unwrap();
        assert_eq!(list.models.len(), 1);
        assert_eq!(list.models[0].id, "gpt-5.5");
        assert_eq!(list.models[0].label, "GPT-5.5");
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
