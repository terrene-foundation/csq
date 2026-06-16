//! Ollama integration — query Ollama server for available models.
//!
//! Lists installed models via the HTTP API at `<base>/api/tags` rather than
//! shelling out to `ollama list`. This avoids the PATH-dependent subprocess
//! failure mode where a Finder-launched Tauri app has
//! `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and cannot locate ollama at
//! `/usr/local/bin/ollama` (Intel Homebrew) or `/opt/homebrew/bin/ollama`
//! (Apple Silicon). HTTP also fails faster on a down server (2s connect
//! timeout vs a subprocess that can hang on TCC/Gatekeeper checks).
//!
//! The base URL is resolved from `OLLAMA_HOST` (matching the official
//! `ollama` CLI), falling back to `http://localhost:11434`. This lets
//! csq see models on a remote daemon (Tailscale/LAN) when the daemon
//! is bound to a non-loopback address.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use tracing::debug;

/// Default base URL when `OLLAMA_HOST` is unset.
const DEFAULT_BASE_URL: &str = "http://localhost:11434";

/// Default Ollama port — used when `OLLAMA_HOST` carries a host but no
/// port, matching the upstream CLI's resolution.
const DEFAULT_PORT: u16 = 11434;

/// Short timeout — the endpoint is localhost, so anything beyond this
/// means the daemon is wedged and we should fail fast rather than freeze
/// the UI.
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct TagsResponse {
    models: Vec<TagEntry>,
}

#[derive(Deserialize)]
struct TagEntry {
    name: String,
}

/// Resolves the Ollama tags endpoint from `OLLAMA_HOST`, falling back
/// to `http://localhost:11434/api/tags`.
///
/// Accepts the same shapes the upstream `ollama` CLI accepts so that
/// users who have already configured `OLLAMA_HOST` for the CLI see the
/// same models in csq:
///
/// - unset → `http://localhost:11434/api/tags`
/// - `http://host:port` / `https://host:port` → preserved scheme + host
/// - `host:port` → `http://host:port`
/// - `host` → `http://host:11434`
/// - `:port` → `http://127.0.0.1:port`
///
/// Trailing slashes on the base are trimmed before appending `/api/tags`.
fn resolve_tags_url() -> String {
    let raw = match std::env::var("OLLAMA_HOST") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => return format!("{DEFAULT_BASE_URL}/api/tags"),
    };

    let base = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw
    } else if let Some(rest) = raw.strip_prefix(':') {
        format!("http://127.0.0.1:{rest}")
    } else if raw.contains(':') {
        format!("http://{raw}")
    } else {
        format!("http://{raw}:{DEFAULT_PORT}")
    };

    format!("{}/api/tags", base.trim_end_matches('/'))
}

/// Returns the list of installed Ollama models by calling the Ollama
/// HTTP API. The endpoint host is resolved from `OLLAMA_HOST`
/// (default: `http://localhost:11434`). Returns empty if the daemon
/// isn't reachable, the request times out, or the response is
/// malformed — callers treat empty as "no models installed" (the UI
/// then prompts for a pull).
pub fn get_ollama_models() -> Vec<String> {
    // Dedicated client — the shared csq-core client is `https_only(true)`
    // for credential safety; ollama is a plaintext endpoint so we build
    // a minimal one here.
    let client = match reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(HTTP_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "failed to build ollama http client");
            return vec![];
        }
    };

    let url = resolve_tags_url();
    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "ollama /api/tags request failed");
            return vec![];
        }
    };

    if !resp.status().is_success() {
        debug!(status = %resp.status(), "ollama /api/tags returned non-2xx");
        return vec![];
    }

    let body = match resp.text() {
        Ok(t) => t,
        Err(e) => {
            debug!(error = %e, "ollama /api/tags response read failed");
            return vec![];
        }
    };

    match serde_json::from_str::<TagsResponse>(&body) {
        Ok(parsed) => parsed.models.into_iter().map(|m| m.name).collect(),
        Err(e) => {
            debug!(error = %e, "ollama /api/tags response parse failed");
            vec![]
        }
    }
}

/// Resolves a usable path to the `ollama` executable for subprocess
/// callers (the pull path streams stdout for progress, so HTTP would
/// require re-implementing the streaming protocol).
///
/// Search order:
///
/// 1. `OLLAMA_BIN` environment variable if set and executable.
/// 2. `/usr/local/bin/ollama` (Intel Homebrew / generic Linux).
/// 3. `/opt/homebrew/bin/ollama` (Apple Silicon Homebrew).
/// 4. Bare `"ollama"` — lets the OS do PATH lookup. Works from a
///    shell-launched context but fails from a Finder-launched macOS
///    GUI where PATH is `/usr/bin:/bin:/usr/sbin:/sbin`.
///
/// Returns `None` only if none of the known paths exist AND the
/// `OLLAMA_BIN` override is unset. Callers surface this as an
/// "ollama not found — install via https://ollama.com" error.
pub fn find_ollama_bin() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("OLLAMA_BIN") {
        let p = PathBuf::from(&override_path);
        if p.is_file() {
            return Some(p);
        }
        debug!(path = %override_path, "OLLAMA_BIN set but not a file — ignoring");
    }

    for candidate in ["/usr/local/bin/ollama", "/opt/homebrew/bin/ollama"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }

    // PATH-based fallback. Only reliable when the caller inherited a
    // user shell's PATH. Callers in a GUI context should treat None
    // from this function as "not found" rather than spawning "ollama"
    // and getting a confusing ENOENT.
    Some(PathBuf::from("ollama"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_ollama_bin_respects_env_override_when_file_exists() {
        // Cargo runs tests in parallel; without the shared mutex,
        // concurrent tests reading or mutating any env var (PATH, HOME,
        // OLLAMA_BIN, …) race with this test's set_var. See
        // `crate::platform::test_env`.
        let _shared_env_guard = crate::platform::test_env::lock();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().into_owned();

        let prev = std::env::var("OLLAMA_BIN").ok();
        std::env::set_var("OLLAMA_BIN", &path);

        let resolved = find_ollama_bin().unwrap();
        assert_eq!(resolved.to_string_lossy(), path);

        match prev {
            Some(v) => std::env::set_var("OLLAMA_BIN", v),
            None => std::env::remove_var("OLLAMA_BIN"),
        }
    }

    #[test]
    fn find_ollama_bin_falls_through_when_override_points_at_nonexistent_file() {
        let _shared_env_guard = crate::platform::test_env::lock();

        let prev = std::env::var("OLLAMA_BIN").ok();
        std::env::set_var("OLLAMA_BIN", "/nonexistent/ollama-binary-xyzzy");

        // Should ignore the bad override and return something (either a
        // known path if this host has ollama installed, or the bare
        // "ollama" fallback).
        let resolved = find_ollama_bin();
        assert!(resolved.is_some());
        assert_ne!(
            resolved.unwrap().to_string_lossy(),
            "/nonexistent/ollama-binary-xyzzy"
        );

        match prev {
            Some(v) => std::env::set_var("OLLAMA_BIN", v),
            None => std::env::remove_var("OLLAMA_BIN"),
        }
    }

    #[test]
    fn tags_response_deserializes_from_real_shape() {
        // Trimmed real payload from `curl http://localhost:11434/api/tags`.
        let json = r#"{"models":[{"name":"qwen3:latest","model":"qwen3:latest","modified_at":"2026-04-08T00:00:00Z","size":5200000000,"digest":"abc"},{"name":"gemma4:latest","model":"gemma4:latest","modified_at":"2026-04-09T00:00:00Z","size":9600000000,"digest":"def"}]}"#;
        let parsed: TagsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.models.len(), 2);
        assert_eq!(parsed.models[0].name, "qwen3:latest");
        assert_eq!(parsed.models[1].name, "gemma4:latest");
    }

    #[test]
    fn tags_response_handles_empty_models_list() {
        let json = r#"{"models":[]}"#;
        let parsed: TagsResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.models.is_empty());
    }

    /// Helper: scopes an `OLLAMA_HOST` value across a closure, restoring
    /// the prior value (or absence) on exit. Acquires the shared env
    /// mutex for the duration so parallel tests don't race.
    fn with_ollama_host<F: FnOnce()>(value: Option<&str>, f: F) {
        let _shared_env_guard = crate::platform::test_env::lock();
        let prev = std::env::var("OLLAMA_HOST").ok();
        match value {
            Some(v) => std::env::set_var("OLLAMA_HOST", v),
            None => std::env::remove_var("OLLAMA_HOST"),
        }
        f();
        match prev {
            Some(v) => std::env::set_var("OLLAMA_HOST", v),
            None => std::env::remove_var("OLLAMA_HOST"),
        }
    }

    #[test]
    fn resolve_tags_url_falls_back_to_localhost_when_unset() {
        with_ollama_host(None, || {
            assert_eq!(resolve_tags_url(), "http://localhost:11434/api/tags");
        });
    }

    #[test]
    fn resolve_tags_url_falls_back_to_localhost_when_empty_or_whitespace() {
        with_ollama_host(Some(""), || {
            assert_eq!(resolve_tags_url(), "http://localhost:11434/api/tags");
        });
        with_ollama_host(Some("   "), || {
            assert_eq!(resolve_tags_url(), "http://localhost:11434/api/tags");
        });
    }

    #[test]
    fn resolve_tags_url_preserves_full_http_url() {
        with_ollama_host(Some("http://100.71.125.70:11434"), || {
            assert_eq!(resolve_tags_url(), "http://100.71.125.70:11434/api/tags");
        });
    }

    #[test]
    fn resolve_tags_url_preserves_full_https_url() {
        with_ollama_host(Some("https://ollama.example.com:8443"), || {
            assert_eq!(
                resolve_tags_url(),
                "https://ollama.example.com:8443/api/tags"
            );
        });
    }

    #[test]
    fn resolve_tags_url_strips_trailing_slash_before_appending_path() {
        with_ollama_host(Some("http://host.local:11434/"), || {
            assert_eq!(resolve_tags_url(), "http://host.local:11434/api/tags");
        });
    }

    #[test]
    fn resolve_tags_url_adds_http_scheme_to_host_port() {
        with_ollama_host(Some("192.168.1.10:11434"), || {
            assert_eq!(resolve_tags_url(), "http://192.168.1.10:11434/api/tags");
        });
    }

    #[test]
    fn resolve_tags_url_adds_default_port_to_bare_host() {
        with_ollama_host(Some("ollama.tail.net"), || {
            assert_eq!(resolve_tags_url(), "http://ollama.tail.net:11434/api/tags");
        });
    }

    #[test]
    fn resolve_tags_url_treats_bare_port_as_loopback() {
        with_ollama_host(Some(":11435"), || {
            assert_eq!(resolve_tags_url(), "http://127.0.0.1:11435/api/tags");
        });
    }
}
