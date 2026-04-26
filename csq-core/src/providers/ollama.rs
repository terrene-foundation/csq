//! Ollama integration — query local Ollama server for available models.
//!
//! Lists installed models via the HTTP API at `http://localhost:11434/api/tags`
//! rather than shelling out to `ollama list`. This avoids the PATH-dependent
//! subprocess failure mode where a Finder-launched Tauri app has
//! `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and cannot locate ollama at
//! `/usr/local/bin/ollama` (Intel Homebrew) or `/opt/homebrew/bin/ollama`
//! (Apple Silicon). HTTP also fails faster on a down server (2s connect
//! timeout vs a subprocess that can hang on TCC/Gatekeeper checks).

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use tracing::debug;

/// URL of the local Ollama server's tags endpoint.
const TAGS_URL: &str = "http://localhost:11434/api/tags";

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

/// Returns the list of locally-installed Ollama models by calling the
/// Ollama HTTP API. Returns empty if the daemon isn't running, the
/// request times out, or the response is malformed — callers treat
/// empty as "no models installed" (the UI then prompts for a pull).
pub fn get_ollama_models() -> Vec<String> {
    // Dedicated client — the shared csq-core client is `https_only(true)`
    // for credential safety; ollama is a local plaintext endpoint so we
    // build a minimal one here.
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

    let resp = match client.get(TAGS_URL).send() {
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
}
