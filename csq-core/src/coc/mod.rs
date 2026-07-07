//! Unified `.coc/` consumer contract.
//!
//! Authoritative spec: `specs/09-unified-coc-artifact-standard.md`. csq is
//! a CONSUMER of `.coc/`; format authorship lives at loom (per
//! `.claude/rules/csq-loom-boundary.md` MUST Rule 1). This module
//! implements the read-only consumer side: discover, parse, fall back to
//! legacy. Writes never happen under `.coc/` per FR-FMT-06 (enforced by
//! `csq-core/tests/coc_readonly.rs`).
//!
//! Per `internal-design-docs` the prior per-artifact signing
//! apparatus (`COC.sig`, `COC_SIGNING_PUBLIC_KEY_BYTES`) and the first-pull
//! trust gate (`coc-trust.json`) were retracted: `.coc/` is files in the
//! user's repo, structurally equivalent to `.claude/`. Deterministic
//! attestation belongs at the runtime lifecycle layer (Step 3, see
//! `internal-design-docs`).
//!
//! Module layout:
//! - `types` — `CocSet` and helpers (the canonical in-memory shape).
//! - `version` — `coc.version` envelope check (refuse / soft-window / ok).
//! - `yaml` — minimal YAML frontmatter parser.
//! - `loader` — walk-from-CWD discovery.
//! - `parser` — assembles `CocSet` from a `.coc/` directory.
//! - `cache` — `COC.lock` SHA-256 (cache-invalidation key) + parse cache.
//! - `fallback` — `.claude/` / `.gemini/` / `AGENTS.md` legacy chain.
//!
//! `load(project_root, base_dir)` orchestrates the full flow per spec 09.
//! Downstream stages (capability layer in spec 10) consume the returned
//! `CocSet` directly. `base_dir` is the csq accounts directory used for
//! version-grace state (`<base_dir>/coc-version-grace.json`).

pub mod cache;
pub mod fallback;
pub mod loader;
pub mod parser;
pub mod translate;
pub mod types;
pub mod version;
pub mod version_grace;
pub mod yaml;

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use self::cache::{lock_sha256, read_lock};
use self::fallback::{probe as legacy_probe, LegacyResolution};
use self::loader::discover;
use self::parser::parse_coc_dir;
use self::types::{CocSet, CocSource};
use self::version::CompatVerdict;

/// Errors that can arise from `load`. Most variants are non-fatal —
/// `load` may degrade to a different `CocSource` rather than propagate.
/// Only structural failures (e.g. corrupt parse) become errors.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("loader error: {0}")]
    Loader(#[from] loader::LoaderError),
    #[error("cache error: {0}")]
    Cache(#[from] cache::CacheError),
    #[error("parse error: {0}")]
    Parse(#[from] parser::ParseError),
    #[error("version compat: artifact requires {required_csq}; observed `{observed}`")]
    VersionRefused {
        observed: String,
        required_csq: String,
    },
}

/// Outcome of `load`. The caller honors `set` regardless — the various
/// degraded paths are recorded in `set.source` so downstream consumers can
/// adjust behavior (e.g. capability layer disables when source = `Empty`).
#[derive(Debug)]
pub struct LoadOutcome {
    pub set: CocSet,
    pub project_root: Option<PathBuf>,
}

/// Whether the load served a parsed result from the on-disk parse cache
/// (`Warm`) or had to run the full parse pipeline (`Cold`).
///
/// Per spec 10 §10.9.1 the bench harness measures both states; the CLI
/// emits `STAGE_COC_LOAD` on Warm and `STAGE_COC_LOAD_COLD` on Cold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warmth {
    /// Parse pipeline ran from disk. Cache was disabled, missing, or
    /// invalidated.
    Cold,
    /// Cache hit: parsed `CocSet` deserialized from
    /// `<coc_root>/.cache/parsed-<lock_sha>.bin`.
    Warm,
}

/// `LoadOutcome` paired with a `Warmth` tag describing whether the
/// parse-cache served the result.
#[derive(Debug)]
pub struct LoadOutcomeWithWarmth {
    pub outcome: LoadOutcome,
    pub warmth: Warmth,
}

/// Load `.coc/` (or fall back to legacy) starting from `start`.
///
/// `base_dir` is csq's accounts directory (typically
/// `~/.claude/accounts/`); the version-grace state file lives at
/// `<base_dir>/coc-version-grace.json`. Tests pass an isolated path.
///
/// This is the cache-disabled entry point. Production callers that want
/// the parse-cache behavior (warm hit emission + atomic write on miss)
/// should use [`load_with_cache`] directly.
pub fn load(start: &Path, base_dir: &Path) -> Result<LoadOutcome, LoadError> {
    Ok(load_with_cache(start, base_dir, false)?.outcome)
}

/// Load `.coc/` with optional parse-cache participation.
///
/// When `cache_enabled` is `true`:
/// - On cache hit (filename matches `lock_sha`, header validates), the
///   cached `CocSet` is returned with `Warmth::Warm`.
/// - On cache miss, the parse pipeline runs and the result is written to
///   `<coc_root>/.cache/parsed-<lock_sha>.bin` before returning Cold.
///
/// When `cache_enabled` is `false`, the cache is neither read nor written;
/// every invocation runs the parse pipeline and returns `Warmth::Cold`.
///
/// Cache is bypassed (Cold) without a write attempt when:
/// - `.coc/` is absent (legacy fallback path).
/// - `COC.lock` is missing (no key for the cache).
pub fn load_with_cache(
    start: &Path,
    base_dir: &Path,
    cache_enabled: bool,
) -> Result<LoadOutcomeWithWarmth, LoadError> {
    let location = match discover(start)? {
        Some(loc) => loc,
        None => {
            return Ok(LoadOutcomeWithWarmth {
                outcome: LoadOutcome {
                    set: load_legacy_or_empty(start),
                    project_root: None,
                },
                warmth: Warmth::Cold,
            });
        }
    };

    // Read COC.lock — required as the cache-invalidation key. Missing →
    // fall through to legacy (no key for the cache + no way to detect
    // content drift between sessions).
    let lock_bytes = match read_lock(&location.coc_dir)? {
        Some(b) => b,
        None => {
            warn!(
                event = "coc.missing_lock",
                project_root = %location.project_root.display(),
                "COC.lock absent under .coc/; treating as missing and falling back"
            );
            return Ok(LoadOutcomeWithWarmth {
                outcome: LoadOutcome {
                    set: load_legacy_or_empty(&location.project_root),
                    project_root: Some(location.project_root),
                },
                warmth: Warmth::Cold,
            });
        }
    };
    let lock_sha = lock_sha256(&lock_bytes);

    // Cache hit attempt.
    if cache_enabled {
        if let Some(mut cached_set) = cache::read_parsed_cache(&location.project_root, &lock_sha) {
            // Replace the cached set's source with the freshly observed
            // lock_sha so downstream consumers see current disk state.
            cached_set.source = CocSource::Coc {
                lock_sha256: lock_sha,
            };
            check_version_envelope(&cached_set, base_dir)?;
            info!(
                event = "coc.cache_hit",
                project_root = %location.project_root.display(),
                version = %cached_set.version,
                rule_count = cached_set.rules.len(),
                "served .coc/ from parse cache"
            );
            return Ok(LoadOutcomeWithWarmth {
                outcome: LoadOutcome {
                    set: cached_set,
                    project_root: Some(location.project_root),
                },
                warmth: Warmth::Warm,
            });
        }
    }

    // Cold path: parse `.coc/` content.
    let source = CocSource::Coc {
        lock_sha256: lock_sha,
    };
    let set = parse_coc_dir(&location.coc_dir, source)?;
    check_version_envelope(&set, base_dir)?;

    // Best-effort cache write on cold path. A write failure must NOT
    // block the load — the parse already produced the canonical result.
    if cache_enabled {
        if let Err(e) = cache::write_parsed_cache(&location.project_root, &lock_sha, &set) {
            warn!(
                event = "coc.cache_write_failed",
                project_root = %location.project_root.display(),
                "failed to persist parse cache: {e}"
            );
        }
    }

    info!(
        event = "coc.fallback",
        source = "coc",
        project_root = %location.project_root.display(),
        version = %set.version,
        rule_count = set.rules.len(),
        "loaded .coc/"
    );

    Ok(LoadOutcomeWithWarmth {
        outcome: LoadOutcome {
            set,
            project_root: Some(location.project_root),
        },
        warmth: Warmth::Cold,
    })
}

/// Run the version envelope check on a `CocSet`. Shared between the
/// cache-hit and cache-miss paths so both honor the same version policy
/// (spec 09 §9.4): warn on experimental / forward-compat-soft / beyond-
/// window, refuse on too-new (subject to the M6 PR-CA13 grace window).
///
/// `base_dir` is csq's accounts directory; the grace state lives at
/// `<base_dir>/coc-version-grace.json`. Tests pass an isolated path.
fn check_version_envelope(set: &CocSet, base_dir: &Path) -> Result<(), LoadError> {
    let raw_verdict = set.version.check();
    // Grace promotion (M6 PR-CA13): RefuseTooNew may degrade into
    // GraceWindowDegraded if first observed within SOFT_GRACE_DAYS.
    // Other verdicts pass through unchanged.
    let verdict = if matches!(raw_verdict, CompatVerdict::RefuseTooNew { .. }) {
        let mut state = version_grace::load_grace_state(base_dir);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let promoted = raw_verdict.apply_grace(&mut state, now_unix);
        // Persist the (possibly-updated) state. A write failure must
        // NOT block the load — the verdict in hand is still
        // load-bearing; we just lose the grace clock for next run.
        if let Err(e) = version_grace::save_grace_state(base_dir, &state) {
            warn!(
                event = "coc.version_grace_write_failed",
                error = %e,
                "failed to persist coc-version-grace.json"
            );
        }
        promoted
    } else {
        raw_verdict
    };

    match verdict {
        CompatVerdict::Ok => Ok(()),
        CompatVerdict::Experimental => {
            warn!(
                event = "coc.version_experimental",
                version = %set.version,
                "loaded experimental coc.version (major=0); behavior may change"
            );
            Ok(())
        }
        CompatVerdict::ForwardCompatSoft { .. } => {
            warn!(
                event = "coc.fallback_forward_compat",
                version = %set.version,
                "csq is older than artifact; loading in forward-compat soft mode"
            );
            Ok(())
        }
        CompatVerdict::ForwardCompatBeyondWindow { .. } => {
            warn!(
                event = "coc.version_window_exceeded",
                version = %set.version,
                "csq is more than 2 minor releases behind artifact"
            );
            Ok(())
        }
        CompatVerdict::GraceWindowDegraded {
            observed,
            max_known_major: _,
            required_csq,
            days_remaining,
        } => {
            // Soft grace: load in degraded mode + surface the
            // "csq update needed" banner via WARN log. A future
            // desktop tray banner consumer subscribes to this event.
            warn!(
                event = "coc.update_needed",
                version = %observed,
                required_csq = %required_csq,
                days_remaining = days_remaining,
                "csq update needed: artifact coc.version exceeds csq's max known major; \
                 loading in degraded passthrough mode for {days_remaining} more days"
            );
            Ok(())
        }
        CompatVerdict::RefuseTooNew {
            observed,
            max_known_major: _,
            required_csq,
        } => Err(LoadError::VersionRefused {
            observed: observed.to_string(),
            required_csq,
        }),
    }
}

/// Probe legacy chain at `project_root` and load whichever source first
/// matches. Currently we record the resolved source on the returned
/// `CocSet`; full legacy parsing (the `.claude/`, `.gemini/`, `AGENTS.md`
/// content) lands in PR-CA2/3/4 alongside the per-Surface translators.
fn load_legacy_or_empty(project_root: &Path) -> CocSet {
    let resolution = legacy_probe(project_root);
    let source = resolution.to_source();
    let log_value = source.as_log_value();
    match &resolution {
        LegacyResolution::Claude { path } => info!(
            event = "coc.fallback",
            source = log_value,
            path = %path.display()
        ),
        LegacyResolution::Gemini { settings_path } => info!(
            event = "coc.fallback",
            source = log_value,
            path = %settings_path.display()
        ),
        LegacyResolution::AgentsMd { path } => info!(
            event = "coc.fallback",
            source = log_value,
            resolved_at = %path.display()
        ),
        LegacyResolution::Empty => info!(event = "coc.fallback", source = log_value),
    }
    CocSet {
        source,
        ..CocSet::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Per the journal-0093 retraction the load functions take `base_dir`
    /// directly (the csq accounts dir; tests pass an isolated path).
    fn isolated_base_dir(dir: &Path) -> PathBuf {
        dir.to_path_buf()
    }

    /// Build a minimal valid `.coc/` tree with COC.md + COC.lock. No
    /// signature step — per an internal journal entry the per-artifact signing
    /// apparatus was retracted.
    fn build_coc_dir(parent: &Path, lock_content: &[u8]) {
        let coc = parent.join(".coc");
        fs::create_dir_all(coc.join("rules")).unwrap();
        fs::create_dir_all(coc.join("agents")).unwrap();
        fs::create_dir_all(coc.join("skills")).unwrap();
        fs::create_dir_all(coc.join("commands")).unwrap();
        fs::write(coc.join("COC.md"), "---\ncoc.version: 1.0.0\n---\n").unwrap();
        fs::write(coc.join("COC.lock"), lock_content).unwrap();
    }

    #[test]
    fn load_returns_empty_when_no_coc_or_legacy_present() {
        let dir = tempfile::tempdir().unwrap();
        // Use a deeply nested path inside the tempdir so the upward walk
        // doesn't accidentally hit a developer's outer `.coc/` or `.claude/`.
        let nested = dir.path().join("a/b/c");
        fs::create_dir_all(&nested).unwrap();

        let base_dir = isolated_base_dir(dir.path());
        let outcome = load(&nested, &base_dir).unwrap();
        // The walk may surface either Empty or a legacy hit from the host
        // filesystem; we only assert on what we control: no `.coc/` was
        // loaded from inside our tempdir.
        assert!(!matches!(outcome.set.source, CocSource::Coc { .. }));
    }

    #[test]
    fn load_finds_coc_with_valid_lock() {
        let dir = tempfile::tempdir().unwrap();
        build_coc_dir(dir.path(), b"{\"version\":\"1.0.0\"}");

        let base_dir = isolated_base_dir(dir.path());
        let outcome = load(dir.path(), &base_dir).unwrap();
        assert!(matches!(outcome.set.source, CocSource::Coc { .. }));
    }

    #[test]
    fn load_refuses_too_new_version() {
        // M6 PR-CA13: a too-new major now passes through a 30-day
        // soft-grace window before hard-refusing. To test the
        // post-grace hard refuse, seed coc-version-grace.json with
        // an observation 31 days old so the grace expires before
        // load() runs.
        let dir = tempfile::tempdir().unwrap();
        let coc = dir.path().join(".coc");
        fs::create_dir_all(coc.join("rules")).unwrap();
        fs::create_dir_all(coc.join("agents")).unwrap();
        fs::create_dir_all(coc.join("skills")).unwrap();
        fs::create_dir_all(coc.join("commands")).unwrap();
        fs::write(coc.join("COC.md"), "---\ncoc.version: 99.0.0\n---\n").unwrap();
        fs::write(coc.join("COC.lock"), b"x").unwrap();

        let base_dir = isolated_base_dir(dir.path());
        // Seed the grace state with a 31-day-old observation so the
        // soft window is already expired by the time load() runs.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut state = version_grace::GraceState::default();
        state.records.push(version_grace::GraceRecord {
            observed_version: "99.0.0".to_string(),
            first_seen_unix: now_unix - (31 * 86400),
        });
        version_grace::save_grace_state(&base_dir, &state).unwrap();

        let err = load(dir.path(), &base_dir).unwrap_err();
        assert!(matches!(err, LoadError::VersionRefused { .. }));
    }

    #[test]
    fn load_grace_window_degrades_for_first_observation_of_too_new_version() {
        // M6 PR-CA13: a fresh observation of a too-new major loads
        // successfully (degraded mode) instead of hard-failing.
        let dir = tempfile::tempdir().unwrap();
        let coc = dir.path().join(".coc");
        fs::create_dir_all(coc.join("rules")).unwrap();
        fs::create_dir_all(coc.join("agents")).unwrap();
        fs::create_dir_all(coc.join("skills")).unwrap();
        fs::create_dir_all(coc.join("commands")).unwrap();
        fs::write(coc.join("COC.md"), "---\ncoc.version: 99.0.0\n---\n").unwrap();
        fs::write(coc.join("COC.lock"), b"x").unwrap();

        let base_dir = isolated_base_dir(dir.path());
        // No pre-seeded grace state → fresh observation → degraded load.
        let outcome = load(dir.path(), &base_dir).unwrap();
        // The set was loaded (not refused). Source records the lock_sha.
        assert!(matches!(outcome.set.source, CocSource::Coc { .. }));

        // The grace state file now contains a record for "99.0.0".
        let state = version_grace::load_grace_state(&base_dir);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0].observed_version, "99.0.0");
    }

    // ── load_with_cache (PR-CA9b Shard 2; an internal ticket) ─────────────────

    /// Cache miss on first invocation returns Cold and populates the
    /// cache. Verified by checking the cache file lands on disk.
    #[test]
    fn load_with_cache_miss_returns_cold_and_writes_cache() {
        let dir = tempfile::tempdir().unwrap();
        let lock = b"{\"v\":1,\"key\":\"miss-cold-write\"}";
        build_coc_dir(dir.path(), lock);
        let base_dir = isolated_base_dir(dir.path());

        let with_warmth = load_with_cache(dir.path(), &base_dir, true).unwrap();

        assert_eq!(with_warmth.warmth, Warmth::Cold);
        assert!(matches!(
            with_warmth.outcome.set.source,
            CocSource::Coc { .. }
        ));
        // Cache file must now exist with the lock_sha key.
        let lock_sha = cache::lock_sha256(lock);
        let cache_path = cache::cache_file(dir.path(), &lock_sha);
        assert!(
            cache_path.exists(),
            "expected cache file at {} after cold load",
            cache_path.display()
        );
    }

    /// Second invocation with cache populated returns Warm; the parser
    /// is bypassed and the returned set's source records the lock_sha.
    #[test]
    fn load_with_cache_hit_returns_warm() {
        let dir = tempfile::tempdir().unwrap();
        let lock = b"{\"v\":1,\"key\":\"hit-warm\"}";
        build_coc_dir(dir.path(), lock);
        let base_dir = isolated_base_dir(dir.path());

        // Populate the cache.
        let first = load_with_cache(dir.path(), &base_dir, true).unwrap();
        assert_eq!(first.warmth, Warmth::Cold);

        // Second call hits the cache.
        let second = load_with_cache(dir.path(), &base_dir, true).unwrap();
        assert_eq!(second.warmth, Warmth::Warm);
        assert!(matches!(second.outcome.set.source, CocSource::Coc { .. }));
    }

    /// `cache_enabled = false` skips both read and write paths: every
    /// invocation runs the parse pipeline and returns Cold. Verified by
    /// asserting no cache file is created after a Cold load.
    #[test]
    fn load_with_cache_disabled_never_writes_cache() {
        let dir = tempfile::tempdir().unwrap();
        let lock = b"{\"v\":1,\"key\":\"disabled\"}";
        build_coc_dir(dir.path(), lock);
        let base_dir = isolated_base_dir(dir.path());

        let with_warmth = load_with_cache(dir.path(), &base_dir, false).unwrap();
        assert_eq!(with_warmth.warmth, Warmth::Cold);

        let lock_sha = cache::lock_sha256(lock);
        let cache_path = cache::cache_file(dir.path(), &lock_sha);
        assert!(
            !cache_path.exists(),
            "expected NO cache file at {} when cache disabled",
            cache_path.display()
        );
    }

    /// Two consecutive `cache_enabled = false` invocations both return
    /// Cold even when a prior Warm-eligible cache file exists on disk.
    /// This is the `--no-coc-cache` semantics: the flag suppresses cache
    /// READS as well as writes.
    #[test]
    fn load_with_cache_disabled_ignores_existing_cache_file() {
        let dir = tempfile::tempdir().unwrap();
        let lock = b"{\"v\":1,\"key\":\"disabled-ignores\"}";
        build_coc_dir(dir.path(), lock);
        let base_dir = isolated_base_dir(dir.path());

        // Populate cache via cache_enabled=true.
        let first = load_with_cache(dir.path(), &base_dir, true).unwrap();
        assert_eq!(first.warmth, Warmth::Cold);

        // Even with the cache file present, cache_enabled=false stays Cold.
        let second = load_with_cache(dir.path(), &base_dir, false).unwrap();
        assert_eq!(second.warmth, Warmth::Cold);
    }
}
