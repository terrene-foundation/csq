//! CLI dependency detection, version-gating, and install/upgrade dispatch.
//!
//! Authoritative spec: `specs/13-multi-cli-detection-contract.md`.
//!
//! This module owns:
//! - Binary detection (`probe`) for Claude, Codex, and Gemini.
//! - Per-surface minimum-version constants and comparison.
//! - Manager classification (npm / brew / native installer / unknown).
//! - Install/upgrade dispatch table + range-pinning policy.
//! - `sanitize_for_display` for safe printing of third-party subprocess output.
//!
//! ## Lifecycle boundary (spec/13 §12)
//!
//! `cli_deps` is **interactive-only**. The csq daemon MUST NOT call `probe`.
//! Pre-flight is per-command:
//! - `csq doctor`  → probes all surfaces with authenticated slots.
//! - `csq login N` → probes the slot's surface before the login spawn.
//! - `csq run N`   → probes once at startup; cached for the process lifetime.

pub mod auto_update;
pub mod cli_shim;
pub mod install_path;
pub mod minimum;
pub mod probe;
pub mod sanitize;
pub mod version;

pub use auto_update::{auto_update_enabled, run_auto_update, UpdateError};
pub use minimum::{
    install_command, min_version, upgrade_command, CLAUDE_NPM_PACKAGE, CODEX_NPM_PACKAGE,
    GEMINI_NPM_PACKAGE,
};
pub use probe::{invalidate, probe_disabled};
pub use sanitize::sanitize_for_display;
pub use version::Version;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The three external CLIs csq integrates with.
///
/// `#[non_exhaustive]` ensures adding a fourth surface is a non-breaking
/// change for downstream `match` blocks (spec/13 §2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SurfaceCli {
    /// Anthropic Claude Code.
    Claude,
    /// OpenAI codex-cli (`@openai/codex`).
    Codex,
    /// Google Gemini CLI (`@google/gemini-cli`).
    Gemini,
}

/// Probe result for a single CLI surface.
///
/// See spec/13 §3 for the full semantic table (doctor row, login default,
/// `--ignore-cli-version` behaviour).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CliStatus {
    /// Binary found, version at or above minimum.
    Ok {
        version: Version,
        path: PathBuf,
        manager: InstallManager,
    },
    /// Binary found but version is below the per-surface minimum.
    Outdated {
        version: Version,
        min_required: Version,
        path: PathBuf,
        manager: InstallManager,
    },
    /// Binary found but it is not the expected CLI (wrong prefix, blocklisted
    /// install path, or version component too large to be a semver).
    WrongBinary {
        /// Raw `--version` output (sanitized via `sanitize_for_display`).
        raw_version_output: String,
        path: PathBuf,
        reason: WrongBinaryReason,
    },
    /// Binary not found in PATH.
    Missing,
    /// Binary found and version line is present, but the version string does
    /// not match `\d+.\d+.\d+`. Bails by default; `--ignore-cli-version`
    /// downgrades to WARN (spec/13 §3 — restrictive).
    UnrecognizedVersion {
        raw_output: String,
        path: PathBuf,
        manager: InstallManager,
    },
    /// The `<name> --version` subprocess did not produce parseable output
    /// within the 2-second wall-clock budget. Proceeds with a WARN by
    /// default; does not punish the user for a slow upstream `--version`.
    ProbeTimedOut {
        path: PathBuf,
        /// Wall-clock milliseconds elapsed before the timeout fired.
        elapsed_ms: u64,
    },
}

/// Reason why a binary was classified as `WrongBinary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WrongBinaryReason {
    /// The `--version` output does not start with the required literal prefix.
    /// Only applies to Codex (`"codex-cli "`).
    PrefixMismatch { expected: &'static str, got: String },
    /// The resolved-canonical path is on the per-surface blocklist.
    /// Homebrew formula `codex` is a different tool with the same binary name.
    InstallPathBlocklisted { resolved: PathBuf },
    /// A version component exceeds 5 ASCII digits.
    /// Homebrew formula `codex` uses date-encoded versions (`0.1.2505291658`).
    ComponentTooLarge { segment: String },
}

/// How the CLI was (or would be) installed.
///
/// Used to select the correct install/upgrade command from the dispatch table
/// (spec/13 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallManager {
    /// `brew install <formula>` / `brew upgrade <formula>`.
    BrewFormula,
    /// `brew install --cask <cask>` / `brew upgrade --cask <cask>`.
    BrewCask,
    /// `npm i -g <package>`.
    NpmGlobal,
    /// Claude's own native installer (`~/.local/share/claude/versions/`).
    /// No auto-runnable upgrade command — csq prints the official command.
    ClaudeNativeInstaller,
    /// Install path does not match any known pattern.
    Unknown,
}

/// Probe a surface CLI for presence and version.
///
/// See `probe::probe` for full documentation. This re-export is the public
/// entry point; callers import `cli_deps::probe(SurfaceCli::Codex)`.
pub fn probe(cli: SurfaceCli) -> CliStatus {
    probe::probe(cli)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Trait bounds ──────────────────────────────────────────────────

    /// Public types must be Debug + Clone + PartialEq (for test assertions).
    #[test]
    fn surface_cli_debug_clone_eq() {
        let a = SurfaceCli::Codex;
        let b = a;
        assert_eq!(a, b);
        assert!(!format!("{a:?}").is_empty());
    }

    #[test]
    fn install_manager_debug_clone_eq() {
        let a = InstallManager::NpmGlobal;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn cli_status_missing_clone() {
        let s = CliStatus::Missing;
        let s2 = s.clone();
        assert_eq!(s, s2);
    }

    // ── Serde round-trips ─────────────────────────────────────────────

    #[test]
    fn surface_cli_serde_roundtrip() {
        let v = SurfaceCli::Gemini;
        let json = serde_json::to_string(&v).unwrap();
        let back: SurfaceCli = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn install_manager_serde_snake_case() {
        // Serde rename_all = "snake_case"
        let json = serde_json::to_string(&InstallManager::NpmGlobal).unwrap();
        assert_eq!(json, r#""npm_global""#);
    }

    #[test]
    fn cli_status_missing_serde_tag() {
        let json = serde_json::to_string(&CliStatus::Missing).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["kind"], "missing");
    }

    #[test]
    fn cli_status_ok_serde_tag() {
        let status = CliStatus::Ok {
            version: Version::new(0, 40, 0),
            path: PathBuf::from("/usr/bin/codex"),
            manager: InstallManager::NpmGlobal,
        };
        let json = serde_json::to_string(&status).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["kind"], "ok");
        assert_eq!(val["manager"], "npm_global");
    }

    #[test]
    fn cli_status_outdated_serde() {
        let status = CliStatus::Outdated {
            version: Version::new(0, 24, 0),
            min_required: Version::new(0, 40, 0),
            path: PathBuf::from("/usr/bin/codex"),
            manager: InstallManager::NpmGlobal,
        };
        let val: serde_json::Value = serde_json::to_value(&status).unwrap();
        assert_eq!(val["kind"], "outdated");
        assert_eq!(val["version"]["major"], 0);
        assert_eq!(val["version"]["minor"], 24);
        assert_eq!(val["min_required"]["minor"], 40);
    }

    #[test]
    fn wrong_binary_reason_prefix_mismatch_serde() {
        let reason = WrongBinaryReason::PrefixMismatch {
            expected: "codex-cli ",
            got: "0.128.0".to_string(),
        };
        let val: serde_json::Value = serde_json::to_value(&reason).unwrap();
        assert_eq!(val["kind"], "prefix_mismatch");
        assert_eq!(val["expected"], "codex-cli ");
    }
}
