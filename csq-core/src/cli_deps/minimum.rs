//! Per-surface minimum version constants and related gate data.
//!
//! Rationale for each floor is code-cited per spec/13 §4.

use super::version::Version;
use super::InstallManager;
use crate::cli_deps::SurfaceCli;

// ── Single-source-of-truth npm package names (IR-L3) ──────────────────────────
// Referenced from `upgrade_command`, `install_command`, and `auto_update`
// to avoid hardcoded literals that can drift independently.

/// npm package name for Anthropic Claude Code.
pub const CLAUDE_NPM_PACKAGE: &str = "@anthropic-ai/claude-code";
/// npm package name for OpenAI Codex CLI.
pub const CODEX_NPM_PACKAGE: &str = "@openai/codex";
/// npm package name for Google Gemini CLI.
pub const GEMINI_NPM_PACKAGE: &str = "@google/gemini-cli";

// ── Self-managed CLI first-install commands (curl | bash `install.sh`) ─────────
// Kimi and Grok are NOT package-manager CLIs. Their first install is the
// vendor's `install.sh`; csq NEVER auto-executes these (no `sh -c curl|bash`
// per spec/13 §10 + security.md) — it prints the string as a manual hint.
// Upgrades use the CLIs' own subcommands (see `upgrade_command`).

/// Vendor first-install hint for Moonshot Kimi Code.
pub const KIMI_INSTALL_HINT: &str = "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash";
/// Vendor first-install hint for xAI Grok CLI.
pub const GROK_INSTALL_HINT: &str = "curl -fsSL https://x.ai/cli/install.sh | bash";

/// Minimum acceptable version for each CLI surface.
///
/// | CLI    | Floor  | Rationale (code-cited at HEAD)                                              |
/// |--------|--------|-----------------------------------------------------------------------------|
/// | Claude | 2.0.0  | `claudeAiOauth` schema introduced in CC 2.x (spec 01, CC `storage.ts`).    |
/// | Codex  | 0.40.0 | `--device-auth` landing version (`providers/codex/desktop_login.rs:1514`). |
/// | Gemini | 0.41.2 | `oauth_login.rs:6` — rewritten for gemini-cli v0.41.2+.                    |
/// | Kimi   | 0.27.0 | csq-integration baseline (Wave 0/2, 2026-07-18 — first shipped `kimi`).    |
/// | Grok   | 0.2.0  | csq-integration baseline (Wave 0/2, 2026-07-18 — first shipped `grok`).    |
pub fn min_version(cli: SurfaceCli) -> Version {
    match cli {
        SurfaceCli::Claude => Version::new(2, 0, 0),
        SurfaceCli::Codex => Version::new(0, 40, 0),
        SurfaceCli::Gemini => Version::new(0, 41, 2),
        SurfaceCli::Kimi => Version::new(0, 27, 0),
        SurfaceCli::Grok => Version::new(0, 2, 0),
    }
}

/// Required `--version` output prefix, or `None` if no prefix gate applies.
///
/// Codex requires the literal prefix `"codex-cli "` to distinguish the
/// OpenAI `@openai/codex` npm package from the Homebrew formula `codex`
/// (a different tool with the same binary name, different version scheme).
pub fn required_prefix(cli: SurfaceCli) -> Option<&'static str> {
    match cli {
        SurfaceCli::Codex => Some("codex-cli "),
        // Grok's `--version` prints `grok 0.2.103 (<hash>)`; the `"grok "`
        // prefix distinguishes it from the unrelated Elastic `grok` tool.
        SurfaceCli::Grok => Some("grok "),
        // Kimi prints a bare semver (`0.27.0`); no prefix gate.
        SurfaceCli::Claude | SurfaceCli::Gemini | SurfaceCli::Kimi => None,
    }
}

/// Per-surface install-path blocklist (substring match against canonicalized path).
///
/// Paths in this list indicate a WRONG binary (different tool, same name).
/// The blocklist gate fires BEFORE version parsing — even a valid version string
/// from a blocklisted path is rejected as `WrongBinary { InstallPathBlocklisted }`.
pub fn install_path_blocklist(cli: SurfaceCli) -> &'static [&'static str] {
    match cli {
        SurfaceCli::Codex => &["/opt/homebrew/Cellar/codex/", "/usr/local/Cellar/codex/"],
        // Kimi/Grok resolve to their own vendor install dirs; the `"grok "`
        // prefix gate already rejects a same-named foreign binary.
        SurfaceCli::Claude | SurfaceCli::Gemini | SurfaceCli::Kimi | SurfaceCli::Grok => &[],
    }
}

/// Binary name for each surface CLI.
pub fn binary_name(cli: SurfaceCli) -> &'static str {
    match cli {
        SurfaceCli::Claude => "claude",
        SurfaceCli::Codex => "codex",
        SurfaceCli::Gemini => "gemini",
        SurfaceCli::Kimi => "kimi",
        SurfaceCli::Grok => "grok",
    }
}

/// Install/upgrade command table per spec/13 §6.
///
/// Returns `None` when there is no auto-runnable command for the
/// `(cli, manager)` combination. The caller is responsible for printing
/// a manual hint.
pub fn install_command(cli: SurfaceCli, manager: InstallManager) -> Option<Vec<String>> {
    match (cli, manager) {
        (SurfaceCli::Codex, InstallManager::NpmGlobal) => Some(vec![
            "npm".into(),
            "i".into(),
            "-g".into(),
            "@openai/codex@>=0.40.0 <1.0.0".into(),
        ]),
        (SurfaceCli::Gemini, InstallManager::NpmGlobal) => Some(vec![
            "npm".into(),
            "i".into(),
            "-g".into(),
            "@google/gemini-cli@>=0.41.2 <1.0.0".into(),
        ]),
        (SurfaceCli::Gemini, InstallManager::BrewFormula) => {
            Some(vec!["brew".into(), "install".into(), "gemini-cli".into()])
        }
        (SurfaceCli::Claude, InstallManager::NpmGlobal) => Some(vec![
            "npm".into(),
            "i".into(),
            "-g".into(),
            "@anthropic-ai/claude-code@>=2.0.0 <3.0.0".into(),
        ]),
        (SurfaceCli::Claude, InstallManager::BrewCask) => Some(vec![
            "brew".into(),
            "install".into(),
            "--cask".into(),
            "claude-code".into(),
        ]),
        // ClaudeNativeInstaller: no curl-bash regression — returns None.
        (SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller) => None,
        // Unknown: no auto-runnable command.
        (_, InstallManager::Unknown) => None,
        // Remaining combinations not in dispatch table.
        _ => None,
    }
}

/// Upgrade command table per spec/13 §6.
///
/// Symmetric with `install_command`: every row that has an install command
/// also has an upgrade command (or both return `None`).
pub fn upgrade_command(cli: SurfaceCli, manager: InstallManager) -> Option<Vec<String>> {
    match (cli, manager) {
        (SurfaceCli::Codex, InstallManager::NpmGlobal) => Some(vec![
            "npm".into(),
            "i".into(),
            "-g".into(),
            "@openai/codex@>=0.40.0 <1.0.0".into(),
        ]),
        (SurfaceCli::Gemini, InstallManager::NpmGlobal) => Some(vec![
            "npm".into(),
            "i".into(),
            "-g".into(),
            "@google/gemini-cli@>=0.41.2 <1.0.0".into(),
        ]),
        (SurfaceCli::Gemini, InstallManager::BrewFormula) => {
            Some(vec!["brew".into(), "upgrade".into(), "gemini-cli".into()])
        }
        (SurfaceCli::Claude, InstallManager::NpmGlobal) => Some(vec![
            "npm".into(),
            "i".into(),
            "-g".into(),
            "@anthropic-ai/claude-code@>=2.0.0 <3.0.0".into(),
        ]),
        (SurfaceCli::Claude, InstallManager::BrewCask) => Some(vec![
            "brew".into(),
            "upgrade".into(),
            "--cask".into(),
            "claude-code".into(),
        ]),
        (SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller) => None,
        // Self-managed CLIs update via their own subcommand — no curl-bash,
        // no package manager. `kimi upgrade` / `grok update` (spec/13 §6).
        (SurfaceCli::Kimi, InstallManager::SelfManaged) => {
            Some(vec!["kimi".into(), "upgrade".into()])
        }
        (SurfaceCli::Grok, InstallManager::SelfManaged) => {
            Some(vec!["grok".into(), "update".into()])
        }
        (_, InstallManager::Unknown) => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── min_version ──────────────────────────────────────────────────

    #[test]
    fn min_version_claude_is_2_0_0() {
        assert_eq!(min_version(SurfaceCli::Claude), Version::new(2, 0, 0));
    }

    #[test]
    fn min_version_codex_is_0_40_0() {
        assert_eq!(min_version(SurfaceCli::Codex), Version::new(0, 40, 0));
    }

    #[test]
    fn min_version_gemini_is_0_41_2() {
        assert_eq!(min_version(SurfaceCli::Gemini), Version::new(0, 41, 2));
    }

    // ── required_prefix ──────────────────────────────────────────────

    #[test]
    fn required_prefix_codex_is_codex_cli_space() {
        assert_eq!(required_prefix(SurfaceCli::Codex), Some("codex-cli "));
    }

    #[test]
    fn required_prefix_claude_is_none() {
        assert_eq!(required_prefix(SurfaceCli::Claude), None);
    }

    #[test]
    fn required_prefix_gemini_is_none() {
        assert_eq!(required_prefix(SurfaceCli::Gemini), None);
    }

    // ── install_path_blocklist ───────────────────────────────────────

    #[test]
    fn install_path_blocklist_codex_contains_brew_path() {
        let list = install_path_blocklist(SurfaceCli::Codex);
        assert!(
            list.contains(&"/opt/homebrew/Cellar/codex/"),
            "expected /opt/homebrew/Cellar/codex/ in blocklist; got {list:?}"
        );
    }

    #[test]
    fn install_path_blocklist_codex_contains_usr_local_brew_path() {
        let list = install_path_blocklist(SurfaceCli::Codex);
        assert!(list.contains(&"/usr/local/Cellar/codex/"));
    }

    #[test]
    fn install_path_blocklist_claude_is_empty() {
        assert!(install_path_blocklist(SurfaceCli::Claude).is_empty());
    }

    #[test]
    fn install_path_blocklist_gemini_is_empty() {
        assert!(install_path_blocklist(SurfaceCli::Gemini).is_empty());
    }

    // ── install_command / upgrade_command ────────────────────────────

    #[test]
    fn install_command_claude_native_is_none() {
        // No curl-bash regression (spec/13 §6).
        assert!(
            install_command(SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller).is_none()
        );
    }

    #[test]
    fn upgrade_command_claude_native_is_none() {
        assert!(
            upgrade_command(SurfaceCli::Claude, InstallManager::ClaudeNativeInstaller).is_none()
        );
    }

    #[test]
    fn install_command_unknown_is_none() {
        assert!(install_command(SurfaceCli::Codex, InstallManager::Unknown).is_none());
    }

    #[test]
    fn install_command_codex_npm_is_range_pinned() {
        let cmd = install_command(SurfaceCli::Codex, InstallManager::NpmGlobal).unwrap();
        // Must NOT be "@latest"
        assert!(
            cmd.iter().any(|a| a.contains(">=0.40.0")),
            "expected range-pinned argv; got {cmd:?}"
        );
        assert!(
            !cmd.iter().any(|a| a == "@latest"),
            "must not use @latest; got {cmd:?}"
        );
    }

    #[test]
    fn install_upgrade_symmetry_gemini_brew() {
        // Both must be non-None (spec/13 §6 symmetry rule)
        assert!(install_command(SurfaceCli::Gemini, InstallManager::BrewFormula).is_some());
        assert!(upgrade_command(SurfaceCli::Gemini, InstallManager::BrewFormula).is_some());
    }

    // ── Kimi / Grok (self-managed CLIs) ──────────────────────────────

    #[test]
    fn min_version_kimi_and_grok() {
        assert_eq!(min_version(SurfaceCli::Kimi), Version::new(0, 27, 0));
        assert_eq!(min_version(SurfaceCli::Grok), Version::new(0, 2, 0));
    }

    #[test]
    fn binary_name_kimi_and_grok() {
        assert_eq!(binary_name(SurfaceCli::Kimi), "kimi");
        assert_eq!(binary_name(SurfaceCli::Grok), "grok");
    }

    #[test]
    fn required_prefix_grok_gates_grok_space() {
        // Grok prints `grok 0.2.103 (<hash>)`; the prefix rejects the unrelated
        // Elastic `grok` tool. Kimi prints a bare semver — no prefix.
        assert_eq!(required_prefix(SurfaceCli::Grok), Some("grok "));
        assert_eq!(required_prefix(SurfaceCli::Kimi), None);
    }

    #[test]
    fn upgrade_command_self_managed_uses_native_subcommand() {
        // No curl-bash, no package manager — the CLI's own subcommand.
        assert_eq!(
            upgrade_command(SurfaceCli::Kimi, InstallManager::SelfManaged),
            Some(vec!["kimi".into(), "upgrade".into()])
        );
        assert_eq!(
            upgrade_command(SurfaceCli::Grok, InstallManager::SelfManaged),
            Some(vec!["grok".into(), "update".into()])
        );
    }

    #[test]
    fn install_command_self_managed_is_none() {
        // First install is the vendor `install.sh`; csq NEVER auto-runs it
        // (no `sh -c curl|bash`). install_command → None → manual hint path.
        assert!(install_command(SurfaceCli::Kimi, InstallManager::SelfManaged).is_none());
        assert!(install_command(SurfaceCli::Grok, InstallManager::SelfManaged).is_none());
        // Also None when probed-Missing (manager defaults to NpmGlobal).
        assert!(install_command(SurfaceCli::Kimi, InstallManager::NpmGlobal).is_none());
        assert!(install_command(SurfaceCli::Grok, InstallManager::NpmGlobal).is_none());
    }
}
