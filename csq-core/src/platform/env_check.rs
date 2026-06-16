//! Environment pre-flight — detects missing runtime dependencies
//! and broken hook wiring BEFORE csq hands off to `claude`.
//!
//! Users on fresh WSL commonly see either:
//!
//! - `node: command not found` — no JS runtime installed. WSL Ubuntu
//!   base images ship without node by default.
//! - `node:internal/modules/cjs/loader:1143` — node IS installed but
//!   a configured hook's `require("./lib/...")` fails because the
//!   sibling `lib/` directory is not alongside the hook script.
//!
//! csq itself never wires hooks into `~/.claude/settings.json`, but
//! users frequently inherit hook configuration from a cloned COC
//! project or template sync. This module lets csq surface the
//! actionable remediation before the error lands in the middle of
//! a CC session.

use std::path::{Path, PathBuf};

/// One category of environment issue that would surface as a CC hook
/// failure. Each variant carries enough context for a human-readable
/// warning or an automated fix prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvIssue {
    /// No `node` / `bun` found on PATH or in known install locations,
    /// AND at least one hook is configured somewhere the user's CC
    /// session will see. `hook_count` is the total number of hook
    /// commands discovered across the scanned settings files.
    NodeMissingForHooks { hook_count: usize },
    /// A configured hook command references a script file that does
    /// not exist on disk.
    HookScriptMissing {
        /// Absolute path where the hook expects to find its script,
        /// after `$CLAUDE_PROJECT_DIR` and `~` expansion.
        script_path: PathBuf,
        /// The settings.json that declared the hook.
        referenced_from: PathBuf,
    },
    /// A hook .js script has a `require("./relative")` that does not
    /// resolve. This is the `loader:1143` failure mode — the top-level
    /// hook was materialized without its sibling helper modules.
    HookRelativeRequireMissing {
        /// The hook script that contains the broken require.
        script_path: PathBuf,
        /// The relative target, resolved to an absolute path, that
        /// the require() would fail to load.
        missing_sibling: PathBuf,
    },
}

/// Linux/WSL distribution family used to pick the right node install
/// command. We intentionally keep the set coarse — the goal is to
/// print one correct command per flavor, not to model every distro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxFlavor {
    /// Linux running inside WSL (detected via `/proc/version`).
    /// Surfaced separately so the remediation can mention that
    /// `apt install` must run inside the WSL shell (not PowerShell).
    Wsl,
    /// Debian / Ubuntu / Mint / Pop!_OS. Uses `apt`.
    Debian,
    /// Fedora / RHEL / Alma / Rocky. Uses `dnf` or `yum`.
    RedHat,
    /// Arch / Manjaro. Uses `pacman`.
    Arch,
    /// Unknown Linux flavor — fall back to a generic nodejs.org hint.
    Other,
}

/// Top-level preflight. Scans common hook configuration sites and
/// returns every issue that would cause a visible hook failure when
/// the user next launches `claude`.
///
/// Scanned settings.json locations:
///
/// 1. `claude_home/settings.json` — the global CC settings csq
///    already patches (statusLine).
/// 2. `cwd/.claude/settings.json` — the project-local settings that
///    Claude Code picks up when invoked from inside a repo.
///
/// `cwd` can be the current process cwd; callers in install/run pass
/// `std::env::current_dir()` (or a caller-supplied base) directly.
pub fn run_preflight(claude_home: &Path, cwd: &Path) -> Vec<EnvIssue> {
    let mut issues = Vec::new();

    let mut scanned_hooks = Vec::new();
    let global_settings = claude_home.join("settings.json");
    scanned_hooks.extend(scan_settings_file(&global_settings, cwd));
    let project_settings = cwd.join(".claude").join("settings.json");
    if project_settings != global_settings {
        scanned_hooks.extend(scan_settings_file(&project_settings, cwd));
    }

    // Node / bun availability gate.
    if !scanned_hooks.is_empty() && crate::http::js_runtime_path().is_none() {
        issues.push(EnvIssue::NodeMissingForHooks {
            hook_count: scanned_hooks.len(),
        });
    }

    for hook in &scanned_hooks {
        if !hook.script_path.exists() {
            issues.push(EnvIssue::HookScriptMissing {
                script_path: hook.script_path.clone(),
                referenced_from: hook.referenced_from.clone(),
            });
            // Script missing → don't bother parsing requires.
            continue;
        }
        // For .js scripts only: surface broken ./relative requires.
        if hook
            .script_path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("js"))
        {
            issues.extend(find_broken_relative_requires(&hook.script_path));
        }
    }

    issues
}

/// Detects WSL vs Debian vs RedHat etc. Linux-only; returns
/// `LinuxFlavor::Other` on platforms where detection is not
/// applicable so callers can still format a generic message.
pub fn detect_linux_flavor() -> LinuxFlavor {
    // WSL check first — WSL kernels report "microsoft" in release
    // string regardless of the userland distro.
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let lower = version.to_ascii_lowercase();
        if lower.contains("microsoft") || lower.contains("wsl") {
            return LinuxFlavor::Wsl;
        }
    }

    // /etc/os-release is the standard LSB file for Linux flavor
    // detection. ID_LIKE gives a family hint when ID is a derivative
    // (e.g. ID=pop, ID_LIKE=ubuntu debian).
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let lower = content.to_ascii_lowercase();
        if lower.contains("debian") || lower.contains("ubuntu") {
            return LinuxFlavor::Debian;
        }
        if lower.contains("rhel")
            || lower.contains("fedora")
            || lower.contains("centos")
            || lower.contains("almalinux")
            || lower.contains("rocky")
        {
            return LinuxFlavor::RedHat;
        }
        if lower.contains("arch") || lower.contains("manjaro") {
            return LinuxFlavor::Arch;
        }
    }

    LinuxFlavor::Other
}

/// Returns a one-line install command for node appropriate to the
/// current platform. Never includes `sudo` silently — callers print
/// this for the user to approve.
pub fn node_install_hint() -> String {
    if cfg!(target_os = "macos") {
        return "brew install node  # requires Homebrew (https://brew.sh)".to_string();
    }
    if cfg!(target_os = "windows") {
        return "winget install OpenJS.NodeJS  # or download from https://nodejs.org".to_string();
    }
    match detect_linux_flavor() {
        LinuxFlavor::Wsl | LinuxFlavor::Debian => "sudo apt install -y nodejs".to_string(),
        LinuxFlavor::RedHat => "sudo dnf install -y nodejs".to_string(),
        LinuxFlavor::Arch => "sudo pacman -S --noconfirm nodejs".to_string(),
        LinuxFlavor::Other => "install Node.js from https://nodejs.org".to_string(),
    }
}

// ── internals ──────────────────────────────────────────────────────

/// Per-hook record extracted from a settings.json.
#[derive(Debug, Clone)]
struct HookRef {
    /// Absolute path to the hook script, after expansion.
    script_path: PathBuf,
    /// Settings file that declared the hook.
    referenced_from: PathBuf,
}

/// Parses a settings.json and emits one [`HookRef`] per hook command
/// whose command string resolves to a file path we can check. Hooks
/// whose command is a bare shell line we don't recognise are ignored
/// (csq is not a general shell parser).
fn scan_settings_file(settings_path: &Path, cwd: &Path) -> Vec<HookRef> {
    let content = match std::fs::read_to_string(settings_path) {
        Ok(c) if !c.trim().is_empty() => c,
        _ => return Vec::new(),
    };
    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(hooks) = value.get("hooks").and_then(|h| h.as_object()) else {
        return Vec::new();
    };

    let mut refs = Vec::new();
    for (_event, groups) in hooks {
        let Some(arr) = groups.as_array() else {
            continue;
        };
        for group in arr {
            let Some(inner) = group.get("hooks").and_then(|h| h.as_array()) else {
                continue;
            };
            for hook in inner {
                let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) else {
                    continue;
                };
                if let Some(script) = extract_script_path(cmd, cwd) {
                    refs.push(HookRef {
                        script_path: script,
                        referenced_from: settings_path.to_path_buf(),
                    });
                }
            }
        }
    }
    refs
}

/// Extracts the script path out of a hook command line.
///
/// Recognises two shapes Claude Code users commonly configure:
///
/// - `node "$CLAUDE_PROJECT_DIR/scripts/hooks/foo.js"`
/// - `node /absolute/path/to/foo.js`
/// - `bash "$CLAUDE_PROJECT_DIR/scripts/hooks/foo.sh"`
///
/// Returns `None` for commands that are not a single-script invocation
/// (e.g. `echo hi`, a multi-step `&&` chain, or a compiled binary with
/// no path argument). `$CLAUDE_PROJECT_DIR` expands to `cwd`; `$HOME`
/// and `~` expand to the user's home directory when available.
fn extract_script_path(cmd: &str, cwd: &Path) -> Option<PathBuf> {
    let trimmed = cmd.trim();
    // Split on whitespace; the second token is usually the script
    // path. We only look at the first "word" after the interpreter.
    let mut tokens = trimmed.split_whitespace();
    let interpreter = tokens.next()?;
    if !matches!(
        interpreter,
        "node" | "bun" | "bash" | "sh" | "zsh" | "python" | "python3"
    ) {
        return None;
    }
    // Second token is the script (possibly quoted); strip surrounding
    // single/double quotes.
    let raw = tokens.next()?;
    let unquoted = raw
        .trim_start_matches('\'')
        .trim_end_matches('\'')
        .trim_start_matches('"')
        .trim_end_matches('"');
    let expanded = expand_vars(unquoted, cwd);
    Some(expanded)
}

/// Expands a subset of shell variables in a path string:
///
/// - `$CLAUDE_PROJECT_DIR` → `cwd`
/// - `${CLAUDE_PROJECT_DIR}` → `cwd`
/// - leading `~/` → `$HOME/`
/// - `$HOME` / `${HOME}` → `$HOME` env var
///
/// Unknown variables are left in place so the caller's existence check
/// fails loudly instead of masking a missing-substitution bug.
fn expand_vars(input: &str, cwd: &Path) -> PathBuf {
    let cwd_str = cwd.to_string_lossy().to_string();
    let mut s = input.to_string();
    s = s.replace("${CLAUDE_PROJECT_DIR}", &cwd_str);
    s = s.replace("$CLAUDE_PROJECT_DIR", &cwd_str);
    if let Some(home) = home_dir_string() {
        s = s.replace("${HOME}", &home);
        s = s.replace("$HOME", &home);
        if let Some(rest) = s.strip_prefix("~/") {
            s = format!("{home}/{rest}");
        } else if s == "~" {
            s = home;
        }
    }
    PathBuf::from(s)
}

fn home_dir_string() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
}

/// Scans a .js hook script for `require("./relative")` or
/// `require('./relative')` calls and returns an [`EnvIssue`] for each
/// one that does not resolve on disk.
///
/// This is a best-effort substring scan — not a full JS parser. It
/// catches the common pattern `require("./lib/foo")` that is the
/// proximate cause of `loader:1143` on partial template syncs, and
/// tolerates false negatives (dynamic requires, template strings)
/// rather than producing spurious warnings.
///
/// Node resolves `require("./x")` by trying, in order: `x.js`, `x.cjs`,
/// `x.mjs`, `x/index.js`, `x/package.json#main`. We check `.js`,
/// `.cjs`, and `index.js` — enough to cover the hook patterns
/// currently in circulation without pulling in node's full resolver.
fn find_broken_relative_requires(script_path: &Path) -> Vec<EnvIssue> {
    let content = match std::fs::read_to_string(script_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let parent = match script_path.parent() {
        Some(p) => p,
        None => return Vec::new(),
    };

    let mut issues = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for target in extract_relative_requires(&content) {
        let base = parent.join(&target);
        if resolve_require_target(&base).is_some() {
            continue;
        }
        // Not resolvable — record the most informative missing path
        // (the `base` itself, before extension probing) and dedupe.
        if seen.insert(base.clone()) {
            issues.push(EnvIssue::HookRelativeRequireMissing {
                script_path: script_path.to_path_buf(),
                missing_sibling: base,
            });
        }
    }
    issues
}

/// Returns every `./relative` string appearing inside a `require(...)`
/// call. Uses a plain substring scan — scope is intentionally narrow
/// so a single `require("./lib/x")` is picked up whether quoted with
/// single or double quotes.
fn extract_relative_requires(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for quote in ['"', '\''] {
        let pat_a = format!("require({quote}./");
        let pat_b = format!("require( {quote}./");
        for pattern in [pat_a, pat_b] {
            let mut rest = source;
            while let Some(idx) = rest.find(&pattern) {
                let after = &rest[idx + pattern.len()..];
                // The path ends at the next matching quote. Node
                // requires are single-line strings, so newline or
                // a quote terminates the literal.
                let end = after.find([quote, '\n']).unwrap_or(after.len());
                let rel = &after[..end];
                if !rel.is_empty() {
                    out.push(format!("./{rel}"));
                }
                rest = &after[end..];
            }
        }
    }
    out
}

/// Probes node's module resolution for a `require("./...")` target.
/// Returns `Some(resolved)` if ANY of the common extension variants
/// exists, `None` if none do.
fn resolve_require_target(base: &Path) -> Option<PathBuf> {
    if base.is_file() {
        return Some(base.to_path_buf());
    }
    for ext in ["js", "cjs", "mjs", "json"] {
        let candidate = base.with_extension(ext);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // Directory with index.js is the last-resort CommonJS resolution.
    let idx = base.join("index.js");
    if idx.is_file() {
        return Some(idx);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn extract_script_path_parses_node_claude_project_dir() {
        let cwd = Path::new("/tmp/proj");
        let got = extract_script_path(
            "node \"$CLAUDE_PROJECT_DIR/scripts/hooks/session-start.js\"",
            cwd,
        );
        assert_eq!(
            got,
            Some(PathBuf::from("/tmp/proj/scripts/hooks/session-start.js"))
        );
    }

    #[test]
    fn extract_script_path_handles_braced_variable() {
        let cwd = Path::new("/tmp/proj");
        let got = extract_script_path("node \"${CLAUDE_PROJECT_DIR}/scripts/hooks/foo.js\"", cwd);
        assert_eq!(got, Some(PathBuf::from("/tmp/proj/scripts/hooks/foo.js")));
    }

    #[test]
    fn extract_script_path_ignores_non_interpreter_commands() {
        assert!(extract_script_path("echo hi", Path::new("/tmp")).is_none());
        assert!(extract_script_path("my-binary --flag", Path::new("/tmp")).is_none());
    }

    #[test]
    fn extract_script_path_handles_bash_shell_script() {
        let cwd = Path::new("/tmp/proj");
        let got = extract_script_path("bash /tmp/proj/scripts/hooks/pre.sh", cwd);
        assert_eq!(got, Some(PathBuf::from("/tmp/proj/scripts/hooks/pre.sh")));
    }

    #[test]
    fn extract_relative_requires_finds_double_and_single_quoted() {
        let src = r#"
            const a = require("./lib/a");
            const b = require('./lib/b');
            const c = require("not-relative");
        "#;
        let rels = extract_relative_requires(src);
        assert!(rels.contains(&"./lib/a".to_string()));
        assert!(rels.contains(&"./lib/b".to_string()));
        assert!(!rels.contains(&"not-relative".to_string()));
    }

    #[test]
    fn resolve_require_target_matches_js_and_cjs() {
        let dir = TempDir::new().unwrap();
        let js = dir.path().join("foo.js");
        std::fs::write(&js, "module.exports = {}").unwrap();
        // base without extension resolves to .js
        assert!(resolve_require_target(&dir.path().join("foo")).is_some());
        let cjs = dir.path().join("bar.cjs");
        std::fs::write(&cjs, "module.exports = {}").unwrap();
        assert!(resolve_require_target(&dir.path().join("bar")).is_some());
    }

    #[test]
    fn resolve_require_target_misses_nonexistent() {
        let dir = TempDir::new().unwrap();
        assert!(resolve_require_target(&dir.path().join("missing")).is_none());
    }

    #[test]
    fn preflight_reports_missing_hook_script() {
        let claude_home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();

        // Project settings references a hook file that doesn't exist.
        let settings = proj.path().join(".claude/settings.json");
        write(
            &settings,
            r#"{
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {"type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/scripts/hooks/session-start.js\""}
                            ]
                        }
                    ]
                }
            }"#,
        );

        let issues = run_preflight(claude_home.path(), proj.path());
        assert!(
            issues.iter().any(|i| matches!(
                i,
                EnvIssue::HookScriptMissing { script_path, .. }
                if script_path.ends_with("scripts/hooks/session-start.js")
            )),
            "expected HookScriptMissing, got: {issues:?}"
        );
    }

    #[test]
    fn preflight_reports_broken_relative_require() {
        // Hook script exists, but a require("./lib/learning-utils")
        // does not. Mirrors the user's reported loader:1143 failure.
        let claude_home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();

        let hook = proj.path().join("scripts/hooks/session-start.js");
        write(
            &hook,
            r#"
            const { foo } = require("./lib/learning-utils");
            module.exports = {};
            "#,
        );

        let settings = proj.path().join(".claude/settings.json");
        write(
            &settings,
            r#"{
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {"type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/scripts/hooks/session-start.js\""}
                            ]
                        }
                    ]
                }
            }"#,
        );

        let issues = run_preflight(claude_home.path(), proj.path());
        assert!(
            issues.iter().any(|i| matches!(
                i,
                EnvIssue::HookRelativeRequireMissing { missing_sibling, .. }
                if missing_sibling.ends_with("lib/learning-utils")
            )),
            "expected HookRelativeRequireMissing, got: {issues:?}"
        );
    }

    #[test]
    fn preflight_silent_when_hook_script_and_siblings_present() {
        let claude_home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();

        // Hook + its sibling lib/*.js exist — nothing to report.
        let hook = proj.path().join("scripts/hooks/session-start.js");
        write(&hook, r#"const { foo } = require("./lib/learning-utils");"#);
        write(
            &proj.path().join("scripts/hooks/lib/learning-utils.js"),
            "module.exports = { foo: 1 };",
        );

        let settings = proj.path().join(".claude/settings.json");
        write(
            &settings,
            r#"{
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/scripts/hooks/session-start.js\""}]}
                    ]
                }
            }"#,
        );

        let issues = run_preflight(claude_home.path(), proj.path());
        // Node may or may not be present in the test env — we assert
        // only that no hook-specific issue was raised.
        assert!(
            !issues.iter().any(|i| matches!(
                i,
                EnvIssue::HookScriptMissing { .. } | EnvIssue::HookRelativeRequireMissing { .. }
            )),
            "unexpected hook-scoped issue: {issues:?}"
        );
    }

    #[test]
    fn node_install_hint_is_non_empty_on_current_platform() {
        let hint = node_install_hint();
        assert!(!hint.is_empty());
    }

    #[test]
    fn detect_linux_flavor_returns_variant() {
        // Smoke test only — we don't mock /proc/version here.
        let _flavor = detect_linux_flavor();
    }
}
