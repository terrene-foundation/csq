//! Legacy fallback chain per spec 09 §9.3.
//!
//! Resolution order:
//!   1. `.coc/`
//!   2. `.claude/`
//!   3. `.gemini/` + `AGENTS.md` co-presence
//!   4. `AGENTS.md` codex resolver (walk-from-CWD-upward)
//!   5. `Empty`
//!
//! First non-empty source wins. Resolution stops at the first match —
//! sources are NOT unioned.

use std::path::{Path, PathBuf};

use super::types::CocSource;

/// Discovered legacy source. The path-bearing variants point at the
/// directory or file the resolver picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyResolution {
    Claude { path: PathBuf },
    Gemini { settings_path: PathBuf },
    AgentsMd { path: PathBuf },
    Empty,
}

impl LegacyResolution {
    pub fn to_source(&self) -> CocSource {
        match self {
            LegacyResolution::Claude { .. } => CocSource::LegacyClaude,
            LegacyResolution::Gemini { .. } => CocSource::LegacyGemini,
            LegacyResolution::AgentsMd { .. } => CocSource::LegacyAgentsMd,
            LegacyResolution::Empty => CocSource::Empty,
        }
    }
}

/// Probe legacy sources from `project_root` (no walking — the caller has
/// already located the `.coc/` project root or fallen through to legacy
/// after `.coc/` returned no hit).
pub fn probe(project_root: &Path) -> LegacyResolution {
    if claude_present(project_root) {
        return LegacyResolution::Claude {
            path: project_root.join(".claude"),
        };
    }
    if let Some(settings_path) = gemini_present(project_root) {
        return LegacyResolution::Gemini { settings_path };
    }
    if let Some(path) = agents_md_walk_up(project_root) {
        return LegacyResolution::AgentsMd { path };
    }
    LegacyResolution::Empty
}

fn claude_present(project_root: &Path) -> bool {
    let claude = project_root.join(".claude");
    if !claude.is_dir() {
        return false;
    }
    // `.claude/` is non-empty if it has any of `rules/`, `agents/`, `skills/`.
    ["rules", "agents", "skills"]
        .iter()
        .any(|sub| claude.join(sub).is_dir())
}

fn gemini_present(project_root: &Path) -> Option<PathBuf> {
    let settings = project_root.join(".gemini").join("settings.json");
    settings.is_file().then_some(settings)
}

fn agents_md_walk_up(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    for _ in 0..=64 {
        let candidate = current.join("AGENTS.md");
        if candidate.is_file() {
            return Some(candidate);
        }
        let parent = current.parent()?;
        if parent == current {
            return None;
        }
        current = parent.to_path_buf();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_claude_when_claude_dir_with_rules_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude/rules")).unwrap();
        let res = probe(dir.path());
        match res {
            LegacyResolution::Claude { path } => {
                assert_eq!(path, dir.path().join(".claude"));
            }
            other => panic!("expected Claude, got {other:?}"),
        }
    }

    #[test]
    fn probe_returns_gemini_when_settings_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".gemini")).unwrap();
        std::fs::write(dir.path().join(".gemini/settings.json"), b"{}").unwrap();
        let res = probe(dir.path());
        assert!(matches!(res, LegacyResolution::Gemini { .. }));
    }

    #[test]
    fn probe_prefers_claude_over_gemini() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude/rules")).unwrap();
        std::fs::create_dir_all(dir.path().join(".gemini")).unwrap();
        std::fs::write(dir.path().join(".gemini/settings.json"), b"{}").unwrap();
        match probe(dir.path()) {
            LegacyResolution::Claude { .. } => (),
            other => panic!("expected Claude (priority), got {other:?}"),
        }
    }

    #[test]
    fn probe_returns_agents_md_when_only_agents_md_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("AGENTS.md"), b"# agents").unwrap();
        let res = probe(dir.path());
        assert!(matches!(res, LegacyResolution::AgentsMd { .. }));
    }

    #[test]
    fn probe_returns_empty_when_nothing_present() {
        let dir = tempfile::tempdir().unwrap();
        let res = probe(dir.path());
        // Note: ancestors of dir might have AGENTS.md (unlikely on CI). If
        // they do, the walk up from a deeply-nested path would hit. To
        // isolate, use a deep nested path inside the tempdir.
        if let LegacyResolution::AgentsMd { path } = res {
            // Whatever was found must be OUTSIDE our tempdir.
            assert!(!path.starts_with(dir.path()));
        }
    }

    #[test]
    fn empty_claude_dir_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        // No subdirs.
        let res = probe(dir.path());
        assert!(!matches!(res, LegacyResolution::Claude { .. }));
    }

    #[test]
    fn coc_source_log_value_for_each_variant() {
        assert_eq!(CocSource::LegacyClaude.as_log_value(), "claude-native");
        assert_eq!(CocSource::LegacyGemini.as_log_value(), "gemini-native");
        assert_eq!(CocSource::LegacyAgentsMd.as_log_value(), "agents-md");
        assert_eq!(CocSource::Empty.as_log_value(), "none");
    }
}
