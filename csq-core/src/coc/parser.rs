//! Parser: walks `.coc/` and assembles a `CocSet` per spec 09 §9.2.
//!
//! Per §9.4.2, duplicate `id` within `.coc/` errors at equal precedence
//! (loom-side authoring bug surfaces, not silently picked). Higher
//! `precedence` field wins on tie-break.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::providers::catalog::Surface;

use super::loader::{sorted_entries, LoaderError};
use super::types::{
    AgentDef, AgentId, CocSet, CocSource, CommandDef, CommandId, IdParseError, RuleDef, RuleId,
    SkillDef, SkillId, TechniqueOptOut,
};
use super::version::{CocVersion, VersionParseError};
use super::yaml::{Frontmatter, YamlError, YamlValue};

/// Errors that can happen while parsing a `.coc/` directory.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("loader error: {0}")]
    Loader(#[from] LoaderError),
    #[error("io error reading {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("yaml error in {path} ({line}): {reason}")]
    Yaml {
        path: std::path::PathBuf,
        line: usize,
        reason: String,
    },
    #[error("version parse error in {path}: {source}")]
    Version {
        path: std::path::PathBuf,
        #[source]
        source: VersionParseError,
    },
    #[error("invalid id in {path}: {source}")]
    Id {
        path: std::path::PathBuf,
        #[source]
        source: IdParseError,
    },
    #[error("missing required field `{field}` in {path}")]
    MissingField {
        path: std::path::PathBuf,
        field: &'static str,
    },
    #[error("invalid value for `{field}` in {path}: {reason}")]
    InvalidValue {
        path: std::path::PathBuf,
        field: &'static str,
        reason: String,
    },
    #[error("duplicate id `{id}` at equal precedence in `{a}` and `{b}`")]
    DuplicateId {
        id: String,
        a: std::path::PathBuf,
        b: std::path::PathBuf,
    },
}

impl ParseError {
    fn from_yaml(path: &Path, e: YamlError) -> Self {
        let (line, reason) = match &e {
            YamlError::Malformed { line, reason } => (*line, reason.clone()),
            YamlError::DuplicateKey { key, line } => (*line, format!("duplicate key `{key}`")),
            YamlError::MissingOpener => (0, "missing frontmatter opener".into()),
            YamlError::MissingCloser => (0, "missing frontmatter closer".into()),
        };
        Self::Yaml {
            path: path.to_path_buf(),
            line,
            reason,
        }
    }
}

/// Read `.coc/` at `coc_dir` and produce a `CocSet`.
pub fn parse_coc_dir(coc_dir: &Path, source: CocSource) -> Result<CocSet, ParseError> {
    let coc_md = coc_dir.join("COC.md");
    let version = parse_coc_md_version(&coc_md)?;

    let mut rules: BTreeMap<RuleId, (RuleDef, std::path::PathBuf)> = BTreeMap::new();
    let mut agents: BTreeMap<AgentId, (AgentDef, std::path::PathBuf)> = BTreeMap::new();
    let mut skills: BTreeMap<SkillId, (SkillDef, std::path::PathBuf)> = BTreeMap::new();
    let mut commands: BTreeMap<CommandId, (CommandDef, std::path::PathBuf)> = BTreeMap::new();

    parse_subdir_rules(coc_dir, "rules", &mut rules)?;
    parse_subdir_agents(coc_dir, "agents", &mut agents)?;
    parse_subdir_skills(coc_dir, "skills", &mut skills)?;
    parse_subdir_commands(coc_dir, "commands", &mut commands)?;

    Ok(CocSet {
        rules: rules.into_iter().map(|(k, (def, _))| (k, def)).collect(),
        agents: agents.into_iter().map(|(k, (def, _))| (k, def)).collect(),
        skills: skills.into_iter().map(|(k, (def, _))| (k, def)).collect(),
        commands: commands.into_iter().map(|(k, (def, _))| (k, def)).collect(),
        version,
        source,
    })
}

/// Read just the version envelope from `COC.md`. Other COC.md content is
/// human-readable primer; csq does not parse it.
pub fn parse_coc_md_version(coc_md: &Path) -> Result<CocVersion, ParseError> {
    let content = match fs::read_to_string(coc_md) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No COC.md → version envelope absent → assume v0 experimental.
            // Loader-level integrity check catches missing COC.md upstream.
            return Ok(CocVersion::ZERO);
        }
        Err(e) => {
            return Err(ParseError::Io {
                path: coc_md.to_path_buf(),
                source: e,
            });
        }
    };
    let fm = super::yaml::parse(&content).map_err(|e| ParseError::from_yaml(coc_md, e))?;
    let Some(value) = fm.fields.get("coc.version") else {
        return Ok(CocVersion::ZERO);
    };
    let raw = value.as_scalar().ok_or_else(|| ParseError::InvalidValue {
        path: coc_md.to_path_buf(),
        field: "coc.version",
        reason: "expected scalar string".into(),
    })?;
    CocVersion::parse(raw).map_err(|source| ParseError::Version {
        path: coc_md.to_path_buf(),
        source,
    })
}

macro_rules! parse_subdir_kind {
    (
        $fn_name:ident,
        $id_ty:ty,
        $def_ty:ty,
        $build_def:expr,
        $kind_label:literal
    ) => {
        fn $fn_name(
            coc_dir: &Path,
            subdir_name: &str,
            out: &mut BTreeMap<$id_ty, ($def_ty, std::path::PathBuf)>,
        ) -> Result<(), ParseError> {
            let subdir = coc_dir.join(subdir_name);
            if !subdir.exists() {
                return Ok(());
            }
            let entries = sorted_entries(&subdir)?;
            for (name, path) in entries {
                if !name.ends_with(".md") {
                    continue;
                }
                let content = fs::read_to_string(&path).map_err(|e| ParseError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                let fm =
                    super::yaml::parse(&content).map_err(|e| ParseError::from_yaml(&path, e))?;

                let id_raw = require_scalar(&fm, "id", &path)?;
                let id = <$id_ty>::parse(id_raw).map_err(|source| ParseError::Id {
                    path: path.clone(),
                    source,
                })?;

                let applies_to = parse_applies_to(&fm, &path)?;
                let precedence = parse_precedence(&fm, &path)?;
                let disable = parse_disable(&fm, &path)?;
                let unknowns = collect_unknowns(&fm, $kind_label);

                let def: $def_ty = $build_def(
                    id.clone(),
                    &fm,
                    &path,
                    applies_to,
                    precedence,
                    disable,
                    unknowns,
                )?;

                if let Some((_existing_def, existing_path)) = out.get(&id) {
                    let existing_prec = precedence_of_def(_existing_def);
                    if existing_prec == precedence {
                        return Err(ParseError::DuplicateId {
                            id: id.as_str().to_string(),
                            a: existing_path.clone(),
                            b: path.clone(),
                        });
                    }
                    if precedence > existing_prec {
                        out.insert(id.clone(), (def, path.clone()));
                    }
                    continue;
                }
                out.insert(id, (def, path));
            }
            Ok(())
        }
    };
}

parse_subdir_kind!(
    parse_subdir_rules,
    RuleId,
    RuleDef,
    |id,
     fm: &Frontmatter,
     path: &Path,
     applies_to,
     precedence,
     disable,
     unknowns|
     -> Result<RuleDef, ParseError> {
        let paths = parse_paths(fm, path)?;
        Ok(RuleDef {
            id,
            paths,
            applies_to,
            precedence,
            disable,
            body: fm.body.clone(),
            unknowns,
        })
    },
    "rule"
);

parse_subdir_kind!(
    parse_subdir_agents,
    AgentId,
    AgentDef,
    |id,
     fm: &Frontmatter,
     _path: &Path,
     applies_to,
     precedence,
     disable,
     unknowns|
     -> Result<AgentDef, ParseError> {
        Ok(AgentDef {
            id,
            applies_to,
            precedence,
            disable,
            body: fm.body.clone(),
            unknowns,
        })
    },
    "agent"
);

parse_subdir_kind!(
    parse_subdir_skills,
    SkillId,
    SkillDef,
    |id,
     fm: &Frontmatter,
     _path: &Path,
     applies_to,
     precedence,
     disable,
     unknowns|
     -> Result<SkillDef, ParseError> {
        Ok(SkillDef {
            id,
            applies_to,
            precedence,
            disable,
            body: fm.body.clone(),
            unknowns,
        })
    },
    "skill"
);

parse_subdir_kind!(
    parse_subdir_commands,
    CommandId,
    CommandDef,
    |id,
     fm: &Frontmatter,
     _path: &Path,
     applies_to,
     precedence,
     disable,
     unknowns|
     -> Result<CommandDef, ParseError> {
        Ok(CommandDef {
            id,
            applies_to,
            precedence,
            disable,
            body: fm.body.clone(),
            unknowns,
        })
    },
    "command"
);

fn require_scalar<'a>(
    fm: &'a Frontmatter,
    field: &'static str,
    path: &Path,
) -> Result<&'a str, ParseError> {
    let value = fm.fields.get(field).ok_or(ParseError::MissingField {
        path: path.to_path_buf(),
        field,
    })?;
    value.as_scalar().ok_or_else(|| ParseError::InvalidValue {
        path: path.to_path_buf(),
        field,
        reason: "expected scalar".into(),
    })
}

fn parse_paths(fm: &Frontmatter, path: &Path) -> Result<Vec<String>, ParseError> {
    match fm.fields.get("paths") {
        None => Ok(vec!["**".to_string()]),
        Some(YamlValue::Array(items)) => Ok(items.clone()),
        Some(YamlValue::Scalar(_)) => Err(ParseError::InvalidValue {
            path: path.to_path_buf(),
            field: "paths",
            reason: "expected inline array".into(),
        }),
    }
}

fn parse_applies_to(fm: &Frontmatter, path: &Path) -> Result<BTreeSet<Surface>, ParseError> {
    let raw_items: Vec<String> = match fm.fields.get("applies_to") {
        None => vec!["all".to_string()],
        Some(YamlValue::Array(items)) => items.clone(),
        Some(YamlValue::Scalar(_)) => {
            return Err(ParseError::InvalidValue {
                path: path.to_path_buf(),
                field: "applies_to",
                reason: "expected inline array".into(),
            });
        }
    };

    let mut out = BTreeSet::new();
    for item in raw_items {
        if item == "all" {
            out.extend(Surface::ALL.iter().copied());
            continue;
        }
        // Every surface tag is addressable by its canonical `as_str` name,
        // resolved through the single `Surface::from_tag` inverse rather
        // than a hand-rolled match. The previous hand-rolled arms omitted
        // `kimi` and `grok` entirely, so `applies_to: [kimi]` was not a
        // no-op — it was a hard ParseError ("unknown surface `kimi`") that
        // failed the whole artifact. A `.coc/` author could not express a
        // rule scoped to either native CLI at all.
        match Surface::from_tag(&item) {
            Some(surface) => {
                out.insert(surface);
            }
            None => {
                return Err(ParseError::InvalidValue {
                    path: path.to_path_buf(),
                    field: "applies_to",
                    reason: format!("unknown surface `{item}`"),
                });
            }
        }
    }
    Ok(out)
}

fn parse_precedence(fm: &Frontmatter, path: &Path) -> Result<i32, ParseError> {
    let Some(value) = fm.fields.get("precedence") else {
        return Ok(0);
    };
    let raw = value.as_scalar().ok_or_else(|| ParseError::InvalidValue {
        path: path.to_path_buf(),
        field: "precedence",
        reason: "expected scalar integer".into(),
    })?;
    raw.parse::<i32>().map_err(|e| ParseError::InvalidValue {
        path: path.to_path_buf(),
        field: "precedence",
        reason: e.to_string(),
    })
}

fn parse_disable(fm: &Frontmatter, path: &Path) -> Result<BTreeSet<TechniqueOptOut>, ParseError> {
    let raw_items: Vec<String> = match fm.fields.get("coc.disable") {
        None => Vec::new(),
        Some(YamlValue::Array(items)) => items.clone(),
        Some(YamlValue::Scalar(_)) => {
            return Err(ParseError::InvalidValue {
                path: path.to_path_buf(),
                field: "coc.disable",
                reason: "expected inline array".into(),
            });
        }
    };
    let mut out = BTreeSet::new();
    for item in raw_items {
        let parsed = TechniqueOptOut::parse(&item).ok_or_else(|| ParseError::InvalidValue {
            path: path.to_path_buf(),
            field: "coc.disable",
            reason: format!("unknown technique `{item}`"),
        })?;
        out.insert(parsed);
    }
    Ok(out)
}

const KNOWN_FIELDS: &[&str] = &[
    "id",
    "coc.version",
    "paths",
    "coc.disable",
    "applies_to",
    "precedence",
];

fn collect_unknowns(fm: &Frontmatter, _kind: &'static str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in &fm.fields {
        if !KNOWN_FIELDS.contains(&key.as_str()) {
            out.insert(key.clone(), value.render_raw());
        }
    }
    out
}

trait HasPrecedence {
    fn precedence(&self) -> i32;
}

impl HasPrecedence for RuleDef {
    fn precedence(&self) -> i32 {
        self.precedence
    }
}
impl HasPrecedence for AgentDef {
    fn precedence(&self) -> i32 {
        self.precedence
    }
}
impl HasPrecedence for SkillDef {
    fn precedence(&self) -> i32 {
        self.precedence
    }
}
impl HasPrecedence for CommandDef {
    fn precedence(&self) -> i32 {
        self.precedence
    }
}

fn precedence_of_def<T: HasPrecedence>(t: &T) -> i32 {
    t.precedence()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_md(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(name), content).unwrap();
    }

    fn build_minimal_coc(root: &Path) {
        fs::create_dir_all(root.join("rules")).unwrap();
        fs::create_dir_all(root.join("agents")).unwrap();
        fs::create_dir_all(root.join("skills")).unwrap();
        fs::create_dir_all(root.join("commands")).unwrap();
        write_md(
            root,
            "COC.md",
            "---\ncoc.version: 1.0.0\n---\n# COC primer\n",
        );
    }

    #[test]
    fn parses_minimal_coc_dir() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        assert_eq!(
            set.version,
            CocVersion {
                major: 1,
                minor: 0,
                patch: 0
            }
        );
        assert!(set.rules.is_empty());
    }

    #[test]
    fn parses_a_rule_with_full_frontmatter() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X.md",
            "---\nid: RULE-X\npaths: [src/**, lib/**]\napplies_to: [claude-code, codex]\nprecedence: 5\ncoc.disable: [scaffold]\n---\nbody text\n",
        );
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        let rule = set.rules.values().next().expect("one rule");
        assert_eq!(rule.id.as_str(), "RULE-X");
        assert_eq!(rule.paths, vec!["src/**", "lib/**"]);
        assert_eq!(rule.precedence, 5);
        assert!(rule.disable.contains(&TechniqueOptOut::Scaffold));
        assert!(rule.applies_to.contains(&Surface::ClaudeCode));
        assert!(rule.applies_to.contains(&Surface::Codex));
        assert!(!rule.applies_to.contains(&Surface::Gemini));
    }

    #[test]
    fn unknown_frontmatter_fields_captured() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X.md",
            "---\nid: RULE-X\nfuture_thing: hello\n---\nbody\n",
        );
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        let rule = set.rules.values().next().unwrap();
        assert_eq!(rule.unknowns.get("future_thing").unwrap(), "hello");
    }

    #[test]
    fn invalid_id_errors() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X.md",
            "---\nid: bad-id\n---\nbody\n",
        );
        let err = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap_err();
        assert!(matches!(err, ParseError::Id { .. }));
    }

    #[test]
    fn duplicate_id_at_equal_precedence_errors() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X-a.md",
            "---\nid: RULE-X\nprecedence: 0\n---\nbody A\n",
        );
        write_md(
            &dir.path().join("rules"),
            "RULE-X-b.md",
            "---\nid: RULE-X\nprecedence: 0\n---\nbody B\n",
        );
        let err = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap_err();
        assert!(matches!(err, ParseError::DuplicateId { .. }));
    }

    #[test]
    fn higher_precedence_wins() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X-a.md",
            "---\nid: RULE-X\nprecedence: 0\n---\nbody A\n",
        );
        write_md(
            &dir.path().join("rules"),
            "RULE-X-b.md",
            "---\nid: RULE-X\nprecedence: 5\n---\nbody B\n",
        );
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        let rule = set.rules.values().next().unwrap();
        assert_eq!(rule.precedence, 5);
        assert_eq!(rule.body.trim(), "body B");
    }

    #[test]
    fn missing_id_errors() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X.md",
            "---\nprecedence: 0\n---\nbody\n",
        );
        let err = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap_err();
        assert!(matches!(err, ParseError::MissingField { field: "id", .. }));
    }

    #[test]
    fn empty_subdirs_load_clean() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        assert!(set.rules.is_empty());
        assert!(set.agents.is_empty());
    }

    #[test]
    fn coc_md_missing_returns_zero_version() {
        let dir = tempfile::tempdir().unwrap();
        // No COC.md.
        fs::create_dir_all(dir.path().join("rules")).unwrap();
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        assert_eq!(set.version, CocVersion::ZERO);
    }

    /// `applies_to: [all]` MUST expand to EVERY surface, not to the three
    /// that existed when the parser was written. Asserted against
    /// `Surface::ALL` rather than a literal count so adding a sixth
    /// surface fails here loudly instead of silently narrowing `[all]`.
    #[test]
    fn parses_all_surface_when_applies_to_all() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-X.md",
            "---\nid: RULE-X\napplies_to: [all]\n---\nbody\n",
        );
        let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap();
        let rule = set.rules.values().next().unwrap();
        let expected: BTreeSet<Surface> = Surface::ALL.iter().copied().collect();
        assert_eq!(
            rule.applies_to, expected,
            "`applies_to: [all]` must cover every Surface variant"
        );
        // The regression this pins: the old hand-rolled list stopped at
        // gemini, so `[all]` reached neither native CLI.
        assert!(rule.applies_to.contains(&Surface::Kimi));
        assert!(rule.applies_to.contains(&Surface::Grok));
    }

    /// The native-CLI surfaces are addressable by name. Before this, both
    /// tags were a hard `ParseError` — a `.coc/` author could not scope a
    /// rule to Kimi or Grok at all, and the whole artifact failed to load.
    #[test]
    fn parses_native_cli_surface_tags() {
        for (tag, expected) in [("kimi", Surface::Kimi), ("grok", Surface::Grok)] {
            let dir = tempfile::tempdir().unwrap();
            build_minimal_coc(dir.path());
            write_md(
                &dir.path().join("rules"),
                "RULE-N.md",
                &format!("---\nid: RULE-N\napplies_to: [{tag}]\n---\nbody\n"),
            );
            let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude)
                .unwrap_or_else(|e| panic!("`applies_to: [{tag}]` must parse, got {e:?}"));
            let rule = set.rules.values().next().unwrap();
            assert_eq!(
                rule.applies_to,
                std::iter::once(expected).collect::<BTreeSet<_>>(),
                "`applies_to: [{tag}]` must resolve to exactly {expected}"
            );
        }
    }

    /// Every surface's canonical `as_str` tag is accepted by the parser.
    /// Enumerated from `Surface::ALL`, so a new variant whose tag the
    /// parser cannot resolve fails here rather than at a user's `csq run`.
    #[test]
    fn every_surface_tag_is_parseable_in_applies_to() {
        for surface in Surface::ALL {
            let dir = tempfile::tempdir().unwrap();
            build_minimal_coc(dir.path());
            write_md(
                &dir.path().join("rules"),
                "RULE-S.md",
                &format!(
                    "---\nid: RULE-S\napplies_to: [{}]\n---\nbody\n",
                    surface.as_str()
                ),
            );
            let set = parse_coc_dir(dir.path(), CocSource::LegacyClaude)
                .unwrap_or_else(|e| panic!("tag `{surface}` must parse, got {e:?}"));
            assert!(set
                .rules
                .values()
                .next()
                .unwrap()
                .applies_to
                .contains(surface));
        }
    }

    /// An unknown tag stays a hard error naming the offending token — the
    /// permissive path (silently ignoring it) would let a typo'd
    /// `applies_to: [codexx]` silently drop the rule from every surface.
    #[test]
    fn unknown_surface_tag_is_still_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        write_md(
            &dir.path().join("rules"),
            "RULE-BAD.md",
            "---\nid: RULE-BAD\napplies_to: [kimmi]\n---\nbody\n",
        );
        let err = parse_coc_dir(dir.path(), CocSource::LegacyClaude)
            .expect_err("a typo'd surface tag must not parse");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("kimmi"),
            "error must name the offending tag, got {rendered}"
        );
    }
}
