//! Type definitions for the unified `.coc/` consumer contract.
//!
//! Authoritative spec: `specs/09-unified-coc-artifact-standard.md` §9.2.4.
//! These types are CONTRACT — implementations of `parser.rs` MUST produce
//! this shape, and downstream consumers (capability-layer pipeline in spec
//! 10) MUST consume only this shape.
//!
//! All maps are `BTreeMap` and all sets are `BTreeSet` — determinism by type.
//! Per spec 09 §9.2.5 the clippy lint `disallowed-types` (configured in the
//! workspace) bans `HashMap`/`HashSet` in `csq-core/src/coc/**`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::version::CocVersion;
use crate::providers::catalog::Surface;

/// In-memory representation of a parsed `.coc/` set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CocSet {
    pub rules: BTreeMap<RuleId, RuleDef>,
    pub agents: BTreeMap<AgentId, AgentDef>,
    pub skills: BTreeMap<SkillId, SkillDef>,
    pub commands: BTreeMap<CommandId, CommandDef>,
    pub version: CocVersion,
    pub source: CocSource,
}

impl CocSet {
    pub fn empty() -> Self {
        Self {
            rules: BTreeMap::new(),
            agents: BTreeMap::new(),
            skills: BTreeMap::new(),
            commands: BTreeMap::new(),
            version: CocVersion::ZERO,
            source: CocSource::Empty,
        }
    }
}

/// Origin of a `CocSet` — which fallback level produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CocSource {
    /// Loaded from `.coc/` with a `COC.lock` content hash recorded.
    ///
    /// Per `workspaces/csq-as-cli/journal/0093`, the prior `sig` field
    /// (Ed25519 over `COC.lock`) was retracted — per-artifact signing is
    /// the wrong layer; deterministic attestation belongs at the runtime
    /// lifecycle (Step 3, `workspaces/csq-pact-eatp-adoption`).
    Coc {
        #[serde(with = "hex_array_32")]
        lock_sha256: [u8; 32],
    },
    LegacyClaude,
    LegacyGemini,
    LegacyAgentsMd,
    Empty,
}

mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        let v = hex::decode(&raw).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 hex bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

impl CocSource {
    pub fn as_log_value(&self) -> &'static str {
        match self {
            CocSource::Coc { .. } => "coc",
            CocSource::LegacyClaude => "claude-native",
            CocSource::LegacyGemini => "gemini-native",
            CocSource::LegacyAgentsMd => "agents-md",
            CocSource::Empty => "none",
        }
    }
}

macro_rules! id_newtype {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Validate per spec 09 §9.2.1: `^[A-Z][A-Z0-9-]{1,32}$`.
            ///
            /// The regex is `[A-Z]` (one uppercase letter) followed by 1-32
            /// characters from `[A-Z0-9-]`. We hand-roll the check rather
            /// than pull `regex`. Total length: 2-33 characters.
            pub fn parse(input: &str) -> Result<Self, IdParseError> {
                let bytes = input.as_bytes();
                if bytes.is_empty() || bytes.len() > 33 {
                    return Err(IdParseError {
                        kind: $kind,
                        input: input.to_string(),
                        reason: format!("length {} not in 2..=33", bytes.len()),
                    });
                }
                if bytes.len() < 2 {
                    return Err(IdParseError {
                        kind: $kind,
                        input: input.to_string(),
                        reason: "must be at least 2 characters".into(),
                    });
                }
                if !bytes[0].is_ascii_uppercase() {
                    return Err(IdParseError {
                        kind: $kind,
                        input: input.to_string(),
                        reason: "first character must be uppercase letter".into(),
                    });
                }
                for &b in &bytes[1..] {
                    if !(b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-') {
                        return Err(IdParseError {
                            kind: $kind,
                            input: input.to_string(),
                            reason: format!("invalid character {:?}", b as char),
                        });
                    }
                }
                Ok(Self(input.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

id_newtype!(RuleId, "rule");
id_newtype!(AgentId, "agent");
id_newtype!(SkillId, "skill");
id_newtype!(CommandId, "command");

#[derive(Debug, thiserror::Error)]
#[error("invalid {kind} id `{input}`: {reason}")]
pub struct IdParseError {
    pub kind: &'static str,
    pub input: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDef {
    pub id: RuleId,
    pub paths: Vec<String>,
    pub applies_to: BTreeSet<Surface>,
    pub precedence: i32,
    pub disable: BTreeSet<TechniqueOptOut>,
    pub body: String,
    pub unknowns: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDef {
    pub id: AgentId,
    pub applies_to: BTreeSet<Surface>,
    pub precedence: i32,
    pub disable: BTreeSet<TechniqueOptOut>,
    pub body: String,
    pub unknowns: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillDef {
    pub id: SkillId,
    pub applies_to: BTreeSet<Surface>,
    pub precedence: i32,
    pub disable: BTreeSet<TechniqueOptOut>,
    pub body: String,
    pub unknowns: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandDef {
    pub id: CommandId,
    pub applies_to: BTreeSet<Surface>,
    pub precedence: i32,
    pub disable: BTreeSet<TechniqueOptOut>,
    pub body: String,
    pub unknowns: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TechniqueOptOut {
    Scaffold,
    McpGate,
    PostValidate,
    StructOut,
}

impl TechniqueOptOut {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "scaffold" => Some(Self::Scaffold),
            "mcp-gate" => Some(Self::McpGate),
            "post-validate" => Some(Self::PostValidate),
            "struct-out" => Some(Self::StructOut),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_parses_uppercase_alphanumeric_with_hyphens() {
        assert!(RuleId::parse("RULE-X").is_ok());
        assert!(RuleId::parse("RULE-NO-SHELL").is_ok());
        assert!(RuleId::parse("R1").is_ok());
        assert!(RuleId::parse("AB").is_ok());
    }

    #[test]
    fn id_rejects_lowercase_first_char() {
        assert!(RuleId::parse("rule-x").is_err());
    }

    #[test]
    fn id_rejects_invalid_chars() {
        assert!(RuleId::parse("RULE_X").is_err());
        assert!(RuleId::parse("RULE.X").is_err());
        assert!(RuleId::parse("rule x").is_err());
        assert!(RuleId::parse("*").is_err());
    }

    #[test]
    fn id_rejects_too_short() {
        assert!(RuleId::parse("R").is_err());
        assert!(RuleId::parse("").is_err());
    }

    #[test]
    fn id_rejects_too_long() {
        // Max length: 33 characters (1 leading + 32 trailing).
        assert!(RuleId::parse(&"R".repeat(33)).is_ok());
        assert!(RuleId::parse(&"R".repeat(34)).is_err());
    }

    #[test]
    fn technique_optout_parses_known_values() {
        assert_eq!(
            TechniqueOptOut::parse("scaffold"),
            Some(TechniqueOptOut::Scaffold)
        );
        assert_eq!(
            TechniqueOptOut::parse("mcp-gate"),
            Some(TechniqueOptOut::McpGate)
        );
        assert_eq!(
            TechniqueOptOut::parse("post-validate"),
            Some(TechniqueOptOut::PostValidate)
        );
        assert_eq!(
            TechniqueOptOut::parse("struct-out"),
            Some(TechniqueOptOut::StructOut)
        );
        assert_eq!(TechniqueOptOut::parse("nope"), None);
    }
}
