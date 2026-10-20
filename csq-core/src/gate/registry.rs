//! Strict reader for the agreed loom hook-registry v1 contract.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_ROWS: usize = 512;
pub const PRECEDENCE: &str =
    "deny > conflicting-rewrite refusal > single rewrite; advise never downgrades a deny";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Event {
    PreToolUse,
    PostToolUse,
    UserPromptSubmit,
    Stop,
    SubagentStop,
    SessionStart,
    SessionEnd,
    PreCompact,
}
impl Event {
    pub const ALL: [Self; 8] = [
        Self::PreToolUse,
        Self::PostToolUse,
        Self::UserPromptSubmit,
        Self::Stop,
        Self::SubagentStop,
        Self::SessionStart,
        Self::SessionEnd,
        Self::PreCompact,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::UserPromptSubmit => "UserPromptSubmit",
            Self::Stop => "Stop",
            Self::SubagentStop => "SubagentStop",
            Self::SessionStart => "SessionStart",
            Self::SessionEnd => "SessionEnd",
            Self::PreCompact => "PreCompact",
        }
    }
    /// Safe fallback when no authenticated manifest defaults can be consulted.
    pub fn default_policy(self) -> FailurePolicy {
        if self == Self::PreToolUse {
            FailurePolicy::Deny
        } else {
            FailurePolicy::Continue
        }
    }
}
impl FromStr for Event {
    type Err = RegistryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|event| event.as_str() == s)
            .ok_or(RegistryError::InvalidContract)
    }
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $value)] $variant),+ }
    };
}
string_enum!(FailurePolicy { Deny => "deny", Continue => "continue" });
string_enum!(Severity { Block => "block", Advise => "advise" });
string_enum!(Form { InProcess => "in-process", Legacy => "legacy" });
string_enum!(Surface { Claude => "claude", Codex => "codex", Gemini => "gemini" });
string_enum!(CwdScope { Payload => "payload", Process => "process" });
string_enum!(ProtocolKind { PermissionDecision => "permission-decision", ContextInjection => "context-injection", PromptGate => "prompt-gate", HandbackDecision => "handback-decision", Advisory => "advisory", FailureReport => "failure-report", CompactionInstructions => "compaction-instructions" });
string_enum!(Source { LoomTemplate => "loom-template", RepoLocal => "repo-local", ThirdParty => "third-party" });
string_enum!(Pool { Template => "template", Repo => "repo" });

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub path: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEntry {
    pub entry: String,
    pub deps: Vec<Dependency>,
    // Frozen schema defines this hash but does not require it. Consumers must
    // refuse runtime verification when absent; never synthesize a hash from deps.
    pub entry_sha256: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutExemption {
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub kind: ProtocolKind,
    pub exit_codes: Vec<i64>,
    pub exit_codes_computed: bool,
    pub decision_fields: Vec<String>,
    pub severity: Severity,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideEffects {
    pub fs_writes: Vec<String>,
    pub network: bool,
    pub spawns: Vec<String>,
    pub declared_by: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cost {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub platform: String,
    pub method: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub payload_stdin: BTreeMap<Surface, String>,
    pub protocol: Protocol,
    pub form: Form,
    pub runtime: String,
    pub cwd_scope: CwdScope,
    pub side_effects: SideEffects,
    pub idempotent: bool,
    pub may_rewrite_input: bool,
    pub cost: Option<Cost>,
}

#[derive(Debug, Clone)]
pub struct HookRow {
    pub id: String,
    pub order: u64,
    pub event: Event,
    pub matcher: String,
    pub file: String,
    pub file_sha256: String,
    pub timeout: Option<u64>,
    pub surfaces: Vec<Surface>,
    pub source: Source,
    pub pool: Pool,
    pub deps: Vec<Dependency>,
    pub timeout_exemption: Option<TimeoutExemption>,
    pub on_incomplete: FailurePolicy,
    pub on_crash: FailurePolicy,
    pub on_timeout: FailurePolicy,
    pub contract: Contract,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRow {
    id: String,
    order: u64,
    event: Event,
    matcher: Option<String>,
    file: String,
    file_sha256: String,
    on_incomplete: Option<FailurePolicy>,
    on_crash: Option<FailurePolicy>,
    on_timeout: Option<FailurePolicy>,
    timeout: Option<u64>,
    surfaces: Vec<Surface>,
    source: Source,
    pool: Pool,
    deps: Vec<Dependency>,
    timeout_exemption: Option<TimeoutExemption>,
    contract: Contract,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    #[serde(rename = "$id")]
    id: String,
    version: String,
    content_sha256: String,
    content_sha256_scheme: String,
    source_sha: String,
    generated_by: String,
    unknown_major_policy: String,
    default_on_incomplete: BTreeMap<Event, FailurePolicy>,
    precedence: String,
    runtimes: Vec<RuntimeEntry>,
    hooks: Vec<RawRow>,
}

#[derive(Debug, Clone)]
pub struct Registry {
    pub version: String,
    pub content_sha256: String,
    pub source_sha: String,
    pub default_on_incomplete: BTreeMap<Event, FailurePolicy>,
    pub hooks: Vec<HookRow>,
    pub runtimes: Vec<RuntimeEntry>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("hook registry is malformed")]
    Malformed,
    #[error("hook registry version is unsupported")]
    UnsupportedVersion,
    #[error("hook registry content hash differs")]
    ContentMismatch,
    #[error("hook registry contract is invalid")]
    InvalidContract,
    #[error("hook registry exceeds admission limits")]
    Limit,
}

impl Registry {
    pub fn parse(bytes: &[u8]) -> Result<Self, RegistryError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(RegistryError::Limit);
        }
        let value = strict_json(bytes)?;
        if value
            .get("runtimes")
            .and_then(Value::as_array)
            .ok_or(RegistryError::Malformed)?
            .iter()
            .any(|runtime| runtime.get("entry_sha256").is_some_and(Value::is_null))
        {
            return Err(RegistryError::InvalidContract);
        }
        for row in value
            .get("hooks")
            .and_then(Value::as_array)
            .ok_or(RegistryError::Malformed)?
        {
            if row
                .get("contract")
                .and_then(|c| c.get("cost"))
                .is_some_and(Value::is_null)
            {
                return Err(RegistryError::InvalidContract);
            }
            if [
                "matcher",
                "timeout",
                "on_incomplete",
                "on_crash",
                "on_timeout",
            ]
            .iter()
            .any(|field| row.get(field).is_none())
            {
                return Err(RegistryError::Malformed);
            }
        }
        let raw: RawRegistry =
            serde_json::from_value(value.clone()).map_err(|_| RegistryError::Malformed)?;
        let parts: Vec<_> = raw.version.split('.').collect();
        if raw.id != "loom.hook-registry/v1"
            || parts.len() != 3
            || parts.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|b| b.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
            })
            || parts[0] != "1"
        {
            return Err(RegistryError::UnsupportedVersion);
        }
        if !valid_digest(&raw.content_sha256)
            || sha256(&canonical_content_bytes(&value)?) != raw.content_sha256
        {
            return Err(RegistryError::ContentMismatch);
        }
        if raw.hooks.len() > MAX_ROWS || raw.runtimes.len() > MAX_ROWS {
            return Err(RegistryError::Limit);
        }
        if raw.source_sha.len() != 40
            || !raw
                .source_sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !valid_relative_file(&raw.generated_by)
            || raw.unknown_major_policy != "fail-closed"
            || raw.content_sha256_scheme != "RFC 8785 JCS"
            || raw.precedence != PRECEDENCE
            || raw.hooks.is_empty()
            || raw.runtimes.is_empty()
            || Event::ALL
                .iter()
                .any(|event| !raw.default_on_incomplete.contains_key(event))
        {
            return Err(RegistryError::InvalidContract);
        }
        let mut ids = BTreeSet::new();
        let mut orders = BTreeSet::new();
        let mut hooks = Vec::new();
        let mut bindings = BTreeMap::new();
        for runtime in &raw.runtimes {
            if !valid_runtime_file(&runtime.entry)
                || !valid_deps(&runtime.deps)
                || runtime.entry_sha256.as_ref().is_some_and(|hash| {
                    !valid_digest(hash) || !bind(&mut bindings, &runtime.entry, hash)
                })
                || runtime
                    .deps
                    .iter()
                    .any(|dep| !bind(&mut bindings, &dep.path, &dep.sha256))
            {
                return Err(RegistryError::InvalidContract);
            }
        }
        let mut runtime_entries = BTreeSet::new();
        if raw
            .runtimes
            .iter()
            .any(|r| !runtime_entries.insert(&r.entry))
        {
            return Err(RegistryError::InvalidContract);
        }
        for row in raw.hooks {
            let matcher = row.matcher.clone().unwrap_or_default();
            let incomplete = row
                .on_incomplete
                .unwrap_or(raw.default_on_incomplete[&row.event]);
            let weaker_timeout = row.on_timeout == Some(FailurePolicy::Continue)
                && incomplete == FailurePolicy::Deny;
            if row.id != stable_row_id(row.event, &matcher, &row.file)
                || !ids.insert(row.id.clone())
                || !(1..=100000).contains(&row.order)
                || !orders.insert((row.event, row.order))
                || matcher.len() > 4096
                || matcher.contains('\0')
                || row.matcher.as_ref().is_some_and(String::is_empty)
                || !valid_hook_file(&row.file)
                || !valid_digest(&row.file_sha256)
                || row
                    .timeout
                    .is_some_and(|timeout| !(1..=3600).contains(&timeout))
                || !valid_deps(&row.deps)
                || !bind(&mut bindings, &row.file, &row.file_sha256)
                || row
                    .deps
                    .iter()
                    .any(|dep| !bind(&mut bindings, &dep.path, &dep.sha256))
                || row.pool
                    != if row.source == Source::LoomTemplate {
                        Pool::Template
                    } else {
                        Pool::Repo
                    }
                || !valid_contract(row.event, &row.surfaces, &row.contract)
                || (row.on_incomplete.is_none()
                    && raw.default_on_incomplete[&row.event] != row.event.default_policy())
                || (row.on_incomplete.is_some()
                    && (row.on_crash.is_none() || row.on_timeout.is_none()))
                || (row.event == Event::PreToolUse
                    && row.contract.protocol.severity == Severity::Block
                    && row.on_incomplete != Some(FailurePolicy::Deny))
                || row.timeout_exemption.as_ref().is_some_and(|e| {
                    e.reason.chars().count() < 10 || !bounded_text(&e.reason, 4096)
                })
                || (weaker_timeout && row.timeout_exemption.is_none())
            {
                return Err(RegistryError::InvalidContract);
            }
            let on_incomplete = row
                .on_incomplete
                .unwrap_or(raw.default_on_incomplete[&row.event]);
            if row.on_crash == Some(FailurePolicy::Continue) && on_incomplete == FailurePolicy::Deny
            {
                return Err(RegistryError::InvalidContract);
            }
            hooks.push(HookRow {
                id: row.id,
                order: row.order,
                event: row.event,
                matcher,
                file: row.file,
                file_sha256: row.file_sha256,
                timeout: row.timeout,
                surfaces: row.surfaces,
                source: row.source,
                pool: row.pool,
                deps: row.deps,
                timeout_exemption: row.timeout_exemption,
                on_incomplete,
                on_crash: row.on_crash.unwrap_or(on_incomplete),
                on_timeout: row.on_timeout.unwrap_or(on_incomplete),
                contract: row.contract,
            });
        }
        // Admission rejects event/order duplicates; stable order is defensive.
        hooks.sort_by_key(|row| (row.event, row.order));
        Ok(Self {
            version: raw.version,
            content_sha256: raw.content_sha256,
            source_sha: raw.source_sha,
            default_on_incomplete: raw.default_on_incomplete,
            hooks,
            runtimes: raw.runtimes,
        })
    }
    pub fn rows_for(&self, event: Event) -> impl Iterator<Item = &HookRow> {
        self.hooks.iter().filter(move |row| row.event == event)
    }
}

fn bounded_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.contains('\0')
}
pub(crate) fn valid_digest(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn valid_relative_file(file: &str) -> bool {
    bounded_text(file, 4096)
        && !file.contains(['\\', ':'])
        && file
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
pub fn stable_row_id(event: Event, matcher: &str, file: &str) -> String {
    format!(
        "hk_{}",
        &sha256(format!("{}\n{matcher}\n{file}", event.as_str()).as_bytes())[..16]
    )
}
fn valid_hook_file(file: &str) -> bool {
    file.strip_prefix(".claude/hooks/")
        .and_then(|name| name.strip_suffix(".js"))
        .is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
fn valid_runtime_file(file: &str) -> bool {
    valid_relative_file(file)
        && file.starts_with(".claude/hooks/")
        && file.ends_with(".js")
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}
fn valid_deps(deps: &[Dependency]) -> bool {
    deps.len() <= MAX_ROWS
        && deps
            .iter()
            .all(|d| valid_relative_file(&d.path) && valid_digest(&d.sha256))
        && deps.windows(2).all(|pair| pair[0].path < pair[1].path)
}
fn bind(bindings: &mut BTreeMap<String, String>, path: &str, hash: &str) -> bool {
    if let Some(previous) = bindings.get(path) {
        previous == hash
    } else {
        bindings.insert(path.into(), hash.into());
        true
    }
}
fn valid_contract(event: Event, surfaces: &[Surface], contract: &Contract) -> bool {
    let p = &contract.protocol;
    let kind = match event {
        Event::PreToolUse => ProtocolKind::PermissionDecision,
        Event::PostToolUse => ProtocolKind::ContextInjection,
        Event::UserPromptSubmit => ProtocolKind::PromptGate,
        Event::Stop | Event::SubagentStop => ProtocolKind::HandbackDecision,
        Event::SessionStart => ProtocolKind::Advisory,
        Event::SessionEnd => ProtocolKind::FailureReport,
        Event::PreCompact => ProtocolKind::CompactionInstructions,
    };
    !surfaces.is_empty()
        && surfaces.iter().collect::<BTreeSet<_>>().len() == surfaces.len()
        && surfaces
            .iter()
            .all(|surface| contract.payload_stdin.contains_key(surface))
        && contract
            .payload_stdin
            .iter()
            .all(|(surface, payload)| match surface {
                Surface::Claude => payload == "cc-hook-json",
                Surface::Codex => payload == "codex-hook-json",
                Surface::Gemini => payload == "gemini-hook-json",
            })
        && matches!(
            (&contract.form, contract.runtime.as_str()),
            (Form::InProcess, "hook-engine-worker") | (Form::Legacy, "node-subprocess")
        )
        && p.kind == kind
        && p.exit_codes.len() <= 256
        && p.exit_codes.iter().all(|exit| (0..=255).contains(exit))
        && p.exit_codes.windows(2).all(|pair| pair[0] < pair[1])
        && p.decision_fields.len() <= 32
        && p.decision_fields.iter().all(|field| {
            matches!(
                field.as_str(),
                "continue"
                    | "hookSpecificOutput"
                    | "permissionDecision"
                    | "decision"
                    | "additionalContext"
                    | "systemMessage"
                    | "reason"
                    | "suppressOutput"
                    | "stopReason"
                    | "refuseHandback"
                    | "updatedInput"
            )
        })
        && (!matches!(event, Event::SessionStart) || p.severity == Severity::Advise)
        && contract.side_effects.declared_by == "author"
        && contract.side_effects.spawns.len() <= 256
        && contract
            .side_effects
            .spawns
            .iter()
            .all(|s| bounded_text(s, 128) && !s.contains(['/', '\\']))
        && contract.side_effects.fs_writes.len() <= 256
        && contract
            .side_effects
            .fs_writes
            .iter()
            .all(|s| bounded_text(s, 4096))
        && contract.cost.as_ref().is_none_or(|c| {
            c.p50_ms.is_finite()
                && c.p95_ms.is_finite()
                && c.p50_ms >= 0.0
                && c.p50_ms.fract() == 0.0
                && c.p95_ms.fract() == 0.0
                && c.p95_ms >= c.p50_ms
                && c.p95_ms <= 3600000.0
                && bounded_text(&c.platform, 128)
                && bounded_text(&c.method, 1024)
        })
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub use super::canonical::canonical_content_bytes;

/// Reject duplicate keys at every depth before either hashing or typed parsing.
pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value, RegistryError> {
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Strict;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("JSON with unique object keys")
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Strict, E> {
                    if v.unsigned_abs() > 9007199254740991 {
                        return Err(E::custom("unsafe integer"));
                    }
                    Ok(Strict(v.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Strict, E> {
                    if v > 9007199254740991 {
                        return Err(E::custom("unsafe integer"));
                    }
                    Ok(Strict(v.into()))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
                    if !v.is_finite() || v.fract() != 0.0 || v.abs() > 9007199254740991.0 {
                        return Err(E::custom("non-integer or unsafe number"));
                    }
                    Ok(Strict(Value::Number((v as i64).into())))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Strict, A::Error> {
                    let mut result = serde_json::Map::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if matches!(key.as_str(), "__proto__" | "prototype" | "constructor") {
                            return Err(serde::de::Error::custom("unsafe object key"));
                        }
                        if result.contains_key(&key) {
                            return Err(serde::de::Error::custom("duplicate key"));
                        }
                        result.insert(key, map.next_value::<Strict>()?.0);
                    }
                    Ok(Strict(Value::Object(result)))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Strict, A::Error> {
                    let mut result = Vec::new();
                    while let Some(value) = seq.next_element::<Strict>()? {
                        result.push(value.0);
                    }
                    Ok(Strict(Value::Array(result)))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    serde_json::from_slice::<Strict>(bytes)
        .map(|v| v.0)
        .map_err(|_| RegistryError::Malformed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn frozen_1b_sample_bytes_and_population_are_admitted() {
        let sample = include_bytes!("../../tests/fixtures/hook_registry_1b/sample.json");
        let schema = include_bytes!("../../tests/fixtures/hook_registry_1b/schema.json");
        assert_eq!(
            sha256(sample),
            "ba28556537d7fd77c1361280a158e6918e8bd33a7cff29e2dc83894299ed199f"
        );
        assert_eq!(
            sha256(schema),
            "8d202ab3d554b4f67af5407131d192b6d2d1b156a7c0e135544ae36d8c209c6d"
        );
        let value = strict_json(sample).unwrap();
        assert_eq!(
            sha256(&canonical_content_bytes(&value).unwrap()),
            "10a48bfb7f1faa41bf14472eeb39c7d61b036c347390277a108bd3e9271fe0c7"
        );
        let registry = Registry::parse(sample).unwrap();
        assert_eq!(registry.hooks.len(), 87);
        assert_eq!(
            registry
                .hooks
                .iter()
                .map(|r| &r.file)
                .collect::<BTreeSet<_>>()
                .len(),
            69
        );
        assert_eq!(registry.runtimes.len(), 2);
        assert!(registry.runtimes.iter().all(|r| r.entry_sha256.is_some()));
        assert!(registry.hooks.iter().any(|r| !r.deps.is_empty()));
        assert!(registry.hooks.iter().all(|r| r.pool
            == if r.source == Source::LoomTemplate {
                Pool::Template
            } else {
                Pool::Repo
            }));
    }
    #[test]
    fn frozen_1b_missing_integrity_fields_and_unknown_shapes_refuse() {
        for field in ["runtimes", "content_sha256_scheme"] {
            let mut value = fixture(b"guard");
            value.as_object_mut().unwrap().remove(field);
            assert!(Registry::parse(&sealed(value)).is_err(), "missing {field}");
        }
        for field in ["deps", "pool"] {
            let mut value = fixture(b"guard");
            value["hooks"][0].as_object_mut().unwrap().remove(field);
            assert!(
                Registry::parse(&sealed(value)).is_err(),
                "missing row {field}"
            );
        }
        {
            let field = "may_rewrite_input";
            let mut value = fixture(b"guard");
            value["hooks"][0]["contract"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                Registry::parse(&sealed(value)).is_err(),
                "missing contract {field}"
            );
        }
        for mutation in 0..5 {
            let mut value = fixture(b"guard");
            match mutation {
                0 => value["runtimes"] = json!([]),
                1 => value["hooks"] = json!([]),
                2 => value["hooks"][0]["pool"] = "template".into(),
                3 => value["hooks"][0]["contract"]["side_effects"]["spawns"] = true.into(),
                _ => value["runtimes"][0]["unknown"] = true.into(),
            }
            assert!(
                Registry::parse(&sealed(value)).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn frozen_1b_dependencies_and_runtime_bindings_refuse_contradictions() {
        let mut value = fixture(b"guard");
        value["hooks"][0]["deps"] =
            json!([{"path":".claude/hooks/lib/helper.js","sha256":sha256(b"helper")}]);
        assert_eq!(
            Registry::parse(&sealed(value.clone())).unwrap().hooks[0]
                .deps
                .len(),
            1
        );
        for path in [
            "../outside.js",
            "/outside.js",
            "a//b",
            "a/../b",
            "a\\b",
            "C:outside.js",
            "",
        ] {
            let mut bad = value.clone();
            bad["hooks"][0]["deps"][0]["path"] = path.into();
            assert!(Registry::parse(&sealed(bad)).is_err(), "{path}");
        }
        let mut conflicting = value.clone();
        conflicting["runtimes"][0]["deps"] =
            json!([{"path":".claude/hooks/lib/helper.js","sha256":sha256(b"different helper")}]);
        assert!(Registry::parse(&sealed(conflicting)).is_err());
        let mut duplicate = value.clone();
        let dep = duplicate["hooks"][0]["deps"][0].clone();
        duplicate["hooks"][0]["deps"]
            .as_array_mut()
            .unwrap()
            .push(dep);
        assert!(Registry::parse(&sealed(duplicate)).is_err());
        let mut missing = value.clone();
        missing["runtimes"][0]
            .as_object_mut()
            .unwrap()
            .remove("deps");
        assert!(Registry::parse(&sealed(missing)).is_err());
        let mut absent_runtime_hash = value;
        absent_runtime_hash["runtimes"][0]
            .as_object_mut()
            .unwrap()
            .remove("entry_sha256");
        assert!(Registry::parse(&sealed(absent_runtime_hash))
            .unwrap()
            .runtimes[0]
            .entry_sha256
            .is_none());
    }
    #[test]
    fn frozen_1b_policy_strength_and_declared_timeout_exemption_are_preserved() {
        let mut value = fixture(b"guard");
        value["hooks"][0]["on_timeout"] = "continue".into();
        assert!(Registry::parse(&sealed(value.clone())).is_err());
        value["hooks"][0]["timeout_exemption"] =
            json!({"reason":"A reviewed exception for this specific timeout."});
        let row = Registry::parse(&sealed(value.clone()))
            .unwrap()
            .hooks
            .remove(0);
        assert_eq!(row.on_timeout, FailurePolicy::Continue);
        assert_eq!(row.on_crash, FailurePolicy::Deny);
        assert!(row.timeout_exemption.is_some());
        value["hooks"][0]["on_crash"] = "continue".into();
        assert!(Registry::parse(&sealed(value)).is_err());
        let mut stronger = fixture(b"guard");
        stronger["hooks"][0]["on_incomplete"] = "continue".into();
        stronger["hooks"][0]["contract"]["protocol"]["severity"] = "advise".into();
        assert_eq!(
            Registry::parse(&sealed(stronger.clone())).unwrap().hooks[0].on_crash,
            FailurePolicy::Deny
        );
        stronger["hooks"][0]["on_crash"] = Value::Null;
        assert!(Registry::parse(&sealed(stronger)).is_err());
        let mut explicit_deny = fixture(b"guard");
        explicit_deny["hooks"][0]["on_incomplete"] = Value::Null;
        explicit_deny["hooks"][0]["on_crash"] = Value::Null;
        explicit_deny["hooks"][0]["on_timeout"] = Value::Null;
        assert!(Registry::parse(&sealed(explicit_deny)).is_err());
    }
    #[test]
    fn frozen_1b_bounds_nullable_defaults_and_integer_lexemes_match_contract() {
        for (field, value) in [("order", 100001), ("timeout", 3601)] {
            let mut bad = fixture(b"guard");
            bad["hooks"][0][field] = value.into();
            assert!(Registry::parse(&sealed(bad)).is_err());
        }
        let mut advisory = fixture(b"guard");
        advisory["hooks"][0]["event"] = "PostToolUse".into();
        advisory["hooks"][0]["contract"]["protocol"]["kind"] = "context-injection".into();
        for field in ["on_incomplete", "on_crash", "on_timeout"] {
            advisory["hooks"][0][field] = Value::Null;
        }
        assert_eq!(
            Registry::parse(&sealed(advisory.clone())).unwrap().hooks[0].on_incomplete,
            FailurePolicy::Continue
        );
        advisory["default_on_incomplete"]["PostToolUse"] = "deny".into();
        assert!(Registry::parse(&sealed(advisory)).is_err());
        let text = String::from_utf8(sealed(fixture(b"guard"))).unwrap();
        let normalized = text
            .replace("\"order\":10", "\"order\":1e1")
            .replace("\"timeout\":30", "\"timeout\":30.0");
        assert_ne!(text, normalized);
        assert!(Registry::parse(normalized.as_bytes()).is_ok());
        for raw in [
            "9007199254740992",
            "-9007199254740992",
            "1.5",
            "1e21",
            "{\"x\":\"\\ud800\"}",
            "{\"x\":1,\"\\u0078\":2}",
        ] {
            assert!(strict_json(raw.as_bytes()).is_err(), "{raw}");
        }
    }
    pub fn fixture(file_bytes: &[u8]) -> Value {
        let defaults: BTreeMap<_, _> = Event::ALL
            .into_iter()
            .map(|event| (event.as_str(), event.default_policy()))
            .collect();
        json!({"$id":"loom.hook-registry/v1","version":"1.0.0","content_sha256":"","content_sha256_scheme":"RFC 8785 JCS","source_sha":"ffffffffffffffffffffffffffffffffffffffff","generated_by":"loom/.claude/bin/emit-hook-registry.mjs","unknown_major_policy":"fail-closed","default_on_incomplete":defaults,"precedence":PRECEDENCE,"runtimes":[{"entry":".claude/hooks/guard.js","entry_sha256":sha256(file_bytes),"deps":[]}],"hooks":[{"id":"test-hook","order":10,"event":"PreToolUse","matcher":"Bash|Edit","file":".claude/hooks/guard.js","file_sha256":sha256(file_bytes),"on_incomplete":"deny","on_crash":"deny","on_timeout":"deny","timeout":30,"source":"repo-local","pool":"repo","deps":[],"surfaces":["claude"],"contract":{"payload_stdin":{"claude":"cc-hook-json"},"protocol":{"kind":"permission-decision","exit_codes":[0,2],"exit_codes_computed":false,"decision_fields":["hookSpecificOutput","permissionDecision"],"severity":"block"},"form":"legacy","runtime":"node-subprocess","cwd_scope":"payload","side_effects":{"fs_writes":[],"network":false,"spawns":[],"declared_by":"author"},"idempotent":true,"may_rewrite_input":false}}]})
    }
    pub fn sealed(mut value: Value) -> Vec<u8> {
        for row in value["hooks"].as_array_mut().unwrap() {
            let event = Event::from_str(row["event"].as_str().unwrap()).unwrap();
            row["id"] = stable_row_id(
                event,
                row["matcher"].as_str().unwrap_or(""),
                row["file"].as_str().unwrap(),
            )
            .into();
        }
        value["content_sha256"] = sha256(&canonical_content_bytes(&value).unwrap()).into();
        serde_json::to_vec(&value).unwrap()
    }
    #[test]
    fn old_draft_sample_without_1b_integrity_fields_is_refused() {
        let schema_bytes =
            include_bytes!("../../tests/fixtures/hook-registry/hook-registry.schema.json");
        let sample =
            include_bytes!("../../tests/fixtures/hook-registry/sample-trestle-base.manifest.json");
        assert_eq!(
            sha256(schema_bytes),
            "5b37f9f26711ff297a5a698b7b98b073e73252e7a8cc8a1274f0a6d6ff41c9eb"
        );
        assert_eq!(
            sha256(sample),
            "b522eff01ec06ccc4dd3df629286088053bc9723d1629310c79338689133b02f"
        );
        let schema: Value = serde_json::from_slice(schema_bytes).unwrap();
        assert_eq!(
            schema["properties"]["$id"]["const"],
            "loom.hook-registry/v1"
        );
        let value: Value = serde_json::from_slice(sample).unwrap();
        for field in schema["required"].as_array().unwrap() {
            assert!(value.get(field.as_str().unwrap()).is_some());
        }
        assert!(Registry::parse(sample).is_err());
    }
    #[test]
    fn v1_policies_and_stable_order_are_resolved() {
        let mut v = fixture(b"guard");
        let mut second = v["hooks"][0].clone();
        second["file"] = ".claude/hooks/second.js".into();
        second["order"] = 11.into();
        second["on_incomplete"] = "continue".into();
        second["on_crash"] = "continue".into();
        second["on_timeout"] = "continue".into();
        second["contract"]["protocol"]["severity"] = "advise".into();
        let mut first = second.clone();
        first["file"] = ".claude/hooks/earlier.js".into();
        first["order"] = 1.into();
        first["on_timeout"] = "continue".into();
        v["hooks"].as_array_mut().unwrap().extend([second, first]);
        let registry = Registry::parse(&sealed(v)).unwrap();
        let rows: Vec<_> = registry.rows_for(Event::PreToolUse).collect();
        assert_eq!(
            rows.iter().map(|r| r.file.as_str()).collect::<Vec<_>>(),
            [
                ".claude/hooks/earlier.js",
                ".claude/hooks/guard.js",
                ".claude/hooks/second.js"
            ]
        );
        assert_eq!(rows[0].on_crash, FailurePolicy::Continue);
        assert_eq!(rows[0].on_timeout, FailurePolicy::Continue);
        assert_eq!(rows[1].on_incomplete, FailurePolicy::Deny);
        assert_eq!(rows[2].on_timeout, FailurePolicy::Continue);
    }
    #[test]
    fn canonical_keys_utf8_and_arrays_have_an_independent_byte_vector() {
        let value = json!({"z":"é","a":[{"z":2,"a":1},false],"content_sha256":"ignored"});
        assert_eq!(
            canonical_content_bytes(&value).unwrap(),
            "{\"a\":[{\"a\":1,\"z\":2},false],\"z\":\"é\"}".as_bytes()
        );
    }
    #[test]
    fn changed_content_refuses_without_reseal() {
        let mut v: Value = serde_json::from_slice(&sealed(fixture(b"guard"))).unwrap();
        v["hooks"][0]["timeout"] = 31.into();
        assert!(matches!(
            Registry::parse(&serde_json::to_vec(&v).unwrap()),
            Err(RegistryError::ContentMismatch)
        ));
    }
    #[test]
    fn schema_and_version_majors_fail_closed() {
        for (id, version) in [
            ("loom.hook-registry/v2", "2.0.0"),
            ("loom.hook-registry/v1", "2.0.0"),
            ("loom.hook-registry/v2", "1.0.0"),
            ("loom.hook-registry/v1", "01.0.0"),
        ] {
            let mut v = fixture(b"guard");
            v["$id"] = id.into();
            v["version"] = version.into();
            assert_eq!(
                Registry::parse(&sealed(v)).unwrap_err(),
                RegistryError::UnsupportedVersion
            );
        }
    }
    #[test]
    fn duplicate_keys_cannot_be_overwritten_before_hashing() {
        assert_eq!(
            Registry::parse(br#"{"$id":"v1","$id":"v2"}"#).unwrap_err(),
            RegistryError::Malformed
        );
        assert!(strict_json(br#"{"contract":{"severity":"block","severity":"advise"}}"#).is_err());
        for key in ["__proto__", "prototype", "constructor"] {
            let value = format!("{{\"nested\":{{\"{key}\":true}}}}");
            assert!(strict_json(value.as_bytes()).is_err());
        }
    }
    #[test]
    fn deadlines_and_order_require_nonnegative_integers() {
        for value in [json!(0), json!(-1), json!(true), json!("30")] {
            let mut v = fixture(b"guard");
            v["hooks"][0]["timeout"] = value;
            assert!(Registry::parse(&sealed(v)).is_err());
        }
        let mut nullable = fixture(b"guard");
        nullable["hooks"][0]["timeout"] = Value::Null;
        assert!(Registry::parse(&sealed(nullable)).is_ok());
        let mut v = fixture(b"guard");
        v["hooks"][0]["order"] = json!(-1);
        assert!(Registry::parse(&sealed(v)).is_err());
    }
    #[test]
    fn paths_and_duplicate_row_ids_refuse() {
        for path in [
            "../guard.js",
            "/guard.js",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            "C:guard.js",
            "",
        ] {
            let mut v = fixture(b"guard");
            v["hooks"][0]["file"] = path.into();
            assert!(Registry::parse(&sealed(v)).is_err());
        }
        let mut v = fixture(b"guard");
        let row = v["hooks"][0].clone();
        v["hooks"].as_array_mut().unwrap().push(row);
        assert!(Registry::parse(&sealed(v)).is_err());
    }
    #[test]
    fn unknown_fields_missing_defaults_and_unmeasured_cost_refuse() {
        let mut v = fixture(b"guard");
        v["hooks"][0]["contract"]["unexpected"] = true.into();
        assert!(Registry::parse(&sealed(v)).is_err());
        let mut v = fixture(b"guard");
        v["default_on_incomplete"]
            .as_object_mut()
            .unwrap()
            .remove("PreToolUse");
        assert!(Registry::parse(&sealed(v)).is_err());
        let mut v = fixture(b"guard");
        v["hooks"][0]["contract"]["cost"] =
            json!({"p50_ms":0,"p95_ms":0,"platform":"","method":""});
        assert!(Registry::parse(&sealed(v)).is_err());
    }
    #[test]
    fn manifest_limit_and_wrong_file_digest_refuse() {
        assert_eq!(
            Registry::parse(&vec![b' '; MAX_MANIFEST_BYTES + 1]).unwrap_err(),
            RegistryError::Limit
        );
        let mut v = fixture(b"guard");
        v["hooks"][0]["file_sha256"] = "ABC".into();
        assert!(Registry::parse(&sealed(v)).is_err());
    }
}
