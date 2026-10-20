//! Seven invariants: pinned bytes; nonempty unique population; complete arm/oracle
//! descriptions; bounded IO/deadlines; independent fixture clones; both arms must
//! match the oracle; unsupported/effect populations never become full qualification.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
};

pub const MAX_BYTES: usize = 8192;
pub const MAX_MANIFEST: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub format: u32,
    pub release: String,
    pub source_revision: String,
    pub profile: String,
    pub files: Vec<Binding>,
    pub cases: Vec<Case>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub stdin: String,
    pub timeout_ms: u64,
    pub initial_files: std::collections::BTreeMap<String, String>,
    pub standalone: Arm,
    pub dispatched: Arm,
    pub expected: Expected,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Arm {
    pub program: String,
    pub program_sha256: String,
    pub args: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub exit_code: i32,
    pub observation: Observation,
    pub stderr: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub decision: Decision,
    pub context: Vec<String>,
    pub rewrite: Option<serde_json::Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Continue,
    Advisory,
    RefuseHandback,
    Incomplete,
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn relative(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .collect::<std::path::PathBuf>()
            .to_string_lossy()
            == value
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
pub fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "file_missing")?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_read")?;
    if bytes.len() > cap {
        return Err("file_limit".into());
    }
    Ok(bytes)
}

/// Pins come from the operator separately, never from a manifest self-hash.
pub fn load(path: &Path, pin: &str) -> Result<(Corpus, String), String> {
    let bytes = read_bounded(path, MAX_MANIFEST)?;
    let actual = hash(&bytes);
    if !digest_valid(pin) || actual != pin {
        return Err("corpus_pin_mismatch".into());
    }
    let corpus: Corpus = super::strict_json::parse(&bytes).map_err(|_| "manifest_shape")?;
    validate(&corpus)?;
    Ok((corpus, actual))
}
pub fn validate(corpus: &Corpus) -> Result<(), String> {
    if corpus.format != 1
        || corpus.release.is_empty()
        || corpus.source_revision.is_empty()
        || corpus.profile.is_empty()
        || corpus.cases.is_empty()
        || corpus.cases.len() > 4096
    {
        return Err("invalid_population".into());
    }
    let mut ids = BTreeSet::new();
    let mut files = BTreeSet::new();
    for binding in &corpus.files {
        if !relative(&binding.path)
            || !digest_valid(&binding.sha256)
            || !files.insert(&binding.path)
        {
            return Err("invalid_file_binding".into());
        }
    }
    for case in &corpus.cases {
        if case.id.is_empty()
            || !ids.insert(&case.id)
            || case.stdin.len() > MAX_BYTES
            || !(1..=5000).contains(&case.timeout_ms)
            || case.expected.stderr.len() > MAX_BYTES
            || serde_json::to_vec(&case.expected.observation)
                .map_err(|_| "oracle_shape")?
                .len()
                > MAX_BYTES
        {
            return Err("invalid_case".into());
        }
        for (path, content) in &case.initial_files {
            if !relative(path) || content.len() > MAX_BYTES {
                return Err("invalid_fixture".into());
            }
        }
        for arm in [&case.standalone, &case.dispatched] {
            if !Path::new(&arm.program).is_absolute()
                || !digest_valid(&arm.program_sha256)
                || arm.args.len() > 128
                || arm.args.iter().any(|a| a.len() > MAX_BYTES)
            {
                return Err("invalid_arm".into());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Captured {
    pub spawned: bool,
    pub forced_cleanup: bool,
    pub cleanup_unknown: bool,
    pub direct_pid_signal: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed_ms: u128,
    pub problem: Option<String>,
}
impl Captured {
    pub fn matches(&self, oracle: &Expected) -> bool {
        self.problem.is_none()
            && !self.forced_cleanup
            && !self.cleanup_unknown
            && self.exit_code == Some(oracle.exit_code)
            && self.stderr == oracle.stderr.as_bytes()
            && super::strict_json::parse::<Observation>(&self.stdout)
                .ok()
                .as_ref()
                == Some(&oracle.observation)
    }
    pub fn same(&self, other: &Self) -> bool {
        let (Ok(left), Ok(right)) = (
            super::strict_json::parse::<Observation>(&self.stdout),
            super::strict_json::parse::<Observation>(&other.stdout),
        ) else {
            return false;
        };
        self.problem.is_none()
            && other.problem.is_none()
            && !self.forced_cleanup
            && !other.forced_cleanup
            && !self.cleanup_unknown
            && !other.cleanup_unknown
            && self.exit_code == other.exit_code
            && self.stderr == other.stderr
            && left == right
    }
}
#[derive(Debug, Serialize)]
pub struct Pair {
    pub id: String,
    pub standalone: Captured,
    pub dispatched: Captured,
    pub oracle_conformant: bool,
    pub differential_matched: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub instrument_sha256: String,
    pub corpus_sha256: String,
    pub source_revision: String,
    pub release: String,
    pub platform: String,
    pub invocation: String,
    pub scope: String,
    pub required_cases: usize,
    pub attempted_cases: usize,
    pub completed_cases: usize,
    pub unsupported_cases: usize,
    pub planned_invocations: usize,
    pub attempted_invocations: usize,
    pub spawned_invocations: usize,
    pub oracle_conformant_cases: usize,
    pub differential_matched_cases: usize,
    pub protocol_equivalent: bool,
    pub full_corpus_qualified: bool,
    pub pairs: Vec<Pair>,
}
