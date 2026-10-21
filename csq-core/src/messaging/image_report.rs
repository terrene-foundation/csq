//! Closed, bounded private image reports; no native capture or freshness verdict.
use super::image_build_grammar::{
    validate_build_target, validate_build_version, validate_revision,
};
use super::model::VerifiedSession;
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(unix)]
const DIRECTORY: &str = ".csq-mcp-images";
pub const SCHEMA: &str = "csq.mcp_image.v1";
pub const MAX_REPORT_BYTES: usize = 4096;
pub const MAX_REPORTS: usize = 8;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Macos,
    Windows,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edition {
    Community,
    Enterprise,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Clean,
    Dirty,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSurface {
    ClaudeCode,
    Codex,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildIdentity {
    pub pid: u32,
    pub start_exact: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionIdentity {
    pub pid: u32,
    pub started_at: u64,
    pub start_exact: u64,
    pub surface: ImageSurface,
    pub handle_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub edition: Edition,
    pub version: String,
    pub target: String,
    pub source_state: SourceState,
    pub availability: Availability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadedKind {
    LinuxProcExe,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadedImage {
    pub kind: LoadedKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<FileIdentity>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageReport {
    schema: String,
    platform: Platform,
    child: ChildIdentity,
    session: SessionIdentity,
    build: BuildIdentity,
    loaded: LoadedImage,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReport {
    schema: String,
    platform: Platform,
    child: ChildIdentity,
    session: SessionIdentity,
    build: BuildIdentity,
    loaded: LoadedImage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("MCP image report refused")]
pub enum ReportError {
    Unavailable,
    Malformed,
    Unsafe,
    Limit,
    Busy,
}
impl ImageReport {
    pub fn new(
        platform: Platform,
        child: ChildIdentity,
        session: SessionIdentity,
        build: BuildIdentity,
        loaded: LoadedImage,
    ) -> Result<Self, ReportError> {
        let report = Self {
            schema: SCHEMA.into(),
            platform,
            child,
            session,
            build,
            loaded,
        };
        report.validate()?;
        Ok(report)
    }
    pub fn child(&self) -> &ChildIdentity {
        &self.child
    }
    pub fn session(&self) -> &SessionIdentity {
        &self.session
    }
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }
    pub fn loaded(&self) -> &LoadedImage {
        &self.loaded
    }
    pub fn platform(&self) -> Platform {
        self.platform
    }
    fn validate(&self) -> Result<(), ReportError> {
        let b = &self.build;
        let available = b.revision.is_some() && b.source_state == SourceState::Clean;
        let valid_identity = self
            .loaded
            .identity
            .as_ref()
            .is_none_or(|i| i.mtime_nsec < 1_000_000_000 && i.ctime_nsec < 1_000_000_000);
        let valid_loaded = match self.loaded.kind {
            LoadedKind::LinuxProcExe => {
                self.platform == Platform::Linux && self.loaded.identity.is_some()
            }
            LoadedKind::Unavailable => self.loaded.identity.is_none(),
        };
        if self.schema != SCHEMA
            || self.child.pid <= 1
            || self.child.start_exact == 0
            || self.session.pid <= 1
            || self.session.start_exact == 0
            || self.session.handle_sha256.len() != 64
            || !validate_revision(&self.session.handle_sha256)
            || !validate_build_version(&b.version)
            || !validate_build_target(&b.target)
            || b.revision.as_ref().is_some_and(|v| !validate_revision(v))
            || (b.availability == Availability::Available) != available
            || (b.revision.is_none() && b.source_state != SourceState::Unknown)
            || !valid_identity
            || !valid_loaded
        {
            return Err(ReportError::Malformed);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, ReportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ReportError::Malformed)?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(ReportError::Limit);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(ReportError::Limit);
        }
        let raw: RawReport = serde_json::from_slice(bytes).map_err(|_| ReportError::Malformed)?;
        let report = Self {
            schema: raw.schema,
            platform: raw.platform,
            child: raw.child,
            session: raw.session,
            build: raw.build,
            loaded: raw.loaded,
        };
        report.validate()?;
        Ok(report)
    }
}

#[cfg(unix)]
impl ImageReport {
    fn filename(&self) -> String {
        format!("{}-{}.json", self.child.pid, self.child.start_exact)
    }
}
#[cfg(unix)]
fn slot(value: &str) -> bool {
    let Some((pid, start)) = value.split_once('-') else {
        return false;
    };
    pid.parse::<u32>()
        .is_ok_and(|n| n > 1 && n.to_string() == pid)
        && start
            .parse::<u64>()
            .is_ok_and(|n| n > 0 && n.to_string() == start)
}
#[cfg(unix)]
#[path = "image_report_files.rs"]
mod files;
pub fn publish(who: &VerifiedSession, report: &ImageReport) -> Result<(), ReportError> {
    #[cfg(unix)]
    {
        files::publish(who, report)
    }
    #[cfg(not(unix))]
    {
        let _ = (who, report);
        Err(ReportError::Unavailable)
    }
}
pub fn read_reports(handle: &Path) -> Result<Vec<ImageReport>, ReportError> {
    #[cfg(unix)]
    {
        files::read(handle)
    }
    #[cfg(not(unix))]
    {
        let _ = handle;
        Err(ReportError::Unavailable)
    }
}

/// One checked report read bracketed by caller-owned read-only observations.
pub struct ObservedReport<T> {
    pub report: ImageReport,
    pub before: T,
    pub after: T,
}
/// Observe only the canonical numeric child identity, never report-selected paths.
pub fn read_reports_observed<T>(
    handle: &Path,
    observe: &impl Fn(&ChildIdentity) -> T,
) -> Result<Vec<ObservedReport<T>>, ReportError> {
    #[cfg(unix)]
    {
        files::read_observed(handle, observe)
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, observe);
        Err(ReportError::Unavailable)
    }
}
#[cfg(test)]
#[path = "image_report_tests.rs"]
mod tests;
