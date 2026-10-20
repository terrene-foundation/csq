//! Read-only lifecycle evidence, not authorization to retire scratch directories.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SessionDiskRow {
    pub generation: String,
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Design-intent operator field: the scratch target identifies which directory
    /// lifecycle evidence concerns. No transcript or credential content is included.
    /// Operator-surface audit excludes the explicit JSON field `"scratch_dir":`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scratch_dir: Option<String>,
    pub state: String,
    pub decision: &'static str,
    pub reasons: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SessionDiskPayload {
    /// Completeness of stored lifecycle evidence, not of host scratch inventory.
    pub complete: bool,
    pub rows: Vec<SessionDiskRow>,
    /// Retirement oracles that remain unknown; every row remains KEEP.
    pub reasons: Vec<&'static str>,
}
