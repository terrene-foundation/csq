//! Project trust is copied only from the owner's canonical Codex configuration.
use crate::types::AccountNum;
use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustWarning {
    MissingSource,
    UnreadableSource,
    UnparseableSource,
    UnreadableSlot,
    UnparseableSlot,
}

pub(crate) struct ProjectTrust {
    projects: Result<Option<toml::Value>, TrustWarning>,
}

fn source_path() -> Option<PathBuf> {
    // Fixture-only seam. Production deliberately ignores CODEX_USER_CONFIG.
    #[cfg(any(test, feature = "test-utils"))]
    {
        std::env::var_os("CSQ_TEST_CODEX_TRUST_CONFIG")
            .or_else(|| std::env::var_os(super::surface::USER_CONFIG_ENV_OVERRIDE))
            .map(PathBuf::from)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    dirs::home_dir().map(|home| home.join(".codex/config.toml"))
}

impl ProjectTrust {
    pub(crate) fn read() -> Self {
        Self {
            projects: source_path()
                .ok_or(TrustWarning::MissingSource)
                .and_then(|path| Self::read_projects(&path)),
        }
    }

    fn read_projects(path: &Path) -> Result<Option<toml::Value>, TrustWarning> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                TrustWarning::MissingSource
            } else {
                TrustWarning::UnreadableSource
            }
        })?;
        let value: toml::Value =
            toml::from_str(&text).map_err(|_| TrustWarning::UnparseableSource)?;
        let projects = value.get("projects").cloned();
        if projects.as_ref().is_some_and(|v| !v.is_table()) {
            return Err(TrustWarning::UnparseableSource);
        }
        Ok(projects)
    }

    pub(crate) fn apply(&self, merged: &mut toml::value::Table, existing: Option<&toml::Value>) {
        let projects = match &self.projects {
            Ok(projects) => projects.clone(),
            Err(warning) => {
                tracing::warn!(warning = ?warning, "Codex project trust source unavailable; preserving slot projects");
                existing.and_then(|v| v.get("projects")).cloned()
            }
        };
        merged.remove("projects");
        if let Some(projects) = projects {
            merged.insert("projects".into(), projects);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProjectTrustDiagnostic {
    pub slot: u16,
    pub drift: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<TrustWarning>,
}

impl ProjectTrust {
    fn inspect(&self, path: &Path) -> Result<(toml::value::Table, bool), TrustWarning> {
        self.inspect_bytes(path)
            .map(|(current, drift, _)| (current, drift))
    }

    /// [`Self::inspect`] plus the exact bytes read, so a writer can publish only if they are
    /// still on disk.
    fn inspect_bytes(
        &self,
        path: &Path,
    ) -> Result<(toml::value::Table, bool, Vec<u8>), TrustWarning> {
        let desired = self.projects.as_ref().map_err(|e| *e)?;
        let bytes = std::fs::read(path).map_err(|_| TrustWarning::UnreadableSlot)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| TrustWarning::UnreadableSlot)?;
        let current: toml::value::Table =
            toml::from_str(text).map_err(|_| TrustWarning::UnparseableSlot)?;
        let drift = current.get("projects") != desired.as_ref();
        Ok((current, drift, bytes))
    }
}

/// Read-only diagnostics use the same source and comparison as launch sync.
pub fn diagnose_project_trust(base: &Path, slots: &[AccountNum]) -> Vec<ProjectTrustDiagnostic> {
    let source = ProjectTrust::read();
    slots
        .iter()
        .map(|slot| {
            let state = source.inspect(&super::surface::config_toml_path(base, *slot));
            ProjectTrustDiagnostic {
                slot: slot.get(),
                drift: state.as_ref().is_ok_and(|(_, drift)| *drift),
                warning: state.err(),
            }
        })
        .filter(|state| state.drift || state.warning.is_some())
        .collect()
}

/// Projects-only refresh for launch paths that do not regenerate other settings.
/// Unknown source leaves the complete existing slot file untouched.
pub fn sync_slot_project_trust(base: &Path, slot: AccountNum) -> io::Result<Option<TrustWarning>> {
    let source = ProjectTrust::read();
    let target = super::surface::config_toml_path(base, slot);
    // No drift (the common case) needs no lock and no write.
    match source.inspect(&target) {
        Ok((_, false)) => return Ok(None),
        Ok((_, true)) => {}
        Err(warning) => return Ok(Some(warning)),
    }
    // Drift: hold the per-slot lock every csq writer of this file holds, and publish only if
    // the bytes read under it are still on disk at the atomic exchange (re-reading on a
    // change), so a concurrent csq writer's carry or a Codex write is never overwritten.
    let _slot_lock = super::surface::lock_slot_config(base, slot)?;
    for _ in 0..super::surface::PUBLISH_ATTEMPTS {
        let (mut current, drift, bytes) = match source.inspect_bytes(&target) {
            Ok(state) => state,
            Err(warning) => return Ok(Some(warning)),
        };
        if !drift {
            return Ok(None);
        }
        source.apply(&mut current, None);
        let text = toml::to_string(&current).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "could not serialize Codex project trust snapshot",
            )
        })?;
        if super::surface::write_config_toml_contents_if_unchanged(&target, &text, Some(&bytes))?
            == super::surface::ConditionalWrite::Written
        {
            return Ok(None);
        }
    }
    Err(super::surface::publish_gave_up())
}

/// Launch remains available when the owner source cannot be synchronized.
pub(crate) fn sync_before_handle(base: &Path, slot: AccountNum) {
    match sync_slot_project_trust(base, slot) {
        Ok(None) => {}
        Ok(Some(warning)) => tracing::warn!(account = %slot, warning = ?warning,
            "Codex project trust unchanged; inspect csq doctor"),
        Err(_) => tracing::warn!(account = %slot, error_kind = "codex_project_trust_write_failed",
            "Codex project trust publication failed; prior slot configuration retained"),
    }
}

#[cfg(test)]
mod tests;
