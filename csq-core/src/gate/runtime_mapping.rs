//! Integrity-bound runtime membership; membership alone is not execution proof.
//! The consumer additionally requires the pinned pool outcome protocol.
use super::pin::{VerifiedRegistry, VerifiedRow};
use super::registry::{self, Event, Pool, Surface};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePoolBinding {
    pub runtime_index: usize,
    pub pool: Pool,
    pub event: Event,
    pub row_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    #[error("runtime_mapping_empty")]
    Empty,
    #[error("runtime_mapping_unverified")]
    Unverified,
    #[error("runtime_mapping_missing")]
    Missing,
    #[error("runtime_mapping_ambiguous")]
    Ambiguous,
    #[error("runtime_mapping_mixed_pool")]
    MixedPool,
    #[error("runtime_mapping_split_pool")]
    SplitPool,
    #[error("runtime_mapping_mixed_cwd_scope")]
    MixedCwdScope,
    #[error("runtime_mapping_closure")]
    Closure,
}

/// Each selected row must belong to exactly one verified entry/closure, and
/// each pool must have exactly one entry. No filename convention or positional
/// association grants authority. Rows for other events/surfaces are not selected.
pub fn prove_runtime_pools(
    verified: &VerifiedRegistry,
    event: Event,
    surface: Surface,
) -> Result<Vec<RuntimePoolBinding>, MappingError> {
    if verified.registry.runtimes.len() != verified.runtimes.len() {
        return Err(MappingError::Unverified);
    }
    let mut rows: Vec<&VerifiedRow> = verified
        .rows
        .iter()
        .filter(|row| row.row.event == event && row.row.surfaces.contains(&surface))
        .collect();
    rows.sort_by_key(|row| row.row.order);
    if rows.is_empty() {
        return Err(MappingError::Empty);
    }
    let mut ids = BTreeSet::new();
    for row in &rows {
        let source = row
            .admission
            .as_ref()
            .map_err(|_| MappingError::Unverified)?;
        if !ids.insert(&row.row.id) || registry::sha256(source.as_bytes()) != row.row.file_sha256 {
            return Err(MappingError::Unverified);
        }
    }
    for (entry, source) in verified.registry.runtimes.iter().zip(&verified.runtimes) {
        if entry.entry_sha256.as_deref() != Some(registry::sha256(source.as_bytes()).as_str())
            || entry.deps.len() != source.dependencies().len()
            || entry.deps.iter().any(|dep| {
                source
                    .dependencies()
                    .get(&dep.path)
                    .is_none_or(|bytes| registry::sha256(bytes.as_bytes()) != dep.sha256)
            })
        {
            return Err(MappingError::Unverified);
        }
    }
    let mut selected: BTreeMap<usize, Vec<&VerifiedRow>> = BTreeMap::new();
    for row in rows {
        let candidates: Vec<_> = verified
            .registry
            .runtimes
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                (entry.entry == row.row.file
                    && entry.entry_sha256.as_deref() == Some(row.row.file_sha256.as_str()))
                    || entry
                        .deps
                        .iter()
                        .any(|dep| dep.path == row.row.file && dep.sha256 == row.row.file_sha256)
            })
            .map(|(index, _)| index)
            .collect();
        let index = match candidates.as_slice() {
            [] => return Err(MappingError::Missing),
            [index] => *index,
            _ => return Err(MappingError::Ambiguous),
        };
        let runtime = &verified.runtimes[index];
        let entry = &verified.registry.runtimes[index];
        if row.row.deps.iter().any(|dep| {
            if dep.path == entry.entry {
                entry.entry_sha256.as_deref() != Some(dep.sha256.as_str())
            } else {
                runtime
                    .dependencies()
                    .get(&dep.path)
                    .is_none_or(|bytes| registry::sha256(bytes.as_bytes()) != dep.sha256)
            }
        }) {
            return Err(MappingError::Closure);
        }
        selected.entry(index).or_default().push(row);
    }
    let mut pools = BTreeSet::new();
    let mut bindings = Vec::new();
    for (runtime_index, rows) in selected {
        let pool = rows[0].row.pool;
        if rows.iter().any(|row| row.row.pool != pool) {
            return Err(MappingError::MixedPool);
        }
        if rows
            .iter()
            .any(|row| row.row.contract.cwd_scope != rows[0].row.contract.cwd_scope)
        {
            return Err(MappingError::MixedCwdScope);
        }
        if !pools.insert(pool) {
            return Err(MappingError::SplitPool);
        }
        bindings.push(RuntimePoolBinding {
            runtime_index,
            pool,
            event,
            row_ids: rows.iter().map(|row| row.row.id.clone()).collect(),
        });
    }
    // Keep declared global order for caller registration validation.
    bindings.sort_by_key(|binding| {
        verified
            .rows
            .iter()
            .find(|row| row.row.id == binding.row_ids[0])
            .unwrap()
            .row
            .order
    });
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{
        pin::Pin,
        registry::tests::{fixture, sealed},
    };
    use serde_json::{json, Value};
    use std::fs;

    pub(crate) fn admitted(
        change: impl FnOnce(&mut Value),
    ) -> (tempfile::TempDir, VerifiedRegistry) {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".claude/hooks")).unwrap();
        let files = [
            ("row-a.js", b"row-a".as_slice()),
            ("row-b.js", b"row-b".as_slice()),
            ("template.js", b"template".as_slice()),
            ("repo.js", b"repo".as_slice()),
            ("extra.js", b"extra".as_slice()),
            ("helper.js", b"helper".as_slice()),
        ];
        for (path, bytes) in files {
            fs::write(temp.path().join(".claude/hooks").join(path), bytes).unwrap();
        }
        let mut registry = fixture(b"row-a");
        let mut a = registry["hooks"][0].clone();
        a["id"] = "row-a".into();
        a["file"] = ".claude/hooks/row-a.js".into();
        a["source"] = "loom-template".into();
        a["pool"] = "template".into();
        let mut b = a.clone();
        b["id"] = "row-b".into();
        b["file"] = ".claude/hooks/row-b.js".into();
        b["file_sha256"] = registry::sha256(b"row-b").into();
        b["order"] = 20.into();
        b["source"] = "repo-local".into();
        b["pool"] = "repo".into();
        registry["hooks"] = json!([a, b]);
        registry["runtimes"] = json!([
            {"entry":".claude/hooks/template.js","entry_sha256":registry::sha256(b"template"),
             "deps":[{"path":".claude/hooks/row-a.js","sha256":registry::sha256(b"row-a")}]},
            {"entry":".claude/hooks/repo.js","entry_sha256":registry::sha256(b"repo"),
             "deps":[{"path":".claude/hooks/row-b.js","sha256":registry::sha256(b"row-b")}]}
        ]);
        change(&mut registry);
        fs::write(
            temp.path().join(crate::gate::pin::MANIFEST_FILE),
            sealed(registry),
        )
        .unwrap();
        let verified = Pin::capture_operator(temp.path())
            .unwrap()
            .verify(temp.path())
            .unwrap();
        (temp, verified)
    }

    #[test]
    fn exact_closures_prove_two_pools_independently_of_entry_position() {
        let (_temp, verified) =
            admitted(|value| value["runtimes"].as_array_mut().unwrap().reverse());
        let bindings = prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude).unwrap();
        // sealed() derives canonical IDs; human fixture labels are not IDs.
        let a_id = verified
            .rows
            .iter()
            .find(|row| row.row.file == ".claude/hooks/row-a.js")
            .unwrap()
            .row
            .id
            .clone();
        let b_id = verified
            .rows
            .iter()
            .find(|row| row.row.file == ".claude/hooks/row-b.js")
            .unwrap()
            .row
            .id
            .clone();
        assert_eq!(
            bindings,
            vec![
                RuntimePoolBinding {
                    runtime_index: 1,
                    pool: Pool::Template,
                    event: Event::PreToolUse,
                    row_ids: vec![a_id]
                },
                RuntimePoolBinding {
                    runtime_index: 0,
                    pool: Pool::Repo,
                    event: Event::PreToolUse,
                    row_ids: vec![b_id]
                },
            ]
        );
    }

    #[test]
    fn ambiguous_membership_is_not_a_positional_pool_assignment() {
        let (_temp, verified) = admitted(|value| {
            let mut extra = value["runtimes"][0].clone();
            extra["entry"] = ".claude/hooks/extra.js".into();
            extra["entry_sha256"] = registry::sha256(b"extra").into();
            value["runtimes"].as_array_mut().unwrap().push(extra);
        });
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::Ambiguous)
        );
    }

    #[test]
    fn a_shared_entry_cannot_silently_run_both_pools() {
        let (_temp, verified) = admitted(|value| {
            let b = value["runtimes"][1]["deps"][0].clone();
            value["runtimes"][0]["deps"].as_array_mut().unwrap().push(b);
            value["runtimes"].as_array_mut().unwrap().truncate(1);
        });
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::MixedPool)
        );
    }

    #[test]
    fn one_pool_cannot_be_split_over_two_process_entries() {
        let (_temp, verified) = admitted(|value| {
            value["hooks"][0]["source"] = "repo-local".into();
            value["hooks"][0]["pool"] = "repo".into();
        });
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::SplitPool)
        );
    }

    #[test]
    fn one_process_cannot_silently_replace_different_row_cwd_scopes() {
        let (_temp, verified) = admitted(|value| {
            value["hooks"][0]["source"] = "repo-local".into();
            value["hooks"][0]["pool"] = "repo".into();
            value["hooks"][1]["contract"]["cwd_scope"] = "process".into();
            let b = value["runtimes"][1]["deps"][0].clone();
            value["runtimes"][0]["deps"].as_array_mut().unwrap().push(b);
            value["runtimes"].as_array_mut().unwrap().truncate(1);
        });
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::MixedCwdScope)
        );
    }

    #[test]
    fn omitted_rows_and_dependency_closure_refuse() {
        let (_temp, verified) = admitted(|value| value["runtimes"][0]["deps"] = json!([]));
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::Missing)
        );
        let (_temp, verified) = admitted(|value| {
            value["hooks"][0]["deps"] =
                json!([{"path":".claude/hooks/helper.js","sha256":registry::sha256(b"helper")}]);
        });
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::Closure)
        );
    }

    #[test]
    fn source_tamper_and_empty_event_do_not_acquire_mapping_authority() {
        let (_temp, mut verified) = admitted(|_| {});
        assert_eq!(
            prove_runtime_pools(&verified, Event::Stop, Surface::Claude),
            Err(MappingError::Empty)
        );
        verified.rows[0].row.file_sha256 = registry::sha256(b"tampered");
        assert_eq!(
            prove_runtime_pools(&verified, Event::PreToolUse, Surface::Claude),
            Err(MappingError::Unverified)
        );
    }

    #[test]
    fn composer_accepts_complete_unique_runtime_registrations() {
        let (_temp, verified) = admitted(|_| {});
        let project = json!({"hooks":{"PreToolUse":[{"hooks":[
            {"type":"command","command":"node .claude/hooks/template.js PreToolUse","timeout":30},
            {"type":"command","command":"node .claude/hooks/repo.js PreToolUse","timeout":30}
        ]}]}});
        assert_eq!(
            crate::gate::settings::compose_registered(&project, &json!({}), true, false, &verified),
            Ok(json!({}))
        );
        let mut missing = project.clone();
        missing["hooks"]["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        assert!(crate::gate::settings::compose_registered(
            &missing,
            &json!({}),
            true,
            false,
            &verified
        )
        .is_err());
        let mut reversed = project;
        reversed["hooks"]["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(crate::gate::settings::compose_registered(
            &reversed,
            &json!({}),
            true,
            false,
            &verified
        )
        .is_err());
    }
}
