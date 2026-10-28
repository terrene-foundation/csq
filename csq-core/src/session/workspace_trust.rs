//! Conservative native Claude 2.1.292 workspace-key resolution.
//! No trust is created here. Unsupported path aliases are an explicit refusal.
use serde_json::{Map, Value};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

const MAX_GIT_METADATA: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("native workspace key cannot be resolved safely")]
    UnsafePath,
    #[error("native workspace key uses an unsupported alias")]
    UnsupportedAlias,
    #[error("native workspace key is not Unicode")]
    NonUnicode,
}

/// Resolve the exact persisted key for supported local filesystem layouts.
/// Valid worktrees require both common-dir topology and the native backlink.
/// A gitdir pointer alone never grants the pointed-to repository's trust.
pub fn native_key(cwd: &Path) -> Result<String, TrustError> {
    if cfg!(windows) {
        return Err(TrustError::UnsupportedAlias);
    }
    let cwd = normalize(cwd)?;
    reject_aliases(&cwd)?;
    let mut root = cwd.clone();
    for candidate in cwd.ancestors() {
        let entry = candidate.join(".git");
        match fs::symlink_metadata(&entry) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(TrustError::UnsupportedAlias);
                }
                if meta.is_dir() {
                    root = candidate.to_owned();
                    break;
                }
                if meta.is_file() {
                    root = worktree_root(candidate, &entry)?;
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(TrustError::UnsafePath),
        }
    }
    let text = root.to_str().ok_or(TrustError::NonUnicode)?;
    Ok(text.nfc().collect())
}

fn normalize(path: &Path) -> Result<PathBuf, TrustError> {
    reject_prefix(path)?;
    if !path.is_absolute() {
        return Err(TrustError::UnsafePath);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn reject_aliases(path: &Path) -> Result<(), TrustError> {
    reject_prefix(path)?;
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component);
        if fs::symlink_metadata(&cursor)
            .map_err(|_| TrustError::UnsafePath)?
            .file_type()
            .is_symlink()
        {
            return Err(TrustError::UnsupportedAlias);
        }
    }
    Ok(())
}

fn reject_prefix(path: &Path) -> Result<(), TrustError> {
    let text = path.to_str().ok_or(TrustError::NonUnicode)?;
    let lower = text.to_ascii_lowercase();
    let forbidden = [
        "/network",
        "/net",
        "/.vol",
        "/.file",
        "/.nofollow",
        "/.resolve",
    ];
    if text.starts_with("//")
        || text.starts_with("\\\\")
        || text.chars().any(|c| matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}'))
        || forbidden.iter().any(|prefix| Path::new(&lower).starts_with(prefix))
        || (cfg!(target_os = "macos") && Path::new(&lower).starts_with("/home"))
    {
        return Err(TrustError::UnsupportedAlias);
    }
    Ok(())
}

fn read_small(path: &Path) -> Result<String, TrustError> {
    reject_aliases(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file: File = options.open(path).map_err(|_| TrustError::UnsafePath)?;
    if !file
        .metadata()
        .map_err(|_| TrustError::UnsafePath)?
        .is_file()
    {
        return Err(TrustError::UnsafePath);
    }
    let mut bytes = Vec::new();
    file.take(MAX_GIT_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TrustError::UnsafePath)?;
    if bytes.len() as u64 > MAX_GIT_METADATA {
        return Err(TrustError::UnsafePath);
    }
    String::from_utf8(bytes).map_err(|_| TrustError::NonUnicode)
}

fn pointer(base: &Path, value: &str) -> Result<PathBuf, TrustError> {
    let value = value.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(TrustError::UnsafePath);
    }
    let path = Path::new(value);
    normalize(&if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    })
}

fn worktree_root(found: &Path, entry: &Path) -> Result<PathBuf, TrustError> {
    let text = read_small(entry)?;
    let Some(value) = text.trim().strip_prefix("gitdir:") else {
        return Ok(found.to_owned());
    };
    let gitdir = pointer(found, value)?;
    // Native falls back to the found working root for invalid topology. We
    // refuse unsupported aliases rather than adopting a foreign root.
    reject_aliases(&gitdir)?;
    let Ok(common) = read_small(&gitdir.join("commondir")) else {
        return Ok(found.to_owned());
    };
    let common = pointer(&gitdir, &common)?;
    reject_aliases(&common)?;
    if gitdir.parent() != Some(common.join("worktrees").as_path()) {
        return Ok(found.to_owned());
    }
    let Ok(backlink) = read_small(&gitdir.join("gitdir")) else {
        return Ok(found.to_owned());
    };
    if pointer(&gitdir, &backlink)? != entry {
        return Ok(found.to_owned());
    }
    if common.file_name().is_some_and(|name| name == ".git") {
        return common
            .parent()
            .map(Path::to_owned)
            .ok_or(TrustError::UnsafePath);
    }
    // Native's separate common-dir fallback has additional filesystem admission
    // semantics. It is unsupported until those can be matched explicitly.
    Err(TrustError::UnsupportedAlias)
}

/// Preserve the native workspace state that is meaningful outside the CWD
/// scope. Resume/session metadata and unknown project fields stay excluded, so
/// unrelated state cannot leak into a subdirectory session. A session-written
/// value (including `false` or an empty list) overrides the source snapshot.
pub(crate) fn preserve_exact_workspace_state(
    scoped: &mut Map<String, Value>,
    projects: &Map<String, Value>,
    key: &str,
) {
    if scoped.contains_key(key) {
        return;
    }
    let Some(source) = projects.get(key).and_then(Value::as_object) else {
        return;
    };
    let mut entry = Map::new();
    if let Some(flag) = source
        .get("hasTrustDialogAccepted")
        .and_then(Value::as_bool)
    {
        entry.insert("hasTrustDialogAccepted".into(), Value::Bool(flag));
    }
    for field in ["disabledMcpServers", "enabledMcpServers"] {
        if let Some(values) = source.get(field).and_then(Value::as_array) {
            if values.iter().all(Value::is_string) {
                entry.insert(field.into(), Value::Array(values.clone()));
            }
        }
    }
    if !entry.is_empty() {
        scoped.insert(key.into(), Value::Object(entry));
    }
}

#[cfg(test)]
pub(crate) fn preserve_exact_flag(
    scoped: &mut Map<String, Value>,
    projects: &Map<String, Value>,
    key: &str,
) {
    preserve_exact_workspace_state(scoped, projects, key);
}

#[cfg(test)]
#[path = "workspace_trust_tests.rs"]
mod tests;
