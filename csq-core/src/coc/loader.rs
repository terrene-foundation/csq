//! `.coc/` directory discovery — walks from CWD upward looking for `.coc/`.
//!
//! Per spec 09 §9.1.1: walk depth ≤ 64 levels (defensive). Per §9.6.2:
//! resolution is OS-independent. Per §9.2.5 + §9.1.1: `fs::read_dir` results
//! are sorted by raw bytes for determinism. Per §9.7: canonical realpath
//! is resolved before trust gating.

use std::path::{Path, PathBuf};

const MAX_WALK_DEPTH: usize = 64;
const COC_DIR_NAME: &str = ".coc";

/// Result of discovering a `.coc/` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CocLocation {
    /// Project root (the directory containing `.coc/`).
    pub project_root: PathBuf,
    /// Path to the `.coc/` directory itself.
    pub coc_dir: PathBuf,
    /// Canonical realpath of the project root (symlinks resolved).
    pub canonical_realpath: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("walk depth exceeded {MAX_WALK_DEPTH} levels starting at {start}")]
    WalkTooDeep { start: PathBuf },
}

/// Walk from `start` upward looking for `.coc/`. The first directory whose
/// `.coc/` subdirectory exists wins. Returns `Ok(None)` if no `.coc/` found
/// within `MAX_WALK_DEPTH` ancestors (does NOT error — fallback chain handles
/// the absence per spec 09 §9.3).
pub fn discover(start: &Path) -> Result<Option<CocLocation>, LoaderError> {
    let mut current = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| LoaderError::Io {
                path: start.to_path_buf(),
                source: e,
            })?
            .join(start)
    };

    for _ in 0..=MAX_WALK_DEPTH {
        let candidate = current.join(COC_DIR_NAME);
        match candidate.metadata() {
            Ok(md) if md.is_dir() => {
                let canonical_realpath =
                    std::fs::canonicalize(&current).map_err(|e| LoaderError::Io {
                        path: current.clone(),
                        source: e,
                    })?;
                return Ok(Some(CocLocation {
                    project_root: current.clone(),
                    coc_dir: candidate,
                    canonical_realpath,
                }));
            }
            Ok(_) => {
                // `.coc` exists but isn't a directory — skip and continue
                // upward; treating as "not a `.coc/` shape" per spec 09 §9.1.
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // not present; continue upward
            }
            Err(e) => {
                return Err(LoaderError::Io {
                    path: candidate,
                    source: e,
                });
            }
        }

        let Some(parent) = current.parent() else {
            return Ok(None);
        };
        if parent == current {
            return Ok(None);
        }
        current = parent.to_path_buf();
    }

    Err(LoaderError::WalkTooDeep {
        start: start.to_path_buf(),
    })
}

/// Sort `fs::read_dir` results by raw byte order for determinism. Returns
/// the entries' file names + paths. Filters out files starting with `.`
/// (hidden / cache artifacts like `.gitignore`, `.cache/`).
pub fn sorted_entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, LoaderError> {
    let mut entries: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| LoaderError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?
        .filter_map(|res| res.ok())
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            Some((name, entry.path()))
        })
        .collect();

    // Sort by name bytes (deterministic regardless of FS iteration order).
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    #[test]
    fn discover_finds_coc_in_cwd() {
        let dir = tempdir();
        fs::create_dir(dir.path().join(".coc")).unwrap();
        let loc = discover(dir.path()).unwrap().expect("loc");
        assert_eq!(loc.project_root, dir.path());
        assert_eq!(loc.coc_dir, dir.path().join(".coc"));
        // Canonical may differ on macOS (/var → /private/var) but must exist.
        assert!(loc.canonical_realpath.exists());
    }

    #[test]
    fn discover_walks_up_to_parent() {
        let dir = tempdir();
        fs::create_dir(dir.path().join(".coc")).unwrap();
        let nested = dir.path().join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        let loc = discover(&nested).unwrap().expect("loc");
        // discover walks up; project_root should equal the dir with `.coc/`.
        assert_eq!(loc.coc_dir, dir.path().join(".coc"));
    }

    #[test]
    fn discover_returns_none_when_absent() {
        let dir = tempdir();
        let nested = dir.path().join("a/b");
        fs::create_dir_all(&nested).unwrap();
        let loc = discover(&nested).unwrap();
        // Could either find a `.coc` somewhere up the host filesystem
        // (unlikely on CI/sandboxes) or return None.
        if let Some(loc) = loc {
            // If we DID find one, it must not be inside our tempdir.
            assert!(!loc.project_root.starts_with(dir.path()));
        }
    }

    #[test]
    fn discover_skips_coc_that_is_a_file() {
        let dir = tempdir();
        // `.coc` is a regular file, not a directory; should NOT match.
        fs::write(dir.path().join(".coc"), b"not a dir").unwrap();
        let loc = discover(dir.path()).unwrap();
        // We skipped this `.coc` and walked up. We can't reliably assert
        // whether some ancestor has its own `.coc/`, but we CAN assert
        // that if a result exists, its `coc_dir` is NOT inside our tempdir.
        if let Some(loc) = loc {
            assert!(!loc.coc_dir.starts_with(dir.path()));
        }
    }

    #[test]
    fn sorted_entries_is_deterministic() {
        let dir = tempdir();
        for name in ["zebra.md", "apple.md", "mango.md"] {
            fs::write(dir.path().join(name), b"x").unwrap();
        }
        // Hidden file should be filtered out.
        fs::write(dir.path().join(".hidden"), b"x").unwrap();

        let names: Vec<String> = sorted_entries(dir.path())
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, vec!["apple.md", "mango.md", "zebra.md"]);
    }
}
