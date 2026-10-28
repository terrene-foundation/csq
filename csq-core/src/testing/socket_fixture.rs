//! Test-only Unix socket fixtures with a bounded kernel pathname.
//!
//! Test state stays in the ordinary `tempfile` root (`TMPDIR`), which on CI is
//! the runner-managed private job directory. Only a socket — or, where the
//! fixture owns no long-lived state, the whole test root — gets a separate,
//! short `/tmp` directory: Unix pathname sockets have a small fixed address
//! limit (`sun_path` is 104 bytes on macOS, 108 on Linux), so nesting them
//! below an arbitrarily deep `TMPDIR` is not portable.
//!
//! Every fixture in this repository that binds a Unix socket MUST obtain its
//! root here. An ad-hoc `TempDir::new()` at a bind site is exactly the class
//! that reds under a deep runner `TMPDIR`; `short_root` is the one source of
//! truth that keeps the kernel pathname bounded regardless of the ambient
//! environment.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::{Builder, TempDir};

/// A private, collision-resistant test root under the fixed short `/tmp`.
///
/// Use this for any fixture that binds a Unix socket, or whose path is fed to
/// code that binds or connects to one. The directory is mode 0700 regardless of
/// the process umask; state that never reaches a socket may stay in the
/// ordinary `TempDir::new()` root under `TMPDIR`.
pub fn short_root(prefix: &str) -> io::Result<TempDir> {
    // The prefix becomes one path component under the fixed root. A
    // separator or a parent component would let a caller escape `/tmp`
    // (or name a directory outside this fixture's ownership), so reject
    // both before the Builder ever sees the prefix. `debug_assert!` is not
    // enough: release-mode test binaries would compile it out.
    if prefix.contains('/') || prefix.contains("..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "short_root prefix must not contain '/' or '..'",
        ));
    }
    // Fixed `/tmp` is deliberate and socket-only. `Builder` creates a
    // collision-resistant owned directory, and `.permissions` pins the mode
    // AT CREATION so it holds even if a later step fails before the chmod.
    let dir = Builder::new()
        .prefix(prefix)
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    // Belt and braces: re-assert the mode after creation so the contract
    // does not depend on the Builder implementation.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

pub struct UnixSocketPath {
    socket_dir: TempDir,
}

impl UnixSocketPath {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            socket_dir: short_root("csq-s-")?,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.socket_dir.path().join("s")
    }
}

pub struct UnixSocketFixture {
    state_dir: TempDir,
    socket: UnixSocketPath,
}

impl UnixSocketFixture {
    pub fn new() -> io::Result<Self> {
        Self::with_state_dir(TempDir::new()?)
    }

    /// A fixture whose state lives under `state_parent` (which may be deep)
    /// while its socket still gets the short `/tmp` root.
    pub fn new_in(state_parent: &Path) -> io::Result<Self> {
        Self::with_state_dir(TempDir::new_in(state_parent)?)
    }

    fn with_state_dir(state_dir: TempDir) -> io::Result<Self> {
        Ok(Self {
            state_dir,
            socket: UnixSocketPath::new()?,
        })
    }

    pub fn path(&self) -> &Path {
        self.state_dir.path()
    }

    pub fn socket_path(&self) -> PathBuf {
        self.socket.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn socket_remains_bindable_with_an_overlong_state_root_and_cleans_up() {
        let outer = TempDir::new().unwrap();
        let long_state_parent = outer.path().join("x".repeat(160));
        fs::create_dir_all(&long_state_parent).unwrap();

        let fixture = UnixSocketFixture::new_in(&long_state_parent).unwrap();
        assert!(fixture.path().starts_with(&long_state_parent));

        let direct_socket = fixture.path().join("s");
        let direct_error = UnixListener::bind(&direct_socket).unwrap_err();
        assert_eq!(
            direct_error.kind(),
            io::ErrorKind::InvalidInput,
            "the forced-long state path must reproduce the Unix socket limit"
        );

        let state_file = fixture.path().join("state-remains-in-runner-temp");
        fs::File::create(&state_file)
            .unwrap()
            .write_all(b"state")
            .unwrap();
        assert!(state_file.exists());

        let socket_path = fixture.socket_path();
        assert!(socket_path.starts_with("/tmp"));
        let socket_parent = socket_path.parent().unwrap().to_path_buf();
        let socket_metadata = fs::metadata(&socket_parent).unwrap();
        let mode = socket_metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "socket fixture directory must be private");
        assert_eq!(
            socket_metadata.uid(),
            fs::metadata(fixture.path()).unwrap().uid(),
            "state and socket fixture directories must share an owner"
        );

        let listener = UnixListener::bind(&socket_path).unwrap();
        let client = UnixStream::connect(&socket_path).unwrap();
        drop(client);
        drop(listener);

        let state_dir = fixture.path().to_path_buf();
        drop(fixture);
        assert!(!state_dir.exists(), "state TempDir must clean up on drop");
        assert!(
            !socket_parent.exists(),
            "socket-only TempDir must clean up on drop"
        );
    }

    /// The shared root itself is short, private, and cleans up — every
    /// socket-binding fixture in the repository depends on all three.
    #[test]
    fn short_root_is_bindable_private_and_cleans_up() {
        let root = short_root("csq-short-root-test-").unwrap();
        let socket = root.path().join("s");
        assert!(
            socket.as_os_str().len() < 104,
            "short root must leave room for a socket name: {} bytes",
            socket.as_os_str().len()
        );
        let mode = fs::metadata(root.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        drop(client);
        drop(listener);
        let root_path = root.path().to_path_buf();
        drop(root);
        assert!(!root_path.exists());
    }

    /// A prefix is one path component: separators and parent components are
    /// rejected with an error (never a debug-only assertion), and an ordinary
    /// prefix is accepted with the mode pinned at creation.
    #[test]
    fn short_root_rejects_path_separators_and_parent_components() {
        for bad in ["a/b", "..", "../x", "a..b"] {
            let error = short_root(bad).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{bad}: {error}");
        }
        let accepted = short_root("csq-accepted-").unwrap();
        assert!(accepted.path().starts_with("/tmp"));
        let mode = fs::metadata(accepted.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "short_root pins 0700 at creation via Builder::permissions"
        );
    }
}
