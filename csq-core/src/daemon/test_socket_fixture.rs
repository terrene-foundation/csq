//! Test-only Unix socket fixture with a bounded kernel pathname.
//!
//! Test state stays in the ordinary `tempfile` root (`TMPDIR`), which on CI is
//! the runner-managed private job directory. Only the socket gets a separate,
//! short `/tmp` directory: Unix pathname sockets have a small fixed address
//! limit, so nesting them below an arbitrarily deep `TMPDIR` is not portable.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::{Builder, TempDir};

pub(super) struct UnixSocketPath {
    socket_dir: TempDir,
}

impl UnixSocketPath {
    pub(super) fn new() -> io::Result<Self> {
        // Fixed `/tmp` is deliberate and socket-only. `Builder` creates a
        // collision-resistant owned directory; the explicit mode makes the
        // privacy requirement independent of the process umask.
        let socket_dir = Builder::new().prefix("csq-s-").tempdir_in("/tmp")?;
        fs::set_permissions(socket_dir.path(), fs::Permissions::from_mode(0o700))?;
        Ok(Self { socket_dir })
    }

    pub(super) fn path(&self) -> PathBuf {
        self.socket_dir.path().join("s")
    }
}

pub(super) struct UnixSocketFixture {
    state_dir: TempDir,
    socket: UnixSocketPath,
}

impl UnixSocketFixture {
    pub(super) fn new() -> io::Result<Self> {
        Self::with_state_dir(TempDir::new()?)
    }

    fn new_in(state_parent: &Path) -> io::Result<Self> {
        Self::with_state_dir(TempDir::new_in(state_parent)?)
    }

    fn with_state_dir(state_dir: TempDir) -> io::Result<Self> {
        Ok(Self {
            state_dir,
            socket: UnixSocketPath::new()?,
        })
    }

    pub(super) fn path(&self) -> &Path {
        self.state_dir.path()
    }

    pub(super) fn socket_path(&self) -> PathBuf {
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
}
