//! Owned launch configuration that can cross an atomic native-spawn boundary.
//!
//! Unlike `Command`, this retains explicit stdio and environment-inheritance
//! policy. Values intentionally have no `Debug` implementation: arguments and
//! environment overrides may contain sensitive data.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Standard streams are inherited unless explicitly configured otherwise.
pub enum LaunchStdio {
    Inherit,
    Null,
    Piped,
    File(File),
}

impl LaunchStdio {
    pub fn inherit() -> Self {
        Self::Inherit
    }
    pub fn null() -> Self {
        Self::Null
    }
    pub fn piped() -> Self {
        Self::Piped
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(match self {
            Self::Inherit => Self::Inherit,
            Self::Null => Self::Null,
            Self::Piped => Self::Piped,
            Self::File(file) => Self::File(file.try_clone()?),
        })
    }

    fn into_stdio(self) -> Stdio {
        match self {
            Self::Inherit => Stdio::inherit(),
            Self::Null => Stdio::null(),
            Self::Piped => Stdio::piped(),
            Self::File(file) => Stdio::from(file),
        }
    }
}

impl From<File> for LaunchStdio {
    fn from(file: File) -> Self {
        Self::File(file)
    }
}

/// Raw arguments preserve the caller's Windows-specific quoting intent.
pub enum LaunchArg {
    Regular(OsString),
    Raw(OsString),
}

impl LaunchArg {
    pub fn as_os_str(&self) -> &OsStr {
        match self {
            Self::Regular(value) | Self::Raw(value) => value,
        }
    }

    fn duplicate(&self) -> Self {
        match self {
            Self::Regular(value) => Self::Regular(value.clone()),
            Self::Raw(value) => Self::Raw(value.clone()),
        }
    }
}

/// A complete owned configuration. Environment changes are applied in order;
/// a later override/removal of the same key takes precedence.
pub struct LaunchParts {
    pub program: OsString,
    pub args: Vec<LaunchArg>,
    pub inherit_env: bool,
    pub env_changes: Vec<(OsString, Option<OsString>)>,
    pub current_dir: Option<PathBuf>,
    pub stdin: LaunchStdio,
    pub stdout: LaunchStdio,
    pub stderr: LaunchStdio,
}

/// Process-independent builder; constructing a plan never starts a process.
pub struct LaunchPlan {
    parts: LaunchParts,
}

impl LaunchPlan {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            parts: LaunchParts {
                program: program.as_ref().to_owned(),
                args: Vec::new(),
                inherit_env: true,
                env_changes: Vec::new(),
                current_dir: None,
                stdin: LaunchStdio::Inherit,
                stdout: LaunchStdio::Inherit,
                stderr: LaunchStdio::Inherit,
            },
        }
    }

    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.parts
            .args
            .push(LaunchArg::Regular(arg.as_ref().to_owned()));
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub fn raw_arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.parts
            .args
            .push(LaunchArg::Raw(arg.as_ref().to_owned()));
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.parts
            .env_changes
            .push((key.as_ref().to_owned(), Some(value.as_ref().to_owned())));
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (key, value) in vars {
            self.env(key, value);
        }
        self
    }

    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.parts.env_changes.push((key.as_ref().to_owned(), None));
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.parts.inherit_env = false;
        self.parts.env_changes.clear();
        self
    }

    pub fn current_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.parts.current_dir = Some(dir.as_ref().to_owned());
        self
    }

    pub fn stdin(&mut self, stdio: impl Into<LaunchStdio>) -> &mut Self {
        self.parts.stdin = stdio.into();
        self
    }

    pub fn stdout(&mut self, stdio: impl Into<LaunchStdio>) -> &mut Self {
        self.parts.stdout = stdio.into();
        self
    }

    pub fn stderr(&mut self, stdio: impl Into<LaunchStdio>) -> &mut Self {
        self.parts.stderr = stdio.into();
        self
    }

    pub fn get_program(&self) -> &OsStr {
        &self.parts.program
    }
    pub fn get_args(&self) -> impl Iterator<Item = &OsStr> {
        self.parts.args.iter().map(LaunchArg::as_os_str)
    }
    /// Ordered changes, including repeated keys and explicit removals.
    pub fn get_envs(&self) -> impl Iterator<Item = (&OsStr, Option<&OsStr>)> {
        self.parts
            .env_changes
            .iter()
            .map(|(key, value)| (key.as_os_str(), value.as_deref()))
    }
    pub fn get_current_dir(&self) -> Option<&Path> {
        self.parts.current_dir.as_deref()
    }
    pub fn inherits_env(&self) -> bool {
        self.parts.inherit_env
    }

    /// Duplicate only owned resources; never infer policy from a `Command`.
    pub fn build_for_spawn(&self) -> io::Result<LaunchParts> {
        Ok(LaunchParts {
            program: self.parts.program.clone(),
            args: self.parts.args.iter().map(LaunchArg::duplicate).collect(),
            inherit_env: self.parts.inherit_env,
            env_changes: self.parts.env_changes.clone(),
            current_dir: self.parts.current_dir.clone(),
            stdin: self.parts.stdin.try_clone()?,
            stdout: self.parts.stdout.try_clone()?,
            stderr: self.parts.stderr.try_clone()?,
        })
    }

    pub fn into_parts(self) -> LaunchParts {
        self.parts
    }

    /// Compatibility bridge for existing callers using standard spawning.
    /// A Windows raw argument has no portable interpretation on Unix.
    pub fn into_std_command(self) -> io::Result<Command> {
        let parts = self.parts;
        let mut command = Command::new(parts.program);
        for arg in parts.args {
            match arg {
                LaunchArg::Regular(value) => {
                    command.arg(value);
                }
                LaunchArg::Raw(value) => {
                    #[cfg(windows)]
                    {
                        use std::os::windows::process::CommandExt;
                        command.raw_arg(value);
                    }
                    #[cfg(not(windows))]
                    {
                        let _ = value;
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "launch_raw_argument_requires_windows",
                        ));
                    }
                }
            }
        }
        if !parts.inherit_env {
            command.env_clear();
        }
        for (key, value) in parts.env_changes {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        if let Some(dir) = parts.current_dir {
            command.current_dir(dir);
        }
        command
            .stdin(parts.stdin.into_stdio())
            .stdout(parts.stdout.into_stdio())
            .stderr(parts.stderr.into_stdio());
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn conversion_preserves_literal_arguments_environment_and_directory() {
        let mut plan = LaunchPlan::new("inert-executable");
        plan.args(["", "space here", "quote\"here", "trailing\\"])
            .env("BEFORE_CLEAR", "discarded")
            .env_clear()
            .envs([("OVERRIDE", "first"), ("OVERRIDE", "last")])
            .env_remove("REMOVED")
            .current_dir("isolated-directory")
            .stdin(LaunchStdio::null())
            .stdout(LaunchStdio::piped());
        assert!(!plan.inherits_env());
        let parts = plan.build_for_spawn().unwrap();
        assert!(!parts.inherit_env);
        assert!(matches!(parts.stdin, LaunchStdio::Null));
        assert!(matches!(parts.stdout, LaunchStdio::Piped));
        assert!(matches!(parts.stderr, LaunchStdio::Inherit));
        let command = plan.into_std_command().unwrap();
        assert_eq!(command.get_program(), "inert-executable");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["", "space here", "quote\"here", "trailing\\"]
        );
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new("isolated-directory"))
        );
        let env = command.get_envs().collect::<Vec<_>>();
        assert!(env.contains(&(OsStr::new("OVERRIDE"), Some(OsStr::new("last")))));
        assert!(!env.iter().any(|(key, _)| *key == "BEFORE_CLEAR"));
        // With env_clear, removing an absent key produces no override in std.
        assert!(!env.iter().any(|(key, _)| *key == "REMOVED"));
    }

    #[test]
    fn default_stream_and_environment_policy_is_explicit() {
        let parts = LaunchPlan::new("inert-executable").into_parts();
        assert!(parts.inherit_env);
        assert!(matches!(parts.stdin, LaunchStdio::Inherit));
        assert!(matches!(parts.stdout, LaunchStdio::Inherit));
        assert!(matches!(parts.stderr, LaunchStdio::Inherit));
    }

    #[test]
    fn repeated_snapshots_retain_file_ownership_after_builder_drop() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"fixture-bytes").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut plan = LaunchPlan::new("inert-executable");
        plan.stdin(file);
        let first = plan.build_for_spawn().unwrap();
        let second = plan.build_for_spawn().unwrap();
        drop(plan);
        drop(first);
        let LaunchStdio::File(mut retained) = second.stdin else {
            panic!("owned file missing")
        };
        let mut bytes = Vec::new();
        retained.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"fixture-bytes");
    }

    #[test]
    fn snapshots_preserve_regular_and_raw_argument_distinction() {
        let mut plan = LaunchPlan::new("inert-executable");
        plan.arg("literal").raw_arg("raw quoted fragment");
        let parts = plan.build_for_spawn().unwrap();
        assert!(matches!(&parts.args[0], LaunchArg::Regular(value) if value == "literal"));
        assert!(matches!(&parts.args[1], LaunchArg::Raw(value) if value == "raw quoted fragment"));
    }

    #[cfg(not(windows))]
    #[test]
    fn raw_windows_argument_refuses_portable_conversion() {
        let mut plan = LaunchPlan::new("inert-executable");
        plan.raw_arg("raw fragment");
        match plan.into_std_command() {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("raw Windows argument was reinterpreted"),
        }
    }
}
