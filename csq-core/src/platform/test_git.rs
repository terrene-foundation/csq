//! Hermetic Git commands for temporary test repositories.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Build a Git command rooted in a temporary repository and caller-owned home.
/// The caller keeps the sandbox alive until the child has exited and holds
/// `test_env::lock()` when ambient PATH may be changed by sibling tests.
pub fn command(repo: &Path, home: &Path) -> io::Result<Command> {
    command_with_program("git", repo, home)
}

/// As `command`, with an explicit executable for fixtures using a fake PATH.
pub fn command_with_program(
    program: impl AsRef<OsStr>,
    repo: &Path,
    home: &Path,
) -> io::Result<Command> {
    let mut command = Command::new(program);
    sanitize(&mut command, repo, home)?;
    Ok(command)
}

// Git for Windows expects ordinary drive/UNC paths rather than the verbatim
// prefixes returned by std::fs::canonicalize. Preserve non-Unicode path units.
fn git_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        let verbatim: Vec<u16> = "\\\\?\\".encode_utf16().collect();
        if wide.starts_with(&verbatim) {
            let unc: Vec<u16> = "UNC\\".encode_utf16().collect();
            let ordinary = if wide[4..].starts_with(&unc) {
                let mut ordinary: Vec<u16> = "\\\\".encode_utf16().collect();
                ordinary.extend_from_slice(&wide[8..]);
                ordinary
            } else {
                wide[4..].to_vec()
            };
            return PathBuf::from(OsString::from_wide(&ordinary));
        }
    }
    path
}

// The constructor and hostile-command test seam share this exact sanitizer.
fn sanitize(command: &mut Command, repo: &Path, home: &Path) -> io::Result<()> {
    let repo = git_path(repo.canonicalize()?);
    let ceiling = repo.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "test Git repository needs a parent ceiling",
        )
    })?;
    let list_separator = if cfg!(windows) { b';' } else { b':' };
    if ceiling
        .as_os_str()
        .as_encoded_bytes()
        .contains(&list_separator)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test Git ceiling contains the platform path-list separator",
        ));
    }
    let hooks = home.join("no-hooks");
    let templates = home.join("no-template");
    for path in [&hooks, &templates] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test Git hook/template directory must remain absent",
                ))
            }
        }
    }
    let mut hooks_arg = OsString::from("core.hooksPath=");
    hooks_arg.push(&hooks);
    let config = home.join("empty-gitconfig");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config)
    {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&config)?;
            if !metadata.is_file() || metadata.len() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test Git config must be an empty regular file",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    // Clear the entire inherited environment, including every present or future
    // GIT_* repository locator, config override, hook/template and credential knob.
    command.env_clear();
    for key in [
        "PATH",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .current_dir(&repo)
        .env("GIT_CEILING_DIRECTORIES", ceiling)
        .env("GIT_TEMPLATE_DIR", templates)
        .env("TMPDIR", home)
        .env("TMP", home)
        .env("TEMP", home)
        .env("APPDATA", home)
        .env("LOCALAPPDATA", home)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", config)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .arg("-c")
        .arg(hooks_arg)
        .args(["-c", "core.fsmonitor=false"]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
        command(repo, home)
            .unwrap()
            .args(args)
            .output()
            .expect("Git is required")
    }

    // Inject only into the Command before the real sanitizer. No malicious
    // process-wide environment can race sibling production Git readers.
    fn injected(repo: &Path, home: &Path, key: &str, value: &OsStr) -> Command {
        let mut child = Command::new("git");
        child.env(key, value);
        sanitize(&mut child, repo, home).unwrap();
        let expected = [
            (
                "GIT_CEILING_DIRECTORIES",
                git_path(repo.canonicalize().unwrap())
                    .parent()
                    .unwrap()
                    .as_os_str()
                    .to_owned(),
            ),
            (
                "GIT_CONFIG_GLOBAL",
                home.join("empty-gitconfig").into_os_string(),
            ),
            ("GIT_CONFIG_NOSYSTEM", "1".into()),
            (
                "GIT_TEMPLATE_DIR",
                home.join("no-template").into_os_string(),
            ),
            ("GIT_AUTHOR_NAME", "test".into()),
            ("GIT_AUTHOR_EMAIL", "test@example.invalid".into()),
            ("GIT_COMMITTER_NAME", "test".into()),
            ("GIT_COMMITTER_EMAIL", "test@example.invalid".into()),
        ];
        let actual: Vec<_> = child
            .get_envs()
            .filter(|(key, _)| key.to_string_lossy().starts_with("GIT_"))
            .collect();
        assert_eq!(actual.len(), expected.len());
        for (key, value) in actual {
            assert!(
                expected
                    .iter()
                    .any(|(name, pinned)| key == OsStr::new(name)
                        && value == Some(pinned.as_os_str())),
                "unapproved Git variable: {key:?}={value:?}"
            );
        }
        child
    }

    fn rejects_variable(key: &str) {
        let _env = crate::platform::test_env::lock();
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let output = injected(repo.path(), home.path(), key, OsStr::new("hostile"))
            .args(["config", "--get", "test.inherited"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{key}: {output:?}");
        assert!(output.stdout.is_empty());
    }

    macro_rules! scrub_tests {
        ($($name:ident => $key:literal),+ $(,)?) => {$(
            #[test]
            fn $name() { rejects_variable($key); }
        )+};
    }
    scrub_tests! {
        scrubs_git_dir => "GIT_DIR",
        scrubs_git_work_tree => "GIT_WORK_TREE",
        scrubs_git_index_file => "GIT_INDEX_FILE",
        scrubs_git_object_directory => "GIT_OBJECT_DIRECTORY",
        scrubs_git_alternate_object_directories => "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        scrubs_git_common_dir => "GIT_COMMON_DIR",
        scrubs_git_namespace => "GIT_NAMESPACE",
        scrubs_git_ceiling_directories => "GIT_CEILING_DIRECTORIES",
        scrubs_git_config => "GIT_CONFIG",
        scrubs_git_config_global => "GIT_CONFIG_GLOBAL",
        scrubs_git_config_system => "GIT_CONFIG_SYSTEM",
        scrubs_git_config_nosystem => "GIT_CONFIG_NOSYSTEM",
        scrubs_git_config_count => "GIT_CONFIG_COUNT",
        scrubs_git_config_parameters => "GIT_CONFIG_PARAMETERS",
        scrubs_git_future_config => "GIT_CONFIG_FUTURE_UNKNOWN",
        scrubs_git_config_key => "GIT_CONFIG_KEY_0",
        scrubs_git_config_value => "GIT_CONFIG_VALUE_0",
        scrubs_git_prefix => "GIT_PREFIX",
        scrubs_git_template_dir => "GIT_TEMPLATE_DIR",
        scrubs_git_exec_path => "GIT_EXEC_PATH",
        scrubs_git_future_variable => "GIT_FUTURE_UNKNOWN_OVERRIDE",
    }

    #[test]
    fn hostile_repository_environment_cannot_redirect_init_or_commit() {
        let _env = crate::platform::test_env::lock();
        let temp = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let decoy = temp.path().join("decoy");
        std::fs::create_dir(&decoy).unwrap();
        assert!(git(&decoy, home.path(), &["init", "--initial-branch=main"])
            .status
            .success());
        assert!(git(
            &decoy,
            home.path(),
            &["commit", "--allow-empty", "-m", "decoy"]
        )
        .status
        .success());
        let identity = || {
            ["HEAD", "refs/heads/main", "config"]
                .map(|name| std::fs::read(decoy.join(".git").join(name)).unwrap())
        };
        let before = identity();
        for (key, value) in [
            ("GIT_DIR", decoy.join(".git")),
            ("GIT_WORK_TREE", decoy.clone()),
        ] {
            let target = temp.path().join(key);
            std::fs::create_dir(&target).unwrap();
            let init = injected(&target, home.path(), key, value.as_os_str())
                .args(["init", "--initial-branch=main"])
                .output()
                .unwrap();
            let commit = injected(&target, home.path(), key, value.as_os_str())
                .args(["commit", "--allow-empty", "-m", "target"])
                .output()
                .unwrap();
            assert_eq!(identity(), before, "decoy changed for {key}");
            assert!(init.status.success(), "{init:?}");
            assert!(commit.status.success(), "{commit:?}");
            assert!(target.join(".git/refs/heads/main").is_file());
            assert_eq!(
                git(&target, home.path(), &["log", "-1", "--format=%s"]).stdout,
                b"target\n"
            );
        }
    }

    #[test]
    fn nested_cwd_in_declared_repository_still_resolves() {
        let _env = crate::platform::test_env::lock();
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(git(repo.path(), home.path(), &["init"]).status.success());
        let nested = repo.path().join("nested/deeper");
        std::fs::create_dir_all(&nested).unwrap();
        let output = command(repo.path(), home.path())
            .unwrap()
            .current_dir(nested)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            Path::new(std::str::from_utf8(&output.stdout).unwrap().trim())
                .canonicalize()
                .unwrap(),
            repo.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn filesystem_root_has_no_safe_parent_ceiling() {
        let _env = crate::platform::test_env::lock();
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let canonical = repo.path().canonicalize().unwrap();
        let root = canonical.ancestors().last().unwrap();
        assert_eq!(
            command(root, home.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn ceiling_with_platform_list_separator_is_rejected() {
        let _env = crate::platform::test_env::lock();
        let temp = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let parent = temp.path().join(if cfg!(windows) {
            "parent;split"
        } else {
            "parent:split"
        });
        let repo = parent.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert_eq!(
            command(&repo, home.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn default_template_directory_is_absent_and_owned() {
        let _env = crate::platform::test_env::lock();
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let child = command(repo.path(), home.path()).unwrap();
        let templates = home.path().join("no-template");
        assert!(!templates.exists());
        assert!(child
            .get_envs()
            .any(|(key, value)| key == "GIT_TEMPLATE_DIR" && value == Some(templates.as_os_str())));
        std::fs::create_dir(&templates).unwrap();
        assert_eq!(
            command(repo.path(), home.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_drive_and_unc_paths_are_normalized_for_git() {
        assert_eq!(
            git_path(PathBuf::from(r"\\?\C:\repo\nested")),
            PathBuf::from(r"C:\repo\nested")
        );
        assert_eq!(
            git_path(PathBuf::from(r"\\?\UNC\server\share\repo")),
            PathBuf::from(r"\\server\share\repo")
        );
    }

    #[test]
    fn nonempty_sandbox_config_is_rejected() {
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("empty-gitconfig"),
            b"[user]\nname=hostile\n",
        )
        .unwrap();
        assert_eq!(
            command(repo.path(), home.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn planted_template_hook_never_runs() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::platform::test_env::lock();
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let template = tempfile::tempdir().unwrap();
        std::fs::create_dir(template.path().join("hooks")).unwrap();
        let hook = template.path().join("hooks/post-commit");
        std::fs::write(
            &hook,
            b"#!/bin/sh\nprintf planted > \"$CSQ_TEST_HOOK_MARKER\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let init = command(repo.path(), home.path())
            .unwrap()
            .arg("init")
            .arg("--template")
            .arg(template.path())
            .output()
            .unwrap();
        assert!(init.status.success(), "{init:?}");
        assert!(repo.path().join(".git/hooks/post-commit").is_file());
        let marker = home.path().join("hook-ran");
        let commit = command(repo.path(), home.path())
            .unwrap()
            .env("CSQ_TEST_HOOK_MARKER", &marker)
            .args(["commit", "--allow-empty", "-m", "target"])
            .output()
            .unwrap();
        assert!(commit.status.success(), "{commit:?}");
        assert!(!marker.exists(), "template hook executed");
    }
    #[test]
    fn ancestor_repository_is_not_discovered_from_uninitialized_inner() {
        let _env = crate::platform::test_env::lock();
        let decoy = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(git(
            decoy.path(),
            home.path(),
            &["init", "--initial-branch=main"]
        )
        .status
        .success());
        std::fs::write(decoy.path().join("seed"), b"seed\n").unwrap();
        assert!(git(decoy.path(), home.path(), &["add", "seed"])
            .status
            .success());
        assert!(git(decoy.path(), home.path(), &["commit", "-m", "decoy"])
            .status
            .success());
        let saved = ["config", "index"]
            .map(|name| std::fs::read(decoy.path().join(".git").join(name)).unwrap());
        let inner = decoy.path().join("uninitialized");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(inner.join("payload"), b"payload\n").unwrap();
        let add = git(&inner, home.path(), &["add", "."]);
        let config = git(&inner, home.path(), &["config", "user.name", "x"]);
        let after = ["config", "index"]
            .map(|name| std::fs::read(decoy.path().join(".git").join(name)).unwrap());
        assert_eq!(
            after, saved,
            "uninitialized inner escaped into ancestor config/index"
        );
        assert_eq!(add.status.code(), Some(128), "{add:?}");
        assert_eq!(config.status.code(), Some(128), "{config:?}");
    }
}
