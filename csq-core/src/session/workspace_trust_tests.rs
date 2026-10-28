use super::*;
use serde_json::json;

#[test]
fn network_and_device_aliases_are_refused_before_metadata_access() {
    for path in [
        "//server/checkout",
        "/Network/checkout",
        "/net/server/repo",
        "/.vol/123/repo",
        "/.file/123/repo",
        "/.nofollow/repo",
        "/.resolve/repo",
        "/network/checkout",
        "/NET/server/repo",
        "/.VOL/123/repo",
        "/n\u{200c}et/server/repo",
    ] {
        assert_eq!(
            native_key(Path::new(path)),
            Err(TrustError::UnsupportedAlias)
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_workspace_key_is_explicitly_unsupported() {
    assert_eq!(
        native_key(Path::new("C:\\workspace")),
        Err(TrustError::UnsupportedAlias)
    );
}

#[cfg(unix)]
#[test]
fn subdirectory_uses_main_checkout_key_and_nongit_uses_exact_cwd() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir(root.join("child")).unwrap();
    assert_eq!(
        native_key(&root.join("child")).unwrap(),
        root.join("child").to_str().unwrap()
    );
    fs::create_dir(root.join(".git")).unwrap();
    assert_eq!(
        native_key(&root.join("child")).unwrap(),
        root.to_str().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn worktree_common_root_requires_exact_backlink() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let main = base.join("main");
    let worktree = base.join("worktree");
    let gitdir = main.join(".git/worktrees/branch");
    fs::create_dir_all(&gitdir).unwrap();
    fs::create_dir_all(worktree.join("child")).unwrap();
    fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
    fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    fs::write(
        gitdir.join("gitdir"),
        worktree.join(".git").to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        native_key(&worktree.join("child")).unwrap(),
        main.to_str().unwrap()
    );
    fs::write(gitdir.join("gitdir"), main.join(".git").to_str().unwrap()).unwrap();
    assert_eq!(
        native_key(&worktree).unwrap(),
        worktree.to_str().unwrap(),
        "a foreign backlink must not inherit main checkout trust"
    );
}

#[cfg(unix)]
#[test]
fn arbitrary_gitdir_pointer_cannot_inherit_a_foreign_trust_key() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let foreign = base.join("foreign");
    let current = base.join("current");
    fs::create_dir_all(&foreign).unwrap();
    fs::create_dir_all(&current).unwrap();
    fs::write(
        current.join(".git"),
        format!("gitdir: {}", foreign.display()),
    )
    .unwrap();
    assert_eq!(native_key(&current).unwrap(), current.to_str().unwrap());
}

#[test]
fn exact_root_flag_survives_without_root_resume_state_or_parent_trust() {
    let projects = json!({"/root":{"hasTrustDialogAccepted":true,"lastSessionId":"other-session"},"/":{"hasTrustDialogAccepted":true}});
    let mut scoped = Map::new();
    preserve_exact_flag(&mut scoped, projects.as_object().unwrap(), "/root");
    assert_eq!(
        Value::Object(scoped),
        json!({"/root":{"hasTrustDialogAccepted":true}})
    );
    let mut scoped = Map::new();
    preserve_exact_flag(&mut scoped, projects.as_object().unwrap(), "/root/child");
    assert!(
        scoped.is_empty(),
        "parent trust is never exact workspace trust"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_git_namespace_is_an_explicit_refusal() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    fs::create_dir(base.join("real-git")).unwrap();
    symlink(base.join("real-git"), base.join(".git")).unwrap();
    assert_eq!(native_key(&base), Err(TrustError::UnsupportedAlias));
}
