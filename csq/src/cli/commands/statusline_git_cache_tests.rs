//! Private proposed companion fixtures. Root/author must integrate and compile.
//! Register in statusline.rs with cfg(all(test, unix)) and an explicit path.
use super::*;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

struct OwnedEnvironment {
    previous: Vec<(OsString, Option<OsString>)>,
}

impl OwnedEnvironment {
    fn set(&mut self, key: &str, value: Option<&OsStr>) {
        let key = OsString::from(key);
        if !self.previous.iter().any(|(saved, _)| saved == &key) {
            self.previous.push((key.clone(), std::env::var_os(&key)));
        }
        unsafe {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }
}

impl Drop for OwnedEnvironment {
    fn drop(&mut self) {
        for (key, value) in self.previous.iter().rev() {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

struct Fixture {
    // Drop environment before TempDir removes paths. The caller's shared env
    // mutex outlives Fixture, including unwind paths.
    _environment: OwnedEnvironment,
    _temporary: TempDir,
    root: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
    counter: PathBuf,
    base: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary_owner = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .expect("private fixture root independent of process temporary variables");
        let root = temporary_owner.path().to_path_buf();
        let home = root.join("home");
        let cache = root.join("cache");
        let temporary = root.join("tmp");
        let bin = root.join("bin");
        let base = home.join(".claude/accounts");
        let config = base.join("term-fixture");
        for path in [&home, &cache, &temporary, &bin, &config] {
            std::fs::create_dir_all(path).unwrap();
        }
        let counter = root.join("git-launches");
        std::fs::write(&counter, "").unwrap();
        let shim = bin.join("git");
        // Only shell builtins before exec: every native invocation is recorded,
        // then genuine Git decides branch/dirty/error results in the owned repo.
        std::fs::write(
            &shim,
            "#!/bin/sh\nprintf '%s\\t' \"$@\" >> \"$STATUSLINE_FIXTURE_COUNTER\"\nprintf '\\n' >> \"$STATUSLINE_FIXTURE_COUNTER\"\nexec /usr/bin/git \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut environment = OwnedEnvironment {
            previous: Vec::new(),
        };
        let keys: Vec<_> = std::env::vars_os()
            .filter(|(key, _)| key.to_string_lossy().starts_with("GIT_"))
            .map(|(key, _)| key)
            .collect();
        for key in keys {
            environment.set(key.to_str().unwrap(), None);
        }
        for name in [
            "ANTHROPIC_MODEL",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CONFIG_ROOT",
        ] {
            environment.set(name, None);
        }
        for name in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "CSQ_HOME"] {
            environment.set(name, Some(home.as_os_str()));
        }
        // Temporary roots belong to each subprocess, never the suite process.
        // Unlocked sibling TempDir users must not become descendants of this
        // fixture and disappear when its owner drops.
        environment.set("XDG_CACHE_HOME", Some(cache.as_os_str()));
        environment.set("XDG_CONFIG_HOME", Some(home.join(".config").as_os_str()));
        environment.set("CLAUDE_HOME", Some(home.join(".claude").as_os_str()));
        environment.set("CSQ_BASE_DIR", Some(base.as_os_str()));
        environment.set("CLAUDE_CONFIG_DIR", Some(config.as_os_str()));
        environment.set("STATUSLINE_FIXTURE_COUNTER", Some(counter.as_os_str()));
        environment.set("PATH", Some(bin.as_os_str()));
        environment.set("GIT_CONFIG_NOSYSTEM", Some(OsStr::new("1")));
        environment.set("GIT_CONFIG_GLOBAL", Some(OsStr::new("/dev/null")));
        // On macOS dirs uses HOME/Library/Caches; on Linux XDG_CACHE_HOME.
        // Create only the resolved owned ancestor, never the real user's cache.
        let platform_cache = dirs::cache_dir().expect("owned cache location");
        assert!(platform_cache.starts_with(&root));
        std::fs::create_dir_all(platform_cache).unwrap();
        Self {
            _environment: environment,
            _temporary: temporary_owner,
            root,
            home,
            temporary,
            counter,
            base,
            config,
        }
    }

    fn setup_git(&self, repo: &Path, args: &[&str]) {
        let status =
            csq_core::platform::test_git::command_with_program("/usr/bin/git", repo, &self.home)
                .expect("sandbox Git command")
                .env("TMPDIR", &self.temporary)
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_AUTHOR_NAME", "fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
                .env("GIT_COMMITTER_NAME", "fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
                .args(["--no-optional-locks", "-C"])
                .arg(repo)
                .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
        assert!(status.success(), "owned fixture Git setup failed: {args:?}");
    }

    fn repo(&self, name: &str, branch: &str) -> PathBuf {
        let repo = self.root.join(name);
        std::fs::create_dir_all(&repo).unwrap();
        self.setup_git(&repo, &["init", "-q", "--initial-branch", branch]);
        std::fs::write(repo.join("README"), "committed\n").unwrap();
        self.setup_git(&repo, &["add", "README"]);
        self.setup_git(&repo, &["commit", "-q", "-m", "fixture"]);
        repo
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.counter)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn render(&self, repo: &Path) -> String {
        let stdin = serde_json::json!({"workspace":{"current_dir":repo},
            "model":{"display_name":"Fixture Model"},
            "context_window":{"current_usage":{"input_tokens":1000},"used_percentage":1.0},
            "cost":{"total_cost_usd":0.12}})
        .to_string();
        build_rich_line(
            &stdin,
            &self.base,
            &self.config,
            AccountNum::try_from(7u16).unwrap(),
            "fixture",
            None,
            false,
        )
        .unwrap()
    }

    fn cache_file(&self, repo: &Path, root: &Path) -> PathBuf {
        git_cache_path(
            root,
            &git_cache_key(repo).expect("owned repository identity"),
        )
    }
}

fn clock() -> SystemTime {
    // Stable controlled year2100 clock, not a today-relative timestamp fixture.
    UNIX_EPOCH + Duration::from_secs(4_102_444_800)
}

fn probe(repo: &Path, cache: &Path, now: SystemTime) -> GitStatus {
    git_status_at(repo, Some(cache), now).expect("owned real repo must be measured")
}

#[test]
fn renderer_cold_four_warm_zero_preserves_display() {
    let _shared = csq_core::platform::test_env::lock();
    let f = Fixture::new();
    let repo = f.repo("renderer", "render-main");
    let first = f.render(&repo);
    assert_eq!(
        f.calls().len(),
        4,
        "cold renderer must launch exactly four real Git processes"
    );
    assert!(first.contains("git:render-main"), "{first}");
    assert!(first.contains("Fixture Model"), "{first}");
    assert!(first.contains("ctx:1.0k"), "{first}");
    let second = f.render(&repo);
    assert_eq!(
        f.calls().len(),
        4,
        "warm renderer must launch zero additional Git processes"
    );
    assert_eq!(
        first, second,
        "warm cache must preserve the actual rendered statusline"
    );
}

#[test]
fn every_runtime_git_process_disables_optional_locks() {
    let _shared = csq_core::platform::test_env::lock();
    let f = Fixture::new();
    let repo = f.repo("options", "options-main");
    let _ = f.render(&repo);
    let calls = f.calls();
    assert_eq!(
        calls.len(),
        4,
        "cold renderer requires the actual four native Git launches"
    );
    for call in calls {
        assert_eq!(
            call.split('\t').next(),
            Some("--no-optional-locks"),
            "every real statusline Git launch must disable optional locks"
        );
    }
}

#[test]
fn age_below_ten_hits_and_exact_ten_refreshes_without_sleep() {
    let _shared = csq_core::platform::test_env::lock();
    let f = Fixture::new();
    let repo = f.repo("age", "age-main");
    let cache = f.root.join("age-cache");
    assert_eq!(probe(&repo, &cache, clock()).dirty, Some(false));
    assert_eq!(f.calls().len(), 4);
    std::fs::write(repo.join("README"), "changed\n").unwrap();
    assert_eq!(
        probe(&repo, &cache, clock() + Duration::from_millis(9_999)).dirty,
        Some(false)
    );
    assert_eq!(
        f.calls().len(),
        4,
        "admitted nine-second cache hit must not launch Git"
    );
    assert_eq!(
        probe(&repo, &cache, clock() + Duration::from_secs(10)).dirty,
        Some(true)
    );
    assert_eq!(
        f.calls().len(),
        8,
        "exact ten-second expiry must perform a fresh four-process probe"
    );
}

#[test]
fn distinct_repositories_and_owned_cache_roots_do_not_share() {
    let _shared = csq_core::platform::test_env::lock();
    let mut f = Fixture::new();
    let a = f.repo("alpha", "alpha-main");
    let b = f.repo("beta", "beta-main");
    let cache = f.root.join("shared-cache");
    assert_eq!(probe(&a, &cache, clock()).branch, "alpha-main");
    assert_eq!(probe(&b, &cache, clock()).branch, "beta-main");
    assert_eq!(
        f.calls().len(),
        8,
        "two actual repositories require independent cold probes"
    );
    let _ = probe(&a, &cache, clock());
    let _ = probe(&b, &cache, clock());
    assert_eq!(f.calls().len(), 8);
    let alias = f.root.join("canonical-alias");
    symlink(&a, &alias).unwrap();
    assert_eq!(probe(&alias, &cache, clock()).branch, "alpha-main");
    assert_eq!(
        f.calls().len(),
        8,
        "canonical symlink alias must reuse the same repository/workdir record"
    );
    let child = a.join("owned-child");
    std::fs::create_dir(&child).unwrap();
    assert_eq!(probe(&child, &cache, clock()).branch, "alpha-main");
    assert_eq!(
        f.calls().len(),
        12,
        "distinct workdir within a repository needs its own cold record"
    );
    let _ = probe(&child, &cache, clock());
    assert_eq!(
        f.calls().len(),
        12,
        "distinct workdir's own warm record must hit"
    );
    let other_home_cache = f.root.join("second-owned-home/cache");
    std::fs::create_dir_all(other_home_cache.parent().unwrap()).unwrap();
    assert_eq!(probe(&a, &other_home_cache, clock()).branch, "alpha-main");
    assert_eq!(
        f.calls().len(),
        16,
        "separate owned cache root must not consume another root's record"
    );
    assert_eq!(probe(&a, &other_home_cache, clock()).branch, "alpha-main");
    assert_eq!(
        f.calls().len(),
        16,
        "second owned cache root must hit its own admitted warm record"
    );
    // Preserve the SAME explicit cache root: these counts distinguish context
    // identity from mere storage-directory separation. All homes/config dirs
    // remain inside the fixture and Git global configuration stays /dev/null.
    let second_home = f.root.join("context-home");
    std::fs::create_dir_all(&second_home).unwrap();
    f._environment.set("HOME", Some(second_home.as_os_str()));
    assert_eq!(probe(&a, &cache, clock()).branch, "alpha-main");
    assert_eq!(
        f.calls().len(),
        20,
        "changed owned HOME with the same cache root requires a fresh probe"
    );
    let _ = probe(&a, &cache, clock());
    assert_eq!(
        f.calls().len(),
        20,
        "changed owned HOME must hit its own warm context record"
    );
    let second_config = f.root.join("context-xdg-config");
    std::fs::create_dir_all(&second_config).unwrap();
    f._environment
        .set("XDG_CONFIG_HOME", Some(second_config.as_os_str()));
    assert_eq!(probe(&a, &cache, clock()).branch, "alpha-main");
    assert_eq!(
        f.calls().len(),
        24,
        "changed owned XDG_CONFIG_HOME with the same cache root requires a fresh probe"
    );
    let _ = probe(&a, &cache, clock());
    assert_eq!(
        f.calls().len(),
        24,
        "changed owned XDG config must hit its own warm context record"
    );
}

#[test]
fn corrupt_future_and_oversized_records_refresh_real_git() {
    let _shared = csq_core::platform::test_env::lock();
    for kind in [
        "corrupt",
        "future",
        "oversized",
        "control-branch",
        "wrong-version",
        "wrong-key",
    ] {
        let f = Fixture::new();
        let repo = f.repo(kind, "safe-main");
        let cache = f.root.join("record-cache");
        let _ = probe(&repo, &cache, clock());
        let path = f.cache_file(&repo, &cache);
        let original = std::fs::read(&path).expect("cold call published actual cache record");
        let bad = match kind {
            "corrupt" => b"not-json".to_vec(),
            "oversized" => {
                // Valid JSON with valid fields: only the byte-size admission
                // boundary should force refresh, not a JSON/schema failure.
                let mut padded = original.clone();
                padded.extend(std::iter::repeat_n(b' ', 16_385));
                padded
            }
            "control-branch" | "wrong-version" | "wrong-key" => {
                let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
                match kind {
                    "control-branch" => record["branch"] = serde_json::json!("\u{1b}[2J"),
                    "wrong-version" => record["version"] = serde_json::json!(99),
                    _ => record["key"] = serde_json::json!("different-repository-identity"),
                }
                serde_json::to_vec(&record).unwrap()
            }
            _ => {
                let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
                record["observed_ms"] = serde_json::json!((clock() + Duration::from_secs(1))
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64);
                record["branch"] = serde_json::json!("poisoned-future");
                serde_json::to_vec(&record).unwrap()
            }
        };
        std::fs::write(&path, bad).unwrap();
        let current = probe(&repo, &cache, clock());
        assert_eq!(
            current.branch, "safe-main",
            "inadmissible cache cannot inject its branch"
        );
        assert_eq!(
            f.calls().len(),
            8,
            "inadmissible cache must trigger four real Git processes"
        );
    }
}

#[test]
fn cache_modes_links_and_write_failure_fall_back_safely() {
    let _shared = csq_core::platform::test_env::lock();
    for kind in ["mode", "symlink", "hardlink", "root-mode"] {
        let f = Fixture::new();
        let repo = f.repo(kind, "private-main");
        let cache = f.root.join("private-cache");
        let _ = probe(&repo, &cache, clock());
        let path = f.cache_file(&repo, &cache);
        assert_eq!(
            std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["branch"] = serde_json::json!("poisoned-unsafe-cache");
        let poison = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &poison).unwrap();
        let external = f.root.join("owned-link-target");
        match kind {
            "mode" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "root-mode" => {
                std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap()
            }
            "symlink" => {
                std::fs::rename(&path, &external).unwrap();
                symlink(&external, &path).unwrap();
            }
            _ => std::fs::hard_link(&path, &external).unwrap(),
        }
        assert_eq!(probe(&repo, &cache, clock()).branch, "private-main");
        assert_eq!(
            f.calls().len(),
            8,
            "unsafe cache metadata must cause a live four-process fallback"
        );
        if external.exists() {
            assert_eq!(
                std::fs::read(&external).unwrap(),
                poison,
                "fallback must not mutate the linked owned target"
            );
        }
    }
    let f = Fixture::new();
    let repo = f.repo("write-failure", "fallback-main");
    let not_directory = f.root.join("not-a-cache-directory");
    std::fs::write(&not_directory, "owned blocker").unwrap();
    assert_eq!(
        probe(&repo, &not_directory, clock()).branch,
        "fallback-main"
    );
    assert_eq!(
        f.calls().len(),
        4,
        "cache write refusal must not suppress live display"
    );
}

#[test]
fn replaced_repository_identity_does_not_replay_old_branch() {
    let _shared = csq_core::platform::test_env::lock();
    let f = Fixture::new();
    let repo = f.repo("replaced", "old-main");
    let cache = f.root.join("identity-cache");
    let _ = probe(&repo, &cache, clock());
    std::fs::rename(&repo, f.root.join("retired-repository")).unwrap();
    let replacement = f.repo("replaced", "new-main");
    assert_eq!(probe(&replacement, &cache, clock()).branch, "new-main");
    assert_eq!(
        f.calls().len(),
        8,
        "new repository inode at the same path requires live measurement"
    );
}

#[test]
fn dirty_unknown_and_detached_state_survive_cache_hits() {
    let _shared = csq_core::platform::test_env::lock();
    for kind in ["worktree", "staged", "unknown", "detached"] {
        let f = Fixture::new();
        let repo = f.repo(kind, "state-main");
        match kind {
            "worktree" => std::fs::write(repo.join("README"), "modified\n").unwrap(),
            "staged" => {
                std::fs::write(repo.join("NEW"), "staged\n").unwrap();
                f.setup_git(&repo, &["add", "NEW"]);
            }
            "unknown" => {
                std::fs::write(repo.join(".git").join("index"), b"NOT-A-GIT-INDEX").unwrap()
            }
            _ => f.setup_git(&repo, &["checkout", "--detach", "-q"]),
        }
        let cache = f.root.join("state-cache");
        let first = probe(&repo, &cache, clock());
        let expected = match kind {
            "worktree" | "staged" => Some(true),
            "unknown" => None,
            _ => Some(false),
        };
        assert_eq!(
            first.dirty, expected,
            "actual diff knowledge must remain three-state"
        );
        if kind == "detached" {
            assert_eq!(first.branch, "detached");
        }
        let second = probe(&repo, &cache, clock());
        assert_eq!(second.dirty, first.dirty);
        assert_eq!(second.branch, first.branch);
        assert_eq!(
            f.calls().len(),
            4,
            "cached dirty/unknown/detached state must not relaunch Git"
        );
        let line = f.render(&repo);
        assert_eq!(
            line.contains('●'),
            expected == Some(true),
            "only known dirtiness earns the actual renderer dot"
        );
    }
}

/// An ordinary sibling tempfile user need not hold the environment mutex:
/// fixture cleanup must not delete that independently owned directory.
#[test]
fn fixture_drop_preserves_an_independent_tempdir() {
    let _shared = csq_core::platform::test_env::lock();
    let fixture = Fixture::new();
    let sibling = std::thread::spawn(|| TempDir::new().expect("independent sibling tempdir"))
        .join()
        .expect("sibling tempfile thread");
    let marker = sibling.path().join("survivor");
    std::fs::write(&marker, b"independently owned").unwrap();
    drop(fixture);
    assert_eq!(
        std::fs::read(&marker).expect("fixture cleanup must preserve the sibling root"),
        b"independently owned"
    );
}

fn sweep_root() -> TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap()
}

fn tmp_file(root: &Path, name: &str, age: Duration, mode: u32) -> PathBuf {
    tmp_file_at(root, name, SystemTime::now(), age, mode)
}

fn tmp_file_at(root: &Path, name: &str, now: SystemTime, age: Duration, mode: u32) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, b"{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_modified(now - age).unwrap();
    path
}

const ORPHAN: &str = "0123456789abcdef.tmp.2147483647.7";

#[test]
fn sweep_removes_a_stale_private_orphan() {
    let dir = sweep_root();
    let p = tmp_file(
        dir.path(),
        ORPHAN,
        GIT_CACHE_STALE + Duration::from_secs(5),
        0o600,
    );
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(!p.exists(), "stale orphan must be reclaimed");
}

#[test]
fn sweep_keeps_a_fresh_tmp_in_flight() {
    let dir = sweep_root();
    let p = tmp_file(dir.path(), ORPHAN, Duration::from_secs(1), 0o600);
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(p.exists(), "a write in flight must survive");
}

#[test]
fn sweep_does_not_follow_or_remove_a_tmp_named_symlink() {
    let dir = sweep_root();
    let outside = sweep_root();
    let target = tmp_file(outside.path(), "victim", GIT_CACHE_STALE * 4, 0o600);
    let link = dir.path().join(ORPHAN);
    symlink(&target, &link).unwrap();
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(std::fs::symlink_metadata(&link).is_ok(), "symlink kept");
    assert!(target.exists(), "symlink target untouched");
}

#[test]
fn sweep_keeps_a_non_private_tmp() {
    let dir = sweep_root();
    let p = tmp_file(dir.path(), ORPHAN, GIT_CACHE_STALE * 4, 0o644);
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(p.exists(), "non-private entry is not ours to remove");
}

#[test]
fn sweep_leaves_non_matching_names_alone() {
    let dir = sweep_root();
    let old = GIT_CACHE_STALE * 4;
    let names = [
        "0123456789abcdef.json.bak",
        "0123456789abcdef.tmp",
        "0123456789abcdef.tmp.1",
        "0123456789abcdef.tmp.1.2.3",
        "0123456789abcdef.tmp.x.2",
        "0123456789ABCDEF.tmp.1.2",
        "123456789abcdef.tmp.1.2",
        "notes.txt",
    ];
    let paths: Vec<_> = names
        .iter()
        .map(|n| tmp_file(dir.path(), n, old, 0o600))
        .collect();
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    for p in paths {
        assert!(p.exists(), "{} must be untouched", p.display());
    }
}

#[test]
fn sweep_caps_removals_per_call() {
    let dir = sweep_root();
    let old = GIT_CACHE_STALE * 4;
    for n in 0..GIT_CACHE_SWEEP_REMOVE_CAP + 4 {
        tmp_file(
            dir.path(),
            &format!("0123456789abcdef.tmp.2147483647.{n}"),
            old,
            0o600,
        );
    }
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    let left = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(left, 4);
}

#[test]
fn failed_write_leaves_no_tmp_file() {
    let dir = sweep_root();
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    // The injected writer creates the tmp file, then fails: a partial write.
    write_git_cache_with(
        dir.path(),
        "k".into(),
        1,
        &status,
        &|tmp, _| {
            std::fs::write(tmp, b"partial")?;
            Err(std::io::Error::other("injected"))
        },
        &|_| {},
    );
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
    assert!(
        left.is_empty(),
        "failed write leaked {} entries",
        left.len()
    );
}

#[test]
fn sweep_reclaims_stale_json_records_and_keeps_fresh_ones() {
    let dir = sweep_root();
    let stale = tmp_file(
        dir.path(),
        "0123456789abcdef.json",
        GIT_CACHE_STALE * 2,
        0o600,
    );
    let fresh = tmp_file(
        dir.path(),
        "fedcba9876543210.json",
        Duration::from_secs(1),
        0o600,
    );
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(
        !stale.exists(),
        "a record past the bound is already refused"
    );
    assert!(fresh.exists(), "a live record must survive");
}

#[test]
fn sweep_progresses_past_the_scan_cap() {
    let dir = sweep_root();
    let total = GIT_CACHE_SWEEP_SCAN_CAP + 40;
    for n in 0..total {
        tmp_file(
            dir.path(),
            &format!("{n:016x}.json"),
            GIT_CACHE_STALE * 2,
            0o600,
        );
    }
    for _ in 0..(total / GIT_CACHE_SWEEP_REMOVE_CAP + 2) {
        sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn sweep_keeps_a_hard_linked_orphan() {
    let dir = sweep_root();
    let p = tmp_file(dir.path(), ORPHAN, GIT_CACHE_STALE * 2, 0o600);
    let outside = sweep_root();
    std::fs::hard_link(&p, outside.path().join("alias")).unwrap();
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(p.exists(), "nlink > 1 is not a private cache file");
}

#[test]
fn sweep_refuses_a_symlinked_root() {
    let real = sweep_root();
    let victim = tmp_file(real.path(), ORPHAN, GIT_CACHE_STALE * 2, 0o600);
    let holder = sweep_root();
    let link = holder.path().join("root");
    symlink(real.path(), &link).unwrap();
    sweep_git_cache_tmp(&link, SystemTime::now(), None);
    assert!(
        victim.exists(),
        "nothing may be deleted through a symlinked root"
    );
}

#[test]
fn sweep_refuses_a_non_private_root() {
    let dir = sweep_root();
    let victim = tmp_file(dir.path(), ORPHAN, GIT_CACHE_STALE * 2, 0o600);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(victim.exists(), "nothing may be deleted from a 0755 root");
}

#[test]
fn sweep_tolerates_a_missing_root() {
    let dir = sweep_root();
    sweep_git_cache_tmp(&dir.path().join("absent"), SystemTime::now(), None);
}

#[test]
fn writer_already_exists_does_not_unlink_the_entry() {
    let dir = sweep_root();
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    let seen = std::cell::RefCell::new(None);
    write_git_cache_with(
        dir.path(),
        "k".into(),
        1,
        &status,
        &|tmp, _| {
            std::fs::write(tmp, b"someone else's")?;
            *seen.borrow_mut() = Some(tmp.to_path_buf());
            Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        },
        &|_| {},
    );
    let tmp = seen.borrow().clone().expect("writer ran");
    assert_eq!(std::fs::read(&tmp).unwrap(), b"someone else's");
}

#[test]
fn production_render_path_reclaims_stale_orphans_only() {
    let _shared = csq_core::platform::test_env::lock();
    let f = Fixture::new();
    let repo = f.repo("sweep-prod", "main");
    let cache = f.root.join("cache-root");
    std::fs::create_dir(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    let now = clock();
    let stale = tmp_file_at(&cache, ORPHAN, now, GIT_CACHE_STALE * 2, 0o600);
    let fresh = tmp_file_at(
        &cache,
        "fedcba9876543210.tmp.2147483647.1",
        now,
        Duration::from_secs(1),
        0o600,
    );
    // Cold cache: real git probe, then the production write + sweep.
    probe(&repo, &cache, now);
    assert!(
        !stale.exists(),
        "production write path must reclaim the stale orphan"
    );
    assert!(
        fresh.exists(),
        "production write path must keep an in-flight tmp"
    );
}

fn record_json(observed_ms: u64) -> String {
    format!(
        r#"{{"version":1,"key":"k","observed_ms":{observed_ms},"branch":"main","dirty":false}}"#
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn sweep_scan_examines_at_most_the_cap_of_all_entries() {
    let dir = sweep_root();
    for n in 0..GIT_CACHE_SWEEP_SCAN_CAP + 80 {
        std::fs::write(dir.path().join(format!("junk-{n}")), b"x").unwrap();
    }
    let examined = sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert_eq!(examined, GIT_CACHE_SWEEP_SCAN_CAP);
}

#[test]
fn sweep_boundary_keeps_inside_and_reclaims_past_the_stale_bound() {
    // Absolute ages: the documented 60s bound, not whatever the constant holds.
    let dir = sweep_root();
    let inside = tmp_file(dir.path(), ORPHAN, Duration::from_secs(55), 0o600);
    let past = tmp_file(
        dir.path(),
        "fedcba9876543210.tmp.2147483647.1",
        Duration::from_secs(65),
        0o600,
    );
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(inside.exists(), "inside the bound must be kept");
    assert!(!past.exists(), "past the bound must be reclaimed");
}

fn blank_stat(uid: libc::uid_t, age: Duration) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_mode = libc::S_IFREG | 0o600;
    st.st_nlink = 1;
    st.st_uid = uid;
    st.st_mtime = (SystemTime::now() - age)
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as _;
    st
}

#[test]
fn reclaimable_requires_the_current_owner() {
    let euid = unsafe { libc::geteuid() };
    let old = GIT_CACHE_STALE * 2;
    assert!(git_cache_reclaimable(
        &blank_stat(euid, old),
        euid,
        SystemTime::now()
    ));
    assert!(
        !git_cache_reclaimable(
            &blank_stat(euid.wrapping_add(1), old),
            euid,
            SystemTime::now()
        ),
        "a foreign-owned entry must be kept"
    );
}

#[test]
fn production_writer_reports_already_exists_and_leaves_the_entry() {
    let dir = sweep_root();
    let tmp = dir.path().join(ORPHAN);
    std::fs::write(&tmp, b"theirs").unwrap();
    let err = write_git_cache_tmp(&tmp, b"ours").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&tmp).unwrap(), b"theirs");
}

#[test]
fn write_and_publish_failures_are_reported_with_fixed_tags() {
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    let run = |writer: &dyn Fn(&Path, &[u8]) -> std::io::Result<()>| {
        let dir = sweep_root();
        let seen = std::cell::RefCell::new(Vec::new());
        write_git_cache_with(dir.path(), "k".into(), 1, &status, writer, &|t| {
            seen.borrow_mut().push(t)
        });
        seen.into_inner()
    };
    assert_eq!(
        run(&|_, _| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))),
        ["git_cache_write"]
    );
    assert_eq!(
        run(&|_, _| Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))),
        ["git_cache_tmp_exists"]
    );
    // The writer "succeeds" without leaving a tmp file, so the rename fails.
    assert_eq!(run(&|_, _| Ok(())), ["git_cache_tmp_missing"]);
}

#[test]
fn sweep_never_reclaims_the_entry_just_published() {
    let dir = sweep_root();
    let old = GIT_CACHE_STALE * 2;
    let keep = tmp_file(dir.path(), "0123456789abcdef.json", old, 0o600);
    let other = tmp_file(dir.path(), "fedcba9876543210.json", old, 0o600);
    sweep_git_cache_tmp(
        dir.path(),
        SystemTime::now(),
        Some(OsStr::new("0123456789abcdef.json")),
    );
    assert!(
        keep.exists(),
        "the just-published name is never a candidate"
    );
    assert!(!other.exists());
}

#[test]
fn record_staleness_follows_observed_ms_not_mtime() {
    let dir = sweep_root();
    let write = |name: &str, observed: u64, age: Duration| {
        let p = tmp_file(dir.path(), name, age, 0o600);
        std::fs::write(&p, record_json(observed)).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
        p
    };
    let skewed_fresh = write("0123456789abcdef.json", now_ms(), GIT_CACHE_STALE * 2);
    let dead_new_mtime = write(
        "fedcba9876543210.json",
        now_ms() - 2 * GIT_CACHE_STALE.as_millis() as u64,
        Duration::from_secs(1),
    );
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(
        skewed_fresh.exists(),
        "a fresh record with a skewed mtime must survive"
    );
    assert!(
        !dead_new_mtime.exists(),
        "an expired record is reclaimed whatever its mtime"
    );
}

#[test]
fn sweep_keeps_a_record_it_cannot_read_but_ages_an_unparseable_one_by_mtime() {
    let dir = sweep_root();
    let old = GIT_CACHE_STALE * 2;
    let unreadable = tmp_file(dir.path(), "0123456789abcdef.json", old, 0o600);
    let unparseable = tmp_file(dir.path(), "fedcba9876543210.json", old, 0o600);
    let reader = |_fd: std::os::fd::RawFd, name: &std::ffi::CStr| {
        if name.to_bytes().starts_with(b"0123") {
            RecordRead::Unreadable
        } else {
            RecordRead::Unparseable
        }
    };
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &reader,
        &|_| {},
        &|_| {},
    );
    assert!(unreadable.exists(), "an unreadable record must be kept");
    assert!(!unparseable.exists(), "an unparseable one is aged by mtime");
}

#[test]
fn sweep_does_not_unlink_a_record_replaced_after_the_staleness_decision() {
    let dir = sweep_root();
    let stale_json = |observed: u64| record_json(observed);
    let target = tmp_file(
        dir.path(),
        "0123456789abcdef.json",
        GIT_CACHE_STALE * 2,
        0o600,
    );
    std::fs::write(
        &target,
        stale_json(now_ms() - 2 * GIT_CACHE_STALE.as_millis() as u64),
    )
    .unwrap();
    let root = dir.path().to_path_buf();
    let swap_in_fresh = |_name: &std::ffi::CStr| {
        let fresh = root.join("fresh.new");
        std::fs::write(&fresh, record_json(now_ms())).unwrap();
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&fresh, root.join("0123456789abcdef.json")).unwrap();
    };
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &swap_in_fresh,
        &|_| {},
    );
    let kept = std::fs::read_to_string(&target).expect("the replacement must survive");
    let observed: u64 = kept
        .split("observed_ms\":")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        now_ms() - observed < GIT_CACHE_STALE.as_millis() as u64,
        "must be the fresh record"
    );
}

#[test]
fn production_write_keeps_its_own_record() {
    let dir = sweep_root();
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    let old = now_ms() - 2 * GIT_CACHE_STALE.as_millis() as u64;
    write_git_cache(dir.path(), "k".into(), old, &status, SystemTime::now());
    assert!(
        git_cache_path(dir.path(), "k").exists(),
        "the record this call published must survive its own sweep"
    );
}

#[test]
fn warn_latch_fires_once_and_write_and_publish_latch_separately() {
    let flag = std::sync::atomic::AtomicBool::new(false);
    assert!(warn_git_cache_once(&flag, "t"), "first call emits");
    assert!(!warn_git_cache_once(&flag, "t"), "second call is latched");
    assert!(
        !std::ptr::eq(
            git_cache_failure_flag("git_cache_write"),
            git_cache_failure_flag("git_cache_publish")
        ),
        "write and publish must not share a latch"
    );
}

#[test]
fn production_reader_classifies_gone_unreadable_unparseable_observed() {
    use std::os::fd::AsRawFd;
    let dir = sweep_root();
    let root = std::fs::File::open(dir.path()).unwrap();
    let fd = root.as_raw_fd();
    assert_eq!(
        git_cache_record_observed(fd, c"0123456789abcdef.json"),
        RecordRead::Gone,
        "ENOENT"
    );
    std::fs::create_dir(dir.path().join("1123456789abcdef.json")).unwrap();
    assert_eq!(
        git_cache_record_observed(fd, c"1123456789abcdef.json"),
        RecordRead::Unreadable,
        "EISDIR read"
    );
    std::fs::write(dir.path().join("2123456789abcdef.json"), b"not json").unwrap();
    assert_eq!(
        git_cache_record_observed(fd, c"2123456789abcdef.json"),
        RecordRead::Unparseable,
        "garbage"
    );
    std::fs::write(dir.path().join("3123456789abcdef.json"), record_json(42)).unwrap();
    assert_eq!(
        git_cache_record_observed(fd, c"3123456789abcdef.json"),
        RecordRead::Observed(42),
        "valid"
    );
}

#[test]
fn sweep_reports_an_unreadable_record() {
    let dir = sweep_root();
    let record = tmp_file(
        dir.path(),
        "0123456789abcdef.json",
        GIT_CACHE_STALE * 2,
        0o600,
    );
    let seen = std::cell::RefCell::new(Vec::new());
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &|_fd: std::os::fd::RawFd, _name: &std::ffi::CStr| RecordRead::Unreadable,
        &|_| {},
        &|tag| seen.borrow_mut().push(tag),
    );
    assert_eq!(*seen.borrow(), vec!["git_cache_sweep_read"]);
    assert!(record.exists(), "an unreadable record must be kept");
}

#[test]
fn sweep_reports_a_failed_recheck_and_keeps_the_entry() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores the missing search bit, so EACCES cannot be provoked
    }
    let dir = sweep_root();
    let orphan = tmp_file(dir.path(), ORPHAN, GIT_CACHE_STALE * 2, 0o600);
    let root = dir.path().to_path_buf();
    let seen = std::cell::RefCell::new(Vec::new());
    let revoke_search = |_name: &std::ffi::CStr| {
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &revoke_search,
        &|tag| seen.borrow_mut().push(tag),
    );
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(*seen.borrow(), vec!["git_cache_sweep_stat"]);
    assert!(orphan.exists(), "a failed recheck must keep the entry");
}

#[test]
fn sweep_keeps_a_tmp_refreshed_by_its_active_writer_before_recheck() {
    let dir = sweep_root();
    let tmp = tmp_file(dir.path(), ORPHAN, Duration::from_secs(120), 0o600);
    let writer = std::fs::OpenOptions::new().write(true).open(&tmp).unwrap();
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &|_| writer.set_modified(SystemTime::now()).unwrap(),
        &|_| {},
    );
    assert!(tmp.exists(), "an active writer refreshed this same inode");
}

#[test]
fn failed_publish_removes_the_owned_tmp_and_preserves_the_destination() {
    let dir = sweep_root();
    let key = "publish-failure";
    let destination = git_cache_path(dir.path(), key);
    let seen = std::cell::RefCell::new(None);
    let reports = std::cell::RefCell::new(Vec::new());
    write_git_cache_with(
        dir.path(),
        key.into(),
        1,
        &GitStatus {
            branch: "main".into(),
            dirty: Some(false),
        },
        &|tmp, bytes| {
            write_git_cache_tmp(tmp, bytes)?;
            *seen.borrow_mut() = Some(tmp.to_path_buf());
            // Deterministically make rename fail after the initial destination
            // validation, with a real owned tmp still present.
            std::fs::create_dir(&destination)?;
            Ok(())
        },
        &|tag| reports.borrow_mut().push(tag),
    );
    assert_eq!(*reports.borrow(), ["git_cache_publish"]);
    assert!(
        !seen.borrow().as_ref().unwrap().exists(),
        "failed rename leaked its owned tmp"
    );
    assert!(
        destination.is_dir(),
        "failed publication must preserve the destination"
    );
}

#[test]
fn concurrent_writers_preserve_a_fresh_in_flight_tmp() {
    let dir = sweep_root();
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    // A bounded two-step handshake, not a Barrier: if either side panics, its
    // channel end drops on unwind and the other side's wait returns at once
    // (`Disconnected`), so a failing writer cannot strand the scope's join.
    const HANDSHAKE: Duration = Duration::from_secs(60);
    let (written_tx, written_rx) = std::sync::mpsc::channel::<()>();
    let (sibling_done_tx, sibling_done_rx) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        // Owned by this closure, so it drops (unblocking the writer) on unwind.
        let sibling_done = sibling_done_tx;
        let (status, dir) = (&status, &dir);
        scope.spawn(move || {
            write_git_cache_with(
                dir.path(),
                "same-key".into(),
                now_ms(),
                status,
                &|tmp, bytes| {
                    write_git_cache_tmp(tmp, bytes)?;
                    written_tx
                        .send(())
                        .expect("the main thread awaits the written tmp");
                    sibling_done_rx
                        .recv_timeout(HANDSHAKE)
                        .expect("the sibling writer must finish while this tmp is in flight");
                    assert!(tmp.exists(), "the sibling writer swept a fresh active tmp");
                    Ok(())
                },
                &|tag| panic!("active writer failed: {tag}"),
            );
        });
        written_rx
            .recv_timeout(HANDSHAKE)
            .expect("the active writer must write its tmp before the sibling runs");
        write_git_cache(
            dir.path(),
            "same-key".into(),
            now_ms(),
            status,
            SystemTime::now(),
        );
        sibling_done
            .send(())
            .expect("the active writer awaits the sibling");
    });
    assert!(read_git_cache(dir.path(), "same-key", now_ms()).is_some());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn sweep_keeps_a_live_writer_even_when_its_tmp_is_old() {
    let dir = sweep_root();
    let name = format!("0123456789abcdef.tmp.{}.7", std::process::id());
    let tmp = tmp_file(dir.path(), &name, Duration::from_secs(120), 0o600);
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(tmp.exists(), "an alive writer owns this old tmp");
}

#[test]
fn sweep_reclaims_a_dead_writer_old_tmp_but_keeps_unparseable_pids() {
    let dir = sweep_root();
    // The fixture must fail rather than accidentally exercise a live writer.
    // SAFETY: signal zero only checks this out-of-range PID; no signal is sent.
    assert_eq!(unsafe { libc::kill(i32::MAX, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    let dead = tmp_file(dir.path(), ORPHAN, Duration::from_secs(120), 0o600);
    let unknown = tmp_file(
        dir.path(),
        "fedcba9876543210.tmp.99999999999999999999.1",
        Duration::from_secs(120),
        0o600,
    );
    let zero = tmp_file(
        dir.path(),
        "fedcba9876543210.tmp.0.1",
        Duration::from_secs(120),
        0o600,
    );
    sweep_git_cache_tmp(dir.path(), SystemTime::now(), None);
    assert!(
        !dead.exists(),
        "a stale tmp of a verified dead writer is reclaimed"
    );
    assert!(unknown.exists(), "an overflowing PID is unknown, not dead");
    assert!(
        zero.exists(),
        "zero names a process group, never one writer"
    );
}

#[test]
fn sweep_rechecks_privacy_after_chmod() {
    let dir = sweep_root();
    let tmp = tmp_file(dir.path(), ORPHAN, Duration::from_secs(120), 0o600);
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap(),
        &|_| {},
    );
    assert!(
        tmp.exists(),
        "a tmp made non-private before unlink must survive"
    );
}

#[test]
fn sweep_rechecks_privacy_after_a_hard_link_is_added() {
    let dir = sweep_root();
    let tmp = tmp_file(dir.path(), ORPHAN, Duration::from_secs(120), 0o600);
    let alias = dir.path().join("alias");
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &|_| std::fs::hard_link(&tmp, &alias).unwrap(),
        &|_| {},
    );
    assert!(
        tmp.exists(),
        "a tmp with a new hard-link alias must survive"
    );
    assert!(alias.exists());
}

#[test]
fn sweep_keeps_a_record_whose_ctime_changes_before_recheck() {
    use std::os::unix::fs::MetadataExt;
    let dir = sweep_root();
    let record = tmp_file(
        dir.path(),
        "0123456789abcdef.json",
        Duration::from_secs(120),
        0o600,
    );
    std::fs::write(&record, record_json(now_ms() - 120_000)).unwrap();
    let original = std::fs::metadata(&record).unwrap();
    let hook = |_: &std::ffi::CStr| {
        // Real chmod syscalls change ctime while restoring privacy, size and
        // inode. A bounded loop accommodates coarse filesystem timestamps.
        for _ in 0..1024 {
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
            let changed = std::fs::metadata(&record).unwrap();
            if (changed.ctime(), changed.ctime_nsec()) != (original.ctime(), original.ctime_nsec())
            {
                return;
            }
        }
        panic!("could not measure a ctime change in the fixture");
    };
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &hook,
        &|_| {},
    );
    let kept =
        std::fs::metadata(&record).expect("same-inode record with changed ctime must survive");
    assert_eq!(kept.ino(), original.ino());
    assert_eq!(kept.len(), original.len());
    assert_ne!(
        (kept.ctime(), kept.ctime_nsec()),
        (original.ctime(), original.ctime_nsec())
    );
}

#[test]
fn sweep_keeps_a_record_whose_size_changes_before_recheck() {
    let dir = sweep_root();
    let record = tmp_file(
        dir.path(),
        "0123456789abcdef.json",
        Duration::from_secs(120),
        0o600,
    );
    std::fs::write(&record, record_json(now_ms() - 120_000)).unwrap();
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &git_cache_record_observed,
        &|_| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&record)
                .unwrap()
                .set_len(4096)
                .unwrap()
        },
        &|_| {},
    );
    assert!(
        record.exists(),
        "a same-inode record changed before unlink must survive"
    );
}

#[test]
fn sweep_reads_at_most_sixty_four_records_independent_of_removals() {
    let dir = sweep_root();
    for n in 0..100 {
        tmp_file(
            dir.path(),
            &format!("{n:016x}.json"),
            Duration::from_secs(120),
            0o600,
        );
    }
    let reads = std::cell::Cell::new(0);
    sweep_git_cache_entries(
        dir.path(),
        SystemTime::now(),
        None,
        &|_, _| {
            reads.set(reads.get() + 1);
            RecordRead::Observed(now_ms())
        },
        &|_| {},
        &|_| {},
    );
    assert_eq!(
        reads.get(),
        64,
        "fresh records consume reads but no removal budget"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 100);
}

#[test]
fn writer_reports_a_non_private_destination_and_an_oversized_record() {
    let dir = sweep_root();
    let path = git_cache_path(dir.path(), "private-refusal");
    std::fs::write(&path, b"theirs").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let reports = std::cell::RefCell::new(Vec::new());
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    write_git_cache_with(
        dir.path(),
        "private-refusal".into(),
        1,
        &status,
        &|_, _| panic!("must not overwrite non-private destination"),
        &|tag| reports.borrow_mut().push(tag),
    );
    assert_eq!(*reports.borrow(), ["git_cache_destination_private"]);
    reports.borrow_mut().clear();
    let large = GitStatus {
        branch: "x".repeat(20_000),
        dirty: Some(false),
    };
    write_git_cache_with(
        dir.path(),
        "oversized".into(),
        1,
        &large,
        &|_, _| panic!("oversized records must not be written"),
        &|tag| reports.borrow_mut().push(tag),
    );
    assert_eq!(*reports.borrow(), ["git_cache_oversize"]);
}

#[test]
fn tmp_writer_pid_and_probe_fail_closed() {
    use std::ffi::CString;
    for (text, expected) in [
        ("0123456789abcdef.tmp.1.2", Some(1)),
        ("0123456789abcdef.tmp.2147483647.2", Some(i32::MAX)),
        ("0123456789abcdef.tmp.0.2", None),
        ("0123456789abcdef.tmp.2147483648.2", None),
        ("0123456789abcdef.tmp.-1.2", None),
        ("0123456789abcdef.json", None),
    ] {
        assert_eq!(
            git_cache_tmp_writer_pid(&CString::new(text).unwrap()),
            expected
        );
    }
    assert!(git_cache_pid_probe_proves_dead(-1, Some(libc::ESRCH)));
    for (result, errno) in [
        (0, None),
        (0, Some(libc::ESRCH)),
        (-1, None),
        (-1, Some(libc::EPERM)),
        (-1, Some(libc::EIO)),
    ] {
        assert!(!git_cache_pid_probe_proves_dead(result, errno));
    }
}

#[test]
fn record_generation_checks_each_ctime_component_and_size() {
    let before = blank_stat(unsafe { libc::geteuid() }, Duration::from_secs(120));
    let mut after = before;
    assert!(git_cache_record_generation_unchanged(&before, &after));
    after.st_ctime += 1;
    assert!(!git_cache_record_generation_unchanged(&before, &after));
    after = before;
    after.st_ctime_nsec += 1;
    assert!(!git_cache_record_generation_unchanged(&before, &after));
    after = before;
    after.st_size += 1;
    assert!(!git_cache_record_generation_unchanged(&before, &after));
}

#[test]
fn writer_root_refusal_is_reported_without_creating_a_tmp() {
    let dir = sweep_root();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let seen = std::cell::RefCell::new(Vec::new());
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    write_git_cache_with(
        dir.path(),
        "k".into(),
        1,
        &status,
        &|_, _| panic!("unsafe root must not write"),
        &|tag| seen.borrow_mut().push(tag),
    );
    assert_eq!(*seen.borrow(), ["git_cache_root"]);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn writer_failure_tags_have_distinct_once_latches() {
    let tags = [
        "git_cache_write",
        "git_cache_publish",
        "git_cache_tmp_missing",
        "git_cache_root",
        "git_cache_destination_private",
        "git_cache_destination_stat",
        "git_cache_serialize",
        "git_cache_oversize",
    ];
    for (i, tag) in tags.iter().enumerate() {
        for other in &tags[i + 1..] {
            assert!(
                !std::ptr::eq(git_cache_failure_flag(tag), git_cache_failure_flag(other)),
                "{tag} and {other} share a latch"
            );
        }
    }
}

fn final_cache_capture(run: impl FnOnce()) -> String {
    #[derive(Clone)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = bytes.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || Capture(sink.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let result = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    result
}

#[test]
fn final_cache_missing_tmp_is_warn_once_with_a_distinct_latch() {
    let dir = sweep_root();
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    let log = final_cache_capture(|| {
        for _ in 0..2 {
            write_git_cache_with(
                dir.path(),
                "missing".into(),
                1,
                &status,
                &|_, _| Ok(()),
                &warn_git_cache_failure_once,
            );
        }
        warn_git_cache_failure_once("git_cache_serialize");
        warn_git_cache_failure_once("git_cache_serialize");
    });
    assert_eq!(
        log.lines().count(),
        2,
        "each anomaly category emits once: {log}"
    );
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("WARN") && line.contains("git_cache_tmp_missing"))
            .count(),
        1,
        "missing publication is an anomaly: {log}"
    );
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("WARN") && line.contains("git_cache_serialize"))
            .count(),
        1
    );
    assert!(!log.contains("DEBUG") && !log.contains("git_cache_tmp_swept"));
    assert!(
        !std::ptr::eq(
            git_cache_failure_flag("git_cache_tmp_missing"),
            git_cache_failure_flag("git_cache_publish")
        ),
        "missing and failed publish require separate latches"
    );
}

#[test]
fn final_cache_already_exists_is_debug_and_keeps_the_foreign_entry() {
    let dir = sweep_root();
    let paths = std::cell::RefCell::new(Vec::new());
    let tags = std::cell::RefCell::new(Vec::new());
    let status = GitStatus {
        branch: "main".into(),
        dirty: Some(false),
    };
    let log = final_cache_capture(|| {
        for _ in 0..2 {
            write_git_cache_with(
                dir.path(),
                "collision".into(),
                1,
                &status,
                &|tmp, _| {
                    std::fs::write(tmp, b"theirs").unwrap();
                    paths.borrow_mut().push(tmp.to_path_buf());
                    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
                },
                &|tag| {
                    tags.borrow_mut().push(tag);
                    warn_git_cache_failure_once(tag);
                },
            );
        }
    });
    for path in paths.borrow().iter() {
        assert_eq!(std::fs::read(path).unwrap(), b"theirs");
    }
    assert_eq!(
        *tags.borrow(),
        ["git_cache_tmp_exists", "git_cache_tmp_exists"]
    );
    assert_eq!(
        log.lines().count(),
        2,
        "each expected collision has a DEBUG diagnostic: {log}"
    );
    assert!(log
        .lines()
        .all(|line| line.contains("DEBUG") && line.contains("git_cache_tmp_exists")));
    assert!(!log.contains("WARN") && !log.contains("git_cache_tmp_missing"));
}

#[test]
fn final_cache_future_observation_beyond_grace_is_stale_despite_future_mtime() {
    let dir = sweep_root();
    let now = SystemTime::now();
    let millis = now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    for (name, modified) in [
        ("0123456789abcdef.json", now - Duration::from_secs(120)),
        ("fedcba9876543210.json", now + Duration::from_secs(120)),
    ] {
        let path = tmp_file(dir.path(), name, Duration::ZERO, 0o600);
        std::fs::write(&path, record_json(millis + 300_001)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }
    sweep_git_cache_tmp(dir.path(), now, None);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "future observations beyond five minutes are stale irrespective of mtime"
    );
}

#[test]
fn final_cache_future_observation_through_five_minute_grace_is_kept() {
    let dir = sweep_root();
    let now = SystemTime::now();
    let millis = now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    for (n, delta) in [1, 300_000].into_iter().enumerate() {
        let path = tmp_file(dir.path(), &format!("{n:016x}.json"), Duration::ZERO, 0o600);
        std::fs::write(&path, record_json(millis + delta)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now - Duration::from_secs(120))
            .unwrap();
    }
    sweep_git_cache_tmp(dir.path(), now, None);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        2,
        "inclusive five-minute grace never falls back to stale mtime"
    );
}

#[test]
fn final_cache_future_prefix_and_old_record_reclaim_within_five_bounded_sweeps() {
    let dir = sweep_root();
    let now = SystemTime::now();
    let millis = now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    for n in 0..65 {
        let path = tmp_file(dir.path(), &format!("{n:016x}.json"), Duration::ZERO, 0o600);
        std::fs::write(&path, record_json(u64::MAX)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now + Duration::from_secs(86_400))
            .unwrap();
    }
    // Assign the old record to the last actual readdir entry. No name is
    // changed after this read; the first admitted prefix is 64 future records.
    let order: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(order.len(), 65);
    let old = order.last().unwrap();
    std::fs::write(old, record_json(millis - 120_000)).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(old)
        .unwrap()
        .set_modified(now - Duration::from_secs(120))
        .unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>(),
        order,
        "fixture entry order must be observed, not assumed"
    );
    for pass in 0..5 {
        let before = std::fs::read_dir(dir.path()).unwrap().count();
        let reads = std::cell::Cell::new(0);
        let first_names = std::cell::RefCell::new(Vec::new());
        let scanned = sweep_git_cache_entries(
            dir.path(),
            now,
            None,
            &|fd, name| {
                reads.set(reads.get() + 1);
                first_names.borrow_mut().push(name.to_bytes().to_vec());
                git_cache_record_observed(fd, name)
            },
            &|_| {},
            &|tag| panic!("unexpected sweep diagnostic: {tag}"),
        );
        let after = std::fs::read_dir(dir.path()).unwrap().count();
        assert!(
            scanned <= 1024 && reads.get() <= 64 && before - after <= 16,
            "unchanged per-sweep scan/read/remove caps"
        );
        assert!(
            before == 0 || after < before,
            "strictly positive progress while removable entries remain"
        );
        if pass == 0 {
            assert!(
                first_names
                    .borrow()
                    .iter()
                    .all(|name| name.as_slice() != old.file_name().unwrap().as_encoded_bytes()),
                "the old entry starts behind the future-record read prefix"
            );
        }
    }
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "ceil(65/16)=5 sweeps reclaim the future prefix and old tail without raising caps"
    );
}
