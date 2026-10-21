//! Explicit per-repository Gate opt-in; absent opt-in/pin preserves native hooks.
//! Configuration and composed launch settings live outside the repository.
use anyhow::{anyhow, bail, Result};
use clap::Args;
use csq_core::gate::{legacy::VerifiedPackage, pin::Pin, registry::Event};
use csq_core::platform::fs::{atomic_replace, unique_tmp_path, write_new_private_synced};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File};
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Args)]
pub struct GateEnableArgs {
    #[arg(long)]
    pub repo: PathBuf,
    #[arg(long)]
    pub pin: PathBuf,
    #[arg(long)]
    pub adapter_manifest: PathBuf,
    /// Independently reviewed raw adapter manifest digest, never self-enrolled.
    #[arg(long)]
    pub expected_adapter_sha256: String,
}

#[derive(Debug, Args)]
pub struct GateDisableArgs {
    #[arg(long)]
    pub repo: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    version: u32,
    repo: PathBuf,
    pin: PathBuf,
    adapter_manifest: PathBuf,
    expected_adapter_sha256: String,
}

fn digest_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(unix)]
fn directory(base: &Path, repo: &Path, create: bool) -> Result<Option<PathBuf>> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let base = base
        .canonicalize()
        .map_err(|_| anyhow!("gate state unavailable"))?;
    let repo = repo
        .canonicalize()
        .map_err(|_| anyhow!("gate repository unavailable"))?;
    let base_meta = fs::metadata(&base).map_err(|_| anyhow!("gate state unavailable"))?;
    // SAFETY: geteuid has no memory-safety preconditions.
    if !base_meta.is_dir()
        || base_meta.uid() != unsafe { libc::geteuid() }
        || base_meta.permissions().mode() & 0o022 != 0
    {
        bail!("gate state parent is not owner controlled");
    }
    let dir = base.join("gate");
    let meta = match fs::symlink_metadata(&dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            if base.starts_with(&repo) {
                bail!("gate state must be outside the repository");
            }
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|_| anyhow!("gate state unavailable"))?;
            fs::symlink_metadata(&dir).map_err(|_| anyhow!("gate state unavailable"))?
        }
        Err(_) => bail!("gate state unavailable"),
    };
    if base.starts_with(&repo) {
        bail!("gate state must be outside the repository");
    }
    // SAFETY: geteuid has no memory-safety preconditions.
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        bail!("gate state is not private");
    }
    Ok(Some(dir))
}

#[cfg(not(unix))]
fn directory(base: &Path, _: &Path, create: bool) -> Result<Option<PathBuf>> {
    if !create && !base.join("gate").exists() {
        Ok(None)
    } else {
        bail!("gate activation is unsupported on this platform")
    }
}

fn config_path(dir: &Path, repo: &Path) -> PathBuf {
    dir.join(format!(
        "{}.json",
        csq_core::gate::registry::sha256(repo.as_os_str().as_encoded_bytes())
    ))
}

fn repository(cwd: &Path) -> Result<PathBuf> {
    for ancestor in cwd.ancestors() {
        match fs::symlink_metadata(ancestor.join(".git")) {
            Ok(meta) if meta.file_type().is_symlink() => bail!("gate repository alias unsupported"),
            Ok(meta) if meta.is_file() || meta.is_dir() => return Ok(ancestor.to_owned()),
            Ok(_) => bail!("gate repository metadata unsupported"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("gate repository metadata unavailable"),
        }
    }
    Ok(cwd.to_owned())
}

#[cfg(unix)]
fn read_private(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("gate configuration unreadable"),
    };
    let meta = file
        .metadata()
        .map_err(|_| anyhow!("gate configuration unreadable"))?;
    // SAFETY: geteuid has no memory-safety preconditions.
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        bail!("gate configuration is not private");
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("gate configuration unreadable"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        bail!("gate configuration exceeds admission limit");
    }
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn read_private(_: &Path) -> Result<Option<Vec<u8>>> {
    bail!("gate activation is unsupported on this platform")
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = unique_tmp_path(path);
    // A failed exclusive creation confers no authority to delete a collision.
    write_new_private_synced(&tmp, bytes).map_err(|_| anyhow!("gate state write failed"))?;
    if atomic_replace(&tmp, path).is_err() {
        let _ = fs::remove_file(&tmp);
        bail!("gate state install failed");
    }
    File::open(
        path.parent()
            .ok_or_else(|| anyhow!("gate state unavailable"))?,
    )
    .and_then(|dir| dir.sync_all())
    .map_err(|_| anyhow!("gate state durability unverified"))?;
    Ok(())
}

fn validate_metadata(activation: &Activation) -> Result<()> {
    if activation.version != 1
        || !digest_is_valid(&activation.expected_adapter_sha256)
        || !activation.repo.is_absolute()
        || !activation.pin.is_absolute()
        || !activation.adapter_manifest.is_absolute()
    {
        bail!("gate activation anchor invalid");
    }
    Ok(())
}

fn pin_present(path: &Path) -> Result<bool> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("gate pin namespace refused"))?;
    let meta = fs::symlink_metadata(parent).map_err(|_| anyhow!("gate pin namespace refused"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        bail!("gate pin namespace refused");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no memory-safety preconditions.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            bail!("gate pin namespace refused");
        }
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("gate pin is not a regular file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => bail!("gate pin availability refused"),
    }
}

fn validate(activation: &Activation) -> Result<csq_core::gate::pin::VerifiedRegistry> {
    validate_metadata(activation)?;
    let verified = Pin::load_verify(&activation.pin, &activation.repo)
        .map_err(|_| anyhow!("gate registry admission refused"))?;
    if verified.rows.iter().any(|row| row.admission.is_err()) {
        bail!("gate registry row admission refused");
    }
    let package = VerifiedPackage::verify(&activation.adapter_manifest, &activation.repo)
        .map_err(|_| anyhow!("gate adapter admission refused"))?;
    if package.manifest_sha256() != activation.expected_adapter_sha256 {
        bail!("gate adapter anchor differs");
    }
    Ok(verified)
}

pub fn handle_enable(base: &Path, args: &GateEnableArgs, json_output: bool) -> Result<i32> {
    let repo = repository(
        &args
            .repo
            .canonicalize()
            .map_err(|_| anyhow!("gate repository unavailable"))?,
    )?;
    let activation = Activation {
        version: 1,
        repo: repo.clone(),
        pin: absolute(&args.pin)?,
        adapter_manifest: absolute(&args.adapter_manifest)?,
        expected_adapter_sha256: args.expected_adapter_sha256.clone(),
    };
    validate(&activation)?;
    let dir = directory(base, &repo, true)?.ok_or_else(|| anyhow!("gate state unavailable"))?;
    write_private(&config_path(&dir, &repo), &serde_json::to_vec(&activation)?)?;
    if json_output {
        println!("{}", json!({"gate":"enabled","scope":"one_repo"}));
    } else {
        println!("Gate opted in for one repository; launch admission still required");
    }
    Ok(0)
}

pub fn handle_disable(base: &Path, args: &GateDisableArgs, json_output: bool) -> Result<i32> {
    let repo = repository(
        &args
            .repo
            .canonicalize()
            .map_err(|_| anyhow!("gate repository unavailable"))?,
    )?;
    if let Some(dir) = directory(base, &repo, false)? {
        let path = config_path(&dir, &repo);
        // Validate any existing entry before authorizing its removal.
        if read_private(&path)?.is_some() {
            fs::remove_file(&path).map_err(|_| anyhow!("gate state removal failed"))?;
            File::open(&dir)
                .and_then(|file| file.sync_all())
                .map_err(|_| anyhow!("gate state durability unverified"))?;
        }
    }
    if json_output {
        println!("{}", json!({"gate":"disabled","scope":"one_repo"}));
    } else {
        println!("Gate opt-in removed for one repository");
    }
    Ok(0)
}

/// Attach before passthrough arguments. No opt-in or missing pin leaves argv untouched.
pub(super) fn attach(cmd: &mut Command, base: &Path, handle: &Path, rest: &[String]) -> Result<()> {
    let repo = std::env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|_| anyhow!("gate launch directory unavailable"))?;
    let repo = repository(&repo)?;
    attach_in_repo(cmd, base, handle, rest, &repo)
}

fn attach_in_repo(
    cmd: &mut Command,
    base: &Path,
    handle: &Path,
    rest: &[String],
    repo: &Path,
) -> Result<()> {
    let Some(dir) = directory(base, repo, false)? else {
        return Ok(());
    };
    let Some(bytes) = read_private(&config_path(&dir, repo))? else {
        return Ok(());
    };
    let activation: Activation = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("gate activation configuration invalid"))?;
    if activation.repo != repo {
        bail!("gate activation repository differs");
    }
    validate_metadata(&activation)?;
    if !pin_present(&activation.pin)? {
        eprintln!("csq: Gate pin absent; retaining original native hook registration");
        return Ok(());
    }
    if rest.iter().any(|arg| {
        arg == "--settings"
            || arg == "--setting-sources"
            || arg.starts_with("--settings=")
            || arg.starts_with("--setting-sources=")
            || arg == "-C"
            || arg == "--add-dir"
            || arg.starts_with("--add-dir=")
    }) {
        bail!("gate launch settings or directory override unsupported");
    }
    let verified = validate(&activation)?;
    let mut settings = super::gate_compose::compose(repo, handle, &verified)?;
    let binary = std::env::current_exe().map_err(|_| anyhow!("gate executable unavailable"))?;
    let mut hooks = serde_json::Map::new();
    for event in Event::ALL {
        let command = dispatch_command(&binary, &activation, event)?;
        hooks.insert(
            event.as_str().into(),
            json!([{"hooks":[{
                "type":"command", "command":command,
                "timeout":if event == Event::SessionEnd {1.5} else {10.0}
            }]}]),
        );
    }
    settings
        .as_object_mut()
        .ok_or_else(|| anyhow!("gate settings invalid"))?
        .insert("hooks".into(), Value::Object(hooks));
    let path = dir.join(format!(
        "settings-{}-{}.json",
        csq_core::gate::registry::sha256(repo.as_os_str().as_encoded_bytes()),
        std::process::id()
    ));
    write_private(&path, &serde_json::to_vec(&settings)?)?;
    cmd.args(["--setting-sources", "user", "--settings"])
        .arg(path);
    Ok(())
}

fn dispatch_command(binary: &Path, activation: &Activation, event: Event) -> Result<String> {
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
    let path = |path: &Path| {
        path.to_str()
            .map(quote)
            .ok_or_else(|| anyhow!("gate launch path is not Unicode"))
    };
    Ok(format!(
        "{} gate dispatch {} --repo {} --pin {} --adapter-manifest {} --expected-adapter-sha256 {}",
        path(binary)?,
        event.as_str(),
        path(&activation.repo)?,
        path(&activation.pin)?,
        path(&activation.adapter_manifest)?,
        quote(&activation.expected_adapter_sha256)
    ))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|_| anyhow!("gate launch directory unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_opt_in_leaves_argv_untouched_and_creates_nothing() {
        let base = tempfile::tempdir().unwrap();
        let mut cmd = Command::new("claude");
        cmd.arg("--verbose");
        attach(&mut cmd, base.path(), base.path(), &[]).unwrap();
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["--verbose"]);
        assert!(!base.path().join("gate").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_opt_in_namespace_is_refused_without_following_it() {
        let base = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(other.path(), base.path().join("gate")).unwrap();
        let mut cmd = Command::new("claude");
        assert!(attach(&mut cmd, base.path(), base.path(), &[]).is_err());
        assert_eq!(fs::read_dir(other.path()).unwrap().count(), 0);
        assert_eq!(cmd.get_args().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn writable_state_parent_refuses_before_creating_an_opt_in_namespace() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(directory(base.path(), repo.path(), true).is_err());
        assert!(!base.path().join("gate").exists());
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn repository_local_base_without_opt_in_preserves_native_launch() {
        let repo = tempfile::tempdir().unwrap();
        let base = repo.path().join("state");
        fs::create_dir(&base).unwrap();
        let mut cmd = Command::new("claude");
        cmd.arg("--verbose");
        attach_in_repo(&mut cmd, &base, &base, &[], repo.path()).unwrap();
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["--verbose"]);
        assert!(!base.join("gate").exists());
        assert!(directory(&base, repo.path(), true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_pin_refuses_instead_of_silently_restoring_native_hooks() {
        let base = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let pin = base.path().join("pin");
        std::os::unix::fs::symlink(base.path().join("missing"), &pin).unwrap();
        let activation = Activation {
            version: 1,
            repo: repo.path().to_owned(),
            pin,
            adapter_manifest: base.path().join("manifest"),
            expected_adapter_sha256: "a".repeat(64),
        };
        let dir = directory(base.path(), repo.path(), true).unwrap().unwrap();
        write_private(
            &config_path(&dir, repo.path()),
            &serde_json::to_vec(&activation).unwrap(),
        )
        .unwrap();
        let before = fs::read_dir(&dir).unwrap().count();
        let mut cmd = Command::new("claude");
        assert!(attach_in_repo(&mut cmd, base.path(), base.path(), &[], repo.path()).is_err());
        assert_eq!(cmd.get_args().count(), 0);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), before);
    }

    #[cfg(unix)]
    #[test]
    fn only_valid_metadata_with_authoritatively_missing_pin_preserves_native_launch() {
        let base = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let mut activation = Activation {
            version: 1,
            repo: repo.path().to_owned(),
            pin: base.path().join("missing"),
            adapter_manifest: base.path().join("manifest"),
            expected_adapter_sha256: "a".repeat(64),
        };
        let dir = directory(base.path(), repo.path(), true).unwrap().unwrap();
        let path = config_path(&dir, repo.path());
        write_private(&path, &serde_json::to_vec(&activation).unwrap()).unwrap();
        let mut cmd = Command::new("claude");
        cmd.arg("--verbose");
        attach_in_repo(&mut cmd, base.path(), base.path(), &[], repo.path()).unwrap();
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["--verbose"]);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        for invalid in 0..3 {
            activation.version = if invalid == 0 { 2 } else { 1 };
            activation.expected_adapter_sha256 = if invalid == 1 {
                "invalid".into()
            } else {
                "a".repeat(64)
            };
            activation.pin = if invalid == 2 {
                PathBuf::from("relative-missing")
            } else {
                base.path().join("missing")
            };
            write_private(&path, &serde_json::to_vec(&activation).unwrap()).unwrap();
            assert!(attach_in_repo(&mut cmd, base.path(), base.path(), &[], repo.path()).is_err());
            assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["--verbose"]);
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        }
    }
    #[cfg(unix)]
    #[test]
    fn absent_pin_in_aliased_or_non_directory_parent_refuses_without_effects() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        std::os::unix::fs::symlink(temp.path().join("missing"), &parent).unwrap();
        assert!(pin_present(&parent.join("pin")).is_err());
        assert!(fs::symlink_metadata(&parent)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!temp.path().join("missing").exists());
        fs::remove_file(&parent).unwrap();
        fs::write(&parent, b"sentinel").unwrap();
        assert!(pin_present(&parent.join("pin")).is_err());
        assert_eq!(fs::read(&parent).unwrap(), b"sentinel");
    }
    #[cfg(unix)]
    #[test]
    fn reviewed_opt_in_attaches_composed_native_settings_and_disable_restores_original_launch() {
        let _env = csq_core::platform::test_env::lock();
        let (temp, args, _) = super::super::gate_dispatch::tests::node_decision_fixture(true);
        let repo = args.repo.canonicalize().unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        let base = temp.path().join("state");
        let handle = temp.path().join("handle");
        fs::create_dir(&base).unwrap();
        fs::create_dir(&handle).unwrap();
        let mut original = json!({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"node .claude/hooks/decision.js","timeout":super::super::gate_dispatch::tests::FIXTURE_ROW_TIMEOUT_SECS}]}]}, "permissions":{"allow":["Bash"],"deny":["Bash(rm *)"]}});
        // Native settings must independently register every authenticated row,
        // including rows whose matchers do not select the current tool.
        for (matcher, name) in [("Edit", "skipped"), ("Read", "unmatched")] {
            original["hooks"]["PreToolUse"]
                .as_array_mut()
                .unwrap()
                .push(json!({"matcher":matcher,"hooks":[{"type":"command",
                    "command":format!("node .claude/hooks/{name}.js"),"timeout":super::super::gate_dispatch::tests::FIXTURE_ROW_TIMEOUT_SECS}]}));
        }
        let original_bytes = serde_json::to_vec(&original).unwrap();
        fs::write(repo.join(".claude/settings.json"), &original_bytes).unwrap();
        let key = csq_core::session::workspace_trust::native_key(&repo).unwrap();
        let trust =
            serde_json::to_vec(&json!({"projects":{key:{"hasTrustDialogAccepted":true}}})).unwrap();
        fs::write(handle.join(".claude.json"), &trust).unwrap();
        let enable = GateEnableArgs {
            repo: repo.clone(),
            pin: args.pin.clone(),
            adapter_manifest: args.adapter_manifest,
            expected_adapter_sha256: args.expected_adapter_sha256,
        };
        assert_eq!(handle_enable(&base, &enable, false).unwrap(), 0);
        let mut incomplete = original.clone();
        incomplete["hooks"]["PreToolUse"]
            .as_array_mut()
            .unwrap()
            .pop();
        fs::write(
            repo.join(".claude/settings.json"),
            serde_json::to_vec(&incomplete).unwrap(),
        )
        .unwrap();
        let before_admission = fs::read_dir(base.join("gate")).unwrap().count();
        let mut refused = Command::new("claude");
        assert!(attach_in_repo(&mut refused, &base, &handle, &[], &repo).is_err());
        assert_eq!(refused.get_args().count(), 0);
        assert_eq!(
            fs::read_dir(base.join("gate")).unwrap().count(),
            before_admission
        );
        fs::write(repo.join(".claude/settings.json"), &original_bytes).unwrap();
        let mut cmd = Command::new("claude");
        attach_in_repo(&mut cmd, &base, &handle, &[], &repo).unwrap();
        let argv = cmd.get_args().collect::<Vec<_>>();
        assert_eq!(&argv[..3], ["--setting-sources", "user", "--settings"]);
        assert_eq!(argv.len(), 4);
        let composed: Value =
            serde_json::from_slice(&fs::read(Path::new(argv[3])).unwrap()).unwrap();
        assert_eq!(composed["permissions"], original["permissions"]);
        assert_eq!(
            composed["hooks"].as_object().unwrap().len(),
            Event::ALL.len()
        );
        assert!(composed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains(" gate dispatch PreToolUse --repo "));
        let before = fs::read_dir(base.join("gate")).unwrap().count();
        let mut override_cmd = Command::new("claude");
        assert!(attach_in_repo(
            &mut override_cmd,
            &base,
            &handle,
            &["--settings=unreviewed.json".into()],
            &repo
        )
        .is_err());
        assert_eq!(override_cmd.get_args().count(), 0);
        assert_eq!(fs::read_dir(base.join("gate")).unwrap().count(), before);
        let other = temp.path().join("other-repo");
        fs::create_dir(&other).unwrap();
        let mut other_cmd = Command::new("claude");
        attach_in_repo(&mut other_cmd, &base, &handle, &[], &other).unwrap();
        assert_eq!(other_cmd.get_args().count(), 0);
        // Registry mutation refuses before touching argv or launch settings.
        let registry_path = repo.join(csq_core::gate::pin::MANIFEST_FILE);
        let registry_bytes = fs::read(&registry_path).unwrap();
        fs::write(&registry_path, b"{}").unwrap();
        let mut tampered = Command::new("claude");
        assert!(attach_in_repo(&mut tampered, &base, &handle, &[], &repo).is_err());
        assert_eq!(tampered.get_args().count(), 0);
        assert_eq!(fs::read_dir(base.join("gate")).unwrap().count(), before);
        fs::write(&registry_path, &registry_bytes).unwrap();
        assert_eq!(
            handle_disable(&base, &GateDisableArgs { repo: repo.clone() }, false).unwrap(),
            0
        );
        let mut disabled = Command::new("claude");
        attach_in_repo(&mut disabled, &base, &handle, &[], &repo).unwrap();
        assert_eq!(disabled.get_args().count(), 0);
        assert_eq!(
            fs::read(repo.join(".claude/settings.json")).unwrap(),
            original_bytes
        );
        assert_eq!(fs::read(handle.join(".claude.json")).unwrap(), trust);
    }
}
