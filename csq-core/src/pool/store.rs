use super::{
    env_file, types, KeySource, PoolEntry, PoolError, PoolName, PoolRow, Reset, RestartRecovery,
    Result,
};
use crate::platform::{
    fs, lock,
    secret::{self, NamedKey, Vault},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    entry: PoolEntry,
    secret_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remove_backup_id: Option<String>,
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    env_file: Option<PathBuf>,
    entries: Vec<StoredEntry>,
}
impl Manifest {
    fn empty() -> Self {
        Self {
            version: 1,
            ..Self::default()
        }
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.entries.len() > MAX_ENTRIES
            || self.env_file.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return Err(PoolError::ManifestInvalid);
        }
        let mut names = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        for row in &self.entries {
            row.entry.validate()?;
            if !names.insert(row.entry.name.as_str()) {
                return Err(PoolError::ManifestInvalid);
            }
            if let Some(generation) = &row.generation {
                validate_id(generation)?;
            }
            if let Some(backup) = &row.remove_backup_id {
                validate_id(backup)?;
                if row.entry.source != KeySource::SecretStore || !ids.insert(backup) {
                    return Err(PoolError::ManifestInvalid);
                }
            }
            match (&row.entry.source, &row.secret_id) {
                (KeySource::EnvFile, None) if self.env_file.is_some() => (),
                (KeySource::SecretStore, Some(id)) => {
                    validate_id(id)?;
                    if !ids.insert(id) {
                        return Err(PoolError::ManifestInvalid);
                    }
                }
                _ => return Err(PoolError::ManifestInvalid),
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Journal {
    Add {
        row: StoredEntry,
        recovery_safe: bool,
        backend_id: String,
        writer: Writer,
    },
    Remove {
        row: StoredEntry,
        #[serde(default)]
        phase: Option<RemovePhase>,
        backup_id: String,
        recovery_safe: bool,
        backend_id: String,
        writer: Writer,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RemovePhase {
    BackupWrite,
    OriginalDelete,
}

/// Never expires: native service requests may outlive their submitting process.
/// Only explicit recovery re-deletes these unreferenced ids; metadata keeps custody.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupTombstones {
    #[serde(default)]
    boot: Option<BootStamp>,
    backend_id: String,
    ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Writer {
    #[serde(default)]
    boot: Option<BootStamp>,
    pid: u32,
    started_at: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootStamp {
    identity: String,
    started_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uptime_ms: Option<u64>,
}
#[cfg(test)]
thread_local! { static TEST_BOOT: std::cell::RefCell<Option<Option<BootStamp>>> = const { std::cell::RefCell::new(None) }; }
fn current_boot() -> Option<BootStamp> {
    #[cfg(test)]
    if let Some(value) = TEST_BOOT.with(|x| x.borrow().clone()) {
        return value;
    }
    #[cfg(target_os = "linux")]
    {
        let identity = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let uuid = uuid::Uuid::parse_str(identity.trim()).ok()?;
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let started_at = stat
            .lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .parse()
            .ok()?;
        Some(BootStamp {
            identity: format!("linux:{uuid}"),
            started_at,
            uptime_ms: None,
        })
    }
    #[cfg(target_os = "macos")]
    {
        let time = crate::sessions::lifecycle_records::boot()?;
        let started_at = time.split(':').nth(1)?.parse().ok()?;
        let mut bytes = [0u8; 128];
        let mut length = bytes.len();
        // SAFETY: fixed writable buffer/valid size pointer, read-only sysctl. Failure,
        // truncation or invalid UUID never establishes a new kernel boot session.
        let result = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || length == 0 || length > bytes.len() {
            return None;
        }
        let uuid = uuid::Uuid::parse_str(
            std::str::from_utf8(&bytes[..length])
                .ok()?
                .trim_end_matches('\0'),
        )
        .ok()?;
        Some(BootStamp {
            identity: format!("macos-session:{uuid}"),
            started_at,
            uptime_ms: None,
        })
    }
    #[cfg(windows)]
    {
        let mut boot = windows_boot_output().and_then(|output| parse_windows_boot(&output))?;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }
        // SAFETY: documented monotonic uptime API takes no arguments/pointers.
        boot.uptime_ms = Some(unsafe { GetTickCount64() });
        Some(boot)
    }
}
#[cfg(any(windows, test))]
fn parse_windows_boot(output: &[u8]) -> Option<BootStamp> {
    const UNIX_EPOCH_TICKS: u64 = 621355968000000000;
    if output.len() > 64 {
        return None;
    }
    let value = std::str::from_utf8(output).ok()?.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ticks = value.parse::<u64>().ok()?;
    let started_at = ticks.checked_sub(UNIX_EPOCH_TICKS)? / 10000000;
    if started_at == 0 {
        return None;
    }
    Some(BootStamp {
        identity: format!("windows-cim:{ticks}"),
        started_at,
        uptime_ms: None,
    })
}
#[cfg(windows)]
fn windows_boot_output() -> Option<Vec<u8>> {
    use std::{
        io::Read,
        os::windows::{ffi::OsStringExt, process::CommandExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut directory = [0u16; 32768];
    // SAFETY: writable initialized UTF-16 buffer with its exact capacity. Missing,
    // truncated or nonabsolute system paths cannot select an executable.
    let count =
        unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if count == 0 || count >= directory.len() {
        return None;
    }
    let system = PathBuf::from(std::ffi::OsString::from_wide(&directory[..count]));
    if !system.is_absolute() {
        return None;
    }
    let windows = system.parent()?;
    let executable = system.join("WindowsPowerShell/v1.0/powershell.exe");
    // Read-only supported WMI property; no credential operations, PATH lookup, user
    // profiles, wall-clock-minus-uptime inference, or opaque NT structure offsets.
    // Microsoft: /windows/win32/cimwin32prov/win32-operatingsystem LastBootUpTime.
    let mut child=Command::new(executable).env_clear().env("SystemRoot",windows).env("windir",windows)
        .args(["-NoLogo","-NoProfile","-NonInteractive","-Command",
            "$ErrorActionPreference='Stop';$b=(Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime).LastBootUpTime.ToUniversalTime();[Console]::Write($b.Ticks.ToString([Globalization.CultureInfo]::InvariantCulture))"])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).creation_flags(0x08000000).spawn().ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    }?;
    if !status.success() {
        return None;
    }
    let mut output = Vec::with_capacity(65);
    child
        .stdout
        .take()?
        .take(65)
        .read_to_end(&mut output)
        .ok()?;
    if output.len() > 64 {
        return None;
    }
    Some(output)
}
fn boot_is_advanced(old: &BootStamp, current: &BootStamp) -> bool {
    let namespace = current.identity.split(':').next();
    if old.identity.is_empty()
        || old.identity.len() > 128
        || old.identity.split(':').next() != namespace
        || old.identity == current.identity
    {
        return false;
    }
    match namespace {
        // Kernel boot-session UUIDs cannot change within one boot. Wall time is metadata,
        // not authority: a real restart can occur after the system clock moved backwards.
        Some("linux" | "macos-session") => {
            let valid = |stamp: &BootStamp| {
                stamp
                    .identity
                    .split_once(':')
                    .and_then(|(_, id)| uuid::Uuid::parse_str(id).ok())
                    .is_some_and(|id| !id.is_nil())
            };
            valid(old) && valid(current)
        }
        Some("windows-cim") => {
            let valid = |stamp: &BootStamp| {
                stamp
                    .identity
                    .strip_prefix("windows-cim:")
                    .and_then(|ticks| ticks.parse::<u64>().ok())
                    .and_then(|ticks| ticks.checked_sub(621355968000000000))
                    .is_some_and(|ticks| {
                        ticks / 10000000 > 0 && ticks / 10000000 == stamp.started_at
                    })
            };
            valid(old)
                && valid(current)
                && old
                    .uptime_ms
                    .zip(current.uptime_ms)
                    .is_some_and(|(old, current)| current < old)
        }
        // Isolated injected fixtures retain explicit chronology; no unknown native
        // identity scheme can establish production reboot proof.
        #[cfg(test)]
        Some("fixture") => old.started_at > 0 && old.started_at < current.started_at,
        _ => false,
    }
}
fn boot_advanced(previous: Option<&BootStamp>) -> bool {
    previous
        .zip(current_boot())
        .is_some_and(|(old, current)| boot_is_advanced(old, &current))
}

impl Writer {
    fn current() -> Self {
        let pid = std::process::id();
        Self {
            boot: current_boot(),
            pid,
            started_at: writer_start(pid),
        }
    }
    fn possibly_alive(&self) -> bool {
        self.possibly_alive_with(writer_alive, writer_start)
    }
    fn possibly_alive_with(
        &self,
        alive: impl FnOnce(u32) -> bool,
        start: impl FnOnce(u32) -> Option<String>,
    ) -> bool {
        if !alive(self.pid) {
            return false;
        }
        match (&self.started_at, start(self.pid)) {
            (Some(expected), Some(actual)) => {
                match (expected.parse::<u64>(), actual.parse::<u64>()) {
                    (Ok(expected), Ok(actual)) => crate::sessions::same_start(expected, actual),
                    // Legacy nonnumeric start records do not establish a safe PID-reuse proof.
                    _ => true,
                }
            }
            _ => true,
        }
    }
}
fn writer_start(pid: u32) -> Option<String> {
    crate::sessions::process_start_time(pid).map(|start| start.to_string())
}
#[cfg(not(windows))]
fn writer_alive(pid: u32) -> bool {
    crate::platform::process::is_pid_alive(pid)
}
#[cfg(windows)]
fn writer_alive(pid: u32) -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_INVALID_PARAMETER},
        System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    // SAFETY: no pointers are passed. OpenProcess returns zero on failure.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle == 0 {
        // Permission/query failures are unknown, never evidence that a writer is dead.
        // SAFETY: GetLastError has no preconditions.
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    let mut code = 0;
    // SAFETY: handle is valid, code is a valid writable stack value, and this owns handle.
    let known = unsafe { GetExitCodeProcess(handle, &mut code) } != 0;
    // SAFETY: this closes the valid handle exactly once after the query.
    unsafe {
        CloseHandle(handle);
    }
    !known || code == 259 // STILL_ACTIVE
}

fn uncertain(error: &secret::SecretError) -> bool {
    matches!(
        error,
        secret::SecretError::Timeout | secret::SecretError::NamedOutcomeUnknown
    )
}

fn validate_id(id: &str) -> Result<()> {
    if id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(PoolError::ManifestInvalid)
    }
}
fn fresh_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn key(id: &str) -> Result<NamedKey> {
    validate_id(id)?;
    NamedKey::pool(id).map_err(|_| PoolError::ManifestInvalid)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let body = serde_json::to_vec_pretty(value).map_err(|_| PoolError::ManifestInvalid)?;
    let tmp = fs::unique_tmp_path(path);
    let result = fs::write_new_private_synced(&tmp, &body)
        .and_then(|()| fs::secure_file(&tmp))
        .and_then(|()| fs::atomic_replace(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(PoolError::MutationRefused);
    }
    Ok(())
}

/// Backend-owned confirmation metadata and an opaque nonsecret admission identity.
#[derive(Clone, Debug)]
pub struct RemovalSnapshot {
    pub entry: PoolEntry,
    row: StoredEntry,
    env_file: Option<PathBuf>,
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static DEFAULT_TEST_VAULT: std::cell::RefCell<Option<std::sync::Arc<dyn Vault>>> = const { std::cell::RefCell::new(None) };
}

/// Pool custody service. A pool-scoped lock serializes reads, mutations and recovery.
/// The vault is opened lazily, so an env-file-only pool needs no native credential access.
pub struct Pool {
    root: PathBuf,
    vault: Option<Box<dyn Vault>>,
}
impl Pool {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            root: base_dir.join("pool"),
            vault: None,
        }
    }
    /// Explicit backend injection for embedding and isolated file-backed tests.
    pub fn with_vault(base_dir: &Path, vault: Box<dyn Vault>) -> Self {
        Self {
            root: base_dir.join("pool"),
            vault: Some(vault),
        }
    }
    /// Same-thread fixture override compiled only for tests/test-utils.
    /// Spawned workers do not inherit it; this seam grants no native permissions.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_default_vault_for_test<T>(
        vault: std::sync::Arc<dyn Vault>,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<std::sync::Arc<dyn Vault>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                DEFAULT_TEST_VAULT.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(DEFAULT_TEST_VAULT.with(|slot| slot.borrow_mut().replace(vault)));
        operation()
    }
    fn with_store<T>(&self, operation: impl FnOnce(&dyn Vault) -> Result<T>) -> Result<T> {
        if let Some(vault) = &self.vault {
            return operation(vault.as_ref());
        }
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(vault) = DEFAULT_TEST_VAULT.with(|slot| slot.borrow().clone()) {
            return operation(vault.as_ref());
        }
        #[cfg(target_os = "linux")]
        if std::env::var("CSQ_SECRET_BACKEND").as_deref() == Ok("file") {
            let vault = secret::file::FileVault::open(&self.root)
                .map_err(|_| PoolError::StoreUnavailable)?;
            return operation(&vault);
        }
        let vault = secret::open_default_vault().map_err(|_| PoolError::StoreUnavailable)?;
        operation(vault.as_ref())
    }
    fn custody(&self) -> Result<lock::FileLockGuard> {
        match std::fs::symlink_metadata(&self.root) {
            Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
                return Err(PoolError::ManifestUnavailable)
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&self.root).map_err(|_| PoolError::ManifestUnavailable)?;
            }
            Err(_) => return Err(PoolError::ManifestUnavailable),
        }
        fs::secure_dir(&self.root).map_err(|_| PoolError::ManifestUnavailable)?;
        lock::try_lock_file_bounded_nofollow(&self.root.join(".lock"), 1, std::time::Duration::ZERO)
            .map_err(|_| PoolError::ManifestUnavailable)?
            .ok_or(PoolError::Busy)
    }
    fn load(&self) -> Result<Manifest> {
        let Some(bytes) =
            fs::read_regular_nofollow_bounded(&self.root.join("manifest.json"), MAX_MANIFEST_BYTES)
                .map_err(|_| PoolError::ManifestUnavailable)?
        else {
            return Ok(Manifest::empty());
        };
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| PoolError::ManifestInvalid)?;
        manifest
            .validate()
            .map_err(|_| PoolError::ManifestInvalid)?;
        Ok(manifest)
    }
    fn save(&self, manifest: &Manifest) -> Result<()> {
        manifest.validate()?;
        write_json(&self.root.join("manifest.json"), manifest)
    }
    fn mark_unknown(&self, mut journal: Journal) -> Result<()> {
        match &mut journal {
            Journal::Add { recovery_safe, .. } | Journal::Remove { recovery_safe, .. } => {
                *recovery_safe = false
            }
        }
        write_json(&self.root.join("transaction.json"), &journal)?;
        Err(PoolError::RecoveryRequired)
    }
    fn clear_journal(&self) -> Result<()> {
        std::fs::remove_file(self.root.join("transaction.json"))
            .map_err(|_| PoolError::RecoveryRequired)
    }
    /// Recovery observes the committed manifest, never a guessed operation outcome.
    /// Until compensation finishes, every public operation refuses to expose pool state.
    fn recover(&self, manifest: &Manifest) -> Result<()> {
        let Some(bytes) = fs::read_regular_nofollow_bounded(
            &self.root.join("transaction.json"),
            MAX_MANIFEST_BYTES,
        )
        .map_err(|_| PoolError::RecoveryRequired)?
        else {
            return Ok(());
        };
        let journal: Journal =
            serde_json::from_slice(&bytes).map_err(|_| PoolError::RecoveryRequired)?;
        self.with_store(|vault| self.compensate(vault, manifest, journal, false))
    }
    fn retain_cleanup(&self, vault: &dyn Vault, manifest: &Manifest, ids: &[String]) -> Result<()> {
        let path = self.root.join("cleanup.json");
        let mut tombstones = match fs::read_regular_nofollow_bounded(&path, MAX_MANIFEST_BYTES)
            .map_err(|_| PoolError::RecoveryRequired)?
        {
            Some(bytes) => serde_json::from_slice::<CleanupTombstones>(&bytes)
                .map_err(|_| PoolError::RecoveryRequired)?,
            None => CleanupTombstones {
                boot: current_boot(),
                backend_id: vault.backend_id().into(),
                ids: Vec::new(),
            },
        };
        if boot_advanced(tombstones.boot.as_ref()) {
            self.recover_cleanup(manifest)?;
            tombstones = CleanupTombstones {
                boot: current_boot(),
                backend_id: vault.backend_id().into(),
                ids: Vec::new(),
            };
        }
        if tombstones.backend_id != vault.backend_id() {
            return Err(PoolError::RecoveryRequired);
        }
        for id in ids {
            validate_id(id).map_err(|_| PoolError::RecoveryRequired)?;
            if manifest.entries.iter().any(|r| {
                r.secret_id.as_ref() == Some(id) || r.remove_backup_id.as_ref() == Some(id)
            }) {
                return Err(PoolError::RecoveryRequired);
            }
            if !tombstones.ids.contains(id) {
                tombstones.ids.push(id.clone());
            }
        }
        if tombstones.ids.len() > MAX_ENTRIES * 4 {
            return Err(PoolError::RecoveryRequired);
        }
        write_json(&path, &tombstones)
    }
    fn recover_cleanup(&self, manifest: &Manifest) -> Result<()> {
        self.recover_cleanup_bounded(manifest, usize::MAX)
            .map(|_| ())
    }
    fn recover_cleanup_bounded(&self, manifest: &Manifest, limit: usize) -> Result<bool> {
        let Some(bytes) =
            fs::read_regular_nofollow_bounded(&self.root.join("cleanup.json"), MAX_MANIFEST_BYTES)
                .map_err(|_| PoolError::RecoveryRequired)?
        else {
            return Ok(true);
        };
        let mut tombstones: CleanupTombstones =
            serde_json::from_slice(&bytes).map_err(|_| PoolError::RecoveryRequired)?;
        if tombstones.ids.len() > MAX_ENTRIES * 4 {
            return Err(PoolError::RecoveryRequired);
        }
        // Validate every identity before the first destructive call.
        for id in &tombstones.ids {
            validate_id(id).map_err(|_| PoolError::RecoveryRequired)?;
            if manifest.entries.iter().any(|r| {
                r.secret_id.as_ref() == Some(id) || r.remove_backup_id.as_ref() == Some(id)
            }) {
                return Err(PoolError::RecoveryRequired);
            }
        }
        self.with_store(|v| {
            if v.backend_id() != tombstones.backend_id {
                return Err(PoolError::RecoveryRequired);
            }
            for id in tombstones.ids.iter().take(limit) {
                v.delete_named(&key(id)?)
                    .map_err(|_| PoolError::RecoveryRequired)?;
            }
            if boot_advanced(tombstones.boot.as_ref()) {
                let completed = tombstones.ids.len().min(limit);
                tombstones.ids.drain(..completed);
                if tombstones.ids.is_empty() {
                    std::fs::remove_file(self.root.join("cleanup.json"))
                        .map_err(|_| PoolError::RecoveryRequired)?;
                } else {
                    write_json(&self.root.join("cleanup.json"), &tombstones)?;
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }
    fn recover_remove(
        &self,
        vault: &dyn Vault,
        manifest: &Manifest,
        journal: &Journal,
        inline: bool,
    ) -> Result<()> {
        let Journal::Remove {
            row,
            phase,
            backup_id,
            backend_id: backend,
            writer,
            recovery_safe,
        } = journal
        else {
            return Err(PoolError::RecoveryRequired);
        };
        let phase = phase.ok_or(PoolError::RecoveryRequired)?; // Legacy journals lack ordering evidence.
        row.entry
            .validate()
            .map_err(|_| PoolError::RecoveryRequired)?;
        if backend != vault.backend_id()
            || writer.pid == 0
            || writer
                .started_at
                .as_ref()
                .is_some_and(|x| x.is_empty() || x.len() > 256)
            || row.entry.source != KeySource::SecretStore
            || row.remove_backup_id.is_some()
        {
            return Err(PoolError::RecoveryRequired);
        }
        let original_id = row.secret_id.as_ref().ok_or(PoolError::RecoveryRequired)?;
        key(original_id).map_err(|_| PoolError::RecoveryRequired)?;
        key(backup_id).map_err(|_| PoolError::RecoveryRequired)?;
        if original_id == backup_id
            || manifest.entries.iter().any(|r| {
                r.entry.name != row.entry.name
                    && [r.secret_id.as_deref(), r.remove_backup_id.as_deref()]
                        .into_iter()
                        .flatten()
                        .any(|id| id == original_id || id == backup_id)
            })
        {
            return Err(PoolError::RecoveryRequired);
        }
        let mut next = Manifest {
            version: manifest.version,
            env_file: manifest.env_file.clone(),
            entries: manifest.entries.clone(),
        };
        let current = next
            .entries
            .iter_mut()
            .find(|r| r.entry.name == row.entry.name);
        let cleanup = match (phase, current) {
            (RemovePhase::BackupWrite, Some(current)) => {
                let mut original = current.clone();
                original.remove_backup_id = None;
                if &original != row
                    || current
                        .remove_backup_id
                        .as_deref()
                        .is_some_and(|id| id != backup_id)
                {
                    return Err(PoolError::RecoveryRequired);
                }
                current.remove_backup_id = None;
                vec![backup_id.to_owned()]
            }
            (RemovePhase::OriginalDelete, Some(current)) => {
                let mut admitted = row.clone();
                admitted.remove_backup_id = Some(backup_id.to_owned());
                let mut repointed = row.clone();
                repointed.secret_id = Some(backup_id.to_owned());
                if current == &admitted {
                    if !vault
                        .contains_named_for_recovery(&key(backup_id)?)
                        .map_err(|_| PoolError::RecoveryRequired)?
                    {
                        return Err(PoolError::RecoveryRequired);
                    }
                    *current = repointed;
                } else if current != &repointed {
                    return Err(PoolError::RecoveryRequired);
                }
                vec![original_id.clone()]
            }
            (RemovePhase::OriginalDelete, None) => vec![original_id.clone(), backup_id.to_owned()],
            _ => return Err(PoolError::RecoveryRequired),
        };
        // Publish only the known-admitted backup identity, never copy a journal-selected value.
        // Persist cleanup before clearing the journal; repeated recovery recognizes the repoint.
        self.save(&next)?;
        let completed_here = writer.pid == std::process::id()
            && writer
                .started_at
                .as_ref()
                .zip(writer_start(writer.pid))
                .is_some_and(|(expected, actual)| {
                    expected
                        .parse::<u64>()
                        .ok()
                        .zip(actual.parse::<u64>().ok())
                        .is_some_and(|(expected, actual)| {
                            crate::sessions::same_start(expected, actual)
                        })
                })
            && vault.named_worker_state(&key(original_id)?) == secret::NamedWorkerState::Completed
            && vault.named_worker_state(&key(backup_id)?) == secret::NamedWorkerState::Completed;
        if inline || *recovery_safe || completed_here || boot_advanced(writer.boot.as_ref()) {
            for id in &cleanup {
                vault
                    .delete_named(&key(id)?)
                    .map_err(|_| PoolError::RecoveryRequired)?;
            }
        } else {
            self.retain_cleanup(vault, &next, &cleanup)?;
        }
        self.clear_journal()
    }
    fn compensate(
        &self,
        vault: &dyn Vault,
        manifest: &Manifest,
        mut journal: Journal,
        inline: bool,
    ) -> Result<()> {
        if matches!(&journal, Journal::Remove { .. }) {
            return self.recover_remove(vault, manifest, &journal, inline);
        }
        let (row, backup, safe, backend, writer) = match &mut journal {
            Journal::Add {
                row,
                recovery_safe,
                backend_id,
                writer,
            } => (row, None, recovery_safe, backend_id, writer),
            Journal::Remove {
                row,
                backup_id,
                recovery_safe,
                backend_id,
                writer,
                ..
            } => (row, Some(backup_id), recovery_safe, backend_id, writer),
        };
        if writer.pid == 0
            || writer
                .started_at
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 256)
        {
            return Err(PoolError::RecoveryRequired);
        }
        if backend != vault.backend_id() {
            return Err(PoolError::RecoveryRequired);
        }
        row.entry
            .validate()
            .map_err(|_| PoolError::RecoveryRequired)?;
        if row.entry.source != KeySource::SecretStore {
            return Err(PoolError::RecoveryRequired);
        }
        let id = row
            .secret_id
            .as_deref()
            .ok_or(PoolError::RecoveryRequired)?;
        let original = key(id).map_err(|_| PoolError::RecoveryRequired)?;
        let current = manifest
            .entries
            .iter()
            .find(|r| r.entry.name == row.entry.name);
        if current.is_some_and(|r| r != row)
            || manifest
                .entries
                .iter()
                .any(|r| r.secret_id.as_deref() == Some(id) && r != row)
            || backup.as_ref().is_some_and(|backup| {
                backup.as_str() == id
                    || manifest
                        .entries
                        .iter()
                        .any(|r| r.secret_id.as_ref() == Some(*backup))
            })
        {
            return Err(PoolError::RecoveryRequired);
        }
        if let Some(backup) = &backup {
            key(backup).map_err(|_| PoolError::RecoveryRequired)?;
        }
        let completed_here = writer.pid == std::process::id()
            && writer
                .started_at
                .as_ref()
                .zip(writer_start(writer.pid))
                .is_some_and(|(expected, actual)| {
                    expected
                        .parse::<u64>()
                        .ok()
                        .zip(actual.parse::<u64>().ok())
                        .is_some_and(|(expected, actual)| {
                            crate::sessions::same_start(expected, actual)
                        })
                })
            && vault.named_worker_state(&original) == secret::NamedWorkerState::Completed
            && backup.as_ref().is_none_or(|id| {
                key(id).is_ok_and(|key| {
                    vault.named_worker_state(&key) == secret::NamedWorkerState::Completed
                })
            });
        let rebooted = boot_advanced(writer.boot.as_ref());
        if !inline && !*safe && !completed_here && !rebooted && writer.possibly_alive() {
            return Err(PoolError::RecoveryWriterAlive);
        }
        let was_uncertain = !*safe && !inline && !completed_here && !rebooted;
        let native = !matches!(vault.backend_id(), "linux-file-aes" | "in-memory");
        if was_uncertain && native && backup.is_some() && current.is_some() {
            // A late external delete may erase a restored original even after PID death.
            // No backend completion proof exists across processes: retain the transaction.
            return Err(PoolError::RecoveryRequired);
        }
        let backup = backup.map(|id| id.clone());
        if was_uncertain && native && current.is_none() {
            let mut ids = vec![id.to_owned()];
            if let Some(backup) = &backup {
                ids.push(backup.clone());
            }
            self.retain_cleanup(vault, manifest, &ids)?;
        }
        // A recovery operation can itself time out. Publish its owner before any mutation.
        *writer = Writer::current();
        *safe = vault.backend_id() == "linux-file-aes" || vault.backend_id() == "in-memory";
        write_json(&self.root.join("transaction.json"), &journal)?;
        let result = (|| -> std::result::Result<(), secret::SecretError> {
            match backup {
                None if current.is_none() => vault.delete_named(&original)?,
                // Committed metadata remains valid even if the item is now missing; list
                // must report present=false rather than leave a completed add blocked.
                None => (),
                Some(_) => return Err(secret::SecretError::NamedOutcomeUnknown),
            }
            Ok(())
        })();
        if let Err(error) = result {
            if uncertain(&error) {
                return self.mark_unknown(journal);
            }
            {
                match &mut journal {
                    Journal::Add { recovery_safe, .. } | Journal::Remove { recovery_safe, .. } => {
                        *recovery_safe = true
                    }
                }
                write_json(&self.root.join("transaction.json"), &journal)?;
            }
            return Err(PoolError::RecoveryRequired);
        }
        self.clear_journal()
    }
    /// Resolve an interrupted transaction once no earlier asynchronous writer can still run.
    pub fn recover_pending(&self) -> Result<()> {
        let _guard = self.custody()?;
        let manifest = self.load()?;
        self.recover(&manifest)?;
        self.recover_cleanup(&self.load()?)
    }
    /// Once-per-start background recovery. Same-boot or unavailable boot proof never
    /// opens the credential backend. At most one old cleanup item and one phase
    /// transaction (at most two deletes) are processed per call; deferred custody
    /// remains durable for explicit recovery or the next launch.
    pub fn recover_after_restart(&self) -> Result<RestartRecovery> {
        match std::fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RestartRecovery::NotNeeded);
            }
            Err(_) => return Err(PoolError::ManifestUnavailable),
            Ok(_) => {}
        }
        let _guard = self.custody()?;
        let manifest = self.load()?;
        let journal_bytes = fs::read_regular_nofollow_bounded(
            &self.root.join("transaction.json"),
            MAX_MANIFEST_BYTES,
        )
        .map_err(|_| PoolError::RecoveryRequired)?;
        if let Some(bytes) = journal_bytes.as_ref() {
            let journal: Journal =
                serde_json::from_slice(bytes).map_err(|_| PoolError::RecoveryRequired)?;
            let writer = match &journal {
                Journal::Add { writer, .. } | Journal::Remove { writer, .. } => writer,
            };
            if !boot_advanced(writer.boot.as_ref()) {
                return Ok(RestartRecovery::NotNeeded);
            }
        }
        let cleanup_bytes =
            fs::read_regular_nofollow_bounded(&self.root.join("cleanup.json"), MAX_MANIFEST_BYTES)
                .map_err(|_| PoolError::RecoveryRequired)?;
        let mut changed = false;
        if let Some(bytes) = cleanup_bytes {
            let cleanup: CleanupTombstones =
                serde_json::from_slice(&bytes).map_err(|_| PoolError::RecoveryRequired)?;
            if !boot_advanced(cleanup.boot.as_ref()) {
                // Avoid a phase recovery that could indirectly drain same-boot cleanup.
                return Ok(RestartRecovery::NotNeeded);
            }
            if !self.recover_cleanup_bounded(&manifest, 1)? {
                return Ok(RestartRecovery::Deferred);
            }
            changed = true;
        }
        if journal_bytes.is_some() {
            self.recover(&manifest)?;
            changed = true;
        }
        Ok(if changed {
            RestartRecovery::Recovered
        } else {
            RestartRecovery::NotNeeded
        })
    }
    /// Check metadata admission and custody before prompting for a secret.
    pub fn check_add_available(&self, name: &str) -> Result<()> {
        let name = PoolName::new(name)?;
        let _guard = self.custody()?;
        let manifest = self.prepare()?;
        if manifest.entries.iter().any(|r| r.entry.name == name) {
            Err(PoolError::NameExists)
        } else {
            Ok(())
        }
    }
    fn prepare(&self) -> Result<Manifest> {
        let manifest = self.load()?;
        if fs::read_regular_nofollow_bounded(
            &self.root.join("transaction.json"),
            MAX_MANIFEST_BYTES,
        )
        .map_err(|_| PoolError::RecoveryRequired)?
        .is_some()
        {
            let bytes = fs::read_regular_nofollow_bounded(
                &self.root.join("transaction.json"),
                MAX_MANIFEST_BYTES,
            )
            .map_err(|_| PoolError::RecoveryRequired)?
            .ok_or(PoolError::RecoveryRequired)?;
            let journal: Journal =
                serde_json::from_slice(&bytes).map_err(|_| PoolError::RecoveryRequired)?;
            let writer = match &journal {
                Journal::Add { writer, .. } | Journal::Remove { writer, .. } => writer,
            };
            if !boot_advanced(writer.boot.as_ref()) {
                return Err(PoolError::RecoveryRequired);
            }
            self.recover(&manifest)?;
            let recovered = self.load()?;
            self.recover_cleanup(&recovered)?;
            return Ok(recovered);
        }
        Ok(manifest)
    }
    pub fn list(&self) -> Result<Vec<PoolRow>> {
        let _guard = self.custody()?;
        let manifest = self.prepare()?;
        manifest
            .entries
            .iter()
            .map(|row| {
                let present = match &row.entry.source {
                    KeySource::EnvFile => env_file::contains(
                        manifest
                            .env_file
                            .as_deref()
                            .ok_or(PoolError::ManifestInvalid)?,
                        &row.entry.name,
                    )?,
                    KeySource::SecretStore => self.with_store(|v| {
                        v.contains_named(&key(row
                            .secret_id
                            .as_deref()
                            .ok_or(PoolError::ManifestInvalid)?)?)
                            .map_err(|_| PoolError::StoreUnavailable)
                    })?,
                };
                Ok(PoolRow {
                    entry: row.entry.clone(),
                    present,
                })
            })
            .collect()
    }
    pub fn add(
        &self,
        name: &str,
        provider: &str,
        secret: SecretString,
        reset: Option<Reset>,
        cap: Option<f64>,
    ) -> Result<()> {
        use secrecy::ExposeSecret;
        super::validate_key(secret.expose_secret())?;
        let row = self.entry(name, provider, KeySource::SecretStore, reset, cap)?;
        let row = StoredEntry {
            entry: row,
            secret_id: Some(fresh_id()),
            generation: Some(fresh_id()),
            remove_backup_id: None,
        };
        let _guard = self.custody()?;
        let mut manifest = self.prepare()?;
        if manifest
            .entries
            .iter()
            .any(|r| r.entry.name == row.entry.name)
        {
            return Err(PoolError::NameExists);
        }
        if manifest.entries.len() >= MAX_ENTRIES {
            return Err(PoolError::ManifestInvalid);
        }
        self.with_store(|v| {
            let journal = Journal::Add {
                row: row.clone(),
                recovery_safe: v.backend_id() == "linux-file-aes" || v.backend_id() == "in-memory",
                backend_id: v.backend_id().into(),
                writer: Writer::current(),
            };
            write_json(&self.root.join("transaction.json"), &journal)?;
            let original = key(row.secret_id.as_deref().ok_or(PoolError::ManifestInvalid)?)?;
            if let Err(error) = v.set_named(&original, &secret) {
                if uncertain(&error) {
                    return self.mark_unknown(journal);
                }
                if matches!(
                    error,
                    secret::SecretError::Locked
                        | secret::SecretError::PermissionDenied { .. }
                        | secret::SecretError::AuthorizationRequired
                ) {
                    self.clear_journal()?;
                    return Err(PoolError::MutationRefused);
                }
                // A definite refusal cannot leave a worker behind. Clean any partial item.
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            manifest.entries.push(row);
            if self.save(&manifest).is_err() {
                manifest.entries.pop();
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            self.clear_journal()
        })
    }
    /// Validate all non-secret add arguments before an operator enters a key.
    pub fn validate_add(
        name: &str,
        provider: &str,
        reset: Option<&Reset>,
        cap: Option<f64>,
    ) -> Result<()> {
        PoolName::new(name)?;
        types::validate_provider(provider)?;
        types::validate_options(reset, cap)
    }
    fn entry(
        &self,
        name: &str,
        provider: &str,
        source: KeySource,
        reset: Option<Reset>,
        cap: Option<f64>,
    ) -> Result<PoolEntry> {
        Self::validate_add(name, provider, reset.as_ref(), cap)?;
        Ok(PoolEntry {
            name: PoolName::new(name)?,
            provider: provider.into(),
            source,
            reset,
            monthly_cap_usd: cap,
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| {
                    chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).map(|d| d.to_rfc3339())
                })
                .ok()
                .flatten()
                .ok_or(PoolError::MutationRefused)?,
        })
    }
    pub fn add_env_file(
        &self,
        path: &Path,
        names: &[String],
        provider: &str,
        reset: Option<Reset>,
        cap: Option<f64>,
    ) -> Result<()> {
        if !path.is_absolute() || names.is_empty() {
            return Err(PoolError::EnvFileInvalid);
        }
        let mut additions = Vec::new();
        for name in names {
            let entry = self.entry(name, provider, KeySource::EnvFile, reset.clone(), cap)?;
            if !env_file::contains(path, &entry.name)? {
                return Err(PoolError::KeyMissing);
            }
            if additions
                .iter()
                .any(|row: &StoredEntry| row.entry.name == entry.name)
            {
                return Err(PoolError::NameExists);
            }
            additions.push(StoredEntry {
                entry,
                secret_id: None,
                generation: Some(fresh_id()),
                remove_backup_id: None,
            });
        }
        let _guard = self.custody()?;
        let mut manifest = self.prepare()?;
        if manifest.env_file.as_deref().is_some_and(|old| old != path)
            && manifest
                .entries
                .iter()
                .any(|r| r.entry.source == KeySource::EnvFile)
        {
            return Err(PoolError::MutationRefused);
        }
        if additions.iter().any(|a| {
            manifest
                .entries
                .iter()
                .any(|r| r.entry.name == a.entry.name)
        }) {
            return Err(PoolError::NameExists);
        }
        manifest.env_file = Some(path.into());
        manifest.entries.extend(additions);
        self.save(&manifest)
    }
    pub fn set_reset(&self, name: &str, reset: Option<Reset>) -> Result<()> {
        if let Some(reset) = &reset {
            reset.validate()?;
        }
        let name = PoolName::new(name)?;
        let _guard = self.custody()?;
        let mut manifest = self.prepare()?;
        let row = manifest
            .entries
            .iter_mut()
            .find(|r| r.entry.name == name)
            .ok_or(PoolError::KeyMissing)?;
        row.entry.reset = reset;
        self.save(&manifest)
    }
    pub fn read_key(&self, name: &str) -> Result<SecretString> {
        let name = PoolName::new(name)?;
        let _guard = self.custody()?;
        let manifest = self.prepare()?;
        let row = manifest
            .entries
            .iter()
            .find(|r| r.entry.name == name)
            .ok_or(PoolError::KeyMissing)?;
        match row.entry.source {
            KeySource::EnvFile => env_file::get(
                manifest
                    .env_file
                    .as_deref()
                    .ok_or(PoolError::ManifestInvalid)?,
                &name,
            ),
            KeySource::SecretStore => self.with_store(|v| {
                v.get_named(&key(row
                    .secret_id
                    .as_deref()
                    .ok_or(PoolError::ManifestInvalid)?)?)
                    .map_err(|error| match error {
                        secret::SecretError::NamedNotFound => PoolError::KeyMissing,
                        _ => PoolError::StoreUnavailable,
                    })
            }),
        }
    }
    pub fn removal_snapshot(&self, name: &str) -> Result<RemovalSnapshot> {
        let name = PoolName::new(name)?;
        let _guard = self.custody()?;
        let manifest = self.prepare()?;
        let row = manifest
            .entries
            .iter()
            .find(|row| row.entry.name == name)
            .ok_or(PoolError::KeyMissing)?
            .clone();
        Ok(RemovalSnapshot {
            entry: row.entry.clone(),
            row,
            env_file: manifest.env_file,
        })
    }
    pub fn remove_if_unchanged(&self, expected: &RemovalSnapshot) -> Result<()> {
        let _guard = self.custody()?;
        let manifest = self.prepare()?;
        let current = manifest
            .entries
            .iter()
            .find(|row| row.entry.name == expected.row.entry.name);
        if current != Some(&expected.row)
            || (expected.row.entry.source == KeySource::EnvFile
                && manifest.env_file != expected.env_file)
        {
            return Err(PoolError::MutationRefused);
        }
        self.remove_locked(expected.row.entry.name.clone(), manifest)
    }
    pub fn remove(&self, name: &str) -> Result<()> {
        let name = PoolName::new(name)?;
        let _guard = self.custody()?;
        self.remove_locked(name, self.prepare()?)
    }
    fn remove_locked(&self, name: PoolName, mut manifest: Manifest) -> Result<()> {
        let index = manifest
            .entries
            .iter()
            .position(|r| r.entry.name == name)
            .ok_or(PoolError::KeyMissing)?;
        let row = manifest.entries[index].clone();
        if row.entry.source == KeySource::EnvFile {
            manifest.entries.remove(index);
            return self.save(&manifest);
        }
        self.with_store(|v| {
            let original = key(row.secret_id.as_deref().ok_or(PoolError::ManifestInvalid)?)?;
            let saved = match v.get_named(&original) {
                Ok(saved) => saved,
                Err(secret::SecretError::NamedNotFound) => {
                    manifest.entries.remove(index);
                    return self.save(&manifest);
                }
                Err(_) => return Err(PoolError::MutationRefused),
            };
            let backup_id = fresh_id();
            let backup = key(&backup_id)?;
            let mut journal = Journal::Remove {
                row: row.clone(),
                phase: Some(RemovePhase::BackupWrite),
                backup_id: backup_id.clone(),
                recovery_safe: v.backend_id() == "linux-file-aes" || v.backend_id() == "in-memory",
                backend_id: v.backend_id().into(),
                writer: Writer::current(),
            };
            write_json(&self.root.join("transaction.json"), &journal)?;
            {
                if let Err(error) = v.set_named(&backup, &saved) {
                    if uncertain(&error) {
                        return self.mark_unknown(journal);
                    }
                    if matches!(
                        error,
                        secret::SecretError::Locked
                            | secret::SecretError::PermissionDenied { .. }
                            | secret::SecretError::AuthorizationRequired
                    ) {
                        self.clear_journal()?;
                    } else {
                        self.compensate(v, &manifest, journal, true)?;
                    }
                    return Err(PoolError::MutationRefused);
                }
            }
            // Successful native write is the admission boundary. Publish it before the
            // phase that can submit an original deletion; either crash order is recoverable.
            manifest.entries[index].remove_backup_id = Some(backup_id.clone());
            self.save(&manifest)?;
            if let Journal::Remove { phase, .. } = &mut journal {
                *phase = Some(RemovePhase::OriginalDelete);
            }
            write_json(&self.root.join("transaction.json"), &journal)?;
            if let Err(error) = v.delete_named(&original) {
                if uncertain(&error) {
                    return self.mark_unknown(journal);
                }
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            manifest.entries.remove(index);
            if self.save(&manifest).is_err() {
                let mut admitted = row;
                admitted.remove_backup_id = Some(backup_id.clone());
                manifest.entries.insert(index, admitted);
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            if let Err(error) = v.delete_named(&backup) {
                if uncertain(&error) {
                    return self.mark_unknown(journal);
                }
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            self.clear_journal()
        })
    }
}
