//! The term mint lock: serialises `term-<pid>` creation against the keychain
//! orphan sweep's delete window.
//!
//! # Why a lock outside the handle dir
//!
//! The orphan sweep (`credentials::keychain::orphans`) deletes the item of a
//! `term-<pid>` whose dir is gone. Between its last "the dir is still gone"
//! check and the `security delete` that follows (a subprocess bounded at 5.25s),
//! a new terminal could take the pid, create `term-<pid>` and write or adopt the
//! item at the same service name; the delete would then remove the new
//! terminal's item. The per-dir `.swap-lock` cannot serialise that: it lives
//! INSIDE the dir that is gone. This lock lives beside the dirs:
//! `<accounts>/.term-mint.lock`.
//!
//! # The invariant it rests on
//!
//! Nothing csq writes, and no Claude Code that csq launches, can write or adopt
//! a keychain item for `term-P` before `term-P` exists (the keychain write path
//! is gated on canonicalising the handle dir, and a launch starts Claude Code
//! only after the dir is minted). So:
//!
//! * a mint that completes BEFORE the sweep takes the lock is seen by the
//!   sweep's dir check, and the item is kept;
//! * a mint that starts AFTER the sweep took the lock waits for the delete to
//!   return, and everything it writes afterwards is a new item the delete never
//!   touched.
//!
//! # Scope and limits
//!
//! * A tool that is not csq and forges `CLAUDE_CONFIG_DIR=<accounts>/term-<pid>`
//!   by creating that dir itself does not take this lock. That is outside the
//!   sweep's contract (it only considers items csq-minted forms hash to) and is
//!   not defended by it.
//! * Holding the lock costs a launch, in the typical case, the sweep's item re-read, its
//!   fresh process scan and its single `security delete`, and only when the two collide.
//!   The constants sum to about 11s (two bounded keychain calls of 5.25s each and the
//!   scan's 500ms budget); [`MINT_WAIT_ATTEMPTS`] x [`MINT_WAIT_DELAY`] is sized against
//!   that sum, not against an enforced wall-clock bound: the directory check, the pid
//!   probe, the ledger write and one kernel read inside the scan are not individually
//!   timed. A launch that cannot get the lock REFUSES (fails closed) rather than creating
//!   the dir unlocked.
//!
//! # Lock order
//!
//! A LEAF: never acquired while this thread holds a swap lock or the keychain
//! pending-clears lock, and no lock of any kind is acquired while it is held.
//! Enforced by `platform::lock::order` at the one chokepoint every acquisition
//! passes through, not by convention.

use crate::platform::lock::{self, order::MINT_LOCK_FILENAME};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Attempts a creator makes to take the lock before refusing the launch.
pub const MINT_WAIT_ATTEMPTS: u32 = 260;

/// Delay between attempts. `MINT_WAIT_ATTEMPTS * MINT_WAIT_DELAY` = 13s, set above the
/// SUM of the constants the sweep holds the lock for, which is about 11s: its re-read of
/// the item and its `security delete` (two bounded calls, each `KEYCHAIN_OP_TIMEOUT` 5s
/// plus `MIN_POST_EXIT_GRACE` 250ms = 5.25s, so 10.5s) and its fresh process scan
/// (`SCAN_BUDGET`, 500ms). The directory check, the pid probe, the ledger write (`forget_mint`)
/// and a single kernel read inside the scan are not in that sum and not individually
/// timed; they must fit in the remaining ~2s. That is a margin, not a bound: past it a
/// creator's launch refuses. The orphan sweep's tests assert the sum, not the hold.
pub const MINT_WAIT_DELAY: Duration = Duration::from_millis(50);

/// Why the lock could not be taken. Fixed vocabulary; no path or OS text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintLockError {
    /// Another holder (the sweep, or another creator) kept it past the wait.
    Busy,
    /// The lock file could not be opened or locked, or taking it would break
    /// the lock order.
    Unavailable,
}

impl MintLockError {
    /// The fixed message a refused creation carries.
    pub fn message(self) -> &'static str {
        match self {
            Self::Busy => "term mint lock busy: another csq process is mid-sweep; retry",
            Self::Unavailable => "term mint lock unavailable",
        }
    }
}

/// Holds the mint lock; releases it on drop.
#[derive(Debug)]
pub struct MintGuard {
    _lock: lock::FileLockGuard,
}

/// Path of the mint lock under the accounts dir `base`.
pub fn mint_lock_path(base: &Path) -> PathBuf {
    base.join(MINT_LOCK_FILENAME)
}

/// The directory name shape this lock and the ledger apply to: exactly
/// `term-<pid>` as [`super::handle_dir::term_handle_dir_name`] spells it.
/// Capture and exec dirs (`interactive-capture-*`, `exec-*`) are not part of
/// the sweep's contract and never take the lock.
pub fn term_pid_of(dir_name: &str) -> Option<u32> {
    let pid: u32 = dir_name.strip_prefix("term-")?.parse().ok()?;
    (super::handle_dir::term_handle_dir_name(pid) == dir_name).then_some(pid)
}

/// Take the lock for a `term-<pid>` creation, waiting up to
/// [`MINT_WAIT_ATTEMPTS`] x [`MINT_WAIT_DELAY`].
pub fn acquire_for_mint(base: &Path) -> Result<MintGuard, MintLockError> {
    acquire_with(base, wait_params())
}

fn acquire_with(
    base: &Path,
    (attempts, delay): (u32, Duration),
) -> Result<MintGuard, MintLockError> {
    match lock::try_lock_file_bounded_nofollow(&mint_lock_path(base), attempts, delay) {
        Ok(Some(guard)) => Ok(MintGuard { _lock: guard }),
        Ok(None) => Err(MintLockError::Busy),
        Err(_) => Err(MintLockError::Unavailable),
    }
}

/// What the sweep got when it tried the lock.
#[derive(Debug)]
pub enum SweepLock {
    /// Held: the sweep may run its final check and delete under it.
    Held(MintGuard),
    /// A creator (or another sweep) holds it: keep the item this cycle.
    Busy,
    /// Could not be taken: keep the item this cycle.
    Unavailable,
}

/// Try the lock once, never waiting: the sweep keeps the item instead of
/// delaying a launch.
pub fn try_acquire_for_sweep(base: &Path) -> SweepLock {
    match acquire_with(base, (1, Duration::ZERO)) {
        Ok(guard) => SweepLock::Held(guard),
        Err(MintLockError::Busy) => SweepLock::Busy,
        Err(MintLockError::Unavailable) => SweepLock::Unavailable,
    }
}

// ── the mint ledger ───────────────────────────────────────────────────────

/// File name of the mint ledger, under the accounts dir.
pub const LEDGER_FILENAME: &str = ".term-mint-ledger";

/// Highest pid the ledger can record (Linux's `pid_max` ceiling, 2^22; macOS
/// pids stop at 99,999). A larger pid is never recorded, so its item is never
/// attested and never swept: the failure direction is a leak, not a delete.
pub const LEDGER_MAX_PID: u32 = 4_194_304;

/// The first format: the magic, then one bit per pid `0..=MAX`. Still READ (a dev build
/// wrote it before the launcher identity existed; `guard-reader-writer-parity` MUST-5);
/// never written. Retire the reader once no dev build writes it: **2026-11-15**, after
/// which a v1 file is `LedgerUnreadable` like any other foreign file.
const LEDGER_MAGIC_V1: &[u8; 8] = b"CSQMNT01";

/// The second format (a dev build, withdrawn before any release): the bitset, a `u32` count
/// and [`RECORD_LEN_V2`]-byte records, with NO checksum. Still READ, but only as bits: its
/// records are not believed, because nothing says they were not changed (D237 R2 security
/// R2-4), so every launcher it names is unrecorded until the next write stamps it. Retires
/// with v1 on **2026-11-15**.
const LEDGER_MAGIC_V2: &[u8; 8] = b"CSQMNT02";

/// The current format: the magic, the same bitset, a `u32` count, then that many
/// [`RECORD_LEN`]-byte records in strictly increasing pid order, each for a pid whose bit is
/// set, then a SHA-256 over every byte before it. A set bit with no record has the default
/// record (nothing known about its launcher). The checksum guards against storage or software
/// corruption that leaves the shape valid (a raised launcher id would read a live descendant
/// as "forked before the launcher"); it is not a defence against a writer with the user's
/// own file access, which could write a matching one.
const LEDGER_MAGIC: &[u8; 8] = b"CSQMNT03";

/// Bytes in the checksum trailer of a current ledger.
const CHECKSUM_LEN: usize = 32;

/// Bytes in the bitset.
const BITS_LEN: usize = (LEDGER_MAX_PID as usize) / 8 + 1;

/// Bytes in a v1 ledger, and the offset of the record count in a v2 or v3 one.
const LEDGER_V1_LEN: usize = LEDGER_MAGIC_V1.len() + BITS_LEN;

/// One record: pid `u32`, launcher unique id `u64`, boot session `[u8; 16]` (little endian).
const RECORD_LEN: usize = 4 + 8 + 16;

/// A v2 record: the same, then 8 reserved bytes (a withdrawn "latch"), ignored.
const RECORD_LEN_V2: usize = RECORD_LEN + 8;

/// Most records a ledger may hold. macOS pids stop at 99,999, so no honest ledger needs more.
pub const LEDGER_MAX_RECORDS: usize = 100_000;

/// A boot session id (`kern.bootsessionuuid`), 16 bytes. All zero means "not known".
///
/// ASSUMPTION, not a measured or sourced fact: the kernel generates this value once per boot,
/// so it is the same for every read during a boot (sleep and wake included) and differs
/// between boots. No kernel source or header is cited for it, and nothing here has read it
/// across a reboot. Both halves matter and fail in different directions: a value that changed
/// DURING a boot would turn every same-boot record into "an earlier boot" and so read a live
/// launcher's descendants as gone (fail-open); one that repeated ACROSS boots would compare
/// ids from two counters. The live test `this_process_has_a_boot_session_and_a_launcher_identity`
/// checks the first half in-process and from a separate process; the second half is the
/// owner's to accept (see spec 13).
pub type BootId = [u8; 16];

const NO_BOOT: BootId = [0; 16];

/// Why the ledger could not be read. It is a fixed token; the sweep that sees
/// it deletes NOTHING that cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerUnreadable;

/// What the ledger knows about the launcher of one minted `term-<pid>`: the process whose
/// pid is `<pid>` when csq minted the dir.
///
/// Unique ids grow with every fork and restart at boot, so an id only means something
/// within one boot session; an item minted in an EARLIER boot has no live descendant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MintRecord {
    /// The launcher's `p_uniqueid`; `0` when csq could not read it.
    pub uniqueid: u64,
    /// The boot session `uniqueid` belongs to; all zero when csq could not read it.
    pub boot: BootId,
}

/// How a minted launcher can be told apart from the processes alive now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherBasis {
    /// Nothing usable was recorded (a v1 bit, an unreadable id or boot, or no boot to compare
    /// against now): no process can be ruled out as its descendant.
    Unrecorded,
    /// Minted in an earlier boot session: every process of that session is gone, so no live
    /// process descends from the launcher.
    PreviousBoot,
    /// Minted in this boot session: its descendants are exactly the processes whose creation
    /// lineage reaches `uniqueid`.
    SameBoot { uniqueid: u64 },
}

impl MintRecord {
    /// The basis this record gives in the boot session `now` (`None` when it cannot be read).
    pub fn basis(&self, now: Option<BootId>) -> LauncherBasis {
        let Some(now) = now.filter(|b| *b != NO_BOOT) else {
            return LauncherBasis::Unrecorded;
        };
        if self.boot == NO_BOOT {
            return LauncherBasis::Unrecorded;
        }
        if self.boot != now {
            return LauncherBasis::PreviousBoot;
        }
        // 0 is "not read" and 1 is launchd: neither is a csq launcher.
        if self.uniqueid <= 1 {
            return LauncherBasis::Unrecorded;
        }
        LauncherBasis::SameBoot {
            uniqueid: self.uniqueid,
        }
    }

    /// The record for a pid minted twice (its dir was removed and a new launcher took the
    /// pid before the item was swept): one record that is safe for the descendants of BOTH
    /// launchers.
    fn merged(old: Self, new: Self) -> Self {
        if new.boot == NO_BOOT {
            return Self::default();
        }
        let unknown_id = Self {
            uniqueid: 0,
            boot: new.boot,
        };
        if new.uniqueid == 0 {
            return unknown_id;
        }
        if old.boot != NO_BOOT && old.boot != new.boot {
            // The earlier launcher's boot session ended: it has no live descendant.
            return new;
        }
        if old.boot == new.boot && old.uniqueid != 0 {
            // Within one boot every descendant of the later launcher has an id above
            // both, so testing against the smaller id covers them (a lineage that stops at
            // the later launcher's dead id is Unknown, never clear).
            return Self {
                uniqueid: old.uniqueid.min(new.uniqueid),
                boot: new.boot,
            };
        }
        unknown_id
    }

    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The pids csq has minted a `term-<pid>` dir for, each with what is known about its
/// launcher. The sweep's candidate set is this ledger intersected with the service-name
/// hashes: an item whose hash only a pid csq never minted would produce (a foreign
/// collision) is not attested.
///
/// An ABSENT file is an empty ledger (no csq has minted since the ledger
/// existed); a file that exists and is not a well-formed ledger is
/// [`LedgerUnreadable`], never an empty ledger.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MintLedger {
    bits: Vec<u8>,
    records: std::collections::BTreeMap<u32, MintRecord>,
}

impl MintLedger {
    /// An empty ledger.
    pub fn empty() -> Self {
        Self::default()
    }

    /// `true` when csq recorded minting a `term-<pid>` for `pid`.
    pub fn contains(&self, pid: u32) -> bool {
        if pid == 0 || pid > LEDGER_MAX_PID {
            return false;
        }
        self.bits
            .get(pid as usize / 8)
            .is_some_and(|byte| byte & (1 << (pid % 8)) != 0)
    }

    /// `true` when csq minted ANY of `pids`.
    pub fn contains_any(&self, pids: &[u32]) -> bool {
        pids.iter().any(|&pid| self.contains(pid))
    }

    /// What is known about the launcher of `pid` (the default record when csq recorded
    /// nothing about it, including when `pid` was never minted).
    pub fn record(&self, pid: u32) -> MintRecord {
        self.records.get(&pid).copied().unwrap_or_default()
    }

    /// Every pid of `pids` csq minted, with its record.
    pub fn attested(&self, pids: &[u32]) -> Vec<(u32, MintRecord)> {
        pids.iter()
            .copied()
            .filter(|&pid| self.contains(pid))
            .map(|pid| (pid, self.record(pid)))
            .collect()
    }

    fn set(&mut self, pid: u32) {
        if self.bits.is_empty() {
            self.bits = vec![0; BITS_LEN];
        }
        self.bits[pid as usize / 8] |= 1 << (pid % 8);
    }

    fn clear(&mut self, pid: u32) {
        if pid == 0 || pid > LEDGER_MAX_PID {
            return;
        }
        if let Some(byte) = self.bits.get_mut(pid as usize / 8) {
            *byte &= !(1 << (pid % 8));
        }
        self.records.remove(&pid);
    }

    /// Give every set bit that has no record the boot session `boot`: whatever launcher
    /// minted it did so no later than now, so in any LATER boot session that launcher (and
    /// everything it started) is gone. This is what lets a restart clear a v1 bit, or a bit
    /// whose launcher id csq could not read, without ever claiming anything about THIS boot.
    /// A no-op without a readable boot or when the record list is full.
    fn stamp_unrecorded(&mut self, boot: Option<BootId>) {
        let Some(boot) = boot.filter(|b| *b != NO_BOOT) else {
            return;
        };
        for (index, byte) in self.bits.iter().enumerate() {
            if *byte == 0 {
                continue;
            }
            for bit in 0..8u32 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let pid = (index as u32) * 8 + bit;
                if pid == 0 || pid > LEDGER_MAX_PID {
                    continue;
                }
                if self.records.len() >= LEDGER_MAX_RECORDS {
                    return;
                }
                self.records
                    .entry(pid)
                    .or_insert(MintRecord { uniqueid: 0, boot });
            }
        }
    }

    fn put(&mut self, pid: u32, record: MintRecord) {
        if record.is_default() {
            self.records.remove(&pid);
        } else {
            self.records.insert(pid, record);
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(LEDGER_V1_LEN + 4 + self.records.len() * RECORD_LEN + CHECKSUM_LEN);
        out.extend_from_slice(LEDGER_MAGIC);
        if self.bits.is_empty() {
            out.resize(LEDGER_V1_LEN, 0);
        } else {
            out.extend_from_slice(&self.bits);
        }
        out.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for (pid, record) in &self.records {
            out.extend_from_slice(&pid.to_le_bytes());
            out.extend_from_slice(&record.uniqueid.to_le_bytes());
            out.extend_from_slice(&record.boot);
        }
        let digest = sha256(&out);
        out.extend_from_slice(&digest);
        out
    }

    /// Parse a v1, v2 or v3 file; `None` when it is none of them, is malformed, or (v3) fails
    /// its checksum.
    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < LEDGER_V1_LEN {
            return None;
        }
        let bits = raw[LEDGER_MAGIC.len()..LEDGER_V1_LEN].to_vec();
        if raw.starts_with(LEDGER_MAGIC_V1) {
            return (raw.len() == LEDGER_V1_LEN).then_some(Self {
                bits,
                records: Default::default(),
            });
        }
        let (body, record_len) = if raw.starts_with(LEDGER_MAGIC) {
            // The digest covers every byte before it; a mismatch is a changed file.
            let split = raw.len().checked_sub(CHECKSUM_LEN)?;
            if split < LEDGER_V1_LEN + 4 || sha256(&raw[..split]) != raw[split..] {
                return None;
            }
            (&raw[..split], RECORD_LEN)
        } else if raw.starts_with(LEDGER_MAGIC_V2) {
            (raw, RECORD_LEN_V2)
        } else {
            return None;
        };
        let tail = &body[LEDGER_V1_LEN..];
        let count = u32::from_le_bytes(tail.get(..4)?.try_into().ok()?) as usize;
        if count > LEDGER_MAX_RECORDS || tail.len() != 4 + count * record_len {
            return None;
        }
        let mut ledger = Self {
            bits,
            records: Default::default(),
        };
        let mut previous = 0u32;
        for chunk in tail[4..].chunks_exact(record_len) {
            let pid = u32::from_le_bytes(chunk[0..4].try_into().ok()?);
            // Strictly increasing, in range, and for a pid that is recorded as minted.
            if pid <= previous || pid > LEDGER_MAX_PID || !ledger.contains(pid) {
                return None;
            }
            previous = pid;
            if record_len == RECORD_LEN_V2 {
                continue; // (a v2 record has no checksum behind it: shape checked, not believed)
            }
            let mut boot = NO_BOOT;
            boot.copy_from_slice(&chunk[12..28]);
            ledger.put(
                pid,
                MintRecord {
                    uniqueid: u64::from_le_bytes(chunk[4..12].try_into().ok()?),
                    boot,
                },
            );
        }
        Some(ledger)
    }
}

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Path of the ledger under the accounts dir `base`.
pub fn ledger_path(base: &Path) -> PathBuf {
    base.join(LEDGER_FILENAME)
}

/// Read the ledger. Absent = empty; anything else that is not a regular file of
/// a well-formed v1, v2 or checksummed v3 ledger = [`LedgerUnreadable`].
pub fn read_ledger(base: &Path) -> Result<MintLedger, LedgerUnreadable> {
    let path = ledger_path(base);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MintLedger::empty()),
        Err(_) => return Err(LedgerUnreadable),
    };
    let most = (LEDGER_V1_LEN + 4 + LEDGER_MAX_RECORDS * RECORD_LEN_V2 + CHECKSUM_LEN) as u64;
    if !meta.is_file() || meta.len() < LEDGER_V1_LEN as u64 || meta.len() > most {
        return Err(LedgerUnreadable);
    }
    let raw = std::fs::read(&path).map_err(|_| LedgerUnreadable)?;
    MintLedger::from_bytes(&raw).ok_or(LedgerUnreadable)
}

/// The boot session this process runs in (`kern.bootsessionuuid`), `None` where it cannot
/// be read (every other platform, or a failed `sysctl`).
pub fn current_boot() -> Option<BootId> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; 64];
        let mut len = buf.len();
        // SAFETY: `sysctlbyname` reads the NUL-terminated name and writes at most `len`
        // bytes into `buf`, updating `len`; both outlive the call and `newp` is null with
        // `newlen` 0, so nothing is set.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        parse_boot_uuid(&buf[..len.min(buf.len())])
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// `8-4-4-4-12` hex text (a trailing NUL allowed) to its 16 bytes; `None` for anything else
/// and for the all-zero id (which is how "not known" is spelled).
pub fn parse_boot_uuid(text: &[u8]) -> Option<BootId> {
    let text = text.strip_suffix(&[0]).unwrap_or(text);
    if text.len() != 36 {
        return None;
    }
    let mut out = NO_BOOT;
    let mut nibbles = 0usize;
    for (i, &c) in text.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return None;
            }
            continue;
        }
        let v = (c as char).to_digit(16)? as u8;
        out[nibbles / 2] |= if nibbles.is_multiple_of(2) { v << 4 } else { v };
        nibbles += 1;
    }
    (out != NO_BOOT).then_some(out)
}

/// The launcher identity csq records when it mints `term-<pid>`: the unique id of the
/// process whose pid is `pid` and the boot session it belongs to. `None` where the kernel
/// has no such id or it cannot be read; the item is then unrecorded (kept), never guessed.
pub fn launcher_identity(pid: u32) -> Option<(u64, BootId)> {
    #[cfg(target_os = "macos")]
    {
        use crate::sessions::macos::{probe_uniq, Probe};
        let boot = current_boot()?;
        match probe_uniq(pid) {
            Probe::Got(u) => Some((u.uniqueid, boot)),
            Probe::Gone | Probe::Failed => None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Record that csq minted `term-<pid>`, with `launcher` (its unique id and boot session)
/// when csq could read it. Requires the mint guard as proof the
/// caller holds the lock (writers are serialised by it; readers need no lock
/// because the file is replaced atomically, never edited in place). A ledger
/// that exists but is unreadable is NOT replaced: it stays on disk untouched, a
/// fixed-vocabulary warning is logged, and `Err` is returned, so this terminal's
/// item is not attested and the sweep, which reads the same corrupt file, keeps
/// publishing `mint_ledger_unreadable` and deletes nothing (fail closed).
///
/// A pid minted twice keeps ONE record that covers both launchers (`MintRecord::merged`).
pub fn record_mint(
    base: &Path,
    pid: u32,
    launcher: Option<(u64, BootId)>,
    _held: &MintGuard,
) -> Result<(), LedgerUnreadable> {
    if pid == 0 || pid > LEDGER_MAX_PID {
        return Err(LedgerUnreadable);
    }
    let mut ledger = match read_ledger(base) {
        Ok(ledger) => ledger,
        Err(unreadable) => {
            tracing::warn!(
                error_kind = "term_mint_ledger_corrupt",
                "the mint ledger is unreadable and was left in place; remove it to start a new one"
            );
            return Err(unreadable);
        }
    };
    let new = launcher
        .map(|(uniqueid, boot)| MintRecord { uniqueid, boot })
        .unwrap_or_default();
    let boot_now = launcher.map(|(_, boot)| boot).or_else(current_boot);
    if ledger.contains(pid) {
        let merged = MintRecord::merged(ledger.record(pid), new);
        if merged == ledger.record(pid) {
            return Ok(());
        }
        ledger.put(pid, merged);
    } else {
        ledger.set(pid);
        ledger.put(pid, new);
    }
    ledger.stamp_unrecorded(boot_now);
    write_ledger(base, &ledger)
}

/// Forget that csq minted each of `pids`: the sweep calls this, under the lock,
/// once its item is gone, so the ledger does not accumulate every pid ever
/// launched (which would, over time, attest every hash collision). A missing
/// ledger or an already-clear bit is a no-op; an unreadable ledger is left
/// untouched and reported.
pub fn forget_mint(base: &Path, pids: &[u32], held: &MintGuard) -> Result<(), LedgerUnreadable> {
    forget_mint_at(base, pids, current_boot(), held)
}

/// [`forget_mint`] in the boot session `boot_now` (what stamps the bits left without a record).
fn forget_mint_at(
    base: &Path,
    pids: &[u32],
    boot_now: Option<BootId>,
    _held: &MintGuard,
) -> Result<(), LedgerUnreadable> {
    let mut ledger = read_ledger(base)?;
    if !ledger.contains_any(pids) {
        return Ok(());
    }
    for &pid in pids {
        ledger.clear(pid);
    }
    ledger.stamp_unrecorded(boot_now);
    write_ledger(base, &ledger)
}

fn write_ledger(base: &Path, ledger: &MintLedger) -> Result<(), LedgerUnreadable> {
    let target = ledger_path(base);
    let tmp = crate::platform::fs::unique_tmp_path(&target);
    let written = std::fs::write(&tmp, ledger.to_bytes()).and_then(|()| {
        crate::platform::fs::atomic_replace(&tmp, &target).map_err(std::io::Error::other)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerUnreadable);
    }
    Ok(())
}

#[cfg(not(test))]
fn wait_params() -> (u32, Duration) {
    (MINT_WAIT_ATTEMPTS, MINT_WAIT_DELAY)
}

#[cfg(test)]
thread_local! {
    static WAIT_OVERRIDE: std::cell::Cell<Option<(u32, Duration)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn wait_params() -> (u32, Duration) {
    WAIT_OVERRIDE
        .with(|w| w.get())
        .unwrap_or((MINT_WAIT_ATTEMPTS, MINT_WAIT_DELAY))
}

/// Test seam: shorten the creator's wait on THIS thread so a "lock busy, the
/// launch refuses" test does not spend the production 8s. Restores on drop.
#[cfg(test)]
pub(crate) struct ShortWait;

#[cfg(test)]
impl ShortWait {
    pub(crate) fn set() -> Self {
        WAIT_OVERRIDE.with(|w| w.set(Some((2, Duration::from_millis(5)))));
        Self
    }
}

#[cfg(test)]
impl Drop for ShortWait {
    fn drop(&mut self) {
        WAIT_OVERRIDE.with(|w| w.set(None));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_pid_of_accepts_only_the_exact_term_shape() {
        assert_eq!(term_pid_of("term-4242"), Some(4242));
        for not_term in [
            "term-",
            "term-0x10",
            "term-+7",
            "term-007",
            "term-42-x",
            "term-4294967296",
            "interactive-capture-abc",
            "exec-codex-1",
            "config-3",
            "",
        ] {
            assert_eq!(term_pid_of(not_term), None, "{not_term:?}");
        }
    }

    /// Run `f` on another thread, as another process's creator or sweep would.
    fn elsewhere<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(f).join().unwrap()
    }

    /// The sweep's try-lock never waits and reports busy; a creator holding it
    /// excludes the sweep, and the reverse; release makes it free again.
    #[test]
    fn the_sweep_and_a_creator_exclude_each_other() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().to_path_buf();

        // A creator (another thread) holds the lock: the sweep is told busy.
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let creator_base = path.clone();
        let creator = std::thread::spawn(move || {
            let _guard = acquire_for_mint(&creator_base).unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx.recv().unwrap();
        assert!(matches!(try_acquire_for_sweep(&path), SweepLock::Busy));
        release_tx.send(()).unwrap();
        creator.join().unwrap();

        // The sweep holds it: a creator that cannot get it inside its wait
        // refuses (fails closed) rather than proceeding.
        let SweepLock::Held(sweep) = try_acquire_for_sweep(&path) else {
            panic!("a free lock must be taken by the sweep");
        };
        let refused = elsewhere({
            let path = path.clone();
            move || {
                let _short = ShortWait::set();
                acquire_for_mint(&path).unwrap_err()
            }
        });
        assert_eq!(refused, MintLockError::Busy);
        drop(sweep);
        assert!(elsewhere(move || acquire_for_mint(&path).is_ok()));
    }

    /// The same thread can never hold the leaf twice (it would self-deadlock a
    /// blocking acquire): the lock order refuses it, reported `Unavailable`.
    #[test]
    fn the_same_thread_cannot_take_the_leaf_twice() {
        let base = tempfile::tempdir().unwrap();
        let _first = acquire_for_mint(base.path()).unwrap();
        assert_eq!(
            acquire_for_mint(base.path()).unwrap_err(),
            MintLockError::Unavailable
        );
        assert!(matches!(
            try_acquire_for_sweep(base.path()),
            SweepLock::Unavailable
        ));
    }

    /// The mint lock lives beside the dirs, under the accounts dir. Only unix materializes
    /// it as a file; on Windows it is a named mutex keyed on the same path.
    #[test]
    fn the_lock_file_lives_under_the_accounts_dir_not_in_a_handle_dir() {
        let base = tempfile::tempdir().unwrap();
        let handle = base
            .path()
            .join(crate::session::handle_dir::term_handle_dir_name(4242));
        std::fs::create_dir(&handle).unwrap();
        let _g = acquire_for_mint(base.path()).unwrap();
        #[cfg(unix)]
        assert!(mint_lock_path(base.path()).is_file());
        assert_eq!(
            mint_lock_path(base.path()).parent(),
            Some(base.path()),
            "never inside a term-<pid> dir, which is what the sweep is deleting around"
        );
        assert_eq!(
            std::fs::read_dir(&handle).unwrap().count(),
            0,
            "taking the mint lock wrote into a handle dir"
        );
    }

    /// Absent is empty; a recorded pid is attested and others are not; an
    /// existing-but-malformed file is UNREADABLE, never empty (RED against a
    /// reader that folds corruption into "nothing minted").
    #[test]
    fn the_ledger_records_pids_and_corruption_is_unreadable_not_empty() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(read_ledger(base.path()), Ok(MintLedger::empty()));
        assert!(!read_ledger(base.path()).unwrap().contains(4242));

        let guard = acquire_for_mint(base.path()).unwrap();
        record_mint(base.path(), 4242, None, &guard).unwrap();
        record_mint(base.path(), 99_999, None, &guard).unwrap();
        record_mint(base.path(), 4242, None, &guard).unwrap();
        drop(guard);
        let ledger = read_ledger(base.path()).unwrap();
        assert!(ledger.contains(4242) && ledger.contains(99_999));
        assert!(!ledger.contains(4243) && !ledger.contains(0));
        assert!(ledger.contains_any(&[1, 4242]));
        assert!(!ledger.contains_any(&[1, 2]));

        let path = ledger_path(base.path());
        // Wrong size, wrong magic, a directory: all unreadable.
        std::fs::write(&path, b"short").unwrap();
        assert_eq!(read_ledger(base.path()), Err(LedgerUnreadable));
        let mut wrong_magic = vec![0u8; LEDGER_V1_LEN];
        wrong_magic[..8].copy_from_slice(b"NOTALEDG");
        std::fs::write(&path, &wrong_magic).unwrap();
        assert_eq!(read_ledger(base.path()), Err(LedgerUnreadable));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(read_ledger(base.path()), Err(LedgerUnreadable));
    }

    /// A symlinked ledger is not followed (it is "something else": unreadable).
    #[cfg(unix)]
    #[test]
    fn a_symlinked_ledger_is_unreadable() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::write(&real, vec![0u8; LEDGER_V1_LEN]).unwrap();
        std::os::unix::fs::symlink(&real, ledger_path(base.path())).unwrap();
        assert_eq!(read_ledger(base.path()), Err(LedgerUnreadable));
    }

    /// F2: a corrupt ledger is never silently replaced. It stays byte-for-byte,
    /// recording refuses (so nothing is attested), and the sweep's reader still
    /// reports it unreadable. Fails on the old `unwrap_or_default` reset, which
    /// replaced it with a fresh ledger containing pid 77.
    #[test]
    fn recording_over_an_unreadable_ledger_leaves_it_in_place_and_fails_closed() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(ledger_path(base.path()), b"junk").unwrap();
        let guard = acquire_for_mint(base.path()).unwrap();
        assert_eq!(
            record_mint(base.path(), 77, None, &guard),
            Err(LedgerUnreadable)
        );
        assert_eq!(std::fs::read(ledger_path(base.path())).unwrap(), b"junk");
        assert_eq!(read_ledger(base.path()), Err(LedgerUnreadable));
        // Out-of-range pids are refused, not recorded.
        assert!(record_mint(base.path(), 0, None, &guard).is_err());
        assert!(record_mint(base.path(), LEDGER_MAX_PID + 1, None, &guard).is_err());
    }

    /// S2-3: forgetting clears only the named pids' bits, keeps the others, and
    /// leaves an unreadable ledger untouched.
    #[test]
    fn forgetting_a_mint_clears_only_its_pids_and_never_touches_a_corrupt_ledger() {
        let base = tempfile::tempdir().unwrap();
        let guard = acquire_for_mint(base.path()).unwrap();
        for pid in [10, 11, 12] {
            record_mint(base.path(), pid, None, &guard).unwrap();
        }
        forget_mint(base.path(), &[10, 12], &guard).unwrap();
        let ledger = read_ledger(base.path()).unwrap();
        assert!(!ledger.contains(10) && !ledger.contains(12) && ledger.contains(11));
        // Nothing to clear: no write, still fine.
        forget_mint(base.path(), &[10], &guard).unwrap();
        std::fs::write(ledger_path(base.path()), b"junk").unwrap();
        assert_eq!(
            forget_mint(base.path(), &[11], &guard),
            Err(LedgerUnreadable)
        );
        assert_eq!(std::fs::read(ledger_path(base.path())).unwrap(), b"junk");
    }

    const BOOT_A: BootId = [0xAA; 16];
    const BOOT_B: BootId = [0xBB; 16];

    fn bitset(bits: &[u32]) -> Vec<u8> {
        let mut set = vec![0u8; BITS_LEN];
        for &pid in bits {
            set[pid as usize / 8] |= 1 << (pid % 8);
        }
        set
    }

    /// A hand-built current-format body (everything but the checksum): the bitset for `bits`,
    /// then `records` as written, in order.
    fn v3_body(bits: &[u32], records: &[(u32, u64, BootId)]) -> Vec<u8> {
        let mut out = LEDGER_MAGIC.to_vec();
        out.extend_from_slice(&bitset(bits));
        out.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for &(pid, uniqueid, boot) in records {
            out.extend_from_slice(&pid.to_le_bytes());
            out.extend_from_slice(&uniqueid.to_le_bytes());
            out.extend_from_slice(&boot);
        }
        out
    }

    /// `body` with a correct checksum behind it, so a shape fault is what rejects it.
    fn seal(mut body: Vec<u8>) -> Vec<u8> {
        let digest = sha256(&body);
        body.extend_from_slice(&digest);
        body
    }

    /// A hand-built second-format file (no checksum, a reserved word per record).
    fn v2_file(bits: &[u32], records: &[(u32, u64, BootId, u64)]) -> Vec<u8> {
        let mut out = LEDGER_MAGIC_V2.to_vec();
        out.extend_from_slice(&bitset(bits));
        out.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for &(pid, uniqueid, boot, reserved) in records {
            out.extend_from_slice(&pid.to_le_bytes());
            out.extend_from_slice(&uniqueid.to_le_bytes());
            out.extend_from_slice(&boot);
            out.extend_from_slice(&reserved.to_le_bytes());
        }
        out
    }

    /// The reader still accepts the first format (a dev build wrote it): its bits attest,
    /// its launchers are unrecorded, and the next write upgrades the file without losing a bit.
    #[test]
    fn a_v1_ledger_is_read_with_unrecorded_launchers_and_upgraded_on_the_next_write() {
        let base = tempfile::tempdir().unwrap();
        let mut v1 = LEDGER_MAGIC_V1.to_vec();
        let mut bits = vec![0u8; BITS_LEN];
        bits[4242 / 8] |= 1 << (4242 % 8);
        v1.extend_from_slice(&bits);
        std::fs::write(ledger_path(base.path()), &v1).unwrap();

        let ledger = read_ledger(base.path()).unwrap();
        assert!(ledger.contains(4242));
        assert_eq!(ledger.record(4242), MintRecord::default());
        assert_eq!(
            ledger.record(4242).basis(Some(BOOT_A)),
            LauncherBasis::Unrecorded
        );

        let guard = acquire_for_mint(base.path()).unwrap();
        record_mint(base.path(), 77, Some((900, BOOT_A)), &guard).unwrap();
        let raw = std::fs::read(ledger_path(base.path())).unwrap();
        assert!(
            raw.starts_with(LEDGER_MAGIC),
            "rewritten as the current format"
        );
        let upgraded = read_ledger(base.path()).unwrap();
        assert!(upgraded.contains(4242) && upgraded.contains(77));
        assert_eq!(upgraded.record(77).uniqueid, 900);
        // (the legacy bit keeps no id; it is stamped with the boot that upgraded it)
        assert_eq!(
            upgraded.record(4242),
            MintRecord {
                uniqueid: 0,
                boot: BOOT_A
            }
        );
    }

    #[test]
    fn a_launcher_identity_round_trips_and_a_malformed_ledger_is_unreadable() {
        let base = tempfile::tempdir().unwrap();
        let guard = acquire_for_mint(base.path()).unwrap();
        record_mint(base.path(), 5000, Some((123_456, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 300, None, &guard).unwrap();
        let ledger = read_ledger(base.path()).unwrap();
        assert_eq!(
            ledger.record(5000),
            MintRecord {
                uniqueid: 123_456,
                boot: BOOT_A
            }
        );
        assert_eq!(ledger.record(300).uniqueid, 0, "no id was read");
        assert_eq!(
            ledger.attested(&[300, 5000, 6000]),
            vec![(300, ledger.record(300)), (5000, ledger.record(5000))]
        );

        let path = ledger_path(base.path());
        let good_body = v3_body(&[5000], &[(5000, 7, BOOT_A)]);
        std::fs::write(&path, seal(good_body.clone())).unwrap();
        assert!(
            read_ledger(base.path()).is_ok(),
            "the hand-built file is valid"
        );
        // Each of these is something no writer produces, with a CORRECT checksum behind it
        // wherever there is one, so the shape check is what rejects it.
        let mut count_too_big = good_body.clone();
        count_too_big[LEDGER_V1_LEN..LEDGER_V1_LEN + 4].copy_from_slice(&2u32.to_le_bytes());
        let mut truncated = good_body.clone();
        truncated.pop();
        let mut trailing = good_body.clone();
        trailing.push(0);
        let too_many = v3_body(&[5000], &[(5000, 7, BOOT_A), (5001, 8, BOOT_A)]);
        let unsorted = v3_body(&[5000, 5001], &[(5001, 7, BOOT_A), (5000, 8, BOOT_A)]);
        let repeated = v3_body(&[5000], &[(5000, 7, BOOT_A), (5000, 8, BOOT_A)]);
        let bit_clear = v3_body(&[], &[(5000, 7, BOOT_A)]);
        let out_of_range = v3_body(&[], &[(LEDGER_MAX_PID + 1, 7, BOOT_A)]);
        let mut shapes: Vec<(&str, Vec<u8>)> = [
            ("count above the records present", count_too_big),
            ("truncated record", truncated),
            ("trailing bytes", trailing),
            ("a record for a pid with no bit", too_many),
            ("pids out of order", unsorted),
            ("a pid recorded twice", repeated),
            ("a record whose bit is clear", bit_clear),
            ("a pid beyond the ledger", out_of_range),
        ]
        .into_iter()
        .map(|(what, body)| (what, seal(body)))
        .collect();
        // And the checksum itself: absent, short, long, or for other bytes.
        let sealed = seal(good_body.clone());
        shapes.push(("no checksum", good_body.clone()));
        shapes.push(("a short checksum", sealed[..sealed.len() - 1].to_vec()));
        let mut long = sealed.clone();
        long.push(0);
        shapes.push(("a long checksum", long));
        let mut other = sealed.clone();
        let last = other.len() - 1;
        other[last] ^= 1;
        shapes.push(("a checksum of other bytes", other));
        for (what, bytes) in shapes {
            std::fs::write(&path, &bytes).unwrap();
            assert!(read_ledger(base.path()).is_err(), "{what}");
        }
    }

    /// A second-format file (a dev build, withdrawn before release) has no checksum, so its
    /// records are not believed: the bits attest, every launcher is unrecorded, and the next
    /// write stamps the bits and replaces the file with a checksummed one. RED against a reader
    /// that believes the launcher ids of a file nothing vouches for.
    #[test]
    fn a_second_format_file_is_read_as_bits_only_and_replaced_on_the_next_write() {
        let base = tempfile::tempdir().unwrap();
        let path = ledger_path(base.path());
        std::fs::write(&path, v2_file(&[5000], &[(5000, 500, BOOT_A, 800)])).unwrap();
        let ledger = read_ledger(base.path()).unwrap();
        assert!(ledger.contains(5000));
        assert_eq!(ledger.record(5000), MintRecord::default());
        assert_eq!(
            ledger.record(5000).basis(Some(BOOT_A)),
            LauncherBasis::Unrecorded
        );
        // The shape is still checked: a second-format file that is malformed is unreadable.
        let mut torn = v2_file(&[5000], &[(5000, 500, BOOT_A, 800)]);
        torn.pop();
        std::fs::write(&path, &torn).unwrap();
        assert!(read_ledger(base.path()).is_err());
        std::fs::write(&path, v2_file(&[5000], &[(5000, 500, BOOT_A, 800)])).unwrap();

        let guard = acquire_for_mint(base.path()).unwrap();
        record_mint(base.path(), 77, Some((900, BOOT_A)), &guard).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            raw.starts_with(LEDGER_MAGIC),
            "replaced by the current format"
        );
        let upgraded = read_ledger(base.path()).unwrap();
        assert_eq!(upgraded.record(77).uniqueid, 900);
        assert_eq!(
            upgraded.record(5000),
            MintRecord {
                uniqueid: 0,
                boot: BOOT_A
            },
            "stamped with the boot that rewrote it, no id"
        );
    }

    /// The file carries a checksum: a byte that changed while the structure stayed valid (a
    /// raised launcher id, another boot's uuid, a bit set for an unrelated pid) makes the
    /// ledger unreadable, so the sweep deletes nothing, instead of being believed (D237 R2
    /// security R2-4). RED against a reader that checks structure only.
    #[test]
    fn a_ledger_whose_bytes_changed_but_whose_shape_is_valid_is_unreadable() {
        let base = tempfile::tempdir().unwrap();
        let file = ledger_path(base.path());
        let guard = acquire_for_mint(base.path()).unwrap();
        record_mint(base.path(), 5000, Some((123_456, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 6000, Some((222_222, BOOT_A)), &guard).unwrap();
        let good = std::fs::read(&file).unwrap();
        assert!(read_ledger(base.path()).is_ok(), "control");
        let record0 = LEDGER_V1_LEN + 4;
        for (what, offset, mask) in [
            ("a launcher id", record0 + 4, 0x40u8),
            ("a boot uuid", record0 + 12, 0x01),
            (
                "a bit of an unrelated pid",
                LEDGER_MAGIC.len() + 7000 / 8,
                1 << (7000 % 8),
            ),
            ("the last byte of the file", good.len() - 1, 0x01),
        ] {
            let mut bad = good.clone();
            bad[offset] ^= mask;
            std::fs::write(&file, &bad).unwrap();
            assert!(read_ledger(base.path()).is_err(), "{what}");
        }
        std::fs::write(&file, &good).unwrap();
        assert!(
            read_ledger(base.path()).is_ok(),
            "the untouched file still reads"
        );
    }

    /// A bit with no record (a v1 bit, or a mint whose launcher id could not be read) is
    /// stamped with the boot session of the write that found it, which is what lets a restart
    /// clear it: the bit was set no later than that write, so in any later boot the launcher
    /// is gone. It never claims anything about the boot that stamped it.
    #[test]
    fn a_bit_without_a_record_is_stamped_with_the_boot_that_wrote_the_ledger() {
        let base = tempfile::tempdir().unwrap();
        let mut v1 = LEDGER_MAGIC_V1.to_vec();
        let mut bits = vec![0u8; BITS_LEN];
        for pid in [4242usize, 99_999] {
            bits[pid / 8] |= 1 << (pid % 8);
        }
        v1.extend_from_slice(&bits);
        std::fs::write(ledger_path(base.path()), &v1).unwrap();
        let guard = acquire_for_mint(base.path()).unwrap();

        record_mint(base.path(), 77, Some((900, BOOT_A)), &guard).unwrap();
        let ledger = read_ledger(base.path()).unwrap();
        for pid in [4242, 99_999] {
            let stamped = ledger.record(pid);
            assert_eq!((stamped.uniqueid, stamped.boot), (0, BOOT_A), "{pid}");
            assert_eq!(stamped.basis(Some(BOOT_A)), LauncherBasis::Unrecorded);
            assert_eq!(stamped.basis(Some(BOOT_B)), LauncherBasis::PreviousBoot);
        }
        assert_eq!(ledger.record(77).uniqueid, 900, "the new mint keeps its id");

        // A mint whose launcher id could not be read is stamped by the boot the writer is in
        // when it can read one; with no readable boot nothing is claimed.
        record_mint(base.path(), 78, None, &guard).unwrap();
        let unstamped = read_ledger(base.path()).unwrap().record(78);
        assert_eq!(unstamped.uniqueid, 0);
        assert_eq!(unstamped.boot, current_boot().unwrap_or(NO_BOOT));
        // Forgetting also stamps what it finds, in the boot it is given.
        let mut bare = LEDGER_MAGIC_V1.to_vec();
        bare.extend_from_slice(&bits);
        std::fs::write(ledger_path(base.path()), &bare).unwrap();
        forget_mint_at(base.path(), &[4242], Some(BOOT_B), &guard).unwrap();
        let after = read_ledger(base.path()).unwrap();
        assert!(!after.contains(4242));
        assert_eq!(after.record(99_999).boot, BOOT_B);
        // No readable boot: the survivor stays unrecorded.
        std::fs::write(ledger_path(base.path()), &bare).unwrap();
        forget_mint_at(base.path(), &[4242], None, &guard).unwrap();
        assert_eq!(
            read_ledger(base.path()).unwrap().record(99_999),
            MintRecord::default()
        );
    }

    /// A pid minted twice gets one record that is safe for both launchers' descendants.
    #[test]
    fn a_pid_minted_twice_keeps_one_record_that_covers_both_launchers() {
        let base = tempfile::tempdir().unwrap();
        let guard = acquire_for_mint(base.path()).unwrap();
        let record_of = |pid| read_ledger(base.path()).unwrap().record(pid);

        // Same boot: the smaller id, because every later launcher's descendants sit above it.
        record_mint(base.path(), 10, Some((500, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 10, Some((900, BOOT_A)), &guard).unwrap();
        assert_eq!(record_of(10).uniqueid, 500);
        // The order they arrive in does not matter.
        record_mint(base.path(), 11, Some((900, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 11, Some((500, BOOT_A)), &guard).unwrap();
        assert_eq!(record_of(11).uniqueid, 500);

        // An earlier boot's launcher is gone with its boot: the new one replaces it.
        record_mint(base.path(), 12, Some((500, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 12, Some((40, BOOT_B)), &guard).unwrap();
        assert_eq!((record_of(12).uniqueid, record_of(12).boot), (40, BOOT_B));

        // Either launcher unrecorded: nothing can be compared, only the boot is known.
        record_mint(base.path(), 13, Some((0, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 13, Some((900, BOOT_A)), &guard).unwrap();
        assert_eq!(
            record_of(13),
            MintRecord {
                uniqueid: 0,
                boot: BOOT_A
            }
        );
        record_mint(base.path(), 14, Some((900, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 14, Some((0, BOOT_A)), &guard).unwrap();
        assert_eq!(
            record_of(14),
            MintRecord {
                uniqueid: 0,
                boot: BOOT_A
            }
        );
    }

    #[test]
    fn a_record_gives_a_basis_only_against_a_boot_it_can_compare() {
        let rec = |uniqueid, boot| MintRecord { uniqueid, boot };
        assert_eq!(
            rec(500, BOOT_A).basis(Some(BOOT_A)),
            LauncherBasis::SameBoot { uniqueid: 500 }
        );
        assert_eq!(
            rec(500, BOOT_A).basis(Some(BOOT_B)),
            LauncherBasis::PreviousBoot
        );
        // Not knowing the id still proves a previous boot; it proves nothing in this one.
        assert_eq!(
            rec(0, BOOT_A).basis(Some(BOOT_B)),
            LauncherBasis::PreviousBoot
        );
        assert_eq!(
            rec(0, BOOT_A).basis(Some(BOOT_A)),
            LauncherBasis::Unrecorded
        );
        // launchd's id is not a launcher's; no boot recorded or no boot now compares nothing.
        assert_eq!(
            rec(1, BOOT_A).basis(Some(BOOT_A)),
            LauncherBasis::Unrecorded
        );
        assert_eq!(
            rec(500, NO_BOOT).basis(Some(BOOT_A)),
            LauncherBasis::Unrecorded
        );
        assert_eq!(rec(500, BOOT_A).basis(None), LauncherBasis::Unrecorded);
        assert_eq!(
            rec(500, BOOT_A).basis(Some(NO_BOOT)),
            LauncherBasis::Unrecorded
        );
    }

    #[test]
    fn the_boot_session_id_parses_only_a_real_uuid() {
        let text = b"0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9\0";
        let parsed = parse_boot_uuid(text).unwrap();
        assert_eq!(parsed[0], 0x0A);
        assert_eq!(parsed[15], 0xF9);
        assert_eq!(
            parse_boot_uuid(&text[..36]),
            Some(parsed),
            "NUL is optional"
        );
        for bad in [
            &b""[..],
            b"0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F",
            b"0A1B2C3D_4E5F_6071_8293_A4B5C6D7E8F9",
            b"0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8FG",
            b"00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(parse_boot_uuid(bad), None, "{bad:?}");
        }
    }

    /// The real kernel reads: this process has a boot session and a launcher identity in it,
    /// and a pid that cannot exist has none (so its item is unrecorded, never guessed).
    #[cfg(target_os = "macos")]
    #[test]
    fn this_process_has_a_boot_session_and_a_launcher_identity() {
        let boot = current_boot().expect("kern.bootsessionuuid is readable");
        assert_ne!(boot, NO_BOOT);
        assert_eq!(current_boot(), Some(boot), "stable within a boot");
        // A separate process reads the same value (the sysctl is the kernel's, not this
        // process's). RED if the uuid were per-process or per-read.
        let out = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.bootsessionuuid"])
            .output()
            .expect("sysctl runs");
        assert!(out.status.success());
        assert_eq!(
            parse_boot_uuid(out.stdout.trim_ascii()),
            Some(boot),
            "another process reads the same boot session"
        );
        let (uniqueid, in_boot) = launcher_identity(std::process::id()).expect("own identity");
        assert!(uniqueid > 1, "a user process is never launchd");
        assert_eq!(in_boot, boot);
        assert_eq!(launcher_identity(2_000_000_000), None);
    }

    /// Where the kernel has no such ids nothing is recorded: the ledger stays a bare bitset.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn without_kernel_unique_ids_no_identity_is_recorded() {
        assert_eq!(current_boot(), None);
        assert_eq!(launcher_identity(std::process::id()), None);
    }

    /// Forgetting a mint drops its record with its bit.
    #[test]
    fn forgetting_a_mint_drops_its_record() {
        let base = tempfile::tempdir().unwrap();
        let guard = acquire_for_mint(base.path()).unwrap();
        record_mint(base.path(), 30, Some((500, BOOT_A)), &guard).unwrap();
        record_mint(base.path(), 31, Some((600, BOOT_A)), &guard).unwrap();
        forget_mint(base.path(), &[30], &guard).unwrap();
        let ledger = read_ledger(base.path()).unwrap();
        assert_eq!(ledger.record(30), MintRecord::default());
        assert_eq!(ledger.record(31).uniqueid, 600);
        // A re-mint of the forgotten pid starts from nothing, not from the old record.
        record_mint(base.path(), 30, Some((9000, BOOT_B)), &guard).unwrap();
        assert_eq!(read_ledger(base.path()).unwrap().record(30).uniqueid, 9000);
    }

    #[test]
    fn the_fixed_messages_name_no_path_or_os_text() {
        for e in [MintLockError::Busy, MintLockError::Unavailable] {
            let m = e.message();
            assert!(!m.contains('/') && !m.contains('\\'), "{m}");
        }
    }
}
