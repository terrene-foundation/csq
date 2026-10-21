//! The delete guard's process scan: which live processes carry a `CLAUDE_CONFIG_DIR`, and which
//! descend from a gone terminal's launcher.
//!
//! This is NOT the session-display listing. `read_session_kind_via` drops a process with no
//! controlling terminal and a process whose argv\[0\] is not `claude`; that is right for a
//! display row and wrong for a guard that gates a DELETE (guard-reader-writer-parity
//! MUST-1: read through the widest accessor). A Claude Code that outlived its launcher is
//! exactly the process most likely to have lost its terminal, and a CC install under a
//! `node` wrapper has a different argv\[0\].
//!
//! The scan therefore reads every process, with no tty and no argv\[0\] filter. For each
//! same-uid process it records every `CLAUDE_CONFIG_DIR` entry of a readable environment; a
//! same-uid process whose environment or identity cannot be read is counted `unreadable`,
//! and the caller keeps (fail closed). For every process of any user it records the
//! creation lineage below, and a live process of ANY user whose unique id cannot be read is
//! counted `unreadable` too: it is in no chain, so a child it forks later could not be placed.
//!
//! **What the environment read sees.** `KERN_PROCARGS2` returns the environment a process
//! was LAUNCHED with. A process that set `CLAUDE_CONFIG_DIR` afterwards (`setenv`, or a
//! wrapper that sets `process.env` and then loads Claude Code in-process), a process whose
//! environment macOS withholds (the kernel returns an empty environment for shared-cache
//! system binaries on macOS 27; a Claude Code tool shell is `/bin/zsh`), and one that rewrote
//! its own environment area are invisible to it. Descent covers all three.
//!
//! # Descent
//!
//! A process holds terminal N when its readable environment names `term-N`, when it is in N's
//! process group, or when it DESCENDS from N's launcher L: the process csq minted
//! `term-<pid>` for, recorded with its unique id `u_L` and its boot session
//! (`session::term_mint`). Descent is decided from unique ids alone, which are facts about
//! the past that nothing can change:
//!
//! * `p_uniqueid` is assigned from a counter that only grows, when a process is forked, and
//!   is kept across `exec` (a live test). `p_puniqueid` is the id of the process that forked
//!   it, fixed at fork time and kept after the creator dies and the process is reparented to
//!   launchd (a live test). Both restart at boot, so an id means something within one boot
//!   session only. That the boot session id (`kern.bootsessionuuid`) is constant within a boot
//!   and new at every boot is an ASSUMPTION (`session::term_mint::BootId`): the kernel's
//!   source is not cited, a live test checks one boot only, and the owner is asked to accept
//!   the rest.
//! * A creator is forked before its children, so every chain `child -> creator -> ...` has
//!   strictly decreasing ids, and every descendant of L has an id above `u_L`.
//!
//! The creator chain of a process P is walked through the scan's own table (unique id to
//! creator id), never through `pbi_ppid`, which names launchd for a launchd-spawned service
//! and for a closed terminal's orphan alike. Let C be the first creator id on the chain:
//!
//! 1. `C == u_L`: P descends from L. HELD.
//! 2. `C < u_L`, or the chain ends at launchd (id 1): P was forked by something older than
//!    L, so it does not descend from L.
//! 3. `C > u_L` and C is in the table: continue from C's creator.
//! 4. `C > u_L` and C is not in the table: C is dead, and its own creator is lost. C may be a
//!    descendant of L (a double-forked daemon) or not. UNKNOWN for this terminal, and for this
//!    terminal only.
//!
//! **There is no way to rule out a dead creator above L's id.** A scan is not a snapshot: a
//! listed process can fork and exit before it is read, and what it forked is then neither
//! listed nor read. Any record made from "this scan found nothing" (an earlier design kept
//! the table's largest id as a "descent-free latch" for later scans) is therefore unsound:
//! the next generation of such a chain has an id above the record and was never examined.
//! Case 4 stays unknown for as long as the dead creator is the first link the table has,
//! and a terminal older than the newest such orphan stays pinned until that orphan exits or
//! the Mac restarts (a launcher of an earlier boot session has no live descendant).
//!
//! **Global unknowns.** A scan that ran out of time, a pid table that cannot be read whole, a
//! live process (of any user) whose unique id, or same-uid process whose environment, cannot be
//! read, and a table that contradicts itself (one unique id on two pids, a creator id of 0 or
//! one not below its child's) are unknown for EVERY terminal, because no descent verdict rests
//! on a damaged table.
//!
//! **The one assumption descent makes**, for the owner to accept or refuse (a named acceptor is
//! required): a process not FORKED (transitively) from N's launcher carries `term-N` only by a
//! manual act or by a broker that replays a stored or client environment (`export`, `tmux -e`,
//! `launchctl setenv`, `sudo VAR=`, `at`, an sshd `AcceptEnv`, `open --env`). Descent covers
//! every process csq or Claude Code forks on that terminal, whatever environment it was handed;
//! it does not cover one a daemon or broker creates on a client's behalf, which is why that
//! class is named and not claimed away. Nothing here reads a process's environment to attribute
//! it to an ancestor: the nearest readable ancestor that names `term-N` is itself a holder, so
//! that walk could not change a verdict.
//!
//! **The process-group witness.** The scan also records the process group of every live
//! same-uid process, from the kernel's process record and so independent of the
//! environment; the caller treats a process in the terminal's group (the launcher's pid) as
//! a holder, whatever its image. A group outlives its leader and survives reparenting, so
//! the dead launcher's descendants stay in it unless they started a session of their own.
//! It only ever adds keeps.

use super::{
    list_pids, parse_procargs, probe_bsd_info, probe_uniq, procargs_capacity, read_cwd,
    read_procargs, BsdFacts, Probe, Uniq,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long one scan may run, counted from BEFORE the pid list is read and the argument
/// buffer allocated, and checked between pids: once it is spent the scan starts no further
/// pid and is incomplete, which the caller reads as unknown (keep). It is not a wall-clock
/// bound: one kernel read for one pid (`KERN_PROCARGS2`, `proc_pidinfo`) has no timeout of
/// its own, so a scan can overrun by that read.
///
/// A scan also runs under the term mint lock, whose creators wait `MINT_WAIT_ATTEMPTS` x
/// `MINT_WAIT_DELAY` (13s, `session::term_mint`). The constants the sweep holds that lock
/// for sum to about 11s: two keychain calls of `KEYCHAIN_OP_TIMEOUT` 5s +
/// `MIN_POST_EXIT_GRACE` 250ms (10.5s) and this scan's 500ms. The directory check, the pid
/// probe, the mint-ledger write and a single unbounded kernel read are not in that sum;
/// they live in the remaining ~2s, with no enforcement behind them. A hold that overruns
/// makes a creator's `csq run` refuse (fail closed), never delete anything.
pub(crate) const SCAN_BUDGET: Duration = Duration::from_millis(500);

/// The most creator hops one chain walk takes before it gives up (unknown, keep). Ids strictly
/// decrease along a chain, so a loop is impossible in an honest table. A chain this long is
/// NOT a damaged table (the scan stays usable for every other terminal): it is unknown for
/// the terminal being asked about (`lineage_broken`), a bound on the work of one walk. Measured
/// on a macOS 27 host: the deepest chain is 9 hops.
pub(crate) const LINEAGE_HOP_CAP: usize = 32;

/// What one process says about the guard's question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entry {
    /// Gone, or a zombie (it has no environment to read and no children to pass one to).
    Absent,
    /// A live process of another user: not a holder by environment (its keychain is not this
    /// user's), though it is still a link in a creation chain.
    Foreign,
    /// A same-uid process whose environment names no config dir, or whose environment region
    /// came back EMPTY (withheld by the kernel, or genuinely empty: they cannot be told
    /// apart, and need not be, because descent does not read the environment).
    NotHolder,
    /// A same-uid process whose readable environment names these config dirs (one per
    /// non-empty `CLAUDE_CONFIG_DIR` entry, never empty), each ABSOLUTE.
    ConfigDirs(Vec<PathBuf>),
    /// Like `ConfigDirs`, but at least one entry was RELATIVE and has been joined onto that
    /// process's own cwd. Right for the process itself.
    RelativeDirs(Vec<PathBuf>),
    /// Like `ConfigDirs`, but at least one OTHER entry was relative and its cwd could not
    /// be read, so the process is also unresolvable. The known dirs still count (a holder
    /// is a holder), and the process still counts unreadable (the caller keeps).
    PartiallyResolved(Vec<PathBuf>),
    /// A same-uid process whose environment could not be established.
    Unreadable,
}

/// The injected kernel reads behind [`entry_via`].
pub(crate) struct HolderReads<'a> {
    pub bsd: &'a dyn Fn(u32) -> Probe<BsdFacts>,
    pub args: &'a mut dyn FnMut(u32) -> Probe<Vec<u8>>,
    /// The process's unique id and its creator's.
    pub uniq: &'a dyn Fn(u32) -> Probe<Uniq>,
    /// The process's own current directory; read only for a relative `CLAUDE_CONFIG_DIR`.
    pub cwd: &'a dyn Fn(u32) -> Option<PathBuf>,
}

/// One pid's classification, plus the kernel record it was classified from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Classified {
    pub entry: Entry,
    /// The kernel's record of a live same-uid process (its process group needs no
    /// environment). `None` for a process that is gone, foreign, a zombie, or whose
    /// record could not be read.
    pub facts: Option<BsdFacts>,
}

/// Classify one pid. No terminal filter and no argv\[0\] filter, by design.
pub(crate) fn entry_via(pid: u32, uid: u32, reads: &mut HolderReads<'_>) -> Classified {
    let without_facts = |entry| Classified { entry, facts: None };
    let facts = match (reads.bsd)(pid) {
        Probe::Gone => return without_facts(Entry::Absent),
        Probe::Failed => return without_facts(Entry::Unreadable),
        Probe::Got(f) => f,
    };
    if facts.pid != pid {
        return without_facts(Entry::Unreadable);
    }
    if facts.zombie {
        return without_facts(Entry::Absent);
    }
    if facts.uid != uid {
        return without_facts(Entry::Foreign);
    }
    Classified {
        entry: env_entry(pid, reads),
        facts: Some(facts),
    }
}

/// What the environment of a live process says, before any reading of its cwd.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvRead {
    Gone,
    Unreadable,
    /// A readable or empty environment with no non-empty `CLAUDE_CONFIG_DIR` entry.
    NoDir,
    /// Every non-empty `CLAUDE_CONFIG_DIR` value, raw, never empty.
    Values(Vec<PathBuf>),
}

fn env_read(pid: u32, reads: &mut HolderReads<'_>) -> EnvRead {
    let raw = match (reads.args)(pid) {
        Probe::Gone => return EnvRead::Gone,
        Probe::Failed => return EnvRead::Unreadable,
        Probe::Got(raw) => raw,
    };
    let Some(parsed) = parse_procargs(&raw) else {
        return EnvRead::Unreadable;
    };
    // EVERY `CLAUDE_CONFIG_DIR` entry counts, not the first: a duplicated key is legal in a
    // raw environment block and which one a runtime honours is not ours to guess.
    let values = parsed.env_get_all("CLAUDE_CONFIG_DIR");
    if !values.is_empty() {
        use std::os::unix::ffi::OsStrExt;
        let named: Vec<PathBuf> = values
            .into_iter()
            .filter(|v| !v.is_empty()) // (an empty value names no directory)
            .map(|v| PathBuf::from(std::ffi::OsStr::from_bytes(v)))
            .collect();
        return if named.is_empty() {
            EnvRead::NoDir
        } else {
            EnvRead::Values(named)
        };
    }
    EnvRead::NoDir
}

/// What the environment of a live same-uid process says.
fn env_entry(pid: u32, reads: &mut HolderReads<'_>) -> Entry {
    match env_read(pid, reads) {
        EnvRead::Gone => Entry::Absent,
        EnvRead::NoDir => Entry::NotHolder,
        EnvRead::Unreadable => Entry::Unreadable,
        EnvRead::Values(values) => {
            let mut dirs = Vec::new();
            let mut unresolved = false;
            let mut relative = false;
            let mut cwd: Option<Option<PathBuf>> = None;
            for value in values {
                if value.is_absolute() {
                    dirs.push(value);
                    continue;
                }
                relative = true;
                // A relative value means nothing without THAT process's cwd (not the
                // daemon's). An unreadable or non-absolute cwd leaves it unresolvable, but
                // every OTHER entry still counts: an absolute entry that names the terminal
                // is a holder whatever a later entry does.
                match cwd.get_or_insert_with(|| (reads.cwd)(pid)) {
                    Some(cwd) if cwd.is_absolute() => dirs.push(cwd.join(value)),
                    _ => unresolved = true,
                }
            }
            match (dirs.is_empty(), unresolved, relative) {
                (true, _, _) => Entry::Unreadable,
                (false, true, _) => Entry::PartiallyResolved(dirs),
                (false, false, true) => Entry::RelativeDirs(dirs),
                (false, false, false) => Entry::ConfigDirs(dirs),
            }
        }
    }
}

/// How a terminal's launcher relates to the processes of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Descent {
    /// A live process descends from the launcher (or is the launcher): the terminal is held.
    Descendant,
    /// No live process descends from the launcher.
    Not,
    /// `processes` live processes have a chain that ends at a dead creator which may descend
    /// from the launcher: this terminal cannot be ruled out.
    Unknown { processes: usize },
}

/// Every `CLAUDE_CONFIG_DIR` found in one pass over the process table, and the creation
/// lineage of every process the pass reached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProcessEnvScan {
    /// The config dir of each same-uid process whose environment named one.
    pub config_dirs: Vec<PathBuf>,
    /// Same-uid processes whose environment or unique id could not be established.
    pub unreadable: usize,
    /// The process group of every live same-uid process the scan reached, read from the
    /// kernel's process record (so it does not depend on the environment). A group
    /// outlives its leader and survives reparenting: a descendant of a dead launcher is
    /// still in the launcher's group unless it started a session of its own.
    pub process_groups: BTreeSet<u32>,
    /// `false` when the scan stopped at its time bound before reaching every pid.
    pub complete: bool,
    /// Unique id to the unique id of the process that forked it, for every live process (any
    /// user) whose id was read. A creator id missing from here is a dead creator.
    pub lineage: HashMap<u64, u64>,
    /// The pid each lineage entry was read at, and every pid the scan's list named: what a
    /// later re-list compares against.
    pub by_pid: HashMap<u32, u64>,
    pub listed: HashSet<u32>,
    /// The largest unique id in `lineage`: everything forked after this scan has a larger one.
    pub max_id: u64,
    /// The table contradicts itself, so no descent verdict may rest on it.
    pub damaged: bool,
}

impl ProcessEnvScan {
    /// Add one live process to the lineage, marking the table damaged when it contradicts
    /// itself: one unique id on two pids, a creator id of 0 on anything but launchd (pid 1),
    /// or a creator id that is not below its child's.
    fn add(&mut self, pid: u32, uniq: Uniq) {
        use std::collections::hash_map::Entry as Slot;
        if pid != 1 && (uniq.puniqueid == 0 || uniq.puniqueid >= uniq.uniqueid) {
            self.damaged = true;
        }
        match self.lineage.entry(uniq.uniqueid) {
            Slot::Occupied(_) => self.damaged = true,
            Slot::Vacant(slot) => {
                slot.insert(uniq.puniqueid);
            }
        }
        self.by_pid.insert(pid, uniq.uniqueid);
    }

    /// Whether the process chain starting at creator id `c` reaches `launcher`. Ids strictly
    /// decrease along a chain, so reaching an id at or below the launcher's settles it.
    fn chain_reaches(&self, mut c: u64, launcher: u64) -> Option<bool> {
        for _ in 0..LINEAGE_HOP_CAP {
            if c == launcher {
                return Some(true);
            }
            if c < launcher {
                return Some(false);
            }
            match self.lineage.get(&c) {
                Some(&next) => c = next,
                // Dead creator, above the launcher: it may be a descendant of the launcher
                // whose own creator is lost.
                None => return None,
            }
        }
        None
    }

    /// Does any live process descend from the launcher whose unique id is `launcher`?
    pub(crate) fn descent(&self, launcher: u64) -> Descent {
        let mut unknown = 0usize;
        for (&id, &creator) in &self.lineage {
            if id < launcher {
                continue;
            }
            if id == launcher {
                return Descent::Descendant;
            }
            match self.chain_reaches(creator, launcher) {
                Some(true) => return Descent::Descendant,
                Some(false) => {}
                None => unknown += 1,
            }
        }
        if unknown == 0 {
            Descent::Not
        } else {
            Descent::Unknown { processes: unknown }
        }
    }

    /// This scan extended with the processes in `pids` (a fresh pid list, taken after the
    /// scan) that it has not seen: each is read with `uniq` and joins the lineage, so a
    /// descent test over the result covers a process forked after the scan listed the table.
    /// A process that cannot be read, or that the scan should have seen and did not, makes
    /// the result `unreadable` (unknown).
    pub(crate) fn with_arrivals(
        &self,
        pids: &[u32],
        uniq: &dyn Fn(u32) -> Probe<Uniq>,
    ) -> ProcessEnvScan {
        let mut next = self.clone();
        for &pid in pids {
            match uniq(pid) {
                Probe::Gone => {}
                Probe::Failed => {
                    // A pid the scan already listed and could not read (a foreign zombie)
                    // is the same unreadable process, not a new one.
                    if !self.listed.contains(&pid) {
                        next.unreadable += 1;
                    }
                }
                Probe::Got(u) => {
                    if self.lineage.contains_key(&u.uniqueid) {
                        continue; // a process the scan has
                    }
                    if u.uniqueid > self.max_id {
                        next.add(pid, u); // forked after the scan: an arrival
                    } else {
                        // Older than the scan's newest process yet absent from it.
                        next.unreadable += 1;
                    }
                }
            }
        }
        next
    }
}

/// Walk `pids`, stopping (incomplete) once `deadline` has passed. Each process is read
/// (bsd info, environment) between two reads of its unique id, which must agree: a pid that
/// was reused during its own read is unreadable, not a mix of two processes.
pub(crate) fn scan_via(
    pids: &[u32],
    uid: u32,
    deadline: Instant,
    reads: &mut HolderReads<'_>,
) -> ProcessEnvScan {
    let mut scan = ProcessEnvScan {
        complete: true,
        ..ProcessEnvScan::default()
    };
    for &pid in pids {
        if Instant::now() >= deadline {
            scan.complete = false;
            break;
        }
        scan.listed.insert(pid);
        let before = (reads.uniq)(pid);
        let classified = entry_via(pid, uid, reads);
        scan.process_groups
            .extend(classified.facts.as_ref().map(|f| f.pgid));
        let entry = classified.entry;
        // Whether the entry already counts this process unreadable.
        let counted = matches!(entry, Entry::Unreadable | Entry::PartiallyResolved(_));
        if !matches!(entry, Entry::Absent) {
            let after = (reads.uniq)(pid);
            match (before, after) {
                (Probe::Got(a), Probe::Got(b)) if a == b => scan.add(pid, a),
                // Gone: it died while being read, so it holds nothing now.
                (Probe::Gone, _) | (_, Probe::Gone) => {}
                // A live process of ANY user whose id cannot be read (or changed while it was
                // read) cannot be placed in a lineage. A foreign one is not merely a lost
                // link: with no child yet it is in no chain at all, and a same-uid child it
                // forks later (a root descendant of the launcher waiting at a prompt) would
                // be invisible. Unreadable, like a same-uid one.
                _ if !counted => scan.unreadable += 1,
                _ => {}
            }
        }
        match entry {
            Entry::Absent | Entry::Foreign | Entry::NotHolder => {}
            Entry::Unreadable => scan.unreadable += 1,
            Entry::ConfigDirs(dirs) | Entry::RelativeDirs(dirs) => scan.config_dirs.extend(dirs),
            Entry::PartiallyResolved(dirs) => {
                scan.config_dirs.extend(dirs);
                scan.unreadable += 1;
            }
        }
    }
    scan.max_id = scan.lineage.keys().copied().max().unwrap_or(0);
    scan
}

/// Read the pid list, then walk it, stopping (incomplete) once `deadline` has passed. A
/// deadline already past when the list arrives therefore gives an incomplete scan: the
/// list read counts against the budget like any pid.
///
/// A list that does not contain `own_pid` (this very process, which is alive and so is in
/// any whole table) was not read whole: `None`, like an unreadable list.
pub(crate) fn scan_listed(
    deadline: Instant,
    list: impl FnOnce() -> Option<Vec<u32>>,
    own_pid: u32,
    uid: u32,
    reads: &mut HolderReads<'_>,
) -> Option<ProcessEnvScan> {
    let pids = list()?;
    if !pids.contains(&own_pid) {
        return None;
    }
    Some(scan_via(&pids, uid, deadline, reads))
}

/// The kernel reads one real scan makes, injectable so the order they are made in is
/// testable.
pub(crate) struct Kernel<'a> {
    pub clock: &'a dyn Fn() -> Instant,
    pub list: &'a dyn Fn() -> Option<Vec<u32>>,
    pub buffer_capacity: &'a dyn Fn() -> usize,
    pub procargs: &'a dyn Fn(u32, &mut Vec<u8>) -> Probe<usize>,
    pub bsd: &'a dyn Fn(u32) -> Probe<BsdFacts>,
    pub uniq: &'a dyn Fn(u32) -> Probe<Uniq>,
    pub cwd: &'a dyn Fn(u32) -> Option<PathBuf>,
    pub own_pid: u32,
    pub uid: u32,
}

/// One pass over the process table through `kernel`. `None` when the table itself cannot
/// be read.
pub(crate) fn scan_with_kernel(budget: Duration, kernel: &Kernel<'_>) -> Option<ProcessEnvScan> {
    // Before the pid list and the buffer, which are part of what the budget pays for.
    let deadline = (kernel.clock)() + budget;
    let mut buf = vec![0u8; (kernel.buffer_capacity)()];
    let mut args = |p: u32| match (kernel.procargs)(p, &mut buf) {
        Probe::Got(len) => Probe::Got(buf[..len].to_vec()),
        Probe::Gone => Probe::Gone,
        Probe::Failed => Probe::Failed,
    };
    let mut reads = HolderReads {
        bsd: kernel.bsd,
        args: &mut args,
        uniq: kernel.uniq,
        cwd: kernel.cwd,
    };
    scan_listed(
        deadline,
        || (kernel.list)(),
        kernel.own_pid,
        kernel.uid,
        &mut reads,
    )
}

/// One pass over the real process table. `None` when the table itself cannot be read.
pub(crate) fn scan_process_env(budget: Duration) -> Option<ProcessEnvScan> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    scan_with_kernel(
        budget,
        &Kernel {
            clock: &Instant::now,
            list: &list_pids,
            buffer_capacity: &procargs_capacity,
            procargs: &read_procargs,
            bsd: &probe_bsd_info,
            uniq: &probe_uniq,
            cwd: &read_cwd,
            own_pid: std::process::id(),
            uid,
        },
    )
}

/// `scan` extended with every process forked since it listed the table, over the real
/// kernel: the pid list is read again and each pid's unique id with it. `None` when the list
/// cannot be read.
pub(crate) fn relist_process_env(scan: &ProcessEnvScan) -> Option<ProcessEnvScan> {
    let pids = list_pids()?;
    Some(scan.with_arrivals(&pids, &probe_uniq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::macos::NODEV;

    const UID: u32 = 501;
    const PID: u32 = 77;

    fn facts(uid: u32, tdev: u32, zombie: bool) -> BsdFacts {
        BsdFacts {
            pid: PID,
            uid,
            start: 1_790_000_000,
            tdev,
            claude_named: false,
            codex_named: false,
            zombie,
            pgid: 0,
        }
    }

    fn procargs(exec: &str, argv: &[&str], env: &[&str]) -> Vec<u8> {
        let mut b = u32::try_from(argv.len()).unwrap().to_ne_bytes().to_vec();
        b.extend_from_slice(exec.as_bytes());
        b.extend_from_slice(&[0, 0, 0]);
        for a in argv {
            b.extend_from_slice(a.as_bytes());
            b.push(0);
        }
        for e in env {
            b.extend_from_slice(e.as_bytes());
            b.push(0);
        }
        b.extend_from_slice(&[0, 0]);
        b
    }

    fn entry(bsd: Probe<BsdFacts>, args: Probe<Vec<u8>>) -> Entry {
        let mut a = |_: u32| args.clone();
        let mut reads = HolderReads {
            bsd: &|_| bsd.clone(),
            args: &mut a,
            uniq: &plain_uniq,
            cwd: &|_| None,
        };
        entry_via(PID, UID, &mut reads).entry
    }

    const DIR: &str = "CLAUDE_CONFIG_DIR=/x/accounts/term-4242";

    /// Every pid reports a unique id of its own, forked by launchd.
    fn plain_uniq(pid: u32) -> Probe<Uniq> {
        Probe::Got(Uniq {
            uniqueid: 1000 + u64::from(pid),
            puniqueid: 1,
        })
    }

    /// The fixture the display listing drops (no tty, argv0 `node`) is a holder here. The
    /// first assertion proves the display classification really does drop it, so the
    /// second is a difference between the two readers, not a restatement.
    #[test]
    fn a_ttyless_node_process_with_the_dir_is_held_though_the_display_listing_drops_it() {
        let raw = procargs("/usr/local/bin/node", &["node", "server.js"], &[DIR]);
        let display = crate::sessions::macos::read_session_kind_via(
            crate::sessions::CliKind::Claude,
            PID,
            UID,
            crate::sessions::macos::Reads {
                bsd: &|_| Probe::Got(facts(UID, NODEV, false)),
                args: &mut |_| Probe::Got(raw.clone()),
                cwd: &|_| Some(PathBuf::from("/")),
            },
        );
        assert_eq!(
            display,
            Ok(None),
            "the display reader drops tty-less non-claude"
        );
        assert_eq!(
            entry(Probe::Got(facts(UID, NODEV, false)), Probe::Got(raw),),
            Entry::ConfigDirs(vec![PathBuf::from("/x/accounts/term-4242")])
        );
    }

    /// An empty environment region names no dir whatever the image: the kernel's doing for a
    /// system binary, indistinguishable from a genuinely empty one elsewhere, and descent
    /// does not need it told apart. Unreadable and unparseable arguments, unreadable bsd info
    /// and an answer about another pid fail closed.
    #[test]
    fn an_empty_environment_names_no_dir_and_an_unreadable_one_fails_closed() {
        let withheld = procargs("/bin/sh", &["sh"], &[]);
        let bsd = || Probe::Got(facts(UID, NODEV, false));
        assert_eq!(entry(bsd(), Probe::Got(withheld.clone())), Entry::NotHolder);
        assert_eq!(entry(bsd(), Probe::Failed), Entry::Unreadable);
        assert_eq!(entry(bsd(), Probe::Got(vec![1, 2])), Entry::Unreadable);
        assert_eq!(
            entry(Probe::Failed, Probe::Got(withheld.clone())),
            Entry::Unreadable
        );
        let mut other = facts(UID, NODEV, false);
        other.pid = PID + 1;
        assert_eq!(
            entry(Probe::Got(other), Probe::Got(withheld)),
            Entry::Unreadable
        );
    }

    #[test]
    fn gone_foreign_zombie_and_unrelated_environments_are_not_holders() {
        let named = procargs("/usr/local/bin/node", &["node"], &[DIR]);
        let plain = procargs("/usr/local/bin/node", &["node"], &["PATH=/usr/bin"]);
        assert_eq!(entry(Probe::Gone, Probe::Got(named.clone())), Entry::Absent);
        assert_eq!(
            entry(
                Probe::Got(facts(UID + 1, NODEV, false)),
                Probe::Got(named.clone())
            ),
            Entry::Foreign,
            "another user's process: not a holder by environment, still a link in a chain"
        );
        assert_eq!(
            entry(
                Probe::Got(facts(UID, NODEV, true)),
                Probe::Got(named.clone())
            ),
            Entry::Absent
        );
        assert_eq!(
            entry(Probe::Got(facts(UID, 1, false)), Probe::Gone),
            Entry::Absent
        );
        assert_eq!(
            entry(Probe::Got(facts(UID, 1, false)), Probe::Got(plain)),
            Entry::NotHolder
        );
        let empty = procargs("/usr/local/bin/node", &["node"], &["CLAUDE_CONFIG_DIR="]);
        assert_eq!(
            entry(Probe::Got(facts(UID, 1, false)), Probe::Got(empty)),
            Entry::NotHolder
        );
    }

    /// RED against a scan that treats a relative value as unresolvable (or resolves it
    /// against the daemon's cwd): it joins the value onto the PROCESS's own cwd, and an
    /// unreadable cwd is unknown.
    #[test]
    fn a_relative_config_dir_is_resolved_against_the_processs_own_cwd() {
        let raw = procargs(
            "/usr/local/bin/node",
            &["node"],
            &["CLAUDE_CONFIG_DIR=../accounts/term-1"],
        );
        let run = |cwd: Option<&'static str>| {
            let mut a = |_: u32| Probe::Got(raw.clone());
            let mut reads = HolderReads {
                bsd: &|p| {
                    Probe::Got(BsdFacts {
                        pid: p,
                        ..facts(UID, 1, false)
                    })
                },
                args: &mut a,
                uniq: &plain_uniq,
                cwd: &|_| cwd.map(PathBuf::from),
            };
            scan_via(
                &[1],
                UID,
                Instant::now() + Duration::from_secs(60),
                &mut reads,
            )
        };
        let ok = run(Some("/w/proj"));
        assert_eq!(
            ok.config_dirs,
            vec![PathBuf::from("/w/proj/../accounts/term-1")]
        );
        assert_eq!(ok.unreadable, 0);
        let blind = run(None);
        assert!(blind.config_dirs.is_empty());
        assert_eq!(blind.unreadable, 1, "no cwd, no resolution: unknown");
        let relative_cwd = run(Some("proj"));
        assert_eq!(
            relative_cwd.unreadable, 1,
            "a cwd that is not absolute resolves nothing"
        );
    }

    /// The scan records the process group of every live same-uid process it reaches, from
    /// the kernel's process record: whatever the environment read made of it (readable,
    /// withheld, unreadable), and never for a process that is
    /// gone, foreign or a zombie.
    #[test]
    fn the_scan_records_the_group_of_every_live_same_uid_process() {
        let withheld = procargs("/bin/sh", &["sh"], &[]);
        let named = procargs("/usr/local/bin/node", &["node"], &[DIR]);
        let run = |uid: u32, zombie: bool, args: Probe<Vec<u8>>| {
            let mut a = |_: u32| args.clone();
            let mut reads = HolderReads {
                bsd: &|p| {
                    Probe::Got(BsdFacts {
                        pid: p,
                        pgid: 4242,
                        ..facts(uid, 1, zombie)
                    })
                },
                args: &mut a,
                uniq: &plain_uniq,
                cwd: &|_| None,
            };
            scan_via(
                &[1],
                UID,
                Instant::now() + Duration::from_secs(60),
                &mut reads,
            )
            .process_groups
        };
        let member = BTreeSet::from([4242]);
        // A withheld environment is no bar to being in the group.
        assert_eq!(run(UID, false, Probe::Got(withheld.clone())), member);
        // A readable environment and an unreadable one are in it too.
        assert_eq!(run(UID, false, Probe::Got(named)), member);
        assert_eq!(run(UID, false, Probe::Failed), member);
        // Foreign and zombie processes are not.
        assert!(run(UID + 1, false, Probe::Got(withheld.clone())).is_empty());
        assert!(run(UID, true, Probe::Got(withheld)).is_empty());
    }

    /// An empty environment is not unreadable (descent places the process by its ids), and a
    /// same-uid process whose arguments cannot be read is.
    #[test]
    fn an_empty_environment_is_not_unreadable_but_unreadable_arguments_are() {
        let withheld = procargs("/Applications/Foo.app/Contents/MacOS/Foo", &["Foo"], &[]);
        // pid 1: empty environment. pid 2: arguments unreadable.
        let mut a = |p: u32| match p {
            2 => Probe::Failed,
            _ => Probe::Got(withheld.clone()),
        };
        let mut reads = HolderReads {
            bsd: &|p| {
                Probe::Got(BsdFacts {
                    pid: p,
                    ..facts(UID, 1, false)
                })
            },
            args: &mut a,
            uniq: &plain_uniq,
            cwd: &|_| None,
        };
        let scan = scan_via(
            &[1, 2],
            UID,
            Instant::now() + Duration::from_secs(60),
            &mut reads,
        );
        assert_eq!(scan.unreadable, 1, "only the unreadable arguments");
        assert!(scan.config_dirs.is_empty());
    }

    /// The budget is counted from before the pid list is read: a list that arrives after the
    /// deadline gives an incomplete scan (unknown, keep), not a whole one that began its
    /// clock late. Control: the same list inside the budget is whole.
    #[test]
    fn the_deadline_covers_reading_the_pid_list() {
        let raw = procargs("/usr/local/bin/node", &["node"], &["PATH=/usr/bin"]);
        let scan = |budget: Duration, list_takes: Duration| {
            let deadline = Instant::now() + budget;
            let mut a = |_: u32| Probe::Got(raw.clone());
            let mut reads = HolderReads {
                bsd: &|p| {
                    Probe::Got(BsdFacts {
                        pid: p,
                        ..facts(UID, 1, false)
                    })
                },
                args: &mut a,
                uniq: &plain_uniq,
                cwd: &|_| None,
            };
            scan_listed(
                deadline,
                || {
                    std::thread::sleep(list_takes);
                    Some(vec![1, 2])
                },
                1,
                UID,
                &mut reads,
            )
            .expect("the list was read")
        };
        let slow = scan(Duration::from_millis(5), Duration::from_millis(60));
        assert!(!slow.complete, "a list read past the deadline: incomplete");
        let fast = scan(Duration::from_secs(60), Duration::ZERO);
        assert!(fast.complete);
        // An unreadable list is no scan at all.
        let mut a = |_: u32| Probe::Failed;
        let mut reads = HolderReads {
            bsd: &|_| Probe::Failed,
            args: &mut a,
            uniq: &plain_uniq,
            cwd: &|_| None,
        };
        assert!(scan_listed(Instant::now(), || None, 1, UID, &mut reads).is_none());
    }

    /// RED against a reader that takes the FIRST `CLAUDE_CONFIG_DIR` entry only: an
    /// environment with a duplicate key where only the LAST one names the terminal still
    /// holds it (which entry a runtime honours is not ours to guess, so every entry counts).
    #[test]
    fn any_claude_config_dir_entry_counts_not_only_the_first() {
        let raw = procargs(
            "/usr/local/bin/node",
            &["node"],
            &[
                "CLAUDE_CONFIG_DIR=/x/accounts/term-1",
                "PATH=/usr/bin",
                "CLAUDE_CONFIG_DIR=",
                "CLAUDE_CONFIG_DIR=/x/accounts/term-4242",
            ],
        );
        let mut a = |_: u32| Probe::Got(raw.clone());
        let mut reads = HolderReads {
            bsd: &|p| {
                Probe::Got(BsdFacts {
                    pid: p,
                    ..facts(UID, 1, false)
                })
            },
            args: &mut a,
            uniq: &plain_uniq,
            cwd: &|_| None,
        };
        let scan = scan_via(
            &[1],
            UID,
            Instant::now() + Duration::from_secs(60),
            &mut reads,
        );
        assert!(
            scan.config_dirs
                .contains(&PathBuf::from("/x/accounts/term-4242")),
            "{:?}",
            scan.config_dirs
        );
        assert_eq!(scan.unreadable, 0);
    }

    #[test]
    fn a_scan_past_its_deadline_is_incomplete() {
        let raw = procargs("/usr/local/bin/node", &["node"], &["PATH=/usr/bin"]);
        let mut a = |_: u32| Probe::Got(raw.clone());
        let mut reads = HolderReads {
            bsd: &|p| {
                Probe::Got(BsdFacts {
                    pid: p,
                    ..facts(UID, 1, false)
                })
            },
            args: &mut a,
            uniq: &plain_uniq,
            cwd: &|_| None,
        };
        let live = scan_via(
            &[1, 2],
            UID,
            Instant::now() + Duration::from_secs(60),
            &mut reads,
        );
        assert!(live.complete && live.config_dirs.is_empty() && live.unreadable == 0);
        let past = scan_via(&[1, 2], UID, Instant::now(), &mut reads);
        assert!(
            !past.complete,
            "a deadline already reached stops before the first pid"
        );
    }
    // ── descent ─────────────────────────────────────────────────────────────

    /// One fixture process. Its parent pid is deliberately not modelled: nothing may need it.
    #[derive(Clone)]
    struct Proc {
        /// This process's unique id.
        id: u64,
        /// The unique id of the process that forked it (`p_puniqueid`).
        creator: u64,
        uid: u32,
        zombie: bool,
        pgid: u32,
        /// `None`: the arguments cannot be read.
        env: Option<Vec<&'static str>>,
    }

    /// launchd: pid 1, id 1, no creator, root's.
    const LAUNCHD: u64 = 1;

    /// A same-uid process with a readable environment.
    fn proc(id: u64, creator: u64, env: Vec<&'static str>) -> Proc {
        Proc {
            id,
            creator,
            uid: UID,
            zombie: false,
            pgid: 8224,
            env: Some(env),
        }
    }

    /// A shell whose environment macOS withholds (an empty region), leading its own group.
    fn withheld_shell(id: u64, creator: u64) -> Proc {
        Proc {
            pgid: 93216,
            ..proc(id, creator, vec![])
        }
    }

    /// `login` or `sshd`: another user's process.
    fn root_proc(id: u64, creator: u64) -> Proc {
        Proc {
            uid: 0,
            ..proc(id, creator, vec![])
        }
    }

    const TERM_N: &str = "CLAUDE_CONFIG_DIR=/x/accounts/term-8224";

    /// The launcher's unique id in these fixtures: dead, so it is in no world. Everything it
    /// forked has a larger id.
    const L: u64 = 500;

    struct World {
        procs: HashMap<u32, Proc>,
        uniq_reads: std::cell::RefCell<HashMap<u32, u32>>,
        /// From the n-th (1-based) `uniq` read of this pid on, report this unique id instead.
        flip_uniq: Option<(u32, u32, u64)>,
        /// These pids' unique ids cannot be read.
        blind_uniq: HashSet<u32>,
        args_reads: std::cell::Cell<u32>,
    }

    impl World {
        /// `procs` plus launchd.
        fn new(mut procs: Vec<(u32, Proc)>) -> Self {
            procs.push((
                1,
                Proc {
                    pgid: 1,
                    ..root_proc(LAUNCHD, 0)
                },
            ));
            World {
                procs: procs.into_iter().collect(),
                uniq_reads: Default::default(),
                flip_uniq: None,
                blind_uniq: HashSet::new(),
                args_reads: Default::default(),
            }
        }

        fn bsd(&self, pid: u32) -> Probe<BsdFacts> {
            let Some(p) = self.procs.get(&pid) else {
                return Probe::Gone;
            };
            Probe::Got(BsdFacts {
                pid,
                uid: p.uid,
                start: 1_790_000_000,
                tdev: 1,
                claude_named: false,
                codex_named: false,
                zombie: p.zombie,
                pgid: p.pgid,
            })
        }

        fn uniq(&self, pid: u32) -> Probe<Uniq> {
            let n = {
                let mut reads = self.uniq_reads.borrow_mut();
                let n = reads.entry(pid).or_insert(0);
                *n += 1;
                *n
            };
            if self.blind_uniq.contains(&pid) {
                return Probe::Failed;
            }
            let Some(p) = self.procs.get(&pid) else {
                return Probe::Gone;
            };
            let mut uniqueid = p.id;
            if let Some((fp, from, to)) = self.flip_uniq {
                if fp == pid && n >= from {
                    uniqueid = to;
                }
            }
            Probe::Got(Uniq {
                uniqueid,
                puniqueid: p.creator,
            })
        }

        fn run<R>(&self, f: impl FnOnce(&mut HolderReads<'_>) -> R) -> R {
            let mut args = |pid: u32| {
                self.args_reads.set(self.args_reads.get() + 1);
                match self.procs.get(&pid) {
                    None => Probe::Gone,
                    Some(Proc { env: None, .. }) => Probe::Failed,
                    Some(Proc { env: Some(env), .. }) => {
                        Probe::Got(procargs("/bin/zsh", &["x"], env))
                    }
                }
            };
            let mut reads = HolderReads {
                bsd: &|pid| self.bsd(pid),
                args: &mut args,
                uniq: &|pid| self.uniq(pid),
                cwd: &|_| None,
            };
            f(&mut reads)
        }

        /// Every process of the world, children before creators (largest pid first), so the
        /// table is complete only after the whole pass.
        fn scan_all(&self) -> ProcessEnvScan {
            let mut pids: Vec<u32> = self.procs.keys().copied().collect();
            pids.sort_unstable_by(|a, b| b.cmp(a));
            self.scan(&pids)
        }

        fn scan(&self, pids: &[u32]) -> ProcessEnvScan {
            self.run(|reads| scan_via(pids, UID, Instant::now() + Duration::from_secs(60), reads))
        }
    }

    const SHELL: u32 = 93216;
    const MID: u32 = 8303;
    const SIB: u32 = 8304;

    /// RED against a descent that cannot tell a creator it has never heard of from the
    /// launcher: a tool shell forked by the (dead) launcher's own unique id descends from it.
    /// This is the case `creator == u_L`.
    #[test]
    fn a_process_forked_by_the_dead_launcher_descends_from_it() {
        let scan = World::new(vec![(SHELL, withheld_shell(900, L))]).scan_all();
        assert!(scan.complete && !scan.damaged && scan.unreadable == 0);
        assert_eq!(scan.descent(L), Descent::Descendant);
        // Control: asked about a launcher newer than its creator, the same scan says no.
        assert_eq!(scan.descent(L + 1), Descent::Not);
    }

    /// `creator < u_L`: forked by something older than the launcher, whatever it is. The
    /// closed-terminal orphan of an OLDER terminal does not pin this one.
    #[test]
    fn a_process_forked_before_the_launcher_does_not_descend_from_it() {
        let scan = World::new(vec![(SHELL, withheld_shell(900, 400))]).scan_all();
        assert_eq!(scan.descent(L), Descent::Not);
        // And one forked by launchd (a service): also older than any launcher.
        let born = World::new(vec![(SHELL, withheld_shell(900, LAUNCHD))]).scan_all();
        assert_eq!(born.descent(L), Descent::Not);
    }

    /// `creator > u_L` and dead: it may be a descendant of the launcher (a double-forked
    /// daemon) or not. Unknown for THIS terminal; another terminal the same scan is asked
    /// about, whose launcher is newer than the dead creator, is still decided.
    #[test]
    fn a_dead_creator_above_the_launcher_is_unknown_for_that_terminal_only() {
        let scan = World::new(vec![(SHELL, withheld_shell(900, 700))]).scan_all();
        assert_eq!(scan.descent(L), Descent::Unknown { processes: 1 });
        assert_eq!(scan.descent(800), Descent::Not, "launcher newer than 700");
        assert!(scan.complete && scan.unreadable == 0 && !scan.damaged);
    }

    /// A live chain is walked through the scan's own table, whoever owns the links: the tool
    /// shell (900) under `login` (700, root's) under a readable process (600) under the dead
    /// launcher. A link whose id cannot be read is a dead creator to the chain above it.
    #[test]
    fn the_chain_is_walked_through_live_links_of_any_owner() {
        let build = || {
            World::new(vec![
                (MID, proc(600, L, vec!["PATH=/usr/bin"])),
                (SIB, root_proc(700, 600)),
                (SHELL, withheld_shell(900, 700)),
            ])
        };
        let scan = build().scan_all();
        // From the shell's creator (the foreign link) up to the launcher.
        assert_eq!(scan.chain_reaches(700, L), Some(true));
        assert_eq!(scan.descent(L), Descent::Descendant);
        // A launcher newer than the readable link: forked before it, so not reached.
        assert_eq!(scan.chain_reaches(700, 650), Some(false));
        assert_eq!(scan.descent(950), Descent::Not);
        // The foreign link's id cannot be read: it is not in the table, so the chain stops at
        // a creator that looks dead.
        let mut cut = build();
        cut.blind_uniq.insert(SIB);
        let scan = cut.scan_all();
        assert_eq!(scan.unreadable, 1, "the foreign link's id is unreadable");
        assert_eq!(scan.chain_reaches(700, L), None);
    }

    /// The launcher itself still alive is a holder (its id is in the table).
    #[test]
    fn a_live_launcher_is_its_own_descendant() {
        let scan = World::new(vec![(MID, proc(L, LAUNCHD, vec![]))]).scan_all();
        assert_eq!(scan.descent(L), Descent::Descendant);
    }

    /// A chain longer than the hop cap is unknown, not a loop and not a non-descendant.
    /// Control: a short chain over the same base is decided.
    #[test]
    fn a_chain_longer_than_the_hop_cap_is_unknown() {
        let chain = |len: u32| {
            let mut procs = Vec::new();
            // Forked by something older than the launcher, so every link that reaches it is "no".
            let mut creator = 400;
            for hop in 0..len {
                let id = 600 + u64::from(hop);
                procs.push((10_000 + hop, proc(id, creator, vec![])));
                creator = id;
            }
            World::new(procs).scan_all()
        };
        let short = chain(5);
        assert!(!short.damaged);
        assert_eq!(short.descent(L), Descent::Not, "control");
        let deep = chain(LINEAGE_HOP_CAP as u32 + 2);
        assert!(!deep.damaged);
        let Descent::Unknown { processes } = deep.descent(L) else {
            panic!(
                "a chain past the cap must be unknown: {:?}",
                deep.descent(L)
            );
        };
        assert!(processes >= 1);
    }

    /// A table that contradicts itself is damaged: no descent verdict may rest on it.
    #[test]
    fn a_table_that_contradicts_itself_is_damaged() {
        let honest = World::new(vec![
            (MID, proc(600, L, vec![])),
            (SHELL, withheld_shell(900, 600)),
        ]);
        assert!(!honest.scan_all().damaged, "control");
        // One unique id on two pids.
        let dup = World::new(vec![
            (MID, proc(600, L, vec![])),
            (SHELL, withheld_shell(600, L)),
        ]);
        assert!(dup.scan_all().damaged, "duplicate id");
        // A creator of 0 on anything but launchd.
        let zero = World::new(vec![(SHELL, withheld_shell(900, 0))]);
        assert!(zero.scan_all().damaged, "creator 0");
        // A creator not below its child.
        let upside = World::new(vec![
            (SHELL, withheld_shell(900, 900)),
            (MID, proc(901, 905, vec![])),
        ]);
        assert!(upside.scan_all().damaged, "creator id >= own id");
        // launchd itself (creator 0) is not.
        assert!(!World::new(vec![]).scan_all().damaged);
    }

    /// Identity is the pair of reads that bracket the process's own: a pid reused while it was
    /// being read is unreadable, not a mix of two processes (LOW-5). Control: no flip.
    #[test]
    fn a_pid_reused_during_its_own_read_is_unreadable() {
        let base = || {
            World::new(vec![
                (MID, proc(600, L, vec![])),
                (SHELL, withheld_shell(900, 600)),
            ])
        };
        let honest = base().scan(&[SHELL, MID]);
        assert_eq!(honest.unreadable, 0, "control");
        // The shell's second id read already reports another process.
        let mut moved = base();
        moved.flip_uniq = Some((SHELL, 2, 424_242));
        let scan = moved.scan(&[SHELL, MID]);
        assert_eq!(scan.unreadable, 1, "{scan:?}");
        assert!(!scan.lineage.contains_key(&900) && !scan.lineage.contains_key(&424_242));
    }

    /// A live process whose unique id cannot be read cannot be placed in a lineage, whoever
    /// owns it: unreadable (global unknown). A foreign one with no children yet (a root
    /// descendant of the launcher waiting at a prompt, whose same-uid child starts later) is
    /// invisible to every chain walk, so dropping it would let the item go while it lives
    /// (D237 R2 security R2-3). RED against a scan that counts only same-uid processes.
    #[test]
    fn a_live_process_without_a_readable_unique_id_is_unreadable_whoever_owns_it() {
        let mut world = World::new(vec![
            (MID, proc(600, L, vec![])),
            (SIB, root_proc(700, 600)),
        ]);
        assert_eq!(world.scan_all().unreadable, 0, "control");
        world.blind_uniq.insert(MID);
        assert_eq!(world.scan_all().unreadable, 1);
        world.blind_uniq.insert(SIB);
        assert_eq!(world.scan_all().unreadable, 2, "the foreign one counts too");
        // On its own, with nothing forked from it: still unreadable, not silently absent.
        let mut lone = World::new(vec![(SIB, root_proc(700, 600))]);
        lone.blind_uniq.insert(SIB);
        let scan = lone.scan_all();
        assert_eq!(scan.unreadable, 1, "{scan:?}");
        assert!(!scan.lineage.contains_key(&700), "its id is unknown");
        // A zombie of another user (nothing to read, nothing to fork) is not one.
        let mut zombie = root_proc(700, 600);
        zombie.zombie = true;
        let mut gone = World::new(vec![(SIB, zombie)]);
        gone.blind_uniq.insert(SIB);
        assert_eq!(gone.scan_all().unreadable, 0, "control: a zombie is absent");
    }

    /// The scan records every live process once, in any pid order, with the creator ids and
    /// the pid map a later re-list compares against.
    #[test]
    fn the_scan_records_the_lineage_of_every_live_process() {
        let world = World::new(vec![
            (MID, proc(600, L, vec![TERM_N])),
            (SHELL, withheld_shell(900, 600)),
        ]);
        let scan = world.scan(&[SHELL, MID]);
        assert_eq!(scan.lineage.get(&900), Some(&600));
        assert_eq!(scan.lineage.get(&600), Some(&L));
        assert_eq!(scan.by_pid.get(&SHELL), Some(&900));
        assert_eq!(scan.max_id, 900);
        assert!(scan.listed.contains(&MID) && scan.listed.contains(&SHELL));
        // A zombie and a process that is gone are not in the lineage.
        let mut z = proc(950, L, vec![]);
        z.zombie = true;
        let with_zombie = World::new(vec![(MID, z)]).scan_all();
        assert!(!with_zombie.lineage.contains_key(&950));
    }

    /// Every process environment is read once however many descend from it.
    #[test]
    fn every_process_environment_is_read_once() {
        let world = World::new(vec![
            (MID, proc(600, LAUNCHD, vec![TERM_N])),
            (SHELL, withheld_shell(900, 600)),
            (SHELL + 1, withheld_shell(901, 600)),
        ]);
        let scan = world.scan(&[SHELL, SHELL + 1, MID]);
        assert_eq!(scan.unreadable, 0);
        assert_eq!(world.args_reads.get(), 3, "one read per listed process");
        assert_eq!(scan.config_dirs.len(), 1, "only the process that names it");
    }

    /// A process forked after the scan listed the table joins the lineage through a fresh
    /// pid list (S3). A creator that is the dead launcher, or dead above it, or an arrival
    /// that cannot be read, or one the scan should have had, are not clean; one forked by a
    /// process the scan has is.
    #[test]
    fn a_process_forked_after_the_scan_is_decided_by_its_creator() {
        let world = World::new(vec![(MID, proc(600, LAUNCHD, vec![]))]);
        let scan = world.scan_all();
        assert_eq!(scan.max_id, 600);
        let pids = |extra: &[u32]| {
            let mut v: Vec<u32> = world.procs.keys().copied().collect();
            v.extend_from_slice(extra);
            v
        };
        let extended = |arrival: Proc, blind: bool| {
            let mut w = World::new(vec![(MID, proc(600, LAUNCHD, vec![])), (4242, arrival)]);
            if blind {
                w.blind_uniq.insert(4242);
            }
            scan.with_arrivals(&pids(&[4242]), &|p| w.uniq(p))
        };
        // Nothing new: the same scan.
        let same = scan.with_arrivals(&pids(&[]), &|p| world.uniq(p));
        assert_eq!(same, scan);
        // Forked by a process the scan has (older than the launcher): not a descendant.
        let ok = extended(withheld_shell(1700, 600), false);
        assert_eq!(ok.descent(L), Descent::Not);
        assert_eq!(ok.unreadable, 0);
        // Forked by the launcher itself, or by a dead creator above it.
        assert_eq!(
            extended(withheld_shell(1700, L), false).descent(L),
            Descent::Descendant
        );
        assert_eq!(
            extended(withheld_shell(1700, 1650), false).descent(L),
            Descent::Unknown { processes: 1 }
        );
        // An arrival whose id cannot be read.
        assert_eq!(extended(withheld_shell(1700, 600), true).unreadable, 1);
        // An unlisted-then-seen process OLDER than the scan's newest, absent from it.
        assert_eq!(extended(withheld_shell(300, LAUNCHD), false).unreadable, 1);
        // A pid the scan listed that is now a different, newer process is an arrival too.
        let mut reborn = World::new(vec![(MID, proc(2000, LAUNCHD, vec![]))]);
        reborn.procs.get_mut(&MID).unwrap().creator = L;
        let after = scan.with_arrivals(&[MID, 1], &|p| reborn.uniq(p));
        assert_eq!(after.descent(L), Descent::Descendant);
    }

    /// The process-group witness is independent of the environment and of the lineage.
    #[test]
    fn the_scan_records_the_group_of_every_live_same_uid_process_only() {
        let world = World::new(vec![
            (MID, proc(600, LAUNCHD, vec![TERM_N])),
            (SHELL, withheld_shell(900, 600)),
            (
                SIB,
                Proc {
                    pgid: 7777,
                    ..root_proc(700, LAUNCHD)
                },
            ),
        ]);
        let scan = world.scan_all();
        assert!(scan.process_groups.contains(&8224), "readable");
        assert!(!scan.process_groups.contains(&7777), "another user's");
        assert!(scan.process_groups.contains(&93216), "withheld");
        assert!(!scan.process_groups.contains(&0));
        assert_eq!(
            scan.process_groups.len(),
            2,
            "root's and launchd's are not recorded"
        );
    }

    /// A census of the live host the tests run on: how its process lineage looks to the
    /// descent test and what that means for terminals of every age. Counts only, never an
    /// identifier or a value. Ignored by default (it reads the whole live table and asserts
    /// nothing about the host); run it with `-- --ignored live_host_lineage_census --nocapture`.
    ///
    /// A terminal is pinned by a dead creator only when the creator's id is ABOVE the
    /// launcher's, so the census reports where the dead creators sit in the id range (as a
    /// percentage of the live ids below each) and how many of 40 hypothetical launchers spread
    /// evenly over that range are deletable, unknown or held.
    #[test]
    #[ignore = "reads the whole live process table; a census, not a check"]
    fn live_host_lineage_census() {
        let scan = scan_process_env(Duration::from_secs(30)).expect("process table readable");
        let mut ids: Vec<u64> = scan.lineage.keys().copied().collect();
        ids.sort_unstable();
        // The first creator id on each chain that the table cannot map (a dead creator), or
        // `None` when the chain reaches launchd.
        let chain_end = |mut c: u64| -> Option<Option<u64>> {
            for _ in 0..LINEAGE_HOP_CAP {
                if c <= 1 {
                    return Some(None);
                }
                match scan.lineage.get(&c) {
                    Some(&next) => c = next,
                    None => return Some(Some(c)),
                }
            }
            None
        };
        let (mut launchd, mut capped) = (0usize, 0usize);
        let mut dead: Vec<u64> = Vec::new();
        for (&id, &creator) in &scan.lineage {
            if id == 1 {
                continue;
            }
            match chain_end(creator) {
                Some(None) => launchd += 1,
                Some(Some(c)) => dead.push(c),
                None => capped += 1,
            }
        }
        dead.sort_unstable();
        dead.dedup();
        let rank = |id: u64| ids.iter().filter(|&&i| i < id).count() * 100 / ids.len().max(1);
        let ranks: Vec<usize> = dead.iter().map(|&c| rank(c)).collect();
        let youngest = ranks.iter().copied().max();
        let launchers: Vec<u64> = (1..40)
            .map(|k| ids[ids.len() * k / 40] + 1)
            .filter(|u| !scan.lineage.contains_key(u))
            .collect();
        let mut counts = [0usize; 3];
        for &u in &launchers {
            match scan.descent(u) {
                Descent::Not => counts[0] += 1,
                Descent::Unknown { .. } => counts[1] += 1,
                Descent::Descendant => counts[2] += 1,
            }
        }
        eprintln!(
            "lineage census: complete={} damaged={} unreadable={} processes={} chain_to_launchd={} \
             chains_ending_at_a_dead_creator={} distinct_dead_creators={} chain_capped={} \
             dead_creator_rank_pct={:?} youngest_dead_creator_rank_pct={:?} \
             hypothetical_launchers={} deletable={} unknown={} held={}",
            scan.complete,
            scan.damaged,
            scan.unreadable,
            scan.lineage.len(),
            launchd,
            scan.lineage
                .keys()
                .filter(|&&i| i != 1 && matches!(chain_end(scan.lineage[&i]), Some(Some(_))))
                .count(),
            dead.len(),
            capped,
            ranks,
            youngest,
            launchers.len(),
            counts[0],
            counts[1],
            counts[2],
        );
    }

    /// A real process: argv0 `node`, its own session (no controlling terminal), the dir in
    /// its environment. The scan finds it; the display listing does not.
    #[test]
    fn the_live_scan_finds_a_ttyless_node_process() {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.arg0("node")
            .args(["--exact", "sessions::macos::tests::fake_claude_sleeper"])
            .env("CSQ_FAKE_CLAUDE_SLEEP", "1")
            .env(
                "CLAUDE_CONFIG_DIR",
                "/csq-holder-scan-test/accounts/term-4242",
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setsid is async-signal-safe and touches no Rust state in the child.
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        struct Reap(std::process::Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let kid = Reap(c.spawn().unwrap());
        let pid = kid.0.id();
        let Probe::Got(f) = probe_bsd_info(pid) else {
            panic!("child readable");
        };
        assert_eq!(
            f.tdev, NODEV,
            "setsid left the child with no controlling terminal"
        );
        let scan = scan_process_env(Duration::from_secs(30)).expect("process table readable");
        eprintln!(
            "holder scan: dirs={} unreadable={} complete={}",
            scan.config_dirs.len(),
            scan.unreadable,
            scan.complete
        );
        assert!(scan.complete);
        assert!(
            scan.config_dirs
                .contains(&PathBuf::from("/csq-holder-scan-test/accounts/term-4242")),
            "the tty-less node child's CLAUDE_CONFIG_DIR is in the scan"
        );
        assert!(
            !crate::sessions::macos::try_list()
                .unwrap()
                .iter()
                .any(|s| s.pid == pid),
            "the display listing does not see it"
        );
    }
}
