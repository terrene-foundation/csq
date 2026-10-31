//! Durable execution accounting bound to custody's ledger identity and secret fingerprint.
//! Stored UTC windows survive metadata edits; unresolved generations retain their holds.

use super::store::ExecutionCandidate;
use super::types::{PoolEntry, Reset};
use super::{LedgerIdentity, LedgerState};
use crate::messaging::storage::secure::SecureDatabase;
use chrono::{Datelike, NaiveDate, Utc};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, BudgetError>;
const NAME: &str = "execution-ledger.sqlite3";
const SCHEMA: &str = "
CREATE TABLE meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 ledger_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0),
 salt_id TEXT NOT NULL, max_admission INTEGER, admission_high_water INTEGER);
CREATE TABLE generations(generation TEXT PRIMARY KEY, name TEXT NOT NULL,
 fingerprint TEXT NOT NULL, provider TEXT NOT NULL, added_at TEXT NOT NULL,
 uncertain INTEGER NOT NULL DEFAULT 0 CHECK(uncertain IN(0,1)), cooldown INTEGER NOT NULL DEFAULT 0);
CREATE TABLE reservations(id TEXT PRIMARY KEY,
 generation TEXT NOT NULL REFERENCES generations(generation), name TEXT NOT NULL,
 fingerprint TEXT NOT NULL, period TEXT NOT NULL, window_start INTEGER NOT NULL,
 window_end INTEGER NOT NULL CHECK(window_end>window_start), deadline INTEGER NOT NULL,
 held INTEGER NOT NULL CHECK(held>0), state INTEGER NOT NULL CHECK(state IN(0,1,2,3)),
 actual INTEGER CHECK(actual>=0), overflow_actual TEXT,
 CHECK((state=0 AND actual IS NULL AND overflow_actual IS NULL) OR
       (state=1 AND actual IS NOT NULL AND overflow_actual IS NULL) OR
       (state=2 AND actual IS NULL AND overflow_actual IS NULL) OR state=3),
 CHECK(actual IS NULL OR overflow_actual IS NULL), CHECK(state!=1 OR actual<=held));
CREATE INDEX reservations_window ON reservations(fingerprint,window_start,window_end);
";
const COMPACTION_SCHEMA: &str = "
CREATE TABLE settled_totals(fingerprint TEXT NOT NULL,window_start INTEGER NOT NULL,
 window_end INTEGER NOT NULL CHECK(window_end>window_start),actual INTEGER NOT NULL CHECK(actual>0),
 PRIMARY KEY(fingerprint,window_start,window_end));
CREATE INDEX reservations_generation ON reservations(generation);
PRAGMA user_version=4;";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BudgetError {
    Unavailable,
    Undetermined,
    IdentityMismatch,
    ClockRegressed,
    ResolveInvariantViolation,
    CandidateUnavailable,
    DefiniteDispositionAlreadyRecorded,
}
impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "pool_budget_unavailable",
            Self::Undetermined => "pool_budget_undetermined",
            Self::IdentityMismatch => "pool_ledger_identity_mismatch",
            Self::ClockRegressed => "pool_clock_regressed",
            Self::ResolveInvariantViolation => "pool_resolve_invariant_violation",
            Self::CandidateUnavailable => "pool_candidate_unavailable",
            Self::DefiniteDispositionAlreadyRecorded => {
                "pool_definite_disposition_already_recorded"
            }
        })
    }
}
impl std::error::Error for BudgetError {}
impl From<rusqlite::Error> for BudgetError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Reservation {
    pub id: String,
    pub generation: String,
    pub period: String,
    pub held_nanos: u64,
}
#[derive(Debug)]
pub(crate) enum ReserveResult {
    Held(Reservation),
    CapBlocked,
    InFlightBlocked,
    Cooling,
    Unresolved,
    NoCap,
    BelowHold,
}

pub(crate) struct BudgetLedger {
    inner: Option<Inner>,
    identity: LedgerIdentity,
}
struct Inner {
    connection: Connection,
    guard: SecureDatabase,
}
// Closing another DB descriptor drops Unix process-scoped fcntl locks. Protect
// opens, transactions and descriptor destruction together; SQLite orders PIDs.
fn process_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
impl Drop for BudgetLedger {
    fn drop(&mut self) {
        let _lock = process_lock();
        drop(self.inner.take());
    }
}

impl BudgetLedger {
    /// Caller holds pool custody and persists the updated anchor even on nested Err.
    pub(crate) fn with_bound<T>(
        base: &Path,
        anchor: &mut Option<LedgerIdentity>,
        salt_id: &str,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let mut ledger = Self::open_inner(base, anchor.as_ref(), salt_id, false)?;
        let result = operation(&mut ledger);
        *anchor = Some(ledger.identity.clone());
        result
    }
    #[cfg(test)]
    pub(crate) fn open(base: &Path) -> Result<Self> {
        Self::open_inner(base, None, &"0".repeat(64), true)
    }
    fn open_inner(
        base: &Path,
        expected: Option<&LedgerIdentity>,
        salt_id: &str,
        unbound: bool,
    ) -> Result<Self> {
        let _lock = process_lock();
        let base = base.canonicalize().map_err(|_| BudgetError::Unavailable)?;
        let exists = match std::fs::symlink_metadata(base.join("pool").join(NAME)) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(BudgetError::Unavailable),
        };
        if !hex_id(salt_id, 64) {
            return Err(BudgetError::IdentityMismatch);
        }
        if !unbound && expected.is_none() {
            return Err(BudgetError::IdentityMismatch);
        }
        if let Some(identity) = expected {
            if !hex_id(&identity.id, 32)
                || identity.salt_id != salt_id
                || (identity.state == LedgerState::PendingInit && identity.sequence != 0)
                || (!exists && identity.state == LedgerState::Active)
            {
                return Err(BudgetError::IdentityMismatch);
            }
        }
        let dir = private_directory(&base, !exists)?;
        if !exists && !unbound {
            for suffix in ["-wal", "-shm", "-journal"] {
                match std::fs::symlink_metadata(dir.join(format!("{NAME}{suffix}"))) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err(BudgetError::IdentityMismatch),
                }
            }
        }
        let guard = if exists {
            // The pool-ledger mode (R1 M2): the ONE caller of the inheriting leaf
            // and inherited-sidecar policy. Every other SecureDatabase caller
            // stays on the strict default.
            SecureDatabase::acquire_pool_ledger_existing(&dir, NAME.as_ref())
        } else {
            SecureDatabase::acquire_pool_ledger(&dir, NAME.as_ref())
        }
        .map_err(|_| BudgetError::Unavailable)?;
        // NOFOLLOW: on unix SQLITE_OPEN_NOFOLLOW is the namespace guard; on
        // Windows the flag is a no-op and the held guard's volume+FileId
        // rechecks are the real check (R1 informational).
        let mut connection = Connection::open_with_flags(
            dir.join(NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        guard.recheck().map_err(|_| BudgetError::Unavailable)?;
        let mode: String = connection.query_row("PRAGMA journal_mode=PERSIST", [], |r| r.get(0))?;
        if mode != "persist" {
            return Err(BudgetError::Unavailable);
        }
        connection.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;
            PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;
            PRAGMA temp_store=MEMORY;",
        )?;
        let sync: i64 = connection.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        let full: i64 = connection.query_row("PRAGMA fullfsync", [], |r| r.get(0))?;
        if sync != 2 || !fullfsync_satisfied(full) {
            return Err(BudgetError::Unavailable);
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let has_meta: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |row| row.get(0),
        )?;
        let pending_empty = expected
            .is_some_and(|identity| identity.state == LedgerState::PendingInit)
            && version == 0
            && !has_meta;
        if (!exists && version == 0) || pending_empty {
            let objects: i64 =
                connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
            if objects != 0 {
                return Err(BudgetError::Unavailable);
            }
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(SCHEMA)?;
            tx.execute_batch(COMPACTION_SCHEMA)?;
            tx.execute(
                "INSERT INTO meta(singleton,ledger_id,sequence,salt_id) VALUES(1,?1,0,?2)",
                params![
                    expected
                        .map(|identity| identity.id.clone())
                        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()),
                    salt_id
                ],
            )?;
            tx.commit()?;
        } else if version != 2 && version != 3 && version != 4 {
            return Err(BudgetError::Unavailable);
        }
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        let bad_reference: Option<i64> = connection
            .query_row("PRAGMA foreign_key_check", [], |r| r.get(1))
            .optional()?;
        if integrity != "ok" || bad_reference.is_some() {
            return Err(BudgetError::Unavailable);
        }
        let (id, sequence, salt): (String, i64, String) = connection.query_row(
            "SELECT ledger_id,sequence,salt_id FROM meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if sequence < 0 || !hex_id(&id, 32) || !hex_id(&salt, 64) {
            return Err(BudgetError::Unavailable);
        }
        let mut identity = LedgerIdentity {
            id,
            sequence: sequence as u64,
            salt_id: salt,
            state: LedgerState::Active,
        };
        if expected.is_some_and(|value| {
            value.id != identity.id
                || value.salt_id != identity.salt_id
                || identity.sequence < value.sequence
        }) {
            return Err(BudgetError::IdentityMismatch);
        }
        // A legacy clock may already have been rebaselined. Window starts preserve
        // a lower bound on future recorded admissions without treating unbounded ends as time.
        if version == 2 || version == 3 {
            let next = sequence.checked_add(1).ok_or(BudgetError::Unavailable)?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if version == 2 {
                tx.execute_batch(COMPACTION_SCHEMA)?;
            }
            tx.execute_batch("ALTER TABLE meta ADD COLUMN admission_high_water INTEGER;")?;
            let previous: Option<i64> =
                tx.query_row("SELECT max_admission FROM meta", [], |row| row.get(0))?;
            let latest_row: Option<i64> =
                tx.query_row("SELECT max(window_start) FROM reservations", [], |row| {
                    row.get(0)
                })?;
            let latest_total: Option<i64> =
                tx.query_row("SELECT max(window_start) FROM settled_totals", [], |row| {
                    row.get(0)
                })?;
            let high_water = [previous, latest_row, latest_total]
                .into_iter()
                .flatten()
                .max();
            tx.execute(
                "UPDATE meta SET sequence=?1,admission_high_water=?2 WHERE singleton=1",
                params![next, high_water],
            )?;
            tx.execute_batch("PRAGMA user_version=4;")?;
            tx.commit()?;
            identity.sequence = next as u64;
        }
        guard.recheck().map_err(|_| BudgetError::Unavailable)?;
        sync_directory(&dir)?;
        Ok(Self {
            inner: Some(Inner { connection, guard }),
            identity,
        })
    }
    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let _lock = process_lock();
        let inner = self.inner.as_mut().ok_or(BudgetError::Unavailable)?;
        inner
            .guard
            .recheck()
            .map_err(|_| BudgetError::Unavailable)?;
        let tx = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sequence: i64 =
            tx.query_row("SELECT sequence FROM meta WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if sequence < 0 || (sequence as u64) < self.identity.sequence {
            return Err(BudgetError::IdentityMismatch);
        }
        let next = sequence.checked_add(1).ok_or(BudgetError::Unavailable)?;
        let value = operation(&tx)?;
        tx.execute("UPDATE meta SET sequence=?1 WHERE singleton=1", [next])?;
        tx.commit()?;
        self.identity.sequence = next as u64; // Preserve committed identity even if the post-check fails.
        inner
            .guard
            .recheck()
            .map_err(|_| BudgetError::Unavailable)?;
        Ok(value)
    }
    // Gated to unix like its ONLY caller, `process_race` in
    // execution_ledger_tests.rs. Under `--target x86_64-pc-windows-gnu
    // --all-targets` a plain `cfg(test)` compiled this method while the
    // unix-only caller did not, and `-D warnings` failed the build with
    // dead_code (`install_busy_probe` is never used).
    #[cfg(all(test, unix))]
    pub(super) fn install_busy_probe(&mut self, callback: fn(i32) -> bool) -> Result<()> {
        self.inner
            .as_mut()
            .ok_or(BudgetError::Unavailable)?
            .connection
            .busy_handler(Some(callback))?;
        Ok(())
    }
    pub(crate) fn reserve(
        &mut self,
        candidate: &ExecutionCandidate,
        hold_nanos: u64,
        now: i64,
        deadline: i64,
    ) -> Result<ReserveResult> {
        let held = i64::try_from(hold_nanos).map_err(|_| BudgetError::CandidateUnavailable)?;
        if held == 0
            || deadline <= now
            || candidate.generation.is_empty()
            || !hex_id(candidate.fingerprint(), 64)
        {
            return Err(BudgetError::CandidateUnavailable);
        }
        candidate
            .entry
            .validate()
            .map_err(|_| BudgetError::CandidateUnavailable)?;
        let cap = candidate.entry.monthly_cap_usd.map(cap_nanos).transpose()?;
        self.transaction(|tx| {
            let rewound = admission_clock(tx,now)?;
            let (start,end)=window(&candidate.entry,now)?;
            tx.execute("INSERT OR IGNORE INTO generations(generation,name,fingerprint,provider,added_at) VALUES(?1,?2,?3,?4,?5)",
                params![candidate.generation,candidate.entry.name.as_str(),candidate.fingerprint(),candidate.entry.provider,candidate.entry.added_at])?;
            let (name,fingerprint,provider,added,uncertain,cooldown):(String,String,String,String,i64,i64)=tx.query_row(
                "SELECT name,fingerprint,provider,added_at,uncertain,cooldown FROM generations WHERE generation=?1", [&candidate.generation],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
            if name!=candidate.entry.name.as_str() || fingerprint!=candidate.fingerprint() || provider!=candidate.entry.provider || added!=candidate.entry.added_at {
                return Err(BudgetError::CandidateUnavailable);
            }
            let unresolved:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM reservations WHERE generation=?1 AND (state=3 OR (state=0 AND deadline<=?2)))",
                params![candidate.generation,now], |r| r.get(0))?;
            if uncertain!=0 || unresolved {
                mark_unknown(tx,&candidate.generation)?;
                return Ok(ReserveResult::Unresolved);
            }
            let Some(cap)=cap else { return Ok(ReserveResult::NoCap); };
            if hold_nanos>cap { return Ok(ReserveResult::BelowHold); }
            if cooldown>now { return Ok(ReserveResult::Cooling); }
            compact_aged(tx,now)?;
            let mut statement=tx.prepare("SELECT held,state,actual,overflow_actual FROM reservations WHERE fingerprint=?1 AND (?4 OR window_start<?2) AND window_end>?3 UNION ALL SELECT actual,1,actual,NULL FROM settled_totals WHERE fingerprint=?1 AND (?4 OR window_start<?2) AND window_end>?3")?;
            let mut rows=statement.query(params![candidate.fingerprint(),end,start,rewound])?;
            let (mut settled,mut pending)=(0u64,0u64);
            while let Some(row)=rows.next()? {
                let (amount,state,actual,overflow):(i64,i64,Option<i64>,Option<String>)=(row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?);
                if amount<=0 { return Err(BudgetError::Unavailable); }
                match (state,actual,overflow) {
                    (0|3,None,None) => pending=pending.checked_add(amount as u64).ok_or(BudgetError::Unavailable)?,
                    (3,Some(actual),None) if actual>=0 => pending=pending.checked_add(amount.max(actual) as u64).ok_or(BudgetError::Unavailable)?,
                    (3,None,Some(value)) => {
                        let actual=value.parse::<u64>().map_err(|_| BudgetError::Unavailable)?;
                        if actual<=i64::MAX as u64 { return Err(BudgetError::Unavailable); }
                        return Ok(ReserveResult::CapBlocked); // Known actual alone exceeds every supported cap.
                    }
                    (1,Some(actual),None) if actual>=0 && actual<=amount => settled=settled.checked_add(actual as u64).ok_or(BudgetError::Unavailable)?,
                    (2,None,None) => (),
                    _ => return Err(BudgetError::Unavailable),
                }
            }
            let needed=settled.checked_add(hold_nanos).ok_or(BudgetError::Unavailable)?;
            if needed>cap { return Ok(ReserveResult::CapBlocked); }
            if needed.checked_add(pending).ok_or(BudgetError::Unavailable)?>cap { return Ok(ReserveResult::InFlightBlocked); }
            let reservation=Reservation { id:uuid::Uuid::new_v4().to_string(), generation:candidate.generation.clone(), period:start.to_string(), held_nanos:hold_nanos };
            tx.execute("INSERT INTO reservations(id,generation,name,fingerprint,period,window_start,window_end,deadline,held,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
                params![reservation.id,reservation.generation,candidate.entry.name.as_str(),candidate.fingerprint(),reservation.period,start,end,deadline,held])?;
            Ok(ReserveResult::Held(reservation))
        })
    }
    pub(crate) fn settle(&mut self, reservation: &Reservation, actual_nanos: u64) -> Result<()> {
        let uncertain = self.transaction(|tx| {
            let (state, actual) = bound(tx, reservation)?;
            if state == 1 && actual == Some(actual_nanos) {
                return Ok(false);
            }
            if state != 0 {
                return Err(BudgetError::Undetermined);
            }
            let uncertain = actual_nanos > reservation.held_nanos;
            let (actual, overflow) = match i64::try_from(actual_nanos) {
                Ok(value) => (Some(value), None),
                Err(_) => (None, Some(actual_nanos.to_string())),
            };
            tx.execute(
                "UPDATE reservations SET state=?2,actual=?3,overflow_actual=?4 WHERE id=?1",
                params![
                    reservation.id,
                    if uncertain { 3 } else { 1 },
                    actual,
                    overflow
                ],
            )?;
            if uncertain {
                mark_unknown(tx, &reservation.generation)?;
            }
            Ok(uncertain)
        })?;
        if uncertain {
            Err(BudgetError::Undetermined)
        } else {
            Ok(())
        }
    }
    pub(crate) fn release(&mut self, reservation: &Reservation) -> Result<()> {
        self.transaction(|tx| {
            let (state, _) = bound(tx, reservation)?;
            if state != 0 {
                return Err(BudgetError::DefiniteDispositionAlreadyRecorded);
            }
            tx.execute(
                "UPDATE reservations SET state=2 WHERE id=?1",
                [&reservation.id],
            )?;
            Ok(())
        })
    }
    pub(crate) fn reject_quota(&mut self, reservation: &Reservation, until: i64) -> Result<()> {
        let recorded = self.transaction(|tx| {
            let state = bound(tx, reservation)?.0;
            if state == 0 {
                tx.execute(
                    "UPDATE reservations SET state=2 WHERE id=?1",
                    [&reservation.id],
                )?;
            }
            tx.execute(
                "UPDATE generations SET cooldown=max(cooldown,?2) WHERE generation=?1",
                params![reservation.generation, until],
            )?;
            Ok(state != 0)
        })?;
        // Report an existing disposition only after its independent cooldown commits.
        if recorded {
            Err(BudgetError::DefiniteDispositionAlreadyRecorded)
        } else {
            Ok(())
        }
    }
    pub(crate) fn retain_unknown(&mut self, reservation: &Reservation) -> Result<()> {
        self.transaction(|tx| {
            match bound(tx, reservation)?.0 {
                0 | 3 => (),
                _ => return Err(BudgetError::Undetermined),
            }
            tx.execute(
                "UPDATE reservations SET state=3 WHERE id=?1",
                [&reservation.id],
            )?;
            mark_unknown(tx, &reservation.generation)
        })
    }
    pub(crate) fn resolve(&mut self, fingerprint: &str, generation: &str, now: i64) -> Result<u64> {
        if !hex_id(fingerprint, 64) || generation.is_empty() {
            return Err(BudgetError::CandidateUnavailable);
        }
        self.transaction(|tx| {
            let oversized:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM reservations WHERE fingerprint=?1 AND generation=?2 AND state=3 AND (overflow_actual IS NOT NULL OR actual>held))", params![fingerprint,generation], |row|row.get(0))?;
            if oversized { return Err(BudgetError::ResolveInvariantViolation); }
            let count=tx.execute("UPDATE reservations SET state=1,actual=held,overflow_actual=NULL WHERE fingerprint=?1 AND (state=3 OR (state=0 AND deadline<=?2)) AND overflow_actual IS NULL AND (actual IS NULL OR actual<=held)", params![fingerprint,now])?;
            tx.execute("UPDATE generations SET uncertain=0 WHERE fingerprint=?1 AND NOT EXISTS(SELECT 1 FROM reservations WHERE generation=generations.generation AND (state=3 OR (state=0 AND deadline<=?2)))", params![fingerprint,now])?;
            u64::try_from(count).map_err(|_|BudgetError::Unavailable)
        })
    }
    pub(crate) fn rebaseline_clock(&mut self, now: i64) -> Result<()> {
        chrono::DateTime::<Utc>::from_timestamp(now, 0).ok_or(BudgetError::Unavailable)?;
        self.transaction(|tx| {
            tx.execute(
                "UPDATE meta SET max_admission=?1 WHERE max_admission>?1",
                [now],
            )?;
            Ok(())
        })
    }
    #[cfg(test)]
    pub(super) fn compact_for_test(&mut self, now: i64) -> Result<u64> {
        self.transaction(|tx| compact_aged(tx, now))
    }
}

// Only request detail is discarded. Its exact settled cost/window survives in
// totals forever, including when a later reset reaches back into an old window.
fn compact_aged(tx: &Transaction<'_>, now: i64) -> Result<u64> {
    let Some(cutoff) = now.checked_sub(31 * 86_400) else {
        return Ok(0);
    };
    let mut statement=tx.prepare("SELECT fingerprint,window_start,window_end,state,held,actual FROM reservations WHERE state IN(1,2) AND window_end<?1 AND window_end<=?2")?;
    let mut rows = statement.query(params![i64::MAX, cutoff])?;
    let mut count = 0u64;
    while let Some(row) = rows.next()? {
        let (fingerprint, start, end, state, held, actual): (
            String,
            i64,
            i64,
            i64,
            i64,
            Option<i64>,
        ) = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        );
        if held <= 0 || start >= end {
            return Err(BudgetError::Unavailable);
        }
        match (state, actual) {
            (1, Some(actual)) if actual >= 0 && actual <= held => {
                if actual > 0 {
                    let prior:Option<i64>=tx.query_row("SELECT actual FROM settled_totals WHERE fingerprint=?1 AND window_start=?2 AND window_end=?3", params![fingerprint,start,end], |r|r.get(0)).optional()?;
                    if prior.is_some_and(|amount| amount <= 0) {
                        return Err(BudgetError::Unavailable);
                    }
                    let total = prior
                        .unwrap_or(0)
                        .checked_add(actual)
                        .ok_or(BudgetError::Unavailable)?;
                    tx.execute("INSERT INTO settled_totals(fingerprint,window_start,window_end,actual) VALUES(?1,?2,?3,?4) ON CONFLICT(fingerprint,window_start,window_end) DO UPDATE SET actual=excluded.actual", params![fingerprint,start,end,total])?;
                }
            }
            (2, None) => (),
            _ => return Err(BudgetError::Unavailable),
        }
        count = count.checked_add(1).ok_or(BudgetError::Unavailable)?;
    }
    drop(rows);
    drop(statement);
    if count == 0 {
        return Ok(0);
    }
    #[cfg(test)]
    super::execution_ledger_tests::compaction_checkpoint();
    let deleted = tx.execute(
        "DELETE FROM reservations WHERE state IN(1,2) AND window_end<?1 AND window_end<=?2",
        params![i64::MAX, cutoff],
    )?;
    if u64::try_from(deleted).map_err(|_| BudgetError::Unavailable)? != count {
        return Err(BudgetError::Unavailable);
    }
    Ok(count)
}

fn admission_clock(tx: &Transaction<'_>, now: i64) -> Result<bool> {
    let (previous, high_water): (Option<i64>, Option<i64>) = tx.query_row(
        "SELECT max_admission,admission_high_water FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    #[cfg(test)]
    super::execution_ledger_tests::admission_read_probe();
    if previous.is_some_and(|value| now < value) {
        return Err(BudgetError::ClockRegressed);
    }
    let rewound = high_water.is_some_and(|value| now < value);
    tx.execute("UPDATE meta SET max_admission=?1,admission_high_water=CASE WHEN admission_high_water IS NULL OR admission_high_water<?1 THEN ?1 ELSE admission_high_water END WHERE singleton=1", [now])?;
    Ok(rewound)
}

fn hex_id(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn mark_unknown(tx: &Transaction<'_>, generation: &str) -> Result<()> {
    tx.execute(
        "UPDATE generations SET uncertain=1 WHERE generation=?1",
        [generation],
    )?;
    Ok(())
}
fn bound(tx: &Transaction<'_>, reservation: &Reservation) -> Result<(i64, Option<u64>)> {
    let row: Option<(String, String, i64, i64, Option<i64>)> = tx
        .query_row(
            "SELECT generation,period,held,state,actual FROM reservations WHERE id=?1",
            [&reservation.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let (generation, period, held, state, actual) = row.ok_or(BudgetError::Undetermined)?;
    if generation != reservation.generation
        || period != reservation.period
        || held <= 0
        || held as u64 != reservation.held_nanos
        || actual.is_some_and(|n| n < 0)
    {
        return Err(BudgetError::Undetermined);
    }
    Ok((state, actual.map(|n| n as u64)))
}

fn cap_nanos(cap: f64) -> Result<u64> {
    if !cap.is_finite() || cap <= 0.0 {
        return Err(BudgetError::CandidateUnavailable);
    }
    // Scale the exact binary value, then floor with an integer shift. A float
    // multiplication can round upward before floor and admit an extra nano.
    let bits = cap.to_bits();
    let encoded_exponent = ((bits >> 52) & 0x7ff) as i32;
    let mantissa = u128::from(bits & ((1u64 << 52) - 1))
        + if encoded_exponent == 0 {
            0
        } else {
            1u128 << 52
        };
    let exponent = if encoded_exponent == 0 {
        -1074
    } else {
        encoded_exponent - 1075
    };
    let scaled = mantissa * 1_000_000_000u128;
    let nanos = if exponent >= 0 {
        let factor = 1u128
            .checked_shl(exponent as u32)
            .ok_or(BudgetError::CandidateUnavailable)?;
        scaled
            .checked_mul(factor)
            .ok_or(BudgetError::CandidateUnavailable)?
    } else if -exponent >= 128 {
        0
    } else {
        scaled >> (-exponent as u32)
    };
    u64::try_from(nanos)
        .ok()
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(BudgetError::CandidateUnavailable)
}

fn window(entry: &PoolEntry, now: i64) -> Result<(i64, i64)> {
    let now_date = chrono::DateTime::<Utc>::from_timestamp(now, 0)
        .ok_or(BudgetError::Unavailable)?
        .date_naive();
    let added = chrono::DateTime::parse_from_rfc3339(&entry.added_at)
        .map_err(|_| BudgetError::CandidateUnavailable)?
        .timestamp();
    if now < added {
        return Err(BudgetError::CandidateUnavailable);
    }
    let midnight = |date: NaiveDate| {
        date.and_hms_opt(0, 0, 0)
            .map(|value| value.and_utc().timestamp())
            .ok_or(BudgetError::CandidateUnavailable)
    };
    if let Some(Reset::Date { date }) = &entry.reset {
        let reset = midnight(
            NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .map_err(|_| BudgetError::CandidateUnavailable)?,
        )?;
        return Ok(if now < reset {
            (added, reset)
        } else {
            (reset.max(added), i64::MAX)
        });
    }
    let day = match &entry.reset {
        Some(Reset::Day { day_of_month }) => u32::from(*day_of_month),
        _ => 1,
    };
    let (year, month) = if now_date.day() >= day {
        (now_date.year(), now_date.month())
    } else if now_date.month() == 1 {
        (
            now_date
                .year()
                .checked_sub(1)
                .ok_or(BudgetError::CandidateUnavailable)?,
            12,
        )
    } else {
        (now_date.year(), now_date.month() - 1)
    };
    let (next_year, next_month) = if month == 12 {
        (
            year.checked_add(1)
                .ok_or(BudgetError::CandidateUnavailable)?,
            1,
        )
    } else {
        (year, month + 1)
    };
    let start = midnight(
        NaiveDate::from_ymd_opt(year, month, day).ok_or(BudgetError::CandidateUnavailable)?,
    )?;
    let end = midnight(
        NaiveDate::from_ymd_opt(next_year, next_month, day)
            .ok_or(BudgetError::CandidateUnavailable)?,
    )?;
    Ok((start, end))
}

#[cfg(unix)]
fn private_directory(base: &Path, create: bool) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    // Resolve an operator-supplied root once; all children are strict no-follow.
    let base = base.canonicalize().map_err(|_| BudgetError::Unavailable)?;
    for ancestor in base.ancestors() {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(ancestor)
            .map_err(|_| BudgetError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| BudgetError::Unavailable)?;
        // SAFETY: geteuid has no preconditions and changes no process state.
        let uid = unsafe { libc::geteuid() };
        if crate::platform::fs::untrusted_directory_reason(metadata.uid(), metadata.mode(), uid)
            .is_some()
            || crate::platform::fs::directory_acl_refusal(file.as_raw_fd()).is_some()
        {
            return Err(BudgetError::Unavailable);
        }
    }
    let dir = base.join("pool");
    if !create {
        return Ok(dir);
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => sync_directory(&base)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(BudgetError::Unavailable),
    }
    Ok(dir)
}

/// Windows has no descriptor-relative `openat(2)`; the equivalent guarantee is built from
/// handle opens. `FILE_FLAG_OPEN_REPARSE_POINT` is the `O_NOFOLLOW` analogue (a junction or
/// symlink is opened as itself and then refused), and the base and every ancestor must be a
/// real directory whose DACL grants no foreign principal write access
/// ([`crate::platform::fs_windows_acl::check_no_foreign_write`]).
///
/// The leaf (`base/pool`) is the ONE private directory here that SQLite writes into
/// itself: sidecars (`-journal`, `-wal`, `-shm`) are created by SQLite with
/// `lpSecurityAttributes = NULL`, so they carry whatever the leaf's DACL propagates. A
/// protected NON-inheriting leaf DACL would therefore leave every sidecar with an empty
/// DACL, which the store's sidecar check can never pass; csq creates the leaf in the
/// owner-only INHERITABLE form and `SecureDatabase::acquire_pool_ledger` validates it —
/// or adopts a verified pre-existing root (R1 F5). This function only creates and
/// flushes the directory entry; it never judges the leaf's ACL.
#[cfg(windows)]
fn private_directory(base: &Path, create: bool) -> Result<PathBuf> {
    use crate::platform::fs_windows_acl::{
        check_no_foreign_write, create_private_directory_inheriting, PrivateAclError,
    };
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES,
    };
    // `GetSecurityInfo` needs READ_CONTROL to read the DACL; a directory needs no other
    // access to be checked, matching the unix branch's search-only ancestor opens.
    const READ_CONTROL: u32 = 0x0002_0000;
    // Resolve an operator-supplied root once; all children are strict no-follow.
    let base = base.canonicalize().map_err(|_| BudgetError::Unavailable)?;
    for ancestor in base.ancestors() {
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)
            .map_err(|_| BudgetError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| BudgetError::Unavailable)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BudgetError::Unavailable);
        }
        check_no_foreign_write(&file).map_err(|_| BudgetError::Unavailable)?;
    }
    let dir = base.join("pool");
    if !create {
        // The database exists, so the leaf must exist too; SecureDatabase's pool
        // mode opens it (adopting a verified pre-existing root, R1 F5) and
        // reports absence or an unverifiable root as Unavailable.
        return Ok(dir);
    }
    match create_private_directory_inheriting(&dir) {
        Ok(()) => {
            // Flush the new entry through the base directory handle: on Windows
            // FlushFileBuffers on a directory handle is the available durability
            // assertion, and a refusal is `Unavailable`.
            sync_directory(&base)?;
        }
        Err(PrivateAclError::Os(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(BudgetError::Unavailable),
    }
    // The leaf is validated by SecureDatabase::acquire_pool_ledger — the single
    // place that decides between the exact inheriting shape and the F5 adoption.
    Ok(dir)
}

#[cfg(not(any(unix, windows)))]
fn private_directory(_: &Path, _: bool) -> Result<PathBuf> {
    Err(BudgetError::Unavailable)
}

/// Flush a directory's entries to stable storage, the durability step that follows a
/// create or a commit.
#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| BudgetError::Unavailable)
}

/// Windows has no `fsync(2)` on a directory descriptor, and `File::open` cannot open a
/// directory at all. `FlushFileBuffers` (`File::sync_all`) on a directory handle is the
/// best available durability assertion on NTFS — a best-effort guarantee, not a claim of
/// equivalence with the unix call: a filesystem that cannot flush a directory makes this
/// fail, and the refusal is `Unavailable`, never a silent continue. `CreateFileW` opens a
/// directory only with `FILE_FLAG_BACKUP_SEMANTICS` and flushes it only with write access;
/// `FILE_FLAG_OPEN_REPARSE_POINT` opens a junction or symlink as itself, which is then
/// refused.
#[cfg(windows)]
pub(super) fn sync_directory(path: &Path) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| BudgetError::Unavailable)?;
    let metadata = directory.metadata().map_err(|_| BudgetError::Unavailable)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(BudgetError::Unavailable);
    }
    directory.sync_all().map_err(|_| BudgetError::Unavailable)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn sync_directory(_: &Path) -> Result<()> {
    Err(BudgetError::Unavailable)
}

/// Whether a `PRAGMA fullfsync` readback holds the ledger's durability requirement.
///
/// `fullfsync` selects SQLite's `F_FULLFSYNC` sync method, which exists only on macOS, so
/// on other targets the flag changes no sync call; the durability guarantee this ledger
/// relies on everywhere is `PRAGMA synchronous=FULL`, read back as 2 and checked
/// separately. R1 F7: the flag is required as 1 on EVERY target until the native
/// `[pool-ledger-pragma-readback]` diagnostic proves a host returns 0; relaxing it is a
/// measured, reviewed change, never an assumption about the platform.
fn fullfsync_satisfied(value: i64) -> bool {
    value == 1
}

#[cfg(test)]
mod fullfsync_requirement {
    use super::fullfsync_satisfied;
    #[test]
    fn requires_exactly_one_until_a_native_readback_proves_otherwise() {
        assert!(fullfsync_satisfied(1));
        assert!(!fullfsync_satisfied(0));
        assert!(!fullfsync_satisfied(2));
        assert!(!fullfsync_satisfied(-1));
    }
}

#[cfg(all(test, windows))]
mod windows_pragma_readback {
    use rusqlite::Connection;
    /// R1 F4: libtest captures `print!`/`eprintln!` from a PASSING test unless
    /// the run passes `--nocapture`; a direct stderr write is not captured, so
    /// this diagnostic reaches the CI log with no workflow change.
    fn emit(line: &str) {
        use std::io::Write as _;
        let _ = std::io::stderr().write_all(format!("{line}\n").as_bytes());
    }
    /// Diagnostic for the PRAGMA readback `open_inner` performs. Native Windows run
    /// 41135325195 failed 110 pool tests before the readback was made platform-correct;
    /// `fullfsync` was assumed to read back 1 there even though it is a macOS-only sync
    /// method. This test PRINTS what Windows reports under the fixed tag
    /// `[pool-ledger-pragma-readback]` instead of assuming the value.
    #[test]
    fn journal_mode_synchronous_and_fullfsync_readback() {
        let temp = tempfile::tempdir().expect("temp dir for the pragma readback");
        let path = temp.path().join("pragma-readback.sqlite3");
        let connection = Connection::open(&path).expect("open a temp database");
        let mode: String = connection
            .query_row("PRAGMA journal_mode=PERSIST", [], |row| row.get(0))
            .expect("journal_mode readback");
        connection
            .execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")
            .expect("durability pragmas");
        let sync: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .expect("synchronous readback");
        let full: i64 = connection
            .query_row("PRAGMA fullfsync", [], |row| row.get(0))
            .expect("fullfsync readback");
        emit(&format!(
            "[pool-ledger-pragma-readback] journal_mode={mode} synchronous={sync} fullfsync={full}"
        ));
        assert_eq!(mode, "persist", "journal_mode must read back persist");
        assert_eq!(sync, 2, "synchronous must read back 2 (FULL)");
        assert!(
            full == 0 || full == 1,
            "fullfsync must read back 0 or 1, got {full}"
        );
    }
    /// ROOT R1 M1 follow-up: what shape does SQLITE's own `-journal` have inside
    /// the pool leaf? The checker accepts a child of the inheriting leaf, and the
    /// native runner copies the leaf's grant WITHOUT inheritance flags on the
    /// DACL while the label arrives `ID`-flagged (run 41151503624). SQLite uses
    /// `CreateFileW(..., NULL, ...)` too, so this must be the same shape — this
    /// test PRINTS it under a fixed tag and FAILS if the pool checker refuses
    /// it, so the next native run carries the real sidecar descriptor.
    #[test]
    fn sqlite_sidecar_shape_inside_the_inheriting_leaf() {
        use crate::platform::fs_windows_acl::{
            check_private_inherited_handle_as, create_private_directory_inheriting,
            observed_sddl_at, open_unchecked_shared_handle, UserSid,
        };
        let _env = crate::platform::test_env::lock();
        let base = tempfile::tempdir().expect("temp dir for the sqlite sidecar probe");
        let dir = base.path().join("pool");
        create_private_directory_inheriting(&dir).expect("the leaf the ledger creates");
        let database = dir.join("probe.sqlite3");
        let connection = Connection::open(&database).expect("open a database in the leaf");
        connection
            .execute_batch(
                "PRAGMA journal_mode=PERSIST; PRAGMA synchronous=FULL;
                 CREATE TABLE t (x INTEGER); BEGIN; INSERT INTO t VALUES (1); COMMIT;",
            )
            .expect("a committed transaction with a persistent journal");
        drop(connection);
        let journal = dir.join("probe.sqlite3-journal");
        assert!(
            journal.exists(),
            "fixture: PERSIST must leave the journal beside the database"
        );
        emit(&format!(
            "[pool-sidecar-sqlite-sddl] leaf={}",
            observed_sddl_at(&dir).unwrap_or_else(|_| "<unreadable>".to_string())
        ));
        emit(&format!(
            "[pool-sidecar-sqlite-sddl] journal={}",
            observed_sddl_at(&journal).unwrap_or_else(|_| "<unreadable>".to_string())
        ));
        let held = open_unchecked_shared_handle(&journal, false)
            .expect("the inherited grant allows a read handle");
        check_private_inherited_handle_as(&held, &UserSid::current().expect("token user"))
            .expect("the pool checker must accept SQLite's own sidecar shape");
    }
}
