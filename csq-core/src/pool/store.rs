use super::execution::PoolClock;
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
use std::time::{Duration, Instant};

#[path = "fingerprint.rs"]
mod fingerprint;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    entry: PoolEntry,
    secret_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remove_backup_id: Option<String>,
}

/// Internal selection snapshot. The secret fingerprint is omitted from Debug.
#[derive(Clone)]
pub(crate) struct ExecutionCandidate {
    pub entry: PoolEntry,
    pub generation: String,
    pub fingerprint: String,
}

/// Carries a committed callback value even when the final mirror publication
/// lags. Dispatch requires a durably active initialization identity.
pub(crate) struct ExecutionAdmission<T> {
    pub value: T,
    pub can_dispatch: bool,
}
impl<T> std::fmt::Debug for ExecutionAdmission<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionAdmission")
            .field("value", &"[REDACTED]")
            .field("can_dispatch", &self.can_dispatch)
            .finish()
    }
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static FAIL_LEDGER_MIRROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_LEDGER_LAG_READ: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_LEDGER_LAG_RECORD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_LEDGER_LAG_CLEAR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    #[cfg(unix)]
    static FAIL_MANIFEST_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
type CustodyPhaseObserver = std::rc::Rc<dyn Fn()>;
#[cfg(test)]
thread_local! {
    static CUSTODY_PHASE_OBSERVER: std::cell::RefCell<Option<CustodyPhaseObserver>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-utils"))]
struct LedgerLagFaultGuard {
    previous: [bool; 4],
    // A thread-local fault must be restored on the thread that installed it.
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(any(test, feature = "test-utils"))]
impl LedgerLagFaultGuard {
    fn new(enabled: [bool; 4]) -> Self {
        let previous = [
            FAIL_LEDGER_MIRROR.with(|slot| slot.replace(slot.get() || enabled[0])),
            FAIL_LEDGER_LAG_READ.with(|slot| slot.replace(slot.get() || enabled[1])),
            FAIL_LEDGER_LAG_RECORD.with(|slot| slot.replace(slot.get() || enabled[2])),
            FAIL_LEDGER_LAG_CLEAR.with(|slot| slot.replace(slot.get() || enabled[3])),
        ];
        Self {
            previous,
            _same_thread: std::marker::PhantomData,
        }
    }
}
#[cfg(any(test, feature = "test-utils"))]
impl Drop for LedgerLagFaultGuard {
    fn drop(&mut self) {
        FAIL_LEDGER_MIRROR.with(|slot| slot.set(self.previous[0]));
        FAIL_LEDGER_LAG_READ.with(|slot| slot.set(self.previous[1]));
        FAIL_LEDGER_LAG_RECORD.with(|slot| slot.set(self.previous[2]));
        FAIL_LEDGER_LAG_CLEAR.with(|slot| slot.set(self.previous[3]));
    }
}

/// Test-only permission fault applied after custody has secured the directory.
/// It surrounds the real writer and restores the original mode on every exit.
#[cfg(all(unix, any(test, feature = "test-utils")))]
struct ManifestWriteModeGuard {
    parent: PathBuf,
    original: std::fs::Permissions,
}
#[cfg(all(unix, any(test, feature = "test-utils")))]
impl ManifestWriteModeGuard {
    fn for_path(path: &Path) -> std::io::Result<Option<Self>> {
        use std::os::unix::fs::PermissionsExt;
        if !FAIL_MANIFEST_WRITE.with(|slot| slot.get())
            || path.file_name() != Some(std::ffi::OsStr::new("manifest.json"))
        {
            return Ok(None);
        }
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture parent"))?;
        let original = std::fs::metadata(parent)?.permissions();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500))?;
        Ok(Some(Self {
            parent: parent.to_path_buf(),
            original,
        }))
    }
}
#[cfg(all(unix, any(test, feature = "test-utils")))]
impl Drop for ManifestWriteModeGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.parent, self.original.clone());
    }
}
impl ExecutionCandidate {
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn from_stored(row: StoredEntry) -> Result<Self> {
        Ok(Self {
            entry: row.entry,
            generation: row.generation.ok_or(PoolError::ManifestInvalid)?,
            fingerprint: row.fingerprint.ok_or(PoolError::ManifestInvalid)?,
        })
    }
}
impl std::fmt::Debug for ExecutionCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionCandidate")
            .field("entry", &self.entry)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for StoredEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredEntry")
            .field("entry", &self.entry)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerIdentity {
    pub id: String,
    pub sequence: u64,
    pub salt_id: String,
    #[serde(default)]
    pub state: LedgerState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LedgerState {
    PendingInit,
    #[default]
    Active,
}

#[cfg(test)]
#[path = "execution_custody_tests.rs"]
mod execution_custody_tests;
#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

#[cfg(test)]
mod collision_tests {
    use super::*;

    #[test]
    fn f_a_pool_json_retries_sibling_collision() {
        let dir = tempfile::TempDir::new().unwrap();
        let value = serde_json::json!({"version": 1, "entries": []});
        let target = dir.path().join("manifest.json");
        let foreign = std::rc::Rc::new(std::cell::RefCell::new(None::<std::path::PathBuf>));
        let planted = std::rc::Rc::clone(&foreign);
        let selected_target = target.clone();
        let result = crate::platform::fs::with_private_create_observer_for_test(
            move |candidate| {
                assert_eq!(candidate.parent(), selected_target.parent());
                assert_ne!(candidate, selected_target.as_path());
                if planted.borrow().is_none() {
                    std::fs::write(candidate, b"foreign collision sentinel").unwrap();
                    *planted.borrow_mut() = Some(candidate.to_path_buf());
                }
            },
            || write_json(&target, &value),
        );
        let foreign = foreign.borrow().clone().expect("create observer must run");
        assert_eq!(
            std::fs::read(&foreign).unwrap(),
            b"foreign collision sentinel"
        );
        assert!(
            result.is_ok(),
            "first temporary collision must not fail the save"
        );
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(saved, value);
    }
}

/// Native-Windows proof that the pool root is created in the shape the ledger and
/// the secure database require, and that a pre-existing broad root is refused, not
/// repaired. The unix root-creation path (`create_dir_all`) is unchanged and stays
/// covered by the pool suite.
#[cfg(all(test, windows))]
mod windows_pool_root {
    use super::Pool;
    use crate::platform::fs_windows_acl::{
        check_no_foreign_write, check_no_foreign_write_for_adoption, current_user_sid_text,
        hard_link_count, observed_acl_at, observed_sddl_at, open_directory_adopt_handle,
        open_directory_check_handle, open_private_directory_inheriting,
        open_unchecked_shared_handle, set_file_dacl, set_owner_to_current_user,
    };
    use crate::pool::execution_ledger::{BudgetError, BudgetLedger};

    /// (a) Custody over a fresh base creates the inheriting leaf, and the ledger
    /// opens over it end to end.
    #[test]
    fn custody_creates_an_inheriting_leaf_the_ledger_accepts() {
        let base = tempfile::tempdir().expect("temp dir for the pool root");
        let root = base.path().join("pool");
        assert!(!root.exists(), "the fixture must start without a pool root");
        // Taking custody is what creates the root.
        drop(
            Pool::new(base.path())
                .custody()
                .expect("custody over a fresh base"),
        );
        // The created leaf must be exactly the shape both openers require.
        drop(
            open_private_directory_inheriting(&root)
                .expect("the created root is the inheriting private shape"),
        );
        // End to end: the ledger opens, initializes its schema and closes.
        drop(BudgetLedger::open(base.path()).expect("the ledger opens over the created root"));
    }

    /// (b) A pre-existing v2.21.3 root — the default DACL, owner the USER — is
    /// ADOPTED by the ledger (R1 F5): the ledger opens, the root's DACL becomes
    /// the owner-only inheriting form custody creates, and the adopted root is
    /// reopened and reopened AGAIN with no further repair. Assertions read the
    /// CONTROL BITS plus the parsed ACE list, never an SDDL substring: the OS
    /// stamps `SE_DACL_AUTO_INHERITED` beside `SE_DACL_PROTECTED` on an adopted
    /// root (`D:PAI(…)`, native run 41157525966), which is the shape a second
    /// launch of an upgraded user must accept.
    #[test]
    fn a_user_owned_default_dacl_root_is_adopted_and_tightened() {
        let base = tempfile::tempdir().expect("temp dir for the pool root");
        let root = base.path().join("pool");
        std::fs::create_dir(&root).expect("pre-create the root with the default DACL");
        // The upgrade fixture: v2.21.3 created this directory with the process
        // default security, so its DACL is inherited and broad. An elevated
        // runner owns it as Administrators; F5 requires the USER SID, so give
        // it back the way the M3 tightening does.
        let adopt = open_directory_adopt_handle(&root).expect("open the pre-existing root");
        set_owner_to_current_user(&adopt).expect("owner back to the user SID");
        drop(adopt);
        let sid = current_user_sid_text().expect("the token user SID as text");
        // The REAL Windows profile default, made deterministic instead of
        // depending on the runner's %TEMP%: SYSTEM and BUILTIN\Administrators
        // beside the user, inherited and entry-removing. ROOT's F5 refinement:
        // ADOPTION may accept these two principals alongside the user (both are
        // already all-powerful on the host); everyone else stays refused.
        set_file_dacl(
            &root,
            &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        )
        .expect("plant the profile-default DACL");
        let before = observed_acl_at(&root).expect("the fixture root's parsed descriptor");
        // Premise, asserted before the behaviour under test: the fixture root is
        // NOT the inheriting shape, so a pass below cannot be vacuous.
        let _ = open_private_directory_inheriting(&root)
            .expect_err("a default-DACL root must not satisfy the inheriting shape");
        assert!(!before.dacl_protected(), "premise: the DACL is inherited");
        for principal in ["S-1-5-18", "S-1-5-32-544", sid.as_str()] {
            assert!(
                before.dacl_sids().contains(&principal),
                "premise: the profile-default principal {principal} is present: {before:?}"
            );
        }
        // Custody tolerates the existing directory (create -> AlreadyExists) ...
        drop(
            Pool::new(base.path())
                .custody()
                .expect("custody tolerates an existing root"),
        );
        // ... and the ledger adopts it instead of refusing the upgraded user.
        drop(BudgetLedger::open(base.path()).expect("the ledger adopts a user-owned root"));
        let after = observed_acl_at(&root).expect("the adopted root's parsed descriptor");
        assert_ne!(after, before, "adoption must re-ACL the root: {before:?}");
        assert_eq!(after.owner, sid, "the owner stays the user SID: {after:?}");
        assert!(
            after.dacl_protected(),
            "the adopted root's DACL is PROTECTED (AI beside P is legal): {after:?}"
        );
        assert_eq!(
            after.dacl.len(),
            1,
            "exactly one owner ACE remains: {after:?}"
        );
        let grant = &after.dacl[0];
        assert!(
            grant.is_access_allowed() && grant.is_file_all_access() && grant.sid == sid,
            "the adopted root grants FILE_ALL_ACCESS to the user: {after:?}"
        );
        assert!(
            grant.inherits_to_children(),
            "the adopted root's ACE inherits to children: {after:?}"
        );
        assert_eq!(after.label.len(), 1, "exactly one label ACE: {after:?}");
        let label = &after.label[0];
        assert!(
            label.is_label() && label.inherits_to_children(),
            "the adopted root's label inherits to children: {after:?}"
        );
        let sids = after.dacl_sids();
        assert!(
            !sids.contains(&"S-1-5-18") && !sids.contains(&"S-1-5-32-544"),
            "adoption must drop the profile-default principals: {after:?}"
        );
        // The adopted root is now the exact shape a fresh one has, so the
        // ledger reopens over it with no further repair.
        drop(
            open_private_directory_inheriting(&root).expect("the adopted root is the exact shape"),
        );
        drop(BudgetLedger::open(base.path()).expect("the ledger reopens over the adopted root"));
    }

    /// (c) A pre-existing root with a FOREIGN entry-removing ACE is refused by
    /// the ledger and its SDDL is unchanged: adoption is a tightening of a
    /// user-owned root, never a repair of a compromised one (R1 F5).
    #[test]
    fn a_root_with_a_foreign_ace_is_refused_with_its_sddl_unchanged() {
        let base = tempfile::tempdir().expect("temp dir for the pool root");
        let root = base.path().join("pool");
        std::fs::create_dir(&root).expect("pre-create the root");
        let adopt = open_directory_adopt_handle(&root).expect("open the pre-existing root");
        set_owner_to_current_user(&adopt).expect("owner back to the user SID");
        drop(adopt);
        let sid = current_user_sid_text().expect("the token user SID as text");
        // Everyone holds generic all: an entry-removing foreign grant the
        // ancestor policy refuses even though the owner is the user. The DACL
        // stays UNPROTECTED (the v2.21.3 shape), so the refusal is the foreign
        // ACE's and not the protected-leaf gate's.
        set_file_dacl(&root, &format!("D:(A;;FA;;;{sid})(A;OICI;GA;;;WD)"))
            .expect("plant the foreign ACE");
        let before = observed_sddl_at(&root).expect("SDDL before the ledger opens");
        // Semantic premise (native run 41155302330: Windows expands/merges the
        // Everyone ACE, so a substring match on the written SDDL is unreliable):
        // the production ancestor policy itself must refuse this root.
        let check = open_directory_check_handle(&root).expect("open the root for the policy");
        assert!(
            check_no_foreign_write_for_adoption(&check).is_err(),
            "premise: the ADOPTION policy refuses a root where Everyone holds \
             entry-removing rights: {before}"
        );
        drop(check);
        drop(
            Pool::new(base.path())
                .custody()
                .expect("custody tolerates an existing root"),
        );
        assert!(
            matches!(
                BudgetLedger::open(base.path()),
                Err(BudgetError::Unavailable)
            ),
            "the ledger must refuse a root with a foreign entry-removing ACE"
        );
        let after = observed_sddl_at(&root).expect("SDDL after the ledger opens");
        assert_eq!(
            after, before,
            "a refused root must not be touched: adoption is not a repair"
        );
    }

    /// (d) R2 NEW-1: a READ-ONLY foreign allow ACE is the case ADOPTION mode
    /// exists for — the ancestry policy tolerates it (it cannot displace an
    /// entry), adoption must not (the principal can still plant entries). The
    /// ledger refuses and the root's parsed descriptor is unchanged. On the
    /// base, where adoption judged entry-removing masks only, this root is
    /// accepted, so this test is the item's native RED.
    #[test]
    fn a_root_with_a_foreign_read_only_ace_is_refused_with_its_descriptor_unchanged() {
        let base = tempfile::tempdir().expect("temp dir for the pool root");
        let root = base.path().join("pool");
        std::fs::create_dir(&root).expect("pre-create the root");
        let adopt = open_directory_adopt_handle(&root).expect("open the pre-existing root");
        set_owner_to_current_user(&adopt).expect("owner back to the user SID");
        drop(adopt);
        let sid = current_user_sid_text().expect("the token user SID as text");
        // Everyone holds READ ONLY beside the user's inheriting grant.
        set_file_dacl(&root, &format!("D:(A;OICI;FA;;;{sid})(A;;FR;;;WD)"))
            .expect("plant the read-only Everyone ACE");
        let before = observed_acl_at(&root).expect("the fixture root's parsed descriptor");
        assert!(
            before
                .dacl
                .iter()
                .any(|ace| ace.is_access_allowed() && ace.sid == "S-1-1-0"),
            "premise: the read-only Everyone ACE is present: {before:?}"
        );
        // Premise: the two policies disagree on exactly this root — the
        // ancestry rule accepts it, ADOPTION refuses it.
        let check = open_directory_check_handle(&root).expect("open the root for the policies");
        check_no_foreign_write(&check)
            .expect("premise: the ancestry policy tolerates a read-only foreign ACE");
        assert!(
            check_no_foreign_write_for_adoption(&check).is_err(),
            "premise: the ADOPTION policy refuses it"
        );
        drop(check);
        drop(
            Pool::new(base.path())
                .custody()
                .expect("custody tolerates an existing root"),
        );
        assert!(
            matches!(
                BudgetLedger::open(base.path()),
                Err(BudgetError::Unavailable)
            ),
            "the ledger must refuse a root with a read-only foreign ACE"
        );
        assert_eq!(
            observed_acl_at(&root).expect("the root after the refusal"),
            before,
            "a refused root must not be touched"
        );
    }

    /// (e) R2 NEW-2: a child with TWO hard links refuses adoption before the
    /// root is re-ACLed; the root, the link target and both names are intact.
    #[test]
    fn a_hardlinked_child_refuses_adoption_untouched() {
        let base = tempfile::tempdir().expect("temp dir for the pool root");
        let root = base.path().join("pool");
        std::fs::create_dir(&root).expect("pre-create the root");
        let adopt = open_directory_adopt_handle(&root).expect("open the pre-existing root");
        set_owner_to_current_user(&adopt).expect("owner back to the user SID");
        drop(adopt);
        let sid = current_user_sid_text().expect("the token user SID as text");
        set_file_dacl(
            &root,
            &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        )
        .expect("plant the profile-default DACL");
        let child = root.join("manifest.json");
        let target = base.path().join("elsewhere.json");
        drop(std::fs::File::create(&child).expect("create the child"));
        std::fs::hard_link(&child, &target).expect("hardlink the child outside the root");
        assert_eq!(
            {
                let held = open_unchecked_shared_handle(&child, false).unwrap();
                hard_link_count(&held).unwrap()
            },
            2,
            "premise: the child has two hard links"
        );
        let root_before = observed_acl_at(&root).expect("the root before");
        let target_before = observed_acl_at(&target).expect("the target before");
        drop(
            Pool::new(base.path())
                .custody()
                .expect("custody tolerates an existing root"),
        );
        assert!(
            matches!(
                BudgetLedger::open(base.path()),
                Err(BudgetError::Unavailable)
            ),
            "the ledger must refuse a root with a hardlinked child"
        );
        assert_eq!(
            observed_acl_at(&root).unwrap(),
            root_before,
            "the root must not be re-ACLed"
        );
        assert_eq!(
            observed_acl_at(&target).unwrap(),
            target_before,
            "the link target must be untouched"
        );
        assert_eq!(
            {
                let held = open_unchecked_shared_handle(&target, false).unwrap();
                hard_link_count(&held).unwrap()
            },
            2,
            "both names survive the refusal"
        );
    }

    /// (f) R2 NEW-2: a clean v2.21.3 layout — the four flat children under the
    /// profile-default DACL — adopts end to end: the root becomes the inheriting
    /// form, every child ends in the shape a pool child must have, and the
    /// ledger reopens over it with no further repair.
    #[test]
    fn a_clean_v2_21_3_layout_adopts_and_the_ledger_reopens() {
        let base = tempfile::tempdir().expect("temp dir for the pool root");
        let root = base.path().join("pool");
        std::fs::create_dir(&root).expect("pre-create the root");
        let adopt = open_directory_adopt_handle(&root).expect("open the pre-existing root");
        set_owner_to_current_user(&adopt).expect("owner back to the user SID");
        drop(adopt);
        let sid = current_user_sid_text().expect("the token user SID as text");
        set_file_dacl(
            &root,
            &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        )
        .expect("plant the profile-default DACL");
        let names = [".lock", "manifest.json", "transaction.json", "cleanup.json"];
        for name in names {
            drop(std::fs::File::create(root.join(name)).expect("create the v2.21.3 child"));
        }
        drop(
            Pool::new(base.path())
                .custody()
                .expect("custody tolerates an existing root"),
        );
        drop(BudgetLedger::open(base.path()).expect("the ledger adopts a clean v2.21.3 root"));
        let after = observed_acl_at(&root).expect("the adopted root");
        assert!(
            after.dacl_protected(),
            "the adopted root's DACL is protected: {after:?}"
        );
        assert_eq!(
            after.dacl.len(),
            1,
            "exactly the owner ACE remains: {after:?}"
        );
        assert_eq!(after.dacl[0].sid, sid, "the grant is the user's: {after:?}");
        assert!(
            after.dacl[0].inherits_to_children(),
            "the root grant inherits: {after:?}"
        );
        for name in names {
            let child = observed_acl_at(&root.join(name)).expect("the child after adoption");
            assert!(
                !child.dacl_protected(),
                "child {name} keeps an auto-inherited DACL: {child:?}"
            );
            assert_eq!(
                child.dacl.len(),
                1,
                "child {name} carries exactly the owner ACE: {child:?}"
            );
            let grant = &child.dacl[0];
            assert!(
                grant.is_access_allowed() && grant.is_file_all_access() && grant.sid == sid,
                "child {name} grants FILE_ALL_ACCESS to the user: {child:?}"
            );
            assert_eq!(
                child.label.len(),
                1,
                "child {name} carries one label ACE: {child:?}"
            );
            assert!(
                child.label[0].is_label(),
                "child {name}'s label is a mandatory label: {child:?}"
            );
        }
        drop(
            open_private_directory_inheriting(&root).expect("the adopted root is the exact shape"),
        );
        drop(BudgetLedger::open(base.path()).expect("the ledger reopens over the adopted root"));
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    env_file: Option<PathBuf>,
    entries: Vec<StoredEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ledger_identity: Option<LedgerIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint_salt: Option<fingerprint::Salt>,
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
        if let Some(salt) = &self.fingerprint_salt {
            salt.validate()?;
        }
        if let Some(identity) = &self.ledger_identity {
            validate_id(&identity.id)?;
            fingerprint::validate_digest(&identity.salt_id)?;
            if identity.state == LedgerState::PendingInit && identity.sequence != 0 {
                return Err(PoolError::ManifestInvalid);
            }
        }
        for row in &self.entries {
            row.entry.validate()?;
            if !names.insert(row.entry.name.as_str()) {
                return Err(PoolError::ManifestInvalid);
            }
            if let Some(generation) = &row.generation {
                validate_id(generation)?;
            }
            if let Some(fingerprint) = &row.fingerprint {
                fingerprint::validate_digest(fingerprint)?;
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
fn named_read_error(error: secret::SecretError) -> PoolError {
    match error {
        secret::SecretError::NamedNotFound => PoolError::KeyMissing,
        secret::SecretError::NamedItemUnreadable => PoolError::ItemReadUnavailable,
        // DecryptionFailed can mean a wrong vault key/KDF, and permission,
        // timeout and I/O errors do not prove that only one item was affected.
        _ => PoolError::StoreUnavailable,
    }
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    #[cfg(all(unix, any(test, feature = "test-utils")))]
    let _write_mode_guard =
        ManifestWriteModeGuard::for_path(path).map_err(|_| PoolError::ManifestWriteUnavailable)?;
    // The private manifest now carries the HMAC salt. Serialize into one bounded
    // zeroizing allocation, so growth cannot free an unwiped prefix.
    struct Body {
        bytes: zeroize::Zeroizing<Vec<u8>>,
        used: usize,
    }
    impl std::io::Write for Body {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let end = self
                .used
                .checked_add(bytes.len())
                .filter(|end| *end <= self.bytes.len())
                .ok_or_else(|| std::io::Error::other("pool_json_capacity"))?;
            self.bytes[self.used..end].copy_from_slice(bytes);
            self.used = end;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut body = Body {
        bytes: zeroize::Zeroizing::new(vec![0; MAX_MANIFEST_BYTES as usize]),
        used: 0,
    };
    serde_json::to_writer_pretty(&mut body, value).map_err(|_| PoolError::ManifestInvalid)?;
    // The retained creator owns cleanup and stays open through publication.
    let result = fs::write_private_tmp_synced_retained(path, &body.bytes[..body.used])
        .and_then(|written| written.replace(path));
    if result.is_err() {
        return Err(PoolError::ManifestWriteUnavailable);
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

/// Creates the pool root `base/pool`, the leaf that the execution ledger and the
/// secure database both open.
///
/// Windows only, because the leaf's ACL shape is what differs: the root must be
/// born in the INHERITING owner-only shape. SQLite creates its `-journal`/`-wal`/
/// `-shm` sidecars with `lpSecurityAttributes = NULL`, so they carry whatever the
/// leaf propagates; under a protected non-inheriting leaf they would be born with
/// an empty DACL, and both
/// [`SecureDatabase`](crate::messaging::storage::secure::SecureDatabase) and the
/// ledger's sidecar check require the private shape. An existing directory is
/// never re-ACLed HERE: `AlreadyExists` is tolerated and the openers judge it.
/// The ONE repair is the ledger's adopt-and-tighten of a v2.21.3 root (R1 F5):
/// `SecureDatabase::acquire_pool_ledger` re-ACLs it only when its owner is
/// byte-exactly the user SID, the ancestor policy passes, and the identity
/// stays stable; any other broad root is REFUSED, not repaired. The ancestors
/// above the leaf only need to exist here; the ledger's ancestor policy
/// inspects them.
#[cfg(windows)]
fn create_pool_root(root: &Path) -> std::io::Result<()> {
    use crate::platform::fs_windows_acl::{create_private_directory_inheriting, PrivateAclError};
    if let Some(parent) = root.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    match create_private_directory_inheriting(root) {
        Ok(()) => Ok(()),
        Err(PrivateAclError::Os(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
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
    /// Observe the held-custody phase immediately before its deadline check.
    #[cfg(test)]
    pub(crate) fn with_custody_phase_observer_for_test<T>(
        observer: impl Fn() + 'static,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<CustodyPhaseObserver>);
        impl Drop for Restore {
            fn drop(&mut self) {
                CUSTODY_PHASE_OBSERVER.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let previous =
            CUSTODY_PHASE_OBSERVER.with(|slot| slot.replace(Some(std::rc::Rc::new(observer))));
        let _restore = Restore(previous);
        operation()
    }
    /// Same-thread fixture failure of final mirror publication only. Pending
    /// initialization prepublication continues to use the real synced writer.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_ledger_mirror_failure_for_test<T>(operation: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FAIL_LEDGER_MIRROR.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(FAIL_LEDGER_MIRROR.with(|slot| slot.replace(true)));
        operation()
    }
    /// Retain this same-thread guard from a synthetic transport through
    /// settlement and the next admission to model an ongoing publication fault.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn ledger_mirror_and_lag_record_failure_for_test() -> impl Drop {
        LedgerLagFaultGuard::new([true, false, true, false])
    }
    /// Same-thread read failure of the durable lag record only.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn ledger_lag_read_failure_for_test() -> impl Drop {
        LedgerLagFaultGuard::new([false, true, false, false])
    }
    /// Same-thread failure to clear an existing durable lag record only.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn ledger_lag_clear_failure_for_test() -> impl Drop {
        LedgerLagFaultGuard::new([false, false, false, true])
    }
    /// Same-thread test fault at the real manifest writer. Both this hook and
    /// its writer callsite are absent without test/test-utils configuration.
    #[cfg(all(unix, any(test, feature = "test-utils")))]
    pub fn with_manifest_write_failure_for_test<T>(operation: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FAIL_MANIFEST_WRITE.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(FAIL_MANIFEST_WRITE.with(|slot| slot.replace(true)));
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
        // No deadline: the clock argument is never read on this path.
        self.custody_with_deadline_and_clock(None, &PoolClock::system())
    }
    fn custody_with_deadline_and_clock(
        &self,
        deadline: Option<Instant>,
        clock: &PoolClock<'_>,
    ) -> Result<lock::FileLockGuard> {
        if deadline.is_some_and(|value| value <= clock.now()) {
            return Err(PoolError::Busy);
        }
        match std::fs::symlink_metadata(&self.root) {
            Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
                return Err(PoolError::ManifestUnavailable)
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(not(windows))]
                std::fs::create_dir_all(&self.root).map_err(|_| PoolError::ManifestUnavailable)?;
                #[cfg(windows)]
                create_pool_root(&self.root).map_err(|_| PoolError::ManifestUnavailable)?;
            }
            Err(_) => return Err(PoolError::ManifestUnavailable),
        }
        fs::secure_dir(&self.root).map_err(|_| PoolError::ManifestUnavailable)?;
        let (attempts, delay) = if let Some(deadline) = deadline {
            let remaining = deadline
                .checked_duration_since(clock.now())
                .ok_or(PoolError::Busy)?;
            if remaining.is_zero() {
                return Err(PoolError::Busy);
            }
            // Use the existing single-open lock primitive. Its fixed retry budget
            // fits inside the remaining deadline on both platform backends.
            let poll_nanos = Duration::from_millis(5).as_nanos();
            let intervals = remaining
                .as_nanos()
                .div_ceil(poll_nanos)
                .min(u128::from(u32::MAX - 1)) as u32;
            let delay = remaining / intervals;
            // Unix sleeps only between attempts; Windows consumes attempts*delay
            // as one total mutex wait budget.
            #[cfg(unix)]
            let attempts = intervals + 1;
            #[cfg(not(unix))]
            let attempts = intervals;
            (attempts, delay)
        } else {
            (1, Duration::ZERO)
        };
        let guard = lock::try_lock_file_bounded_nofollow(&self.root.join(".lock"), attempts, delay)
            .map_err(|_| PoolError::ManifestUnavailable)?
            .ok_or(PoolError::Busy)?;
        #[cfg(test)]
        if let Some(observer) = CUSTODY_PHASE_OBSERVER.with(|slot| slot.borrow().clone()) {
            observer();
        }
        if deadline.is_some_and(|value| value <= clock.now()) {
            return Err(PoolError::Busy);
        }
        Ok(guard)
    }
    fn load(&self) -> Result<Manifest> {
        let Some(bytes) =
            fs::read_regular_nofollow_bounded(&self.root.join("manifest.json"), MAX_MANIFEST_BYTES)
                .map_err(|_| PoolError::ManifestUnavailable)?
        else {
            return Ok(Manifest::empty());
        };
        let bytes = zeroize::Zeroizing::new(bytes);
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
            ledger_identity: manifest.ledger_identity.clone(),
            fingerprint_salt: manifest.fingerprint_salt.clone(),
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
    /// Select admitted metadata without probing or opening a key source.
    /// Legacy rows acquire durable generation identities before selection.
    #[cfg(test)]
    pub(crate) fn execution_candidates(&self, provider: &str) -> Result<Vec<ExecutionCandidate>> {
        self.execution_candidates_inner(provider, None, false, &PoolClock::system())
    }
    #[cfg(test)]
    pub(crate) fn execution_candidates_bound(
        &self,
        provider: &str,
        deadline: Instant,
    ) -> Result<Vec<ExecutionCandidate>> {
        self.execution_candidates_bound_with_clock(provider, deadline, &PoolClock::system())
    }
    /// Reads every deadline from the execution's [`PoolClock`]; production passes `PoolClock::system()`.
    pub(crate) fn execution_candidates_bound_with_clock(
        &self,
        provider: &str,
        deadline: Instant,
        clock: &PoolClock<'_>,
    ) -> Result<Vec<ExecutionCandidate>> {
        self.execution_candidates_inner(provider, Some(deadline), true, clock)
    }
    fn execution_candidates_inner(
        &self,
        provider: &str,
        deadline: Option<Instant>,
        bind_fingerprints: bool,
        clock: &PoolClock<'_>,
    ) -> Result<Vec<ExecutionCandidate>> {
        types::validate_provider(provider)?;
        let _guard = self.custody_with_deadline_and_clock(deadline, clock)?;
        let mut manifest = self.execution_manifest()?;
        // A missing native store is a pool-wide outage, including rows for a
        // different provider or a name sorted after healthy env-file entries.
        if manifest
            .entries
            .iter()
            .any(|row| row.entry.source == KeySource::SecretStore)
        {
            self.with_store(|vault| {
                if vault
                    .named_store_present()
                    .map_err(|_| PoolError::StoreUnavailable)?
                {
                    Ok(())
                } else {
                    Err(PoolError::StoreUnavailable)
                }
            })?;
        }
        // load() treats absence as empty for configuration operations. Execution
        // distinguishes an unconfigured pool from a configured, exhausted one.
        let mut changed = if bind_fingerprints {
            self.sync_fingerprints(&mut manifest, None)?
        } else {
            false
        };
        for row in &mut manifest.entries {
            if row.entry.provider == provider && row.generation.is_none() {
                row.generation = Some(fresh_id());
                changed = true;
            }
        }
        if changed {
            self.save(&manifest)?;
        }
        if deadline.is_some_and(|value| value <= clock.now()) {
            return Err(PoolError::Busy);
        }
        manifest
            .entries
            .into_iter()
            .filter(|row| row.entry.provider == provider)
            .map(|row| {
                // Only the explicitly unbound test compatibility path permits
                // a legacy row without a fingerprint. Production always refuses.
                #[cfg(test)]
                let row = if !bind_fingerprints && row.fingerprint.is_none() {
                    StoredEntry {
                        fingerprint: Some(String::new()),
                        ..row
                    }
                } else {
                    row
                };
                ExecutionCandidate::from_stored(row)
            })
            .collect()
    }

    fn execution_manifest(&self) -> Result<Manifest> {
        let manifest = self.prepare()?;
        std::fs::symlink_metadata(self.root.join("manifest.json"))
            .map_err(|_| PoolError::ManifestUnavailable)?;
        Ok(manifest)
    }
    fn salt_id(manifest: &Manifest) -> Result<String> {
        let salt_id = manifest
            .fingerprint_salt
            .as_ref()
            .ok_or(PoolError::LedgerIdentityMismatch)?
            .id();
        if manifest
            .ledger_identity
            .as_ref()
            .is_some_and(|identity| identity.salt_id != salt_id)
        {
            return Err(PoolError::LedgerIdentityMismatch);
        }
        Ok(salt_id)
    }
    /// Legacy migration publishes only after every required read and live-duplicate
    /// check succeeds. Modern rows use their stored fingerprints; ordinary
    /// execution reads only its selected source in fresh_execution_key.
    fn sync_fingerprints(
        &self,
        manifest: &mut Manifest,
        selected: Option<&PoolName>,
    ) -> Result<bool> {
        let created = manifest.fingerprint_salt.is_none();
        if created {
            if manifest.ledger_identity.is_some() {
                return Err(PoolError::LedgerIdentityMismatch);
            }
            manifest.fingerprint_salt = Some(fingerprint::Salt::fresh()?);
        }
        Self::salt_id(manifest)?;
        let salt = manifest
            .fingerprint_salt
            .as_ref()
            .ok_or(PoolError::ManifestInvalid)?;
        let migrate_all = created || manifest.entries.iter().any(|row| row.fingerprint.is_none());
        let mut seen = std::collections::HashMap::new();
        let mut updated = Vec::with_capacity(manifest.entries.len());
        for row in &manifest.entries {
            let value = if migrate_all {
                let secret = self.read_stored_key(manifest, row).map_err(|error| {
                    if selected.is_some_and(|name| name != &row.entry.name)
                        && matches!(
                            error,
                            PoolError::KeyMissing
                                | PoolError::EnvFileInvalid
                                | PoolError::EnvFileUnavailable
                                | PoolError::StoreUnavailable
                                | PoolError::ItemReadUnavailable
                        )
                    {
                        PoolError::UnrelatedKeyUnavailable
                    } else {
                        error
                    }
                })?;
                salt.fingerprint(&secret)?
            } else {
                row.fingerprint.clone().ok_or(PoolError::ManifestInvalid)?
            };
            if let Some(previous) = seen.insert(value.clone(), row.entry.name.clone()) {
                if selected.is_some_and(|name| name != &row.entry.name && name != &previous) {
                    return Err(PoolError::UnrelatedKeyUnavailable);
                }
                return Err(PoolError::MutationRefused);
            }
            updated.push(value);
        }
        let mut changed = created;
        for (row, value) in manifest.entries.iter_mut().zip(updated) {
            if row.fingerprint.as_ref() != Some(&value) {
                row.generation = Some(fresh_id());
                changed = true;
            }
            row.fingerprint = Some(value);
        }
        Ok(changed)
    }
    fn prepare_ledger_identity(&self, manifest: &mut Manifest, salt_id: &str) -> Result<()> {
        if manifest.ledger_identity.is_none() {
            manifest.ledger_identity = Some(LedgerIdentity {
                id: fresh_id(),
                sequence: 0,
                salt_id: salt_id.to_owned(),
                state: LedgerState::PendingInit,
            });
            // Database creation may begin only after this pending identity is
            // synced and published. A crash can resume exactly this identity.
            self.save(manifest)
                .map_err(|_| PoolError::LedgerMirrorUnavailable)?;
        }
        Ok(())
    }
    fn save_ledger_mirror(&self, manifest: &Manifest) -> Result<()> {
        #[cfg(any(test, feature = "test-utils"))]
        if FAIL_LEDGER_MIRROR.with(|slot| slot.get()) {
            return Err(PoolError::LedgerMirrorUnavailable);
        }
        self.save(manifest)
    }
    fn ledger_mirror_lag(&self) -> Result<Option<LedgerIdentity>> {
        #[cfg(any(test, feature = "test-utils"))]
        if FAIL_LEDGER_LAG_READ.with(|slot| slot.get()) {
            return Err(PoolError::LedgerMirrorUnavailable);
        }
        let Some(bytes) = fs::read_regular_nofollow_bounded(
            &self.root.join("ledger-mirror-lag.json"),
            MAX_MANIFEST_BYTES,
        )
        .map_err(|_| PoolError::LedgerMirrorUnavailable)?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map_err(|_| PoolError::LedgerMirrorUnavailable)
    }
    fn save_ledger_mirror_lag(&self, identity: Option<&LedgerIdentity>) -> Result<()> {
        #[cfg(any(test, feature = "test-utils"))]
        if (identity.is_some() && FAIL_LEDGER_LAG_RECORD.with(|slot| slot.get()))
            || (identity.is_none() && FAIL_LEDGER_LAG_CLEAR.with(|slot| slot.get()))
        {
            return Err(PoolError::LedgerMirrorUnavailable);
        }
        // Some records one failed publication; null durably clears it. Reuse
        // the same atomic private write for both states, so a failed clear
        // cannot silently make a second failure look like the first one.
        write_json(&self.root.join("ledger-mirror-lag.json"), &identity)
            .map_err(|_| PoolError::LedgerMirrorUnavailable)?;
        // F9: the directory flush uses the ledger's platform-correct
        // `sync_directory` — on Windows a directory handle + FlushFileBuffers,
        // failing closed when the platform cannot flush.
        crate::pool::execution_ledger::sync_directory(&self.root)
            .map_err(|_| PoolError::LedgerMirrorUnavailable)?;
        Ok(())
    }
    fn finish_identity<T>(
        &self,
        manifest: &Manifest,
        previous: Option<LedgerIdentity>,
        salt_id: &str,
        result: T,
    ) -> Result<ExecutionAdmission<T>> {
        let current = &manifest.ledger_identity;
        if let Some(identity) = current {
            validate_id(&identity.id).map_err(|_| PoolError::LedgerIdentityMismatch)?;
            if identity.salt_id != salt_id {
                return Err(PoolError::LedgerIdentityMismatch);
            }
            if identity.state == LedgerState::PendingInit && identity.sequence != 0 {
                return Err(PoolError::LedgerIdentityMismatch);
            }
        }
        if let Some(previous) = &previous {
            if current.as_ref().is_none_or(|value| {
                value.id != previous.id
                    || value.salt_id != previous.salt_id
                    || value.sequence < previous.sequence
                    || (previous.state == LedgerState::Active && value.state != LedgerState::Active)
            }) {
                return Err(PoolError::LedgerIdentityMismatch);
            }
        }
        let lag = self.ledger_mirror_lag()?;
        if let Some(lagged) = &lag {
            if lagged.state != LedgerState::Active
                || current.as_ref().is_none_or(|identity| {
                    identity.id != lagged.id
                        || identity.salt_id != lagged.salt_id
                        || identity.sequence < lagged.sequence
                        || identity.state != LedgerState::Active
                })
            {
                return Err(PoolError::LedgerIdentityMismatch);
            }
        }
        let mut can_dispatch = previous
            .as_ref()
            .is_some_and(|identity| identity.state == LedgerState::Active);
        // The ledger committed before this mirror write. Keep the callback's
        // reservation/result on failure so the caller can dispatch or release.
        // An initial PendingInit identity may not dispatch until Active is durable.
        if *current != previous || lag.is_some() {
            if self.save_ledger_mirror(manifest).is_err() {
                tracing::warn!(error_kind = "pool_ledger_mirror_lagging");
                if lag.is_some() {
                    // Preserve the committed callback value for definitely-
                    // unsent cleanup, but never dispatch through a second
                    // consecutive publication failure.
                    can_dispatch = false;
                } else {
                    let identity = current.as_ref().ok_or(PoolError::LedgerIdentityMismatch)?;
                    self.save_ledger_mirror_lag(Some(identity))?;
                }
            } else {
                if lag.is_some() {
                    self.save_ledger_mirror_lag(None)?;
                }
                can_dispatch = current
                    .as_ref()
                    .is_some_and(|identity| identity.state == LedgerState::Active);
            }
        }
        Ok(ExecutionAdmission {
            value: result,
            can_dispatch,
        })
    }
    #[cfg(test)]
    pub(crate) fn with_ledger_identity<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce(&mut Option<LedgerIdentity>, &str) -> T,
    ) -> Result<T> {
        self.with_ledger_identity_with_clock(deadline, &PoolClock::system(), operation)
    }
    /// Reads every deadline from the execution's [`PoolClock`]; production passes `PoolClock::system()`.
    pub(crate) fn with_ledger_identity_with_clock<T>(
        &self,
        deadline: Instant,
        clock: &PoolClock<'_>,
        operation: impl FnOnce(&mut Option<LedgerIdentity>, &str) -> T,
    ) -> Result<T> {
        let _guard = self.custody_with_deadline_and_clock(Some(deadline), clock)?;
        let mut manifest = self.execution_manifest()?;
        if self.sync_fingerprints(&mut manifest, None)? {
            self.save(&manifest)?;
        }
        let salt_id = Self::salt_id(&manifest)?;
        self.prepare_ledger_identity(&mut manifest, &salt_id)?;
        let previous = manifest.ledger_identity.clone();
        if clock.now() >= deadline {
            return Err(PoolError::Busy);
        }
        let result = operation(&mut manifest.ledger_identity, &salt_id);
        // Accounting callbacks retain their nested ledger outcome. A failed
        // post-commit mirror/lag read or write must not discard a paid result;
        // admission still uses the strict finalization path below before send.
        match self.finish_identity(&manifest, previous, &salt_id, ()) {
            Ok(_) => Ok(result),
            Err(PoolError::LedgerMirrorUnavailable) => {
                tracing::warn!(error_kind = "pool_accounting_mirror_unavailable");
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(test)]
    pub(crate) fn with_execution_key_bound<T>(
        &self,
        candidate: &ExecutionCandidate,
        deadline: Instant,
        operation: impl FnOnce(SecretString, &mut Option<LedgerIdentity>, &str) -> T,
    ) -> Result<ExecutionAdmission<T>> {
        self.with_execution_key_bound_with_clock(
            candidate,
            deadline,
            &PoolClock::system(),
            operation,
        )
    }
    /// Reads every deadline from the execution's [`PoolClock`]; production passes `PoolClock::system()`.
    pub(crate) fn with_execution_key_bound_with_clock<T>(
        &self,
        candidate: &ExecutionCandidate,
        deadline: Instant,
        clock: &PoolClock<'_>,
        operation: impl FnOnce(SecretString, &mut Option<LedgerIdentity>, &str) -> T,
    ) -> Result<ExecutionAdmission<T>> {
        let _guard = self.custody_with_deadline_and_clock(Some(deadline), clock)?;
        let mut manifest = self.execution_manifest()?;
        let index = manifest
            .entries
            .iter()
            .position(|row| row.entry.name == candidate.entry.name)
            .ok_or(PoolError::KeyMissing)?;
        let row = &manifest.entries[index];
        if row.entry != candidate.entry
            || row.generation.as_deref() != Some(candidate.generation.as_str())
        {
            return Err(PoolError::MutationRefused);
        }
        let (secret, fingerprint) = self.fresh_execution_key(&mut manifest, index)?;
        if fingerprint != candidate.fingerprint
            || manifest.entries[index].generation.as_deref() != Some(candidate.generation.as_str())
        {
            return Err(PoolError::MutationRefused);
        }
        let salt_id = Self::salt_id(&manifest)?;
        self.prepare_ledger_identity(&mut manifest, &salt_id)?;
        let previous = manifest.ledger_identity.clone();
        if clock.now() >= deadline {
            return Err(PoolError::Busy);
        }
        let result = operation(secret, &mut manifest.ledger_identity, &salt_id);
        self.finish_identity(&manifest, previous, &salt_id, result)
    }
    fn fresh_execution_key(
        &self,
        manifest: &mut Manifest,
        index: usize,
    ) -> Result<(SecretString, String)> {
        let selected = manifest.entries[index].entry.name.clone();
        if self.sync_fingerprints(manifest, Some(&selected))? {
            self.save(manifest)?;
        }
        let secret = self.read_stored_key(manifest, &manifest.entries[index])?;
        let fingerprint = manifest
            .fingerprint_salt
            .as_ref()
            .ok_or(PoolError::ManifestInvalid)?
            .fingerprint(&secret)?;
        if manifest
            .entries
            .iter()
            .enumerate()
            .any(|(other, row)| other != index && row.fingerprint.as_ref() == Some(&fingerprint))
        {
            return Err(PoolError::MutationRefused);
        }
        if manifest.entries[index].fingerprint.as_ref() != Some(&fingerprint)
            || manifest.entries[index].generation.is_none()
        {
            manifest.entries[index].fingerprint = Some(fingerprint.clone());
            manifest.entries[index].generation = Some(fresh_id());
            self.save(manifest)?;
        }
        Ok((secret, fingerprint))
    }
    #[cfg(test)]
    pub(crate) fn with_resolution_identity<T>(
        &self,
        name: &PoolName,
        deadline: Instant,
        operation: impl FnOnce(&str, &str, &mut Option<LedgerIdentity>, &str) -> T,
    ) -> Result<T> {
        self.with_resolution_identity_with_clock(name, deadline, &PoolClock::system(), operation)
    }
    /// Reads every deadline from the execution's [`PoolClock`]; production passes `PoolClock::system()`.
    pub(crate) fn with_resolution_identity_with_clock<T>(
        &self,
        name: &PoolName,
        deadline: Instant,
        clock: &PoolClock<'_>,
        operation: impl FnOnce(&str, &str, &mut Option<LedgerIdentity>, &str) -> T,
    ) -> Result<T> {
        let _guard = self.custody_with_deadline_and_clock(Some(deadline), clock)?;
        let mut manifest = self.execution_manifest()?;
        let index = manifest
            .entries
            .iter()
            .position(|row| row.entry.name == *name)
            .ok_or(PoolError::KeyMissing)?;
        let (_, fingerprint) = self.fresh_execution_key(&mut manifest, index)?;
        let salt_id = Self::salt_id(&manifest)?;
        self.prepare_ledger_identity(&mut manifest, &salt_id)?;
        let previous = manifest.ledger_identity.clone();
        if clock.now() >= deadline {
            return Err(PoolError::Busy);
        }
        let generation = manifest.entries[index]
            .generation
            .as_deref()
            .ok_or(PoolError::ManifestInvalid)?;
        let result = operation(
            &fingerprint,
            generation,
            &mut manifest.ledger_identity,
            &salt_id,
        );
        // Resolution may have committed before mirror publication fails. Keep
        // its outcome while preserving identity and nested ledger errors.
        match self.finish_identity(&manifest, previous, &salt_id, ()) {
            Ok(_) => Ok(result),
            Err(PoolError::LedgerMirrorUnavailable) => {
                tracing::warn!(error_kind = "pool_accounting_mirror_unavailable");
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    /// Bind a fresh key read to the selected generation and public metadata.
    /// The closure performs only the local reservation step under custody;
    /// transport starts after this method returns and releases custody.
    #[cfg(test)]
    pub(crate) fn with_execution_key<T>(
        &self,
        candidate: &ExecutionCandidate,
        operation: impl FnOnce(SecretString) -> T,
    ) -> Result<T> {
        let guard = self.custody()?;
        let manifest = self.prepare()?;
        let row = manifest
            .entries
            .iter()
            .find(|row| row.entry.name == candidate.entry.name)
            .ok_or(PoolError::KeyMissing)?;
        if row.entry != candidate.entry
            || row.generation.as_deref() != Some(candidate.generation.as_str())
        {
            return Err(PoolError::MutationRefused);
        }
        let secret = self.read_stored_key(&manifest, row)?;
        let result = operation(secret);
        drop(guard);
        Ok(result)
    }

    pub fn list(&self) -> Result<Vec<PoolRow>> {
        let _guard = self.custody()?;
        let manifest = self.prepare()?;
        manifest
            .entries
            .iter()
            .map(|row| {
                let (present, vault_file_missing) = match &row.entry.source {
                    KeySource::EnvFile => (
                        env_file::contains(
                            manifest
                                .env_file
                                .as_deref()
                                .ok_or(PoolError::ManifestInvalid)?,
                            &row.entry.name,
                        )?,
                        false,
                    ),
                    KeySource::SecretStore => self.with_store(|v| {
                        if !v
                            .named_store_present()
                            .map_err(|_| PoolError::StoreUnavailable)?
                        {
                            return Ok((false, true));
                        }
                        let present = v
                            .contains_named(&key(row
                                .secret_id
                                .as_deref()
                                .ok_or(PoolError::ManifestInvalid)?)?)
                            .map_err(|_| PoolError::StoreUnavailable)?;
                        Ok((present, false))
                    })?,
                };
                Ok(PoolRow {
                    entry: row.entry.clone(),
                    present,
                    vault_file_missing,
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
        let mut row = StoredEntry {
            entry: row,
            secret_id: Some(fresh_id()),
            generation: Some(fresh_id()),
            fingerprint: None,
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
        if manifest
            .entries
            .iter()
            .any(|row| row.entry.source == KeySource::SecretStore)
        {
            self.with_store(|v| {
                if v.named_store_present()
                    .map_err(|_| PoolError::StoreUnavailable)?
                {
                    Ok(())
                } else {
                    Err(PoolError::StoreUnavailable)
                }
            })?;
        }
        if self.sync_fingerprints(&mut manifest, Some(&row.entry.name))? {
            self.save(&manifest)?;
        }
        let fingerprint = manifest
            .fingerprint_salt
            .as_ref()
            .ok_or(PoolError::ManifestInvalid)?
            .fingerprint(&secret)?;
        if manifest
            .entries
            .iter()
            .any(|row| row.fingerprint.as_ref() == Some(&fingerprint))
        {
            return Err(PoolError::MutationRefused);
        }
        row.fingerprint = Some(fingerprint);
        self.with_store(|v| {
            let journal = Journal::Add {
                row: row.clone(),
                recovery_safe: v.backend_id() == "linux-file-aes" || v.backend_id() == "in-memory",
                backend_id: v.backend_id().into(),
                writer: Writer::current(),
            };
            write_json(&self.root.join("transaction.json"), &journal)?;
            let original = key(row.secret_id.as_deref().ok_or(PoolError::ManifestInvalid)?)?;
            let create_allowed = !manifest
                .entries
                .iter()
                .any(|entry| entry.entry.source == KeySource::SecretStore);
            let written = if create_allowed {
                v.set_named(&original, &secret)
            } else {
                v.set_named_existing(&original, &secret)
            };
            if let Err(error) = written {
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
                let unavailable = matches!(
                    error,
                    secret::SecretError::BackendUnavailable { .. }
                        | secret::SecretError::Io { .. }
                        | secret::SecretError::DecryptionFailed
                );
                // A definite refusal cannot leave a worker behind. Clean any partial item.
                self.compensate(v, &manifest, journal, true)?;
                return Err(if unavailable {
                    PoolError::StoreUnavailable
                } else {
                    PoolError::MutationRefused
                });
            }
            manifest.entries.push(row);
            if let Err(error) = self.save(&manifest) {
                manifest.entries.pop();
                self.compensate(v, &manifest, journal, true)?;
                return Err(error);
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
                fingerprint: None,
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
        if self.sync_fingerprints(&mut manifest, Some(&additions[0].entry.name))? {
            self.save(&manifest)?;
        }
        let salt = manifest
            .fingerprint_salt
            .as_ref()
            .ok_or(PoolError::ManifestInvalid)?;
        let mut live: std::collections::HashSet<String> = manifest
            .entries
            .iter()
            .filter_map(|row| row.fingerprint.clone())
            .collect();
        for row in &mut additions {
            let value = salt.fingerprint(&env_file::get(path, &row.entry.name)?)?;
            if !live.insert(value.clone()) {
                return Err(PoolError::MutationRefused);
            }
            row.fingerprint = Some(value);
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
        self.read_stored_key(&manifest, row)
    }
    /// Shared source dispatch. Callers must retain the pool custody guard.
    fn read_stored_key(&self, manifest: &Manifest, row: &StoredEntry) -> Result<SecretString> {
        match row.entry.source {
            KeySource::EnvFile => env_file::get(
                manifest
                    .env_file
                    .as_deref()
                    .ok_or(PoolError::ManifestInvalid)?,
                &row.entry.name,
            ),
            KeySource::SecretStore => self.with_store(|v| {
                v.get_named(&key(row
                    .secret_id
                    .as_deref()
                    .ok_or(PoolError::ManifestInvalid)?)?)
                    .map_err(named_read_error)
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
        self.remove_if_unchanged_with_outcome(expected).map(|_| ())
    }
    /// Returns true only when removal dropped a row from a confirmed absent
    /// named vault. The outcome is measured under the same custody guard.
    pub fn remove_if_unchanged_with_outcome(&self, expected: &RemovalSnapshot) -> Result<bool> {
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
        self.remove_with_outcome(name).map(|_| ())
    }
    /// Returns true only when no named vault file remained to delete from.
    pub fn remove_with_outcome(&self, name: &str) -> Result<bool> {
        let name = PoolName::new(name)?;
        let _guard = self.custody()?;
        self.remove_locked(name, self.prepare()?)
    }
    fn remove_locked(&self, name: PoolName, mut manifest: Manifest) -> Result<bool> {
        let index = manifest
            .entries
            .iter()
            .position(|r| r.entry.name == name)
            .ok_or(PoolError::KeyMissing)?;
        let row = manifest.entries[index].clone();
        if row.entry.source == KeySource::EnvFile {
            manifest.entries.remove(index);
            return self.save(&manifest).map(|_| false);
        }
        self.with_store(|v| {
            if !v
                .named_store_present()
                .map_err(|_| PoolError::StoreUnavailable)?
            {
                manifest.entries.remove(index);
                return self.save(&manifest).map(|_| true);
            }
            let original = key(row.secret_id.as_deref().ok_or(PoolError::ManifestInvalid)?)?;
            let saved = match v.get_named(&original) {
                Ok(saved) => saved,
                Err(secret::SecretError::NamedNotFound) => {
                    manifest.entries.remove(index);
                    return self.save(&manifest).map(|_| false);
                }
                Err(_) => return Err(PoolError::StoreUnavailable),
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
                if let Err(error) = v.set_named_existing(&backup, &saved) {
                    if uncertain(&error) {
                        return self.mark_unknown(journal).map(|_| false);
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
                    return Err(
                        if matches!(
                            error,
                            secret::SecretError::BackendUnavailable { .. }
                                | secret::SecretError::Io { .. }
                                | secret::SecretError::DecryptionFailed
                        ) {
                            PoolError::StoreUnavailable
                        } else {
                            PoolError::MutationRefused
                        },
                    );
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
                    return self.mark_unknown(journal).map(|_| false);
                }
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            manifest.entries.remove(index);
            if let Err(error) = self.save(&manifest) {
                let mut admitted = row;
                admitted.remove_backup_id = Some(backup_id.clone());
                manifest.entries.insert(index, admitted);
                self.compensate(v, &manifest, journal, true)?;
                return Err(error);
            }
            if let Err(error) = v.delete_named(&backup) {
                if uncertain(&error) {
                    return self.mark_unknown(journal).map(|_| false);
                }
                self.compensate(v, &manifest, journal, true)?;
                return Err(PoolError::MutationRefused);
            }
            self.clear_journal().map(|_| false)
        })
    }
}
