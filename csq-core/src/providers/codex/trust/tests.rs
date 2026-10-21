use super::super::surface;
use super::*;
use tempfile::TempDir;

struct Fixture {
    _lock: crate::platform::test_env::EnvTestGuard,
    root: TempDir,
    prior: [Option<std::ffi::OsString>; 2],
}
impl Fixture {
    fn new(source: &str) -> Self {
        let lock = crate::platform::test_env::lock();
        let root = TempDir::new().unwrap();
        let prior = [
            std::env::var_os("CSQ_TEST_CODEX_TRUST_CONFIG"),
            std::env::var_os(surface::USER_CONFIG_ENV_OVERRIDE),
        ];
        let path = root.path().join("owner.toml");
        std::fs::write(&path, source).unwrap();
        // SAFETY: the workspace environment mutex remains held until Drop.
        unsafe {
            std::env::set_var("CSQ_TEST_CODEX_TRUST_CONFIG", &path);
            std::env::set_var(surface::USER_CONFIG_ENV_OVERRIDE, &path);
        }
        Self {
            _lock: lock,
            root,
            prior,
        }
    }
    fn base(&self) -> &Path {
        self.root.path()
    }
    fn owner(&self, text: &str) {
        std::fs::write(self.base().join("owner.toml"), text).unwrap();
    }
    fn slot(&self, n: u16, text: &str) -> AccountNum {
        let slot = AccountNum::try_from(n).unwrap();
        let path = surface::config_toml_path(self.base(), slot);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        std::fs::write(path.parent().unwrap().join(".csq-account"), n.to_string()).unwrap();
        std::fs::create_dir_all(self.base().join("credentials")).unwrap();
        std::fs::write(
            self.base().join(format!("credentials/codex-{n}.json")),
            "{}",
        )
        .unwrap();
        slot
    }
    fn read(&self, slot: AccountNum) -> toml::value::Table {
        toml::from_str(
            &std::fs::read_to_string(surface::config_toml_path(self.base(), slot)).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: the workspace environment mutex remains held throughout Drop.
        unsafe {
            for (name, prior) in [
                "CSQ_TEST_CODEX_TRUST_CONFIG",
                surface::USER_CONFIG_ENV_OVERRIDE,
            ]
            .into_iter()
            .zip(self.prior.iter_mut())
            {
                match prior.take() {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}
const OWNER: &str = "[projects.\"/owner/work\"]\ntrust_level = \"trusted\"\n";
const STALE: &str = "model = \"owner-model\"\ncli_auth_credentials_store = \"file\"\n[projects.\"/deleted/work\"]\ntrust_level = \"trusted\"\n[agents]\nmax_threads = 12\n[features.multi_agent_v2]\nenabled = true\n[extension]\nowner = \"keep\"\n";

#[test]
fn projects_only_sync_converges_and_preserves_nonprojects() {
    let f = Fixture::new(OWNER);
    let slot = f.slot(12, STALE);
    let mut before = f.read(slot);
    before.remove("projects");
    assert_eq!(sync_slot_project_trust(f.base(), slot).unwrap(), None);
    let mut after = f.read(slot);
    assert_eq!(
        after.remove("projects"),
        toml::from_str::<toml::Value>(OWNER)
            .unwrap()
            .get("projects")
            .cloned(),
        "owner projects must be the exact set"
    );
    assert_eq!(
        before, after,
        "projects-only launch sync must preserve every nonproject value"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(surface::config_toml_path(f.base(), slot))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn owner_removal_and_valid_absent_table_clear_old_grants() {
    let f = Fixture::new(OWNER);
    let slot = f.slot(12, STALE);
    sync_slot_project_trust(f.base(), slot).unwrap();
    assert!(
        !f.read(slot)["projects"]
            .as_table()
            .unwrap()
            .contains_key("/deleted/work"),
        "deleted owner project must be removed"
    );
    f.owner("model = \"global\"\n");
    sync_slot_project_trust(f.base(), slot).unwrap();
    assert!(
        !f.read(slot).contains_key("projects"),
        "valid source without projects must clear grants"
    );
}

#[test]
fn unknown_source_keeps_slot_bytes_and_typed_warning() {
    let f = Fixture::new("invalid=[");
    let slot = f.slot(12, STALE);
    let path = surface::config_toml_path(f.base(), slot);
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        sync_slot_project_trust(f.base(), slot).unwrap(),
        Some(TrustWarning::UnparseableSource)
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "unparseable owner source must leave slot untouched"
    );
    std::fs::remove_file(f.base().join("owner.toml")).unwrap();
    assert_eq!(
        sync_slot_project_trust(f.base(), slot).unwrap(),
        Some(TrustWarning::MissingSource)
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "missing owner source must leave slot untouched"
    );
    std::fs::create_dir(f.base().join("owner.toml")).unwrap();
    assert_eq!(
        sync_slot_project_trust(f.base(), slot).unwrap(),
        Some(TrustWarning::UnreadableSource)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn malformed_global_still_repairs_auth_without_losing_projects() {
    let f = Fixture::new("invalid=[");
    let slot = f.slot(12, &STALE.replace("\"file\"", "\"keychain\""));
    let before = f.read(slot)["projects"].clone();
    surface::regenerate_slot_config(f.base(), slot).unwrap();
    let after = f.read(slot);
    assert_eq!(
        after["cli_auth_credentials_store"].as_str(),
        Some("file"),
        "legacy malformed-global auth repair must remain"
    );
    assert_eq!(
        after.get("projects"),
        Some(&before),
        "unknown canonical trust source must preserve slot projects during auth repair"
    );
    assert_eq!(after["agents"]["max_threads"].as_integer(), Some(12));
}

#[test]
fn canonical_trust_is_distinct_from_legacy_nonproject_selector() {
    let f = Fixture::new(OWNER);
    let slot = f.slot(12, STALE);
    let legacy = f.base().join("legacy.toml");
    std::fs::write(
        &legacy,
        "sandbox_mode=\"workspace-write\"\n[projects.\"/arbitrary\"]\ntrust_level=\"trusted\"\n",
    )
    .unwrap();
    // SAFETY: Fixture holds the workspace environment mutex.
    unsafe {
        std::env::set_var(surface::USER_CONFIG_ENV_OVERRIDE, legacy);
    }
    surface::regenerate_slot_config(f.base(), slot).unwrap();
    let after = f.read(slot);
    assert_eq!(after["sandbox_mode"].as_str(), Some("workspace-write"));
    assert_eq!(
        after.get("projects"),
        toml::from_str::<toml::Value>(OWNER)
            .unwrap()
            .get("projects"),
        "TRUST must use canonical authority independently of legacy settings selector"
    );
    assert!(
        !after.contains_key("extension"),
        "ordinary regeneration retains legacy refresh/deletion behavior"
    );
}

#[test]
fn doctor_comparison_reports_drift_unknown_and_never_writes() {
    let f = Fixture::new(OWNER);
    let slot = f.slot(12, STALE);
    let before = std::fs::read(surface::config_toml_path(f.base(), slot)).unwrap();
    let rows = diagnose_project_trust(f.base(), &[slot]);
    assert_eq!(
        rows,
        vec![ProjectTrustDiagnostic {
            slot: 12,
            drift: true,
            warning: None
        }],
        "doctor must report actual owner project drift"
    );
    assert_eq!(
        std::fs::read(surface::config_toml_path(f.base(), slot)).unwrap(),
        before
    );
    f.owner("invalid=[");
    let rows = diagnose_project_trust(f.base(), &[slot]);
    assert_eq!(rows[0].warning, Some(TrustWarning::UnparseableSource));
    let serialized = serde_json::to_value(&rows[0]).unwrap();
    assert_eq!(serialized["warning"], "unparseable_source");
    assert_eq!(serialized["slot"], 12);
    assert_eq!(serialized["drift"], false);
    assert_eq!(
        serialized.as_object().unwrap().len(),
        3,
        "doctor must not disclose source or project paths"
    );
    assert!(
        !rows[0].drift,
        "unknown source must not be reported as measured drift"
    );
    assert_eq!(
        std::fs::read(surface::config_toml_path(f.base(), slot)).unwrap(),
        before
    );
}

#[cfg(unix)]
#[test]
fn actual_handle_creation_synchronizes_config12_drift() {
    let f = Fixture::new(OWNER);
    let slot = f.slot(12, STALE);
    let source_before = std::fs::read(f.base().join("owner.toml")).unwrap();
    let mut values_before = f.read(slot);
    values_before.remove("projects");
    let handle = crate::session::handle_dir::create_handle_dir_codex_named(
        f.base(),
        slot,
        91234,
        "codex-exec-91234",
    )
    .unwrap();
    let linked: toml::Value =
        toml::from_str(&std::fs::read_to_string(handle.join("config.toml")).unwrap()).unwrap();
    assert_eq!(
        linked["projects"],
        toml::from_str::<toml::Value>(OWNER).unwrap()["projects"],
        "handle creation must synchronize owner trust before linking config"
    );
    let mut values_after = f.read(slot);
    values_after.remove("projects");
    assert_eq!(values_before, values_after);
    assert_eq!(
        std::fs::read(f.base().join("owner.toml")).unwrap(),
        source_before
    );
}

#[cfg(unix)]
#[test]
fn actual_handle_repoint_synchronizes_target_slot_drift() {
    let f = Fixture::new(OWNER);
    let from = f.slot(11, STALE);
    let to = f.slot(12, STALE);
    let handle =
        crate::session::handle_dir::create_handle_dir_codex(f.base(), from, 91235).unwrap();
    let next = "[projects.\"/owner/next\"]\ntrust_level=\"trusted\"\n";
    f.owner(next);
    crate::session::handle_dir::repoint_handle_dir_codex(f.base(), &handle, to).unwrap();
    let linked: toml::Value =
        toml::from_str(&std::fs::read_to_string(handle.join("config.toml")).unwrap()).unwrap();
    assert_eq!(
        linked["projects"],
        toml::from_str::<toml::Value>(next).unwrap()["projects"],
        "handle repoint must synchronize target owner trust before linking config"
    );
}

#[test]
fn bad_canonical_preserves_projects_while_legacy_settings_refresh() {
    let f = Fixture::new("broken=[");
    let slot = f.slot(12, STALE);
    let expected = f.read(slot).get("projects").cloned();
    let legacy = f.base().join("legacy.toml");
    std::fs::write(
        &legacy,
        "sandbox_mode=\"workspace-write\"\n[projects.\"/fake/legacy\"]\ntrust_level=\"trusted\"\n",
    )
    .unwrap();
    // SAFETY: Fixture holds the workspace environment mutex.
    unsafe {
        std::env::set_var(surface::USER_CONFIG_ENV_OVERRIDE, legacy);
    }
    for source in [Some("broken=["), Some("projects=1"), None] {
        match source {
            Some(text) => f.owner(text),
            None => std::fs::remove_file(f.base().join("owner.toml")).unwrap(),
        }
        surface::regenerate_slot_config(f.base(), slot).unwrap();
        let current = f.read(slot);
        assert_eq!(
            current.get("projects"),
            expected.as_ref(),
            "unknown canonical source must not import legacy-selected project grants"
        );
        assert_eq!(current["sandbox_mode"].as_str(), Some("workspace-write"));
        assert!(!current.contains_key("extension"));
    }
}

#[test]
fn project_trust_sync_preserves_codex_hook_trust_state() {
    let f = Fixture::new(OWNER);
    let key = "/h/hooks.json:stop:0:0";
    let slot = f.slot(
        12,
        &format!("{STALE}[hooks.state.\"{key}\"]\ntrusted_hash = \"abc\"\nenabled = true\n"),
    );
    assert_eq!(sync_slot_project_trust(f.base(), slot).unwrap(), None);
    let after = f.read(slot);
    let entry = &after["hooks"]["state"][key];
    assert_eq!(entry["trusted_hash"].as_str(), Some("abc"));
    assert_eq!(entry["enabled"].as_bool(), Some(true));
    assert!(
        after["projects"]
            .as_table()
            .unwrap()
            .contains_key("/owner/work"),
        "the sync itself must still have run"
    );
}

/// Item 1: with project-trust drift pending, `sync_slot_project_trust` holds the per-slot lock
/// across its publish, so a concurrent csq carry (here a second thread) cannot interleave and
/// have its dropped or carried state overwritten.
#[cfg(unix)]
#[test]
fn sync_holds_the_slot_lock_so_a_concurrent_carry_cannot_interleave() {
    use crate::providers::codex::surface::test_seam::BEFORE_RENAME;
    use crate::session::codex_hook_trust::{carry_hook_trust, CarryMode};
    let f = Fixture::new(OWNER);
    let slot = f.slot(4, "cli_auth_credentials_store = \"file\"\n");
    let base = f.base().canonicalize().unwrap();
    let key = |h: &str| format!("{}/{h}/hooks.json:stop:0:0", base.display());
    // a stale own key of reused PID 4242 (disabled), plus drift to sync
    let stale = format!(
        "cli_auth_credentials_store = \"file\"\n[hooks.state.\"{}\"]\ntrusted_hash = \"sha256:stale\"\nenabled = false\n",
        key("term-4242")
    );
    std::fs::write(surface::config_toml_path(&base, slot), stale).unwrap();
    let new = base.join("term-4242");
    std::fs::create_dir_all(&new).unwrap();
    let finished = std::rc::Rc::new(std::cell::Cell::new(None));
    let jh: std::rc::Rc<std::cell::RefCell<Option<std::thread::JoinHandle<()>>>> =
        Default::default();
    let (fin, jh2, b2, n2) = (finished.clone(), jh.clone(), base.clone(), new.clone());
    BEFORE_RENAME.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |_| {
            if jh2.borrow().is_some() {
                return;
            }
            let (b3, n3) = (b2.clone(), n2.clone());
            let t = std::thread::spawn(move || {
                carry_hook_trust(&b3, &n3, slot, None, CarryMode::Create).unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(400));
            fin.set(Some(t.is_finished()));
            *jh2.borrow_mut() = Some(t);
        }));
    });
    let r = sync_slot_project_trust(&base, slot);
    BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
    assert_eq!(r.unwrap(), None);
    assert_eq!(
        finished.get(),
        Some(false),
        "the carry ran while the sync held the slot lock"
    );
    jh.borrow_mut().take().unwrap().join().unwrap();
    let after = f.read(slot);
    assert!(
        after.contains_key("projects"),
        "the sync itself must have run"
    );
    let state = after
        .get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(|s| s.as_table());
    assert!(
        state.is_none_or(|s| !s.contains_key(&key("term-4242"))),
        "the stale own key came back: the sync overwrote the carry's drop"
    );
}

/// Item 1: a write that lands between the sync's read and its publish is kept (the sync
/// re-reads and publishes again) instead of being overwritten.
#[cfg(unix)]
#[test]
fn sync_keeps_a_write_landing_mid_publish_and_still_syncs_projects() {
    use crate::providers::codex::surface::test_seam::BEFORE_RENAME;
    let f = Fixture::new(OWNER);
    let slot = f.slot(4, "cli_auth_credentials_store = \"file\"\n");
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let f2 = fired.clone();
    BEFORE_RENAME.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |t: &Path| {
            if !f2.replace(true) {
                let mut cur = std::fs::read_to_string(t).unwrap();
                cur.push_str("\n[codex_user]\nkeep = 1\n");
                std::fs::write(t, cur).unwrap();
            }
        }));
    });
    let r = sync_slot_project_trust(f.base(), slot);
    BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
    assert_eq!(r.unwrap(), None);
    let after = f.read(slot);
    assert_eq!(
        after["codex_user"]["keep"].as_integer(),
        Some(1),
        "a mid-publish write was lost"
    );
    assert!(after["projects"]
        .as_table()
        .unwrap()
        .contains_key("/owner/work"));
}
