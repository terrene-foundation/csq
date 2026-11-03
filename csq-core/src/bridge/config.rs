//! `<base_dir>/telegram-bridge.json` — owner pinning and enablement;
//! `<base_dir>/telegram-bridge-state.json` — the poll cursor;
//! `<base_dir>/telegram-bridge-killed` — the kill-switch marker.
//!
//! # Threat model
//!
//! These are owner-local files guarded by 0600 permissions and atomic replace.
//! The bot token and the attestation origin key live in the platform vault
//! ([`secrets`](crate::bridge::secrets)). No pairing code or challenge is
//! persisted: the config this build writes carries no pairing artifact at all,
//! and the challenge fields an older build stored are parsed and then ignored,
//! so a copied state directory has nothing to brute-force.
//!
//! # Writers
//!
//! `telegram-bridge.json` is written ONLY by a local, on-machine action; the
//! daemon never writes it. The daemon writes `telegram-bridge-state.json` (the poll
//! cursor) and the kill marker [`KILLED_FILE`], and nothing else. Because the
//! daemon never read-modify-writes the config, an in-flight poll cannot
//! resurrect a `csq telegram off` — the guarantee is structural, not a timing
//! window.
//!
//! # Failure posture
//!
//! A corrupt or unreadable config is an `Err`, never `Ok(None)`: treating
//! "cannot read" as "not configured" would silently fail open on a path that
//! gates who may command the owner's machine (`guard-reader-writer-parity.md`
//! MUST-2). Only genuine absence (`NotFound`) yields `Ok(None)`.

use crate::platform::fs;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Config file name inside `<base_dir>` (`~/.claude/accounts`).
pub const CONFIG_FILE: &str = "telegram-bridge.json";

/// Poll-cursor file name inside `<base_dir>`.
///
/// Separate from [`CONFIG_FILE`] so the BRIDGE never writes the owner config:
/// the local CLI is the config's only writer, which removes the
/// read-modify-write race that could resurrect a phone `csq telegram off`
/// (fail-open).
pub const STATE_FILE: &str = "telegram-bridge-state.json";

/// Kill-switch marker written by the DAEMON when the owner sends `/csq off`
/// from the phone.
///
/// While the marker exists the daemon refuses to poll, so a phone message can
/// stop the bridge but never restart it: ONLY the local `csq telegram on`
/// removes the marker ([`clear_kill_switch`]). The daemon writes it atomically
/// at 0600.
pub const KILLED_FILE: &str = "telegram-bridge-killed";

/// Upper bound on the config file we are willing to parse.
const CONFIG_MAX_BYTES: u64 = 64 * 1024;

/// Upper bound on the poll-cursor file we are willing to parse.
const STATE_MAX_BYTES: u64 = 4 * 1024;

/// Owner-pinned bridge configuration.
///
/// `owner_user_id` / `owner_chat_id` are Telegram's numeric ids; they are
/// pinned the first time the owner completes the pairing handshake and are the
/// only identity the bridge will ever accept (`from_id` AND `chat_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Whether the daemon should poll the bot at all. `false` is the safe
    /// direction: `csq telegram off` must work with no credential present.
    pub enabled: bool,
    /// Telegram user id of the owner. `0` means "not pinned yet".
    pub owner_user_id: i64,
    /// Telegram private-chat id of the owner. `0` means "not pinned yet".
    pub owner_chat_id: i64,
    /// Action classes the owner may trigger from Telegram, e.g. `swap`.
    ///
    /// Empty by default, and empty means "no action may run from Telegram":
    /// absence in the JSON must never be read as permission. Only the LOCAL
    /// `csq telegram on --allow <class>` setter writes this list; nothing an
    /// inbound Telegram message contains can add to it.
    #[serde(default)]
    pub allow_classes: Vec<String>,
}

/// The only action class the bridge can allow today: a swap.
pub const SWAP_CLASS: &str = "swap";

impl BridgeConfig {
    /// Whether both owner ids have been pinned. The bridge MUST NOT accept an
    /// update, and `csq telegram on` MUST refuse, until this is true.
    pub fn is_pinned(&self) -> bool {
        self.owner_user_id > 0 && self.owner_chat_id > 0
    }

    /// Whether a Telegram message may trigger a credential-class swap.
    ///
    /// Unknown strings in the list are inert: only [`SWAP_CLASS`] matches.
    pub fn allows_swap(&self) -> bool {
        self.allow_classes.iter().any(|c| c == SWAP_CLASS)
    }
}

/// Errors from reading or writing bridge state.
///
/// Every variant carries a fixed message: no path, no upstream `io::Error`
/// text and no secret material, so the value is safe to log verbatim
/// (`security.md` MUST-2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeConfigError {
    /// `<base_dir>` could not be created.
    #[error("bridge state directory is unusable")]
    DirectoryUnusable,
    /// The config file exists but could not be read.
    #[error("bridge config file could not be read")]
    ConfigUnreadable,
    /// The config file parsed as neither absent nor valid JSON.
    #[error("bridge config file is not valid JSON")]
    ConfigCorrupt,
    /// The config file could not be published atomically.
    #[error("bridge config file could not be written")]
    ConfigUnwritable,
}

impl BridgeConfigError {
    /// Fixed-vocabulary tag for structured logging (`security.md` MUST-2).
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            BridgeConfigError::DirectoryUnusable => "bridge_state_directory_unusable",
            BridgeConfigError::ConfigUnreadable => "bridge_config_unreadable",
            BridgeConfigError::ConfigCorrupt => "bridge_config_corrupt",
            BridgeConfigError::ConfigUnwritable => "bridge_config_unwritable",
        }
    }
}

/// Reads `<base_dir>/telegram-bridge.json`.
///
/// Returns `Ok(None)` only when the file is absent. An unreadable, oversized,
/// non-regular or corrupt file is an error — a guard that silently treats
/// those as "not configured" would fail open.
pub fn load(base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError> {
    let path = base_dir.join(CONFIG_FILE);
    let bytes = fs::read_private_regular_nofollow_bounded(&path, CONFIG_MAX_BYTES)
        .map_err(|_| BridgeConfigError::ConfigUnreadable)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Err(BridgeConfigError::ConfigCorrupt);
    }
    let config: BridgeConfig =
        serde_json::from_slice(&bytes).map_err(|_| BridgeConfigError::ConfigCorrupt)?;
    Ok(Some(config))
}

/// Writes `<base_dir>/telegram-bridge.json` atomically at 0600.
///
/// Uses the target-taking private-temp factory so the temporary file is born
/// owner-only and the created-inode identity is retained through publication
/// (`security.md` MUST-4/5, §5a).
pub fn save(config: &BridgeConfig, base_dir: &Path) -> Result<(), BridgeConfigError> {
    std::fs::create_dir_all(base_dir).map_err(|_| BridgeConfigError::DirectoryUnusable)?;
    let bytes =
        serde_json::to_vec_pretty(config).map_err(|_| BridgeConfigError::ConfigUnwritable)?;
    let path = base_dir.join(CONFIG_FILE);
    let writer = fs::write_private_tmp_synced_retained(&path, &bytes)
        .map_err(|_| BridgeConfigError::ConfigUnwritable)?;
    writer
        .replace(&path)
        .map_err(|_| BridgeConfigError::ConfigUnwritable)
}

/// The bridge's poll cursor, persisted in its own file.
///
/// The bridge writes only this file and the [`KILLED_FILE`] marker — never the
/// owner config. Keeping the cursor out of [`BridgeConfig`] means the bridge
/// performs no read-modify-write of the config at all, so it cannot resurrect a
/// `csq telegram off` that lands while an update is in flight — the guarantee
/// is structural, not a timing window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeCursor {
    /// Highest `update_id` already consumed. The poll offset is this + 1.
    pub high_water_update_id: u64,
}

/// Reads the poll cursor, seeding it from a pre-move config on first use.
///
/// A config written before the cursor moved may still carry
/// `high_water_update_id`. Ignoring it would restart the poll at 0 and replay
/// up to 24 hours of Telegram backlog into live sessions, so a present legacy
/// value is written to [`STATE_FILE`] once, before the first poll.
///
/// Returns `Ok(default)` only when neither file exists.
pub fn load_cursor(base_dir: &Path) -> Result<BridgeCursor, BridgeConfigError> {
    let path = base_dir.join(STATE_FILE);
    let bytes = fs::read_private_regular_nofollow_bounded(&path, STATE_MAX_BYTES)
        .map_err(|_| BridgeConfigError::ConfigUnreadable)?;
    if let Some(bytes) = bytes {
        if bytes.is_empty() {
            return Err(BridgeConfigError::ConfigCorrupt);
        }
        return serde_json::from_slice(&bytes).map_err(|_| BridgeConfigError::ConfigCorrupt);
    }
    let Some(legacy) = legacy_config_cursor(base_dir)? else {
        return Ok(BridgeCursor::default());
    };
    let cursor = BridgeCursor {
        high_water_update_id: legacy,
    };
    save_cursor(cursor, base_dir)?;
    Ok(cursor)
}

/// Writes the poll cursor atomically at 0600.
///
/// Same target-taking private-temp factory as [`save`] (`security.md`
/// MUST-4/5, §5a).
pub fn save_cursor(cursor: BridgeCursor, base_dir: &Path) -> Result<(), BridgeConfigError> {
    std::fs::create_dir_all(base_dir).map_err(|_| BridgeConfigError::DirectoryUnusable)?;
    let bytes =
        serde_json::to_vec_pretty(&cursor).map_err(|_| BridgeConfigError::ConfigUnwritable)?;
    let path = base_dir.join(STATE_FILE);
    let writer = fs::write_private_tmp_synced_retained(&path, &bytes)
        .map_err(|_| BridgeConfigError::ConfigUnwritable)?;
    writer
        .replace(&path)
        .map_err(|_| BridgeConfigError::ConfigUnwritable)
}

/// Reads a pre-move `high_water_update_id` out of the config, if present.
///
/// The field is no longer part of [`BridgeConfig`]; the raw JSON is inspected
/// so an old file can seed the new state file without the struct knowing the
/// field.
fn legacy_config_cursor(base_dir: &Path) -> Result<Option<u64>, BridgeConfigError> {
    let path = base_dir.join(CONFIG_FILE);
    let bytes = fs::read_private_regular_nofollow_bounded(&path, CONFIG_MAX_BYTES)
        .map_err(|_| BridgeConfigError::ConfigUnreadable)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Err(BridgeConfigError::ConfigCorrupt);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| BridgeConfigError::ConfigCorrupt)?;
    Ok(value
        .get("high_water_update_id")
        .and_then(serde_json::Value::as_u64))
}

/// Whether the daemon's kill-switch marker exists.
///
/// Presence is the whole protocol: the daemon writes the marker on a phone
/// `/csq off` and refuses to poll while it exists. A metadata error is `Err`
/// (fail closed), never "not engaged".
pub fn kill_switch_engaged(base_dir: &Path) -> Result<bool, BridgeConfigError> {
    let marker = base_dir.join(KILLED_FILE);
    match std::fs::symlink_metadata(&marker) {
        Ok(_) => Ok(true),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && crate::platform::fs::confirm_absent(&marker).is_ok() =>
        {
            Ok(false)
        }
        Err(_) => Err(BridgeConfigError::ConfigUnreadable),
    }
}

/// Removes the kill-switch marker. Idempotent; called ONLY by the local
/// `csq telegram on`.
pub fn clear_kill_switch(base_dir: &Path) -> Result<(), BridgeConfigError> {
    match std::fs::remove_file(base_dir.join(KILLED_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BridgeConfigError::ConfigUnwritable),
    }
}

/// The two durable steps of `csq telegram on`, in order.
///
/// Split into a trait so the interleaving with a phone `/csq off` is tested
/// deterministically, not by timing a real race.
pub trait EnableSteps {
    /// Removes the kill-switch marker (the step that must run FIRST).
    fn clear_kill_switch(&self, base_dir: &Path) -> Result<(), BridgeConfigError>;
    /// Publishes a config whose `enabled` is already `true`.
    fn save_enabled(&self, config: &BridgeConfig, base_dir: &Path)
        -> Result<(), BridgeConfigError>;
}

/// The production steps: the same atomic/0600 writers as [`save`] and
/// [`clear_kill_switch`].
pub struct FsEnable;

impl EnableSteps for FsEnable {
    fn clear_kill_switch(&self, base_dir: &Path) -> Result<(), BridgeConfigError> {
        clear_kill_switch(base_dir)
    }

    fn save_enabled(
        &self,
        config: &BridgeConfig,
        base_dir: &Path,
    ) -> Result<(), BridgeConfigError> {
        save(config, base_dir)
    }
}

/// Enables the bridge: the kill marker is removed FIRST, then `enabled = true`
/// is published.
///
/// The order is what keeps a concurrent phone `csq telegram off` from being
/// lost. A phone off writes the marker and never touches the config. If it
/// lands between the two steps, the marker is re-created AFTER this command's
/// clear, so it survives — and the marker outranks `enabled`, so the bridge
/// still does not poll. Clearing AFTER the write would remove a marker the
/// phone had just written, turning the owner's stop into an enablement.
///
/// Returns whether the kill switch is engaged after the write, so the caller
/// can report the real state rather than claiming the bridge is on.
pub fn enable_bridge(
    config: &BridgeConfig,
    base_dir: &Path,
    steps: &dyn EnableSteps,
) -> Result<bool, BridgeConfigError> {
    let mut enabled = config.clone();
    enabled.enabled = true;
    steps.clear_kill_switch(base_dir)?;
    steps.save_enabled(&enabled, base_dir)?;
    kill_switch_engaged(base_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BridgeConfig {
        BridgeConfig {
            enabled: true,
            owner_user_id: 42,
            owner_chat_id: 42,
            allow_classes: vec![SWAP_CLASS.to_owned()],
        }
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = sample();
        save(&config, dir.path()).expect("save");
        let loaded = load(dir.path()).expect("load").expect("present");
        assert_eq!(loaded, config);
        assert!(loaded.allows_swap());
    }

    /// A config written before `allow_classes` existed (or by a build that
    /// never allowed anything) MUST load with an EMPTY list: absence is not
    /// permission, so Telegram-initiated swaps stay off.
    #[test]
    fn absent_allow_classes_defaults_to_empty_and_denies_swap() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            br#"{"enabled":true,"owner_user_id":42,"owner_chat_id":42,"high_water_update_id":9,"default_target":null}"#,
        )
        .expect("write");
        let loaded = load(dir.path()).expect("load").expect("present");
        assert!(loaded.allow_classes.is_empty());
        assert!(!loaded.allows_swap());
        assert!(loaded.enabled, "the field default must not flip the bridge");
    }

    /// A config written before the cursor moved to its own file still carries
    /// `high_water_update_id`. It MUST seed the state file on first use:
    /// ignoring it would restart the poll at 0 and replay up to 24 hours of
    /// Telegram backlog into live sessions.
    #[test]
    fn a_legacy_cursor_seeds_the_state_file_and_the_offset_does_not_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            br#"{"enabled":true,"owner_user_id":42,"owner_chat_id":42,"high_water_update_id":77}"#,
        )
        .expect("write");
        let cursor = load_cursor(dir.path()).expect("load cursor");
        assert_eq!(
            cursor.high_water_update_id, 77,
            "the legacy cursor must NOT be ignored"
        );
        // The seed is durable: the state file now holds exactly the legacy
        // value, so the first poll offset is 78, not 1.
        let persisted =
            std::fs::read_to_string(dir.path().join(STATE_FILE)).expect("state file written");
        let parsed: BridgeCursor = serde_json::from_str(&persisted).expect("parse state");
        assert_eq!(parsed.high_water_update_id, 77);
        // And the state file wins once it exists.
        std::fs::remove_file(dir.path().join(CONFIG_FILE)).expect("remove config");
        assert_eq!(
            load_cursor(dir.path())
                .expect("reload")
                .high_water_update_id,
            77
        );
    }

    #[test]
    fn cursor_round_trips_and_an_absent_state_defaults_to_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            load_cursor(dir.path())
                .expect("absent")
                .high_water_update_id,
            0
        );
        save_cursor(
            BridgeCursor {
                high_water_update_id: 12,
            },
            dir.path(),
        )
        .expect("save");
        assert_eq!(
            load_cursor(dir.path()).expect("load").high_water_update_id,
            12
        );
    }

    /// The bridge's cursor write must NEVER touch the config file: that is the
    /// structural guarantee that a concurrent `csq telegram off` cannot be
    /// resurrected. Asserted on the FILE BYTES, not on a timing window.
    #[test]
    fn saving_the_cursor_never_rewrites_the_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = sample();
        save(&config, dir.path()).expect("save config");
        let before = std::fs::read(dir.path().join(CONFIG_FILE)).expect("read before");
        let mut off = config.clone();
        off.enabled = false;
        save(&off, dir.path()).expect("save off");
        let off_bytes = std::fs::read(dir.path().join(CONFIG_FILE)).expect("read off");
        save_cursor(
            BridgeCursor {
                high_water_update_id: 77,
            },
            dir.path(),
        )
        .expect("save cursor");
        let after = std::fs::read(dir.path().join(CONFIG_FILE)).expect("read after");
        assert_ne!(before, off_bytes, "the kill switch really changed the file");
        assert_eq!(
            after, off_bytes,
            "the cursor write must not rewrite the config file"
        );
        let loaded = load(dir.path()).expect("load").expect("present");
        assert!(!loaded.enabled, "the kill switch survives the cursor write");
    }

    /// A config written by a build that still carried on-disk challenge fields
    /// MUST parse (serde ignores unknown fields) and the fields MUST be
    /// ignored: there is no code to honour and no migration to run.
    #[test]
    fn a_legacy_challenge_in_the_config_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            br#"{"enabled":false,"owner_user_id":0,"owner_chat_id":0,"allow_classes":[],"pairing_code_sha256":"deadbeef","pairing_expires_at":123,"pairing_code":"ABCDEFGH"}"#,
        )
        .expect("write");
        let loaded = load(dir.path()).expect("must parse").expect("present");
        assert!(!loaded.enabled);
        assert!(!loaded.is_pinned());
        assert!(loaded.allow_classes.is_empty());
    }

    #[test]
    fn unknown_allow_class_is_inert() {
        let config = BridgeConfig {
            allow_classes: vec!["run".into(), "shell".into()],
            ..sample()
        };
        assert!(!config.allows_swap());
    }

    #[test]
    fn load_absent_is_none_not_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(load(dir.path()).expect("absent is not an error"), None);
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        save(&sample(), dir.path()).expect("save");
        let meta = std::fs::metadata(dir.path().join(CONFIG_FILE)).expect("metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "bridge config must be owner-only"
        );
    }

    #[test]
    fn corrupt_config_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONFIG_FILE), b"{not json").expect("write");
        assert_eq!(
            load(dir.path()).expect_err("corrupt must not be read as absent"),
            BridgeConfigError::ConfigCorrupt
        );
    }

    #[test]
    fn empty_config_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONFIG_FILE), b"").expect("write");
        assert_eq!(
            load(dir.path()).expect_err("empty is corrupt"),
            BridgeConfigError::ConfigCorrupt
        );
    }

    #[test]
    fn kill_switch_is_presence_only_and_the_local_cli_clears_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!kill_switch_engaged(dir.path()).expect("absent"));
        std::fs::write(dir.path().join(KILLED_FILE), b"phone /csq off\n").expect("write marker");
        assert!(kill_switch_engaged(dir.path()).expect("engaged"));
        clear_kill_switch(dir.path()).expect("clear");
        assert!(!kill_switch_engaged(dir.path()).expect("cleared"));
        // Idempotent: the local CLI may clear an absent marker.
        clear_kill_switch(dir.path()).expect("clear again");
    }

    /// A phone `off` that happened BEFORE this command is superseded: the
    /// local `on` clears the marker and publishes `enabled = true`.
    #[test]
    fn an_off_before_the_local_on_is_superseded() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(KILLED_FILE), b"phone /csq off\n").expect("marker");
        let mut config = sample();
        config.enabled = false;
        let engaged = enable_bridge(&config, dir.path(), &FsEnable).expect("enable");
        assert!(!engaged, "the local on must clear the marker");
        assert!(!kill_switch_engaged(dir.path()).expect("cleared"));
        assert!(
            load(dir.path()).expect("load").expect("present").enabled,
            "the local on must publish enabled = true"
        );
    }

    /// A phone `off` that lands BETWEEN the steps must still hold: the marker
    /// it writes comes after the local clear, so it survives and outranks
    /// `enabled`. The fake fires the phone off after whichever step runs
    /// FIRST, so this test discriminates the order — with save-then-clear the
    /// local clear would erase the phone's marker and the owner's stop would
    /// be lost.
    #[test]
    fn a_phone_off_between_the_steps_still_holds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = sample();
        struct PhoneOffBetweenSteps {
            fired: std::cell::Cell<bool>,
        }
        impl PhoneOffBetweenSteps {
            fn phone_off_between(&self, base_dir: &Path) {
                if self.fired.replace(true) {
                    return;
                }
                // The phone's `/csq off` lands here: after the first step,
                // before the second. A phone off writes only the marker; it
                // never touches the config.
                std::fs::write(base_dir.join(KILLED_FILE), b"phone /csq off\n")
                    .expect("simulate the phone off");
            }
        }
        impl EnableSteps for PhoneOffBetweenSteps {
            fn clear_kill_switch(&self, base_dir: &Path) -> Result<(), BridgeConfigError> {
                clear_kill_switch(base_dir)?;
                self.phone_off_between(base_dir);
                Ok(())
            }
            fn save_enabled(
                &self,
                config: &BridgeConfig,
                base_dir: &Path,
            ) -> Result<(), BridgeConfigError> {
                save(config, base_dir)?;
                self.phone_off_between(base_dir);
                Ok(())
            }
        }
        let steps = PhoneOffBetweenSteps {
            fired: std::cell::Cell::new(false),
        };
        let engaged = enable_bridge(&config, dir.path(), &steps).expect("enable");
        assert!(engaged, "the phone's stop must survive the local on");
        assert!(kill_switch_engaged(dir.path()).expect("engaged"));
        assert!(
            load(dir.path()).expect("load").expect("present").enabled,
            "the config write still lands; the marker is what keeps the bridge off"
        );
    }

    /// A group- or world-writable config is foreign-controlled: the private
    /// reader refuses it, and `load` reports an unreadable file rather than
    /// trusting it (`guard-reader-writer-parity.md` MUST-2).
    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_config_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(CONFIG_FILE);
        std::fs::write(
            &path,
            br#"{"enabled":false,"owner_user_id":0,"owner_chat_id":0,"allow_classes":[]}"#,
        )
        .expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).expect("chmod");
        assert_eq!(
            load(dir.path()).expect_err("a writable config must fail closed"),
            BridgeConfigError::ConfigUnreadable
        );
    }

    /// The cursor is read through the same private reader; a writable state
    /// file must not be trusted.
    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_cursor_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        save_cursor(
            BridgeCursor {
                high_water_update_id: 5,
            },
            dir.path(),
        )
        .expect("save cursor");
        let path = dir.path().join(STATE_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).expect("chmod");
        assert_eq!(
            load_cursor(dir.path()).expect_err("a writable cursor must fail closed"),
            BridgeConfigError::ConfigUnreadable
        );
    }

    /// The pre-move legacy cursor is read from the config file, through the
    /// private reader as well.
    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_legacy_config_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(CONFIG_FILE);
        std::fs::write(
            &path,
            br#"{"enabled":false,"owner_user_id":0,"owner_chat_id":0,"high_water_update_id":77}"#,
        )
        .expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).expect("chmod");
        assert_eq!(
            load_cursor(dir.path()).expect_err("a writable legacy config must fail closed"),
            BridgeConfigError::ConfigUnreadable
        );
    }

    /// The config's atomic publication is what makes "a crash mid-pin leaves a
    /// valid config" true. Simulate the crash: a partial private temp is
    /// written and dropped WITHOUT publishing, exactly what a killed process
    /// leaves behind. The previous config must still load intact.
    #[test]
    fn a_crash_before_publication_leaves_the_previous_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = sample();
        save(&old, dir.path()).expect("save old");
        let path = dir.path().join(CONFIG_FILE);
        let mut next = old.clone();
        next.owner_user_id = 999;
        next.owner_chat_id = 999;
        let partial = serde_json::to_vec_pretty(&next).expect("serialize");
        let writer = fs::write_private_tmp_synced_retained(&path, &partial).expect("private temp");
        // Dropping without `replace` is the crash: the target is untouched.
        drop(writer);
        let loaded = load(dir.path())
            .expect("the config must still parse")
            .expect("the config must still exist");
        assert_eq!(loaded, old, "a crash must not publish a partial config");
        assert_ne!(loaded.owner_user_id, 999);
    }
}
