//! Launch block for a slot whose sign-in is shared with another slot (orgident r7 item 9).
//!
//! The refresh brake (`refresh_token_audit`) only stops csq's own daemon from presenting
//! a duplicated refresh grant. A freshly started Claude Code session in the same slot
//! would refresh that grant itself, so csq refuses to START or SWAP INTO such a slot.
//! There is no override flag or environment variable: the only exit is `csq login N`.
//!
//! This module owns the operator wording and the single gate every launch surface calls.
//! It never decides suppression: that is `refresh_token_audit::suppressed_slots`
//! (identity-anchored; an unreadable state is judged by a live audit there). It reads local
//! state files only: no keychain, no network, no writes. Already-open sessions are not
//! touched, because nothing here reaches a running process.

use std::collections::BTreeMap;
use std::path::Path;

use crate::accounts::refresh_token_audit;

/// Tag the desktop IPC returns instead of prose; the renderer maps `slot_sign_in_shared:N`
/// to [`refusal_message`]-equivalent text.
pub const DESKTOP_REFUSAL_TAG: &str = "slot_sign_in_shared";

/// Desktop tag for the fail-closed refusal while the suppression record cannot be trusted.
pub const DESKTOP_DAMAGED_TAG: &str = "suppression_state_damaged";

/// Why a launch is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The slot's bound identity is suppressed (its sign-in is shared).
    SharedSignIn(u16),
    /// The suppression record is damaged with no usable last-good copy, so suppression
    /// cannot be proven absent for this Anthropic slot: fail CLOSED.
    StateDamaged,
}

impl Refusal {
    /// Fixed operator message for the CLI.
    pub fn message(self) -> String {
        match self {
            Refusal::SharedSignIn(slot) => refusal_message(slot),
            Refusal::StateDamaged => damaged_message(),
        }
    }

    /// Fixed IPC tag for the desktop renderer.
    pub fn desktop_tag(self) -> String {
        match self {
            Refusal::SharedSignIn(slot) => desktop_refusal(slot),
            Refusal::StateDamaged => DESKTOP_DAMAGED_TAG.to_string(),
        }
    }

    /// Fixed short status-line warning.
    pub fn status_text(self) -> String {
        match self {
            Refusal::SharedSignIn(slot) => status_warning(slot),
            Refusal::StateDamaged => status_damaged(),
        }
    }
}

/// Fixed refusal while the suppression record is damaged and has no last-good copy.
pub fn damaged_message() -> String {
    "refresh-suppression state is damaged; run `csq doctor`".to_string()
}

/// Fixed short status-line warning for the same state.
pub fn status_damaged() -> String {
    "sign-in state unreadable, run csq doctor".to_string()
}

/// Fixed `csq doctor` line for the fail-closed state. It does not repeat the repair text
/// of `refresh_token_audit::operator_lines`, which describes the damaged file itself.
pub fn doctor_damaged_line() -> String {
    "new launches and swaps into Anthropic slots are refused while the suppression record is \
     unknown; re-login each affected slot (`csq login N`; that slot then launches again), then \
     repair or remove the record yourself. csq never deletes it"
        .to_string()
}

/// Fixed refusal for `csq run N`, `csq swap N` and the desktop launch.
pub fn refusal_message(slot: u16) -> String {
    format!("slot {slot} shares its sign-in with another account; run `csq login {slot}`")
}

/// Fixed status-line warning for a terminal bound to a suppressed slot.
pub fn status_warning(slot: u16) -> String {
    format!("sign-in shared, run csq login {slot}")
}

/// Fixed `csq doctor` line for one blocked slot (`holder` is the slot that keeps the grant).
pub fn doctor_line(slot: u16, holder: u16) -> String {
    format!(
        "slot {slot} shares its sign-in with slot {holder}; new launches and swaps into it are \
         refused: run `csq login {slot}`"
    )
}

/// The desktop IPC error for a refused launch: fixed tag plus the slot number.
pub fn desktop_refusal(slot: u16) -> String {
    format!("{DESKTOP_REFUSAL_TAG}:{slot}")
}

/// Every slot whose launch is currently refused (slot -> holder).
pub fn blocked_slots(base: &Path) -> BTreeMap<u16, u16> {
    refresh_token_audit::suppressed_slots(base)
}

/// `true` when `slot` is suppressed itself.
pub fn is_launch_blocked(base: &Path, slot: u16) -> bool {
    refresh_token_audit::is_refresh_suppressed(base, slot)
}

/// `true` when the suppression record cannot be trusted (damaged, no last-good copy).
pub fn state_undetermined(base: &Path) -> bool {
    refresh_token_audit::suppression_undetermined(base)
}

/// `true` unless `slot` is provably not an Anthropic OAuth slot. An unreadable
/// `profiles.json` proves nothing, so it counts as Anthropic (fail closed).
fn may_be_anthropic(base: &Path, slot: u16) -> bool {
    let profiles = crate::accounts::profiles::profiles_path(base);
    if crate::accounts::profiles::load(&profiles).is_err() {
        return true;
    }
    crate::accounts::discovery::discover_anthropic(base)
        .iter()
        .any(|a| a.id == slot)
}

/// The single decision every launch surface asks: why (if at all) a launch into `slot`
/// is refused. A suppressed slot is named precisely; while the record is untrusted, every
/// Anthropic slot is refused.
pub fn launch_refusal(base: &Path, slot: u16) -> Option<Refusal> {
    if is_launch_blocked(base, slot) {
        return Some(Refusal::SharedSignIn(slot));
    }
    if state_undetermined(base)
        && may_be_anthropic(base, slot)
        && !refresh_token_audit::slot_reverified_since_damage(base, slot)
    {
        return Some(Refusal::StateDamaged);
    }
    None
}

/// The gate: `Err(message)` when the launch is refused, `Ok(())` otherwise.
pub fn check_launch(base: &Path, slot: u16) -> Result<(), String> {
    match launch_refusal(base, slot) {
        Some(refusal) => Err(refusal.message()),
        None => Ok(()),
    }
}

/// Status-line segment for the terminal's bound slot, `None` when it is not blocked.
pub fn status_segment(base: &Path, slot: u16) -> Option<String> {
    launch_refusal(base, slot).map(Refusal::status_text)
}

/// Hermetic fixture shared by the csq-core and csq-crate tests.
#[cfg(any(test, feature = "test-utils"))]
pub mod fixture {
    use std::path::Path;

    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::testing::identity_fixtures::fixture_uuid_for_slot;
    use crate::types::{AccessToken, RefreshToken};

    fn creds(refresh: &str) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(format!("at-for-{refresh}")),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 4_102_444_800_000,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        })
    }

    /// Bind `slot` to its fixture identity with a saved credential carrying `refresh`.
    pub fn bind(base: &Path, slot: u16, refresh: &str) {
        let uuid = fixture_uuid_for_slot(slot);
        let pp = crate::accounts::profiles::profiles_path(base);
        let mut pf = if pp.exists() {
            crate::accounts::profiles::load(&pp).unwrap()
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        pf.by_slot.insert(slot.to_string(), uuid);
        crate::accounts::profiles::save(&pp, &pf).unwrap();
        let path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
        crate::platform::fs::secure_dir(path.parent().unwrap()).unwrap();
        crate::credentials::save(&path, &creds(refresh)).unwrap();
    }

    /// Slots `holder` and `suppressed` share one refresh grant and the startup audit has
    /// persisted the suppression of `suppressed` (the later slot). `holder < suppressed`.
    pub fn seed_shared_grant(base: &Path, holder: u16, suppressed: u16) {
        assert!(holder < suppressed, "the audit suppresses the later slot");
        bind(base, holder, "launch-block-shared-grant");
        bind(base, suppressed, "launch-block-shared-grant");
        super::refresh_token_audit::run_startup_audit(base);
        assert!(
            super::is_launch_blocked(base, suppressed),
            "fixture must suppress"
        );
        assert!(
            !super::is_launch_blocked(base, holder),
            "holder must stay free"
        );
    }

    /// A test that reaches the suppression-damage warning callsite without capturing it must
    /// hold this for its whole body (`crate::testing::TRACING_CAPTURE_LOCK` explains why).
    pub fn hold_tracing_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Each damage gets its own modification time, as a second damage in real life would
    /// (a coarse filesystem clock can give two quick writes one timestamp, which would make
    /// a test about "a different episode" depend on the host clock).
    static DAMAGE_EPISODES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Damage the suppression record beyond repair: garbage primary, no last-good copy.
    pub fn destroy_suppression_state(base: &Path) {
        let primary = base.join("refresh-suppressed.json");
        std::fs::write(&primary, b"garbage").unwrap();
        crate::platform::fs::secure_file(&primary).unwrap();
        let n = DAMAGE_EPISODES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&primary)
            .unwrap()
            .set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + 1_000 * n),
            )
            .unwrap();
        let _ = std::fs::remove_file(base.join("refresh-suppressed.last-good.json"));
        assert!(
            super::state_undetermined(base),
            "fixture must be undetermined"
        );
    }

    /// The operator's repair: remove the damaged record, then the next audit rewrites it.
    pub fn repair_suppression_state(base: &Path) {
        std::fs::remove_file(base.join("refresh-suppressed.json")).unwrap();
        super::refresh_token_audit::run_startup_audit(base);
        assert!(
            !super::state_undetermined(base),
            "repair must clear the unknown"
        );
    }

    /// The operator deletes the damaged record by hand: csq code does not run.
    pub fn operator_removes_record(base: &Path) {
        std::fs::remove_file(base.join("refresh-suppressed.json")).unwrap();
    }

    /// The operator replaces the damaged record with a sound, empty one by hand.
    pub fn operator_writes_sound_record(base: &Path) {
        let primary = base.join("refresh-suppressed.json");
        std::fs::write(&primary, br#"{"version":2,"suppressed":{}}"#).unwrap();
        crate::platform::fs::secure_file(&primary).unwrap();
    }

    /// Slot bindings written by the PRODUCTION writers (guard-reader-writer-parity MUST-4),
    /// never a hand-shaped file.
    pub mod production {
        use std::path::Path;

        use crate::providers::catalog::Surface;
        use crate::types::AccountNum;

        fn acct(slot: u16) -> AccountNum {
            AccountNum::try_from(slot).unwrap()
        }

        /// `csq login N --provider codex`: identity mint under the profiles lock, then the
        /// canonical Codex credential (`providers::codex::login`).
        pub fn bind_codex(base: &Path, slot: u16) {
            let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base).unwrap();
            crate::daemon::identity_mint::mint_for_codex_login(
                &lock,
                base,
                slot,
                Some(&format!("fx{slot:08x}-fixture")),
            )
            .unwrap();
            let creds = crate::credentials::CredentialFile::Codex(
                crate::credentials::CodexCredentialFile {
                    auth_mode: Some("chatgpt".into()),
                    openai_api_key: None,
                    tokens: crate::credentials::CodexTokensFile {
                        account_id: Some(format!("fx{slot:08x}-fixture")),
                        access_token: format!("codex-at-{slot}"),
                        refresh_token: Some(format!("codex-rt-{slot}")),
                        id_token: None,
                        extra: Default::default(),
                    },
                    last_refresh: Some("2100-01-01T00:00:00Z".into()),
                    extra: Default::default(),
                },
            );
            crate::credentials::file::save_canonical_for(base, acct(slot), &creds).unwrap();
        }

        /// `csq login N --provider kimi-cli|grok`: the credential-less native binding marker.
        pub fn bind_native(base: &Path, slot: u16, surface: Surface) {
            crate::providers::native::write_binding(base, acct(slot), surface).unwrap();
        }

        /// `csq setkey mm --slot N`: the per-slot 3P API-key binding.
        pub fn bind_api_key(base: &Path, slot: u16) {
            crate::accounts::third_party::bind_provider_to_slot(
                base,
                "mm",
                acct(slot),
                Some("sk-fixture-api-key-0123456789"),
                None,
            )
            .unwrap();
        }

        /// Cloud-Claude Vertex slot (`bind_cloud_claude_backend_to_slot`).
        #[cfg(feature = "enterprise")]
        pub fn bind_vertex(base: &Path, slot: u16, sa_file: &Path) {
            crate::accounts::third_party::bind_cloud_claude_backend_to_slot(
                base,
                acct(slot),
                &crate::accounts::third_party::CloudClaudeBackendSpec::Vertex {
                    project: "fixture-project",
                    region: "us-east5",
                    sa_path: sa_file,
                    model: None,
                },
            )
            .unwrap();
        }

        /// Cloud-Claude Bedrock slot (`bind_cloud_claude_backend_to_slot`).
        #[cfg(feature = "enterprise")]
        pub fn bind_bedrock(base: &Path, slot: u16) {
            crate::accounts::third_party::bind_cloud_claude_backend_to_slot(
                base,
                acct(slot),
                &crate::accounts::third_party::CloudClaudeBackendSpec::Bedrock {
                    region: "us-east-1",
                    bearer_token: "bedrock-fixture-token-0123456789",
                    model: None,
                },
            )
            .unwrap();
        }
    }

    /// What a successful `csq login <slot>` leaves behind: a fresh, distinct grant in the
    /// slot's canonical, then the real clear path.
    pub fn simulate_login(base: &Path, slot: u16) {
        bind(base, slot, &format!("launch-block-fresh-grant-{slot}"));
        super::refresh_token_audit::clear_on_login(base, slot);
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{self, seed_shared_grant, simulate_login};
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn wording_is_fixed_and_names_the_slot() {
        assert_eq!(
            refusal_message(7),
            "slot 7 shares its sign-in with another account; run `csq login 7`"
        );
        assert_eq!(status_warning(7), "sign-in shared, run csq login 7");
        assert_eq!(desktop_refusal(7), "slot_sign_in_shared:7");
        assert!(doctor_line(7, 2).contains("run `csq login 7`"));
    }

    #[test]
    fn suppressed_slot_is_refused_and_holder_is_not() {
        let _tracing = fixture::hold_tracing_lock();
        let dir = TempDir::new().unwrap();
        seed_shared_grant(dir.path(), 1, 2);
        assert_eq!(check_launch(dir.path(), 2), Err(refusal_message(2)));
        assert_eq!(check_launch(dir.path(), 1), Ok(()));
        assert_eq!(check_launch(dir.path(), 9), Ok(()));
        assert_eq!(
            blocked_slots(dir.path())
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(status_segment(dir.path(), 2), Some(status_warning(2)));
        assert_eq!(status_segment(dir.path(), 1), None);
    }

    #[test]
    fn damaged_state_without_last_good_refuses_every_anthropic_slot_until_repaired() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{bind, destroy_suppression_state, repair_suppression_state};
        let dir = TempDir::new().unwrap();
        seed_shared_grant(dir.path(), 1, 2);
        bind(dir.path(), 3, "launch-block-distinct-three");
        destroy_suppression_state(dir.path());
        assert_eq!(check_launch(dir.path(), 1), Err(damaged_message()));
        assert_eq!(check_launch(dir.path(), 3), Err(damaged_message()));
        assert!(check_launch(dir.path(), 2).is_err());
        assert_eq!(status_segment(dir.path(), 3), Some(status_damaged()));
        repair_suppression_state(dir.path());
        assert_eq!(
            check_launch(dir.path(), 3),
            Ok(()),
            "free once the record is sound"
        );
        assert_eq!(check_launch(dir.path(), 1), Ok(()));
        assert_eq!(check_launch(dir.path(), 2), Err(refusal_message(2)));
    }

    /// Bound (i): a record that was never written (fresh install) is not "undetermined".
    #[test]
    fn an_absent_record_is_not_undetermined_and_launches_proceed() {
        use super::fixture::bind;
        let dir = TempDir::new().unwrap();
        bind(dir.path(), 1, "launch-block-one");
        bind(dir.path(), 3, "launch-block-three");
        assert!(!dir.path().join("refresh-suppressed.json").exists());
        assert!(!state_undetermined(dir.path()));
        assert_eq!(check_launch(dir.path(), 1), Ok(()));
        assert_eq!(check_launch(dir.path(), 3), Ok(()));
        assert_eq!(status_segment(dir.path(), 3), None);
    }

    /// Bound (ii): only Anthropic slots are refused while the record is unknown.
    #[test]
    fn undetermined_state_leaves_non_anthropic_slots_alone() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{bind, destroy_suppression_state};
        let dir = TempDir::new().unwrap();
        seed_shared_grant(dir.path(), 1, 2);
        // A Gemini-bound slot (bound, but its marker file says Gemini) and a slot csq has
        // no Anthropic binding for at all (Codex/3P/Kimi/Grok slots are in that class).
        bind(dir.path(), 9, "launch-block-gemini-nine");
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(dir.path().join("credentials").join("gemini-9.json"), b"{}").unwrap();
        destroy_suppression_state(dir.path());
        assert_eq!(check_launch(dir.path(), 9), Ok(()), "gemini slot");
        assert_eq!(
            check_launch(dir.path(), 8),
            Ok(()),
            "slot with no anthropic binding"
        );
        assert_eq!(
            check_launch(dir.path(), 1),
            Err(damaged_message()),
            "anthropic slot"
        );
    }

    /// Bound (iii): `csq login N` clears the unknown for THAT slot only.
    #[test]
    fn login_while_undetermined_frees_that_slot_only_and_repair_clears_the_marks() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{bind, destroy_suppression_state, repair_suppression_state};
        let dir = TempDir::new().unwrap();
        seed_shared_grant(dir.path(), 1, 2);
        bind(dir.path(), 3, "launch-block-distinct-three");
        destroy_suppression_state(dir.path());
        assert!(check_launch(dir.path(), 2).is_err());
        simulate_login(dir.path(), 2);
        assert_eq!(
            check_launch(dir.path(), 2),
            Ok(()),
            "re-logged-in slot launches"
        );
        assert_eq!(check_launch(dir.path(), 3), Err(damaged_message()));
        assert_eq!(check_launch(dir.path(), 1), Err(damaged_message()));
        repair_suppression_state(dir.path());
        assert!(
            !dir.path()
                .join("refresh-suppression-reverified.json")
                .exists(),
            "the marks do not outlive the damage"
        );
    }

    /// Bound (iv): nothing csq does while the record is damaged deletes or rewrites it.
    #[test]
    fn no_code_path_here_removes_or_rewrites_a_damaged_record() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{bind, destroy_suppression_state};
        let dir = TempDir::new().unwrap();
        seed_shared_grant(dir.path(), 1, 2);
        bind(dir.path(), 3, "launch-block-distinct-three");
        destroy_suppression_state(dir.path());
        let path = dir.path().join("refresh-suppressed.json");
        let _ = refresh_token_audit::run_startup_audit(dir.path());
        let _ = check_launch(dir.path(), 3);
        let _ = blocked_slots(dir.path());
        let _ = refresh_token_audit::operator_lines(dir.path());
        simulate_login(dir.path(), 2);
        let _ = refresh_token_audit::run_startup_audit(dir.path());
        assert_eq!(std::fs::read(&path).unwrap(), b"garbage", "bytes untouched");
    }

    #[test]
    fn doctor_text_for_the_damaged_state_names_the_recovery() {
        let t = doctor_damaged_line();
        assert!(t.contains("csq login N"), "{t}");
        assert!(t.contains("repair or remove the record yourself"), "{t}");
        assert!(t.contains("never deletes"), "{t}");
    }

    #[test]
    fn damaged_wording_is_fixed() {
        assert_eq!(
            damaged_message(),
            "refresh-suppression state is damaged; run `csq doctor`"
        );
        assert_eq!(status_damaged(), "sign-in state unreadable, run csq doctor");
        assert_eq!(
            Refusal::StateDamaged.desktop_tag(),
            "suppression_state_damaged"
        );
    }

    #[test]
    fn no_state_file_means_no_refusal() {
        let dir = TempDir::new().unwrap();
        assert_eq!(check_launch(dir.path(), 3), Ok(()));
        assert!(blocked_slots(dir.path()).is_empty());
    }

    #[test]
    fn refusal_ends_after_login_clears_the_suppression() {
        let _tracing = fixture::hold_tracing_lock();
        let dir = TempDir::new().unwrap();
        seed_shared_grant(dir.path(), 1, 2);
        assert!(check_launch(dir.path(), 2).is_err());
        simulate_login(dir.path(), 2);
        assert_eq!(check_launch(dir.path(), 2), Ok(()));
        assert_eq!(status_segment(dir.path(), 2), None);
        assert!(blocked_slots(dir.path()).is_empty());
    }

    // ── r7c: re-verified marks count only within the damage episode that made them ──

    fn marks_path(base: &Path) -> std::path::PathBuf {
        base.join("refresh-suppression-reverified.json")
    }

    /// Slots 1/2 share a grant, slot 3 is distinct, the record is destroyed and slot 2 logs
    /// in again: slot 2 is marked re-verified in the CURRENT episode.
    fn damaged_with_slot_two_reverified(base: &Path) {
        use super::fixture::{bind, destroy_suppression_state};
        seed_shared_grant(base, 1, 2);
        bind(base, 3, "launch-block-distinct-three");
        destroy_suppression_state(base);
        simulate_login(base, 2);
        assert_eq!(check_launch(base, 2), Ok(()), "marked in this episode");
        assert!(marks_path(base).exists(), "the mark is on disk");
    }

    /// (i) A failed mark clear can never open the gate: recovery whose clear fails, then
    /// damage again, leaves the slot refused.
    #[test]
    fn a_failed_mark_clear_during_recovery_never_opens_a_later_damage() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{destroy_suppression_state, repair_suppression_state};
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        refresh_token_audit::fail_reverified_clear_for_test(dir.path(), true);
        repair_suppression_state(dir.path());
        refresh_token_audit::fail_reverified_clear_for_test(dir.path(), false);
        assert!(
            marks_path(dir.path()).exists(),
            "the injected failure left the marks on disk"
        );
        destroy_suppression_state(dir.path());
        assert_eq!(
            check_launch(dir.path(), 2),
            Err(damaged_message()),
            "a mark from the earlier episode must not free the slot in the new one"
        );
    }

    /// (ii) The operator deletes the damaged record by hand (no csq code runs), then the
    /// record is damaged again: the earlier mark is void.
    #[test]
    fn an_out_of_band_delete_then_new_damage_voids_the_earlier_mark() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{destroy_suppression_state, operator_removes_record};
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        operator_removes_record(dir.path());
        assert!(
            !state_undetermined(dir.path()),
            "deleted, nothing records suppression"
        );
        destroy_suppression_state(dir.path());
        assert_eq!(check_launch(dir.path(), 2), Err(damaged_message()));
    }

    /// (iii) The operator repairs by hand, then the record is damaged again with IDENTICAL
    /// bytes: still a different episode, the earlier mark is void.
    #[test]
    fn identical_damage_after_an_out_of_band_repair_is_a_new_episode() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{destroy_suppression_state, operator_writes_sound_record};
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        operator_writes_sound_record(dir.path());
        assert!(!state_undetermined(dir.path()));
        destroy_suppression_state(dir.path());
        assert_eq!(
            std::fs::read(dir.path().join("refresh-suppressed.json")).unwrap(),
            b"garbage",
            "same bytes as the first damage"
        );
        assert_eq!(check_launch(dir.path(), 2), Err(damaged_message()));
    }

    /// A login in a NEW episode starts a fresh set of marks: it must not carry an earlier
    /// episode's marks along under the new fingerprint.
    #[test]
    fn a_login_in_a_new_episode_does_not_revive_the_earlier_episodes_marks() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{destroy_suppression_state, operator_removes_record};
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        operator_removes_record(dir.path());
        destroy_suppression_state(dir.path());
        simulate_login(dir.path(), 3);
        assert_eq!(
            check_launch(dir.path(), 3),
            Ok(()),
            "marked in the new episode"
        );
        assert_eq!(
            check_launch(dir.path(), 2),
            Err(damaged_message()),
            "slot 2 was marked only in the earlier episode"
        );
    }

    /// A repair that goes through csq (marks cleared first) also voids the mark.
    #[test]
    fn a_repair_through_csq_voids_the_mark_for_a_later_damage() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{destroy_suppression_state, repair_suppression_state};
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        repair_suppression_state(dir.path());
        assert!(!marks_path(dir.path()).exists());
        destroy_suppression_state(dir.path());
        assert_eq!(check_launch(dir.path(), 2), Err(damaged_message()));
    }

    /// (iv) No over-blocking: inside the SAME episode the mark keeps the slot launching,
    /// across reads, audits, and a second slot's login.
    #[test]
    fn the_same_episode_keeps_a_reverified_slot_launching() {
        let _tracing = fixture::hold_tracing_lock();
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        let _ = blocked_slots(dir.path());
        let _ = refresh_token_audit::operator_lines(dir.path());
        let _ = refresh_token_audit::run_startup_audit(dir.path());
        assert_eq!(check_launch(dir.path(), 2), Ok(()), "same episode");
        simulate_login(dir.path(), 3);
        assert_eq!(
            check_launch(dir.path(), 3),
            Ok(()),
            "second login, same episode"
        );
        assert_eq!(
            check_launch(dir.path(), 2),
            Ok(()),
            "first mark survives the second"
        );
        assert_eq!(check_launch(dir.path(), 1), Err(damaged_message()));
    }

    /// A FIFO in place of the marks file reads as "not re-verified" and never blocks.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_the_marks_is_not_a_reverification() {
        let _tracing = fixture::hold_tracing_lock();
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        std::fs::remove_file(marks_path(dir.path())).unwrap();
        let c = std::ffi::CString::new(marks_path(dir.path()).to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(check_launch(dir.path(), 2), Err(damaged_message()));
    }

    /// A symlink in place of the marks file is refused even when its target holds the
    /// genuine marks.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_marks_file_is_not_a_reverification() {
        let _tracing = fixture::hold_tracing_lock();
        let dir = TempDir::new().unwrap();
        damaged_with_slot_two_reverified(dir.path());
        let real = dir.path().join("marks-copy.json");
        std::fs::copy(marks_path(dir.path()), &real).unwrap();
        crate::platform::fs::secure_file(&real).unwrap();
        std::fs::remove_file(marks_path(dir.path())).unwrap();
        std::os::unix::fs::symlink(&real, marks_path(dir.path())).unwrap();
        assert_eq!(check_launch(dir.path(), 2), Err(damaged_message()));
    }

    // ── r7c item 4: Anthropic-only bound, fixtures written by the production writers ──

    fn assert_not_discovered_as_anthropic(base: &Path, slots: &[u16]) {
        let ids: Vec<u16> = crate::accounts::discovery::discover_anthropic(base)
            .iter()
            .map(|a| a.id)
            .collect();
        for s in slots {
            assert!(
                !ids.contains(s),
                "slot {s} must not be an Anthropic slot: {ids:?}"
            );
        }
    }

    #[test]
    fn production_written_non_anthropic_slots_stay_ungated_while_anthropic_stays_gated() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{bind, destroy_suppression_state, production};
        use crate::providers::catalog::Surface;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_shared_grant(base, 1, 2);
        bind(base, 3, "launch-block-distinct-three");
        production::bind_codex(base, 4);
        production::bind_native(base, 5, Surface::Kimi);
        production::bind_native(base, 6, Surface::Grok);
        production::bind_api_key(base, 7);
        assert_not_discovered_as_anthropic(base, &[4, 5, 6, 7]);
        destroy_suppression_state(base);
        for (slot, what) in [(4, "codex"), (5, "kimi"), (6, "grok"), (7, "3p api key")] {
            assert_eq!(check_launch(base, slot), Ok(()), "{what} slot {slot}");
            assert_eq!(status_segment(base, slot), None, "{what} slot {slot}");
        }
        // Slot 2 is still named precisely: the live audit sees the duplicate grant.
        assert!(check_launch(base, 2).is_err(), "anthropic 2");
        for slot in [1, 3] {
            assert_eq!(
                check_launch(base, slot),
                Err(damaged_message()),
                "anthropic {slot}"
            );
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn production_written_cloud_claude_slots_stay_ungated_while_anthropic_stays_gated() {
        let _tracing = fixture::hold_tracing_lock();
        use super::fixture::{bind, destroy_suppression_state, production};
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        seed_shared_grant(base, 1, 2);
        bind(base, 3, "launch-block-distinct-three");
        let sa = dir.path().join("sa-fixture.json");
        std::fs::write(&sa, b"{}").unwrap();
        production::bind_vertex(base, 8, &sa);
        production::bind_bedrock(base, 9);
        assert_not_discovered_as_anthropic(base, &[8, 9]);
        destroy_suppression_state(base);
        assert_eq!(check_launch(base, 8), Ok(()), "vertex slot");
        assert_eq!(check_launch(base, 9), Ok(()), "bedrock slot");
        // Slot 2 is still named precisely: the live audit sees the duplicate grant.
        assert!(check_launch(base, 2).is_err(), "anthropic 2");
        for slot in [1, 3] {
            assert_eq!(
                check_launch(base, slot),
                Err(damaged_message()),
                "anthropic {slot}"
            );
        }
    }
}
