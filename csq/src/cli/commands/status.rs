//! `csq status` — display all accounts with quota usage.
//!
//! # Execution paths
//!
//! 1. **Daemon-delegated (preferred on Unix)** — when a healthy
//!    daemon is running, the CLI fetches the account list via
//!    `GET /api/accounts` and composes it with the local quota
//!    file. The daemon's 5s discovery cache means a cold
//!    filesystem scan happens at most once per 5 seconds across
//!    every CLI invocation, rather than once per invocation.
//!
//! 2. **Direct (fallback)** — when no daemon is running or the
//!    daemon is unhealthy, the CLI runs `discover_anthropic`
//!    itself. Behaviour is byte-identical to pre-M8 versions.
//!
//! The quota file is a local read in both paths — the daemon does
//! not currently expose `/api/quota`, and adding one is M8.6 work
//! (the background poller). Composing daemon-discovered accounts
//! with locally-read quota produces identical output to the direct
//! path for the same `(accounts, quota)` pair.

use anyhow::Result;
use csq_core::accounts::snapshot;
use csq_core::quota::status::{render_status_table, show_status, AccountStatus};
use csq_core::sdk::{self, Envelope, SCHEMA_STATUS_V2};
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::Path;

#[cfg(unix)]
use csq_core::accounts::AccountInfo;
#[cfg(unix)]
use csq_core::daemon::{self, DetectResult};
#[cfg(unix)]
use csq_core::quota::status::compose_status;

/// `csq.status.v2` preserves v1 account rows and adds token-free daemon
/// snapshot evidence. Missing or stale evidence is explicitly unknown.
#[derive(Debug, Serialize)]
struct StatusPayload {
    data: Vec<AccountStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    session_logins: Vec<csq_core::credentials::session_login::SessionLogin>,
    sessions_undetermined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    keychain_mirror_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keychain_mirror: Option<csq_core::credentials::keychain::MirrorSyncStatus>,
    /// The orphan sweep's published state, from the SAME accessor `csq doctor`
    /// and the desktop use. Omitted when the sweep never published.
    #[serde(skip_serializing_if = "Option::is_none")]
    keychain_orphans: Option<csq_core::credentials::keychain::orphans::OrphanDiagnosticView>,
    /// Slots whose identity holds a pending post-commit rescue record.
    /// A pending record blocks the refresher's provider request (the
    /// canonical may hold an already-consumed token), so it is surfaced
    /// here instead of staying a log-only state. Fixed vocabulary; no
    /// paths, no credential material.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rescue_pending: Vec<csq_core::credentials::rescue::PendingRescue>,
    /// Slots in the classified LOGIN-NEEDED state — the JSON twin of the
    /// text lines, and the SAME list `csq doctor` prints. Additive to
    /// `csq.status.v2` (omitted when empty).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    login_needed: Vec<u16>,
    /// Slots whose marker exists but whose cause cannot be classified (the
    /// text lines use [`csq_core::refresh::sentinel::refresh_failing_line`]).
    /// Never a login demand, never healthy. Additive; omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    refresh_failing: Vec<u16>,
    /// True when `credentials/` could not be enumerated, so both lists are
    /// UNDETERMINED rather than empty. Omitted from JSON when false.
    #[serde(skip_serializing_if = "is_false")]
    login_state_undetermined: bool,
}

/// `serde` helper: omit a `false` boolean from the JSON surface.
fn is_false(value: &bool) -> bool {
    !*value
}

/// The JSON twin of the two text lists, from the SAME scan the text surface
/// uses: `(login_needed, refresh_failing, undetermined)`. Extracted so the
/// JSON wiring is testable and cannot silently omit either list.
fn sentinel_json_lists(
    scan: &csq_core::refresh::sentinel::SentinelScan,
) -> (Vec<u16>, Vec<u16>, bool) {
    (
        scan.login_needed_slots()
            .iter()
            .map(|account| account.get())
            .collect(),
        scan.refresh_failing_slots()
            .iter()
            .map(|account| account.get())
            .collect(),
        !scan.readable,
    )
}

/// The text line for an unenumerable `credentials/` directory, or `None`
/// when the scan was readable. Extracted so the text is testable without
/// capturing stdout.
fn login_state_undetermined_text(readable: bool) -> Option<String> {
    (!readable).then(|| {
        format!(
            "  {}",
            csq_core::refresh::sentinel::SENTINEL_SCAN_UNDETERMINED
        )
    })
}

/// The one text line `csq status` prints for the orphan sweep (the wording is
/// the accessor's `summary`; only the level tag is added here).
pub(crate) fn keychain_orphans_text(
    view: &csq_core::credentials::keychain::orphans::OrphanDiagnosticView,
) -> String {
    use csq_core::credentials::keychain::orphans::DiagnosticLevel;
    let tag = match view.level {
        DiagnosticLevel::Ok => "ok",
        DiagnosticLevel::Info => "info",
        DiagnosticLevel::Warn => "warn",
        DiagnosticLevel::NeedsAction => "NEEDS ACTION",
    };
    format!("Keychain orphans [{tag}]: {}", view.summary)
}

pub fn handle(base_dir: &Path, json: bool) -> Result<()> {
    // Resolve active account authority-first (workspace
    // an internal workspace): snapshot_account reads `.csq-account`
    // (numeric direct / UUID via by_slot) and self-heals the cache, so the
    // "active" highlight cannot be pinned to a stale `.current-account`.
    let active = super::current_config_dir()
        .as_deref()
        .and_then(|cd| snapshot::snapshot_account(cd, base_dir));

    let accounts = resolve_accounts(base_dir, active);

    let login_diagnostics = csq_core::credentials::session_login::read_diagnostics(base_dir);
    let keychain_orphans =
        csq_core::credentials::keychain::orphans::read_diagnostic(base_dir).view();
    let rescue_pending = csq_core::credentials::rescue::pending_rescues(base_dir);
    // The sentinel state, from the files the daemon's refresh path writes.
    // TWO DISTINCT lists — a classified login demand and a marker whose
    // cause was never recorded — plus the scan's own readability. Pure file
    // reads: no credential read, no keychain read
    // (`diagnostic-surface-parity.md` MUST NOT 4).
    let sentinel_scan = csq_core::refresh::sentinel::sentinel_scan(base_dir);
    let login_needed = sentinel_scan.login_needed_slots();
    let refresh_failing = sentinel_scan.refresh_failing_slots();
    let (login_needed_json, refresh_failing_json, login_state_undetermined) =
        sentinel_json_lists(&sentinel_scan);

    if json {
        // R3: emit() is the only stdout writer for the enveloped surface.
        sdk::emit(&Envelope::success(
            SCHEMA_STATUS_V2,
            None,
            StatusPayload {
                data: accounts,
                session_logins: login_diagnostics.session_logins,
                sessions_undetermined: login_diagnostics.sessions_undetermined,
                keychain_mirror_age_secs: login_diagnostics.snapshot_age_secs,
                keychain_mirror: login_diagnostics.keychain_mirror,
                keychain_orphans,
                rescue_pending,
                login_needed: login_needed_json,
                refresh_failing: refresh_failing_json,
                login_state_undetermined,
            },
        ))?;
        return Ok(());
    }

    for login in &login_diagnostics.session_logins {
        if let Some(line) = csq_core::credentials::session_login::finding_line(login) {
            println!("{line}");
        }
    }
    println!(
        "{}",
        csq_core::credentials::session_login::snapshot_line(
            login_diagnostics.keychain_mirror.as_ref(),
            login_diagnostics.snapshot_age_secs,
            login_diagnostics.sessions_undetermined
        )
    );
    if let Some(view) = &keychain_orphans {
        println!("{}", keychain_orphans_text(view));
    }
    for rescue in &rescue_pending {
        println!("{}", render_rescue_line(rescue));
    }
    // Each login-needed slot gets its OWN line — never folded into a quota
    // row — with the shared fixed-vocabulary message the statusline and
    // `csq doctor` also print.
    for line in login_needed_text_lines(&login_needed) {
        println!("{line}");
    }
    // A marker whose cause was never recorded is its own, DIFFERENT line:
    // never a login demand, never healthy.
    for line in refresh_failing_text_lines(&refresh_failing) {
        println!("{line}");
    }
    // The directory could not be enumerated: both lists above are
    // UNDETERMINED, not empty. Never let silence read as all-clear.
    if let Some(line) = login_state_undetermined_text(sentinel_scan.readable) {
        println!("{line}");
    }

    if accounts.is_empty() {
        println!("No accounts configured.");
        println!();
        println!("Run `csq login 1` to add your first account.");
        return Ok(());
    }

    let clock = chrono::Local::now().format("%a %H:%M").to_string();
    print!("{}", render_status_table(&accounts, active, &clock));
    println!();

    Ok(())
}

/// Renders ONE pending-rescue status line with the shared fixed-vocabulary
/// message from `csq-core` (`PendingRescue::status_line`), so `csq status`,
/// `csq doctor` and the desktop row cannot drift apart.
fn render_rescue_line(rescue: &csq_core::credentials::rescue::PendingRescue) -> String {
    use csq_core::credentials::rescue::RescuePendingState;
    let icon = match rescue.state {
        // Undetermined is a warning too: silence would read as "all clear".
        RescuePendingState::Unadoptable | RescuePendingState::Unknown => "⚠",
        RescuePendingState::Adoptable => "ℹ",
    };
    format!("  Rescue: {icon} {}", rescue.status_line())
}

/// One line per login-needed slot, in the order the sentinel scan returns
/// them (ascending). Each slot gets its OWN line, and the text is the shared
/// [`csq_core::refresh::sentinel::login_needed_line`] — never a quota row and
/// never a second copy of the message that could drift from the statusline's.
fn login_needed_text_lines(slots: &[AccountNum]) -> Vec<String> {
    slots
        .iter()
        .map(|account| {
            format!(
                "  {}",
                csq_core::refresh::sentinel::login_needed_line(*account)
            )
        })
        .collect()
}

/// One line per slot whose marker exists but whose cause is unclassifiable.
///
/// The phrase is the shared
/// [`csq_core::refresh::sentinel::REFRESH_FAILING_CAUSE_NOT_RECORDED`], prefixed
/// with the slot so two unknown slots are distinguishable. Deliberately a
/// different line from [`login_needed_text_lines`]: such a marker is not
/// evidence the credential is dead.
fn refresh_failing_text_lines(slots: &[AccountNum]) -> Vec<String> {
    slots
        .iter()
        .map(|account| {
            format!(
                "  {}",
                csq_core::refresh::sentinel::refresh_failing_line(*account)
            )
        })
        .collect()
}

/// Returns the composed [`AccountStatus`] entries, trying the
/// daemon first and falling back to direct discovery on any
/// failure.
///
/// Silent fallback — a failed daemon round trip must not produce
/// user-visible noise on a successful status call. Tracing at the
/// debug level captures the detection reason for troubleshooting.
fn resolve_accounts(base_dir: &Path, active: Option<AccountNum>) -> Vec<AccountStatus> {
    #[cfg(unix)]
    {
        if let Some(accounts) = try_daemon_accounts(base_dir) {
            return compose_status(base_dir, accounts, active);
        }
    }

    show_status(base_dir, active)
}

/// Attempts to fetch accounts from the running daemon via
/// `GET /api/accounts`. Returns `None` on any failure
/// (daemon not running, unhealthy, parse error, non-200 status)
/// so the caller can fall back to direct discovery.
///
/// All non-200 outcomes are silent — the user runs `csq status`
/// expecting output, not a fallback warning. Debug-level tracing
/// captures the reason for troubleshooting.
#[cfg(unix)]
fn try_daemon_accounts(base_dir: &Path) -> Option<Vec<AccountInfo>> {
    let socket_path = match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy {
            socket_path,
            daemon_version,
            ..
        } => {
            // Stale-daemon defense: a long-running daemon spawned from
            // a pre-upgrade binary will silently serve stale
            // `/api/accounts` (e.g. missing Gemini slots from before
            // `discover_gemini` was wired in). Rather than consume the
            // stale view, fall back to the direct path AND tell the
            // user — they need to restart the daemon to refresh.
            if let Some(reason) = daemon::version_drift_reason(&daemon_version) {
                eprintln!("warning: {reason}");
                return None;
            }
            socket_path
        }
        other => {
            tracing::debug!(result = ?other, "csq status: daemon not healthy, using direct path");
            return None;
        }
    };

    let resp = match daemon::http_get_unix(&socket_path, "/api/accounts") {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "csq status: daemon GET /api/accounts failed");
            return None;
        }
    };

    if resp.status != 200 {
        tracing::debug!(
            status = resp.status,
            "csq status: daemon returned non-200 for /api/accounts"
        );
        return None;
    }

    // AccountsResponse is `{ "accounts": [...] }`. `AccountInfo`
    // already derives Deserialize in csq-core, so we navigate to
    // the inner array via `serde_json::Value` rather than adding a
    // direct `serde` dependency to csq-cli just for an envelope.
    let value: serde_json::Value = match serde_json::from_str(&resp.body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "csq status: /api/accounts body is not valid JSON");
            return None;
        }
    };

    let arr = value.get("accounts")?.clone();
    match serde_json::from_value::<Vec<AccountInfo>>(arr) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::debug!(error = %e, "csq status: could not deserialize accounts array");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::accounts::{AccountSource, Backend};
    use csq_core::providers::catalog::Surface;

    fn sample_row() -> AccountStatus {
        AccountStatus {
            id: 1,
            label: "user@example.com".into(),
            is_active: true,
            five_hour_pct: Some(42.5),
            five_hour_resets_in: Some(3600),
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        }
    }

    /// Golden fixture (an internal ticket Track B): every pre-existing `AccountStatus`
    /// row field remains unchanged at `data[N].<field>` under the
    /// `csq.status.v2` envelope. A rename or retype of ANY field asserted here
    /// REDS this test — that non-vacuity is the entire point of versioning the
    /// schema (verified by hand: renaming `StatusPayload.data` to `.rows` fails
    /// this test with "missing field `data`" / a null `data[0]` lookup).
    #[test]
    fn login_needed_text_lines_are_one_own_line_per_slot() {
        let slots = [
            AccountNum::try_from(2u16).unwrap(),
            AccountNum::try_from(7u16).unwrap(),
        ];
        let lines = login_needed_text_lines(&slots);
        assert_eq!(
            lines,
            vec![
                "  login needed — run csq login 2".to_string(),
                "  login needed — run csq login 7".to_string(),
            ],
            "each login-needed slot gets its own line from the shared message"
        );
        assert_eq!(login_needed_text_lines(&[]), Vec::<String>::new());
    }

    /// A marker whose cause was never recorded prints the not-recorded line,
    /// NOT a login demand — the pre-classification writer marked every
    /// failure with a generic tag, so `csq status` must not tell the operator
    /// to re-authenticate a healthy slot. Removing the refresh-failing loop
    /// from `handle` (or the helper) REDs this.
    #[test]
    fn refresh_failing_text_lines_are_distinct_from_login_lines() {
        let slots = [
            AccountNum::try_from(4u16).unwrap(),
            AccountNum::try_from(9u16).unwrap(),
        ];
        let lines = refresh_failing_text_lines(&slots);
        assert_eq!(
            lines,
            vec![
                "  slot 4: refresh failing, cause not recorded".to_string(),
                "  slot 9: refresh failing, cause not recorded".to_string(),
            ]
        );
        for line in &lines {
            assert!(!line.contains("login needed"), "{line}");
            assert!(!line.contains("LOGIN-NEEDED"), "{line}");
        }
        assert_eq!(refresh_failing_text_lines(&[]), Vec::<String>::new());
    }

    #[test]
    fn status_json_envelope_matches_golden_shape() {
        let payload = StatusPayload {
            data: vec![sample_row()],
            session_logins: Vec::new(),
            sessions_undetermined: true,
            keychain_mirror_age_secs: None,
            keychain_mirror: None,
            keychain_orphans: None,
            rescue_pending: Vec::new(),
            login_needed: Vec::new(),
            refresh_failing: Vec::new(),
            login_state_undetermined: false,
        };
        let env = Envelope::success(SCHEMA_STATUS_V2, None, payload);
        let line = env.to_line().unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(v["schema"], "csq.status.v2");
        assert_eq!(v["sessions_undetermined"], true);
        assert_eq!(v["ok"], true);
        assert!(
            v.get("error").is_none(),
            "success envelope carries no error"
        );

        let row = &v["data"][0];
        assert_eq!(row["id"], 1);
        assert_eq!(row["label"], "user@example.com");
        assert_eq!(row["is_active"], true);
        assert_eq!(row["five_hour_pct"], 42.5);
        assert_eq!(row["five_hour_resets_in"], 3600);
        assert!(row["seven_day_pct"].is_null());
        assert!(row["seven_day_resets_in"].is_null());
        assert_eq!(row["source"], "Anthropic");
        assert_eq!(row["surface"], "claude-code");
        assert_eq!(row["method"], "oauth");
        assert_eq!(row["backend"], "direct");
        // Optional, skip_serializing_if fields stay ABSENT (not null) when None —
        // the pre-existing `AccountStatus` wire behavior, unchanged by the envelope.
        assert!(row.get("balance").is_none());
        assert!(row.get("stale_secs").is_none());
    }

    /// LOW-5: the JSON surface carries the same two lists the text surface
    /// prints — a machine consumer must not read "all clear" while the text
    /// says login needed. Both are additive v2 fields, omitted when empty.
    /// The lists come from `sentinel_json_lists`, the helper `handle` uses.
    #[test]
    fn status_json_carries_both_sentinel_lists() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("2.broker-failed"), "invalid_grant").unwrap();
        std::fs::write(creds.join("7.broker-failed"), "unauthorized_client").unwrap();
        std::fs::write(creds.join("4.broker-failed"), "oauth").unwrap();
        std::fs::write(creds.join("9.broker-failed"), "").unwrap();
        let scan = csq_core::refresh::sentinel::sentinel_scan(dir.path());
        let (login_needed, refresh_failing, login_state_undetermined) = sentinel_json_lists(&scan);
        assert_eq!(login_needed, vec![2, 7]);
        assert_eq!(refresh_failing, vec![4, 9]);
        assert!(!login_state_undetermined);

        let payload = StatusPayload {
            data: Vec::new(),
            session_logins: Vec::new(),
            sessions_undetermined: false,
            keychain_mirror_age_secs: None,
            keychain_mirror: None,
            keychain_orphans: None,
            rescue_pending: Vec::new(),
            login_needed,
            refresh_failing,
            login_state_undetermined,
        };
        let env = Envelope::success(SCHEMA_STATUS_V2, None, payload);
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["login_needed"], serde_json::json!([2, 7]));
        assert_eq!(v["refresh_failing"], serde_json::json!([4, 9]));
        assert!(v.get("login_state_undetermined").is_none());
    }

    /// An unenumerable `credentials/` directory prints the undetermined line;
    /// a readable scan prints nothing extra.
    #[test]
    fn unreadable_credentials_directory_prints_undetermined() {
        let line = login_state_undetermined_text(false).expect("must print");
        assert!(line.contains(csq_core::refresh::sentinel::SENTINEL_SCAN_UNDETERMINED));
        assert!(login_state_undetermined_text(true).is_none());
    }

    /// Seeds a profiles binding plus an identity directory for `slot`, and
    /// writes `record` at the legacy rescue path when given.
    fn seed_slot_with_rescue(
        base: &Path,
        slot: u16,
        record: Option<&[u8]>,
    ) -> csq_core::accounts::identity_store::IdentityId {
        let uuid = csq_core::testing::identity_fixtures::fixture_uuid_for_slot(slot);
        let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot.to_string(), uuid);
        csq_core::accounts::profiles::save(
            &csq_core::accounts::profiles::profiles_path(base),
            &profiles,
        )
        .unwrap();
        let identity_dir = csq_core::accounts::identity_store::credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();
        if let Some(bytes) = record {
            std::fs::write(
                csq_core::credentials::rescue::rescue_record_path(&identity_dir),
                bytes,
            )
            .unwrap();
        }
        uuid
    }

    /// A record adoption can never install is VISIBLE on `csq status` with
    /// the fixed-vocabulary action — the block is otherwise log-only.
    ///
    /// RED mutation: make `render_rescue_line` print the adoptable text for
    /// every state — the exact line assertion fails.
    #[test]
    fn unparseable_rescue_renders_visible_status_line() {
        let dir = tempfile::TempDir::new().unwrap();
        seed_slot_with_rescue(dir.path(), 3, Some(b"not json"));

        let lines: Vec<String> = csq_core::credentials::rescue::pending_rescues(dir.path())
            .iter()
            .map(render_rescue_line)
            .collect();
        assert_eq!(
            lines,
            vec![
                "  Rescue: ⚠ slot 3: a saved login could not be restored; sign in again for this account"
                    .to_string()
            ],
            "an unadoptable rescue must be visible with its action"
        );

        // The JSON envelope carries the same state additively.
        let payload = StatusPayload {
            data: Vec::new(),
            session_logins: Vec::new(),
            sessions_undetermined: true,
            keychain_mirror_age_secs: None,
            keychain_mirror: None,
            keychain_orphans: None,
            rescue_pending: csq_core::credentials::rescue::pending_rescues(dir.path()),
            login_needed: Vec::new(),
            refresh_failing: Vec::new(),
            login_state_undetermined: false,
        };
        let line = Envelope::success(SCHEMA_STATUS_V2, None, payload)
            .to_line()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["rescue_pending"][0]["slot"], 3);
        assert_eq!(v["rescue_pending"][0]["state"], "unadoptable");
    }

    /// A slot with no pending record prints no rescue line at all — the
    /// unadoptable line above is not a constant.
    #[test]
    fn no_rescue_record_renders_no_line() {
        let dir = tempfile::TempDir::new().unwrap();
        seed_slot_with_rescue(dir.path(), 4, None);
        assert!(
            csq_core::credentials::rescue::pending_rescues(dir.path()).is_empty(),
            "no record means no visible rescue state"
        );
    }

    /// `profiles.json` unreadable: the fallback enumerator still surfaces the
    /// rescued identity on `csq status`, labelled by its canonical UUID.
    ///
    /// RED mutation: return `Vec::new()` when profiles cannot be loaded —
    /// this test renders zero lines.
    #[test]
    fn fallback_rescue_renders_identity_line_when_profiles_unreadable() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let uuid = csq_core::testing::identity_fixtures::fixture_uuid_for_slot(6);
        let identity_dir = csq_core::accounts::identity_store::identity_path(base, uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(
            csq_core::credentials::rescue::rescue_record_path(&identity_dir),
            b"not json",
        )
        .unwrap();
        std::fs::write(
            csq_core::accounts::profiles::profiles_path(base),
            b"not json",
        )
        .unwrap();

        let lines: Vec<String> = csq_core::credentials::rescue::pending_rescues(base)
            .iter()
            .map(render_rescue_line)
            .collect();
        assert_eq!(
            lines,
            vec![format!(
                "  Rescue: ⚠ identity {uuid}: a saved login could not be restored; sign in again for this account"
            )],
            "the fallback identity must be visible with its action"
        );
    }

    /// `profiles.json` AND the identities directory unreadable/absent: ONE
    /// explicit UNKNOWN line, never silence.
    ///
    /// RED mutation: return `Vec::new()` from the identities-scan failure arm
    /// — this test renders zero lines.
    #[test]
    fn unknown_rescue_renders_one_explicit_line() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        std::fs::write(
            csq_core::accounts::profiles::profiles_path(base),
            b"not json",
        )
        .unwrap();
        assert!(!csq_core::accounts::identity_store::identities_dir(base).exists());

        let lines: Vec<String> = csq_core::credentials::rescue::pending_rescues(base)
            .iter()
            .map(render_rescue_line)
            .collect();
        assert_eq!(
            lines,
            vec!["  Rescue: ⚠ rescue status unknown: profiles unreadable".to_string()],
            "exactly one explicit unknown row"
        );
    }

    #[test]
    fn status_json_envelope_is_a_single_line() {
        let env = Envelope::success(
            SCHEMA_STATUS_V2,
            None,
            StatusPayload {
                data: vec![sample_row()],
                session_logins: Vec::new(),
                sessions_undetermined: true,
                keychain_mirror_age_secs: None,
                keychain_mirror: None,
                keychain_orphans: None,
                rescue_pending: Vec::new(),
                login_needed: Vec::new(),
                refresh_failing: Vec::new(),
                login_state_undetermined: false,
            },
        );
        let line = env.to_line().unwrap();
        assert_eq!(line.matches('\n').count(), 0);
    }
}
