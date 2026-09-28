//! Read-only operator guidance, not a recovery operation (spec 04 §4.1.1).
//!
//! The health handshake reports a version, NOT the process host or executable.
//! Do not infer launchd from macOS, foreground from a failed supervisor probe,
//! or the loaded executable from an on-disk service file. Unknown evidence stays
//! explicit. These pure formatters neither probe the host nor print private paths.

/// Platform selects inspection syntax; it does not establish supervision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPlatform {
    MacOs,
    Linux,
    Windows,
    Other,
}

impl RecoveryPlatform {
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

/// Only an independent observation can select a known host. A version-only
/// health response always selects `Unknown`, including on macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonHost {
    Unknown,
    Launchd,
    Systemd,
    Foreground,
    Desktop,
}

pub const LAUNCHD_LABEL: &str = "foundation.terrene.csq";

/// Platform-specific but supervision-agnostic guidance for health callers.
pub fn recovery_guidance() -> String {
    recovery_guidance_for(RecoveryPlatform::current(), DaemonHost::Unknown)
}

/// Render from explicitly supplied evidence. Executable paths and their on-disk
/// versions have NOT been measured by this function, even when the host is known.
/// No user-controlled path, process argument, environment or error body is echoed.
pub fn recovery_guidance_for(platform: RecoveryPlatform, host: DaemonHost) -> String {
    let mut parts = vec![
        "Service executable versus PATH-selected CLI executable is unverified. Compare the loaded service program, its on-disk configuration, and the CLI you actually invoked (an explicit path or shell alias may differ from PATH). Verify both executable versions before recovery; restarting the same old binary does not fix a two-installation mismatch.".to_owned(),
    ];
    if host == DaemonHost::Unknown {
        parts.push(
            "Daemon supervisor is unverified; platform alone does not identify its owner.".into(),
        );
    }
    if host == DaemonHost::Launchd
        || (host == DaemonHost::Unknown && platform == RecoveryPlatform::MacOs)
    {
        parts.push(format!(
            "For launchd: inspect `launchctl print gui/$(id -u)/{LAUNCHD_LABEL}` and `command -v csq`; compare the loaded program with Program/ProgramArguments[0] in the LaunchAgent. If the executable differs or is outdated, correct the intended service executable with a backup, preserving other settings, and reload the service definition first. Only after the loaded executable and version are verified, use `launchctl kickstart -k gui/$(id -u)/{LAUNCHD_LABEL}`. Do not use `csq daemon stop` followed by a foreground start as routine launchd repair: a clean stop disarms KeepAlive."
        ));
    }
    if host == DaemonHost::Systemd
        || (host == DaemonHost::Unknown && platform == RecoveryPlatform::Linux)
    {
        parts.push("For systemd: inspect `systemctl --user show csq.service -p ExecStart -p FragmentPath` and `command -v csq`; compare loaded ExecStart with the unit and drop-ins. Correct any executable mismatch first, preserving other settings; after a unit edit use `systemctl --user daemon-reload`. Only after the loaded executable and version are verified, use `systemctl --user restart csq.service`.".into());
    }
    if host == DaemonHost::Unknown && platform == RecoveryPlatform::Windows {
        parts.push("On Windows, inspect `Get-Command csq -All` and the actual desktop/service/task owner and configured executable; do not assume a Unix supervisor or that PATH controls the daemon.".into());
    }
    if matches!(host, DaemonHost::Unknown | DaemonHost::Foreground) {
        parts.push("Only for a confirmed standalone foreground daemon: stop that daemon in its owning terminal and restart the verified intended executable with `daemon start`; this remains foreground, not persistent supervision.".into());
    }
    if matches!(host, DaemonHost::Unknown | DaemonHost::Desktop) {
        parts.push("For a desktop-owned daemon, verify the desktop executable/version and use its owning application's recovery procedure; do not substitute a foreground daemon.".into());
    }
    parts.push("Recovery is an operator action, not automatic. Preserve coding-agent sessions, credentials and history; do not install binaries or bypass the version refusal. Recheck daemon health and version before retrying.".into());
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_launchd_requires_path_correction_before_kickstart() {
        let text = recovery_guidance_for(RecoveryPlatform::MacOs, DaemonHost::Launchd);
        assert!(
            text.contains("Service executable versus PATH-selected CLI executable is unverified")
        );
        assert!(text.contains("restarting the same old binary does not fix"));
        assert!(
            text.find("correct the intended service executable")
                .unwrap()
                < text.find("launchctl kickstart").unwrap()
        );
        assert!(text.contains("clean stop disarms KeepAlive"));
        assert!(!text.contains("systemctl"));
    }

    #[test]
    fn recovery_unknown_macos_does_not_assert_launchd_ownership() {
        let text = recovery_guidance_for(RecoveryPlatform::MacOs, DaemonHost::Unknown);
        assert!(text.contains("Daemon supervisor is unverified"));
        assert!(text.contains("For launchd:"));
        assert!(text.contains("Only for a confirmed standalone foreground"));
        assert!(text.contains("For a desktop-owned daemon"));
    }

    #[test]
    fn recovery_systemd_requires_loaded_execstart_and_reload_before_restart() {
        let text = recovery_guidance_for(RecoveryPlatform::Linux, DaemonHost::Systemd);
        assert!(text.contains("-p ExecStart -p FragmentPath"));
        assert!(
            text.find("Correct any executable mismatch first").unwrap()
                < text.find("systemctl --user restart").unwrap()
        );
        assert!(text.contains("daemon-reload"));
        assert!(!text.contains("launchctl"));
    }

    #[test]
    fn recovery_confirmed_foreground_does_not_invent_supervision() {
        let text = recovery_guidance_for(RecoveryPlatform::MacOs, DaemonHost::Foreground);
        assert!(text.contains("remains foreground, not persistent supervision"));
        assert!(!text.contains("launchctl"));
        assert!(!text.contains("Daemon supervisor is unverified"));
    }

    #[test]
    fn recovery_windows_and_unknown_platform_do_not_offer_unix_commands() {
        for platform in [RecoveryPlatform::Windows, RecoveryPlatform::Other] {
            let text = recovery_guidance_for(platform, DaemonHost::Unknown);
            assert!(!text.contains("launchctl"));
            assert!(!text.contains("systemctl"));
            assert!(text.contains("supervisor is unverified"));
            assert!(text.contains("do not install binaries or bypass the version refusal"));
        }
        assert!(
            recovery_guidance_for(RecoveryPlatform::Windows, DaemonHost::Unknown)
                .contains("Get-Command csq -All")
        );
    }

    #[test]
    fn recovery_desktop_does_not_offer_foreground_substitute() {
        let text = recovery_guidance_for(RecoveryPlatform::MacOs, DaemonHost::Desktop);
        assert!(text.contains("owning application's recovery procedure"));
        assert!(!text.contains("`daemon start`"));
        assert!(!text.contains("launchctl"));
    }
}

/// Planned roster/bundle maintenance, deliberately NOT version-drift recovery.
/// Liveness alone does not identify a supervisor or a safe stop/start command.
pub fn maintenance_guidance() -> String {
    maintenance_guidance_for(RecoveryPlatform::current(), DaemonHost::Unknown)
}

/// Pure maintenance policy over supplied owner evidence. No executable paths,
/// process arguments, host queries or operations are accepted or performed.
pub fn maintenance_guidance_for(platform: RecoveryPlatform, host: DaemonHost) -> String {
    let host = match (platform, host) {
        (RecoveryPlatform::MacOs, DaemonHost::Launchd)
        | (RecoveryPlatform::Linux, DaemonHost::Systemd)
        | (_, DaemonHost::Foreground | DaemonHost::Desktop) => host,
        _ => DaemonHost::Unknown,
    };
    let (quiesce, restore) = match host {
        DaemonHost::Launchd => (
            "Quiesce through launchd: unload the confirmed owning job for the maintenance interval so KeepAlive cannot restart the writer; preserve its loaded job and on-disk LaunchAgent definition. A kickstart is a restart, not quiescence.",
            "Restore through launchd by loading the preserved, verified LaunchAgent definition; verify the loaded program rather than substituting a foreground daemon.",
        ),
        DaemonHost::Systemd => (
            "Quiesce through systemd: stop the confirmed owning unit and control its activation triggers for the maintenance interval; preserve the unit and drop-ins.",
            "Restore through systemd using the same verified unit and activation configuration, not a foreground substitute.",
        ),
        DaemonHost::Foreground => (
            "Quiesce the confirmed standalone foreground daemon in its owning terminal; do not signal an unidentified process.",
            "Restore the confirmed standalone foreground daemon in its owning terminal with the verified executable and original configuration using `daemon start`; this remains foreground, not persistent supervision.",
        ),
        DaemonHost::Desktop => (
            "Quiesce through the owning desktop application's maintenance procedure, including any automatic daemon relaunch; preserve that application's executable and configuration.",
            "Restore through the same desktop application with its verified executable and configuration; do not substitute a foreground daemon.",
        ),
        DaemonHost::Unknown => (
            "Daemon ownership is unverified. Do not guess stop/start commands or proceed with installation: identify the actual supervisor, desktop or foreground owner first, then quiesce through that owner.",
            "Restore only through the independently verified original owner and configuration; no restart command can be selected from platform or PID liveness alone.",
        ),
    };
    format!(
        "Planned maintenance, not routine restart. Coordinate interruption with the operator and preserve coding-agent sessions, credentials and history. Identify the actual owner and compare its loaded executable with its configured executable and the CLI selected for installation; preserve and verify the intended configuration before changing state. {quiesce} Verify that the daemon writer is absent and cannot automatically relaunch before proceeding. Perform the requested roster or bundle installation only while quiesced. {restore} Recheck loaded executable, daemon health and installation outcome afterward. The existing live-writer refusal remains fail-closed; a one-time liveness check does not prove universal race freedom. This guidance performs no host operation."
    )
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;

    #[test]
    fn maintenance_unknown_owner_never_guesses_a_restart_command() {
        for platform in [
            RecoveryPlatform::MacOs,
            RecoveryPlatform::Linux,
            RecoveryPlatform::Windows,
            RecoveryPlatform::Other,
        ] {
            let text = maintenance_guidance_for(platform, DaemonHost::Unknown);
            assert!(text.contains("Daemon ownership is unverified"));
            assert!(text.contains("Do not guess stop/start commands or proceed with installation"));
            assert!(!text.contains("launchctl"));
            assert!(!text.contains("systemctl"));
            assert!(!text.contains("`daemon start`"));
        }
    }

    #[test]
    fn maintenance_launchd_quiesces_then_restores_same_definition() {
        let text = maintenance_guidance_for(RecoveryPlatform::MacOs, DaemonHost::Launchd);
        assert!(text.contains("KeepAlive cannot restart the writer"));
        assert!(text.contains("A kickstart is a restart, not quiescence"));
        assert!(
            text.find("unload the confirmed owning job").unwrap()
                < text.find("Perform the requested").unwrap()
        );
        assert!(
            text.find("Perform the requested").unwrap()
                < text.find("Restore through launchd").unwrap()
        );
        assert!(text.contains("preserved, verified LaunchAgent definition"));
        assert!(!text.contains("`daemon start`"));
    }

    #[test]
    fn maintenance_systemd_controls_activation_and_preserves_unit() {
        let text = maintenance_guidance_for(RecoveryPlatform::Linux, DaemonHost::Systemd);
        assert!(text.contains("control its activation triggers"));
        assert!(text.contains("preserve the unit and drop-ins"));
        assert!(text.contains("same verified unit and activation configuration"));
        assert!(!text.contains("launchd"));
    }

    #[test]
    fn maintenance_foreground_is_explicit_and_restarts_after_install() {
        let text = maintenance_guidance_for(RecoveryPlatform::Other, DaemonHost::Foreground);
        assert!(text.contains("confirmed standalone foreground daemon in its owning terminal"));
        assert!(text.find("Perform the requested").unwrap() < text.find("`daemon start`").unwrap());
        assert!(text.contains("remains foreground, not persistent supervision"));
    }

    #[test]
    fn maintenance_desktop_preserves_its_owner_and_automatic_relaunch_policy() {
        let text = maintenance_guidance_for(RecoveryPlatform::Windows, DaemonHost::Desktop);
        assert!(text.contains("including any automatic daemon relaunch"));
        assert!(text.contains("Restore through the same desktop application"));
        assert!(!text.contains("`daemon start`"));
    }

    #[test]
    fn maintenance_conflicting_platform_owner_evidence_stays_unknown() {
        for (platform, host) in [
            (RecoveryPlatform::Windows, DaemonHost::Launchd),
            (RecoveryPlatform::MacOs, DaemonHost::Systemd),
        ] {
            let text = maintenance_guidance_for(platform, host);
            assert!(text.contains("Daemon ownership is unverified"));
            assert!(!text.contains("Quiesce through launchd"));
            assert!(!text.contains("Quiesce through systemd"));
        }
    }

    #[test]
    fn maintenance_requires_writer_absence_without_claiming_race_freedom() {
        let text = maintenance_guidance();
        assert!(text.contains("loaded executable with its configured executable"));
        assert!(
            text.find("Verify that the daemon writer is absent")
                .unwrap()
                < text.find("Perform the requested").unwrap()
        );
        assert!(text.contains("live-writer refusal remains fail-closed"));
        assert!(text.contains("does not prove universal race freedom"));
        assert!(text.contains("preserve coding-agent sessions, credentials and history"));
    }
}
