//! PTY relay for session input control (spec 34).
//!
//! The relay owns the pseudo-terminal a launched CLI runs on, so csq can
//! deliver input to a live session under the Enter rule (spec 34a §34a.1)
//! instead of racing the user's keystrokes. This module is the shared skeleton:
//! [`types`] holds the outcome, state and chord vocabulary every later
//! shard codes against, and [`require_supported_platform`] is the platform gate.
//!
//! # Platform
//!
//! The relay, its control socket and its tools are `cfg(unix)` (spec 34 §34.9).
//! Later shards MUST declare their submodules as `#[cfg(unix)] mod x;` lines
//! (never inside a macro: rustfmt does not descend into macro-declared modules,
//! so the format gate would skip them); the test
//! `every_relay_module_but_types_is_cfg_unix` fails when one lacks the
//! attribute. The shared [`types`] are
//! platform-neutral so a refusal can be named everywhere; on any non-unix
//! target [`require_supported_platform`] returns
//! [`SdkErrorCode::UnsupportedPlatform`], launch is unchanged and no relay
//! starts.

use crate::sdk::SdkErrorCode;

pub mod types;

#[cfg(unix)]
pub use state::{
    ClockFn, DropReason, EnterCapableInputs, EnterWait, EntryKind, GateSnapshot, InputFlushed,
    Outcome, PasteStall, Pasted, Queued, RelayState, Role, SlashCmd, SourceScan, StopSource,
    Terminal, Transaction, TurnStartSource, WriterLock,
};
pub use types::{
    ChallengeAttempt, ChordEvent, ChordFilter, ChordResult, ClassifiedKey, CliKind, CsqEnter,
    GrantSlot, IdleReturn, InjectOutcome, InputClass, Key, Phase, Run, SessionIdentity,
};

// Later shards add their modules here (S1b, S3a, ...), each as its own
// `#[cfg(unix)]` line.
#[cfg(unix)]
pub mod pty;
#[cfg(unix)]
pub mod state;
#[cfg(unix)]
pub mod term;

/// Whether this platform can host the relay (spec 34 §34.2, §34.9).
///
/// `Ok(())` on unix. On every other platform the `unsupported_platform`
/// refusal (spec 34 §34.5.1); callers surface it as the inject outcome and
/// leave the launch path unchanged.
pub fn require_supported_platform() -> Result<(), SdkErrorCode> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(SdkErrorCode::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The module name of a `mod x;` declaration line, with any visibility
    /// (`pub`, `pub(crate)`, `pub(in path)`, `pub(super)`).
    fn module_decl(line: &str) -> Option<&str> {
        let l = line.trim();
        let l = match l.strip_prefix("pub") {
            Some(r) if r.starts_with('(') => r.split_once(')')?.1.trim_start(),
            Some(r) => r.trim_start(),
            None => l,
        };
        l.strip_prefix("mod ")
            .map(str::trim_start)
            .filter(|r| r.ends_with(';'))
    }

    /// Every `mod x;` declaration in this file except the platform-neutral
    /// `types` carries `#[cfg(unix)]` directly above it (spec 34 §34.9).
    #[test]
    fn every_relay_module_but_types_is_cfg_unix() {
        let src = include_str!("mod.rs");
        let lines: Vec<&str> = src.lines().map(str::trim).collect();
        let mut seen = 0;
        for (i, l) in lines.iter().enumerate() {
            let Some(rest) = module_decl(l) else {
                continue;
            };
            seen += 1;
            if rest == "types;" {
                continue;
            }
            assert!(
                i > 0 && lines[i - 1] == "#[cfg(unix)]",
                "relay module `{rest}` lacks #[cfg(unix)] on the line above"
            );
        }
        assert!(seen >= 2, "scan saw {seen} module lines; it is blind");
    }

    /// The declaration reader sees every visibility spelling, so a
    /// `pub(crate) mod x;` without the attribute cannot slip past the test above.
    #[test]
    fn module_decl_reads_every_visibility_form() {
        for line in [
            "mod x;",
            "pub mod x;",
            "pub(crate) mod x;",
            "pub(super) mod x;",
            "pub(in crate::relay) mod x;",
            "    pub(crate)   mod   x;",
        ] {
            assert_eq!(module_decl(line), Some("x;"), "{line}");
        }
        for line in ["mod x {", "pub use x::y;", "// mod x;", "fn mod_x();"] {
            assert_eq!(module_decl(line), None, "{line}");
        }
    }

    #[test]
    fn platform_gate_matches_target() {
        let r = require_supported_platform();
        if cfg!(unix) {
            assert_eq!(r, Ok(()));
        } else {
            assert_eq!(r, Err(SdkErrorCode::UnsupportedPlatform));
        }
    }
}
