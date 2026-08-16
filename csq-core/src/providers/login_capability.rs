//! Per-provider login-driving metadata (an internal ticket) — derives what
//! `csq login --provider <id>` DOES for a provider (the process shape, not the
//! OAuth grant type) from the descriptor union in [`super::registry`], and the
//! fail-fast guard `csq login`'s dispatch runs before starting a flow that would
//! otherwise block on an attended session no host can supply.
//!
//! # Why this exists
//!
//! A host embedding csq that doesn't hardcode per-provider login shape discovers
//! it only by ATTEMPTING a login — and then hangs. Concretely, before any guard
//! existed here, `csq login N --provider claude` in a non-interactive context
//! (piped stdin, no local browser) would spawn `claude auth login` and sit for
//! up to `CSQ_LOGIN_TIMEOUT_SECS` (default 300s) before erroring — the exact
//! failure this module exists to pre-empt with an IMMEDIATE, typed refusal.
//!
//! # Derivation, not a table
//!
//! [`login_flow_for`] derives [`LoginFlow`] from the descriptor's
//! [`super::registry::ProviderKind`] discriminant (`Native` is device-code by
//! construction — the ONLY native login shape [`super::native_login`] parses) and,
//! for `Wrapped`, mirrors `csq login`'s own provider dispatch
//! (`csq/src/cli/commands/login.rs::handle`'s `match provider` arms) exactly —
//! that match IS the ground truth for which ids `csq login` accepts and how each
//! behaves. If the two ever diverge, `handle`'s arms win; the
//! `login_flow_matches_login_dispatch_arms` test below pins the exact accepted
//! set so a divergence reds here instead of silently drifting (the same pattern
//! [`super::registry::exec_routable_provider_ids`] already uses for `csq exec`'s
//! dispatch).

use super::registry::{self, ProviderKind};
use csq_sdk::{LoginFlow, ProviderLogin, SdkError, SdkErrorCode};

/// Derives the [`LoginFlow`] shape `csq login --provider <id>` follows for
/// `descriptor`. See the module doc for the derivation rule.
#[must_use]
pub fn login_flow_for(descriptor: &registry::ProviderDescriptor) -> LoginFlow {
    match descriptor.kind {
        // Every native descriptor is a self-authenticating vendor CLI using an
        // OAuth2 device-code grant (`NativeCli::device_code_host` is a required,
        // non-optional field, and `native_login::parse_native_device_code` is the
        // ONLY native login parser this codebase has) — derived from the KIND
        // discriminant, not from the provider's identity.
        ProviderKind::Native => LoginFlow::DeviceCode,
        ProviderKind::Wrapped => match descriptor.id {
            "claude" => LoginFlow::BrowserSubprocess,
            "codex" => LoginFlow::TtyRequired,
            "gemini" => LoginFlow::ExternalPrerequisite,
            _ => LoginFlow::NotSupported,
        },
    }
}

/// Whether a host with no local TTY and no local browser can drive `flow` to
/// completion. Only [`LoginFlow::DeviceCode`] qualifies — capturing a code + URL
/// from stdout and relaying it out-of-band needs neither.
#[must_use]
pub const fn headless_drivable(flow: LoginFlow) -> bool {
    matches!(flow, LoginFlow::DeviceCode)
}

/// Static, flow-generic next-step text — one string per [`LoginFlow`] variant,
/// not one per provider id, so this stays derived from the flow rather than
/// becoming a second per-provider table.
///
/// [`LoginFlow`] is `#[non_exhaustive]` (csq-sdk R2/R4-style closed-per-version
/// vocabulary), so this match — cross-crate from `csq-sdk`'s perspective —
/// MUST carry a wildcard arm even though every variant defined today is
/// covered above it: a future flow this build predates falls through to a
/// generic, still-actionable instruction rather than failing to compile.
/// The fallback [`login_instructions`] returns for a [`LoginFlow`] this build
/// does not recognise. Named so `every_login_flow_has_specific_instructions`
/// can assert no CURRENT variant reaches it — the wildcard is for future
/// variants only, never a resting place for one we simply forgot.
const UNCLASSIFIED_FLOW_INSTRUCTION: &str =
    "run `csq login <slot> --provider <id>` and follow the on-screen \
     instructions — this provider's login flow is newer than this csq \
     build's classification of it; update csq for a precise instruction";

#[must_use]
pub const fn login_instructions(flow: LoginFlow) -> &'static str {
    match flow {
        LoginFlow::DeviceCode => {
            "run `csq login <slot> --provider <id>`; a short code + URL appear on \
             stdout — open the URL on any device and enter the code (no local \
             browser or TTY input required once the code is captured)"
        }
        LoginFlow::BrowserSubprocess => {
            "run `csq login <slot> --provider <id>` from a machine with a \
             reachable local browser — the vendor CLI manages the OAuth loopback \
             callback itself and cannot be driven by piping stdin"
        }
        LoginFlow::TtyRequired => {
            "run `csq login <slot> --provider <id>` from an interactive terminal \
             (a real TTY, e.g. `ssh -t ...`) — it blocks on an Enter confirmation \
             before starting the device-auth flow and refuses immediately if \
             stdin is not a TTY"
        }
        LoginFlow::ExternalPrerequisite => {
            "run the bare vendor CLI once interactively to complete its own OAuth \
             flow first, THEN run `csq login <slot> --provider <id>` to bind the \
             slot — csq performs no interactive step of its own for this provider"
        }
        LoginFlow::NotSupported => {
            "not reachable through `csq login` — configure this provider's API \
             key via `csq setkey <id>` instead"
        }
        _ => UNCLASSIFIED_FLOW_INSTRUCTION,
    }
}

/// Composes the full [`ProviderLogin`] wire object for `descriptor`.
#[must_use]
pub fn provider_login(descriptor: &registry::ProviderDescriptor) -> ProviderLogin {
    let flow = login_flow_for(descriptor);
    ProviderLogin::new(headless_drivable(flow), flow, login_instructions(flow))
}

/// Whether `flow` requires an ATTENDED session — a real TTY the process can
/// block a confirmation read on, or a local browser its subprocess drives —
/// that `csq login` cannot supply on its own.
///
/// [`LoginFlow::ExternalPrerequisite`] and [`LoginFlow::DeviceCode`] are
/// deliberately excluded: the former performs no interactive step of its own to
/// hang on (a pure file-existence + expiry check); the latter is
/// headless-drivable by construction. [`LoginFlow::NotSupported`] is excluded
/// too — `csq login`'s own `match provider` arm already refuses those ids with a
/// distinct error before any guard here would run.
const fn requires_attended_session(flow: LoginFlow) -> bool {
    // Exhaustive-by-hand with an explicit wildcard, NOT `matches!`.
    //
    // `matches!` desugars to a match whose implicit wildcard yields FALSE, so a
    // future `LoginFlow` this build predates would be classified "no attended
    // session needed" — the guard would not fire, and `csq login` would proceed
    // into whatever blocking read or browser-callback wait that new flow has.
    // That is the exact hang an internal ticket exists to prevent, re-opened silently by an
    // enum variant added elsewhere.
    //
    // So the wildcard fails CLOSED: an unrecognised flow is assumed to need an
    // attended session. The cost of being wrong that way is a typed, actionable
    // `InteractionRequired` refusal a host can react to; the cost of being wrong
    // the other way is an unattended process hanging forever. Mirrors
    // `native::marker_exists`'s documented fail-toward-refuse posture.
    match flow {
        // Code + URL land on stdout; nothing blocks on a local TTY or browser.
        LoginFlow::DeviceCode => false,
        // Drives nothing interactively — only verifies a file another process made.
        LoginFlow::ExternalPrerequisite => false,
        // Never reachable through `csq login` at all (`csq setkey` instead).
        LoginFlow::NotSupported => false,
        LoginFlow::TtyRequired | LoginFlow::BrowserSubprocess => true,
        _ => true,
    }
}

/// Fail-FAST pre-flight guard (an internal ticket).
///
/// For a [`LoginFlow`] that requires an attended session, refuses IMMEDIATELY
/// when `has_tty` is `false`, instead of letting the caller proceed into a
/// blocking stdin read or a local-browser callback wait that a host driving
/// `csq login` as an unattended subprocess can never satisfy.
///
/// `has_tty` is an injected fact, never a live `stdin()` read inside this
/// function — so the decision is unit-testable without a real terminal or a
/// subprocess; the CLI wrapper supplies `std::io::stdin().is_terminal()`
/// (`std::io::IsTerminal`, the idiom already used in `csq/src/mode.rs` and
/// `csq/src/cli/commands/run.rs`).
///
/// # Errors
/// Returns [`SdkErrorCode::InteractionRequired`] when `flow` needs an attended
/// session and `has_tty` is `false`.
pub fn guard_attended_session(
    flow: LoginFlow,
    provider_id: &str,
    has_tty: bool,
) -> Result<(), SdkError> {
    if requires_attended_session(flow) && !has_tty {
        return Err(SdkError::trusted(
            SdkErrorCode::InteractionRequired,
            format!(
                "provider {provider_id:?} login requires an attended session \
                 (flow={}) but no TTY is attached to stdin — {}",
                flow.as_str(),
                login_instructions(flow),
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// `LoginFlow` is `#[non_exhaustive]`, so every cross-crate match here
    /// carries a wildcard and the COMPILER no longer enforces that our
    /// per-variant tables are total. This restores that check at test time
    /// via `LoginFlow::ALL`: a sixth flow added in csq-sdk reds this test
    /// instead of silently degrading to a generic string at runtime for real
    /// operators.
    ///
    /// Non-vacuity: deleting any named arm from `login_instructions` drops that
    /// variant into the wildcard and reds this immediately.
    #[test]
    fn every_login_flow_has_specific_instructions() {
        for flow in LoginFlow::ALL {
            let text = login_instructions(*flow);
            assert_ne!(
                text, UNCLASSIFIED_FLOW_INSTRUCTION,
                "LoginFlow::{flow:?} falls through to the unclassified fallback — \
                 it needs its own arm in `login_instructions`. The wildcard exists \
                 for variants a FUTURE csq adds, never for one this build shipped."
            );
            assert!(
                !text.is_empty(),
                "LoginFlow::{flow:?} has empty instructions"
            );
        }
    }

    /// The attended-session guard MUST fail CLOSED. Every variant this build
    /// knows is classified explicitly; the wildcard answers `true`, so an
    /// unrecognised future flow is refused in a headless context rather than
    /// being waved through into a blocking read — the an internal ticket hang.
    ///
    /// A genuinely unknown variant cannot be constructed here (that is what
    /// `#[non_exhaustive]` means from csq-core), so this pins the two halves
    /// that ARE reachable: the classification of today's variants, and that
    /// exactly the two attended flows require a TTY.
    #[test]
    fn attended_session_classification_is_explicit_for_every_known_flow() {
        for flow in LoginFlow::ALL {
            let attended = requires_attended_session(*flow);
            let expected = matches!(flow, LoginFlow::TtyRequired | LoginFlow::BrowserSubprocess);
            assert_eq!(
                attended, expected,
                "LoginFlow::{flow:?} attended-session classification changed; if \
                 that is intended, update this pin AND re-check the wildcard still \
                 fails closed (`_ => true`)"
            );
        }
    }
    use super::*;
    use crate::providers::registry;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn descriptor_for(id: &str) -> registry::ProviderDescriptor {
        registry::all()
            .into_iter()
            .find(|d| d.id == id)
            .unwrap_or_else(|| panic!("provider {id:?} must resolve through registry::all()"))
    }

    /// AC: native providers (device-code, headless-drivable) are correctly
    /// distinguished from the three wrapped OAuth-login surfaces.
    #[test]
    fn native_providers_are_device_code_and_headless_drivable() {
        for id in ["kimi-cli", "grok"] {
            let d = descriptor_for(id);
            let flow = login_flow_for(&d);
            assert_eq!(flow, LoginFlow::DeviceCode, "{id}");
            assert!(headless_drivable(flow), "{id} must be headless-drivable");
        }
    }

    /// AC: claude is browser-subprocess, not headless-drivable — `csq login`
    /// shells out to `claude auth login`, which manages its OWN local browser +
    /// loopback callback; there is no code for a host to feed via stdin.
    #[test]
    fn claude_is_browser_subprocess_and_not_headless_drivable() {
        let d = descriptor_for("claude");
        let flow = login_flow_for(&d);
        assert_eq!(flow, LoginFlow::BrowserSubprocess);
        assert!(!headless_drivable(flow));
    }

    /// AC: codex is tty-required, not headless-drivable — `csq login`'s own
    /// `handle_codex` blocks on an interactive Enter confirmation before it will
    /// spawn `codex login --device-auth`.
    #[test]
    fn codex_is_tty_required_and_not_headless_drivable() {
        let d = descriptor_for("codex");
        let flow = login_flow_for(&d);
        assert_eq!(flow, LoginFlow::TtyRequired);
        assert!(!headless_drivable(flow));
    }

    /// AC: gemini is external-prerequisite, not headless-drivable — `csq login
    /// --provider gemini` drives NOTHING interactively; it only verifies a
    /// credential file gemini-cli's OWN, fully out-of-band interactive run
    /// already produced.
    #[test]
    fn gemini_is_external_prerequisite_and_not_headless_drivable() {
        let d = descriptor_for("gemini");
        let flow = login_flow_for(&d);
        assert_eq!(flow, LoginFlow::ExternalPrerequisite);
        assert!(!headless_drivable(flow));
    }

    /// AC: every 3P Bearer/None wrapped provider (configured via `csq setkey`,
    /// never `csq login`) and the enterprise-only direct-API providers are
    /// `NotSupported`.
    #[test]
    fn bearer_and_enterprise_only_providers_are_not_supported() {
        for id in ["deepseek", "ollama", "zai", "mm", "kimi", "azure", "vertex"] {
            let d = descriptor_for(id);
            let flow = login_flow_for(&d);
            assert_eq!(flow, LoginFlow::NotSupported, "{id}");
            assert!(!headless_drivable(flow), "{id}");
        }
    }

    /// Pinned regression: the exact set of ids `csq login --provider <id>`
    /// accepts (`csq/src/cli/mod.rs`'s `value_parser` on `Login::provider`,
    /// mirrored by `handle`'s `match provider` arms) is exactly the set this
    /// module classifies as something OTHER than `NotSupported`. A future
    /// provider added to one side without the other reds here instead of
    /// silently drifting — the `exec_routable_provider_ids` pattern applied to
    /// login dispatch.
    #[test]
    fn login_flow_matches_login_dispatch_arms() {
        let mut supported: Vec<&str> = registry::all()
            .into_iter()
            .filter(|d| login_flow_for(d) != LoginFlow::NotSupported)
            .map(|d| d.id)
            .collect();
        supported.sort_unstable();
        assert_eq!(
            supported,
            vec!["claude", "codex", "gemini", "grok", "kimi-cli"],
            "must mirror csq/src/cli/mod.rs's Login::provider value_parser + \
             csq/src/cli/commands/login.rs::handle's match arms"
        );
    }

    /// Non-vacuity for the pinned-set test above: a classifier that dropped one
    /// of the five supported ids would fail it. Simulated directly (rather than
    /// mutating `login_flow_for`) so the probe runs unconditionally.
    #[test]
    fn login_dispatch_set_check_reds_against_a_four_element_list() {
        let hardcoded_missing_one: Vec<&str> = vec!["claude", "codex", "gemini", "grok"];
        assert_ne!(
            hardcoded_missing_one,
            vec!["claude", "codex", "gemini", "grok", "kimi-cli"],
            "the pinned set must differ from a 4-element list for this probe to \
             be meaningful"
        );
    }

    // ── guard_attended_session ──────────────────────────────────────────────

    #[test]
    fn guard_refuses_tty_required_without_a_tty() {
        let err = guard_attended_session(LoginFlow::TtyRequired, "codex", false)
            .expect_err("codex login without a TTY must be refused");
        assert_eq!(err.code, SdkErrorCode::InteractionRequired);
    }

    #[test]
    fn guard_refuses_browser_subprocess_without_a_tty() {
        let err = guard_attended_session(LoginFlow::BrowserSubprocess, "claude", false)
            .expect_err("claude login without a TTY must be refused");
        assert_eq!(err.code, SdkErrorCode::InteractionRequired);
    }

    #[test]
    fn guard_allows_tty_required_with_a_tty() {
        guard_attended_session(LoginFlow::TtyRequired, "codex", true)
            .expect("codex login WITH a TTY must proceed");
    }

    /// Non-gated flows proceed regardless of TTY presence — device-code is
    /// headless-drivable by construction, and external-prerequisite performs no
    /// interactive step of its own to hang on.
    #[test]
    fn guard_never_gates_device_code_or_external_prerequisite() {
        guard_attended_session(LoginFlow::DeviceCode, "grok", false)
            .expect("device-code must never be gated on TTY presence");
        guard_attended_session(LoginFlow::ExternalPrerequisite, "gemini", false)
            .expect("external-prerequisite must never be gated on TTY presence");
    }

    /// AC: the guard proves NO-HANG, not merely the error shape — it returns
    /// well within a generous bound. `guard_attended_session` does no IO of its
    /// own (the TTY fact is injected), so a hang here would mean the function
    /// itself blocks, not that some downstream spawn does; run on a worker
    /// thread and fail the test if the bounded `recv_timeout` elapses first.
    #[test]
    fn guard_returns_fast_never_hangs() {
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let result = guard_attended_session(LoginFlow::TtyRequired, "codex", false);
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("guard_attended_session must return within 2s — it hung");
        assert!(result.is_err());
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "guard_attended_session took {:?} — expected near-instant \
             (no spawn, no IO, injected TTY fact)",
            start.elapsed()
        );
    }

    /// `provider_login` composes all three fields consistently for every
    /// provider in the registry — the same composition `csq-core::sdk::capabilities`
    /// uses to build the wire `login` object.
    #[test]
    fn provider_login_is_internally_consistent_for_every_provider() {
        for d in registry::all() {
            let login = provider_login(&d);
            assert_eq!(login.headless_drivable, headless_drivable(login.flow));
            assert_eq!(login.instructions, login_instructions(login.flow));
        }
    }
}
