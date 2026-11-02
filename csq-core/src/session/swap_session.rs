//! Remote session swap — change the account a LIVE session is bound to.
//!
//! `csq swap N` run inside a terminal swaps that terminal's own handle dir from
//! `CLAUDE_CONFIG_DIR`. This module adds the remote form: a caller that is NOT
//! the terminal (the daemon's Telegram bridge, or `csq swap N --session <name>`)
//! names the TARGET session by its proved identity — `(pid, started_at)` — and
//! the swap acts on the handle dir THAT live process reports, never on the
//! caller's environment and never on a directory name
//! (`account-terminal-separation.md` MUST NOT Rule 3).
//!
//! # One implementation, two entry points
//!
//! The same-surface ClaudeCode swap body is lifted out of
//! `csq/src/cli/commands/swap.rs::handle_inner` — the two-lock acquisition
//! (`.swap-lock` then `.swap.lock` + profiles custody), the keychain
//! force-write-before-repoint and the post-repoint reconcile, the audit
//! INTENT/OUTCOME pair, and the `.current-account` cache refresh. The CLI's own
//! `csq swap` path calls [`same_surface_claude_code_swap`] with the handle dir it
//! detected from its environment; [`swap_session`] calls it with the handle dir
//! resolved from a verified target. Neither path reimplement any of it: a fix in
//! this file fixes both.
//!
//! # What a remote swap refuses, and why
//!
//! Only an IN-FLIGHT same-surface ClaudeCode swap can be driven from outside the
//! process. Every other [`RouteKind`] needs an exec-replace INSIDE the target
//! session (a tombstone and a fresh binary in that terminal), which a remote
//! caller cannot perform, so each is an honest named refusal rather than a
//! silent no-op (`zero-tolerance.md` Rule 2):
//!
//! - [`SwapError::CrossSurface`] — the session and the slot are different
//!   surfaces (e.g. Anthropic <-> Codex). The running process cannot be moved
//!   across surfaces without being replaced.
//! - [`SwapError::ThirdPartySlot`] — either side pins `env.ANTHROPIC_BASE_URL`
//!   (3P/Ollama). Those variables are frozen at launch; an in-flight repoint
//!   would leave CC talking to the old endpoint with the new token
//!   (token exfiltration — see `RouteKind::ClaudeCodeEnvTransportExecReplace`).
//! - [`SwapError::UnsupportedSurface`] — a same-surface pair whose in-flight
//!   adoption csq has not characterised (Codex today: its auth-reload guard
//!   requires a matching `account_id`, and the supervisor handoff only covers a
//!   Codex->Codex relaunch inside the session).
//! - [`SwapError::DeadTarget`] / [`SwapError::UnverifiableTarget`] — the target
//!   process is gone, or the process at that pid is not the proved incarnation
//!   (a recycled pid, a changed exact start, an unreadable table).
//! - [`SwapError::InvalidHandleDir`] — the process's config dir is not a
//!   `term-<pid>` dir inside the csq accounts base.
//! - [`SwapError::SlotOutOfRange`] — the raw slot is outside `1..=MAX_ACCOUNTS`
//!   (see [`slot_from_wire`]; the typed [`AccountNum`] cannot carry one).
//! - [`SwapError::TargetNotReady`] — no account is provisioned for the slot.
//! - [`SwapError::LaunchBlocked`] — `accounts::launch_block` refused the target
//!   (a sign-in shared with another slot).
//! - [`SwapError::ClassNotAllowed`] — the owner has not enabled the `swap`
//!   class for the Telegram bridge. A swap is a credential-class action, so
//!   the bridge entry refuses by default; only the machine-terminal
//!   `csq telegram on --allow swap` can lift it, and no Telegram message can.
//!   The local `csq swap N --session <name>` path is not gated: a human at the
//!   machine is the authority there.
//! - [`SwapError::TargetSlotLoginNeeded`] — bridge-only, and only when the
//!   CALLER's daemon state says the target slot cannot authenticate. Swapping
//!   onto a dead login moves a working session onto a credential that will
//!   not refresh; the owner at the terminal may still choose it deliberately.

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use crate::accounts::discovery;
use crate::audit::op_emit;
use crate::audit::types::{AccountSwapPayload, EventKind, EventPayload, OpOutcome, RecordId};
use crate::cli_deps::sanitize::redact_path;
use crate::messaging::{Recipient, Surface as SessionSurface, VerifiedSession};
use crate::providers::catalog::Surface;
use crate::sessions::{CliKind, SessionInfo, Undetermined};
use crate::types::AccountNum;

use super::handle_dir;

// ─── Public outcome and refusals ─────────────────────────────────────

/// A completed same-surface ClaudeCode swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapOutcome {
    /// The account the handle dir was bound to when the swap started (read from
    /// the target's own `.csq-account` marker, never from the caller).
    pub from: AccountNum,
    /// The account the handle dir's marker resolves to after the swap. Equal to
    /// the requested slot on success; reported from the marker (the authority),
    /// never merely echoed from the request.
    pub account: AccountNum,
}

/// Which side of a remote swap a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapSide {
    /// The account the target session is bound to today.
    Source,
    /// The account the caller asked to switch to.
    Target,
}

/// Why a remote swap did not run (or did not complete).
///
/// Every variant is a NAMED refusal: [`Self::code`] is the fixed vocabulary a
/// caller (the daemon's bridge reply) may log or forward, and `Display` is the
/// operator-facing line. The variants carrying `&'static str`/`String` never
/// contain a credential, a token or a keychain payload
/// (`security.md` MUST-2).
#[derive(Debug)]
pub enum SwapError {
    /// The target session's process is gone.
    DeadTarget {
        /// The pid the caller named.
        pid: u32,
    },
    /// The process at `pid` is not the proved session: a recycled pid, a
    /// changed exact start, an unreadable process table, or a handle dir that
    /// cannot be read.
    UnverifiableTarget {
        /// The pid the caller named.
        pid: u32,
        /// Fixed reason tag, safe for logs.
        reason: &'static str,
    },
    /// The target process's config dir is not a `term-<pid>` dir inside the csq
    /// accounts base.
    InvalidHandleDir {
        /// Fixed reason tag, safe for logs.
        reason: &'static str,
    },
    /// The session and the slot are on different surfaces.
    CrossSurface {
        /// The target session's surface.
        source: Surface,
        /// The requested slot's surface.
        target: Surface,
    },
    /// A slot that freezes its provider env at launch (3P / Ollama).
    ThirdPartySlot {
        /// Which side is env-transport.
        side: SwapSide,
        /// The env-transport slot.
        slot: AccountNum,
    },
    /// Same surface, but this surface has no remote in-flight swap path.
    UnsupportedSurface {
        /// The session's surface.
        surface: Surface,
    },
    /// No account is provisioned for the requested slot.
    TargetNotReady {
        /// The requested slot.
        slot: AccountNum,
    },
    /// The raw slot number is outside `1..=MAX_ACCOUNTS`.
    SlotOutOfRange {
        /// The rejected raw number.
        slot: u16,
    },
    /// `accounts::launch_block` refused the target slot (shared sign-in).
    LaunchBlocked {
        /// The launch block's operator line.
        message: String,
    },
    /// The owner has not enabled this command class for the Telegram bridge.
    /// A swap moves credentials, so it is a class the owner must lift AT THE
    /// TERMINAL (`csq telegram on --allow swap`); it is off by default and no
    /// Telegram message can enable it.
    ClassNotAllowed {
        /// The class name (`swap`).
        class: &'static str,
    },
    /// The target slot is known to be unable to authenticate (its credential
    /// refresh is failing). Moving a live session onto it would bind the
    /// session to a dead credential. Bridge-only: the owner at the terminal
    /// may still choose it deliberately.
    TargetSlotLoginNeeded {
        /// The requested slot.
        slot: AccountNum,
    },
    /// The shared swap path itself failed; this carries its operator line and
    /// causal chain unchanged.
    Failed(anyhow::Error),
}

impl SwapError {
    /// The fixed error-kind tag for logs and bridge replies. Never a path, a
    /// token or an upstream body.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DeadTarget { .. } => "swap_target_dead",
            Self::UnverifiableTarget { .. } => "swap_target_unverifiable",
            Self::InvalidHandleDir { .. } => "swap_handle_dir_invalid",
            Self::CrossSurface { .. } => "swap_cross_surface",
            Self::ThirdPartySlot { .. } => "swap_third_party_slot",
            Self::UnsupportedSurface { .. } => "swap_surface_unsupported",
            Self::TargetNotReady { .. } => "swap_target_not_ready",
            Self::SlotOutOfRange { .. } => "swap_slot_out_of_range",
            Self::LaunchBlocked { .. } => "swap_launch_blocked",
            Self::ClassNotAllowed { .. } => "class_not_allowed",
            Self::TargetSlotLoginNeeded { .. } => "target_slot_login_needed",
            Self::Failed(_) => "swap_failed",
        }
    }
}

impl std::fmt::Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeadTarget { pid } => write!(
                f,
                "csq swap: session {pid} is no longer running; nothing changed"
            ),
            Self::UnverifiableTarget { pid, reason } => write!(
                f,
                "csq swap: session {pid} could not be verified ({reason}); nothing changed"
            ),
            Self::InvalidHandleDir { reason } => {
                write!(f, "csq swap: {reason}; nothing changed")
            }
            Self::CrossSurface { source, target } => write!(
                f,
                "csq swap: {source} -> {target} is a cross-surface swap; it needs a restart \
                 INSIDE the session, so it cannot be driven remotely — nothing changed"
            ),
            Self::ThirdPartySlot { side, slot } => {
                let side = match side {
                    SwapSide::Source => "the session's current slot",
                    SwapSide::Target => "the requested slot",
                };
                write!(
                    f,
                    "csq swap: {side} {slot} is a third-party (env-pinned) slot; its \
                     ANTHROPIC_BASE_URL is frozen at launch, so a swap needs a restart \
                     INSIDE the session — nothing changed"
                )
            }
            Self::UnsupportedSurface { surface } => write!(
                f,
                "csq swap: a {surface} session has no remote in-flight swap path; swap it \
                 from inside the session — nothing changed"
            ),
            Self::TargetNotReady { slot } => write!(
                f,
                "account {slot} not found — run `csq login {slot}` first, or check \
                 `csq status` for available accounts"
            ),
            Self::SlotOutOfRange { slot } => write!(
                f,
                "csq swap: slot {slot} is out of range (1..={}); nothing changed",
                crate::types::MAX_ACCOUNTS
            ),
            Self::LaunchBlocked { message } => f.write_str(message),
            Self::ClassNotAllowed { class } => write!(
                f,
                "csq swap: the `{class}` command class is not enabled for Telegram; run \
                 `csq telegram on --allow {class}` at the machine's terminal to allow it — \
                 nothing changed"
            ),
            Self::TargetSlotLoginNeeded { slot } => write!(
                f,
                "csq swap: account {slot} cannot authenticate (its credential refresh is \
                 failing), so a swap onto it would bind the session to a dead login; run \
                 `csq login {slot}` at the machine, or choose another slot — nothing changed"
            ),
            Self::Failed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SwapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => {
                let inner: &(dyn std::error::Error + Send + Sync + 'static) = error.as_ref();
                inner.source()
            }
            _ => None,
        }
    }
}

/// Parse a raw slot number from a command or wire payload into the validated
/// [`AccountNum`], naming the refusal. The CLI's plain `csq swap` keeps its own
/// `invalid account:` path; the named-session form and the bridge use this.
pub fn slot_from_wire(raw: u16) -> std::result::Result<AccountNum, SwapError> {
    AccountNum::try_from(raw).map_err(|_| SwapError::SlotOutOfRange { slot: raw })
}

// ─── Remote entry points ─────────────────────────────────────────────

/// Swap the account of the session `target` was proved to be, to `slot`.
///
/// The handle dir is resolved from the LIVE process at `target`'s `(pid,
/// started_at)` through the existing session resolver, and the resolved path is
/// bound to the hash the resolver captured — a directory name is never parsed
/// for identity (`account-terminal-separation.md` MUST NOT Rule 3).
///
/// # Errors
///
/// Every refusal in [`SwapError`]; nothing is written before the refusal point.
pub fn swap_session(
    base_dir: &Path,
    target: &VerifiedSession,
    slot: AccountNum,
) -> std::result::Result<SwapOutcome, SwapError> {
    let recipient = target.as_recipient();
    swap_session_inner(
        base_dir,
        &recipient,
        slot,
        Some(target.handle_dir_hash()),
        &crate::sessions::session_info_exact_for_pid_kind,
    )
}

/// [`swap_session`] for a caller that resolved the target through the shared
/// name/pair resolver and holds only the public [`Recipient`] — the LOCAL
/// terminal path (`csq swap N --session <name>`). The recipient is re-verified
/// against the live process table here, so a stale or fabricated recipient is
/// refused, never acted on.
///
/// **The Telegram bridge MUST NOT call this entry** — it has no class gate.
/// Bridge callers use [`swap_session_from_bridge`], which enforces the
/// owner-granted class allow-list before reaching this function.
///
/// # Keychain scope
///
/// The CALLER owns the `security` timeout scope: `csq swap --session` wraps this
/// in `with_interactive_keychain` (a human is at that terminal); the daemon
/// bridge must NOT (a remote request cannot answer a macOS password dialog, so
/// the 5 s non-interactive bound and its refusal are the honest outcome).
///
/// # Errors
///
/// As [`swap_session`]; plus the handle-dir identity cross-check is skipped
/// because a `Recipient` carries no resolver hash (the swap still binds to the
/// path the live process itself reports, re-read under the start-time check).
pub fn swap_session_for_recipient(
    base_dir: &Path,
    target: &Recipient,
    slot: AccountNum,
) -> std::result::Result<SwapOutcome, SwapError> {
    swap_session_inner(
        base_dir,
        target,
        slot,
        None,
        &crate::sessions::session_info_exact_for_pid_kind,
    )
}

/// Alias of the ONE shared class literal ([`crate::bridge::config::SWAP_CLASS`]).
/// A swap moves credentials, so it is a class the owner must lift at the
/// terminal; see [`swap_session_from_bridge`]. Never re-state the literal here:
/// two independent strings for one credential-class gate could drift, silently
/// disabling or wrongly enabling the gate.
const SWAP_BRIDGE_CLASS: &str = crate::bridge::config::SWAP_CLASS;

/// The bridge's permission + target-state gate, shared by BOTH bridge entry
/// points below so the two can never drift. Runs before any handle-dir
/// resolution, credential read or write.
fn bridge_swap_gate(
    allow_classes: &[String],
    slot: AccountNum,
    target_login_dead: bool,
) -> std::result::Result<(), SwapError> {
    if !allow_classes.iter().any(|class| class == SWAP_BRIDGE_CLASS) {
        return Err(SwapError::ClassNotAllowed {
            class: SWAP_BRIDGE_CLASS,
        });
    }
    if target_login_dead {
        return Err(SwapError::TargetSlotLoginNeeded { slot });
    }
    Ok(())
}

/// [`swap_session_from_bridge`] for a caller holding the public [`Recipient`] —
/// what the daemon's dispatcher has after name/pair resolution. Same gate, same
/// behaviour; the target is re-verified against the live process table.
///
/// # Errors
///
/// [`SwapError::ClassNotAllowed`] / [`SwapError::TargetSlotLoginNeeded`] from
/// the gate; otherwise as [`swap_session_for_recipient`].
pub fn swap_session_from_bridge_for_recipient(
    base_dir: &Path,
    target: &Recipient,
    slot: AccountNum,
    allow_classes: &[String],
    target_login_dead: bool,
) -> std::result::Result<SwapOutcome, SwapError> {
    bridge_swap_gate(allow_classes, slot, target_login_dead)?;
    swap_session_for_recipient(base_dir, target, slot)
}

/// The TELEGRAM bridge's swap entry: gated by the owner-granted class
/// allow-list AND by the target slot's login state.
///
/// `allow_classes` MUST be the value the owner stored locally
/// (`BridgeConfig::allow_classes`, written only by the machine-terminal
/// `csq telegram on --allow swap` command and default-empty). The ingress never
/// parses a class out of message text, so Telegram text can never flip its own
/// permission: an empty or unrelated list is refused here with
/// [`SwapError::ClassNotAllowed`] BEFORE any handle-dir resolution, credential
/// read or write.
///
/// `target_login_dead` is the CALLER's daemon-state verdict for the target slot
/// (a broker-failed sentinel / refresh cooldown). Swapping a live session onto
/// a slot whose credential cannot authenticate would bind the session to a dead
/// login, so it is refused with [`SwapError::TargetSlotLoginNeeded`]. csq-core
/// takes no daemon dependency for this: the caller computes the fact and passes
/// it, which also makes the refusal directly unit-testable.
///
/// The LOCAL terminal path (`csq swap N --session <name>`) calls
/// [`swap_session_for_recipient`] directly: a human at the machine is the
/// authority, may deliberately choose a slot the daemon cannot refresh, and the
/// gate exists for the remote surface only.
///
/// # Errors
///
/// [`SwapError::ClassNotAllowed`] / [`SwapError::TargetSlotLoginNeeded`] from
/// the gate; otherwise as [`swap_session`].
pub fn swap_session_from_bridge(
    base_dir: &Path,
    target: &VerifiedSession,
    slot: AccountNum,
    allow_classes: &[String],
    target_login_dead: bool,
) -> std::result::Result<SwapOutcome, SwapError> {
    bridge_swap_gate(allow_classes, slot, target_login_dead)?;
    swap_session_inner(
        base_dir,
        &target.as_recipient(),
        slot,
        Some(target.handle_dir_hash()),
        &crate::sessions::session_info_exact_for_pid_kind,
    )
}

/// The exact-start probe the remote path is driven by, injectable so every
/// refusal class is testable without owning a live stub `claude` process.
type ExactStartLookup<'a> =
    &'a dyn Fn(CliKind, u32) -> std::result::Result<Option<(SessionInfo, u64)>, Undetermined>;

fn swap_session_inner(
    base_dir: &Path,
    target: &Recipient,
    slot: AccountNum,
    expected_handle_hash: Option<&str>,
    exact_lookup: ExactStartLookup<'_>,
) -> std::result::Result<SwapOutcome, SwapError> {
    // Same first statement as the CLI's own path: a shared sign-in is refused
    // before any credential, marker or symlink operation.
    crate::accounts::launch_block::check_launch(base_dir, slot.get())
        .map_err(|message| SwapError::LaunchBlocked { message })?;

    let handle_dir =
        resolve_target_handle_dir(base_dir, target, expected_handle_hash, exact_lookup)?;

    // A session's wire surface (`csq.message.v1`) names one of the two CLIs; the
    // slot side uses the catalog's five-surface enum. Both name the same CLI for
    // a ClaudeCode/Codex session, so the comparison is made in the catalog type.
    let session_surface = catalog_surface(target.surface);
    let target_surface = discovery::discover_all(base_dir)
        .iter()
        .find(|account| account.id == slot.get())
        .map(|account| account.surface)
        .ok_or(SwapError::TargetNotReady { slot })?;
    if target_surface != session_surface {
        return Err(SwapError::CrossSurface {
            source: session_surface,
            target: target_surface,
        });
    }
    if target_surface != Surface::ClaudeCode {
        return Err(SwapError::UnsupportedSurface {
            surface: target_surface,
        });
    }

    // The source slot comes from the TARGET handle dir's own marker
    // (`resolve_marker_to_slot` accepts both the numeric and the UUID content a
    // writer may produce). An unreadable marker is a refusal, not an "unknown
    // that is probably fine": the CLI's fail-closed env-transport discriminator
    // turns exactly this state into exec-replace, which is unavailable here.
    let from_slot =
        read_slot_from_handle_dir(base_dir, &handle_dir).ok_or(SwapError::UnverifiableTarget {
            pid: target.pid,
            reason: "the session's account marker could not be read",
        })?;

    // 3P/env-transport on either side freezes the process env at launch.
    if crate::providers::settings::slot_pins_anthropic_base_url(base_dir, slot.get()) {
        return Err(SwapError::ThirdPartySlot {
            side: SwapSide::Target,
            slot,
        });
    }
    if crate::providers::settings::slot_pins_anthropic_base_url(base_dir, from_slot.get()) {
        return Err(SwapError::ThirdPartySlot {
            side: SwapSide::Source,
            slot: from_slot,
        });
    }

    // Resolved by the shared body at its own point in the sequence; the error is
    // re-wrapped (not cloned — `anyhow::Error` is not `Clone`) with the same
    // operator text.
    let claude_home = default_claude_home();
    same_surface_claude_code_swap(base_dir, &handle_dir, slot, Some(from_slot), &|| {
        match &claude_home {
            Ok(path) => Ok(path.clone()),
            Err(error) => Err(anyhow!("{error}")),
        }
    })
    .map(|account| SwapOutcome {
        from: from_slot,
        account,
    })
    .map_err(SwapError::Failed)
}

/// Resolves the handle dir of the session `target` names, from the live process
/// table, and refuses anything that is not a `term-<pid>` dir strictly inside
/// the accounts base. `expected_handle_hash` binds the resolved path to the hash
/// the §2.2 resolver captured for a [`VerifiedSession`] (SHA-256 of the
/// canonicalized handle dir); `None` for a plain [`Recipient`].
fn resolve_target_handle_dir(
    base_dir: &Path,
    target: &Recipient,
    expected_handle_hash: Option<&str>,
    exact_lookup: ExactStartLookup<'_>,
) -> std::result::Result<PathBuf, SwapError> {
    let kind = match target.surface {
        SessionSurface::ClaudeCode => CliKind::Claude,
        SessionSurface::Codex => CliKind::Codex,
    };
    let (info, exact_start) = match exact_lookup(kind, target.pid) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return Err(SwapError::DeadTarget { pid: target.pid });
        }
        Err(_) => {
            return Err(SwapError::UnverifiableTarget {
                pid: target.pid,
                reason: "the process table could not be read",
            });
        }
    };
    let listed_start = info.started_at.ok_or(SwapError::UnverifiableTarget {
        pid: target.pid,
        reason: "the process start time could not be read",
    })?;
    if !crate::sessions::same_start(listed_start, target.started_at) {
        return Err(SwapError::UnverifiableTarget {
            pid: target.pid,
            reason: "the pid now names a different process",
        });
    }
    if target
        .started_exact
        .is_some_and(|exact| exact != exact_start)
    {
        return Err(SwapError::UnverifiableTarget {
            pid: target.pid,
            reason: "the process incarnation changed",
        });
    }

    let base = std::fs::canonicalize(base_dir).map_err(|_| SwapError::InvalidHandleDir {
        reason: "swap_source_base_unavailable",
    })?;
    if !base.is_dir() {
        return Err(SwapError::InvalidHandleDir {
            reason: "swap_source_base_unavailable",
        });
    }
    let handle =
        std::fs::canonicalize(&info.config_dir).map_err(|_| SwapError::UnverifiableTarget {
            pid: target.pid,
            reason: "the session's config dir could not be resolved",
        })?;
    if !handle.is_dir() || !is_term_handle_dir(&handle) {
        return Err(SwapError::InvalidHandleDir {
            reason: "the session's config dir is not a csq handle dir",
        });
    }
    if handle == base || !handle.starts_with(&base) {
        return Err(SwapError::InvalidHandleDir {
            reason: "the session's handle dir is outside the csq accounts dir",
        });
    }
    if let Some(expected) = expected_handle_hash {
        let actual = handle_dir_hash(&handle);
        if actual != expected {
            return Err(SwapError::UnverifiableTarget {
                pid: target.pid,
                reason: "the session's handle dir changed since it was verified",
            });
        }
    }
    Ok(handle)
}

/// The catalog surface named by a session's wire surface. The two enums describe
/// the same CLI; the wire one is the closed two-variant set, the catalog one also
/// carries the launch-env surfaces a session can never be (`csq.message.v1` has no
/// such session). Exhaustive, no wildcard.
fn catalog_surface(surface: SessionSurface) -> Surface {
    match surface {
        SessionSurface::ClaudeCode => Surface::ClaudeCode,
        SessionSurface::Codex => Surface::Codex,
    }
}

/// SHA-256 (lowercase hex) of the canonicalized handle dir — exactly the value
/// the §2.2 session resolver stores as `handle_dir_hash`.
fn handle_dir_hash(handle_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(handle_dir.to_string_lossy().as_bytes())
    )
}

/// The `~/.claude` root a remote swap uses for shared-item materialization.
/// `CLAUDE_HOME` keeps the same override contract as the CLI's own path; a
/// non-absolute or empty override refuses rather than silently falling back.
fn default_claude_home() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("CLAUDE_HOME") {
        let path = PathBuf::from(&raw);
        if raw.is_empty() || !path.is_absolute() {
            return Err(anyhow!(
                "CLAUDE_HOME must be a non-empty absolute path (got {raw:?})"
            ));
        }
        return Ok(path);
    }
    crate::platform::home::home_dir()
        .map(|home| home.join(".claude"))
        .ok_or_else(|| anyhow!("could not determine home directory"))
}

// ─── The shared same-surface ClaudeCode body (lifted from the CLI) ───

/// Perform a same-surface ClaudeCode swap on `handle_dir`, which MUST already
/// be the validated `term-<pid>` handle dir of the session being swapped.
///
/// This is the ONE implementation shared by `csq swap` (the CLI passes the dir
/// it detected from its own environment) and [`swap_session`] (the remote path
/// passes the dir resolved from the verified target). It holds BOTH locks in the
/// existing order: the per-dir keychain-swap lock (`.swap-lock`) from before the
/// keychain force-write through the post-repoint reconcile, and — inside
/// `repoint_handle_dir_guarded` — the rename lock (`.swap.lock`) plus profiles
/// custody. Merging them self-deadlocks (flock is per open file description).
///
/// `claude_home` is a closure because the CLI resolves it at exactly that point
/// in the sequence (inside the audited region, immediately before the repoint);
/// calling it earlier would change where a `CLAUDE_HOME` failure lands.
///
/// Returns the account the handle dir's marker resolves to after the swap.
pub fn same_surface_claude_code_swap(
    base_dir: &Path,
    handle_dir: &Path,
    target: AccountNum,
    from_slot: Option<AccountNum>,
    claude_home: &dyn Fn() -> Result<PathBuf>,
) -> Result<AccountNum> {
    // M4-8 (Phase 4 an internal ticket): the only valid same-surface ClaudeCode swap
    // path is the handle-dir model. Both callers validate the source before
    // reaching here; this defensive check preserves a clear error if the
    // routing contract is ever broken from above.
    if !is_term_handle_dir(handle_dir) {
        return Err(anyhow!(
            "source dir is not a csq-managed handle dir: {}. \
             Relaunch with `csq run {target}` to use per-terminal swap.",
            redact_path(handle_dir)
        ));
    }

    // Capture the exact selected UUID and credential version. Legacy local
    // custody permits its own canonical bytes, never organization trust.
    let target_binding = crate::accounts::anthropic_identity::capture_anthropic_binding(
        base_dir, target,
    )
    .map_err(|error| {
        if error == crate::accounts::anthropic_identity::IdentityError::BindingBusy {
            anyhow::anyhow!("csq swap: identity_binding_busy; nothing changed — retry the swap")
        } else {
            anyhow::anyhow!(
                "csq swap: organization_identity_unconfirmed; run `csq login {target}` \
                         and retry the swap"
            )
        }
    })?;
    if matches!(
        target_binding.context(),
        crate::accounts::anthropic_identity::StoredAnthropicContext::LegacyUnknown
    ) {
        tracing::info!(
            error_kind = "swap_legacy_context_unconfirmed",
            account = target.get(),
            "swap uses only the selected legacy UUID's own canonical credentials; daemon organization verification remains pending"
        );
    }

    // A4a — close the daemon-custodian mid-swap race: hold the per-dir swap lock
    // so the custodian's harvest (which try-locks the same file) SKIPS this dir
    // until it settles. v4 A1: read and force-write the TARGET account's token
    // BEFORE the repoint, under the lock; chosen order: write X, then repoint.
    //
    // K5: an UNREADABLE X, or a write failure over a CONFIRMED-absent X
    // (F4/F8), means nothing was mutated and the switch does NOT proceed — the
    // `?` below returns before any repoint runs. A write failure over KNOWN
    // (`Content`) prior state (S4) leaves the disk state UNKNOWN —
    // `force_swap_write_before_repoint` passes that through as
    // `Ok(WriteFailedUnknown)` and this function proceeds exactly as for a
    // confirmed write. v5 ("keychain follows the links", 2026-09-26 owner
    // directive): `reconcile_keychain_to_marker` is the SOLE compensating action
    // for ANY downstream failure, run once the repoint's own outcome is known.
    // The three values the post-repoint reconciliation needs — the native
    // capture, the exact token this call attempted to write, and the handle
    // dir's absolute path for the keychain hint — are the block's own outputs,
    // so no path can leave them uninitialised while the guard is held.
    let (swap_native_capture, _swap_target_creds_for_reconcile, _swap_abs_for_hint, _swap_guard) = {
        let (abs, keychain_write_allowed) =
            crate::credentials::keychain::canonicalize_for_keychain_sync(handle_dir);
        if keychain_write_allowed {
            // round 7c D5: opportunistically harvest the SOURCE account's own
            // live keychain candidates via the D3 IPC route BEFORE taking the
            // per-dir lock. Best-effort; its only job is to give the decide()
            // call inside the force-write a chance to see a freshly-adopted
            // token first.
            if let Some(source_account) = from_slot {
                let sock = crate::daemon::socket_path(base_dir);
                let _ = crate::daemon::harvest_account(&sock, source_account.get());
            }
            use crate::credentials::keychain::BoundedLockOutcome;
            let guard = match crate::credentials::keychain::lock_handle_dir_for_swap_bounded(&abs) {
                BoundedLockOutcome::Acquired(g) => Some(g),
                BoundedLockOutcome::NotNeeded => None,
                BoundedLockOutcome::TimedOut | BoundedLockOutcome::Failed => {
                    anyhow::bail!(
                        "csq swap: the keychain is busy; nothing changed — retry the swap"
                    );
                }
            };
            // Preserve the complete source context under the existing swap lock
            // before selecting canonical target bytes or mutating the keychain.
            let native_capture =
                handle_dir::capture_native_swap(base_dir, &abs).map_err(|error| {
                    match profiles_busy_operator_line(Some(&error), "") {
                        Some(_) => anyhow::anyhow!(
                            "csq swap: profiles lock busy; nothing changed — retry the swap"
                        ),
                        None => anyhow::Error::from(error),
                    }
                })?;
            // Source the target's token via the shared helper so this and
            // `auto_rotate`'s tick can never drift apart on the resolver
            // (`guard-reader-writer-parity.md` MUST-1).
            let target_creds =
                crate::accounts::identity_store::target_token_for_forced_write(base_dir, target);
            // A target whose own canonical token is not Valid is refused BEFORE
            // any mutation — same rule `auto_rotate::find_target` enforces.
            if target_creds.as_valid_str().is_none() {
                anyhow::bail!(
                    "csq swap: account {target} has no valid login; nothing changed — \
                     run `csq login {target}` first"
                );
            }
            if let Err(msg) = crate::credentials::keychain::force_swap_write_before_repoint_guarded(
                base_dir,
                &abs,
                target_creds.as_valid_str(),
                &target_binding,
                &native_capture,
            ) {
                anyhow::bail!("csq swap: {msg}");
            }
            (native_capture, target_creds, abs, guard)
        } else {
            // F3/KC4-3: a canonicalize failure means we cannot even name the
            // handle dir's absolute path, so the "CC falls back to the symlinked
            // .credentials.json" claim does not follow. Refuse BEFORE any
            // repoint runs.
            anyhow::bail!(
                "csq swap: could not locate this terminal's keychain item; nothing changed — \
                 retry the swap"
            );
        }
    };

    // Audit INTENT, repoint, audit OUTCOME. The marker-absent case skips audit
    // and proceeds (pre-side-effect information unavailable — not fail-closed);
    // an INTENT that cannot be persisted aborts the side effect (F-LEDGER-02).
    let mut result: Result<()> = match begin_swap_audit(base_dir, from_slot, target)? {
        Some(ctx) => {
            let result = same_surface_claude_code_repoint(
                base_dir,
                handle_dir,
                target,
                &target_binding,
                &swap_native_capture,
                claude_home,
            );
            finish_swap_audit(base_dir, ctx, &result);
            result
        }
        None => same_surface_claude_code_repoint(
            base_dir,
            handle_dir,
            target,
            &target_binding,
            &swap_native_capture,
            claude_home,
        ),
    };

    // v5: the keychain side was written BEFORE the repoint above. The
    // compensating action runs on BOTH outcomes — an `Ok(())` repoint does not
    // prove the earlier force-write's mirror actually landed. It re-reads this
    // handle dir's `.csq-account` marker AS IT IS NOW (never a pre-write
    // snapshot) and makes the keychain agree with whatever account that marker
    // names (`guard-reader-writer-parity.md`).
    let forced_write = Some(crate::credentials::keychain::ForcedWriteAttempt {
        account: target,
        raw_json: _swap_target_creds_for_reconcile.as_valid_str(),
    });
    let reconcile_outcome = crate::credentials::keychain::reconcile_keychain_to_marker(
        base_dir,
        handle_dir,
        forced_write,
    );
    // B4: the account the switch STARTED from, passed as `Option` — falling
    // back to `target` would substitute the destination for "unknown start" and
    // make switched/not-switched a claim about the marker's value rather than an
    // honest statement about where this started.
    let reconcile_line = crate::credentials::keychain::reconcile_outcome_operator_line(
        &reconcile_outcome,
        from_slot,
    );
    let credential_error = result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<crate::error::CredentialError>());
    // K3: `repoint_handle_dir`'s S7 pre-flight refusal fires BEFORE any symlink
    // mutation — a real file blocks where an `ACCOUNT_BOUND_ITEMS` symlink
    // belongs — but the keychain WAS already force-written above, so it can
    // still disagree with the (unmoved) marker. Fold the reconcile outcome into
    // this message rather than reporting the blocked item alone.
    let refused_item = credential_error.and_then(|error| error.repoint_refused_item());
    // B3: the handle dir's OWN symlinks may be left mixed across two accounts by
    // a partially-rolled-back repoint — a signal independent of the reconcile.
    let mixed_links = credential_error.is_some_and(|error| {
        crate::credentials::keychain::repoint_left_mixed_links(error, base_dir, handle_dir)
    });
    // S-H-A/D-F1: a repoint `Ok(())` is NOT the final word — only
    // `AlreadyCurrent`/`Reconciled` mean the keychain genuinely agrees with the
    // marker now; every other outcome on an `Ok(())` repoint becomes a non-zero
    // exit carrying the reconcile line, so the operator is never told "Swapped"
    // while the keychain disagrees.
    let mut marker_account: Option<AccountNum> = None;
    if result.is_err() {
        let operator_line =
            if let Some(line) = profiles_busy_operator_line(credential_error, &reconcile_line) {
                line
            } else if let Some(item) = refused_item {
                crate::credentials::keychain::repoint_refused_real_file_operator_line(
                    item,
                    &reconcile_line,
                )
            } else if mixed_links {
                // C-F8: two independently-checked things, so the message folds
                // both in rather than picking one and silently discarding the
                // other.
                match reconcile_outcome.marker_account() {
                    Some(marker) => format!(
                        "{} {reconcile_line}",
                        crate::credentials::keychain::mixed_links_operator_line(marker)
                    ),
                    None => reconcile_line,
                }
            } else {
                reconcile_line
            };
        result = result.map_err(|error| error.context(operator_line));
    } else {
        match decide_ok_repoint_disposition(&reconcile_outcome, &reconcile_line) {
            OkRepointDisposition::Success {
                marker_account: account,
            } => {
                marker_account = Some(account);
            }
            OkRepointDisposition::Fail(message) => {
                result = Err(anyhow::anyhow!(message));
            }
        }
    }
    // KC4-2: record the hint ONLY now that the switch has actually succeeded,
    // and ONLY if the file is still absent — never on an abort path, and never
    // overwriting a value an earlier launch of this SAME handle dir recorded.
    if result.is_ok() {
        crate::credentials::keychain::record_keychain_account_hint_if_absent(&_swap_abs_for_hint);
    }
    // `_swap_guard` drops here.

    match (result, marker_account) {
        (Ok(()), Some(account)) => Ok(account),
        // Unreachable through `decide_ok_repoint_disposition` (its `Success` arm
        // is the only `Ok` producer and always names an account). Stated as an
        // internal inconsistency, never as "nothing changed" — the repoint has
        // already run at this point.
        (Ok(()), None) => Err(anyhow!(
            "csq swap: internal inconsistency — the repoint reported success \
             without a reconciled account; check `csq status` before retrying"
        )),
        (Err(error), _) => Err(error),
    }
}

/// The repoint step plus the cache refresh, run inside the audit INTENT/OUTCOME
/// wrapper. `claude_home` resolves here, exactly where the original CLI code
/// resolved it (after the keychain write and after the INTENT record).
fn same_surface_claude_code_repoint(
    base_dir: &Path,
    handle_dir: &Path,
    target: AccountNum,
    target_binding: &crate::accounts::anthropic_identity::CapturedBinding,
    native_capture: &handle_dir::NativeSwapCapture,
    claude_home: &dyn Fn() -> Result<PathBuf>,
) -> Result<()> {
    let claude_home = claude_home()?;
    crate::session::handle_dir::repoint_handle_dir_guarded(
        base_dir,
        &claude_home,
        handle_dir,
        target_binding,
        native_capture,
    )?;
    refresh_current_account_cache(base_dir, target);
    notify_daemon_cache_invalidation(base_dir);
    Ok(())
}

// ─── M13b audit helpers (shared with the CLI's Codex route) ─────────

/// The result of a successful [`begin_swap_audit`] call.
#[derive(Debug)]
pub struct SwapAuditContext {
    /// Audit chain the INTENT/OUTCOME pair belongs to.
    pub chain_id: String,
    /// Correlation id carried on both records.
    pub correlation_id: RecordId,
    /// The `AccountSwap` payload echoed onto the OUTCOME.
    pub payload: EventPayload,
}

/// Attempt to emit the INTENT record for a same-surface swap.
///
/// Returns:
/// - `Ok(Some(ctx))` — INTENT persisted; caller MUST call [`finish_swap_audit`]
///   after the side effect.
/// - `Ok(None)` — marker absent; audit skipped (pre-side-effect detection
///   failure is NOT fail-closed for same-surface swaps — swap proceeds).
/// - `Err(..)` — INTENT could not be persisted; caller MUST abort the side
///   effect (F-LEDGER-02 fail-closed contract).
pub fn begin_swap_audit(
    base_dir: &Path,
    from_slot: Option<AccountNum>,
    to_slot: AccountNum,
) -> Result<Option<SwapAuditContext>> {
    let from = match from_slot {
        Some(from) => from,
        None => {
            // Marker absent — skip audit gracefully. No INTENT emitted.
            return Ok(None);
        }
    };

    let chain_id = op_emit::load_chain_id(base_dir);
    let correlation_id =
        op_emit::gen_correlation_id().map_err(|error| anyhow!("audit correlation_id: {error}"))?;
    let payload = EventPayload::AccountSwap(AccountSwapPayload {
        from_slot: from,
        to_slot,
    });

    // FIX-1: Ok(true)=emitted → Ok(Some(ctx)); Ok(false)=chain-broken skip →
    // Ok(None) (swap proceeds without audit); Err=fail-closed.
    let intent_emitted = op_emit::emit_intent(
        base_dir,
        &chain_id,
        EventKind::AccountSwap,
        payload.clone(),
        correlation_id.clone(),
    )
    .map_err(|error| anyhow!("audit intent persist failed — swap aborted: {error}"))?;

    if !intent_emitted {
        // Chain broken — proceed without audit trail (same pattern as
        // marker-absent).
        return Ok(None);
    }

    Ok(Some(SwapAuditContext {
        chain_id,
        correlation_id,
        payload,
    }))
}

/// Emit the OUTCOME record. Best-effort — if this fails the intent is a visible
/// orphan detectable by `scan_orphan_intents`. The swap result is returned
/// unchanged. `e.to_string()` from `anyhow::Error` may contain paths from
/// underlying IO errors, so it is routed through `op_emit::redact_reason`.
pub fn finish_swap_audit(base_dir: &Path, ctx: SwapAuditContext, result: &Result<()>) {
    let outcome = match result {
        Ok(()) => OpOutcome::Ok,
        Err(error) => OpOutcome::Failed {
            reason: op_emit::redact_reason(error.to_string()),
        },
    };
    if let Err(error) = op_emit::emit_outcome(
        base_dir,
        &ctx.chain_id,
        EventKind::AccountSwap,
        ctx.payload,
        ctx.correlation_id,
        outcome,
    ) {
        // S-LOW-C: the swap itself already completed (or failed) by this point —
        // this OUTCOME write is best-effort audit trail, never a gate on the
        // operation. `fixed_tag()` is fixed vocabulary, never an upstream body
        // (`security.md` MUST-2).
        tracing::warn!(
            error_kind = "audit_outcome_emit_failed",
            op = "swap",
            audit_error_kind = error.fixed_tag(),
            "finish_swap_audit: failed to emit AccountSwap OUTCOME record \
             (op already completed; audit trail incomplete — the INTENT is \
             left as an orphan for scan_orphan_intents)"
        );
    }
}

// ─── Routing taxonomy (shared with the CLI's dispatcher) ────────────

/// Whether a RUNNING process of a given surface can adopt a credential change
/// made beneath it — a repointed symlink, a rewritten auth file — without being
/// replaced.
///
/// Declaring the capability HERE, exhaustively ([`in_flight_adoption`] has no
/// wildcard arm), makes a silent third instance impossible: a new [`Surface`]
/// variant fails to compile until its adoption rule is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightAdoption {
    /// Unconditionally re-reads/re-adopts the credential before every API call.
    /// **ClaudeCode**: CC re-stats `.credentials.json` before each API call path
    /// (`account-terminal-separation.md` Retracted Rule 7; spec 01 §1.4,
    /// `src/utils/auth.ts:1313-1336` / `:1453`). This does NOT cover an
    /// env-transport (3P/Ollama) swap, which is a SEPARATE axis — the process
    /// env vars are frozen at launch regardless of credential-file re-read
    /// capability, and `route()` checks that axis independently.
    Always,
    /// Adopts an in-flight change ONLY when an additional per-swap condition
    /// holds; otherwise the reload is REFUSED and the process keeps serving the
    /// OLD state. **Codex**: codex-cli's own auth-reload guard only accepts a
    /// reload when the new file's `tokens.account_id` matches the in-memory
    /// session's. Measured at RUNTIME on codex-cli 0.154.0:
    /// `codex_login::auth::manager: Skipping auth reload due to account id
    /// mismatch (expected: …, found: …)`. Silent at the LOG layer (the guard's
    /// line is INFO and default `exec`-mode logging is ERROR-only); the
    /// CONSEQUENCE reaches the terminal at ERROR on the next refresh attempt,
    /// misattributing the cause. The healthy-token silent window is UNDETERMINED
    /// (every synthetic token 401s). No override was found, within a BOUNDED
    /// search; an override under a name not guessed would not have been found.
    WhenSameAccountId,
    /// Freezes the relevant state at process launch; a running process can never
    /// adopt a change without being replaced. Not currently declared for any
    /// surface, but kept as a distinct variant from `Unknown` so a surface later
    /// PROVEN to never adopt is a decision, not a guess.
    #[allow(dead_code)] // no surface declares this today; kept for the taxonomy
    Never,
    /// Not established for this surface — its reload behavior has not been
    /// verified against the vendor CLI's source or observed behavior. Treated
    /// identically to `Never`: exec-replace is the fail-closed default for a
    /// capability nobody has characterised. Declaring a surface `Always` or
    /// `WhenSameAccountId` without the verification their doc comments cite is
    /// BLOCKED — an unverified "it probably re-reads" is exactly the bug this
    /// enum exists to close.
    Unknown,
}

/// Exhaustive per-surface [`InFlightAdoption`] declaration. **No wildcard
/// arm** — adding a [`Surface`] variant fails this match at compile time until
/// its adoption rule is declared here.
///
/// Gemini/Kimi/Grok are `Unknown`, NOT `Always` (see each arm's evidence).
pub fn in_flight_adoption(surface: Surface) -> InFlightAdoption {
    match surface {
        Surface::ClaudeCode => InFlightAdoption::Always,
        Surface::Codex => InFlightAdoption::WhenSameAccountId,
        // gemini-cli memoizes its OAuth client PER PROCESS and reads the
        // credential file exactly once, inside `initOauthClient`. Verified in the
        // shipped bundle (`@google/gemini-cli/bundle/chunk-Z7C7OBI2.js`): the
        // memo map is created at :245418, populated at :245615, and has exactly
        // TWO `clear()` sites — :245810 and :245848. The only live caller is
        // `clearCachedCredentialFile()` (gemini deleting its OWN creds during an
        // in-process logout); the other is test-only. Neither is reachable from
        // an external file change.
        Surface::Gemini => InFlightAdoption::Never,
        // No instrument discriminated. The binary is a Node single-executable, so
        // reload/watcher vocabulary returns Node's OWN runtime surface whether or
        // not kimi uses it; a window that read as proof of re-reading turned out,
        // at statement boundary, to be about `globalMcpOAuth` AND inverted in
        // polarity. `Unknown` is the honest verdict; Kimi exec-replaces
        // regardless via `SlotBinding::LaunchEnv`.
        Surface::Kimi => InFlightAdoption::Unknown,
        // Grok's credential STORE genuinely hot-reloads, on the vendor's own
        // compiled-in documentation; no codex-shape account-mismatch guard
        // exists. TRUE and, on its own, NOT SUFFICIENT: a Grok swap changes which
        // HOME the process is bound to, not what is inside the home — see
        // `SlotBinding::LaunchEnv`, which is what actually forces exec-replace.
        Surface::Grok => InFlightAdoption::Always,
    }
}

/// Is the RUNNING process's binding to a SLOT repointable in flight, or frozen
/// at launch? The SECOND axis, independent of [`InFlightAdoption`]: that one
/// asks whether a process adopts a change to the credential store it is bound
/// to; this asks whether csq can change WHICH store it is bound to at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotBinding {
    /// csq owns a symlink in the handle dir and repoints it. Changing the slot
    /// is a filesystem operation the running process can observe.
    HandleDirSymlink,
    /// The slot is carried by an environment variable set at spawn
    /// (`KIMI_CODE_HOME` / `GROK_HOME`) naming a per-slot vendor home. Frozen
    /// for the process lifetime; csq never reads or writes inside that home.
    LaunchEnv,
}

/// Exhaustive by construction, for the same reason [`in_flight_adoption`] is.
pub fn slot_binding(surface: Surface) -> SlotBinding {
    match surface {
        Surface::ClaudeCode => SlotBinding::HandleDirSymlink,
        Surface::Codex => SlotBinding::HandleDirSymlink,
        Surface::Gemini => SlotBinding::HandleDirSymlink,
        Surface::Kimi => SlotBinding::LaunchEnv,
        Surface::Grok => SlotBinding::LaunchEnv,
    }
}

/// Pure dispatch decision for the CLI's `swap` dispatcher. Any future refactor
/// MUST keep `route()` in lockstep — the `route_*` unit tests pin the matrix.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// Source + target both ClaudeCode AND both OAuth/Anthropic (neither pins
    /// `env.ANTHROPIC_BASE_URL`). In-flight symlink repoint; no exec, no
    /// tombstone — CC re-stats `.credentials.json` and picks up the new account
    /// on its next API call.
    SameSurfaceClaudeCode,
    /// Source + target both Codex, AND both sides' `tokens.account_id` match.
    /// In-flight symlink repoint via the Codex-aware mirror. No exec, no
    /// tombstone.
    SameSurfaceCodex,
    /// Source + target both Codex, but the codex `account_id` differs between
    /// them — OR either side's `account_id` could not be determined (fail-closed;
    /// an unknown id is treated as a mismatch, never as a match). MUST
    /// exec-replace so a fresh codex process reads the new account at startup.
    CodexAccountMismatchExecReplace,
    /// Both ClaudeCode, but at least ONE side is an env-transport slot (3P /
    /// Ollama — `settings.json` pins `env.ANTHROPIC_BASE_URL` +
    /// `env.ANTHROPIC_AUTH_TOKEN`). MUST exec-replace so a fresh CC reads the new
    /// settings.json env at startup (a 3P->Anthropic repoint would leave CC
    /// sending the freshly-repointed Anthropic OAuth token to the frozen 3P
    /// endpoint — token exfiltration; see `daemon::auto_rotate` VP-F1).
    ClaudeCodeEnvTransportExecReplace,
    /// Source + target are the SAME surface, but that surface's
    /// [`InFlightAdoption`] is `Never` or `Unknown` — Gemini/Kimi/Grok today.
    /// Exec-replace is the fail-closed default for a capability nobody has
    /// verified.
    SameSurfaceUnknownAdoptionExecReplace,
    /// Source ≠ target surface. INV-P05 confirm + INV-P10 tombstone + `exec` of
    /// the target binary.
    CrossSurface,
}

/// Pure routing decision.
///
/// The FIRST question is surface equality: `source != target` is always
/// [`RouteKind::CrossSurface`], unconditionally. For a same-surface pair, the
/// decision is driven by [`in_flight_adoption`] (exhaustive, no wildcard):
///
/// - `Always` (ClaudeCode): in-flight, UNLESS `source_env_transport` or
///   `target_env_transport` is set — a SEPARATE, per-swap axis (frozen process
///   env, not a credential-file-reload question).
/// - `WhenSameAccountId` (Codex): in-flight only when both `account_id`s are
///   `Some` and equal. Fail-closed: `(None, _)`, `(_, None)`, and a genuine
///   mismatch are ALL treated as "cannot adopt", never as a match.
/// - `Never` / `Unknown` (Gemini/Kimi/Grok today): always exec-replace.
pub fn route(
    source: Surface,
    target: Surface,
    source_env_transport: bool,
    target_env_transport: bool,
    source_codex_account_id: Option<&str>,
    target_codex_account_id: Option<&str>,
) -> RouteKind {
    if source != target {
        return RouteKind::CrossSurface;
    }
    // AXIS 2 FIRST, and before any arm that could return an in-flight kind. A
    // frozen process->slot binding makes the store axis moot. Checked here rather
    // than inside the `Always` arm so a future native surface carrying an account
    // id cannot slip through `WhenSameAccountId` and repeat the class.
    if slot_binding(source) == SlotBinding::LaunchEnv
        || slot_binding(target) == SlotBinding::LaunchEnv
    {
        return RouteKind::SameSurfaceUnknownAdoptionExecReplace;
    }

    match in_flight_adoption(source) {
        InFlightAdoption::Always => {
            if source_env_transport || target_env_transport {
                RouteKind::ClaudeCodeEnvTransportExecReplace
            } else {
                RouteKind::SameSurfaceClaudeCode
            }
        }
        InFlightAdoption::WhenSameAccountId => {
            match (source_codex_account_id, target_codex_account_id) {
                (Some(source_id), Some(target_id)) if source_id == target_id => {
                    RouteKind::SameSurfaceCodex
                }
                _ => RouteKind::CodexAccountMismatchExecReplace,
            }
        }
        InFlightAdoption::Never | InFlightAdoption::Unknown => {
            RouteKind::SameSurfaceUnknownAdoptionExecReplace
        }
    }
}

// ─── Shared primitive readers (moved from the CLI swap module) ──────

/// Read the slot number from a handle dir's `.csq-account` marker.
///
/// Returns `None` when the marker is absent or not resolvable to a slot. M4-7:
/// the marker's CONTENT is a UUID whenever a `by_slot` mapping exists, so this
/// resolves through `resolve_marker_to_slot` (numeric-or-UUID) rather than the
/// numeric-only `read_csq_account` — the latter returned `None` on every modern
/// slot, which silently dropped the `AccountSwap` audit record AND defeated the
/// `source_env_transport` exfiltration guard below
/// (`guard-reader-writer-parity.md`).
pub fn read_slot_from_handle_dir(base_dir: &Path, handle_dir_path: &Path) -> Option<AccountNum> {
    crate::accounts::markers::resolve_marker_to_slot(base_dir, handle_dir_path)
}

/// Resolves the source-side env-transport discriminator for the
/// `(ClaudeCode, ClaudeCode)` routing cell, FAIL-CLOSED.
///
/// `from_slot == None` means csq CANNOT determine whether the source is an
/// env-transport slot — it does NOT mean the source is Anthropic. Reporting
/// `false` in that case would let `route()` choose an in-flight repoint for a
/// source that might actually be 3P/Ollama, which is exactly the
/// Anthropic-OAuth-token-to-frozen-3P-endpoint exfiltration path. This function
/// fails CLOSED instead: an unresolved marker reports `true`, forcing the safer
/// exec-replace path.
pub fn resolve_source_env_transport(base_dir: &Path, from_slot: Option<AccountNum>) -> bool {
    from_slot
        .map(|slot| crate::providers::settings::slot_pins_anthropic_base_url(base_dir, slot.get()))
        .unwrap_or(true)
}

/// Reads slot `slot`'s Codex `tokens.account_id` for the `(Codex, Codex)`
/// routing-cell discriminator, via the SAME channel daemon production paths read
/// (`diagnostic-surface-parity.md` MUST NOT Rule 4).
///
/// Returns `None` when the slot has no UUID mapping AND no legacy mirror, when
/// the file cannot be parsed or is not Codex-shaped, or when `account_id` is
/// absent/empty. `None` is NOT "this account has no id" — it means UNKNOWN, and
/// `route()` MUST treat it as a mismatch (fail-closed), never as a match.
pub fn read_codex_account_id(base_dir: &Path, slot: AccountNum) -> Option<String> {
    let path = codex_canonical_auth_path(base_dir, slot);
    let credentials = crate::credentials::load(&path).ok()?;
    let account_id = credentials.codex()?.tokens.account_id.clone()?;
    if account_id.is_empty() {
        None
    } else {
        Some(account_id)
    }
}

/// The canonical Codex credential path: the identity-keyed file when a `by_slot`
/// UUID resolves, the legacy numeric mirror otherwise.
pub fn codex_canonical_auth_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    match crate::accounts::profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        Some(uuid) => crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid),
        None => crate::credentials::file::canonical_path_for(base_dir, slot, Surface::Codex),
    }
}

/// `true` when `path`'s file name starts with `term-` (a csq handle dir).
pub fn is_term_handle_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with("term-"))
        .unwrap_or(false)
}

/// N5: a held profiles lock is contention, not an identity problem — the
/// operator is told to retry, never to `csq login`. `None` for every other error.
///
/// Public so the CLI's swap tests pin the wording without duplicating it.
pub fn profiles_busy_operator_line(
    error: Option<&crate::error::CredentialError>,
    reconcile_line: &str,
) -> Option<String> {
    error.filter(|error| handle_dir::is_profiles_lock_busy(error)).map(|_| {
        format!(
            "csq swap: profiles lock busy; the repoint did not run — retry the swap. {reconcile_line}"
        )
    })
}

/// S-H-A/D-F1 decision seam: what a same-surface ClaudeCode swap's `Ok(())`
/// repoint should report, given the [`crate::credentials::keychain::ReconcileOutcome`]
/// that ran right after it — a PURE function so it is directly unit-testable
/// with a synthetic outcome, no `security` subprocess, no lock, no CLI harness.
#[derive(Debug, PartialEq, Eq)]
pub enum OkRepointDisposition {
    /// The keychain genuinely agrees with the marker now — report success naming
    /// the account the marker (not necessarily the originally-intended target)
    /// resolved to.
    Success { marker_account: AccountNum },
    /// The repoint itself succeeded, but the keychain did not confirm following
    /// it — report failure (non-zero exit) with the reconcile line as the
    /// message, rather than announcing a clean "Swapped".
    Fail(String),
}

pub fn decide_ok_repoint_disposition(
    reconcile_outcome: &crate::credentials::keychain::ReconcileOutcome,
    reconcile_line: &str,
) -> OkRepointDisposition {
    use crate::credentials::keychain::ReconcileOutcome;
    match reconcile_outcome {
        ReconcileOutcome::AlreadyCurrent { marker_account }
        | ReconcileOutcome::Reconciled { marker_account } => OkRepointDisposition::Success {
            marker_account: *marker_account,
        },
        ReconcileOutcome::MarkerUnreadable
        | ReconcileOutcome::WriteFailed { .. }
        | ReconcileOutcome::KeychainUnknown { .. } => {
            OkRepointDisposition::Fail(reconcile_line.to_string())
        }
    }
}

/// Refreshes the canonical `config-N/.current-account` cache after a swap
/// repoints a handle dir to slot N (INV-03b).
///
/// Writes the canonical `config-N` file directly (never the handle dir, whose
/// `.current-account` is a symlink into config-N). Non-fatal: snapshot's
/// authority-first self-heal is the structural backstop, so a failed write here
/// only delays the heal by one render.
pub fn refresh_current_account_cache(base_dir: &Path, target: AccountNum) {
    let config_dir = base_dir.join(format!("config-{}", target.get()));
    if config_dir.is_dir() {
        if let Err(error) = crate::accounts::markers::write_current_account(&config_dir, target) {
            tracing::debug!(
                error = %error,
                slot = target.get(),
                "swap: failed to refresh config-N/.current-account cache"
            );
        }
    }
}

/// Fire-and-forget daemon cache invalidation after a successful repoint.
pub fn notify_daemon_cache_invalidation(base_dir: &Path) {
    crate::daemon::notify::cache_invalidation(base_dir);
}

// The fixture commits real (synthetic) Anthropic logins through the production
// pipeline, which needs the in-memory vault (`test-utils` pulls it in, and the
// workspace sign-off runs every lib test with `csq-core/test-utils`). Unix only:
// the handle dir's account-bound items ARE symlinks.
#[cfg(all(test, unix, feature = "secret-in-memory"))]
mod tests {
    use super::*;
    use crate::accounts::anthropic_identity as ai;
    use crate::accounts::profiles;
    use crate::messaging::model::Sender;
    use crate::messaging::Surface as SessionSurface;
    use crate::platform::test_env;
    use std::os::unix::fs::symlink;

    const SOURCE_SLOT: u16 = 1;
    const TARGET_SLOT: u16 = 2;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// One hermetic Anthropic identity committed through the production login
    /// pipeline (two distinct complete contexts, so two distinct UUIDs).
    fn commit_identity(base: &Path, slot_num: u16, email_tag: &str, token_tag: &str) {
        let credential: crate::credentials::CredentialFile =
            serde_json::from_value(serde_json::json!({"claudeAiOauth": {
                "accessToken": format!("fixture-{token_tag}-access"),
                "refreshToken": format!("fixture-{token_tag}-refresh"),
                "expiresAt": 4102444800000_u64,
                "scopes": ["user:profile", "user:inference"]}}))
            .unwrap();
        let access = format!("fixture-{token_tag}-access");
        // Everything the responder needs is owned before the closure, so it
        // captures nothing borrowed (HttpGetFn is `+ 'static`).
        let account_uuid = format!("{slot_num:08x}-1111-4111-8111-111111111111");
        let organization_uuid = format!("{slot_num:08x}-2222-4222-8222-222222222222");
        let body = format!(
            r#"{{"account":{{"uuid":"{account_uuid}","email":"{email_tag}@test.invalid"}},"organization":{{"uuid":"{organization_uuid}"}}}}"#
        );
        let profile: crate::daemon::usage_poller::HttpGetFn =
            std::sync::Arc::new(move |_url: &str, token: &str, _headers: &[(&str, &str)]| {
                assert_eq!(token, access.as_str());
                Ok((200, body.clone().into_bytes()))
            });
        let prior = ai::capture_login_prior(base, slot(slot_num)).unwrap();
        ai::commit_anthropic_login_with(base, slot(slot_num), &credential, &profile, None, prior)
            .unwrap();
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        base: PathBuf,
        claude_home: PathBuf,
        target_handle: PathBuf,
        caller_handle: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let base = dir.path().to_path_buf();
            let claude_home = base.join("claude-home");
            std::fs::create_dir_all(&claude_home).unwrap();
            test_env::with_in_memory_secret_backend(|| {
                commit_identity(&base, SOURCE_SLOT, "source", "source");
                commit_identity(&base, TARGET_SLOT, "target", "target");
            });
            for n in [SOURCE_SLOT, TARGET_SLOT] {
                let config = base.join(format!("config-{n}"));
                std::fs::create_dir_all(&config).unwrap();
                let uuid = profiles::resolve_slot_to_uuid(&base, n).expect("fixture by_slot");
                crate::accounts::markers::write_csq_account(&config, uuid).unwrap();
            }
            let pid = std::process::id();
            let target_handle = base.join(format!("term-{pid}"));
            let caller_handle = base.join(format!("term-{}", pid + 1));
            for handle in [&target_handle, &caller_handle] {
                seed_handle(&base, handle, SOURCE_SLOT);
            }
            Self {
                _dir: dir,
                base,
                claude_home,
                target_handle,
                caller_handle,
            }
        }

        fn fake_session(&self, surface: SessionSurface) -> Recipient {
            let info = SessionInfo {
                pid: std::process::id(),
                cwd: self.base.clone(),
                config_dir: self.target_handle.clone(),
                account_id: None,
                started_at: Some(1_000),
                tty: None,
                term_window: None,
                term_tab: None,
                term_pane: None,
                iterm_profile: None,
                terminal_title: None,
            };
            Recipient {
                pid: info.pid,
                started_at: 1_000,
                surface,
                started_exact: Some(9_999),
            }
        }
    }

    fn seed_handle(base: &Path, handle: &Path, source_slot: u16) {
        std::fs::create_dir_all(handle).unwrap();
        let config = base.join(format!("config-{source_slot}"));
        let uuid = profiles::resolve_slot_to_uuid(base, source_slot).unwrap();
        symlink(config.join(".csq-account"), handle.join(".csq-account")).unwrap();
        symlink(
            crate::accounts::identity_store::credentials_path_for(base, uuid),
            handle.join(".credentials.json"),
        )
        .unwrap();
        symlink(
            config.join(".current-account"),
            handle.join(".current-account"),
        )
        .unwrap();
        symlink(config.join(".quota-cursor"), handle.join(".quota-cursor")).unwrap();
    }

    fn live_lookup(
        expect_pid: u32,
        config_dir: PathBuf,
    ) -> impl Fn(CliKind, u32) -> std::result::Result<Option<(SessionInfo, u64)>, Undetermined>
    {
        move |_kind, pid| {
            assert_eq!(
                pid, expect_pid,
                "the probe must be asked about the TARGET pid"
            );
            Ok(Some((
                SessionInfo {
                    pid,
                    cwd: PathBuf::from("/"),
                    config_dir: config_dir.clone(),
                    account_id: None,
                    started_at: Some(1_000),
                    tty: None,
                    term_window: None,
                    term_tab: None,
                    term_pane: None,
                    iterm_profile: None,
                    terminal_title: None,
                },
                9_999,
            )))
        }
    }

    /// THE core test: the swap acts on the TARGET session's handle dir and
    /// leaves the caller's own handle dir untouched. The caller's environment is
    /// pointed at `caller_handle`, so an implementation that reads
    /// `CLAUDE_CONFIG_DIR` (the caller) instead of the verified target REDs here.
    #[test]
    fn swaps_the_target_handle_dir_not_the_callers() {
        let fixture = Fixture::new();
        let _env = test_env::lock();
        let _caller_env = CallerEnvGuard::point_at(&fixture.caller_handle);

        let expected_pid = std::process::id();
        let target_handle = fixture.target_handle.clone();
        // The probe returns a SessionInfo whose config_dir IS the target handle.
        let lookup =
            move |_kind: CliKind,
                  pid: u32|
                  -> std::result::Result<Option<(SessionInfo, u64)>, Undetermined> {
                assert_eq!(pid, expected_pid);
                Ok(Some((
                    SessionInfo {
                        pid,
                        cwd: PathBuf::from("/"),
                        config_dir: target_handle.clone(),
                        account_id: None,
                        started_at: Some(1_000),
                        tty: None,
                        term_window: None,
                        term_tab: None,
                        term_pane: None,
                        iterm_profile: None,
                        terminal_title: None,
                    },
                    9_999,
                )))
            };
        let outcome = swap_session_inner(
            &fixture.base,
            &fixture.fake_session(SessionSurface::ClaudeCode),
            slot(TARGET_SLOT),
            None,
            &lookup,
        )
        .expect("the target session swaps");

        assert_eq!(
            outcome,
            SwapOutcome {
                from: slot(SOURCE_SLOT),
                account: slot(TARGET_SLOT)
            }
        );
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(TARGET_SLOT)),
            "the TARGET's marker must point at the new account"
        );
        let caller_marker =
            crate::accounts::markers::resolve_marker_to_slot(&fixture.base, &fixture.caller_handle);
        assert_eq!(
            caller_marker,
            Some(slot(SOURCE_SLOT)),
            "the CALLER's handle dir must be untouched"
        );
        // The real symlink content, not only the marker reader.
        let resolved = std::fs::read_link(fixture.caller_handle.join(".csq-account")).unwrap();
        assert!(
            resolved.starts_with(fixture.base.join(format!("config-{SOURCE_SLOT}"))),
            "caller's .csq-account link still points at the source config: {resolved:?}"
        );
        // The per-command audit record: ONE AccountSwap INTENT and its OUTCOME,
        // not a second kind and not just one half (an unpaired INTENT would be
        // an orphan).
        let swaps: Vec<String> = audit_records(&fixture.base)
            .into_iter()
            .filter(|line| line.contains("account_swap"))
            .collect();
        assert!(
            swaps.len() >= 2,
            "expected an AccountSwap INTENT and OUTCOME, got {}: {swaps:?}",
            swaps.len()
        );
        assert!(
            crate::audit::intent_scan::scan_orphan_intents(&fixture.base)
                .expect("the chain is readable")
                .is_empty(),
            "the INTENT must carry its correlated OUTCOME"
        );
    }

    /// Every committed op-chain record, as raw JSON lines. The chain is
    /// non-secret; this reads the same `csq-runs/*.jsonl` the verifier walks.
    fn audit_records(base: &Path) -> Vec<String> {
        let mut lines = Vec::new();
        let Ok(entries) = std::fs::read_dir(base.join("csq-runs")) else {
            return lines;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                lines.extend(
                    text.lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(str::to_string),
                );
            }
        }
        lines
    }

    /// Points this process's `CLAUDE_CONFIG_DIR` at `handle` for the duration of
    /// the test — the caller's own environment, which the swap MUST ignore. The
    /// drop restores absence so a panicking assertion cannot leak the fixture
    /// into another test in this binary.
    struct CallerEnvGuard;

    impl CallerEnvGuard {
        fn point_at(handle: &Path) -> Self {
            // SAFETY: the caller holds `test_env::lock()` for the whole test, so
            // no other test in this binary reads or writes the environment
            // concurrently; the guard removes the variable on drop.
            unsafe {
                std::env::set_var("CLAUDE_CONFIG_DIR", handle);
            }
            Self
        }
    }

    impl Drop for CallerEnvGuard {
        fn drop(&mut self) {
            // SAFETY: as above — the env mutex is still held by the test.
            unsafe {
                std::env::remove_var("CLAUDE_CONFIG_DIR");
            }
        }
    }

    #[test]
    fn dead_target_is_a_named_refusal_and_writes_nothing() {
        let fixture = Fixture::new();
        let dead =
            |_: CliKind, _: u32| -> std::result::Result<Option<(SessionInfo, u64)>, Undetermined> {
                Ok(None)
            };
        let error = swap_session_inner(
            &fixture.base,
            &fixture.fake_session(SessionSurface::ClaudeCode),
            slot(TARGET_SLOT),
            None,
            &dead,
        )
        .expect_err("a dead target must refuse");
        assert!(matches!(error, SwapError::DeadTarget { .. }), "{error}");
        assert_eq!(error.code(), "swap_target_dead");
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "a refusal writes nothing"
        );
    }

    #[test]
    fn unverifiable_target_is_a_named_refusal() {
        let fixture = Fixture::new();
        // The pid now names a different process: the listed start differs.
        let recycled = |_: CliKind,
                        pid: u32|
         -> std::result::Result<Option<(SessionInfo, u64)>, Undetermined> {
            Ok(Some((
                SessionInfo {
                    pid,
                    cwd: PathBuf::from("/"),
                    config_dir: fixture.target_handle.clone(),
                    account_id: None,
                    started_at: Some(2_000),
                    tty: None,
                    term_window: None,
                    term_tab: None,
                    term_pane: None,
                    iterm_profile: None,
                    terminal_title: None,
                },
                9_999,
            )))
        };
        let error = swap_session_inner(
            &fixture.base,
            &fixture.fake_session(SessionSurface::ClaudeCode),
            slot(TARGET_SLOT),
            None,
            &recycled,
        )
        .expect_err("a recycled pid must refuse");
        assert!(
            matches!(error, SwapError::UnverifiableTarget { .. }),
            "{error}"
        );
        assert_eq!(error.code(), "swap_target_unverifiable");
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "a refusal writes nothing"
        );
    }

    #[test]
    fn cross_surface_is_refused_with_its_reason() {
        let fixture = Fixture::new();
        let lookup = live_lookup(std::process::id(), fixture.target_handle.clone());
        // A Codex target slot does not exist in this fixture, so add the
        // surface check itself first: a ClaudeCode session naming a Codex
        // TARGET surface.
        let error = swap_session_inner(
            &fixture.base,
            &fixture.fake_session(SessionSurface::Codex),
            slot(TARGET_SLOT),
            None,
            &lookup,
        )
        .expect_err("a cross-surface pair must refuse");
        assert!(
            matches!(
                error,
                SwapError::CrossSurface {
                    source: Surface::Codex,
                    target: Surface::ClaudeCode
                }
            ),
            "{error}"
        );
        assert_eq!(error.code(), "swap_cross_surface");
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "a refusal writes nothing"
        );
    }

    #[test]
    fn third_party_slot_is_refused_with_its_reason() {
        let fixture = Fixture::new();
        // Bind slot 2 as a 3P slot: settings.json pins ANTHROPIC_BASE_URL.
        let config = fixture.base.join(format!("config-{TARGET_SLOT}"));
        std::fs::write(
            config.join("settings.json"),
            serde_json::json!({
                "env": {
                    "ANTHROPIC_BASE_URL": "https://example.invalid/api",
                    "ANTHROPIC_AUTH_TOKEN": "fixture-3p-token"
                }
            })
            .to_string(),
        )
        .unwrap();
        let lookup = live_lookup(std::process::id(), fixture.target_handle.clone());
        let error = swap_session_inner(
            &fixture.base,
            &fixture.fake_session(SessionSurface::ClaudeCode),
            slot(TARGET_SLOT),
            None,
            &lookup,
        )
        .expect_err("a 3P target must refuse");
        assert!(
            matches!(
                error,
                SwapError::ThirdPartySlot {
                    side: SwapSide::Target,
                    slot: _
                }
            ),
            "{error}"
        );
        assert_eq!(error.code(), "swap_third_party_slot");
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "a refusal writes nothing"
        );
    }

    /// The Telegram gate: default-off. An empty (or unrelated) allow-list
    /// refuses with the named reason BEFORE any handle-dir work, and echoes the
    /// terminal remedy. Mutation: drop the allow-list check in
    /// `swap_session_from_bridge` -> this test REDs (the call proceeds to the
    /// real resolver and reports DeadTarget instead).
    #[test]
    fn bridge_swap_is_refused_when_the_owner_has_not_enabled_the_class() {
        let fixture = Fixture::new();
        let recipient = fixture.fake_session(SessionSurface::ClaudeCode);
        let empty: Vec<String> = Vec::new();
        let unrelated = vec!["clear".to_string()];
        // Exact match only: no case folding and no prefix/substring acceptance
        // (the class vocabulary is closed, so a near-miss must never enable it).
        let wrong_case = vec!["SWAP".to_string()];
        let trailing_space = vec!["swap ".to_string()];
        for classes in [empty, unrelated, wrong_case, trailing_space] {
            let error = swap_session_from_bridge_for_recipient(
                &fixture.base,
                &recipient,
                slot(TARGET_SLOT),
                &classes,
                false,
            )
            .expect_err("a class the owner did not enable must refuse");
            assert!(
                matches!(
                    error,
                    SwapError::ClassNotAllowed {
                        class: SWAP_BRIDGE_CLASS
                    }
                ),
                "{error}"
            );
            assert_eq!(error.code(), "class_not_allowed");
            assert!(
                error.to_string().contains("csq telegram on --allow swap"),
                "the refusal must name the terminal remedy: {error}"
            );
            assert_eq!(
                read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
                Some(slot(SOURCE_SLOT)),
                "a gate refusal writes nothing"
            );
        }
    }

    /// Once the owner enables the class, the call reaches the real resolver —
    /// proving the gate opens rather than silently swallowing the command.
    #[test]
    fn bridge_swap_delegates_once_the_class_is_enabled() {
        let fixture = Fixture::new();
        let mut recipient = fixture.fake_session(SessionSurface::ClaudeCode);
        recipient.pid = 999_999; // no such session
        let error = swap_session_from_bridge_for_recipient(
            &fixture.base,
            &recipient,
            slot(TARGET_SLOT),
            &["swap".to_string()],
            false,
        )
        .expect_err("a dead target still refuses");
        assert!(
            matches!(error, SwapError::DeadTarget { .. }),
            "the enabled class must reach the resolver, got {error}"
        );
        assert_ne!(error.code(), "class_not_allowed");
    }

    /// Owner decision (an internal journal entry): a target slot the daemon already knows
    /// cannot authenticate must not receive a live session. Mutation: drop the
    /// `target_login_dead` check in `bridge_swap_gate` -> this test REDs.
    #[test]
    fn bridge_swap_refuses_a_login_dead_target_slot() {
        let fixture = Fixture::new();
        let recipient = fixture.fake_session(SessionSurface::ClaudeCode);
        let error = swap_session_from_bridge_for_recipient(
            &fixture.base,
            &recipient,
            slot(TARGET_SLOT),
            &["swap".to_string()],
            true,
        )
        .expect_err("a login-dead target slot must refuse");
        assert!(
            matches!(error, SwapError::TargetSlotLoginNeeded { .. }),
            "{error}"
        );
        assert_eq!(error.code(), "target_slot_login_needed");
        assert!(
            error.to_string().contains("csq login"),
            "the refusal must name the remedy: {error}"
        );
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "a login-dead refusal writes nothing"
        );
    }

    /// The requested `VerifiedSession` entry applies the SAME gate, permission
    /// first, then login state — both before any handle-dir or credential work.
    #[test]
    fn bridge_verified_entry_applies_the_gate_in_order() {
        let fixture = Fixture::new();
        let canonical = std::fs::canonicalize(&fixture.target_handle).unwrap();
        let sender = Sender {
            pid: std::process::id(),
            started_at: 1_000,
            surface: SessionSurface::ClaudeCode,
            handle_dir_hash: handle_dir_hash(&canonical),
            handle_dir: fixture.target_handle.to_string_lossy().into_owned(),
            name: None,
            started_exact: Some(9_999),
        };
        let verified = VerifiedSession::from_resolved(sender);
        let denied =
            swap_session_from_bridge(&fixture.base, &verified, slot(TARGET_SLOT), &[], true)
                .expect_err("the class gate runs first");
        assert!(
            matches!(denied, SwapError::ClassNotAllowed { .. }),
            "{denied}"
        );
        let dead = swap_session_from_bridge(
            &fixture.base,
            &verified,
            slot(TARGET_SLOT),
            &["swap".to_string()],
            true,
        )
        .expect_err("a login-dead slot refuses");
        assert!(
            matches!(dead, SwapError::TargetSlotLoginNeeded { .. }),
            "{dead}"
        );
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "gate refusals write nothing"
        );
    }

    #[test]
    fn slot_out_of_range_is_named() {
        let error = slot_from_wire(0).expect_err("slot 0 must refuse");
        assert!(matches!(error, SwapError::SlotOutOfRange { slot: 0 }));
        assert_eq!(error.code(), "swap_slot_out_of_range");
        assert!(slot_from_wire(1).is_ok());
    }

    /// The caller-own-dir path is unchanged: the CLI passes its own handle dir
    /// and the same body swaps exactly that dir.
    #[test]
    fn caller_own_dir_path_still_swaps_that_dir() {
        let fixture = Fixture::new();
        let outcome = same_surface_claude_code_swap(
            &fixture.base,
            &fixture.caller_handle,
            slot(TARGET_SLOT),
            Some(slot(SOURCE_SLOT)),
            &|| Ok(fixture.claude_home.clone()),
        )
        .expect("the caller's own handle dir swaps");
        assert_eq!(outcome, slot(TARGET_SLOT));
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.caller_handle),
            Some(slot(TARGET_SLOT))
        );
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(SOURCE_SLOT)),
            "the sibling handle dir is untouched"
        );
    }

    /// A `VerifiedSession` target binds the resolved path to the hash the
    /// resolver captured: a hash for a different dir is refused.
    #[test]
    fn verified_session_hash_mismatch_is_unverifiable() {
        let fixture = Fixture::new();
        let sender = Sender {
            pid: std::process::id(),
            started_at: 1_000,
            surface: SessionSurface::ClaudeCode,
            handle_dir_hash: "0".repeat(64),
            handle_dir: fixture.target_handle.to_string_lossy().into_owned(),
            name: None,
            started_exact: Some(9_999),
        };
        let verified = VerifiedSession::from_resolved(sender);
        let lookup = live_lookup(std::process::id(), fixture.target_handle.clone());
        let error = swap_session_inner(
            &fixture.base,
            &verified.as_recipient(),
            slot(TARGET_SLOT),
            Some(verified.handle_dir_hash()),
            &lookup,
        )
        .expect_err("a hash mismatch must refuse");
        assert!(
            matches!(error, SwapError::UnverifiableTarget { .. }),
            "{error}"
        );
    }

    /// The positive side of the hash binding: a `VerifiedSession` whose stored
    /// hash equals the resolver's convention for the resolved dir swaps. Proves
    /// the mismatch test above refuses for the HASH, not because every hash
    /// refuses.
    #[test]
    fn verified_session_matching_hash_swaps() {
        let fixture = Fixture::new();
        let canonical = std::fs::canonicalize(&fixture.target_handle).unwrap();
        let sender = Sender {
            pid: std::process::id(),
            started_at: 1_000,
            surface: SessionSurface::ClaudeCode,
            handle_dir_hash: handle_dir_hash(&canonical),
            handle_dir: fixture.target_handle.to_string_lossy().into_owned(),
            name: None,
            started_exact: Some(9_999),
        };
        let verified = VerifiedSession::from_resolved(sender);
        let lookup = live_lookup(std::process::id(), fixture.target_handle.clone());
        let outcome = swap_session_inner(
            &fixture.base,
            &verified.as_recipient(),
            slot(TARGET_SLOT),
            Some(verified.handle_dir_hash()),
            &lookup,
        )
        .expect("a matching handle hash swaps");
        assert_eq!(outcome.account, slot(TARGET_SLOT));
        assert_eq!(
            read_slot_from_handle_dir(&fixture.base, &fixture.target_handle),
            Some(slot(TARGET_SLOT))
        );
    }

    #[test]
    fn handle_dir_hash_matches_the_resolver_convention() {
        use sha2::{Digest, Sha256};
        let dir = PathBuf::from("/tmp/term-1");
        let expected = format!("{:x}", Sha256::digest(dir.to_string_lossy().as_bytes()));
        assert_eq!(handle_dir_hash(&dir), expected);
    }
}
