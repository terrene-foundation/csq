//! `csq swap N` — swap the active account in the current terminal.
//!
//! # Three paths
//!
//! 1. **Same-surface ClaudeCode** (source + target both Anthropic or
//!    3P) — atomic symlink repoint in `term-<pid>`. CC re-reads on
//!    next API call. In-flight swap, no process restart.
//! 2. **Same-surface Codex** (source + target both Codex, AND the
//!    running codex process's `tokens.account_id` matches the
//!    target's) — atomic symlink repoint in `term-<pid>` via the
//!    Codex-aware mirror `repoint_handle_dir_codex` (spec 07 §7.2.2
//!    symlink set). codex-cli re-stats `auth.json` before each API
//!    call so the next request resolves through the new symlink;
//!    UNIX open-after-rename keeps in-flight session fds valid until
//!    close. Resolves M10 / an internal journal entry — the pre-PR-C9a behavior
//!    was to take the exec-replace path, which silently dropped the
//!    user's conversation.
//!
//!    **A cross-ACCOUNT codex→codex swap can never be in-flight.**
//!    codex-cli's own auth-reload guard only accepts a reload when
//!    the new file's `account_id` matches the in-memory session's
//!    (measured at RUNTIME on codex-cli 0.154.0: "Skipping auth reload
//!    due to account id mismatch (expected: …, found: …)" — the
//!    binary's string table truncates this literal at `(expected: `, so
//!    its tail is only observable at runtime). A same-surface repoint
//!    across accounts therefore keeps the OLD account live while csq
//!    reports success. That refusal is not silent to the user — the
//!    guard's own line is INFO and suppressed at default logging, but
//!    the next refresh attempt surfaces an ERROR-level message that
//!    misattributes the cause, and whether the window before it is
//!    silent for a still-VALID token is UNDETERMINED (see
//!    `InFlightAdoption::WhenSameAccountId`). No override was found
//!    among CLI flags, `CODEX_*` env names, slash commands, or 7 probed
//!    config keys — a bounded search, not a proof of universality.
//!    `route()` detects this by comparing
//!    `tokens.account_id` on both sides and forces the exec-replace
//!    path below whenever they differ or either is unreadable
//!    (fail-closed — see `RouteKind::CodexAccountMismatchExecReplace`).
//! 3. **Cross-surface** (source ≠ target surface), **or same-surface
//!    ClaudeCode env-transport, or same-surface Codex account
//!    mismatch** — INV-P05 requires prompt-and-confirm (`--yes`
//!    bypasses; env-transport/account-mismatch skip the prompt, see
//!    `exec_replace_swap`), then INV-P10 requires renaming the source
//!    handle dir to a sweep tombstone BEFORE `exec`ing the target
//!    binary. The tombstone is what makes the transfer question real:
//!    no in-flight session state transfers, and a resume is ATTEMPTED on
//!    the fresh process whenever the TARGET surface is ClaudeCode or
//!    Codex (`--continue` / `resume --last`) — cross-surface included —
//!    and not attempted for Gemini/Kimi/Grok. Whether that attempt
//!    succeeds is UNVERIFIED; see `exec_replace_swap`.
//!
//! # Legacy mode retirement (M4-8, Phase 4 an internal ticket)
//!
//! The pre-handle-dir `CLAUDE_CONFIG_DIR=config-<N>` swap mode is
//! **fully retired**. If `CLAUDE_CONFIG_DIR` points at a `config-<N>`
//! dir, `csq swap` refuses with the spec 02 §2.6 error directing the
//! user to relaunch with `csq run N`. The previous credential-copy
//! fallback through `rotation::swap_to` was deleted with the
//! `csq-core::rotation::swap` module — there is no longer any
//! production code path that writes credentials directly into
//! `config-<N>/.credentials.json` from a swap operation.

use anyhow::{anyhow, Result};
use csq_core::accounts::discovery;
use csq_core::audit::op_emit;
use csq_core::audit::types::{AccountSwapPayload, EventKind, EventPayload, OpOutcome, RecordId};
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::providers::catalog::Surface;
#[cfg(unix)]
use csq_core::providers::codex::surface as codex_surface;
use csq_core::providers::native;
#[cfg(unix)]
use csq_core::session::codex_supervisor as sup;
use csq_core::session::handle_dir;
use csq_core::types::AccountNum;
use std::path::{Path, PathBuf};

/// One of the three env vars a csq-managed terminal sets pointing at
/// its handle dir. Which one is set tells us the source surface
/// without any on-disk introspection.
#[derive(Debug)]
enum SourceHandle {
    /// `CLAUDE_CONFIG_DIR` set → source is ClaudeCode (Anthropic or 3P).
    ClaudeCode(PathBuf),
    /// `CODEX_HOME` set → source is Codex.
    Codex(PathBuf),
    /// `GEMINI_CLI_HOME` set → source is Gemini. PR-G4b: gemini-cli
    /// does not re-read `GEMINI_API_KEY` mid-process, so even
    /// same-surface Gemini→Gemini takes the exec-replace path
    /// (handled via `RouteKind::CrossSurface` below).
    Gemini(PathBuf),
}

impl SourceHandle {
    fn path(&self) -> &Path {
        match self {
            Self::ClaudeCode(p) | Self::Codex(p) | Self::Gemini(p) => p,
        }
    }

    fn surface(&self) -> Surface {
        match self {
            Self::ClaudeCode(_) => Surface::ClaudeCode,
            Self::Codex(_) => Surface::Codex,
            Self::Gemini(_) => Surface::Gemini,
        }
    }
}

/// Whether a RUNNING process of a given surface can adopt a credential
/// change made beneath it — a repointed symlink, a rewritten auth file —
/// without being replaced.
///
/// This is the root-cause fix for a recurring failure shape: `route()`
/// used to encode "can this surface adopt in-flight?" implicitly, per
/// surface-pair cell, and got the DEFAULT backwards — every surface not
/// given an explicit arm fell through a wildcard to `RouteKind::CrossSurface`
/// (which happens to be safe — exec-replace — but by accident, and its own
/// doc comment claimed "Source ≠ target surface", which was FALSE for a
/// same-surface pair landing there). Twice now a surface has shipped with
/// an assumed capability that broke in production before anyone added an
/// explicit arm: ClaudeCode env-transport (an accepted-risk incident), then
/// Codex account-id (this fix). Declaring the capability HERE, exhaustively
/// (see [`in_flight_adoption`] — no wildcard arm), makes a THIRD silent
/// instance impossible: a new [`Surface`] variant fails to compile until
/// its adoption rule is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightAdoption {
    /// Unconditionally re-reads/re-adopts the credential before every API
    /// call — no vendor-side guard blocks a same-account in-flight change.
    /// **ClaudeCode**: CC re-stats `.credentials.json` before each API call
    /// path (`account-terminal-separation.md` Retracted Rule 7; spec 01
    /// §1.4, `src/utils/auth.ts:1313-1336` / `:1453`). This does NOT cover
    /// an env-transport (3P/Ollama) swap, which is a SEPARATE axis — the
    /// process env vars (`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`) are
    /// frozen at launch regardless of credential-file re-read capability,
    /// and `route()` checks that axis independently via
    /// `source_env_transport` / `target_env_transport`.
    Always,
    /// Adopts an in-flight change ONLY when an additional per-swap
    /// condition holds; otherwise the reload is REFUSED and the process
    /// keeps serving the OLD state. **Codex**: codex-cli's own
    /// auth-reload guard only accepts a reload when the new file's
    /// `tokens.account_id` matches the in-memory session's. Measured at
    /// RUNTIME on codex-cli 0.154.0 — the mismatch literal is quoted
    /// from the runtime line, not from `strings`, because the binary's
    /// string table truncates it at `(expected: `:
    /// `codex_login::auth::manager: Skipping auth reload due to account
    /// id mismatch (expected: …, found: …)`. (The sibling literal
    /// "Skipping auth reload because no account id is available." ends at
    /// its sentence-final period in the string table, so it is not
    /// truncated the way the mismatch literal is.) Both account ids are
    /// printed verbatim — opaque identifiers, a mild log disclosure, not
    /// a credential leak.
    ///
    /// **Silent at the LOG layer, not silent to the user.** The guard's
    /// own line is INFO and default `exec`-mode logging is ERROR-only
    /// (measured: 0 guard lines without `RUST_LOG`, 19 with; no durable
    /// capture either — no `$CODEX_HOME/log/` directory, 0 rows in
    /// `logs_2.sqlite`). The CONSEQUENCE reaches the terminal at ERROR
    /// on the next refresh attempt: "Your access token could not be
    /// refreshed because you have since logged out or signed in to
    /// another account. Please sign in again." That message
    /// MISATTRIBUTES the cause — it describes user action for what is an
    /// external credential repoint, and "sign in again" does not
    /// resolve it.
    ///
    /// **UNDETERMINED — the healthy-token window.** Every synthetic
    /// token 401s, forcing the refresh path, so whether a session whose
    /// token stays VALID ever re-reads `auth.json` — and therefore
    /// whether a repoint is silent until the first refresh need — is NOT
    /// measured (it requires real credentials). The silent window is
    /// bounded by token LIFETIME, not by the guard. Evidence:
    /// `internal-design-docs`.
    ///
    /// **No override found**, within a BOUNDED search: CLI flags, ~40
    /// `CODEX_*` env names, slash commands, and 7 candidate config keys
    /// (all rejected by `--strict-config`, whose discriminating power was
    /// validated by a positive control accepted in the same run). An
    /// override under a name not guessed would not have been found.
    WhenSameAccountId,
    /// Freezes the relevant state at process launch; a running process can
    /// never adopt a change without being replaced. Not currently declared
    /// for any surface (ClaudeCode's env-transport freeze is a per-swap
    /// axis, not a per-surface one — see `Always`'s doc), but kept as a
    /// distinct variant from `Unknown` so a surface later PROVEN to never
    /// adopt is a decision, not a guess.
    #[allow(dead_code)]
    // no surface declares this today; kept for the taxonomy (see doc above)
    Never,
    /// Not established for this surface — its reload behavior has not been
    /// verified against the vendor CLI's source or observed behavior.
    /// Treated identically to `Never`: exec-replace is the fail-closed
    /// default for a capability nobody has characterised. Declaring a
    /// surface `Always` or `WhenSameAccountId` without the verification
    /// `Always`'s and `WhenSameAccountId`'s doc comments cite is BLOCKED —
    /// an unverified "it probably re-reads" is exactly the bug this enum
    /// exists to close.
    Unknown,
}

/// Exhaustive per-surface [`InFlightAdoption`] declaration. **No wildcard
/// arm** — adding a [`Surface`] variant fails this match at compile time
/// until its adoption rule is declared here, which is the structural half
/// of the fix (the taxonomy comment on [`InFlightAdoption`] is the
/// narrative half).
///
/// Gemini/Kimi/Grok are `Unknown`, NOT `Always`: none of their reload
/// behavior under an in-flight credential change has been verified against
/// source or observed behavior. Do not upgrade one of these to `Always` or
/// `WhenSameAccountId` without the same class of verification ClaudeCode
/// and Codex cite in their own doc comments above.
fn in_flight_adoption(surface: Surface) -> InFlightAdoption {
    match surface {
        Surface::ClaudeCode => InFlightAdoption::Always,
        Surface::Codex => InFlightAdoption::WhenSameAccountId,
        // gemini-cli memoizes its OAuth client PER PROCESS and reads the
        // credential file exactly once, inside `initOauthClient`. Verified in
        // the shipped bundle (`@google/gemini-cli/bundle/chunk-Z7C7OBI2.js`):
        // the memo map is created at :245418, populated at :245615, and has
        // exactly TWO `clear()` sites — :245810 and :245848. The only live
        // caller is `clearCachedCredentialFile()`, gemini deleting its OWN
        // creds during an in-process logout; the other is test-only. Neither
        // is reachable from an external file change. Falsifying checks: zero
        // reads of `oauth_creds.json` on any request path, and the bundle's
        // only `watchFile` is a general utility ~96k lines away with no creds
        // path near it. (The cached client DOES refresh its own token in
        // memory — that is gemini refreshing ITS account, not adopting a
        // different one.) Independent of, and agreeing with, the PR-G4b env
        // finding above.
        Surface::Gemini => InFlightAdoption::Never,
        // No instrument discriminated. The binary is a Node single-executable,
        // so reload/watcher vocabulary returns Node's OWN runtime surface
        // (`internal/fs/watchers`, `FSWatcher`) whether or not kimi uses it,
        // and the `getCredentials` family is vendored google-auth-library
        // bundled for other providers. A window that read as proof of
        // re-reading turned out, at statement boundary, to be about
        // `globalMcpOAuth` (MCP server OAuth, not kimi's own credential) AND
        // inverted in polarity. `Unknown` is the honest verdict; note this
        // surface exec-replaces regardless via SlotBinding::LaunchEnv below.
        Surface::Kimi => InFlightAdoption::Unknown,
        // Grok's credential STORE genuinely hot-reloads, on the vendor's own
        // compiled-in documentation (`~/.grok/downloads/grok-macos-aarch64`
        // @10348164): "Grok picks up changes to ~/.grok/auth.json
        // automatically … uses the new credentials on the next API call
        // without a restart." Corroborated by runtime log strings (code, not
        // prose): "Auth token hot-reloaded from config watcher",
        // "auth hot-reload failed, keeping previous credentials",
        // "auth: adopted sibling token after lock-loss revalidation" — grok
        // expects OTHER processes to write auth.json. No codex-shape guard: a
        // whole-binary search for an account-mismatch string returns nothing,
        // against codex 0.154.0 which has exactly one.
        //
        // This is TRUE and, on its own, NOT SUFFICIENT: a Grok swap changes
        // which HOME the process is bound to, not what is inside the home —
        // see SlotBinding::LaunchEnv below, which is what actually forces
        // exec-replace here.
        //
        // Residual: the mechanism is conditional on a watcher that can fail
        // ("Config file watcher failed to start; hot-reload disabled") and the
        // failure mode is silent-keep-old.
        Surface::Grok => InFlightAdoption::Always,
    }
}

/// Is the RUNNING process's binding to a SLOT repointable in flight, or frozen
/// at launch?
///
/// The SECOND axis, and it is independent of [`InFlightAdoption`]. That one
/// asks whether a process adopts a change to the credential store it is bound
/// to; this asks whether csq can change WHICH store it is bound to at all.
///
/// Grok is why both are needed. Its store demonstrably hot-reloads, so the
/// store axis is honestly `Always` — but a Grok swap does not rewrite
/// `auth.json`, it points the vendor at a different per-slot home, and that
/// pointer is an environment variable set on the child `Command` at spawn
/// (`run.rs::set_native_home_env`) and frozen for the process lifetime. A
/// running grok keeps hot-reloading slot N's credentials promptly and
/// correctly, forever, while csq intended slot M. The vendor's reload
/// capability is real and irrelevant.
///
/// NOTE this is NOT the same thing as `source_env_transport` /
/// `target_env_transport`. Those resolve through
/// `settings::slot_pins_anthropic_base_url`, which asks whether a slot's
/// `config-<N>/settings.json` pins `env.ANTHROPIC_BASE_URL`. A native slot
/// pins nothing of the sort, so both flags evaluate FALSE for it — reusing
/// them here would drop a native surface through the `Always` arm into
/// `RouteKind::SameSurfaceClaudeCode`, i.e. the ClaudeCode handle-dir symlink
/// repoint, for a surface that HAS no handle-dir symlinks. Silent success,
/// old account still live: the 2026-09-12 codex defect through a different
/// door. Keep those two scoped to ClaudeCode exactly as documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotBinding {
    /// csq owns a symlink in the handle dir and repoints it. Changing the
    /// slot is a filesystem operation the running process can observe.
    HandleDirSymlink,
    /// The slot is carried by an environment variable set at spawn
    /// (`KIMI_CODE_HOME` / `GROK_HOME`, `providers/native.rs:113,133`) naming
    /// a per-slot vendor home (`native-homes/<surface>-<N>/`,
    /// `native::native_home_path`). Frozen for the process lifetime; csq never
    /// reads or writes inside that home (`run.rs` § set_native_home_env).
    LaunchEnv,
}

/// Exhaustive by construction, for the same reason [`in_flight_adoption`] is:
/// adding a `Surface` MUST fail to compile until someone declares how its
/// process binds to a slot, rather than inheriting a default nobody chose.
fn slot_binding(surface: Surface) -> SlotBinding {
    match surface {
        Surface::ClaudeCode => SlotBinding::HandleDirSymlink,
        Surface::Codex => SlotBinding::HandleDirSymlink,
        Surface::Gemini => SlotBinding::HandleDirSymlink,
        Surface::Kimi => SlotBinding::LaunchEnv,
        Surface::Grok => SlotBinding::LaunchEnv,
    }
}

/// Pure dispatch decision for `handle()`. Extracted as a free function
/// (PR-C9b L-CDX-3) so the routing matrix is unit-testable without the
/// env-var + filesystem setup that `handle()` requires. Any future
/// refactor of the dispatcher MUST keep `route()` in lockstep — the
/// `route_*` unit tests pin the matrix.
#[derive(Debug, PartialEq, Eq)]
enum RouteKind {
    /// Source + target both ClaudeCode AND both OAuth/Anthropic (neither
    /// pins `env.ANTHROPIC_BASE_URL`). In-flight symlink repoint; no exec,
    /// no tombstone — CC re-stats `.credentials.json` and picks up the new
    /// account on its next API call.
    SameSurfaceClaudeCode,
    /// Source + target both Codex, AND both sides' `tokens.account_id`
    /// match. In-flight symlink repoint via the Codex-aware mirror (M10 /
    /// an internal journal entry). No exec, no tombstone.
    SameSurfaceCodex,
    /// Source + target both Codex, but the codex `account_id` differs
    /// between them — OR either side's `account_id` could not be
    /// determined (fail-closed; an unknown id is treated as a mismatch,
    /// never as a match). codex-cli's own auth-reload guard only accepts
    /// a reload when the new file's `account_id` matches the in-memory
    /// session's (measured at RUNTIME on codex-cli 0.154.0: "Skipping
    /// auth reload due to account id mismatch (expected: …, found: …)" /
    /// "Skipping auth reload because no account id is available."). An
    /// in-flight repoint across accounts is therefore REFUSED by the
    /// running codex process — it keeps serving the OLD account while
    /// csq reports success. Not silent to the user: the guard's own line
    /// is INFO and suppressed at default logging, but the next refresh
    /// attempt surfaces an ERROR-level terminal message that
    /// misattributes the cause (see
    /// `InFlightAdoption::WhenSameAccountId` for the measured detail and
    /// for the UNDETERMINED healthy-token window). No override was found
    /// among CLI flags, `CODEX_*` env names, slash commands, or 7 probed
    /// config keys — a bounded search, not a proof of universality. MUST
    /// exec-replace
    /// so a fresh codex process reads the new account from disk at
    /// startup. Tombstone + exec; a resume is ATTEMPTED via
    /// `codex resume --last`, and the store it reads IS the one holding
    /// the source's thread: the fresh handle dir's `sessions` link
    /// resolves to `config-<target>/codex-sessions`, which is a symlink
    /// into the shared codex state (`CODEX_SHARED.shared`, linked before
    /// vendor login by design — `providers/codex/login.rs`). The earlier
    /// store-isolation suspect for this route is therefore REFUTED
    /// (measured: every live `config-<N>/codex-sessions` resolves through
    /// to one shared directory). The resume OUTCOME is still UNVERIFIED —
    /// refuting a failure mechanism is not evidence the resume succeeds
    /// (see `exec_replace_swap`).
    CodexAccountMismatchExecReplace,
    /// Both ClaudeCode, but at least ONE side is an env-transport slot
    /// (3P / Ollama — `settings.json` pins `env.ANTHROPIC_BASE_URL` +
    /// `env.ANTHROPIC_AUTH_TOKEN`). A running CC froze those env vars at
    /// launch and never re-reads them, so an in-flight repoint cannot
    /// switch the base URL / token — and a 3P→Anthropic repoint would leave
    /// CC sending the freshly-repointed Anthropic OAuth token to the frozen
    /// 3P endpoint (token exfiltration; see `daemon::auto_rotate` VP-F1).
    /// MUST exec-replace so a fresh CC reads the new settings.json env at
    /// startup. Tombstone + exec; no in-flight session state transfers —
    /// a resume is ATTEMPTED on the fresh process (`claude --continue`),
    /// outcome UNVERIFIED (see `exec_replace_swap`).
    ClaudeCodeEnvTransportExecReplace,
    /// Source + target are the SAME surface, but that surface's
    /// [`InFlightAdoption`] is `Never` or `Unknown` (not yet characterised)
    /// — Gemini/Kimi/Grok today. Exec-replace is the fail-closed default
    /// for a capability nobody has verified. Tombstone + exec; the
    /// conversation does NOT resume (none of these surfaces have a resume
    /// flag csq drives today — `resume_conversation` in `exec_replace_swap`
    /// is `false` for all three), so the notice MUST NOT promise otherwise.
    SameSurfaceUnknownAdoptionExecReplace,
    /// Source ≠ target surface. INV-P05 confirm + INV-P10 tombstone +
    /// `exec` of the target binary. No in-flight session state transfers —
    /// a resume is ATTEMPTED on the fresh process when the TARGET is
    /// ClaudeCode/Codex (not for Gemini/Kimi/Grok); outcome UNVERIFIED
    /// (see `exec_replace_swap`).
    ///
    /// This variant is returned ONLY when `source != target` (see `route()`
    /// — the surface-equality check is the first, unconditional branch).
    /// Before the `InFlightAdoption` reshape, a same-surface pair whose
    /// capability fell through a wildcard ALSO landed here, making this
    /// doc comment's "Source ≠ target surface" claim false for those pairs
    /// (`doc-property-claims.md`) — `SameSurfaceUnknownAdoptionExecReplace`
    /// now owns that case explicitly, so the claim holds unconditionally.
    CrossSurface,
}

/// Pure routing decision.
///
/// The FIRST question is surface equality: `source != target` is always
/// [`RouteKind::CrossSurface`], unconditionally — no capability, no flag,
/// overrides a true surface change. For a same-surface pair, the decision
/// is driven by [`in_flight_adoption`] (exhaustive over [`Surface`], no
/// wildcard — see that function's doc comment for why this is the
/// structural fix rather than a per-cell patch):
///
/// - `Always` (ClaudeCode): in-flight, UNLESS `source_env_transport` or
///   `target_env_transport` is set — a SEPARATE, per-swap axis (frozen
///   process env, not a credential-file-reload question; see
///   [`InFlightAdoption::Always`]'s doc comment).
/// - `WhenSameAccountId` (Codex): in-flight only when
///   `source_codex_account_id == target_codex_account_id`, BOTH `Some`.
///   Fail-closed: `(None, _)`, `(_, None)`, and a genuine mismatch are ALL
///   treated as "cannot adopt", never as a match — mirroring
///   `resolve_source_env_transport`'s discipline (an unresolved
///   discriminator is the UNSAFE direction to report as safe-in-flight).
/// - `Never` / `Unknown` (Gemini/Kimi/Grok today): always exec-replace.
///
/// `source_env_transport` / `target_env_transport` are `true` when the
/// respective slot pins `env.ANTHROPIC_BASE_URL` in its
/// `config-<N>/settings.json` (3P / Ollama); they are meaningful ONLY when
/// `in_flight_adoption(source) == Always`. `source_codex_account_id` /
/// `target_codex_account_id` are each slot's Codex `tokens.account_id`
/// (`None` when unreadable/absent); they are meaningful ONLY when
/// `in_flight_adoption(source) == WhenSameAccountId`. Callers compute both
/// pairs unconditionally (cheap: booleans / cached reads) and `route()`
/// consults only the pair its capability match needs.
fn route(
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
    // AXIS 2 FIRST, and before any arm that could return an in-flight kind.
    // A frozen process->slot binding makes the store axis moot: it does not
    // matter how eagerly the vendor re-reads its credential file if csq cannot
    // change WHICH file it is bound to. Checked here rather than inside the
    // `Always` arm so a future native surface carrying an account id cannot
    // slip through `WhenSameAccountId` and repeat the class.
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
                (Some(s), Some(t)) if s == t => RouteKind::SameSurfaceCodex,
                _ => RouteKind::CodexAccountMismatchExecReplace,
            }
        }
        InFlightAdoption::Never | InFlightAdoption::Unknown => {
            RouteKind::SameSurfaceUnknownAdoptionExecReplace
        }
    }
}

/// Read the slot number from a handle dir's `.csq-account` marker.
///
/// Returns `None` when the marker is absent or not resolvable to a slot.
/// Used by the audit wiring to derive `from_slot` for the `AccountSwap`
/// payload without modifying the `SourceHandle` API.
///
/// M4-7 (an internal ticket Phase 4): the marker's CONTENT is a UUID whenever a
/// `by_slot` mapping exists (`markers::write_csq_account`, written by
/// `csq run` / `finalize_login`), so this resolves through
/// `resolve_marker_to_slot` (numeric-or-UUID) rather than the numeric-only
/// `read_csq_account` — the latter returned `None` on every modern slot,
/// which silently dropped the `AccountSwap` audit record AND defeated the
/// `source_env_transport` exfiltration guard below
/// (`guard-reader-writer-parity.md`).
fn read_slot_from_handle_dir(base_dir: &Path, handle_dir_path: &Path) -> Option<AccountNum> {
    csq_core::accounts::markers::resolve_marker_to_slot(base_dir, handle_dir_path)
}

/// Resolves the source-side env-transport discriminator for the
/// `(ClaudeCode, ClaudeCode)` routing cell, FAIL-CLOSED.
///
/// A slot that pins `env.ANTHROPIC_BASE_URL` (3P: DeepSeek/Z.AI/MiniMax, or
/// Ollama) injects its base URL + auth token into CC's process env at
/// launch — FROZEN for the process lifetime. An in-flight symlink repoint
/// cannot change them, so any swap touching such a slot on either side MUST
/// exec-replace (a fresh CC reads the new settings.json env). The source
/// flag is only knowable when the source marker resolved (`from_slot`).
///
/// `from_slot == None` means csq CANNOT determine whether the source is an
/// env-transport slot — it does NOT mean the source is Anthropic. Reporting
/// `false` in that case (the pre-fix behavior) is the UNSAFE direction: it
/// lets `route()` choose `SameSurfaceClaudeCode` (in-flight repoint) for a
/// source that might actually be 3P/Ollama, which is exactly the
/// Anthropic-OAuth-token-to-frozen-3P-endpoint exfiltration path
/// `RouteKind::ClaudeCodeEnvTransportExecReplace`'s doc comment describes.
/// This function fails CLOSED instead: an unresolved marker reports `true`,
/// forcing the safer exec-replace path. The target flag alone (computed
/// separately by the caller) still forces exec-replace whenever the TARGET
/// is env-transport, covering the Anthropic→3P direction independently.
fn resolve_source_env_transport(base_dir: &Path, from_slot: Option<AccountNum>) -> bool {
    from_slot
        .map(|s| csq_core::providers::settings::slot_pins_anthropic_base_url(base_dir, s.get()))
        .unwrap_or(true)
}

/// Reads slot `slot`'s Codex `tokens.account_id` for the `(Codex, Codex)`
/// routing-cell discriminator, via the SAME channel daemon production paths
/// read (`diagnostic-surface-parity.md` MUST NOT Rule 4 / `refresh::check`'s
/// `broker_codex_check`): the identity-keyed path when a `by_slot` UUID
/// mapping exists, falling back to the legacy `credentials/codex-<N>.json`
/// mirror otherwise.
///
/// Returns `None` when the slot has no UUID mapping AND no legacy mirror,
/// when the file cannot be parsed or is not Codex-shaped, or when
/// `account_id` is absent/empty. `None` is NOT "this account has no id" —
/// it means UNKNOWN, and `route()` MUST treat it as a mismatch (fail-closed),
/// never as a match: codex-cli refuses to reload `auth.json` in-flight
/// unless the account id it already holds matches the new file's, so
/// proceeding with an in-flight repoint on an unreadable id risks leaving
/// the running process bound to the OLD account — a binding the user
/// learns of only through the refresh-error message, not from the refusal
/// itself (see `InFlightAdoption::WhenSameAccountId`).
fn read_codex_account_id(base_dir: &Path, slot: AccountNum) -> Option<String> {
    let path = codex_canonical_auth_path(base_dir, slot);
    let creds = csq_core::credentials::load(&path).ok()?;
    let account_id = creds.codex()?.tokens.account_id.clone()?;
    if account_id.is_empty() {
        None
    } else {
        Some(account_id)
    }
}

/// PR-C7 entry point. `yes` bypasses the cross-surface confirmation
/// prompt (INV-P05 `--yes`).
///
/// A swap is an operator-initiated command, so its keychain calls run inside
/// `with_interactive_keychain`: a macOS password dialog gets the interactive
/// bound instead of being killed after the 5s non-interactive bound. The
/// whole synchronous body runs on this thread; the daemon's `auto_rotate`
/// does not pass through here and stays non-interactive.
pub fn handle(base_dir: &Path, target: AccountNum, yes: bool) -> Result<()> {
    csq_core::credentials::keychain::with_interactive_keychain(|| {
        handle_inner(base_dir, target, yes)
    })
}

fn handle_inner(base_dir: &Path, target: AccountNum, yes: bool) -> Result<()> {
    let source = detect_source_handle(base_dir, target)?;
    let target_surface = resolve_target_surface(base_dir, target)?;

    // Phase B' billing-ledger attribution (an internal journal entry D2). Best-effort
    // append; failures MUST NOT block the swap.
    super::run::append_launch_log(base_dir, "swap", target);

    // M13b — derive from_slot from the source handle dir marker.
    // If the marker is absent we skip audit (pre-side-effect information
    // unavailable → no intent emitted, consistent with the WBS T4 invariant).
    let from_slot = read_slot_from_handle_dir(base_dir, source.path());

    // Capture the handle-dir path before `source` is moved into the route arms.
    // After a Claude-surface swap we mirror the new account's credential into
    // the keychain item CC reads for this handle dir (current CC reads OAuth
    // from the keychain, not the symlinked `.credentials.json`).
    let handle_dir_path = source.path().to_path_buf();

    // Env-transport discriminator for the (ClaudeCode, ClaudeCode) cell — see
    // `resolve_source_env_transport` for the fail-closed rationale.
    let source_env_transport = resolve_source_env_transport(base_dir, from_slot);
    let target_env_transport =
        csq_core::providers::settings::slot_pins_anthropic_base_url(base_dir, target.get());

    // Codex account-id discriminator for the (Codex, Codex) cell — see
    // `read_codex_account_id` for the fail-closed rationale. Only computed
    // when relevant: `from_slot` is the SOURCE slot bound to this handle
    // dir today (the account the running codex process actually holds).
    let source_codex_account_id = if matches!(source.surface(), Surface::Codex) {
        from_slot.and_then(|slot| read_codex_account_id(base_dir, slot))
    } else {
        None
    };
    let target_codex_account_id = if matches!(target_surface, Surface::Codex) {
        read_codex_account_id(base_dir, target)
    } else {
        None
    };

    let route_kind = route(
        source.surface(),
        target_surface,
        source_env_transport,
        target_env_transport,
        source_codex_account_id.as_deref(),
        target_codex_account_id.as_deref(),
    );
    // F2(d): captured before `route_kind` moves into `exec_replace_swap`
    // below — only the same-surface ClaudeCode route repoints an EXISTING
    // dir (the one F2's rollback/consistency check applies to).
    let route_is_same_surface_claude_code = matches!(route_kind, RouteKind::SameSurfaceClaudeCode);

    // A4a — close the daemon-custodian mid-swap race for a same-surface ClaudeCode
    // swap (the only path that repoints an EXISTING dir whose keychain still holds
    // the PREVIOUS account's token). Hold the per-dir swap lock so the daemon
    // custodian's harvest (which try-locks the same file) SKIPS this dir until it
    // settles. Cross-surface / Codex routes create a FRESH handle dir (keychain
    // absent from birth), so they have no such race and need no lock here.
    // v4 A1 ("switch now or say so"): for a same-surface ClaudeCode swap,
    // read X and force-write the TARGET account's token BEFORE the repoint,
    // under the lock — the daemon custodian's harvest must never observe
    // this dir between the write and the repoint. Chosen order: write X,
    // then repoint.
    //
    // K5 (doc fix — this comment previously claimed a write failure or an
    // unreadable X always means nothing was mutated, which contradicts S4
    // and F8 below): an UNREADABLE X, or a write failure over a
    // CONFIRMED-absent X (F4/F8), does mean nothing was mutated, and the
    // switch does NOT proceed (the `?` below returns before any repoint
    // runs). But a write failure over KNOWN (`Content`) prior state (S4)
    // leaves the resulting disk state UNKNOWN — `force_swap_write_before_repoint`
    // passes that through as `Ok(WriteFailedUnknown)` rather than `Err`, and
    // this function proceeds to the repoint exactly as for a confirmed
    // write. v5 ("keychain follows the links", 2026-09-26 owner directive):
    // there is no immediate restore-to-snapshot attempt here any more — the
    // SOLE compensating action for ANY downstream failure is
    // `reconcile_keychain_to_marker`, run once `result` (the repoint's own
    // outcome) is known, below.
    // KC4-2: the hint is recorded ONLY after a successful switch (see below,
    // after `result` is known) and ONLY if absent — the running session that
    // OWNS this handle dir had its keychain username fixed at ITS OWN launch;
    // swap must never overwrite that recorded value, including on an abort
    // path. `_swap_abs_for_hint` carries the canonicalized path forward so the
    // post-result block below can still reach it.
    let mut _swap_abs_for_hint: Option<std::path::PathBuf> = None;
    // B2/PRIMARY DIRECTIVE: exactly what the pre-repoint force-write
    // attempted, carried forward so the post-repoint reconcile below can
    // classify X by IDENTITY against it (rule 4) rather than re-deriving a
    // possibly-different value from a second read of the target's file.
    let mut _swap_target_creds_for_reconcile: Option<
        csq_core::accounts::identity_store::TargetToken,
    > = None;
    let _swap_guard = if matches!(route_kind, RouteKind::SameSurfaceClaudeCode) {
        let (abs, keychain_write_allowed) =
            csq_core::credentials::keychain::canonicalize_for_keychain_sync(&handle_dir_path);
        if keychain_write_allowed {
            // round 7c D5: opportunistically harvest the SOURCE account's
            // own live keychain candidates via the D3 IPC route BEFORE
            // taking the per-dir lock below — a separate process (unlike
            // D4's in-daemon auto_rotate call, this asks the daemon, it does
            // not run the custodian itself). Best-effort and its result is
            // not branched on directly: if the daemon adopts a foreign token
            // into the SOURCE account's store here, the post-lock
            // `force_swap_write_before_repoint` call below will find X now
            // matches a known token (rule 2, Write) instead of nothing
            // (rule 3, `ForeignLoginUnharvested`) — that decide() call is
            // what actually produces the refuse-vs-proceed disposition D5
            // requires ("refuse after harvest still unmatched" / "unreachable
            // daemon but nothing unmatched -> proceed" are both exactly what
            // `decide_cc_keychain_write`'s rule 2/3 already implement; this
            // call's only job is to give that decision a chance to see a
            // freshly-adopted token first).
            if let Some(source_account) = from_slot {
                let sock = csq_core::daemon::socket_path(base_dir);
                let _ = csq_core::daemon::harvest_account(&sock, source_account.get());
            }
            use csq_core::credentials::keychain::BoundedLockOutcome;
            let guard =
                match csq_core::credentials::keychain::lock_handle_dir_for_swap_bounded(&abs) {
                    BoundedLockOutcome::Acquired(g) => Some(g),
                    BoundedLockOutcome::NotNeeded => None,
                    BoundedLockOutcome::TimedOut | BoundedLockOutcome::Failed => {
                        anyhow::bail!(
                            "csq swap: the keychain is busy; nothing changed — retry the swap"
                        );
                    }
                };
            _swap_abs_for_hint = Some(abs.clone());
            // M3-7/guard-reader-writer-parity.md MUST-1/F5: source the
            // target's token via the shared `target_token_for_forced_write`
            // helper, so this and `auto_rotate`'s tick can never drift apart
            // on how the resolver is invoked — never a hardcoded config-N
            // guess, which a UUID-keyed slot's config-N copy may be stale or
            // absent for.
            let target_creds =
                csq_core::accounts::identity_store::target_token_for_forced_write(base_dir, target);
            // round 7c D5: a target whose own canonical token is not Valid
            // (unreadable/expired) is refused BEFORE any mutation — same
            // rule `auto_rotate::find_target` enforces at selection time
            // (D4). This route (`SameSurfaceClaudeCode`) only ever intends
            // an Anthropic token (never a strip — see `route()`'s
            // `target_env_transport` gate), so `None` here always means
            // "nothing valid to switch to", never "positively non-Anthropic".
            if target_creds.as_valid_str().is_none() {
                anyhow::bail!(
                    "csq swap: account {target} has no valid login; nothing changed — \
                     run `csq login {target}` first"
                );
            }
            // v5: every `Ok(_)` outcome (Applied, AbsentWriteFailed, or
            // WriteFailedUnknown) proceeds to the repoint below identically
            // — `reconcile_keychain_to_marker` is the single compensating
            // action for whatever the repoint does next, so this call site
            // no longer needs to branch on the write's own outcome. H1:
            // `.as_valid_str()` reproduces the old "is there a token to
            // write" behaviour; `target_creds` itself (the richer
            // three-way classification) is carried forward below so the
            // post-repoint reconcile can classify X by IDENTITY against
            // exactly what THIS call attempted to write.
            if let Err(msg) = csq_core::credentials::keychain::force_swap_write_before_repoint(
                base_dir,
                &abs,
                target_creds.as_valid_str(),
            ) {
                anyhow::bail!("csq swap: {msg}");
            }
            _swap_target_creds_for_reconcile = Some(target_creds);
            guard
        } else {
            // F3/KC4-3: a canonicalize failure means we cannot even name the
            // handle dir's absolute path, so the "CC falls back to the
            // symlinked .credentials.json" claim below does not follow — CC's
            // fallback is read through the SAME dir this canonicalize just
            // failed on. Refuse rather than proceed with an unverified path,
            // BEFORE any repoint runs (this arm is reached before `result` is
            // computed below).
            anyhow::bail!(
                "csq swap: could not locate this terminal's keychain item; nothing changed — retry the swap"
            );
        }
    } else {
        None
    };

    let mut result = match route_kind {
        RouteKind::SameSurfaceClaudeCode => {
            same_surface_claude_code_audited(base_dir, source.path(), target, from_slot)
        }
        RouteKind::SameSurfaceCodex => {
            same_surface_codex_audited(base_dir, source.path(), target, from_slot)
        }
        // Env-transport-exec-replace (ClaudeCode 3P/Ollama),
        // codex-account-mismatch-exec-replace, same-surface-unknown-
        // adoption-exec-replace (Gemini/Kimi/Grok), and true cross-surface
        // swaps all share the tombstone-then-exec machinery; they differ
        // only in the notice/confirmation wording, which `exec_replace_swap`
        // derives from `same_surface` (source/target surface equality) plus
        // `route_kind` itself.
        RouteKind::ClaudeCodeEnvTransportExecReplace
        | RouteKind::CodexAccountMismatchExecReplace
        | RouteKind::SameSurfaceUnknownAdoptionExecReplace
        | RouteKind::CrossSurface => exec_replace_swap(
            base_dir,
            source,
            target,
            target_surface,
            yes,
            from_slot,
            route_kind,
        ),
    };

    // v5 ("keychain follows the links", 2026-09-26 owner directive): the
    // keychain side of a same-surface ClaudeCode switch was already written
    // BEFORE the repoint above (under `_swap_guard`'s lock). B2: the
    // compensating action `reconcile_keychain_to_marker` is now run on
    // BOTH outcomes, not only `Err` — an `Ok(())` repoint does not prove
    // the earlier force-write's keychain mirror actually landed
    // (`ForcedSyncResult::AbsentWriteFailed`/`WriteFailedUnknown` are both
    // `Ok(_)` write outcomes at that earlier call site). It re-reads this
    // handle dir's `.csq-account` marker AS IT IS NOW (never a pre-write
    // snapshot) and makes X agree with whatever account that marker names.
    // The marker read is the source of truth
    // (`guard-reader-writer-parity.md`); this is what makes the operator
    // line honest regardless of how (or whether) a repoint failed.
    if route_is_same_surface_claude_code {
        let forced_write = _swap_target_creds_for_reconcile.as_ref().map(|tt| {
            csq_core::credentials::keychain::ForcedWriteAttempt {
                account: target,
                raw_json: tt.as_valid_str(),
            }
        });
        let reconcile_outcome = csq_core::credentials::keychain::reconcile_keychain_to_marker(
            base_dir,
            &handle_dir_path,
            forced_write,
        );
        // B4: the account the switch STARTED from — `from_slot` is exactly
        // the same `resolve_marker_to_slot` read reconcile itself uses,
        // taken before this switch attempted anything. Passed through as
        // `Option`, NOT `.unwrap_or(target)` — falling back to `target`
        // silently substituted the DESTINATION for "unknown start", which
        // made "switched"/"not switched" a claim about whether the marker
        // ended up on the target rather than an honest "we don't know
        // where this started". `None` (the rare, pre-side-effect-unavailable
        // case the source marker was already unreadable at swap start)
        // now omits the switched/not-switched claim entirely (B4).
        let reconcile_line = csq_core::credentials::keychain::reconcile_outcome_operator_line(
            &reconcile_outcome,
            from_slot,
        );
        let credential_error = result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<csq_core::error::CredentialError>());
        // K3: `repoint_handle_dir`'s S7 pre-flight refusal fires BEFORE any
        // symlink mutation — a real file blocks where an
        // `ACCOUNT_BOUND_ITEMS` symlink belongs — but the keychain WAS
        // already force-written above, so it can still disagree with the
        // (unmoved) marker. D-F2: fold the reconcile outcome into this
        // message rather than reporting the blocked item alone.
        let refused_item = credential_error.and_then(|e| e.repoint_refused_item());
        // B3: the handle dir's OWN symlinks may ALSO be left mixed across
        // two accounts by a partially-rolled-back repoint — a signal
        // independent of the keychain reconcile above. Only meaningful when
        // the repoint actually failed.
        let mixed_links = credential_error.is_some_and(|e| {
            csq_core::credentials::keychain::repoint_left_mixed_links(e, base_dir, &handle_dir_path)
        });
        // S-H-A/D-F1: a repoint `Ok(())` is NOT the final word — reconcile
        // ran unconditionally above (B2), and its outcome may say the
        // keychain never actually followed the switch (`WriteFailed`,
        // `KeychainUnknown`, `MarkerUnreadable`). Only `AlreadyCurrent`/
        // `Reconciled` mean the keychain genuinely agrees with the marker
        // now; every other outcome on an `Ok(())` repoint is converted to a
        // non-zero exit carrying the reconcile line, so the operator is
        // never told "Swapped" while the keychain disagrees.
        if result.is_err() {
            let operator_line = if let Some(item) = refused_item {
                csq_core::credentials::keychain::repoint_refused_real_file_operator_line(
                    item,
                    &reconcile_line,
                )
            } else if mixed_links {
                // C-F8: the prior version REPLACED reconcile_line with the
                // mixed-links line, silently discarding whatever
                // reconcile_outcome itself said (a `WriteFailed`/
                // `KeychainUnknown` detail is lost, and the operator sees
                // only "links are mixed" with no explanation of the
                // keychain's own disagreement). Two independently-checked
                // things (`csq-core/src/credentials/keychain.rs`'s
                // `mixed_links_operator_line` doc), so the message folds
                // both in rather than picking one.
                match reconcile_outcome.marker_account() {
                    Some(m) => format!(
                        "{} {reconcile_line}",
                        csq_core::credentials::keychain::mixed_links_operator_line(m)
                    ),
                    None => reconcile_line,
                }
            } else {
                reconcile_line
            };
            result = result.map_err(|e| e.context(operator_line));
        } else {
            match decide_ok_repoint_disposition(&reconcile_outcome, &reconcile_line) {
                OkRepointDisposition::Success { marker_account } => {
                    println!(
                        "Swapped to account {} — CC will pick up on next API call",
                        marker_account.get()
                    );
                }
                OkRepointDisposition::Fail(message) => {
                    result = Err(anyhow::anyhow!(message));
                }
            }
        }
    }
    // KC4-2: record the hint ONLY now that the switch has actually
    // succeeded, and ONLY if the file is still absent — never on an abort
    // path (the `Err` arm above), and never overwriting a value some
    // earlier launch of this SAME handle dir already recorded. See
    // `record_keychain_account_hint_if_absent`'s doc.
    if result.is_ok() {
        if let Some(abs) = _swap_abs_for_hint.take() {
            csq_core::credentials::keychain::record_keychain_account_hint_if_absent(&abs);
        }
    }
    // `_swap_guard` drops here.

    result
}

// ─── M13b audit helpers ──────────────────────────────────────────────

/// The result of a successful `begin_swap_audit` call.
#[derive(Debug)]
struct SwapAuditContext {
    chain_id: String,
    correlation_id: RecordId,
    payload: EventPayload,
}

/// Attempt to emit the INTENT record for a same-surface swap.
///
/// Returns:
/// - `Ok(Some(ctx))` — INTENT persisted; caller MUST call `finish_swap_audit`
///   after the side effect.
/// - `Ok(None)` — marker absent; audit skipped (pre-side-effect detection
///   failure is NOT fail-closed for same-surface swaps — swap proceeds).
/// - `Err(..)` — INTENT could not be persisted; caller MUST abort the side
///   effect (F-LEDGER-02 fail-closed contract).
///
/// FIX-3: typed return replaces the `contains("from_slot unavailable")`
/// string discrimination that was brittle across refactors.
///
/// Round 7 (D-F3/S-M-1) added a `nonce: Option<&str>` parameter here, embedded
/// on the INTENT payload so the codex supervisor could require it to match
/// before writing the correlated OUTCOME. Round 8 (C-B1/C-B2) RETRACTED that:
/// see `AccountSwapPayload`'s doc for why. The codex-supervisor handoff path
/// (`handoff_to_supervisor_write_and_signal`) still mints and carries a
/// request nonce (`SwapRequest::nonce`, `SwapHandoffArgs::nonce`) — it is
/// simply never embedded in this function's payload.
fn begin_swap_audit(
    base_dir: &Path,
    from_slot: Option<AccountNum>,
    to_slot: AccountNum,
) -> Result<Option<SwapAuditContext>> {
    let from = match from_slot {
        Some(f) => f,
        None => {
            // Marker absent — skip audit gracefully. No INTENT emitted.
            return Ok(None);
        }
    };

    let chain_id = op_emit::load_chain_id(base_dir);
    let correlation_id =
        op_emit::gen_correlation_id().map_err(|e| anyhow!("audit correlation_id: {e}"))?;
    let payload = EventPayload::AccountSwap(AccountSwapPayload {
        from_slot: from,
        to_slot,
    });

    // FIX-7: reason uses RedactedString::from_untrusted; the audit framework
    // does path-free string redaction. No filesystem paths reach the chain.
    // FIX-1: Ok(true)=emitted → Ok(Some(ctx)); Ok(false)=chain-broken skip →
    // Ok(None) (swap proceeds without audit); Err=fail-closed.
    let intent_emitted = op_emit::emit_intent(
        base_dir,
        &chain_id,
        EventKind::AccountSwap,
        payload.clone(),
        correlation_id.clone(),
    )
    .map_err(|e| anyhow!("audit intent persist failed — swap aborted: {e}"))?;

    if !intent_emitted {
        // Chain broken — proceed without audit trail (same pattern as marker-absent).
        return Ok(None);
    }

    Ok(Some(SwapAuditContext {
        chain_id,
        correlation_id,
        payload,
    }))
}

/// Emit the OUTCOME record. Best-effort — if this fails the intent is a
/// visible orphan detectable by `scan_orphan_intents`. The swap result is
/// returned unchanged.
///
/// FIX-7: `e.to_string()` from `anyhow::Error` may contain paths from
/// underlying IO errors. Route through `op_emit::redact_reason` (token scrub
/// + `$HOME` strip).
///
/// D-F5/S-LOW-3 (round 7): this used to be a private copy of the same logic
/// now shared as `op_emit::redact_reason` — moved to csq-core so every
/// lifecycle-op outcome writer (this function, `exec_replace_swap`'s own
/// OUTCOME write below, AND `codex_supervise.rs`'s supervisor-side writes)
/// scrubs `$HOME` identically rather than each deciding independently. See
/// that function's doc for the full rationale.
fn finish_swap_audit(base_dir: &Path, ctx: SwapAuditContext, result: &Result<()>) {
    let outcome = match result {
        Ok(()) => OpOutcome::Ok,
        Err(e) => OpOutcome::Failed {
            reason: op_emit::redact_reason(e.to_string()),
        },
    };
    if let Err(e) = op_emit::emit_outcome(
        base_dir,
        &ctx.chain_id,
        EventKind::AccountSwap,
        ctx.payload,
        ctx.correlation_id,
        outcome,
    ) {
        // S-LOW-C (round 8): the swap itself already completed (or failed)
        // by this point — this OUTCOME write is best-effort audit trail,
        // never a gate on the operation — so a WARN is correct, not a
        // propagated error. `e.fixed_tag()` is itself a fixed vocabulary
        // (`AuditV2Error::fixed_tag`), so this never echoes an upstream
        // error body onto the log (`security.md` MUST-2).
        tracing::warn!(
            error_kind = "audit_outcome_emit_failed",
            op = "swap",
            audit_error_kind = e.fixed_tag(),
            "finish_swap_audit: failed to emit AccountSwap OUTCOME record \
             (op already completed; audit trail incomplete — the INTENT is \
             left as an orphan for scan_orphan_intents)"
        );
    }
}

// ─── Source-surface detection ────────────────────────────────────────

fn detect_source_handle(base_dir: &Path, target: AccountNum) -> Result<SourceHandle> {
    // Surface-specific env vars may all be set by a well-meaning
    // parent shell. Probe in surface-specific order:
    //   1. GEMINI_CLI_HOME — set ONLY by `csq run` for Gemini slots
    //   2. CODEX_HOME — set by `csq run` for Codex slots
    //   3. CLAUDE_CONFIG_DIR — set by `csq run` for Claude/3P slots
    //
    // Each `csq run` path scrubs the OTHER surfaces' env vars, so
    // ordering only matters when a parent shell exports multiple of
    // them by mistake. In that case the most-specific match wins:
    // the first term-* candidate must validate under our base. An invalid
    // candidate refuses rather than falling through to another surface.
    if let Ok(raw) = std::env::var("GEMINI_CLI_HOME") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::Gemini(validate_source_handle_path(
                base_dir, &p,
            )?));
        }
    }
    if let Ok(raw) = std::env::var("CODEX_HOME") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::Codex(validate_source_handle_path(
                base_dir, &p,
            )?));
        }
    }
    if let Ok(raw) = std::env::var("CLAUDE_CONFIG_DIR") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::ClaudeCode(validate_source_handle_path(
                base_dir, &p,
            )?));
        }
        // M4-8 (Phase 4 an internal ticket): legacy `CLAUDE_CONFIG_DIR=config-N`
        // swap mode is fully retired. The pre-M4-8 fallback through
        // `rotation::swap_to` would write credentials into config-N
        // and silently move every terminal sharing that dir; the
        // handle-dir model makes per-terminal swap the contract and
        // legacy launches are non-isolated by construction. Refuse
        // with the spec 02 §2.6 message — the message threads the
        // target slot the user typed so the suggested `csq run`
        // command is copy-pasteable rather than a literal `N`.
        if is_legacy_config_dir(&p) {
            let dir_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("config-?");
            return Err(anyhow!(
                "this terminal was launched in legacy per-account mode; \
                 swap would affect all terminals on {dir_name}. \
                 Relaunch with `csq run {target}` to use per-terminal swap."
            ));
        }
        return Err(anyhow!("swap_source_handle_invalid"));
    }
    // A Kimi/Grok session IS csq-managed — `csq run` launched it — but it
    // carries `KIMI_CODE_HOME` / `GROK_HOME` (providers/native.rs:113,133)
    // rather than any of the three probed above, so it lands here. Telling
    // that operator "csq swap must run inside a csq-managed session" asserts
    // something false about their state (`doc-property-claims.md`); they are
    // inside one. Name the real reason instead, which is the SlotBinding axis:
    // those surfaces bind a slot through an env var frozen at spawn, so there
    // is nothing csq can repoint beneath a running process.
    //
    // This is a REFUSAL, not a swap — the safe outcome either way. Before
    // this arm existed the same case reached the generic message purely
    // because `SourceHandle` has no native variant, i.e. safe by accident
    // rather than by decision.
    for descriptor in [&native::KIMI, &native::GROK] {
        if std::env::var(descriptor.home_env).is_ok() {
            let surface = descriptor.surface;
            return Err(anyhow!(
                "this is a {surface} session, and {surface} binds its slot through \
                 ${} — an environment variable csq sets at launch and cannot change \
                 beneath a running process. Its credential store may reload, but the \
                 slot it reads FROM will not. Start the other slot in a new session: \
                 `csq run {target}`.",
                descriptor.home_env
            ));
        }
    }

    Err(anyhow!(
        "none of CLAUDE_CONFIG_DIR / CODEX_HOME / GEMINI_CLI_HOME is set — \
         csq swap must run inside a csq-managed session"
    ))
}

/// Validate before account discovery, logging, credentials, repoint or tombstone.
/// Canonical component containment permits a symlinked base, but not an escape.
/// This is not a defense against concurrent same-UID path replacement.
fn validate_source_handle_path(base_dir: &Path, source: &Path) -> Result<PathBuf> {
    let base = base_dir
        .canonicalize()
        .map_err(|_| anyhow!("swap_source_base_unavailable"))?;
    if !base.is_dir() {
        return Err(anyhow!("swap_source_base_unavailable"));
    }
    let source = source
        .canonicalize()
        .map_err(|_| anyhow!("swap_source_handle_unavailable"))?;
    if !source.is_dir() || !is_term_handle_dir(&source) {
        return Err(anyhow!("swap_source_handle_invalid"));
    }
    if source == base || !source.starts_with(&base) {
        return Err(anyhow!("swap_source_handle_outside_base"));
    }
    Ok(source)
}

fn is_term_handle_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("term-"))
        .unwrap_or(false)
}

fn is_legacy_config_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("config-"))
        .unwrap_or(false)
}

fn resolve_target_surface(base_dir: &Path, target: AccountNum) -> Result<Surface> {
    let accounts = discovery::discover_all(base_dir);
    accounts
        .iter()
        .find(|a| a.id == target.get())
        .map(|a| a.surface)
        .ok_or_else(|| {
            anyhow!(
                "account {target} not found — run `csq login {target}` first, \
                 or check `csq status` for available accounts"
            )
        })
}

// ─── Same-surface ClaudeCode (existing behavior) ────────────────────

/// Wrapper that adds M13b INTENT/OUTCOME audit emit around the same-surface
/// ClaudeCode symlink repoint.
///
/// FIX-3: uses typed `SwapAuditContext` — no string discrimination.
fn same_surface_claude_code_audited(
    base_dir: &Path,
    source_dir: &Path,
    target: AccountNum,
    from_slot: Option<AccountNum>,
) -> Result<()> {
    match begin_swap_audit(base_dir, from_slot, target)? {
        Some(ctx) => {
            // INTENT committed. Run side effect, then emit OUTCOME.
            let result = same_surface_claude_code(base_dir, source_dir, target);
            finish_swap_audit(base_dir, ctx, &result);
            result
        }
        None => {
            // Marker absent → audit skipped, swap proceeds (not fail-closed).
            same_surface_claude_code(base_dir, source_dir, target)
        }
    }
}

/// S-H-A/D-F1 decision seam: what a same-surface ClaudeCode swap's `Ok(())`
/// repoint should report, given the [`csq_core::credentials::keychain::ReconcileOutcome`]
/// that ran right after it — factored out as a PURE function of that
/// outcome so it is directly unit-testable with a synthetic
/// `ReconcileOutcome`, no `security` subprocess, no lock, no CLI harness.
#[derive(Debug, PartialEq, Eq)]
enum OkRepointDisposition {
    /// The keychain genuinely agrees with the marker now — print the
    /// success line naming the account the marker (not necessarily the
    /// originally-intended target) resolved to.
    Success { marker_account: AccountNum },
    /// The repoint itself succeeded, but the keychain did not confirm
    /// following it — report failure (non-zero exit) with the reconcile
    /// line as the message, rather than announcing a clean "Swapped".
    Fail(String),
}

fn decide_ok_repoint_disposition(
    reconcile_outcome: &csq_core::credentials::keychain::ReconcileOutcome,
    reconcile_line: &str,
) -> OkRepointDisposition {
    use csq_core::credentials::keychain::ReconcileOutcome;
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

fn same_surface_claude_code(base_dir: &Path, source_dir: &Path, target: AccountNum) -> Result<()> {
    // M4-8 (Phase 4 an internal ticket): the only valid same-surface ClaudeCode
    // swap path is the handle-dir model. `detect_source_handle` already
    // refuses legacy `config-N` sources with the spec 02 §2.6 message,
    // so any source reaching this function MUST be a `term-<pid>` dir.
    // The defensive check below preserves a clear error if the routing
    // contract is ever broken from above.
    let dir_name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !dir_name.starts_with("term-") {
        return Err(anyhow!(
            "source dir is not a csq-managed handle dir: {}. \
             Relaunch with `csq run {target}` to use per-terminal swap.",
            redact_path(source_dir)
        ));
    }

    let claude_home = super::claude_home()?;
    handle_dir::repoint_handle_dir(base_dir, &claude_home, source_dir, target)?;
    refresh_current_account_cache(base_dir, target);
    notify_daemon_cache_invalidation(base_dir);
    // S-H-A/D-F1: the success line is printed by the caller, AFTER
    // `reconcile_keychain_to_marker` has run — printing it here means a
    // repoint that succeeds but leaves the keychain desynced (reconcile
    // outcome anything other than `AlreadyCurrent`/`Reconciled`) is
    // announced as a clean success before that outcome is even known.
    Ok(())
}

/// Refreshes the canonical `config-N/.current-account` cache after a swap
/// repoints a handle dir to slot N.
///
/// `csq swap` repoints the handle dir's symlinks but does NOT touch the
/// target `config-N`'s `.current-account`, which can hold a stale value (a
/// pre-handle-dir-migration leftover, or a value left behind by `csq move`).
/// Without this refresh the next statusline render on any sibling terminal
/// bound to slot N would surface the stale slot until `snapshot_account`'s
/// lazy self-heal runs — the exact `csq swap N → wrong slot` bug (workspace
/// an internal workspace, C2/M4).
///
/// Writes the canonical `config-N` file directly (never the handle dir, whose
/// `.current-account` is a symlink into config-N). Non-fatal: snapshot's
/// authority-first self-heal is the structural backstop, so a failed write
/// here only delays the heal by one render.
fn refresh_current_account_cache(base_dir: &Path, target: AccountNum) {
    let config_dir = base_dir.join(format!("config-{}", target.get()));
    if config_dir.is_dir() {
        if let Err(e) = csq_core::accounts::markers::write_current_account(&config_dir, target) {
            tracing::debug!(
                error = %e,
                slot = target.get(),
                "swap: failed to refresh config-N/.current-account cache"
            );
        }
    }
}

// ─── Same-surface Codex (M10 / an internal journal entry) ────────────────────────

/// Same-surface Codex→Codex symlink repoint. Mirrors
/// `same_surface_claude_code` but uses the Codex-aware
/// [`handle_dir::repoint_handle_dir_codex`] (spec 07 §7.2.2 symlink
/// set). No exec-replace, no tombstone — the running codex process
/// keeps its open fds and picks up the new auth.json on the next API
/// call.
///
/// **Reachable only when `route()` already confirmed the source and
/// target `tokens.account_id` match** (`RouteKind::SameSurfaceCodex`).
/// codex-cli's own auth-reload guard refuses an in-flight `auth.json`
/// change whose `account_id` differs from the one it already holds —
/// silently at the log layer, with an ERROR-level refresh message
/// reaching the user only once a refresh is attempted (see
/// `InFlightAdoption::WhenSameAccountId`) — so the "picks up on the next
/// API call" claim above depends on that precondition — a cross-account
/// repoint instead takes `RouteKind::CodexAccountMismatchExecReplace` /
/// `exec_replace_swap`.
///
/// Legacy `config-N` Codex source dirs are not supported: there is no
/// pre-handle-dir layout for Codex (the surface launched after the
/// handle-dir model was already in place), so any Codex source must be
/// a `term-<pid>` dir. Returns a clear error otherwise.
/// Wrapper that adds M13b INTENT/OUTCOME audit emit around the same-surface
/// Codex symlink repoint.
///
/// FIX-3: uses typed `SwapAuditContext` — no string discrimination.
fn same_surface_codex_audited(
    base_dir: &Path,
    source_dir: &Path,
    target: AccountNum,
    from_slot: Option<AccountNum>,
) -> Result<()> {
    match begin_swap_audit(base_dir, from_slot, target)? {
        Some(ctx) => {
            let result = same_surface_codex(base_dir, source_dir, target);
            finish_swap_audit(base_dir, ctx, &result);
            result
        }
        None => same_surface_codex(base_dir, source_dir, target),
    }
}

fn same_surface_codex(base_dir: &Path, source_dir: &Path, target: AccountNum) -> Result<()> {
    let dir_name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !dir_name.starts_with("term-") {
        return Err(anyhow!(
            "Codex source dir is not a csq-managed handle dir: {}. \
             Relaunch with `csq run {target}` to get per-terminal isolation.",
            redact_path(source_dir)
        ));
    }

    handle_dir::repoint_handle_dir_codex(base_dir, source_dir, target)?;
    refresh_current_account_cache(base_dir, target);
    notify_daemon_cache_invalidation(base_dir);
    println!(
        "Swapped to account {} — codex will pick up on next API call",
        target
    );
    Ok(())
}

// ─── Exec-replace path (cross-surface + ClaudeCode env-transport) ────

/// Refuses an exec-replace swap BEFORE any tombstone when the source is
/// Codex and this process is running as a descendant of a live `codex`
/// process (`csq_core::providers::codex::ancestry::find_live_codex_ancestor_pid`)
/// — UNLESS that ancestor is supervised (shard S2,
/// `csq::cli::commands::codex_supervise`) and the target is ALSO Codex, in
/// which case the swap is handed back to the supervisor instead
/// (shard S3) and `exec_replace_swap` must not run its tombstone/exec steps
/// at all.
///
/// `exec_replace_swap` tombstones the source handle dir and then
/// `exec()`s a fresh target binary IN THIS PROCESS — correct when this
/// process IS the user's terminal session, wrong when it is a `!`
/// shell-out child of a live codex TUI: the exec replaces the child, the
/// TUI is untouched and left holding a tombstoned handle dir, and the
/// user sees no error.
///
/// The supervisor protocol only covers a Codex→Codex handoff — the
/// supervisor's `relaunch` closure recurses into `launch_codex`, which
/// launches Codex and nothing else — so a true cross-surface swap (e.g.
/// Codex→ClaudeCode) from inside a live codex ancestor still has no
/// handoff path and refuses exactly as before, even when a supervisor is
/// present.
///
/// **This whole check fires ONLY for `source_surface == Surface::Codex`** —
/// a live **ClaudeCode** ancestor (a `!` shell-out from inside a running
/// `claude` TUI) running `csq swap` toward ANY target takes this
/// function's early `Ok(false)` return unconditionally and is NOT checked
/// here against `csq_core::platform::process::find_cc_pid`. That gap
/// (item 2 of the governing task) is CLOSED, but NOT by widening this
/// function — `refuse_if_inside_live_cc_ancestor` (defined below) is
/// called separately and unconditionally, before this function, at the
/// top of `exec_replace_swap` (see that call site), so a live CC ancestor
/// is still refused before any tombstone regardless of `source_surface`.
///
/// C-F10: this comment previously described that gap as "no fix in this
/// shard's scope"; grep `swap.rs` for "item 2 of the governing task"
/// before trusting a similar claim elsewhere in this file — several were
/// written before shard S1/S2/S3 landed and have since been closed.
///
/// Returns `Ok(true)` when the swap was handed off to a live supervisor —
/// the caller MUST return `Ok(())` immediately without tombstoning or
/// exec'ing anything. Returns `Ok(false)` when neither the refusal nor the
/// handoff applies (not a Codex source, or a Codex source with no live
/// ancestor) and `exec_replace_swap` should proceed normally. Returns `Err`
/// for the refusal case, unchanged in wording from before this shard.
///
/// A no-op for every other source surface, and a no-op on Windows (see
/// `ancestry`'s `imp` module doc — ancestor detection is not implemented
/// there, so this refusal is currently inert on that platform).
fn refuse_or_handoff_if_inside_live_codex_ancestor(
    source_surface: Surface,
    target_surface: Surface,
    source_handle_dir: &Path,
    base_dir: &Path,
    target: AccountNum,
    from_slot: Option<AccountNum>,
) -> Result<bool> {
    if source_surface != Surface::Codex {
        return Ok(false);
    }
    let Some(ancestor_pid) = csq_core::providers::codex::ancestry::find_live_codex_ancestor_pid()
    else {
        return Ok(false);
    };

    #[cfg(unix)]
    {
        if target_surface == Surface::Codex && sup::verify_supervisor_alive(source_handle_dir) {
            handoff_to_supervisor(base_dir, source_handle_dir, target, ancestor_pid, from_slot)?;
            return Ok(true);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (target_surface, source_handle_dir, base_dir, from_slot);
    }

    Err(anyhow!(
        "csq swap cannot switch Codex accounts from inside a running codex \
         session — this command is executing as a subprocess of a live codex \
         process (pid {ancestor_pid}), and replacing it would leave that \
         session untouched with no visible error. Exit codex first, then run \
         `csq run {target}` to start account {target} directly."
    ))
}

/// Refuses an exec-replace swap BEFORE any tombstone when this process is
/// running as a descendant of a live Claude Code (`claude`) process —
/// the same failure class `refuse_or_handoff_if_inside_live_codex_ancestor`
/// closes for a live `codex` ancestor, extended to the ClaudeCode side
/// (cross-slot swap-resume governing task, item 2 — that function returns
/// `Ok(false)` unconditionally for any non-Codex source surface, so a `!`
/// shell-out from inside a live `claude` TUI reached `exec_replace_swap`
/// unguarded on every exec-replace route).
///
/// Reuses the SAME ancestor detector the rest of csq uses
/// (`csq_core::platform::process::find_cc_pid`) rather than a second
/// implementation. `exec_replace_swap` always tombstones the source handle
/// dir and then `exec()`s a fresh target binary IN THIS PROCESS — correct
/// when this process IS the user's terminal session, wrong when it is a `!`
/// shell-out child of a live `claude` TUI: the exec replaces the child only,
/// the TUI is left holding a tombstoned handle dir, and nothing prints to
/// the user's screen.
///
/// Called unconditionally at the top of every exec-replace route (cross-
/// surface, ClaudeCode env-transport, Codex account-mismatch, and the
/// not-yet-characterised same-surface-unknown-adoption route) — regardless
/// of `source_surface`, because the danger is "a live claude process is
/// somewhere up this ancestry", not which surface `route()` resolved the
/// source to. `SameSurfaceClaudeCode`'s in-flight repoint never calls
/// `exec_replace_swap` at all (it repoints symlinks in-place — no exec, no
/// tombstone), so it is unaffected and keeps working from inside a live CC
/// session, per this shard's scope.
///
/// A no-op when introspection cannot determine an ancestor (process gone,
/// permission denied, unsupported platform — `find_cc_pid` fails OPEN on
/// those, per its own doc) — a swap that is not actually nested inside a
/// live `claude` process must not be blocked by a detector that could not
/// answer. Also a no-op (inert) on Windows, matching the existing Codex
/// ancestor check's platform posture.
fn refuse_if_inside_live_cc_ancestor(target_surface: Surface, target: AccountNum) -> Result<()> {
    match find_cc_pid_for_refusal() {
        // C-F8: restored the `\` line continuations lost in a prior edit
        // — without them the compiled string embeds each source line's
        // leading indentation as a literal run of spaces. Also reworded:
        // the prior text asserted "this Claude Code session" as though
        // the CURRENT command's own session were Claude Code, when what
        // is actually known is only that a live `claude` process sits
        // somewhere up THIS process's ancestry (this check runs
        // regardless of the routed `source_surface` — see the caller's
        // doc). "from inside a running Claude Code session" names that
        // ancestor without claiming the swap's own source surface.
        Some(cc_pid) => Err(anyhow!(
            "csq swap cannot switch to {target_surface} from inside a running Claude \
             Code session — this command is executing as a subprocess of a live claude \
             process (pid {cc_pid}), and replacing it would leave that session \
             untouched with no visible error. Exit claude first, then run \
             `csq run {target}` to start account {target} directly."
        )),
        None => Ok(()),
    }
}

// Test-only injection seam for `refuse_if_inside_live_cc_ancestor`'s
// ancestor detection (cross-slot swap-resume governing task, item 2's
// hermeticity follow-up). `find_cc_pid()` walks the REAL process table, so
// a unit test asserting "no ancestor" or exercising `exec_replace_swap`'s
// LATER checks is not hermetic when this test binary itself happens to be
// running as a descendant of a live `claude` process — the case whenever
// `cargo test` is invoked from inside an agentic coding session, on every
// developer machine. Same idiom as [`COUNT_CODEX_ANCESTORS_OVERRIDE`]
// above: thread-local, defaults to "no override" (the real detector),
// RAII-reset on drop so a reused test-harness thread never leaks an
// override into an unrelated test. `Ok(None)` and `Err(_)` collapse to the
// SAME `None` here because the caller already treats them identically
// (see the match above) — there is nothing for a test to distinguish by
// forcing an `Err` specifically, and `PlatformError` is not `Clone`.
#[cfg(test)]
thread_local! {
    static FIND_CC_PID_OVERRIDE: std::cell::RefCell<Option<Option<u32>>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII guard returned by [`force_find_cc_pid`]; clears the override on
/// drop (including on test panic/unwind) so a later test reusing the same
/// harness thread always starts from "no override".
#[cfg(test)]
struct FindCcPidOverrideGuard;

#[cfg(test)]
impl Drop for FindCcPidOverrideGuard {
    fn drop(&mut self) {
        FIND_CC_PID_OVERRIDE.with(|c| *c.borrow_mut() = None);
    }
}

/// Forces `refuse_if_inside_live_cc_ancestor`'s ancestor-pid answer on THIS
/// thread until the returned guard drops — `Some(pid)` simulates a live
/// `claude` ancestor, `None` simulates none (or an unreadable process
/// table, which the caller treats identically). See
/// [`FIND_CC_PID_OVERRIDE`]'s doc for why this exists instead of relying
/// on whatever the real process tree happens to be at test time.
#[cfg(test)]
fn force_find_cc_pid(value: Option<u32>) -> FindCcPidOverrideGuard {
    FIND_CC_PID_OVERRIDE.with(|c| *c.borrow_mut() = Some(value));
    FindCcPidOverrideGuard
}

#[cfg(test)]
fn find_cc_pid_for_refusal() -> Option<u32> {
    if let Some(forced) = FIND_CC_PID_OVERRIDE.with(|c| *c.borrow()) {
        return forced;
    }
    csq_core::platform::process::find_cc_pid().ok().flatten()
}

#[cfg(not(test))]
fn find_cc_pid_for_refusal() -> Option<u32> {
    csq_core::platform::process::find_cc_pid().ok().flatten()
}

/// Resolves the canonical Codex credential path for `slot` — identity-keyed
/// (`identities/<UUID>/credentials-codex.json`) when a `by_slot` mapping
/// exists, else the legacy `credentials/codex-<N>.json` mirror. The SAME
/// resolution order `read_codex_account_id` uses, factored out so
/// `verify_codex_target_ready_for_handoff` (below) can reuse it rather than
/// duplicating the `resolve_slot_to_uuid` match a second time.
fn codex_canonical_auth_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        Some(uuid) => {
            csq_core::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)
        }
        None => csq_core::credentials::file::canonical_path_for(base_dir, slot, Surface::Codex),
    }
}

/// C-F2/S-F3: the same preconditions `super::run::launch_codex` enforces
/// before a governed Codex spawn — `config-<N>/config.toml` exists, the
/// canonical credential path is a regular file (never a symlink — same-user
/// TOCTOU guard), and the access token is not expired — re-derived here so
/// `handoff_to_supervisor` can refuse BEFORE writing the swap request
/// rather than after signalling the supervisor and having the ASYNC
/// relaunch (which recurses into `launch_codex`, and so re-runs these same
/// checks anyway) fail silently from the CALLER's point of view.
///
/// `super::run::verify_codex_config_toml` and
/// `super::run::verify_codex_canonical_is_regular_file` are private `fn`s
/// in `run.rs`, not `pub(crate)` — they cannot be called from this module,
/// and `run.rs` is owned by a concurrent shard in this wave, so it is not
/// touched here. **Needs widening**: both should become `pub(crate) fn` so
/// this duplication can be replaced with direct calls to the originals.
///
/// `#[cfg(unix)]`: its only caller, `handoff_to_supervisor`, is itself
/// unix-only (the supervised codex-handoff path signals a live supervisor
/// process via a unix signal), so this is genuinely unreachable — not
/// merely untested — on a non-unix build.
#[cfg(unix)]
fn verify_codex_target_ready_for_handoff(
    base_dir: &Path,
    target: AccountNum,
    now_secs: u64,
) -> Result<()> {
    let config_toml = codex_surface::config_toml_path(base_dir, target);
    if !config_toml.exists() {
        return Err(anyhow!(
            "slot {target} is missing {} — run `csq login {target} --provider codex` \
             to complete login",
            redact_path(&config_toml)
        ));
    }

    let canonical_path = codex_canonical_auth_path(base_dir, target);
    let meta = std::fs::symlink_metadata(&canonical_path).map_err(|_| {
        anyhow!(
            "slot {target} has no Codex credentials at the canonical path — \
             run `csq login {target} --provider codex`"
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing Codex handoff: account {target}'s credential path is a symlink. \
             csq only writes a regular file at this path (spec 07 §7.2.2 + INV-P08); \
             a symlink here means an external process mutated the credentials \
             directory. Re-run `csq login {target} --provider codex` to rewrite."
        ));
    }
    if !meta.file_type().is_file() {
        return Err(anyhow!(
            "refusing Codex handoff: account {target}'s credential path is not a \
             regular file"
        ));
    }

    super::run::check_codex_token_freshness(&canonical_path, target, now_secs)
}

/// C-R4-8/S-F5: names whichever on-disk file is ACTUALLY responsible for
/// `swap_request_pending(source_handle_dir)` reading true, so a stuck-switch
/// error message can direct the user to remove the real cause rather than
/// unconditionally naming [`sup::SWAP_REQUEST_FILE`] (`swap_request_pending`'s
/// own doc: it reads pending on either a fresh request file OR a still-present
/// [`sup::SWAP_INFLIGHT_FILE`] — the two are not the same file and not always
/// both present). Pure function over the filesystem state — no daemon, no
/// audit, no signalling — so it is testable without any of `handoff_to_supervisor`'s
/// other preconditions.
#[cfg(unix)]
fn describe_stuck_swap_paths(source_handle_dir: &Path) -> String {
    let inflight_path = source_handle_dir.join(sup::SWAP_INFLIGHT_FILE);
    let request_path = source_handle_dir.join(sup::SWAP_REQUEST_FILE);
    match (inflight_path.exists(), request_path.exists()) {
        (true, true) => format!(
            "{} and {}",
            redact_path(&inflight_path),
            redact_path(&request_path)
        ),
        (true, false) => redact_path(&inflight_path).to_string(),
        // Neither on disk, or only the request file — the request-file case
        // (including "neither observably present, but `swap_request_pending`
        // still returned true due to a race") keeps the original, still-
        // accurate suggestion.
        (false, _) => redact_path(&request_path).to_string(),
    }
}

/// Hands a verified-supervised, in-place Codex→Codex swap back to the live
/// supervisor named in `source_handle_dir`'s [`sup::SupervisorRecord`]
/// (shard S3, built against S2's `codex_supervise::run_supervised`
/// contract).
///
/// Validates the target (exists, is a Codex slot, has Codex credentials —
/// the same "run `csq login N --provider codex`" condition
/// `create_handle_dir_codex_named` checks), runs the SAME M6 T6.1
/// spawn-boundary governance gate `exec_replace_swap` runs before its own
/// tombstone (C-F2/S-F3 — enterprise builds only) plus the config.toml /
/// canonical-credential / token-freshness preconditions
/// `verify_codex_target_ready_for_handoff` checks, refuses a second
/// pending request, discovers the ancestor's current thread id on a
/// best-effort (never-guessing) basis, writes the [`sup::SwapRequest`]
/// under an M13b audit intent/outcome pair (C-F3 — this handoff previously
/// wrote the request with NO audit record at all), and signals the
/// supervisor. On success this prints exactly one line and returns; the
/// caller (`exec_replace_swap`) must return `Ok(())` immediately — no
/// tombstone, no exec, both belong to the supervisor's own relaunch path
/// now.
#[cfg(unix)]
fn handoff_to_supervisor(
    base_dir: &Path,
    source_handle_dir: &Path,
    target: AccountNum,
    ancestor_pid: u32,
    from_slot: Option<AccountNum>,
) -> Result<()> {
    // C-R4-3: with the daemon down, the SAME "Codex spawn refused" check
    // `require_daemon_healthy`/`validate_codex_relaunch_target` already
    // run for a fresh launch or a same-process relaunch was previously
    // skipped for a supervised handoff — this function would write the
    // request, signal the supervisor, print success, and record an OK
    // audit outcome, and only THEN would the supervisor's own relaunch
    // (which re-enters `launch_codex` and re-runs this check) discover
    // the daemon is down and refuse — silently, under the live codex
    // screen, with no error surfacing to the terminal the user is
    // actually looking at. Checked here, BEFORE any request is written
    // and BEFORE the M13b audit intent, so a daemon-down refusal is
    // reported to the caller directly instead of being swallowed by the
    // supervisor's own poll loop.
    if let Some(reason) =
        super::run::codex_daemon_refusal(&csq_core::daemon::detect_daemon(base_dir))
    {
        return Err(anyhow!("{reason}"));
    }

    if sup::swap_request_pending(source_handle_dir) {
        // C-R4-8/S-F5: name whichever file is ACTUALLY responsible for the
        // "already in progress" verdict (`describe_stuck_swap_paths`) —
        // `swap_request_pending` treats either a fresh SWAP_REQUEST_FILE or
        // a still-present SWAP_INFLIGHT_FILE as "pending" (see that
        // function's doc); the prior message named only SWAP_REQUEST_FILE
        // unconditionally, which sent a user stuck on an in-flight relaunch
        // to remove a file that was never the actual cause and, on some
        // builds, does not even exist at that point
        // (`doc-property-claims.md`: the message asserted a mechanism it
        // did not check).
        let stuck_paths = describe_stuck_swap_paths(source_handle_dir);
        return Err(anyhow!(
            "a switch is already in progress for this terminal (if it is stuck, \
             remove {stuck_paths})"
        ));
    }

    // Validate the target: `resolve_target_surface` (already run by
    // `handle()` before `exec_replace_swap`) confirmed the slot exists and
    // its surface; `read_codex_account_id` re-derives whether it actually
    // has Codex credentials via the SAME channel
    // `create_handle_dir_codex_named` requires before it will bind a handle
    // dir — reusing that condition rather than duplicating handle-dir
    // creation here (which would be destructive and premature: the
    // supervisor, not this process, creates the target handle dir).
    if read_codex_account_id(base_dir, target).is_none() {
        return Err(anyhow!(
            "account {target} has no Codex credentials — run \
             `csq login {target} --provider codex` first"
        ));
    }

    // C-F2/S-F3: the M6 T6.1 governance gate — the SAME function
    // `exec_replace_swap` calls before its Step-2 tombstone. Evaluated here
    // too so a refused target is refused BEFORE the swap request is
    // written and the supervisor is signalled, matching the exec-replace
    // path's "nothing written on refusal" posture. Discarded (not threaded
    // through to the supervisor's relaunch): the supervisor's `relaunch`
    // closure recurses into `launch_codex`, which evaluates this SAME gate
    // again at actual spawn time and applies its own returned scope env —
    // this call is a fail-fast precondition, not the gate of record.
    #[cfg(feature = "enterprise")]
    {
        let start_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut audit_emitter = super::run::build_audit_emitter(
            base_dir,
            csq_core::cli_deps::SurfaceCli::Codex.audit_surface(),
            format!("csq swap account {target}"),
            start_ts,
        );
        super::run::evaluate_codex_spawn_gate(base_dir, &mut audit_emitter)?;
        // F3: a `Refuse` verdict above already took (and flushed) the
        // record via `try_flush_now` before the `?` propagated, so this
        // line is reached only on `Ungoverned`/`Proceed` — this call is a
        // fail-fast precondition, NOT the gate of record (see this
        // function's doc above), and `launch_codex` evaluates the same
        // gate again for real at actual spawn time. Without `discard()`
        // here, `audit_emitter`'s `Drop` impl flushes ITS placeholder
        // `ResultState::Degraded`/`Decision::Bypass` record as a genuine
        // audit entry — a phantom duplicate of whatever the real spawn-time
        // gate evaluation records moments later.
        audit_emitter.discard();
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_codex_target_ready_for_handoff(base_dir, target, now_secs)?;

    // C-F3: begin the M13b swap audit BEFORE writing the request — mirrors
    // `exec_replace_swap`'s Step 1. Nothing has been written yet, so an
    // intent-persist failure aborts here with no cleanup needed (fail-closed
    // per F-LEDGER-02).
    //
    // PRIMARY DIRECTIVE (round 6): the supervisor, not `csq swap`, is the
    // authority for this INTENT's correlated OUTCOME. `csq swap` persists
    // the INTENT here (as before) and hands its `chain_id`/`correlation_id`
    // across in the request line (`SwapRequest::chain_id` /
    // `::correlation_id` / `::from_slot`) — it no longer calls
    // `finish_swap_audit` itself for this handoff. An accepted-then-timeout
    // or a failure before the supervisor ever saw the request leaves this
    // INTENT with no OUTCOME: the defined-unknown state `scan_orphan_intents`
    // / `csq doctor` already surface, not a gap this function papers over.
    //
    // The request nonce is minted HERE, before the SwapRequest below is
    // constructed, and carried into `SwapHandoffArgs::nonce` /
    // `SwapRequest::nonce` — it binds a `SwapVerdict` to this specific
    // request (`codex_supervisor::take_swap_verdict`). Round 7 (D-F3/S-M-1)
    // also embedded this same string on the INTENT's own payload so the
    // supervisor could require it to match before writing the correlated
    // OUTCOME; round 8 (C-B1/C-B2) retracted that embedding (see
    // `AccountSwapPayload`'s doc) — `begin_swap_audit` no longer takes a
    // nonce argument, and the correlation authority is chain identity plus
    // (once established) the INTENT's own signature, verified by
    // `csq_core::audit::verify_swap_correlation`.
    let handoff_nonce = sup::gen_swap_nonce();
    let audit_ctx = match begin_swap_audit(base_dir, from_slot, target) {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::warn!(
                error_kind = "audit_intent_persist_failed_codex_handoff",
                "M13b: codex-supervisor handoff swap audit intent could not be \
                 persisted — aborting before the swap request is written \
                 (fail-closed per F-LEDGER-02)"
            );
            return Err(e);
        }
    };
    let (chain_id, correlation_id, from_slot_for_request) = match &audit_ctx {
        Some(ctx) => (
            ctx.chain_id.clone(),
            ctx.correlation_id.as_str().to_string(),
            from_slot.map(|f| f.get()).unwrap_or(0),
        ),
        // No INTENT was recorded (marker absent) — nothing to correlate;
        // the supervisor must never write an OUTCOME with no matching
        // INTENT (see `SwapAuditCorrelation::from_request`'s doc).
        None => (String::new(), String::new(), 0u16),
    };

    // PRIMARY METHODOLOGICAL DIRECTIVE: outcome authority boundary is the
    // SIGNAL, not "the supervisor exists" or "a request was written." Every
    // exit from `handoff_to_supervisor_write_and_signal` BEFORE a successful
    // `signal_supervisor` call is THIS process's own failure to hand the
    // swap off at all — the supervisor never learned of it, so it can never
    // write the correlated OUTCOME either, and the INTENT `begin_swap_audit`
    // just persisted (above) would otherwise sit as a silent orphan
    // indistinguishable from a genuine crash. `audit_ctx` is moved in so
    // every such early-return path can close it out as `Failed` via
    // `finish_swap_audit`/`abort_handoff` before propagating the error.
    // AFTER a successful signal, `audit_ctx` is simply dropped unused — the
    // supervisor is the sole authority for the OUTCOME from that point on,
    // exactly as it already is for the accepted/refused/timeout verdicts
    // (see the two `handoff_reports_*_and_writes_no_outcome_*` tests).
    handoff_to_supervisor_write_and_signal(
        base_dir,
        SwapHandoffArgs {
            source_handle_dir,
            target,
            ancestor_pid,
            chain_id: &chain_id,
            correlation_id: &correlation_id,
            from_slot: from_slot_for_request,
            nonce: &handoff_nonce,
        },
        audit_ctx,
    )
}

/// Closes out `audit_ctx`'s correlated OUTCOME as `Failed(reason)` (via
/// [`finish_swap_audit`]/`op_emit::redact_reason`) when an INTENT was actually
/// recorded, then returns `err` unchanged — a single choke point so every
/// pre-signal failure branch in [`handoff_to_supervisor_write_and_signal`]
/// gets identical treatment. A no-op (beyond returning `err`) when
/// `audit_ctx` is `None`: `begin_swap_audit` already decided there was
/// nothing to correlate (marker absent / chain broken), and writing an
/// OUTCOME with no matching INTENT would itself be an orphan in the other
/// direction (see `SwapAuditCorrelation::from_request`'s doc in
/// `codex_supervisor.rs`, which states the identical constraint for the
/// supervisor side of this same contract).
#[cfg(unix)]
fn abort_handoff(
    base_dir: &Path,
    audit_ctx: Option<SwapAuditContext>,
    err: anyhow::Error,
) -> Result<()> {
    let result: Result<()> = Err(err);
    if let Some(ctx) = audit_ctx {
        finish_swap_audit(base_dir, ctx, &result);
    }
    result
}

// Test-only injection seam for `count_codex_ancestors_before`'s two
// fail-closed branches (`Some(n) if n > 1` — "more than one codex in the
// ancestor chain" — and `None` — "ancestor chain unreadable"). Both
// branches depend on a real OS process-tree SHAPE (a genuinely nested
// codex-inside-codex session, or a supervisor pid that becomes
// unreadable mid-walk) that is impractical to construct deterministically
// from a spawned-subprocess test fixture. Forcing the return value here
// lets a test exercise the branch directly while every other code path —
// including every OTHER test — takes the real walk unchanged (the
// thread-local defaults to `None`, i.e. "no override", and each setter
// returns an RAII guard that resets it on drop so a reused test-harness
// thread can never leak an override into an unrelated test).
#[cfg(all(unix, test))]
thread_local! {
    static COUNT_CODEX_ANCESTORS_OVERRIDE: std::cell::RefCell<Option<Option<usize>>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII guard returned by [`force_count_codex_ancestors_before`]; clears
/// the override on drop (including on test panic/unwind) so a later test
/// reusing the same harness thread always starts from "no override".
#[cfg(all(unix, test))]
struct CountCodexAncestorsOverrideGuard;

#[cfg(all(unix, test))]
impl Drop for CountCodexAncestorsOverrideGuard {
    fn drop(&mut self) {
        COUNT_CODEX_ANCESTORS_OVERRIDE.with(|c| *c.borrow_mut() = None);
    }
}

/// Forces `count_codex_ancestors_before_for_handoff`'s return value on THIS
/// thread until the returned guard drops. See
/// [`COUNT_CODEX_ANCESTORS_OVERRIDE`]'s doc for why this exists instead of
/// constructing the real process-tree shape.
#[cfg(all(unix, test))]
fn force_count_codex_ancestors_before(value: Option<usize>) -> CountCodexAncestorsOverrideGuard {
    COUNT_CODEX_ANCESTORS_OVERRIDE.with(|c| *c.borrow_mut() = Some(value));
    CountCodexAncestorsOverrideGuard
}

#[cfg(all(unix, test))]
fn count_codex_ancestors_before_for_handoff(
    start_pid: u32,
    stop_at_pid: u32,
    max_hops: usize,
) -> Option<usize> {
    if let Some(forced) = COUNT_CODEX_ANCESTORS_OVERRIDE.with(|c| *c.borrow()) {
        return forced;
    }
    csq_core::providers::codex::ancestry::count_codex_ancestors_before(
        start_pid,
        stop_at_pid,
        max_hops,
    )
}

#[cfg(all(unix, not(test)))]
fn count_codex_ancestors_before_for_handoff(
    start_pid: u32,
    stop_at_pid: u32,
    max_hops: usize,
) -> Option<usize> {
    csq_core::providers::codex::ancestry::count_codex_ancestors_before(
        start_pid,
        stop_at_pid,
        max_hops,
    )
}

// Test-only injection seam (round 6, item 2): lowers
// `handoff_to_supervisor_write_and_signal`'s bounded wait for the
// supervisor's verdict, so a test exercising the "no verdict ever arrives"
// (undetermined) branch does not have to sleep out the real
// [`sup::VERDICT_WAIT_TIMEOUT_SECS`] (10s). Same idiom as
// [`COUNT_CODEX_ANCESTORS_OVERRIDE`] above: thread-local, defaults to "no
// override" (the real 10s constant), RAII-reset on drop so a reused
// test-harness thread never leaks an override into an unrelated test.
#[cfg(all(unix, test))]
thread_local! {
    static VERDICT_WAIT_TIMEOUT_OVERRIDE: std::cell::RefCell<Option<std::time::Duration>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(unix, test))]
struct VerdictWaitTimeoutOverrideGuard;

#[cfg(all(unix, test))]
impl Drop for VerdictWaitTimeoutOverrideGuard {
    fn drop(&mut self) {
        VERDICT_WAIT_TIMEOUT_OVERRIDE.with(|c| *c.borrow_mut() = None);
    }
}

/// Forces the bound `handoff_to_supervisor_write_and_signal` waits on THIS
/// thread until the returned guard drops.
#[cfg(all(unix, test))]
fn force_verdict_wait_timeout(value: std::time::Duration) -> VerdictWaitTimeoutOverrideGuard {
    VERDICT_WAIT_TIMEOUT_OVERRIDE.with(|c| *c.borrow_mut() = Some(value));
    VerdictWaitTimeoutOverrideGuard
}

#[cfg(all(unix, test))]
fn verdict_wait_timeout() -> std::time::Duration {
    VERDICT_WAIT_TIMEOUT_OVERRIDE
        .with(|c| *c.borrow())
        .unwrap_or_else(|| std::time::Duration::from_secs(sup::VERDICT_WAIT_TIMEOUT_SECS))
}

// Narrowed from the single `#[cfg(not(all(unix, test)))]` fallback this
// used to be: that predicate is true on windows-gnu in EVERY build (unix
// is false, so `all(unix, test)` is false regardless of `test`), and the
// old body referenced `sup::VERDICT_WAIT_TIMEOUT_SECS` — but `sup` is the
// `#[cfg(unix)]`-gated alias for `codex_supervisor` declared at this file's
// top, so it does not exist on that target
// (`E0433: could not find "sup"` — pre-existing, found compiling this file
// for `x86_64-pc-windows-gnu`). This function's only caller
// (`handoff_to_supervisor_write_and_signal`) is itself `#[cfg(unix)]`, so
// there is no non-unix case to serve — narrowing to `all(unix, not(test))`
// (rather than adding a `#[cfg(not(unix))]` arm that would be dead code
// under `-D warnings`) is the correct fix, not a workaround.
#[cfg(all(unix, not(test)))]
fn verdict_wait_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(sup::VERDICT_WAIT_TIMEOUT_SECS)
}

/// The side effect `handoff_to_supervisor` wraps in an M13b audit
/// intent/outcome pair (C-F3): read + verify the supervisor, resolve the
/// ancestor's thread id, write the [`sup::SwapRequest`], signal the
/// supervisor, and — F1 (round 5) — wait (bounded) for the supervisor's
/// VERDICT and report FROM it, never from this function's own pre-checks.
/// Split out so the `Result<()>` it produces can be passed to
/// `finish_swap_audit` by reference, matching `exec_replace_swap`'s own
/// OUTCOME-from-real-result pattern.
///
/// S-L2 (round 5) ordering: the supervisor-record read and BOTH ancestor-
/// chain checks now run FIRST, before anything is written — a refusal at
/// any of those points has touched no on-disk state, so it needs no
/// cleanup (`take_swap_request`/`clear_swap_inflight` calls on those
/// branches were removed; they would have been operating on a request THIS
/// process never wrote). The request write moves to the END, immediately
/// before signalling, via [`sup::write_swap_request_if_absent`]
/// (create-if-absent — the caller's own `swap_request_pending` precondition
/// check happened before this whole admission walk, so a request
/// materializing HERE means a genuinely concurrent writer, which must be
/// refused rather than clobbered). Only the post-write failure branch
/// (`signal_supervisor` erroring) clears the marker — THIS process's own
/// request, safe to withdraw.
/// Grouped parameters for [`handoff_to_supervisor_write_and_signal`] — item 6
/// (round 7): keeps the function under clippy's `too_many_arguments` lint
/// without an `#[allow]`. `base_dir` and `audit_ctx` stay as separate
/// top-level parameters: both have call-site-visible special handling
/// (`audit_ctx` is moved into every `abort_handoff` early-return, `base_dir`
/// is threaded through those same calls), so folding them in here would
/// obscure rather than clarify the two moving parts.
#[cfg(unix)]
struct SwapHandoffArgs<'a> {
    source_handle_dir: &'a Path,
    target: AccountNum,
    ancestor_pid: u32,
    chain_id: &'a str,
    correlation_id: &'a str,
    from_slot: u16,
    /// C-F6 (round 6): a CSPRNG nonce, minted by `handoff_to_supervisor`
    /// (via `sup::gen_swap_nonce`) BEFORE this struct is built, that binds
    /// this request to its eventual `SwapVerdict`
    /// (`codex_supervisor::take_swap_verdict`). Round 7 (D-F3/S-M-1) also
    /// embedded this same string on the INTENT's own payload so the
    /// supervisor could require it to match before writing the correlated
    /// OUTCOME; round 8 (C-B1/C-B2) RETRACTED that embedding (see
    /// `AccountSwapPayload`'s doc — `begin_swap_audit` no longer takes a
    /// nonce parameter at all). This field is therefore the request's ONLY
    /// nonce now, not a reuse of one already on the chain.
    nonce: &'a str,
}

#[cfg(unix)]
fn handoff_to_supervisor_write_and_signal(
    base_dir: &Path,
    args: SwapHandoffArgs<'_>,
    audit_ctx: Option<SwapAuditContext>,
) -> Result<()> {
    let SwapHandoffArgs {
        source_handle_dir,
        target,
        ancestor_pid,
        chain_id,
        correlation_id,
        from_slot,
        nonce,
    } = args;
    // Re-read the record for its pid: `verify_supervisor_alive` (checked by
    // the caller) confirmed the record verifies at that moment, but does
    // not itself return the pid to signal.
    let Some(record) = sup::read_supervisor_record(source_handle_dir) else {
        return abort_handoff(
            base_dir,
            audit_ctx,
            anyhow!(
                "the codex supervisor record disappeared before the swap request \
                 could be written — nothing was changed; try again"
            ),
        );
    };

    // S-F11: the supervisor record is a plain file this process reads by
    // path — it is NOT itself proof that `record.pid` is the process that
    // actually spawned/owns the live codex ancestor at `ancestor_pid`. A
    // forged, stale, or PID-recycled record naming an unrelated process
    // must never receive `SIGUSR1`.
    //
    // FM-13: requiring `record.pid` to be the EXACT immediate parent of
    // `ancestor_pid` refused every swap under an npm-installed `codex` —
    // the npm launcher (`#!/usr/bin/env node` running `codex.js`) is the
    // pid the supervisor actually forked, but that launcher then SPAWNS
    // (a genuine fork, not an in-place exec — see
    // `ancestry::DEFAULT_ANCESTOR_CHAIN_BOUND`'s doc) the native `codex`
    // binary as a NEW child. `find_live_codex_ancestor_pid` names that
    // native binary (`ancestor_pid`); its immediate parent is the
    // launcher, not the supervisor, so the exact-match check failed on
    // every such install. Accept `record.pid` anywhere within a small,
    // bounded ancestor chain above `ancestor_pid` instead of requiring the
    // exact immediate parent — this is still a destructive-adjacent,
    // security-bearing operation (it can trigger an involuntary relaunch
    // of a live session), so an EMPTY or non-matching chain (introspection
    // failed, or `record.pid` is genuinely absent within the bound) still
    // fails CLOSED on ambiguity (`guard-reader-writer-parity.md` MUST-2) —
    // only widened FROM "exact parent" TO "within N hops", never to
    // "assume a match".
    let chain = csq_core::providers::codex::ancestry::ancestor_chain(
        ancestor_pid,
        csq_core::providers::codex::ancestry::DEFAULT_ANCESTOR_CHAIN_BOUND,
    );
    if !chain.contains(&record.pid) {
        return abort_handoff(
            base_dir,
            audit_ctx,
            anyhow!(
                "the codex supervisor record (pid {}) is not within the ancestor \
                 chain of the live codex process (pid {ancestor_pid}) — refusing \
                 to signal it; nothing was changed",
                record.pid
            ),
        );
    }

    // S-F1: `chain.contains(&record.pid)` above only proves the supervisor
    // is REACHABLE within the bound — it does not rule out a SECOND live
    // codex process sitting between `ancestor_pid` and the supervisor. That
    // shape arises when a plain `codex` is run inside the `!` shell-out of
    // an ALREADY-supervised codex session: the caller's nearest codex
    // ancestor is the INNER, unsupervised codex, but the chain still
    // reaches the OUTER session's supervisor within
    // `DEFAULT_ANCESTOR_CHAIN_BOUND` hops. Signalling it would relaunch the
    // OUTER session in response to a swap the user typed inside the INNER
    // one. Refuse (fail closed) on more than one codex instance, or on an
    // unreadable count (`guard-reader-writer-parity.md` MUST-2) — same
    // posture as the ambiguous-chain case above.
    match count_codex_ancestors_before_for_handoff(
        ancestor_pid,
        record.pid,
        csq_core::providers::codex::ancestry::DEFAULT_ANCESTOR_CHAIN_BOUND,
    ) {
        Some(n) if n <= 1 => {}
        Some(n) => {
            return abort_handoff(
                base_dir,
                audit_ctx,
                anyhow!(
                    "found {n} live codex processes between this shell and its \
                     supervisor (pid {}) — likely a `codex` session nested inside \
                     another supervised one. Exit the inner codex session, then \
                     run `csq swap {target}` there directly; nothing was changed.",
                    record.pid
                ),
            );
        }
        None => {
            return abort_handoff(
                base_dir,
                audit_ctx,
                anyhow!(
                    "could not read the process chain between this shell and its \
                     codex supervisor (pid {}) — refusing to signal it; nothing \
                     was changed",
                    record.pid
                ),
            );
        }
    }

    // Resolve the SAME two shared-state dirs `discover_thread_id` needs,
    // canonicalized per its contract (both are symlinks into shared state —
    // see `providers::codex::thread_id`'s module doc). A resolution
    // failure (dir missing/unreadable) degrades to `None` — "start fresh"
    // — never to a guess. No side effect, so it can run at any point —
    // kept here, immediately before the write, so nothing above depends on
    // it.
    let sessions_dir = std::fs::canonicalize(source_handle_dir.join("sessions")).ok();
    let locks_dir = std::fs::canonicalize(source_handle_dir.join("thread-writer-locks")).ok();
    let thread_id = match (sessions_dir, locks_dir) {
        (Some(sessions), Some(locks)) => csq_core::providers::codex::thread_id::discover_thread_id(
            ancestor_pid,
            &sessions,
            &locks,
        ),
        _ => None,
    };

    // D-F6/S-LOW-1 (round 7): millisecond precision — the supervisor's
    // dynamic validation budget (`sup::remaining_validation_budget`) is
    // computed in milliseconds against this timestamp, and second-precision
    // truncation could under- or over-state a request's true age by up to
    // 999ms against that budget.
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let req = sup::SwapRequest {
        target_slot: target.get(),
        thread_id: thread_id.clone(),
        requested_at,
        // C-F6: a CSPRNG nonce binds this request to its eventual verdict —
        // never the timestamp (see `SwapVerdict`'s doc). `nonce` here is
        // `args.nonce` (`SwapHandoffArgs::nonce`, see its doc) — minted
        // ONCE by `handoff_to_supervisor` before `begin_swap_audit` ran, not
        // regenerated here. Round 7 (D-F3/S-M-1) additionally embedded this
        // same string on the INTENT's payload; round 8 (C-B1/C-B2)
        // RETRACTED that embedding (see `AccountSwapPayload`'s doc) — this
        // request nonce is unaffected by the retraction and remains the
        // sole binding between this request and its eventual verdict.
        nonce: nonce.to_string(),
        chain_id: chain_id.to_string(),
        correlation_id: correlation_id.to_string(),
        from_slot,
    };
    // S-L2: create-if-absent — the caller's `swap_request_pending` check
    // ran before this whole admission walk; a request present NOW means a
    // genuinely concurrent writer landed in the meantime. Refuse rather
    // than clobber it.
    let wrote = match sup::write_swap_request_if_absent(source_handle_dir, &req) {
        Ok(wrote) => wrote,
        Err(e) => {
            return abort_handoff(
                base_dir,
                audit_ctx,
                anyhow!("failed to write swap request: {e}"),
            );
        }
    };
    if !wrote {
        return abort_handoff(
            base_dir,
            audit_ctx,
            anyhow!(
                "a switch is already in progress for this terminal (a concurrent \
                 request landed while this one's admission checks were running); \
                 nothing was changed — try again"
            ),
        );
    }

    if let Err(e) = sup::signal_supervisor(record.pid, libc::SIGUSR1) {
        // Theoretical gap (round 8b, item 12): `signal_supervisor` failing
        // means OUR kill(2) call did not deliver — it does NOT mean the
        // supervisor never consumed the request. The supervisor's poll
        // loop wakes on a PROCESS-WIDE flag (any SIGUSR1 delivery, not
        // only ours) and, once awake, consumes WHATEVER request currently
        // sits at `source_handle_dir` — so a stale/queued signal from
        // elsewhere (or the OS having delivered ours anyway despite
        // reporting an error) can race this exact branch and let the
        // supervisor take ownership of THIS request before we ever get
        // here.
        //
        // `take_swap_request` tells us which happened: `Some(_)` means the
        // request file was STILL PRESENT and WE just consumed/withdrew it
        // — the supervisor genuinely never touched it, so clearing the
        // marker WE just created and writing OUR OWN Failed OUTCOME is
        // correct and exclusive. `None` means it was ALREADY GONE — the
        // supervisor got there first and its OWN in-flight marker is now
        // live; clearing it here would destroy the supervisor's active
        // state (`swap_request_pending` would wrongly report "not
        // pending" while the supervisor is still mid-validation), and
        // writing our own Failed OUTCOME would race the supervisor's own
        // write for the SAME correlation_id (the PRIMARY METHODOLOGICAL
        // DIRECTIVE above: outcome authority is the SIGNAL, and here the
        // supervisor is the one that actually acted on it). In that case
        // we do neither — just report the error to our own caller.
        let request_was_still_pending = sup::take_swap_request(source_handle_dir).is_some();
        let err = anyhow!(
            "failed to signal the codex supervisor (pid {}): {e} — the switch \
             was not started",
            record.pid
        );
        if !request_was_still_pending {
            tracing::warn!(
                error_kind = "swap_signal_failed_but_request_already_consumed",
                pid = record.pid,
                "handoff_to_supervisor_write_and_signal: signal_supervisor \
                 failed, but the swap request was already gone by the time \
                 we checked — the supervisor consumed it via some other \
                 path; leaving its in-flight marker and OUTCOME authority \
                 untouched rather than racing it"
            );
            return Err(err);
        }
        sup::clear_swap_inflight(source_handle_dir);
        return abort_handoff(base_dir, audit_ctx, err);
    }

    // PRIMARY METHODOLOGICAL DIRECTIVE: `signal_supervisor` above succeeded
    // — the supervisor now owns this request's correlated OUTCOME
    // exclusively (see `SwapAuditCorrelation`'s doc in `codex_supervisor.rs`
    // and the two `handoff_reports_*_and_writes_no_outcome_*` tests below).
    // `audit_ctx` is deliberately dropped here, unused, rather than finished
    // — writing anything past this point (accept, refuse, or the bounded
    // wait's own timeout) would race the supervisor's own write of the same
    // correlated OUTCOME and risk a double-write `scan_orphan_intents`
    // cannot see (this struct's `written` idempotency guard lives on the
    // SUPERVISOR's copy of the correlation, not on any copy `csq swap`
    // could construct here).
    drop(audit_ctx);

    // F1 (round 5): the supervisor is the single source of truth for the
    // swap's outcome. Wait (bounded) for its verdict and report FROM it —
    // never report success merely because the signal was delivered.
    //
    // (round 6, item 2): `verdict_wait_timeout()` is the real
    // `VERDICT_WAIT_TIMEOUT_SECS` on every non-test build and on every
    // test that does not install an override — see that function's doc.
    let wait_bound = verdict_wait_timeout();
    match sup::wait_for_swap_verdict(source_handle_dir, &req.nonce, wait_bound) {
        Some(sup::SwapVerdict {
            outcome: sup::SwapOutcome::Accepted,
            ..
        }) => {
            use std::io::Write as _;
            // The supervisor is about to tear this session down; stdout may
            // already be a broken pipe by the time this prints (the outer
            // shell's `!` job control racing the teardown) — a `println!`
            // panicking on `EPIPE` here would turn a successful swap into a
            // reported crash. `writeln!` + discard is the same posture
            // `write_terminal_reset_if_tty` already takes for exactly this
            // class of write.
            if thread_id.is_some() {
                let _ = writeln!(
                    std::io::stdout(),
                    "Switching this terminal to account {target} — codex will restart \
                     and resume this conversation."
                );
            } else {
                // C-R4-15: a bare `codex resume` targets whatever CODEX_HOME the
                // shell happens to have — not necessarily this slot's. The
                // csq-managed form pins the slot explicitly and passes `resume`
                // through to codex, matching the syntax
                // `codex_supervise::relaunch_recovery_hint` already uses for the
                // known-thread-id case (`csq run <slot> -- resume <id>`).
                let _ = writeln!(
                    std::io::stdout(),
                    "Switching this terminal to account {target} — codex will restart; \
                     this conversation can be reopened with `csq run {target} -- resume`."
                );
            }
            Ok(())
        }
        Some(sup::SwapVerdict {
            outcome: sup::SwapOutcome::Refused(reason),
            ..
        }) => Err(anyhow!("swap to account {target} refused — {reason}")),
        None => Err(anyhow!(
            "swap outcome undetermined — check the terminal (no verdict from \
             the codex supervisor within {}s)",
            wait_bound.as_secs_f64()
        )),
    }
}

/// Exec-replace swap. Handles true cross-surface swaps
/// (`RouteKind::CrossSurface`, e.g. Codex→Claude) AND every same-surface
/// pair whose [`InFlightAdoption`] forces exec-replace: ClaudeCode
/// env-transport (`RouteKind::ClaudeCodeEnvTransportExecReplace`), Codex
/// account mismatch (`RouteKind::CodexAccountMismatchExecReplace`), and
/// Gemini/Kimi/Grok's not-yet-characterised adoption capability
/// (`RouteKind::SameSurfaceUnknownAdoptionExecReplace`). All four must
/// tombstone the source handle dir and `exec` a fresh target binary because
/// the running client cannot switch its auth in-flight (frozen process env,
/// a vendor-side reload guard, or a capability nobody has verified). The
/// confirmation wording is derived from whether the SURFACE actually
/// changed (`source_surface != target_surface`) and, when it did not, from
/// `route_kind` — the caller MUST pass one of the four route kinds named
/// above; `SameSurfaceClaudeCode` / `SameSurfaceCodex` never reach this
/// function (see the `unreachable!` arms below).
///
/// ## Append-FIRST ordering (FIX-2, OD-3 corrected)
///
/// The M13b audit contract for exec-replace swaps is:
///
/// 1. (optional) Emit INTENT — before any destructive operation.
///    If intent-persist fails and from_slot is known, FAIL CLOSED before the
///    tombstone rename (the intent gates the side effect, per F-LEDGER-02).
///    If from_slot is absent, skip audit and proceed.
/// 2. Tombstone the source handle dir (INV-P10).
/// 3. Create the target handle dir (the binding step — together with the
///    tombstone, this is the complete "audited side effect").
/// 4. Emit OUTCOME (from the real result of steps 2-3) BEFORE exec.
///    OUTCOME:ok attests tombstone + target-binding. OUTCOME:Failed if
///    target-binding failed.
/// 5. exec() the target binary. Replaces the process on success; returns
///    an error on failure.
///
/// exec(2) replaces the process so code after exec is unreachable on success.
/// OUTCOME therefore MUST precede exec.
fn exec_replace_swap(
    base_dir: &Path,
    source: SourceHandle,
    target: AccountNum,
    target_surface: Surface,
    yes: bool,
    from_slot: Option<AccountNum>,
    route_kind: RouteKind,
) -> Result<()> {
    let source_surface = source.surface();

    // ── Live-codex-ancestor refusal / supervised handoff (issue: "unable to
    // csq swap between codex sessions") ───────────────────────────────────
    //
    // Every route below this point tombstones the source handle dir (INV-P10)
    // and then `exec()`s a fresh target binary IN THIS PROCESS. That is only
    // useful when this process is the thing the user is looking at. When the
    // source surface is Codex, the report was: a running codex session's `!`
    // shell-out spawns `csq swap` as a CHILD of the codex TUI, so `exec()`
    // replaces that child — not the TUI. The TUI is left holding a tombstoned
    // handle dir, nothing prints to the user's screen, and the swap silently
    // does not happen from the user's point of view. Shard S2
    // (`codex_supervise`) now lets `csq run`/`csq exec` supervise codex as a
    // CHILD instead of exec'ing it; when the ancestor IS such a supervisor
    // and the target is ALSO Codex, this hands the swap back to it instead
    // of refusing. Every other case (no supervisor, or a true cross-surface
    // target) still refuses BEFORE any tombstone, exactly as before this
    // shard.
    // Refuses BEFORE any tombstone when this process is nested inside a
    // live Claude Code TUI — item 2 of the governing task. Runs regardless
    // of `source_surface`: unlike the Codex-ancestor check below (which
    // only fires for a Codex source, because ONLY a Codex-surface swap can
    // be routed back to a live supervisor), there is no CC-side handoff
    // path, so any exec-replace route reached while nested inside a live
    // `claude` process is refused outright.
    refuse_if_inside_live_cc_ancestor(target_surface, target)?;

    if refuse_or_handoff_if_inside_live_codex_ancestor(
        source_surface,
        target_surface,
        source.path(),
        base_dir,
        target,
        from_slot,
    )? {
        return Ok(());
    }

    // ── M6 T6.1 spawn-boundary governance gate + M6 T6.2 MCP-proxy rewrite
    // (parity fix, item 1 of the governing task: "governance bypass") ─────
    //
    // GATE-FIRST ordering, chosen deliberately: this runs — and can refuse
    // — before Step 2's tombstone rename further down. A Block/Escalate
    // verdict therefore returns `Err` here with NOTHING tombstoned and
    // NOTHING created; the alternative (moving the tombstone to after the
    // gate, inside `exec_codex_after_binding`) would still work but would
    // put the refusal after the cross-surface confirmation prompt below,
    // making the user answer "Continue? [y/N]" for a swap that governance
    // was always going to refuse. Gating first also means `Err` here never
    // needs a "source handle dir was already tombstoned" recovery hint —
    // there is nothing to recover from.
    //
    // Only evaluated for a Codex TARGET — the same restriction `launch_codex`
    // applies (`SpawnCli::Codex`); a swap into ClaudeCode/Gemini/Kimi/Grok is
    // unaffected. Uses the SAME `evaluate_codex_spawn_gate` /
    // `resolve_codex_mcp_rewrite` functions `launch_codex` calls, so the two
    // spawn surfaces cannot drift apart again.
    #[cfg(feature = "enterprise")]
    let (codex_spawn_scope_env, codex_gate_env): (
        Vec<(String, String)>,
        Option<Box<csq_trust_contract::OperatingEnvelope>>,
    ) = if target_surface == Surface::Codex {
        let start_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut audit_emitter = super::run::build_audit_emitter(
            base_dir,
            csq_core::cli_deps::SurfaceCli::Codex.audit_surface(),
            format!("csq swap account {target}"),
            start_ts,
        );
        super::run::evaluate_codex_spawn_gate(base_dir, &mut audit_emitter)?
    } else {
        (Vec::new(), None)
    };
    #[cfg(not(feature = "enterprise"))]
    let codex_spawn_scope_env: Vec<(String, String)> = Vec::new();

    // S-F5: token-freshness check MOVED here from `exec_codex_after_binding`
    // (which ran it via the just-created TARGET handle dir's `auth.json`
    // symlink, well after Step 2's tombstone and Step 3's target-dir
    // creation). Read directly through the canonical credential path
    // (`codex_canonical_auth_path`) — the same one
    // `verify_codex_target_ready_for_handoff` uses for the supervised
    // handoff — since neither the source tombstone nor the target handle
    // dir exists yet at this point, so there is no symlink to read
    // through. Gated the same way as the M6 gate above (Codex target
    // only), and — like that gate — runs BEFORE any tombstone: an expired
    // token now refuses with NOTHING tombstoned and NOTHING created.
    if target_surface == Surface::Codex {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let canonical_path = codex_canonical_auth_path(base_dir, target);
        super::run::check_codex_token_freshness(&canonical_path, target, now_secs)?;
    }

    let is_cross_surface = source_surface != target_surface;

    // Resume is driven by the TARGET surface's capability, applied on BOTH exec-replace
    // routes (env-transport provider swap AND true cross-surface). `resume_conversation`
    // records only that csq PASSES the flag — it is NOT a claim that the target CLI
    // re-attaches:
    //   - ClaudeCode → `claude --continue`, which re-attaches to the most recent
    //     conversation IN THE CWD (see `exec_claude_code_after_binding`). The transcript
    //     itself survives the source tombstone: `projects/` is a SHARED_ITEM symlinked
    //     into `~/.claude/` (see `session::isolation`).
    //   - Codex → `codex resume --last`. The store it reads IS shared: the fresh
    //     handle dir's `sessions` link resolves to `config-<target>/codex-sessions`,
    //     a symlink into the shared codex state (`CODEX_SHARED.shared`, linked
    //     before vendor login by design — `providers/codex/login.rs`). On an account
    //     swap the exec'd codex therefore DOES reach the tombstoned source's store;
    //     the store-isolation suspect previously recorded for this arm is REFUTED.
    //     (`providers/codex/login.rs`'s `!is_symlink()` assertions govern the
    //     pre-existing-local-entry migration guard and the shared-attachment-failure
    //     fallback, not a fresh slot — the fresh-slot test asserts `is_symlink()`.)
    //   - Gemini/Kimi/Grok → no resume flag csq drives; they start fresh.
    //
    // UNVERIFIED (B3): whether any of these attempts actually RE-ATTACHES. No test
    // exercises a live resume — this file's 52 tests cover routing and pre-exec setup,
    // and nothing in the workspace asserts a resumed session (no test references
    // `resume_conversation` or either exec helper). The user reports the resume does not
    // work; that is evidence against the outcome, not a determination of which of the
    // tombstone/resume claims is false. Settling it needs a live `csq swap` against a
    // real transcript, which the test suite does not do.
    //
    // The Codex arm's earlier mechanism-level suspect (per-slot
    // `codex-sessions`, above) is REFUTED — the link resolves into the shared
    // store; the ClaudeCode arm's DATA is genuinely shared
    // (`projects`) but its `--continue` resolves against the CWD.
    let resume_conversation = matches!(target_surface, Surface::ClaudeCode | Surface::Codex);

    if !is_cross_surface {
        // Same surface, forced exec-replace (env-transport / codex account
        // mismatch / unknown adoption capability): no y/N prompt — the
        // surface itself did not change — just an informational notice.
        // The wording MUST NOT promise an in-flight pickup that cannot
        // happen, nor a resume the target CLI does not perform
        // (`doc-property-claims.md`).
        match route_kind {
            RouteKind::CodexAccountMismatchExecReplace => {
                eprintln!(
                    "Switching Codex account for slot {target} — a running codex \
                     process only reloads auth.json when the account id matches, \
                     so this session is being replaced (codex will be asked to \
                     resume your most recent session)…"
                );
            }
            RouteKind::ClaudeCodeEnvTransportExecReplace => {
                eprintln!(
                    "Switching provider for slot {target} — Claude Code restarts to load \
                     the new endpoint and will attempt to resume this conversation…"
                );
            }
            RouteKind::SameSurfaceUnknownAdoptionExecReplace => {
                eprintln!(
                    "Switching accounts for slot {target} — whether {target_surface} can \
                     adopt an account change in-flight has not been established, so this \
                     session is being replaced…"
                );
            }
            RouteKind::CrossSurface => unreachable!(
                "exec_replace_swap: RouteKind::CrossSurface with is_cross_surface == false \
                 — CrossSurface is returned only when source != target (route()'s first, \
                 unconditional check), which contradicts is_cross_surface being false here"
            ),
            RouteKind::SameSurfaceClaudeCode | RouteKind::SameSurfaceCodex => unreachable!(
                "exec_replace_swap must never be called for an in-flight RouteKind — \
                 handle()'s dispatch match routes these to same_surface_*_audited instead"
            ),
        }
    } else if !yes {
        // True surface change: the current thread stays saved (swap back to attempt a
        // resume); the target surface is asked to resume its most-recent session (or
        // starts fresh for Gemini/Kimi/Grok).
        confirm_surface_switch(source_surface, target_surface, resume_conversation)?;
    }

    // ── Step 1: emit INTENT (before any destructive operation) ──────────────
    //
    // FIX-2: INTENT now precedes the tombstone rename, not follows it.
    // FIX-3: uses typed begin_swap_audit → Ok(None) = skip, Ok(Some) = intent
    //         committed, Err = fail-closed.
    let audit_ctx = match begin_swap_audit(base_dir, from_slot, target) {
        Ok(Some(ctx)) => Some(ctx),
        Ok(None) => {
            // from_slot absent → skip audit, proceed with exec.
            None
        }
        Err(e) => {
            // Intent-persist failed with from_slot present → FAIL CLOSED
            // before the tombstone (the side effect has not started yet).
            // FIX-8: warn not debug — audit visibility posture (M06).
            tracing::warn!(
                error_kind = "audit_intent_persist_failed_cross_surface",
                "M13b: cross-surface swap audit intent could not be persisted — \
                 aborting swap before tombstone (fail-closed per F-LEDGER-02)"
            );
            return Err(e);
        }
    };

    // ── Step 2: tombstone source handle dir (INV-P10) ────────────────────────
    //
    // NOTE (an internal workspace, R1 review LOW-3): unlike the
    // same-surface paths, cross-surface does NOT eagerly call
    // `refresh_current_account_cache` here. The exec'd launch path
    // (`run::launch_*` → `markers::write_current_account`) writes
    // `config-target/.current-account` as part of normal spawn.
    let source_path = source.path();
    if is_term_handle_dir(source_path) {
        rename_handle_dir_to_sweep_tombstone(source_path).map_err(|e| {
            anyhow!(
                "failed to tombstone source handle dir {} before cross-surface exec: {e}",
                redact_path(source_path)
            )
        })?;
    }
    // Legacy config-N source: do NOT remove the config dir (permanent
    // account home per spec 02 INV-01). Just exec; the config dir stays.

    let pid = std::process::id();

    // ── Step 3: create target handle dir (binding step) ──────────────────────
    //
    // FIX-2: split out of exec_* so the result is available for OUTCOME.
    // OUTCOME:ok = tombstone + target-binding committed. OUTCOME:Failed if
    // this step errors. exec(2) runs after OUTCOME.
    let binding_result = create_target_handle_dir(base_dir, target, target_surface, pid);

    // ── Step 4: emit OUTCOME (from real result of steps 2-3) BEFORE exec ─────
    //
    // OUTCOME attests tombstone + target-binding. Must precede exec because
    // exec(2) replaces the process on success, making post-exec code unreachable.
    if let Some(ctx) = audit_ctx {
        let outcome = match &binding_result {
            Ok(()) => OpOutcome::Ok,
            Err(e) => OpOutcome::Failed {
                reason: op_emit::redact_reason(e.to_string()),
            },
        };
        if let Err(e) = op_emit::emit_outcome(
            base_dir,
            &ctx.chain_id,
            EventKind::AccountSwap,
            ctx.payload,
            ctx.correlation_id,
            outcome,
        ) {
            // S-LOW-C (round 8): the tombstone + target-binding steps above
            // already completed (or failed) by this point — this OUTCOME
            // write is best-effort audit trail, never a gate on exec(2) —
            // so a WARN is correct, not a propagated error. `e.fixed_tag()`
            // is a fixed vocabulary, so this never echoes an upstream error
            // body onto the log (`security.md` MUST-2).
            tracing::warn!(
                error_kind = "audit_outcome_emit_failed",
                op = "exec_replace_swap",
                audit_error_kind = e.fixed_tag(),
                "exec_replace_swap: failed to emit AccountSwap OUTCOME record \
                 (op already completed; audit trail incomplete — the INTENT \
                 is left as an orphan for scan_orphan_intents)"
            );
        }
    }

    // ── Step 5: exec ─────────────────────────────────────────────────────────
    //
    // R2-FIX-5: if binding failed after the source was already tombstoned,
    // surface a recovery hint. The OUTCOME:Failed was emitted in step 4.
    binding_result.map_err(|e| {
        anyhow!(
            "{e} — source handle dir was already tombstoned; \
             re-run `csq run {target}` to start a new session"
        )
    })?;

    // M6 T6.2 Shard 3a MCP-proxy rewrite resolution (parity fix, item 1):
    // consumes the SAME resolved envelope the gate above already validated
    // (`codex_gate_env`) — no second `load_spawn_envelope` read (redteam R1
    // finding 1.1). Runs only now, after Step 3, because the envelope
    // snapshot is staged INTO the just-created target handle dir; the gate
    // verdict itself was already enforced before Step 2's tombstone.
    //
    // S-F5: unlike the freshness check above, this genuinely CANNOT move
    // before the tombstone — `resolve_codex_mcp_rewrite` writes
    // `.pact-mcp-envelope.json` INTO the target handle dir, which does not
    // exist until Step 3. What moves instead is the FAILURE HANDLING: a
    // failure here previously left BOTH the tombstoned source AND a
    // half-materialized target handle dir behind (`?` propagated straight
    // out with no cleanup) — this now rolls the target handle dir back
    // (best-effort) before returning, so a failed swap leaves only the
    // (already-surfaced-via-error) tombstoned source, not an orphaned
    // half-bound target directory too.
    #[cfg(feature = "enterprise")]
    let codex_mcp_rewrite: Option<(String, PathBuf)> = if target_surface == Surface::Codex {
        let handle_dir_for_mcp = base_dir.join(format!("term-{pid}"));
        let handle_dir_abs = std::fs::canonicalize(&handle_dir_for_mcp)
            .unwrap_or_else(|_| handle_dir_for_mcp.clone());
        match super::run::resolve_codex_mcp_rewrite(codex_gate_env.as_deref(), &handle_dir_abs) {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&handle_dir_for_mcp);
                return Err(anyhow!(
                    "{e} — source handle dir was already tombstoned, and the \
                     partially-created target handle dir has been removed; \
                     re-run `csq run {target}` to start a new session"
                ));
            }
        }
    } else {
        None
    };
    #[cfg(not(feature = "enterprise"))]
    let codex_mcp_rewrite: Option<(String, PathBuf)> = None;

    match target_surface {
        Surface::Codex => exec_codex_after_binding(
            base_dir,
            target,
            pid,
            resume_conversation,
            &codex_spawn_scope_env,
            codex_mcp_rewrite,
        ),
        Surface::ClaudeCode => {
            exec_claude_code_after_binding(base_dir, target, pid, resume_conversation)
        }
        Surface::Gemini => exec_gemini_after_binding(base_dir, target, pid),
        // W3-4 (an internal journal entry): native-CLI swap exec. Mirrors
        // exec_gemini_after_binding — no resume flag (native CLIs have no
        // resume concept csq drives).
        Surface::Kimi | Surface::Grok => {
            exec_native_after_binding(base_dir, target, target_surface, pid)
        }
    }
}

/// Create the target handle dir for a cross-surface swap.
///
/// This is step 3 of the FIX-2 ordering: split from exec_* so the result
/// is available to OUTCOME before exec(2) replaces the process.
///
/// Returns Ok(()) when the binding directory and its marker are in place.
/// Returns Err when the binding cannot be created.
fn create_target_handle_dir(
    base_dir: &Path,
    target: AccountNum,
    target_surface: Surface,
    pid: u32,
) -> Result<()> {
    match target_surface {
        Surface::Codex => {
            csq_core::session::handle_dir::create_handle_dir_codex(base_dir, target, pid)
                .map(|_| ())
                .map_err(|e| anyhow!("failed to create Codex handle dir for slot {target}: {e}"))
        }
        Surface::ClaudeCode => {
            let claude_home = super::claude_home()?;
            csq_core::session::handle_dir::create_handle_dir(base_dir, &claude_home, target, pid)
                .map(|_| ())
                .map_err(|e| {
                    anyhow!("failed to create ClaudeCode handle dir for slot {target}: {e}")
                })
        }
        Surface::Gemini => {
            // Gemini binding: verify the marker exists and create the handle dir.
            // The vault open and spawn_gemini are deferred to exec_gemini_after_binding.
            create_gemini_handle_dir(base_dir, target, pid)
        }
        // W3-4 (an internal journal entry): native-CLI binding: verify the marker exists
        // and create the handle dir. The vendor-binary resolution + exec are
        // deferred to exec_native_after_binding.
        Surface::Kimi | Surface::Grok => {
            create_native_handle_dir(base_dir, target, target_surface, pid)
        }
    }
}

/// Atomically renames `source_path` to a
/// `.sweep-tombstone-swap-<pid>-<nanos>` sibling so the source is
/// structurally unreachable from subsequent csq commands while
/// remaining intact for any still-running process holding fds into
/// it. The daemon sweep's `cleanup_stale_tombstones` picks up the
/// `.sweep-tombstone-` prefix and reaps it.
///
/// The `-swap-` infix distinguishes swap tombstones from the sweep's
/// own rename-then-remove tombstones; both share the cleanup path
/// but the infix is debuggable evidence for which created it.
///
/// `pub(crate)` (shard S3, item 2 of the governing task): also called by
/// `codex_supervise::tombstone_handle_dir`, which previously carried its own
/// copy of this exact naming convention. Behavior is unchanged — the naming
/// scheme, the parent-lookup failure mode, and the plain `std::fs::rename`
/// call are identical to what codex_supervise's copy did.
pub(crate) fn rename_handle_dir_to_sweep_tombstone(source_path: &Path) -> std::io::Result<()> {
    let base = source_path
        .parent()
        .ok_or_else(|| std::io::Error::other("source handle dir has no parent"))?;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let tombstone = base.join(format!(".sweep-tombstone-swap-{pid}-{nanos:x}"));
    std::fs::rename(source_path, &tombstone)
}

/// Confirmation for a true surface change (e.g. Claude↔Codex). The tombstone step
/// only RENAMES the source handle dir — it deletes nothing — and the ClaudeCode
/// transcript lives in a shared store (`projects`, see `session::isolation`). Codex's
/// store is shared too: the fresh handle dir's `sessions` link resolves to
/// `config-<target>/codex-sessions`, a symlink into the shared codex state
/// (`CODEX_SHARED.shared`), so the store-isolation suspect for this route is REFUTED.
/// `target_resumes` reflects only whether the TARGET CLI is LAUNCHED with a resume flag
/// (`claude --continue` / `codex resume --last`) or starts fresh (Gemini/Kimi/Grok);
/// it is NOT a claim that the flag re-attaches — that outcome is UNVERIFIED (see
/// `exec_replace_swap`).
fn confirm_surface_switch(source: Surface, target: Surface, target_resumes: bool) -> Result<()> {
    use std::io::{BufRead, Write};
    let target_line = if target_resumes {
        format!("{target} will attempt to resume its most recent session.")
    } else {
        format!("A new {target} session will start.")
    };
    eprintln!(
        "Swapping from {source} to {target}. This {source} conversation stays saved — \
         swap back to return to it. {target_line}"
    );
    eprint!("Continue? [y/N]: ");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    if !line.trim().eq_ignore_ascii_case("y") {
        return Err(anyhow!("swap cancelled"));
    }
    Ok(())
}

/// Exec the Codex binary after the target handle dir has already been created
/// by `create_target_handle_dir`. The handle dir path is re-derived from the PID.
///
/// When `resume` is true (a swap INTO a Codex slot), exec `codex resume --last`
/// to ASK codex to re-attach to its most-recent session. The store it reads IS the
/// tombstoned source's: the fresh handle dir's `sessions` link resolves to
/// `config-<target>/codex-sessions`, a symlink into the shared codex state
/// (`CODEX_SHARED.shared`, linked before vendor login by design), so the earlier
/// store-isolation suspect is REFUTED. Whether the resume actually re-attaches
/// remains UNVERIFIED (see `exec_replace_swap`). Otherwise exec bare `codex`.
#[cfg(unix)]
fn exec_codex_after_binding(
    base_dir: &Path,
    target: AccountNum,
    pid: u32,
    resume: bool,
    codex_spawn_scope_env: &[(String, String)],
    codex_mcp_rewrite: Option<(String, PathBuf)>,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // Re-derive the handle dir path — do NOT call `create_handle_dir_codex` again.
    // `create_target_handle_dir` (step 3) already created `term-<pid>` and wrote its
    // live `.live-pid`; a second create with the same pid trips the live-PID guard and
    // aborts the swap. `create_handle_dir_codex` names the dir `term-<pid>`, so deriving
    // the path here is exact. Mirrors the ClaudeCode + Gemini exec arms.
    let handle_dir = base_dir.join(format!("term-{pid}"));

    // Cross-slot swap-resume shard S3 (parity, item 3 of the governing
    // task): this used to build a bare `Command::new(CLI_BINARY)` setting
    // only `CODEX_HOME` + removing `CLAUDE_CONFIG_DIR` — bypassing
    // `launch_codex`'s env strip (`strip_sensitive_env`, `CLAUDE_HOME`
    // removal), its sandbox/approval flag derivation (GH an internal ticket), and its JWT
    // pre-flight (Task 8). This process must `exec()` in-process rather
    // than route through `launch_codex`'s supervised spawn+wait — it runs
    // from a plain shell here (`refuse_or_handoff_if_inside_live_codex_ancestor`
    // already sent the supervised, live-codex-ancestor case to
    // `handoff_to_supervisor` instead, which never reaches this function) —
    // so it now builds its command through the SAME helpers `launch_codex`
    // uses instead of a hand-rolled subset of them.
    //
    // Parity fix (item 1 of the governing task, "governance bypass"): the
    // M6 T6.1 spawn gate and the M6 T6.2 MCP-proxy rewrite now DO run for
    // this exec path — `exec_replace_swap` evaluates the gate before the
    // Step-2 tombstone (via `super::run::evaluate_codex_spawn_gate`, the
    // SAME function `launch_codex` calls) and resolves the MCP rewrite
    // after Step 3 (via `super::run::resolve_codex_mcp_rewrite`), then
    // passes both results down here as `codex_spawn_scope_env` and
    // `codex_mcp_rewrite` — plain, cfg-independent types, so this
    // function's signature does not need to name `OperatingEnvelope`
    // (which does not exist as a type in a non-`enterprise` build).
    //
    // S-F5: the token-freshness check that used to run HERE (reading
    // through this just-created handle dir's `auth.json` symlink) has
    // MOVED to `exec_replace_swap`, before Step 2's tombstone — an expired
    // token now refuses with nothing tombstoned and nothing created,
    // instead of discovering the expiry only after both destructive/
    // creating steps have already run.
    let rest: Vec<String> = if resume {
        // `codex resume --last`: ask codex to re-attach to the most-recent recorded session.
        vec!["resume".to_string(), "--last".to_string()]
    } else {
        Vec::new()
    };
    let mut cmd = super::run::build_codex_exec_command(base_dir, target, &handle_dir, &rest)?;

    // M6 T6.4: inject the advisory path-scope env (empty unless the gate
    // returned Conditional with a declared path-scope). Mirrors
    // `launch_codex`'s identical loop over `codex_spawn_scope_env`.
    for (k, v) in codex_spawn_scope_env {
        cmd.env(k, v);
    }

    // M6 T6.2 Shard 3a: same materialize-then-verify sequence
    // `launch_codex`'s `LayerControl::Inherit` arm runs — breaking the
    // Inherit symlink `create_target_handle_dir` planted only when an MCP
    // rewrite is actually staged; a session with no MCP policy keeps the
    // v2.3.1 symlink path verbatim.
    let mcp_wrap = codex_mcp_rewrite
        .as_ref()
        .map(|(bin, path)| (bin.as_str(), path.as_path()));
    if mcp_wrap.is_some() {
        let skipped = super::run::materialize_handle_config_toml(
            base_dir,
            target,
            &handle_dir,
            None,
            mcp_wrap,
        )
        .map_err(|e| anyhow!("failed to materialize per-spawn config.toml (MCP proxy): {e}"))?;
        super::run::warn_skipped_remote_mcp(&skipped);
        // Post-rename re-stat closes the materialize->spawn TOCTOU window.
        super::run::verify_codex_handle_config_toml_is_regular_file(&handle_dir)?;
    }

    // S-F3 (this file's instance): `err` is `std::io::Error` from a failed
    // `exec()` and is not expected to carry secrets, but this whole module
    // is OAuth-adjacent (`security.md` MUST-2/Rule 8) — route every
    // operator-facing error through the same redaction the rest of this
    // exec-error family in this file now uses, rather than trusting each
    // call site's `{e}`/`{err}` interpolation to stay harmless as the
    // underlying error type evolves.
    let err = cmd.exec();
    Err(anyhow!(
        "exec `{}` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {}",
        codex_surface::CLI_BINARY,
        csq_core::error::redact_tokens(&err.to_string())
    ))
}

/// Exec the ClaudeCode binary after the target handle dir has already been
/// created by `create_target_handle_dir`.
///
/// When `resume` is true (any swap INTO a ClaudeCode slot), exec `claude --continue`.
/// The transcript under `~/.claude/projects/` is a SHARED_ITEM (`session::isolation`)
/// that survives the source tombstone, so the conversation DATA stays reachable from
/// the fresh handle dir — but `--continue` is documented as re-attaching to the most
/// recent conversation IN THE CWD, and whether it re-attaches at all is UNVERIFIED
/// (no live resume is covered by this file's tests; see `exec_replace_swap`).
#[cfg(unix)]
fn exec_claude_code_after_binding(
    base_dir: &Path,
    target: AccountNum,
    pid: u32,
    resume: bool,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // Re-derive the handle dir path — do NOT call `create_handle_dir` again.
    // `create_target_handle_dir` (step 3) already created `term-<pid>` and wrote
    // its `.live-pid = <pid>`; a second `create_handle_dir` with the same pid sees
    // that live marker and refuses ("in use by live PID … Refusing to remove"),
    // which would abort every ClaudeCode-target exec-replace swap. `create_handle_dir`
    // names the dir `term-<pid>` (see its impl), so deriving the path here is exact.
    // Mirrors `exec_gemini_after_binding`, which already re-derives rather than recreates.
    let handle_dir = base_dir.join(format!("term-{pid}"));

    // Security review 1386 M4 (sibling instance): the usual non-canonical
    // fallback stays for `handle_dir_abs` (still the right `CLAUDE_CONFIG_DIR`
    // to exec against) but the keychain mirror below is gated on canonicalize
    // having actually succeeded.
    let (handle_dir_abs, keychain_write_allowed) =
        csq_core::credentials::keychain::canonicalize_for_keychain_sync(&handle_dir);

    // v4 A2 ("switch now or say so"): this is a FRESH term-<pid> dir with no
    // prior CC session, so a readable X gets a FORCED write; a write
    // failure or a lock timeout/failure means this swap does NOT exec — a
    // fresh dir with a colliding stale item from PID reuse must not launch
    // against the wrong account.
    //
    // F3/KC4-3: a canonicalize FAILURE (as opposed to a readable-keychain
    // Unreadable result) means we cannot even name this dir's absolute
    // path, so "CC falls back to the symlinked .credentials.json" does not
    // follow — refuse to exec rather than launch against an unverified path.
    if keychain_write_allowed {
        if let Err(msg) =
            csq_core::credentials::keychain::force_sync_for_launch(base_dir, &handle_dir_abs)
        {
            return Err(anyhow!("csq swap: {msg}"));
        }
    } else {
        return Err(anyhow!(
            "csq swap: keychain item could not be located; retry the launch"
        ));
    }

    let mut cmd = std::process::Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir_abs);
    cmd.env_remove(codex_surface::HOME_ENV_VAR);
    if resume {
        // `-c/--continue`: re-attach to the most recent conversation in the CWD.
        // The transcript is shared across handle dirs (SHARED_ITEMS `projects`), so
        // the conversation data stays reachable from the fresh dir — but the actual
        // re-attach is UNVERIFIED, and `--continue` resolves against the CWD.
        cmd.arg("--continue");
    }

    // S-F3 (this file's instance): see the codex exec arm's identical note.
    let err = cmd.exec();
    Err(anyhow!(
        "exec `claude` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {}",
        csq_core::error::redact_tokens(&err.to_string())
    ))
}

#[cfg(not(unix))]
fn exec_codex_after_binding(
    _base_dir: &Path,
    _target: AccountNum,
    _pid: u32,
    _resume: bool,
    _codex_spawn_scope_env: &[(String, String)],
    _codex_mcp_rewrite: Option<(String, PathBuf)>,
) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

#[cfg(not(unix))]
fn exec_claude_code_after_binding(
    _base_dir: &Path,
    _target: AccountNum,
    _pid: u32,
    _resume: bool,
) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

/// FIX-2: Create the Gemini handle dir (binding step, step 3 of cross_surface_exec).
///
/// Verifies the binding marker exists, creates `term-<pid>/`, writes
/// `.csq-account`. Returns Ok(()) on success. Does NOT open the vault or
/// exec — those are deferred to `exec_gemini_after_binding` (step 5).
#[cfg(unix)]
fn create_gemini_handle_dir(base_dir: &Path, target: AccountNum, pid: u32) -> Result<()> {
    use csq_core::accounts::markers;
    use csq_core::credentials::file as cred_file;

    // Refuse symlink at the binding marker.
    let binding_path = cred_file::canonical_path_for(base_dir, target, Surface::Gemini);
    let meta = std::fs::symlink_metadata(&binding_path).map_err(|e| {
        anyhow!(
            "stat {} — Gemini binding missing for swap target {target}; \
             run `csq setkey gemini --slot {target}` or `csq login {target} --provider gemini` first ({e})",
            redact_path(&binding_path)
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing Gemini swap: {} is a symlink — external mutation detected",
            redact_path(&binding_path)
        ));
    }

    // Build the minimal handle dir + .csq-account marker.
    let handle_dir = base_dir.join(format!("term-{pid}"));
    std::fs::create_dir_all(&handle_dir)
        .map_err(|e| anyhow!("failed to create Gemini handle dir for swap target {target}: {e}"))?;
    // M4-7: use UUID marker when available.
    let marker_result =
        match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get()) {
            Some(uuid) => markers::write_csq_account(&handle_dir, uuid),
            None => markers::write_csq_account_legacy(&handle_dir, target),
        };
    if let Err(e) = marker_result {
        let _ = std::fs::remove_dir_all(&handle_dir);
        return Err(anyhow!(
            ".csq-account marker write failed for swap target {target}: {e}"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_gemini_handle_dir(_base_dir: &Path, _target: AccountNum, _pid: u32) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

/// Exec the Gemini binary after the target handle dir has already been created
/// by `create_gemini_handle_dir` (step 3). Vault open + spawn_gemini are step 5.
///
/// PR-G4b: mirrors `launch_gemini` in `commands/run.rs`.
/// **Why a duplicate**: both call sites are inside csq-cli; factoring into
/// csq-core requires a new `gemini::session` module + typed error enum;
/// deferred until PR-G5 (desktop) becomes the third caller.
#[cfg(unix)]
fn exec_gemini_after_binding(base_dir: &Path, target: AccountNum, pid: u32) -> Result<()> {
    use csq_core::platform::secret;
    use csq_core::providers::gemini::spawn::spawn_gemini;

    let handle_dir = base_dir.join(format!("term-{pid}"));
    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    let vault = secret::open_default_vault().map_err(|e| {
        let _ = std::fs::remove_dir_all(&handle_dir);
        anyhow!(
            "Gemini vault unavailable for swap target {target} ({}): {e}",
            e.error_kind_tag()
        )
    })?;

    println!("Swapping to Gemini account {} (term-{})...", target, pid);

    match spawn_gemini(
        base_dir,
        &handle_dir_abs,
        target,
        Vec::new(),
        vault.as_ref(),
    ) {
        Ok(_never) => unreachable!("spawn_gemini returns Infallible on success"),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&handle_dir);
            // S-F3 (this file's instance): see the codex exec arm's note.
            Err(anyhow!(
                "Gemini swap exec failed after source handle dir was tombstoned — \
                 re-run `csq run {target}` to relaunch. Error: {}",
                csq_core::error::redact_tokens(&e.to_string())
            ))
        }
    }
}

#[cfg(not(unix))]
fn exec_gemini_after_binding(_base_dir: &Path, _target: AccountNum, _pid: u32) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

/// W3-4 (an internal journal entry): Create the native-CLI (Kimi/Grok) handle dir for a
/// cross-surface swap (binding step, step 3 of `exec_replace_swap`).
///
/// Verifies the credential-less binding marker exists, creates `term-<pid>/`,
/// writes `.csq-account`. Returns Ok(()) on success. Does NOT resolve the
/// vendor binary or exec — those are deferred to `exec_native_after_binding`
/// (step 5). Mirrors `create_gemini_handle_dir`.
#[cfg(unix)]
fn create_native_handle_dir(
    base_dir: &Path,
    target: AccountNum,
    target_surface: Surface,
    pid: u32,
) -> Result<()> {
    use csq_core::accounts::markers;
    use csq_core::providers::native;

    let descriptor = native::descriptor(target_surface).ok_or_else(|| {
        anyhow!("swap target surface {target_surface} is not a native-CLI surface")
    })?;

    // Refuse symlink at the binding marker — same posture as
    // `create_gemini_handle_dir`.
    let binding_path = native::marker_path(base_dir, target, target_surface);
    let meta = std::fs::symlink_metadata(&binding_path).map_err(|e| {
        anyhow!(
            "stat {} — {} binding missing for swap target {target}; \
             run `csq login {target} --provider {}` first ({e})",
            redact_path(&binding_path),
            descriptor.display_name,
            descriptor.id,
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing {} swap: {} is a symlink — external mutation detected",
            descriptor.display_name,
            redact_path(&binding_path)
        ));
    }

    // Build the minimal handle dir + .csq-account marker.
    let handle_dir = base_dir.join(format!("term-{pid}"));
    std::fs::create_dir_all(&handle_dir).map_err(|e| {
        anyhow!(
            "failed to create {} handle dir for swap target {target}: {e}",
            descriptor.display_name
        )
    })?;
    // M4-7: use UUID marker when available.
    let marker_result =
        match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get()) {
            Some(uuid) => markers::write_csq_account(&handle_dir, uuid),
            None => markers::write_csq_account_legacy(&handle_dir, target),
        };
    if let Err(e) = marker_result {
        let _ = std::fs::remove_dir_all(&handle_dir);
        return Err(anyhow!(
            ".csq-account marker write failed for swap target {target}: {e}"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_native_handle_dir(
    _base_dir: &Path,
    _target: AccountNum,
    _target_surface: Surface,
    _pid: u32,
) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

/// W3-4 (an internal journal entry): Exec the native vendor binary (`kimi`/`grok`) after
/// the target handle dir has already been created by
/// `create_native_handle_dir`. The handle dir path is re-derived from the
/// PID (mirrors `exec_codex_after_binding`/`exec_claude_code_after_binding`
/// — a second `create_*_handle_dir` call with the same pid would trip the
/// live-PID guard).
///
/// No resume flag: native CLIs have no resume concept csq drives (mirrors
/// `exec_gemini_after_binding`) — `resume_conversation` in
/// `exec_replace_swap` is already `false` for `Surface::Kimi | Surface::Grok`.
#[cfg(unix)]
fn exec_native_after_binding(
    // Unused: unlike Codex/Gemini, native CLIs have no HOME-equivalent env
    // var to redirect — the handle dir written by `create_native_handle_dir`
    // exists only for `.csq-account` bookkeeping, and the vendor binary
    // execs directly in the caller's inherited cwd.
    _base_dir: &Path,
    target: AccountNum,
    target_surface: Surface,
    pid: u32,
) -> Result<()> {
    use csq_core::providers::native;
    use std::os::unix::process::CommandExt;

    let descriptor = native::descriptor(target_surface).ok_or_else(|| {
        anyhow!("swap target surface {target_surface} is not a native-CLI surface")
    })?;

    let binary_path = csq_core::cli_deps::install_path::find_in_path(descriptor.binary)
        .ok_or_else(|| {
            anyhow!(
                "{} binary ({}) not found on PATH or in its known install dir — \
                 run `csq cli install {}` first",
                descriptor.display_name,
                descriptor.binary,
                descriptor.binary
            )
        })?;

    println!(
        "Swapping to {} account {} (term-{})...",
        descriptor.display_name, target, pid
    );

    let mut cmd = std::process::Command::new(&binary_path);
    // Scrub csq-session-dir env so the native CLI never accidentally
    // resolves a stale csq-managed config dir from the source surface
    // (mirrors exec_codex_after_binding / exec_claude_code_after_binding's
    // identical scrub posture).
    cmd.env_remove("CLAUDE_CONFIG_DIR");
    cmd.env_remove("CLAUDE_HOME");
    cmd.env_remove(codex_surface::HOME_ENV_VAR);

    // S-F3 (this file's instance): see the codex exec arm's identical note.
    let err = cmd.exec();
    Err(anyhow!(
        "exec `{}` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {}",
        descriptor.binary,
        csq_core::error::redact_tokens(&err.to_string())
    ))
}

#[cfg(not(unix))]
fn exec_native_after_binding(
    _base_dir: &Path,
    _target: AccountNum,
    _target_surface: Surface,
    _pid: u32,
) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

// ─── Daemon cache invalidation ───────────────────────────────────────

/// Best-effort cache invalidation: notify the daemon (Unix socket or
/// Windows named pipe) that on-disk account state changed. Routes through
/// the single cross-platform chokepoint — see `csq_core::daemon::notify`
/// (an internal ticket).
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    csq_core::daemon::notify::cache_invalidation(base_dir);
}

// ─── Tests ──────────────────────────────────────────────────────────
//
// HERMETICITY NOTE: any test that calls `refuse_if_inside_live_cc_ancestor`
// or `exec_replace_swap` DIRECTLY (i.e. not via a spawned, renamed-binary
// fixture) and asserts a DETERMINISTIC outcome MUST wrap it in
// `let _guard = force_find_cc_pid(None);` (or `Some(pid)` to simulate an
// ancestor). Without it the test reads the REAL process ancestry, which
// includes a live `claude` process on every developer machine and every
// agentic-coding-session CI run (`test-hermeticity.md`) — see
// `refuse_if_inside_live_cc_ancestor_is_ok_when_no_ancestor` for the
// pattern. The spawned-process tests below (which rename a copy of this
// binary to `claude`) are the exception: they deliberately do NOT use the
// override, because they exist to prove the REAL detector still works.

#[cfg(test)]
#[allow(dead_code)] // ensure markers/Surface paths compile on all targets
mod tests {
    use super::*;

    /// Wait (bounded, 10s) until `path` holds a complete pid. Polling for
    /// mere EXISTENCE races the shell's `echo $! > file`, which creates the
    /// file before writing it: the enterprise CI leg read it empty
    /// (`ParseIntError { kind: Empty }`). A timeout is a FAILURE, never a skip.
    fn wait_for_pid_file(path: &std::path::Path) -> u32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(s) = std::fs::read_to_string(path) {
                if let Ok(pid) = s.trim().parse::<u32>() {
                    return pid;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{} never held a complete pid within 10s",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    #[cfg(unix)]
    use crate::cli::commands::fake_daemon_test_support::{
        spawn_fake_healthy_daemon, spawn_no_daemon_env_guard,
    };

    // Unit tests exercise the pure helpers (source detection +
    // target-surface resolution). Full swap integration is covered
    // by the handle_dir repoint tests and the new cross-surface
    // integration tests in csq-cli/tests/.

    /// S-H-A/D-F1: repoint succeeded, and the keychain genuinely agrees
    /// with the marker (`AlreadyCurrent`/`Reconciled`) — success, printing
    /// the account the MARKER resolved to.
    #[test]
    fn decide_ok_repoint_disposition_success_on_already_current_or_reconciled() {
        let acct = AccountNum::try_from(4u16).unwrap();
        for outcome in [
            csq_core::credentials::keychain::ReconcileOutcome::AlreadyCurrent {
                marker_account: acct,
            },
            csq_core::credentials::keychain::ReconcileOutcome::Reconciled {
                marker_account: acct,
            },
        ] {
            assert_eq!(
                decide_ok_repoint_disposition(&outcome, "unused"),
                OkRepointDisposition::Success {
                    marker_account: acct
                }
            );
        }
    }

    /// S-H-A/D-F1: repoint succeeded, but reconcile could not confirm the
    /// keychain followed (`WriteFailed`/`KeychainUnknown`/
    /// `MarkerUnreadable`) — every one of these MUST fail, carrying the
    /// reconcile line, rather than reporting a clean "Swapped".
    #[test]
    fn decide_ok_repoint_disposition_fails_on_every_non_reconciled_outcome() {
        let acct = AccountNum::try_from(4u16).unwrap();
        let outcomes = [
            csq_core::credentials::keychain::ReconcileOutcome::MarkerUnreadable,
            csq_core::credentials::keychain::ReconcileOutcome::WriteFailed {
                marker_account: acct,
            },
            csq_core::credentials::keychain::ReconcileOutcome::KeychainUnknown {
                marker_account: acct,
                reason: csq_core::credentials::keychain::KeychainUnknownReason::ForeignLogin,
            },
        ];
        for outcome in outcomes {
            match decide_ok_repoint_disposition(&outcome, "terminal on 4, reconcile failed") {
                OkRepointDisposition::Fail(msg) => {
                    assert_eq!(msg, "terminal on 4, reconcile failed");
                }
                other => panic!("expected Fail for {outcome:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn is_term_handle_dir_accepts_term_prefix() {
        assert!(is_term_handle_dir(Path::new("/base/term-42")));
        assert!(is_term_handle_dir(Path::new("/base/term-1001")));
    }

    #[test]
    fn is_term_handle_dir_rejects_config_prefix() {
        assert!(!is_term_handle_dir(Path::new("/base/config-3")));
        assert!(!is_term_handle_dir(Path::new("/base/not-a-handle")));
    }

    #[test]
    fn is_legacy_config_dir_accepts_config_prefix() {
        assert!(is_legacy_config_dir(Path::new("/base/config-7")));
        assert!(!is_legacy_config_dir(Path::new("/base/term-99")));
    }

    #[test]
    fn source_handle_surface_matches_variant() {
        let ch = SourceHandle::ClaudeCode(PathBuf::from("/x/term-1"));
        assert_eq!(ch.surface(), Surface::ClaudeCode);
        let cx = SourceHandle::Codex(PathBuf::from("/x/term-2"));
        assert_eq!(cx.surface(), Surface::Codex);
    }

    // ── C-R4-8/S-F5: stuck-switch message names the file that is actually
    // present ──────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn describe_stuck_swap_paths_names_inflight_when_only_inflight_present() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(sup::SWAP_INFLIGHT_FILE), "1\n").unwrap();
        let described = describe_stuck_swap_paths(dir.path());
        assert!(
            described.contains(sup::SWAP_INFLIGHT_FILE),
            "only the inflight marker is on disk — the message must name it; got {described:?}"
        );
        assert!(
            !described.contains(sup::SWAP_REQUEST_FILE),
            "the request file does not exist — it must not be named; got {described:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn describe_stuck_swap_paths_names_request_when_only_request_present() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(sup::SWAP_REQUEST_FILE), "garbage\n").unwrap();
        let described = describe_stuck_swap_paths(dir.path());
        assert!(
            described.contains(sup::SWAP_REQUEST_FILE),
            "only the request file is on disk — the message must name it; got {described:?}"
        );
        assert!(
            !described.contains(sup::SWAP_INFLIGHT_FILE),
            "the inflight marker does not exist — it must not be named; got {described:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn describe_stuck_swap_paths_names_both_when_both_present() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(sup::SWAP_INFLIGHT_FILE), "1\n").unwrap();
        std::fs::write(dir.path().join(sup::SWAP_REQUEST_FILE), "garbage\n").unwrap();
        let described = describe_stuck_swap_paths(dir.path());
        assert!(
            described.contains(sup::SWAP_INFLIGHT_FILE)
                && described.contains(sup::SWAP_REQUEST_FILE),
            "both files are on disk — the message must name both; got {described:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn describe_stuck_swap_paths_falls_back_to_request_when_neither_present() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let described = describe_stuck_swap_paths(dir.path());
        assert!(
            described.contains(sup::SWAP_REQUEST_FILE),
            "neither file is observably present (e.g. a race) — the original, \
             still-accurate suggestion must be kept; got {described:?}"
        );
    }

    // ── Live-codex-ancestor refusal ("unable to csq swap between codex
    // sessions") ──────────────────────────────────────────────────────────

    #[test]
    fn refusal_is_a_noop_for_non_codex_source_surfaces() {
        let target = AccountNum::try_from(5u16).unwrap();
        let dir = tempfile::TempDir::new().expect("tempdir");
        for s in [Surface::ClaudeCode, Surface::Gemini] {
            assert!(
                !refuse_or_handoff_if_inside_live_codex_ancestor(
                    s,
                    Surface::Codex,
                    dir.path(),
                    dir.path(),
                    target,
                    None
                )
                .unwrap(),
                "a non-Codex source must be a no-op (Ok(false)), never a handoff or refusal"
            );
        }
    }

    #[test]
    fn refusal_is_ok_for_codex_source_when_not_under_a_live_codex_ancestor() {
        // Under `cargo test`/`cargo nextest` this process is not a
        // descendant of a real `codex` — must not refuse, and must not
        // report a handoff (there is no ancestor to hand off to). The
        // positive case (a genuine codex ancestor) is exercised by the
        // spawned test below.
        let target = AccountNum::try_from(5u16).unwrap();
        let dir = tempfile::TempDir::new().expect("tempdir");
        assert!(!refuse_or_handoff_if_inside_live_codex_ancestor(
            Surface::Codex,
            Surface::Codex,
            dir.path(),
            dir.path(),
            target,
            None
        )
        .unwrap());
    }

    /// Spawned-process test: a genuine live process named `codex`, with a
    /// CHILD (distinctly named, standing in for `csq`'s own binary) that
    /// calls `refuse_or_handoff_if_inside_live_codex_ancestor` against a
    /// handle dir carrying NO supervisor record, MUST get an `Err` naming
    /// the pid and directing the user to exit codex and run `csq run N` —
    /// never a silent `Ok` or a handoff. Mirrors
    /// `csq-core::providers::codex::ancestry`'s own spawned tests.
    #[cfg(unix)]
    #[test]
    fn refuses_before_any_tombstone_when_a_live_codex_ancestor_is_detected() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        const RESULT_ENV: &str = "CSQ_TEST_SWAP_ANCESTOR_REFUSAL_RESULT_FILE";
        const CHILD_EXE_ENV: &str = "CSQ_TEST_SWAP_ANCESTOR_REFUSAL_CHILD_EXE";
        const PARENT_TEST: &str = "cli::commands::swap::tests::swap_ancestor_refusal_parent_helper";
        const CHILD_TEST: &str = "cli::commands::swap::tests::swap_ancestor_refusal_child_probe";

        fn copy_self_to(dir: &Path, name: &str) -> PathBuf {
            let src = std::env::current_exe().expect("current_exe for the running test binary");
            let dst = dir.join(name);
            std::fs::copy(&src, &dst).expect("copy running test binary to renamed path");
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dst).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dst, perms).unwrap();
            dst
        }

        let dir = tempfile::TempDir::new().expect("tempdir");
        let result_path = dir.path().join("result.txt");
        let codex_bin = copy_self_to(dir.path(), "codex");
        let child_bin = copy_self_to(dir.path(), "csq-test-swap-child-probe");

        let mut parent = Command::new(&codex_bin)
            .args(["--ignored", "--exact", PARENT_TEST])
            .env(RESULT_ENV, &result_path)
            .env(CHILD_EXE_ENV, &child_bin)
            .env("CSQ_TEST_SWAP_ANCESTOR_REFUSAL_CHILD_TEST", CHILD_TEST)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn renamed-to-codex parent helper");
        let parent_pid = parent.id();

        let deadline = Instant::now() + Duration::from_secs(60);
        let content = loop {
            if let Ok(s) = std::fs::read_to_string(&result_path) {
                if !s.is_empty() {
                    break s;
                }
            }
            if Instant::now() >= deadline {
                let _ = parent.kill();
                panic!("result file never became non-empty within the deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let status = parent.wait().expect("wait on parent helper");
        assert!(
            status.success(),
            "parent helper exited non-zero: {status:?}"
        );

        let content = content.trim();
        assert!(
            content.starts_with("err:"),
            "expected a refusal (Err), got {content:?}"
        );
        assert!(
            content.contains(&parent_pid.to_string()),
            "refusal message must name the detected ancestor pid {parent_pid}; got {content:?}"
        );
        assert!(
            content.contains("csq run"),
            "refusal message must direct the user to `csq run N`; got {content:?}"
        );
    }

    /// Ignored helper: spawns a CHILD (a distinctly-named copy) running the
    /// child probe, waits for it, then exits.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn swap_ancestor_refusal_parent_helper() {
        let child_exe = std::env::var("CSQ_TEST_SWAP_ANCESTOR_REFUSAL_CHILD_EXE")
            .expect("child exe env var set");
        let child_test = std::env::var("CSQ_TEST_SWAP_ANCESTOR_REFUSAL_CHILD_TEST")
            .expect("child test name env var set");
        let status = std::process::Command::new(&child_exe)
            .args(["--ignored", "--exact", &child_test])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .expect("spawn child probe");
        assert!(status.success(), "child probe exited non-zero: {status:?}");
    }

    /// Ignored helper: calls `refuse_or_handoff_if_inside_live_codex_ancestor`
    /// from ITS OWN ancestry, against a handle dir with no supervisor
    /// record, and writes the outcome to the result file.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn swap_ancestor_refusal_child_probe() {
        use std::io::Write as _;
        let out_path = std::env::var("CSQ_TEST_SWAP_ANCESTOR_REFUSAL_RESULT_FILE")
            .expect("result file env var set");
        let target = AccountNum::try_from(5u16).unwrap();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let line = match refuse_or_handoff_if_inside_live_codex_ancestor(
            Surface::Codex,
            Surface::Codex,
            dir.path(),
            dir.path(),
            target,
            None,
        ) {
            Ok(false) => "ok\n".to_string(),
            Ok(true) => "handoff\n".to_string(),
            Err(e) => format!("err:{e}\n"),
        };
        let mut f = std::fs::File::create(&out_path).expect("create result file");
        f.write_all(line.as_bytes()).expect("write result file");
    }

    // ── Live-CC-ancestor refusal (item 2 of the governing task) ─────────

    #[test]
    fn refuse_if_inside_live_cc_ancestor_is_ok_when_no_ancestor() {
        // Hermetic: force "no ancestor" via the injection seam rather than
        // relying on this test binary's REAL ancestry — `cargo test`
        // invoked from inside an agentic coding session genuinely IS a
        // descendant of a live `claude` process, which would otherwise
        // make this assertion host-dependent (`test-hermeticity.md`). The
        // positive case (a genuine claude ancestor) is exercised by the
        // spawned test below, which does NOT use this override and so
        // still proves the real detector.
        let _cc_guard = force_find_cc_pid(None);
        let target = AccountNum::try_from(5u16).unwrap();
        assert!(refuse_if_inside_live_cc_ancestor(Surface::Codex, target).is_ok());
    }

    /// Spawned-process test (mirrors `refuses_before_any_tombstone_when_a_
    /// live_codex_ancestor_is_detected` above, for the Claude Code side):
    /// a genuine live process named `claude`, with a CHILD calling
    /// `refuse_if_inside_live_cc_ancestor`, MUST get an `Err` naming the
    /// detected ancestor pid and directing the user to exit claude and run
    /// `csq run N` — never a silent `Ok`.
    #[cfg(unix)]
    #[test]
    fn refuses_before_any_tombstone_when_a_live_cc_ancestor_is_detected() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        const RESULT_ENV: &str = "CSQ_TEST_SWAP_CC_ANCESTOR_REFUSAL_RESULT_FILE";
        const CHILD_EXE_ENV: &str = "CSQ_TEST_SWAP_CC_ANCESTOR_REFUSAL_CHILD_EXE";
        const PARENT_TEST: &str =
            "cli::commands::swap::tests::swap_cc_ancestor_refusal_parent_helper";
        const CHILD_TEST: &str = "cli::commands::swap::tests::swap_cc_ancestor_refusal_child_probe";

        fn copy_self_to(dir: &Path, name: &str) -> PathBuf {
            let src = std::env::current_exe().expect("current_exe for the running test binary");
            let dst = dir.join(name);
            std::fs::copy(&src, &dst).expect("copy running test binary to renamed path");
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dst).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dst, perms).unwrap();
            dst
        }

        let dir = tempfile::TempDir::new().expect("tempdir");
        let result_path = dir.path().join("result.txt");
        let claude_bin = copy_self_to(dir.path(), "claude");
        let child_bin = copy_self_to(dir.path(), "csq-test-swap-cc-child-probe");

        let mut parent = Command::new(&claude_bin)
            .args(["--ignored", "--exact", PARENT_TEST])
            .env(RESULT_ENV, &result_path)
            .env(CHILD_EXE_ENV, &child_bin)
            .env("CSQ_TEST_SWAP_CC_ANCESTOR_REFUSAL_CHILD_TEST", CHILD_TEST)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn renamed-to-claude parent helper");
        let parent_pid = parent.id();

        let deadline = Instant::now() + Duration::from_secs(60);
        let content = loop {
            if let Ok(s) = std::fs::read_to_string(&result_path) {
                if !s.is_empty() {
                    break s;
                }
            }
            if Instant::now() >= deadline {
                let _ = parent.kill();
                panic!("result file never became non-empty within the deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let status = parent.wait().expect("wait on parent helper");
        assert!(
            status.success(),
            "parent helper exited non-zero: {status:?}"
        );

        let content = content.trim();
        assert!(
            content.starts_with("err:"),
            "expected a refusal (Err), got {content:?}"
        );
        // C-F8: assert the EXACT message text, not just substrings — the
        // prior bug (lost `\` continuations) produced a message that
        // still `contains` every substring below while embedding runs of
        // 14 literal spaces where the continuations should have joined
        // the lines with a single space. A substring-only assertion
        // would not have caught it.
        let expected = format!(
            "err:csq swap cannot switch to codex from inside a running Claude \
             Code session — this command is executing as a subprocess of a live claude \
             process (pid {parent_pid}), and replacing it would leave that session \
             untouched with no visible error. Exit claude first, then run \
             `csq run 5` to start account 5 directly."
        );
        assert_eq!(
            content, expected,
            "refusal message must match exactly (child probe target is Surface::Codex, \
             account 5); got {content:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore]
    fn swap_cc_ancestor_refusal_parent_helper() {
        let child_exe = std::env::var("CSQ_TEST_SWAP_CC_ANCESTOR_REFUSAL_CHILD_EXE")
            .expect("child exe env var set");
        let child_test = std::env::var("CSQ_TEST_SWAP_CC_ANCESTOR_REFUSAL_CHILD_TEST")
            .expect("child test name env var set");
        let status = std::process::Command::new(&child_exe)
            .args(["--ignored", "--exact", &child_test])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .expect("spawn child probe");
        assert!(status.success(), "child probe exited non-zero: {status:?}");
    }

    #[cfg(unix)]
    #[test]
    #[ignore]
    fn swap_cc_ancestor_refusal_child_probe() {
        use std::io::Write as _;
        let out_path = std::env::var("CSQ_TEST_SWAP_CC_ANCESTOR_REFUSAL_RESULT_FILE")
            .expect("result file env var set");
        let target = AccountNum::try_from(5u16).unwrap();
        let line = match refuse_if_inside_live_cc_ancestor(Surface::Codex, target) {
            Ok(()) => "ok\n".to_string(),
            Err(e) => format!("err:{e}\n"),
        };
        let mut f = std::fs::File::create(&out_path).expect("create result file");
        f.write_all(line.as_bytes()).expect("write result file");
    }

    /// The `SameSurfaceClaudeCode` in-flight repoint route never calls
    /// `refuse_if_inside_live_cc_ancestor` (or `exec_replace_swap` at all —
    /// `route()` dispatches it straight to `same_surface_claude_code_audited`,
    /// see the dispatch `match` above). Proven from INSIDE a live `claude`
    /// ancestor: the call fails for an entirely unrelated, pre-existing
    /// reason (a source dir that is not a csq-managed handle dir) rather
    /// than the CC-ancestor refusal wording — if the new check had been
    /// wired into this route by mistake, the error would instead say "exit
    /// claude first".
    #[cfg(unix)]
    #[test]
    fn same_surface_claude_code_route_is_unaffected_by_cc_ancestor_check() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        const RESULT_ENV: &str = "CSQ_TEST_SWAP_SAME_SURFACE_CC_RESULT_FILE";
        const CHILD_EXE_ENV: &str = "CSQ_TEST_SWAP_SAME_SURFACE_CC_CHILD_EXE";
        const PARENT_TEST: &str = "cli::commands::swap::tests::swap_same_surface_cc_parent_helper";
        const CHILD_TEST: &str = "cli::commands::swap::tests::swap_same_surface_cc_child_probe";

        fn copy_self_to(dir: &Path, name: &str) -> PathBuf {
            let src = std::env::current_exe().expect("current_exe for the running test binary");
            let dst = dir.join(name);
            std::fs::copy(&src, &dst).expect("copy running test binary to renamed path");
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dst).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dst, perms).unwrap();
            dst
        }

        let dir = tempfile::TempDir::new().expect("tempdir");
        let result_path = dir.path().join("result.txt");
        let claude_bin = copy_self_to(dir.path(), "claude");
        let child_bin = copy_self_to(dir.path(), "csq-test-swap-same-surface-cc-child-probe");

        let mut parent = Command::new(&claude_bin)
            .args(["--ignored", "--exact", PARENT_TEST])
            .env(RESULT_ENV, &result_path)
            .env(CHILD_EXE_ENV, &child_bin)
            .env("CSQ_TEST_SWAP_SAME_SURFACE_CC_CHILD_TEST", CHILD_TEST)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn renamed-to-claude parent helper");

        let deadline = Instant::now() + Duration::from_secs(60);
        let content = loop {
            if let Ok(s) = std::fs::read_to_string(&result_path) {
                if !s.is_empty() {
                    break s;
                }
            }
            if Instant::now() >= deadline {
                let _ = parent.kill();
                panic!("result file never became non-empty within the deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let status = parent.wait().expect("wait on parent helper");
        assert!(
            status.success(),
            "parent helper exited non-zero: {status:?}"
        );

        let content = content.trim();
        assert!(
            !content.contains("Exit claude first"),
            "the SameSurfaceClaudeCode route must be UNAFFECTED by the new \
             CC-ancestor check; got {content:?}"
        );
        assert!(
            content.contains("not a csq-managed handle dir"),
            "expected the route's own pre-existing validation error; got {content:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore]
    fn swap_same_surface_cc_parent_helper() {
        let child_exe = std::env::var("CSQ_TEST_SWAP_SAME_SURFACE_CC_CHILD_EXE")
            .expect("child exe env var set");
        let child_test = std::env::var("CSQ_TEST_SWAP_SAME_SURFACE_CC_CHILD_TEST")
            .expect("child test name env var set");
        let status = std::process::Command::new(&child_exe)
            .args(["--ignored", "--exact", &child_test])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .expect("spawn child probe");
        assert!(status.success(), "child probe exited non-zero: {status:?}");
    }

    #[cfg(unix)]
    #[test]
    #[ignore]
    fn swap_same_surface_cc_child_probe() {
        use std::io::Write as _;
        let out_path = std::env::var("CSQ_TEST_SWAP_SAME_SURFACE_CC_RESULT_FILE")
            .expect("result file env var set");
        let base = tempfile::TempDir::new().expect("tempdir");
        let bogus_source = base.path().join("not-a-handle-dir");
        std::fs::create_dir_all(&bogus_source).unwrap();
        let target = AccountNum::try_from(5u16).unwrap();
        let line = match same_surface_claude_code_audited(base.path(), &bogus_source, target, None)
        {
            Ok(()) => "ok\n".to_string(),
            Err(e) => format!("err:{e}\n"),
        };
        let mut f = std::fs::File::create(&out_path).expect("create result file");
        f.write_all(line.as_bytes()).expect("write result file");
    }

    // ── M6 T6.1 spawn-gate parity for the swap exec path (item 1 of the
    // governing task: "governance bypass") ──────────────────────────────

    /// A Block-verdict operating envelope refuses the swap BEFORE any
    /// tombstone — the fix for `exec_codex_after_binding` previously
    /// skipping the M6 T6.1 gate entirely (swap's call site carried no
    /// `AuditEmitter`/`OperatingEnvelope`). This calls `exec_replace_swap`
    /// directly, which is the SAME function `route()` dispatches into for
    /// every exec-replace route, and which now evaluates the gate via
    /// `super::run::evaluate_codex_spawn_gate` — the identical function
    /// `launch_codex` (`csq run`) calls — before Step 2's tombstone rename.
    /// A single shared function cannot drift between the two call sites by
    /// construction, which is the parity this test demonstrates.
    #[cfg(all(unix, feature = "enterprise"))]
    #[test]
    fn swap_exec_replace_refuses_and_leaves_nothing_tombstoned_when_codex_spawn_blocked() {
        // Hermetic: `exec_replace_swap` calls `refuse_if_inside_live_cc_ancestor`
        // FIRST, before the operating-envelope gate this test exercises —
        // force "no ancestor" so a real `claude` ancestor on the host
        // running this test cannot pre-empt the assertion below with the
        // wrong refusal reason (`test-hermeticity.md`).
        let _cc_guard = force_find_cc_pid(None);
        let base = tempfile::TempDir::new().expect("tempdir");
        let pid = std::process::id();
        let source_dir = base.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("marker"), b"source").unwrap();

        // Operating envelope denying `spawn_codex` -> the real seam governor
        // returns Block (mirrors `kailash_governor::tests::
        // factory_builds_governor_that_blocks_denied_submit_turn`).
        let gate_body = serde_json::json!({
            "provider": "claude",
            "schema": { "type": "object" },
            "max_tokens": 1024,
            "envelope": {
                "version": csq_trust_contract::OPERATING_ENVELOPE_SCHEMA_VERSION,
                "role": "D1-R1",
                "allowed_operations": [],
                "denied_operations": ["spawn_codex"],
                "require_approval_for": [],
                "declared_posture": "autonomous",
                "posture_floor": "supervised"
            }
        });
        std::fs::write(
            base.path()
                .join(csq_core::daemon::interactive_live::GATE_FILENAME),
            gate_body.to_string(),
        )
        .unwrap();

        let target = AccountNum::try_from(9u16).unwrap();
        let result = exec_replace_swap(
            base.path(),
            SourceHandle::ClaudeCode(source_dir.clone()),
            target,
            Surface::Codex,
            true,
            None,
            RouteKind::CrossSurface,
        );

        let err = result.expect_err("a Block verdict must refuse the swap");
        assert!(
            err.to_string().contains("refused by operating envelope"),
            "got: {err}"
        );

        // Nothing tombstoned: the source dir is exactly as it was.
        assert!(
            source_dir.join("marker").exists(),
            "source handle dir must be untouched — refusal happens BEFORE the tombstone"
        );
        let no_tombstone_sibling = std::fs::read_dir(base.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| {
                !e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-swap-")
            });
        assert!(
            no_tombstone_sibling,
            "no sweep-tombstone sibling must have been created"
        );
        // The gate refused before Step 3 (`create_target_handle_dir`) ever
        // ran, so `term-{pid}` is still exactly the ORIGINAL source dir —
        // still holding `marker`, asserted above — not a freshly-created
        // target binding.
        assert!(
            source_dir.exists() && source_dir.join("marker").exists(),
            "term-{pid} must still be the untouched original source dir"
        );
    }

    /// The sibling of the Block test: with NO gate file present at all
    /// (`SpawnGate::Ungoverned`), `evaluate_codex_spawn_gate` returns `Ok`
    /// and the swap proceeds PAST the gate — proving the gate call is real
    /// (not a no-op) and that an ungoverned session is unaffected, matching
    /// `launch_codex`'s community-equivalent default. Proceeding reaches
    /// (S-F5) the token-freshness check now inlined in `exec_replace_swap`
    /// — non-fatal here since no target credential file exists at all
    /// (`check_codex_token_freshness` treats a missing/unreadable file as
    /// "no JWT to check", not a refusal) — then fails downstream for the
    /// unrelated, expected reason that no target codex credentials exist
    /// in this fixture — proof the gate did not block.
    #[cfg(all(unix, feature = "enterprise"))]
    #[test]
    fn swap_exec_replace_proceeds_past_ungoverned_codex_spawn_gate() {
        // Hermetic — see the sibling test above for why this seam is
        // needed even though this test's own assertion (no "refused by
        // operating envelope") would coincidentally still pass under a
        // real CC-ancestor refusal; forcing "no ancestor" keeps the test
        // proving what its name claims regardless.
        let _cc_guard = force_find_cc_pid(None);
        let base = tempfile::TempDir::new().expect("tempdir");
        let pid = std::process::id();
        let source_dir = base.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&source_dir).unwrap();

        let target = AccountNum::try_from(9u16).unwrap();
        let result = exec_replace_swap(
            base.path(),
            SourceHandle::ClaudeCode(source_dir),
            target,
            Surface::Codex,
            true,
            None,
            RouteKind::CrossSurface,
        );

        let err = result.expect_err("no target codex creds exist in this fixture");
        assert!(
            !err.to_string().contains("refused by operating envelope"),
            "an ungoverned session must not be refused by the spawn gate; got: {err}"
        );
    }

    /// S-F5: an expired Codex access token at the TARGET refuses BEFORE any
    /// tombstone — the freshness check used to run inside
    /// `exec_codex_after_binding`, well after both Step 2 (tombstone) and
    /// Step 3 (target handle dir creation) had already mutated disk state.
    /// It now runs directly in `exec_replace_swap`, reading the target's
    /// canonical credential path (no handle-dir symlink involved, since
    /// neither the tombstone nor the target dir exists yet at that point).
    #[cfg(unix)]
    #[test]
    fn exec_replace_swap_refuses_before_tombstone_when_target_codex_token_is_expired() {
        // Hermetic: this test's own assertion is on the token-freshness
        // check, which runs AFTER `refuse_if_inside_live_cc_ancestor` in
        // `exec_replace_swap` — force "no ancestor" so a real `claude`
        // ancestor on the host cannot pre-empt it with the wrong refusal
        // (`test-hermeticity.md`).
        let _cc_guard = force_find_cc_pid(None);
        let base = tempfile::TempDir::new().expect("tempdir");
        let pid = std::process::id();
        let source_dir = base.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("marker"), b"source").unwrap();

        let target = AccountNum::try_from(9u16).unwrap();
        // Genuinely EXPIRED JWT (exp=1_700_000_000, Nov 2023 — permanently
        // in the past, no test-timebomb risk per
        // `feedback_no_test_timebombs`), same literal fixture as
        // `csq-core/src/http/codex.rs::jwt_exp_secs_decodes_payload_exp_claim`.
        let creds_path = base.path().join("credentials").join("codex-9.json");
        std::fs::create_dir_all(creds_path.parent().unwrap()).unwrap();
        let json = serde_json::json!({
            "tokens": {
                "account_id": "acct-9",
                "access_token": "eyJhbGciOiJub25lIn0.eyJleHAiOjE3MDAwMDAwMDB9.sig"
            }
        });
        std::fs::write(&creds_path, serde_json::to_vec(&json).unwrap()).unwrap();

        let result = exec_replace_swap(
            base.path(),
            SourceHandle::ClaudeCode(source_dir.clone()),
            target,
            Surface::Codex,
            true,
            None,
            RouteKind::CrossSurface,
        );

        let err = result.expect_err("an expired target Codex token must refuse the swap");
        assert!(
            err.to_string().contains("expired Codex access token"),
            "got: {err}"
        );

        assert!(
            source_dir.exists() && source_dir.join("marker").exists(),
            "source handle dir must be untouched by a pre-tombstone refusal"
        );
        let no_tombstone_sibling = std::fs::read_dir(base.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| {
                !e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-")
            });
        assert!(
            no_tombstone_sibling,
            "no sweep-tombstone sibling must have been created"
        );
    }

    // ── Supervised handoff (`handoff_to_supervisor`, shard S3) ──────────

    // C-R4-3: `handoff_to_supervisor` now checks daemon health up front
    // (before any request is written), so every one of this section's
    // fixtures must make `daemon::detect_daemon(base_dir)` report `Healthy`
    // or they all refuse before reaching the behavior under test. Governing
    // task item 4 (test-helper hoist): the fixture previously duplicated
    // here as `SwapFakeHealthyDaemon`/`spawn_swap_fake_healthy_daemon` now
    // lives in the shared `fake_daemon_test_support` module (imported via
    // the `use` at the top of this `mod tests` block) alongside
    // `codex_supervise`'s own former copy.

    /// C-R4-3, DIRECT: proves the gate itself, not merely that every OTHER
    /// fixture in this section happens to spawn a healthy daemon. No
    /// `spawn_fake_healthy_daemon` call here — `base` is a fresh tempdir
    /// with no pid file / socket, so `daemon::detect_daemon` reports
    /// `NotRunning` and `handoff_to_supervisor` must refuse BEFORE writing
    /// anything, even though the target slot genuinely has Codex
    /// credentials (so a pass here cannot be explained by the OTHER two
    /// refusal branches — pending-request or missing-credentials).
    #[cfg(unix)]
    #[test]
    fn handoff_refuses_when_daemon_is_not_healthy() {
        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        // Deliberately NO spawn_fake_healthy_daemon(base.path()) call — but
        // STILL needs the env guard: on Linux, detect_daemon prefers
        // $XDG_RUNTIME_DIR over base_dir whenever that var is set, so
        // without this a concurrently-running sibling test's
        // spawn_fake_healthy_daemon fixture (or the ambient real runtime
        // dir) is what actually gets checked, not this fresh tempdir.
        let _no_daemon = spawn_no_daemon_env_guard(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        let err = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            std::process::id(),
            None,
        )
        .expect_err("must refuse a handoff when the daemon is not healthy");
        assert!(
            err.to_string().contains("csq daemon is not running"),
            "refusal must name the daemon-down reason `codex_daemon_refusal` \
             produces for `DetectResult::NotRunning`; got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "a daemon-down refusal must write NOTHING — no swap request file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn handoff_refuses_when_swap_request_already_pending() {
        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        // A FRESH timestamp, not a fixed historical one — `swap_request_pending`
        // now ages a request out after `STALE_REQUEST_SECS` (FM-3, sibling
        // shard S), so a hardcoded past timestamp would read as stale and
        // this fixture would stop exercising the "already pending" branch
        // this test names (`feedback_no_test_timebombs`).
        sup::write_swap_request(
            handle_dir.path(),
            &sup::SwapRequest {
                target_slot: 3,
                thread_id: None,
                requested_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ..Default::default()
            },
        )
        .expect("write pending request");

        let err = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            std::process::id(),
            None,
        )
        .expect_err("must refuse when a request is already pending");
        // FM-3: the refusal must name the file to remove if the request is
        // stuck, so an operator has a concrete recovery step rather than
        // just a description of the state.
        let expected_hint = format!(
            "remove {}",
            redact_path(&handle_dir.path().join(sup::SWAP_REQUEST_FILE))
        );
        let err_string = err.to_string();
        assert!(
            err_string.contains("a switch is already in progress for this terminal"),
            "got: {err_string}"
        );
        assert!(
            err_string.contains(&expected_hint),
            "refusal must name the swap-request file to remove; got: {err_string}"
        );
        // The PRE-EXISTING pending request must be untouched by the refusal.
        assert!(sup::swap_request_pending(handle_dir.path()));
    }

    #[cfg(unix)]
    #[test]
    fn handoff_refuses_and_writes_nothing_when_target_has_no_codex_credentials() {
        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        // No `write_codex_creds_fixture` call — slot 12 has no credentials.
        let target = AccountNum::try_from(12u16).unwrap();

        let err = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            std::process::id(),
            None,
        )
        .expect_err("must refuse when the target has no Codex credentials");
        assert!(
            err.to_string().contains("csq login 12 --provider codex"),
            "refusal must direct the user to log in the target slot; got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "an invalid-target refusal must not leave a swap request behind"
        );
    }

    /// A supervisor record naming a pid that is genuinely dead: spawn a
    /// real short-lived child, capture its pid + start time, then wait for
    /// it to exit before writing the record.
    ///
    /// S-F11 (post-fix): a dead recorded pid is now caught by the ppid
    /// check BEFORE `signal_supervisor` is ever called — `std::process::id()`
    /// (this test's own pid, standing in for the ancestor) is never a
    /// child of the already-exited, unrelated `dead_pid`, so the refusal
    /// reason is the ppid mismatch, not `signal_supervisor`'s ESRCH. This
    /// is a STRICTER outcome than before (caught earlier, without
    /// depending on a `kill(2)` failure mode), not a regression — this
    /// test previously asserted "failed to signal" and has been updated to
    /// assert the new, earlier refusal reason. The still-alive-but-wrong-
    /// parent case is covered separately by
    /// `handoff_refuses_and_does_not_signal_when_record_pid_is_not_the_ancestors_parent`,
    /// and the still-alive-and-correct-parent success case by
    /// `handoff_writes_request_with_thread_id_and_signals_supervisor`.
    /// e68ba0fe / C-R4-3-adjacent, refusal branch 1 of 5: the supervisor
    /// record is genuinely ABSENT at the moment `handoff_to_supervisor_
    /// write_and_signal` re-reads it (`sup::read_supervisor_record`
    /// returns `None`) — as opposed to the OTHER four fixtures in this
    /// section, which all write SOME record and then fail a check on its
    /// CONTENT. Distinct from `handoff_refuses_and_withdraws_request_
    /// when_recorded_supervisor_is_dead` (despite the similar name): that
    /// test writes a record naming a genuinely-dead pid and refuses on the
    /// ANCESTOR-CHAIN check (branch 2) because the record file itself
    /// still exists; this one never writes a record file at all.
    #[cfg(unix)]
    #[test]
    fn handoff_refuses_and_clears_inflight_when_supervisor_record_is_absent() {
        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);
        // Deliberately no SUPERVISOR_FILE written at all.

        let err = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            std::process::id(),
            None,
        )
        .expect_err("must refuse when no supervisor record exists to re-read");
        assert!(
            err.to_string()
                .contains("the codex supervisor record disappeared"),
            "got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "S-L2 (round 5): the record read is now the FIRST admission \
             check, before anything is written — an absent-record refusal \
             must leave nothing pending because nothing was ever written, \
             not because a written request was withdrawn"
        );
    }

    #[cfg(unix)]
    #[test]
    fn handoff_refuses_and_withdraws_request_when_recorded_supervisor_is_dead() {
        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn short-lived child");
        let dead_pid = child.id();
        let start_time = sup::process_start_time(dead_pid).unwrap_or_else(|| "unknown".to_string());
        let status = child.wait().expect("wait for child exit");
        assert!(status.success());
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{dead_pid}\n{start_time}\n"),
        )
        .unwrap();

        let err = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            std::process::id(),
            None,
        )
        .expect_err(
            "must refuse when the recorded supervisor does not match the ancestor's real parent",
        );
        assert!(
            err.to_string().contains("is not within the ancestor"),
            "got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "S-L2 (round 5): the ancestor-chain check now runs before \
             anything is written — a ppid-mismatch refusal must leave \
             nothing pending because nothing was ever written"
        );
    }

    /// PRIMARY METHODOLOGICAL DIRECTIVE: the outcome-authority boundary is
    /// the SIGNAL, not "a supervisor record exists." This is the SAME
    /// ppid-mismatch admission failure as
    /// `handoff_refuses_and_withdraws_request_when_recorded_supervisor_is_dead`
    /// — a refusal that occurs BEFORE `signal_supervisor` is ever called —
    /// but here `from_slot` is `Some(_)`, so `begin_swap_audit` actually
    /// persists an INTENT. Before this fix, that INTENT would be left on
    /// the chain as a silent orphan (indistinguishable from a genuine
    /// crash) because nothing downstream of `begin_swap_audit` ever closed
    /// it out — the supervisor never learns of a swap that never reaches
    /// `signal_supervisor`, so it can never write the correlated OUTCOME
    /// either. `csq swap` itself must close the loop it opened.
    #[cfg(unix)]
    #[test]
    fn handoff_writes_failed_outcome_when_refused_before_any_signal_is_sent() {
        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);
        let from_slot = Some(AccountNum::try_from(3u16).unwrap());

        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn short-lived child");
        let dead_pid = child.id();
        let start_time = sup::process_start_time(dead_pid).unwrap_or_else(|| "unknown".to_string());
        let status = child.wait().expect("wait for child exit");
        assert!(status.success());
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{dead_pid}\n{start_time}\n"),
        )
        .unwrap();

        let err = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            std::process::id(),
            from_slot,
        )
        .expect_err("must refuse — this is the same admission failure as the sibling test");
        assert!(
            err.to_string().contains("is not within the ancestor"),
            "got: {err}"
        );

        // RED (before the fix): this would be 1 — the INTENT persisted by
        // `begin_swap_audit`, with NO OUTCOME ever written to close it,
        // because the refusal happens before `signal_supervisor` and the
        // supervisor (a genuinely dead process here) never receives — and
        // never could receive — the signal that would let IT write one.
        assert_eq!(
            count_chain_records(base.path()),
            2,
            "the INTENT must be closed out by `csq swap` itself with a \
             Failed OUTCOME — nothing downstream of this refusal will ever \
             write one"
        );

        let runs_dir = base.path().join("csq-runs");
        let jsonl = std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .find(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .expect("a chain JSONL must exist")
            .path();
        let content = std::fs::read_to_string(&jsonl).unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let outcome = records
            .iter()
            .find(|r| r["op_phase"]["phase"].as_str() == Some("outcome"))
            .expect("an OUTCOME record must be present");
        assert_eq!(
            outcome["op_phase"]["result"]["result"].as_str(),
            Some("failed"),
            "the OUTCOME must record Failed, not Ok: {outcome:?}"
        );
        let reason = outcome["op_phase"]["result"]["reason"]
            .as_str()
            .expect("reason must be a string");
        assert!(
            reason.contains("is not within the ancestor"),
            "the redacted reason must carry the actual refusal cause; got: {reason}"
        );
        let intent = records
            .iter()
            .find(|r| r["op_phase"]["phase"].as_str() == Some("intent"))
            .expect("the INTENT record must still be present");
        assert_eq!(
            intent["op_phase"]["correlation_id"], outcome["op_phase"]["correlation_id"],
            "the OUTCOME must correlate with the SAME intent this call persisted"
        );
    }

    /// End-to-end success: a genuine supervisor process (SIGUSR1-trapping)
    /// receives the signal, and a genuine "ancestor" process — spawned AS
    /// THE SUPERVISOR'S OWN CHILD, matching the real production shape
    /// (`codex_supervisor`'s module doc: "csq run/csq exec … supervises
    /// its codex child") — holding a matched (lock, rollout) pair open
    /// yields a discovered thread id, both written into the
    /// `SwapRequest`. Also exercises S-F11's ppid check on its PASSING
    /// branch: `record.pid` (the supervisor) genuinely IS the parent of
    /// `ancestor_pid` here, so the signal must still be delivered.
    #[cfg(unix)]
    #[test]
    fn handoff_writes_request_with_thread_id_and_signals_supervisor() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let uuid = "0123abcd-0123-4abc-8def-0123456789ab";

        let sessions_real = handle_dir.path().join("sessions_real");
        let locks_real = handle_dir.path().join("locks_real");
        std::fs::create_dir_all(&sessions_real).unwrap();
        std::fs::create_dir_all(&locks_real).unwrap();
        std::os::unix::fs::symlink(&sessions_real, handle_dir.path().join("sessions")).unwrap();
        std::os::unix::fs::symlink(&locks_real, handle_dir.path().join("thread-writer-locks"))
            .unwrap();

        let day_dir = sessions_real.join("2026/09/26");
        std::fs::create_dir_all(&day_dir).unwrap();
        let rollout_path = day_dir.join(format!("rollout-2026-09-26T00-00-00-{uuid}.jsonl"));
        std::fs::write(&rollout_path, b"").unwrap();
        let lock_path = locks_real.join(format!("{uuid}.lock"));
        std::fs::write(&lock_path, b"").unwrap();

        let mark = handle_dir.path().join("signalled");
        let child_pid_file = handle_dir.path().join("child_pid");
        // F1 (round 5): `handoff_to_supervisor_write_and_signal` now waits
        // (bounded) for a `.csq-swap-verdict` before returning — this
        // stand-in supervisor must write one (bound to the request's
        // `nonce`, the 4th line of the request file — see `SwapRequest::to_line`)
        // or the real
        // call below would time out reporting "undetermined" instead of
        // the accepted-request assertions this test makes.
        let request_path = handle_dir.path().join(sup::SWAP_REQUEST_FILE);
        let verdict_path = handle_dir.path().join(sup::SWAP_VERDICT_FILE);
        // "Supervisor": traps SIGUSR1 (writes the accepted verdict, then
        // touches a marker file proving delivery rather than merely that
        // `kill` returned success), and forks the fd-holding "ancestor"
        // stand-in AS ITS OWN CHILD via a backgrounded subshell — `$!`
        // captures that child's pid, written out before the parent blocks
        // in `wait` so the test can read it.
        let mut supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'nonce=$(sed -n 4p \"{}\"); \
                 printf \"%s\\naccepted\\n\" \"$nonce\" > \"{}.tmp\" && mv \"{}.tmp\" \"{}\"; \
                 touch \"{}\"; exit 0' USR1; \
                 ( exec 3<>'{}' 4<>'{}'; sleep 30 ) & \
                 echo $! > '{}'; \
                 wait",
                request_path.display(),
                verdict_path.display(),
                verdict_path.display(),
                verdict_path.display(),
                mark.display(),
                lock_path.display(),
                rollout_path.display(),
                child_pid_file.display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping supervisor stand-in");
        let supervisor_pid = supervisor.id();

        let ancestor_pid: u32 = wait_for_pid_file(&child_pid_file);

        // Give the child a moment to reach steady state (open fds) before
        // this test relies on it, and confirm S-F11's precondition holds
        // in THIS fixture — the supervisor really is the child's parent.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor stand-in must be the ancestor \
             stand-in's real parent, or this test exercises the wrong branch \
             of S-F11's ppid check"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        let result =
            handoff_to_supervisor(base.path(), handle_dir.path(), target, ancestor_pid, None);
        assert!(result.is_ok(), "{result:?}");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !mark.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(mark.exists(), "supervisor never received SIGUSR1");
        let status = supervisor.wait().expect("wait for supervisor stand-in");
        assert!(status.success(), "supervisor exited non-zero: {status:?}");

        // `handoff_to_supervisor` writes the request; it is the SUPERVISOR's
        // job (codex_supervise::drive_child) to consume it — our stand-in
        // supervisor doesn't, so it must still be on disk, with the exact
        // target slot and the discovered thread id.
        let req = sup::take_swap_request(handle_dir.path()).expect("request present on disk");
        assert_eq!(req.target_slot, 9);
        assert_eq!(
            req.thread_id.as_deref(),
            Some(uuid),
            "the ancestor's matched (lock, rollout) pair must be discovered as the thread id"
        );
    }

    /// FM-13: the npm-installed-codex shape — supervisor -> launcher ->
    /// codex-native, TWO hops between the recorded supervisor pid and the
    /// detected ancestor pid (the launcher's `child_process.spawn` is a
    /// genuine fork, unlike the shebang re-exec that keeps the launcher
    /// itself at the supervisor-forked pid — see
    /// `ancestry::DEFAULT_ANCESTOR_CHAIN_BOUND`'s doc). Before the fix this
    /// refused every such swap (`parent_pid(ancestor_pid)` names the
    /// launcher, never the supervisor); the widened chain check must
    /// accept it.
    #[cfg(unix)]
    #[test]
    fn handoff_accepts_a_supervisor_two_hops_above_the_ancestor_npm_launcher_shape() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let uuid = "0123abcd-0123-4abc-8def-0123456789ab";

        let sessions_real = handle_dir.path().join("sessions_real");
        let locks_real = handle_dir.path().join("locks_real");
        std::fs::create_dir_all(&sessions_real).unwrap();
        std::fs::create_dir_all(&locks_real).unwrap();
        std::os::unix::fs::symlink(&sessions_real, handle_dir.path().join("sessions")).unwrap();
        std::os::unix::fs::symlink(&locks_real, handle_dir.path().join("thread-writer-locks"))
            .unwrap();

        let day_dir = sessions_real.join("2026/09/26");
        std::fs::create_dir_all(&day_dir).unwrap();
        let rollout_path = day_dir.join(format!("rollout-2026-09-26T00-00-00-{uuid}.jsonl"));
        std::fs::write(&rollout_path, b"").unwrap();
        let lock_path = locks_real.join(format!("{uuid}.lock"));
        std::fs::write(&lock_path, b"").unwrap();

        let mark = handle_dir.path().join("signalled");
        let launcher_pid_file = handle_dir.path().join("launcher_pid");
        let ancestor_pid_file = handle_dir.path().join("ancestor_pid");
        // F1 (round 5): see the identical comment in
        // `handoff_writes_request_with_thread_id_and_signals_supervisor` —
        // this stand-in must also write the accepted verdict on SIGUSR1.
        let request_path = handle_dir.path().join(sup::SWAP_REQUEST_FILE);
        let verdict_path = handle_dir.path().join(sup::SWAP_VERDICT_FILE);
        // "Supervisor": traps SIGUSR1, then backgrounds a "launcher"
        // subshell — which ITSELF backgrounds the fd-holding "ancestor"
        // stand-in as ITS OWN child (a second, genuine fork) before
        // waiting on it. The supervisor never directly parents the
        // ancestor; the launcher sits between them, matching the npm
        // shape exactly.
        let mut supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'nonce=$(sed -n 4p \"{}\"); \
                 printf \"%s\\naccepted\\n\" \"$nonce\" > \"{}.tmp\" && mv \"{}.tmp\" \"{}\"; \
                 touch \"{}\"; exit 0' USR1; \
                 ( ( exec 3<>'{}' 4<>'{}'; sleep 30 ) & \
                   echo $! > '{}'; \
                   wait ) & \
                 echo $! > '{}'; \
                 wait",
                request_path.display(),
                verdict_path.display(),
                verdict_path.display(),
                verdict_path.display(),
                mark.display(),
                lock_path.display(),
                rollout_path.display(),
                ancestor_pid_file.display(),
                launcher_pid_file.display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping supervisor stand-in");
        let supervisor_pid = supervisor.id();

        let deadline = Instant::now() + Duration::from_secs(10);
        while (!launcher_pid_file.exists() || !ancestor_pid_file.exists())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let launcher_pid: u32 = std::fs::read_to_string(&launcher_pid_file)
            .expect("launcher pid file readable")
            .trim()
            .parse()
            .expect("launcher pid file parses as u32");
        let ancestor_pid: u32 = std::fs::read_to_string(&ancestor_pid_file)
            .expect("ancestor pid file readable")
            .trim()
            .parse()
            .expect("ancestor pid file parses as u32");

        std::thread::sleep(Duration::from_millis(200));

        // Fixture invariants: genuinely TWO hops, not one — the exact-match
        // check this fix replaces would refuse this shape.
        assert_ne!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor must NOT be the ancestor's \
             immediate parent, or this test does not exercise the multi-hop \
             widening at all"
        );
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(launcher_pid),
            "fixture invariant: the launcher stand-in must be the ancestor's \
             immediate parent"
        );
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(launcher_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor must be the launcher's \
             immediate parent — i.e. two hops above the ancestor"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        let result =
            handoff_to_supervisor(base.path(), handle_dir.path(), target, ancestor_pid, None);
        assert!(
            result.is_ok(),
            "must accept a supervisor two hops above the ancestor (npm-launcher \
             shape); got {result:?}"
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        while !mark.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(mark.exists(), "supervisor never received SIGUSR1");
        let status = supervisor.wait().expect("wait for supervisor stand-in");
        assert!(status.success(), "supervisor exited non-zero: {status:?}");

        let req = sup::take_swap_request(handle_dir.path()).expect("request present on disk");
        assert_eq!(req.target_slot, 9);
    }

    /// S-F11: a supervisor record naming a pid that is genuinely ALIVE and
    /// SIGUSR1-trapping — but is NOT the parent of the live codex ancestor
    /// pid `handoff_to_supervisor` was told about — must be refused
    /// WITHOUT ever being signalled. Both stand-in processes here are
    /// spawned as SIBLINGS of the test process (neither is the other's
    /// parent), standing in for a forged/stale/PID-recycled record.
    #[cfg(unix)]
    #[test]
    fn handoff_refuses_and_does_not_signal_when_record_pid_is_not_the_ancestors_parent() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        // A live, unrelated "ancestor" stand-in — its real parent is THIS
        // test process, not the "supervisor" stand-in below.
        let mut unrelated_ancestor = Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn unrelated ancestor stand-in");
        let ancestor_pid = unrelated_ancestor.id();

        // A live, SIGUSR1-trapping "supervisor" stand-in — genuinely alive
        // and genuinely able to receive a signal, so if S-F11's check were
        // absent or wrong this test would observe a FALSE success (mark
        // exists) instead of the correct refusal.
        let mark = handle_dir.path().join("signalled");
        let mut unrelated_supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'touch \"{}\"; exit 0' USR1; while true; do sleep 0.05; done",
                mark.display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping unrelated supervisor stand-in");
        let supervisor_pid = unrelated_supervisor.id();

        std::thread::sleep(Duration::from_millis(200));
        assert_ne!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: these two stand-ins must NOT be parent/child, \
             or this test exercises the wrong branch of S-F11's ppid check"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let err = handoff_to_supervisor(base.path(), handle_dir.path(), target, ancestor_pid, None)
            .expect_err("must refuse when record.pid is not the ancestor's real parent");
        assert!(
            err.to_string().contains("is not within the ancestor"),
            "got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "S-L2 (round 5): the ancestor-chain check runs before anything \
             is written — a ppid mismatch must leave nothing pending \
             because nothing was ever written"
        );

        // Give the (incorrectly targeted) supervisor stand-in a moment it
        // does NOT need — proving absence, not merely racing the assertion.
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !mark.exists(),
            "the unrelated supervisor stand-in must NEVER receive SIGUSR1"
        );

        let _ = unrelated_ancestor.kill();
        let _ = unrelated_ancestor.wait();
        let _ = unrelated_supervisor.kill();
        let _ = unrelated_supervisor.wait();
    }

    /// S-F1's "more than one live codex between this shell and its
    /// supervisor" refusal branch — the shape produced by a plain `codex`
    /// run inside the `!` shell-out of an ALREADY-supervised codex session.
    /// Constructing that exact process tree from a spawned-subprocess
    /// fixture would mean literally nesting two supervised codex sessions,
    /// which is not practical to arrange deterministically; instead this
    /// test builds a genuine, directly-related supervisor/ancestor pair
    /// (so the chain-containment check above it passes for real) and
    /// forces `count_codex_ancestors_before_for_handoff`'s return value via
    /// [`force_count_codex_ancestors_before`] to exercise this specific
    /// branch. Every other check — daemon health, credentials, chain
    /// containment, the supervisor liveness verification — runs for real.
    #[cfg(unix)]
    #[test]
    fn handoff_refuses_and_does_not_signal_when_more_than_one_codex_is_between_shell_and_supervisor(
    ) {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        let mark = handle_dir.path().join("signalled");
        let child_pid_file = handle_dir.path().join("child_pid");
        // "Supervisor": traps SIGUSR1, backgrounds the fd-holding "ancestor"
        // stand-in AS ITS OWN CHILD, and writes that child's pid out before
        // blocking in `wait` — a genuine, directly-related parent/child
        // pair, so the chain-containment check passes without any override.
        let mut supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'touch \"{}\"; exit 0' USR1; \
                 sleep 30 & \
                 echo $! > '{}'; \
                 wait",
                mark.display(),
                child_pid_file.display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping supervisor stand-in");
        let supervisor_pid = supervisor.id();

        let ancestor_pid: u32 = wait_for_pid_file(&child_pid_file);

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor stand-in must be the ancestor \
             stand-in's real parent, or this test exercises the wrong branch"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let _forced = force_count_codex_ancestors_before(Some(2));
        let err = handoff_to_supervisor(base.path(), handle_dir.path(), target, ancestor_pid, None)
            .expect_err("must refuse when more than one codex sits between shell and supervisor");
        assert!(
            err.to_string().contains("found 2 live codex processes"),
            "got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "S-L2 (round 5): the ambiguous-count check runs before anything \
             is written — the refusal must leave nothing pending because \
             nothing was ever written"
        );

        // Give the (incorrectly targeted) supervisor stand-in a moment it
        // does NOT need — proving absence, not merely racing the assertion.
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !mark.exists(),
            "the supervisor stand-in must NEVER receive SIGUSR1 when more \
             than one codex sits between the shell and it"
        );

        let _ = supervisor.kill();
        let _ = supervisor.wait();
    }

    /// S-F1's "could not read the process chain" refusal branch —
    /// `count_codex_ancestors_before` returning `None` (introspection
    /// failed partway through the walk). Same rationale as the sibling
    /// test above: forcing an unreadable process chain from a real OS
    /// process tree is not practical to arrange deterministically, so
    /// [`force_count_codex_ancestors_before`] forces the value this
    /// specific branch reads while every other check runs for real.
    #[cfg(unix)]
    #[test]
    fn handoff_refuses_and_does_not_signal_when_the_ancestor_chain_is_unreadable() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);

        let mark = handle_dir.path().join("signalled");
        let child_pid_file = handle_dir.path().join("child_pid");
        let mut supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'touch \"{}\"; exit 0' USR1; \
                 sleep 30 & \
                 echo $! > '{}'; \
                 wait",
                mark.display(),
                child_pid_file.display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping supervisor stand-in");
        let supervisor_pid = supervisor.id();

        let ancestor_pid: u32 = wait_for_pid_file(&child_pid_file);

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor stand-in must be the ancestor \
             stand-in's real parent, or this test exercises the wrong branch"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let _forced = force_count_codex_ancestors_before(None);
        let err = handoff_to_supervisor(base.path(), handle_dir.path(), target, ancestor_pid, None)
            .expect_err("must refuse when the ancestor chain cannot be read");
        assert!(
            err.to_string().contains("could not read the process chain"),
            "got: {err}"
        );
        assert!(
            !sup::swap_request_pending(handle_dir.path()),
            "S-L2 (round 5): the unreadable-chain check runs before anything \
             is written — the refusal must leave nothing pending because \
             nothing was ever written"
        );

        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !mark.exists(),
            "the supervisor stand-in must NEVER receive SIGUSR1 when the \
             ancestor chain is unreadable"
        );

        let _ = supervisor.kill();
        let _ = supervisor.wait();
    }

    // ── round 6, item 2: `csq swap` never writes the correlated AccountSwap
    //    OUTCOME itself — the supervisor is the sole authority for it ─────

    /// (a) A live, SIGUSR1-receiving supervisor stand-in that NEVER writes
    /// a `.csq-swap-verdict` at all. With the wait bound lowered via
    /// [`force_verdict_wait_timeout`], `handoff_to_supervisor` must report
    /// "undetermined" — never a guessed accept/refuse — and, critically,
    /// must NOT have written any OUTCOME record onto the chain itself: the
    /// INTENT this call persisted is left as exactly the kind of orphan
    /// `scan_orphan_intents`/`csq doctor` are meant to surface, not silently
    /// closed by `csq swap` guessing at a result the supervisor never gave it.
    #[cfg(unix)]
    #[test]
    fn handoff_reports_undetermined_and_writes_no_outcome_when_no_verdict_ever_arrives() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);
        // A real `from_slot` so `begin_swap_audit` actually persists an
        // INTENT — otherwise "no outcome record" would be trivially true
        // with nothing recorded at all, proving nothing.
        let from_slot = Some(AccountNum::try_from(3u16).unwrap());

        let mark = handle_dir.path().join("signalled");
        let child_pid_file = handle_dir.path().join("child_pid");
        // Traps SIGUSR1 (proves delivery via `mark`) but writes NO verdict —
        // the exact "waiter never gets an answer" shape this test covers.
        let mut supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'touch \"{}\"' USR1; \
                 sleep 30 & \
                 echo $! > '{}'; \
                 wait",
                mark.display(),
                child_pid_file.display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping supervisor stand-in");
        let supervisor_pid = supervisor.id();

        let ancestor_pid: u32 = wait_for_pid_file(&child_pid_file);

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor stand-in must be the ancestor \
             stand-in's real parent"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let _wait_guard = force_verdict_wait_timeout(Duration::from_millis(200));
        let result = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            ancestor_pid,
            from_slot,
        );
        let err = result.expect_err("no verdict ever arrives -> must be Err, never a guess");
        assert!(err.to_string().contains("undetermined"), "got: {err}");

        let deadline = Instant::now() + Duration::from_secs(2);
        while !mark.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(mark.exists(), "supervisor never received SIGUSR1");

        assert_eq!(
            count_chain_records(base.path()),
            1,
            "exactly the INTENT must be on the chain — `csq swap` itself must \
             never write an OUTCOME for an undetermined (timed-out) swap"
        );
        let runs_dir = base.path().join("csq-runs");
        let jsonl = std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .find(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .expect("a chain JSONL must exist")
            .path();
        let line = std::fs::read_to_string(&jsonl).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
        assert_eq!(
            rec["op_phase"]["phase"].as_str(),
            Some("intent"),
            "the sole record must be the INTENT, not an OUTCOME csq swap wrote itself"
        );

        let _ = supervisor.kill();
        let _ = supervisor.wait();
    }

    /// (b) A live, SIGUSR1-receiving supervisor stand-in that writes a
    /// REFUSED verdict. `handoff_to_supervisor` must report `Err` containing
    /// the refusal reason, and — the actual subject of this test — must
    /// NOT itself have written an OUTCOME record: the only record on the
    /// chain after the call is the INTENT (the stand-in supervisor here is a
    /// shell script, not real production code, so it cannot append a real
    /// signed OUTCOME — the assertion below is exactly "csq swap wrote no
    /// outcome", the parenthetical option named in the governing brief).
    #[cfg(unix)]
    #[test]
    fn handoff_reports_the_refusal_reason_and_writes_no_outcome_itself() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let handle_dir = tempfile::TempDir::new().expect("tempdir");
        let base = tempfile::TempDir::new().expect("tempdir");
        let _daemon = spawn_fake_healthy_daemon(base.path());
        let target = AccountNum::try_from(9u16).unwrap();
        write_codex_creds_fixture(base.path(), 9, "acct-9", false);
        let from_slot = Some(AccountNum::try_from(3u16).unwrap());

        let mark = handle_dir.path().join("signalled");
        let child_pid_file = handle_dir.path().join("child_pid");
        let request_path = handle_dir.path().join(sup::SWAP_REQUEST_FILE);
        let verdict_path = handle_dir.path().join(sup::SWAP_VERDICT_FILE);
        let refusal_reason = "account 9 has stale credentials";
        // Traps SIGUSR1: reads the request's nonce (4th line —
        // `SwapRequest::to_line`) and writes a REFUSED verdict bound to it.
        let mut supervisor = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'nonce=$(sed -n 4p \"{}\"); \
                 printf \"%s\\nrefused\\n{}\\n\" \"$nonce\" > \"{}.tmp\" && mv \"{}.tmp\" \"{}\"; \
                 touch \"{}\"' USR1; \
                 sleep 30 & \
                 echo $! > '{}'; \
                 wait",
                request_path.display(),
                refusal_reason,
                verdict_path.display(),
                verdict_path.display(),
                verdict_path.display(),
                mark.display(),
                child_pid_file.display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping supervisor stand-in");
        let supervisor_pid = supervisor.id();

        let ancestor_pid: u32 = wait_for_pid_file(&child_pid_file);

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            csq_core::providers::codex::ancestry::parent_pid(ancestor_pid),
            Some(supervisor_pid),
            "fixture invariant: the supervisor stand-in must be the ancestor \
             stand-in's real parent"
        );

        let start_time =
            sup::process_start_time(supervisor_pid).expect("supervisor start time readable");
        std::fs::write(
            handle_dir.path().join(sup::SUPERVISOR_FILE),
            format!("{supervisor_pid}\n{start_time}\n"),
        )
        .unwrap();
        assert!(sup::verify_supervisor_alive(handle_dir.path()));

        let result = handoff_to_supervisor(
            base.path(),
            handle_dir.path(),
            target,
            ancestor_pid,
            from_slot,
        );
        let err = result.expect_err("a refused verdict must surface as Err");
        assert!(err.to_string().contains(refusal_reason), "got: {err}");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !mark.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(mark.exists(), "supervisor never received SIGUSR1");

        assert_eq!(
            count_chain_records(base.path()),
            1,
            "exactly the INTENT must be on the chain — `csq swap` itself must \
             never write an OUTCOME for a refused swap (the refusal's OUTCOME, \
             if any, is the supervisor's to write, not csq swap's)"
        );
        let runs_dir = base.path().join("csq-runs");
        let jsonl = std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .find(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .expect("a chain JSONL must exist")
            .path();
        let line = std::fs::read_to_string(&jsonl).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
        assert_eq!(
            rec["op_phase"]["phase"].as_str(),
            Some("intent"),
            "the sole record must be the INTENT, not an OUTCOME csq swap wrote itself"
        );

        let _ = supervisor.kill();
        let _ = supervisor.wait();
    }

    // ── PR-C9b L-CDX-3 — dispatcher routing matrix ────────────────────

    /// Pinning: ClaudeCode→ClaudeCode with BOTH sides OAuth/Anthropic
    /// (neither pins env.ANTHROPIC_BASE_URL) MUST stay on the same-surface
    /// in-flight repoint path.
    #[test]
    fn route_claudecode_to_claudecode_is_same_surface_claudecode() {
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::ClaudeCode,
                false,
                false,
                None,
                None
            ),
            RouteKind::SameSurfaceClaudeCode
        );
    }

    /// Regression guard for the Anthropic↔3P swap bug: a ClaudeCode→ClaudeCode
    /// swap where EITHER side is an env-transport slot (3P/Ollama pinning
    /// env.ANTHROPIC_BASE_URL) MUST take the exec-replace path — a running CC
    /// froze its base URL + token at launch and cannot switch in-flight, and a
    /// 3P→Anthropic in-flight repoint would exfiltrate the Anthropic OAuth token
    /// to the frozen 3P endpoint.
    #[test]
    fn route_claudecode_env_transport_forces_exec_replace() {
        // target is 3P (Anthropic → DeepSeek/Z.AI/MiniMax/Ollama).
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::ClaudeCode,
                false,
                true,
                None,
                None
            ),
            RouteKind::ClaudeCodeEnvTransportExecReplace
        );
        // source is 3P (3P → Anthropic) — the exfiltration-risk direction.
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::ClaudeCode,
                true,
                false,
                None,
                None
            ),
            RouteKind::ClaudeCodeEnvTransportExecReplace
        );
        // both 3P (3P → different 3P).
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::ClaudeCode,
                true,
                true,
                None,
                None
            ),
            RouteKind::ClaudeCodeEnvTransportExecReplace
        );
    }

    /// The env-transport flags ONLY affect the (ClaudeCode, ClaudeCode) cell;
    /// a true surface change always routes CrossSurface regardless of them.
    #[test]
    fn route_env_transport_flags_do_not_affect_cross_surface() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::Codex, true, true, None, None),
            RouteKind::CrossSurface
        );
        assert_eq!(
            route(Surface::Codex, Surface::ClaudeCode, true, true, None, None),
            RouteKind::CrossSurface
        );
    }

    /// Pinning: Codex→Codex, matching `account_id` on both sides, MUST stay
    /// on the same-surface in-flight repoint path (M10 / an internal journal entry).
    /// Regression guard against any future refactor that re-routes through
    /// cross_surface_exec and silently drops the user's conversation again.
    #[test]
    fn route_codex_to_codex_is_same_surface_codex() {
        assert_eq!(
            route(
                Surface::Codex,
                Surface::Codex,
                false,
                false,
                Some("acct-a"),
                Some("acct-a")
            ),
            RouteKind::SameSurfaceCodex
        );
    }

    /// THE ORIGINATING BUG this fix closes: a codex→codex swap between two
    /// DIFFERENT accounts MUST NOT take the in-flight repoint path. codex-cli
    /// refuses to reload `auth.json` in-flight when `account_id` differs
    /// from the running session's ("Skipping auth reload due to account id
    /// mismatch"), so the pre-fix `SameSurfaceCodex` route left the OLD
    /// account live while csq reported success. This assertion MUST go RED
    /// against the pre-fix `route()` (which routed ALL codex→codex pairs to
    /// `SameSurfaceCodex` regardless of account id).
    #[test]
    fn route_codex_to_codex_account_mismatch_forces_exec_replace() {
        assert_eq!(
            route(
                Surface::Codex,
                Surface::Codex,
                false,
                false,
                Some("acct-a"),
                Some("acct-b")
            ),
            RouteKind::CodexAccountMismatchExecReplace
        );
    }

    /// Fail-closed: codex→codex with the SOURCE account id unknown (marker
    /// unresolved / credential file unreadable) MUST exec-replace, never
    /// assume a match. Mirrors `resolve_source_env_transport`'s fail-closed
    /// discipline for the ClaudeCode cell.
    #[test]
    fn route_codex_to_codex_unknown_source_account_id_forces_exec_replace() {
        assert_eq!(
            route(
                Surface::Codex,
                Surface::Codex,
                false,
                false,
                None,
                Some("acct-b")
            ),
            RouteKind::CodexAccountMismatchExecReplace
        );
    }

    /// Fail-closed: codex→codex with the TARGET account id unknown MUST
    /// exec-replace, never assume a match.
    #[test]
    fn route_codex_to_codex_unknown_target_account_id_forces_exec_replace() {
        assert_eq!(
            route(
                Surface::Codex,
                Surface::Codex,
                false,
                false,
                Some("acct-a"),
                None
            ),
            RouteKind::CodexAccountMismatchExecReplace
        );
    }

    /// Fail-closed: codex→codex with BOTH account ids unknown MUST
    /// exec-replace — two unknowns are not a match.
    #[test]
    fn route_codex_to_codex_both_unknown_account_ids_forces_exec_replace() {
        assert_eq!(
            route(Surface::Codex, Surface::Codex, false, false, None, None),
            RouteKind::CodexAccountMismatchExecReplace
        );
    }

    /// The codex-account-id flags ONLY affect the (Codex, Codex) cell; a
    /// true surface change always routes CrossSurface regardless of them,
    /// and the (ClaudeCode, ClaudeCode) cell ignores them entirely.
    #[test]
    fn route_codex_account_id_flags_do_not_affect_other_cells() {
        assert_eq!(
            route(
                Surface::Codex,
                Surface::ClaudeCode,
                false,
                false,
                Some("acct-a"),
                Some("acct-b")
            ),
            RouteKind::CrossSurface
        );
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::ClaudeCode,
                false,
                false,
                Some("acct-a"),
                Some("acct-b")
            ),
            RouteKind::SameSurfaceClaudeCode
        );
    }

    /// Pinning: any cross-surface combination MUST take the exec-replace
    /// path (INV-P05 confirm + INV-P10 tombstone + exec).
    #[test]
    fn route_cross_surface_is_cross_surface() {
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::Codex,
                false,
                false,
                None,
                None
            ),
            RouteKind::CrossSurface
        );
        assert_eq!(
            route(
                Surface::Codex,
                Surface::ClaudeCode,
                false,
                false,
                None,
                None
            ),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Gemini → ClaudeCode is cross-surface (tombstone + exec).
    #[test]
    fn route_gemini_to_claudecode_is_cross_surface() {
        assert_eq!(
            route(
                Surface::Gemini,
                Surface::ClaudeCode,
                false,
                false,
                None,
                None
            ),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — ClaudeCode → Gemini is cross-surface.
    #[test]
    fn route_claudecode_to_gemini_is_cross_surface() {
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::Gemini,
                false,
                false,
                None,
                None
            ),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Codex → Gemini is cross-surface.
    #[test]
    fn route_codex_to_gemini_is_cross_surface() {
        assert_eq!(
            route(Surface::Codex, Surface::Gemini, false, false, None, None),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Gemini → Codex is cross-surface.
    #[test]
    fn route_gemini_to_codex_is_cross_surface() {
        assert_eq!(
            route(Surface::Gemini, Surface::Codex, false, false, None, None),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b, reshaped under `InFlightAdoption`: Gemini→Gemini takes the
    /// exec-replace path because Gemini's in-flight adoption capability is
    /// declared `Unknown` (not yet characterised against gemini-cli source
    /// — see `in_flight_adoption`'s doc comment). This is now an EXPLICIT
    /// same-surface route (`SameSurfaceUnknownAdoptionExecReplace`), not
    /// the `CrossSurface` wildcard it fell through pre-reshape — that
    /// wildcard's own doc comment claimed "Source ≠ target surface", which
    /// was false for this pair (`doc-property-claims.md`).
    #[test]
    fn route_gemini_to_gemini_is_same_surface_unknown_adoption() {
        assert_eq!(
            route(Surface::Gemini, Surface::Gemini, false, false, None, None),
            RouteKind::SameSurfaceUnknownAdoptionExecReplace
        );
    }

    /// Kimi→Kimi: same `Unknown` capability, same exec-replace outcome.
    /// Not exercised before the reshape (silently absorbed by the
    /// `CrossSurface` wildcard with no dedicated test).
    #[test]
    fn route_kimi_to_kimi_is_same_surface_unknown_adoption() {
        assert_eq!(
            route(Surface::Kimi, Surface::Kimi, false, false, None, None),
            RouteKind::SameSurfaceUnknownAdoptionExecReplace
        );
    }

    /// Grok→Grok: same `Unknown` capability, same exec-replace outcome.
    #[test]
    fn route_grok_to_grok_is_same_surface_unknown_adoption() {
        assert_eq!(
            route(Surface::Grok, Surface::Grok, false, false, None, None),
            RouteKind::SameSurfaceUnknownAdoptionExecReplace
        );
    }

    /// Exhaustiveness freeze: every `Surface` has a DECLARED
    /// `InFlightAdoption`. Primary enforcement is the compiler — there is
    /// no wildcard arm in `in_flight_adoption`, so a new `Surface` variant
    /// fails to compile until its adoption rule is added there. This test
    /// freezes the CURRENT declared capability per surface so a future
    /// change is a visible, reviewed diff rather than a silent behavior
    /// change.
    /// A Kimi/Grok session IS csq-managed, so the generic
    /// "must run inside a csq-managed session" message asserts something
    /// false about the operator's state. Pins the honest refusal instead.
    ///
    /// Holds the shared process-env lock per `test-hermeticity.md` MUST-1:
    /// this test both MUTATES and transitively READS process-global env, and
    /// `detect_source_handle` probes four other vars that a parent shell or a
    /// sibling test could be setting concurrently.
    #[test]
    fn native_session_refusal_names_the_frozen_env_not_a_missing_session() {
        let _lock = csq_core::platform::test_env::lock();
        let base = tempfile::TempDir::new().unwrap();
        let _env = clear_source_env();

        // Clear everything `detect_source_handle` probes, so the native arm is
        // reached for the reason under test and not by accident.
        for var in [
            "GEMINI_CLI_HOME",
            "CODEX_HOME",
            "CLAUDE_CONFIG_DIR",
            native::KIMI.home_env,
            native::GROK.home_env,
        ] {
            std::env::remove_var(var);
        }

        // Control: with nothing set at all, the generic message is correct.
        let generic = detect_source_handle(base.path(), AccountNum::try_from(3u16).unwrap())
            .expect_err("no surface env set must refuse");
        assert!(
            generic.to_string().contains("csq-managed session"),
            "the no-env case keeps its original message: {generic}"
        );

        for descriptor in [&native::KIMI, &native::GROK] {
            std::env::set_var(descriptor.home_env, "/tmp/does-not-need-to-exist");
            let e = detect_source_handle(base.path(), AccountNum::try_from(3u16).unwrap())
                .expect_err("a native session must refuse to swap in place");
            let msg = e.to_string();
            std::env::remove_var(descriptor.home_env);

            assert!(
                msg.contains(descriptor.home_env),
                "must name the frozen variable that actually blocks it: {msg}"
            );
            assert!(
                !msg.contains("csq-managed session"),
                "must NOT tell an operator inside a csq-managed session that they \
                 are not in one: {msg}"
            );
            assert!(
                msg.contains("csq run 3"),
                "must give the copy-pasteable recovery with the slot they typed: {msg}"
            );
        }
    }

    /// Every `Surface` declares a slot binding. Companion to the adoption
    /// exhaustiveness freeze: a new surface must state BOTH axes or the build
    /// fails — `slot_binding` has no wildcard arm.
    #[test]
    fn slot_binding_declared_for_every_surface() {
        assert_eq!(
            slot_binding(Surface::ClaudeCode),
            SlotBinding::HandleDirSymlink
        );
        assert_eq!(slot_binding(Surface::Codex), SlotBinding::HandleDirSymlink);
        assert_eq!(slot_binding(Surface::Gemini), SlotBinding::HandleDirSymlink);
        assert_eq!(slot_binding(Surface::Kimi), SlotBinding::LaunchEnv);
        assert_eq!(slot_binding(Surface::Grok), SlotBinding::LaunchEnv);
    }

    /// THE TRAP THIS AXIS EXISTS FOR. Grok's credential STORE hot-reloads on
    /// the vendor's own documented contract, so its `InFlightAdoption` is
    /// honestly `Always` — but its slot binding is `GROK_HOME`, frozen on the
    /// child `Command` at spawn. Without the `SlotBinding` check, `Always`
    /// falls through to the env-transport branch, where
    /// `slot_pins_anthropic_base_url` returns FALSE for every native slot
    /// (they pin no Anthropic settings), yielding
    /// `RouteKind::SameSurfaceClaudeCode` — a ClaudeCode handle-dir symlink
    /// repoint for a surface that has no handle-dir symlinks. Silent success,
    /// old account still serving: the 2026-09-12 codex defect, different door.
    ///
    /// REDs if the `SlotBinding::LaunchEnv` early return is removed.
    #[test]
    fn launch_env_bound_surfaces_never_route_in_flight() {
        for surface in [Surface::Grok, Surface::Kimi] {
            let r = route(surface, surface, false, false, None, None);
            assert_eq!(
                r,
                RouteKind::SameSurfaceUnknownAdoptionExecReplace,
                "{surface:?} binds its slot through a launch env var frozen at \
                 spawn — it MUST exec-replace however eagerly its credential \
                 store reloads, got {r:?}"
            );
            assert_ne!(
                r,
                RouteKind::SameSurfaceClaudeCode,
                "{surface:?} must never take the ClaudeCode symlink-repoint \
                 path — it has no handle-dir symlinks to repoint"
            );
        }
    }

    /// A launch-env surface exec-replaces even when a matching account id
    /// would otherwise authorise an in-flight swap. Guards the `Always` arm
    /// AND the `WhenSameAccountId` arm, so a future native surface that grows
    /// an account id cannot repeat the class.
    #[test]
    fn launch_env_beats_a_matching_account_id() {
        let r = route(
            Surface::Grok,
            Surface::Grok,
            false,
            false,
            Some("same-account-id"),
            Some("same-account-id"),
        );
        assert_eq!(r, RouteKind::SameSurfaceUnknownAdoptionExecReplace);
    }

    /// Gemini is now `Never` on evidence rather than `Unknown` by default.
    /// Routing is unchanged (both exec-replace) — this pins the DECLARATION,
    /// so a future edit cannot quietly promote it to `Always`.
    #[test]
    fn gemini_adoption_is_never_on_evidence() {
        assert_eq!(in_flight_adoption(Surface::Gemini), InFlightAdoption::Never);
        assert_eq!(
            route(Surface::Gemini, Surface::Gemini, false, false, None, None),
            RouteKind::SameSurfaceUnknownAdoptionExecReplace
        );
    }

    fn in_flight_adoption_declared_for_every_surface() {
        assert_eq!(
            in_flight_adoption(Surface::ClaudeCode),
            InFlightAdoption::Always
        );
        assert_eq!(
            in_flight_adoption(Surface::Codex),
            InFlightAdoption::WhenSameAccountId
        );
        assert_eq!(
            in_flight_adoption(Surface::Gemini),
            InFlightAdoption::Unknown
        );
        assert_eq!(in_flight_adoption(Surface::Kimi), InFlightAdoption::Unknown);
        assert_eq!(in_flight_adoption(Surface::Grok), InFlightAdoption::Unknown);
    }

    /// PR-G4b — `SourceHandle::Gemini` reports `Surface::Gemini`.
    #[test]
    fn source_handle_gemini_surface_matches_variant() {
        let g = SourceHandle::Gemini(PathBuf::from("/x/term-3"));
        assert_eq!(g.surface(), Surface::Gemini);
    }

    // ── PR-C9a an internal journal entry finding 10 — rename-to-tombstone ─

    /// The tombstone rename MUST atomically move the source handle
    /// dir to a sibling path with the `.sweep-tombstone-` prefix so
    /// the daemon's existing `cleanup_stale_tombstones` sweep reaps
    /// it. The source path is free; the directory inode survives for
    /// any process still holding fds into it.
    #[test]
    fn rename_handle_dir_to_sweep_tombstone_moves_dir() {
        let base = tempfile::TempDir::new().unwrap();
        let source = base.path().join("term-99999");
        std::fs::create_dir(&source).unwrap();
        // Seed a sentinel to prove the inode survived the move.
        std::fs::write(source.join("sentinel"), b"alive").unwrap();

        rename_handle_dir_to_sweep_tombstone(&source).unwrap();

        // Source path is gone.
        assert!(
            !source.exists(),
            "source handle dir must be gone after rename"
        );
        // A .sweep-tombstone-swap-<pid>-<nanos> sibling exists with
        // the sentinel intact.
        let mut tombstone_names: Vec<String> = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(".sweep-tombstone-swap-"))
            .collect();
        assert_eq!(
            tombstone_names.len(),
            1,
            "exactly one swap tombstone must exist"
        );
        let name = tombstone_names.pop().unwrap();
        let tomb = base.path().join(&name);
        assert!(tomb.is_dir(), "tombstone must be a directory");
        let sentinel = tomb.join("sentinel");
        let body = std::fs::read(&sentinel).expect("sentinel readable after rename");
        assert_eq!(body, b"alive", "tombstone preserves contents");
        // Prefix matches the daemon's cleanup harness.
        assert!(
            name.starts_with(".sweep-tombstone-"),
            "must share prefix with sweep's existing tombstone cleanup: {name}"
        );
    }

    /// Guard against the regression the old `remove_dir_all` had:
    /// if the sibling process had an open fd, the rename must NOT
    /// disturb the on-disk file — exactly one atomic syscall and the
    /// contents must be readable through the new name. (Unix only;
    /// Windows rename-over-open-handle semantics differ and this
    /// path is Unix-only anyway via `cross_surface_exec`.)
    #[cfg(unix)]
    #[test]
    fn rename_handle_dir_preserves_contents_during_atomic_swap() {
        let base = tempfile::TempDir::new().unwrap();
        let source = base.path().join("term-77777");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("a"), b"one").unwrap();
        std::fs::write(source.join("b"), b"two").unwrap();

        rename_handle_dir_to_sweep_tombstone(&source).unwrap();

        let tomb = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-swap-")
            })
            .expect("tombstone present")
            .path();
        assert_eq!(std::fs::read(tomb.join("a")).unwrap(), b"one");
        assert_eq!(std::fs::read(tomb.join("b")).unwrap(), b"two");
    }

    // ── M4-8 (Phase 4 an internal ticket) — legacy-fallback retirement ─────

    /// Serializes the env-var-driven tests below — `CLAUDE_CONFIG_DIR`,
    /// `CODEX_HOME`, and `GEMINI_CLI_HOME` are process-globals, so
    /// concurrent test invocations would race and produce
    /// non-deterministic results.
    ///
    /// Uses the workspace-wide `csq_core::platform::test_env::lock()`
    /// per `rules/testing.md` MUST Rule 6 — an in-module mutex would
    /// NOT serialize against tests in OTHER modules that mutate or
    /// read the same env vars (e.g. surface.rs tests mutating
    /// `CODEX_USER_CONFIG`). The shared lock subsumes the local-only
    /// serialization need.
    fn env_swap_guard() -> std::sync::MutexGuard<'static, ()> {
        csq_core::platform::test_env::lock()
    }

    /// RAII wrapper that restores `CLAUDE_CONFIG_DIR` to its prior
    /// value (or removes it if previously unset) when dropped.
    struct EnvVarGuard {
        key: &'static str,
        prior: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prior }
        }

        fn unset(key: &'static str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prior }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn clear_source_env() -> Vec<EnvVarGuard> {
        [
            "GEMINI_CLI_HOME",
            "CODEX_HOME",
            "CLAUDE_CONFIG_DIR",
            native::KIMI.home_env,
            native::GROK.home_env,
        ]
        .into_iter()
        .map(EnvVarGuard::unset)
        .collect()
    }

    const SOURCE_ENVS: [(&str, Surface); 3] = [
        ("GEMINI_CLI_HOME", Surface::Gemini),
        ("CODEX_HOME", Surface::Codex),
        ("CLAUDE_CONFIG_DIR", Surface::ClaudeCode),
    ];

    #[test]
    fn source_handle_validation_rejects_base_itself_but_accepts_real_child() {
        let _lock = env_swap_guard();
        let _env = clear_source_env();
        let root = tempfile::TempDir::new().unwrap();
        // The configured base may itself have a term-* name; containment must
        // be strict so an exec route cannot tombstone the entire base.
        let base = root.path().join("term-base");
        let child = base.join("term-child");
        std::fs::create_dir_all(&child).unwrap();
        let target = AccountNum::try_from(2u16).unwrap();
        for (key, surface) in SOURCE_ENVS {
            {
                let _selected = EnvVarGuard::set(key, base.to_str().unwrap());
                assert_eq!(
                    detect_source_handle(&base, target).unwrap_err().to_string(),
                    "swap_source_handle_outside_base"
                );
            }
            let _selected = EnvVarGuard::set(key, child.to_str().unwrap());
            let source = detect_source_handle(&base, target).unwrap();
            assert_eq!(source.surface(), surface);
            assert_eq!(source.path(), child.canonicalize().unwrap());
        }
    }

    #[test]
    fn source_handle_validation_rejects_foreign_term_dirs_for_all_surfaces() {
        let _lock = env_swap_guard();
        let _env = clear_source_env();
        let root = tempfile::TempDir::new().unwrap();
        let base = root.path().join("accounts");
        // Shared textual prefix must not satisfy Path component containment.
        let foreign = root.path().join("accounts-other/term-fixture");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("sentinel"), b"untouched").unwrap();
        for (key, _) in SOURCE_ENVS {
            let _selected = EnvVarGuard::set(key, foreign.to_str().unwrap());
            let error =
                detect_source_handle(&base, AccountNum::try_from(2u16).unwrap()).unwrap_err();
            assert_eq!(error.to_string(), "swap_source_handle_outside_base");
        }
        assert_eq!(
            std::fs::read(foreign.join("sentinel")).unwrap(),
            b"untouched"
        );
        assert_eq!(
            std::fs::read_dir(foreign.parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn source_handle_validation_accepts_each_surface_and_preserves_precedence() {
        let _lock = env_swap_guard();
        let _env = clear_source_env();
        let base = tempfile::TempDir::new().unwrap();
        let target = AccountNum::try_from(2u16).unwrap();
        let mut guards = Vec::new();
        for (key, surface) in SOURCE_ENVS.into_iter().rev() {
            // Preserve the existing prefix grammar; do not require numeric PIDs.
            let path = base.path().join(format!("term-{key}"));
            std::fs::create_dir(&path).unwrap();
            guards.push(EnvVarGuard::set(key, path.to_str().unwrap()));
            let source = detect_source_handle(base.path(), target).unwrap();
            assert_eq!(source.surface(), surface);
            assert_eq!(source.path(), path.canonicalize().unwrap());
        }
        // A bad higher-priority candidate cannot fall back to valid Claude/Codex.
        let _bad = EnvVarGuard::set(
            "GEMINI_CLI_HOME",
            base.path().join("term-missing").to_str().unwrap(),
        );
        assert_eq!(
            detect_source_handle(base.path(), target)
                .unwrap_err()
                .to_string(),
            "swap_source_handle_unavailable"
        );
    }

    #[test]
    fn source_handle_validation_rejects_missing_and_nondirectory_paths() {
        let _lock = env_swap_guard();
        let _env = clear_source_env();
        let base = tempfile::TempDir::new().unwrap();
        let file = base.path().join("term-file");
        std::fs::write(&file, b"not a directory").unwrap();
        for (path, expected) in [
            (
                base.path().join("term-missing"),
                "swap_source_handle_unavailable",
            ),
            (file, "swap_source_handle_invalid"),
        ] {
            for (key, _) in SOURCE_ENVS {
                let _selected = EnvVarGuard::set(key, path.to_str().unwrap());
                assert_eq!(
                    detect_source_handle(base.path(), AccountNum::try_from(2u16).unwrap())
                        .unwrap_err()
                        .to_string(),
                    expected
                );
            }
        }
        assert_eq!(
            validate_source_handle_path(&base.path().join("absent-base"), base.path())
                .unwrap_err()
                .to_string(),
            "swap_source_base_unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_handle_validation_rejects_symlink_escape() {
        let _lock = env_swap_guard();
        let _env = clear_source_env();
        let root = tempfile::TempDir::new().unwrap();
        let base = root.path().join("base");
        let foreign = root.path().join("term-victim");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("sentinel"), b"untouched").unwrap();
        let link = base.join("term-link");
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        for (key, _) in SOURCE_ENVS {
            let _selected = EnvVarGuard::set(key, link.to_str().unwrap());
            assert_eq!(
                detect_source_handle(&base, AccountNum::try_from(2u16).unwrap())
                    .unwrap_err()
                    .to_string(),
                "swap_source_handle_outside_base"
            );
        }
        assert_eq!(
            std::fs::read(foreign.join("sentinel")).unwrap(),
            b"untouched"
        );
        assert_eq!(std::fs::read_link(link).unwrap(), foreign);
    }

    #[cfg(unix)]
    #[test]
    fn source_handle_validation_accepts_symlinked_base() {
        let root = tempfile::TempDir::new().unwrap();
        let base = root.path().join("base");
        let handle = base.join("term-fixture");
        std::fs::create_dir_all(&handle).unwrap();
        let alias = root.path().join("base-alias");
        std::os::unix::fs::symlink(&base, &alias).unwrap();
        assert_eq!(
            validate_source_handle_path(&alias, &alias.join("term-fixture")).unwrap(),
            handle.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_handle_validation_rejects_symlink_to_legacy_directory() {
        let base = tempfile::TempDir::new().unwrap();
        let legacy = base.path().join("config-7");
        std::fs::create_dir(&legacy).unwrap();
        let link = base.path().join("term-alias");
        std::os::unix::fs::symlink(legacy, &link).unwrap();
        assert_eq!(
            validate_source_handle_path(base.path(), &link)
                .unwrap_err()
                .to_string(),
            "swap_source_handle_invalid"
        );
    }

    /// M4-8 acceptance (a): `csq swap` invoked with `CLAUDE_CONFIG_DIR`
    /// pointing at a `config-<N>` dir refuses with the spec 02 §2.6
    /// message instructing the user to relaunch via `csq run <target>`
    /// (the actual target slot the user typed, not a literal `N` —
    /// R2 actionability fix). This is the post-M4-8 contract; the
    /// pre-M4-8 fallback through `rotation::swap_to` (which silently
    /// copied credentials) is gone.
    #[test]
    fn csq_swap_refuses_legacy_config_dir_with_relaunch_guidance() {
        let _serialize = env_swap_guard();
        let base = tempfile::TempDir::new().unwrap();
        let legacy = base.path().join("config-7");
        std::fs::create_dir(&legacy).unwrap();
        let _cc = EnvVarGuard::set("CLAUDE_CONFIG_DIR", legacy.to_str().unwrap());
        let _codex = EnvVarGuard::unset("CODEX_HOME");
        let _gemini = EnvVarGuard::unset("GEMINI_CLI_HOME");
        // Simulate `csq swap 3` from a legacy `config-7` terminal —
        // the refusal must surface BOTH the source dir AND the target
        // slot the user typed so the suggested command is copy-pasteable.
        let target = AccountNum::try_from(3u16).unwrap();

        let err = detect_source_handle(base.path(), target)
            .expect_err("M4-8: legacy config-N source MUST be refused (rotation::swap_to retired)");
        let msg = format!("{err}");
        assert!(
            msg.contains("legacy per-account mode"),
            "refusal must cite the legacy-mode phrasing from spec 02 §2.6: {msg}"
        );
        assert!(
            msg.contains("csq run 3"),
            "refusal must include the user-typed target slot for a copy-pasteable relaunch hint: {msg}"
        );
        assert!(
            msg.contains("config-7"),
            "refusal must name the source config dir: {msg}"
        );
    }

    /// M4-8 acceptance (a): `csq swap` invoked inside a `term-<pid>`
    /// handle dir takes the handle-dir model path (same-surface
    /// ClaudeCode routing → `handle_dir::repoint_handle_dir`). The
    /// repoint itself is exhaustively covered by the 20+
    /// `repoint_handle_dir_*` tests in `csq-core/src/session/handle_dir.rs`;
    /// this test pins the CLI-side routing contract that survives M4-8 —
    /// `detect_source_handle` recognizes a `term-<pid>` dir as a
    /// ClaudeCode handle and the routing matrix dispatches to
    /// `SameSurfaceClaudeCode`.
    #[test]
    fn csq_swap_succeeds_in_handle_dir() {
        let _serialize = env_swap_guard();
        let base = tempfile::TempDir::new().unwrap();
        let handle = base.path().join("term-54321");
        std::fs::create_dir(&handle).unwrap();
        let _cc = EnvVarGuard::set("CLAUDE_CONFIG_DIR", handle.to_str().unwrap());
        let _codex = EnvVarGuard::unset("CODEX_HOME");
        let _gemini = EnvVarGuard::unset("GEMINI_CLI_HOME");
        let target = AccountNum::try_from(2u16).unwrap();

        let detected = detect_source_handle(base.path(), target)
            .expect("term-<pid> source MUST be recognized as ClaudeCode");
        assert_eq!(
            detected.surface(),
            Surface::ClaudeCode,
            "handle dir source surface must be ClaudeCode"
        );
        assert_eq!(
            detected.path(),
            handle.canonicalize().unwrap().as_path(),
            "detected path must point at the supplied handle dir"
        );
        // Routing contract: same-surface ClaudeCode targets the
        // in-flight `handle_dir::repoint_handle_dir` path (M4-8's only
        // ClaudeCode swap entry).
        assert_eq!(
            route(
                Surface::ClaudeCode,
                Surface::ClaudeCode,
                false,
                false,
                None,
                None
            ),
            RouteKind::SameSurfaceClaudeCode,
        );
    }

    // ── M13b FIX-3+4 — swap audit tests ─────────────────────────────────────

    /// Helper: write a minimal `.csq-account` marker file into `handle_dir`
    /// containing the decimal string for `slot`.
    ///
    /// **This is the LEGACY (pre-M4-7) shape, not what `csq run` writes
    /// today.** M4-7 (an internal ticket Phase 4) flipped the writer
    /// (`markers::write_csq_account`) to UUID content whenever the slot has
    /// a `by_slot` mapping — `finalize_login` and `csq run` both write UUIDs
    /// on any modern install. This helper's original doc comment claimed
    /// otherwise (`guard-reader-writer-parity.md`); it is retained ONLY for
    /// pure-legacy-slot coverage (a slot with no `by_slot` entry). Tests
    /// exercising the production (UUID) marker shape MUST use
    /// `csq_core::testing::identity_fixtures::write_uuid_account_marker`
    /// instead — see `read_slot_from_handle_dir_resolves_uuid_marker`.
    fn write_csq_account_marker(handle_dir: &std::path::Path, slot: u16) {
        std::fs::write(handle_dir.join(".csq-account"), slot.to_string()).unwrap();
    }

    /// Helper: count JSONL records across all `csq-runs/*.jsonl` files.
    fn count_chain_records(base: &std::path::Path) -> usize {
        let runs_dir = base.join("csq-runs");
        if !runs_dir.exists() {
            return 0;
        }
        std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .map(|e| {
                let bytes = std::fs::read(e.path()).unwrap_or_default();
                bytes.iter().filter(|&&b| b == b'\n').count()
            })
            .sum()
    }

    /// FIX-4 AC: typed begin_swap_audit returns Ok(None) when the handle dir
    /// has no `.csq-account` marker — no record emitted, no error.
    #[test]
    fn begin_swap_audit_absent_marker_returns_ok_none() {
        let base = tempfile::TempDir::new().unwrap();
        // No .csq-account in the handle dir.
        let handle_dir = base.path().join("term-99");
        std::fs::create_dir(&handle_dir).unwrap();

        let from_slot = read_slot_from_handle_dir(base.path(), &handle_dir); // → None
        let result = begin_swap_audit(base.path(), from_slot, AccountNum::try_from(2u16).unwrap());
        assert!(result.is_ok(), "absent marker must not error: {result:?}");
        assert!(result.unwrap().is_none(), "absent marker → Ok(None)");
        assert_eq!(
            count_chain_records(base.path()),
            0,
            "no record must be written when marker is absent"
        );
    }

    /// FIX-4 AC-S1: `from_slot` / `to_slot` in the payload match the detected
    /// source marker and the target slot passed to begin_swap_audit.
    #[test]
    fn begin_swap_audit_payload_slots_match_detected_source_and_target() {
        let base = tempfile::TempDir::new().unwrap();
        let handle_dir = base.path().join("term-42");
        std::fs::create_dir(&handle_dir).unwrap();
        write_csq_account_marker(&handle_dir, 3);

        let from_slot = read_slot_from_handle_dir(base.path(), &handle_dir);
        assert_eq!(
            from_slot.map(|a| a.get()),
            Some(3),
            "marker must resolve to slot 3"
        );

        let to = AccountNum::try_from(5u16).unwrap();
        let ctx = begin_swap_audit(base.path(), from_slot, to)
            .expect("begin_swap_audit must succeed")
            .expect("ctx must be Some");

        // Parse the emitted record and check the payload.
        let runs_dir = base.path().join("csq-runs");
        let jsonl = std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .find(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .expect("a chain JSONL must exist")
            .path();
        let line = std::fs::read_to_string(&jsonl).unwrap();
        let record: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let payload = &record["payload"]["data"];
        assert_eq!(
            payload["from_slot"].as_u64(),
            Some(3),
            "from_slot must be 3 (detected marker)"
        );
        assert_eq!(
            payload["to_slot"].as_u64(),
            Some(5),
            "to_slot must be 5 (target)"
        );

        // op_phase must be Intent (serialized as {"phase": "intent", ...}).
        let op_phase = &record["op_phase"];
        assert_eq!(
            op_phase["phase"].as_str(),
            Some("intent"),
            "emitted record must have op_phase.phase == 'intent', got: {op_phase}"
        );

        let _ = ctx;
    }

    /// `resolve_source_env_transport` MUST fail CLOSED (`true`) when the
    /// source marker is unresolvable — this is the security-relevant half
    /// of the M4-7 marker-reader fix: pre-fix, an unresolvable marker
    /// (which was EVERY modern slot, since `read_slot_from_handle_dir` could
    /// not parse a UUID marker) reported `false`, letting `route()` choose
    /// the in-flight-repoint path for a source that might actually be a
    /// frozen 3P/Ollama env-transport slot.
    #[test]
    fn resolve_source_env_transport_fails_closed_when_marker_unresolved() {
        let base = tempfile::TempDir::new().unwrap();
        assert!(
            resolve_source_env_transport(base.path(), None),
            "unresolved source marker must fail CLOSED (assume env-transport), not open"
        );
    }

    /// A resolved source slot with no `env.ANTHROPIC_BASE_URL` pin reports
    /// `false` — the safe, correct, non-fail-closed case.
    #[test]
    fn resolve_source_env_transport_false_for_plain_anthropic_slot() {
        let base = tempfile::TempDir::new().unwrap();
        let config_dir = base.path().join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        // No settings.json written — slot_pins_anthropic_base_url returns false.
        assert!(!resolve_source_env_transport(
            base.path(),
            Some(AccountNum::try_from(3u16).unwrap())
        ));
    }

    /// A resolved source slot whose `settings.json` pins
    /// `env.ANTHROPIC_BASE_URL` reports `true`.
    #[test]
    fn resolve_source_env_transport_true_for_env_transport_slot() {
        let base = tempfile::TempDir::new().unwrap();
        let config_dir = base.path().join("config-4");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://3p.example.com"}}"#,
        )
        .unwrap();
        assert!(resolve_source_env_transport(
            base.path(),
            Some(AccountNum::try_from(4u16).unwrap())
        ));
    }

    // ── `read_codex_account_id` — identity-keyed path + legacy fallback ──

    /// Writes a minimal Codex credential file with `tokens.account_id` at
    /// slot `slot`'s canonical READ path. `identity_keyed=true` provisions a
    /// `by_slot` UUID mapping (via the shared fixture helper) and writes to
    /// the identity-keyed `identities/<UUID>/credentials-codex.json`;
    /// `identity_keyed=false` writes directly to the legacy
    /// `credentials/codex-<N>.json` mirror with NO `by_slot` entry, so
    /// `resolve_slot_to_uuid` returns `None` and the reader must fall back.
    fn write_codex_creds_fixture(base: &Path, slot: u16, account_id: &str, identity_keyed: bool) {
        let path = if identity_keyed {
            let dummy_dir = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&dummy_dir).unwrap();
            let uuid = csq_core::testing::identity_fixtures::write_uuid_account_marker(
                base, &dummy_dir, slot,
            );
            csq_core::accounts::identity_store::credentials_codex_path_for(base, uuid)
        } else {
            base.join("credentials").join(format!("codex-{slot}.json"))
        };
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // "eyJ.test.sig" is a JWT-shaped-but-malformed access token (2 dots,
        // an unparseable payload segment) — `jwt_exp_secs` returns `None`
        // for it, and `check_codex_token_freshness` treats "no exp found"
        // as non-fatal, so this fixture's token reads as fresh (C-F2/S-F3's
        // handoff-time freshness check does not reject it).
        let json = serde_json::json!({
            "tokens": { "account_id": account_id, "access_token": "eyJ.test.sig" }
        });
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        // C-F2/S-F3: `handoff_to_supervisor` now also requires the target's
        // `config-<N>/config.toml` to exist (mirrors `launch_codex`'s
        // `verify_codex_config_toml`) — a real Codex slot always has this
        // after `csq login N --provider codex`, so every caller of this
        // fixture that exercises the handoff path needs it too.
        let config_toml = base.join(format!("config-{slot}")).join("config.toml");
        std::fs::create_dir_all(config_toml.parent().unwrap()).unwrap();
        if !config_toml.exists() {
            std::fs::write(&config_toml, b"").unwrap();
        }
    }

    /// `read_codex_account_id` MUST read through the identity-keyed path
    /// when a `by_slot` UUID mapping exists — the same channel
    /// `refresh::check::broker_codex_check` reads (`diagnostic-surface-
    /// parity.md` MUST NOT Rule 4).
    #[test]
    fn read_codex_account_id_reads_identity_keyed_path() {
        let base = tempfile::TempDir::new().unwrap();
        write_codex_creds_fixture(
            base.path(),
            11,
            "3bf322e8-561c-4349-910e-a79ee0a76fc1",
            true,
        );
        assert_eq!(
            read_codex_account_id(base.path(), AccountNum::try_from(11u16).unwrap()),
            Some("3bf322e8-561c-4349-910e-a79ee0a76fc1".to_string())
        );
    }

    /// `read_codex_account_id` falls back to the legacy
    /// `credentials/codex-<N>.json` mirror when no `by_slot` UUID mapping
    /// exists (`resolve_slot_to_uuid` returns `None`).
    #[test]
    fn read_codex_account_id_falls_back_to_legacy_mirror() {
        let base = tempfile::TempDir::new().unwrap();
        write_codex_creds_fixture(
            base.path(),
            12,
            "e5116d30-74a9-42d7-a39a-64b0490ae9f3",
            false,
        );
        assert_eq!(
            read_codex_account_id(base.path(), AccountNum::try_from(12u16).unwrap()),
            Some("e5116d30-74a9-42d7-a39a-64b0490ae9f3".to_string())
        );
    }

    /// `read_codex_account_id` returns `None` (unknown, NOT "no id") when
    /// neither the identity-keyed path nor the legacy mirror exists.
    #[test]
    fn read_codex_account_id_none_when_no_credential_file() {
        let base = tempfile::TempDir::new().unwrap();
        assert_eq!(
            read_codex_account_id(base.path(), AccountNum::try_from(13u16).unwrap()),
            None
        );
    }

    /// `read_codex_account_id` returns `None` when the credential file
    /// exists but is ClaudeCode-shaped (not Codex) — `creds.codex()`
    /// returns `None`, and the `?` propagates.
    #[test]
    fn read_codex_account_id_none_when_file_is_anthropic_shaped() {
        let base = tempfile::TempDir::new().unwrap();
        let path = base.path().join("credentials").join("codex-14.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            br#"{"claudeAiOauth":{"accessToken":"x","refreshToken":"y","expiresAt":1,"scopes":[]}}"#,
        )
        .unwrap();
        assert_eq!(
            read_codex_account_id(base.path(), AccountNum::try_from(14u16).unwrap()),
            None
        );
    }

    /// M4-7 regression (`guard-reader-writer-parity.md`): a UUID-content
    /// `.csq-account` marker — the shape `csq run` / `finalize_login`
    /// actually write on any modern install — MUST resolve to a slot.
    /// Before the fix, `read_slot_from_handle_dir` called the numeric-only
    /// `markers::read_csq_account`, so `from_slot` came back `None` for
    /// EVERY swap sourced from a modern slot: `begin_swap_audit` then
    /// skipped emitting an `AccountSwap` record (an unaudited swap), and
    /// `source_env_transport` fell back to `false` — the unsafe direction
    /// for the exfiltration guard this same defect closes (see
    /// `resolve_source_env_transport_fails_closed_when_marker_unresolved`).
    #[test]
    fn read_slot_from_handle_dir_resolves_uuid_marker() {
        let base = tempfile::TempDir::new().unwrap();
        let handle_dir = base.path().join("term-88");
        std::fs::create_dir(&handle_dir).unwrap();
        // UUID-content marker (M4-7 writer shape), provisions
        // profiles.json::by_slot[9] via the shared fixture helper.
        csq_core::testing::identity_fixtures::write_uuid_account_marker(
            base.path(),
            &handle_dir,
            9,
        );

        assert_eq!(
            read_slot_from_handle_dir(base.path(), &handle_dir),
            Some(AccountNum::try_from(9u16).unwrap()),
            "UUID .csq-account marker must resolve to its by_slot slot number"
        );
    }

    /// FIX-4 AC: intent-persist failure (read-only csq-runs/) → begin_swap_audit
    /// returns Err, and the audited wrappers fail closed (swap does NOT proceed).
    #[cfg(unix)]
    #[test]
    fn swap_audit_intent_persist_failure_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::TempDir::new().unwrap();

        // Create csq-runs/ as read-only so the intent write fails.
        let runs_dir = base.path().join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        let handle_dir = base.path().join("term-55");
        std::fs::create_dir(&handle_dir).unwrap();
        write_csq_account_marker(&handle_dir, 1);

        let from_slot = read_slot_from_handle_dir(base.path(), &handle_dir);
        let result = begin_swap_audit(base.path(), from_slot, AccountNum::try_from(2u16).unwrap());

        // Restore so TempDir cleanup works.
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        assert!(
            result.is_err(),
            "intent-persist failure must return Err (fail-closed): {result:?}"
        );
    }

    /// FIX-4 AC: intent-before-tombstone ordering is structurally pinned.
    /// The INTENT emit in cross_surface_exec MUST precede the tombstone rename.
    #[test]
    fn cross_surface_intent_before_tombstone_pinned_in_source() {
        let src = include_str!("swap.rs");
        // Look for the sentinel text that documents FIX-2 ordering.
        assert!(
            src.contains("Step 1: emit INTENT (before any destructive operation)"),
            "swap.rs must contain the FIX-2 ordering sentinel for INTENT-before-tombstone"
        );
        assert!(
            src.contains("Step 2: tombstone source handle dir"),
            "swap.rs must contain the Step 2 tombstone sentinel after INTENT"
        );
        assert!(
            src.contains("Step 4: emit OUTCOME"),
            "swap.rs must contain the Step 4 OUTCOME-before-exec sentinel"
        );
    }

    /// Regression guard for the double-create bug: the step-5 exec helpers MUST
    /// re-derive the target handle dir path (`term-<pid>`), NOT call the create fn
    /// a second time. `create_target_handle_dir` (step 3) already created the dir
    /// and wrote its live `.live-pid`; a second `create_handle_dir[_codex]` with the
    /// same pid trips the live-PID guard ("in use by live PID … Refusing to remove")
    /// and aborts every exec-replace swap to a ClaudeCode/Codex target.
    #[test]
    fn exec_helpers_rederive_handle_dir_not_recreate() {
        let src = include_str!("swap.rs");
        // Split off the test module so we only inspect production code.
        let prod = src
            .split("mod tests")
            .next()
            .expect("swap.rs must have production code before the test module");
        // All three step-5 exec arms (ClaudeCode, Codex, Gemini) MUST re-derive the
        // target handle dir by path rather than calling the create fn a second time.
        // `create_target_handle_dir` (step 3) is the SINGLE creator; a second create
        // with the same pid trips the live-PID guard and aborts the swap.
        assert!(
            prod.matches("base_dir.join(format!(\"term-{pid}\"))")
                .count()
                >= 3,
            "all three exec arms must re-derive term-<pid> by path (double-create trips \
             the live-PID guard — see exec_*_after_binding)"
        );
        // create_handle_dir must appear EXACTLY once in production (step 3's creator);
        // create_handle_dir_codex likewise. A second occurrence means an exec arm
        // regressed to re-creating.
        assert_eq!(
            prod.matches("handle_dir::create_handle_dir(").count(),
            1,
            "create_handle_dir must be called exactly once (step 3 creator only)"
        );
    }

    /// Round-3 FIX-1: when the `.chain-broken` sentinel is set,
    /// `begin_swap_audit` MUST return `Ok(None)` (degrade-not-fail-closed).
    /// This mirrors the absent-marker path — no audit context means no
    /// outcome emitted, but swap itself is NOT blocked.
    #[test]
    fn begin_swap_audit_skips_when_chain_broken() {
        let base = tempfile::TempDir::new().unwrap();
        let handle_dir = base.path().join("term-77");
        std::fs::create_dir(&handle_dir).unwrap();
        write_csq_account_marker(&handle_dir, 3);

        // Set the .chain-broken sentinel.
        csq_core::audit::set_chain_broken(base.path(), "chain_broken_test");

        let from_slot = read_slot_from_handle_dir(base.path(), &handle_dir);
        let result = begin_swap_audit(base.path(), from_slot, AccountNum::try_from(5u16).unwrap());

        // MUST succeed with None (degrade, not fail-closed).
        assert!(
            result.is_ok(),
            "begin_swap_audit must not Err when chain is broken: {result:?}"
        );
        assert!(
            result.unwrap().is_none(),
            "begin_swap_audit must return Ok(None) (skip audit) when chain is broken"
        );

        // Zero records on chain.
        assert_eq!(
            count_chain_records(base.path()),
            0,
            "no audit records must be written when chain is broken"
        );
    }

    // ── round 7c D-F7: end-to-end `handle()` harness (PRIMARY METHODOLOGICAL
    // DIRECTIVE) ────────────────────────────────────────────────────────────
    //
    // Every test above this point drives a PURE helper extracted from
    // `handle()` (`decide_swap_disposition`, `decide_ok_repoint_disposition`,
    // `route`, ...) — none of them calls `handle()` itself. That is exactly
    // why D5 (b5e86cd9) landed with its swap-level test list undone:
    // `force_sync_account_changed`/`reconcile_keychain_to_marker` short-
    // circuit to a no-op under `keychain_mirror_disabled()` (true for every
    // `cfg(test)`/`test-utils` build), so a `handle()`-level test never
    // reached the real `decide_cc_keychain_write`/`apply_cc_keychain_write`
    // policy — it always observed the disabled-mirror stub.
    //
    // `set_test_keychain_executor` (round 7c D-F7, `csq-core`) installs a
    // `ScriptedKeychainExecutor` that the two public entry points consult
    // BEFORE that short-circuit, so `handle()` now drives the REAL policy
    // against fixture-controlled state. `harvest_account`'s daemon-IPC call
    // needs no seam at all: an absent Unix socket already maps to
    // `HarvestAccountOutcome::Unavailable` in production code, and a present
    // one (a bare `UnixListener` this module binds and replies through) is a
    // real IPC round-trip — not a mock of the client, a peer of it.
    #[cfg(target_os = "macos")]
    mod handle_e2e {
        use super::*;
        use csq_core::accounts::identity_store::{self, IdentityId};
        use csq_core::credentials::keychain::{
            clear_test_keychain_executor, set_test_keychain_executor, RawContentClassification,
            ScriptedKeychainExecutor,
        };
        use csq_core::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use csq_core::session::handle_dir::create_handle_dir;
        use csq_core::testing::identity_fixtures::write_uuid_account_marker;
        use csq_core::types::{AccessToken, RefreshToken};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::rc::Rc;

        /// Clears the thread-local executor override on drop, so a panicking
        /// assertion in one test can never leak a scripted executor into the
        /// next test that happens to run on the same worker thread.
        struct ExecutorGuard;
        impl Drop for ExecutorGuard {
            fn drop(&mut self) {
                clear_test_keychain_executor();
            }
        }

        fn install_executor(
            find_result: RawContentClassification,
        ) -> (Rc<ScriptedKeychainExecutor>, ExecutorGuard) {
            install_scripted(ScriptedKeychainExecutor::scripted(find_result))
        }

        /// Same as [`install_executor`] but takes an already-configured
        /// executor (e.g. `.with_add_failing()`), so a test can script both
        /// the initial state AND a failure mode in one call.
        fn install_scripted(
            exec: ScriptedKeychainExecutor,
        ) -> (Rc<ScriptedKeychainExecutor>, ExecutorGuard) {
            let exec = Rc::new(exec);
            set_test_keychain_executor(exec.clone());
            (exec, ExecutorGuard)
        }

        fn make_creds(access: &str, refresh: &str, expires_at_ms: u64) -> CredentialFile {
            CredentialFile::Anthropic(AnthropicCredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new(access.into()),
                    refresh_token: RefreshToken::new(refresh.into()),
                    expires_at: expires_at_ms,
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: Default::default(),
                },
                extra: Default::default(),
            })
        }

        fn creds_json(cf: &CredentialFile) -> String {
            serde_json::to_string(cf).expect("fixture: serialize CredentialFile")
        }

        /// Mirrors production's mint path (`csq login` / the daemon's
        /// first-start mint pass): `config-<slot>/` on disk, a UUID-content
        /// `.csq-account` marker (`markers::write_csq_account` shape, via
        /// the shared `write_uuid_account_marker` fixture helper per
        /// `feedback_test_fixtures_mirror_real_csq_state`), `profiles.json`
        /// `by_slot[slot]`, and `identities/<uuid>/credentials.json` — the
        /// identity-keyed file `target_token_for_forced_write` reads.
        fn provision_account(
            base: &Path,
            slot: u16,
            access: &str,
            refresh: &str,
            expires_at_ms: u64,
        ) -> IdentityId {
            let config_dir = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&config_dir).unwrap();
            let uuid = write_uuid_account_marker(base, &config_dir, slot);
            let cf = make_creds(access, refresh, expires_at_ms);
            credentials::save(&identity_store::credentials_path_for(base, uuid), &cf).unwrap();
            uuid
        }

        const FAR_FUTURE_EXPIRY_MS: u64 = 4_102_444_800_000; // year 2100 (feedback_no_test_timebombs)
        const PAST_EXPIRY_MS: u64 = 1_000; // 1970 — unambiguously expired

        /// Creates `term-<pid>/` bound to `slot` via the real production
        /// helper (`create_handle_dir`) — identical symlink/marker shape a
        /// live `csq run` produces. `slot`'s `config-<slot>/` MUST already
        /// exist (`provision_account`).
        fn make_source_handle_dir(base: &Path, claude_home: &Path, pid: u32, slot: u16) -> PathBuf {
            let account = AccountNum::try_from(slot).unwrap();
            create_handle_dir(base, claude_home, account, pid).unwrap()
        }

        /// A one-shot fake `/api/harvest-account` responder: binds the exact
        /// socket path `handle()`'s harvest call resolves
        /// (`csq_core::daemon::socket_path(base)`), accepts ONE connection,
        /// drains the request, and replies with a fixed
        /// `{"outcome":"<outcome>"}` body — a real peer of `harvest_account`,
        /// not a mock of it: the same HTTP/1.1-over-Unix-socket wire format
        /// axum serves in production. Absent entirely (no call to this
        /// helper) reproduces `HarvestAccountOutcome::Unavailable` for free,
        /// since `harvest_account` maps a missing socket to `Unavailable`
        /// without ever connecting.
        fn spawn_fake_harvest_server(
            base: &Path,
            outcome: &'static str,
        ) -> std::thread::JoinHandle<()> {
            let sock = csq_core::daemon::socket_path(base);
            let listener = UnixListener::bind(&sock).expect("fixture: bind fake harvest socket");
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let body = format!("{{\"outcome\":\"{outcome}\"}}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            })
        }

        /// (a) [`keychain-fix-r8c.md`'s C-F7 swap half]: the pre-repoint
        /// forced write lands (X now holds the TARGET account's token), but
        /// `repoint_handle_dir` itself then refuses — here via its S-final
        /// F3 pre-flight guard (target `config-N` missing `.csq-account`,
        /// the ONE item it requires to exist before repointing — see that
        /// function's doc) — so the handle dir's marker never moves off the
        /// SOURCE account. `result.is_err()` reaches the `if
        /// route_is_same_surface_claude_code` block regardless (B2: it runs
        /// on both outcomes), which re-reads the (unmoved) marker and must
        /// make X agree with it again — i.e. the keychain ends up holding
        /// the SOURCE account's token, not left stranded on the target's.
        /// "Keychain matches marker" is checked via `last_add_payload()`,
        /// since the scripted executor has no separate "current effective
        /// content" query — the last successful `add()` IS the content.
        #[test]
        fn t_a_repoint_fails_keychain_reconciles_to_marker() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90000, 1);

            // Break the repoint's own pre-flight guard: the target config
            // dir must have a `.csq-account` marker or `repoint_handle_dir`
            // refuses before touching any symlink (`session::handle_dir`'s
            // "VP-final F3" pre-flight check). This does NOT affect the
            // force-write step above it in `handle()`, which resolves the
            // target's own token via the identity store (`by_slot` in
            // `profiles.json`), never via this file.
            std::fs::remove_file(base.path().join("config-2").join(".csq-account")).expect(
                "fixture: remove target .csq-account to force the repoint precondition to fail",
            );

            // X starts absent; the pre-repoint forced write (target=2)
            // succeeds and becomes the scripted executor's `current` state.
            let (exec, _guard) = install_executor(RawContentClassification::Absent);

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(
                result.is_err(),
                "a repoint precondition failure must fail the swap: {result:?}"
            );

            let payload = exec
                .last_add_payload()
                .expect("reconcile must write X back toward the (unmoved) marker account");
            assert!(
                payload.contains("rt-1"),
                "keychain must end up matching the marker (source account 1's token), \
                 not left holding the target's — last add payload: {payload}"
            );
            assert!(
                !payload.contains("rt-2"),
                "keychain must not be left on the target's token after a failed repoint: {payload}"
            );
        }

        /// [`keychain-fix-r8c.md`'s C-F8 swap half] mixed-links-only case:
        /// the repoint fails for a reason OTHER than `RepointRefusedRealFile`
        /// (the same `.csq-account`-precondition Corrupt error as (a)), and
        /// this handle dir's OWN `.credentials.json` symlink was ALSO left
        /// pointing somewhere inconsistent (simulating the "non-rolled-back
        /// partial repoint" shape `handle_dir_symlinks_are_consistent`'s own
        /// doc names) — `mixed_links` is true, `refused_item` is `None`.
        /// Prior to C-F8 the mixed-links branch REPLACED `reconcile_line`
        /// with `mixed_links_operator_line`'s wording alone, silently
        /// dropping whatever `reconcile_outcome` said. The fix folds both
        /// in — this test is the regression guard: the final message MUST
        /// carry both the "links are mixed" wording and the reconcile
        /// line's own content, not either in isolation.
        #[test]
        fn t_i_mixed_links_only_folds_in_reconcile_line() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90007, 1);

            // Same repoint-precondition failure as (a) — Corrupt, not
            // RepointRefusedRealFile, so `refused_item` stays `None`.
            std::fs::remove_file(base.path().join("config-2").join(".csq-account")).expect(
                "fixture: remove target .csq-account to force the repoint precondition to fail",
            );

            // Independently leave `.credentials.json` pointing at a target
            // outside the expected set, so
            // `handle_dir_symlinks_are_consistent` returns false regardless
            // of the repoint outcome above.
            let creds_link = handle_dir.join(".credentials.json");
            std::fs::remove_file(&creds_link).expect("fixture: remove real .credentials.json link");
            std::os::unix::fs::symlink(
                base.path().join("config-2").join(".credentials.json"),
                &creds_link,
            )
            .expect("fixture: point .credentials.json at an inconsistent target");

            let (_exec, _guard) = install_executor(RawContentClassification::Absent);

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(result.is_err(), "must still fail the swap: {result:?}");
            let msg = format!("{:#}", result.unwrap_err());
            assert!(
                msg.contains("links are mixed across accounts"),
                "mixed_links must be detected and reported: {msg}"
            );
            assert!(
                msg.contains("not switched") || msg.contains("terminal and keychain"),
                "the reconcile_line's own content must be folded in, not discarded: {msg}"
            );
        }

        /// [`keychain-fix-r8c.md`'s C-F8 swap half] precedence test (i):
        /// `refused_item` (`RepointRefusedRealFile`) and `mixed_links` are
        /// BOTH true simultaneously — a real regular file at
        /// `.credentials.json` trips the S7 pre-flight refusal AND makes
        /// `handle_dir_symlinks_are_consistent` return false (a non-symlink
        /// can never match an expected symlink target). The `if let
        /// Some(item) = refused_item` arm is checked FIRST, so it must win:
        /// `repoint_refused_real_file_operator_line` (which already folds
        /// `reconcile_line` in) is used, never `mixed_links_operator_line`.
        #[test]
        fn t_i_refused_item_takes_precedence_over_mixed_links() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90008, 1);

            // Replace the `.credentials.json` symlink with a REAL regular
            // file: trips repoint_handle_dir's S7 pre-flight guard
            // (`RepointRefusedRealFile { item: ".credentials.json" }`)
            // BEFORE any rename runs, and separately makes
            // `handle_dir_symlinks_are_consistent` return false (its
            // `read_link` on a non-symlink errors, and `.credentials.json`
            // is one of the two `always_created` items).
            let creds_link = handle_dir.join(".credentials.json");
            std::fs::remove_file(&creds_link).expect("fixture: remove real .credentials.json link");
            std::fs::write(&creds_link, b"not a symlink")
                .expect("fixture: write a real file where a symlink belongs");

            let (_exec, _guard) = install_executor(RawContentClassification::Absent);

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(result.is_err(), "must fail the swap: {result:?}");
            let msg = format!("{:#}", result.unwrap_err());
            assert!(
                msg.contains("is a regular file, not a link"),
                "refused_item must win precedence and name the blocking item: {msg}"
            );
            assert!(
                !msg.contains("links are mixed across accounts"),
                "mixed_links_operator_line must NOT be used when refused_item is Some: {msg}"
            );
            assert!(
                msg.contains("not switched") || msg.contains("terminal and keychain"),
                "the refused-item message must still fold in the reconcile line: {msg}"
            );
        }

        /// (b)/(j): repoint succeeds, but the pre-repoint forced write left
        /// X's disk state UNKNOWN (`ForcedSyncResult::WriteFailedUnknown` —
        /// a scripted `add()` failure over KNOWN `Content`, per
        /// `apply_cc_keychain_write`'s S4 branch). The post-repoint
        /// `reconcile_keychain_to_marker` re-reads X (still the STALE
        /// source-account content, since the scripted `find()` result is
        /// static) against the NOW-current marker (the target account,
        /// since the repoint itself succeeded) — they disagree, so the
        /// disposition MUST be a non-zero exit carrying the reconcile line,
        /// never a bare "Swapped".
        ///
        /// This is ALSO the regression test for B2 ("run reconcile on BOTH
        /// outcomes, not only Err"): reverting B2 to "reconcile only on
        /// Err" skips reconcile entirely on this test's `Ok(())` repoint,
        /// so `decide_ok_repoint_disposition` is never consulted and the
        /// bare "Swapped to account 2" message prints — RED quoted below.
        #[test]
        fn t_b_repoint_ok_forced_write_unknown_is_non_zero_never_swapped() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let source_cf = make_creds("at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90001, 1);

            // X currently holds the SOURCE account's own token (a KNOWN,
            // Content classification) — decide_cc_keychain_write reaches
            // apply_cc_keychain_write's write branch, whose scripted add()
            // is set to fail: WriteFailedUnknown, not Unreadable/Absent.
            let (_exec, _guard) = install_scripted(
                ScriptedKeychainExecutor::scripted(RawContentClassification::Content(creds_json(
                    &source_cf,
                )))
                .with_add_failing(),
            );

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(
                result.is_err(),
                "a repoint that succeeds over an unresolved keychain write MUST NOT report success: {result:?}"
            );
            let msg = format!("{:#}", result.unwrap_err());
            assert!(
                !msg.contains("Swapped"),
                "operator message must never claim success when reconcile disagrees: {msg}"
            );
        }

        /// (d): X holds a valid Anthropic identity matching NO known
        /// account (rule 3, `ForeignLoginUnharvested`). The pre-lock
        /// harvest call reaches a REAL fake daemon that reports
        /// `ownership_unknown` — per D5's design this is "not branched on
        /// directly": the disposition comes from decide()'s OWN re-read of
        /// X (still unmatched, since the scripted executor is static), so
        /// the swap refuses with zero keychain mutation regardless of the
        /// harvest outcome. This test's job is to prove the harvest call
        /// actually reaches the daemon (asserted via the join handle) and
        /// that the refusal still holds when it reports the least helpful
        /// outcome, `ownership_unknown`.
        #[test]
        fn t_d_unmatched_token_harvest_ownership_unknown_refuses_no_mutation() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90002, 1);

            let foreign = make_creds("at-FOREIGN", "rt-FOREIGN", FAR_FUTURE_EXPIRY_MS);
            let (exec, _guard) =
                install_executor(RawContentClassification::Content(creds_json(&foreign)));

            let server = spawn_fake_harvest_server(base.path(), "ownership_unknown");

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }
            server.join().expect("fake harvest server thread panicked");

            assert!(
                result.is_err(),
                "an unmatched foreign login MUST refuse the swap: {result:?}"
            );
            let msg = format!("{:#}", result.unwrap_err());
            assert!(
                msg.contains("csq could not identify as this account's own"),
                "refusal must use the fixed ForeignLoginUnharvested message: {msg}"
            );
            assert!(
                exec.calls().iter().all(|(verb, ..)| *verb == "find"),
                "no add/delete call may occur on an unresolved refusal — got {:?}",
                exec.calls()
            );
        }

        /// (e): same unmatched-token scenario as (d), but NO fake harvest
        /// server is running at all — `harvest_account` maps the absent
        /// socket to `HarvestAccountOutcome::Unavailable` without ever
        /// connecting. Per D5's design (the harvest outcome is "not
        /// branched on directly") this produces the IDENTICAL refusal and
        /// message as (d) — there is no separate "background service not
        /// running" wording anywhere in `decide_swap_disposition`; a
        /// grep confirms it (`grep -rn 'background service' csq-core/src
        /// csq/src` — zero hits). This test is the evidence for that
        /// uniformity, not a claim about wording the code does not have
        /// (`doc-property-claims.md`).
        #[test]
        fn t_e_unmatched_token_daemon_unavailable_refuses_same_message_as_ownership_unknown() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90003, 1);

            let foreign = make_creds("at-FOREIGN", "rt-FOREIGN", FAR_FUTURE_EXPIRY_MS);
            let (_exec, _guard) =
                install_executor(RawContentClassification::Content(creds_json(&foreign)));
            // No spawn_fake_harvest_server call: socket absent -> Unavailable.
            assert!(
                !csq_core::daemon::socket_path(base.path()).exists(),
                "fixture sanity: no daemon socket must exist for this scenario"
            );

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(
                result.is_err(),
                "an unmatched foreign login MUST refuse: {result:?}"
            );
            let msg = format!("{:#}", result.unwrap_err());
            assert!(
                msg.contains("csq could not identify as this account's own"),
                "an unreachable daemon must not change the refusal wording: {msg}"
            );
        }

        /// (f): X already holds a KNOWN token (the source account's own —
        /// rule 1, `AlreadyCurrent`/no-op write) and NO daemon is running.
        /// Nothing was ever unmatched, so the harvest call's
        /// `Unavailable` outcome is irrelevant — the swap proceeds to a
        /// successful repoint and a clean reconcile.
        #[test]
        fn t_f_nothing_unmatched_daemon_unavailable_proceeds() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            provision_account(base.path(), 2, "at-2", "rt-2", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90004, 1);

            let source_cf = make_creds("at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            let (_exec, _guard) =
                install_executor(RawContentClassification::Content(creds_json(&source_cf)));

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(
                result.is_ok(),
                "a resolvable keychain state with no daemon MUST proceed: {result:?}"
            );
        }

        /// (g): the TARGET account's own canonical token is expired
        /// (`TargetToken::ExpiredOrInvalid`, `as_valid_str() == None`).
        /// `handle()` MUST refuse BEFORE `force_swap_write_before_repoint`
        /// is ever called — asserted directly via the scripted executor
        /// recording ZERO calls, not inferred from the error message alone.
        #[test]
        fn t_g_target_token_not_valid_refuses_before_any_mutation() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            // Target's own token is EXPIRED.
            provision_account(base.path(), 2, "at-2", "rt-2", PAST_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90005, 1);

            let source_cf = make_creds("at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            let (exec, _guard) =
                install_executor(RawContentClassification::Content(creds_json(&source_cf)));

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(2u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(
                result.is_err(),
                "an expired target token MUST refuse the swap: {result:?}"
            );
            let msg = format!("{:#}", result.unwrap_err());
            assert!(
                msg.contains("has no valid login"),
                "refusal must name the remedy (`csq login N`): {msg}"
            );
            assert!(
                exec.calls().is_empty(),
                "zero keychain calls may occur before the target-Valid check: {:?}",
                exec.calls()
            );
        }

        /// (h): swapping a handle dir to the account it is ALREADY bound
        /// to. X holds that same account's own token by IDENTITY (rule 1,
        /// `AlreadyCurrent`) — the write is a recognized no-op: `add()` is
        /// never called, only `find()`.
        #[test]
        fn t_h_same_account_swap_issues_no_forced_write() {
            let _env_lock = csq_core::platform::test_env::lock();
            let base = tempfile::TempDir::new().unwrap();
            let claude_home = tempfile::TempDir::new().unwrap();
            provision_account(base.path(), 1, "at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            let handle_dir = make_source_handle_dir(base.path(), claude_home.path(), 90006, 1);

            let source_cf = make_creds("at-1", "rt-1", FAR_FUTURE_EXPIRY_MS);
            let (exec, _guard) =
                install_executor(RawContentClassification::Content(creds_json(&source_cf)));

            let saved = std::env::var("CLAUDE_CONFIG_DIR").ok();
            std::env::set_var("CLAUDE_CONFIG_DIR", &handle_dir);
            let result = handle(base.path(), AccountNum::try_from(1u16).unwrap(), true);
            match saved {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }

            assert!(
                result.is_ok(),
                "a same-account swap MUST succeed: {result:?}"
            );
            assert!(
                !exec.calls().iter().any(|(verb, ..)| *verb == "add" || *verb == "delete"),
                "a same-account swap (X already matches by identity) must not mutate the keychain: {:?}",
                exec.calls()
            );
        }
    }
}
