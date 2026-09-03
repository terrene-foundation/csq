//! csq CLI surface.
//!
//! Originally `csq-cli/src/main.rs`, moved here under an internal ticket (single-binary
//! restructure). The unified `csq` binary's `main()` calls `cli::run()` after
//! mode detection determines this is a terminal invocation.

mod audit_emit;
pub(crate) mod commands;
mod log_volume_layer;
mod trace_file;

use crate::daemon_log;
use anyhow::Result;
use clap::{Parser, Subcommand};
use clap_complete::Shell;
use csq_core::capability_layer::log_volume::{self as core_log_volume, CeilingMode};
use csq_core::types::AccountNum;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// User intent for the capability layer (spec 10), derived from the
/// `--capability-layer` / `--no-capability-layer` flag pair at the CLI
/// boundary. Distinct from the internal `LayerControl` enum in
/// `commands::run` (which represents the *outcome* of resolving `.coc/`
/// + running pre-spawn); this represents what the *user asked for*.
///
/// M7 (2026-05-17): the default flipped from opt-in (`AutoDefault`
/// used to mean "off") to auto-engage. `AutoDefault` now means "engage
/// iff a `.coc/` is found by the spec-09 fallback walk"; the pipeline's
/// existing FR-RUN-04 path makes this a ≤5 ms no-op when `.coc/` is
/// absent (spec 10 §10.1.2), so non-COC projects pay an imperceptible
/// cost while COC projects get enforcement automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerIntent {
    /// `--capability-layer` passed: force ON (FR-RUN-04 still no-ops
    /// gracefully if `.coc/` is absent).
    ForcedOn,
    /// `--no-capability-layer` passed: force OFF regardless of `.coc/`.
    ForcedOff,
    /// Neither flag: auto-engage iff `.coc/` is found.
    AutoDefault,
}

impl LayerIntent {
    /// Map the `--capability-layer` / `--no-capability-layer` flag
    /// pair to an intent. clap's `conflicts_with` already rejects
    /// both-true at parse time, so that case is unreachable; we treat
    /// it as `ForcedOff` defensively (force-off is the safe bias).
    pub fn from_flags(capability_layer: bool, no_capability_layer: bool) -> Self {
        if no_capability_layer {
            LayerIntent::ForcedOff
        } else if capability_layer {
            LayerIntent::ForcedOn
        } else {
            LayerIntent::AutoDefault
        }
    }

    /// Whether the pre-spawn pipeline should be allowed to run. Both
    /// `ForcedOn` and `AutoDefault` return `true`; the `.coc/`-absent
    /// case is handled downstream by FR-RUN-04 (a ≤5 ms no-op), not
    /// by suppressing the layer here — that keeps `.coc/` detection in
    /// ONE place (the spec-09 fallback walk) instead of duplicating it
    /// at the CLI boundary.
    pub fn enabled(self) -> bool {
        !matches!(self, LayerIntent::ForcedOff)
    }

    /// Whether this is the no-flag default path (used to decide if the
    /// one-time "layer auto-engaged" stderr note should print).
    pub fn is_auto(self) -> bool {
        matches!(self, LayerIntent::AutoDefault)
    }
}

/// csq — Claude Code multi-account rotation and session management
#[derive(Parser, Debug)]
#[command(name = "csq", version = crate::VERSION_LINE, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Output results as JSON (for scripting/automation)
    #[arg(long, global = true)]
    json: bool,

    /// Write a per-pid trace log file with full unredacted-volume
    /// tracing events (PR-CA11c). Stderr remains count-gated
    /// (default ≤ 10 events / `--debug` ≤ 50). Trace file lives at
    /// `~/.claude/accounts/csq-runs/.trace/<pid>-<ts>.log` (mode 0600,
    /// parent dir 0700). Operator-debugging affordance only — not
    /// performance-tuned for production use.
    #[arg(long, global = true)]
    trace: bool,

    /// Positional account number — shorthand for `csq run <N>`
    #[arg(value_name = "ACCOUNT")]
    account: Option<u16>,

    /// Remaining args passed through to `claude`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    rest: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run claude with an isolated config directory for the given account
    Run {
        /// Account number (1-999)
        account: Option<u16>,
        /// Optional profile (overrides credentials with a provider settings file)
        #[arg(short, long)]
        profile: Option<String>,
        /// Force the capability layer (spec 10) ON for this
        /// invocation, even if no `.coc/` is found (the layer still
        /// no-ops gracefully via FR-RUN-04 if `.coc/` is absent).
        ///
        /// Default behavior (no flag): the layer auto-engages when a
        /// `.coc/` directory is found by the spec-09 fallback walk
        /// from the CWD; in projects with no `.coc/` it is a ≤5 ms
        /// no-op (FR-RUN-04, NFR-COMPAT-02). This flag is only needed
        /// to force the layer ON in a `.coc/`-less tree (rare).
        #[arg(long = "capability-layer", conflicts_with = "no_capability_layer")]
        capability_layer: bool,
        /// Force the capability layer OFF for this invocation,
        /// regardless of `.coc/` presence (FR-CL-05 global opt-out).
        /// Use this in a `.coc/` project where you want bit-for-bit
        /// v2.3.1 behavior for one run. The desktop tray's
        /// `disable_capability_layer` toggle is the durable
        /// equivalent.
        #[arg(long = "no-capability-layer")]
        no_capability_layer: bool,
        /// Surface capability-layer pipeline events as JSONL on stderr.
        /// PR-CA7d1; spec 10 §10.7.4 auditability. Emits one record
        /// per stage: classifier verdict (always when layer is on),
        /// post-validate result (one-shot mode after the spawn). The
        /// harness parses these to score per-turn behavior in live
        /// runs. No-op when `--capability-layer` is OFF or `.coc/`
        /// resolves to fallback.
        #[arg(long = "debug")]
        debug: bool,
        /// Bench-mode flag — terminates after the capability-layer preflight
        /// without spawning the CLI subprocess. Gated behind
        /// `CSQ_BENCH_MODE=1` env var (design 08 §11; R2/B56). NOT part of
        /// the public CLI surface.
        #[arg(long = "bench-mode", value_name = "MODE")]
        bench_mode: Option<String>,
        /// Disable the `.coc/` parse cache, forcing a re-parse every
        /// invocation. Useful for development and reproducing cold-start
        /// latency. Spec 10 §10.9.5. Default is cache-on.
        ///
        /// When the cache is disabled both reads and writes are
        /// suppressed: pre-existing cache files on disk are ignored, and
        /// no new cache file is produced for this invocation. The
        /// capability-layer pipeline emits `STAGE_COC_LOAD_COLD`.
        #[arg(long = "no-coc-cache")]
        no_coc_cache: bool,
        /// Downgrade `Outdated` and `UnrecognizedVersion` probe results
        /// from BAIL to WARN for this invocation. `Missing` and
        /// `WrongBinary` remain unconditional bails — there is nothing to
        /// proceed against. Per spec/13 §3 + §3.1. Per-invocation only;
        /// no env var; no persistent state (an internal journal entry).
        #[arg(long = "ignore-cli-version")]
        ignore_cli_version: bool,
        /// Disable the automatic CLI upgrade that fires when an outdated
        /// binary is detected. By default csq runs
        /// `npm install -g <package>` automatically before bailing, so
        /// the user never has to manually upgrade codex, gemini, or
        /// claude-code. Pass this flag (or set `CSQ_NO_AUTO_UPDATE_CLI=1`)
        /// to revert to the old bail-and-tell behaviour.
        #[arg(long = "no-auto-update-cli")]
        no_auto_update_cli: bool,
        /// Keep this slot's managed CLI at the ABSOLUTE latest release
        /// within its supported major, rather than only guarding the
        /// minimum-version floor. When set, csq attempts an upgrade
        /// (`npm install -g <package>`, range-pinned so never a cross-major
        /// bump) even when the binary already passes the floor — throttled
        /// to at most once per CLI per day so it does not slow every launch.
        /// The once-a-day check may add a brief pause before the CLI starts
        /// (and up to ~2 min if the npm registry is unreachable); it never
        /// blocks the launch — a failed check proceeds with the installed
        /// binary. Suppressed by `--no-auto-update-cli`. Also enabled by
        /// `CSQ_TRACK_LATEST=1`. Default: OFF (the floor guard is the safe
        /// default).
        #[arg(long = "track-latest")]
        track_latest: bool,
        /// Skip writing the audit record for THIS invocation only (M06).
        ///
        /// By default `csq run` writes a tamper-evident audit record for the
        /// launch; if that write fails (disk full, unwritable
        /// `~/.claude/accounts/csq-runs/.pending/`) csq exits non-zero with a
        /// remediation message rather than silently losing the record. Pass
        /// `--no-audit` to launch WITHOUT writing the record for this run —
        /// the run is not blocked, but the event will not appear in your
        /// audit chain. There is NO persistent opt-out; type `--no-audit`
        /// each time you accept the gap (per-invocation acknowledgment keeps
        /// the gap visible).
        #[arg(long = "no-audit")]
        no_audit: bool,
        /// Drive the native governed coding-agent loop (P0-B) against this
        /// slot's 3P provider instead of spawning a CLI. Enterprise-only.
        #[cfg(feature = "native-harness")]
        #[arg(long = "native")]
        native: bool,
        /// Raw model id for `--native` (overrides the catalog default;
        /// CC-only `[...]` annotations are stripped). Enterprise-only.
        #[cfg(feature = "native-harness")]
        #[arg(long = "native-model")]
        native_model: Option<String>,
        /// Governance arm for `--native`: `on` (gated) or `off` (ungoverned).
        /// Defaults to `on`. Enterprise-only.
        #[cfg(feature = "native-harness")]
        #[arg(long = "governance", default_value = "on")]
        governance: String,
        /// Emit only the `native_run_summary` JSON line on stdout (for the
        /// P0-A bench); streamed text goes to stderr. Enterprise-only.
        #[cfg(feature = "native-harness")]
        #[arg(long = "bench-json")]
        bench_json: bool,
        /// Arguments passed through to `claude` (or the `--native` prompt)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },

    /// Swap the active account in the current config dir
    Swap {
        /// Account number to swap to
        account: u16,
        /// Bypass the cross-surface confirmation prompt (INV-P05).
        /// Same-surface swaps never prompt; this flag only affects
        /// the Anthropic ↔ Codex crossing where the conversation
        /// would not transfer.
        #[arg(long)]
        yes: bool,
    },

    /// Show status of all accounts
    Status,

    /// Suggest the best account to switch to (JSON output)
    Suggest,

    /// Show the statusline string (reads CC JSON from stdin)
    Statusline,

    /// Run a single non-interactive completion and print one JSON envelope
    /// (`csq.exec.v1`). Spawn-captures `claude --print --output-format json` for a
    /// Claude slot, normalizes the result, and re-emits it. Every outcome — success
    /// or failure — is a single `\n`-terminated JSON line on stdout; the exit code is
    /// 0 on success, non-zero on failure.
    Exec {
        /// The prompt to send (positional). Mutually exclusive with `--stdin`.
        prompt: Option<String>,
        /// Read the prompt from stdin instead of the positional argument.
        #[arg(long)]
        stdin: bool,
        /// Target a specific slot (1-999). Mutually exclusive with `--provider`.
        #[arg(long)]
        slot: Option<u16>,
        /// Target a provider by name (`claude`); resolves to a healthy slot.
        /// Mutually exclusive with `--slot`.
        #[arg(long)]
        provider: Option<String>,
        /// Model alias or id to request (`opus`, `sonnet`, or a full model id).
        #[arg(long)]
        model: Option<String>,
        /// A system prompt to append (maps to Claude's `--append-system-prompt`).
        #[arg(long)]
        system: Option<String>,
        /// Correlation id echoed back verbatim on the envelope's `id` field.
        #[arg(long)]
        id: Option<String>,
        /// Seconds to wait before killing the child process (default 120).
        #[arg(long = "timeout", default_value_t = 120)]
        timeout: u64,
    },

    /// Run a single governed completion and print one JSON envelope
    /// (`csq.eval.v1`). Validates the response against a JSON Schema, retries
    /// on governance failures, and emits `ok=true` (Passed) or `ok=false`
    /// (MaxRetriesExceeded) — both as DATA envelopes; hard errors emit
    /// `ok=null` failure envelopes. Enterprise-only.
    #[cfg(feature = "enterprise")]
    Eval {
        /// The prompt to send (positional). Mutually exclusive with `--stdin`.
        prompt: Option<String>,
        /// Read the prompt from stdin instead of the positional argument.
        #[arg(long)]
        stdin: bool,
        /// Target a specific slot (1-999). Mutually exclusive with `--provider`.
        #[arg(long)]
        slot: Option<u16>,
        /// Target a provider by name (`claude`); resolves to a healthy slot.
        /// Mutually exclusive with `--slot`.
        #[arg(long)]
        provider: Option<String>,
        /// Model alias or id to request.
        #[arg(long)]
        model: Option<String>,
        /// A system prompt to inject before the user message.
        #[arg(long)]
        system: Option<String>,
        /// Correlation id echoed back verbatim on the envelope's `id` field.
        #[arg(long)]
        id: Option<String>,
        /// Path to the JSON Schema file the response must conform to, or `-`
        /// to read from stdin (mutually exclusive with `--stdin` prompt read).
        #[arg(long = "schema-file")]
        schema_file: String,
        /// Seconds to wait before aborting the governed turn (default 120).
        #[arg(long = "timeout", default_value_t = 120)]
        timeout: u64,
    },

    /// SDK surface introspection (`csq.capabilities.v1`).
    Sdk {
        #[command(subcommand)]
        command: SdkCommands,
    },

    /// Refresh the macOS keychain entries Claude Code reads from csq's
    /// on-disk credentials (fixes "Please run /login · 401" after a token
    /// rotation). `csq run`/`csq swap` do this automatically for the session
    /// they touch; this sweeps every live session.
    #[command(name = "keychain-sync")]
    KeychainSync,

    /// OAuth login flow for a new account
    Login {
        /// Account number to login as
        account: u16,
        /// Which provider to login as. `claude` (default) runs the
        /// Anthropic OAuth flow; `codex` runs the Codex device-auth
        /// flow (spec 07 §7.3.3 — REQUIRES "Device code authorization"
        /// to be ENABLED in your ChatGPT Security Settings before the
        /// device code can be redeemed; if you see "Enable device code
        /// authorization" in the browser, that's the prerequisite);
        /// `gemini` records a Code Assist OAuth binding (an internal journal entry —
        /// gemini-cli v0.41.2+ has no non-interactive auth surface, so
        /// you MUST run `gemini` once interactively first to OAuth
        /// against your Google account; csq then verifies
        /// `~/.gemini/oauth_creds.json` and writes the binding marker).
        /// For Gemini AI Studio API keys or Vertex AI service accounts
        /// (non-OAuth credential paths), use `csq setkey gemini --slot N`
        /// instead. `kimi-cli` / `grok` (an internal journal entry) run the native
        /// vendor CLI's own device-code login (`kimi login` /
        /// `grok login --device-auth`) into a PER-SLOT isolated vendor
        /// home (`native-homes/{kimi,grok}-N/`, via `KIMI_CODE_HOME` /
        /// `GROK_HOME`) — so each slot is an independent vendor account,
        /// like Codex. csq stores no credentials of its own for these; the
        /// vendor CLI owns + self-refreshes its auth inside that per-slot
        /// home. Distinct from the Bearer 3P `kimi` provider
        /// (`csq setkey kimi --slot N`), which runs `claude` against
        /// `ANTHROPIC_BASE_URL=kimi.com`.
        #[arg(long, default_value = "claude", value_parser = ["claude", "codex", "gemini", "kimi-cli", "grok"])]
        provider: String,
        /// No-op alias for the default. Kept so scripts that hard-coded
        /// `--legacy-shell` keep parsing. `csq login` already shells
        /// out to `claude auth login` for the `claude` provider; the
        /// in-process race flow was removed from the CLI because its
        /// IPv4 loopback redirect is rejected by Anthropic for the
        /// Claude Code client_id.
        #[arg(long = "legacy-shell")]
        legacy_shell: bool,
        /// Reset the handle dir for this slot: re-create symlinks and
        /// provider-specific artifacts (Codex config.toml, Gemini
        /// settings.json) to recover from drift without a full logout.
        /// R2/B80. With `--non-interactive`, exits 64 if tokens are
        /// expired (caller must re-login interactively first).
        #[arg(long = "reset-handle-dir")]
        reset_handle_dir: bool,
        /// Non-interactive mode: skip interactive prompts. When combined
        /// with `--reset-handle-dir`, exits 64 if tokens are expired.
        #[arg(long = "non-interactive")]
        non_interactive: bool,
        /// Downgrade `Outdated` and `UnrecognizedVersion` probe results
        /// from BAIL to WARN for this invocation. `Missing` and
        /// `WrongBinary` remain unconditional bails — there is nothing to
        /// proceed against. Per spec/13 §3 + §3.1. Per-invocation only;
        /// no env var; no persistent state (an internal journal entry).
        #[arg(long = "ignore-cli-version")]
        ignore_cli_version: bool,
        /// Disable the automatic CLI upgrade that fires when an outdated
        /// binary is detected. By default csq runs
        /// `npm install -g <package>` automatically before bailing. Pass
        /// this flag (or set `CSQ_NO_AUTO_UPDATE_CLI=1`) to revert to
        /// the old bail-and-tell behaviour.
        #[arg(long = "no-auto-update-cli")]
        no_auto_update_cli: bool,
        /// Keep the managed CLI at the ABSOLUTE latest release within its
        /// supported major during the login pre-flight, rather than only
        /// guarding the minimum-version floor. Range-pinned (never a
        /// cross-major bump); throttled to once per CLI per day; never blocks
        /// the login. Suppressed by `--no-auto-update-cli`. Also enabled by
        /// `CSQ_TRACK_LATEST=1`. Default: OFF.
        #[arg(long = "track-latest")]
        track_latest: bool,
        /// Emit the an internal ticket fail-fast pre-flight refusal as a `csq.login.v1`
        /// JSON envelope on stdout instead of plain text, when this
        /// provider's login flow needs an attended session (TTY/browser)
        /// and none is present. Does not change the human-facing text
        /// output of a login flow that proceeds normally.
        #[arg(long = "json")]
        json: bool,
    },

    /// Remove an account: deletes credentials, config dir, and profile entry.
    /// Refuses if a live `claude` process is still bound to the account.
    #[command(alias = "remove")]
    Logout {
        /// Account number to log out
        account: u16,
        /// Skip the interactive confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Release a stuck login lock for a slot. If a `csq login N` hung (e.g.
    /// its OAuth browser callback never completed), it holds `.login-N.lock`
    /// and blocks every re-auth attempt (CLI and desktop). This shows what is
    /// holding the lock, terminates the stuck login, and clears the lock so
    /// you can retry.
    Unlock {
        /// Account/slot number whose login lock to release
        account: u16,
        /// Skip the interactive confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Move an account from one slot number to another. Renames the
    /// config dir, canonical credential files, profiles entry, and
    /// quota entry. Refuses if a live `claude` process is bound to the
    /// source slot or the target slot is already configured.
    #[command(alias = "rename")]
    Move {
        /// Source slot number (must be configured)
        from: u16,
        /// Target slot number (must be unused)
        to: u16,
        /// Skip the interactive confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Provider key management
    #[command(subcommand)]
    Setkey(SetkeyCmd),

    /// List configured provider keys
    Listkeys,

    /// Remove a provider key
    Rmkey {
        /// Provider ID (mm, zai, etc.)
        provider: String,
    },

    /// Model catalog operations
    Models {
        #[command(subcommand)]
        action: Option<ModelsCmd>,
    },

    /// Install csq into ~/.claude (creates dirs, patches settings.json)
    Install,

    /// Run diagnostics and report system health
    Doctor {
        /// Restrict the report to a single account slot. The output
        /// shape changes from the system-level health report to a
        /// compact per-slot report
        /// (`{status, quota: {utilization}, credentials: {present, expired}}`).
        ///
        /// Used by the `coc-eval/scripts/record_baselines.sh` doctor
        /// pre-flight (R2/B78). When omitted, the existing system
        /// report is returned unchanged.
        #[arg(long, value_name = "N")]
        slot: Option<u16>,

        /// One-shot legacy → identity credentials migration. For every
        /// UUID-mapped slot in `profiles.json::by_slot` whose
        /// `identities/<UUID>/credentials.json` / `settings.json` /
        /// `credentials-codex.json` is missing AND whose legacy source
        /// (`credentials/<N>.json` / `config-<N>/settings.json` /
        /// `credentials/codex-<N>.json`) exists, byte-copies the
        /// legacy file into the identity path. Operator entry point
        /// for the v2.7.3 → v2.7.7+ upgrade-skip class documented in
        /// an internal journal entry
        ///
        /// Idempotent — already-seeded identity files are reported as
        /// `AlreadySeeded` and skipped. When the daemon is running, the
        /// same migration runs automatically inside `phase4_gate_check`;
        /// this flag is for operators who hit the gate refusal AND
        /// cannot or do not want to start the daemon.
        ///
        /// Mutually exclusive with `--slot`.
        #[arg(long, conflicts_with = "slot")]
        repair_identities: bool,

        /// Detect cross-slot OAuth token contamination (an internal ticket). For every
        /// Anthropic slot, verifies — via one live `GET /api/oauth/profile` with
        /// the slot's STORE token — that the token actually belongs to the
        /// account bound to that slot (its `identity.json` anchor). A slot whose
        /// store token belongs to a DIFFERENT account shows the right label but
        /// polls a foreign account's quota; heal with `csq login <N>`.
        ///
        /// Opt-in because it makes one network call per Anthropic slot. Requires
        /// a JS runtime (Node/Bun) for the Cloudflare-safe transport. Read-only.
        #[arg(long, conflicts_with = "slot")]
        check_token_owners: bool,
    },

    /// Live-wire `(provider × auth-mode)` contract verification per
    /// `specs/11-probe-driven-verification.md`. Operator-only — MUST
    /// NOT run in CI.
    Probe {
        /// Probe a single slot. Mutually exclusive with `--all`.
        #[arg(value_name = "SLOT", conflicts_with = "all")]
        slot: Option<u16>,
        /// Probe every provisioned slot.
        #[arg(long, conflicts_with = "slot")]
        all: bool,
    },

    /// Background daemon lifecycle (start/stop/status)
    Daemon {
        #[command(subcommand)]
        action: DaemonCmd,
    },

    /// Check for newer csq releases on GitHub
    Update {
        #[command(subcommand)]
        action: UpdateCmd,
    },

    /// Repair credential + slot-attribution inconsistencies
    ///
    /// Detects (and with `--apply` repairs): cross-slot refresh-token
    /// contamination, stale `config-N/.current-account` caches that make
    /// `csq swap` show the wrong slot, and orphaned `by_slot` entries for
    /// repurposed slots. Without `--apply` it is a dry run. Aliased as
    /// `repair-credentials` for back-compat.
    #[command(visible_alias = "repair-credentials")]
    Repair {
        /// Actually apply repairs (delete contaminated canonical files,
        /// rewrite drifted caches, prune orphaned mappings). Off by
        /// default (dry run).
        #[arg(long)]
        apply: bool,
        /// Also check each Anthropic slot's STORE token against
        /// `/api/oauth/profile` and, with `--apply`, clear any whose token
        /// belongs to a DIFFERENT account (an internal ticket cross-slot scramble).
        /// Network + opt-in: off by default so the offline passes stay fast.
        #[arg(long)]
        heal_contaminated: bool,
    },

    /// Generate shell completions for bash, zsh, fish, or powershell
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },

    /// Inspect csq's view of the project tree (read-only diagnostics)
    Inspect {
        #[command(subcommand)]
        target: InspectCmd,
    },

    /// Translate the project's `.coc/` set into the deterministic spawn-time
    /// payload for a target Surface (read-only; writes nothing under `.coc/`).
    ///
    /// This is the top-level, contract-stable conversion surface the neutral
    /// `coc-run` launcher and harnesses drive. It mirrors `csq inspect
    /// translate` but is promoted out of the `inspect` diagnostic namespace and
    /// accepts the `cc` alias for `claude-code` (the `--surface cc|codex|gemini`
    /// spelling established by `csq classify`, spec-10 §10.7.4.1). `--json`
    /// emits the full `SpawnPayload`.
    ///
    /// `kimi` and `grok` are accepted too: each native surface has its OWN
    /// translator (workspace hermes-parity an internal journal entry supersedes journal
    /// 0133's Codex-aliasing) — `--surface kimi` emits `SpawnPayload::Kimi`
    /// and `--surface grok` emits `SpawnPayload::Grok`, distinct shapes from
    /// `--surface codex`'s `SpawnPayload::Codex`.
    Translate {
        /// Which Surface translator to invoke. Accepts `cc` (alias of
        /// `claude-code`), `claude-code`, `codex`, `gemini`, `kimi`, or
        /// `grok` — each with its own translator (see above).
        #[arg(long = "surface", value_parser = ["cc", "claude-code", "codex", "gemini", "kimi", "grok"])]
        surface: String,
        /// Start the discovery walk from this path instead of CWD.
        #[arg(long)]
        start: Option<std::path::PathBuf>,
    },

    /// Manage external CLI dependencies (claude, codex, gemini, kimi, grok).
    ///
    /// Fully implemented since v2.7.0 (M4 PR-MCD4): `csq cli install <name>`
    /// and `csq cli upgrade <name>` dispatch to the real probe +
    /// package-manager flow in `cli/commands/cli.rs`. See spec/13 §6
    /// (dispatch table).
    Cli {
        #[command(subcommand)]
        command: CliCommand,
    },

    /// Audit-trail key-custody operations (M04 an internal workspace).
    ///
    /// Manages the local Ed25519 signing key used to sign audit records.
    /// All keychain access goes through the `keyring` crate
    /// (`csq-audit-signing` service, macOS Keychain / Linux Secret Service /
    /// Windows Credential Manager).
    Audit {
        #[command(subcommand)]
        command: AuditCmd,
    },

    /// Classify a prompt against the active `.coc/` set (PR-CA7d1).
    ///
    /// Pure classifier path — loads `.coc/`, builds the keyword index
    /// for the requested Surface, and emits a JSON record with
    /// `{class, confidence, threshold, low_confidence,
    /// in_scope_rule_ids}`. No CC / codex / gemini spawn.
    ///
    /// Used by the `coc-eval/suites/classifier.py` harness to score
    /// 100 fixtures (50 free-form + 50 compliance) against the
    /// precision/recall thresholds in spec 10 §10.7.3.
    Classify {
        /// Prompt text to classify (required).
        #[arg(long)]
        prompt: String,
        /// Surface filter for the keyword index. Defaults to
        /// `claude-code`. Accepts `cc` as an alias. Ignored when
        /// `--keywords` is supplied — the explicit set is already
        /// filter-resolved.
        #[arg(long, default_value = "claude-code")]
        surface: String,
        /// Start the discovery walk from this path instead of CWD.
        /// Ignored when `--keywords` is supplied.
        #[arg(long)]
        start: Option<std::path::PathBuf>,
        /// Comma-separated keyword list. Bypasses `.coc/` loading
        /// entirely — the harness supplies an explicit compliance
        /// vocabulary. Used by `coc-eval/suites/classifier.py` to
        /// score 100 fixtures. Each token is lowercased + trimmed;
        /// the harness is responsible for length and prefix filtering.
        #[arg(long)]
        keywords: Option<String>,
    },

    /// Run the OQ-1 Tier-0 content pre-filter against a prompt (OQ1-S5,
    /// enterprise-only).
    ///
    /// Pure classifier path — runs the production
    /// `csq_core::phase2b::oq1::prefilter_advisory` deterministic keyword
    /// pre-filter and emits a JSON record `{ok, categories, tier, is_finding}`
    /// where `categories` is the fixed GDPR Art.9/Art.10 vocabulary. No CC /
    /// codex / gemini spawn, no API call, no signed-chain write. The prompt is
    /// classified and dropped — never echoed (INV-1). Used by the
    /// `coc-eval/suites/oq1_special_category.py` harness to score recall/FPR of
    /// special-category detection against synthetic labelled fixtures.
    #[cfg(feature = "enterprise")]
    #[command(name = "oq1-classify")]
    Oq1Classify {
        /// Prompt text to classify (required). Read, classified, and dropped;
        /// never echoed to stdout (INV-1 — no special-category content leaves
        /// the classifier).
        #[arg(long)]
        prompt: String,
    },

    /// M-DEK org-root key-hierarchy administration (enterprise-only).
    ///
    /// Establishes the per-seat key hierarchy M7's 4-eyes gate depends on: an
    /// org KEK (from a ≥2-participant ceremony) wraps independently-generated
    /// seat DEKs for recovery. See `specs/26-per-seat-key-hierarchy.md`.
    #[cfg(feature = "enterprise")]
    Admin {
        #[command(subcommand)]
        command: AdminCmd,
    },

    /// Gate an MCP server's stdio JSON-RPC through the PACT `mcp_verdict`
    /// allow-path (M6 T6.2 Shard 2, enterprise-only).
    ///
    /// Interposes on a CLI↔MCP-server channel: spawns the real server given
    /// after `--`, forwards its traffic, and denies `tools/call`s the operator's
    /// `mcp` policy does not clear (never-delegated actions require human review;
    /// unlisted tools are default-denied). Denials are answered in-band
    /// (`isError:true` result) so the channel is never torn down. With no
    /// `--envelope`, every tool call is denied (default-deny). Shard 3 wires this
    /// into `csq run` codex/gemini spawns; run it standalone to gate any MCP server.
    #[cfg(feature = "enterprise")]
    #[command(name = "mcp-proxy")]
    McpProxy {
        /// Path to the PACT operating envelope JSON whose `mcp.allowed_tools`
        /// policy clears tool calls. Loaded fail-closed (a malformed or
        /// wrong-version envelope refuses to start). Absent → default-deny.
        #[arg(long)]
        envelope: Option<std::path::PathBuf>,
        /// The spawned CLI whose MCP traffic this proxy gates (`codex` | `gemini`).
        /// Set by the `csq run` config-rewrite (Shard 3a) so each gate decision is
        /// attested to the right surface. Absent on a standalone invocation → gate
        /// decisions are still enforced but NOT attested to the audit chain (no CLI
        /// identity to attribute them to).
        #[arg(long, value_parser = ["codex", "gemini"])]
        cli: Option<String>,
        /// The real MCP server command to launch and proxy, given after `--`
        /// (e.g. `-- npx -y @modelcontextprotocol/server-filesystem /tmp`).
        #[arg(last = true, required = true, allow_hyphen_values = true)]
        server_cmd: Vec<String>,
    },
}

/// Subcommands for `csq sdk` — SDK surface introspection.
#[derive(Subcommand, Debug)]
pub enum SdkCommands {
    /// Print the `csq.capabilities.v1` envelope: the ops this build implements + edition.
    Capabilities,
}

/// Subcommands for `csq cli` — external CLI dependency management.
///
/// Per spec/13 §10: the `<name>` allowlist (`claude | codex | gemini | kimi |
/// grok`) is enforced at the clap layer via `value_parser`. Any other input is
/// rejected before the handler is called. This mirrors the precedent at line
/// 154 (`csq login --provider`) and line 348 (`csq inspect translate <surface>`).
///
/// For the npm/brew session surfaces `install` and `upgrade` run the full
/// dispatch (npm/brew spawn, consent gate, re-probe) — shipped in M4 PR-MCD4.
/// For the self-managed CLIs (kimi/grok) `install` prints the vendor
/// `install.sh` hint (no curl-bash auto-exec) and `upgrade` runs the CLI's own
/// update subcommand.
#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Install the named CLI via the user's package manager (npm, brew).
    ///
    /// Requires interactive consent ([y/N]). Non-TTY refusal enforced.
    /// Range-pinned semver (`@>=<floor> <next-major>`, NOT `@latest`).
    /// EACCES non-escalation: csq does NOT invoke sudo.
    Install {
        /// CLI name to install. Allowed: claude, codex, gemini, kimi, grok.
        #[arg(value_parser = ["claude", "codex", "gemini", "kimi", "grok"])]
        name: String,
    },
    /// Upgrade the named CLI to the latest version within csq's supported
    /// range. Requires interactive consent ([y/N]). Non-TTY refusal enforced.
    Upgrade {
        /// CLI name to upgrade. Allowed: claude, codex, gemini, kimi, grok.
        #[arg(value_parser = ["claude", "codex", "gemini", "kimi", "grok"])]
        name: String,
    },
}

/// Subcommands for `csq admin` — M-DEK org-root key-hierarchy operations
/// (enterprise-only; the whole surface + its `admin` module are moat-stripped).
#[cfg(feature = "enterprise")]
#[derive(Subcommand, Debug)]
enum AdminCmd {
    /// Run the org-root ceremony: derive the org KEK from ≥2 distinct
    /// participants' entropy shares and emit a signed `OrgRootCeremony` record.
    ///
    /// For each `--participant`, paste their own 64-hex entropy share when
    /// prompted, or press Enter to generate one (displayed ONCE — record it
    /// offline; the org KEK is re-derivable only from all recorded shares).
    /// Requires `csq audit init` first (so the ceremony record is signed).
    #[command(name = "init-org")]
    InitOrg {
        /// The org id (path-safe: `[A-Za-z0-9._-]`, ≤64 chars).
        #[arg(long, value_name = "ORG_ID")]
        org_id: String,
        /// A participant's `person_id`. Repeat for each contributor; ≥2 DISTINCT
        /// participants are required (a solo org KEK makes M7's 4-eyes gate
        /// cosmetic).
        #[arg(long = "participant", value_name = "PERSON_ID", required = true)]
        participants: Vec<String>,
        /// Intentionally rotate an EXISTING org's KEK. Without this, init-org
        /// refuses to overwrite an existing org KEK (doing so would orphan every
        /// provisioned seat's recovery envelope).
        #[arg(long)]
        rotate: bool,
    },

    /// Provision a seat: mint its independent DEK, wrap it under the org KEK
    /// (recovery envelope on disk), and store the unwrapped seed in the seat
    /// keychain. Requires the org KEK (`init-org`) to exist first.
    #[command(name = "provision-seat")]
    ProvisionSeat {
        /// The org whose KEK wraps this seat's recovery envelope.
        #[arg(long, value_name = "ORG_ID")]
        org_id: String,
        /// The seat id (path-safe: `[A-Za-z0-9._-]`, ≤64 chars).
        #[arg(long, value_name = "SEAT_ID")]
        seat_id: String,
        /// Intentionally re-provision an EXISTING seat (mints a NEW signing
        /// identity). Without this, provision-seat refuses to overwrite.
        #[arg(long)]
        force: bool,
    },

    /// Export a seat's recovery package: re-encrypt its org-KEK-wrapped envelope
    /// under a recovery authority's key for out-of-band custody.
    #[command(name = "export-seat-recovery")]
    ExportSeatRecovery {
        /// The seat whose recovery envelope to export.
        #[arg(long, value_name = "SEAT_ID")]
        seat_id: String,
        /// Path to the recovery authority's 32-byte key as 64-hex (0o600-enforced).
        #[arg(long, value_name = "PATH")]
        recovery_key: std::path::PathBuf,
        /// Where to write the encrypted recovery package.
        #[arg(long, value_name = "PATH")]
        out: std::path::PathBuf,
    },

    /// Rotate (reanchor) a seat's DEK: supersede its current signing
    /// identity with a freshly generated one, recording the succession
    /// endorsement on the audit chain (M-DEK T-DEK.4). Requires the seat to
    /// already be provisioned (`provision-seat`) and the org KEK to exist
    /// (`init-org`). Refuses when a prior rotation attempt left an
    /// unresolved retry hazard (`csq admin doctor-seat` diagnoses it).
    #[command(name = "rotate-seat")]
    RotateSeat {
        /// The org whose KEK wraps this seat's recovery envelope.
        #[arg(long, value_name = "ORG_ID")]
        org_id: String,
        /// The seat id to rotate (path-safe: `[A-Za-z0-9._-]`, ≤64 chars).
        #[arg(long, value_name = "SEAT_ID")]
        seat_id: String,
        /// Reason for the rotation. Defaults to `operator`.
        /// Valid values: `operator`, `policy`, `compromised`, `scheduled`.
        #[arg(long, value_name = "REASON")]
        reason: Option<String>,
    },

    /// Report a seat's `.persist-broken` sentinel state — set when a prior
    /// rotation's rollback could not restore the outgoing envelope
    /// byte-identical after a keychain-write failure. Read-only diagnostic;
    /// a SET sentinel does not brick the seat — a normal retry of
    /// `provision-seat --force` / `rotate-seat` resolves it and clears the
    /// sentinel automatically.
    #[command(name = "doctor-seat")]
    DoctorSeat {
        /// The seat id to inspect.
        #[arg(long, value_name = "SEAT_ID")]
        seat_id: String,
    },

    /// Resume an interrupted seat rotation: resolve the orphan `SeatKeyReanchor`
    /// audit INTENT a prior `rotate-seat` left when its OUTCOME record was lost
    /// to a crash / kill (the retry hazard `doctor-seat` diagnoses and
    /// `rotate-seat` refuses over). Reads the seat's LIVE keychain key to PROVE
    /// what happened, then writes the completing OUTCOME — `Ok` when the
    /// rotation had committed, `Failed` (freeing the seat to rotate again) when
    /// it had not. Idempotent; refuses (fail-closed) when it cannot prove the
    /// outcome. Requires `csq audit init`.
    #[command(name = "resume-seat-rotation")]
    ResumeSeatRotation {
        /// The seat id whose interrupted rotation to resume.
        #[arg(long, value_name = "SEAT_ID")]
        seat_id: String,
    },
}

/// Subcommands for `csq audit` — M04 + M05 key-custody and chain-verification operations.
#[derive(Subcommand, Debug)]
enum AuditCmd {
    /// Idempotent signing-key initialisation.
    ///
    /// Generates an Ed25519 keypair, stores the private key in the OS keychain
    /// under the `csq-audit-signing` service, and writes `signing_key_id` +
    /// `pubkey` into `chain.json`. Safe to call multiple times — exits 0 with
    /// "already present" when a key is already in the keychain.
    Init,

    /// Rotate the signing key.
    ///
    /// Generates a fresh Ed25519 keypair, archives the outgoing key in the
    /// keychain under its `KeyId` account (for historical-record verification),
    /// and writes the signed `KeyRotate` audit record as JSON to stdout.
    /// The caller is responsible for appending it to the ledger (M05 wires
    /// this).
    RotateKey {
        /// Reason for the rotation. Defaults to `operator`.
        /// Valid values: `operator`, `policy`, `compromised`, `scheduled`.
        #[arg(long, value_name = "REASON")]
        reason: Option<String>,
    },

    /// Get or set the active audit sink (M07).
    ///
    /// `csq audit config sink get` — print the current sink name (default: "none").
    /// `csq audit config sink set <name>` — activate a sink by name.
    ///   Valid names: none, rekor, s3, azure, gcp, csq-ledger.
    ///   Fails loud when the sink was not compiled into this binary.
    ConfigSink {
        /// Sink name to activate. Omit to read the current value.
        #[arg(value_name = "NAME")]
        name: Option<String>,
    },

    /// Get or set the per-sink replication cadence (M07).
    ///
    /// `csq audit config cadence <sink> <key> <value>`
    ///   key: cadence | cadence-high-impact | fail-loud
    ///   value examples: "1d", "6h", "immediate", "true", "false"
    ConfigCadence {
        /// Sink name (e.g. "rekor", "s3").
        sink: String,
        /// Cadence key: cadence | cadence-high-impact | fail-loud.
        key: String,
        /// Value to set (e.g. "1d", "immediate").
        value: String,
    },

    /// Verify the audit chain integrity (M05).
    ///
    /// Walks the on-disk JSONL chain and checks hash-chain links, seq
    /// monotonicity, chain_id consistency, and Ed25519 signatures.
    ///
    /// Exit codes:
    ///   0 — clean (all verified records passed)
    ///   1 — integrity failure (ChainBroken or InvalidSignature)
    ///   2 — partial (signing key not found for historical records)
    Verify {
        /// Verify the entire chain (all records). Without this flag,
        /// only the last 1,000 records are verified (tail mode).
        #[arg(long)]
        full: bool,

        /// Only verify records with `ts` >= this ISO-8601 timestamp.
        /// Example: `--since 2026-05-01T00:00:00Z`.
        #[arg(long, value_name = "TIMESTAMP")]
        since: Option<String>,

        /// Output results as machine-parseable JSON.
        /// Shape: `{status, verified_count, skipped_v1_count, failure_detail?}`.
        #[arg(long)]
        json: bool,

        /// Look up a specific record by its record-id and include its
        /// `VerificationLevel` as `record_verification_level` in the JSON output.
        /// Only meaningful with `--json`. Returns `"NOT_FOUND"` when the id is absent.
        #[arg(long, value_name = "RECORD_ID")]
        record: Option<String>,
    },

    /// Migrate audit signing keys from the OS keychain into the file store.
    ///
    /// Run this INTERACTIVELY (a terminal where you can grant the one-time
    /// macOS keychain prompt) to copy the active + historical signing seeds into
    /// the 0o600 file store at `csq-runs/keys/`, so the NON-INTERACTIVE daemon
    /// can read them without a prompt. This is the recovery path when
    /// `csq doctor` reports the signing key as "inaccessible". Idempotent and
    /// additive — keychain entries are NOT deleted (they remain the integrity
    /// anchor).
    MigrateKeys,

    /// Diagnose and (optionally) repair the audit chain.
    ///
    /// Without `--apply`: report the chain's health. If the signing key is
    /// merely inaccessible, recommends `csq audit migrate-keys` (NOT a reset).
    /// If the chain is genuinely broken, reports what `--apply` would reset.
    ///
    /// With `--apply`: clears a stale `.chain-broken` sentinel when the chain
    /// now verifies, or backs up the broken chain to
    /// `csq-runs-broken-backup-<ts>/` and resets it so a fresh `csq audit init`
    /// starts clean. The file-store keys are preserved.
    Repair {
        /// Apply the repair (reset a broken chain, with backup). Without this
        /// flag, `repair` is a read-only diagnosis.
        #[arg(long)]
        apply: bool,
    },

    /// Declare or clear **attestation intent** (M6 an internal ticket shard C).
    ///
    /// Controls whether gated MCP decisions made BEFORE `csq audit init` are
    /// preserved or dropped. On a host where you intend to keep the signed audit
    /// record, run `csq audit intent on` during setup (before wiring the gate):
    /// pre-init decisions then QUEUE to the durable outbox and flush automatically
    /// once you run `csq audit init`, instead of being dropped. Default (unset) is
    /// drop — so a non-audit host never accumulates a queue.
    ///
    /// `csq audit intent`        — print the current state (on/off) + any queued count.
    /// `csq audit intent on`     — declare intent (idempotent).
    /// `csq audit intent off`    — clear intent; pre-init decisions drop again.
    ///
    /// Intent is NOT cleared by `csq audit init` — it survives a later chain
    /// reset/re-init (`csq audit repair --apply`) so the re-init window is covered
    /// too. Clear it explicitly when you no longer want attestation on this host.
    Intent {
        /// `on` to declare intent, `off` to clear it. Omit to print the state.
        #[arg(value_name = "STATE")]
        state: Option<String>,
    },

    /// Export the audit chain as a self-contained, verifiable bundle (M09).
    ///
    /// Produces `csq-audit-bundle-<chain_id>-<exp_id>.tar` containing the
    /// chain, every signing key referenced, the key-rotation history, embedded
    /// canonical-form golden vectors, a SHA-256 lock, an Ed25519 signature over
    /// the lock by the chain's genesis-anchored key, and a self-contained
    /// `verify` script.
    ///
    /// An external auditor — with NO csq install — extracts the bundle and runs
    /// `./verify` (Python 3 standard library only; no `cryptography` PyPI
    /// package and no `openssl` CLI — Ed25519 is verified in pure Python) to
    /// get a PASS / FAIL verdict. The script
    /// reproduces every check: BUNDLE.sig over BUNDLE.lock, per-file SHA-256,
    /// per-record canonical_hash + Ed25519 signature, prev_hash chain links,
    /// and rotation-chain anchoring. `./verify --rekor <url>` additionally runs
    /// a best-effort Rekor entry-EXISTENCE check for records that carry a
    /// `rekor_log_index` (it confirms the named Rekor entry references the
    /// record's canonical_hash). This is NOT a cryptographic Merkle
    /// inclusion-proof verification — real inclusion-proof verification against
    /// a signed tree head is Phase B (spec 16 §16.7). Without `--rekor`, local
    /// verification still PASSes with a WARN that the Rekor check was skipped.
    ///
    /// Trust caveat: the bundle is self-attesting. A PASS confirms internal
    /// integrity but NOT provenance — the auditor MUST confirm the genesis
    /// public key out-of-band before trusting a PASS (the verify script prints
    /// this NOTE on every PASS).
    ///
    /// A pre-flight `verify` runs before packaging — csq refuses to export a
    /// chain that does not verify locally.
    Export {
        /// ISO-8601 lower bound (accepted for CLI-surface stability; the bundle
        /// currently always exports the whole local chain — partial-range
        /// export is a future addition, mirroring `verify --since`).
        #[arg(long, value_name = "TIMESTAMP")]
        since: Option<String>,

        /// ISO-8601 upper bound (accepted for CLI-surface stability; see
        /// `--since`).
        #[arg(long, value_name = "TIMESTAMP")]
        until: Option<String>,

        /// Output path for the bundle. Defaults to
        /// `csq-audit-bundle-<chain_id>-<exp_id>.tar` in the current
        /// working directory.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,
    },

    /// Enroll a developer principal for per-developer identity resolution (M17).
    ///
    /// Generates an Ed25519 keypair for the principal, stores the private key in
    /// the OS keychain under `csq-dev-signing-<principal>`, and writes the public
    /// key to `<base>/audit/dev-enrollment.json`. Requires interactive
    /// confirmation (human-present gate — CRITICAL-2).
    ///
    /// Granularity defaults to `accountable-principal` (works-council-safe).
    /// Use `--granularity per-individual` only after explicit works-council opt-in
    /// for deployments where BetrVG §87(1)6 or equivalent monitoring-regulation
    /// law applies.
    EnrollDev {
        /// Principal to enroll (1..=128 chars, `[A-Za-z0-9._@-]`).
        /// Examples: "backend-team@rrps.example", "alice@example.com".
        principal: String,

        /// Attribution granularity.
        /// Valid values: `accountable-principal` (default), `per-individual`.
        #[arg(long, value_name = "GRANULARITY")]
        granularity: Option<String>,
    },

    /// Resolve a developer principal and print Verified or Unbacked (M17).
    ///
    /// Operator smoke test: prints `Verified` when the principal is enrolled
    /// and the private key is accessible in the OS keychain, or `Unbacked`
    /// when it is not. Does not sign anything.
    ProveDev {
        /// Principal to resolve.
        principal: String,
    },

    /// Install a signed authority roster (M12).
    ///
    /// Loads the roster from a JSON file, verifies its Ed25519 signature
    /// against the configured root pubkey, pins `roster_activation_seq` in
    /// `chain.json`, and bumps `roster_version_floor`. After installation,
    /// records with `seq >= roster_activation_seq` on guarded op-classes
    /// (KeyRotate, IdentityMint, ReleaseAuth) will have their signer pubkeys
    /// membership-checked against the roster.
    ///
    /// Requires `CSQ_AUDIT_ROSTER_ROOT_PUBKEY` (hex 32 bytes) or a
    /// `<base>/audit/roster-root.pub` file to be present.
    RosterInstall {
        /// Path to the signed roster JSON file.
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// Override the computed activation seq (default: chain tail seq + 1).
        ///
        /// By default, `roster install` computes the chain's current tail seq
        /// and sets `roster_activation_seq = tail_seq + 1`, which grandfathers
        /// all existing records (they are pre-activation). Use this flag to set
        /// a specific activation seq — useful in scripts or when you want
        /// membership enforcement to start at a specific future seq.
        ///
        /// Setting this to 0 means ALL records (including pre-existing ones) are
        /// subject to membership checking. Use with caution on a live chain.
        #[arg(long, value_name = "SEQ")]
        activation_seq: Option<u64>,
    },

    /// Show the active authority roster summary (M12).
    ///
    /// Prints the enrolled principals, op-class grants, root pubkey
    /// fingerprint, and activation seq. Works in both community (no roster)
    /// and enterprise (roster required) editions.
    RosterShow,

    /// Generate an Ed25519 org-root keypair for roster signing (an internal ticket).
    ///
    /// Writes `roster-root.sec` (the SECRET seed, mode 0600 — keep offline,
    /// never commit) and `roster-root.pub` (the PUBLIC trust anchor, mode 0600)
    /// and prints the public key as hex. The public key is the value for
    /// `CSQ_AUDIT_ROSTER_ROOT_PUBKEY`. The secret is NEVER printed.
    RosterKeygen {
        /// Output directory. Defaults to `<base>/audit/`.
        #[arg(long, value_name = "DIR")]
        out: Option<std::path::PathBuf>,
        /// Overwrite an existing keypair (invalidates rosters signed with the old key).
        #[arg(long)]
        force: bool,
    },

    /// Author an UNSIGNED authority roster (an internal ticket).
    ///
    /// Builds a roster enrolling one principal for one op-class with one key
    /// and writes it as unsigned JSON (the input to `roster-sign`). The
    /// `roster_pubkey` anchor is taken from `CSQ_AUDIT_ROSTER_ROOT_PUBKEY` or
    /// the `roster-root.pub` file.
    RosterCreate {
        /// Principal (email/identity) to enroll.
        #[arg(long, value_name = "EMAIL")]
        principal: String,
        /// Op-class: `key_rotate`, `identity_mint`, or `release_auth`.
        #[arg(long, value_name = "OP_CLASS")]
        op_class: String,
        /// The enrolled member's Ed25519 public key (64 hex chars).
        #[arg(long, value_name = "HEX")]
        pubkey: String,
        /// Roster version (monotonic; defaults to 1).
        #[arg(long, value_name = "N")]
        roster_version: Option<u64>,
        /// Output file. Defaults to `<base>/audit/authority-roster.unsigned.json`.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
    },

    /// Sign an unsigned roster with the org-root secret key (an internal ticket).
    ///
    /// Reads the unsigned roster as raw bytes, signs, THEN writes
    /// (byte-preserving). Default emits the embedded `SignedRoster` form;
    /// `--detached` emits the roster verbatim plus a `.sig` sidecar. The output
    /// verifies with `roster-install`.
    RosterSign {
        /// Path to the unsigned roster JSON file.
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// Path to the org-root secret key file (raw 32-byte seed, mode 0600).
        #[arg(long, value_name = "PATH")]
        secret_key: Option<std::path::PathBuf>,
        /// The org-root secret key as 64 hex chars (alternative to --secret-key).
        /// WARNING: a hex value passed on the command line enters process argv
        /// (`/proc/<pid>/cmdline`) and shell history — high-security operators should
        /// prefer `--secret-key <file>` (0600-checked, never in argv).
        #[arg(long, value_name = "HEX")]
        secret_key_hex: Option<String>,
        /// Emit the detached-signature form (roster + `.sig` sidecar).
        #[arg(long)]
        detached: bool,
        /// Output file. Defaults to the canonical audit-dir roster path.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
    },

    /// Rotate keys in a roster, emitting a new UNSIGNED roster (an internal ticket).
    ///
    /// Reads an existing roster (signed or unsigned), adds and/or retires keys,
    /// and writes a new unsigned roster to re-sign. `--bump-version` increments
    /// `roster_version` (monotonic); retired keys keep a `retired_at_seq`.
    RosterRotate {
        /// Source roster (signed or unsigned).
        #[arg(long, value_name = "FILE")]
        from: std::path::PathBuf,
        /// Add a key: `<email>:<pubkey-hex>`.
        #[arg(long, value_name = "EMAIL:HEX")]
        add_key: Option<String>,
        /// Retire a key: `<email>:<pubkey-hex>`.
        #[arg(long, value_name = "EMAIL:HEX")]
        retire_key: Option<String>,
        /// Increment `roster_version` by 1.
        #[arg(long)]
        bump_version: bool,
        /// Output file. Defaults to `<base>/audit/authority-roster.rotated.json`.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
    },

    /// Install a signed governance policy bundle (Phase-2b, b2a — enterprise-only).
    ///
    /// Loads the policy bundle from a JSON file, verifies its Ed25519 detached
    /// signature against the operator-supplied trusted pubkey (`--pubkey`), persists
    /// the bundle + sidecar, and bumps the `policy-bundle.floor` rollback floor.
    /// Verification runs BEFORE any write (CRIT-2: install returns Err ⇒ on-disk
    /// state unchanged).
    ///
    /// The `--pubkey` argument is the OUT-OF-BAND root of trust: the customer org-admin
    /// Ed25519 public key (32 bytes, 64 lowercase hex chars). It MUST be supplied via a
    /// separate channel — NEVER extracted from the bundle itself (which would make the
    /// signature check tautological).
    ///
    /// Requires the daemon to be stopped first (`csq daemon stop`); restart after
    /// install to activate the new policy (`csq daemon start`).
    #[cfg(feature = "enterprise")]
    BundleInstall {
        /// Path to the signed policy bundle JSON file.
        /// A detached signature sidecar at `<file>.sig` must be present alongside it.
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// The customer org-admin Ed25519 public key (32 bytes, 64 lowercase hex chars).
        /// This is the out-of-band root of trust for the bundle signature.
        #[arg(long, value_name = "PUBKEY_HEX")]
        pubkey: String,
    },

    /// Generate an Ed25519 org-admin keypair for policy-bundle signing (an internal ticket, FR-GOV).
    ///
    /// Writes `bundle-signing.sec` (the SECRET seed, mode 0600 — keep offline,
    /// never commit) and `bundle-signing.pub` (the PUBLIC out-of-band trust anchor,
    /// mode 0600) and prints the public key as hex. The public key is the value for
    /// `csq audit bundle-install --pubkey <hex>`. The secret is NEVER printed.
    #[cfg(feature = "enterprise")]
    BundleKeygen {
        /// Output directory. Defaults to `<base>/phase2b/`.
        #[arg(long, value_name = "DIR")]
        out: Option<std::path::PathBuf>,
        /// Overwrite an existing keypair (invalidates bundles signed with the old key).
        #[arg(long)]
        force: bool,
    },

    /// Author an UNSIGNED policy bundle from a schemas file (an internal ticket, FR-GOV).
    ///
    /// Builds a policy bundle carrying the supplied `response_format` schemas and
    /// the `GovernanceConfig` (from `--config <file>`, or the public-law safe default),
    /// anchored to the org-admin `--pubkey`, and writes it as unsigned JSON (the input
    /// to `bundle-sign`).
    #[cfg(feature = "enterprise")]
    BundleCreate {
        /// JSON object mapping schema-name → JSON-Schema value (the enforced schemas).
        #[arg(long, value_name = "FILE")]
        schemas: std::path::PathBuf,
        /// GovernanceConfig JSON file. If omitted, the public-law safe default is used.
        #[arg(long, value_name = "FILE")]
        config: Option<std::path::PathBuf>,
        /// The customer org-admin Ed25519 public key (64 hex chars) — the trust anchor.
        #[arg(long, value_name = "PUBKEY_HEX")]
        pubkey: String,
        /// Monotonic bundle version (rollback floor; defaults to 1).
        #[arg(long, value_name = "N")]
        bundle_version: Option<u64>,
        /// Output file. Defaults to `<base>/phase2b/policy-bundle.unsigned.json`.
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
    },

    /// Sign an unsigned policy bundle with the org-admin secret key (an internal ticket, FR-GOV).
    ///
    /// Reads the unsigned bundle as raw bytes, signs the RAW bytes (byte-preserving),
    /// and writes the bundle verbatim plus a `.sig` sidecar (the detached form
    /// `bundle-install` accepts). The signer's public key must equal the file's
    /// `bundle_pubkey` anchor.
    #[cfg(feature = "enterprise")]
    BundleSign {
        /// Path to the unsigned policy bundle JSON file.
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// Path to the org-admin secret key file (raw 32-byte seed, mode 0600).
        #[arg(long, value_name = "PATH")]
        secret_key: Option<std::path::PathBuf>,
        /// The org-admin secret key as 64 hex chars (alternative to --secret-key).
        /// WARNING: a hex value passed on the command line enters process argv
        /// (`/proc/<pid>/cmdline`) and shell history — high-security operators should
        /// prefer `--secret-key <file>` (0600-checked, never in argv).
        #[arg(long, value_name = "HEX")]
        secret_key_hex: Option<String>,
        /// Output file. Defaults to the canonical live bundle path (+ `.sig` sidecar).
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
    },

    /// Validate a signed policy bundle against a pubkey (an internal ticket, FR-GOV).
    ///
    /// Read-only round-trip check: verifies the detached Ed25519 signature against
    /// the supplied `--pubkey` and runs the non-configurable governance floor.
    /// Answers "would `bundle-install --pubkey <hex>` accept this?" without any
    /// install, write, or daemon interaction.
    #[cfg(feature = "enterprise")]
    BundleValidate {
        /// Path to the signed policy bundle JSON file (with a sibling `.sig` sidecar).
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// The customer org-admin Ed25519 public key (32 bytes, 64 lowercase hex chars).
        #[arg(long, value_name = "PUBKEY_HEX")]
        pubkey: String,
    },

    /// Compliance report — model-residency enforcement summary (M5).
    ///
    /// Reads the signed audit chain and reports, per session, which providers
    /// were used, their data-residency region, the residency policy that applied,
    /// and each request's verdict (pass / block), plus whole-store counts and
    /// whether any blocked request was overridden. Residency enforcement is an
    /// enterprise feature; the community build reports that it is unavailable.
    Report {
        /// Output the residency summary as machine-parseable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Plain-language compliance report — auditor-readable evidence (FR-GOV).
    ///
    /// Renders the signed audit chain into a human-readable document distinguishing
    /// governed decisions (pass / block / override-with-justification, residency
    /// verdicts) from lifecycle operations, grounded in the verified canonical
    /// records — never re-deriving facts, only presenting verified ones. The
    /// header states the chain's verification verdict so the document is honest
    /// about whether the facts come from a chain that verified end-to-end.
    /// Governed decisions are produced by the enterprise Phase-2b interactive
    /// enforcement session; a community-edition chain carries only the lifecycle
    /// section.
    ComplianceReport {
        /// Output format for the report document.
        #[arg(long, value_enum, default_value_t = ReportFormat::Md)]
        format: ReportFormat,

        /// Write the report to this file instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,
    },

    /// Submit an audit anchor request to the daemon and print the
    /// `AnchorPayload` projection as JSON (enterprise-only, an internal ticket S3).
    ///
    /// POSTs the current audit record to the daemon's
    /// `POST /api/audit/anchor` route.  The daemon signs the record
    /// using the chain's Ed25519 key and returns the signed
    /// `AnchorPayload` projection — containing the daemon-assigned
    /// `canonical_hash`, `chain_id`, `seq`, and `verification_level`.
    ///
    /// The CLI NEVER computes `canonical_hash` client-side; the daemon
    /// is the sole signer (DIRECTIVE-1 from an internal ticket).
    #[cfg(feature = "enterprise")]
    Anchor {
        /// Output the anchor result as machine-parseable JSON.
        /// Shape: `{canonical_hash, chain_id, seq, verification_level}`.
        #[arg(long)]
        json: bool,
    },
}

/// Render format for `csq audit compliance-report`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum ReportFormat {
    /// Markdown (default) — portable, diff-able, greppable.
    Md,
    /// Self-contained HTML document.
    Html,
}

#[derive(Subcommand, Debug)]
enum InspectCmd {
    /// Show the resolved `.coc/` set csq sees for this working tree.
    /// Walks from the current directory upward looking for `.coc/`,
    /// falls through to the legacy chain (`.claude/` → `.gemini/` →
    /// `AGENTS.md`) per spec 09 §9.3, and prints what loaded.
    Coc {
        /// Implies `--show-unknowns` and includes the artifact body.
        #[arg(long)]
        debug: bool,
        /// Surface forward-compat fields csq does not yet understand.
        #[arg(long = "show-unknowns")]
        show_unknowns: bool,
        /// Start the discovery walk from this path instead of CWD.
        #[arg(long)]
        start: Option<std::path::PathBuf>,
    },

    /// Show what the per-Surface translator emits for this `.coc/` set.
    /// Output is the deterministic spawn-time payload (per spec 09
    /// FR-DISP-* family). Used by harness fixtures + cross-process
    /// determinism tests. Accepts `kimi`/`grok` — each has its own
    /// translator (see the top-level `csq translate` doc comment).
    Translate {
        /// Which Surface translator to invoke. Accepts the `cc` alias for
        /// `claude-code` (consistent with the top-level `csq translate`).
        #[arg(value_parser = ["cc", "claude-code", "codex", "gemini", "kimi", "grok"])]
        surface: String,
        /// Start the discovery walk from this path instead of CWD.
        #[arg(long)]
        start: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum UpdateCmd {
    /// Query GitHub Releases and compare to the current version.
    /// Prints a one-line notice if a newer release is available.
    Check,
    /// Download, verify (SHA256 + Ed25519), and atomically replace the
    /// current binary with the latest GitHub Release for this platform.
    Install,
}

#[derive(Subcommand, Debug)]
enum DaemonCmd {
    /// Start the daemon (foreground by default; use -d to background)
    Start {
        /// Detach and run in the background (re-execs the binary without this flag)
        #[arg(short = 'd', long = "background")]
        background: bool,

        /// Run under the in-process supervisor loop (crash-restart + backoff +
        /// PidFile cohabitation). Set by the launchd-managed plist installed by
        /// the desktop app / `csq daemon install` (daemon-auth-resilience Wave B);
        /// not intended for direct interactive use. Hidden from `--help`.
        #[arg(long = "supervised", hide = true, conflicts_with = "background")]
        supervised: bool,

        /// Maximum number of audit chain records to verify at daemon start
        /// (M05). Records beyond this limit produce an `audit_verify_limit_exceeded`
        /// WARN and are not verified. Default: 10,000.
        #[arg(long = "audit-verify-limit", value_name = "N")]
        audit_verify_limit: Option<usize>,
    },
    /// Stop the running daemon via SIGTERM
    Stop,
    /// Show the daemon's status (running / stale / not running)
    Status,
    /// Install csq as a platform service (launchd on macOS, systemd on Linux)
    Install,
    /// Uninstall the platform service installed by `csq daemon install`
    Uninstall,
}

#[derive(Subcommand, Debug)]
enum SetkeyCmd {
    /// MiniMax API key
    Mm {
        #[arg(long)]
        key: Option<String>,
        /// Bind the key to slot N (e.g. `--slot 9`). If omitted, the key
        /// is only stored in the global settings-mm.json.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Z.AI API key
    Zai {
        #[arg(long)]
        key: Option<String>,
        /// Bind the key to slot N (e.g. `--slot 10`). If omitted, the key
        /// is only stored in the global settings-zai.json.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// DeepSeek API key (Anthropic-API-compatible bridge at
    /// `https://api.deepseek.com/anthropic`)
    Deepseek {
        #[arg(long)]
        key: Option<String>,
        /// Bind the key to slot N. If omitted, the key is only stored
        /// in the global settings-deepseek.json.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Kimi coding-subscription API key (`sk-kimi-…`, Anthropic-API-compatible
    /// endpoint at `https://api.kimi.com/coding`)
    Kimi {
        #[arg(long)]
        key: Option<String>,
        /// Bind the key to slot N. If omitted, the key is only stored
        /// in the global settings-kimi.json.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Claude API key (for non-OAuth flows), OR — with `--backend` — provision a
    /// slot to route Anthropic Claude through Google Vertex AI / AWS Bedrock (an internal ticket).
    Claude {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        slot: Option<u16>,
        /// Cloud-Claude routing backend: `vertex` (Google Vertex AI) or `bedrock`
        /// (AWS Bedrock). Enterprise-only. Requires `--slot`, `--region`, and —
        /// for vertex — `--project` + `--sa-file`; for bedrock the bearer token is
        /// read from stdin. Fail-closed-refused on an OAuth/Codex/Gemini/3P slot.
        #[cfg(feature = "enterprise")]
        #[arg(long, requires_all = ["slot", "region"])]
        backend: Option<String>,
        /// GCP project id (vertex backend). DNS-label-validated. Requires `--backend`.
        #[cfg(feature = "enterprise")]
        #[arg(long, requires = "backend")]
        project: Option<String>,
        /// GCP/AWS region (e.g. `us-east5` / `us-east-1`). DNS-label-validated.
        /// Requires `--backend` (a region is only meaningful for cloud routing).
        #[cfg(feature = "enterprise")]
        #[arg(long, requires = "backend")]
        region: Option<String>,
        /// Path to the GCP service-account JSON (vertex backend). Validated:
        /// regular non-symlink file ≤ 64 KiB, canonicalised. Requires `--backend`.
        #[cfg(feature = "enterprise")]
        #[arg(long, requires = "backend")]
        sa_file: Option<String>,
        /// Pin the model this cloud slot uses, written as `ANTHROPIC_MODEL`
        /// into the slot's settings (e.g. `claude-opus-4-6@default`). Without
        /// it CC picks its own default, which may be a model the project has
        /// no quota for — CC retries that 429 silently, so the slot appears to
        /// hang. Requires `--backend`.
        #[cfg(feature = "enterprise")]
        #[arg(long, requires = "backend")]
        model: Option<String>,
    },
    /// Ollama profile (keyless — creates the settings file with defaults)
    Ollama {
        /// Bind the Ollama profile to slot N (e.g. `--slot 9`). If
        /// omitted, only the global `settings-ollama.json` is written.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Gemini (AI Studio API key OR Vertex SA JSON path)
    ///
    /// The `--key` flag is intentionally absent per FR-G-CLI-03:
    /// Gemini API keys are read from stdin only so they cannot
    /// leak into process argv or shell history. Pipe the key, or
    /// run `csq setkey gemini --slot N` interactively and paste
    /// at the prompt.
    Gemini {
        /// Bind to slot N. Mandatory — Gemini lives per-slot;
        /// there is no global `settings-gemini.json`.
        #[arg(long)]
        slot: u16,
        /// Provision in Vertex AI mode by pointing at the SA JSON
        /// file path. When set, no API-key prompt is shown.
        /// Mutually exclusive with the AI Studio paste flow.
        #[arg(long)]
        vertex_sa_json: Option<std::path::PathBuf>,
    },
    /// Azure OpenAI (an internal ticket) — direct-API native client (OpenAI Chat
    /// Completions wire, `api-key` header). Config lives in the global
    /// `settings-azure.json`; the key is read from stdin (hidden/piped)
    /// so it never enters argv or shell history.
    ///
    /// Enterprise-only: the native client lives in the moat-stripped
    /// `phase2b` tree, so this variant is `#[cfg(feature = "enterprise")]` —
    /// the community CLI does not expose (or accept) it.
    #[cfg(feature = "enterprise")]
    Azure {
        /// Azure resource name — the `{resource}` in
        /// `https://{resource}.openai.azure.com`. Required.
        #[arg(long)]
        resource: String,
        /// Deployment name — the `{deployment}` path segment. Optional;
        /// when omitted the per-request model override (or the catalog
        /// default) is used.
        #[arg(long)]
        deployment: Option<String>,
        /// `api-version` query parameter. Optional; a stable GA default
        /// is written when omitted.
        #[arg(long)]
        api_version: Option<String>,
        /// The Azure OpenAI api-key. If omitted, read from stdin
        /// (hidden on a TTY, piped otherwise).
        #[arg(long)]
        key: Option<String>,
    },
    /// GCP Vertex AI (an internal ticket) — direct-API native client (Google
    /// generateContent wire, Bearer access-token). Config lives in the
    /// global `settings-vertex.json`; the access token is read from stdin
    /// (hidden/piped) so it never enters argv or shell history.
    ///
    /// Enterprise-only: the native client lives in the moat-stripped
    /// `phase2b` tree, so this variant is `#[cfg(feature = "enterprise")]` —
    /// the community CLI does not expose (or accept) it.
    #[cfg(feature = "enterprise")]
    Vertex {
        /// GCP project id — the `{project}` path segment. Required.
        #[arg(long)]
        project: String,
        /// GCP region — the host prefix AND `locations/{region}` path
        /// segment (e.g. `us-central1`). Required.
        #[arg(long)]
        region: String,
        /// The Vertex access token (gcloud ADC / service-account). If
        /// omitted, read from stdin (hidden on a TTY, piped otherwise).
        #[arg(long)]
        access_token: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ModelsCmd {
    /// List all models, or filter by provider
    List {
        /// Provider ID or "all"
        #[arg(default_value = "all")]
        provider: String,
    },
    /// Switch the active model for a provider
    Switch {
        /// Provider ID (claude, mm, zai, deepseek, ollama, codex)
        provider: String,
        /// Model ID or alias
        model: String,
        /// Retarget a slot's `config-N/settings.json` (ClaudeCode) or
        /// `config-N/config.toml` (Codex) instead of the global
        /// profile file. Required for Codex — the model lives on
        /// a per-slot config.toml and there is no global profile.
        #[arg(long)]
        slot: Option<u16>,
        /// For keyless providers (Ollama): when the chosen model
        /// isn't in `ollama list`, run `ollama pull <model>`
        /// before writing. Default: on. Pass `--no-pull` to
        /// refuse the network fetch (e.g. writing a model id
        /// for a machine you'll `ollama pull` on later).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        pull_if_missing: bool,
        /// For catalog-less providers (Codex): accept a model id
        /// that isn't in csq's curated catalog. csq doesn't
        /// validate the id against your ChatGPT subscription —
        /// passing a model your plan doesn't include will surface
        /// as a runtime codex-cli error on first call. FR-CLI-04.
        #[arg(long)]
        force: bool,
    },
}

/// Enforce the enterprise license gate before an enterprise-only op (W4, journal
/// 0004). Inert while the license key is the seed-2 placeholder
/// (`csq_core::license::is_placeholder_key`); once the real Foundation license key
/// is baked, a missing / invalid / expired license surfaces here as a
/// `license_required` error instead of running the op.
///
/// Call sites: the enterprise CLI admin arms (`mcp-proxy`, `audit bundle-install`) AND
/// the enterprise CLI moat entrypoints (`emit_eatp_genesis` for `audit init`,
/// `report_residency` for `audit report`) — gating at the moat entrypoint covers the op
/// regardless of the caller. As of task #77 shard 3, **`csq run`
/// (`commands::run::handle`) is ALSO gated** with this full per-op `enforce`. The task #77
/// gate-coverage remediation extends the same gate to the remaining LLM-execution surfaces
/// that had slipped it — **`csq run --native`** (`commands::run::handle_native`, dispatched
/// via an early `return` before `handle`) and **`csq exec`**
/// (`commands::exec::run_exec`, via an enveloped `SdkError`) — plus the enterprise-only
/// **`audit verify` trust-plane grade** (suppressed when unlicensed so the wire matches
/// community). Shared read-only surfaces (`audit compliance-report`, `audit export`) are
/// deliberately left ungated: they render the already-local signed chain, leak no
/// enterprise-only value, and are a maintainer moat-policy choice, not a fail-open.
///
/// The daemon-hosted governance / audit / EATP stack — brought up by `csq daemon start`
/// (`commands::daemon::handle_start`) and the desktop supervisor
/// (`desktop::daemon_supervisor::run_daemon`) — is gated with the sibling
/// [`enforce_enterprise_license_startup`] (validity + definitive revocation, but NO
/// liveness deny, so a licensed-but-offline daemon can still start to run the CRL
/// refresher that recovers its cache — see that fn's docs).
///
/// The gate is INERT today (seed-2 placeholder key), so no enterprise op runs differently
/// until the real key is baked at go-live.
#[cfg(feature = "enterprise")]
pub(crate) fn enforce_enterprise_license(base_dir: &std::path::Path) -> anyhow::Result<()> {
    let now = license_now_fail_closed()?;
    // Soft enforcement (an internal ticket): the gate verdict is unchanged (fail-closed on any
    // missing/invalid/expired/revoked license); on success we additionally surface an
    // approaching-expiry renewal nudge to STDERR — never stdout, so JSON envelopes on
    // the per-op surfaces stay clean.
    let advisory = csq_core::license::enforce_returning_advisory(base_dir, now)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.message.as_str()))?;
    if let Some(a) = advisory {
        eprintln!("csq: license notice — {}", a.message);
    }
    Ok(())
}

/// Read the wall clock as unix seconds, failing CLOSED on a broken clock. If the clock
/// is before the UNIX epoch (dead RTC, VM snapshot reset), `duration_since` errors — the
/// old `unwrap_or(0)` substituted `now = 0`, which is fail-OPEN for a security gate:
/// expiry (`0 > exp` is never true) and grace (`0.saturating_sub(..) == 0 <= grace`) both
/// pass unconditionally, so a revoked/expired licensee could evade the gate by setting
/// their clock to before 1970. A gate that cannot trust the clock cannot validate the
/// license, so it MUST deny. (Redteam R1 — security + deep-analyst.)
#[cfg(feature = "enterprise")]
fn license_now_fail_closed() -> anyhow::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| {
            anyhow::anyhow!(
                "license_required: system clock is invalid (before the UNIX epoch) — \
                 cannot validate the enterprise license"
            )
        })
}

/// Startup variant of [`enforce_enterprise_license`] for DAEMON bring-up (task #77 shard
/// 3). Verifies the license is present, signature-valid, unexpired, and not DEFINITIVELY
/// revoked — but skips the CRL liveness/staleness deny, because the daemon HOSTS the CRL
/// refresher: a stale-beyond-grace cache is exactly the state it must start in to
/// re-fetch and recover. Using the full [`enforce_enterprise_license`] here would brick a
/// licensed customer offline longer than the grace window in a fail-closed deadlock (they
/// could never start the daemon that would refresh their CRL). See
/// [`csq_core::license::enforce_startup`]. Inert while the placeholder key is baked.
#[cfg(feature = "enterprise")]
pub(crate) fn enforce_enterprise_license_startup(base_dir: &std::path::Path) -> anyhow::Result<()> {
    let now = license_now_fail_closed()?;
    csq_core::license::enforce_startup(base_dir, now)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.message.as_str()))
}

/// Event-ceiling mode for the tracing stderr layer, by command.
///
/// The ceiling bounds a single one-shot command's stderr volume (NFR-OBS-01).
/// `csq daemon` is a long-lived process, NOT one-shot: applying the one-shot
/// ceiling silences the refresher's warn/error trail after ~10 events for the
/// daemon's entire multi-day lifetime, which hid a ~3.5-day silent token-
/// refresh outage on disk (2026-07-24 mass-expiry incident). The daemon logs
/// unbounded; `csq run --debug` keeps its higher debug ceiling; everything
/// else keeps the default.
fn ceiling_mode_for(command: &Command) -> CeilingMode {
    if matches!(command, Command::Run { debug: true, .. }) {
        CeilingMode::Debug
    } else if matches!(command, Command::Daemon { .. }) {
        CeilingMode::Unbounded
    } else {
        CeilingMode::Default
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    // No subcommand: default to `run` (optionally with positional account)
    let command = cli.command.unwrap_or(Command::Run {
        account: cli.account,
        profile: None,
        capability_layer: false,
        no_capability_layer: false,
        debug: false,
        bench_mode: None,
        no_coc_cache: false,
        ignore_cli_version: false,
        no_auto_update_cli: false,
        track_latest: false,
        no_audit: false,
        #[cfg(feature = "native-harness")]
        native: false,
        #[cfg(feature = "native-harness")]
        native_model: None,
        #[cfg(feature = "native-harness")]
        governance: "on".to_string(),
        #[cfg(feature = "native-harness")]
        bench_json: false,
        rest: cli.rest,
    });

    let json = cli.json;
    let base_dir = commands::base_dir()?;

    // Tracing-subscriber init (PR-CA11c T5+T6).
    //
    // Layer chain:
    //   Registry
    //     ↳ LogVolumeFilter (count-gated stderr; default 10 / debug 50 events)
    //     ↳ fmt::Layer     (writes the gated subset to stderr)
    //     ↳ TraceFileLayer (when --trace; unbounded; per-pid file under
    //                       the trace dir computed by trace_file::trace_log_path)
    //
    // The count-gated and trace-file Layers are independent — `--trace`
    // never lifts the stderr ceiling. See an internal journal entry (Q4 resolution).
    let ceiling_mode = ceiling_mode_for(&command);
    core_log_volume::reset_event_counter();
    let env_filter = EnvFilter::try_from_env("CSQ_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_filter(log_volume_layer::LogVolumeFilter::new(ceiling_mode));
    let trace_layer = if cli.trace {
        match trace_file::TraceFileLayer::open(&base_dir) {
            Ok(layer) => Some(layer),
            Err(e) => {
                let path = trace_file::trace_log_path(&base_dir);
                eprintln!(
                    "csq: warning — could not open trace log at {}: {e}",
                    path.display()
                );
                None
            }
        }
    } else {
        None
    };
    // #1a-2 (daemon-auth-resilience Wave A2) — `csq daemon` gets a
    // persistent rolling-file log layer in addition to the stderr layer
    // above. A long-lived daemon's stderr is easy to lose (Finder-launched
    // `.app`, closed terminal, a redirected-then-truncated file); the
    // rolling file survives the daemon's whole lifetime and is GC'd on a
    // 14-day retention by `csq_core::daemon::log_gc`. Non-fatal:
    // `make_writer` returns `None` on a directory-create failure and the
    // daemon still runs with only the stderr layer.
    let (daemon_file_layer, daemon_log_guard) = if matches!(command, Command::Daemon { .. }) {
        match daemon_log::make_writer(&base_dir) {
            Some((nb, guard)) => (
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(nb),
                ),
                Some(guard),
            ),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    tracing_subscriber::registry()
        .with(env_filter)
        .with(stderr_layer)
        .with(trace_layer)
        .with(daemon_file_layer)
        .init();
    if let Some(g) = daemon_log_guard {
        daemon_log::store_guard(g);
    }

    // Spawn a background thread to check for updates on every command run
    // except `csq update` itself. The thread checks at most once per 24 hours
    // (cached) and prints a one-line notice if a newer version is available.
    // It never blocks or delays the main command.
    match &command {
        Command::Update { .. } => {} // skip: user is already in the update flow
        // `statusline` runs on EVERY prompt render in EVERY terminal — the hot
        // path. Spawning an update-check thread (+ a cache stat, + a possible
        // GitHub request when the 24h cache lapses) there is both wasteful and
        // the trigger that, combined with the now-fixed cache-on-failure bug,
        // hammered GitHub's 60/hour unauthenticated limit. Update notices still
        // surface on every other command (`run`, `swap`, `login`, …) and via
        // the desktop app's own periodic check.
        Command::Statusline => {}
        // Edition independence (rules/independence.md): the background notice
        // reads the COMMUNITY latest.json and nudges toward `csq update install`
        // — itself disabled in enterprise. An enterprise binary must not query
        // the community channel or advise a community "upgrade" (mirrors the
        // check()/install() + desktop community_auto_update_enabled gates).
        _ if crate::BUILD_EDITION == "enterprise" => {}
        _ => csq_core::update::auto_update_bg(base_dir.clone()),
    }

    match command {
        Command::Run {
            account,
            profile,
            capability_layer,
            no_capability_layer,
            debug,
            bench_mode,
            no_coc_cache,
            ignore_cli_version,
            no_auto_update_cli,
            track_latest,
            no_audit,
            #[cfg(feature = "native-harness")]
            native,
            #[cfg(feature = "native-harness")]
            native_model,
            #[cfg(feature = "native-harness")]
            governance,
            #[cfg(feature = "native-harness")]
            bench_json,
            rest,
        } => {
            let account_num = match account {
                Some(n) => Some(
                    AccountNum::try_from(n).map_err(|e| anyhow::anyhow!("invalid account: {e}"))?,
                ),
                None => None,
            };
            // Native governed loop dispatch (P0-B) — enterprise-only; routes
            // before the CLI-spawn surface logic.
            #[cfg(feature = "native-harness")]
            if native {
                return commands::run::handle_native(
                    &base_dir,
                    account_num,
                    native_model.as_deref(),
                    &governance,
                    bench_json,
                    &rest,
                );
            }
            // M7 (2026-05-17): default flipped from opt-in to
            // auto-engage. Explicit flags still win; the no-flag
            // path is now `AutoDefault` (engage iff `.coc/` found —
            // FR-RUN-04 no-ops at ≤5 ms when absent).
            let layer_intent = LayerIntent::from_flags(capability_layer, no_capability_layer);
            // Cache is on by default; `--no-coc-cache` suppresses both
            // reads and writes (spec 10 §10.9.5).
            let coc_cache_enabled = !no_coc_cache;
            commands::run::handle(
                &base_dir,
                account_num,
                profile.as_deref(),
                layer_intent,
                debug,
                bench_mode.as_deref(),
                coc_cache_enabled,
                ignore_cli_version,
                no_auto_update_cli,
                track_latest,
                no_audit,
                &rest,
            )
        }
        Command::Swap { account, yes } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::swap::handle(&base_dir, account_num, yes)
        }
        Command::Status => commands::status::handle(&base_dir, json),
        Command::Suggest => commands::suggest::handle(&base_dir),
        Command::Statusline => commands::statusline::handle(&base_dir),
        Command::Exec {
            prompt,
            stdin,
            slot,
            provider,
            model,
            system,
            id,
            timeout,
        } => {
            let claude_home = commands::claude_home()?;
            commands::exec::handle(
                &base_dir,
                &claude_home,
                commands::exec::ExecArgs {
                    prompt,
                    stdin,
                    provider,
                    slot,
                    model,
                    system,
                    id,
                    timeout_secs: timeout,
                },
            )
        }
        #[cfg(feature = "enterprise")]
        Command::Eval {
            prompt,
            stdin,
            slot,
            provider,
            model,
            system,
            id,
            schema_file,
            timeout,
        } => commands::eval::handle(
            &base_dir,
            commands::eval::EvalArgs {
                prompt,
                stdin,
                slot,
                provider,
                model,
                system,
                id,
                schema_file,
                timeout_secs: timeout,
            },
        ),
        Command::Sdk { command } => match command {
            SdkCommands::Capabilities => commands::exec::handle_capabilities(),
        },
        Command::KeychainSync => commands::keychain_sync::handle(&base_dir),
        Command::Login {
            account,
            provider,
            legacy_shell,
            reset_handle_dir,
            non_interactive,
            ignore_cli_version,
            no_auto_update_cli,
            track_latest,
            json,
        } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::login::handle(
                &base_dir,
                account_num,
                &provider,
                legacy_shell,
                reset_handle_dir,
                non_interactive,
                ignore_cli_version,
                no_auto_update_cli,
                track_latest,
                json,
            )
        }
        Command::Logout { account, yes } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::logout::handle(&base_dir, account_num, yes)
        }
        Command::Unlock { account, yes } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::unlock::handle(&base_dir, account_num, yes)
        }
        Command::Move { from, to, yes } => {
            let from_num = AccountNum::try_from(from)
                .map_err(|e| anyhow::anyhow!("invalid FROM slot: {e}"))?;
            let to_num =
                AccountNum::try_from(to).map_err(|e| anyhow::anyhow!("invalid TO slot: {e}"))?;
            commands::move_slot::handle(&base_dir, from_num, to_num, yes)
        }
        Command::Setkey(sk) => {
            // Gemini's setkey contract is distinct enough (no
            // --key, mandatory --slot, optional --vertex-sa-json)
            // that it dispatches through its own handler — see
            // FR-G-CLI-01..03.
            if let SetkeyCmd::Gemini {
                slot,
                vertex_sa_json,
            } = sk
            {
                let slot_num = AccountNum::try_from(slot)
                    .map_err(|e| anyhow::anyhow!("invalid --slot: {e}"))?;
                return commands::setkey::handle_gemini(
                    &base_dir,
                    slot_num,
                    vertex_sa_json.as_deref(),
                );
            }
            // Azure OpenAI / Vertex AI (an internal ticket) — multi-field direct-API config
            // (endpoint coordinates + credential) that does not fit the single
            // `{key, slot}` shape. They persist to the GLOBAL settings file
            // (`settings-azure.json` / `settings-vertex.json`), which the native
            // client reads at request time; there is no per-slot ANTHROPIC_*
            // passthrough bind. Enterprise-only (the native client is in the
            // moat-stripped `phase2b` tree).
            #[cfg(feature = "enterprise")]
            if let SetkeyCmd::Azure {
                resource,
                deployment,
                api_version,
                key,
            } = &sk
            {
                return commands::setkey::handle_azure(
                    &base_dir,
                    resource,
                    deployment.as_deref(),
                    api_version.as_deref(),
                    key.as_deref(),
                );
            }
            #[cfg(feature = "enterprise")]
            if let SetkeyCmd::Vertex {
                project,
                region,
                access_token,
            } = &sk
            {
                return commands::setkey::handle_vertex(
                    &base_dir,
                    project,
                    region,
                    access_token.as_deref(),
                );
            }
            // Cloud-Claude routing (an internal ticket): `setkey claude --backend vertex|bedrock`
            // provisions a per-slot ClaudeCode binding routed through Vertex/Bedrock.
            // Distinct from the direct-API-key path below (which has no `--backend`).
            #[cfg(feature = "enterprise")]
            if let SetkeyCmd::Claude {
                backend: Some(backend),
                slot,
                project,
                region,
                sa_file,
                model,
                key,
            } = &sk
            {
                return commands::setkey::handle_cloud_claude(
                    &base_dir,
                    backend,
                    *slot,
                    project.as_deref(),
                    region.as_deref(),
                    sa_file.as_deref(),
                    model.as_deref(),
                    key.as_deref(),
                );
            }
            let (provider, key, slot) = match sk {
                SetkeyCmd::Mm { key, slot } => ("mm", key, slot),
                SetkeyCmd::Zai { key, slot } => ("zai", key, slot),
                SetkeyCmd::Deepseek { key, slot } => ("deepseek", key, slot),
                SetkeyCmd::Kimi { key, slot } => ("kimi", key, slot),
                SetkeyCmd::Claude { key, slot, .. } => ("claude", key, slot),
                SetkeyCmd::Ollama { slot } => ("ollama", None, slot),
                SetkeyCmd::Gemini { .. } => unreachable!("handled above"),
                #[cfg(feature = "enterprise")]
                SetkeyCmd::Azure { .. } | SetkeyCmd::Vertex { .. } => {
                    unreachable!("handled above")
                }
            };
            let slot = match slot {
                Some(n) => Some(
                    AccountNum::try_from(n).map_err(|e| anyhow::anyhow!("invalid --slot: {e}"))?,
                ),
                None => None,
            };
            commands::setkey::handle(&base_dir, provider, key.as_deref(), slot)
        }
        Command::Listkeys => commands::listkeys::handle(&base_dir, json),
        Command::Rmkey { provider } => commands::rmkey::handle(&base_dir, &provider),
        Command::Models { action } => {
            let action = action.unwrap_or(ModelsCmd::List {
                provider: "all".to_string(),
            });
            match action {
                ModelsCmd::List { provider } => {
                    commands::models::handle_list(&base_dir, &provider, json)
                }
                ModelsCmd::Switch {
                    provider,
                    model,
                    slot,
                    pull_if_missing,
                    force,
                } => {
                    let slot = match slot {
                        Some(n) => Some(
                            AccountNum::try_from(n)
                                .map_err(|e| anyhow::anyhow!("invalid --slot: {e}"))?,
                        ),
                        None => None,
                    };
                    commands::models::handle_switch(
                        &base_dir,
                        &provider,
                        &model,
                        slot,
                        pull_if_missing,
                        force,
                    )
                }
            }
        }
        Command::Install => commands::install::handle(),
        Command::Doctor {
            slot,
            repair_identities,
            check_token_owners,
        } => commands::doctor::handle(&base_dir, json, slot, repair_identities, check_token_owners),
        Command::Probe { slot, all } => {
            if slot.is_none() && !all {
                return Err(anyhow::anyhow!(
                    "csq probe requires either a SLOT argument or --all"
                ));
            }
            commands::probe::handle(&base_dir, slot, json)
        }
        Command::Daemon { action } => match action {
            DaemonCmd::Start {
                background,
                supervised,
                audit_verify_limit,
            } => {
                // M05: propagate --audit-verify-limit via env var so
                // the daemon session's tokio runtime can read it.
                if let Some(limit) = audit_verify_limit {
                    // SAFETY: single-threaded at this point (before tokio runtime starts).
                    unsafe {
                        std::env::set_var("CSQ_AUDIT_VERIFY_LIMIT", limit.to_string());
                    }
                }
                if supervised {
                    // Wave B — the launchd-managed background daemon: the daemon
                    // session wrapped in the crash-restart supervisor loop.
                    commands::daemon::handle_start_supervised(&base_dir)
                } else if background {
                    commands::daemon::handle_start_background(&base_dir)
                } else {
                    commands::daemon::handle_start(&base_dir)
                }
            }
            DaemonCmd::Stop => commands::daemon::handle_stop(&base_dir),
            DaemonCmd::Status => commands::daemon::handle_status(&base_dir),
            DaemonCmd::Install => commands::daemon::handle_install(&base_dir),
            DaemonCmd::Uninstall => commands::daemon::handle_uninstall(&base_dir),
        },
        Command::Update { action } => match action {
            UpdateCmd::Check => commands::update::check(),
            UpdateCmd::Install => commands::update::install(),
        },
        Command::Repair {
            apply,
            heal_contaminated,
        } => commands::repair::handle(&base_dir, apply, heal_contaminated),
        Command::Completions { shell } => {
            commands::completions::handle(shell);
            Ok(())
        }
        Command::Cli { command } => match command {
            CliCommand::Install { name } => commands::cli::handle_install(&name),
            CliCommand::Upgrade { name } => commands::cli::handle_upgrade(&name),
        },
        Command::Classify {
            prompt,
            surface,
            start,
            keywords,
        } => commands::classify::handle(
            &base_dir,
            commands::classify::ClassifyOptions {
                prompt,
                surface,
                start,
                keywords,
            },
        ),
        #[cfg(feature = "enterprise")]
        Command::Oq1Classify { prompt } => {
            // Dev/bench measurement surface — NOT license-gated (no production
            // side effect, no credential access, no signed-chain write). The
            // `enterprise` compile-gate keeps it out of the community binary;
            // license-gating would break the coc-eval harness in CI/dev.
            commands::oq1_classify::handle(commands::oq1_classify::Oq1ClassifyOptions { prompt })
        }
        #[cfg(feature = "enterprise")]
        Command::Admin { command } => match command {
            AdminCmd::InitOrg {
                org_id,
                participants,
                rotate,
            } => commands::admin::handle_init_org(&base_dir, &org_id, &participants, rotate),
            AdminCmd::ProvisionSeat {
                org_id,
                seat_id,
                force,
            } => commands::admin::handle_provision_seat(&base_dir, &org_id, &seat_id, force),
            AdminCmd::ExportSeatRecovery {
                seat_id,
                recovery_key,
                out,
            } => commands::admin::handle_export_seat_recovery(
                &base_dir,
                &seat_id,
                &recovery_key,
                &out,
            ),
            AdminCmd::RotateSeat {
                org_id,
                seat_id,
                reason,
            } => {
                commands::admin::handle_rotate_seat(&base_dir, &org_id, &seat_id, reason.as_deref())
            }
            AdminCmd::DoctorSeat { seat_id } => {
                commands::admin::handle_doctor_seat(&base_dir, &seat_id)
            }
            AdminCmd::ResumeSeatRotation { seat_id } => {
                commands::admin::handle_resume_seat_rotation(&base_dir, &seat_id)
            }
        },
        #[cfg(feature = "enterprise")]
        Command::McpProxy {
            envelope,
            cli,
            server_cmd,
        } => {
            // Enterprise op — gate on the license before spawning the proxy (W4).
            enforce_enterprise_license(&base_dir)?;
            // The proxy propagates the real MCP server's exit code verbatim, like
            // the `csq run` spawn path — `process::exit` (not a `Result` return) so
            // the parent CLI sees the child's code. The proxy already reaped the
            // child and flushed each line; flush stdout once more before the
            // Drop-bypassing exit.
            use std::io::Write as _;
            let code = commands::mcp_proxy::run(
                &base_dir,
                envelope.as_deref(),
                cli.as_deref(),
                &server_cmd,
            );
            let _ = std::io::stdout().flush();
            std::process::exit(code);
        }
        Command::Inspect { target } => match target {
            InspectCmd::Coc {
                debug,
                show_unknowns,
                start,
            } => commands::inspect_coc::handle(
                &base_dir,
                commands::inspect_coc::InspectOptions {
                    json,
                    show_unknowns,
                    debug,
                    start,
                },
            ),
            InspectCmd::Translate { surface, start } => commands::inspect_coc::handle_translate(
                &base_dir,
                commands::inspect_coc::TranslateOptions {
                    surface,
                    json,
                    start,
                },
            ),
        },
        Command::Translate { surface, start } => commands::inspect_coc::handle_translate(
            &base_dir,
            commands::inspect_coc::TranslateOptions {
                surface,
                json,
                start,
            },
        ),
        Command::Audit { command } => match command {
            AuditCmd::Init => commands::audit::handle_init(&base_dir),
            AuditCmd::RotateKey { reason } => {
                commands::audit::handle_rotate_key(&base_dir, reason.as_deref())
            }
            AuditCmd::ConfigSink { name } => {
                commands::audit::handle_config_sink(&base_dir, name.as_deref())
            }
            AuditCmd::ConfigCadence { sink, key, value } => {
                commands::audit::handle_config_cadence(&base_dir, &sink, &key, &value)
            }
            AuditCmd::Verify {
                full,
                since,
                json,
                record,
            } => commands::audit::handle_verify(
                &base_dir,
                full,
                since.as_deref(),
                json,
                record.as_deref(),
            ),
            AuditCmd::MigrateKeys => commands::audit::handle_migrate_keys(&base_dir),
            AuditCmd::Repair { apply } => commands::audit::handle_repair(&base_dir, apply),
            AuditCmd::Intent { state } => {
                commands::audit::handle_intent(&base_dir, state.as_deref())
            }
            AuditCmd::Export { since, until, out } => commands::audit::handle_export(
                &base_dir,
                since.as_deref(),
                until.as_deref(),
                out.as_deref(),
            ),
            AuditCmd::EnrollDev {
                principal,
                granularity,
            } => commands::dev_identity::handle_enroll_dev(
                &base_dir,
                &principal,
                granularity.as_deref(),
            ),
            AuditCmd::ProveDev { principal } => {
                commands::dev_identity::handle_prove_dev(&base_dir, &principal)
            }
            AuditCmd::RosterInstall {
                file,
                activation_seq,
            } => commands::roster::handle_roster_install(&base_dir, &file, activation_seq),
            AuditCmd::RosterShow => commands::roster::handle_roster_show(&base_dir),
            AuditCmd::RosterKeygen { out, force } => {
                commands::roster::handle_roster_keygen(&base_dir, out.as_deref(), force)
            }
            AuditCmd::RosterCreate {
                principal,
                op_class,
                pubkey,
                roster_version,
                out,
            } => commands::roster::handle_roster_create(
                &base_dir,
                &principal,
                &op_class,
                &pubkey,
                roster_version,
                out.as_deref(),
            ),
            AuditCmd::RosterSign {
                file,
                secret_key,
                secret_key_hex,
                detached,
                out,
            } => commands::roster::handle_roster_sign(
                &base_dir,
                &file,
                secret_key.as_deref(),
                secret_key_hex.as_deref(),
                detached,
                out.as_deref(),
            ),
            AuditCmd::RosterRotate {
                from,
                add_key,
                retire_key,
                bump_version,
                out,
            } => commands::roster::handle_roster_rotate(
                &base_dir,
                &from,
                add_key.as_deref(),
                retire_key.as_deref(),
                bump_version,
                out.as_deref(),
            ),
            #[cfg(feature = "enterprise")]
            AuditCmd::BundleInstall { file, pubkey } => {
                // Enterprise op — gate on the license before installing the bundle (W4).
                enforce_enterprise_license(&base_dir)?;
                commands::bundle::handle_bundle_install(&base_dir, &file, &pubkey)
            }
            #[cfg(feature = "enterprise")]
            AuditCmd::BundleKeygen { out, force } => {
                enforce_enterprise_license(&base_dir)?;
                commands::bundle::handle_bundle_keygen(&base_dir, out.as_deref(), force)
            }
            #[cfg(feature = "enterprise")]
            AuditCmd::BundleCreate {
                schemas,
                config,
                pubkey,
                bundle_version,
                out,
            } => {
                enforce_enterprise_license(&base_dir)?;
                commands::bundle::handle_bundle_create(
                    &base_dir,
                    &schemas,
                    config.as_deref(),
                    &pubkey,
                    bundle_version,
                    out.as_deref(),
                )
            }
            #[cfg(feature = "enterprise")]
            AuditCmd::BundleSign {
                file,
                secret_key,
                secret_key_hex,
                out,
            } => {
                enforce_enterprise_license(&base_dir)?;
                commands::bundle::handle_bundle_sign(
                    &base_dir,
                    &file,
                    secret_key.as_deref(),
                    secret_key_hex.as_deref(),
                    out.as_deref(),
                )
            }
            #[cfg(feature = "enterprise")]
            AuditCmd::BundleValidate { file, pubkey } => {
                enforce_enterprise_license(&base_dir)?;
                commands::bundle::handle_bundle_validate(&base_dir, &file, &pubkey)
            }
            #[cfg(feature = "enterprise")]
            AuditCmd::Anchor { json } => commands::audit::handle_anchor(&base_dir, json),
            AuditCmd::Report { json } => commands::audit::handle_report(&base_dir, json),
            AuditCmd::ComplianceReport { format, out } => {
                commands::audit::handle_compliance_report(
                    &base_dir,
                    matches!(format, ReportFormat::Html),
                    out.as_deref(),
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{ceiling_mode_for, Cli, Command, InspectCmd, LayerIntent};
    use clap::Parser;
    use csq_core::capability_layer::log_volume::CeilingMode;

    /// 2026-07-24 mass-expiry regression: the daemon is long-lived, so its
    /// tracing must NOT be capped by the one-shot event ceiling (which silenced
    /// the refresher's failure trail for the whole process lifetime).
    #[test]
    fn daemon_command_logs_unbounded() {
        let cli = Cli::try_parse_from(["csq", "daemon", "status"]).unwrap();
        let cmd = cli.command.expect("daemon status parses to a command");
        assert_eq!(ceiling_mode_for(&cmd), CeilingMode::Unbounded);
    }

    #[test]
    fn non_daemon_command_keeps_default_ceiling() {
        let cli = Cli::try_parse_from(["csq", "logout", "1"]).unwrap();
        let cmd = cli.command.expect("logout parses to a command");
        assert_eq!(ceiling_mode_for(&cmd), CeilingMode::Default);
    }

    #[test]
    fn run_debug_keeps_debug_ceiling() {
        let cli = Cli::try_parse_from(["csq", "run", "1", "--debug"]).unwrap();
        let cmd = cli.command.expect("run --debug parses to a command");
        assert_eq!(ceiling_mode_for(&cmd), CeilingMode::Debug);
    }

    /// an internal ticket redteam F4: cloud-Claude flags MUST require `--backend`, so a typo'd
    /// invocation errors loudly instead of silently discarding them and prompting
    /// for an API key.
    #[cfg(feature = "enterprise")]
    #[test]
    fn setkey_claude_cloud_flags_require_backend() {
        // --project without --backend → clap error, not silent-discard.
        Cli::try_parse_from(["csq", "setkey", "claude", "--slot", "5", "--project", "p"])
            .expect_err("--project without --backend must be a clap error");
        // --backend without --region → clap error (backend requires slot+region).
        Cli::try_parse_from([
            "csq",
            "setkey",
            "claude",
            "--backend",
            "vertex",
            "--slot",
            "5",
        ])
        .expect_err("--backend without --region must be a clap error");
        // Full vertex invocation parses cleanly.
        Cli::try_parse_from([
            "csq",
            "setkey",
            "claude",
            "--backend",
            "vertex",
            "--slot",
            "5",
            "--region",
            "us-east5",
            "--project",
            "p",
            "--sa-file",
            "/x/sa.json",
        ])
        .expect("full vertex cloud-Claude invocation must parse");
        // R2 LOW-1: the ordinary direct-API-key path (no --backend) must STILL
        // parse — the cloud `requires` constraints are one-directional and must
        // not gate --key/--slot.
        Cli::try_parse_from([
            "csq", "setkey", "claude", "--key", "sk-ant-x", "--slot", "5",
        ])
        .expect("direct-API-key path must parse without --backend");
        Cli::try_parse_from(["csq", "setkey", "claude", "--slot", "5"])
            .expect("--slot alone (stdin key) must parse without --backend");
    }

    #[test]
    fn login_default_does_not_set_legacy_shell() {
        let cli = Cli::try_parse_from(["csq", "login", "3"]).expect("parse default login");
        match cli.command {
            Some(Command::Login {
                account,
                provider,
                legacy_shell,
                ..
            }) => {
                assert_eq!(account, 3);
                assert_eq!(provider, "claude");
                assert!(!legacy_shell, "default must NOT enable legacy shell");
            }
            other => panic!("expected Login subcommand, got {other:?}"),
        }
    }

    #[test]
    fn login_legacy_shell_flag_parses() {
        let cli = Cli::try_parse_from(["csq", "login", "5", "--legacy-shell"])
            .expect("parse legacy-shell login");
        match cli.command {
            Some(Command::Login {
                account,
                legacy_shell,
                ..
            }) => {
                assert_eq!(account, 5);
                assert!(legacy_shell, "--legacy-shell must enable the flag");
            }
            other => panic!("expected Login subcommand, got {other:?}"),
        }
    }

    #[test]
    fn login_provider_codex_parses() {
        let cli = Cli::try_parse_from(["csq", "login", "1", "--provider", "codex"])
            .expect("parse codex login");
        match cli.command {
            Some(Command::Login { provider, .. }) => assert_eq!(provider, "codex"),
            other => panic!("expected Login subcommand, got {other:?}"),
        }
    }

    /// an internal ticket: `--json` defaults to off (unchanged human-facing text output on
    /// every pre-existing invocation) and parses when passed explicitly.
    #[test]
    fn login_json_flag_defaults_off_and_parses() {
        let cli = Cli::try_parse_from(["csq", "login", "2"]).expect("parse default login");
        match cli.command {
            Some(Command::Login { json, .. }) => assert!(!json, "--json must default to off"),
            other => panic!("expected Login subcommand, got {other:?}"),
        }

        let cli =
            Cli::try_parse_from(["csq", "login", "2", "--json"]).expect("parse login with --json");
        match cli.command {
            Some(Command::Login { json, .. }) => assert!(json),
            other => panic!("expected Login subcommand, got {other:?}"),
        }
    }

    /// Stage 2 of an internal journal entry: `csq login N --provider gemini`
    /// shells out to `gemini auth login` (Code Assist OAuth path C).
    /// A regression in the parser's value_parser allowlist would
    /// silently drop this path; this test pins the value as accepted.
    #[test]
    fn login_provider_gemini_parses() {
        let cli = Cli::try_parse_from(["csq", "login", "12", "--provider", "gemini"])
            .expect("parse gemini login");
        match cli.command {
            Some(Command::Login {
                provider, account, ..
            }) => {
                assert_eq!(provider, "gemini");
                assert_eq!(account, 12);
            }
            other => panic!("expected Login subcommand, got {other:?}"),
        }
    }

    #[test]
    fn run_debug_flag_parses_with_capability_layer() {
        let cli = Cli::try_parse_from(["csq", "run", "3", "--capability-layer", "--debug"])
            .expect("parse run with debug + capability-layer");
        match cli.command {
            Some(Command::Run {
                capability_layer,
                debug,
                account,
                ..
            }) => {
                assert_eq!(account, Some(3));
                assert!(capability_layer);
                assert!(debug);
            }
            other => panic!("expected Run subcommand, got {other:?}"),
        }
    }

    #[test]
    fn run_debug_default_is_false() {
        let cli = Cli::try_parse_from(["csq", "run", "1"]).expect("parse bare run");
        match cli.command {
            Some(Command::Run { debug, .. }) => assert!(!debug, "debug must default to false"),
            other => panic!("expected Run subcommand, got {other:?}"),
        }
    }

    // M7: capability-layer default flipped opt-in → `.coc/`-gated
    // auto-engage. These pin the flag→intent mapping + its semantics.

    #[test]
    fn layer_intent_no_flags_is_auto_default() {
        let intent = LayerIntent::from_flags(false, false);
        assert_eq!(intent, LayerIntent::AutoDefault);
        assert!(intent.enabled(), "AutoDefault must let the pipeline run");
        assert!(intent.is_auto(), "AutoDefault must report is_auto");
    }

    #[test]
    fn layer_intent_explicit_on_is_forced_on() {
        let intent = LayerIntent::from_flags(true, false);
        assert_eq!(intent, LayerIntent::ForcedOn);
        assert!(intent.enabled());
        assert!(
            !intent.is_auto(),
            "explicit --capability-layer must NOT print the auto-engaged note"
        );
    }

    #[test]
    fn layer_intent_explicit_off_is_forced_off() {
        let intent = LayerIntent::from_flags(false, true);
        assert_eq!(intent, LayerIntent::ForcedOff);
        assert!(!intent.enabled(), "ForcedOff must suppress the pipeline");
        assert!(!intent.is_auto());
    }

    #[test]
    fn layer_intent_no_capability_wins_over_capability() {
        // clap's conflicts_with rejects both at parse time; from_flags
        // biases to ForcedOff defensively if both ever arrive true.
        assert_eq!(
            LayerIntent::from_flags(true, true),
            LayerIntent::ForcedOff,
            "force-off is the safe bias when both flags somehow set"
        );
    }

    #[test]
    fn bare_run_maps_to_auto_default_intent() {
        let cli = Cli::try_parse_from(["csq", "run", "2"]).expect("parse bare run");
        match cli.command {
            Some(Command::Run {
                capability_layer,
                no_capability_layer,
                ..
            }) => {
                assert!(!capability_layer);
                assert!(!no_capability_layer);
                assert_eq!(
                    LayerIntent::from_flags(capability_layer, no_capability_layer),
                    LayerIntent::AutoDefault,
                    "bare `csq run N` must auto-engage (M7), not stay opt-in-off"
                );
            }
            other => panic!("expected Run subcommand, got {other:?}"),
        }
    }

    #[test]
    fn classify_subcommand_parses_with_required_prompt() {
        let cli = Cli::try_parse_from([
            "csq",
            "classify",
            "--prompt",
            "Is PII exposed?",
            "--surface",
            "claude-code",
        ])
        .expect("parse classify");
        match cli.command {
            Some(Command::Classify {
                prompt,
                surface,
                start,
                keywords,
            }) => {
                assert_eq!(prompt, "Is PII exposed?");
                assert_eq!(surface, "claude-code");
                assert!(start.is_none());
                assert!(keywords.is_none(), "--keywords defaults to None");
            }
            other => panic!("expected Classify subcommand, got {other:?}"),
        }
    }

    /// `csq translate --surface kimi|grok` MUST clap-parse — pre-fix, clap's
    /// `value_parser` allowlist rejected these two strings BEFORE the
    /// command handler ever ran (a loud, structural refusal distinct from
    /// the handler-level `handle_translate` fix covered in
    /// `inspect_coc.rs`'s own tests).
    #[test]
    fn translate_subcommand_accepts_kimi_and_grok_surface() {
        for surface in ["kimi", "grok"] {
            let cli = Cli::try_parse_from(["csq", "translate", "--surface", surface])
                .unwrap_or_else(|e| panic!("--surface {surface} must clap-parse, got: {e}"));
            match cli.command {
                Some(Command::Translate {
                    surface: parsed, ..
                }) => assert_eq!(parsed, surface),
                other => panic!("expected Translate subcommand, got {other:?}"),
            }
        }
    }

    /// `csq inspect translate kimi|grok` — the sibling `InspectCmd::Translate`
    /// value_parser MUST accept the same two names.
    #[test]
    fn inspect_translate_subcommand_accepts_kimi_and_grok_surface() {
        for surface in ["kimi", "grok"] {
            let cli = Cli::try_parse_from(["csq", "inspect", "translate", surface])
                .unwrap_or_else(|e| panic!("inspect translate {surface} must parse, got: {e}"));
            match cli.command {
                Some(Command::Inspect {
                    target:
                        InspectCmd::Translate {
                            surface: parsed, ..
                        },
                }) => assert_eq!(parsed, surface),
                other => panic!("expected Inspect Translate subcommand, got {other:?}"),
            }
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn oq1_classify_subcommand_parses_with_required_prompt() {
        let cli = Cli::try_parse_from(["csq", "oq1-classify", "--prompt", "SYNTHETIC: diagnosis"])
            .expect("parse oq1-classify");
        match cli.command {
            Some(Command::Oq1Classify { prompt }) => {
                assert_eq!(prompt, "SYNTHETIC: diagnosis");
            }
            other => panic!("expected Oq1Classify subcommand, got {other:?}"),
        }
    }

    #[test]
    fn classify_surface_defaults_to_claude_code() {
        let cli = Cli::try_parse_from(["csq", "classify", "--prompt", "x"])
            .expect("parse classify default surface");
        match cli.command {
            Some(Command::Classify { surface, .. }) => assert_eq!(surface, "claude-code"),
            other => panic!("expected Classify subcommand, got {other:?}"),
        }
    }
}
