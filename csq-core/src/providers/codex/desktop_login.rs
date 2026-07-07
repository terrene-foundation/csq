//! Desktop-facing Codex login orchestrator.
//!
//! The CLI path in [`crate::providers::codex::login::perform_with`]
//! uses interactive stdin/stdout for the keychain-residue prompt and
//! inherits stdio when spawning `codex login --device-auth`. The
//! desktop modal can't run an interactive TTY — the Tauri commands
//! instead split the flow into two calls:
//!
//! 1. [`start_login`] — inspects preconditions (ToS acknowledgement,
//!    keychain residue) and returns a structured status. No side
//!    effects beyond the keychain probe.
//! 2. [`complete_login`] — given the user's purge decision, writes
//!    `config.toml`, spawns `codex login --device-auth` with stdout
//!    captured, parses the device-code line, invokes an
//!    `on_device_code` callback so the Tauri layer can forward the
//!    code to the Svelte modal as an event, then waits for the
//!    subprocess to exit and relocates the resulting `auth.json`.
//!
//! Both functions are DI-heavy for the same reason the CLI path is:
//! the keychain probe, subprocess spawn, and profiles.json write are
//! each substitutable so tests exercise every branch without live
//! system access.

use super::keychain::ProbeResult;
use super::surface;
use super::tos;
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::credentials::{self, file as cred_file, CredentialFile};
use crate::daemon::identity_mint;
use crate::error::redact_tokens;
use crate::types::AccountNum;
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::path::Path;
use std::process::ExitStatus;

/// Outcome of [`start_login`]. IPC-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartLoginView {
    /// Target account slot, echoed for correlation.
    pub account: u16,
    /// True when the user has NOT acknowledged the current Codex ToS
    /// version. The UI MUST show the disclosure and call
    /// `acknowledge_codex_tos` before proceeding.
    pub tos_required: bool,
    /// Keychain residue state. `"absent"` / `"present"` / `"unsupported"`
    /// (non-macOS platforms) / `"probe_failed"` (spawn failure).
    pub keychain: String,
    /// True when the user must make an explicit decision about the
    /// keychain residue before proceeding — i.e. `keychain == "present"`.
    pub awaiting_keychain_decision: bool,
    /// an internal journal entry / round-2 redteam MEDIUM-5 — Codex device-auth
    /// requires "Device code authorization" to be ENABLED in the
    /// user's ChatGPT Security Settings before the device code can
    /// be redeemed; otherwise OpenAI's browser flow rejects with
    /// "Enable device code authorization for Codex in ChatGPT
    /// Security Settings, then run `codex login --device-auth` again".
    /// The UI MUST display this message before the device-auth
    /// subprocess starts so the user can pre-enable the toggle. csq
    /// has no way to detect whether the toggle is on (OpenAI exposes
    /// no API for it) — this is purely a heads-up.
    pub device_auth_prereq_message: String,
    /// Companion to `device_auth_prereq_message` — the URL to the
    /// settings page (best-effort; UI moves over time and the user
    /// may need to navigate manually). Round-2 redteam MEDIUM-5.
    pub device_auth_prereq_url: String,
}

/// Pre-rendered prerequisite message for the desktop Codex login modal.
/// Mirrors the CLI banner in `csq-cli/src/commands/login.rs::handle_codex`.
/// Round-2 redteam MEDIUM-5.
pub const DEVICE_AUTH_PREREQ_MESSAGE: &str =
    "Codex requires \"Device code authorization\" to be ENABLED in your \
     ChatGPT Security Settings BEFORE the device code can be redeemed. \
     If the browser shows \"Enable device code authorization for Codex \
     in ChatGPT Security Settings\" after you submit the code, that's \
     the prerequisite — turn it on at the link below, then re-run.";

pub const DEVICE_AUTH_PREREQ_URL: &str = "https://chatgpt.com/#settings/Security";

/// Outcome of [`complete_login`]. IPC-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompleteLoginView {
    pub account: u16,
    pub label: String,
}

/// Device-code payload handed to the UI callback while the subprocess
/// is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCodeInfo {
    /// Short alphanumeric code the user types at the verification URL.
    pub user_code: String,
    /// Full verification URL (already URL-encoded).
    pub verification_url: String,
}

/// Starts a Codex login by consulting the ToS marker and the keychain.
/// No filesystem writes happen inside `config-<N>/` — the caller MUST
/// resolve [`StartLoginView::tos_required`] and
/// [`StartLoginView::awaiting_keychain_decision`] before calling
/// [`complete_login`].
///
/// `probe` is factored out for tests; production wiring is
/// `keychain::probe_residue`.
pub fn start_login<P>(base_dir: &Path, account: AccountNum, probe: P) -> Result<StartLoginView>
where
    P: FnOnce() -> ProbeResult,
{
    if !base_dir.is_dir() {
        return Err(anyhow!(
            "base directory does not exist: {}",
            base_dir.display()
        ));
    }
    let tos_required = !tos::is_acknowledged(base_dir);
    let probe_result = probe();
    let (keychain_label, awaiting_keychain_decision) = match probe_result {
        ProbeResult::Absent => ("absent", false),
        ProbeResult::Present => ("present", true),
        ProbeResult::Unsupported => ("unsupported", false),
        ProbeResult::ProbeFailed => ("probe_failed", false),
    };
    Ok(StartLoginView {
        account: account.get(),
        tos_required,
        keychain: keychain_label.into(),
        awaiting_keychain_decision,
        device_auth_prereq_message: DEVICE_AUTH_PREREQ_MESSAGE.into(),
        device_auth_prereq_url: DEVICE_AUTH_PREREQ_URL.into(),
    })
}

/// Completes a Codex login after the desktop modal has resolved the
/// ToS and keychain prompts. Writes `config.toml`, spawns
/// `codex login --device-auth` with stdout piped, forwards any
/// device-code line to `on_device_code`, waits for the subprocess to
/// exit, and relocates `auth.json` to `credentials/codex-<N>.json`.
///
/// DI parameters mirror [`crate::providers::codex::login::perform_with`]:
///
/// * `purge_keychain` — pre-collected user decision; `true` runs
///   `keychain::purge_residue` before spawn, `false` is a noop.
/// * `purge` — the purge implementation (test seam).
/// * `spawn_codex` — spawns the subprocess, captures stdout, and
///   must invoke `on_device_code` as soon as the verification URL +
///   code are visible. Returns the eventual [`ExitStatus`].
/// * `on_device_code` — receives the parsed code payload so the
///   Tauri layer can emit a `codex-device-code` event.
pub fn complete_login<U, S, C>(
    base_dir: &Path,
    account: AccountNum,
    purge_keychain: bool,
    purge: U,
    spawn_codex: S,
    mut on_device_code: C,
) -> Result<CompleteLoginView>
where
    U: FnOnce() -> std::result::Result<bool, String>,
    S: FnOnce(&Path, &mut dyn FnMut(DeviceCodeInfo)) -> Result<ExitStatus>,
    C: FnMut(DeviceCodeInfo),
{
    if !base_dir.is_dir() {
        return Err(anyhow!(
            "base directory does not exist: {}",
            base_dir.display()
        ));
    }
    if !tos::is_acknowledged(base_dir) {
        return Err(anyhow!(
            "Codex terms-of-service have not been acknowledged — call acknowledge_codex_tos first"
        ));
    }

    // Step 1: create config-<N>/ + codex-sessions/.
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("create {}", config_dir.display()))?;
    let sessions_dir = surface::sessions_dir(base_dir, account);
    std::fs::create_dir_all(&sessions_dir)
        .with_context(|| format!("create {}", sessions_dir.display()))?;

    // Step 2: honour the user's keychain decision.
    if purge_keychain {
        match purge() {
            Ok(_) => {}
            Err(e) => {
                // an internal journal entry finding M4: the `security` CLI's
                // stderr echoes service names and adjacent keychain
                // bytes on some failure modes — route through
                // `redact_tokens` before surfacing to the caller.
                let redacted = redact_tokens(&e);
                return Err(anyhow!(
                    "could not purge com.openai.codex keychain entry: {redacted} — delete it manually with `security delete-generic-password -s com.openai.codex` and retry"
                ));
            }
        }
    }

    // Step 3: pre-seed config.toml BEFORE shelling out. INV-P03.
    surface::write_config_toml(base_dir, account, surface::default_model())
        .with_context(|| "pre-seed config-<N>/config.toml failed")?;

    // Step 4: shell out via the caller-supplied spawn closure. The
    // closure bridges stdout lines into device-code events.
    let mut forwarder = |info: DeviceCodeInfo| on_device_code(info);
    let status = spawn_codex(&config_dir, &mut forwarder)
        .with_context(|| "spawn `codex login --device-auth`")?;
    if !status.success() {
        return Err(anyhow!(
            "codex login exited with non-zero status — user may have cancelled in the browser"
        ));
    }

    // Step 5: parse config-<N>/auth.json and relocate it. Identical
    // to the CLI path's H1-hardened error routing — a malformed
    // auth.json must not echo tokens to the UI via the anyhow chain.
    let written = surface::written_auth_json_path(base_dir, account);
    let creds_from_codex = match credentials::load(&written) {
        Ok(c) => c,
        Err(e) => {
            let redacted = redact_tokens(&e.to_string());
            tracing::warn!(
                account = %account,
                error_kind = "codex_desktop_login_auth_json_parse_failed",
                reason = %redacted,
                "codex auth.json could not be parsed after device-auth"
            );
            return Err(anyhow!(
                "could not parse {} after `codex login` — retry the Add Account flow",
                written.display()
            ));
        }
    };
    let codex_creds = creds_from_codex
        .codex()
        .ok_or_else(|| anyhow!("auth.json written by codex is not a Codex credential file"))?
        .clone();
    // Filter empty-string hints at the boundary so `mint_for_codex_login`
    // only ever sees `Some(non_empty)` or `None` — mirrors the CLI path in
    // `login::perform_with`. The same filtered hint feeds `format_label`.
    let account_id_hint = codex_creds
        .tokens
        .account_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned());
    let canonical = CredentialFile::Codex(codex_creds);

    // Mint a `by_slot` UUID for this slot BEFORE the fail-closed
    // `save_canonical_for`. Symmetric with the CLI codex login path
    // (`login::perform_with`): daemon Pass 0 only mints UUIDs for Anthropic
    // accounts (`discover_anthropic` skips codex-only slots), so a codex-only
    // slot re-authed from the desktop has no `by_slot[N]` entry, and
    // `save_canonical_for` is fail-closed without one (returns
    // `CredentialError::NoCredentials`). The desktop twin previously omitted
    // this mint, surfacing the misleading "could not write
    // credentials/codex-N.json — check permissions" error (the numeric path
    // is a retired M4-12 write destination). Acquire the lock ONCE and hold it
    // across mint + save so both writes are atomic cross-process; on save
    // failure roll back the `by_slot[N]` mapping (CRIT-2) so the slot is not
    // left partial-minted (`by_email` is preserved for retry idempotency).
    let mint_lock = ProfilesFileLock::acquire(base_dir).map_err(|_| {
        tracing::warn!(
            account = %account,
            error_kind = "codex_desktop_login_profiles_lock_failed",
            "could not acquire profiles lock for UUID mint — login cannot complete"
        );
        anyhow!(
            "could not acquire profiles.json lock for Codex slot {} — check profiles.json permissions",
            account
        )
    })?;

    if let Err(e) = identity_mint::mint_for_codex_login(
        &mint_lock,
        base_dir,
        account.get(),
        account_id_hint.as_deref(),
    ) {
        tracing::warn!(
            account = %account,
            error_kind = "codex_desktop_login_uuid_mint_failed",
            reason = %redact_tokens(&e),
            "could not mint UUID for Codex slot — login cannot complete"
        );
        // Scrub the raw auth.json before returning (live tokens must not sit
        // readable between attempts) — the mint failed, so no canonical write
        // happened; the retry path expects `written` absent.
        scrub_and_remove_written(&written, account, "mint_failed");
        return Err(anyhow!(
            "could not mint identity UUID for Codex slot {} — check profiles.json permissions and disk space",
            account
        ));
    }

    if let Err(e) = cred_file::save_canonical_for(base_dir, account, &canonical) {
        let redacted = redact_tokens(&e.to_string());
        tracing::warn!(
            account = %account,
            error_kind = "codex_desktop_login_canonical_save_failed",
            reason = %redacted,
            "could not persist codex canonical credential"
        );
        // CRIT-2: roll back the by_slot mapping the mint just wrote so the slot
        // is not left partial-minted. by_email is preserved so a retry reuses
        // the same UUID. Best-effort — log on failure but propagate the
        // original save error.
        if let Err(rb_err) = profiles::remove_slot_mapping(&mint_lock, base_dir, account.get()) {
            tracing::warn!(
                account = %account,
                error_kind = "codex_desktop_login_rollback_failed",
                reason = %redact_tokens(&rb_err.to_string()),
                "could not roll back partial-mint by_slot mapping after save_canonical_for failure"
            );
        }
        // R4 cleanup (an internal journal entry finding 15): scrub the raw auth.json before
        // returning so live access+refresh tokens don't sit readable between
        // the failed attempt and the next one.
        scrub_and_remove_written(&written, account, "save_failed");
        return Err(anyhow!(
            "could not write identities/<UUID>/credentials-codex.json for account {} — check `identities/` permissions",
            account
        ));
    }
    // Lock released after save completes (minted + written atomically).
    drop(mint_lock);

    // Cleanup: secure_file + unlink the raw auth.json codex wrote.
    scrub_and_remove_written(&written, account, "post_save");

    // Clear any stale broker_failed sentinel — symmetric to the CLI
    // codex login path. See `providers::codex::login::perform_with` for
    // the rationale.
    crate::refresh::sentinel::clear_broker_failed(base_dir, account);

    // Step 6: marker + profile entry.
    //
    // M4-7 (an internal ticket Phase 4, spec 02 §INV-03 + §2.3.1): the marker
    // content is the slot's identity UUID when a `by_slot` mapping
    // exists, falling back to the legacy decimal slot id for pure-legacy
    // installs. Symmetric to the CLI codex login path in
    // `providers::codex::login::perform_with`. The filename
    // `.csq-account` is unchanged per OQ #3.
    match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => markers::write_csq_account(&config_dir, uuid)
            .with_context(|| format!(".csq-account marker in {}", config_dir.display()))?,
        None => markers::write_csq_account_legacy(&config_dir, account)
            .with_context(|| format!(".csq-account marker in {}", config_dir.display()))?,
    }

    let label = format_label(account, account_id_hint.as_deref());
    update_profile(base_dir, account, &label)
        .with_context(|| "update profiles.json with the new Codex account entry")?;

    // M4-2: pair `identities/<UUID>/settings.json` when a UUID mapping exists
    // for this slot. Symmetric to the CLI codex login path in
    // `providers::codex::login::perform_with`. Codex has no
    // `config-<N>/settings.json`, so the source bytes are `{}`.
    //
    // Non-fatal: pair failure does not block the desktop login completion.
    if let Some(uuid) = profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        let bytes = b"{}";
        if let Err(e) = credentials::save_uuid_settings(base_dir, uuid, bytes) {
            tracing::warn!(
                account = %account,
                error_kind = "codex_desktop_uuid_settings_pair_failed",
                "codex desktop finalize_login: could not pair UUID settings.json (non-fatal): {}",
                redact_tokens(&e.to_string())
            );
        } else {
            tracing::debug!(
                account = %account,
                "codex desktop finalize_login: paired UUID settings.json"
            );
        }
    }

    Ok(CompleteLoginView {
        account: account.get(),
        label,
    })
}

/// Allowlisted hosts for codex-cli device-authorization auto-launch.
///
/// codex-cli v0.41+ emits the verification URL on a dedicated stdout
/// line; csq parses that line and auto-opens the URL in the user's
/// browser. The auto-launch is a credential-flow trust boundary — the
/// page the user lands on is where they sign in. Any URL csq sends to
/// `open_in_browser` MUST be on a host the user could reasonably expect
/// for OpenAI device auth. Hostname comparison is exact-match (no
/// suffix matching, no wildcards).
///
/// Origin: redteam round 1 H2. The pre-fix filter was a path-substring
/// match (`contains("/device")`) which accepted `https://evil.example.com/foo/device`
/// — phishing-shaped on a credential flow.
const CODEX_DEVICE_AUTH_HOST_ALLOWLIST: &[&str] = &["auth.openai.com", "chatgpt.com"];

/// Stateful accumulator for codex-cli output that prints the
/// verification URL and the device code on SEPARATE lines.
///
/// codex-cli 0.128.0 emits the device-auth flow as:
///
/// ```text
/// 1. Open this link in your browser and sign in to your account
///    https://auth.openai.com/codex/device
///
/// 2. Enter this one-time code (expires in 15 minutes)
///    PDZD-0XC93
/// ```
///
/// [`parse_device_code_line`] requires URL + code on the same line and
/// returns `None` for each of those, leaving the desktop modal stuck
/// at "waiting for codex-cli to surface the device code." This
/// accumulator remembers the last URL it saw and pairs it with the
/// next code (or vice-versa). The same-line shape is preserved as a
/// shortcut so legacy codex-cli output is unaffected.
///
/// `observe` returns `Some(DeviceCodeInfo)` exactly once per
/// (URL, code) pair. Caller is responsible for de-duping further
/// emissions across the lifetime of the spawn.
#[derive(Debug, Default)]
pub struct DeviceCodeAccumulator {
    pending_url: Option<String>,
    pending_code: Option<String>,
    /// Set to `true` the first time `observe` finds a verification URL,
    /// regardless of whether the URL ever pairs with a code. Stays
    /// `true` after the URL is consumed by a successful pair, so a
    /// post-spawn caller can ask the accumulator "did we ever reach
    /// the URL stage?" to distinguish two failure modes:
    ///
    /// * URL never seen → codex-cli broke before reaching the
    ///   verification step (binary missing, OAuth endpoint down).
    /// * URL seen but code never recognised → codex-cli output shape
    ///   may have changed (e.g. OpenAI bumped the code length past
    ///   the `is_device_code_shape` 4-{4..=5} window).
    saw_url: bool,
}

impl DeviceCodeAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if any URL was observed since construction. See
    /// the field doc on `saw_url` for the diagnostic motivation.
    pub fn saw_url(&self) -> bool {
        self.saw_url
    }

    pub fn observe(&mut self, line: &str) -> Option<DeviceCodeInfo> {
        // Same-line shortcut.
        if let Some(info) = parse_device_code_line(line) {
            self.pending_url = None;
            self.pending_code = None;
            self.saw_url = true;
            return Some(info);
        }
        // Cross-line path: codex-cli 0.128.0+ emits URL and code on
        // separate lines. Strip ANSI escapes once so a TTY-colorized
        // URL or code still tokenizes — the URL extractor strips its
        // own copy too (idempotent), but stripping here lets the code
        // scan see the un-wrapped token.
        let stripped = strip_ansi_escapes(line);
        let found_url = extract_device_auth_url(&stripped);
        let mut found_code: Option<String> = None;
        for token in stripped.split_whitespace() {
            let trimmed = trim_token_punct(token);
            if is_device_code_shape(trimmed) {
                found_code = Some(trimmed.to_string());
                break;
            }
        }
        if let Some(u) = found_url {
            self.pending_url = Some(u);
            self.saw_url = true;
        }
        if let Some(c) = found_code {
            self.pending_code = Some(c);
        }
        if self.pending_url.is_some() && self.pending_code.is_some() {
            let info = DeviceCodeInfo {
                user_code: self.pending_code.take().unwrap(),
                verification_url: self.pending_url.take().unwrap(),
            };
            return Some(info);
        }
        None
    }
}

/// Strips trailing sentence punctuation around URLs / codes. Mirrors
/// the trim pattern in [`parse_device_code_line`].
fn trim_token_punct(token: &str) -> &str {
    token.trim_end_matches(|c: char| {
        !c.is_ascii_alphanumeric()
            && c != '/'
            && c != '-'
            && c != '_'
            && c != '='
            && c != '?'
            && c != '&'
            && c != '%'
    })
}

/// Extracts the device-authorization URL from a single codex-cli stdout
/// line. codex-cli v0.41+ emits the URL on its own line (separate from
/// the code's line) — the legacy [`parse_device_code_line`] requires
/// both on the same line and misses this shape.
///
/// Trust-boundary semantics:
///
/// - [`url::Url::parse`] is the structural defense. It rejects malformed
///   URLs and exposes `username()`/`password()`/`host_str()` for the
///   userinfo + host checks below.
/// - The `username()` / `password()` rejection defeats the
///   `https://auth.openai.com@evil.example.com/...` userinfo-phishing
///   trick where a browser navigates to `evil.example.com` while the
///   user's eye reads `auth.openai.com` (origin: redteam round 1 H1).
/// - The host-allowlist rejection defeats `https://evil.example.com/foo/device`
///   path-substring bypass (origin: redteam round 1 H2).
/// - HTTPS-only — the OpenAI device flow is HTTPS-only; an `http://`
///   device URL is an exfiltration vector against the device-code
///   grant (origin: redteam round 1 LOW).
/// - ANSI escape sequences are stripped before tokenizing so a TTY-
///   colorized URL still launches (origin: redteam round 1 M2).
///
/// First-match wins: if a single line carries multiple URLs (unusual
/// in current codex-cli output but supported by line-iteration), the
/// first one whose host is on the allowlist is returned. The allowlist
/// makes this safe; without it, ordering would be a vulnerability.
/// Origin: redteam round 1 M3.
///
/// Returns `None` if the line has no URL, or the URL is malformed,
/// uses HTTP, carries userinfo, has an off-allowlist host, or has no
/// `/device` substring in the path.
pub fn extract_device_auth_url(line: &str) -> Option<String> {
    extract_codex_url(line, /* require_device_path = */ true)
}

/// Shared URL extraction core for both `extract_device_auth_url`
/// (cross-line, requires `/device` path) and the same-line shortcut
/// in [`parse_device_code_line`] (legacy `/codex/verify` shape, no
/// `/device` requirement).
///
/// All other guards (HTTPS-only, userinfo rejection, host allowlist)
/// are applied uniformly. The host allowlist is the primary defense
/// against off-allowlist phishing URLs; the `/device` check is
/// defense-in-depth that the legacy same-line shape predates.
fn extract_codex_url(line: &str, require_device_path: bool) -> Option<String> {
    let stripped = strip_ansi_escapes(line);
    for token in stripped.split_whitespace() {
        // Strip trailing sentence punctuation while keeping URL-internal
        // characters. Mirrors [`parse_device_code_line`]'s trim pattern.
        let trimmed = trim_token_punct(token);
        // Cheap pre-filter: only `https://...` candidates pass to the
        // `url` crate parse. Case-insensitive per RFC 3986 §3.1.
        if trimmed.len() < 8
            || !trimmed
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        {
            continue;
        }
        let parsed = match ::url::Url::parse(trimmed) {
            Ok(u) => u,
            Err(_) => continue,
        };
        // HTTPS-only — `Url::parse` already validated the scheme but
        // re-assert here so future maintainers don't widen the pre-filter
        // and forget to widen this guard. Drop `http://` per round-1 LOW.
        if parsed.scheme() != "https" {
            continue;
        }
        // Userinfo guard — defeats `https://auth.openai.com@evil/...`.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            continue;
        }
        // Host allowlist — defeats `https://evil/.../device`. Comparison
        // is exact-match on the host string (no suffix matching, no
        // wildcards) per RFC 3986 §3.2.2 (host comparison is case-
        // insensitive, but `Url::parse` normalizes to lowercase).
        let host = match parsed.host_str() {
            Some(h) => h,
            None => continue,
        };
        if !CODEX_DEVICE_AUTH_HOST_ALLOWLIST.contains(&host) {
            continue;
        }
        // Path must contain "/device" for cross-line extraction
        // (`/codex/device` shape AND future variants like
        // `/api/device-authorization`). The legacy same-line shape
        // (`/codex/verify`) predates the `/device` segment so the
        // shortcut path skips this check; the host allowlist remains
        // the primary defense in both shapes.
        if require_device_path && !parsed.path().contains("/device") {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

/// Strips CSI / SGR ANSI escape sequences (`\x1b[...m` and friends)
/// from a line so a TTY-colorized URL or code still tokenizes correctly.
/// codex-cli detects TTY at startup and emits color by default; when
/// codex-cli's stdout is captured via piped readers (which is exactly
/// what csq does to extract the device-auth URL), the ANSI bytes are
/// preserved. Origin: redteam round 1 M2.
fn strip_ansi_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC [ <params> <intermediate> <final>
            // OR ESC <single-char> for non-CSI sequences.
            // Consume the introducer if any.
            match chars.peek() {
                Some(&'[') => {
                    chars.next();
                    // Drain through the final byte (a char in 0x40..=0x7e).
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if (0x40u32..=0x7e).contains(&(p as u32)) {
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Non-CSI escape; drop the next char.
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        // Replace bare CR (TTY redraw) with space — codex-cli may emit
        // `\r` for progress repaints. Dropping the CR entirely would
        // CONCATENATE the URL with the next-frame text; substituting a
        // space preserves token boundaries so `split_whitespace` still
        // isolates the URL.
        if c == '\r' {
            out.push(' ');
            continue;
        }
        out.push(c);
    }
    out
}

/// Scans a single line of `codex login --device-auth` stdout for a
/// device-code + verification URL. Returns `Some(DeviceCodeInfo)`
/// when both pieces land on the same line (codex-cli's observed shape
/// PRE-0.128.0 was `Go to: https://... and enter: XXXX-XXXX`).
/// codex-cli 0.128.0+ splits URL and code across lines — callers MUST
/// use [`DeviceCodeAccumulator`] to handle that shape.
///
/// URL extraction routes through the shared [`extract_codex_url`]
/// core (with `require_device_path = false` so the legacy
/// `/codex/verify` shape still matches) so the same-line shortcut
/// inherits the host allowlist + HTTPS-only + userinfo guard. Without
/// this, an off-allowlist host on the same line as a code-shape token
/// (e.g. `Visit https://evil.example.com/codex/device and enter ABCD-EFGH`)
/// would be returned through this shortcut while
/// [`DeviceCodeAccumulator`]'s cross-line path correctly rejected it.
/// Origin: redteam round-N follow-up to PRs #335-#337 (LOW finding —
/// same-line allowlist gap).
pub fn parse_device_code_line(line: &str) -> Option<DeviceCodeInfo> {
    let url = extract_codex_url(line, /* require_device_path = */ false)?;
    let stripped = strip_ansi_escapes(line);
    for token in stripped.split_whitespace() {
        let trimmed = trim_token_punct(token);
        if is_device_code_shape(trimmed) {
            return Some(DeviceCodeInfo {
                user_code: trimmed.to_string(),
                verification_url: url,
            });
        }
    }
    None
}

fn is_device_code_shape(token: &str) -> bool {
    // an internal journal entry finding M1 narrowed this to EXACTLY 4-4. codex-cli
    // 0.128.0 emits 4-5 (e.g. `PDZD-0XC93`) — observed verbatim
    // 2026-05-08. Widen to 4 + dash + {4..=5}: tight enough to reject
    // help-output tokens (`NOTICE`, `WARNING`, `ID-ABCDE`) and the
    // legacy 4-3 shape pinned by the regression test below, while
    // covering both observed OpenAI device-code shapes.
    let bytes = token.as_bytes();
    if !(9..=10).contains(&bytes.len()) {
        return false;
    }
    if bytes[4] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 {
            continue; // the dash
        }
        let c = b as char;
        if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Formats the profiles.json label for a newly-logged-in Codex slot.
/// Mirrors [`crate::providers::codex::login::format_label`] (not
/// re-exported — intentionally duplicated to keep the two call sites
/// independent; a future refactor may unify).
pub(crate) fn format_label(account: AccountNum, account_id_hint: Option<&str>) -> String {
    match account_id_hint {
        Some(id) if !id.is_empty() => {
            let prefix = id.split('-').next().unwrap_or(id);
            format!("codex-{}/{}", account, prefix)
        }
        _ => format!("codex-{}", account),
    }
}

/// Scrubs and removes the raw `auth.json` that codex-cli wrote into
/// `config-<N>/`. Called from two sites: after a successful
/// `save_canonical_for` (expected cleanup) AND from the
/// `save_canonical_for` error branch (R4 cleanup — an internal journal entry
/// finding 15; without this the live access+refresh tokens persist
/// on disk between failed attempts).
///
/// Best-effort with three layers of defense in this order:
///   1. `secure_file`: chmod 0o600 so only the owner can read.
///   2. `remove_file`: the common case — unlink on APFS/ext4 moves
///      to unused.
///   3. On remove failure: open+truncate+zero-write+fsync to ensure
///      the token bytes are overwritten even if the inode lingers.
///      Uses a fixed 64 KiB zero buffer (codex auth.json is ~8 KiB
///      in practice) instead of `meta.len()` which could race a
///      file-grow between the metadata read and the write. Retry
///      `remove_file` after the zero-write.
///
/// `context` is an operator-readable tag ("post_save" | "save_failed")
/// so the fixed-vocabulary log line distinguishes which call site
/// originated the cleanup.
fn scrub_and_remove_written(written: &Path, account: AccountNum, context: &'static str) {
    use std::io::{Seek, SeekFrom, Write};

    if !written.exists() {
        return;
    }
    let _ = crate::platform::fs::secure_file(written);

    if let Err(remove_err) = std::fs::remove_file(written) {
        // Fallback: truncate + fixed zero-fill + fsync + retry remove.
        // Fixed-size zero buffer avoids the race where `meta.len()`
        // is read before a concurrent write grows the file.
        match std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(written)
        {
            Ok(mut f) => {
                // Write 64 KiB of zeros — comfortably larger than
                // any real auth.json. Errors are swallowed: this is
                // best-effort scrubbing.
                let zeros = [0u8; 64 * 1024];
                let _ = f.write_all(&zeros);
                let _ = f.flush();
                let _ = f.seek(SeekFrom::Start(0));
                let _ = f.sync_all();
            }
            Err(open_err) => {
                tracing::error!(
                    account = %account,
                    error_kind = "codex_desktop_login_raw_auth_json_truncate_failed",
                    context = context,
                    remove_error = %remove_err,
                    open_error = %open_err,
                    "failed to truncate raw auth.json after remove failure"
                );
            }
        }
        // Retry remove after the zero-write — the original
        // `remove_file` failure might have been transient
        // (e.g. EBUSY on a fresh fd).
        if let Err(second_remove_err) = std::fs::remove_file(written) {
            tracing::error!(
                account = %account,
                error_kind = "codex_desktop_login_raw_auth_json_remove_failed",
                context = context,
                first_error = %remove_err,
                second_error = %second_remove_err,
                "failed to remove raw auth.json after zero-fill fallback; \
                 content is zeroed but inode still present"
            );
        }
    }
}

/// Codex desktop-login `profiles.json` hook.
///
/// **F-C-2 fix (RN1-E):** WBS M8 converted the CLI twin
/// (`login.rs::update_profile`) from a no-op to a real
/// `by_slot_identity` write, but the desktop twin was missed.  This
/// function is now the canonical desktop hook — it mirrors the CLI twin
/// exactly.  Every successful desktop Codex login writes
/// `by_slot_identity[N] = label` so `get_email(N)` step 1.5 resolves
/// the slot identity for dashboards, statusline, and `csq doctor`.
///
/// ## Idempotency
///
/// Delegated to `set_slot_identity`: if `by_slot_identity[N]` already
/// equals `label`, the function returns `Ok(())` without touching disk.
fn update_profile(
    base_dir: &Path,
    account: AccountNum,
    label: &str,
) -> std::result::Result<(), crate::error::ConfigError> {
    let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir)?;
    crate::accounts::profiles::set_slot_identity(&lock, base_dir, account.get(), label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// M4-12: insert `profiles.json::by_slot[account] = fixture_uuid_for_slot(account)`
    /// so that `save_canonical_for` (now fail-closed) can resolve the UUID-keyed write
    /// path for the given slot. Must be called before any `complete_login` invocation.
    fn provision_uuid_for_account(base: &std::path::Path, account: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(account.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
    }

    #[cfg(unix)]
    fn fake_success() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(unix)]
    fn fake_failure() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(1 << 8)
    }

    #[cfg(windows)]
    fn fake_success() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn fake_failure() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(1)
    }

    fn stub_codex_auth_json(config_dir: &Path, account_id: &str) {
        let body = serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "account_id": account_id,
                "access_token": "eyJhbGciOiJIUzI1NiJ9.test-at.sig",
                "refresh_token": "rt_test",
                "id_token": "eyJhbGciOiJIUzI1NiJ9.test-id.sig",
            },
            "last_refresh": "2026-04-22T00:00:00Z",
        });
        std::fs::write(
            config_dir.join("auth.json"),
            serde_json::to_string_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    // ── start_login ────────────────────────────────────────────

    #[test]
    fn start_login_requires_tos_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        let view = start_login(dir.path(), acc(2), || ProbeResult::Absent).unwrap();
        assert!(view.tos_required);
        assert_eq!(view.keychain, "absent");
        assert!(!view.awaiting_keychain_decision);
    }

    #[test]
    fn start_login_does_not_require_tos_when_acknowledged() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();
        let view = start_login(dir.path(), acc(2), || ProbeResult::Absent).unwrap();
        assert!(!view.tos_required);
    }

    #[test]
    fn start_login_surfaces_keychain_present_and_decision_required() {
        let dir = TempDir::new().unwrap();
        let view = start_login(dir.path(), acc(3), || ProbeResult::Present).unwrap();
        assert_eq!(view.keychain, "present");
        assert!(view.awaiting_keychain_decision);
    }

    #[test]
    fn start_login_maps_all_probe_variants() {
        let dir = TempDir::new().unwrap();
        for (probe, expected) in [
            (ProbeResult::Absent, "absent"),
            (ProbeResult::Present, "present"),
            (ProbeResult::Unsupported, "unsupported"),
            (ProbeResult::ProbeFailed, "probe_failed"),
        ] {
            let view = start_login(dir.path(), acc(4), || probe).unwrap();
            assert_eq!(view.keychain, expected);
        }
    }

    #[test]
    fn start_login_rejects_missing_base_dir() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");
        let err = start_login(&missing, acc(1), || ProbeResult::Absent).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    // ── complete_login ─────────────────────────────────────────

    #[test]
    fn complete_login_rejects_without_tos_acknowledgement() {
        let dir = TempDir::new().unwrap();
        let err = complete_login(
            dir.path(),
            acc(2),
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("terms-of-service"));
    }

    #[test]
    fn complete_login_success_path_writes_canonical_and_profile() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(dir.path(), 3);

        let purge_called = std::cell::Cell::new(false);
        let view = complete_login(
            dir.path(),
            acc(3),
            false,
            || {
                purge_called.set(true);
                Ok(false)
            },
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "acct-uuid-xyz");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(view.account, 3);
        assert_eq!(view.label, "codex-3/acct");
        assert!(!purge_called.get(), "no purge when purge_keychain=false");
        // M4-12: numeric path `credentials/codex-3.json` is retired as a write
        // destination. Assert the UUID-keyed identity path instead.
        let uuid3 = crate::testing::identity_fixtures::fixture_uuid_for_slot(3);
        let uuid_path3 =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid3);
        assert!(
            uuid_path3.exists(),
            "M4-12: identities/<UUID>/credentials-codex.json must exist; path: {uuid_path3:?}"
        );
        assert!(
            !dir.path().join("credentials/codex-3.json").exists(),
            "M4-12: numeric credentials/codex-3.json must NOT be written post-M4-12"
        );
        // M3-7: config-N/codex-auth.json live mirror is retired (OQ #3 — Codex
        // handle dirs symlink auth.json to identities/<UUID>/credentials-codex.json
        // post-M3-3/M3-4). Desktop Codex login no longer materializes the mirror.
        assert!(
            !dir.path().join("config-3/codex-auth.json").exists(),
            "M3-7: config-N/codex-auth.json mirror MUST NOT be written"
        );
        assert!(dir.path().join("config-3/.csq-account").exists());
        assert!(dir.path().join("config-3/codex-sessions").is_dir());
    }

    /// Regression for the desktop codex re-auth write failure (slot 12):
    /// a codex-only slot has NO `by_slot[N]` UUID mapping (daemon Pass 0 skips
    /// codex-only slots), and `save_canonical_for` is fail-closed without one.
    /// `complete_login` MUST mint the UUID itself (mirroring the CLI path) — it
    /// previously did not, surfacing "could not write credentials/codex-N.json
    /// — check permissions". This test does NOT pre-provision the UUID, so it
    /// fails on the pre-fix code and passes once the mint is wired.
    #[test]
    fn complete_login_mints_uuid_for_codex_only_slot_without_preprovision() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();
        // Deliberately NO provision_uuid_for_account — this is the codex-only
        // slot scenario the desktop re-auth hits.

        let view = complete_login(
            dir.path(),
            acc(12),
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "acct-codex-only");
                Ok(fake_success())
            },
            |_| {},
        )
        .expect("complete_login must mint the UUID and succeed for a codex-only slot");

        assert_eq!(view.account, 12);

        // (a) by_slot[12] mapping now exists (minted by complete_login).
        let uuid = crate::accounts::profiles::resolve_slot_to_uuid(dir.path(), 12)
            .expect("by_slot[12] UUID must exist after complete_login mints it");

        // (b) the UUID-keyed identity credential was written.
        let cred_path =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid);
        assert!(
            cred_path.exists(),
            "identities/<UUID>/credentials-codex.json must exist post-mint; path: {cred_path:?}"
        );

        // (c) the retired numeric mirror is NOT written.
        assert!(
            !dir.path().join("credentials/codex-12.json").exists(),
            "retired numeric credentials/codex-12.json must NOT be written"
        );
    }

    #[test]
    fn complete_login_purges_keychain_when_flag_true() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(dir.path(), 4);

        let purge_called = std::cell::Cell::new(false);
        complete_login(
            dir.path(),
            acc(4),
            true,
            || {
                purge_called.set(true);
                Ok(true)
            },
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        assert!(purge_called.get());
    }

    #[test]
    fn complete_login_honors_purge_failure() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let err = complete_login(
            dir.path(),
            acc(5),
            true,
            || Err("security barked".into()),
            |_, _| panic!("must not spawn after purge failure"),
            |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("could not purge"));
    }

    #[test]
    fn complete_login_bubbles_spawn_nonzero_exit() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let err = complete_login(
            dir.path(),
            acc(6),
            false,
            || Ok(false),
            |_, _| Ok(fake_failure()),
            |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn complete_login_forwards_device_code_from_spawn() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(dir.path(), 7);

        let emitted: RefCell<Vec<DeviceCodeInfo>> = RefCell::new(Vec::new());
        complete_login(
            dir.path(),
            acc(7),
            false,
            || Ok(false),
            |config_dir, on_code| {
                on_code(DeviceCodeInfo {
                    user_code: "ABCD-EFGH".into(),
                    verification_url: "https://chat.openai.com/codex/verify?user_code=ABCD-EFGH"
                        .into(),
                });
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |info| emitted.borrow_mut().push(info),
        )
        .unwrap();

        let calls = emitted.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].user_code, "ABCD-EFGH");
        assert!(calls[0].verification_url.contains("chat.openai.com"));
    }

    #[test]
    fn complete_login_writes_config_toml_before_spawn() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(dir.path(), 8);

        let observed = std::cell::Cell::new(false);
        complete_login(
            dir.path(),
            acc(8),
            false,
            || Ok(false),
            |config_dir, _| {
                let toml = config_dir.join("config.toml");
                assert!(toml.exists(), "config.toml MUST exist before codex runs");
                let body = std::fs::read_to_string(&toml).unwrap();
                assert!(body.contains("cli_auth_credentials_store = \"file\""));
                observed.set(true);
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        assert!(observed.get());
    }

    #[test]
    fn complete_login_redacts_malformed_auth_json_tokens() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let err = complete_login(
            dir.path(),
            acc(9),
            false,
            || Ok(false),
            |config_dir, _| {
                let poisoned = r#"{
                    "auth_mode": "chatgpt",
                    "tokens": "rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }"#;
                std::fs::write(config_dir.join("auth.json"), poisoned).unwrap();
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            !chain.contains("rt_AAAA"),
            "error chain must not echo token fragments: {chain}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn complete_login_canonical_is_mode_0400() {
        // M4-12: the UUID-keyed `identities/<UUID>/credentials-codex.json` is written
        // at 0o600 (secure_file). The 0o400 flip on the numeric
        // `credentials/codex-<N>.json` is retired alongside the numeric write path.
        // Test updated to assert 0o600 on the UUID-keyed path.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(dir.path(), 11);

        complete_login(
            dir.path(),
            acc(11),
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        let uuid11 = crate::testing::identity_fixtures::fixture_uuid_for_slot(11);
        let uuid_path =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid11);
        let mode = std::fs::metadata(&uuid_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "M4-12: UUID-keyed codex canonical must be at 0o600 (numeric 0o400 flip retired)"
        );
        assert!(
            !dir.path().join("credentials/codex-11.json").exists(),
            "M4-12: numeric credentials/codex-11.json must NOT be written post-M4-12"
        );
    }

    // ── parse_device_code_line ─────────────────────────────────

    /// codex-cli 0.128.0 wire shape: URL on its own line, code on its
    /// own line, separated by an instructional banner. `parse_device_code_line`
    /// returns None per line; the accumulator MUST emit when the
    /// second half is observed.
    #[test]
    fn accumulator_pairs_url_then_code_across_lines() {
        let mut acc = DeviceCodeAccumulator::new();
        let lines = [
            "Welcome to Codex [v0.128.0]",
            "Follow these steps to sign in with ChatGPT using device code authorization:",
            "1. Open this link in your browser and sign in to your account",
            "   https://auth.openai.com/codex/device",
            "",
            "2. Enter this one-time code (expires in 15 minutes)",
            "   PDZD-0XC93",
            "Device codes are a common phishing target. Never share this code.",
        ];
        let mut emitted = None;
        for line in lines {
            if let Some(info) = acc.observe(line) {
                emitted = Some(info);
                break;
            }
        }
        let info = emitted.expect("accumulator never paired URL + code");
        assert_eq!(info.user_code, "PDZD-0XC93");
        assert_eq!(
            info.verification_url,
            "https://auth.openai.com/codex/device"
        );
    }

    /// Reverse order — code first, then URL — also works (codex-cli
    /// could in theory swap the line ordering on a future version).
    #[test]
    fn accumulator_pairs_code_then_url_across_lines() {
        let mut acc = DeviceCodeAccumulator::new();
        assert!(acc.observe("   PDZD-0XC93").is_none());
        let info = acc
            .observe("   https://auth.openai.com/codex/device")
            .expect("expected emission");
        assert_eq!(info.user_code, "PDZD-0XC93");
        assert_eq!(
            info.verification_url,
            "https://auth.openai.com/codex/device"
        );
    }

    /// Same-line shape (legacy codex-cli) MUST still emit immediately.
    #[test]
    fn accumulator_preserves_same_line_shortcut() {
        let mut acc = DeviceCodeAccumulator::new();
        let info = acc
            .observe("Go to https://auth.openai.com/codex/device and enter ABCD-1234")
            .expect("same-line shortcut failed");
        assert_eq!(info.user_code, "ABCD-1234");
    }

    /// Off-allowlist host must NOT match — defense against codex-cli
    /// printing a phishing URL alongside a real code.
    #[test]
    fn accumulator_rejects_off_allowlist_host() {
        let mut acc = DeviceCodeAccumulator::new();
        assert!(acc
            .observe("   https://evil.example.com/codex/device")
            .is_none());
        // No URL stored → bare code line cannot pair → still None.
        assert!(acc.observe("   PDZD-0XC93").is_none());
    }

    /// Userinfo phishing — `https://auth.openai.com@evil/...` — MUST
    /// be rejected. The `@` makes `evil` the actual host.
    #[test]
    fn accumulator_rejects_userinfo_phishing() {
        let mut acc = DeviceCodeAccumulator::new();
        assert!(acc
            .observe("   https://auth.openai.com@evil.example.com/codex/device")
            .is_none());
    }

    /// Path without `/device` substring is not a device-auth URL —
    /// e.g. an auth-success redirect that happens to be on
    /// `auth.openai.com`.
    #[test]
    fn accumulator_rejects_non_device_path() {
        let mut acc = DeviceCodeAccumulator::new();
        assert!(acc
            .observe("   https://auth.openai.com/codex/login/done")
            .is_none());
    }

    /// `saw_url` defaults to `false` — a fresh accumulator that has
    /// observed nothing must report no URL seen.
    #[test]
    fn accumulator_saw_url_starts_false() {
        let acc = DeviceCodeAccumulator::new();
        assert!(!acc.saw_url());
    }

    /// `saw_url` flips to `true` the first time the URL extractor
    /// finds a verification URL, even if no code has paired yet. This
    /// is the signal `spawn_codex_device_auth_piped` uses to detect
    /// the "URL emitted but no recognised code shape" failure mode
    /// (e.g. OpenAI bumps the device-code length past 4-{4..=5}).
    #[test]
    fn accumulator_saw_url_set_after_solo_url_line() {
        let mut acc = DeviceCodeAccumulator::new();
        let line = "   https://auth.openai.com/codex/device";
        let info = acc.observe(line);
        // No code on this line, so no DeviceCodeInfo.
        assert!(info.is_none());
        assert!(
            acc.saw_url(),
            "saw_url must flip true after URL line even without a code"
        );
    }

    /// `saw_url` stays `false` while the accumulator is fed only
    /// code-shaped lines without a matching URL line — the failure
    /// shape this distinguishes is "URL phase reached, code phase
    /// failed", not "code phase only".
    #[test]
    fn accumulator_saw_url_stays_false_for_code_only_input() {
        let mut acc = DeviceCodeAccumulator::new();
        let _ = acc.observe("   ABCD-EFGH");
        assert!(
            !acc.saw_url(),
            "saw_url must remain false when only code-shaped tokens arrive"
        );
    }

    /// `saw_url` persists after a successful pair so the post-spawn
    /// diagnostic check can still tell whether the URL stage was
    /// reached. (Without this, a successful login would leave
    /// `saw_url` false and the diagnostic would mis-classify a
    /// later-stage failure.)
    #[test]
    fn accumulator_saw_url_persists_after_successful_pair() {
        let mut acc = DeviceCodeAccumulator::new();
        let _ = acc.observe("   https://auth.openai.com/codex/device");
        let pair = acc.observe("   ABCD-EFGH");
        assert!(pair.is_some(), "URL+code across lines must pair");
        assert!(
            acc.saw_url(),
            "saw_url must remain true after the pair is consumed"
        );
    }

    /// Same-line shape (`parse_device_code_line` short-circuit) MUST
    /// also set `saw_url` — otherwise legacy codex-cli output that
    /// pairs URL+code on one line would leave `saw_url` false even
    /// though the URL was clearly observed.
    #[test]
    fn accumulator_saw_url_set_after_same_line_url_and_code() {
        let mut acc = DeviceCodeAccumulator::new();
        let info =
            acc.observe("Visit https://auth.openai.com/codex/device and enter the code: ABCD-EFGH");
        assert!(info.is_some(), "same-line shape must pair");
        assert!(
            acc.saw_url(),
            "saw_url must flip true via the same-line shortcut"
        );
    }

    #[test]
    fn parse_device_code_line_extracts_url_and_code() {
        let line = "Go to https://chatgpt.com/codex/verify?user_code=ABCD-EFGH and enter ABCD-EFGH";
        let info = parse_device_code_line(line).unwrap();
        assert_eq!(info.user_code, "ABCD-EFGH");
        assert!(info.verification_url.contains("chatgpt.com"));
    }

    #[test]
    fn parse_device_code_line_ignores_lines_without_url() {
        assert!(parse_device_code_line("Waiting for user…").is_none());
        assert!(parse_device_code_line("Code: ABCD-EFGH").is_none());
    }

    #[test]
    fn parse_device_code_line_rejects_lowercase_codes() {
        let line = "Visit https://example.com with code abcd-efgh";
        // All-lowercase is not a device-code shape per
        // is_device_code_shape (uppercase/digits only).
        assert!(parse_device_code_line(line).is_none());
    }

    /// an internal journal entry finding M1: narrow `is_device_code_shape` to
    /// exactly `XXXX-XXXX`. The prior 6-16-char predicate would
    /// match routine stderr tokens like `NOTICE`, `WARNING`,
    /// `FATAL7`, `ID-ABCDE`. This test pins the refusal.
    #[test]
    fn parse_device_code_line_rejects_help_output_shapes() {
        // URL + a mixed-case status word — would have matched the
        // pre-fix 6-16 predicate for `FATAL7`, `NOTICE`.
        assert!(parse_device_code_line("See https://foo NOTICE: connection").is_none());
        assert!(parse_device_code_line("https://foo WARNING please").is_none());
        assert!(parse_device_code_line("https://foo FATAL7").is_none());
        // An ID-like token with a dash but wrong segment lengths.
        assert!(parse_device_code_line("Visit https://foo code ID-ABCDE").is_none());
        // No dash.
        assert!(parse_device_code_line("https://foo ABCDEFGH").is_none());
        // Dash in the wrong position.
        assert!(parse_device_code_line("https://foo AB-CDEFGH").is_none());
        // Too long.
        assert!(parse_device_code_line("https://foo ABCDE-FGHIJ").is_none());
    }

    #[test]
    fn is_device_code_shape_accepts_exactly_xxxx_dash_xxxx() {
        assert!(is_device_code_shape("ABCD-EFGH"));
        assert!(is_device_code_shape("1234-5678"));
        assert!(is_device_code_shape("A1B2-C3D4"));
    }

    #[test]
    fn is_device_code_shape_rejects_anything_else() {
        assert!(!is_device_code_shape(""));
        assert!(!is_device_code_shape("ABCD"));
        assert!(!is_device_code_shape("ABCD-"));
        assert!(!is_device_code_shape("-EFGH"));
        assert!(!is_device_code_shape("ABCD-EFG"));
        assert!(!is_device_code_shape("ABCDE-FGHI"));
        assert!(!is_device_code_shape("ABCD_EFGH"));
        assert!(!is_device_code_shape("abcd-efgh"));
        assert!(!is_device_code_shape("ABCD-EFGH-IJKL"));
        // 4-6 (11 chars) is outside the accepted 4-{4..=5} range.
        assert!(!is_device_code_shape("ABCD-EFGHIJ"));
    }

    /// codex-cli 0.128.0 emits 4-5 codes (`PDZD-0XC93`). Pin acceptance.
    #[test]
    fn is_device_code_shape_accepts_4_5_split() {
        assert!(is_device_code_shape("PDZD-0XC93"));
        assert!(is_device_code_shape("ABCD-EFGHI"));
    }

    #[test]
    fn parse_device_code_line_tolerates_trailing_punctuation_on_url() {
        let line = "See https://chatgpt.com/codex/verify, then enter ABCD-EFGH.";
        let info = parse_device_code_line(line).unwrap();
        assert!(!info.verification_url.ends_with(','));
        assert_eq!(info.user_code, "ABCD-EFGH");
    }

    /// Same-line shortcut MUST inherit the host allowlist. An
    /// off-allowlist URL bundled on the same line as a code-shape
    /// token would otherwise be returned via the shortcut while
    /// `DeviceCodeAccumulator`'s cross-line path (which routes
    /// through `extract_device_auth_url`) correctly rejected it.
    /// Origin: redteam follow-up to PRs #335-#337.
    #[test]
    fn parse_device_code_line_rejects_off_allowlist_url() {
        let line = "Visit https://evil.example.com/codex/device and enter ABCD-EFGH";
        assert!(parse_device_code_line(line).is_none());
    }

    /// Same-line shortcut MUST reject `http://` URLs even when host
    /// would be on the allowlist — the device flow is HTTPS-only.
    #[test]
    fn parse_device_code_line_rejects_http_url() {
        let line = "Visit http://chat.openai.com/codex/verify and enter ABCD-EFGH";
        assert!(parse_device_code_line(line).is_none());
    }

    /// Same-line shortcut MUST reject userinfo phishing.
    #[test]
    fn parse_device_code_line_rejects_userinfo_phishing() {
        let line = "Visit https://chat.openai.com@evil.example.com/codex/verify ABCD-EFGH";
        assert!(parse_device_code_line(line).is_none());
    }

    // ── R4 scrub regression (an internal journal entry finding 15) ─────────

    /// If `save_canonical_for` fails AFTER codex has written
    /// `auth.json`, the raw auth.json MUST be removed before the
    /// error returns. Otherwise live access+refresh tokens sit on
    /// disk between the failed attempt and the next retry.
    ///
    /// We simulate save failure by making the `credentials/`
    /// identity-store tree read-only before the login runs. The spawn closure
    /// writes a stub auth.json; the per-identity write (UUID mint's identity.json
    /// or `save_canonical_for`'s credentials-codex.json under
    /// `identities/<UUID>/`) then fails on the read-only dir, and the scrub
    /// helper removes the raw auth.json before the Err returns.
    ///
    /// NOTE: post-M4-12 the credential write target is
    /// `identities/<UUID>/credentials-codex.json`, NOT the retired numeric
    /// `credentials/codex-N.json`. The mint (added so codex-only slots get a
    /// `by_slot` UUID) runs first and also writes under `identities/`, so a
    /// read-only `identities/` exercises the persist-failure scrub branch
    /// regardless of which write trips first. The invariant under test — raw
    /// auth.json scrubbed + no token leak on failure (an internal journal entry finding 15) —
    /// holds for both the mint-failure and save-failure scrub branches.
    #[cfg(unix)]
    #[test]
    fn complete_login_scrubs_written_auth_json_when_identity_persist_fails() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // Pre-create identities/ read-only so the per-identity write under
        // identities/<UUID>/ (mint's identity.json or the codex credential)
        // fails to create the UUID subdir.
        let identities_dir = dir.path().join("identities");
        std::fs::create_dir_all(&identities_dir).unwrap();
        std::fs::set_permissions(
            &identities_dir,
            std::fs::Permissions::from_mode(0o500), // r-x, no write
        )
        .unwrap();

        let account = acc(21);
        let written = surface::written_auth_json_path(dir.path(), account);

        let result = complete_login(
            dir.path(),
            account,
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        );

        // Must return Err — the per-identity write fails on the read-only dir.
        assert!(
            result.is_err(),
            "expected Err when identities/ is read-only, got: {result:?}"
        );
        let err_msg = format!("{}", result.unwrap_err());
        // The outward-facing message is operator-readable and does
        // NOT echo tokens — the same guarantee we assert in
        // `complete_login_redacts_malformed_auth_json_tokens`.
        assert!(
            !err_msg.contains("rt_"),
            "no raw refresh prefix may appear in the error: {err_msg}"
        );

        // Restore permissions so TempDir cleanup works.
        std::fs::set_permissions(&identities_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Invariant: the raw auth.json that codex wrote MUST be
        // gone (R4 fix). Pre-fix this file would sit on disk at
        // whatever mode codex-cli wrote, with live tokens in it.
        assert!(
            !written.exists(),
            "raw auth.json at {} must be scrubbed after identity-persist failure \
             (an internal journal entry finding 15)",
            written.display()
        );
    }

    // ── extract_device_auth_url tests (moved from csq-cli/login.rs) ──────

    #[test]
    fn extract_device_auth_url_finds_codex_url_on_dedicated_line() {
        // codex-cli v0.128.0 output shape:
        let out = extract_device_auth_url("   https://auth.openai.com/codex/device");
        assert_eq!(out.as_deref(), Some("https://auth.openai.com/codex/device"));
    }

    #[test]
    fn extract_device_auth_url_finds_url_with_trailing_punctuation() {
        let out = extract_device_auth_url("Open this link: https://auth.openai.com/codex/device.");
        assert_eq!(out.as_deref(), Some("https://auth.openai.com/codex/device"));
    }

    #[test]
    fn extract_device_auth_url_skips_non_device_url() {
        // codex-cli emits help links + general OpenAI URLs that
        // should NOT trigger an auto-launch.
        assert!(extract_device_auth_url("Visit https://help.openai.com for more info").is_none());
        assert!(extract_device_auth_url("https://chatgpt.com/").is_none());
    }

    #[test]
    fn extract_device_auth_url_returns_none_on_lines_without_urls() {
        assert!(extract_device_auth_url("Enter this one-time code").is_none());
        assert!(extract_device_auth_url("NCYX-XQA48").is_none());
        assert!(extract_device_auth_url("").is_none());
    }

    // Round-1 redteam H1: userinfo-phishing rejection.
    // `https://auth.openai.com@evil.example.com/...` must NOT auto-launch
    // because browsers honor RFC 3986 userinfo and navigate to evil.com.
    #[test]
    fn extract_device_auth_url_rejects_userinfo_phishing() {
        assert!(
            extract_device_auth_url("https://auth.openai.com@evil.example.com/codex/device")
                .is_none(),
            "userinfo-phishing URL must not auto-launch"
        );
        assert!(
            extract_device_auth_url("https://user:pass@auth.openai.com/codex/device").is_none(),
            "userinfo with password must not auto-launch"
        );
    }

    // Round-1 redteam H2: off-allowlist host rejection.
    // Path-substring `/device` is not enough; host MUST be on the allowlist.
    #[test]
    fn extract_device_auth_url_rejects_off_allowlist_host() {
        assert!(
            extract_device_auth_url("https://evil.example.com/codex/device").is_none(),
            "off-allowlist host with /device path must not auto-launch"
        );
        assert!(
            extract_device_auth_url("https://api.openai.com/v1/foo/device/bar").is_none(),
            "even openai.com sibling subdomains must not auto-launch"
        );
        assert!(
            extract_device_auth_url("https://auth.openai.com.evil.com/codex/device").is_none(),
            "suffix-trick host must not auto-launch"
        );
    }

    // Round-1 redteam LOW: drop http:// support — device flow is HTTPS-only.
    #[test]
    fn extract_device_auth_url_rejects_http_scheme() {
        assert!(
            extract_device_auth_url("http://auth.openai.com/codex/device").is_none(),
            "http:// must not auto-launch"
        );
    }

    // Round-1 redteam LOW: case-insensitive scheme acceptance.
    #[test]
    fn extract_device_auth_url_accepts_case_insensitive_scheme() {
        let out = extract_device_auth_url("HTTPS://auth.openai.com/codex/device");
        assert_eq!(
            out.as_deref(),
            Some("HTTPS://auth.openai.com/codex/device"),
            "uppercase HTTPS:// must auto-launch (case-insensitive scheme per RFC 3986)"
        );
    }

    // Round-1 redteam M2: ANSI escape sequences must be stripped.
    // codex-cli ships with TTY-detected color by default; the auth URL
    // can be wrapped in `\x1b[...m...\x1b[0m`.
    #[test]
    fn extract_device_auth_url_strips_ansi_color_codes() {
        let line = "\u{1b}[36mhttps://auth.openai.com/codex/device\u{1b}[0m";
        let out = extract_device_auth_url(line);
        assert_eq!(
            out.as_deref(),
            Some("https://auth.openai.com/codex/device"),
            "ANSI-wrapped URL must be extracted after escape strip"
        );
    }

    // Round-1 redteam M2: bare CR (TTY redraw) must not glue to the URL.
    #[test]
    fn extract_device_auth_url_strips_carriage_returns() {
        let line = "https://auth.openai.com/codex/device\rprogress...";
        let out = extract_device_auth_url(line);
        assert_eq!(
            out.as_deref(),
            Some("https://auth.openai.com/codex/device"),
            "trailing CR must not corrupt the URL"
        );
    }

    // Round-1 redteam M3: with the host allowlist, two-URL-on-a-line is
    // safe regardless of order. Test both orderings to pin the contract.
    #[test]
    fn extract_device_auth_url_two_urls_picks_allowlisted() {
        let line = "https://evil.com/codex/device https://auth.openai.com/codex/device";
        // First URL is off-allowlist; helper falls through to second.
        assert_eq!(
            extract_device_auth_url(line).as_deref(),
            Some("https://auth.openai.com/codex/device"),
        );
        let line2 = "https://auth.openai.com/codex/device https://evil.com/codex/device";
        // First URL is allowlisted; first-match wins.
        assert_eq!(
            extract_device_auth_url(line2).as_deref(),
            Some("https://auth.openai.com/codex/device"),
        );
    }

    // Round-1 redteam M1: the call site uses
    // `parse_device_code_line(...).or_else(|| extract_device_auth_url(...))`
    // to handle BOTH the v0.40.x same-line shape AND the v0.41+
    // dedicated-line shape. This test exercises the orchestration so a
    // future refactor that drops one path fails loudly.
    #[test]
    fn extract_url_orchestration_handles_both_codex_shapes() {
        // Closure mirroring the cli call-site orchestration in
        // `csq-cli/src/commands/login.rs::handle_codex`.
        let try_extract_url = |line: &str| -> Option<String> {
            parse_device_code_line(line)
                .map(|info| info.verification_url.clone())
                .or_else(|| extract_device_auth_url(line))
        };
        // v0.40.x same-line shape (URL + code on one line).
        let v40 = "Visit https://auth.openai.com/codex/device and enter the code: ABCD-EFGH";
        let v40_url = try_extract_url(v40);
        assert!(
            v40_url.is_some(),
            "v0.40.x same-line shape must extract: {:?}",
            v40_url
        );
        // v0.41+ dedicated-line shape (URL on its own line).
        let v41 = "https://auth.openai.com/codex/device";
        let v41_url = try_extract_url(v41);
        assert_eq!(
            v41_url.as_deref(),
            Some("https://auth.openai.com/codex/device"),
            "v0.41+ dedicated-line shape must extract via fallback"
        );
        // Neither shape — both paths return None.
        let neither = "ABCD-EFGH";
        assert!(try_extract_url(neither).is_none());
    }

    #[test]
    fn strip_ansi_escapes_passes_through_plain_text() {
        assert_eq!(strip_ansi_escapes("plain text"), "plain text");
        assert_eq!(strip_ansi_escapes(""), "");
    }

    #[test]
    fn strip_ansi_escapes_drops_csi_sequences() {
        // CSI sequences: ESC [ ... <final byte 0x40..=0x7e>
        assert_eq!(strip_ansi_escapes("\u{1b}[31mred\u{1b}[0m"), "red");
        assert_eq!(strip_ansi_escapes("\u{1b}[1;36;7mfoo"), "foo");
    }

    #[test]
    fn strip_ansi_escapes_replaces_carriage_returns_with_spaces() {
        // Substitution preserves token boundaries — a CR-glued URL+text
        // pair like `<url>\r<progress>` must split cleanly under
        // `split_whitespace` after the strip pass.
        assert_eq!(strip_ansi_escapes("a\rb\rc"), "a b c");
    }

    /// M4-7 acceptance: the Codex desktop login (`complete_login`) emits
    /// the slot's identity UUID as the `.csq-account` marker content
    /// when `profiles.json::by_slot` carries a mapping. Filename
    /// `.csq-account` is unchanged per OQ #3.
    ///
    /// The acceptance name `claude_login_subprocess_writes_uuid_to_csq_account_marker`
    /// is preserved verbatim from the M4-7 WBS — naming reflects the
    /// shared shape of the Codex + Anthropic desktop subprocess-login
    /// flow (both shell out to a CLI binary and write the marker
    /// post-success).
    #[test]
    fn claude_login_subprocess_writes_uuid_to_csq_account_marker() {
        use crate::accounts::identity_store::IdentityId;
        use crate::accounts::profiles;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        tos::acknowledge(base).unwrap();

        // Seed profiles.json with a by_slot mapping for slot 4.
        let uuid = IdentityId::from_str("33333333-4444-5555-6666-777777777777").unwrap();
        let mut profiles_file = profiles::ProfilesFile::empty();
        profiles_file.by_slot.insert("4".to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &profiles_file).unwrap();

        let view = complete_login(
            base,
            acc(4),
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "acct-codex-desktop-m47");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(view.account, 4);

        let config_dir = base.join("config-4");
        assert_eq!(
            crate::accounts::markers::read_csq_account_uuid(&config_dir),
            Some(uuid),
            "M4-7: Codex desktop complete_login must write UUID content to \
             .csq-account when by_slot maps the slot"
        );
        assert_eq!(
            crate::accounts::markers::read_csq_account(&config_dir),
            None,
            "M4-7: numeric reader rejects UUID-content markers"
        );
    }

    /// F-C-2 regression: `complete_login` (desktop path) MUST write
    /// `by_slot_identity[N]` via `update_profile`.  The no-op form of
    /// `update_profile` that existed before the F-C-2 fix silently left
    /// the slot invisible to `get_email`, dashboards, statusline, and
    /// `csq doctor`.
    ///
    /// Mirrors `codex_finalize_login_writes_by_slot_identity` from the
    /// CLI login.rs test suite — same assert shape, desktop call path.
    #[test]
    fn desktop_codex_complete_login_writes_by_slot_identity() {
        use crate::accounts::profiles;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(5);

        // M4-12: provision UUID mapping so save_canonical_for can resolve
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 5);

        // TOS must be acknowledged for complete_login to proceed.
        crate::providers::codex::tos::acknowledge(base).unwrap();

        complete_login(
            base,
            account,
            false,
            || Ok(false),
            |config_dir, _| {
                // account_id "desktop-abc12345-long" → format_label strips to "desktop"
                // (first dash-block)
                stub_codex_auth_json(config_dir, "desktop-abc12345-long");
                Ok(fake_success())
            },
            |_| {},
        )
        .expect("complete_login should succeed");

        // Assert: by_slot_identity["5"] == "codex-5/desktop"
        let pf = profiles::load(&profiles::profiles_path(base))
            .expect("profiles.json must be readable after desktop codex login");
        assert_eq!(
            pf.by_slot_identity.get("5").map(|s| s.as_str()),
            Some("codex-5/desktop"),
            "F-C-2: by_slot_identity[\"5\"] must equal \"codex-5/desktop\" after desktop \
             codex login with account_id=\"desktop-abc12345-long\"; got: {:?}",
            pf.by_slot_identity.get("5")
        );
    }
}
