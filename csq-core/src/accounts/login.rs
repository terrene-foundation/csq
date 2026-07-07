//! Account login helpers shared between csq-cli and csq-desktop.
//!
//! - [`find_claude_binary`] locates the `claude` CLI from BOTH the
//!   inherited `$PATH` and a fixed list of well-known install
//!   directories. The well-known list matters because Finder-launched
//!   macOS apps (the desktop bundle) inherit only a minimal `PATH`
//!   (`/usr/bin:/bin:/usr/sbin:/sbin`) — the user's shell-installed
//!   `claude` (typically in `/usr/local/bin`, `/opt/homebrew/bin`, or
//!   `~/.npm-global/bin`) is invisible to plain `Command::new("claude")`.
//!   The desktop's `start_claude_login` Tauri command was disabled in
//!   alpha.5 (per an internal journal entry §2) precisely because of this PATH gap.
//!
//! - [`read_email_from_claude_json`] reads the OAuth account email
//!   that CC writes to `<config_dir>/.claude.json` after a successful
//!   `claude auth login`. Both `csq login N` and the desktop Add
//!   Account modal use this to populate the `profiles.json` entry.
//!
//! - [`finalize_login`] does the post-login bookkeeping shared by
//!   both code paths: writes the `.csq-account` marker, reads the
//!   email, updates `profiles.json`, clears the broker-failed flag.

use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::accounts::{markers, profiles};
use crate::credentials::{self, file as cred_file};
use crate::error::ConfigError;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

/// Returns the absolute path to the `claude` CLI binary, if
/// installed and executable.
///
/// Search order:
///  1. Walk `$PATH` (matches the legacy `which_claude` behaviour).
///  2. Walk a fixed list of well-known install directories that
///     survive a Finder launch (i.e. don't depend on the shell rc).
///  3. Walk `$HOME/<sub>` for common per-user install layouts
///     (`.local/bin`, `.npm-global/bin`, `.bun/bin`, `.cargo/bin`).
///
/// Returns `None` if no executable `claude` is found anywhere.
///
/// # Per-spawn resolution (R3/B87)
///
/// This function MUST NOT cache its result at startup or across
/// invocations. Every call must probe the filesystem fresh so that
/// `CSQ_BENCH_MODE=1` runs (which inject a temporary binary via
/// `CLAUDE_PATH`) always see the current value of `$PATH` at the
/// moment of the probe. Any `static` or `OnceLock` cache would
/// silently lock in the binary path from the first call and break
/// bench-mode PATH injection. This is the authoritative per-spawn
/// resolution site; no other site may cache the result.
pub fn find_claude_binary() -> Option<PathBuf> {
    // 1. $PATH walk.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if let Some(p) = check_dir(&dir) {
                return Some(p);
            }
        }
    }

    // 2. System-wide well-known locations.
    for sys_dir in SYSTEM_WIDE_DIRS {
        if let Some(p) = check_dir(Path::new(sys_dir)) {
            return Some(p);
        }
    }

    // 3. Per-user well-known locations under $HOME.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in PER_USER_SUBDIRS {
            if let Some(p) = check_dir(&home.join(sub)) {
                return Some(p);
            }
        }
    }

    None
}

/// Reads the OAuth account email out of `<config_dir>/.claude.json`.
///
/// CC writes `oauthAccount.emailAddress` to its local `.claude.json`
/// during `claude auth login`. This is a file-only read with no
/// subprocess and no race window — it's the preferred source over
/// `claude auth status --json`, which has a documented timing
/// window where stdout can lack `email` if csq runs it too soon
/// after auth completes (see an internal journal entry §1).
///
/// Returns `None` if the file is missing, malformed, or has no
/// non-empty `emailAddress` field. Callers should fall back to
/// `"unknown"` in that case rather than fail the whole login.
pub fn read_email_from_claude_json(config_dir: &Path) -> Option<String> {
    let path = config_dir.join(".claude.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let email = json
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(|v| v.as_str())?;
    if email.is_empty() {
        None
    } else {
        Some(email.to_string())
    }
}

/// Ensures the slot's identity UUID is minted into `profiles.json::by_slot`
/// BEFORE the canonical credential save (an internal ticket).
///
/// `credentials::file::save_canonical_for` is fail-closed on an absent UUID
/// (M4-12), but on a fresh install the UUID is only minted by `finalize_login`
/// — which runs AFTER `save_canonical_for` in both the CLI (`csq login`) and
/// desktop login flows — and on macOS the daemon Pass-0 fallback cannot mint
/// from a keychain-only credential (it reads `credentials/<N>.json`, never
/// written when creds go to the keychain). The result, pre-fix: the first
/// login on a fresh (especially macOS) install failed with "no credentials
/// configured". This helper closes the gap: it mints the UUID up front, using
/// the OAuth email `claude auth login` wrote to `config-N/.claude.json` — the
/// same source `finalize_login` uses, so the minted UUID + `by_email` key match
/// and `finalize_login`'s later `mint_for_login` is an idempotent no-op reuse.
///
/// No-ops (returns `Ok`) when the slot already has a UUID, or when the email is
/// unavailable (the caller's `save_canonical_for` then surfaces its own
/// fail-closed error rather than this helper inventing an identity). Holds
/// `ProfilesFileLock` across the re-check + mint to serialize against a
/// concurrent daemon Pass-0 / login mint.
pub fn ensure_login_identity_minted(base_dir: &Path, account: AccountNum) -> Result<(), String> {
    if crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()).is_some() {
        return Ok(());
    }
    let config_dir = base_dir.join(format!("config-{account}"));
    let Some(email) = read_email_from_claude_json(&config_dir) else {
        // No email source yet — do NOT invent an identity. The caller's
        // save_canonical_for will surface the genuine fail-closed error.
        return Ok(());
    };
    // Fixed-vocabulary error tag — NO path. ProfilesFileLock::acquire returns
    // ConfigError::InvalidJson whose Display embeds the `.profiles.lock` path
    // (discloses $HOME / OS username), and both callers surface this String to
    // operator stderr / IPC. redact_home_prefix is prefix-only and would NOT
    // strip a path embedded mid-message, so we drop the path entirely per
    // rules/operator-surface-verification.md Rule 6 + rules/security.md MUST-2.
    let lock = ProfilesFileLock::acquire(base_dir)
        .map_err(|_e| "could not acquire profiles lock for identity mint".to_string())?;
    // Re-check under the lock: a concurrent daemon Pass-0 / login may have
    // minted between the unlocked check above and acquiring the lock.
    if crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()).is_some() {
        return Ok(());
    }
    crate::daemon::identity_mint::mint_for_login(&lock, base_dir, account.get(), &email)
        .map(|_uuid| ())
}

/// Post-login bookkeeping shared by `csq login` and the desktop
/// Add Account flow.
///
/// 1. Writes the `.csq-account` marker for `account` inside its
///    `config-N/` directory (best-effort if the dir doesn't exist
///    yet — the canonical save in `credentials::save_canonical`
///    will create it).
/// 2. **Unbinds any third-party provider pinned to this slot.** If a
///    user ran `csq setkey mm --slot N` earlier (intentionally or by
///    accidentally submitting a junk key, an internal journal entry), slot N's
///    `settings.json` contains `ANTHROPIC_BASE_URL` +
///    `ANTHROPIC_AUTH_TOKEN` env vars that override OAuth
///    credentials at CC startup. Strip them here so the fresh OAuth
///    tokens actually route to Anthropic.
/// 3. Reads the OAuth email from `config-N/.claude.json` and
///    updates `profiles.json`. Falls back to `"unknown"` if the
///    email is missing — non-fatal because the credential file is
///    already written and CC can use the account.
/// 4. Clears the `broker_failed` sentinel for this account so the
///    daemon retries refresh on the next tick.
///
/// Errors are propagated only when the *bookkeeping* itself fails
/// (e.g. profiles.json save fails). The credential file is
/// authoritative — losing the profile entry is recoverable, losing
/// the credential file is not.
pub fn finalize_login(base_dir: &Path, account: AccountNum) -> Result<String, ConfigError> {
    let config_dir = base_dir.join(format!("config-{}", account));
    // M4-7 (an internal ticket Phase 4, spec 02 §INV-03 + §2.3.1): the
    // `.csq-account` marker is written AFTER `mint_for_login` below so
    // we can resolve the slot's identity UUID and emit it as the
    // marker content. For pure-legacy installs (mint deferred to
    // daemon Pass 0), the post-mint resolution falls through to
    // `write_csq_account_legacy` which preserves the decimal-content
    // contract until `phase4_gate_check` refuses pure-legacy. See the
    // marker write below the mint block.

    // Strip any pre-existing 3P binding. If this fails we let the
    // error propagate — we'd rather the user see "login cleanup
    // failed" than a silent-success followed by "my OAuth login
    // didn't take because the slot is still pinned to MiniMax".
    match crate::accounts::third_party::unbind_provider_from_slot(base_dir, account) {
        Ok(true) => {
            tracing::info!(
                account = account.get(),
                "finalize_login: stripped third-party provider binding"
            );
        }
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    let email = read_email_from_claude_json(&config_dir).unwrap_or_else(|| "unknown".to_string());

    // Acquire the profiles.json lock BEFORE the load+save cycle.
    //
    // This lock is held across BOTH steps:
    //   1. profiles::save  — writes the AccountProfile row.
    //   2. mint_for_login  — writes the by_slot/by_email UUID mappings.
    //
    // Holding the lock across both steps makes the two-write sequence atomic
    // from a cross-process perspective. Without the lock, a concurrent daemon
    // Pass 0 could interleave its own load between these two writes and
    // clobber the profile row or the UUID mapping. (A-HIGH-1 fix, round 1.5.)
    //
    // Error path: if we cannot acquire the lock, fail the entire finalize_login.
    // The credential file is already written; the profile row failure is
    // recoverable by the next login or daemon Pass 0, but we should surface it.
    let profiles_lock = ProfilesFileLock::acquire(base_dir)?;

    // F-H-1 fix: clear any stale `by_slot_identity[N]` left from a prior
    // non-OAuth binding (3P API-key or Codex) on this slot.  Without this
    // cleanup `get_email`'s step 1.5 returns `"apikey:<provider>"` instead
    // of the OAuth email resolved via step 3, making the newly-logged-in
    // slot misidentified.
    //
    // Non-fatal: the credential file is already written.  A failure here is
    // logged and skipped; the next daemon reconciler pass can prune the stale
    // entry when the information-preserving arm-4 predicate no longer fires.
    match profiles::clear_slot_identity(&profiles_lock, base_dir, account.get()) {
        Ok(()) => {
            tracing::debug!(
                account = account.get(),
                "finalize_login: cleared stale by_slot_identity (if any)"
            );
        }
        Err(e) => {
            tracing::warn!(
                account = account.get(),
                error_kind = "clear_slot_identity_failed",
                "finalize_login: could not clear by_slot_identity (non-fatal): {e}"
            );
        }
    }

    // M4-9 (release N affordance, an internal ticket Phase 4): the v1
    // `profiles.accounts` field is empty-write in production. The email
    // is captured in `profiles.json::by_email` by `mint_for_login`
    // below — that is the post-M4-9 source of truth for the slot's
    // display label, resolved via `ProfilesFile::get_email`'s primary
    // `by_slot → UUID → by_email` reverse lookup.
    //
    // The v1 `accounts` field stays as `HashMap<String, AccountProfile>`
    // for release N (serializes as `accounts: {}`) so the v2.6.x
    // forward-compat round-trip (M1-2 regression test) still holds.
    // M4-13 (release N+1) deletes the field after the v2.6.x downgrade
    // window closes.
    //
    // The load+save cycle that previously seeded the slot's AccountProfile
    // row is retired. The subsequent `mint_for_login` call performs its
    // own load+save under the SAME `profiles_lock` held here, writing
    // `by_slot[N] = uuid` + `by_email[email] = uuid`.

    // A++ Phase 1 (M1-4): attempt per-login identity mint for this slot.
    // Non-fatal: if minting fails (e.g. partial upgrade, no identities/ dir
    // yet) we log and continue — the daemon's startup Pass 0 handles bulk
    // minting on the next start. The email is already available here.
    //
    // The profiles_lock is passed as a type-witness to mint_for_login,
    // documenting that the caller (us) already holds the lock. This prevents
    // accidental re-acquisition inside mint_for_login (which would deadlock
    // on some platforms).
    //
    // Skip if email is "unknown" — we can't establish a stable by_email key.
    if email != "unknown" {
        match crate::daemon::identity_mint::mint_for_login(
            &profiles_lock,
            base_dir,
            account.get(),
            &email,
        ) {
            Ok(_) => {
                tracing::debug!(
                    account = account.get(),
                    "finalize_login: identity mint hook succeeded"
                );
            }
            Err(reason) => {
                // All Err(reason) strings from mint_for_login are fixed-vocabulary
                // static literals (see identity_mint.rs) — no PII, safe to log.
                tracing::warn!(
                    account = account.get(),
                    error_kind = "identity_mint_failed",
                    reason = %reason,
                    "finalize_login: identity mint hook failed (non-fatal)"
                );
            }
        }
    }

    // M4-7: write the `.csq-account` marker now that `mint_for_login` has
    // run. If a UUID mapping exists in `profiles.json::by_slot`, write the
    // canonical UUID-v4 string; otherwise (pure-legacy install where mint
    // failed or was skipped), fall back to the decimal slot id via
    // `write_csq_account_legacy` so the M1-5 reader still surfaces the
    // numeric account.
    //
    // Best-effort: the marker write is non-fatal because the credential
    // file is already authoritative and the daemon's next sweep can
    // re-seed the marker. Failures are logged with a fixed-vocabulary tag.
    if config_dir.exists() {
        match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
            Some(uuid) => {
                if let Err(e) = markers::write_csq_account(&config_dir, uuid) {
                    tracing::warn!(
                        account = account.get(),
                        error_kind = "csq_account_marker_uuid_write_failed",
                        "finalize_login: could not write UUID marker (non-fatal)"
                    );
                    let _ = e;
                }
            }
            None => {
                if let Err(e) = markers::write_csq_account_legacy(&config_dir, account) {
                    tracing::warn!(
                        account = account.get(),
                        error_kind = "csq_account_marker_legacy_write_failed",
                        "finalize_login: could not write legacy decimal marker (non-fatal)"
                    );
                    let _ = e;
                }
            }
        }
    }

    // M4-2: explicit settings.json pair-write — mirror `config-<N>/settings.json`
    // into `identities/<UUID>/settings.json` byte-equivalent.
    //
    // `mint_for_login` seeds the UUID settings file ONLY when it is absent
    // (idempotent seed). That covers fresh logins but NOT re-logins where
    // a stale UUID settings.json from a prior session must be refreshed to
    // match the legacy `config-<N>/settings.json` written by 3P bind/unbind
    // (which `unbind_provider_from_slot` above just ran).
    //
    // The pair is intentionally byte-equivalent — the WBS acceptance criterion
    // for M4-2 is "finalize_login writes identities/<UUID>/settings.json
    // byte-equivalent to config-<N>/settings.json". A merged / transformed copy
    // would break downstream readers that expect identical content at both
    // paths during the M4-2 → M4-5 transition window.
    //
    // Non-fatal: settings pairing failure does not block login. The credential
    // write above is authoritative; the settings overlay is a per-slot 3P env
    // mirror that the daemon's next pass can rebuild from `config-<N>/`.
    if let Some(uuid) = profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        let config_settings_path = config_dir.join("settings.json");
        if config_settings_path.exists() {
            match std::fs::read(&config_settings_path) {
                Ok(bytes) => {
                    if let Err(e) = credentials::save_uuid_settings(base_dir, uuid, &bytes) {
                        tracing::warn!(
                            account = account.get(),
                            error_kind = "uuid_settings_pair_failed",
                            "finalize_login: could not pair UUID settings.json (non-fatal): \
                             daemon backsync will retry"
                        );
                        let _ = e;
                    } else {
                        tracing::debug!(
                            account = account.get(),
                            "finalize_login: UUID settings paired from config-N/settings.json"
                        );
                    }
                }
                Err(_) => {
                    // Settings file unreadable (race with concurrent setkey?) — skip.
                    tracing::debug!(
                        account = account.get(),
                        "finalize_login: config-N/settings.json unreadable; UUID pair deferred"
                    );
                }
            }
        }
    }

    // HIGH-2 (M2-2 redteam): seed identities/<UUID>/credentials.json immediately
    // after mint succeeds, while still holding the ProfilesFileLock — a fresh
    // login that did NOT pre-seed the store (legacy callers, or a UUID minted
    // for the first time just above) otherwise leaves credentials.json missing
    // until the daemon's first refresh tick, and csq doctor reports
    // MissingCredentialsAtUuidPath on every freshly-logged-in slot.
    //
    // **The freshness guard (config-N login-overwrite fix, 2026-06-24).** The
    // `live_path` read here (`config-N/.credentials.json`) was, pre-keychain-CC,
    // the freshest token: the `claude auth login` subprocess wrote its OAuth
    // payload there before csq's post-subprocess hook ran. That assumption is
    // no longer reliable — modern keychain-first CC commits the fresh token to
    // the macOS keychain and may leave `config-N/.credentials.json` STALE or
    // absent (empirically observed: refreshed daemon stores while config-N sat
    // weeks behind). EVERY production caller of finalize_login now pre-seeds the
    // store with the freshest token the flow produced BEFORE calling us — the
    // subprocess flows via `read_fresh_after_login` (keychain ∪ config-N, later
    // `expiresAt` wins) and the paste/race flows via `oauth::exchange_code`
    // (which never writes config-N) → `save_canonical_for` — so the store is
    // already ≥ config-N here. An UNCONDITIONAL re-seed from config-N (the prior
    // `save_canonical_for` call) therefore REGRESSED the store back to a
    // stale/rotated-dead token, 401-ing every session of the account.
    //
    // Fix: route the re-seed through `save_canonical_for_if_fresher`, which
    // re-reads the store expiry UNDER the write lock and writes config-N's token
    // ONLY when it is strictly fresher (fail-closed — Ok(false), no write — on a
    // non-Anthropic/corrupt store). The seed is now MONOTONIC: it can advance a
    // store that a non-pre-seeding caller left empty/older (the HIGH-2 safety
    // net), but it can NEVER regress the fresh token a pre-seeding caller already
    // wrote. On the happy path (store already holds the caller's fresh token) it
    // cleanly no-ops. `min_expiry_exclusive = 0` because we carry no harvested
    // baseline; the under-lock store re-read is the SOLE guard for this caller.
    //
    // Scope of the guard: this is a FRESHNESS guard, not an IDENTITY guard.
    // config-N is per-slot-path-keyed (`config-<N>/.credentials.json`), so under
    // the same-account threat model it cannot carry a FOREIGN account's token —
    // unlike the keychain custodian, whose harvest source is account-anonymous
    // and so carries an explicit same-account email gate. The residual the
    // monotonic guard does NOT cover is shared with `read_fresh_after_login`:
    // `expiresAt` is a recency proxy, not a chain-liveness proof, so a
    // dead-but-later-expiry token could in principle be selected upstream. That
    // is a pre-existing limitation of expiry-based selection (post_login.rs),
    // not introduced here; `if_fresher` is strictly more conservative than the
    // unconditional write it replaces.
    //
    // Non-fatal: if the live creds are missing (e.g. CC wrote only the keychain)
    // we log and skip; the caller's pre-seed already populated the store.
    let live_path = cred_file::live_path(base_dir, account);
    match credentials::load(&live_path) {
        Ok(live_creds) => {
            // RN1-C (M4-12): the UUID-keyed write is fail-closed — an absent
            // by_slot mapping yields Err(NoCredentials).
            //
            // Propagation policy (unchanged by the freshness guard):
            // - When by_slot IS populated (mint succeeded above), an Err MUST be
            //   propagated fail-closed: the caller sees "login bookkeeping failed"
            //   rather than Ok(email) while no UUID-keyed credential file exists.
            //   broker_check reads the UUID path — a missing UUID credentials.json
            //   means LOGIN_REQUIRED on the very next daemon tick.
            // - When by_slot is NOT populated (legacy/pure-legacy install,
            //   email="unknown" so mint was skipped), Err(NoCredentials) is
            //   "non-fatal": broker_check falls back to the numeric path for
            //   legacy accounts. Preserve the non-fatal behaviour for this case.
            //
            // Ok(true) = config-N was strictly fresher and was written;
            // Ok(false) = the store already held an at-or-fresher token (the
            // pre-seed, a daemon refresh) OR the store was non-Anthropic/corrupt
            // (fail-closed) — either way the seed is correctly a no-op.
            let uuid_populated = profiles::resolve_slot_to_uuid(base_dir, account.get()).is_some();
            // No harvested baseline at this callsite: the under-lock store re-read
            // inside `save_canonical_for_if_fresher` is the sole TOCTOU guard.
            const NO_HARVEST_BASELINE: u64 = 0;
            match cred_file::save_canonical_for_if_fresher(
                base_dir,
                account,
                &live_creds,
                NO_HARVEST_BASELINE,
            ) {
                Ok(true) => {
                    tracing::debug!(
                        account = account.get(),
                        "finalize_login: UUID credentials seeded from live (config-N was fresher)"
                    );
                }
                Ok(false) => {
                    tracing::debug!(
                        account = account.get(),
                        "finalize_login: live re-seed skipped \
                         (store at-or-fresher, or non-Anthropic/corrupt — fail-closed)"
                    );
                }
                Err(cred_err) if uuid_populated => {
                    tracing::warn!(
                        account = account.get(),
                        error_kind = "uuid_credential_seed_failed",
                        "finalize_login: could not seed UUID credentials path"
                    );
                    return Err(ConfigError::InvalidJson {
                        path: live_path.clone(),
                        reason: format!("UUID credential seed failed: {cred_err}"),
                    });
                }
                Err(_) => {
                    // Legacy install: no UUID mapping, NoCredentials is expected.
                    // broker_check uses the numeric path fallback for legacy accounts.
                    tracing::debug!(
                        account = account.get(),
                        "finalize_login: UUID seed skipped (no by_slot mapping — legacy install)"
                    );
                }
            }
        }
        Err(crate::error::CredentialError::NotFound { .. }) => {
            // CC has not written live creds yet — backsync will seed UUID path.
            tracing::debug!(
                account = account.get(),
                "finalize_login: live creds not yet present; UUID seed deferred to backsync"
            );
        }
        Err(_) => {
            tracing::warn!(
                account = account.get(),
                error_kind = "uuid_credential_seed_live_corrupt",
                "finalize_login: live credential file unreadable; UUID seed deferred to backsync"
            );
        }
    }

    // Release the profiles lock explicitly before the broker fanout so any
    // reader of profiles.json can proceed.
    drop(profiles_lock);

    crate::refresh::sentinel::clear_broker_failed(base_dir, account);

    // Mirror the freshly-logged-in token into the keychain CC reads for every
    // live handle dir (current CC is keychain-first). `claude auth login` wrote
    // the keychain only for the LOGIN config dir, so a session already bound to
    // this account on a different `term-<pid>` path keeps the stale token until
    // its next launch. Done HERE (the shared finalize) — not in the CLI wrapper —
    // so every caller gets it: `csq login` AND all three desktop login twins
    // (subprocess, paste-code, race). Account-agnostic sweep; the
    // newer-than-keychain guard no-ops unaffected dirs. Best-effort; never blocks
    // login. Test-safe: a base with no `term-*` dirs sweeps nothing.
    let _ = crate::credentials::keychain::sync_all_handle_dirs(base_dir);

    Ok(email)
}

/// System-wide install directories searched after `$PATH`.
///
/// Order is deliberate: Homebrew on Apple Silicon (`/opt/homebrew/bin`)
/// is checked before Intel Homebrew / manual installs (`/usr/local/bin`)
/// because Apple Silicon machines often have BOTH and the user wants
/// the modern one.
const SYSTEM_WIDE_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];

/// Per-user install subdirectories, joined to `$HOME`.
const PER_USER_SUBDIRS: &[&str] = &[
    ".local/bin",
    ".npm-global/bin",
    ".bun/bin",
    ".cargo/bin",
    ".volta/bin",
    "n/bin",
];

/// If `dir/claude` (or `dir/claude.exe` on Windows) is an executable
/// regular file, returns its path. Otherwise returns `None`.
fn check_dir(dir: &Path) -> Option<PathBuf> {
    check_dir_named(dir, "claude")
}

/// Generalized form of [`check_dir`] for arbitrary CLI binary names.
/// Used by [`find_cli_binary`] to share the search infrastructure
/// across `claude`, `codex`, and any future first-party CLI shellouts.
pub(crate) fn check_dir_named(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(name);
    if is_executable_file(&candidate) {
        return Some(candidate);
    }
    #[cfg(windows)]
    {
        let exe = dir.join(format!("{name}.exe"));
        if is_executable_file(&exe) {
            return Some(exe);
        }
    }
    None
}

/// Generalized binary locator. Same search order as
/// [`find_claude_binary`] (`$PATH` → SYSTEM_WIDE_DIRS → per-user
/// HOME-relative dirs) but parameterized by binary name. Used for
/// `codex` (the OpenAI CLI) and any future first-party CLI csq
/// shells out to from the Tauri-launched desktop bundle, where the
/// Finder PATH is `/usr/bin:/bin:/usr/sbin:/sbin` and Homebrew /
/// per-user installs are otherwise invisible.
pub fn find_cli_binary(name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if let Some(p) = check_dir_named(&dir, name) {
                return Some(p);
            }
        }
    }
    for sys_dir in SYSTEM_WIDE_DIRS {
        if let Some(p) = check_dir_named(Path::new(sys_dir), name) {
            return Some(p);
        }
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in PER_USER_SUBDIRS {
            if let Some(p) = check_dir_named(&home.join(sub), name) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_dir_finds_executable_claude() {
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh\necho hi").unwrap();
        make_executable(&claude);

        let found = check_dir(dir.path()).expect("should find claude");
        assert_eq!(found, claude);
    }

    #[cfg(unix)]
    #[test]
    fn check_dir_skips_non_executable() {
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh\necho hi").unwrap();
        // Mode 0o644 — readable but not executable.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&claude).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&claude, perms).unwrap();

        assert!(check_dir(dir.path()).is_none());
    }

    #[test]
    fn check_dir_returns_none_for_missing_dir() {
        let missing = Path::new("/definitely/not/a/real/path/12345abcde");
        assert!(check_dir(missing).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn find_claude_binary_picks_up_path_entry() {
        // Override $PATH and $HOME to point at an isolated tempdir
        // so the assertion is hermetic regardless of what's installed
        // on the test machine.
        let dir = TempDir::new().unwrap();
        let claude = dir.path().join("claude");
        fs::write(&claude, "#!/bin/sh").unwrap();
        make_executable(&claude);

        // Cross-module env-var mutex (`crate::platform::test_env`)
        // serializes against any other test mutating PATH / HOME
        // concurrently. PATH especially is read transitively by many
        // libraries, so a parallel set_var elsewhere can flip what
        // `find_claude_binary` sees mid-call.
        let _shared_env_guard = crate::platform::test_env::lock();

        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("PATH", dir.path());
        // Point HOME at an empty dir so the per-user fallbacks miss.
        let empty_home = TempDir::new().unwrap();
        std::env::set_var("HOME", empty_home.path());

        let found = find_claude_binary();

        // Restore env before asserting so a panic doesn't poison
        // sibling tests.
        match prev_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(found, Some(claude));
    }

    /// Regression for the live-discovered Codex spawn bug: the
    /// Finder-launched desktop bundle inherits `PATH=/usr/bin:/bin`
    /// and cannot find Homebrew-installed `codex` via bare
    /// `Command::new("codex")`. `find_cli_binary("codex")` MUST find
    /// it via the same SYSTEM_WIDE_DIRS / PER_USER_SUBDIRS fallback
    /// search Claude uses.
    #[cfg(unix)]
    #[test]
    fn find_cli_binary_finds_codex_in_path() {
        let dir = TempDir::new().unwrap();
        let codex = dir.path().join("codex");
        fs::write(&codex, "#!/bin/sh").unwrap();
        make_executable(&codex);

        let _shared_env_guard = crate::platform::test_env::lock();

        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("PATH", dir.path());
        let empty_home = TempDir::new().unwrap();
        std::env::set_var("HOME", empty_home.path());

        let found = find_cli_binary("codex");

        match prev_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(found, Some(codex));
    }

    /// HIGH-2 regression: `finalize_login` seeds `identities/<UUID>/credentials.json`
    /// when the UUID is present in profiles.json (i.e. Pass 0 has already run).
    ///
    /// Uses `coexisting_fixture(1)` which provides:
    /// - `config-1/.credentials.json` (live creds CC would have written)
    /// - `profiles.json` with `by_slot["1"] = fixture_uuid_for_slot(1)`
    /// - `identities/<uuid>/identity.json` (Pass 0 already ran)
    ///
    /// After `finalize_login`, `identities/<UUID>/credentials.json` MUST exist
    /// with bytes identical to what was in `config-1/.credentials.json`.
    #[test]
    fn finalize_login_seeds_uuid_credentials_when_uuid_present() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: fixture with live creds + profiles UUID mapping
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        // Write .claude.json with the fixture email so mint_for_login reuses the
        // existing fixture UUID (by_email lookup succeeds → Reused path, no new UUID).
        // This keeps the test hermetic — fixture_uuid_for_slot(1) stays canonical.
        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        // fixture email for slot 1 is "fixture-slot-1@test.invalid" (see identity_fixtures.rs)
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Overwrite live creds with csq CredentialFile JSON (the fixture writes CC's
        // native format which credentials::load cannot parse; this replaces it).
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-seed-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-seed-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Also write the marker so the config dir is fully set up.
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Act
        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: identities/<UUID>/credentials.json exists
        let uuid_creds = uuid_creds_path(base, uuid);
        assert!(
            uuid_creds.exists(),
            "HIGH-2: identities/<UUID>/credentials.json must be seeded by finalize_login; \
             path: {uuid_creds:?}"
        );

        // Assert: UUID credentials carry the same access_token as live creds
        let live_creds =
            credentials::load(&cred_file::live_path(base, account)).expect("live creds present");
        let seeded_creds = credentials::load(&uuid_creds).expect("UUID creds readable");
        assert_eq!(
            live_creds
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            seeded_creds
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "HIGH-2: UUID credentials must carry the same access_token as live creds"
        );
    }

    /// config-N login-overwrite regression (HIGH, 2026-06-24): a STALE
    /// `config-N/.credentials.json` MUST NOT regress a fresher store token.
    ///
    /// Every production caller pre-seeds the store with the authoritative
    /// token (`read_fresh_after_login` → `save_canonical_for`) before calling
    /// `finalize_login`. Modern keychain-first CC may leave
    /// `config-N/.credentials.json` stale or weeks-old. The prior unconditional
    /// `save_canonical_for` re-seed reverted the store to that stale token,
    /// 401-ing every session. The freshness guard
    /// (`save_canonical_for_if_fresher`) makes the re-seed monotonic.
    ///
    /// Arrange:
    /// - store `identities/<UUID>/credentials.json` pre-seeded FRESH (expiry 2100)
    /// - `config-1/.credentials.json` STALE (expiry 2033, different access_token)
    ///
    /// After `finalize_login`, the store MUST still carry the FRESH token.
    #[test]
    fn finalize_login_stale_config_n_does_not_regress_fresh_store() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        fn anthropic_creds(access: &str, expires_at: u64) -> crate::credentials::CredentialFile {
            crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(access.into()),
                        refresh_token: crate::types::RefreshToken::new(format!(
                            "sk-ant-ort01-{access}"
                        )),
                        expires_at,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            )
        }

        const FRESH_EXPIRY: u64 = 4102444800000; // 2100-01-01
        const STALE_EXPIRY: u64 = 2000000000000; // 2033-05-18 (< FRESH)

        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);
        let config_dir = base.join("config-1");

        // .claude.json with the fixture email → mint reuses the fixture UUID.
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Pre-seed the store with the FRESH token (what a caller's
        // read_fresh_after_login → save_canonical_for would have written).
        credentials::save_canonical_for(
            base,
            account,
            &anthropic_creds("sk-ant-oat01-FRESH", FRESH_EXPIRY),
        )
        .expect("pre-seed store with fresh token");

        // config-N holds a STALE token (older expiry, different access_token) —
        // the leftover keychain-first CC never refreshed.
        credentials::save(
            &cred_file::live_path(base, account),
            &anthropic_creds("sk-ant-oat01-STALE", STALE_EXPIRY),
        )
        .unwrap();

        // Act
        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {result:?}");

        // Assert: the store STILL carries the FRESH token — NOT regressed to STALE.
        let store = credentials::load(&uuid_creds_path(base, uuid)).expect("store readable");
        assert_eq!(
            store
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-FRESH",
            "config-N login-overwrite: a stale config-N must NOT regress the fresher store token"
        );
        assert_eq!(
            store.expect_anthropic().claude_ai_oauth.expires_at,
            FRESH_EXPIRY,
            "store expiry must remain the fresh value after finalize_login"
        );
    }

    /// config-N login-overwrite — monotonic-UP direction (R1 deep-analyst MED-2):
    /// a config-N STRICTLY FRESHER than the store MUST advance the store. Pins the
    /// `<=` boundary in `save_canonical_for_if_fresher` so a future operator flip
    /// (`<` vs `<=`) or a regression to "never write" is caught. This is the
    /// HIGH-2 safety net's general case: a non-pre-seeding caller (or a store left
    /// behind an older token) is still seeded from a genuinely-fresh config-N.
    #[test]
    fn finalize_login_fresher_config_n_advances_store() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        fn anthropic_creds(access: &str, expires_at: u64) -> crate::credentials::CredentialFile {
            crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(access.into()),
                        refresh_token: crate::types::RefreshToken::new(format!(
                            "sk-ant-ort01-{access}"
                        )),
                        expires_at,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            )
        }

        const OLD_EXPIRY: u64 = 2000000000000; // 2033
        const NEWER_EXPIRY: u64 = 4102444800000; // 2100 (> OLD)

        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);
        let config_dir = base.join("config-1");
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Store holds an OLDER token; config-N holds a strictly NEWER token.
        credentials::save_canonical_for(
            base,
            account,
            &anthropic_creds("sk-ant-oat01-OLD", OLD_EXPIRY),
        )
        .expect("pre-seed older store token");
        credentials::save(
            &cred_file::live_path(base, account),
            &anthropic_creds("sk-ant-oat01-NEWER", NEWER_EXPIRY),
        )
        .unwrap();

        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {result:?}");

        let store = credentials::load(&uuid_creds_path(base, uuid)).expect("store readable");
        assert_eq!(
            store
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-NEWER",
            "a strictly-fresher config-N MUST advance the store (monotonic-up)"
        );
        assert_eq!(
            store.expect_anthropic().claude_ai_oauth.expires_at,
            NEWER_EXPIRY,
            "store expiry must advance to the fresher config-N value"
        );
    }

    /// config-N login-overwrite — fail-closed on a corrupt store (R1 code-review
    /// LOW): the new `save_canonical_for_if_fresher` path returns Ok(false) WITHOUT
    /// writing when the store is unreadable/corrupt, whereas the old unconditional
    /// `save_canonical_for` would have overwritten it from config-N. This pins the
    /// fail-closed posture (an account-global store must never be clobbered on
    /// doubt) so a future refactor cannot silently reintroduce the overwrite.
    #[test]
    fn finalize_login_corrupt_store_no_ops_fail_closed() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        fn anthropic_creds(access: &str, expires_at: u64) -> crate::credentials::CredentialFile {
            crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(access.into()),
                        refresh_token: crate::types::RefreshToken::new(format!(
                            "sk-ant-ort01-{access}"
                        )),
                        expires_at,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            )
        }

        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);
        let config_dir = base.join("config-1");
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Corrupt the store file (exists but unparseable) and place a valid,
        // fresher token in config-N. if_fresher must read the corrupt store,
        // fail closed (Ok(false)), and leave it untouched.
        let store_path = uuid_creds_path(base, uuid);
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let corrupt_bytes = b"{ this is not valid credential json ";
        std::fs::write(&store_path, corrupt_bytes).unwrap();
        credentials::save(
            &cred_file::live_path(base, account),
            &anthropic_creds("sk-ant-oat01-CONFIGN", 4102444800000),
        )
        .unwrap();

        let result = finalize_login(base, account);
        assert!(
            result.is_ok(),
            "finalize_login must remain Ok (non-fatal) on a corrupt store: {result:?}"
        );

        let after = std::fs::read(&store_path).expect("store file still present");
        assert_eq!(
            after.as_slice(),
            corrupt_bytes,
            "fail-closed: a corrupt store MUST NOT be overwritten from config-N"
        );
    }

    /// config-N login-overwrite — ABSENT config-N path (R2 completeness NIT):
    /// keychain-first CC may leave NO `config-N/.credentials.json` at all. That
    /// routes to the Err(NotFound) deferral branch, which MUST NOT write the
    /// store. Pins "absent config-N => no store write, finalize_login still Ok"
    /// so a future refactor cannot make the NotFound branch seed a default cred.
    #[test]
    fn finalize_login_absent_config_n_defers_without_touching_store() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        fn anthropic_creds(access: &str, expires_at: u64) -> crate::credentials::CredentialFile {
            crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(access.into()),
                        refresh_token: crate::types::RefreshToken::new(format!(
                            "sk-ant-ort01-{access}"
                        )),
                        expires_at,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            )
        }

        const FRESH_EXPIRY: u64 = 4102444800000; // 2100

        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);
        let config_dir = base.join("config-1");
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();
        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Pre-seed a FRESH store, then ensure config-N/.credentials.json is ABSENT.
        credentials::save_canonical_for(
            base,
            account,
            &anthropic_creds("sk-ant-oat01-FRESH", FRESH_EXPIRY),
        )
        .expect("pre-seed fresh store");
        let live = cred_file::live_path(base, account);
        let _ = std::fs::remove_file(&live);
        assert!(
            !live.exists(),
            "precondition: config-N/.credentials.json must be absent"
        );

        let result = finalize_login(base, account);
        assert!(
            result.is_ok(),
            "finalize_login must remain Ok when config-N is absent: {result:?}"
        );

        let store = credentials::load(&uuid_creds_path(base, uuid)).expect("store readable");
        assert_eq!(
            store
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-FRESH",
            "absent config-N: the fresh store token MUST be left untouched"
        );
    }

    /// M4-2 Criterion: `finalize_login` writes `identities/<UUID>/settings.json`
    /// byte-equivalent to `config-<N>/settings.json`.
    ///
    /// The pair-write in `finalize_login` (post-`mint_for_login`) reads the
    /// legacy `config-<N>/settings.json` and writes the same bytes verbatim to
    /// `identities/<UUID>/settings.json`. The two paths must be byte-equivalent
    /// during the M4-2 → M4-5 transition window (spec 02 §2.3.3) so
    /// `materialize_handle_settings` reads identical content regardless of which
    /// overlay-source branch it takes.
    ///
    /// Arrange:
    /// - `coexisting_fixture(1)` — live creds + profiles UUID mapping
    /// - Write a sentinel `config-1/settings.json` with a 3P-style env block
    ///   (`ANTHROPIC_BASE_URL` + a recognizable model name)
    /// - Pre-write `identities/<UUID>/settings.json` with STALE bytes (different
    ///   model) to verify the pair-write OVERWRITES the stale UUID copy
    ///
    /// Assert: after `finalize_login`, `identities/<UUID>/settings.json` has
    /// bytes identical to `config-1/settings.json`.
    #[test]
    fn finalize_login_writes_uuid_settings_byte_equivalent_to_legacy() {
        use crate::accounts::identity_store::settings_path_for;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        // Set up the config-1 marker + .claude.json so finalize_login's
        // mint_for_login reuses the fixture UUID by email.
        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Live creds (so finalize_login's credential seed step doesn't bail).
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-m42-pair-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-m42-pair-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        let _ = crate::accounts::markers::write_csq_account_legacy(&config_dir, account);

        // Write the LEGACY settings.json with a recognizable sentinel.
        //
        // CRITICAL: the bytes MUST NOT trigger `unbind_provider_from_slot`
        // (which `finalize_login` runs as its FIRST step). Unbind rewrites
        // `config-N/settings.json` if any 3P provider markers are present
        // (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, etc.) — that rewrite
        // changes the bytes BEFORE the pair-write reads them. We avoid those
        // markers and use a plain user-custom key under `env` so unbind is a
        // no-op and the legacy bytes round-trip verbatim into the UUID pair.
        let legacy_settings = config_dir.join("settings.json");
        let legacy_bytes = br#"{"plain_user_key":"m42-pair-source","other_field":42}"#;
        fs::write(&legacy_settings, legacy_bytes).unwrap();

        // Pre-write a STALE UUID settings file so we can verify the pair-write
        // OVERWRITES it (not just "absent → write" idempotency).
        std::fs::create_dir_all(settings_path_for(base, uuid).parent().unwrap()).unwrap();
        fs::write(
            settings_path_for(base, uuid),
            br#"{"env":{"CLAUDE_MODEL":"STALE-pre-finalize"}}"#,
        )
        .unwrap();

        // Act
        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: UUID settings.json now byte-equivalent to legacy.
        let uuid_settings = settings_path_for(base, uuid);
        assert!(
            uuid_settings.exists(),
            "M4-2: identities/<UUID>/settings.json must exist after finalize_login; path: {uuid_settings:?}"
        );
        let written_uuid_bytes = std::fs::read(&uuid_settings).expect("UUID settings readable");
        assert_eq!(
            written_uuid_bytes.as_slice(),
            legacy_bytes.as_slice(),
            "M4-2: identities/<UUID>/settings.json must be byte-equivalent to \
             config-N/settings.json after finalize_login; UUID bytes: {written_uuid_bytes:?}"
        );
    }

    /// M4-7 acceptance: `finalize_login` writes UUID content to
    /// `config-<N>/.csq-account` when `profiles.json::by_slot` carries a
    /// mapping for the slot. `mint_for_login` runs inside `finalize_login`
    /// and (re)uses the fixture UUID via the by_email lookup, so the
    /// post-mint marker write surfaces `Some(uuid)` and emits the
    /// canonical UUID-v4 string. Filename `.csq-account` is unchanged
    /// per OQ #3.
    #[test]
    fn finalize_login_writes_uuid_to_csq_account_marker() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture seeds profiles.json with the
        // by_email entry for slot 1; finalize_login's mint_for_login
        // hook re-uses the fixture UUID via by_email lookup so the
        // by_slot mapping resolves after the lock release.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let uuid = fixture_uuid_for_slot(1);

        let config_dir = base.join("config-1");
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Live creds so the credential-seed step does not bail.
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-m47-marker-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-m47-marker-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Act
        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: UUID accessor returns the fixture UUID.
        assert_eq!(
            crate::accounts::markers::read_csq_account_uuid(&config_dir),
            Some(uuid),
            "M4-7: .csq-account must contain the canonical UUID after finalize_login \
             when by_slot maps; got {:?}",
            crate::accounts::markers::read_identity_marker(&config_dir)
        );
        // The numeric reader (M1-5 contract) returns None for UUID-content.
        assert_eq!(
            crate::accounts::markers::read_csq_account(&config_dir),
            None,
            "M4-7: numeric reader must reject UUID-content markers"
        );
    }

    /// M4-7 acceptance: when no `by_slot` mapping is resolvable for the
    /// slot (pure-legacy install where mint failed or was skipped),
    /// `finalize_login` falls back to the legacy decimal writer so the
    /// M1-5 numeric reader still surfaces the slot id. Achieved here by
    /// providing a `.claude.json` whose email is `"unknown"` — that
    /// short-circuits the mint hook (cannot establish a stable by_email
    /// key per the existing mint guard), leaving `by_slot` empty.
    #[test]
    fn finalize_login_legacy_writes_decimal_when_no_by_slot() {
        // Build a base where profiles.json carries no by_slot mapping at all.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let config_dir = base.join("config-2");
        std::fs::create_dir_all(&config_dir).unwrap();

        // `.claude.json` with empty email field → read_email returns None
        // → finalize_login uses "unknown" → mint_for_login is skipped
        // → no by_slot entry materializes → resolve_slot_to_uuid is None.
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":""}}"#,
        )
        .unwrap();

        // Live creds for the credential-seed step (best-effort).
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-m47-legacy-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-m47-legacy-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Act
        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {:?}", result);

        // Assert: marker content is decimal slot id (legacy writer used
        // because no by_slot mapping exists for slot 2).
        assert_eq!(
            crate::accounts::markers::read_csq_account(&config_dir),
            Some(account),
            "M4-7: pure-legacy install (no by_slot) must write the decimal slot id"
        );
        // No UUID is recoverable from the marker file.
        assert_eq!(
            crate::accounts::markers::read_csq_account_uuid(&config_dir),
            None,
            "M4-7: legacy marker has no UUID content"
        );
    }

    /// M4-9 (release N affordance, an internal ticket Phase 4):
    /// `finalize_login` MUST NOT populate the v1
    /// `profiles.json::accounts[N]` map. After login, the map is `{}`.
    /// The slot's email is carried by `by_email` (written by
    /// `mint_for_login`), and `ProfilesFile::get_email(N)` resolves it
    /// via the `by_slot → UUID → by_email` reverse-lookup fallback.
    #[test]
    fn finalize_login_does_not_populate_v1_accounts_map() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture seeds by_slot/by_email already.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");

        // Write .claude.json so finalize_login can resolve the email.
        let claude_json_path = config_dir.join(".claude.json");
        fs::write(
            &claude_json_path,
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Overwrite live creds with valid csq-shaped CredentialFile JSON.
        let live_creds_path = config_dir.join(".credentials.json");
        credentials::save(
            &live_creds_path,
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-m4-9-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-m4-9-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Wipe any accounts[N] entry the fixture might have set so the
        // assertion measures finalize_login's own behavior.
        {
            use crate::accounts::profiles;
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
            // M4-13: accounts field removed; clear via extra["accounts"] mutation.
            if let Some(accounts_val) = pf.extra.get_mut("accounts") {
                if let Some(obj) = accounts_val.as_object_mut() {
                    obj.clear();
                }
            }
            profiles::save(&path, &pf).unwrap();
        }

        // Act
        let result = finalize_login(base, account);
        assert!(result.is_ok(), "finalize_login must succeed: {result:?}");

        // Assert: profiles.json::accounts is still empty.
        let path = crate::accounts::profiles::profiles_path(base);
        let pf = crate::accounts::profiles::load(&path).unwrap();
        let accounts_in_extra = pf.extra.get("accounts").and_then(|v| v.as_object());
        assert!(
            accounts_in_extra.is_none() || accounts_in_extra.is_some_and(|m| m.is_empty()),
            "M4-9/M4-13: finalize_login MUST NOT populate the v1 accounts map; \
             extra[accounts]: {:?}",
            pf.extra.get("accounts")
        );

        // Assert: the email survives — by_email carries it, and
        // get_email's reverse-lookup retrieves it.
        assert_eq!(
            pf.get_email(account.get()),
            Some("fixture-slot-1@test.invalid"),
            "M4-9: get_email MUST resolve the email via by_email reverse-lookup"
        );
    }

    /// F-H-1 regression: `finalize_login` MUST clear a stale
    /// `by_slot_identity[N]` entry left from a prior non-OAuth (3P
    /// API-key) binding when the user subsequently logs in with
    /// Anthropic OAuth on the same slot.
    ///
    /// Sequence under test:
    ///   1. Slot 5 has `by_slot_identity["5"] = "apikey:mm"` (prior bind).
    ///   2. User runs `csq login 5` (Anthropic OAuth) → `finalize_login`.
    ///   3. After login, `by_slot_identity["5"]` MUST be absent so that
    ///      `get_email(5)` returns the OAuth email via step 3 (by_email),
    ///      not `"apikey:mm"` via the stale step 1.5.
    #[test]
    fn finalize_login_clears_stale_by_slot_identity_after_3p_to_oauth_transition() {
        use crate::accounts::profiles;
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture seeds by_slot/by_email for slot 1.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.join("config-1");

        // Simulate a prior 3P bind by writing by_slot_identity["1"] = "apikey:mm".
        {
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
            pf.by_slot_identity.insert("1".into(), "apikey:mm".into());
            profiles::save(&path, &pf).unwrap();
        }

        // Verify pre-condition: stale identity exists.
        {
            let path = profiles::profiles_path(base);
            let pf = profiles::load(&path).unwrap();
            assert_eq!(
                pf.by_slot_identity.get("1").map(|s| s.as_str()),
                Some("apikey:mm"),
                "pre: by_slot_identity[1] must be 'apikey:mm' before finalize_login"
            );
        }

        // Write .claude.json so finalize_login can resolve the OAuth email.
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Write live creds so save_canonical_for can seed the UUID path.
        credentials::save(
            &config_dir.join(".credentials.json"),
            &crate::credentials::CredentialFile::Anthropic(
                crate::credentials::AnthropicCredentialFile {
                    claude_ai_oauth: crate::credentials::OAuthPayload {
                        access_token: crate::types::AccessToken::new(
                            "sk-ant-oat01-fh1-test".into(),
                        ),
                        refresh_token: crate::types::RefreshToken::new(
                            "sk-ant-ort01-fh1-test".into(),
                        ),
                        expires_at: 4102444800000,
                        scopes: vec!["user:inference".into()],
                        subscription_type: Some("max".into()),
                        rate_limit_tier: None,
                        extra: std::collections::HashMap::new(),
                    },
                    extra: std::collections::HashMap::new(),
                },
            ),
        )
        .unwrap();

        // Act: perform Anthropic OAuth finalize on the same slot.
        let result = finalize_login(base, account);
        assert!(
            result.is_ok(),
            "finalize_login must succeed on 3P→OAuth transition: {result:?}"
        );

        // Assert: by_slot_identity["1"] is now absent.
        let path = profiles::profiles_path(base);
        let pf = profiles::load(&path).unwrap();
        assert!(
            !pf.by_slot_identity.contains_key("1"),
            "F-H-1: by_slot_identity[1] must be absent after OAuth login \
             on a previously 3P-bound slot; got: {:?}",
            pf.by_slot_identity.get("1")
        );
    }

    /// #633: `ensure_login_identity_minted` mints a fresh slot's UUID from the
    /// OAuth email in `config-N/.claude.json` when no `by_slot` mapping exists.
    /// This is the fresh-install / macOS-keychain-only case where the later
    /// `save_canonical_for` would otherwise fail-closed on the absent UUID
    /// (M4-12) because the only mint site (`finalize_login`) runs AFTER it.
    #[test]
    fn ensure_login_identity_minted_mints_when_absent_on_fresh_install() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(3u16).unwrap();

        // Fresh install: config-3 carries the email CC wrote; no profiles.json.
        let config_dir = base.join("config-3");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fresh-slot-3@test.invalid"}}"#,
        )
        .unwrap();

        assert!(
            profiles::resolve_slot_to_uuid(base, 3).is_none(),
            "pre-condition: slot 3 must have no UUID before mint"
        );

        ensure_login_identity_minted(base, account).expect("mint must succeed");

        let uuid = profiles::resolve_slot_to_uuid(base, 3)
            .expect("slot 3 must resolve to a minted UUID after ensure_login_identity_minted");
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_email.get("fresh-slot-3@test.invalid").copied(),
            Some(uuid),
            "by_email must map the OAuth email to the same minted UUID so \
             finalize_login's later mint_for_login is an idempotent reuse"
        );
    }

    /// #633: a second call is a no-op — the slot keeps its original UUID.
    /// This is the property that makes `finalize_login`'s later
    /// `mint_for_login` an idempotent reuse rather than a churn / second UUID.
    #[test]
    fn ensure_login_identity_minted_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(2u16).unwrap();
        let config_dir = base.join("config-2");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"idem-slot-2@test.invalid"}}"#,
        )
        .unwrap();

        ensure_login_identity_minted(base, account).expect("first mint must succeed");
        let first = profiles::resolve_slot_to_uuid(base, 2).unwrap();
        ensure_login_identity_minted(base, account).expect("second call must be a no-op Ok");
        let second = profiles::resolve_slot_to_uuid(base, 2).unwrap();
        assert_eq!(first, second, "UUID must not churn across repeat calls");
    }

    /// #633: with no email source (no `.claude.json`), the helper returns `Ok`
    /// WITHOUT inventing an identity. The caller's `save_canonical_for` then
    /// surfaces its own genuine fail-closed error rather than this helper
    /// minting a UUID against a guessed / absent email.
    #[test]
    fn ensure_login_identity_minted_noops_without_email() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(4u16).unwrap();
        // config-4 exists but CC hasn't written `.claude.json` yet.
        fs::create_dir_all(base.join("config-4")).unwrap();

        ensure_login_identity_minted(base, account).expect("must return Ok with no mint");

        assert!(
            profiles::resolve_slot_to_uuid(base, 4).is_none(),
            "no email → no UUID minted; helper must not invent an identity"
        );
    }
}
