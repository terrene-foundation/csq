//! Code Assist OAuth binding — verifies the user's prior interactive
//! gemini-cli OAuth state at `~/.gemini/oauth_creds.json` and records
//! a binding marker in `CodeAssistOAuth` mode.
//!
//! Stage 2 of journal 0048, **rewritten for gemini-cli v0.41.2+**
//! (journal 0054). gemini-cli v0.41.2 removed the `gemini auth login`
//! subcommand: positional args now default to interactive mode and
//! `gemini auth login` is parsed as a prompt to the model rather than
//! an OAuth subcommand. There is no longer ANY non-interactive surface
//! for triggering OAuth in gemini-cli — auth happens lazily on first
//! interactive run, period.
//!
//! Per `feedback_delegate_to_reference_client`: csq does not perform
//! OAuth itself. The user is expected to run `gemini` once
//! interactively (which writes `~/.gemini/oauth_creds.json`); csq's
//! `csq login N --provider gemini` then propagates that state into
//! the per-slot binding by:
//!
//! 1. Refusing if the slot is bound to a non-Gemini surface.
//! 2. Refusing if a CWD-ancestor `.env` declares
//!    `GOOGLE_API_KEY` / `GEMINI_API_KEY` /
//!    `GOOGLE_APPLICATION_CREDENTIALS` — gemini-cli prefers ambient
//!    API-key auth over OAuth, silently binding the slot to an
//!    unrelated identity.
//! 3. Verifying `~/.gemini/oauth_creds.json` exists, parses, and
//!    carries a non-expired `access_token`.
//! 4. Writing the binding marker via [`provision_code_assist_oauth`].
//!
//! Per-slot `.gemini/settings.json::security.auth.selectedType` is
//! pinned to `oauth-personal` by [`super::probe::reassert_settings_drift`]
//! at every `csq run N` spawn (and by the desktop spawn path), so
//! gemini-cli does NOT prompt for first-run auth on subsequent
//! invocations — the prompt the user saw before the v0.41.2 fix was
//! exactly because csq used to leave `selectedType` unset for
//! OAuth-mode bindings.
//!
//! Both the desktop Tauri command (`gemini_provision_oauth`) and the
//! CLI handler (`csq login N --provider gemini`) call into [`perform`]
//! so the verification + binding-write sequence stays in one place.

use super::provisioning::{
    detect_other_surface_binding, provision_code_assist_oauth, BoundSurface, ProvisionError,
};
use super::spawn::{pre_spawn_dotenv_scan, DotenvScanResult};
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

// Round-2 redteam MEDIUM-6 — `BROWSER_ENV_ALLOWLIST` was deleted on
// 2026-05-07. Pre-journal-0054 code shelled out to `gemini auth login`
// with `env_clear()` + a strict allowlist of browser-open env vars
// (HOME/PATH/DISPLAY/WAYLAND_DISPLAY/...) so OAuth tokens / API keys
// from the parent shell could not leak into the child gemini process.
// Journal 0054 removed the shell-out: there is no longer a child
// process to env-scrub. The allowlist had no remaining caller and
// `#[allow(dead_code)]` on it (with a "for future re-introduction"
// comment) is the deferred-implementation pattern that
// `rules/zero-tolerance.md` Rule 2 + `rules/no-stubs.md` block.
//
// If gemini-cli ever restores a non-interactive auth surface, the
// security analysis (round-1 + round-2 redteam MED) is preserved in
// journal 0054 and can be reconstructed by listing the env vars
// gemini-cli's documented "browser-open" needs vs the workspace's
// known-secret-bearing env vars.

/// Errors raised by the Code Assist OAuth binding flow.
#[derive(Debug, thiserror::Error)]
pub enum OauthLoginError {
    /// `~/.gemini/oauth_creds.json` is absent. Per journal 0054, the
    /// user must run `gemini` once interactively (gemini-cli's first-run
    /// prompt), select "Sign in with Google", complete the browser
    /// OAuth flow, and quit. Then re-run `csq login N --provider gemini`.
    #[error(
        "gemini-cli has not signed in yet — run `gemini` once interactively \
         (select \"Sign in with Google\" in the first-run prompt + complete \
         the browser flow), then re-run `csq login {slot} --provider gemini`"
    )]
    GeminiOauthCredsNotFound { slot: u16 },
    /// `~/.gemini/oauth_creds.json` exists but its `access_token` has
    /// expired (per `expiry_date`, Unix milliseconds). gemini-cli will
    /// re-OAuth automatically on its next interactive run; the user
    /// just needs to launch `gemini` once to refresh.
    #[error(
        "gemini-cli OAuth tokens at ~/.gemini/oauth_creds.json are expired — \
         run `gemini` once interactively to refresh, then re-run `csq login {slot} --provider gemini`"
    )]
    GeminiOauthCredsStale { slot: u16 },
    /// `~/.gemini/oauth_creds.json` exists but does not parse as the
    /// expected shape (missing `access_token` / `expiry_date`, or
    /// invalid JSON). Treat as gemini-cli state corruption — user
    /// should re-run `gemini` interactively and re-OAuth.
    #[error(
        "gemini-cli oauth_creds.json is malformed at {path}: {reason} — \
         re-run `gemini` interactively to regenerate"
    )]
    GeminiOauthCredsMalformed { path: PathBuf, reason: String },
    /// `~/.gemini/oauth_creds.json` exists but I/O on it failed for a
    /// reason OTHER than NotFound — typically `PermissionDenied`
    /// (mode 0 file). Distinct from `Malformed` because the
    /// remediation differs: re-OAuth won't help; the user needs to
    /// fix file permissions or rebuild the file.
    /// Round-2 redteam MEDIUM-3.
    #[error(
        "gemini-cli oauth_creds.json is unreadable at {path}: {reason} — \
         check file permissions (expected mode 0600) or remove + run `gemini` to regenerate"
    )]
    GeminiOauthCredsUnreadable { path: PathBuf, reason: String },
    /// `gemini` binary not found on PATH. The user can still write the
    /// binding (validated against existing oauth_creds.json), but the
    /// next `csq run N` will fail because gemini-cli is not installed.
    /// Surfaced here so the user gets the install hint up front.
    #[error("gemini-cli not installed: install from https://github.com/google-gemini/gemini-cli")]
    GeminiCliNotInstalled,
    /// The slot is bound to a non-Gemini surface; user needs to run
    /// `csq logout` first.
    #[error("slot {slot} is bound to {surface} — run `csq logout {slot}` to rebind to Gemini")]
    OtherSurfaceBound { slot: u16, surface: &'static str },
    /// Binding marker write failed after OAuth verification succeeded.
    /// User can retry safely.
    #[error("provision oauth binding: {0}")]
    BindingWriteFailed(#[from] ProvisionError),
    /// Caller-supplied `base_dir` does not exist or is not a
    /// directory. Validated here (centralized) so all entry points —
    /// CLI, Tauri, future deep-link handlers — share the same
    /// boundary check.
    #[error("base directory does not exist: {0}")]
    BaseDirMissing(PathBuf),
    /// CWD or one of its ancestors up to `$HOME` contains a `.env`
    /// file declaring `GOOGLE_API_KEY` / `GEMINI_API_KEY` /
    /// `GOOGLE_APPLICATION_CREDENTIALS` — gemini-cli would prefer
    /// that ambient credential over the OAuth flow, silently binding
    /// the slot to an unrelated identity. Refuse the login.
    ///
    /// Round-2 redteam MED: the Display string surfaces only the
    /// `.env` BASENAME (not the full path) so a future telemetry /
    /// crash-reporter / "share diagnostics" feature cannot leak the
    /// user's directory tree. The full `env_file` path is retained
    /// in the variant for local-only debugging via tracing.
    #[error(
        "shadow auth detected in a .env file (variable {variable}) — \
         remove the variable or run `csq login` from a different directory"
    )]
    ShadowAuthInDotenv { env_file: PathBuf, variable: String },
    /// CWD could not be resolved (rare — process started without a
    /// valid cwd, or the cwd was deleted between `getcwd` calls).
    #[error("could not resolve current directory: {0}")]
    CwdResolveFailed(std::io::Error),
    /// Round-7: csq drove the OAuth flow itself but it failed
    /// (browser open failed, callback timed out, state mismatch, token
    /// exchange failed, etc.). Variant carries the upstream error so
    /// the operator gets a precise diagnostic.
    #[error("Code Assist OAuth flow failed: {0}")]
    OauthFlowFailed(#[from] super::oauth_flow::OauthFlowError),
}

/// Verifies the user's prior interactive gemini-cli OAuth state and
/// writes a Code Assist OAuth binding marker for the slot.
///
/// **Behavioral change from Stage 2 of journal 0048** (journal 0054
/// codifies the regression discovery): csq no longer shells out to
/// `gemini auth login`. gemini-cli v0.41.2 removed the `auth`
/// subcommand; positional args default to interactive mode and the
/// previous shell-out is now silently parsed as a prompt. csq's role
/// is to verify + record, not to drive OAuth.
///
/// Steps:
///
/// 1. Validate `base_dir` exists.
/// 2. Refuse if the slot is bound to a non-Gemini surface.
/// 3. CWD-ancestor `.env` scan — refuse on shadow-auth match (gemini-cli
///    prefers ambient API-key over OAuth, would silently bind to the
///    wrong identity at next `csq run N`).
/// 4. Verify `~/.gemini/oauth_creds.json` exists, parses, and carries
///    a non-expired `access_token`. Each failure mode maps to a
///    specific error variant with a remediation hint.
/// 5. Write the binding marker via [`provision_code_assist_oauth`].
///
/// Synchronous and fast (no network, no subprocess). Idempotent — if
/// the binding already exists, calling `perform` again refreshes any
/// staleness in the marker shape without disturbing OAuth state.
pub fn perform(base_dir: &Path, slot: AccountNum) -> Result<(), OauthLoginError> {
    if !base_dir.is_dir() {
        return Err(OauthLoginError::BaseDirMissing(base_dir.to_path_buf()));
    }

    if let Some(existing) = detect_other_surface_binding(base_dir, slot) {
        let surface = match existing {
            BoundSurface::Codex => "Codex",
            BoundSurface::ClaudeCode => "Claude (Anthropic OAuth)",
        };
        return Err(OauthLoginError::OtherSurfaceBound {
            slot: slot.get(),
            surface,
        });
    }

    // CWD-ancestor `.env` scan. gemini-cli walks CWD ancestors for
    // `.env` and prefers ambient `GOOGLE_API_KEY` / `GEMINI_API_KEY` /
    // `GOOGLE_APPLICATION_CREDENTIALS` over the OAuth flow. Refuse
    // here so a slot does not get bound in OAuth mode while
    // gemini-cli would silently use ambient API-key auth at next
    // `csq run N`.
    let cwd = std::env::current_dir().map_err(OauthLoginError::CwdResolveFailed)?;
    // Round-2 redteam LOW-2: treat HOME=="" the same as HOME unset; an
    // empty HOME would resolve `~/.gemini/oauth_creds.json` to the
    // CWD-relative path `.gemini/oauth_creds.json`, which then fails
    // with NotFound and surfaces the wrong remediation hint.
    let home_dir = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    if let DotenvScanResult::ShadowAuthFound { env_file, variable } =
        pre_spawn_dotenv_scan(&cwd, home_dir.as_deref())
    {
        return Err(OauthLoginError::ShadowAuthInDotenv { env_file, variable });
    }

    // Verify `~/.gemini/oauth_creds.json` exists + valid + fresh. If
    // missing or stale, drive the OAuth flow ourselves (Round-7 — csq
    // owns the dance now that gemini-cli v0.41.2+ has no
    // non-interactive auth surface; see `oauth_flow` module + journal
    // 0054 amendment).
    let oauth_creds_path = home_dir
        .as_ref()
        .map(|h| h.join(".gemini").join("oauth_creds.json"))
        .ok_or_else(|| {
            OauthLoginError::CwdResolveFailed(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "HOME env var not set or empty",
            ))
        })?;
    match verify_oauth_creds(&oauth_creds_path, slot) {
        Ok(()) => {
            // Tokens are valid; no OAuth needed (idempotent path).
        }
        Err(OauthLoginError::GeminiOauthCredsNotFound { .. })
        | Err(OauthLoginError::GeminiOauthCredsStale { .. })
        | Err(OauthLoginError::GeminiOauthCredsMalformed { .. }) => {
            // No tokens or unusable tokens — run the OAuth flow.
            super::oauth_flow::run().map_err(OauthLoginError::OauthFlowFailed)?;
            // Re-verify post-flow (paranoia: confirm we wrote what we
            // think we wrote).
            verify_oauth_creds(&oauth_creds_path, slot)?;
        }
        Err(other) => return Err(other),
    }

    provision_code_assist_oauth(base_dir, slot)?;
    Ok(())
}

/// Verifies `~/.gemini/oauth_creds.json` is present, parses, and has
/// a non-expired `access_token`. Returns the appropriate error variant
/// for each failure mode so the CLI can surface an actionable hint.
///
/// gemini-cli writes oauth_creds.json with the shape:
/// ```json
/// {
///   "access_token": "ya29....",
///   "refresh_token": "1//...",
///   "scope": "https://www.googleapis.com/auth/cloud-platform ...",
///   "token_type": "Bearer",
///   "id_token": "eyJ...",
///   "expiry_date": 1778125985912  // Unix milliseconds
/// }
/// ```
///
/// We do NOT extract or copy any secrets — only verify the shape +
/// freshness. Per `feedback_delegate_to_reference_client`, gemini-cli
/// owns these tokens; csq is read-only.
fn verify_oauth_creds(path: &Path, slot: AccountNum) -> Result<(), OauthLoginError> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OauthLoginError::GeminiOauthCredsNotFound { slot: slot.get() });
        }
        // Round-2 redteam MEDIUM-3 — distinguish PermissionDenied / I/O
        // from Malformed. The remediations differ ("chmod 600" vs
        // "re-run gemini"). Mapping every I/O error to Malformed is
        // an unhelpful coalesce.
        Err(e) => {
            return Err(OauthLoginError::GeminiOauthCredsUnreadable {
                path: path.to_path_buf(),
                reason: format!("{e}"),
            });
        }
    };
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| OauthLoginError::GeminiOauthCredsMalformed {
            path: path.to_path_buf(),
            reason: format!("invalid JSON: {e}"),
        })?;
    // access_token must be a non-empty string. We do not log or store
    // it — just confirm presence.
    let access_token_present = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .is_some_and(|s| !s.is_empty());
    if !access_token_present {
        return Err(OauthLoginError::GeminiOauthCredsMalformed {
            path: path.to_path_buf(),
            reason: "missing or empty `access_token` field".into(),
        });
    }
    // expiry_date is Unix milliseconds. gemini-cli is JS — `Date.now()`
    // is integer-typed but a future google-auth-library upgrade could
    // serialize via f64 (e.g. `(Date.now() / 1000) * 1000` introduces
    // a `.0`, serde_json deserializes to f64 even though the integer
    // value is exact). `as_i64()` returns None for f64 numbers; round-2
    // redteam MEDIUM-1 found this would mis-classify as Malformed and
    // tell the user to "re-run gemini" — which would not fix anything.
    // Accept either i64 or f64-with-integer-value.
    let expiry_ms = v
        .get("expiry_date")
        .and_then(|e| e.as_i64().or_else(|| e.as_f64().map(|f| f as i64)))
        .unwrap_or(0);
    if expiry_ms <= 0 {
        return Err(OauthLoginError::GeminiOauthCredsMalformed {
            path: path.to_path_buf(),
            reason: "missing, null, or non-positive `expiry_date` field".into(),
        });
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if expiry_ms <= now_ms {
        return Err(OauthLoginError::GeminiOauthCredsStale { slot: slot.get() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Journal 0048 + 0054 — verify the binary-name constant is still
    /// importable. csq no longer shells out to gemini-cli from this
    /// module (v0.41.2 removed the auth subcommand), but `spawn::spawn_gemini`
    /// continues to pin the binary name; this assertion stays here as
    /// a sanity check that the workspace-wide pinning is healthy.
    #[test]
    fn gemini_cli_binary_pinned_to_literal_gemini() {
        assert_eq!(super::super::GEMINI_CLI_BINARY, "gemini");
    }

    #[test]
    fn refuses_when_base_dir_missing() {
        let err = perform(Path::new("/nonexistent/csq-base-redteam"), slot(1)).unwrap_err();
        match err {
            OauthLoginError::BaseDirMissing(p) => {
                assert_eq!(p, PathBuf::from("/nonexistent/csq-base-redteam"))
            }
            other => panic!("expected BaseDirMissing, got {other:?}"),
        }
    }

    #[test]
    fn refuses_when_slot_bound_to_codex() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-7.json"), b"{}").unwrap();

        let err = perform(dir.path(), slot(7)).unwrap_err();
        match err {
            OauthLoginError::OtherSurfaceBound {
                slot: 7,
                surface: "Codex",
            } => {}
            other => panic!("expected OtherSurfaceBound{{Codex}}, got {other:?}"),
        }
    }

    #[test]
    fn refuses_when_slot_bound_to_claude_oauth() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join("8.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let err = perform(dir.path(), slot(8)).unwrap_err();
        match err {
            OauthLoginError::OtherSurfaceBound {
                slot: 8,
                surface: "Claude (Anthropic OAuth)",
            } => {}
            other => panic!("expected OtherSurfaceBound{{Claude}}, got {other:?}"),
        }
    }

    /// Error display strings match the UI contract (see
    /// `rules/tauri-commands.md` MUST 6 — every named error variant
    /// MUST surface specific UI text).
    #[test]
    fn error_display_strings_are_actionable() {
        assert_eq!(
            OauthLoginError::GeminiCliNotInstalled.to_string(),
            "gemini-cli not installed: install from https://github.com/google-gemini/gemini-cli"
        );
        // Journal 0054 — replaced OauthFlowDidNotComplete (was raised
        // when `gemini auth login` shell-out exited non-zero; v0.41.2
        // has no such subcommand) with three preflight-check variants.
        let err = OauthLoginError::GeminiOauthCredsNotFound { slot: 13 };
        let display = err.to_string();
        assert!(display.contains("run `gemini` once interactively"));
        assert!(display.contains("csq login 13 --provider gemini"));
        let err = OauthLoginError::GeminiOauthCredsStale { slot: 13 };
        let display = err.to_string();
        assert!(display.contains("expired"));
        assert!(display.contains("csq login 13 --provider gemini"));
        let err = OauthLoginError::GeminiOauthCredsMalformed {
            path: PathBuf::from("/Users/me/.gemini/oauth_creds.json"),
            reason: "missing or empty `access_token` field".into(),
        };
        assert!(err.to_string().contains("missing or empty `access_token`"));

        let err = OauthLoginError::OtherSurfaceBound {
            slot: 3,
            surface: "Codex",
        };
        assert_eq!(
            err.to_string(),
            "slot 3 is bound to Codex — run `csq logout 3` to rebind to Gemini"
        );
        let err = OauthLoginError::ShadowAuthInDotenv {
            env_file: PathBuf::from("/home/jack-private/work-confidential/.env"),
            variable: "GOOGLE_API_KEY".into(),
        };
        let display = err.to_string();
        assert!(display.contains("GOOGLE_API_KEY"));
        // Round-2 redteam MED: the user's directory tree MUST NOT
        // appear in the Display string — it could leak via future
        // telemetry / crash-reporter surfaces.
        assert!(
            !display.contains("/home/jack-private"),
            "ShadowAuthInDotenv must not leak directory tree: {display}"
        );
        assert!(
            !display.contains("work-confidential"),
            "ShadowAuthInDotenv must not leak directory tree: {display}"
        );
    }

    /// Journal 0054 — verify_oauth_creds is the new core check.
    /// Tests cover the three failure modes + the success path.
    #[test]
    fn verify_oauth_creds_succeeds_on_fresh_token() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oauth_creds.json");
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64)
            + 3_600_000;
        std::fs::write(
            &path,
            format!(
                r#"{{"access_token":"ya29.X","refresh_token":"1//Y","scope":"s","token_type":"Bearer","expiry_date":{future_ms}}}"#
            ),
        )
        .unwrap();
        verify_oauth_creds(&path, slot(13)).unwrap();
    }

    #[test]
    fn verify_oauth_creds_returns_not_found_on_missing_file() {
        let err =
            verify_oauth_creds(Path::new("/nonexistent/oauth_creds.json"), slot(13)).unwrap_err();
        match err {
            OauthLoginError::GeminiOauthCredsNotFound { slot: 13 } => {}
            other => panic!("expected GeminiOauthCredsNotFound, got {other:?}"),
        }
    }

    #[test]
    fn verify_oauth_creds_returns_stale_on_expired_token() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oauth_creds.json");
        // Past timestamp.
        std::fs::write(
            &path,
            r#"{"access_token":"ya29.X","refresh_token":"1//Y","scope":"s","token_type":"Bearer","expiry_date":1000000}"#,
        )
        .unwrap();
        let err = verify_oauth_creds(&path, slot(13)).unwrap_err();
        match err {
            OauthLoginError::GeminiOauthCredsStale { slot: 13 } => {}
            other => panic!("expected GeminiOauthCredsStale, got {other:?}"),
        }
    }

    #[test]
    fn verify_oauth_creds_returns_malformed_on_missing_access_token() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oauth_creds.json");
        std::fs::write(&path, r#"{"expiry_date":99999999999999}"#).unwrap();
        let err = verify_oauth_creds(&path, slot(13)).unwrap_err();
        match err {
            OauthLoginError::GeminiOauthCredsMalformed { reason, .. } => {
                assert!(reason.contains("access_token"));
            }
            other => panic!("expected GeminiOauthCredsMalformed, got {other:?}"),
        }
    }

    /// Round-2 redteam MEDIUM-2 — `expiry_date: null` should be
    /// treated as malformed (gemini-cli always sets it after OAuth).
    #[test]
    fn verify_oauth_creds_returns_malformed_on_null_expiry_date() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oauth_creds.json");
        std::fs::write(
            &path,
            r#"{"access_token":"ya29.X","refresh_token":"1//Y","scope":"s","token_type":"Bearer","expiry_date":null}"#,
        )
        .unwrap();
        let err = verify_oauth_creds(&path, slot(13)).unwrap_err();
        match err {
            OauthLoginError::GeminiOauthCredsMalformed { reason, .. } => {
                assert!(
                    reason.contains("expiry_date"),
                    "expected expiry_date in reason, got: {reason}"
                );
            }
            other => panic!("expected GeminiOauthCredsMalformed, got {other:?}"),
        }
    }

    /// Round-2 redteam MEDIUM-1 — float-typed `expiry_date` (e.g. from
    /// a future google-auth-library upgrade that introduces a `.0`)
    /// must NOT misclassify as Malformed. The fix uses
    /// `as_i64().or_else(as_f64.map(|f| f as i64))` so f64-with-integer-value
    /// gets accepted.
    #[test]
    fn verify_oauth_creds_accepts_f64_expiry_date() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oauth_creds.json");
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64)
            + 3_600_000;
        // Force serde_json to deserialize as f64 by using a literal
        // with a decimal point.
        std::fs::write(
            &path,
            format!(
                r#"{{"access_token":"ya29.X","refresh_token":"1//Y","scope":"s","token_type":"Bearer","expiry_date":{future_ms}.0}}"#
            ),
        )
        .unwrap();
        verify_oauth_creds(&path, slot(13)).expect("f64 expiry_date should be accepted");
    }

    /// Round-2 redteam MEDIUM-3 — I/O errors that are NOT NotFound
    /// (e.g. PermissionDenied) get the `GeminiOauthCredsUnreadable`
    /// variant with a chmod-fix hint, NOT Malformed (which would
    /// (incorrectly) tell the user to re-OAuth).
    #[cfg(unix)]
    #[test]
    fn verify_oauth_creds_returns_unreadable_on_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oauth_creds.json");
        std::fs::write(
            &path,
            r#"{"access_token":"x","expiry_date":99999999999999}"#,
        )
        .unwrap();
        // Strip read permission.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&path, perms.clone()).unwrap();
        let result = verify_oauth_creds(&path, slot(13));
        // Restore so TempDir can clean up.
        let mut p = perms;
        p.set_mode(0o600);
        let _ = std::fs::set_permissions(&path, p);
        match result.unwrap_err() {
            OauthLoginError::GeminiOauthCredsUnreadable { reason, .. } => {
                assert!(
                    !reason.is_empty(),
                    "Unreadable variant must surface OS error message"
                );
            }
            other => panic!("expected GeminiOauthCredsUnreadable, got {other:?}"),
        }
    }

    // Note: pre-journal-0054 tests for `OauthFlowDidNotComplete` token
    // redaction were removed when that variant was deleted. The
    // current code path never inspects gemini-cli's stderr (no shell-out),
    // so there is no token-leak vector to defend against in this module.
    // Token redaction at the workspace level is still covered by
    // `crate::error::redact_tokens`'s own test suite.
}
