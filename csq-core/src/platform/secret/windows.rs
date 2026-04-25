//! Windows [`Vault`] backend — Credential Manager via DPAPI.
//!
//! Uses the Win32 `Cred*` API (`CredWriteW` / `CredReadW` /
//! `CredDeleteW` / `CredEnumerateW` / `CredFree`). Items are stored as
//! `CRED_TYPE_GENERIC` with `CRED_PERSIST_LOCAL_MACHINE` so they
//! survive a logoff but stay tied to the user's DPAPI master key
//! (NOT the roaming `CRED_PERSIST_ENTERPRISE` flavor — see Q7 in
//! workspaces/gemini/journal/0005, which closes the iCloud/AD
//! "deleted entries may resurrect" class of bugs by refusing to use
//! the roaming persistence type).
//!
//! # Refuse-to-operate as `LocalSystem`
//!
//! DPAPI keys are derived from the user profile. A daemon launched
//! as `LocalSystem` (e.g. via a Windows service installed by an
//! enterprise admin) sees a different DPAPI scope from a user-launched
//! `csq-cli` — credentials written by one are invisible to the other,
//! and the daemon would silently re-prompt the user every session.
//! The whole multi-account-rotation premise breaks.
//!
//! [`open_windows_default`] checks the process token's user SID
//! against `WinLocalSystemSid` and refuses with `BackendUnavailable`
//! when it matches, naming the reason so an admin who deployed csq as
//! a service can self-diagnose. The check is fail-CLOSED — if the
//! token cannot be queried (e.g. corrupted token, missing
//! `TOKEN_QUERY` right) the dispatch refuses too rather than assume
//! "not SYSTEM" (security review M2).
//!
//! `LocalService` and `NetworkService` use per-account DPAPI scopes
//! and are not subject to the same SYSTEM-binding mismatch — they are
//! intentionally not refused. If a future deployment surfaces issues
//! under those identities the refusal can be widened.
//!
//! # Sole ownership
//!
//! Sole-owned by Gemini per H8 in the implementation plan. Codex
//! continues to use `credentials/file.rs` + `secure_file` for its
//! OAuth artefact; Anthropic continues to use `~/.claude/.credentials.json`.
//! `platform::secret` is reserved for surfaces with no OAuth lifecycle
//! (Gemini today, possibly Bedrock tomorrow).

#![cfg(target_os = "windows")]

use super::{run_with_timeout, SecretError, SlotKey, Vault};
use crate::types::AccountNum;
use secrecy::{ExposeSecret, SecretString};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::warn;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_FOUND, FILETIME, HANDLE,
};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroizing;

/// Production Windows Credential Manager backend. Stateless — every
/// method is a fresh syscall, matching the macOS / Linux patterns'
/// "no in-process caching" rule.
pub struct WindowsCredentialVault;

impl WindowsCredentialVault {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsCredentialVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault for WindowsCredentialVault {
    fn set(&self, slot: SlotKey, secret: &SecretString) -> Result<(), SecretError> {
        if secret.expose_secret().is_empty() {
            return Err(SecretError::InvalidKey {
                reason: "secret must not be empty".into(),
            });
        }
        validate_slot_for_windows(slot)?;
        let target = to_wide(&slot.native_name())?;
        let username = to_wide("csq")?;
        // `Zeroizing<Vec<u8>>` derefs to `Vec<u8>` so `as_mut_ptr` /
        // `len` still work; `Drop` wipes the cleartext copy after the
        // syscall returns. CredWriteW copies into its own internal
        // storage per Microsoft's documentation, so the local buffer
        // never has to outlive the call.
        let mut blob: Zeroizing<Vec<u8>> =
            Zeroizing::new(secret.expose_secret().as_bytes().to_vec());

        run_with_timeout("csq-vault-credman", move || {
            let mut cred = CREDENTIALW {
                Flags: 0,
                Type: CRED_TYPE_GENERIC,
                TargetName: target.as_ptr() as *mut u16,
                Comment: ptr::null_mut(),
                LastWritten: FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                },
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: ptr::null_mut(),
                TargetAlias: ptr::null_mut(),
                UserName: username.as_ptr() as *mut u16,
            };
            // SAFETY: pointers in `cred` reference buffers owned by
            // the move closure; they outlive the call. CredWriteW
            // does NOT take ownership of any pointer — the API copies
            // into its own internal storage.
            let ok = unsafe { CredWriteW(&mut cred, 0) };
            if ok == 0 {
                return Err(map_last_error("CredWriteW"));
            }
            // Explicit drops keep the move-only buffers visible to a
            // future reader of this code: the API has copied out of
            // them, so we wipe `blob` (cleartext) and free the wide
            // strings here rather than at end-of-closure scope.
            drop(blob);
            drop(target);
            drop(username);
            Ok(())
        })
    }

    fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError> {
        validate_slot_for_windows(slot)?;
        let target = to_wide(&slot.native_name())?;
        let surface = slot.surface;
        let account = slot.account.get();
        run_with_timeout("csq-vault-credman", move || {
            let mut out: *mut CREDENTIALW = ptr::null_mut();
            // SAFETY: `out` is a writable pointer location; CredReadW
            // either fails or fills it with an allocated `CREDENTIALW`
            // that we MUST free with CredFree.
            let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut out) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_NOT_FOUND {
                    return Err(SecretError::NotFound { surface, account });
                }
                return Err(map_error_code("CredReadW", err));
            }

            // SAFETY: `out` is valid for the duration of this block;
            // we copy the blob bytes into a `Zeroizing` Vec so the
            // cleartext copy is wiped on drop even if the UTF-8
            // conversion path fails.
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(unsafe {
                let cred = &*out;
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                    .to_vec()
            });
            // SAFETY: `out` came from CredReadW — must be released
            // via CredFree before we exit this block.
            unsafe { CredFree(out as *mut c_void) };

            // Non-UTF-8 is a foreign-writer / corruption signal, NOT
            // a decryption failure (the variant doc on
            // SecretError::DecryptionFailed prompts re-provisioning
            // which is not the right action here). Map to InvalidKey
            // so the audit log carries the right tag.
            let s = String::from_utf8(bytes.to_vec()).map_err(|_| SecretError::InvalidKey {
                reason: "stored Windows Credential Manager secret is not valid UTF-8".into(),
            })?;
            Ok(SecretString::new(s.into()))
        })
    }

    fn delete(&self, slot: SlotKey) -> Result<(), SecretError> {
        validate_slot_for_windows(slot)?;
        let target = to_wide(&slot.native_name())?;
        run_with_timeout("csq-vault-credman", move || {
            // SAFETY: `target` is a null-terminated UTF-16 string for
            // the duration of the call (closure owns the Vec).
            let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_NOT_FOUND {
                    return Ok(());
                }
                return Err(map_error_code("CredDeleteW", err));
            }
            Ok(())
        })
    }

    fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError> {
        validate_surface_for_windows(surface)?;
        // Wildcard filter `csq.<surface>.*` — restricts enumeration
        // to our namespace so a host with thousands of unrelated
        // Credential Manager entries does not pay for them on every
        // call. `validate_surface_for_windows` already rejected `*`,
        // `?`, `,`, `\0` so the format-string path cannot inject a
        // pattern metacharacter.
        let filter = to_wide(&format!("csq.{surface}.*"))?;
        let prefix = format!("csq.{surface}.");

        run_with_timeout("csq-vault-credman", move || {
            let mut count: u32 = 0;
            let mut creds: *mut *mut CREDENTIALW = ptr::null_mut();

            // SAFETY: filter is null-terminated UTF-16; `count` and
            // `creds` are writable pointers CredEnumerateW either
            // fails or fills.
            let ok = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut creds) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_NOT_FOUND {
                    return Ok(Vec::new());
                }
                return Err(map_error_code("CredEnumerateW", err));
            }

            let mut out: Vec<u16> = Vec::with_capacity(count as usize);
            // SAFETY: `creds` points at `count` valid `CREDENTIALW`
            // pointers; every dereference is bounded.
            unsafe {
                for i in 0..count {
                    let cred_ptr = *creds.add(i as usize);
                    if cred_ptr.is_null() {
                        continue;
                    }
                    let cred = &*cred_ptr;
                    if cred.TargetName.is_null() {
                        continue;
                    }
                    let mut len = 0usize;
                    while *cred.TargetName.add(len) != 0 {
                        len += 1;
                        if len > 256 {
                            // L1: emit a structured warning so an
                            // operator can spot Credential Manager
                            // corruption before it spreads silently.
                            warn!(
                                error_kind = "vault_corrupt_target_name",
                                "skipping Credential Manager entry with runaway target name"
                            );
                            break;
                        }
                    }
                    let name_bytes = std::slice::from_raw_parts(cred.TargetName, len);
                    let Ok(name) = String::from_utf16(name_bytes) else {
                        // L2: warn on invalid UTF-16 — same logic.
                        warn!(
                            error_kind = "vault_invalid_utf16_target_name",
                            "skipping Credential Manager entry with invalid UTF-16 target name"
                        );
                        continue;
                    };
                    if let Some(acct_str) = name.strip_prefix(&prefix).filter(|s| !s.is_empty()) {
                        if let Ok(n) = acct_str.parse::<u16>() {
                            out.push(n);
                        }
                    }
                }
            }

            // SAFETY: `creds` came from CredEnumerateW — freeing the
            // outer pointer also releases the inner CREDENTIALW
            // entries per Microsoft documentation.
            unsafe { CredFree(creds as *mut c_void) };

            out.sort_unstable();
            out.dedup();
            Ok(out
                .into_iter()
                .filter_map(|n| AccountNum::try_from(n).ok())
                .collect())
        })
    }

    fn backend_id(&self) -> &'static str {
        "windows-credential-manager"
    }
}

// ── helpers ───────────────────────────────────────────────────────────

/// Converts a Rust `&str` to a null-terminated UTF-16 vector for the
/// Win32 `*W` APIs. Rejects inputs containing an interior `\0` so a
/// caller cannot truncate the string the API will see (security
/// review H2 — embedded NULs in target names silently rebind to a
/// shorter slot identity).
fn to_wide(s: &str) -> Result<Vec<u16>, SecretError> {
    if s.contains('\0') {
        return Err(SecretError::InvalidKey {
            reason: format!("string {s:?} contains an interior NUL byte"),
        });
    }
    Ok(std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

/// Validates that `surface` is safe for use in a Credential Manager
/// target name AND in the `CredEnumerateW` filter pattern. The Win32
/// pattern syntax treats `*`, `?`, and `,` as metacharacters; an
/// embedded NUL would silently truncate the wide string. Today every
/// caller uses a static surface string ("gemini", "gemini-test"), but
/// validating at the boundary defends against future callers that
/// might thread untrusted data through (security review H1).
fn validate_surface_for_windows(surface: &str) -> Result<(), SecretError> {
    if surface.is_empty() {
        return Err(SecretError::InvalidKey {
            reason: "surface tag must not be empty".into(),
        });
    }
    let safe = surface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !safe {
        return Err(SecretError::InvalidKey {
            reason: format!(
                "surface tag {surface:?} contains characters not safe for Win32 \
                 Credential Manager target names (allowed: ASCII alphanumeric, '-', '_')"
            ),
        });
    }
    Ok(())
}

/// Convenience wrapper around [`validate_surface_for_windows`] for
/// per-slot operations. The account number comes from `AccountNum`
/// which is already validated 1..MAX_ACCOUNTS so it cannot inject.
fn validate_slot_for_windows(slot: SlotKey) -> Result<(), SecretError> {
    validate_surface_for_windows(slot.surface)
}

/// Reads `GetLastError` and maps the resulting code through
/// [`map_error_code`].
fn map_last_error(operation: &'static str) -> SecretError {
    let code = unsafe { GetLastError() };
    map_error_code(operation, code)
}

/// Maps a known Win32 error code to a [`SecretError`]. Reason strings
/// describe the operation + numeric code so the audit log records
/// enough to file an issue without needing platform expertise.
fn map_error_code(operation: &'static str, code: u32) -> SecretError {
    // Win32 error codes referenced from the official documentation
    // for the Cred* family.
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NO_SUCH_LOGON_SESSION: u32 = 1312;
    const ERROR_BAD_USERNAME: u32 = 2202;

    match code {
        ERROR_NO_SUCH_LOGON_SESSION => SecretError::AuthorizationRequired,
        ERROR_BAD_USERNAME => SecretError::PermissionDenied {
            reason: format!("{operation}: ERROR_BAD_USERNAME ({code})"),
        },
        ERROR_INVALID_PARAMETER => SecretError::InvalidKey {
            reason: format!("{operation}: ERROR_INVALID_PARAMETER ({code})"),
        },
        _ => SecretError::BackendUnavailable {
            reason: format!("{operation} failed with Win32 error code {code}"),
        },
    }
}

/// Result form of the LocalSystem check — fail-closed per security
/// review M2. Returns `Ok(true)` when the process IS running as
/// SYSTEM, `Ok(false)` when it is NOT, and `Err(...)` when the token
/// cannot be queried (do not assume "not SYSTEM" in that case — a
/// daemon with a corrupted token landing in a privileged scope is
/// the security boundary we are protecting).
pub fn check_local_system_posture() -> Result<bool, SecretError> {
    let process = unsafe { GetCurrentProcess() };
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(SecretError::BackendUnavailable {
            reason: format!("OpenProcessToken failed with Win32 error code {code}"),
        });
    }

    let mut needed = 0u32;
    // First call: query the required buffer size.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        let code = unsafe { GetLastError() };
        unsafe { CloseHandle(token) };
        return Err(SecretError::BackendUnavailable {
            reason: format!("GetTokenInformation size query returned 0 (Win32 error code {code})"),
        });
    }

    let mut buf = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        unsafe { CloseHandle(token) };
        return Err(SecretError::BackendUnavailable {
            reason: format!("GetTokenInformation failed with Win32 error code {code}"),
        });
    }

    // SAFETY: buf is sized to `needed` and TokenUser fills exactly a
    // `TOKEN_USER` plus a SID payload at the trailing pointer.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    let is_system = unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0;

    unsafe { CloseHandle(token) };
    Ok(is_system)
}

/// Convenience wrapper that downgrades the M2-style error path to a
/// `bool` for callers that only care about the binary outcome
/// (display layers, logging). Production dispatch uses
/// [`check_local_system_posture`] directly so it can fail-closed.
pub fn is_running_as_local_system() -> bool {
    check_local_system_posture().unwrap_or(false)
}

// ── factory ───────────────────────────────────────────────────────────

/// Windows backend selector called from [`super::open_native_default`].
///
/// - `CSQ_SECRET_BACKEND=file` → refuse: file backend is Linux-only
///   per journal 0005 §1 (no silent fallback when DPAPI exists).
/// - Default / `keychain` / `auto` → check for `LocalSystem` posture
///   (fail-CLOSED on token query failure per security review M2),
///   then return [`WindowsCredentialVault`].
pub fn open_windows_default(override_kind: Option<&str>) -> Result<Box<dyn Vault>, SecretError> {
    match override_kind {
        Some("file") => Err(SecretError::BackendUnavailable {
            reason: "CSQ_SECRET_BACKEND=file is Linux-only — Windows uses DPAPI / Credential \
                     Manager"
                .into(),
        }),
        Some("keychain") | Some("auto") | None => {
            // Fail-closed: if we cannot tell whether we are running
            // as LocalSystem, refuse rather than guess. A daemon
            // with a stripped TOKEN_QUERY right is exactly the
            // misconfigured-deployment case the SYSTEM check exists
            // to catch.
            let is_system =
                check_local_system_posture().map_err(|e| SecretError::BackendUnavailable {
                    reason: format!(
                        "could not determine LocalSystem posture (refusing fail-closed): {}",
                        match e {
                            SecretError::BackendUnavailable { reason } => reason,
                            other => other.to_string(),
                        }
                    ),
                })?;
            if is_system {
                return Err(SecretError::BackendUnavailable {
                    reason: "csq daemon is running as LocalSystem — DPAPI binds to the user \
                             profile, so a SYSTEM-launched daemon cannot read or write \
                             credentials provisioned by a user-launched csq-cli. Re-launch csq \
                             under the target user account or use Task Scheduler with \
                             'Run only when user is logged on'."
                        .into(),
                });
            }
            Ok(Box::new(WindowsCredentialVault::new()))
        }
        Some(other) => Err(SecretError::BackendUnavailable {
            reason: format!("unknown CSQ_SECRET_BACKEND value: {other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    //! Windows Credential Manager tests touch the real Vault and
    //! require a logged-in user session. They are gated by both
    //! `#[cfg(target_os = "windows")]` (compile-time) and `#[ignore]`
    //! (runtime, opt-in via `cargo test -- --ignored`). Standard
    //! `cargo test --workspace` does NOT run them — they pollute the
    //! developer's Credential Manager with throwaway entries.
    //!
    //! Run them locally on a Windows dev box before signing off
    //! PR-G2a.3 per the security-reviewer's gate.

    use super::*;
    use crate::types::AccountNum;

    fn slot(n: u16) -> SlotKey {
        SlotKey {
            surface: "gemini-test",
            account: AccountNum::try_from(n).unwrap(),
        }
    }

    /// RAII guard that deletes the test slot on drop so a panicking
    /// test cannot leave Credential Manager residue.
    struct ScopedSlot(SlotKey);
    impl Drop for ScopedSlot {
        fn drop(&mut self) {
            let v = WindowsCredentialVault::new();
            let _ = v.delete(self.0);
        }
    }

    #[test]
    #[ignore = "touches real Windows Credential Manager — run with --ignored"]
    fn live_set_get_round_trip() {
        let s = slot(900);
        let _g = ScopedSlot(s);
        let v = WindowsCredentialVault::new();
        // Obviously-fake test fixture per security.md §1 + L3 — does
        // not match any production secret format scanner regex.
        v.set(s, &SecretString::new("NOT-A-REAL-KEY-windows-test".into()))
            .expect("set");
        let got = v.get(s).expect("get");
        assert_eq!(got.expose_secret(), "NOT-A-REAL-KEY-windows-test");
    }

    #[test]
    #[ignore = "touches real Windows Credential Manager — run with --ignored"]
    fn live_delete_idempotent() {
        let s = slot(901);
        let _g = ScopedSlot(s);
        let v = WindowsCredentialVault::new();
        v.delete(s).expect("delete on empty");
        v.set(s, &SecretString::new("x".into())).expect("set");
        v.delete(s).expect("delete after set");
        v.delete(s).expect("delete idempotent");
        assert!(matches!(v.get(s), Err(SecretError::NotFound { .. })));
    }

    #[test]
    #[ignore = "touches real Windows Credential Manager — run with --ignored"]
    fn live_list_slots_filters_by_surface() {
        let v = WindowsCredentialVault::new();
        let s1 = slot(910);
        let s2 = slot(911);
        let _g1 = ScopedSlot(s1);
        let _g2 = ScopedSlot(s2);
        v.set(s1, &SecretString::new("a".into())).unwrap();
        v.set(s2, &SecretString::new("b".into())).unwrap();
        let listed: Vec<u16> = v
            .list_slots("gemini-test")
            .unwrap()
            .iter()
            .map(|a| a.get())
            .collect();
        assert!(listed.contains(&910));
        assert!(listed.contains(&911));
    }

    #[test]
    fn backend_id_is_windows_credential_manager() {
        let v = WindowsCredentialVault::new();
        assert_eq!(v.backend_id(), "windows-credential-manager");
    }

    #[test]
    fn empty_secret_rejected_at_set_without_syscall() {
        // Validation runs before any Win32 call.
        let v = WindowsCredentialVault::new();
        let err = v
            .set(slot(1), &SecretString::new(String::new().into()))
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    #[test]
    fn to_wide_null_terminates() {
        let w = to_wide("csq.gemini.3").unwrap();
        assert_eq!(*w.last().unwrap(), 0u16);
        // 12 chars + 1 null = 13 u16s.
        assert_eq!(w.len(), 13);
    }

    /// Regression for security review H2: an interior NUL would
    /// silently truncate the wide string and rebind the call to a
    /// shorter slot identity. `to_wide` now refuses at the boundary.
    #[test]
    fn to_wide_rejects_embedded_nul() {
        let err = to_wide("csq.gem\0ini.1").unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    /// Regression for security review H1: a surface containing a
    /// pattern metacharacter could broaden the `CredEnumerateW`
    /// filter beyond the csq namespace. Validation refuses at the
    /// boundary.
    #[test]
    fn validate_surface_rejects_pattern_metachars() {
        for bad in ["gemini*", "gemi?ni", "gemini,leak", "gemini\0", ""] {
            let err = validate_surface_for_windows(bad).unwrap_err();
            assert!(
                matches!(err, SecretError::InvalidKey { .. }),
                "expected InvalidKey for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_surface_accepts_documented_tags() {
        for ok in ["gemini", "gemini-test", "future_surface", "anthropic"] {
            assert!(
                validate_surface_for_windows(ok).is_ok(),
                "expected accept for {ok:?}"
            );
        }
    }

    #[test]
    fn map_error_code_classifies_known_codes() {
        assert!(matches!(
            map_error_code("test", 1312),
            SecretError::AuthorizationRequired
        ));
        assert!(matches!(
            map_error_code("test", 87),
            SecretError::InvalidKey { .. }
        ));
        assert!(matches!(
            map_error_code("test", 99999),
            SecretError::BackendUnavailable { .. }
        ));
    }

    #[test]
    fn open_windows_default_refuses_file_override() {
        match open_windows_default(Some("file")) {
            Err(SecretError::BackendUnavailable { reason }) => {
                assert!(
                    reason.to_lowercase().contains("linux-only"),
                    "reason must explain why file is refused on Windows, got: {reason}"
                );
            }
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn open_windows_default_refuses_unknown_value() {
        match open_windows_default(Some("typo")) {
            Err(SecretError::BackendUnavailable { reason }) => {
                assert!(reason.contains("typo"));
            }
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }
}
