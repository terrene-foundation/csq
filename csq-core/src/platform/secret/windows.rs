//! Windows Vault backend stub — full implementation lands in PR-G2a.3.
//!
//! Per the implementation plan §M3 ("split for parallelism") the
//! Windows DPAPI / Credential Manager backend (via `windows-sys`
//! `CredWriteW` / `CredReadW` / `CredDeleteW`) lands in a follow-up
//! PR with its own security-reviewer sign-off and a separate audit
//! of the `LocalSystem` refusal posture (see security-reviewer Q5).
//!
//! This file exists in PR-G2a so the `pub mod windows;` declaration
//! in [`super`] resolves on every platform (cargo fmt walks mod
//! declarations regardless of `cfg(target_os)`).
//!
//! The factory in [`super::open_native_default`] currently returns
//! [`super::SecretError::BackendUnavailable`] on Windows with a
//! pointer to PR-G2a.3.

#![cfg(target_os = "windows")]
