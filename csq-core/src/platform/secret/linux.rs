//! Linux Vault backend stub — full implementation lands in PR-G2a.2.
//!
//! Per the implementation plan §M3 ("split for parallelism") the
//! Linux Secret Service backend (via `secret-service` crate) plus
//! the explicit AES-GCM file fallback (via `aes-gcm` + `argon2`)
//! land in a follow-up PR with its own security-reviewer sign-off.
//!
//! This file exists in PR-G2a so the `pub mod linux;` declaration
//! in [`super`] resolves on every platform (cargo fmt walks mod
//! declarations regardless of `cfg(target_os)`).
//!
//! The factory in [`super::open_native_default`] currently returns
//! [`super::SecretError::BackendUnavailable`] on Linux with a
//! pointer to PR-G2a.2.

#![cfg(target_os = "linux")]
