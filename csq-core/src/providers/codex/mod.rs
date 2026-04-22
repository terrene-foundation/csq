//! Codex (OpenAI ChatGPT subscription) surface glue.
//!
//! This module carries the login orchestration (PR-C3b) + keychain
//! residue probe for the `Surface::Codex` surface. Refresher + usage
//! polling live in `csq-core/src/daemon/*` and land in PR-C4 / PR-C5;
//! the `csq run` launch flow + `env_clear` allowlist land in PR-C3c.
//!
//! Authoritative reference: `specs/07-provider-surface-dispatch.md`
//! §7.2.2 (on-disk layout), §7.3.3 (login sequence), §7.5 invariants
//! P01–P11 (daemon prerequisite, mode-flip coordination, pre-seed
//! ordering).

pub mod desktop_login;
pub mod keychain;
pub mod login;
pub mod models;
pub mod surface;
pub mod tos;

pub use login::{perform, LoginOutcome};
