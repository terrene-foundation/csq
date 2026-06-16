//! M12 — AuthorityRegistry error types.
//!
//! All variants use fixed-vocabulary `&'static str` messages — no attacker-
//! controlled bytes are echoed (per `rules/security.md §2`). The roster and
//! pubkeys are PUBLIC material; private signing seeds NEVER appear here.

use thiserror::Error;

/// Errors from M12 authority-registry operations.
///
/// `#[non_exhaustive]` allows future variants without breaking callers.
/// All variants carry fixed-vocabulary messages only.
///
/// # Secret-leak policy
///
/// Messages carry op tags and fixed strings only. Roster versions, pubkey hex,
/// and principal strings are public and safe to surface to operators. Private
/// material is never present in a roster or in these errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthorityError {
    /// The enterprise roster file is absent from disk.
    ///
    /// Enterprise edition requires a signed roster. Missing roster is
    /// a misconfiguration — fail closed; do NOT fall back to community.
    #[error("enterprise authority roster is missing — cannot start without a signed roster")]
    RosterMissing,

    /// The roster file exists but could not be parsed (`#[serde(deny_unknown_fields)]`
    /// parse failure or JSON corruption).
    ///
    /// Fail closed — a corrupt roster could indicate tampering.
    #[error("authority roster is corrupt or unrecognized format — cannot trust it")]
    RosterCorrupt,

    /// The roster's Ed25519 signature does not verify against the org-root pubkey.
    ///
    /// The roster was either not signed by the org-root key, or was tampered
    /// with after signing. Fail closed.
    #[error("authority roster signature is invalid — possible tampering")]
    RosterSignatureInvalid,

    /// The roster's `roster_version` is below the `roster_version_floor` stored
    /// in `chain.json`. This indicates a rollback attempt.
    ///
    /// Fail closed — do NOT accept a rolled-back roster.
    #[error(
        "authority roster version is below the installed floor — \
         possible rollback attempt; install a newer roster"
    )]
    RosterRollback,

    /// The org-root pubkey could not be resolved: neither
    /// `CSQ_AUDIT_ROSTER_ROOT_PUBKEY` is set nor a `roster-root.pub` file
    /// exists under the audit directory.
    ///
    /// Enterprise edition cannot verify the roster without a root of trust.
    /// Fail closed.
    #[error(
        "roster root pubkey is not configured — set CSQ_AUDIT_ROSTER_ROOT_PUBKEY \
         or place roster-root.pub in the audit directory"
    )]
    RootPubkeyMissing,

    /// An I/O error occurred reading the roster or root pubkey file.
    /// The variant carries a fixed op tag (never a raw path or errno string).
    #[error("I/O error reading roster ({0})")]
    Io(&'static str),

    /// The roster's `format_version` is higher than what this version of csq
    /// supports. Install a newer csq to read this roster.
    ///
    /// Fail closed — an unrecognized format_version may carry unknown fields
    /// that affect membership semantics.
    #[error(
        "authority roster format_version {0} exceeds the maximum supported version \
         {1} — upgrade csq to read this roster"
    )]
    RosterFormatTooNew(u32, u32),

    /// The `roster-root.pub` file has insecure permissions (group- or
    /// world-readable/writable). The file MUST be mode 0o600 (owner read/write
    /// only) because it is the on-disk root-of-trust anchor for roster
    /// signature verification.
    ///
    /// Set permissions with: `chmod 600 <base>/audit/roster-root.pub`
    #[error(
        "roster-root.pub has insecure permissions — file must be mode 0o600 \
         (owner read/write only); run: chmod 600 <base>/audit/roster-root.pub"
    )]
    RootPubkeyInsecurePermissions,
}
