//! Launch-time isolation for `csq run` — Fact Guard X1, slice 1.
//!
//! Contract and rationale: `internal-design-docs`
//! (it becomes a spec section when the wiring lands with it). The three surfaces here are:
//!
//! 1. [`LaunchReceipt`] — the JSON facts a guard reads about a launch.
//! 2. [`scrub_env`] — removes admin-capable GitHub tokens from the child environment,
//!    failing CLOSED for a token whose scope cannot be determined.
//! 3. [`verify_manifest`] — the guard-file integrity check, with `Absent` as a
//!    first-class outcome that is never confused with `Verified`.
//!
//! The stated limit (plan §35.6): everything here runs as the session's own uid, so a
//! same-uid process can chmod and can rewrite its handle dir after the receipt is
//! written. The receipt records launch-time facts; it is not a live integrity assertion.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::types::AccountNum;

/// Receipt schema version. A change to the field set bumps this.
pub const RECEIPT_VERSION: u32 = 1;
/// Guard-manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;
/// Receipt filename inside the session's handle dir.
pub const RECEIPT_FILE: &str = "launch-receipt.json";
/// Environment variable carrying the receipt's absolute path to the child.
pub const RECEIPT_ENV_VAR: &str = "CSQ_LAUNCH_RECEIPT";
/// Guard manifest filename under the accounts base dir.
pub const MANIFEST_FILE: &str = "guard-manifest.json";
/// Approval mode csq sets on the command line when the sandbox is requested. What
/// the session effectively runs under can be looser (plan §35.6 limit 4).
pub const PERMISSION_MODE_SANDBOXED: &str = "manual";
/// Prefixes that carry a bypass request. Present in this module so the
/// `--sandbox` refusal and the argument builder cannot drift apart.
const BYPASS_FLAGS: [&str; 2] = [
    "--dangerously-skip-permissions",
    "--allow-dangerously-skip-permissions",
];

/// Why a receipt could not be written. The launch MUST NOT proceed without one.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptError {
    /// The receipt could not be staged or published atomically. `kind` is a
    /// fixed-vocabulary tag (`not_found`, `permission_denied`, `already_exists`,
    /// `invalid_input`, `other_io`, `platform`), never OS error text.
    #[error("the launch receipt could not be written ({kind})")]
    Unwritable {
        /// Fixed-vocabulary failure kind.
        kind: &'static str,
    },
    /// The receipt could not be serialised.
    #[error("the launch receipt could not be serialised")]
    Unserialisable,
}

/// Outcome of the guard-manifest check. The vocabulary is CLOSED: a value not in
/// this set cannot appear in a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardManifestState {
    /// Every entry matched at launch.
    Verified,
    /// No manifest existed, so nothing was checked. **Not integrity evidence.**
    Absent,
    /// An entry's bytes did not match its declared hash.
    Mismatch,
    /// The manifest existed but was unreadable, unparseable, or not contained.
    Invalid,
}

impl GuardManifestState {
    /// The wire spelling. `Absent` MUST NEVER render as `verified` (plan §35.4.3).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Absent => "absent",
            Self::Mismatch => "mismatch",
            Self::Invalid => "invalid",
        }
    }
}

impl serde::Serialize for GuardManifestState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Whether the sandbox is genuinely enforced, only the permission mode is pinned,
/// or the launch did not request it at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    /// csq wrote configuration the installed CLI honours.
    Enforced,
    /// Only the permission mode and the bypass refusal apply. Labelled honestly;
    /// plan §35.5 forbids calling this `enforced`.
    PermissionModeOnly,
    /// The operator did not pass `--sandbox`; csq pinned no mode and the receipt
    /// must not imply a weaker sandbox guarantee that was never requested.
    NotRequested,
}

impl SandboxState {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::PermissionModeOnly => "permission-mode-only",
            Self::NotRequested => "not-requested",
        }
    }
}

impl serde::Serialize for SandboxState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// What the environment scrub covers. A single-variant enum so a receipt cannot
/// claim more: `scrubbed_env_keys` is NEVER evidence that no token is reachable.
/// `gh auth token` (login keychain / `hosts.yml`) and `git credential-osxkeychain`
/// stay reachable by the same uid until the planned P2 credential broker (plan §35.6 limit 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvScrubScope {
    /// Only inherited environment variables were scrubbed.
    EnvOnly,
}

impl EnvScrubScope {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnvOnly => "env-only",
        }
    }
}

impl serde::Serialize for EnvScrubScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A SHA-256 digest: exactly 64 lowercase hex characters, validated at
/// construction so a receipt cannot carry free-form text in a digest field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Digest256(String);

impl Digest256 {
    /// Accepts exactly 64 lowercase hex characters.
    pub fn parse(text: &str) -> Option<Self> {
        is_lower_hex_64(text).then(|| Self(text.to_owned()))
    }

    /// The lowercase hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn serialize_slot<S: serde::Serializer>(
    slot: &AccountNum,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u16(slot.get())
}

/// Basis of [`LaunchReceipt::account_slot`] and
/// [`LaunchReceipt::account_identity_digest`].
///
/// Always `launch_instant`: those fields record who the LAUNCH was made as.
/// An in-place `csq swap` rebinds the handle dir's marker and credentials
/// without launching, so the receipt is not the session's current identity.
/// A guard MUST compare `account_slot` with the handle dir's CURRENT
/// `.csq-account` marker (or read the marker directly) and treat a difference
/// as "rebound after launch", never as identity evidence about now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum IdentityBasis {
    /// The identity fields describe the launch instant, not the current binding.
    #[serde(rename = "launch_instant")]
    LaunchInstant,
}

/// The facts one launch records for its guards.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LaunchReceipt {
    /// Schema version of this object.
    pub receipt_version: u32,
    /// Absolute path of the session's handle dir.
    pub session_handle: String,
    /// Account slot, read through the marker at the launch instant (§35.2).
    #[serde(serialize_with = "serialize_slot")]
    pub account_slot: AccountNum,
    /// Digest of the identity UUID ([`identity_digest`]) — never the UUID itself.
    pub account_identity_digest: Digest256,
    /// What the two fields above describe: always the launch instant.
    pub identity_basis: IdentityBasis,
    /// Digest over the handle dir's tracked file set at launch ([`config_dir_digest`]).
    pub config_dir_digest: Digest256,
    /// The guard-manifest outcome; `absent` is not integrity evidence.
    pub guard_manifest: GuardManifestState,
    /// What `scrubbed_env_keys` covers: environment only, never "no token reachable".
    pub env_scrub_scope: EnvScrubScope,
    /// Names of environment keys removed from the child. Never values.
    pub scrubbed_env_keys: Vec<String>,
    /// Names of scope-bearing keys that were kept by explicit allowlist.
    pub unresolved_env_keys: Vec<String>,
    /// Names the operator explicitly allowed through.
    pub allowed_env_keys: Vec<String>,
    /// Sandbox state.
    pub sandbox: SandboxState,
    /// The approval mode csq set on the command line. This is NOT the effective
    /// approval mode: project or user settings and hooks (`.claude/settings*.json`)
    /// can loosen it, and no argument check sees them (plan §35.6 limit 4).
    pub permission_mode: String,
    /// Unix seconds, one clock read.
    pub launched_at: i64,
    /// Emitting csq version.
    pub csq_version: String,
}

impl LaunchReceipt {
    /// Serialises to the receipt JSON.
    pub fn to_json(&self) -> Result<String, ReceiptError> {
        serde_json::to_string(self).map_err(|_| ReceiptError::Unserialisable)
    }
}

fn io_kind_tag(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::AlreadyExists => "already_exists",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        _ => "other_io",
    }
}

fn platform_kind_tag(error: &crate::error::PlatformError) -> &'static str {
    match error {
        crate::error::PlatformError::Io(io) => io_kind_tag(io.kind()),
        _ => "platform",
    }
}

/// Writes `receipt` to `<handle_dir>/launch-receipt.json`, mode 0600, atomically,
/// returning its absolute path. `handle_dir` MUST be absolute.
///
/// A failure here MUST refuse the launch: a session without the fact its guards
/// read is a session they will decide about from the agent's account of it.
pub fn write_receipt(handle_dir: &Path, receipt: &LaunchReceipt) -> Result<PathBuf, ReceiptError> {
    if !handle_dir.is_absolute() {
        return Err(ReceiptError::Unwritable {
            kind: "invalid_input",
        });
    }
    let json = receipt.to_json()?;
    let target = handle_dir.join(RECEIPT_FILE);
    let writer = crate::platform::fs::write_private_tmp_synced_retained(&target, json.as_bytes())
        .map_err(|error| ReceiptError::Unwritable {
        kind: platform_kind_tag(&error),
    })?;
    writer
        .replace(&target)
        .map_err(|error| ReceiptError::Unwritable {
            kind: platform_kind_tag(&error),
        })?;
    Ok(target)
}

/// Domain-separation prefix for [`identity_digest`].
const IDENTITY_DIGEST_DOMAIN: &[u8] = b"csq-x1-identity-v1\0";
/// Domain-separation prefix for [`config_dir_digest`].
const CONFIG_DIGEST_DOMAIN: &[u8] = b"csq-x1-config-dir-v1\0";
/// Largest regular file [`config_dir_digest`] will hash.
const CONFIG_FILE_MAX_BYTES: u64 = 64 << 20;
/// Deepest directory nesting [`config_dir_digest`] will walk.
const CONFIG_WALK_MAX_DEPTH: usize = 16;
/// Most entries [`config_dir_digest`] will visit.
const CONFIG_WALK_MAX_ENTRIES: usize = 100_000;

/// Digest of an identity UUID: SHA-256 over `"csq-x1-identity-v1\0"` then the
/// hyphenated lowercase UUID text. The UUID itself is never recorded.
pub fn identity_digest(identity: &uuid::Uuid) -> Digest256 {
    identity_label_digest(&identity.as_hyphenated().to_string())
}

/// Digest of a non-UUID identity label (a 3P slot's `by_slot_identity` value, or
/// the `slot:<N>` fallback for a legacy slot with no identity mapping). Uses the
/// SAME domain separation as [`identity_digest`], so a receipt always carries a
/// digest over the slot's identity text and never a fabricated UUID. Callers MUST
/// read the slot's identity through the WIDEST accessor: `by_slot` first, then
/// `by_slot_identity`, then the slot fallback
/// (`guard-reader-writer-parity.md` MUST-1).
pub fn identity_label_digest(label: &str) -> Digest256 {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DIGEST_DOMAIN);
    hasher.update(label.as_bytes());
    Digest256(hex_lower(&hasher.finalize()))
}

/// Handle-dir TOP-LEVEL names the config-dir digest does not cover, matched EXACTLY:
/// credential material and keys that rotate (covering them would fingerprint token
/// rotation), the receipt itself and the liveness marker. `.claude.json` and the
/// per-slot `settings.json` carry rotating keys. A nested file with a similar name
/// (`hooks/x-launch-receipt.sh`, `sub/auth.json`) IS covered.
const DIGEST_EXCLUDED_TOP_LEVEL: [&str; 8] = [
    ".credentials.json",
    "credentials.json",
    "auth.json",
    "oauth_creds.json",
    RECEIPT_FILE,
    ".live-pid",
    ".claude.json",
    "settings.json",
];

/// True for an entry the digest skips: an exact top-level name from
/// [`DIGEST_EXCLUDED_TOP_LEVEL`]. `depth` is the walk depth of the directory holding
/// the entry (0 = the handle dir itself).
fn is_digest_excluded(name: &str, depth: usize) -> bool {
    depth == 0 && DIGEST_EXCLUDED_TOP_LEVEL.contains(&name)
}

fn path_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        name.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().as_bytes().to_vec()
    }
}

/// Fingerprint of the handle dir's tracked set at launch.
///
/// Format: SHA-256 over `"csq-x1-config-dir-v1\0"` followed by one line per entry,
/// `<kind> <hex(relpath bytes)> <payload>\n`, sorted by relpath bytes (so the result
/// is independent of directory iteration order and relpath text cannot inject a
/// line). Kinds: `F` regular file, payload = SHA-256 of its bytes; `L` symlink,
/// payload = SHA-256 of the link-target TEXT (links are never followed, so a link
/// fingerprints where it points, not what it points at); `D` directory, payload
/// `-`, recursed; `O` anything else (FIFO, socket), payload `-`, never opened.
/// The exact top-level names in `DIGEST_EXCLUDED_TOP_LEVEL` are EXCLUDED; nothing
/// nested is.
///
/// A FINGERPRINT of the launch instant, not an integrity proof (plan §35.6).
/// Fails (rather than hashing partially) on a file over 64 MiB, nesting over 16, or
/// more than 100000 entries.
pub fn config_dir_digest(handle_dir: &Path) -> std::io::Result<Digest256> {
    if !handle_dir.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "handle_dir must be absolute",
        ));
    }
    let mut rows: Vec<(Vec<u8>, String)> = Vec::new();
    walk_config_dir(handle_dir, &[], 0, &mut rows)?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    hasher.update(CONFIG_DIGEST_DOMAIN);
    for (_, line) in &rows {
        hasher.update(line.as_bytes());
    }
    Ok(Digest256(hex_lower(&hasher.finalize())))
}

fn walk_config_dir(
    dir: &Path,
    prefix: &[u8],
    depth: usize,
    rows: &mut Vec<(Vec<u8>, String)>,
) -> std::io::Result<()> {
    if depth > CONFIG_WALK_MAX_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config dir nesting too deep",
        ));
    }
    // Re-check, immediately before listing, that a directory we are about to recurse
    // into is still a plain directory: the entry type was read a moment ago, and a
    // swap for a symlink would redirect the walk (and the digest) outside the tree.
    // This narrows the window; it does not close it, and a same-uid process can still
    // race it (plan §35.6).
    if depth > 0 && !std::fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config dir entry changed type during the walk",
        ));
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if is_digest_excluded(&name.to_string_lossy(), depth) {
            continue;
        }
        if rows.len() >= CONFIG_WALK_MAX_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config dir has too many entries",
            ));
        }
        let mut rel = prefix.to_vec();
        if !rel.is_empty() {
            rel.push(b'/');
        }
        rel.extend_from_slice(&path_bytes(&name));
        let file_type = entry.file_type()?;
        let path = entry.path();
        let (kind, payload) = if file_type.is_symlink() {
            let target = std::fs::read_link(&path)?;
            ('L', sha256_hex(&path_bytes(target.as_os_str())))
        } else if file_type.is_dir() {
            ('D', "-".to_owned())
        } else if file_type.is_file() {
            let bytes =
                crate::platform::fs::read_regular_nofollow_bounded(&path, CONFIG_FILE_MAX_BYTES)?
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            ('F', sha256_hex(&bytes))
        } else {
            ('O', "-".to_owned())
        };
        rows.push((
            rel.clone(),
            format!("{kind} {} {payload}\n", hex_lower(&rel)),
        ));
        if kind == 'D' {
            walk_config_dir(&path, &rel, depth + 1, rows)?;
        }
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Name fragments that mark a git/GitHub-related variable (matched anywhere, ASCII
/// case-insensitive). `GIT` covers `GIT_TOKEN`, `GIT_PASSWORD`, `GIT_HTTP_PASSWORD`.
const GITHUB_NAME_MARKERS: [&str; 3] = ["GH", "GITHUB", "GIT"];
/// Name fragments that mark a credential-bearing variable.
const CREDENTIAL_NAME_MARKERS: [&str; 6] = ["TOKEN", "PAT", "KEY", "SECRET", "PASSWORD", "AUTH"];
/// Token prefixes whose presence in a VALUE removes the variable. A removal
/// trigger only: csq never classifies a token by prefix (plan §35.3.4). Classic
/// 40-hex tokens carry no prefix and are NOT detected by value: the shape is
/// indistinguishable from a git object id (plan §35.6 limit 5).
const GITHUB_VALUE_PREFIXES: [&str; 6] = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"];
/// Variables that can smuggle git configuration (credential helpers), redirect git's
/// config files, expose the ssh agent, or raise an interactive credential prompt in
/// the child. Always removed, never allowlistable. Compared ASCII case-insensitively
/// (Windows environment names are case-insensitive).
const GIT_PLUMBING_KEYS: [&str; 8] = [
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
];
/// What a receipt records instead of a variable NAME that itself carries token text.
pub const REDACTED_NAME: &str = "<redacted-name>";
/// Prefix of the per-launch directory `GH_CONFIG_DIR` is pointed at, inside the
/// handle dir; [`isolate_gh_config`] appends `<pid>-<n>`.
pub const GH_CONFIG_DIR_PREFIX: &str = "gh-config-empty-";

/// True when `name` looks like a git/GitHub credential variable: it contains `GH`,
/// `GITHUB` or `GIT` AND one of `TOKEN`, `PAT`, `KEY`, `SECRET`, `PASSWORD`,
/// `AUTH`, anywhere in the name.
///
/// The rule is deliberately broad: over-scrubbing a lookalike (`HIGH_TOKEN`,
/// `GITHUB_PATH`, `DIGITAL_KEY`) is the fail-closed direction; the alternative is
/// passing an admin-capable credential because its name did not fit a fixed shape.
pub fn is_github_admin_token_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    GITHUB_NAME_MARKERS
        .iter()
        .any(|marker| upper.contains(marker))
        && CREDENTIAL_NAME_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
}

/// Decodes `%XX` escapes once. `None` when `text` holds no valid escape.
fn percent_decode_once(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]));
            if let (Some(high), Some(low)) = pair {
                out.push(high * 16 + low);
                index += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    changed.then(|| String::from_utf8_lossy(&out).into_owned())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// How many nested percent-decoding rounds are tried before failing closed.
const PERCENT_DECODE_ROUNDS: usize = 4;

/// True when `text` carries a GitHub token prefix anywhere, raw or after repeated
/// percent-decoding (`ghp%5F…`, `ghp%255F…`). Text still decoding after
/// [`PERCENT_DECODE_ROUNDS`] rounds fails CLOSED (reported as carrying a token).
fn text_carries_github_token(text: &str) -> bool {
    let mut current = text.to_owned();
    for _ in 0..=PERCENT_DECODE_ROUNDS {
        if GITHUB_VALUE_PREFIXES
            .iter()
            .any(|prefix| current.contains(prefix))
        {
            return true;
        }
        match percent_decode_once(&current) {
            Some(next) => current = next,
            None => return false,
        }
    }
    true
}

/// The name a receipt may record for `name`: the name itself, or [`REDACTED_NAME`]
/// when the name carries token text.
fn recordable_name(name: &str) -> String {
    if text_carries_github_token(name) {
        REDACTED_NAME.to_owned()
    } else {
        name.to_owned()
    }
}

/// True for `GIT_CONFIG_KEY_<n>` / `GIT_CONFIG_VALUE_<n>` and the fixed plumbing keys,
/// in any ASCII case.
fn is_git_plumbing_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if GIT_PLUMBING_KEYS.contains(&upper.as_str()) {
        return true;
    }
    ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"]
        .iter()
        .any(|prefix| {
            upper
                .strip_prefix(prefix)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// What [`scrub_env`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvScrubOutcome {
    /// Names removed from the child environment.
    pub removed: Vec<String>,
    /// Names kept by explicit allowlist whose scope is unknown. A guard reading a
    /// non-empty list sees a session carrying a token csq could not classify.
    /// A removed key is NEVER listed here.
    pub unresolved: Vec<String>,
    /// Names the operator explicitly allowed through.
    pub allowed: Vec<String>,
}

/// Removes admin-capable GitHub credentials from `vars` in place.
///
/// Removed: any variable whose NAME satisfies [`is_github_admin_token_key`], any
/// variable whose VALUE contains a GitHub token prefix, and the git/ssh credential
/// plumbing keys (`GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n`/`PARAMETERS`, `GIT_ASKPASS`,
/// `GIT_CONFIG_GLOBAL`/`SYSTEM`, `GIT_ASKPASS`, `SSH_ASKPASS`, `SSH_AUTH_SOCK`; plumbing
/// names match in any ASCII case). Names only are recorded, never values; a NAME that
/// itself carries a token prefix is recorded as [`REDACTED_NAME`]. Values are checked
/// raw and percent-decoded.
///
/// **Fail closed**: a credential whose scope cannot be determined offline is
/// REMOVED. A name or value match is a removal trigger, not a scope classification.
///
/// An allowlisted token key is kept and appears in both `allowed` and `unresolved`
/// (only on that path; a removed key is not unresolved). Plumbing keys cannot be
/// allowlisted.
///
/// **Scope: environment only** (plan §35.6 limit 3). This does not and cannot
/// stop `gh auth token`, `hosts.yml` or `git credential-osxkeychain` from
/// reaching the same uid's stored credentials.
///
/// The caller MUST launch the child with `env_clear()` and then apply only the map
/// this function leaves, so nothing it did not see (for example a non-UTF-8
/// variable; see [`scrub_os_env`]) is inherited.
pub fn scrub_env(vars: &mut BTreeMap<String, String>, allow: &BTreeSet<String>) -> EnvScrubOutcome {
    let mut outcome = EnvScrubOutcome::default();
    let doomed: Vec<(String, bool)> = vars
        .iter()
        .filter_map(|(key, value)| {
            if is_git_plumbing_key(key) || text_carries_github_token(key) {
                // Never allowlistable: plumbing can inject a helper, and a name that
                // carries token text must not be echoed back by an allowlist entry.
                Some((key.clone(), false))
            } else if is_github_admin_token_key(key) || text_carries_github_token(value) {
                Some((key.clone(), true))
            } else {
                None
            }
        })
        .collect();
    for (key, allowlistable) in doomed {
        if allowlistable && allow.contains(&key) {
            outcome.unresolved.push(key.clone());
            outcome.allowed.push(key);
        } else {
            vars.remove(&key);
            outcome.removed.push(recordable_name(&key));
        }
    }
    outcome.removed.sort();
    outcome.removed.dedup();
    outcome.unresolved.sort();
    outcome.allowed.sort();
    outcome
}

/// [`scrub_env`] over the raw process environment. A variable whose name or value
/// is not valid UTF-8 cannot be classified, so it is DROPPED (fail closed) and its
/// lossy name is recorded in `removed`.
pub fn scrub_os_env<I>(
    vars: I,
    allow: &BTreeSet<String>,
) -> (BTreeMap<String, String>, EnvScrubOutcome)
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    let mut kept = BTreeMap::new();
    let mut dropped = Vec::new();
    for (key, value) in vars {
        match (key.to_str(), value.to_str()) {
            (Some(key), Some(value)) => {
                kept.insert(key.to_owned(), value.to_owned());
            }
            _ => dropped.push(recordable_name(&key.to_string_lossy())),
        }
    }
    let mut outcome = scrub_env(&mut kept, allow);
    outcome.removed.extend(dropped);
    outcome.removed.sort();
    outcome.removed.dedup();
    (kept, outcome)
}

/// Most names [`isolate_gh_config`] tries before giving up.
const GH_CONFIG_DIR_ATTEMPTS: usize = 64;

/// Process-global launch sequence, so concurrent launches in this process never
/// contend for the same `gh-config-empty-<pid>-<n>` name. A collision still
/// advances the sequence rather than failing. Test-visible because the
/// collision test resets it to a known start under [`ISOLATE_TEST_LOCK`].
static LAUNCH_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Creates `path` as a new directory, mode 0700, failing if anything already exists
/// there (a symlink included).
#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

/// Non-unix: there is no mode to set; the directory inherits its parent's ACL.
#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().create(path)
}

/// Refuses anything but a plain directory that is not a symlink, is owned by the
/// effective uid and carries no group or other permission bits.
fn verify_private_dir(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "gh config dir is not a plain directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // SAFETY: geteuid has no memory or synchronization preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "gh config dir is not owned by this user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "gh config dir is accessible to group or other",
            ));
        }
    }
    Ok(())
}

/// Points `GH_CONFIG_DIR` at a FRESH, empty, private directory inside `handle_dir`,
/// so `gh` finds no `hosts.yml` from the parent's config.
///
/// Semantics: every launch creates its own directory
/// `<handle_dir>/gh-config-empty-<pid>-<n>` with an exclusive `mkdir` at mode 0700,
/// then verifies it (not a symlink, owned by the effective uid, no group/other bits).
/// An existing path is NEVER adopted: an exclusive create that finds one (a symlink
/// included) moves on to the next name. A reused handle dir therefore never fails
/// because `gh` wrote state into an earlier launch's directory, and a planted
/// directory is never used. Earlier launches' directories are left alone (they live
/// and die with the handle dir). Refuses a relative `handle_dir`.
pub fn isolate_gh_config(
    vars: &mut BTreeMap<String, String>,
    handle_dir: &Path,
) -> std::io::Result<PathBuf> {
    if !handle_dir.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "handle_dir must be absolute",
        ));
    }
    let pid = std::process::id();
    for _ in 0..GH_CONFIG_DIR_ATTEMPTS {
        let sequence = LAUNCH_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let target = handle_dir.join(format!("{GH_CONFIG_DIR_PREFIX}{pid}-{sequence}"));
        match create_private_dir(&target) {
            Ok(()) => {
                verify_private_dir(&target)?;
                let text = target.to_str().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 handle_dir")
                })?;
                vars.insert("GH_CONFIG_DIR".to_owned(), text.to_owned());
                return Ok(target);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free gh config dir name",
    ))
}

/// The scope a manifest entry resolves against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardScope {
    /// The session's handle dir.
    HandleDir,
    /// The launched workspace root.
    Repo,
}

/// One manifest row. The field set is EXACTLY `{path, sha256, scope}` — no
/// `asset_id`, no `contract_version`, no per-row `digest`. A later seam adds
/// P4's snapshot files as additional required entries, not as new fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardManifestEntry {
    /// Path relative to the entry's scope root.
    pub path: String,
    /// Expected lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Which root `path` resolves against.
    pub scope: GuardScope,
}

/// The guard manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardManifest {
    /// Schema version; a mismatch is `Invalid`, never a silent skip.
    pub manifest_version: u32,
    /// Provenance of the manifest (for example `local`).
    pub source: String,
    /// The required integrity members.
    pub entries: Vec<GuardManifestEntry>,
}

/// The result of the launch-time integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCheck {
    /// Every entry matched.
    Verified,
    /// No manifest exists. Nothing was checked.
    Absent,
    /// An entry's bytes did not match.
    Mismatch {
        /// The offending entry's path, as written in the manifest. Entry paths are
        /// rejected as `Invalid` when they carry control characters, so this never
        /// holds raw terminal-control text.
        path: String,
    },
    /// The manifest existed but could not be trusted.
    Invalid {
        /// A fixed reason tag; never a path fragment from outside the tree.
        reason: &'static str,
        /// The manifest-relative path of the offending entry, for entry-level
        /// reasons. Control-character paths are never echoed (the reason is
        /// `manifest_path_invalid` and this is `None`).
        path: Option<String>,
    },
}

impl ManifestCheck {
    fn invalid(reason: &'static str) -> Self {
        Self::Invalid { reason, path: None }
    }

    /// The receipt state for this outcome.
    pub fn state(&self) -> GuardManifestState {
        match self {
            Self::Verified => GuardManifestState::Verified,
            Self::Absent => GuardManifestState::Absent,
            Self::Mismatch { .. } => GuardManifestState::Mismatch,
            Self::Invalid { .. } => GuardManifestState::Invalid,
        }
    }

    /// True when the launch must be refused.
    pub fn refuses_launch(&self) -> bool {
        matches!(self, Self::Mismatch { .. } | Self::Invalid { .. })
    }
}

/// Upper bound on the manifest file. A larger file is `Invalid`, never read whole.
const MANIFEST_MAX_BYTES: u64 = 1 << 20;
/// Upper bound on one guarded file.
const ENTRY_MAX_BYTES: u64 = 64 << 20;

/// True for a character a manifest path must not contain: a control character, or a
/// Unicode format character (general category Cf) that can reorder or hide text when
/// the path is printed (bidi overrides and isolates, zero-width characters, the word
/// joiner family, the byte-order mark, the soft hyphen and the other Cf code points).
fn is_unsafe_path_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
}

/// True for 64 lowercase hexadecimal characters.
fn is_lower_hex_64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verifies `<base_dir>/guard-manifest.json` against the files on disk.
///
/// A missing manifest is [`ManifestCheck::Absent`] — the launch proceeds and the
/// receipt records that nothing was checked. **Once a manifest is present, a
/// mismatch or an invalid manifest REFUSES the launch**; there is no setting in
/// which a present manifest is checked less strictly. Only `NotFound` on the
/// manifest path is `Absent`: a dangling symlink, a FIFO or any other non-regular
/// file at that path is `Invalid("manifest_not_regular")`.
///
/// `base_dir`, `handle_dir` and `repo_root` MUST be absolute; a relative one is `Invalid`. Every read is a
/// bounded `O_NOFOLLOW` regular-file read, so a FIFO cannot hang the launch.
pub fn verify_manifest(base_dir: &Path, handle_dir: &Path, repo_root: &Path) -> ManifestCheck {
    if !handle_dir.is_absolute() {
        return ManifestCheck::invalid("handle_dir_not_absolute");
    }
    if !base_dir.is_absolute() {
        return ManifestCheck::invalid("base_dir_not_absolute");
    }
    if !repo_root.is_absolute() {
        return ManifestCheck::invalid("repo_root_not_absolute");
    }
    let manifest_path = base_dir.join(MANIFEST_FILE);
    match std::fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return ManifestCheck::invalid("manifest_not_regular");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ManifestCheck::Absent;
        }
        Err(_) => return ManifestCheck::invalid("manifest_unreadable"),
    }
    let bytes = match crate::platform::fs::read_regular_nofollow_bounded(
        &manifest_path,
        MANIFEST_MAX_BYTES,
    ) {
        Ok(Some(bytes)) => bytes,
        // Present a moment ago, gone now: a swap, not an absence.
        Ok(None) | Err(_) => return ManifestCheck::invalid("manifest_unreadable"),
    };
    let manifest: GuardManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return ManifestCheck::invalid("manifest_unparseable"),
    };
    if manifest.manifest_version != MANIFEST_VERSION {
        return ManifestCheck::invalid("manifest_version");
    }
    // An empty list checks nothing; reporting it `verified` would be an absence
    // dressed as a check (plan §35.4.3).
    if manifest.entries.is_empty() {
        return ManifestCheck::invalid("manifest_empty");
    }
    // Syntax pass first: nothing is read from disk for a manifest that is malformed.
    for entry in &manifest.entries {
        if entry.path.chars().any(is_unsafe_path_char) {
            return ManifestCheck::invalid("manifest_path_invalid");
        }
        if !is_lower_hex_64(&entry.sha256) {
            return ManifestCheck::Invalid {
                reason: "manifest_hash_malformed",
                path: Some(entry.path.clone()),
            };
        }
    }
    for entry in &manifest.entries {
        match verify_entry(entry, handle_dir, repo_root) {
            EntryCheck::Ok => {}
            EntryCheck::Mismatch => {
                return ManifestCheck::Mismatch {
                    path: entry.path.clone(),
                };
            }
            EntryCheck::Invalid(reason) => {
                return ManifestCheck::Invalid {
                    reason,
                    path: Some(entry.path.clone()),
                };
            }
        }
    }
    ManifestCheck::Verified
}

enum EntryCheck {
    Ok,
    Mismatch,
    Invalid(&'static str),
}

fn verify_entry(entry: &GuardManifestEntry, handle_dir: &Path, repo_root: &Path) -> EntryCheck {
    let root = match entry.scope {
        GuardScope::HandleDir => handle_dir,
        GuardScope::Repo => repo_root,
    };
    let canonical_root = match std::fs::canonicalize(root) {
        Ok(path) => path,
        Err(_) => return EntryCheck::Invalid("manifest_root_unresolvable"),
    };
    // Only plain names are accepted: `..`, `.`, a root and a Windows prefix
    // (`C:foo`) are all refused, not normalised.
    let mut names = Vec::new();
    for component in Path::new(&entry.path).components() {
        match component {
            Component::Normal(name) => names.push(name),
            _ => return EntryCheck::Invalid("manifest_path_not_contained"),
        }
    }
    if names.is_empty() {
        return EntryCheck::Invalid("manifest_path_not_contained");
    }
    // Walk component by component from the canonical root, refusing a symlink at
    // ANY depth. `symlink_metadata` on the final path alone checks only the last
    // component and lets a symlinked parent directory carry the read outside.
    let mut current = canonical_root.clone();
    for (index, name) in names.iter().enumerate() {
        current.push(name);
        let last = index + 1 == names.len();
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return EntryCheck::Invalid("manifest_entry_missing");
            }
            Err(_) => return EntryCheck::Invalid("manifest_entry_unreadable"),
        };
        if metadata.file_type().is_symlink() {
            return EntryCheck::Invalid(if last {
                "manifest_entry_not_regular"
            } else {
                "manifest_path_not_contained"
            });
        }
        let well_formed = if last {
            metadata.is_file()
        } else {
            metadata.is_dir()
        };
        if !well_formed {
            return EntryCheck::Invalid("manifest_entry_not_regular");
        }
    }
    let bytes = match crate::platform::fs::read_regular_nofollow_bounded(&current, ENTRY_MAX_BYTES)
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return EntryCheck::Invalid("manifest_entry_missing"),
        Err(_) => return EntryCheck::Invalid("manifest_entry_unreadable"),
    };
    // Post-read containment re-check. `read_regular_nofollow_bounded` applies
    // `O_NOFOLLOW` to the LAST component only, so this DETECTS a persistent parent
    // swap (the path resolves outside the root after the read). It does not close the
    // race: a transient parent swap during the read is within the same-uid limit
    // (plan §35.6). An fd-relative walk would close it, but `platform::fs::DirFd`
    // has no leaf `openat` or bounded read and no fd-relative form off unix.
    match std::fs::canonicalize(&current) {
        Ok(after) if after.starts_with(&canonical_root) => {}
        Ok(_) => return EntryCheck::Invalid("manifest_path_not_contained"),
        Err(_) => return EntryCheck::Invalid("manifest_entry_unreadable"),
    }
    if sha256_hex(&bytes) == entry.sha256 {
        EntryCheck::Ok
    } else {
        EntryCheck::Mismatch
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

/// Flags (lowercase) refused outright in sandbox mode: each one replaces the settings
/// csq pinned, widens the tool permissions, loads hooks or plugins (a plugin can carry
/// an auto-approving hook), or hands approval to something other than a person —
/// any of which would make the recorded `permission_mode: "manual"` misleading.
/// Checked against the installed `claude --help` (2.1.316), owner decision an internal journal entry
const SANDBOX_REFUSED_FLAGS: [&str; 12] = [
    "--settings",
    "--allowedtools",
    "--allowed-tools",
    "--plugin-dir",
    "--plugin-url",
    "--permission-prompt-tool",
    "--permission-prompts",
    "--mcp-config",
    "--strict-mcp-config",
    "--agent",
    "--agents",
    "--setting-sources",
];

/// True when the operator's arguments conflict with `--sandbox`, so the recorded
/// `permission_mode` could be false. The launch MUST be refused
/// (`csq_run_sandbox_bypass_conflict`), never silently edited.
///
/// Refused, in the space-separated and `=` forms alike:
/// - any `--permission-mode` whose value is not exactly `manual`, or has none;
/// - any `--dangerously-*` / `--allow-dangerously-*` flag, whatever its value
///   (`=true` included);
/// - `--settings`, `--allowedTools`, `--allowed-tools`;
/// - the plugin, hook-carrying and approval-delegating flags: `--plugin-dir`,
///   `--plugin-url`, `--permission-prompt-tool`, `--permission-prompts`,
///   `--mcp-config`, `--strict-mcp-config`, `--agent`, `--agents`,
///   `--setting-sources`.
///
/// This checks the ARGUMENTS only. Project or user settings and hooks
/// (`.claude/settings*.json`) can still loosen the effective approval, and no
/// argument check sees them (plan §35.6 limit 4).
///
/// This is a denylist, not an allowlist: the child's argument space (prompt text,
/// `--model`, `-p`, ...) is not enumerable here. It over-refuses (any argument
/// spelled like a refused flag, even as another flag's value) because that is the
/// fail-closed direction. Flag names compare ASCII case-insensitively; the
/// permission-mode VALUE compares exactly.
pub fn sandbox_conflict(args: &[String]) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (arg.as_str(), None),
        };
        let flag = flag.to_ascii_lowercase();
        if BYPASS_FLAGS.contains(&flag.as_str())
            || flag.starts_with("--dangerously-")
            || flag.starts_with("--allow-dangerously")
        {
            return true;
        }
        if flag == "--permission-mode" {
            let value = inline.or_else(|| args.get(index + 1).map(String::as_str));
            return value != Some(PERMISSION_MODE_SANDBOXED);
        }
        SANDBOX_REFUSED_FLAGS.contains(&flag.as_str())
    })
}

/// The arguments `--sandbox` contributes: the pinned permission mode.
///
/// The refusal is separate ([`sandbox_conflict`]) because the refusal must
/// happen BEFORE any argument is assembled — a silently dropped flag would launch
/// a session the operator did not ask for (plan §35.5).
pub fn sandbox_args() -> Vec<String> {
    vec![
        "--permission-mode".to_owned(),
        PERMISSION_MODE_SANDBOXED.to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Serializes the tests that select a name from the process-global
    /// [`LAUNCH_SEQUENCE`]: without it, a sibling test's `fetch_add` can land
    /// inside a reset/planted-name window and make the assertions vacuous (or
    /// exhaust the attempt budget).
    static ISOLATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn isolate_test_lock() -> std::sync::MutexGuard<'static, ()> {
        ISOLATE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn receipt_with(state: GuardManifestState) -> LaunchReceipt {
        LaunchReceipt {
            receipt_version: RECEIPT_VERSION,
            session_handle: "/tmp/term-1".to_owned(),
            account_slot: AccountNum::try_from(3).expect("slot"),
            account_identity_digest: Digest256::parse(&"a".repeat(64)).expect("digest"),
            identity_basis: IdentityBasis::LaunchInstant,
            config_dir_digest: Digest256::parse(&"b".repeat(64)).expect("digest"),
            guard_manifest: state,
            env_scrub_scope: EnvScrubScope::EnvOnly,
            scrubbed_env_keys: vec!["GITHUB_TOKEN".to_owned()],
            unresolved_env_keys: Vec::new(),
            allowed_env_keys: Vec::new(),
            sandbox: SandboxState::PermissionModeOnly,
            permission_mode: PERMISSION_MODE_SANDBOXED.to_owned(),
            launched_at: 1_793_637_475,
            csq_version: "2.21.5".to_owned(),
        }
    }

    // T3 — the failure this whole surface exists for: an absence dressed as a check.
    #[test]
    fn an_absent_manifest_never_serialises_as_verified() {
        let json = receipt_with(GuardManifestState::Absent)
            .to_json()
            .expect("serialise");
        assert!(
            json.contains("\"guard_manifest\":\"absent\""),
            "absent must serialise as absent: {json}"
        );
        assert!(
            !json.contains("\"verified\""),
            "absent must never render as verified: {json}"
        );
        assert_eq!(GuardManifestState::Absent.as_str(), "absent");
        assert_ne!(GuardManifestState::Absent.as_str(), "verified");
    }

    // T1 — a verifier that records but does not enforce is the failure mode.
    #[test]
    fn a_manifest_entry_that_does_not_match_refuses_the_launch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle dir");
        std::fs::write(handle.join("settings.json"), b"{\"a\":1}").expect("write");
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "source": "local",
            "entries": [
                { "path": "settings.json", "sha256": "0".repeat(64), "scope": "handle-dir" }
            ]
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            manifest.to_string().as_bytes(),
        )
        .expect("manifest");
        let check = verify_manifest(dir.path(), &handle, dir.path());
        assert_eq!(
            check,
            ManifestCheck::Mismatch {
                path: "settings.json".to_owned()
            }
        );
        assert!(check.refuses_launch());
        assert_eq!(check.state(), GuardManifestState::Mismatch);
    }

    #[test]
    fn a_matching_manifest_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle dir");
        let bytes = b"{\"a\":1}";
        std::fs::write(handle.join("settings.json"), bytes).expect("write");
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "source": "local",
            "entries": [
                { "path": "settings.json", "sha256": sha256_hex(bytes), "scope": "handle-dir" }
            ]
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            manifest.to_string().as_bytes(),
        )
        .expect("manifest");
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Verified
        );
    }

    // T2 — containment and file-type refusals.
    #[test]
    fn an_escaping_manifest_path_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle dir");
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "source": "local",
            "entries": [ { "path": "../outside", "sha256": "0".repeat(64), "scope": "handle-dir" } ]
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            manifest.to_string().as_bytes(),
        )
        .expect("manifest");
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Invalid {
                reason: "manifest_path_not_contained",
                path: Some("../outside".to_owned())
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_manifest_entry_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle dir");
        let real = dir.path().join("real.json");
        std::fs::write(&real, b"{}").expect("real");
        std::os::unix::fs::symlink(&real, handle.join("settings.json")).expect("symlink");
        write_manifest(
            dir.path(),
            serde_json::json!([
                { "path": "settings.json", "sha256": "0".repeat(64), "scope": "handle-dir" }
            ]),
        );
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Invalid {
                reason: "manifest_entry_not_regular",
                path: Some("settings.json".to_owned())
            }
        );
    }

    // A directory entry is non-regular on every platform (replaces the old
    // Windows fallback that wrote a regular file and so asserted nothing).
    #[test]
    fn a_directory_manifest_entry_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(handle.join("settings.json")).expect("dir entry");
        write_manifest(
            dir.path(),
            serde_json::json!([
                { "path": "settings.json", "sha256": "0".repeat(64), "scope": "handle-dir" }
            ]),
        );
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Invalid {
                reason: "manifest_entry_not_regular",
                path: Some("settings.json".to_owned())
            }
        );
    }

    // T2 (schema half) — the row shape is exactly {path, sha256, scope}.
    #[test]
    fn a_manifest_row_carrying_an_extra_field_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle dir");
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "source": "local",
            "entries": [ {
                "path": "settings.json",
                "sha256": "0".repeat(64),
                "scope": "handle-dir",
                "asset_id": "not-allowed"
            } ]
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            manifest.to_string().as_bytes(),
        )
        .expect("manifest");
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Invalid {
                reason: "manifest_unparseable",
                path: None
            }
        );
    }

    #[test]
    fn no_manifest_is_absent_and_does_not_refuse() {
        let dir = tempfile::tempdir().expect("tempdir");
        let check = verify_manifest(dir.path(), dir.path(), dir.path());
        assert_eq!(check, ManifestCheck::Absent);
        assert!(!check.refuses_launch());
        assert_eq!(check.state(), GuardManifestState::Absent);
    }

    // T4 — remove, and never leak a value into the record.
    #[test]
    fn github_tokens_are_removed_and_only_their_names_are_recorded() {
        let mut vars = env(&[
            ("GITHUB_TOKEN", "ghp_secret_value"),
            ("GH_TOKEN", "github_pat_secret"),
            ("PATH", "/usr/bin"),
        ]);
        let outcome = scrub_env(&mut vars, &BTreeSet::new());
        assert!(!vars.contains_key("GITHUB_TOKEN"));
        assert!(!vars.contains_key("GH_TOKEN"));
        assert!(vars.contains_key("PATH"));
        assert_eq!(
            outcome.removed,
            vec!["GH_TOKEN".to_owned(), "GITHUB_TOKEN".to_owned()]
        );
        assert!(outcome.allowed.is_empty());
        assert!(
            outcome.unresolved.is_empty(),
            "removed keys are not unresolved"
        );
        let recorded = format!("{outcome:?}");
        assert!(
            !recorded.contains("secret"),
            "no value may be recorded: {recorded}"
        );
    }

    // T5 — an allowlisted scope-bearing token stays, and is still reported unresolved.
    #[test]
    fn an_allowlisted_token_is_kept_and_reported_unresolved() {
        let mut vars = env(&[("GH_TOKEN", "github_pat_x")]);
        let allow: BTreeSet<String> = ["GH_TOKEN".to_owned()].into_iter().collect();
        let outcome = scrub_env(&mut vars, &allow);
        assert!(vars.contains_key("GH_TOKEN"));
        assert_eq!(outcome.allowed, vec!["GH_TOKEN".to_owned()]);
        assert_eq!(outcome.unresolved, vec!["GH_TOKEN".to_owned()]);
        assert!(outcome.removed.is_empty());
    }

    #[test]
    fn lookalike_names_are_not_scope_bearing() {
        assert!(!is_github_admin_token_key("PATH"));
        assert!(!is_github_admin_token_key("ANTHROPIC_API_KEY"));
        assert!(is_github_admin_token_key("GITHUB_TOKEN"));
        assert!(is_github_admin_token_key("GH_TOKEN"));
        assert!(is_github_admin_token_key("GH_ENTERPRISE_TOKEN"));
    }

    // T6 — a conflicting bypass request refuses rather than being dropped.
    #[test]
    fn sandbox_conflicts_with_a_bypass_request() {
        for args in [
            vec!["--dangerously-skip-permissions".to_owned()],
            vec!["--allow-dangerously-skip-permissions".to_owned()],
            vec![
                "--permission-mode".to_owned(),
                "bypassPermissions".to_owned(),
            ],
            vec!["--permission-mode=bypassPermissions".to_owned()],
        ] {
            assert!(sandbox_conflict(&args), "must detect bypass: {args:?}");
        }
        assert!(!sandbox_conflict(&[
            "--permission-mode".to_owned(),
            "manual".to_owned()
        ]));
    }

    // T7 — the sandbox arguments never carry a bypass flag.
    #[test]
    fn sandbox_arguments_never_contain_a_bypass_flag() {
        let args = sandbox_args();
        for flag in BYPASS_FLAGS {
            assert!(!args.iter().any(|arg| arg == flag));
        }
        assert!(args.iter().any(|arg| arg == "--permission-mode"));
        assert!(args.iter().any(|arg| arg == PERMISSION_MODE_SANDBOXED));
        assert!(!sandbox_conflict(&args));
    }

    // T8 — no receipt, no launch.
    #[test]
    fn an_unwritable_receipt_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-handle");
        let error = write_receipt(&missing, &receipt_with(GuardManifestState::Absent))
            .expect_err("must refuse");
        assert_eq!(error, ReceiptError::Unwritable { kind: "not_found" });
    }

    #[test]
    fn a_written_receipt_is_private_and_reads_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path =
            write_receipt(dir.path(), &receipt_with(GuardManifestState::Absent)).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("\"guard_manifest\":\"absent\""));
        assert!(text.contains("\"receipt_version\":1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "receipt must be private, got {mode:o}");
        }
    }

    // ---- R1 fix-list tests (each reddens without its fix) ----

    fn write_manifest(base: &Path, entries: serde_json::Value) {
        let manifest = serde_json::json!({
            "manifest_version": 1, "source": "local", "entries": entries
        });
        std::fs::write(base.join(MANIFEST_FILE), manifest.to_string().as_bytes())
            .expect("manifest");
    }

    // H-e
    #[test]
    fn an_empty_manifest_is_invalid_never_verified() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest(dir.path(), serde_json::json!([]));
        let check = verify_manifest(dir.path(), dir.path(), dir.path());
        assert_eq!(
            check,
            ManifestCheck::Invalid {
                reason: "manifest_empty",
                path: None
            }
        );
        assert!(check.refuses_launch());
    }

    // H-d
    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_directory_cannot_escape_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside");
        let bytes = b"payload";
        std::fs::write(outside.join("f.json"), bytes).expect("outside file");
        std::os::unix::fs::symlink(&outside, handle.join("sub")).expect("symlink");
        write_manifest(
            dir.path(),
            serde_json::json!([
                { "path": "sub/f.json", "sha256": sha256_hex(bytes), "scope": "handle-dir" }
            ]),
        );
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Invalid {
                reason: "manifest_path_not_contained",
                path: Some("sub/f.json".to_owned())
            }
        );
    }

    #[test]
    fn only_normal_path_components_are_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle");
        let bytes = b"x";
        std::fs::write(handle.join("settings.json"), bytes).expect("write");
        write_manifest(
            dir.path(),
            serde_json::json!([
                { "path": "./settings.json", "sha256": sha256_hex(bytes), "scope": "handle-dir" }
            ]),
        );
        assert_eq!(
            verify_manifest(dir.path(), &handle, dir.path()),
            ManifestCheck::Invalid {
                reason: "manifest_path_not_contained",
                path: Some("./settings.json".to_owned())
            }
        );
    }

    // H-f
    #[test]
    fn removed_keys_are_not_reported_unresolved() {
        let mut vars = env(&[("GITHUB_TOKEN", "x"), ("GH_TOKEN", "y")]);
        let outcome = scrub_env(&mut vars, &BTreeSet::new());
        assert_eq!(outcome.removed.len(), 2);
        assert!(
            outcome.unresolved.is_empty(),
            "a removed key is not unresolved: {:?}",
            outcome.unresolved
        );
    }

    // H-a
    #[test]
    fn every_github_credential_shaped_name_is_removed() {
        let names = [
            "COPILOT_GHE_TOKEN",
            "CI_GHPAT_TOKEN",
            "GH_TOKEN_2",
            "GITHUB_TOKEN_FILE",
            "GITHUB_AUTH",
            "GITHUB_SECRET",
            "GITHUB_PASSWORD",
            "GITHUB_APP_PRIVATE_KEY",
            "NPM_CONFIG_//NPM.PKG.GITHUB.COM/:_AUTHTOKEN",
            "gh_token",
        ];
        for name in names {
            let mut vars = env(&[(name, "v"), ("PATH", "/usr/bin")]);
            let outcome = scrub_env(&mut vars, &BTreeSet::new());
            assert!(!vars.contains_key(name), "{name} must be removed");
            assert_eq!(outcome.removed, vec![name.to_owned()], "{name}");
            assert!(vars.contains_key("PATH"));
        }
    }

    #[test]
    fn a_github_token_prefix_in_any_value_removes_the_variable() {
        for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
            let mut vars = env(&[
                ("DEPLOY_CREDENTIAL", &format!("x{prefix}abc")),
                ("HOME", "/h"),
            ]);
            let outcome = scrub_env(&mut vars, &BTreeSet::new());
            assert!(!vars.contains_key("DEPLOY_CREDENTIAL"), "{prefix}");
            assert_eq!(outcome.removed, vec!["DEPLOY_CREDENTIAL".to_owned()]);
            assert!(!format!("{outcome:?}").contains("abc"));
        }
    }

    #[test]
    fn git_and_ssh_credential_plumbing_is_removed() {
        let mut vars = env(&[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "credential.helper"),
            ("GIT_CONFIG_VALUE_0", "store"),
            ("GIT_ASKPASS", "/x"),
            ("SSH_ASKPASS", "/y"),
            ("PATH", "/usr/bin"),
        ]);
        let outcome = scrub_env(&mut vars, &BTreeSet::new());
        assert_eq!(vars.keys().collect::<Vec<_>>(), vec!["PATH"]);
        assert_eq!(outcome.removed.len(), 5);
    }

    // H-b
    #[test]
    fn the_receipt_states_that_the_scrub_is_env_only() {
        let json = receipt_with(GuardManifestState::Absent)
            .to_json()
            .expect("serialise");
        assert!(
            json.contains("\"env_scrub_scope\":\"env-only\""),
            "receipt must carry the scrub scope: {json}"
        );
    }

    // H-c
    #[test]
    fn sandbox_refuses_every_flag_that_could_falsify_the_recorded_mode() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        for args in [
            s(&["--permission-mode", "auto"]),
            s(&["--permission-mode=auto"]),
            s(&["--permission-mode", "acceptEdits"]),
            s(&["--permission-mode"]),
            s(&["--dangerously-skip-permissions=true"]),
            s(&["--dangerously-anything"]),
            s(&["--allow-dangerously-skip-permissions=true"]),
            s(&["--settings", "/tmp/s.json"]),
            s(&["--settings=/tmp/s.json"]),
            s(&["--allowedTools", "Bash"]),
            s(&["--allowedTools=Bash"]),
            s(&["--allowed-tools", "Bash"]),
        ] {
            assert!(sandbox_conflict(&args), "must refuse: {args:?}");
        }
        assert!(!sandbox_conflict(&s(&["--permission-mode", "manual"])));
        assert!(!sandbox_conflict(&s(&["--model", "opus", "-p", "hi"])));
    }

    fn invalid(reason: &'static str, path: Option<&str>) -> ManifestCheck {
        ManifestCheck::Invalid {
            reason,
            path: path.map(str::to_owned),
        }
    }

    // M-b
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_manifest_is_invalid_not_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join(MANIFEST_FILE))
            .expect("symlink");
        let check = verify_manifest(dir.path(), dir.path(), dir.path());
        assert_eq!(check, invalid("manifest_not_regular", None));
        assert_ne!(check, ManifestCheck::Absent);
    }

    // M-a / M-b: a FIFO in place of the manifest must neither hang nor read as absent.
    #[cfg(unix)]
    #[test]
    fn a_fifo_manifest_is_refused_without_hanging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join(MANIFEST_FILE);
        let c = std::ffi::CString::new(fifo.to_str().expect("utf8")).expect("cstr");
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let base = dir.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(verify_manifest(&base, &base, &base));
        });
        let check = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("verify_manifest hung on a FIFO");
        assert_eq!(check, invalid("manifest_not_regular", None));
    }

    // M-a: a FIFO as an ENTRY is also refused without hanging.
    #[cfg(unix)]
    #[test]
    fn a_fifo_manifest_entry_is_refused_without_hanging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).expect("handle");
        let c = std::ffi::CString::new(handle.join("f").to_str().expect("utf8")).expect("cstr");
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        write_manifest(
            dir.path(),
            serde_json::json!([{ "path": "f", "sha256": "0".repeat(64), "scope": "handle-dir" }]),
        );
        let base = dir.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(verify_manifest(&base, &handle, &base));
        });
        let check = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("verify_manifest hung on a FIFO entry");
        assert_eq!(check, invalid("manifest_entry_not_regular", Some("f")));
    }

    // M-a: the manifest read is bounded.
    #[test]
    fn an_oversized_manifest_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            vec![b' '; (MANIFEST_MAX_BYTES as usize) + 1],
        )
        .expect("write");
        assert_eq!(
            verify_manifest(dir.path(), dir.path(), dir.path()),
            invalid("manifest_unreadable", None)
        );
    }

    // M-e
    #[test]
    fn a_control_character_in_a_manifest_path_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest(
            dir.path(),
            serde_json::json!([
                { "path": "a\u{1b}[31mb", "sha256": "0".repeat(64), "scope": "handle-dir" }
            ]),
        );
        let check = verify_manifest(dir.path(), dir.path(), dir.path());
        assert_eq!(check, invalid("manifest_path_invalid", None));
        assert!(!format!("{check:?}").contains("31m"), "raw text echoed");
    }

    // M-f
    #[test]
    fn a_malformed_sha256_is_invalid() {
        for bad in ["zz", &"A".repeat(64), &"0".repeat(63), &"0".repeat(65), ""] {
            let dir = tempfile::tempdir().expect("tempdir");
            write_manifest(
                dir.path(),
                serde_json::json!([{ "path": "s", "sha256": bad, "scope": "handle-dir" }]),
            );
            assert_eq!(
                verify_manifest(dir.path(), dir.path(), dir.path()),
                invalid("manifest_hash_malformed", Some("s")),
                "{bad:?}"
            );
        }
    }

    // L-c
    #[test]
    fn a_wrong_manifest_version_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = serde_json::json!({
            "manifest_version": 2, "source": "local",
            "entries": [{ "path": "s", "sha256": "0".repeat(64), "scope": "handle-dir" }]
        });
        std::fs::write(dir.path().join(MANIFEST_FILE), manifest.to_string()).expect("write");
        assert_eq!(
            verify_manifest(dir.path(), dir.path(), dir.path()),
            invalid("manifest_version", None)
        );
    }

    // L-c: an unreadable manifest is Invalid, never Absent (skipped for root, which
    // reads through mode 000).
    #[cfg(unix)]
    #[test]
    fn an_unreadable_manifest_is_invalid() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest(
            dir.path(),
            serde_json::json!([{ "path": "s", "sha256": "0".repeat(64), "scope": "handle-dir" }]),
        );
        let path = dir.path().join(MANIFEST_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let check = verify_manifest(dir.path(), dir.path(), dir.path());
        assert_eq!(check, invalid("manifest_unreadable", None));
    }

    // L-d
    #[test]
    fn a_relative_handle_dir_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            verify_manifest(dir.path(), Path::new("term-1"), dir.path()),
            invalid("handle_dir_not_absolute", None)
        );
    }

    // M-d
    #[cfg(unix)]
    #[test]
    fn non_utf8_variables_are_dropped_and_named() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let bad_name = OsString::from_vec(b"GH_\xff_TOKEN".to_vec());
        let bad_value = OsString::from_vec(b"\xff\xfe".to_vec());
        let vars = vec![
            (bad_name, OsString::from("v")),
            (OsString::from("ODD"), bad_value),
            (OsString::from("PATH"), OsString::from("/usr/bin")),
        ];
        let (kept, outcome) = scrub_os_env(vars, &BTreeSet::new());
        assert_eq!(kept.keys().collect::<Vec<_>>(), vec!["PATH"]);
        assert_eq!(outcome.removed.len(), 2, "{:?}", outcome.removed);
        assert!(outcome.removed.contains(&"ODD".to_owned()));
    }

    #[test]
    fn plumbing_keys_cannot_be_allowlisted() {
        let mut vars = env(&[("GIT_ASKPASS", "/x")]);
        let allow: BTreeSet<String> = ["GIT_ASKPASS".to_owned()].into_iter().collect();
        let outcome = scrub_env(&mut vars, &allow);
        assert!(vars.is_empty());
        assert_eq!(outcome.removed, vec!["GIT_ASKPASS".to_owned()]);
        assert!(outcome.allowed.is_empty() && outcome.unresolved.is_empty());
    }

    #[test]
    fn gh_config_dir_points_at_an_empty_dir_in_the_handle() {
        let _serial = isolate_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vars = env(&[("GH_CONFIG_DIR", "/home/u/.config/gh")]);
        let target = isolate_gh_config(&mut vars, dir.path()).expect("isolate");
        assert_eq!(vars["GH_CONFIG_DIR"], target.to_str().expect("utf8"));
        assert!(target.starts_with(dir.path()));
        assert!(std::fs::read_dir(&target).expect("read").next().is_none());
        assert!(isolate_gh_config(&mut vars, Path::new("rel")).is_err());
    }

    // R2 item 5: the directory is private (0700), and a reused handle dir works however
    // much state gh wrote into an earlier launch's directory. Each launch gets a FRESH
    // empty directory; nothing planted or left behind is ever adopted.
    #[cfg(unix)]
    #[test]
    fn the_gh_config_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let _serial = isolate_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vars = env(&[]);
        let target = isolate_gh_config(&mut vars, dir.path()).expect("isolate");
        let mode = std::fs::metadata(&target)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "gh config dir must be private, got {mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_private_dir_refuses_loose_modes_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let loose = dir.path().join("loose");
        std::fs::create_dir(&loose).expect("loose");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(verify_private_dir(&loose).is_err(), "0755 must be refused");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(
            verify_private_dir(&loose).is_ok(),
            "0700 owned by us is fine"
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&loose, &link).expect("link");
        assert!(
            verify_private_dir(&link).is_err(),
            "a symlink must be refused"
        );
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("file");
        assert!(verify_private_dir(&file).is_err(), "a file must be refused");
    }

    #[test]
    fn a_reused_handle_dir_gets_a_fresh_empty_gh_config_dir() {
        let _serial = isolate_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vars = env(&[]);
        let first = isolate_gh_config(&mut vars, dir.path()).expect("first");
        std::fs::write(first.join("hosts.yml"), b"state gh wrote").expect("state");
        let second = isolate_gh_config(&mut vars, dir.path()).expect("reuse must not refuse");
        assert_ne!(first, second, "each launch gets a fresh directory");
        assert!(std::fs::read_dir(&second).expect("read").next().is_none());
        assert_eq!(vars["GH_CONFIG_DIR"], second.to_str().expect("utf8"));
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_never_adopted_as_the_gh_config_dir() {
        // The sequence is process-global; hold the isolate tests serialized and
        // start from 0 so the planted names are the ones this call tries.
        let _serial = isolate_test_lock();
        LAUNCH_SEQUENCE.store(0, std::sync::atomic::Ordering::Relaxed);
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("hosts.yml"), b"parent creds").expect("hosts");
        // Pre-plant a symlink at the next several names a launch could pick, and
        // at the pre-R2 fixed name.
        let _ = std::os::unix::fs::symlink(outside.path(), dir.path().join("gh-config-empty"));
        for n in 0..8 {
            let name = format!("{GH_CONFIG_DIR_PREFIX}{}-{n}", std::process::id());
            let _ = std::os::unix::fs::symlink(outside.path(), dir.path().join(name));
        }
        let mut vars = env(&[]);
        let target = isolate_gh_config(&mut vars, dir.path()).expect("isolate");
        let meta = std::fs::symlink_metadata(&target).expect("meta");
        assert!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "{target:?}"
        );
        assert!(std::fs::read_dir(&target).expect("read").next().is_none());
    }

    // R2 item 6: digest exclusions are EXACT names at the handle-dir top level only.
    #[test]
    fn a_nested_file_that_merely_contains_a_receipt_name_is_digested() {
        // Both trees hold `hooks/`, so only the file under test differs.
        let (_a, ra) = digest_dir(&[("CLAUDE.md", b"s"), ("hooks/keep.sh", b"k")]);
        let (_b, rb) = digest_dir(&[
            ("CLAUDE.md", b"s"),
            ("hooks/keep.sh", b"k"),
            ("hooks/x-launch-receipt.sh", b"#!/bin/sh\n"),
        ]);
        assert_ne!(
            config_dir_digest(&ra).expect("a"),
            config_dir_digest(&rb).expect("b"),
            "a hook whose name contains launch-receipt must be covered"
        );
    }

    #[test]
    fn nested_and_lookalike_names_are_digested_but_exact_top_level_names_are_not() {
        let (_base, base) = digest_dir(&[("CLAUDE.md", b"s")]);
        let base_digest = config_dir_digest(&base).expect("base");
        for name in [
            "hooks/auth.json",
            "sub/.credentials.json",
            "sub/.live-pid",
            "sub/settings.json",
            "sub/.claude.json",
            "my-launch-receipt.json",
            "xauth.json",
        ] {
            // The without-tree holds the same parent directory, so a covered file is
            // the only difference.
            let mut without = vec![("CLAUDE.md", b"s".as_slice())];
            if let Some((parent, _)) = name.split_once('/') {
                without.push((
                    if parent == "hooks" {
                        "hooks/keep"
                    } else {
                        "sub/keep"
                    },
                    b"k".as_slice(),
                ));
            }
            let (_w, wroot) = digest_dir(&without);
            let mut with = without.clone();
            with.push((name, b"z".as_slice()));
            let (_d, root) = digest_dir(&with);
            assert_ne!(
                config_dir_digest(&root).expect("with"),
                config_dir_digest(&wroot).expect("without"),
                "{name} must be covered"
            );
        }
        for name in [
            ".credentials.json",
            "credentials.json",
            "auth.json",
            "oauth_creds.json",
            RECEIPT_FILE,
            ".live-pid",
            ".claude.json",
            "settings.json",
        ] {
            let (_d, root) = digest_dir(&[("CLAUDE.md", b"s"), (name, b"z")]);
            assert_eq!(
                config_dir_digest(&root).expect("with"),
                base_digest,
                "top-level {name} must be excluded"
            );
        }
    }

    // R2 item 7: a directory swapped for a symlink cannot redirect the walk.
    #[cfg(unix)]
    #[test]
    fn the_walk_refuses_to_descend_through_a_symlinked_directory() {
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret"), b"x").expect("secret");
        let (_a, root) = digest_dir(&[("CLAUDE.md", b"s")]);
        std::os::unix::fs::symlink(outside.path(), root.join("sub")).expect("symlink");
        let mut rows = Vec::new();
        let result = walk_config_dir(&root.join("sub"), b"sub", 1, &mut rows);
        assert!(result.is_err(), "must refuse a symlinked dir: {rows:?}");
        assert!(rows.is_empty());
    }

    // R2 item 8: Unicode format characters (category Cf) in a manifest path.
    #[test]
    fn a_unicode_format_character_in_a_manifest_path_is_invalid() {
        for ch in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}',
            '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}',
            '\u{2064}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{FEFF}',
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = format!("a{ch}b");
            write_manifest(
                dir.path(),
                serde_json::json!([{ "path": path, "sha256": "0".repeat(64), "scope": "handle-dir" }]),
            );
            let check = verify_manifest(dir.path(), dir.path(), dir.path());
            assert_eq!(
                check,
                invalid("manifest_path_invalid", None),
                "U+{:04X}",
                ch as u32
            );
        }
    }

    // R2 item 9: a relative base_dir or repo_root is refused.
    #[test]
    fn a_relative_base_dir_or_repo_root_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = b"x";
        std::fs::write(dir.path().join("f"), bytes).expect("f");
        write_manifest(
            dir.path(),
            serde_json::json!([{ "path": "f", "sha256": sha256_hex(bytes), "scope": "handle-dir" }]),
        );
        assert_eq!(
            verify_manifest(dir.path(), dir.path(), dir.path()),
            ManifestCheck::Verified
        );
        assert_eq!(
            verify_manifest(Path::new("rel"), dir.path(), dir.path()),
            invalid("base_dir_not_absolute", None)
        );
        assert_eq!(
            verify_manifest(dir.path(), dir.path(), Path::new("rel")),
            invalid("repo_root_not_absolute", None)
        );
    }

    // R2 item 10: token text inside a variable NAME is never recorded.
    #[test]
    fn a_token_prefix_inside_a_variable_name_is_recorded_as_a_placeholder() {
        for name in [
            "ghp_AAAA1111",
            "X_github_pat_ZZZ_TOKEN",
            "ghs_abc_token",
            "ghp%5FAAAA1111",
        ] {
            let mut vars = env(&[(name, "v"), ("HOME", "/h")]);
            let allow: BTreeSet<String> = [name.to_owned()].into_iter().collect();
            let outcome = scrub_env(&mut vars, &allow);
            assert!(!vars.contains_key(name), "{name} must be removed");
            assert_eq!(outcome.removed, vec![REDACTED_NAME.to_owned()], "{name}");
            assert!(outcome.allowed.is_empty() && outcome.unresolved.is_empty());
            let recorded = format!("{outcome:?}");
            assert!(
                !recorded.contains("AAAA")
                    && !recorded.contains("ZZZ")
                    && !recorded.contains("abc"),
                "raw name leaked: {recorded}"
            );
        }
    }

    // M-c
    fn digest_dir(files: &[(&str, &[u8])]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canon");
        for (name, bytes) in files {
            let path = root.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("parent");
            }
            std::fs::write(path, bytes).expect("write");
        }
        (dir, root)
    }

    #[test]
    fn the_config_digest_is_independent_of_creation_order() {
        let (_a, ra) = digest_dir(&[("a", b"1"), ("b", b"2"), ("d/c", b"3")]);
        let (_b, rb) = digest_dir(&[("d/c", b"3"), ("b", b"2"), ("a", b"1")]);
        assert_eq!(
            config_dir_digest(&ra).expect("a"),
            config_dir_digest(&rb).expect("b")
        );
    }

    #[test]
    fn the_config_digest_changes_on_a_one_byte_change_or_a_rename() {
        let (_a, ra) = digest_dir(&[("a", b"1")]);
        let (_b, rb) = digest_dir(&[("a", b"2")]);
        let (_c, rc) = digest_dir(&[("b", b"1")]);
        let base = config_dir_digest(&ra).expect("a");
        assert_ne!(base, config_dir_digest(&rb).expect("b"));
        assert_ne!(base, config_dir_digest(&rc).expect("c"));
    }

    #[test]
    fn the_config_digest_excludes_credentials_receipt_and_liveness() {
        let (_a, ra) = digest_dir(&[("settings.json", b"s")]);
        let (_b, rb) = digest_dir(&[
            ("settings.json", b"s"),
            (".credentials.json", b"token-1"),
            ("credentials.json", b"token-2"),
            ("auth.json", b"token-3"),
            ("oauth_creds.json", b"token-4"),
            (RECEIPT_FILE, b"{}"),
            (".live-pid", b"42"),
        ]);
        assert_eq!(
            config_dir_digest(&ra).expect("a"),
            config_dir_digest(&rb).expect("b"),
            "token rotation must not move the digest"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_config_digest_does_not_follow_links() {
        let outside = tempfile::tempdir().expect("outside");
        let target = outside.path().join("t");
        std::fs::write(&target, b"one").expect("t");
        let (_a, root) = digest_dir(&[]);
        std::os::unix::fs::symlink(&target, root.join("link")).expect("link");
        let before = config_dir_digest(&root).expect("before");
        std::fs::write(&target, b"two-two").expect("rewrite target");
        assert_eq!(before, config_dir_digest(&root).expect("after"));
        std::fs::remove_file(root.join("link")).expect("rm");
        std::os::unix::fs::symlink(outside.path().join("other"), root.join("link"))
            .expect("relink");
        assert_ne!(before, config_dir_digest(&root).expect("retargeted"));
    }

    #[test]
    fn the_config_digest_refuses_a_relative_dir() {
        assert!(config_dir_digest(Path::new("term-1")).is_err());
    }

    #[test]
    fn the_identity_digest_is_domain_separated_and_hides_the_uuid() {
        let uuid = uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").expect("uuid");
        let digest = identity_digest(&uuid);
        assert_eq!(digest, identity_digest(&uuid));
        assert_ne!(digest.as_str(), sha256_hex(uuid.to_string().as_bytes()));
        assert!(Digest256::parse(digest.as_str()).is_some());
        assert!(!digest.as_str().contains("123e4567"));
    }

    #[test]
    fn digest_fields_accept_only_64_lowercase_hex() {
        assert!(Digest256::parse(&"a".repeat(64)).is_some());
        for bad in [&"A".repeat(64), &"a".repeat(63), &"g".repeat(64), ""] {
            assert!(Digest256::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_receipt_slot_serialises_as_a_number() {
        let json = receipt_with(GuardManifestState::Absent)
            .to_json()
            .expect("serialise");
        assert!(json.contains("\"account_slot\":3"), "{json}");
    }

    // L-a / L-d
    #[test]
    fn a_relative_receipt_dir_is_refused_with_a_fixed_kind() {
        let error = write_receipt(Path::new("rel"), &receipt_with(GuardManifestState::Absent))
            .expect_err("refuse");
        assert_eq!(
            error,
            ReceiptError::Unwritable {
                kind: "invalid_input"
            }
        );
    }

    // ---- R2 fix-list tests ----

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    // R2 item 1 (owner decision an internal journal entry): every flag that loads hooks or plugins,
    // or hands approval to something other than a person, is refused in every form.
    #[test]
    fn sandbox_refuses_every_plugin_hook_and_approval_delegating_flag() {
        for flag in [
            "--plugin-dir",
            "--plugin-url",
            "--permission-prompt-tool",
            "--mcp-config",
            "--strict-mcp-config",
            "--agent",
            "--agents",
            "--setting-sources",
            "--permission-prompts",
        ] {
            let upper = flag.to_ascii_uppercase();
            for form in [
                args(&[flag, "x"]),
                args(&[flag]),
                args(&[&format!("{flag}=x")]),
                args(&[&format!("{flag}=")]),
                args(&["-p", "hi", flag, "x"]),
                args(&[&upper, "x"]),
                args(&[&format!("{upper}=x")]),
            ] {
                assert!(sandbox_conflict(&form), "must refuse {form:?}");
            }
        }
        // Ordinary arguments stay accepted (the denylist must not become a wall).
        assert!(!sandbox_conflict(&args(&["--model", "opus", "-p", "hi"])));
        assert!(!sandbox_conflict(&args(&["--agentic-mode-prompt"])));
    }

    // R2 item 2: git config redirection and the ssh agent socket are plumbing, removed
    // whatever their case and never allowlistable.
    #[test]
    fn git_config_redirection_and_ssh_agent_are_removed_in_any_case() {
        for name in [
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG",
            "SSH_AUTH_SOCK",
            "git_config_global",
            "Git_Config_System",
            "git_config",
            "ssh_auth_sock",
            "git_askpass",
            "Ssh_Askpass",
            "git_config_count",
            "git_config_parameters",
            "git_config_key_0",
            "Git_Config_Value_12",
        ] {
            let mut vars = env(&[(name, "/x"), ("PATH", "/usr/bin")]);
            let allow: BTreeSet<String> = [name.to_owned()].into_iter().collect();
            let outcome = scrub_env(&mut vars, &allow);
            assert!(!vars.contains_key(name), "{name} must be removed");
            assert_eq!(outcome.removed, vec![name.to_owned()], "{name}");
            assert!(
                outcome.allowed.is_empty() && outcome.unresolved.is_empty(),
                "{name} is plumbing and cannot be allowlisted"
            );
            assert!(vars.contains_key("PATH"));
        }
    }

    // R2 item 3a: `GIT` pairs with the credential markers.
    #[test]
    fn git_prefixed_credential_names_are_removed() {
        for name in [
            "GIT_TOKEN",
            "GIT_PASSWORD",
            "GIT_HTTP_PASSWORD",
            "GIT_PAT",
            "GIT_SECRET",
            "GIT_AUTH_HEADER",
            "git_api_key",
        ] {
            let mut vars = env(&[(name, "v"), ("HOME", "/h")]);
            let outcome = scrub_env(&mut vars, &BTreeSet::new());
            assert!(!vars.contains_key(name), "{name} must be removed");
            assert_eq!(outcome.removed, vec![name.to_owned()], "{name}");
        }
        // A GIT name with no credential marker is untouched.
        let mut vars = env(&[("GIT_EDITOR", "vi"), ("GIT_PAGER", "less")]);
        assert!(scrub_env(&mut vars, &BTreeSet::new()).removed.is_empty());
    }

    // R2 item 3b: a percent-encoded token prefix in a value still removes the variable.
    #[test]
    fn a_percent_encoded_token_prefix_in_a_value_removes_the_variable() {
        for value in [
            "ghp%5Fabc",
            "x%67hp_abc",
            "github%5fpat%5Fabc",
            "https://u:gho%5Fabc@github.com/o/r",
            "ghp%255Fabc",
        ] {
            let mut vars = env(&[("DEPLOY_CREDENTIAL", value), ("HOME", "/h")]);
            let outcome = scrub_env(&mut vars, &BTreeSet::new());
            assert!(
                !vars.contains_key("DEPLOY_CREDENTIAL"),
                "{value} must remove the variable"
            );
            assert_eq!(outcome.removed, vec!["DEPLOY_CREDENTIAL".to_owned()]);
            assert!(!format!("{outcome:?}").contains("abc"));
        }
        // Percent signs that do not decode to a token prefix are left alone.
        let mut vars = env(&[("PROGRESS", "50%"), ("ENC", "a%20b%zz")]);
        assert!(scrub_env(&mut vars, &BTreeSet::new()).removed.is_empty());
    }
}
