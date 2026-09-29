use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Maximum number of accounts supported.
pub const MAX_ACCOUNTS: u16 = 999;

/// Validated account number (1..=MAX_ACCOUNTS).
///
/// Prevents path traversal and keychain namespace injection by ensuring
/// the value is always a valid positive integer in the allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountNum(u16);

impl AccountNum {
    /// Returns the underlying account number.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for AccountNum {
    type Error = crate::error::CredentialError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if (1..=MAX_ACCOUNTS).contains(&value) {
            Ok(AccountNum(value))
        } else {
            Err(crate::error::CredentialError::InvalidAccount(
                value.to_string(),
            ))
        }
    }
}

impl fmt::Display for AccountNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AccountNum {
    type Err = crate::error::CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: u16 = s
            .parse()
            .map_err(|_| crate::error::CredentialError::InvalidAccount(s.to_string()))?;
        AccountNum::try_from(n)
    }
}

// Serde impls. Serialize emits the raw u16; Deserialize routes through
// the validating `TryFrom<u16>` constructor so any non-1..=MAX_ACCOUNTS
// value (e.g. attacker-injected 0 or 65535 in an audit payload) is
// rejected at deserialize time. Added by M01 fix-wave for the audit
// trail payload types (`OAuthRefreshPayload.slot`, `AccountSwapPayload.
// {from_slot, to_slot}`, `IdentityMintPayload.slot`).
impl Serialize for AccountNum {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for AccountNum {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let n = u16::deserialize(deserializer)?;
        AccountNum::try_from(n).map_err(D::Error::custom)
    }
}

/// OAuth access token with masked Display and zeroize-on-drop.
///
/// The inner value is never serialized or logged in full.
/// Use `expose_secret()` when the raw value is needed for HTTP headers.
pub struct AccessToken(SecretString);

impl AccessToken {
    pub fn new(value: String) -> Self {
        Self(SecretString::from(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for AccessToken {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_string())
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccessToken({})", self)
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.expose_secret();
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..8], &s[s.len() - 4..])
        } else {
            write!(f, "****")
        }
    }
}

impl Serialize for AccessToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for AccessToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(AccessToken::new(s))
    }
}

/// 3P provider API key with masked Display and zeroize-on-drop.
///
/// Wraps API keys from `ProviderSettings` so every raw-value access
/// is auditable via `expose_secret()`. On-disk format remains plain
/// JSON; protection is in-memory only.
pub struct ApiKey(SecretString);

impl ApiKey {
    pub fn new(value: String) -> Self {
        Self(SecretString::from(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// Returns a masked fingerprint: `prefix6...suffix4`.
    /// Keys under 20 chars display as `(short)` to avoid revealing
    /// too much of the key space.
    pub fn fingerprint(&self) -> String {
        let s = self.0.expose_secret();
        if s.len() < 20 {
            "(short)".into()
        } else {
            format!("{}...{}", &s[..6], &s[s.len() - 4..])
        }
    }
}

impl Clone for ApiKey {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_string())
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey({})", self)
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.expose_secret();
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..6], &s[s.len() - 4..])
        } else {
            write!(f, "****")
        }
    }
}

/// OAuth refresh token with masked Display and zeroize-on-drop.
pub struct RefreshToken(SecretString);

impl RefreshToken {
    pub fn new(value: String) -> Self {
        Self(SecretString::from(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for RefreshToken {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_string())
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefreshToken({})", self)
    }
}

impl fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.expose_secret();
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..8], &s[s.len() - 4..])
        } else {
            write!(f, "****")
        }
    }
}

impl Serialize for RefreshToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for RefreshToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(RefreshToken::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_num_valid() {
        assert!(AccountNum::try_from(1u16).is_ok());
        assert!(AccountNum::try_from(7u16).is_ok());
        assert!(AccountNum::try_from(999u16).is_ok());
    }

    #[test]
    fn account_num_invalid() {
        assert!(AccountNum::try_from(0u16).is_err());
        assert!(AccountNum::try_from(1000u16).is_err());
    }

    #[test]
    fn account_num_from_str() {
        assert!("1".parse::<AccountNum>().is_ok());
        assert!("abc".parse::<AccountNum>().is_err());
        assert!("0".parse::<AccountNum>().is_err());
        assert!("../etc".parse::<AccountNum>().is_err());
    }

    #[test]
    fn access_token_masked_display() {
        let token = AccessToken::new("sk-ant-oat01-abcdefghijklmnop".to_string());
        let display = format!("{token}");
        assert!(display.starts_with("sk-ant-o"));
        assert!(display.ends_with("mnop"));
        assert!(display.contains("..."));
        assert!(!display.contains("abcdefghijklmnop"));
    }

    #[test]
    fn refresh_token_masked_display() {
        let token = RefreshToken::new("sk-ant-ort01-xyzxyzxyzxyzxyz".to_string());
        let display = format!("{token}");
        assert!(!display.contains("xyzxyzxyzxyzxyz"));
    }

    #[test]
    fn access_token_expose_secret() {
        let raw = "sk-ant-oat01-full-value";
        let token = AccessToken::new(raw.to_string());
        assert_eq!(token.expose_secret(), raw);
    }

    #[test]
    fn api_key_masked_display() {
        let key = ApiKey::new("sk-mm-abcdefghijklmnopqrstuv".to_string());
        let display = format!("{key}");
        assert!(display.starts_with("sk-mm-"));
        assert!(display.ends_with("stuv"));
        assert!(display.contains("..."));
        assert!(!display.contains("abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn api_key_expose_secret() {
        let raw = "sk-mm-test-key-value-12345";
        let key = ApiKey::new(raw.to_string());
        assert_eq!(key.expose_secret(), raw);
    }

    #[test]
    fn api_key_fingerprint() {
        let key = ApiKey::new("abcdef012345678901234xyz".to_string());
        assert_eq!(key.fingerprint(), "abcdef...4xyz");
    }

    #[test]
    fn api_key_fingerprint_short() {
        let key = ApiKey::new("abcdef01234567890xy".to_string());
        assert_eq!(key.fingerprint(), "(short)");
    }

    #[test]
    fn api_key_debug_masked() {
        let key = ApiKey::new("sk-mm-abcdefghijklmnopqrstuv".to_string());
        let debug = format!("{key:?}");
        assert!(debug.starts_with("ApiKey("));
        assert!(!debug.contains("abcdefghijklmnopqrstuv"));
    }

    // ── Serializable token-holder surface (durable-instruments.md MUST-1/2) ──
    //
    // `AccessToken` and `RefreshToken`'s `Serialize` impls (above) deliberately
    // emit the RAW secret — `Display`/`Debug` mask, `Serialize` does not, because
    // the credential MUST round-trip byte-for-byte to
    // `identities/<UUID>/credentials.json`. That asymmetry is intentional and is
    // NOT what this test guards. What it guards: nothing at the type level stops
    // a FUTURE struct that embeds one of these tokens and derives `Serialize`
    // from emitting the raw secret into a log line, a telemetry payload, an
    // error body, or an audit record — `redact_tokens` (security.md MUST-8)
    // never sees it, because it never becomes a `String` the redactor can scan
    // until the moment it has already left the process as JSON. `ApiKey` has no
    // `Serialize` impl at all (verified: `grep -rn "for ApiKey" csq-core/src
    // csq/src` finds only Clone/Debug/Display) and is correctly out of scope —
    // its on-disk persistence goes through a separate plain-`String` field that
    // `ApiKey` only wraps as a VIEW at the point of access (`providers/settings.rs`).

    /// The known-legitimate credential-persistence chain: every type that (a)
    /// derives `Serialize` and (b) holds an `AccessToken`/`RefreshToken` field
    /// directly or transitively, established by manual audit
    /// (`daemon-auth-resilience` zeroize-guard follow-up) and re-verified by
    /// [`serializable_token_holder_surface_matches_known_legitimate_set`] on
    /// every test run: `OAuthPayload` (the direct holder) -> wrapped by
    /// `AnthropicCredentialFile` (`claude_ai_oauth: OAuthPayload`) -> wrapped by
    /// the `CredentialFile` enum (`Anthropic(AnthropicCredentialFile)`). All
    /// three MUST serialize the raw secret — this is the on-disk credential
    /// file shape csq reads and writes at `identities/<UUID>/credentials.json`.
    const KNOWN_LEGITIMATE_TOKEN_HOLDERS: &[&str] =
        &["OAuthPayload", "AnthropicCredentialFile", "CredentialFile"];

    /// Sanity floor for the "could not measure" outcome
    /// (`durable-instruments.md` MUST-2's third outcome): a full scan of
    /// `csq-core/src`'s PRODUCTION code (test modules stripped) declares several
    /// hundred struct/enum types. A parser regression that stops matching
    /// declarations would report a near-zero count instead of a real "no new
    /// holders" result — this floor turns that silent failure into a loud one.
    /// Measured at introduction: ~500-600 production declarations; 300 leaves
    /// ample margin against normal codebase growth/shrinkage while still being
    /// far above what a broken parser would find.
    const MIN_EXPECTED_TYPE_COUNT: usize = 300;

    /// Removes every `#[cfg(test)] mod ... { ... }` block from `content`
    /// (brace-depth-tracked, so it survives nesting) — test fixtures MUST NOT
    /// count as a production risk. Generalizes the single-suffix-module
    /// `\nmod tests {` boundary this file's sibling `keychain.rs` uses in its
    /// own self-scan tripwire (`no_bare_unbounded_output_call_in_this_file`) to
    /// the general case needed here: many files, `#[cfg(test)]` anywhere.
    fn strip_cfg_test_modules(content: &str) -> String {
        let mut out = String::with_capacity(content.len());
        let mut skipping = false;
        let mut skip_depth: i32 = 0;
        let mut saw_cfg_test = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if skipping {
                skip_depth += line.matches('{').count() as i32;
                skip_depth -= line.matches('}').count() as i32;
                if skip_depth <= 0 {
                    skipping = false;
                }
                continue;
            }
            if trimmed == "#[cfg(test)]" {
                saw_cfg_test = true;
                continue;
            }
            if saw_cfg_test {
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue; // allow stray attributes between #[cfg(test)] and `mod`
                }
                if trimmed.starts_with("mod ") {
                    let opens = line.matches('{').count() as i32;
                    let closes = line.matches('}').count() as i32;
                    skip_depth = opens - closes;
                    saw_cfg_test = false;
                    if skip_depth > 0 {
                        skipping = true;
                    }
                    continue;
                }
                saw_cfg_test = false; // not followed by `mod` — nothing to skip
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Scans every `.rs` file under `csq-core/src` (production code only —
    /// [`strip_cfg_test_modules`] removes test modules first) and returns
    /// `(holders, total_type_count)`: `holders` is every type name that (a) is
    /// reachable, via zero or more "struct/variant embeds type" hops, from
    /// `{AccessToken, RefreshToken}`, AND (b) derives or manually implements
    /// `Serialize`. `total_type_count` is every struct/enum declaration found
    /// (the [`MIN_EXPECTED_TYPE_COUNT`] sanity signal).
    ///
    /// Deliberately line-based, not a real Rust parser — matches this
    /// codebase's existing self-scan-tripwire style (see
    /// `keychain.rs::no_bare_unbounded_output_call_in_this_file`), which is
    /// sufficient because rustfmt (CI-enforced) guarantees the brace-placement
    /// conventions this scan relies on.
    fn scan_serializable_token_holders() -> (std::collections::BTreeSet<String>, usize) {
        use std::collections::{HashMap, HashSet};

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_root = std::path::PathBuf::from(manifest_dir).join("src");

        let field_re = regex::Regex::new(
            r"^(?:pub(?:\([^)]*\))?\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:\s*(?:Option<|Vec<|Box<)*([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("valid field regex");
        let variant_re =
            regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(\s*(?:Box<)?([A-Za-z_][A-Za-z0-9_]*)")
                .expect("valid variant regex");
        let type_decl_re = regex::Regex::new(
            r"^(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("valid type-decl regex");
        let manual_impl_re =
            regex::Regex::new(r"^impl(?:<[^>]*>)?\s+Serialize\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
                .expect("valid manual-impl regex");

        let mut holds: HashMap<String, HashSet<String>> = HashMap::new();
        let mut serialize_types: HashSet<String> = HashSet::new();
        let mut total_types: usize = 0;

        let mut stack: Vec<std::path::PathBuf> = vec![src_root];
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        assert!(
            files.len() > 20,
            "could not measure — found only {} .rs files under csq-core/src \
             (directory walk likely broken)",
            files.len()
        );

        for path in files {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let production = strip_cfg_test_modules(&content);

            let mut pending_derive_serialize = false;
            let mut current: Option<String> = None;
            let mut current_start_depth: i32 = 0;
            let mut depth: i32 = 0;

            for line in production.lines() {
                let trimmed = line.trim();

                if let Some(caps) = manual_impl_re.captures(trimmed) {
                    serialize_types.insert(caps[1].to_string());
                }

                if trimmed.starts_with("#[derive(") {
                    if trimmed.contains("Serialize") {
                        pending_derive_serialize = true;
                    }
                } else if current.is_none()
                    && !trimmed.is_empty()
                    && !trimmed.starts_with("//")
                    && !trimmed.starts_with('#')
                {
                    if let Some(caps) = type_decl_re.captures(trimmed) {
                        let name = caps[2].to_string();
                        total_types += 1;
                        if pending_derive_serialize {
                            serialize_types.insert(name.clone());
                        }
                        current = Some(name);
                        current_start_depth = depth;
                    }
                    pending_derive_serialize = false;
                }

                if let Some(name) = &current {
                    if depth > current_start_depth {
                        if let Some(caps) = field_re.captures(trimmed) {
                            holds
                                .entry(name.clone())
                                .or_default()
                                .insert(caps[1].to_string());
                        } else if let Some(caps) = variant_re.captures(trimmed) {
                            holds
                                .entry(name.clone())
                                .or_default()
                                .insert(caps[1].to_string());
                        }
                    }
                }

                depth += trimmed.matches('{').count() as i32;
                depth -= trimmed.matches('}').count() as i32;
                if current.is_some() && depth <= current_start_depth {
                    current = None;
                }
            }
        }

        let seed: HashSet<String> = ["AccessToken", "RefreshToken"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut reachable = seed.clone();
        loop {
            let mut added = false;
            for (holder, held) in &holds {
                if !reachable.contains(holder) && held.iter().any(|h| reachable.contains(h)) {
                    reachable.insert(holder.clone());
                    added = true;
                }
            }
            if !added {
                break;
            }
        }

        let result: std::collections::BTreeSet<String> = reachable
            .into_iter()
            .filter(|t| serialize_types.contains(t) && t != "AccessToken" && t != "RefreshToken")
            .collect();

        (result, total_types)
    }

    /// The discriminating check (durable-instruments.md MUST-2 — three
    /// outcomes, never a pass/fail binary): **holds** (the discovered
    /// Serialize-deriving token-holder set is exactly
    /// [`KNOWN_LEGITIMATE_TOKEN_HOLDERS`]) / **a new unaudited holder
    /// appeared, or a known one vanished** (named in the panic message,
    /// forcing a conscious decision) / **could not measure** (the scan found
    /// suspiciously few types — [`MIN_EXPECTED_TYPE_COUNT`] — a parser
    /// break, never silently read as "nothing found").
    #[test]
    fn serializable_token_holder_surface_matches_known_legitimate_set() {
        let (found, total_types) = scan_serializable_token_holders();

        assert!(
            total_types >= MIN_EXPECTED_TYPE_COUNT,
            "could not measure — the scan found only {total_types} struct/enum \
             declarations in csq-core/src production code (expected >= \
             {MIN_EXPECTED_TYPE_COUNT}); the parser likely broke — this is NOT \
             evidence the token-holder set is empty"
        );

        let expected: std::collections::BTreeSet<String> = KNOWN_LEGITIMATE_TOKEN_HOLDERS
            .iter()
            .map(|s| s.to_string())
            .collect();

        if found != expected {
            let extra: Vec<&String> = found.difference(&expected).collect();
            let missing: Vec<&String> = expected.difference(&found).collect();
            panic!(
                "serializable token-holder surface drifted from the known-legitimate \
                 set.\nNew unaudited Serialize-deriving type(s) holding \
                 AccessToken/RefreshToken: {extra:?}\nKnown-legitimate type(s) no \
                 longer found (renamed/removed?): {missing:?}\nIf a new type \
                 genuinely needs to round-trip credentials to disk, add it to \
                 KNOWN_LEGITIMATE_TOKEN_HOLDERS with a comment stating why. \
                 Otherwise its Serialize derive/impl is the bug — see \
                 credential-type-hygiene.md and security.md MUST-2."
            );
        }
    }
}
