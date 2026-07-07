//! EATP audit-chain canonical-form **projection** (CF1 / M08b).
//!
//! # What this is — and what it is NOT
//!
//! This module is a *projection*, not an adoption. csq's own session-custody
//! chain ([`crate::audit::types::SignedRecord`] + [`persist::canonical_bytes_for`])
//! is unchanged and remains the sovereign authority over csq's 14
//! [`crate::audit::types::EventKind`] session-custody events (CsqRun,
//! OAuthRefresh, KeyRotate, …). Those events are NOT EATP authorization-envelope
//! events; replacing their canonical form with the EATP form would be both
//! invasive and domain-wrong (workspace an internal journal entry Finding B).
//!
//! Instead, this module adds a *separate, standalone* encoder that reproduces
//! the Foundation EATP governance audit-chain canonical form **byte-for-byte**,
//! so that the loom↔csq seam (workspace an internal journal entry) can feed governance /
//! decision-provenance events through csq's existing sign/anchor pipeline while
//! remaining wire-conformant to the published cross-SDK vectors.
//!
//! # The canonical form (authoritative source: kailash-py)
//!
//! Per the CF1 sourcing rule, the conformance target is the **published**
//! `terrene-foundation/kailash-py` implementation
//! (`src/kailash/trust/pact/audit.py::AuditAnchor.compute_hash`, v2.28.1) — NOT
//! the the enterprise edition copy. The canonical content is:
//!
//! ```text
//! {anchor_id}:{sequence}:{previous_hash|GENESIS}:{agent_id}:{action}:
//! {verification_level}:{envelope_id_or_empty}:{result}:{iso8601_+00:00}
//! [:{metadata_json_sorted_compact_ensure_ascii}]
//! ```
//!
//! The SHA-256 of the UTF-8 encoding of that string is the anchor's content
//! hash. Key byte-exactness requirements, each verified against kailash-py's
//! reference output:
//!
//! 1. **Genesis sentinel.** A `None` `previous_hash` renders as 64 lowercase
//!    hex zeros ([`Sha256Hex::GENESIS`]), mirroring Python's
//!    `self.previous_hash or GENESIS_HASH`.
//! 2. **Empty `envelope_id`.** A `None` `envelope_id` renders as the empty
//!    string between its colons, mirroring `self.envelope_id or ''`.
//! 3. **Metadata truthiness (community / default form).** In the default
//!    [`EatpAuditAnchor::canonical_input`] (community / kailash-py dialect) the
//!    metadata segment (AND its leading colon) is omitted when metadata is
//!    `None` OR an empty object — mirroring Python's `if self.metadata:` (an
//!    empty `dict` is falsy). The enterprise (the enterprise edition) dialect renders an
//!    explicit empty object as `:{}` via `canonical_input_kailash_rs` (an
//!    `enterprise`-gated method). See the edition-split note below.
//! 4. **Metadata serialization.** Non-empty metadata is serialized with sorted
//!    keys, compact separators (`,` `:`), and `ensure_ascii=True` — every
//!    codepoint ≥ U+007F escapes as `\uXXXX` (lowercase), and codepoints above
//!    the BMP escape as a UTF-16 surrogate pair (`\uHHHH\uLLLL`), per RFC 8259
//!    §7. This is `escape_json_ascii`.
//!
//! # Edition dialect split — empty metadata object (M2 T2.3, an internal journal entry/0013)
//!
//! the enterprise edition serializes an empty object `{}` as `:{}`; kailash-py's
//! `compute_hash` uses `if self.metadata:` truthiness, so an empty `dict` is
//! **omitted**. csq deliberately ships BOTH dialects as EXPLICIT methods, so the
//! choice is keyed on the method called — NOT on the `enterprise` crate feature
//! (the originating R1 HIGH-1 fix: a feature-keyed default made the community
//! engine drift to the enterprise form under feature unification):
//!
//! - [`EatpAuditAnchor::canonical_input`] / [`EatpAuditAnchor::compute_hash`] —
//!   the **community** (kailash-py) dialect: empty `{}` omitted. The default,
//!   edition-stable form the community engine uses.
//! - `canonical_input_kailash_rs` / `compute_hash_kailash_rs` — the
//!   **enterprise** (the enterprise edition) dialect: empty `{}` → `:{}`. Enterprise edition
//!   only (`#[cfg(feature = "enterprise")]`); the dep-free reference encoder
//!   pinned byte-for-byte against the real the enterprise edition seam.
//!
//! Absent metadata (`None`) omits in both dialects; non-empty metadata is
//! byte-identical. The published kailash-py vectors (U1, U2) both carry
//! non-empty metadata, so neither exercises the empty-object edge; the
//! divergence is documented + pinned by tests, not by the published vectors.
//!
//! # Metadata value contract (floats + `default=str`)
//!
//! Governance metadata is structured string/integer/boolean/null data. Integer
//! and boolean/null formatting is byte-identical across Python `json.dumps` and
//! this encoder.
//!
//! **Floats are rejected, fail-closed.** Python `repr`-based float formatting
//! and Rust's formatter can diverge, and the JSON contract rejects NaN/Infinity.
//! [`EatpAuditAnchor::canonical_input`] / [`EatpAuditAnchor::compute_hash`]
//! therefore return [`EatpCanonicalError::MetadataContainsFloat`] when any float
//! appears in metadata (at any depth) — a load-bearing guard in BOTH debug and
//! release builds. Important asymmetry: kailash-py's `compute_hash` does NOT
//! itself reject floats (it hashes whatever `json.dumps(default=str)` emits), so
//! the enforcement point is the csq encoder + the seam, not a mutual SDK
//! invariant.
//!
//! **`default=str` is NOT replicated.** Python's `compute_hash` serializes
//! metadata with `json.dumps(..., default=str)`, coercing non-JSON-native values
//! (`datetime`, `Decimal`, `UUID`, `Enum`, …) to their `str()`. This encoder
//! accepts only `serde_json::Value` (already JSON-native), so it CANNOT see such
//! a value and does NOT replicate `default=str` coercion. **Seam contract:** the
//! loom↔csq seam (loom#411) MUST normalize governance metadata to JSON-native
//! values BEFORE an anchor reaches either SDK's hash path — otherwise a
//! kailash-py anchor (whose `datetime` went through `default=str`) and a csq
//! anchor for the same logical event would diverge. csq is JSON-native-in,
//! byte-exact-out; normalization is the seam's responsibility.

use crate::audit::persist::sha256_hex;
use crate::audit::types::Sha256Hex;
use serde_json::{Map, Value};

/// The kailash-py published audit-chain canonical-form spec version.
///
/// Pinned against the `spec_version` field of
/// `terrene-foundation/kailash-py`'s `test-vectors/audit-chain-canonical.json`
/// (v2.28.1 → `"1.0"`). This is the version of the **EATP projection** form and
/// is intentionally distinct from [`persist::AUDIT_SCHEMA_VERSION`] (`"2"`),
/// which versions csq's *own* session-custody chain envelope. They are two
/// different forms over two different domains; conflating them would be the
/// error an internal journal entry Finding A guards against.
///
/// [`persist::AUDIT_SCHEMA_VERSION`]: crate::audit::persist
pub const EATP_CANONICAL_FORM_SPEC_VERSION: &str = "1.0";

/// Error returned when an [`EatpAuditAnchor`] cannot be reduced to the EATP
/// canonical form byte-for-byte against the kailash-py reference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EatpCanonicalError {
    /// Metadata contained a floating-point number (at any nesting depth). The
    /// cross-SDK byte-exactness contract admits string / integer / boolean /
    /// null / nested values only: Rust's `f64` formatting diverges from
    /// Python's `repr`-based `json.dumps` float formatting (and the JSON
    /// contract rejects NaN/Infinity outright). This is a **load-bearing**
    /// release-mode guard — a float silently hashed here would produce a
    /// pre-image that a kailash-py/the enterprise edition verifier rejects, far from the
    /// sign site. The loom↔csq seam MUST normalize or reject floats before an
    /// anchor reaches the hash path. NOTE: kailash-py's `compute_hash` does NOT
    /// itself reject floats (it serializes whatever `json.dumps(default=str)`
    /// produces); the enforcement point is therefore the csq encoder + the seam,
    /// not a mutual SDK invariant.
    MetadataContainsFloat,
}

impl std::fmt::Display for EatpCanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetadataContainsFloat => f.write_str(
                "EATP canonical-form metadata contains a float; only \
                 string/integer/boolean/null/nested values are byte-exact across SDKs",
            ),
        }
    }
}

impl std::error::Error for EatpCanonicalError {}

/// PACT verification level.
///
/// # Edition split (M2 T2.3, an internal journal entry)
///
/// The **community** edition targets kailash-py's authoritative
/// `kailash.trust.pact.audit.VerificationLevel` — the 4-level gradient
/// (`AUTO_APPROVED`/`FLAGGED`/`HELD`/`BLOCKED`). The two richer the enterprise edition
/// levels (`PEER_REVIEWED`, `SIGNED_ATTESTATION`) are **structurally absent**
/// from the community build: they are `#[cfg(feature = "enterprise")]` variants,
/// so the community encoder cannot name, emit, or parse them. The
/// `community_verification_level_is_four_levels` test pins this.
///
/// The **enterprise** edition (csq-ee) adopts the full the enterprise edition gradient —
/// `PEER_REVIEWED` (a named human peer reviewed + signed off) and
/// `SIGNED_ATTESTATION` (an identified party made a provable signed statement).
/// These express multi-operator / regulated governance states the 4-level
/// gradient cannot. This is the dog/tail model applied to the audit chain:
/// community gets the open standard, enterprise gets the proprietary depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    AutoApproved,
    Flagged,
    Held,
    Blocked,
    /// the enterprise edition only: a named human peer reviewed and signed off (4-eyes /
    /// works-council / regulated change-control). Enterprise edition only.
    #[cfg(feature = "enterprise")]
    PeerReviewed,
    /// the enterprise edition only: an identified party made a provable, cryptographically
    /// signed attestation (not merely an automated-policy outcome). Enterprise
    /// edition only.
    #[cfg(feature = "enterprise")]
    SignedAttestation,
}

impl VerificationLevel {
    /// The canonical wire string (e.g. `"AUTO_APPROVED"`) used in the
    /// colon-delimited canonical input — byte-identical to kailash-py's
    /// `VerificationLevel.value`.
    #[must_use]
    pub fn as_canonical_str(self) -> &'static str {
        match self {
            Self::AutoApproved => "AUTO_APPROVED",
            Self::Flagged => "FLAGGED",
            Self::Held => "HELD",
            Self::Blocked => "BLOCKED",
            #[cfg(feature = "enterprise")]
            Self::PeerReviewed => "PEER_REVIEWED",
            #[cfg(feature = "enterprise")]
            Self::SignedAttestation => "SIGNED_ATTESTATION",
        }
    }

    /// Parses a canonical wire string in the **community** (kailash-py) 4-level
    /// gradient.
    ///
    /// Returns `None` for anything outside `AUTO_APPROVED`/`FLAGGED`/`HELD`/
    /// `BLOCKED` — INCLUDING `"PEER_REVIEWED"`/`"SIGNED_ATTESTATION"`. This is
    /// edition-stable: it returns `None` for the two the enterprise edition levels even in a
    /// feature-unified `enterprise` build, so the community engine's level
    /// acceptance does not drift (R1 HIGH-1 fix, an internal journal entry). For the
    /// enterprise 6-level parse, see `from_canonical_str_kailash_rs`.
    #[must_use]
    pub fn from_canonical_str(s: &str) -> Option<Self> {
        match s {
            "AUTO_APPROVED" => Some(Self::AutoApproved),
            "FLAGGED" => Some(Self::Flagged),
            "HELD" => Some(Self::Held),
            "BLOCKED" => Some(Self::Blocked),
            _ => None,
        }
    }

    /// Parses a canonical wire string in the **enterprise** (the enterprise edition) 6-level
    /// gradient: the 4 community levels PLUS `PEER_REVIEWED` and
    /// `SIGNED_ATTESTATION`. Enterprise edition only.
    #[cfg(feature = "enterprise")]
    #[must_use]
    pub fn from_canonical_str_kailash_rs(s: &str) -> Option<Self> {
        match s {
            "PEER_REVIEWED" => Some(Self::PeerReviewed),
            "SIGNED_ATTESTATION" => Some(Self::SignedAttestation),
            other => Self::from_canonical_str(other),
        }
    }
}

// Step 1 — Serialize / Deserialize for VerificationLevel (M3a).
//
// Serialize: emit the canonical wire string (e.g. `"AUTO_APPROVED"`).
// Deserialize: edition-aware parse — enterprise 6-level in enterprise builds,
// community 4-level otherwise. Fails closed on unrecognised strings (including
// `"PEER_REVIEWED"` / `"SIGNED_ATTESTATION"` in a community build), preserving
// the `community_verification_level_is_four_levels` guard intent.
impl serde::Serialize for VerificationLevel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_canonical_str())
    }
}

impl<'de> serde::Deserialize<'de> for VerificationLevel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        #[cfg(feature = "enterprise")]
        {
            Self::from_canonical_str_kailash_rs(&s).ok_or_else(|| {
                serde::de::Error::custom(format!("unknown VerificationLevel: {s:?}"))
            })
        }
        #[cfg(not(feature = "enterprise"))]
        {
            Self::from_canonical_str(&s).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "unknown VerificationLevel (community 4-level): {s:?}"
                ))
            })
        }
    }
}

/// A single EATP governance audit-chain anchor, in a form that reproduces
/// kailash-py's `AuditAnchor.compute_hash()` byte-for-byte.
///
/// This is the projection csq emits for EATP-relevant (seam) events. It does
/// NOT replace [`crate::audit::types::SignedRecord`]; see the module docs.
///
/// # `Debug` redacts `metadata`
///
/// `Debug` is implemented by hand (NOT derived) so that `{:?}` never prints the
/// `metadata` contents. Governance metadata may carry PII (works-council / RRPS
/// context), and `security.md` MUST-2 forbids credential/PII-bearing content in
/// logs. The redaction is a forward-guard for when the loom↔csq seam (loom#411)
/// wires this encoder to a live sign/anchor path: any future `{:?}` log of an
/// anchor shows `metadata: <redacted N keys>`, never the values.
#[derive(Clone)]
pub struct EatpAuditAnchor {
    /// Unique anchor identifier.
    pub anchor_id: String,
    /// 0-based position in the chain.
    pub sequence: u64,
    /// Hash of the previous anchor; `None` for genesis (renders as
    /// [`Sha256Hex::GENESIS`]).
    pub previous_hash: Option<Sha256Hex>,
    /// Agent that performed the action.
    pub agent_id: String,
    /// The action that was performed (e.g. `"envelope_created"`).
    pub action: String,
    /// PACT verification level for this action.
    pub verification_level: VerificationLevel,
    /// Constraint envelope evaluated, if any; `None` renders as the empty
    /// string.
    pub envelope_id: Option<String>,
    /// Action outcome (e.g. `"success"`).
    pub result: String,
    /// ISO-8601 UTC timestamp with explicit `+00:00` offset.
    pub timestamp: String,
    /// Additional structured governance metadata. `None` or an empty map omits
    /// the metadata segment. MUST be string/integer/boolean/null/nested values
    /// only — see the module-level number-formatting constraint.
    pub metadata: Option<Map<String, Value>>,
}

impl std::fmt::Debug for EatpAuditAnchor {
    /// Hand-written `Debug` that redacts `metadata` (may carry PII). Prints only
    /// the key count, never the values. See the type-level docs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EatpAuditAnchor")
            .field("anchor_id", &self.anchor_id)
            .field("sequence", &self.sequence)
            .field("previous_hash", &self.previous_hash)
            .field("agent_id", &self.agent_id)
            .field("action", &self.action)
            .field("verification_level", &self.verification_level)
            .field("envelope_id", &self.envelope_id)
            .field("result", &self.result)
            .field("timestamp", &self.timestamp)
            .field(
                "metadata",
                &self
                    .metadata
                    .as_ref()
                    .map(|m| format!("<redacted {} keys>", m.len())),
            )
            .finish()
    }
}

impl EatpAuditAnchor {
    /// Returns the canonical input string (the SHA-256 pre-image) in the
    /// **community** (kailash-py) dialect.
    ///
    /// Empty-`{}` metadata is OMITTED (Python `if self.metadata:` truthiness).
    /// This is the edition-stable, dependency-free default the community engine
    /// uses; its output does NOT depend on the `enterprise` crate feature — a
    /// feature-unified enterprise build still gets the community form here. For
    /// the enterprise (the enterprise edition) dialect, see `canonical_input_kailash_rs`.
    ///
    /// Fails with [`EatpCanonicalError::MetadataContainsFloat`] if `metadata`
    /// carries a float at any depth — a load-bearing release-mode guard (see the
    /// error docs). All other field types are constrained to byte-exact-safe
    /// forms by the struct's types.
    pub fn canonical_input(&self) -> Result<String, EatpCanonicalError> {
        // Community dialect: empty `{}` is NOT emitted.
        self.canonical_input_form(false)
    }

    /// Shared encoder for both dialects. `emit_empty_braces` selects the
    /// Divergence-1 behaviour for an EXPLICIT empty metadata object: `false` →
    /// omit (kailash-py / community); `true` → emit the `:{}` segment
    /// (the enterprise edition / enterprise). Absent metadata (`None`) omits regardless;
    /// non-empty metadata is byte-identical for both dialects. Keying the
    /// dialect on this PARAMETER (not the crate feature) keeps each engine's
    /// output stable under feature unification — the originating fix for the
    /// `CommunityAttestationEngine` drift (R1 HIGH-1, an internal journal entry).
    fn canonical_input_form(&self, emit_empty_braces: bool) -> Result<String, EatpCanonicalError> {
        let prev = self
            .previous_hash
            .as_ref()
            .map_or(Sha256Hex::GENESIS, Sha256Hex::as_str);
        let envelope = self.envelope_id.as_deref().unwrap_or("");
        let mut content = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.anchor_id,
            self.sequence,
            prev,
            self.agent_id,
            self.action,
            self.verification_level.as_canonical_str(),
            envelope,
            self.result,
            self.timestamp,
        );
        if let Some(meta) = &self.metadata {
            if !meta.is_empty() || emit_empty_braces {
                // Reject floats BEFORE serialization (fail closed in release).
                // No-op for the empty-object case (no values to scan).
                reject_floats_in_object(meta)?;
                content.push(':');
                // Empty map renders as `{}` (the enterprise edition empty-object form).
                canonicalize_object(meta, &mut content);
            }
        }
        Ok(content)
    }

    /// Returns the canonical input string in the **enterprise** (the enterprise edition)
    /// dialect: an explicit empty-`{}` metadata object emits the `:{}` segment
    /// (Divergence 1).
    ///
    /// This is the dependency-free reference encoder for the enterprise dialect;
    /// it is pinned byte-for-byte against the real the enterprise edition seam
    /// (`the enterprise seam crate`) by the dual-encoder parity guard
    /// (`csq/tests/enterprise_dialect_parity.rs`). Enterprise edition only.
    #[cfg(feature = "enterprise")]
    pub fn canonical_input_kailash_rs(&self) -> Result<String, EatpCanonicalError> {
        self.canonical_input_form(true)
    }

    /// Lowercase-hex SHA-256 of [`canonical_input`] (community dialect).
    ///
    /// Propagates [`EatpCanonicalError`] from [`canonical_input`].
    ///
    /// [`canonical_input`]: Self::canonical_input
    pub fn compute_hash(&self) -> Result<Sha256Hex, EatpCanonicalError> {
        Self::hash_of(&self.canonical_input()?)
    }

    /// Lowercase-hex SHA-256 of [`canonical_input_kailash_rs`] (enterprise
    /// dialect). Enterprise edition only.
    ///
    /// [`canonical_input_kailash_rs`]: Self::canonical_input_kailash_rs
    #[cfg(feature = "enterprise")]
    pub fn compute_hash_kailash_rs(&self) -> Result<Sha256Hex, EatpCanonicalError> {
        Self::hash_of(&self.canonical_input_kailash_rs()?)
    }

    fn hash_of(input: &str) -> Result<Sha256Hex, EatpCanonicalError> {
        // `sha256_hex` always returns exactly 64 lowercase hex chars, so
        // `try_new` cannot fail. Halt-on-fatal mirrors the persist.rs rationale:
        // a truncated audit hash is worse than a crash.
        Ok(Sha256Hex::try_new(sha256_hex(input.as_bytes()))
            .expect("sha256_hex must return 64 lowercase hex chars"))
    }
}

/// Recursively rejects any floating-point number in a JSON object (the
/// load-bearing release-mode float guard for [`EatpAuditAnchor::canonical_input`]).
fn reject_floats_in_object(map: &Map<String, Value>) -> Result<(), EatpCanonicalError> {
    for value in map.values() {
        reject_floats_in_value(value)?;
    }
    Ok(())
}

fn reject_floats_in_value(value: &Value) -> Result<(), EatpCanonicalError> {
    match value {
        Value::Number(n) if n.is_f64() => Err(EatpCanonicalError::MetadataContainsFloat),
        Value::Array(items) => {
            for item in items {
                reject_floats_in_value(item)?;
            }
            Ok(())
        }
        Value::Object(map) => reject_floats_in_object(map),
        _ => Ok(()),
    }
}

/// Serializes a JSON object into `out` with sorted keys and compact separators,
/// matching Python `json.dumps(obj, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)`.
fn canonicalize_object(map: &Map<String, Value>, out: &mut String) {
    // Python `sort_keys=True` sorts by Unicode code point. Rust `String` Ord
    // compares by UTF-8 bytes, which for valid UTF-8 yields the identical
    // ordering as code-point comparison.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_unstable();
    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_json_ascii(key, out);
        out.push(':');
        canonicalize_value(&map[*key], out);
    }
    out.push('}');
}

/// Serializes an arbitrary JSON value into `out` per the canonical contract.
fn canonicalize_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        // Integers/booleans/null are byte-identical across Python json.dumps
        // and serde_json. Floats are rejected UPSTREAM by `reject_floats_in_*`
        // (called from `canonical_input` before this runs), so a float cannot
        // reach here on the canonical path. `to_string` on an integer `Number`
        // matches Python's `int` repr byte-for-byte.
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => escape_json_ascii(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => canonicalize_object(map, out),
    }
}

/// Appends a JSON string literal (including the surrounding quotes) to `out`,
/// escaping exactly as Python `json.dumps(ensure_ascii=True)` does.
///
/// Escapes: `"` `\` the five short control escapes (`\b \f \n \r \t`), any other
/// control char (< U+0020) as `\u00XX`, and every codepoint ≥ U+007F as
/// `\uXXXX` (lowercase), using a UTF-16 surrogate pair for codepoints above the
/// BMP.
fn escape_json_ascii(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xFFFF {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => panic!("test helper expects a JSON object"),
        }
    }

    /// U1 published vector — BMP non-ASCII in metadata key AND value.
    #[test]
    fn u1_bmp_metadata_matches_published_vector() {
        let anchor = EatpAuditAnchor {
            anchor_id: "anc-u1-001".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent-u1".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: Some("env-u1".into()),
            result: "success".into(),
            timestamp: "2026-01-15T11:00:00+00:00".into(),
            metadata: Some(obj(json!({"role": "café", "中文": "value"}))),
        };
        assert_eq!(
            anchor.canonical_input().unwrap(),
            "anc-u1-001:0:0000000000000000000000000000000000000000000000000000000000000000:\
             agent-u1:envelope_created:AUTO_APPROVED:env-u1:success:2026-01-15T11:00:00+00:00:\
             {\"role\":\"caf\\u00e9\",\"\\u4e2d\\u6587\":\"value\"}"
        );
        assert_eq!(
            anchor.compute_hash().unwrap().as_str(),
            "6946e734daa8279d4dc173918109995e0d10b647a7d3cd0b36aeb4114e8e12c3"
        );
    }

    /// U2 published vector — above-BMP emoji (surrogate-pair escaping).
    #[test]
    fn u2_above_bmp_emoji_matches_published_vector() {
        let anchor = EatpAuditAnchor {
            anchor_id: "anc-u2-001".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent-u2".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: Some("env-u2".into()),
            result: "success".into(),
            timestamp: "2026-01-15T12:00:00+00:00".into(),
            metadata: Some(obj(json!({"celebration": "🎉🚀"}))),
        };
        assert_eq!(
            anchor.canonical_input().unwrap(),
            "anc-u2-001:0:0000000000000000000000000000000000000000000000000000000000000000:\
             agent-u2:envelope_created:AUTO_APPROVED:env-u2:success:2026-01-15T12:00:00+00:00:\
             {\"celebration\":\"\\ud83c\\udf89\\ud83d\\ude80\"}"
        );
        assert_eq!(
            anchor.compute_hash().unwrap().as_str(),
            "4bba3681171049d96f6ba5863ae33dafdfa6bc0d82e26dca5267f21021872427"
        );
    }

    /// `None` metadata omits the segment (and its leading colon).
    #[test]
    fn none_metadata_omits_segment() {
        let anchor = EatpAuditAnchor {
            anchor_id: "anc-v1-001".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent-genesis".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: Some("env-genesis".into()),
            result: "success".into(),
            timestamp: "2026-01-15T10:00:00+00:00".into(),
            metadata: None,
        };
        let input = anchor.canonical_input().unwrap();
        assert!(input.ends_with(":success:2026-01-15T10:00:00+00:00"));
        assert!(!input.ends_with("{}"));
        // Genesis sentinel rendered for None previous_hash.
        assert!(input.contains(&format!(":{}:", Sha256Hex::GENESIS)));
    }

    /// Empty metadata object — Divergence 1 (M2 T2.3, an internal journal entry/0013).
    /// The DEFAULT `canonical_input` is the community (kailash-py) dialect:
    /// empty `{}` omits the segment. This holds in BOTH builds — `canonical_input`
    /// no longer keys on the crate feature (R1 HIGH-1 fix), so the test is
    /// unconditional.
    #[test]
    fn empty_object_metadata_omits_segment() {
        let anchor = EatpAuditAnchor {
            anchor_id: "anc-empty".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent-empty".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: None,
            result: "success".into(),
            timestamp: "2026-01-15T10:00:00+00:00".into(),
            metadata: Some(Map::new()),
        };
        let input = anchor.canonical_input().unwrap();
        assert!(
            !input.contains("{}"),
            "community: empty object must omit the segment, got {input}"
        );
        // Empty envelope_id renders as the empty string between colons; the
        // timestamp is the final (metadata-less) segment.
        assert!(input.ends_with(":AUTO_APPROVED::success:2026-01-15T10:00:00+00:00"));
    }

    /// Empty metadata object — Divergence 1 (M2 T2.3, an internal journal entry/0013).
    /// The explicit enterprise (the enterprise edition) form `canonical_input_kailash_rs`
    /// emits a real `:{}` segment, and it MUST diverge from the absent-metadata
    /// (omitted) form. Enterprise edition only.
    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_empty_object_metadata_emits_colon_braces() {
        let anchor = EatpAuditAnchor {
            anchor_id: "anc-empty".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent-empty".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: None,
            result: "success".into(),
            timestamp: "2026-01-15T10:00:00+00:00".into(),
            metadata: Some(Map::new()),
        };
        let input = anchor.canonical_input_kailash_rs().unwrap();
        assert!(
            input.ends_with(":{}"),
            "enterprise: empty object must emit `:{{}}`, got {input}"
        );
        assert!(input.contains(":AUTO_APPROVED::success:"));
        // The enterprise empty-object `:{}` form MUST differ from the
        // absent-metadata (omitted) form for the identical anchor — the
        // divergence's whole point. `None` omits in BOTH dialects, so the
        // the enterprise edition form of the None-metadata anchor is the omitted form.
        let omitted = EatpAuditAnchor {
            metadata: None,
            ..anchor
        };
        assert_ne!(
            input,
            omitted.canonical_input_kailash_rs().unwrap(),
            "enterprise: empty-object `:{{}}` must diverge from absent-metadata omit"
        );
    }

    /// A continuation anchor renders its real previous_hash (not GENESIS).
    #[test]
    fn continuation_uses_real_previous_hash() {
        let prev =
            Sha256Hex::try_new("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let anchor = EatpAuditAnchor {
            anchor_id: "anc-cont".into(),
            sequence: 1,
            previous_hash: Some(prev),
            agent_id: "agent-cont".into(),
            action: "access_granted".into(),
            verification_level: VerificationLevel::Flagged,
            envelope_id: Some("env-cont".into()),
            result: "success".into(),
            timestamp: "2026-01-15T13:00:00+00:00".into(),
            metadata: None,
        };
        let input = anchor.canonical_input().unwrap();
        assert!(input.starts_with(
            "anc-cont:1:1111111111111111111111111111111111111111111111111111111111111111:"
        ));
        assert!(input.contains(":FLAGGED:"));
    }

    /// Nested objects/arrays in metadata sort keys recursively and stay compact.
    #[test]
    fn nested_metadata_sorts_keys_recursively() {
        let mut out = String::new();
        canonicalize_object(
            &obj(json!({"b": 2, "a": {"d": 4, "c": 3}, "arr": [1, 2, 3]})),
            &mut out,
        );
        assert_eq!(out, "{\"a\":{\"c\":3,\"d\":4},\"arr\":[1,2,3],\"b\":2}");
    }

    /// Control characters use the short escapes; other controls use `\u00XX`.
    #[test]
    fn control_characters_escape_per_python() {
        let mut out = String::new();
        escape_json_ascii("a\tb\nc\r\x00\x1f\"\\", &mut out);
        assert_eq!(out, "\"a\\tb\\nc\\r\\u0000\\u001f\\\"\\\\\"");
    }

    /// Boundary lock around U+007E/U+007F/U+0080. The published U1/U2 vectors do
    /// NOT exercise this boundary; R1 redteam (rust-specialist) questioned the
    /// `> 0x7e` cutoff. Empirically, Python `json.dumps(ensure_ascii=True)`
    /// escapes U+007F (DEL) as `` and passes `~` (U+007E) through literally:
    ///   json.dumps("~\x7f") == '"~\\u007f\\u0080"'
    /// so the encoder's `> 0x7e` cutoff is CORRECT — `~` literal, DEL escaped.
    /// Changing it to `> 0x7f` would WRONGLY pass DEL through. This test pins it.
    #[test]
    fn ascii_escape_boundary_07e_07f_080() {
        let mut out = String::new();
        escape_json_ascii("~\u{7f}\u{80}", &mut out);
        assert_eq!(out, "\"~\\u007f\\u0080\"");
    }

    /// Floats in metadata are rejected fail-closed (load-bearing in release),
    /// at top level AND nested in arrays/objects. R2 deep-analyst finding.
    #[test]
    fn float_metadata_is_rejected_fail_closed() {
        let mk = |meta: Value| EatpAuditAnchor {
            anchor_id: "anc".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: None,
            result: "success".into(),
            timestamp: "2026-01-15T10:00:00+00:00".into(),
            metadata: Some(obj(meta)),
        };
        // Top-level float.
        assert_eq!(
            mk(json!({"ratio": 0.5})).canonical_input(),
            Err(EatpCanonicalError::MetadataContainsFloat)
        );
        // Nested-in-array float.
        assert_eq!(
            mk(json!({"samples": [1, 2, 3.0]})).compute_hash(),
            Err(EatpCanonicalError::MetadataContainsFloat)
        );
        // Nested-in-object float.
        assert_eq!(
            mk(json!({"a": {"b": 1.5}})).canonical_input(),
            Err(EatpCanonicalError::MetadataContainsFloat)
        );
        // Integers are NOT floats — must succeed.
        assert!(mk(json!({"count": 42, "neg": -7})).compute_hash().is_ok());
    }

    /// `Debug` MUST NOT print metadata values (PII forward-guard). It prints the
    /// key count only.
    #[test]
    fn debug_redacts_metadata_values() {
        let anchor = EatpAuditAnchor {
            anchor_id: "anc".into(),
            sequence: 0,
            previous_hash: None,
            agent_id: "agent".into(),
            action: "envelope_created".into(),
            verification_level: VerificationLevel::AutoApproved,
            envelope_id: None,
            result: "success".into(),
            timestamp: "2026-01-15T10:00:00+00:00".into(),
            metadata: Some(obj(json!({"ssn": "123-45-6789", "name": "secret"}))),
        };
        let dbg = format!("{anchor:?}");
        assert!(dbg.contains("<redacted 2 keys>"), "got: {dbg}");
        assert!(!dbg.contains("123-45-6789"), "PII leaked in Debug: {dbg}");
        assert!(!dbg.contains("secret"), "PII leaked in Debug: {dbg}");
    }

    #[test]
    fn verification_level_round_trips() {
        for lvl in [
            VerificationLevel::AutoApproved,
            VerificationLevel::Flagged,
            VerificationLevel::Held,
            VerificationLevel::Blocked,
        ] {
            assert_eq!(
                VerificationLevel::from_canonical_str(lvl.as_canonical_str()),
                Some(lvl)
            );
        }
    }

    /// Community structural guard (M2 T2.3, an internal journal entry/0013): the community
    /// 4-level parser `from_canonical_str` rejects the two the enterprise edition levels.
    /// This is edition-STABLE — it holds even in a feature-unified `enterprise`
    /// build (the R1 HIGH-1 fix moved the community parser off the crate-feature
    /// cfg), so the test is unconditional. It pins that the community engine's
    /// level acceptance cannot drift to 6-level under feature unification.
    #[test]
    fn community_verification_level_is_four_levels() {
        assert_eq!(VerificationLevel::from_canonical_str("PEER_REVIEWED"), None);
        assert_eq!(
            VerificationLevel::from_canonical_str("SIGNED_ATTESTATION"),
            None
        );
    }

    /// Enterprise: the two the enterprise edition levels round-trip through the EXPLICIT
    /// enterprise parser `from_canonical_str_kailash_rs` (the community
    /// `from_canonical_str` rejects them — see above).
    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_verification_level_adds_two_kailash_rs_levels() {
        for lvl in [
            VerificationLevel::PeerReviewed,
            VerificationLevel::SignedAttestation,
        ] {
            assert_eq!(
                VerificationLevel::from_canonical_str_kailash_rs(lvl.as_canonical_str()),
                Some(lvl)
            );
            // The community parser MUST reject them — edition-stable.
            assert_eq!(
                VerificationLevel::from_canonical_str(lvl.as_canonical_str()),
                None
            );
        }
        assert_eq!(
            VerificationLevel::PeerReviewed.as_canonical_str(),
            "PEER_REVIEWED"
        );
        assert_eq!(
            VerificationLevel::SignedAttestation.as_canonical_str(),
            "SIGNED_ATTESTATION"
        );
    }
}
