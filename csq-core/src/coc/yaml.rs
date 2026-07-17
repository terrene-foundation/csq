//! Minimal YAML frontmatter parser scoped to csq's known fields.
//!
//! Per spec 09 §9.2, csq reads only:
//! - `id` (string)
//! - `coc.version` (string semver — also at COC.md level)
//! - `paths` (string array, glob)
//! - `coc.disable` (string array, technique opt-out)
//! - `applies_to` (string array, surface allowlist)
//! - `precedence` (integer)
//!
//! Unknown fields are tolerated (forward-compat per §9.2.3) and surfaced
//! via `csq inspect coc --show-unknowns`. We capture them as raw strings.
//!
//! This parser is intentionally a SUBSET of YAML 1.2:
//!
//! - Frontmatter is delimited by `---` lines (open + close).
//! - Each non-empty, non-comment line is `key: value` at column 0.
//! - Values are scalars (strings, optionally quoted), inline-flow arrays
//!   (`[a, b, c]`), OR a following block sequence (`key:` then indented
//!   `- item` lines) — the block form maps to the same [`YamlValue::Array`].
//! - No anchors. Block-scalar / nested-mapping continuation lines under a key
//!   are TOLERATED (consumed, never a parse failure) per spec 09 §9.2.3, but
//!   only block SEQUENCES are captured as a list value.
//!
//! Loom's emit uses this subset; the block-sequence tolerance (an internal ticket)
//! exists because §9.2.3 requires csq to accept unknown/forward-compat
//! frontmatter fields — including block-list-valued ones — WITHOUT a parse
//! failure. Richer YAML in the artifact body (after the `---`) is NOT csq's
//! concern (csq treats it as opaque text).

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontmatter {
    pub fields: BTreeMap<String, YamlValue>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YamlValue {
    Scalar(String),
    Array(Vec<String>),
}

impl YamlValue {
    pub fn as_scalar(&self) -> Option<&str> {
        match self {
            YamlValue::Scalar(s) => Some(s.as_str()),
            YamlValue::Array(_) => None,
        }
    }

    pub fn as_array(&self) -> Option<&[String]> {
        match self {
            YamlValue::Scalar(_) => None,
            YamlValue::Array(items) => Some(items.as_slice()),
        }
    }

    /// Render the value as a raw display string for the unknowns bucket.
    pub fn render_raw(&self) -> String {
        match self {
            YamlValue::Scalar(s) => s.clone(),
            YamlValue::Array(items) => format!("[{}]", items.join(", ")),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum YamlError {
    #[error("missing frontmatter `---` opener")]
    MissingOpener,
    #[error("missing frontmatter `---` closer")]
    MissingCloser,
    #[error("malformed line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("duplicate key `{key}` at line {line}")]
    DuplicateKey { key: String, line: usize },
}

/// Parse a Markdown file with YAML frontmatter. Returns the parsed
/// frontmatter and the body (everything after the closing `---`).
///
/// If `input` does not start with `---\n` (or `---\r\n`), this is treated
/// as an artifact without frontmatter — `Frontmatter::fields` will be empty
/// and `body` will be the whole input. This matches loom's expected emit
/// where `COC.md` MAY have a frontmatter block.
pub fn parse(input: &str) -> Result<Frontmatter, YamlError> {
    let mut lines = input.lines().enumerate().peekable();

    // Look for the opening `---` line.
    let first = lines.next();
    let has_opener = matches!(first, Some((_, "---")));
    if !has_opener {
        return Ok(Frontmatter {
            fields: BTreeMap::new(),
            body: input.to_string(),
        });
    }

    let mut fields: BTreeMap<String, YamlValue> = BTreeMap::new();
    let mut body_start: Option<usize> = None;

    while let Some((idx, line)) = lines.next() {
        if line == "---" {
            // Closer; body starts on the NEXT line.
            body_start = Some(idx + 1);
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Indented continuation lines (block-sequence items `- x`, nested
        // mappings) belong to the PREVIOUS top-level key — a bare one at
        // column 0 with no owning key is unexpected. If we reach one here it
        // means a top-level key had a non-empty inline value AND an indented
        // block followed; skip the orphan continuation (tolerated per §9.2.3,
        // never a parse failure). See the block-collection below for the
        // normal `key:`-then-block path.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let (key, mut value) = parse_kv_line(line, idx)?;
        // Block sequence (#58, spec 09 §9.2.3): a top-level `key:` with an empty
        // inline value MAY be followed by indented `- item` lines — csq's known
        // list fields (`paths`/`coc.disable`/`applies_to`) and unknown fields
        // alike. Collect them into an Array so csq TOLERATES the shape instead of
        // mis-parsing `- item` as a new key (`invalid key character in - item`).
        // Scalar items are unquoted; mapping items (`- matcher: X`) are captured
        // as raw strings (csq reads no such field semantically).
        if matches!(&value, YamlValue::Scalar(s) if s.is_empty()) {
            let mut items: Vec<String> = Vec::new();
            while let Some((_, next)) = lines.peek() {
                if !next.starts_with(char::is_whitespace) && !next.is_empty() {
                    break; // next top-level key or the `---` closer
                }
                let t = next.trim();
                if t.is_empty() {
                    lines.next(); // blank line inside the block
                    continue;
                }
                if let Some(item) = t.strip_prefix("- ") {
                    let it = item.trim();
                    let it = it
                        .strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .or_else(|| it.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                        .unwrap_or(it);
                    items.push(it.to_string());
                    lines.next();
                } else {
                    // Indented non-sequence continuation (nested mapping / block
                    // scalar) — tolerated, consumed, not captured as a list item.
                    lines.next();
                }
            }
            if !items.is_empty() {
                value = YamlValue::Array(items);
            }
        }
        if fields.contains_key(&key) {
            return Err(YamlError::DuplicateKey { key, line: idx });
        }
        fields.insert(key, value);
    }

    let body_start = body_start.ok_or(YamlError::MissingCloser)?;

    // Reconstruct the body by joining the lines from `body_start` onward.
    // We use a fresh iteration over `input.lines()` to preserve original
    // newline-stripped text accurately.
    let body = input
        .lines()
        .skip(body_start)
        .collect::<Vec<_>>()
        .join("\n");

    Ok(Frontmatter { fields, body })
}

fn parse_kv_line(line: &str, idx: usize) -> Result<(String, YamlValue), YamlError> {
    let colon = line.find(':').ok_or_else(|| YamlError::Malformed {
        line: idx,
        reason: "expected `key: value`".into(),
    })?;
    let (key_raw, rest) = line.split_at(colon);
    let key = key_raw.trim();
    if key.is_empty() {
        return Err(YamlError::Malformed {
            line: idx,
            reason: "empty key".into(),
        });
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(YamlError::Malformed {
            line: idx,
            reason: format!("invalid key character in `{key}`"),
        });
    }
    let raw_value = rest.strip_prefix(':').unwrap_or(rest).trim();
    let value = parse_value(raw_value, idx)?;
    Ok((key.to_string(), value))
}

fn parse_value(raw: &str, idx: usize) -> Result<YamlValue, YamlError> {
    if raw.is_empty() {
        return Ok(YamlValue::Scalar(String::new()));
    }
    if raw.starts_with('[') {
        if !raw.ends_with(']') {
            return Err(YamlError::Malformed {
                line: idx,
                reason: "inline array missing closing `]`".into(),
            });
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.trim().is_empty() {
            return Ok(YamlValue::Array(Vec::new()));
        }
        let items = inner
            .split(',')
            .map(|item| strip_optional_quotes(item.trim()).to_string())
            .collect::<Vec<_>>();
        Ok(YamlValue::Array(items))
    } else {
        Ok(YamlValue::Scalar(strip_optional_quotes(raw).to_string()))
    }
}

fn strip_optional_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return &s[1..s.len() - 1];
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_frontmatter() {
        let input = "---\nid: RULE-X\ncoc.version: 1.0.0\n---\nbody text";
        let fm = parse(input).unwrap();
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
        assert_eq!(
            fm.fields.get("coc.version").unwrap().as_scalar(),
            Some("1.0.0")
        );
        assert_eq!(fm.body, "body text");
    }

    #[test]
    fn parses_array_value() {
        let input = "---\nid: RULE-X\npaths: [src/**, lib/**]\n---\n";
        let fm = parse(input).unwrap();
        let paths = fm.fields.get("paths").unwrap().as_array().unwrap();
        assert_eq!(paths, &["src/**", "lib/**"]);
    }

    // #58: a known list field emitted as a YAML BLOCK sequence (not inline flow)
    // must parse to the same Array, not crash.
    #[test]
    fn parses_block_sequence_for_known_list_field() {
        let input = "---\nid: RULE-X\npaths:\n  - src/**\n  - \"lib/**\"\n---\nbody";
        let fm = parse(input).unwrap();
        let paths = fm.fields.get("paths").unwrap().as_array().unwrap();
        assert_eq!(paths, &["src/**", "lib/**"]);
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
        assert_eq!(fm.body, "body");
    }

    // #58 (the reported case): a block sequence of MAPPINGS (`- matcher: X`) under
    // an unknown field must be TOLERATED (§9.2.3 — no parse failure, captured), not
    // yield `invalid key character in \`- matcher\``.
    #[test]
    fn tolerates_block_sequence_of_mappings_unknown_field() {
        let input = "---\nid: RULE-X\nhooks:\n  - matcher: Bash\n  - matcher: Edit\n---\nbody";
        let fm = parse(input).expect("block-sequence-of-mappings must not fail to parse");
        // Known scalar field still read.
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
        // Unknown field captured (surfaced via --show-unknowns), not dropped.
        let hooks = fm.fields.get("hooks").unwrap().as_array().unwrap();
        assert_eq!(hooks, &["matcher: Bash", "matcher: Edit"]);
    }

    // #58 edge: a bare `key:` immediately before the `---` closer (no block, no
    // value) is a legal empty-scalar field; block collection breaks on `---`.
    #[test]
    fn bare_key_before_closer_is_empty_scalar() {
        let input = "---\nid: RULE-X\nfuture:\n---\nbody";
        let fm = parse(input).unwrap();
        assert_eq!(fm.fields.get("future").unwrap().as_scalar(), Some(""));
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
        assert_eq!(fm.body, "body");
    }

    // A `key:` followed by a nested mapping (not a sequence) is tolerated: the key
    // is captured with an empty value, the indented lines are consumed, no crash.
    #[test]
    fn tolerates_nested_mapping_continuation() {
        let input = "---\nid: RULE-X\nmeta:\n  author: jack\n  team: core\ndesc: ok\n---\n";
        let fm = parse(input).unwrap();
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
        assert_eq!(fm.fields.get("desc").unwrap().as_scalar(), Some("ok"));
        // `meta` captured (empty scalar — nested map not a list), never a failure.
        assert!(fm.fields.contains_key("meta"));
    }

    #[test]
    fn parses_quoted_strings() {
        let input = "---\nid: \"RULE-X\"\ndesc: 'hello'\n---\n";
        let fm = parse(input).unwrap();
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
        assert_eq!(fm.fields.get("desc").unwrap().as_scalar(), Some("hello"));
    }

    #[test]
    fn empty_array() {
        let input = "---\nid: RULE-X\npaths: []\n---\n";
        let fm = parse(input).unwrap();
        assert_eq!(fm.fields.get("paths").unwrap().as_array(), Some(&[][..]));
    }

    #[test]
    fn no_frontmatter_returns_whole_body() {
        let input = "no frontmatter here\nsecond line";
        let fm = parse(input).unwrap();
        assert!(fm.fields.is_empty());
        assert_eq!(fm.body, input);
    }

    #[test]
    fn missing_closer_errors() {
        // No closing `---`. The iterator exhausts after parsing valid kv
        // lines, so we surface MissingCloser rather than Malformed.
        let input = "---\nid: RULE-X\ncoc.version: 1.0.0";
        match parse(input) {
            Err(YamlError::MissingCloser) => (),
            other => panic!("expected MissingCloser, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_key_errors() {
        let input = "---\nid: RULE-X\nid: RULE-Y\n---\n";
        match parse(input) {
            Err(YamlError::DuplicateKey { key, .. }) => assert_eq!(key, "id"),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let input =
            "---\n# leading comment\nid: RULE-X\n\n# blank above\ncoc.version: 1.0.0\n---\nbody";
        let fm = parse(input).unwrap();
        assert_eq!(fm.fields.get("id").unwrap().as_scalar(), Some("RULE-X"));
    }

    #[test]
    fn unknown_fields_preserved() {
        let input = "---\nid: RULE-X\nfuture_thing: yes\n---\n";
        let fm = parse(input).unwrap();
        assert_eq!(
            fm.fields.get("future_thing").unwrap().as_scalar(),
            Some("yes")
        );
    }

    #[test]
    fn render_raw_array() {
        let v = YamlValue::Array(vec!["a".into(), "b".into()]);
        assert_eq!(v.render_raw(), "[a, b]");
    }

    #[test]
    fn integer_value_round_trips_as_scalar() {
        let input = "---\nprecedence: 5\n---\n";
        let fm = parse(input).unwrap();
        // integers round-trip as scalars; downstream parses with i32::from_str.
        assert_eq!(fm.fields.get("precedence").unwrap().as_scalar(), Some("5"));
    }

    #[test]
    fn malformed_line_no_colon_errors() {
        let input = "---\nno-colon-here\n---\n";
        match parse(input) {
            Err(YamlError::Malformed { .. }) => (),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }
}
