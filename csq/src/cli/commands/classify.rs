//! `csq classify` — pure classifier path for harness fixture scoring
//! (PR-CA7d1, spec 10 §10.7.4 auditability).
//!
//! Loads the active `.coc/` set, builds the keyword index for the
//! requested Surface, runs the classifier against the supplied prompt,
//! and emits a JSON record on stdout. No CC / codex / gemini spawn,
//! no API call. The harness suite at `coc-eval/suites/classifier.py`
//! invokes this for every fixture to score precision/recall against
//! expected labels.
//!
//! Output shape (deterministic):
//!
//! ```json
//! {
//!   "ok": true,
//!   "surface": "claude-code",
//!   "class": "compliance",
//!   "confidence": 0.4286,
//!   "threshold": 0.15,
//!   "low_confidence": false,
//!   "keyword_count": 3,
//!   "in_scope_rule_ids": ["RULE-NO-PII"]
//! }
//! ```
//!
//! `low_confidence` is `true` iff the classifier returned the
//! `ClassifierLowConfidence` tagged-success (spec 10 §10.7.2). The
//! `class` value is the post-fail-secure verdict (always `compliance`
//! when low-confidence; harness scores against this resolved class).

use std::path::PathBuf;

use anyhow::{Context, Result};
use csq_core::capability_layer::errors::CLASSIFIER_THRESHOLD;
use csq_core::capability_layer::{
    build_keyword_index, extract_rule_ids_in_scope, ClassifierInputs, ClassifierStage,
    PipelineStage, PromptClass, PromptClassKind, StageError, UserPrompt,
};
use csq_core::providers::catalog::Surface;

#[derive(Default)]
pub struct ClassifyOptions {
    /// Prompt text to classify.
    pub prompt: String,
    /// Surface to filter the keyword index by (`claude-code`, `codex`,
    /// `gemini`). Different surfaces may produce different
    /// keyword sets because in-scope rules are filtered by the rule's
    /// `applies_to` set (same filter the scaffold + classifier driver
    /// use). Ignored when `keywords` is supplied — the explicit
    /// keyword set is already filter-resolved.
    pub surface: String,
    /// `--start <path>` — start the discovery walk from `<path>`
    /// instead of CWD. For tests + CI fixtures. Ignored when
    /// `keywords` is supplied.
    pub start: Option<PathBuf>,
    /// `--keywords <COMMA_LIST>` — explicit keyword set, bypasses
    /// `.coc/` loading entirely. Used by the PR-CA7d2 classifier
    /// benchmark suite at `coc-eval/suites/classifier.py`: the harness
    /// supplies a known compliance vocabulary so fixture scoring is
    /// orthogonal to `.coc/` content. Each comma-separated token is
    /// lowercased and inserted verbatim — the harness is responsible
    /// for matching the tokenizer's contract (length ≥ 3, no `rule`
    /// prefix).
    pub keywords: Option<String>,
}

pub fn handle(base_dir: &std::path::Path, opts: ClassifyOptions) -> Result<()> {
    let surface = match opts.surface.as_str() {
        "claude-code" | "cc" => Surface::ClaudeCode,
        "codex" => Surface::Codex,
        "gemini" => Surface::Gemini,
        other => anyhow::bail!("unknown surface `{other}`"),
    };

    // Two paths: explicit `--keywords` (PR-CA7d2 benchmark surface) or
    // `.coc/` loading (production / inspect parity). The `--keywords`
    // path skips project walk entirely — the harness owns the keyword
    // set and `in_scope_rule_ids` is empty by construction.
    let (keywords, in_scope_rule_ids) = if let Some(raw) = opts.keywords.as_deref() {
        (parse_explicit_keywords(raw), Vec::new())
    } else {
        let start = opts
            .start
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .context("could not resolve starting directory for `csq classify`")?;

        let outcome = csq_core::coc::load(&start, base_dir)
            .context("loading `.coc/` set for classification")?;

        let kw = build_keyword_index(&outcome.set, surface);
        let ids = extract_rule_ids_in_scope(&outcome.set, surface)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        (kw, ids)
    };

    let mut class = PromptClass::PR_CA4_DEFAULT;
    let inputs = ClassifierInputs {
        prompt: UserPrompt {
            text: opts.prompt.clone(),
        },
        keywords: keywords.clone(),
    };
    let low_confidence = match ClassifierStage::run(inputs, &mut class) {
        Ok(()) => false,
        Err(StageError::ClassifierLowConfidence { .. }) => true,
        Err(other) => anyhow::bail!("classifier stage error: {other}"),
    };

    let class_str = match class.class {
        PromptClassKind::Compliance => "compliance",
        PromptClassKind::FreeForm => "freeform",
    };

    let payload = serde_json::json!({
        "ok": true,
        "surface": surface_str(surface),
        "class": class_str,
        "confidence": round4(class.conf),
        "threshold": round4(CLASSIFIER_THRESHOLD),
        "low_confidence": low_confidence,
        "keyword_count": keywords.len(),
        "in_scope_rule_ids": in_scope_rule_ids,
    });
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

/// Parse a comma-separated keyword list into the `BTreeSet<String>`
/// the classifier consumes. Tokens are trimmed + lowercased + filtered
/// for empty values. Mirrors the tokenizer's lowercase contract; the
/// harness is responsible for length-3 + `rule`-prefix filtering since
/// the explicit-keywords path skips `build_keyword_index` (which is
/// where those filters normally apply for `.coc/`-loaded inputs).
fn parse_explicit_keywords(raw: &str) -> std::collections::BTreeSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn surface_str(s: Surface) -> &'static str {
    match s {
        Surface::ClaudeCode => "claude-code",
        Surface::Codex => "codex",
        Surface::Gemini => "gemini",
    }
}

/// Round a `f32` to 4 decimal places for stable JSON output. The
/// classifier is deterministic, but `serde_json` serializes `f32` with
/// full precision, which leaks platform-rounding noise into harness
/// fixture diffs. 4 places is well below the 0.15 threshold and well
/// above the precision the harness needs to score precision/recall.
fn round4(x: f32) -> f64 {
    let scaled = (x as f64 * 10_000.0).round();
    scaled / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn surface_str_maps_all_three_surfaces() {
        assert_eq!(surface_str(Surface::ClaudeCode), "claude-code");
        assert_eq!(surface_str(Surface::Codex), "codex");
        assert_eq!(surface_str(Surface::Gemini), "gemini");
    }

    #[test]
    fn round4_truncates_to_four_decimals() {
        assert!((round4(0.142857_f32) - 0.1429).abs() < 1e-9);
        assert!((round4(0.0_f32) - 0.0).abs() < 1e-9);
        assert!((round4(1.0_f32) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn unknown_surface_errors() {
        let dir = TempDir::new().unwrap();
        let opts = ClassifyOptions {
            prompt: "x".into(),
            surface: "bogus".into(),
            start: Some(dir.path().to_path_buf()),
            keywords: None,
        };
        let err = handle(dir.path(), opts).unwrap_err();
        assert!(err.to_string().contains("unknown surface"), "got: {err}");
    }

    #[test]
    fn parse_explicit_keywords_lowercases_trims_drops_empty() {
        let kw = parse_explicit_keywords(" PII , Auth, , secret ,, ");
        assert!(kw.contains("pii"));
        assert!(kw.contains("auth"));
        assert!(kw.contains("secret"));
        assert_eq!(kw.len(), 3, "empty tokens must be dropped: {kw:?}");
    }

    #[test]
    fn parse_explicit_keywords_empty_string_returns_empty_set() {
        let kw = parse_explicit_keywords("");
        assert!(kw.is_empty());
    }

    // Note: the CA7d2 harness suite at `coc-eval/suites/classifier.py`
    // is the system-level coverage for the loaded-`.coc/` path and runs
    // the binary against 100 fixtures.

    #[test]
    fn empty_coc_returns_zero_conf_compliance_via_failsecure() {
        // No `.coc/` directory anywhere → CocSet::Empty → keyword
        // index empty → classifier returns conf 0.0 → fail-secure
        // routes to Compliance. The handler must NOT error.
        let dir = TempDir::new().unwrap();
        let outcome = csq_core::coc::load(dir.path(), dir.path()).expect("load empty .coc/");
        let kw = build_keyword_index(&outcome.set, Surface::ClaudeCode);
        assert!(kw.is_empty(), "empty .coc/ → empty keyword index");
        let mut class = PromptClass::PR_CA4_DEFAULT;
        let res = ClassifierStage::run(
            ClassifierInputs {
                prompt: UserPrompt {
                    text: "anything goes here".into(),
                },
                keywords: kw,
            },
            &mut class,
        );
        // Tagged-success: low-confidence but class set to Compliance.
        match res {
            Err(StageError::ClassifierLowConfidence { conf, threshold }) => {
                assert_eq!(threshold, CLASSIFIER_THRESHOLD);
                assert_eq!(conf, 0.0);
            }
            other => panic!("expected low-conf, got {other:?}"),
        }
        assert_eq!(class.class, PromptClassKind::Compliance);
    }
}
