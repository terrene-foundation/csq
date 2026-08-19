//! Prompt classifier (FR-CL-classifier; spec 10 §10.7).
//!
//! Routes user prompts to `PromptClassKind::Compliance` or
//! `::FreeForm` so downstream stages know whether RULE_ID-citation
//! enforcement and structured-output validation should apply.
//!
//! # Mechanism (spec 10 §10.7.1 FROZEN; §10.7.0 deviation acknowledged)
//!
//! Deterministic keyword heuristic over the active `.coc/` artifact's
//! compliance vocabulary:
//!
//! 1. The driver pre-builds a keyword index from RULE_ID name tokens
//!    of in-scope rules (rules whose `applies_to` is empty (universal)
//!    or contains the target `Surface`). Rule body text is **not**
//!    indexed at PR-CA7a — see spec 10 §10.7.0 for the deferral note.
//! 2. The classifier tokenizes the user's prompt (lowercase, split
//!    on non-alphanumeric, filter tokens shorter than 3 chars).
//! 3. Confidence = `hits / token_count` (with vocabulary_density_factor
//!    defaulting to 1.0 per spec 10 §10.7.0).
//! 4. Confidence ≥ [`crate::capability_layer::errors::CLASSIFIER_THRESHOLD`]
//!    yields `Class::Compliance`; below yields a "tagged success"
//!    `StageError::ClassifierLowConfidence` AND populates the output
//!    with the fail-secure `Compliance` default per spec 10 §10.7.2.
//!
//! # Why no ML or opaque scoring
//!
//! Spec 10 §10.7.4 + A4 mitigation require the classifier output be
//! reproducible from `(prompt, .coc/ content)` alone — auditable
//! offline by anyone with the same fixtures. Keyword heuristic is
//! the simplest mechanism that meets that constraint. PR-CA7d adds
//! `--debug` surfacing of the per-turn classifier verdict.
//!
//! # PR-CA7a ship state
//!
//! Classifier types + PipelineStage impl + driver wiring. The
//! precision/recall harness metric (spec 10 §10.7.3 — ≥ 0.9 / ≥ 0.85)
//! lands in a follow-up PR alongside the fixture suite at
//! `coc-eval/suites/classifier.py`. The contract here is "deterministic,
//! fail-secure, observable" — quantitative quality is gated by the
//! harness fixture set, not by this module.

use std::collections::BTreeSet;

use crate::capability_layer::errors::{StageError, CLASSIFIER_THRESHOLD};
use crate::capability_layer::pipeline::PipelineStage;
use crate::capability_layer::state::{PromptClass, PromptClassKind, UserPrompt};
use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

/// Stable stage tag for structured-log events and audit-decision
/// attribution.
pub const STAGE: &str = "classifier";

/// Inputs to the classifier stage. Owned (`UserPrompt` + a precomputed
/// `BTreeSet<String>` of compliance keywords) so the classifier doesn't
/// need to own the parent `CocSet` — the driver builds the index once
/// and hands ownership to the classifier, leaving `CocSet` available
/// for downstream scaffold/translate work.
#[derive(Debug, Clone)]
pub struct ClassifierInputs {
    pub prompt: UserPrompt,
    pub keywords: BTreeSet<String>,
}

/// Build the per-`.coc/` keyword index. Pure function; called by the
/// driver before the classifier runs. Reuses RULE_ID name tokens
/// (split on `-`, length ≥ 3, lowercased, with the literal `rule`
/// stripped because it's a constant prefix in every rule id).
///
/// Filters by `Surface` via the SAME shared predicate the scaffold +
/// translator flatten uses (`crate::coc::translate::flatten::in_scope` —
/// universal rules, rules whose `applies_to` contains the target `Surface`,
/// and — for Kimi/Grok — rules scoped `applies_to: [codex]`, since Kimi/Grok
/// share the Codex capability-layer scope, not just its header; an internal journal entry).
/// Rule body text is not indexed at PR-CA7a (see spec 10 §10.7.0).
///
/// This used to carry its OWN inline copy of the surface-scope check
/// (`applies_to.is_empty() || applies_to.contains(&surface)`) rather than
/// calling `flatten::in_scope` — the exact duplication `flatten::in_scope`'s
/// own doc comment says must not happen ("THE single surface-scope
/// predicate... cannot drift"). It had already drifted: the inline copy
/// lacked the Kimi/Grok→Codex fallback, so the classifier's keyword index
/// (and therefore Compliance-vs-FreeForm prompt classification) silently
/// used a narrower rule set than the scaffold/citation set for a live
/// Kimi/Grok session. Routing through the shared predicate closes both the
/// duplication and the drift in one fix.
pub fn build_keyword_index(coc_set: &CocSet, surface: Surface) -> BTreeSet<String> {
    let mut keywords = BTreeSet::new();
    for (rule_id, rule) in &coc_set.rules {
        if !crate::coc::translate::flatten::in_scope(&rule.applies_to, surface) {
            continue;
        }
        for token in rule_id.as_str().split('-') {
            let lc = token.to_ascii_lowercase();
            if lc.len() < 3 {
                continue;
            }
            // The literal `rule` prefix is a noise token because
            // every RULE_ID begins with it by convention; including
            // it would inflate hit counts for any prompt that contains
            // the word "rule" regardless of compliance content.
            if lc == "rule" {
                continue;
            }
            keywords.insert(lc);
        }
    }
    keywords
}

/// Marker type for the classifier stage.
pub struct ClassifierStage;

impl PipelineStage for ClassifierStage {
    type Reads = ClassifierInputs;
    type Writes = PromptClass;

    fn run(input: Self::Reads, output: &mut Self::Writes) -> Result<(), StageError> {
        let (class, conf) = classify(&input.prompt, &input.keywords);
        // Spec 10 §10.7.2 fail-secure: ALWAYS write the result, even on
        // the low-confidence path. The output is populated before any
        // tagged-success error is returned, so the driver's
        // continuation logic sees the right class either way.
        *output = PromptClass { class, conf };
        if conf < CLASSIFIER_THRESHOLD {
            // Tagged success — driver catches and continues.
            return Err(StageError::ClassifierLowConfidence {
                conf,
                threshold: CLASSIFIER_THRESHOLD,
            });
        }
        Ok(())
    }
}

/// Pure classification function. Returns `(class, confidence)` where
/// confidence is in `[0.0, 1.0]`. Same input always produces the
/// same output (spec 10 §10.3.5 determinism by construction —
/// `BTreeSet` iteration is sorted, prompt tokenization is sequential).
///
/// Edge cases:
/// - Empty prompt: 0 tokens → confidence 0.0 → fail-secure Compliance.
/// - Empty keyword index: any prompt → 0 hits → confidence 0.0 →
///   fail-secure Compliance. Matches the "absent `.coc/` policy ⇒
///   safest default" intuition.
fn classify(prompt: &UserPrompt, keywords: &BTreeSet<String>) -> (PromptClassKind, f32) {
    let tokens = tokenize_prompt(&prompt.text);
    if tokens.is_empty() {
        return (PromptClassKind::Compliance, 0.0);
    }
    let mut hits = 0u32;
    for token in &tokens {
        if keywords.contains(token) {
            hits += 1;
        }
    }
    let conf = (hits as f32) / (tokens.len() as f32);
    let class = if conf >= CLASSIFIER_THRESHOLD {
        PromptClassKind::Compliance
    } else {
        // Spec 10 §10.7.2 fail-secure default — misclassified
        // compliance is the worse failure mode (RULE_ID citation
        // skipped), so confidence below threshold still routes to
        // Compliance. The driver records the low-conf signal via
        // `StageError::ClassifierLowConfidence`.
        PromptClassKind::Compliance
    };
    (class, conf)
}

/// Tokenize a prompt for keyword matching. Stable across runs: same
/// input always produces the same `Vec<String>`.
///
/// Rules:
/// - Lowercase ASCII (non-ASCII letters pass through `to_ascii_lowercase`
///   unchanged; that's fine — keyword index is also lowercase ASCII).
/// - Split on any non-alphanumeric byte (`split` on a closure).
/// - Drop tokens shorter than 3 chars (filters out "do", "of", "to",
///   "is", etc. without a stopword list).
fn tokenize_prompt(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(|t| t.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::types::{RuleDef, RuleId};
    use std::collections::{BTreeMap, BTreeSet};

    fn rule(id: &str, body: &str, applies: &[Surface]) -> (RuleId, RuleDef) {
        let id = RuleId::parse(id).unwrap();
        let mut applies_to = BTreeSet::new();
        for s in applies {
            applies_to.insert(*s);
        }
        let def = RuleDef {
            id: id.clone(),
            paths: Vec::new(),
            applies_to,
            precedence: 0,
            disable: BTreeSet::new(),
            body: body.to_string(),
            unknowns: BTreeMap::new(),
        };
        (id, def)
    }

    fn coc_set(rules: Vec<(RuleId, RuleDef)>) -> CocSet {
        let mut set = CocSet::empty();
        for (id, def) in rules {
            set.rules.insert(id, def);
        }
        set
    }

    #[test]
    fn build_keyword_index_extracts_rule_id_terms_minus_rule_prefix() {
        let set = coc_set(vec![rule("RULE-NO-PII", "Do not echo PII.", &[])]);
        let kw = build_keyword_index(&set, Surface::ClaudeCode);
        // "rule" filtered as constant prefix; "no" filtered as < 3
        // chars; "pii" kept.
        assert!(kw.contains("pii"), "expected `pii` in {kw:?}");
        assert!(!kw.contains("rule"), "constant prefix must be filtered");
        assert!(!kw.contains("no"), "tokens < 3 chars must be filtered");
    }

    #[test]
    fn build_keyword_index_filters_by_surface() {
        let set = coc_set(vec![
            rule("RULE-CC-AUTH", "cc-only", &[Surface::ClaudeCode]),
            rule("RULE-CDX-LOG", "codex-only", &[Surface::Codex]),
        ]);
        let kw_cc = build_keyword_index(&set, Surface::ClaudeCode);
        let kw_cdx = build_keyword_index(&set, Surface::Codex);
        assert!(kw_cc.contains("auth"));
        assert!(!kw_cc.contains("log") || !kw_cc.contains("cdx"));
        assert!(kw_cdx.contains("log"));
        assert!(!kw_cdx.contains("auth"));
    }

    /// `build_keyword_index` now routes through the shared
    /// `flatten::in_scope` predicate — a codex-scoped rule MUST contribute
    /// keywords for Kimi/Grok exactly like it does for Codex (an internal journal entry;
    /// the Kimi/Grok→Codex `applies_to` fallback lives in `in_scope`). Before
    /// the de-duplication this returned an empty set for Kimi/Grok because
    /// the inline copy never had the fallback clause.
    #[test]
    fn build_keyword_index_kimi_grok_share_codex_scope() {
        let set = coc_set(vec![
            rule("RULE-CDX-LOG", "codex-only", &[Surface::Codex]),
            rule("RULE-CC-AUTH", "cc-only", &[Surface::ClaudeCode]),
        ]);
        for surface in [Surface::Kimi, Surface::Grok] {
            let kw = build_keyword_index(&set, surface);
            assert!(
                kw.contains("log"),
                "{surface} must see codex-scoped `log`, got {kw:?}"
            );
            assert!(
                !kw.contains("auth"),
                "{surface} must NOT see cc-only `auth`, got {kw:?}"
            );
        }
    }

    #[test]
    fn classify_high_density_compliance_returns_compliance_above_threshold() {
        // Prompt is 6 tokens (after filter): pii, pii, exposed, our,
        // logs, please. Wait, "our" is 3 chars, kept. "pii" appears
        // twice. With keywords = {pii}, hits = 2, conf = 2/6 = 0.33,
        // which is above the 0.15 threshold.
        let kw = BTreeSet::from(["pii".to_string()]);
        let (class, conf) = classify(
            &UserPrompt {
                text: "Is PII exposed in our PII logs please?".into(),
            },
            &kw,
        );
        assert_eq!(class, PromptClassKind::Compliance);
        assert!(
            conf >= CLASSIFIER_THRESHOLD,
            "conf {conf} must clear threshold {CLASSIFIER_THRESHOLD}"
        );
    }

    #[test]
    fn classify_low_density_returns_compliance_with_low_conf_failsecure() {
        // Long prompt, single keyword hit. Confidence below threshold.
        // Spec 10 §10.7.2: low-confidence still routes to Compliance.
        let kw = BTreeSet::from(["pii".to_string()]);
        let prompt = UserPrompt {
            text: "Tell me a joke about cats and dogs and birds and \
                   PII and houses and cars."
                .into(),
        };
        let (class, conf) = classify(&prompt, &kw);
        assert_eq!(
            class,
            PromptClassKind::Compliance,
            "fail-secure: low-conf still routes to Compliance"
        );
        assert!(
            conf < CLASSIFIER_THRESHOLD,
            "conf {conf} must be below threshold {CLASSIFIER_THRESHOLD}"
        );
    }

    #[test]
    fn classify_empty_prompt_returns_zero_conf_compliance() {
        let kw = BTreeSet::from(["pii".to_string()]);
        let (class, conf) = classify(
            &UserPrompt {
                text: String::new(),
            },
            &kw,
        );
        assert_eq!(class, PromptClassKind::Compliance);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn classify_empty_keyword_index_returns_zero_conf_compliance() {
        let kw = BTreeSet::new();
        let (class, conf) = classify(
            &UserPrompt {
                text: "Anything about PII or auth or logs".into(),
            },
            &kw,
        );
        assert_eq!(class, PromptClassKind::Compliance);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn stage_high_conf_returns_ok_and_writes_compliance() {
        let mut out = PromptClass::PR_CA4_DEFAULT;
        let kw = BTreeSet::from(["pii".to_string()]);
        let result = ClassifierStage::run(
            ClassifierInputs {
                prompt: UserPrompt {
                    text: "PII PII PII PII".into(),
                },
                keywords: kw,
            },
            &mut out,
        );
        assert!(
            result.is_ok(),
            "high-conf classify must return Ok: {result:?}"
        );
        assert_eq!(out.class, PromptClassKind::Compliance);
        assert!(out.conf >= CLASSIFIER_THRESHOLD);
    }

    #[test]
    fn stage_low_conf_returns_tagged_success_error_with_threshold() {
        let mut out = PromptClass::PR_CA4_DEFAULT;
        let kw = BTreeSet::from(["pii".to_string()]);
        let result = ClassifierStage::run(
            ClassifierInputs {
                prompt: UserPrompt {
                    // ~10 tokens, 0 keyword hits → 0.0 conf
                    text: "tell me about cats and dogs running in fields".into(),
                },
                keywords: kw,
            },
            &mut out,
        );
        match result {
            Err(StageError::ClassifierLowConfidence { conf, threshold }) => {
                assert_eq!(threshold, CLASSIFIER_THRESHOLD);
                assert!(conf < threshold);
            }
            other => panic!("expected ClassifierLowConfidence, got {other:?}"),
        }
        // Spec 10 §10.7.2: output is populated even on low-conf path.
        assert_eq!(
            out.class,
            PromptClassKind::Compliance,
            "fail-secure default must be set even when Err returned"
        );
    }

    #[test]
    fn stage_is_deterministic_across_repeated_calls() {
        // Spec 10 §10.3.5 cross-process determinism: same input must
        // always produce the same output. BTreeSet iteration is
        // sorted; tokenization is sequential; classify is pure.
        let kw = BTreeSet::from(["pii".to_string(), "auth".to_string()]);
        let prompt = UserPrompt {
            text: "Does my auth log expose PII?".into(),
        };
        let mut last: Option<PromptClass> = None;
        for _ in 0..5 {
            let mut out = PromptClass::PR_CA4_DEFAULT;
            let _ = ClassifierStage::run(
                ClassifierInputs {
                    prompt: prompt.clone(),
                    keywords: kw.clone(),
                },
                &mut out,
            );
            if let Some(prev) = last {
                assert_eq!(prev.class, out.class);
                assert!((prev.conf - out.conf).abs() < f32::EPSILON);
            }
            last = Some(out);
        }
    }

    #[test]
    fn classifier_low_conf_exit_code_is_25_tagged_success() {
        // Reaffirms the contract: low-confidence is mapped to exit 25
        // by the driver, but the variant DOES NOT abort the pipeline
        // — the driver catches it and continues.
        let e = StageError::ClassifierLowConfidence {
            conf: 0.0,
            threshold: CLASSIFIER_THRESHOLD,
        };
        assert_eq!(e.exit_code(), 25);
        assert_eq!(e.tag(), "classifier_low_confidence");
    }
}
