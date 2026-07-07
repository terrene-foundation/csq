//! Pre-classifier (interactive vs one-shot) — `PipelineStage` that
//! sits between `.coc/` resolution and the spawn step.
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.4.2 ("Pre-classification of interactive-vs-one-shot uses argv
//! inspection (`--print` / `-p` / piped stdin → one-shot; otherwise
//! interactive). Pre-classification IS a `PipelineStage<Reads =
//! UserPrompt + Argv, Writes = SpawnMode>`; same data-flow typing
//! applies (per an internal journal entry § For Discussion #2).").
//!
//! # PR-CA5 ship state
//!
//! The classifier is **real** at PR-CA5 — argv inspection is a pure
//! string check that cannot fail. The output `SpawnMode` informs the
//! spawn-step branch decision (PTY for interactive; pipes for
//! one-shot) when the spawn step lands in PR-CA6+.
//!
//! At PR-CA5 itself, the spawn step is unreachable: `mcp_gate` /
//! `struct_out` / `post_validate` are still stubs, so the pipeline
//! aborts before spawn. The pre-classifier output is computed and
//! recorded but the SpawnMode dispatch is exercised only when
//! mcp_gate becomes real.

use crate::capability_layer::errors::StageError;
use crate::capability_layer::pipeline::PipelineStage;
use crate::providers::catalog::Surface;

/// Inputs to the pre-classifier.
#[derive(Debug, Clone)]
pub struct PreClassifyInputs {
    /// The argv segment that csq passes through to the downstream
    /// CLI (everything after `csq run [N]` and known csq flags).
    pub argv: Vec<String>,
    /// Whether stdin is a TTY at csq launch time. False = stdin is
    /// piped or redirected → one-shot per spec 10 §10.4.2.
    pub stdin_is_tty: bool,
    /// Target surface. Used to select surface-specific one-shot
    /// detection arms (e.g. Gemini uses `--prompt` / `--prompt=`,
    /// CC uses `--print` / `-p`). Added in CU2 (an internal ticket).
    pub surface: Surface,
}

/// Spawn-mode decision per spec 10 §10.4.2 — fork+pipe vs PTY at
/// the spawn step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnMode {
    /// Interactive — child gets a PTY (forkpty Unix / ConPTY Windows)
    /// so `isatty(stdout)` returns 1 and TUI rendering works.
    Interactive,
    /// One-shot — child gets piped stdin/stdout (no PTY); cheaper
    /// path for `--print` and piped invocations where the model
    /// output is read non-interactively.
    OneShot,
}

impl Default for SpawnMode {
    /// Spec 10 §10.4.2 default: assume interactive when in doubt.
    /// Misclassifying interactive as one-shot loses TTY rendering
    /// (visible regression); the inverse just costs a PTY allocation.
    fn default() -> Self {
        Self::Interactive
    }
}

/// Marker type for the pre-classifier stage.
pub struct PreClassifyStage;

impl PipelineStage for PreClassifyStage {
    type Reads = PreClassifyInputs;
    type Writes = SpawnMode;

    fn run(input: Self::Reads, output: &mut Self::Writes) -> Result<(), StageError> {
        *output = classify(&input.argv, input.stdin_is_tty, input.surface);
        Ok(())
    }
}

/// Pure classification function. Stable; no I/O. Same input always
/// produces the same output (FR-DISP-05 determinism applies here too,
/// even though the classifier output is not part of the translator
/// surface).
///
/// Surface-aware one-shot detection (CU2, spec 10 §10.4.2):
/// - CC / Codex: `--print` / `-p` / `-pX` combinator.
/// - Gemini: `--prompt=<text>` (single-arg) or `--prompt <text>`
///   (space-separated). Match EXACT `--prompt` / `--prompt=`, never
///   `starts_with("--prompt")` to avoid false positives on
///   `--prompt-fallback` or similar flags.
fn classify(argv: &[String], stdin_is_tty: bool, surface: Surface) -> SpawnMode {
    // Non-TTY stdin always means one-shot regardless of argv —
    // piped input has no human at the terminal to interact with.
    if !stdin_is_tty {
        return SpawnMode::OneShot;
    }

    // Surface-specific one-shot flag detection.
    if surface == Surface::Gemini {
        // Gemini CLI's non-interactive flag is `--prompt` (space-sep or `=`).
        // Match EXACTLY to avoid false positives on similar-looking flags.
        for arg in argv {
            if arg == "--prompt" {
                // Space-separated form: `--prompt <text>` — argv carries
                // the flag; the next element is the prompt text. We detect
                // on the flag alone; prompt extraction is in
                // `extract_prompt_from_argv` (driver.rs).
                return SpawnMode::OneShot;
            }
            if arg.starts_with("--prompt=") {
                // Single-arg form: `--prompt=<text>`.
                return SpawnMode::OneShot;
            }
        }
        // Gemini does NOT use `-p` / `--print` — those are CC-only.
        return SpawnMode::Interactive;
    }

    // CC / Codex: `--print` / `-p` flag is documented as one-shot mode —
    // CC emits the model's output and exits.
    for arg in argv {
        if arg == "--print" || arg == "-p" {
            return SpawnMode::OneShot;
        }
        // CC accepts `-pX` (no space) as a short combinator; treat
        // any arg starting with `-p` (but not `-print` which would
        // be a different long flag form) as one-shot.
        if arg.starts_with("-p") && !arg.starts_with("--") && arg.len() > 2 {
            return SpawnMode::OneShot;
        }
    }
    SpawnMode::Interactive
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // CC / Codex surface tests (existing behavior, unchanged by CU2)
    // ---------------------------------------------------------------

    #[test]
    fn print_long_flag_is_one_shot() {
        let mode = classify(
            &["--print".into(), "hello".into()],
            true,
            Surface::ClaudeCode,
        );
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn p_short_flag_is_one_shot() {
        let mode = classify(&["-p".into(), "hello".into()], true, Surface::ClaudeCode);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn p_combinator_short_form_is_one_shot() {
        // `-phello` is the combinator form (some CLIs accept this).
        let mode = classify(&["-phello".into()], true, Surface::ClaudeCode);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn non_tty_stdin_is_one_shot_even_without_print_flag() {
        // Non-TTY stdin triggers OneShot for ALL surfaces (surface-agnostic).
        let mode = classify(&["chat".into()], false, Surface::ClaudeCode);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn empty_argv_with_tty_stdin_is_interactive() {
        let mode = classify(&[], true, Surface::ClaudeCode);
        assert_eq!(mode, SpawnMode::Interactive);
    }

    #[test]
    fn arbitrary_args_with_tty_stdin_are_interactive() {
        let mode = classify(
            &[
                "chat".into(),
                "--model".into(),
                "claude-opus-4-7".into(),
                "--continue".into(),
            ],
            true,
            Surface::ClaudeCode,
        );
        assert_eq!(mode, SpawnMode::Interactive);
    }

    #[test]
    fn unrelated_flags_starting_with_hyphen_p_are_not_misread() {
        // `--port` should NOT be classified as one-shot just because
        // it starts with `-p`. Our combinator rule excludes `--`
        // long-flag forms.
        let mode = classify(&["--port=8080".into()], true, Surface::ClaudeCode);
        assert_eq!(mode, SpawnMode::Interactive);
    }

    #[test]
    fn run_through_pipeline_stage_trait() {
        // Round-trips through the trait surface — the rest of the
        // pipeline driver invokes this same way.
        let inputs = PreClassifyInputs {
            argv: vec!["--print".into(), "x".into()],
            stdin_is_tty: true,
            surface: Surface::ClaudeCode,
        };
        let mut mode = SpawnMode::default();
        PreClassifyStage::run(inputs, &mut mode).unwrap();
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn default_is_interactive_per_spec_10_4_2() {
        // Misclassifying interactive as one-shot loses TTY rendering
        // (visible regression); spec 10 §10.4.2 picks Interactive as
        // the safer default.
        assert_eq!(SpawnMode::default(), SpawnMode::Interactive);
    }

    // ---------------------------------------------------------------
    // CU2 (an internal ticket): Gemini surface one-shot detection
    // AC-1: --prompt=<text> single-arg form → OneShot
    // ---------------------------------------------------------------

    #[test]
    fn cu2_gemini_prompt_equals_form_is_one_shot() {
        // Spec 10 §10.4.2 (CU2): `--prompt=<text>` is gemini-cli's
        // non-interactive flag and MUST classify as OneShot on
        // Surface::Gemini.
        let mode = classify(
            &["--prompt=explain the rules".into()],
            true,
            Surface::Gemini,
        );
        assert_eq!(mode, SpawnMode::OneShot);
    }

    // AC-1: --prompt <text> space-separated form → OneShot
    #[test]
    fn cu2_gemini_prompt_space_form_is_one_shot() {
        // Spec 10 §10.4.2 (CU2): `--prompt <text>` space-separated form
        // MUST classify as OneShot on Surface::Gemini.
        let mode = classify(
            &["--prompt".into(), "explain the rules".into()],
            true,
            Surface::Gemini,
        );
        assert_eq!(mode, SpawnMode::OneShot);
    }

    // AC-5: bare gemini interactive (no --prompt) → Interactive (INV-2 guard)
    #[test]
    fn cu2_gemini_bare_interactive_stays_interactive() {
        // INV-2 (GOTCHA-E): Interactive Gemini MUST keep inherited stdio
        // and NOT be classified as OneShot just because the surface is Gemini.
        let mode = classify(&[], true, Surface::Gemini);
        assert_eq!(mode, SpawnMode::Interactive);
    }

    // AC-5: CC / Codex are not affected by Gemini detection (GOTCHA-C guard)
    #[test]
    fn cu2_cc_is_not_affected_by_gemini_detection() {
        // `--prompt` in CC argv MUST NOT trigger OneShot on
        // Surface::ClaudeCode — CC uses `--print`, not `--prompt`.
        let mode = classify(&["--prompt=hello".into()], true, Surface::ClaudeCode);
        assert_eq!(mode, SpawnMode::Interactive);
    }

    // AC-5: Codex is not affected either
    #[test]
    fn cu2_codex_is_not_affected_by_gemini_detection() {
        let mode = classify(&["--prompt".into(), "hello".into()], true, Surface::Codex);
        assert_eq!(mode, SpawnMode::Interactive);
    }

    // GOTCHA-B: piped-stdin Gemini MUST classify OneShot (surface-agnostic
    // non-TTY arm fires first, before surface-specific check).
    #[test]
    fn cu2_gemini_piped_stdin_classifies_one_shot() {
        // Non-TTY stdin → OneShot regardless of surface or argv.
        // This is the regression case for GOTCHA-B: the dead arm that
        // would silently drop inputs even when stdin is piped.
        let mode = classify(&[], false, Surface::Gemini);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    // Exact-match guard: `--prompt-fallback` must NOT trigger OneShot.
    #[test]
    fn cu2_gemini_prompt_prefix_does_not_classify_one_shot() {
        // MUST match `--prompt` exactly, not `starts_with("--prompt")`.
        // `--prompt-fallback` is a hypothetical Gemini flag that MUST
        // remain classified as Interactive.
        let mode = classify(
            &["--prompt-fallback".into(), "some text".into()],
            true,
            Surface::Gemini,
        );
        assert_eq!(mode, SpawnMode::Interactive);
    }
}
