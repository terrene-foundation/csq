//! Pre-classifier (interactive vs one-shot) — `PipelineStage` that
//! sits between `.coc/` resolution and the spawn step.
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.4.2 ("Pre-classification of interactive-vs-one-shot uses argv
//! inspection (`--print` / `-p` / piped stdin → one-shot; otherwise
//! interactive). Pre-classification IS a `PipelineStage<Reads =
//! UserPrompt + Argv, Writes = SpawnMode>`; same data-flow typing
//! applies (per journal 0008 § For Discussion #2).").
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

/// Inputs to the pre-classifier.
#[derive(Debug, Clone)]
pub struct PreClassifyInputs {
    /// The argv segment that csq passes through to the downstream
    /// CLI (everything after `csq run [N]` and known csq flags).
    pub argv: Vec<String>,
    /// Whether stdin is a TTY at csq launch time. False = stdin is
    /// piped or redirected → one-shot per spec 10 §10.4.2.
    pub stdin_is_tty: bool,
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
        *output = classify(&input.argv, input.stdin_is_tty);
        Ok(())
    }
}

/// Pure classification function. Stable; no I/O. Same input always
/// produces the same output (FR-DISP-05 determinism applies here too,
/// even though the classifier output is not part of the translator
/// surface).
fn classify(argv: &[String], stdin_is_tty: bool) -> SpawnMode {
    // Non-TTY stdin always means one-shot regardless of argv —
    // piped input has no human at the terminal to interact with.
    if !stdin_is_tty {
        return SpawnMode::OneShot;
    }
    // CC's `--print` / `-p` flag is documented as one-shot mode —
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

    #[test]
    fn print_long_flag_is_one_shot() {
        let mode = classify(&["--print".into(), "hello".into()], true);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn p_short_flag_is_one_shot() {
        let mode = classify(&["-p".into(), "hello".into()], true);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn p_combinator_short_form_is_one_shot() {
        // `-phello` is the combinator form (some CLIs accept this).
        let mode = classify(&["-phello".into()], true);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn non_tty_stdin_is_one_shot_even_without_print_flag() {
        let mode = classify(&["chat".into()], false);
        assert_eq!(mode, SpawnMode::OneShot);
    }

    #[test]
    fn empty_argv_with_tty_stdin_is_interactive() {
        let mode = classify(&[], true);
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
        );
        assert_eq!(mode, SpawnMode::Interactive);
    }

    #[test]
    fn unrelated_flags_starting_with_hyphen_p_are_not_misread() {
        // `--port` should NOT be classified as one-shot just because
        // it starts with `-p`. Our combinator rule excludes `--`
        // long-flag forms.
        let mode = classify(&["--port=8080".into()], true);
        assert_eq!(mode, SpawnMode::Interactive);
    }

    #[test]
    fn run_through_pipeline_stage_trait() {
        // Round-trips through the trait surface — the rest of the
        // pipeline driver invokes this same way.
        let inputs = PreClassifyInputs {
            argv: vec!["--print".into(), "x".into()],
            stdin_is_tty: true,
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
}
