# coc-eval — multi-CLI COC evaluation harness

Tests CLI + model behavior across four axes — **capability**, **compliance**, **safety**, **implementation** — against three CLIs: `claude` (cc), `codex`, `gemini`.

Authoritative spec at `specs/08-coc-eval-harness.md`. This README is operator-facing quick-start; drifts from the spec are README bugs.

## Quick start

```bash
# Run everything (all four suites, all available CLIs)
coc-eval/run.py all

# One suite × one CLI
coc-eval/run.py compliance --cli cc

# Single test for debugging
coc-eval/run.py compliance --cli cc --test CM3-directive-recommend

# Aggregate report for the latest run
coc-eval/aggregate.py

# Aggregate across the past 7 days
coc-eval/aggregate.py --since 7d
```

Run-ids are printed on first and last stdout lines. Results land in `coc-eval/results/<run_id>/`.

## Sandbox prerequisites

The implementation suite runs each test inside a process-level sandbox to keep models away from credentials.

- **Linux:** `apt install bubblewrap` (or `dnf install bubblewrap`). `bwrap` is the sandbox.
- **macOS:** `sandbox-exec` is preinstalled. Apple-deprecated as of 10.10 but still functional. v1.1 follow-up to replace with the `sandbox` framework.
- **Windows:** implementation suite is gated out at argparse. Phase 1 supports macOS + Linux only.

## First-run errors

If no CLI passes auth probe, the harness exits 78 with:

```
ERROR: no CLI passed auth probe.
  cc:     no ~/.claude/.credentials.json (run: claude /login)
  codex:  no ~/.codex/auth.json          (run: codex login)
  gemini: no ~/.gemini/oauth_creds.json  (run: gemini auth login)

Need at least one authenticated CLI. See coc-eval/README.md#first-run.
```

Authenticate at least one CLI and re-run.

## Profiles (CC-only)

`--profile <name>` overlays `~/.claude/settings-<name>.json` to route the implementation suite against a specific model:

```bash
coc-eval/run.py implementation --profile mm --cli cc --label "MiniMax M2.7"
```

Profiles only apply to `--cli cc` because they manipulate cc's settings.json. Use `--list-profiles` to see what's installed.

## Ablation modes (implementation suite, CC-only)

```bash
# COC + bare comparison (default)
coc-eval/run.py implementation --mode full

# Just bare baseline
coc-eval/run.py implementation --mode bare-only

# Specific layer ablation
coc-eval/run.py implementation --mode ablation --ablation-group no-rules
```

## Test selection

```bash
# Filter by test ID
coc-eval/run.py compliance --test CM3,CM7

# Filter by tag
coc-eval/run.py all --tag credentials

# Skip a CLI
coc-eval/run.py all --skip-cli gemini

# Skip a suite
coc-eval/run.py all --skip-suite implementation
```

## Resuming an interrupted run

If you Ctrl-C mid-run, the harness writes `results/<run_id>/INTERRUPTED.json` and prints the resume command. Continue with:

```bash
coc-eval/run.py --resume <run_id>
```

This skips already-complete `(suite, cli)` pairs and continues from where it left off.

## Output formats

```bash
coc-eval/run.py compliance --format pretty   # default when isatty
coc-eval/run.py compliance --format jsonl    # default when piped
coc-eval/run.py compliance --format json     # single document
```

Persisted JSONL is unchanged regardless of `--format`.

## Validating a suite definition

```bash
coc-eval/run.py compliance --validate
```

Checks the SUITE dict against `schemas/suite-v1.json`, verifies test IDs match the manifest, and asserts criteria-count parity across CLIs. Exit 64 on schema fail.

## Common errors

**Wrong CLI identifier:**

```
$ coc-eval/run.py compliance --cli claude
error: --cli: 'claude' is not a CLI identifier; the cc CLI is referenced as 'cc' (the binary is 'claude').
       valid: cc | codex | gemini | all
```

**Profile + non-cc CLI:**

```
$ coc-eval/run.py implementation --profile mm --cli codex
error: --profile is implementation-suite + cc-only (you ran --cli codex).
       codex routes models via ~/.codex/config.toml, not via csq settings profiles.
```

**Auth probe failure for one CLI:** harness emits a WARN banner, marks that CLI's tests as `skipped_cli_auth`, runs the others normally.

## Architecture

```
coc-eval/
  lib/                    -- Python stdlib library
    validators.py         -- name validation + SUITE_MANIFEST
    redact.py             -- token redaction (port of csq-core error.rs)
    launcher.py           -- LaunchInputs/LaunchSpec dataclasses + CLI_REGISTRY
    states.py             -- State enum + precedence ladders
    suite_validator.py    -- suite-v1.json validator
  schemas/
    v1.0.0.json           -- JSONL record schema
    suite-v1.json         -- SUITE dict schema
  suites/
    capability.py, compliance.py, safety.py, implementation.py
  fixtures/               -- per-suite isolated fixtures (cp+git-init per test)
  scaffolds/              -- implementation-suite scaffolds
  results/<run_id>/       -- per-run JSONL + .log files (gitignored)
  run.py                  -- top-level CLI entry
  aggregate.py            -- run-scoped Markdown matrix generator
  baselines.json          -- per-(suite, cli, profile) min pass-rate baselines
```

See `specs/08-coc-eval-harness.md` for the full contract.
