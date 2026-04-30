#!/usr/bin/env python3
"""coc-eval harness entry point.

Usage:

    coc-eval/run.py <suite> [--cli CLI] [--test ID,ID] [--skip-cli CLI ...]
                            [--skip-suite SUITE ...] [--validate] [--tag TAG]
                            [--format pretty|jsonl|json] [--resume RUN_ID]
                            [--list-profiles] [--token-budget-input N]
                            [--token-budget-output N]

Positional `<suite>` is one of `capability | compliance | safety |
implementation | all`. The harness writes one JSONL file per
`(suite, cli)` to `coc-eval/results/<run_id>/`. The first and last
stdout lines always include `run_id=<id>` (AC-45).

Custom error semantics (UX-13):

  A. unknown suite       → exit 64 (EX_USAGE) + suggested suites
  B. unknown CLI         → exit 64 + KNOWN_CLI_IDS list
  C. invalid test name   → exit 64 + per-suite manifest
  D. no args / --help    → full usage banner with examples
  E. --resume RUN_ID malformed → exit 64 + format reminder

Exit codes:

  0   success (all selected tests pass / appropriate skips)
  1   one or more tests failed
  64  EX_USAGE — argparse / suite / CLI / test name validation failed
  78  EX_CONFIG — zero-auth state on every selected CLI
  130 SIGINT
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

# Allow `coc-eval/run.py` invocation: ensure `coc-eval/` is on sys.path so
# `from lib...` and `from suites...` resolve.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Imported AFTER sys.path manipulation.
from lib import runner  # noqa: E402
from lib.suite_validator import SuiteValidationError, validate_suite  # noqa: E402
from lib.validators import (  # noqa: E402
    KNOWN_CLI_IDS,
    SUITE_MANIFEST,
    SUITE_TEST_MANIFESTS,
    validate_name,
)


_USAGE_BANNER = """\
coc-eval — multi-CLI COC harness (Phase 1: cc-only)

USAGE
  coc-eval/run.py <suite> [options]

POSITIONAL
  suite                One of: capability, compliance, safety, implementation, all

CLI SELECTION
  --cli CLI            Run against ONE CLI (cc | codex | gemini | all). Default: all.
  --skip-cli CLI       Skip a CLI even if listed. Repeatable.

TEST SELECTION
  --test ID            Comma-list of test ids (e.g. C1-baseline-root,C3-pathscoped-canary).
  --tag TAG            Run only tests carrying the given tag. Repeatable.
  --skip-suite SUITE   Skip a suite. Repeatable.

LIFECYCLE
  --validate           Validate every suite SUITE dict against schemas/suite-v1.json. Exit 0 on all-pass.
  --resume RUN_ID      Resume from a prior run that wrote INTERRUPTED.json.
  --list-profiles      Scan ~/.claude/settings-*.json and print profile name + model.

OUTPUT
  --format pretty|jsonl|json
                        Default: pretty when stdout is a TTY; jsonl otherwise.
  --token-budget-input N      Abort run if cumulative input tokens >= N.
  --token-budget-output N     Abort run if cumulative output tokens >= N.

EXAMPLES
  coc-eval/run.py capability --cli cc
  coc-eval/run.py capability --cli cc --test C1-baseline-root
  coc-eval/run.py all --skip-suite implementation --skip-cli gemini
  coc-eval/run.py --validate
  coc-eval/run.py --list-profiles
  coc-eval/run.py --resume 2026-04-29T10-15-22Z-12345-0001-AaBbCcDd

LEGACY COMPAT (H7 — informational only; legacy runner.py shim)
  --mode {full,coc-only,bare}            ablation mode for the legacy single-CLI runner
  --ablation-group {no-rules,no-agents,no-skills,rules-only}
                                          which COC layer to strip (legacy ablation)
  --profile NAME                          settings profile name (e.g. opus, sonnet);
                                          validated via validate_name (CRIT-02)

EXIT CODES
  0    success
  1    tests failed
  64   usage error (UX-13 cases A/B/C/E)
  78   no working auth on any selected CLI (AC-32)
  130  SIGINT
"""


# ---------------------------------------------------------------------------
# Argparse


def _split_csv(s: str) -> list[str]:
    """Split a comma-separated argv value, drop empties."""
    return [p.strip() for p in s.split(",") if p.strip()]


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with custom usage + error semantics."""
    parser = argparse.ArgumentParser(
        prog="coc-eval/run.py",
        add_help=False,  # custom --help to print banner
        description=("csq coc-eval — multi-CLI COC harness. Use --help for usage."),
    )
    parser.add_argument(
        "suite",
        nargs="*",
        choices=list(SUITE_MANIFEST) + ["all"],
        help=(
            "one or more suites to run, in canonical order "
            "(capability < compliance < safety < implementation), "
            "or 'all'. INV-RUN-8: out-of-order positional values "
            "exit 64."
        ),
    )
    parser.add_argument(
        "--cli",
        choices=list(KNOWN_CLI_IDS) + ["all"],
        default="all",
        help="CLI to run against (default: all)",
    )
    parser.add_argument(
        "--test",
        action="append",
        default=[],
        help="comma-list of test ids to run",
    )
    parser.add_argument(
        "--skip-cli",
        action="append",
        default=[],
        choices=list(KNOWN_CLI_IDS),
        help="skip CLI (repeatable)",
    )
    parser.add_argument(
        "--skip-suite",
        action="append",
        default=[],
        choices=list(SUITE_MANIFEST),
        help="skip suite (repeatable)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="validate suite dicts and exit",
    )
    parser.add_argument(
        "--tag",
        action="append",
        default=[],
        help="run only tests carrying tag (repeatable)",
    )
    parser.add_argument(
        "--format",
        choices=("pretty", "jsonl", "json"),
        default=None,
        help="output format (default: pretty if TTY, jsonl otherwise)",
    )
    parser.add_argument(
        "--resume",
        default=None,
        help="resume run_id from a prior interrupted run",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="list ~/.claude/settings-*.json profiles",
    )
    parser.add_argument(
        "--token-budget-input",
        type=int,
        default=None,
        help=(
            "abort run if cumulative input tokens reach N. "
            "NOTE (H8 R1-B-MED-1): in multi-suite invocations the "
            "budget is enforced per-sub-run, not across sub-runs — "
            "`--token-budget-input 1000 safety implementation` lets "
            "EACH suite spend up to 1000."
        ),
    )
    parser.add_argument(
        "--token-budget-output",
        type=int,
        default=None,
        help=(
            "abort run if cumulative output tokens reach N. See "
            "--token-budget-input for multi-suite semantics."
        ),
    )
    parser.add_argument(
        "--results-root",
        default=None,
        help=(
            "directory to write JSONL + logs under (default: "
            "coc-eval/results/). Tests pass a tmp_path to avoid "
            "polluting the developer tree."
        ),
    )
    # Implementation-suite ablation flags (FR-10). Accepted by run.py for
    # forward compat with the legacy runner.py shim — the new SUITE-based
    # path uses fixtures, not modes. The flags are validated at parse
    # time; a future PR can wire them to per-test fixture selection.
    parser.add_argument(
        "--mode",
        choices=("full", "coc-only", "bare"),
        default=None,
        help=(
            "implementation-suite ablation mode (legacy compat). "
            "full=COC + memory; coc-only=COC, no memory; bare=no COC. "
            "Currently informational; set on the run record only."
        ),
    )
    parser.add_argument(
        "--ablation-group",
        choices=("no-rules", "no-agents", "no-skills", "rules-only"),
        default=None,
        help=(
            "implementation-suite ablation layer (legacy compat). "
            "Validated; informational only in Phase 1."
        ),
    )
    parser.add_argument(
        "--profile",
        default=None,
        help=(
            "settings profile name (e.g. 'opus', 'sonnet'). Validated "
            "via validate_name (CRIT-02). Use --list-profiles to see "
            "available."
        ),
    )
    parser.add_argument("-h", "--help", action="store_true")
    return parser


# ---------------------------------------------------------------------------
# Custom error helpers


def _err(msg: str) -> None:
    sys.stderr.write(f"coc-eval: error: {msg}\n")


def _ux13_unknown_suite(suite: str) -> int:
    _err(f"unknown suite: {suite!r}")
    sys.stderr.write(f"  valid suites: {', '.join(SUITE_MANIFEST)}, all\n")
    sys.stderr.write("  see: coc-eval/run.py --help\n")
    return 64


def _ux13_unknown_cli(cli: str) -> int:
    _err(f"unknown CLI id: {cli!r}")
    sys.stderr.write(f"  valid: {', '.join(KNOWN_CLI_IDS)}, all\n")
    return 64


def _ux13_unknown_test(suite: str, test: str) -> int:
    _err(f"unknown test {test!r} for suite {suite!r}")
    valid = SUITE_TEST_MANIFESTS.get(suite, ())
    sys.stderr.write(f"  valid tests for {suite}: {', '.join(valid)}\n")
    return 64


def _ux13_bad_resume(run_id: str) -> int:
    _err(f"--resume value is not a valid run_id: {run_id!r}")
    sys.stderr.write(
        "  expected format: <iso8601-second>-<pid>-<counter>-<rand>\n"
        "  example: 2026-04-29T10-15-22Z-12345-0001-AaBbCcDd\n"
    )
    return 64


# H8 / INV-RUN-8: canonical suite execution order. Implementation runs
# AFTER safety because implementation uses cc with
# `--dangerously-skip-permissions` and a process-level sandbox; safety
# verifies rule-citation refusal under `--permission-mode plan` first,
# so a regression in the safety baseline is caught before any
# permission escalation. Compliance + capability are cheap canaries
# that gate the harness wiring before either of those.
_CANONICAL_SUITE_ORDER: tuple[str, ...] = (
    "capability",
    "compliance",
    "safety",
    "implementation",
)

# H8 R1-B-HIGH-4: assert canonical-order set matches SUITE_MANIFEST.
# A future PR that adds a 5th suite to SUITE_MANIFEST without updating
# `_CANONICAL_SUITE_ORDER` would silently produce 64-exit on every
# run. This assertion catches the drift at module-import time.
assert set(_CANONICAL_SUITE_ORDER) == set(SUITE_MANIFEST), (
    f"INV-RUN-8 drift: _CANONICAL_SUITE_ORDER={_CANONICAL_SUITE_ORDER} "
    f"missing or extra entries vs SUITE_MANIFEST={SUITE_MANIFEST}"
)


def _normalize_and_validate_suites(
    raw_suites: list[str],
    *,
    enforce_canonical_order: bool = True,
) -> tuple[int, str | None, str | None, tuple[str, ...]]:
    """Validate the positional suite list and produce a normalized form.

    Returns `(exit_code, error_msg, all_or_none, canonical_tuple)`:

    - `exit_code == 0` → success; consult `all_or_none` and
      `canonical_tuple`.
    - `exit_code == 64` → input is invalid; `error_msg` is the user-
      visible reason. The CLI returns 64 to the OS.

    Normalized output:

    - `("all", ())` when the user passed exactly `["all"]`. Downstream
      consumers expand to `SUITE_MANIFEST`.
    - `(None, ("safety", "implementation"))` when the user passed an
      explicit ordered list. The tuple is in CANONICAL order regardless
      of input order — but if the input order violates canonical
      order, we already returned 64 via `error_msg`.

    Empty list returns `(0, None, None, ())` so the caller can show
    the usage banner.
    """
    if not raw_suites:
        return 0, None, None, ()
    # Reject mixing "all" with specific suites — semantically ambiguous.
    if "all" in raw_suites and len(raw_suites) > 1:
        return (
            64,
            "cannot combine 'all' with specific suite names",
            None,
            (),
        )
    if raw_suites == ["all"]:
        return 0, None, "all", ()
    # Reject duplicates explicitly — argparse's `choices` allows them,
    # but the canonical-ordering check below would surface them as
    # "ordering violation" with a less clear message.
    seen: set[str] = set()
    for s in raw_suites:
        if s in seen:
            return (
                64,
                f"suite {s!r} listed twice — each suite may run at "
                f"most once per invocation",
                None,
                (),
            )
        seen.add(s)
    # Canonical ordering check (INV-RUN-8 / AC-32-quat). Optional —
    # `--validate` skips this since it's a schema-only operation
    # (B-MED-3). Membership in canonical order is still checked as a
    # defense-in-depth backstop for argparse `choices=` regressions.
    positions = {name: idx for idx, name in enumerate(_CANONICAL_SUITE_ORDER)}
    last_pos = -1
    for s in raw_suites:
        if s not in positions:
            # argparse `choices=` already rejects unknown names; reaching
            # here means SUITE_MANIFEST drifted from _CANONICAL_SUITE_ORDER.
            return (
                64,
                f"INV-RUN-8 sanity: suite {s!r} not in canonical order "
                f"(rebuild _CANONICAL_SUITE_ORDER)",
                None,
                (),
            )
        if enforce_canonical_order and positions[s] <= last_pos:
            return (
                64,
                (
                    f"ordering violation (INV-RUN-8): suite {s!r} cannot "
                    f"follow a later canonical suite. Canonical order: "
                    f"{', '.join(_CANONICAL_SUITE_ORDER)}"
                ),
                None,
                (),
            )
        last_pos = positions[s]
    return 0, None, None, tuple(raw_suites)


# ---------------------------------------------------------------------------
# --validate / --list-profiles


def cmd_validate(suites_to_check: Sequence[str] | None = None) -> int:
    """Validate every suite SUITE dict against suite-v1.json.

    Phase 1: Only `capability` is wired up. H6/H7/H8 add the rest.
    """
    from suites import SUITE_REGISTRY  # noqa: E402

    names = list(suites_to_check) if suites_to_check else list(SUITE_REGISTRY.keys())
    failed: list[str] = []
    total_tests = 0
    total_criteria = 0
    clis_seen: set[str] = set()
    for name in names:
        suite_def = SUITE_REGISTRY.get(name)
        if suite_def is None:
            sys.stderr.write(f"FAIL: suite {name!r} not registered in SUITE_REGISTRY\n")
            failed.append(name)
            continue
        try:
            validate_suite(suite_def)
        except SuiteValidationError as e:
            sys.stderr.write(f"FAIL: suite {name!r}: {e}\n")
            failed.append(name)
            continue
        total_tests += len(suite_def["tests"])
        for test in suite_def["tests"]:
            for cli, criteria in (test.get("expect") or {}).items():
                clis_seen.add(cli)
                if isinstance(criteria, list):
                    total_criteria += len(criteria)
    if failed:
        sys.stderr.write(f"FAILED: {len(failed)} suite(s): {', '.join(failed)}\n")
        return 64
    sys.stdout.write(
        f"OK: {total_tests} tests, {total_criteria} criteria across "
        f"{len(clis_seen)} CLIs ({', '.join(sorted(clis_seen))})\n"
    )
    return 0


def cmd_list_profiles() -> int:
    """List ~/.claude/settings-*.json profiles + their resolved models."""
    profiles = runner.list_profiles()
    if not profiles:
        sys.stdout.write("(no ~/.claude/settings-*.json profiles found)\n")
        return 0
    name_w = max(len(p["name"]) for p in profiles)
    sys.stdout.write(
        f"{'name'.ljust(name_w)}  {'model':<30}  profile_compatible_clis\n"
    )
    sys.stdout.write(f"{'-' * name_w}  {'-' * 30}  -----------------------\n")
    for p in profiles:
        sys.stdout.write(
            f"{p['name'].ljust(name_w)}  {p['model']:<30}  "
            f"{p['profile_compatible_clis']}\n"
        )
    return 0


# ---------------------------------------------------------------------------
# Main


def _resolve_format(arg: str | None) -> str:
    """Pick output format. H5-A-3: `isatty()` raises ValueError/OSError on a
    closed-or-detached stdout (some sandboxes / nohup patterns). Fall back
    to jsonl rather than crashing — JSONL is the safer default for any
    non-interactive path.
    """
    if arg is not None:
        return arg
    try:
        return "pretty" if sys.stdout.isatty() else "jsonl"
    except (ValueError, OSError):
        return "jsonl"


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(argv if argv is not None else sys.argv[1:])

    if not raw_argv or "-h" in raw_argv or "--help" in raw_argv:
        sys.stdout.write(_USAGE_BANNER)
        return 0

    try:
        args = parser.parse_args(raw_argv)
    except SystemExit as e:
        # argparse exits 2 on parse failure; map to UX-13 64.
        return e.code if isinstance(e.code, int) else 64

    invocation = " ".join(["coc-eval/run.py", *raw_argv])

    # H8 / INV-RUN-8: validate the positional suite list (with canonical
    # ordering) BEFORE other branches consume it. Empty list is OK at
    # this point — `--validate` and `--list-profiles` don't need a
    # suite; the run-loop branch checks for an empty list itself.
    #
    # H8 R1-B-MED-3: `--validate` is a schema-only operation that does
    # NOT execute tests. Ordering enforcement is a RUNTIME invariant
    # (sandbox-after-safety). Skip the ordering check for --validate
    # so an operator can `--validate implementation safety` without
    # being forced to retype in canonical order. Other guards
    # (duplicates, mixing 'all' + specific) still apply.
    rc_suite, suite_err, suite_all, suite_tuple = _normalize_and_validate_suites(
        args.suite, enforce_canonical_order=not args.validate
    )
    if rc_suite != 0:
        _err(suite_err or "suite validation failed")
        return rc_suite

    # Standalone modes (no run loop).
    if args.list_profiles:
        return cmd_list_profiles()
    if args.validate:
        # `--validate` operates on the registered suites; explicit
        # suite list narrows the target. Empty list and 'all' both mean
        # "every suite".
        if suite_tuple:
            return cmd_validate(list(suite_tuple))
        return cmd_validate()

    # Validate --resume run_id BEFORE further work — UX-13 case E.
    resume_run_id = args.resume
    if resume_run_id is not None:
        from lib.run_id import RUN_ID_RE  # noqa: E402

        if not RUN_ID_RE.fullmatch(resume_run_id):
            return _ux13_bad_resume(resume_run_id)

    # Validate --profile (CRIT-02 — path traversal in profile filenames).
    # `validate_name` rejects `..`, leading dots, slashes, control chars,
    # and over-length names. AC-38 surface: bad profile name exits 64
    # with the validator's error message.
    if args.profile is not None:
        try:
            validate_name(args.profile)
        except ValueError as e:
            _err(f"--profile: {e}")
            return 64

    # From here we need a suite. Empty positional list AND no 'all' means
    # show the banner and exit 64 (UX-13 D — no usable input).
    if not suite_all and not suite_tuple:
        sys.stderr.write(_USAGE_BANNER)
        return 64

    tests_csv: list[str] = []
    for entry in args.test or []:
        for tok in _split_csv(entry):
            # H5-A-5: defense-in-depth — tokens flow into closed-set
            # lookups below, but `validate_name` surfaces traversal /
            # NUL / whitespace immediately with a clearer error.
            try:
                validate_name(tok)
            except ValueError as e:
                _err(str(e))
                return 64
            tests_csv.append(tok)
    tags: list[str] = list(args.tag or [])

    # Cross-validate test ids against the manifest for the chosen suite(s).
    if tests_csv:
        suites_for_check = list(SUITE_MANIFEST) if suite_all else list(suite_tuple)
        valid_ids: set[str] = set()
        for s in suites_for_check:
            valid_ids.update(SUITE_TEST_MANIFESTS.get(s, ()))
        for t in tests_csv:
            if t not in valid_ids:
                # Surface the per-suite manifest for the operator.
                target_suite = suites_for_check[0] if suites_for_check else "all"
                return _ux13_unknown_test(target_suite, t)

    # H8: when multiple suites are explicitly listed, run them sequentially
    # via runner.run() one at a time so each gets its own selection. The
    # canonical-ordering check above already guarantees they are in the
    # safe-execution order. A single suite (or 'all') flows the original
    # path. The aggregate exit code is the worst of all per-suite codes.
    selection_arg = "all" if suite_all else suite_tuple[0]
    if not suite_all and len(suite_tuple) > 1:
        # H8 R1-B-HIGH-1: --resume + multi-suite is unsupported. The
        # parse_resume side effects (delete in-flight JSONL files) would
        # repeat per sub-run, and INTERRUPTED.json would be overwritten
        # by the second sub-run with stale state. Reject explicitly
        # rather than silently corrupting resume state.
        if resume_run_id is not None:
            _err(
                "--resume is not supported with multi-suite invocations. "
                "Resume one suite at a time, or wait for full multi-suite "
                "resume support (tracked under H9+)."
            )
            return 64

        # H8 R1-B-HIGH-3: generate ONE run_id upfront so all sub-runs
        # write to the same `results/<run_id>/` directory and the
        # operator sees a single run_id printed at start AND end (even
        # though each sub-run echoes it). AC-45 contract preserved.
        from lib.run_id import generate_run_id  # noqa: E402

        shared_run_id = generate_run_id()

        worst_rc = 0
        fmt = _resolve_format(args.format)
        base_results_dir = (
            Path(args.results_root).resolve() if args.results_root else None
        )
        for sname in suite_tuple:
            try:
                sub_selection = runner.resolve_selection(
                    sname,
                    args.cli,
                    tests=tests_csv or None,
                    tags=tags or None,
                    skip_clis=args.skip_cli,
                    skip_suites=args.skip_suite,
                )
            except ValueError as e:
                _err(str(e))
                return 64
            sub_rc = runner.run(
                sub_selection,
                format=fmt,
                run_id_override=shared_run_id,
                base_results_dir=base_results_dir,
                invocation=invocation,
                token_budget_input=args.token_budget_input,
                token_budget_output=args.token_budget_output,
            )
            # H8 R1-B-HIGH-2: short-circuit on EX_CONFIG (78). Auth
            # state cannot recover mid-run; running subsequent suites
            # would just re-print the zero-auth banner per suite.
            if sub_rc == 78:
                return 78
            if sub_rc > worst_rc:
                worst_rc = sub_rc
        return worst_rc

    try:
        selection = runner.resolve_selection(
            selection_arg,
            args.cli,
            tests=tests_csv or None,
            tags=tags or None,
            skip_clis=args.skip_cli,
            skip_suites=args.skip_suite,
        )
    except ValueError as e:
        _err(str(e))
        return 64

    fmt = _resolve_format(args.format)
    base_results_dir = Path(args.results_root).resolve() if args.results_root else None

    return runner.run(
        selection,
        format=fmt,
        resume_run_id=resume_run_id,
        base_results_dir=base_results_dir,
        invocation=invocation,
        token_budget_input=args.token_budget_input,
        token_budget_output=args.token_budget_output,
    )


if __name__ == "__main__":
    raise SystemExit(main())
