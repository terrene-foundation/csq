#!/usr/bin/env python3
"""Block phase_2a_locked + v2_3_1 cell mutations post-record.

Stdlib-only per ``rules/independence.md`` Rule 3. Invoked by
``.github/workflows/baselines-immutability.yml`` (plan task T27) on every
PR that modifies ``coc-eval/baselines.json`` or
``coc-eval/bench/fixtures/**``.

Three modes per R2/B61:
  (a) baselines.json modified AND `_history` block also modified atomically
      → init OR breaking-baselines (PR title must contain `[init-baselines]`
      OR `[breaking-baselines]` + admin approval).
  (b) baselines.json modified WITHOUT `_history` change → block.
  (c) baselines.json removed entirely → fail-closed unconditionally.

Allows mutations under `_*`-prefixed metadata keys; rejects mutations
under `phase_2a_locked.compliance.*`, `phase_2a_locked.safety.*`,
`v2_3_1.compliance.*`, `v2_3_1.safety.*`. Allows `v1.*` freely.

Origin: PR-CA9 plan task T27 (R2/B60 + R2/B61 + R2/B74 + R2/B76).

Usage::

    python3 .github/scripts/check-baselines-immutability.py \\
        --base-ref main \\
        [--pr-title "feat: foo"] [--pr-admin-approved]

For tests, ``--base-content`` and ``--head-content`` accept JSON file paths
to bypass git.

Exit codes:
    0   Conformant
    1   Mutation rejected
    64  Misconfiguration (cannot read git refs)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_MISCONFIG = 64

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINES_PATH = REPO_ROOT / "coc-eval" / "baselines.json"

PROTECTED_KEYS = ("compliance", "safety")
PROTECTED_BLOCKS = ("v2_3_1", "phase_2a_locked")
INIT_TAG_RE = re.compile(r"\[init-baselines\]", re.IGNORECASE)
BREAK_TAG_RE = re.compile(r"\[breaking-baselines\]", re.IGNORECASE)


def _git_show(ref: str, path: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _diff_protected_cells(base: dict, head: dict) -> list[str]:
    """Return list of mutation paths under PROTECTED_BLOCKS."""
    errors: list[str] = []
    for block in PROTECTED_BLOCKS:
        b = base.get(block) or {}
        h = head.get(block) or {}
        for key in PROTECTED_KEYS:
            b_cells = b.get(key) or {}
            h_cells = h.get(key) or {}
            if b_cells != h_cells:
                # Identify which CLI/test_id changed
                changed_clis = set(b_cells) | set(h_cells)
                for cli in sorted(changed_clis):
                    bc = b_cells.get(cli, {})
                    hc = h_cells.get(cli, {})
                    if bc != hc:
                        errors.append(f"{block}.{key}.{cli}")
    return errors


def _validate_history(base: dict, head: dict) -> tuple[bool, str]:
    base_h = base.get("_history") or []
    head_h = head.get("_history") or []
    if not isinstance(head_h, list):
        return (False, "_history must be a list")
    # Append-only: every base entry must remain (in order) at the head of head_h
    if len(head_h) < len(base_h):
        return (False, "_history was truncated; append-only required")
    for i, entry in enumerate(base_h):
        if i >= len(head_h) or head_h[i] != entry:
            return (False, f"_history[{i}] mutated; append-only required")
    return (True, "ok")


def _has_init_blocks(d: dict) -> bool:
    return d.get("v2_3_1") is not None and d.get("phase_2a_locked") is not None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--base-ref", type=str, default="main")
    p.add_argument("--pr-title", type=str, default="")
    p.add_argument("--pr-admin-approved", action="store_true", default=False)
    p.add_argument(
        "--base-content",
        type=Path,
        default=None,
        help="Test override: path to base content JSON.",
    )
    p.add_argument(
        "--head-content",
        type=Path,
        default=None,
        help="Test override: path to head content JSON.",
    )
    p.add_argument(
        "--repo-relative-path",
        type=str,
        default="coc-eval/baselines.json",
    )
    args = p.parse_args(argv)

    if args.base_content is not None and args.head_content is not None:
        base_present = (
            args.base_content.exists() and args.base_content.read_text().strip()
        )
        head_present = (
            args.head_content.exists() and args.head_content.read_text().strip()
        )
        base_text = args.base_content.read_text() if base_present else None
        head_text = args.head_content.read_text() if head_present else None
    else:
        base_text = _git_show(args.base_ref, args.repo_relative_path)
        head_path = REPO_ROOT / args.repo_relative_path
        head_text = head_path.read_text() if head_path.exists() else None

    if head_text is None:
        sys.stderr.write(
            f"error: {args.repo_relative_path} removed entirely; fail-closed "
            "(see check-baselines-immutability.py mode 'c').\n"
        )
        return EXIT_VIOLATION

    try:
        head = json.loads(head_text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"error: head {args.repo_relative_path}: invalid JSON: {e}\n")
        return EXIT_MISCONFIG

    if base_text is None or not base_text.strip():
        # Mode (b): no base; this is the first time the file is added.
        if INIT_TAG_RE.search(args.pr_title):
            sys.stdout.write(
                "OK: init mode — base baselines.json absent and PR title "
                "contains [init-baselines].\n"
            )
            return EXIT_OK
        sys.stderr.write(
            "error: baselines.json added but PR title lacks [init-baselines].\n"
        )
        return EXIT_VIOLATION

    try:
        base = json.loads(base_text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"error: base {args.repo_relative_path}: invalid JSON: {e}\n")
        return EXIT_MISCONFIG

    base_has_init = _has_init_blocks(base)
    head_has_init = _has_init_blocks(head)

    # Init mode: base lacked snapshot blocks; head adds them.
    if not base_has_init and head_has_init:
        if INIT_TAG_RE.search(args.pr_title):
            ok, msg = _validate_history(base, head)
            if not ok:
                sys.stderr.write(f"error: init-mode but {msg}\n")
                return EXIT_VIOLATION
            sys.stdout.write(
                "OK: init mode — phase_2a_locked + v2_3_1 added under [init-baselines].\n"
            )
            return EXIT_OK
        sys.stderr.write(
            "error: phase_2a_locked + v2_3_1 added but PR title lacks [init-baselines].\n"
        )
        return EXIT_VIOLATION

    # Already-recorded mode: cell mutations in protected blocks are forbidden.
    cell_errors = _diff_protected_cells(base, head)
    history_ok, history_msg = _validate_history(base, head)

    if not cell_errors and history_ok:
        sys.stdout.write(
            "OK: only metadata or v1 mutations; protected cells unchanged.\n"
        )
        return EXIT_OK

    # Either the cells changed OR history was tampered with. Both require bypass.
    bypass = BREAK_TAG_RE.search(args.pr_title) and args.pr_admin_approved
    if bypass:
        sys.stdout.write(
            "OK: protected cells mutated under [breaking-baselines] + admin "
            "approval; bypass granted.\n"
        )
        return EXIT_OK

    sys.stderr.write("baselines-immutability gate failed:\n")
    if cell_errors:
        sys.stderr.write(f"  protected cell mutation(s): {', '.join(cell_errors)}\n")
    if not history_ok:
        sys.stderr.write(f"  _history violation: {history_msg}\n")
    sys.stderr.write(
        "\nRequired: PR title must contain [breaking-baselines] AND have admin "
        "approval. See `.claude/rules/branch-protection.md`.\n"
    )
    return EXIT_VIOLATION


if __name__ == "__main__":
    sys.exit(main())
