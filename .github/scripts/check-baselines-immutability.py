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

The head SHA-256 companion is checked against exact baseline bytes BEFORE
any immutability-policy bypass. Missing both companions is allowed only before
either snapshot is recorded. Removal and invalid head seals cannot be bypassed;
adding the first companion requires [init-baselines]. Its target is compared as
opaque text, never opened or interpreted by a shell.

For tests, ``--base-content`` and ``--head-content`` accept JSON file paths
to bypass git. Companion overrides are explicit or adjacent to these private
fixtures; canonical companions are never consulted in fixture mode.

Exit codes:
    0   Conformant
    1   Mutation rejected
    64  Misconfiguration (cannot read git refs)
"""
from __future__ import annotations

import argparse
import hashlib
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


def _git_result(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Local Git read with explicit failure; no oracle error becomes absence."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OSError("baseline Git oracle unavailable") from exc


def _resolve_base_ref(base_ref: str) -> str:
    refs = [base_ref] if "/" in base_ref else [base_ref, f"origin/{base_ref}"]
    for ref in refs:
        result = _git_result(
            ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"]
        )
        if result.returncode == 0:
            revision = result.stdout.strip()
            if re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
                return revision.decode("ascii")
            raise OSError("baseline Git oracle returned an invalid commit identity")
    raise OSError("baseline Git base revision is unavailable")


def _read_git_optional(revision: str, path: str) -> bytes | None:
    # Only a successful tree enumeration can establish that this path is absent.
    listed = _git_result(
        ["ls-tree", "--name-only", "-z", "--full-tree", revision, "--", path]
    )
    if listed.returncode != 0:
        raise OSError("baseline Git tree oracle unavailable")
    if not listed.stdout:
        return None
    if listed.stdout != path.encode("utf-8") + b"\0":
        raise OSError("baseline Git tree oracle returned ambiguous membership")
    blob = _git_result(["show", f"{revision}:{path}"])
    if blob.returncode != 0:
        raise OSError("baseline Git blob oracle unavailable")
    return blob.stdout


def _read_base_text(base_ref: str, path: str) -> bytes | None:
    """Resolve local/remote base once; absent path is distinct from unreadable Git."""
    return _read_git_optional(_resolve_base_ref(base_ref), path)


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


def _read_optional_bytes(path: Path) -> bytes | None:
    return path.read_bytes() if path.exists() else None


def _read_base_checksum(base_ref: str, path: str) -> bytes | None:
    """Read historical seal bytes without decoding even a malformed old seal.

    Only presence matters for removal/init checks; valid head bytes can repair
    arbitrary old contents. Mirror the base-ref fallback used for JSON input.
    """
    return _read_git_optional(_resolve_base_ref(base_ref), path)


def _validate_checksum(
    base: dict,
    head: dict,
    base_seal: bytes | None,
    head_seal: bytes | None,
    head_bytes: bytes,
    target: str,
    pr_title: str,
) -> tuple[bool, str]:
    """Validate integrity before any policy bypass; never open a parsed target.

    The companion authenticates baseline bytes only, not profiles or recording
    provenance. Until recording, missing BOTH companions is an explicit legacy
    transition; either snapshot key present ends that transition. A bad base
    companion may be repaired, but a present head companion is always checked.
    """
    if head_seal is None:
        if base_seal is not None:
            return False, "SHA-256 companion removed; no bypass permitted"
        if any(
            d.get(key) is not None for d in (base, head) for key in PROTECTED_BLOCKS
        ):
            return False, "recorded baseline requires a SHA-256 companion"
        return True, "unrecorded transition: both SHA-256 companions absent"

    # Accept the standard text or binary sha256sum line, and nothing else:
    # no extra targets, blank/duplicate lines, whitespace prefixes or escapes.
    pattern = rb"([0-9a-f]{64}) [ *]" + re.escape(target.encode("utf-8")) + rb"\n?"
    match = re.fullmatch(pattern, head_seal)
    if match is None:
        return (
            False,
            "malformed SHA-256 companion or wrong target; expected one canonical target line",
        )
    expected = hashlib.sha256(head_bytes).hexdigest().encode("ascii")
    if match.group(1) != expected:
        return False, "SHA-256 companion mismatch for exact head baseline bytes"
    if base_seal is None and not INIT_TAG_RE.search(pr_title):
        return False, "first SHA-256 companion requires [init-baselines]"
    return True, "SHA-256 companion matches exact head baseline bytes"


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
        "--base-checksum-content",
        type=Path,
        default=None,
        help="Private fixture companion; requires both content overrides.",
    )
    p.add_argument(
        "--head-checksum-content",
        type=Path,
        default=None,
        help="Private fixture companion; requires both content overrides.",
    )
    p.add_argument(
        "--repo-relative-path",
        type=str,
        default="coc-eval/baselines.json",
    )
    args = p.parse_args(argv)

    fixture_mode = args.base_content is not None and args.head_content is not None
    if (args.base_content is None) != (args.head_content is None) or (
        not fixture_mode and (args.base_checksum_content or args.head_checksum_content)
    ):
        sys.stderr.write(
            "error: fixture overrides require both --base-content and --head-content\n"
        )
        return EXIT_MISCONFIG
    try:
        if fixture_mode:
            # Missing adjacent fixture seals mean absent; NEVER read canonical
            # seals when baseline content is overridden by a private fixture.
            base_bytes = _read_optional_bytes(args.base_content)
            head_bytes = _read_optional_bytes(args.head_content)
            base_text = base_bytes if base_bytes and base_bytes.strip() else None
            head_text = head_bytes if head_bytes and head_bytes.strip() else None
            base_seal = _read_optional_bytes(
                args.base_checksum_content
                or args.base_content.with_name(args.base_content.name + ".sha256")
            )
            head_seal = _read_optional_bytes(
                args.head_checksum_content
                or args.head_content.with_name(args.head_content.name + ".sha256")
            )
        else:
            # Both historical files use ONE resolved commit, even if refs move.
            revision = _resolve_base_ref(args.base_ref)
            base_text = _read_git_optional(revision, args.repo_relative_path)
            head_text = _read_optional_bytes(REPO_ROOT / args.repo_relative_path)
            base_seal = _read_git_optional(
                revision, args.repo_relative_path + ".sha256"
            )
            head_seal = _read_optional_bytes(
                REPO_ROOT / (args.repo_relative_path + ".sha256")
            )
    except OSError as exc:
        sys.stderr.write(f"error: cannot read baseline/checksum inputs: {exc}\n")
        return EXIT_MISCONFIG

    if head_text is None:
        sys.stderr.write(
            f"error: {args.repo_relative_path} removed entirely; fail-closed "
            "(see check-baselines-immutability.py mode 'c').\n"
        )
        return EXIT_VIOLATION

    try:
        head = json.loads(head_text)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.stderr.write(f"error: head {args.repo_relative_path}: invalid JSON: {e}\n")
        return EXIT_MISCONFIG

    try:
        base = json.loads(base_text) if base_text and base_text.strip() else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        sys.stderr.write(
            f"error: base {args.repo_relative_path}: invalid JSON: {exc}\n"
        )
        return EXIT_MISCONFIG
    if not isinstance(base, dict) or not isinstance(head, dict):
        sys.stderr.write("error: baseline top level must be an object\n")
        return EXIT_MISCONFIG
    checksum_ok, checksum_message = _validate_checksum(
        base,
        head,
        base_seal,
        head_seal,
        head_text,
        args.repo_relative_path,
        args.pr_title,
    )
    if not checksum_ok:
        sys.stderr.write(f"error: {checksum_message}\n")
        return EXIT_VIOLATION
    sys.stdout.write(f"OK: {checksum_message}\n")

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
