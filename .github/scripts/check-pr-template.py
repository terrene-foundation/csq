#!/usr/bin/env python3
"""Validate PR body content density for capability-layer-touching PRs.

Stdlib-only per ``rules/independence.md`` Rule 3. Invoked by
``.github/workflows/csq-pr-template-check.yml`` (plan task T26) on every
PR. Reads the PR body + file diff via ``gh pr view --json``; if any
touched path matches the capability-layer regex, both ``## Harness
delta`` and ``## Latency bench delta`` sections must contain ≥ 50 chars
of non-skeleton content (or ``N/A — <reason>`` ≥ 20 chars).

Origin: PR-CA9 plan task T26 (R2/B35 + R2/B36 + R2/B37 + T16.3).

Usage::

    python3 .github/scripts/check-pr-template.py [--pr-number N]
    # OR for offline tests:
    python3 .github/scripts/check-pr-template.py \\
        --body-file body.md --files-file files.txt

Exit codes:
    0   Conformant (or non-capability PR — gate doesn't apply)
    1   Section missing or content-density violation
    64  Misconfiguration (gh CLI absent, malformed JSON)
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

CAPABILITY_PATH_PATTERNS = [
    r"^csq-core/src/coc/",
    r"^csq-core/src/capability_layer/",
    r"^csq-core/src/audit/",
    r"^csq-core/src/providers/[^/]+/probe\.rs$",
    r"^csq/src/cli/commands/run\.rs$",
    r"^coc-eval/bench/",
    r"^coc-eval/baselines\.json$",
    r"^coc-eval/tests/",
    r"^specs/09-",
    r"^specs/10-",
    r"^csq-core/src/daemon/coc_cache_sweeper\.rs$",
]

REQUIRED_SECTIONS = ("## Harness delta", "## Latency bench delta")
MIN_CONTENT_CHARS = 50
MIN_NA_CHARS = 20

_NA_PATTERN = re.compile(r"^\s*N/A\s*[—\-:]\s*(.+)$", re.IGNORECASE)
_SKELETON_LINE = re.compile(r"^[\s\|\-—]*$")


def _matches_capability(paths: list[str]) -> bool:
    for path in paths:
        for pat in CAPABILITY_PATH_PATTERNS:
            if re.search(pat, path):
                return True
    return False


def _extract_section_body(body: str, header: str) -> str:
    """Return the text between the named header and the next ##-level header.

    Strips HTML comments (`<!-- ... -->`) and table skeleton rows. The
    remaining content density is what the gate measures.
    """
    lines = body.splitlines()
    capture = False
    out: list[str] = []
    for ln in lines:
        if ln.startswith(header):
            capture = True
            continue
        if capture and ln.startswith("## "):
            break
        if capture:
            out.append(ln)
    text = "\n".join(out)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    return text


def _density_chars(section_body: str) -> int:
    """Return the count of non-whitespace, non-skeleton characters."""
    keep_lines: list[str] = []
    for ln in section_body.splitlines():
        if _SKELETON_LINE.match(ln):
            continue
        if (
            "---" in ln
            and ln.strip().replace("|", "").replace("-", "").replace(" ", "") == ""
        ):
            continue
        keep_lines.append(ln.strip())
    text = " ".join(keep_lines)
    return len(re.sub(r"\s+", "", text))


def _has_skeleton_row(section_body: str) -> bool:
    """Detect the literal skeleton row (`| — | — | ...`) signalling unfilled."""
    for ln in section_body.splitlines():
        s = ln.strip()
        cells = [c.strip() for c in s.strip("|").split("|") if c.strip()]
        if len(cells) >= 3 and all(
            c in ("—", "-", "_", "TBD", "TODO", "?") for c in cells
        ):
            return True
    return False


def _validate_section(body: str, header: str) -> tuple[bool, str]:
    section = _extract_section_body(body, header)
    if not section.strip():
        return (False, f"missing or empty section {header}")

    for line in section.splitlines():
        m = _NA_PATTERN.match(line.strip())
        if m:
            reason = m.group(1).strip()
            full = line.strip()
            if len(full) < MIN_NA_CHARS:
                return (
                    False,
                    f"{header}: 'N/A — <reason>' must be ≥ {MIN_NA_CHARS} chars",
                )
            if len(reason) < 5:
                return (False, f"{header}: N/A reason too short ({reason!r})")
            return (True, "N/A explained")

    chars = _density_chars(section)
    if _has_skeleton_row(section):
        return (
            False,
            f"{header}: contains the literal skeleton row (— — —) — fill it in or write N/A",
        )
    if chars < MIN_CONTENT_CHARS:
        return (
            False,
            f"{header}: only {chars} chars of content; need ≥ {MIN_CONTENT_CHARS} or 'N/A — <reason>'",
        )
    return (True, "ok")


def _gh_pr_view(pr_number: int | None) -> tuple[str, list[str]]:
    cmd = ["gh", "pr", "view"]
    if pr_number is not None:
        cmd.append(str(pr_number))
    cmd.extend(["--json", "body,files"])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=30
        )
    except (FileNotFoundError, OSError) as e:
        sys.stderr.write(f"error: gh CLI not available: {e}\n")
        sys.exit(EXIT_MISCONFIG)
    if result.returncode != 0:
        sys.stderr.write(f"error: gh pr view failed: {result.stderr}\n")
        sys.exit(EXIT_MISCONFIG)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"error: gh pr view JSON malformed: {e}\n")
        sys.exit(EXIT_MISCONFIG)
    body = str(data.get("body") or "")
    paths = [f["path"] for f in data.get("files") or []]
    return body, paths


def _read_offline(body_file: Path, files_file: Path) -> tuple[str, list[str]]:
    body = body_file.read_text() if body_file.exists() else ""
    paths = []
    if files_file.exists():
        paths = [ln.strip() for ln in files_file.read_text().splitlines() if ln.strip()]
    return body, paths


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--pr-number", type=int, default=None)
    p.add_argument("--body-file", type=Path, default=None)
    p.add_argument("--files-file", type=Path, default=None)
    args = p.parse_args(argv)

    if args.body_file is not None and args.files_file is not None:
        body, paths = _read_offline(args.body_file, args.files_file)
    else:
        body, paths = _gh_pr_view(args.pr_number)

    if not _matches_capability(paths):
        sys.stdout.write(
            "OK: no capability-layer paths touched; PR-template gate skipped.\n"
        )
        return EXIT_OK

    errors: list[str] = []
    for header in REQUIRED_SECTIONS:
        ok, msg = _validate_section(body, header)
        if not ok:
            errors.append(msg)

    if errors:
        sys.stderr.write("PR template gate failed:\n")
        for e in errors:
            sys.stderr.write(f"  - {e}\n")
        sys.stderr.write(
            f"\nThe PR touches capability-layer paths; both '## Harness delta' "
            f"and '## Latency bench delta' must contain ≥ {MIN_CONTENT_CHARS} chars "
            f"of content OR 'N/A — <reason>' (≥ {MIN_NA_CHARS} chars).\n"
        )
        return EXIT_VIOLATION

    sys.stdout.write(
        "OK: capability-layer PR — both required sections have sufficient content.\n"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
