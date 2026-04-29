"""Run-id generator (R1-HIGH-04).

Format: `<iso8601-second>-<pid>-<counter>-<rand>`. Per
`workspaces/coc-harness-unification/01-analysis/06-jsonl-schema-v1.md`:

- `<iso8601-second>`: UTC, format `YYYY-MM-DDThh-mm-ssZ`. Hyphens (not
  colons) for filename safety on every platform.
- `<pid>`: `os.getpid()` decimal. Distinguishes concurrent harness
  invocations on the same host.
- `<counter>`: 4-digit zero-padded process-local `itertools.count()`.
  Distinguishes sub-second invocations within one process.
- `<rand>`: 8-char `secrets.token_urlsafe(6)`. Cryptographic random via
  `os.urandom`, not the lower-entropy `random` module.

Two harness invocations starting in the same wall-clock second produce
distinct run_ids (AC-11a). Acceptance test: spawn five generators in
parallel, assert all five values are distinct.
"""

from __future__ import annotations

import itertools
import os
import re
import secrets
from datetime import datetime, timezone

# Process-local counter. Module-level state — Phase 1 is concurrency=1
# (INV-RUN-6), so a single counter per process is sufficient. The PID +
# counter pair is the cross-process disambiguator.
_counter = itertools.count()

# Run-id components are carefully constrained to the alphabet that
# `secrets.token_urlsafe` produces (A-Z a-z 0-9 _ -) plus digits, `Z`,
# and `T` from the timestamp. The validator regex below pins this so
# downstream code (filesystem paths, HTTP query strings) can trust the
# shape.
RUN_ID_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-\d+-\d{4}-[A-Za-z0-9_-]{6,12}$"
)


def generate_run_id() -> str:
    """Return a fresh, deterministically-distinct run id.

    Returns:
        e.g. ``2026-04-29T10-15-22Z-12345-0001-AaBbCcDd``.
    """
    now = datetime.now(timezone.utc)
    iso_second = now.strftime("%Y-%m-%dT%H-%M-%SZ")
    pid = os.getpid()
    counter = next(_counter)
    rand = secrets.token_urlsafe(6)
    return f"{iso_second}-{pid}-{counter:04d}-{rand}"


def validate_run_id(run_id: object) -> None:
    """Reject a run id that does not match `RUN_ID_RE`.

    Used at JSONL writer entry: a malformed `run_id` MUST never become
    a directory name on disk (path-traversal hardening + filename safety).
    Accepts `object` so dynamic call sites (argparse, JSON-decoded args)
    that pass non-string values surface a clear error rather than a
    `TypeError` from `re.fullmatch`.
    """
    if type(run_id) is not str:
        raise ValueError(f"run_id must be a string, got {type(run_id).__name__}")
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError(f"run_id does not match RUN_ID_RE: {run_id!r}")
