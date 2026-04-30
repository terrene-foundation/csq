"""sys.addaudithook tripwire for credential-file reads (R1-HIGH-07).

DEFENSE-IN-DEPTH ONLY. The primary defense for credential isolation
in the implementation suite is the process-level sandbox (sandbox-exec
on macOS, bwrap on Linux). The audit hook is a SECONDARY tripwire
that catches accidental credential reads from the harness's OWN
Python process — for example, a future regression in a helper that
reads `.credentials.json` to "verify auth" before passing it to cc.

Scope:
- The hook fires on `open` audit events from the harness Python
  process. It does NOT see syscalls performed by cc (or any
  subprocess) — that's what the sandbox is for.
- The hook is `install`-once-per-process. Repeated installs are
  idempotent (sys.addaudithook supports duplicate installs but the
  module guards against it for clarity).
- Detection raises a `CredentialAuditViolation` so callers can choose
  to convert to test failure or log + continue. The default
  `arm_for_implementation_run()` raises.

Usage:

    from coc_eval.lib import credential_audit
    credential_audit.arm_for_implementation_run()
    # ... run implementation suite ...
    # If any harness code calls open("/Users/.../.credentials.json"),
    # CredentialAuditViolation is raised at that open call.

The list of canonical credential paths is intentionally short and
explicit — adding paths is a deliberate change requiring an in-PR
discussion (more paths = more false positives).

Cross-references:
- Plan §H7 R1-HIGH-07: credential audit ongoing.
- Spec 08 §"Audit-hook scope" (added in H7).
- `coc-eval/lib/canary.py` (the canary file paths the hook also
  defends).
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any, Iterable

# Canonical credential-shaped path suffixes the hook flags. Anchored at
# end-of-string to keep matching cheap. `~/.claude/.credentials.json` is
# the cc credential; the others are sibling agent-credential conventions
# we deliberately isolate per spec 08.
_GUARDED_PATH_SUFFIXES: tuple[str, ...] = (
    "/.claude/.credentials.json",
    "/.claude/accounts/credentials.json",
    "/.config/claude/.credentials.json",  # XDG layout (B-MED-2)
    "/.local/share/claude/.credentials.json",  # XDG layout (B-MED-2)
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/id_ecdsa",
    "/.aws/credentials",
    "/.codex/credentials.json",
    "/.gemini/credentials.json",
    "/.gnupg/private-keys-v1.d",
    # Cross-CLI credential vectors cc could shell out to (B-MED-2):
    "/.config/gh/hosts.yml",
    "/.netrc",
    "/.pgpass",
    "/.docker/config.json",
    "/.kube/config",
    "/.npmrc",
    "/.pypirc",
)

# Per-process guard. `sys.addaudithook` accepts duplicate installs but
# we want install-once for clarity (no duplicate violations on a single
# read). Threading lock handles the unlikely concurrent install path.
_install_lock = threading.Lock()
_installed: bool = False
_armed_paths: set[str] = set()


class CredentialAuditViolation(RuntimeError):
    """Raised when the audit hook observes a credential-shaped open()."""


def _suffix_match(path: str, suffixes: Iterable[str]) -> str | None:
    """Return the matching suffix, or None.

    `path` is normalized via `os.path.normpath` to collapse `..` and
    duplicate slashes before suffix-matching. We intentionally do NOT
    `realpath` (would follow symlinks and may surface a different
    path than what the caller passed) — sufix on `normpath` is the
    minimum-surprise behavior.
    """
    if not isinstance(path, str):
        return None
    norm = os.path.normpath(path)
    for sfx in suffixes:
        if norm.endswith(sfx):
            return sfx
    return None


def _hook(event: str, args: tuple[Any, ...]) -> None:
    """Audit-hook callback. Bound by `arm_for_implementation_run`.

    `sys.audit` events of interest:
        "open"         — args = (path, mode, flags). path is str | bytes | int.

    Bytes paths are decoded with errors='replace' before suffix match;
    int paths (already-open fds) are ignored — the hook fires earlier
    on the original `open()` that produced the fd.

    R1-B-HIGH-5: snapshot `_armed_paths` under the install-lock at
    hook entry. CPython makes single-set ops atomic but iterating a
    set under concurrent `set.add` raises `RuntimeError: Set changed
    size during iteration`, which `sys.audit` propagates out of the
    triggering `open()` and crashes unrelated harness code.
    """
    if event != "open":
        return
    if not args:
        return
    # H10 round-1 followup: respect the install-once flag so
    # `disarm_for_tests()` actually disarms within a single Python
    # process. `sys.addaudithook` cannot be removed, but checking
    # `_installed` here lets cross-test-file isolation work.
    if not _installed:
        return
    raw_path = args[0]
    if isinstance(raw_path, bytes):
        # `errors='replace'` cannot raise — guaranteed to return a str. Pyright
        # would warn on a try/except wrapper here as unreachable.
        path = raw_path.decode("utf-8", errors="replace")
    elif isinstance(raw_path, str):
        path = raw_path
    else:
        # int file descriptor or other types — already-open. Skip.
        return
    # B-HIGH-5: snapshot armed extras under the lock so iteration is
    # safe against concurrent arm_for_implementation_run() calls.
    with _install_lock:
        armed_snapshot = tuple(_armed_paths)
    suffix = _suffix_match(path, _GUARDED_PATH_SUFFIXES) or _suffix_match(
        path, armed_snapshot
    )
    if suffix is None:
        return
    raise CredentialAuditViolation(
        f"credential-audit tripwire: harness process called open() on "
        f"a guarded path: {path!r} (matched suffix {suffix!r})"
    )


def arm_for_implementation_run(extra_paths: Iterable[str] = ()) -> None:
    """Install the audit hook (idempotent) and register extra path suffixes.

    Args:
        extra_paths: Additional path suffixes to flag (e.g. canary-fixture
            credential paths). Suffixes are stored verbatim — callers are
            responsible for prefixing with `/`.

    Idempotent across calls in the same process. Adding more
    `extra_paths` on a later call appends to the armed set; existing
    suffixes stay armed.
    """
    global _installed
    with _install_lock:
        for p in extra_paths:
            if isinstance(p, str) and p:
                _armed_paths.add(p)
        if _installed:
            return
        sys.addaudithook(_hook)
        _installed = True


def is_installed() -> bool:
    """Return whether the hook has been armed in this process."""
    return _installed


def armed_extra_paths() -> tuple[str, ...]:
    """Snapshot of currently armed extra-path suffixes (for tests)."""
    return tuple(sorted(_armed_paths))


def disarm_for_tests() -> None:
    """Test-only: clear armed extras + reset install flag.

    sys.addaudithook cannot be uninstalled — once added, the callback
    runs for the lifetime of the interpreter. This helper resets the
    module's bookkeeping so unit tests can re-exercise install-once
    semantics without spawning a subprocess. The actual `_hook` stays
    bound; the flag flip is safe because the function checks the
    install-time path-set state at fire time.
    """
    global _installed
    with _install_lock:
        _armed_paths.clear()
        _installed = False


def is_path_guarded(path: str) -> bool:
    """Return True if `path` matches any guarded suffix.

    Public helper for tests and for callers that want to assert the
    hook would fire on a given path WITHOUT actually calling `open()`.
    Snapshots `_armed_paths` under the lock for the same race-safety
    reason as `_hook` (B-HIGH-5).
    """
    if _suffix_match(path, _GUARDED_PATH_SUFFIXES) is not None:
        return True
    with _install_lock:
        armed_snapshot = tuple(_armed_paths)
    return _suffix_match(path, armed_snapshot) is not None


def guarded_suffixes() -> tuple[str, ...]:
    """Return the canonical guarded-path suffixes (for spec/audit reference)."""
    return _GUARDED_PATH_SUFFIXES


# `Path` import retained for type-hint hygiene; some callers will pass
# `Path` objects to `is_path_guarded` via str(path). Keep the import to
# document the expected caller shape.
_ = Path
