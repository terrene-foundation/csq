"""Per-CLI authentication probe (INV-AUTH-3, real probe replacing mtime heuristic).

The probe runs an actual short CLI invocation rather than checking credential
file mtimes, because mtime checks miss expired tokens (R1-MED-02). For cc:

    claude --print --permission-mode plan "ping"

with a 10s timeout. Exit 0 → ok; non-zero or timeout → ok=False with reason.

Caching (INV-AUTH-1, INV-AUTH-3):
    Probe results are cached per `(cli, suite)`. Re-probe before each suite
    begins. Mid-run `401|invalid_grant|expired_token` stderr triggers a
    re-probe via `mark_auth_changed(cli)`, which clears that CLI's cache.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Mapping

from .launcher import AuthProbeResult
from .redact import redact_tokens

# Per-(cli, suite) cache. Cleared by `mark_auth_changed(cli)` on mid-run
# auth-state changes (INV-AUTH-3). Module-level dict is acceptable because
# Phase 1 is concurrency=1 (INV-RUN-6).
_AUTH_CACHE: dict[tuple[str, str], AuthProbeResult] = {}

# Probe wall-clock budget. Tuned to be generous enough for a slow-network
# token validation round-trip but short enough that a hung CLI does not
# wedge a suite invocation.
_PROBE_TIMEOUT_SEC: float = 10.0
_VERSION_TIMEOUT_SEC: float = 5.0

# H10 R1-MED-1: codex `exec ping` round-trips through ChatGPT API.
# Cold-start + model-load on a slow link can exceed 10s, especially
# on first use of the day. Raised to 20s for codex specifically; cc
# stays at 10s (well-tuned local-network OAuth refresh path).
_CODEX_PROBE_TIMEOUT_SEC: float = 20.0

# Mid-run stderr lines containing any of these substrings invalidate the
# auth cache (caller scans stderr line-by-line via `is_auth_error_line`).
# H10 R1-HIGH-2: codex patterns tightened. Bare `"unauthorized"` would
# false-positive on legitimate model output discussing auth (e.g. a
# model explanation containing the word). Anchor each codex pattern
# to an HTTP-style or error-shape context so prose mentions don't
# trigger a cache flush + re-probe.
_AUTH_ERROR_PATTERNS: tuple[str, ...] = (
    "401",
    "invalid_grant",
    "expired_token",
    "401 Unauthorized",
    "Error: Token expired",
    "error: Token expired",
    "Please sign in to ChatGPT",
    "codex login required",
)


def probe_auth(
    cli: str,
    suite: str,
    env: Mapping[str, str] | None = None,
) -> AuthProbeResult:
    """Probe authentication for `cli`, caching per `(cli, suite)`.

    Args:
        cli: CLI id ("cc" supported in H3; "codex"/"gemini" land in H10/H11).
        suite: Suite name. Used as a cache scope so that re-probing before
            each suite (INV-AUTH-3) returns a fresh result per suite.
        env: Optional env mapping for the probe subprocess. Callers running
            against a stub-HOME pass `{"CLAUDE_CONFIG_DIR": str(stub_home),
            "HOME": str(home_root), "PATH": "..."}`.

    Returns:
        AuthProbeResult with `ok` indicating whether the probe succeeded.
        `reason` carries a short failure message on `ok=False`.
    """
    cache_key = (cli, suite)
    cached = _AUTH_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if cli == "cc":
        result = _probe_cc(env)
    elif cli == "codex":
        result = _probe_codex(env)
    else:
        result = AuthProbeResult(
            ok=False,
            reason=f"no probe registered for cli={cli!r} (H11 adds gemini)",
            version="",
            probed_at=time.monotonic(),
        )
    _AUTH_CACHE[cache_key] = result
    return result


def mark_auth_changed(cli: str) -> None:
    """Invalidate cached probe results for `cli` (INV-AUTH-3 mid-run signal).

    Call this on stderr lines matching `is_auth_error_line()`. Subsequent
    `probe_auth(cli, ...)` re-probes for every suite scope.
    """
    keys_to_drop = [k for k in _AUTH_CACHE if k[0] == cli]
    for k in keys_to_drop:
        _AUTH_CACHE.pop(k, None)


def is_auth_error_line(line: str) -> bool:
    """Return True if `line` looks like an INV-AUTH-3 mid-run auth-changed trigger."""
    return any(pat in line for pat in _AUTH_ERROR_PATTERNS)


def reset_cache() -> None:
    """Clear the entire probe cache. Test-only entry point."""
    _AUTH_CACHE.clear()


def _probe_cc(env: Mapping[str, str] | None) -> AuthProbeResult:
    """Real cc probe: `claude --version` for version capture, then
    `claude --print --permission-mode plan ping` for auth validation.
    """
    binary = shutil.which("claude")
    if binary is None:
        return AuthProbeResult(
            ok=False,
            reason="claude binary not found on PATH",
            version="",
            probed_at=time.monotonic(),
        )

    # Build a single env shape used by BOTH the version capture and the
    # auth probe (L1 from H3 review). Distinguishing inheritance behavior
    # by call site was a contract footgun — both subprocess invocations
    # now run under the same env.
    probe_env: dict[str, str] | None
    if env is None:
        # Inherit caller's env so PATH and home env survive.
        probe_env = None
    else:
        probe_env = dict(env)
        # subprocess won't resolve binaries without PATH; if caller forgot it,
        # backfill from the current process so the spawn can find `claude`.
        probe_env.setdefault("PATH", os.environ.get("PATH", ""))

    # Capture version cheaply (no auth required). Failures here do not
    # short-circuit the probe — version is best-effort metadata.
    version = ""
    try:
        v = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SEC,
            env=probe_env,
            check=False,
        )
        if v.returncode == 0:
            version = v.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass

    try:
        result = subprocess.run(
            [binary, "--print", "--permission-mode", "plan", "ping"],
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SEC,
            env=probe_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return AuthProbeResult(
            ok=False,
            reason=f"probe timed out after {_PROBE_TIMEOUT_SEC:.0f}s",
            version=version,
            probed_at=time.monotonic(),
        )
    except OSError as e:
        return AuthProbeResult(
            ok=False,
            reason=f"probe spawn failed: {e}",
            version=version,
            probed_at=time.monotonic(),
        )

    if result.returncode == 0:
        return AuthProbeResult(
            ok=True,
            reason=None,
            version=version,
            probed_at=time.monotonic(),
        )

    # Failure path: capture a short stderr snippet. Defense-in-depth:
    # redact at the source rather than relying on a downstream JSONL writer
    # to apply `redact_tokens`. OAuth error bodies have been observed
    # echoing refresh-token prefixes inside `invalid_grant` responses
    # (journals 0007 + 0010) — the probe MUST NOT carry an unredacted token
    # in `AuthProbeResult.reason` even briefly.
    stderr_text = (result.stderr or "").strip()
    raw = stderr_text[:500] if stderr_text else f"exit code {result.returncode}"
    reason = redact_tokens(raw)
    return AuthProbeResult(
        ok=False,
        reason=reason,
        version=version,
        probed_at=time.monotonic(),
    )


def _probe_codex(env: Mapping[str, str] | None) -> AuthProbeResult:
    """Real codex probe: `codex --version` for version capture, then
    `codex exec --sandbox read-only "ping"` for auth validation.

    Mirrors `_probe_cc`. codex's auth lives at `$CODEX_HOME/auth.json`
    (or `~/.codex/auth.json` if CODEX_HOME unset); the probe will
    surface auth failures via non-zero exit code + stderr containing
    the patterns in `_AUTH_ERROR_PATTERNS`.
    """
    binary = shutil.which("codex")
    if binary is None:
        return AuthProbeResult(
            ok=False,
            reason="codex binary not found on PATH",
            version="",
            probed_at=time.monotonic(),
        )

    probe_env: dict[str, str] | None
    if env is None:
        probe_env = None
    else:
        probe_env = dict(env)
        probe_env.setdefault("PATH", os.environ.get("PATH", ""))

    version = ""
    try:
        v = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SEC,
            env=probe_env,
            check=False,
        )
        if v.returncode == 0:
            version = v.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass

    try:
        result = subprocess.run(
            [binary, "exec", "--sandbox", "read-only", "ping"],
            capture_output=True,
            text=True,
            timeout=_CODEX_PROBE_TIMEOUT_SEC,
            env=probe_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return AuthProbeResult(
            ok=False,
            reason=f"probe timed out after {_CODEX_PROBE_TIMEOUT_SEC:.0f}s",
            version=version,
            probed_at=time.monotonic(),
        )
    except OSError as e:
        return AuthProbeResult(
            ok=False,
            reason=f"probe spawn failed: {e}",
            version=version,
            probed_at=time.monotonic(),
        )

    if result.returncode == 0:
        return AuthProbeResult(
            ok=True,
            reason=None,
            version=version,
            probed_at=time.monotonic(),
        )

    stderr_text = (result.stderr or "").strip()
    raw = stderr_text[:500] if stderr_text else f"exit code {result.returncode}"
    reason = redact_tokens(raw)
    return AuthProbeResult(
        ok=False,
        reason=reason,
        version=version,
        probed_at=time.monotonic(),
    )
