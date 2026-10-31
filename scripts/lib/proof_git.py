"""Lazy pinned Git with process-owned empty configuration and scrubbed inputs.

The Git HOME lease is process-scoped, created on first use, and disposed by an
atexit callback on normal interpreter exit. SIGKILL cannot run this cleanup.
"""
import atexit
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading

from proof_types import ProofUnavailable


SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_LOCK = threading.RLock()
_HOME_LEASE = None
_GIT = None


def _cleanup_home(lease):
    try:
        lease.cleanup()
    finally:
        lease.close()


def _private_home():
    global _HOME_LEASE
    with _LOCK:
        if _HOME_LEASE is None:
            # Lazy import avoids import-time discovery or a helper-load cycle.
            # Cargo target discovery is topology metadata, not Git global config.
            from proof_paths import OwnedLeg, cargo_target_roots
            root = Path.cwd().resolve()
            lease = OwnedLeg.create(root, cargo_target_roots(root),
                                     parent="/tmp", prefix="csq-proof-git-")
            atexit.register(_cleanup_home, lease)
            _HOME_LEASE = lease
        _HOME_LEASE.identity
        return str(_HOME_LEASE.path)


def git_environment(inherited=None, *, index_file=None):
    """Only explicit Git index authority survives; configuration is private."""
    values = os.environ if inherited is None else inherited
    if not hasattr(values, "items"):
        raise ProofUnavailable("Git environment metadata is unavailable")
    denied = {"DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS"}
    env = {key: value for key, value in values.items()
           if isinstance(key, str) and key.upper() not in denied
           and not key.upper().startswith(("GIT_", "LD_", "DYLD_"))}
    home = _private_home()
    env.update(PATH=SAFE_PATH, HOME=home, XDG_CONFIG_HOME=home,
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    if index_file is not None:
        try:
            index = Path(index_file)
            if not index.is_absolute() or index.is_symlink():
                raise ProofUnavailable("Git index must be an explicit absolute private file")
            env["GIT_INDEX_FILE"] = str(index)
        except (TypeError, ValueError, OSError):
            raise ProofUnavailable("Git index metadata is unavailable") from None
    return env


def _vetted_executable(name):
    try:
        path = Path(name)
        if not path.is_absolute():
            raise ProofUnavailable("Git executable path is not absolute")
        path = path.resolve(strict=True)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            raise ProofUnavailable("Git executable is unavailable")
        for component in (path, *path.parents):
            metadata = component.stat()
            if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                clauses = []
                if metadata.st_uid != 0:
                    clauses.append("not_root_owned")
                if metadata.st_mode & stat.S_IWGRP:
                    clauses.append("group_writable")
                if metadata.st_mode & stat.S_IWOTH:
                    clauses.append("world_writable")
                raise ProofUnavailable(json.dumps(
                    {"kind": "git_executable_path_refused", "path": str(component),
                     "clauses": clauses}, sort_keys=True))
        return str(path)
    except (OSError, ValueError, RuntimeError) as error:
        if isinstance(error, ProofUnavailable):
            raise
        raise ProofUnavailable("trusted absolute Git executable is unavailable") from None


def _trusted_git():
    global _GIT
    with _LOCK:
        if _GIT is not None:
            return _GIT
        env = git_environment()
        try:
            if sys.platform == "darwin":
                xcrun = _vetted_executable("/usr/bin/xcrun")
                result = subprocess.run([xcrun, "--find", "git"], env=env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, timeout=30)
                if result.returncode != 0:
                    raise ProofUnavailable("Darwin real Git resolution is unavailable")
                candidate = _vetted_executable(result.stdout.strip())
                if candidate == _vetted_executable("/usr/bin/git"):
                    raise ProofUnavailable("Darwin Git resolution returned the developer trampoline")
            else:
                candidate = _vetted_executable("/usr/bin/git")
            version = subprocess.run([candidate, "--version"], env=env,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, timeout=30)
            match = re.fullmatch(r"git version ([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?: [^\n]+)?\n?",
                                 version.stdout)
            if version.returncode != 0 or match is None or tuple(map(int, match.groups())) < (2, 32):
                raise ProofUnavailable("Git version 2.32 or newer is required")
            _GIT = candidate
            return candidate
        except (OSError, subprocess.SubprocessError):
            raise ProofUnavailable("trusted Git resolution or version probe is unavailable") from None


def git_argv(*args):
    """Build an argv for the lazily resolved, version-checked executable."""
    try:
        values = [os.fspath(arg) for arg in args]
    except TypeError:
        raise ProofUnavailable("Git argument metadata is unavailable") from None
    if any(not isinstance(value, str) or "\x00" in value for value in values):
        raise ProofUnavailable("Git arguments must be strings without NUL")
    return [_trusted_git(), "-c", "core.excludesFile=/dev/null",
            "-c", "core.attributesFile=/dev/null", "-c", "core.hooksPath=/dev/null", *values]
