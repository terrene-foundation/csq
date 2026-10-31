"""Refuse imports until a finalized, hash-bound canonical helper bundle exists."""
from pathlib import Path
import hashlib
import json
import re
import sys
import types

HELPER_FILES = ("proof_types.py", "proof_git.py", "proof_paths.py", "proof_mutations.py",
                "proof_inventory.py", "proof_support.py")
RUNTIME_ALIASES = {"proof_bootstrap.py": "proof_bootstrap.py",
                   "proof_stdout.py": "stdout_transport.py",
                   "proof_bundle.py": "_support_binding.py",
                   "deadline_run.py": "deadline_run.py"}


def _runtime_files(hashes):
    if not isinstance(hashes, dict) or not set(RUNTIME_ALIASES).issubset(hashes):
        raise RuntimeError("canonical runtime binding is incomplete")
    runtime = dict(RUNTIME_ALIASES)
    reserved = set(HELPER_FILES) | set(RUNTIME_ALIASES) | set(RUNTIME_ALIASES.values())
    for name, digest in hashes.items():
        if (not isinstance(name, str) or not isinstance(digest, str)
                or re.fullmatch(r"[a-f0-9]{64}", digest) is None):
            raise RuntimeError("canonical runtime identity is invalid")
        if name not in RUNTIME_ALIASES:
            if name in reserved or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", name) is None:
                raise RuntimeError("additional runtime name collides or is unsafe")
            runtime[name] = name
    if len(set(runtime.values())) != len(runtime):
        raise RuntimeError("canonical runtime aliases collide")
    return runtime

HERE = Path(__file__).resolve().parent
BINDING = HERE / "SUPPORT-BINDING.json"
if not BINDING.is_file() or BINDING.is_symlink():
    raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: canonical helper bundle is not finalized")
try:
    metadata = json.loads(BINDING.read_text())
except Exception:
    raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: helper binding JSON is unavailable") from None
if not isinstance(metadata, dict) or metadata.get("state") != "FINALIZED_REVIEW_REQUIRED":
    raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: unsupported helper binding state")
if not isinstance(metadata.get("hashes"), dict) or set(metadata["hashes"]) != set(HELPER_FILES):
    raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: incomplete helper binding")
runtime = _runtime_files(metadata.get("runtime_hashes"))
permitted = {"manifest.json", "SUPPORT-BINDING.json"} | set(runtime.values())
permitted.update("support/" + name for name in HELPER_FILES)
actual = set()
for path in HERE.iterdir():
    if path.name == "support" and path.is_dir() and not path.is_symlink():
        for helper in path.iterdir():
            if not helper.is_file() or helper.is_symlink():
                raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: unsupported support entry")
            actual.add("support/" + helper.name)
    elif path.is_file() and not path.is_symlink():
        actual.add(path.name)
    else:
        raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: unsupported payload entry")
if actual != permitted:
    raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: missing or unbound payload files")
for name, alias in runtime.items():
    path = HERE / alias
    if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["runtime_hashes"][name]:
        raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: canonical runtime bytes changed")
verified = {}
for name, digest in metadata["hashes"].items():
    path = HERE / "support" / name
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: canonical helper bytes changed")
    verified[name] = raw
for name in HELPER_FILES:
    loaded = sys.modules.get(name[:-3])
    if loaded is not None and Path(loaded.__file__).resolve() != HERE / "support" / name:
        raise RuntimeError("NOTDISPATCHABLE_UNVERIFIED: another helper installation is already loaded")
sys.path.append(str(HERE / "support"))
# Compile the already verified bytes instead of selecting an earlier module
# from sys.path. Dependencies are loaded before their consumers.
for name in HELPER_FILES:
    path = HERE / "support" / name
    module = types.ModuleType(name[:-3])
    module.__file__ = str(path)
    sys.modules[name[:-3]] = module
    exec(compile(verified[name], str(path), "exec"), module.__dict__)
from proof_support import (OwnedLeg, ProofUnavailable, applied_edits, cargo_target_roots,
                           evaluate_runtime, make_inventory, materialized_tree,
                           preflight_manifest, private_environment, render_manifest,
                           support_hashes)
