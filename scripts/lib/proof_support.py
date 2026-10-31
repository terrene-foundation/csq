"""Composition boundary for source-bound, external proof legs.

This module prepares instruments. It never dispatches a product command or
turns artifact transport success into a product verdict.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from proof_types import ProofUnavailable
from proof_mutations import applied_edits, render_edits, validate_edits
from proof_paths import OwnedLeg, assert_external, cargo_target_roots
from proof_inventory import evaluate_runtime, make_inventory
from proof_git import SAFE_PATH, git_argv, git_environment


CONTRACT = "csq.proof-support.v1"


def _manifest_header(value):
    if not isinstance(value, dict):
        raise ProofUnavailable("proof manifest must be an object")
    for key in ("commit", "tree"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[a-f0-9]{40}", value[key]):
            raise ProofUnavailable(f"proof manifest lacks a full frozen {key}")
    hashes = value.get("source_hashes")
    if not isinstance(hashes, dict) or not hashes:
        raise ProofUnavailable("proof manifest lacks its frozen source hash map")
    if not isinstance(value.get("cases"), list) or not value["cases"]:
        raise ProofUnavailable("proof manifest has no mutation cases")
    ids = set()
    for case in value["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"]:
            raise ProofUnavailable("proof case lacks a nonempty identity")
        if case["id"] in ids:
            raise ProofUnavailable("proof case identities are duplicated")
        ids.add(case["id"])
        if not isinstance(case.get("edits"), list) or not case["edits"]:
            raise ProofUnavailable("proof case lacks its edit selection")
        if any(not isinstance(edit, dict) for edit in case["edits"]):
            raise ProofUnavailable("proof edit must be an object")


def _git(root, *args, env=None, index_file=None):
    try:
        return subprocess.check_output(
            git_argv(*args), cwd=root, text=True, stderr=subprocess.PIPE,
            timeout=30, env=git_environment(env, index_file=index_file),
        ).strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise ProofUnavailable(f"Git source observation unavailable: {type(error).__name__}") from error


def source_guard(root, commit, tree):
    """Require the exact clean frozen checkout used by a proof leg."""
    if Path(root).resolve() != Path(_git(root, "rev-parse", "--show-toplevel")).resolve():
        raise ProofUnavailable("proof checkout is not the named repository root")
    if _git(root, "rev-parse", "HEAD") != commit:
        raise ProofUnavailable("proof checkout commit differs from frozen source")
    if _git(root, "rev-parse", "HEAD^{tree}") != tree:
        raise ProofUnavailable("proof checkout tree differs from frozen source")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ProofUnavailable("proof checkout contains undeclared source changes")
    return {"commit": commit, "tree": tree, "clean": True}


def materialized_tree(root, owned_leg):
    """Observe tracked working bytes through an external disposable Git index."""
    if not isinstance(owned_leg, OwnedLeg):
        raise ProofUnavailable("materialized tree requires a live owned index leg")
    parent = owned_leg.child("indexes")
    parent.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="index-", dir=parent) as directory:
        index = Path(directory) / "index"
        _git(root, "read-tree", "HEAD", index_file=index)
        _git(root, "add", "-u", "--", ".", index_file=index)
        return _git(root, "write-tree", index_file=index)


def render_manifest(root, raw_manifest):
    """Emit complete edit metadata from the caller's frozen full-file hashes."""
    _manifest_header(raw_manifest)
    final = deepcopy(raw_manifest)
    source_guard(root, final["commit"], final["tree"])
    for case in final["cases"]:
        case["edits"] = list(render_edits(root, case["edits"], final["source_hashes"]))
        validate_edits(root, case["edits"])
    final["proof_support_contract"] = CONTRACT
    return final


def preflight_manifest(root, final_manifest, *, owned_leg):
    """Apply and restore the actual emitted edits before any product work.

    The caller must supply its invocation-owned control checkout. Shipping
    source is never an acceptable mutation target.
    """
    if not isinstance(owned_leg, OwnedLeg) or Path(root).resolve() != owned_leg.child("source"):
        raise ProofUnavailable("preflight requires this invocation's owned control checkout")
    if not isinstance(final_manifest, dict) or final_manifest.get("proof_support_contract") != CONTRACT:
        raise ProofUnavailable("final manifest was not emitted through this proof contract")
    _manifest_header(final_manifest)
    commit, tree = final_manifest["commit"], final_manifest["tree"]
    source_guard(root, commit, tree)
    # Validate every final case before the first write, including hash equality
    # to the manifest frozen map. Never silently repair missing final metadata.
    cases = final_manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ProofUnavailable("final manifest contains no cases")
    for case in cases:
        validate_edits(root, case["edits"])
        for edit in case.get("edits", []):
            if edit.get("source_sha256") != final_manifest["source_hashes"].get(edit.get("file")):
                raise ProofUnavailable("final edit hash differs from manifest frozen map")
    rows = []
    for case in cases:
        with applied_edits(root, case["edits"], owned_leg=owned_leg):
            changed = _git(root, "diff", "--name-only").splitlines()
            if set(changed) != {edit["file"] for edit in case["edits"]}:
                raise ProofUnavailable("actual mutation changed unexpected tracked paths")
            actual_tree = materialized_tree(root, owned_leg)
            if "control_tree" in case and case["control_tree"] != actual_tree:
                raise ProofUnavailable("actual rendered mutation differs from frozen control tree")
            rows.append({"case": case["id"], "changed_files": changed,
                         "actual_control_tree": actual_tree})
        source_guard(root, commit, tree)
    return {"contract": CONTRACT, "state": "PREFLIGHT_COMPLETE_NOT_PRODUCT_PASS",
            "commit": commit, "tree": tree, "cases": rows, "restored": True}


@contextmanager
def external_control(source, commit, tree, *, target_roots, parent="/tmp"):
    """Create a frozen control checkout outside all declared Cargo targets."""
    source = Path(source).resolve()
    if any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value)
           for value in (commit, tree)):
        raise ProofUnavailable("control clone requires full frozen commit/tree identities")
    roots = tuple(target_roots)
    # Include source configuration as well as authoritative caller roots.
    roots = tuple(set(roots) | set(cargo_target_roots(source)))
    with OwnedLeg.create(source, roots, parent=parent, prefix="csq-proof-") as leg:
        control = assert_external(leg.child("source"), roots)
        try:
            subprocess.run(git_argv("clone", "--local", "--no-hardlinks", "--no-checkout",
                                   str(source), str(control)), check=True, env=git_environment(),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            subprocess.run(git_argv("checkout", "--detach", commit), cwd=control, env=git_environment(),
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            raise ProofUnavailable(f"control clone unavailable: {type(error).__name__}") from error
        source_guard(control, commit, tree)
        yield leg, control


def private_environment(leg, inherited):
    """Isolate environment state only from an actual cwd outside original HOME.

    Callers must change into their external leg before preparing or executing
    fixtures: replacing HOME does not stop Cargo's ancestor config discovery.
    """
    old_home = inherited.get("HOME")
    if not old_home:
        raise ProofUnavailable("toolchain home cannot be resolved without original HOME")
    try:
        # Reuse the inode-aware boundary, including canonical/case aliases.
        # Check the actual process cwd; a caller-supplied path is no authority.
        assert_external(Path.cwd(), (old_home,))
    except (ProofUnavailable, OSError, RuntimeError, TypeError, ValueError):
        raise ProofUnavailable("proof-environment: cwd is within original HOME or unverifiable") from None
    allowed = ("LANG", "LC_ALL", "TERM", "USER")
    env = {key: inherited[key] for key in allowed if key in inherited}
    for name in ("home", "tmp", "base", "cargo", "bin"):
        leg.child(name).mkdir(mode=0o700)
    # Only known toolchain installations may supply a proxy executable. Do not
    # follow inherited PATH, RUSTC_WRAPPER or arbitrary compiler overrides.
    candidates = [Path(old_home) / ".cargo/bin/rustup"]
    candidates += [Path(parent) / "rustup" for parent in SAFE_PATH.split(os.pathsep)]
    rustup = None
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.stat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid())
                    and not info.st_mode & 0o022 and os.access(resolved, os.X_OK)):
                rustup = resolved
                break
        except OSError:
            continue
    if rustup is not None:
        for name in ("rustup", "cargo", "rustc", "rustdoc", "rustfmt", "cargo-fmt",
                     "cargo-clippy", "clippy-driver"):
            leg.child(Path("bin") / name).symlink_to(rustup)
    env.update(HOME=str(leg.child("home")), TMPDIR=str(leg.child("tmp")),
               TMP=str(leg.child("tmp")), TEMP=str(leg.child("tmp")),
               CSQ_BASE_DIR=str(leg.child("base")),
               CARGO_HOME=str(leg.child("cargo")),
               RUSTUP_HOME=inherited.get("RUSTUP_HOME", str(Path(old_home) / ".rustup")),
               PATH=str(leg.child("bin")) + os.pathsep + SAFE_PATH,
               CSQ_SECRET_BACKEND="in-memory", CARGO_TERM_COLOR="never",
               CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1", CARGO_NET_OFFLINE="true")
    return env


def support_hashes():
    """Bind materialized adapters to the canonical helper bytes they execute."""
    directory = Path(__file__).parent
    names = ("proof_types.py", "proof_git.py", "proof_mutations.py", "proof_paths.py",
             "proof_inventory.py", "proof_support.py")
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in names}


def collect_native_runtime(listing, listing_rc, raw, actual_rc, binding,
                           required, allowed_ignored, *, observed_binding):
    """Compose a same-leg native inventory with its actual runtime observation."""
    try:
        inventory = make_inventory(listing, binding, required, allowed_ignored,
                                   actual_rc=listing_rc)
        return evaluate_runtime(raw, actual_rc, inventory, observed_binding)
    except ProofUnavailable as error:
        return {"state": "UNDETERMINED", "code": 2, "reason": str(error)}
