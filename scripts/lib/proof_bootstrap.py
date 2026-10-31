"""Inline-only D2 bootstrap: hash-bound external leases, raw export, cleanup."""
import ast
import base64
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import types
from contextlib import contextmanager


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


def pack(files):
    """One exact byte-preserving packet builder shared with synthetic fixtures."""
    try:
        raw = json.dumps({"files": {name: base64.b64encode(data).decode()
                                  for name, data in files.items()}}, sort_keys=True).encode()
    except Exception:
        raise RuntimeError("bootstrap payload cannot be encoded") from None
    encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    return hashlib.sha256(raw).hexdigest(), [encoded[n:n + 12000] for n in range(0, len(encoded), 12000)]


def _load(name, raw, *, path=None):
    module = types.ModuleType(name)
    module.__file__ = str(path) if path is not None else "<hash-bound-" + name + ">"
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module



@contextmanager
def _extra_runtimes(runtime, files, instrument):
    """Load declared extras from verified bytes; restore prior module entries.

    Static intra-packet imports determine a deterministic order. Cycles are
    unsupported and refused. Dynamic dependencies are not inferred or ordered.
    No import hook or name-based fallback is installed by this loader.
    """
    extras = {Path(alias).stem: alias for name, alias in runtime.items()
              if name not in RUNTIME_ALIASES}
    dependencies = {}
    for name, alias in extras.items():
        imports = set()
        for node in ast.walk(ast.parse(files[alias], filename=str(instrument / alias))):
            if isinstance(node, ast.Import):
                imports.update(item.name.split(".")[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".")[0])
        dependencies[name] = (imports & extras.keys()) - {name}
    missing = object()
    previous = {name: sys.modules.get(name, missing) for name in extras}
    loaded = set()
    try:
        while loaded != extras.keys():
            ready = sorted(name for name in extras.keys() - loaded
                           if dependencies[name] <= loaded)
            if not ready:
                raise RuntimeError("bound extra runtime import cycle is unsupported")
            for name in ready:
                alias = extras[name]
                _load(name, files[alias], path=instrument / alias)
                loaded.add(name)
        yield
    finally:
        for name, module in previous.items():
            if module is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _object_json(raw, label):
    try:
        value = json.loads(raw)
    except Exception:
        raise RuntimeError("bootstrap " + label + " JSON is unavailable") from None
    if not isinstance(value, dict):
        raise RuntimeError("bootstrap " + label + " must be an object")
    return value


def _source(root, manifest):
    from proof_git import git_argv, git_environment

    def git(*args):
        return subprocess.check_output(git_argv(*args), cwd=root, text=True,
                                       env=git_environment(), stderr=subprocess.PIPE,
                                       timeout=30).strip()
    ancestor = subprocess.run(git_argv("merge-base", "--is-ancestor", manifest["commit"], "HEAD"),
                              cwd=root, env=git_environment(), stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=30).returncode
    result = dict(reference_commit=manifest["commit"], carried_head=git("rev-parse", "HEAD"),
                  tree=git("rev-parse", "HEAD^{tree}"), ancestor=ancestor == 0,
                  clean=not git("status", "--porcelain=v1", "--untracked-files=all"))
    if result["tree"] != manifest["tree"] or not result["ancestor"] or not result["clean"]:
        raise RuntimeError("bootstrap source identity is unavailable")
    return result


def main(expected_payload, encoded):
    cleanup = dict(payload_sha256=expected_payload, complete=False)
    cancellation = None
    try:
        raw = gzip.decompress(base64.b64decode("".join(encoded), validate=True))
        if hashlib.sha256(raw).hexdigest() != expected_payload:
            raise RuntimeError("bootstrap payload digest differs")
        payload = _object_json(raw, "payload")
        if set(payload) != {"files"} or not isinstance(payload["files"], dict):
            raise RuntimeError("bootstrap payload file map is unavailable")
        files = {}
        for name, data in payload["files"].items():
            if not isinstance(name, str) or not name or "\x00" in name:
                raise RuntimeError("bootstrap payload path is unsafe")
            relative = PurePosixPath(name)
            if (relative.is_absolute() or str(relative) != name or ".." in relative.parts
                    or "\\" in name or relative.parts[0] in (".git", ".cargo", "target")
                    or not (len(relative.parts) == 1 or len(relative.parts) == 2 and relative.parts[0] == "support")):
                raise RuntimeError("bootstrap payload path is unsafe")
            files[name] = base64.b64decode(data, validate=True)
        manifest = _object_json(files["manifest.json"], "manifest")
        if any(not isinstance(manifest.get(key), str) or re.fullmatch(r"[a-f0-9]{40}", manifest[key]) is None
               for key in ("commit", "tree")):
            raise RuntimeError("bootstrap requires full frozen source identities")
        binding = _object_json(files["SUPPORT-BINDING.json"], "binding")
        helpers = set(HELPER_FILES)
        if (binding.get("state") != "FINALIZED_REVIEW_REQUIRED"
                or not isinstance(binding.get("hashes"), dict)
                or set(binding["hashes"]) != helpers
                or manifest.get("support_hashes") != binding["hashes"]):
            raise RuntimeError("bootstrap canonical helper binding is incomplete")
        runtime = _runtime_files(binding.get("runtime_hashes"))
        if manifest.get("runtime_hashes") != binding["runtime_hashes"]:
            raise RuntimeError("bootstrap canonical runtime binding differs")
        permitted = {"manifest.json", "SUPPORT-BINDING.json"} | set(runtime.values())
        permitted.update("support/" + name for name in helpers)
        if set(files) != permitted:
            raise RuntimeError("bootstrap payload contains missing or unbound files")
        for name, alias in runtime.items():
            if hashlib.sha256(files[alias]).hexdigest() != binding["runtime_hashes"][name]:
                raise RuntimeError("bootstrap canonical runtime digest differs")
        for name in helpers:
            if hashlib.sha256(files["support/" + name]).hexdigest() != binding["hashes"][name]:
                raise RuntimeError("bootstrap canonical helper digest differs")
        root = Path.cwd().resolve()
        if manifest["platform"] != sys.platform:
            raise RuntimeError("bootstrap native platform differs")
        previous = {name: sys.modules.get(name) for name in ("proof_types", "proof_git", "proof_paths")}
        try:
            _load("proof_types", files["support/proof_types.py"])
            _load("proof_git", files["support/proof_git.py"])
            paths = _load("proof_paths", files["support/proof_paths.py"])
            cleanup["source_before"] = _source(root, manifest)
            carrier = paths.OwnedLeg.create(root, paths.cargo_target_roots(root), prefix="csq-d2-carrier-")
        finally:
            for name, module in previous.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
        with carrier:
            cleanup["carrier_identity"] = carrier.identity
            instrument = carrier.child("instrument"); instrument.mkdir(mode=0o700)
            for name, data in files.items():
                path = instrument / name; path.parent.mkdir(mode=0o700, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(data)
            sys.path.append(str(instrument))
            support = _load("_support_binding", files["_support_binding.py"], path=instrument / "_support_binding.py")
            transport = _load("stdout_transport", files["stdout_transport.py"], path=instrument / "stdout_transport.py")
            with support.OwnedLeg.create(root, support.cargo_target_roots(root), prefix="csq-d2-output-") as output:
                cleanup["output_identity"] = output.identity
                directory = output.child("output"); directory.mkdir(mode=0o700)
                with _extra_runtimes(runtime, files, instrument):
                    runner = _load("deadline_run", files["deadline_run.py"], path=instrument / "deadline_run.py")
                    cleanup["runner_returncode"] = runner.main(cleanup["source_before"]["carried_head"], output_leg=output)
                    with (directory / "manifest.json").open("xb") as stream:
                        stream.write(files["manifest.json"])
                    transport.emit(sys.stdout.buffer, directory, manifest, expected_payload)
            cleanup["source_after"] = _source(root, manifest)
            if cleanup["source_after"] != cleanup["source_before"]:
                raise RuntimeError("bootstrap carried source changed")
        cleanup["complete"] = True
    except (KeyboardInterrupt, SystemExit) as error:
        cleanup["error_type"] = "KeyboardInterrupt" if isinstance(error, KeyboardInterrupt) else "SystemExit"
        cancellation = error
    except BaseException as error:
        cleanup["error_type"] = type(error).__name__
    print("D2_EXPORT_CLEANUP " + json.dumps(cleanup, sort_keys=True), flush=True)
    if cancellation is not None:
        raise cancellation
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2:]))
