"""Invocation-owned proof scaffolds, outside every resolved Cargo cache root.

This module owns only directories it allocated. It does not place jobs, reclaim
caches, or clean historical proof artifacts. Callers must pass Cargo metadata's
target directory when the Cargo invocation supplies additional config overrides.
"""

from pathlib import Path
from contextlib import contextmanager
import os
import re
import secrets
import shutil
import stat
import tomllib

from proof_types import ProofUnavailable


class TargetRoots(tuple):
    """Resolved roots plus the discovery inputs recorded for an invocation."""

    def __new__(cls, roots, provenance):
        instance = super().__new__(cls, roots)
        instance.provenance = provenance
        return instance


def _canonical(value, base=None):
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or any(c in raw for c in "\x00\n\r"):
            raise ProofUnavailable("proof-path: invalid path metadata")
        path = Path(raw)
        if ".." in path.parts:
            raise ProofUnavailable("proof-path: traversal is not permitted")
        if not path.is_absolute():
            if base is None:
                raise ProofUnavailable("proof-path: absolute base is required")
            path = base / path
        return path.resolve(strict=False)
    except (TypeError, ValueError, OSError, RuntimeError) as error:
        if isinstance(error, ProofUnavailable):
            raise
        raise ProofUnavailable("proof-path: canonical path is unavailable") from error


def _lexical(value, base=None):
    """Validate like `_canonical` but keep the path as written (absolute)."""
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or any(c in raw for c in "\x00\n\r"):
            raise ProofUnavailable("proof-path: invalid path metadata")
        path = Path(raw)
        if ".." in path.parts:
            raise ProofUnavailable("proof-path: traversal is not permitted")
        if not path.is_absolute():
            if base is None:
                raise ProofUnavailable("proof-path: absolute base is required")
            path = base / path
        return path
    except (TypeError, ValueError) as error:
        raise ProofUnavailable("proof-path: invalid path metadata") from error


def _build_dir_root(value, base):
    # build-dir may hold {workspace-path-hash}-style templates whose expansion
    # is Cargo's; an unexpanded root cannot be inventoried, so any target or
    # build directory containing `{` is refused (a literal brace included).
    if isinstance(value, str) and "{" in value:
        raise ProofUnavailable("proof-targets: templated Cargo target or build directory is unsupported")
    return _canonical(value, base)


def cargo_target_roots(repo, *, env=None, metadata_target=None,
                       config_paths=None, extra_roots=(), invocation_dir=None):
    """Collect roots conservatively; never discard lower-precedence aliases.

    ``config_paths`` is an explicit list of applicable config files; when absent
    normal ancestor/CARGO_HOME config discovery is used. Cargo ``--config`` or
    other invocation-specific overrides must be supplied as extra roots or the
    actual ``cargo metadata`` target. Values are resolved without creating paths.
    """
    root = _canonical(repo)
    environment = os.environ if env is None else env
    try:
        if isinstance(extra_roots, (str, bytes, Path)):
            raise TypeError
        extra_roots = tuple(extra_roots)
    except TypeError:
        raise ProofUnavailable("proof-targets: extra roots must be a path inventory") from None
    if not isinstance(environment, dict) and not hasattr(environment, "get"):
        raise ProofUnavailable("proof-targets: environment metadata is unavailable")
    if invocation_dir is None:
        try:
            invoking = _canonical(Path.cwd())
        except OSError:
            raise ProofUnavailable("proof-targets: invoking directory is unavailable") from None
        if invoking != root and root not in invoking.parents:
            invoking = root
    else:
        invoking = _canonical(invocation_dir, root)
        if invoking != root and root not in invoking.parents:
            raise ProofUnavailable("proof-targets: invoking directory is outside source")
    # Cargo resolves relative environment paths against ITS working directory,
    # which this process can only guess (the invoking dir, or the root), so
    # both candidates are kept: an extra root only refuses more, a missing one
    # fails open.
    relative_bases = tuple(dict.fromkeys((invoking, root)))
    # Cargo takes CARGO_HOME as written and never resolves symlinks in it, so
    # config-relative paths are based on the lexical path. The canonical form
    # is only compared.
    cargo_home = environment.get("CARGO_HOME")
    if cargo_home is None:
        home = environment.get("HOME")
        if home is None:
            raise ProofUnavailable("proof-targets: HOME or CARGO_HOME is required")
        cargo_homes = [_lexical(home) / ".cargo"]
    else:
        cargo_homes = list(dict.fromkeys(_lexical(cargo_home, base) for base in relative_bases))
    cargo_home_canonical = {_canonical(path): path for path in reversed(cargo_homes)}
    roots = {root / "target"}
    environment_keys = ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR")
    for key in environment_keys:
        value = environment.get(key)
        if value is not None:
            for base in relative_bases:
                roots.add(_build_dir_root(value, base))
    for value in extra_roots:
        roots.add(_canonical(value, root))
    if metadata_target is not None:
        roots.add(_canonical(metadata_target, root))
    if config_paths is None:
        configs = [parent / ".cargo" / leaf
                   for parent in (invoking, *invoking.parents)
                   for leaf in ("config", "config.toml")]
        configs.extend(home / leaf for home in cargo_homes for leaf in ("config", "config.toml"))
        configs = [path for path in configs if path.exists() or path.is_symlink()]
    else:
        try:
            if isinstance(config_paths, (str, bytes, Path)):
                raise TypeError
            configs = [Path(path) for path in config_paths]
        except (TypeError, ValueError):
            raise ProofUnavailable("proof-targets: Cargo configs must be a path inventory") from None
    for config in configs:
        try:
            config = _lexical(config, root)
            if config.is_symlink():
                raise ProofUnavailable("proof-targets: symlinked Cargo config is unsupported")
            # A config directly under CARGO_HOME is standard whatever that
            # directory is named (CI runners set e.g. ~/.cargo-runner-11);
            # anywhere else Cargo only reads configs inside a `.cargo` dir.
            home_alias = cargo_home_canonical.get(_canonical(config.parent))
            if config.parent.name != ".cargo" and home_alias is None:
                raise ProofUnavailable("proof-targets: nonstandard Cargo config is unsupported")
            # Cargo bases config-relative paths on the directory above the
            # config's directory, taken as written: a symlinked `.cargo` or
            # CARGO_HOME directory does not move the base to its target. A
            # CARGO_HOME config named through an alias keeps both bases.
            bases = {config.parent.parent}
            if home_alias is not None:
                bases.add(home_alias.parent)
            with config.open("rb") as stream:
                parsed = tomllib.load(stream)
            # `include` loads further configs, based on their own location;
            # they are not inventoried here, so the config cannot be judged.
            if "include" in parsed:
                raise ProofUnavailable("proof-targets: Cargo config include is unsupported")
            build = parsed.get("build", {})
            if not isinstance(build, dict):
                raise ProofUnavailable("proof-targets: malformed build configuration")
            for key in ("target-dir", "build-dir"):
                if key in build:
                    for base in bases:
                        roots.add(_build_dir_root(build[key], base))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            raise ProofUnavailable("proof-targets: Cargo configuration unreadable") from None
    return TargetRoots(
        sorted((_canonical(path) for path in roots), key=os.fspath),
        {"repo": str(root), "invocation_dir": str(invoking),
         "cargo_home": str(_canonical(cargo_homes[0])),
         "cargo_home_candidates": [str(path) for path in cargo_homes],
         "configs": [str(path) for path in configs],
         "metadata_target": None if metadata_target is None else str(metadata_target),
         "environment_targets": {key: environment.get(key) for key in environment_keys},
         "extra_roots": [str(path) for path in extra_roots],
         "override_contract": "caller supplies invocation-specific Cargo overrides"},
    )


def _existing_identity(path):
    try:
        info = path.stat()
        return info.st_dev, info.st_ino
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError):
        raise ProofUnavailable("proof-layout: existing path identity is unavailable") from None


def assert_external(path, roots):
    """Reject lexical containment and existing-ancestor inode aliases."""
    candidate = _canonical(path)
    canonical_roots = tuple(_canonical(root) for root in roots)
    if not canonical_roots:
        raise ProofUnavailable("proof-layout: target inventory is empty")
    if any(candidate == root or root in candidate.parents for root in canonical_roots):
        raise ProofUnavailable("proof-layout: scaffold is inside a Cargo target")
    roots_by_identity = {identity for root in canonical_roots
                         if (identity := _existing_identity(root)) is not None}
    for ancestor in (candidate, *candidate.parents):
        identity = _existing_identity(ancestor)
        if identity is not None and identity in roots_by_identity:
            raise ProofUnavailable("proof-layout: scaffold is inside a Cargo target")
    return candidate


def _identity(info):
    return info.st_dev, info.st_ino, info.st_uid


def _safe_parent(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
        raise ProofUnavailable("proof-owned: temporary parent owner is not root or euid")
    if info.st_mode & stat.S_IWOTH and not info.st_mode & stat.S_ISVTX:
        raise ProofUnavailable("proof-owned: temporary parent is world-writable without sticky bit")
    if info.st_mode & stat.S_IWGRP and not info.st_mode & stat.S_ISVTX:
        raise ProofUnavailable("proof-owned: temporary parent is group-writable without sticky bit")


def _walk_delete(descriptor):
    """Iterative postorder deletion, with constant simultaneous descriptors.

    Frames retain names and inode identities, never an FD per tree level.
    Each cursor is reopened from the retained root and checks every component.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_identity = _identity(os.fstat(descriptor))

    @contextmanager
    def open_chain(parts, identities):
        cursor = os.open(".", flags, dir_fd=descriptor)
        try:
            if _identity(os.fstat(cursor)) != root_identity:
                raise ProofUnavailable("proof-owned: cleanup root identity changed")
            for name, expected in zip(parts, identities):
                before = os.stat(name, dir_fd=cursor, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode) or _identity(before) != expected:
                    raise ProofUnavailable("proof-owned: cleanup child name changed")
                child = os.open(name, flags, dir_fd=cursor)
                try:
                    if _identity(os.fstat(child)) != expected:
                        raise ProofUnavailable("proof-owned: cleanup child identity changed")
                    # Reuse one cursor descriptor instead of retaining parents.
                    os.dup2(child, cursor, inheritable=False)
                finally:
                    os.close(child)
            yield cursor
        finally:
            os.close(cursor)

    stack = [((), (), False)]
    while stack:
        parts, identities, visited = stack.pop()
        with open_chain(parts, identities) as cursor:
            if visited:
                if parts:
                    with open_chain(parts[:-1], identities[:-1]) as parent:
                        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                        if (not stat.S_ISDIR(current.st_mode)
                                or _identity(current) != _identity(os.fstat(cursor))):
                            raise ProofUnavailable("proof-owned: cleanup child name changed")
                        os.rmdir(parts[-1], dir_fd=parent)
                continue
            children = []
            with os.scandir(cursor) as entries:
                for entry in entries:
                    before = os.stat(entry.name, dir_fd=cursor, follow_symlinks=False)
                    if stat.S_ISDIR(before.st_mode):
                        child = os.open(entry.name, flags, dir_fd=cursor)
                        try:
                            if _identity(os.fstat(child)) != _identity(before):
                                raise ProofUnavailable("proof-owned: cleanup child identity changed")
                            children.append((entry.name, _identity(before)))
                        finally:
                            os.close(child)
                    else:
                        os.unlink(entry.name, dir_fd=cursor)
            stack.append((parts, identities, True))
            for name, identity in reversed(children):
                stack.append(((*parts, name), (*identities, identity), False))


class OwnedLeg:
    """A retained-parent-FD lease for one external, private directory.

    Use as a context manager, or call cleanup in the invoking scope's finally.
    A refusal retains the directory and FDs for an explicit retry after restoring
    identity; ``close`` releases FDs without claiming that cleanup succeeded.

    Boundary: the leg is invocation-private (0700). Cleanup walks through the
    retained child FD and refuses to rmdir an exchanged root name. Final name
    checks are point-in-time observations, not an inode-conditional delete/CAS.
    This helper must not be used to reclaim shared or historical directories.
    """

    @classmethod
    def create(cls, repo, target_roots, *, parent="/tmp", prefix="csq-proof-"):
        if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}-", prefix):
            raise ProofUnavailable("proof-owned: invalid temporary prefix")
        if (not hasattr(os, "geteuid") or not hasattr(os, "O_NOFOLLOW")
                or not getattr(shutil.rmtree, "avoids_symlink_attacks", False)):
            raise ProofUnavailable("proof-owned: safe directory operations unavailable")
        root = _canonical(repo)
        roots = tuple(_canonical(path) for path in target_roots)
        if not roots:
            raise ProofUnavailable("proof-owned: target inventory is empty")
        parent_path = assert_external(_canonical(parent), (*roots, root))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent_fd = child_fd = None
        created_name = None
        created_identity = None
        try:
            parent_fd = os.open(parent_path, flags)
            parent_info = os.fstat(parent_fd)
            _safe_parent(parent_info)
            parent_identity = _identity(parent_info)
            if _identity(os.lstat(parent_path)) != parent_identity:
                raise ProofUnavailable("proof-owned: temporary parent changed")
            name = prefix + secrets.token_hex(12)
            path = assert_external(parent_path / name, (*roots, root))
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            created_name = name
            created_identity = _identity(os.stat(name, dir_fd=parent_fd,
                                                follow_symlinks=False))
            child_fd = os.open(name, flags, dir_fd=parent_fd)
            info = os.fstat(child_fd)
            if (_identity(info) != created_identity or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ProofUnavailable("proof-owned: private ownership unavailable")
            owned = cls()
            owned.path, owned.parent = path, parent_path
            owned._roots = (*roots, root)
            owned._parent_fd, owned._child_fd = parent_fd, child_fd
            owned._parent_identity, owned._identity = parent_identity, _identity(info)
            owned._cleaned = False
            owned._verify()
            return owned
        except (OSError, ProofUnavailable) as error:
            # No payload exists before a lease is returned. Remove only an empty
            # entry allocated by this invocation, through its retained parent FD.
            empty_cleanup = created_name is None
            if created_identity is not None and parent_fd is not None:
                try:
                    info = os.stat(created_name, dir_fd=parent_fd, follow_symlinks=False)
                    if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                            and _identity(info) == created_identity):
                        os.rmdir(created_name, dir_fd=parent_fd)
                        empty_cleanup = True
                except OSError:
                    pass
            for fd in (child_fd, parent_fd):
                if fd is not None:
                    os.close(fd)
            if not empty_cleanup:
                raise ProofUnavailable("proof-owned: allocation failed; empty-leg cleanup unconfirmed") from error
            if isinstance(error, ProofUnavailable):
                raise
            raise ProofUnavailable("proof-owned: allocation did not establish custody") from error

    def _verify(self):
        if self._parent_fd is None or self._child_fd is None:
            raise ProofUnavailable("proof-owned: directory lease is closed")
        try:
            if self.parent.resolve(strict=True) != self.parent:
                raise ProofUnavailable("proof-owned: temporary parent became an alias")
            parent = os.lstat(self.parent)
            _safe_parent(parent)
            if (not stat.S_ISDIR(parent.st_mode)
                    or _identity(parent) != self._parent_identity
                    or _identity(os.fstat(self._parent_fd)) != self._parent_identity):
                raise ProofUnavailable("proof-owned: temporary parent identity changed")
            info = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or _identity(info) != self._identity
                    or _identity(os.fstat(self._child_fd)) != self._identity):
                raise ProofUnavailable("proof-owned: directory identity changed")
            assert_external(self.path, self._roots)
        except (OSError, RuntimeError) as error:
            if isinstance(error, ProofUnavailable):
                raise
            raise ProofUnavailable("proof-owned: directory identity unavailable") from error

    def child(self, relative):
        """Return a verified child path; the caller owns its payload lifecycle."""
        self._verify()
        if not isinstance(relative, (str, Path)) or not os.fspath(relative):
            raise ProofUnavailable("proof-owned: child name is unavailable")
        leaf = Path(relative)
        if leaf.is_absolute() or ".." in leaf.parts or leaf == Path("."):
            raise ProofUnavailable("proof-owned: child must remain within its lease")
        child = assert_external(self.path / leaf, self._roots)
        if self.path not in child.parents:
            raise ProofUnavailable("proof-owned: child resolves outside its lease")
        return child

    @property
    def identity(self):
        """A metadata-only receipt after rechecking the retained identities."""
        self._verify()
        device, inode, uid = self._identity
        parent_device, parent_inode, parent_uid = self._parent_identity
        return {"path": str(self.path), "device": device, "inode": inode, "uid": uid,
                "parent": str(self.parent), "parent_device": parent_device,
                "parent_inode": parent_inode, "parent_uid": parent_uid}

    def cleanup(self):
        if self._cleaned:
            raise ProofUnavailable("proof-owned: cleanup was already completed")
        identity = self.identity
        try:
            _walk_delete(self._child_fd)
            current = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            if _identity(current) != self._identity or not stat.S_ISDIR(current.st_mode):
                raise ProofUnavailable("proof-owned: cleanup root name identity changed")
            os.rmdir(self.path.name, dir_fd=self._parent_fd)
            try:
                os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                self._cleaned = True
                self.close()
                return {"cleanup_complete": True, "scope": "invocation-owned-leg",
                        "identity": identity}
            raise ProofUnavailable("proof-owned: cleanup left a directory entry")
        except (OSError, RuntimeError) as error:
            if isinstance(error, ProofUnavailable):
                raise
            raise ProofUnavailable("proof-owned: cleanup did not complete") from None

    def close(self):
        """Release descriptors; this alone never establishes cleanup."""
        for name in ("_child_fd", "_parent_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        self._verify()
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.cleanup()
        finally:
            self.close()
