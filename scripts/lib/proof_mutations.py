"""Frozen-source mutation composition for invocation-owned control checkouts.

This module does not run product commands. Schema, source and restoration failures
are instrument uncertainty. Callers must separately bind and check the complete
checkout tree before/after these file-level operations. The checkout must have one
writer: filesystem checks are point-in-time checks, not a cross-process CAS.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess

from proof_types import ProofUnavailable
from proof_git import git_argv, git_environment
from proof_paths import OwnedLeg


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _name(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProofUnavailable("mutation file must be a canonical relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(p in (".", "..") for p in path.parts):
        raise ProofUnavailable("mutation file must stay inside its source root")
    if not path.parts or any(part.casefold() in {".git", ".cargo", "target"} for part in path.parts):
        raise ProofUnavailable("mutation file contains a forbidden administrative or build component")
    return value


def _root(value):
    try:
        root = Path(value).resolve(strict=True)
        if not root.is_dir():
            raise ProofUnavailable("mutation source root is not a directory")
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise ProofUnavailable("mutation source requires no-follow directory operations")
        return root
    except (OSError, TypeError, ValueError):
        raise ProofUnavailable("mutation source root is unavailable") from None


@contextmanager
def _parent(root, name):
    descriptors = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors.append(os.open(root, flags))
        for part in PurePosixPath(name).parts[:-1]:
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        yield descriptors[-1], PurePosixPath(name).name
    except OSError:
        raise ProofUnavailable(f"mutation source parent unavailable: {name}") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@dataclass(frozen=True)
class _Snapshot:
    raw: bytes = field(repr=False)
    device: int
    inode: int
    uid: int
    mode: int


def _read_at(parent, leaf, name):
    descriptor = None
    try:
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProofUnavailable(f"mutation source is not a regular file: {name}")
        if before.st_uid != os.geteuid():
            raise ProofUnavailable(f"mutation source is not owned by this user: {name}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                      after.st_mtime_ns, after.st_ctime_ns):
            raise ProofUnavailable(f"mutation source changed during read: {name}")
        return _Snapshot(raw, after.st_dev, after.st_ino, after.st_uid,
                         stat.S_IMODE(after.st_mode))
    except OSError:
        raise ProofUnavailable(f"mutation source unavailable: {name}") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read(root, name):
    with _parent(root, name) as (parent, leaf):
        return _read_at(parent, leaf, name)


def _edits(values):
    if not isinstance(values, (list, tuple)) or not values:
        raise ProofUnavailable("mutation edit selection is empty or not a sequence")
    for edit in values:
        if not isinstance(edit, dict):
            raise ProofUnavailable("mutation edit must be an object")
        missing = {"file", "before", "after", "expected_matches"} - edit.keys()
        if missing:
            raise ProofUnavailable("mutation edit missing fields: " + ", ".join(sorted(missing)))
        _name(edit["file"])
        if (not isinstance(edit["before"], str) or not edit["before"] or
                not isinstance(edit["after"], str) or edit["before"] == edit["after"]):
            raise ProofUnavailable("mutation before/after must describe a nonempty change")
        if type(edit["expected_matches"]) is not int or edit["expected_matches"] < 1:
            raise ProofUnavailable("mutation expected_matches must be a positive integer")
        try:
            edit["before"].encode("utf-8")
            edit["after"].encode("utf-8")
        except UnicodeError:
            raise ProofUnavailable("mutation text must be valid UTF-8") from None
    return values


def _tracked_names(root):
    """Require both the scrubbed index inventory and the frozen HEAD tree."""
    try:
        def names(*args):
            raw = subprocess.check_output(git_argv(*args), cwd=root, env=git_environment(),
                                          stderr=subprocess.PIPE, timeout=30)
            return {name for name in raw.decode("utf-8").split("\x00") if name}
        return names("ls-files", "--cached", "-z") & names("ls-tree", "-r", "--name-only", "-z", "HEAD")
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise ProofUnavailable("mutation frozen tracked-file inventory is unavailable") from None


def render_edits(root, raw_edits, frozen_hashes):
    """Populate complete metadata only from bytes matching a caller-pinned map.

    The map must come from the caller's verified source snapshot, not a convenient
    hash recomputed after mutation. This renderer never weakens that binding.
    """
    root = _root(root)
    edits = _edits(raw_edits)
    if not isinstance(frozen_hashes, dict):
        raise ProofUnavailable("mutation frozen source hash map is missing")
    tracked = _tracked_names(root)
    rendered = []
    for edit in edits:
        name = edit["file"]
        if name not in tracked:
            raise ProofUnavailable(f"mutation file is absent from the frozen tracked tree: {name}")
        expected = frozen_hashes.get(name)
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ProofUnavailable(f"mutation frozen source hash unavailable: {name}")
        if _sha(_read(root, name).raw) != expected:
            raise ProofUnavailable(f"mutation frozen source hash mismatch: {name}")
        supplied = edit.get("source_sha256", expected)
        if supplied != expected:
            raise ProofUnavailable(f"mutation supplied source hash mismatch: {name}")
        rendered.append(dict(edit, source_sha256=expected))
    validate_edits(root, rendered)
    return tuple(rendered)


@dataclass(frozen=True)
class FileMutation:
    file: str
    original: _Snapshot = field(repr=False)
    updated: bytes = field(repr=False)


def validate_edits(root, final_edits):
    """Validate the final rendered adapter input completely before any write."""
    root = _root(root)
    edits = _edits(final_edits)
    tracked = _tracked_names(root)
    originals, updated = {}, {}
    for edit in edits:
        name = edit["file"]
        if name not in tracked:
            raise ProofUnavailable(f"mutation file is absent from the frozen tracked tree: {name}")
        expected = edit.get("source_sha256")
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ProofUnavailable(f"mutation source_sha256 missing or invalid: {name}")
        if name not in originals:
            originals[name] = _read(root, name)
            try:
                updated[name] = originals[name].raw.decode("utf-8")
            except UnicodeError:
                raise ProofUnavailable(f"mutation source is not UTF-8: {name}") from None
        if _sha(originals[name].raw) != expected:
            raise ProofUnavailable(f"mutation source hash mismatch: {name}")
        count = updated[name].count(edit["before"])
        if count != edit["expected_matches"]:
            raise ProofUnavailable(f"mutation match count mismatch: {name}")
        updated[name] = updated[name].replace(edit["before"], edit["after"])
    mutations = tuple(FileMutation(name, original, updated[name].encode("utf-8"))
                      for name, original in originals.items())
    if any(mutation.original.raw == mutation.updated for mutation in mutations):
        raise ProofUnavailable("composed mutation leaves a selected file unchanged")
    return mutations


def _replace(root, mutation, expected, raw):
    """Replace one checked source atomically; retain no partial temporary file."""
    temporary, temporary_identity = None, None
    with _parent(root, mutation.file) as (parent, leaf):
        try:
            if _read_at(parent, leaf, mutation.file) != expected:
                raise ProofUnavailable(f"mutation source changed before replacement: {mutation.file}")
            candidate = ".csq-proof-" + secrets.token_hex(16)
            descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW, 0o600, dir_fd=parent)
            temporary = candidate
            created = os.fstat(descriptor)
            temporary_identity = (created.st_dev, created.st_ino)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), mutation.original.mode)
                os.fsync(stream.fileno())
                info = os.fstat(stream.fileno())
            installed = _Snapshot(raw, info.st_dev, info.st_ino, info.st_uid,
                                  stat.S_IMODE(info.st_mode))
            if _read_at(parent, leaf, mutation.file) != expected:
                raise ProofUnavailable(f"mutation source changed before publication: {mutation.file}")
            os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
            temporary = None
            return installed
        except OSError:
            raise ProofUnavailable(f"mutation atomic replacement unavailable: {mutation.file}") from None
        finally:
            if temporary is not None:
                try:
                    current = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != temporary_identity:
                        raise ProofUnavailable(f"mutation temporary identity changed: {mutation.file}")
                    os.unlink(temporary, dir_fd=parent)
                except OSError:
                    raise ProofUnavailable(f"mutation temporary cleanup unavailable: {mutation.file}") from None


@dataclass
class MutationReceipt:
    files: tuple[FileMutation, ...] = field(repr=False)
    applied: bool = False
    restored: bool = False

    def evidence(self):
        return {"applied": self.applied, "restored": self.restored,
                "files": [{"file": item.file, "source_sha256": _sha(item.original.raw),
                           "mutated_sha256": _sha(item.updated), "mode": item.original.mode}
                          for item in self.files]}

    def as_dict(self):
        return self.evidence()


@contextmanager
def applied_edits(root, final_edits, *, owned_leg=None):
    """Apply the actual adapter input and restore owned installations in finally.

    An externally replaced or edited source is left untouched and reported as
    UNDETERMINED through ProofUnavailable. A successful receipt binds file bytes
    and modes; the caller remains responsible for its full-tree identity guard.
    """
    root = _root(root)
    if not isinstance(owned_leg, OwnedLeg) or root != owned_leg.child("source"):
        raise ProofUnavailable("mutation requires this invocation's live owned control checkout")
    mutations = validate_edits(root, final_edits)
    receipt, installed = MutationReceipt(mutations), []
    try:
        for mutation in mutations:
            observed = _replace(root, mutation, mutation.original, mutation.updated)
            installed.append((mutation, observed))
        receipt.applied = True
        yield receipt
    finally:
        failures = []
        for mutation, observed in reversed(installed):
            try:
                _replace(root, mutation, observed, mutation.original.raw)
                actual = _read(root, mutation.file)
                if actual.raw != mutation.original.raw or actual.mode != mutation.original.mode:
                    raise ProofUnavailable("restoration bytes or mode differ")
            except (ProofUnavailable, OSError):
                failures.append(mutation.file)
        if failures:
            raise ProofUnavailable("mutation restoration unavailable: " + ", ".join(failures)) from None
        receipt.restored = True


def preflight_edits(root, final_edits, check_applied=None, check_restored=None, *, owned_leg=None):
    """Exercise rendered edits through the same transaction before product work.

    Optional full-tree guards must return True; false/unknown is uncertainty.
    No product command or verdict is produced here.
    """
    with applied_edits(root, final_edits, owned_leg=owned_leg) as receipt:
        if check_applied is not None and check_applied() is not True:
            raise ProofUnavailable("mutation preflight applied tree guard did not establish identity")
    if check_restored is not None and check_restored() is not True:
        raise ProofUnavailable("mutation preflight restored tree guard did not establish identity")
    return receipt
