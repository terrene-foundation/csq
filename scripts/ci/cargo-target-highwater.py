#!/usr/bin/env python3
"""Internal engine for cargo-target-highwater.sh; Python standard library only.

Admission accounts allocated blocks, not logical size. A successful receipt is
only a pre-leg policy decision. Admitted payloads inherit a shared target lease;
eviction requires an exclusive upgrade plus Cargo profile locks. Concurrent legs
skip eviction only below a hard ceiling. Network or unknown filesystems never
evict. This is no quota. Never clean after the payload.
"""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

LIMIT = 34359738368  # 32 GiB policy, not a measured healthy bound.
LEASE = "csq-highwater.lease"
LEASE_WAIT_SECONDS, LEASE_RETRY_SECONDS = 1.0, 0.01
LOCAL_FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "tmpfs",
                     "ramfs", "overlay", "bcachefs", "f2fs", "jfs", "reiserfs",
                     "apfs", "hfs", "ufs", "exfat", "msdos"}
MAX_ENTRIES, MAX_DEPTH, MAX_SECONDS = 500000, 64, 30
PROTECTED = {".git", ".cargo", ".rustup", "Cargo.toml", "Cargo.lock",
             "rust-toolchain", "rust-toolchain.toml"}
# The ONE interior of a cargo target that is regenerable build output rather
# than a source tree: trybuild writes a throwaway crate with its own manifest
# and lockfile under <target>/tests/trybuild/<crate>/ on every run of the
# compile-fail tests. Those two names are in PROTECTED because a real checkout
# inside the target is a red flag, so the exact four-part path shape is matched
# here and nothing else is: `.git`/`.cargo`/`.rustup` anywhere (this directory
# included) and a manifest anywhere else under the target still refuse.
TRYBUILD_SCRATCH_PARENT = ("tests", "trybuild")
# Case-folded membership set for the PROTECTED check (see
# `protected_interior`): `.GIT`/`cargo.TOML` are the same protected thing on a
# case-insensitive filesystem.
PROTECTED_FOLDED = {name.casefold() for name in PROTECTED}


def allowed_interior(name, relative):
    """True only for trybuild's scratch manifest/lockfile at its exact path.

    `relative` is the entry's path RELATIVE TO THE TARGET ROOT, so the caller
    must pass the parent path joined with the entry name.
    """
    if name not in ("Cargo.toml", "Cargo.lock"):
        return False
    parts = Path(relative).parts
    return (len(parts) == 4 and parts[:2] == TRYBUILD_SCRATCH_PARENT
            and parts[2] not in ("", ".", ".."))


def protected_interior(entry_name, relative):
    """The PROTECTED check both walks apply, with its one documented exception.

    Membership is CASE-INSENSITIVE: APFS resolves `.GIT` and `.Git` to the same
    directory as `.git`, so a name that only differs in case is the same
    protected thing and must refuse. The trybuild allowance, by contrast, is
    matched on the EXACT-CASE form only (`allowed_interior`), so a capitalised
    parent segment names a different directory on a case-sensitive filesystem
    and is never admitted by the exception.
    """
    return entry_name.casefold() in PROTECTED_FOLDED and not allowed_interior(
        entry_name, relative)


DIRECTORY = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
             if hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") else None)


class Undetermined(Exception):
    def __init__(self, reason, offenders=None, offender_count=0, complete=True):
        super().__init__(reason)
        self.offenders = offenders or []
        self.offender_count = offender_count or len(self.offenders)
        self.offender_scan_complete = complete


# Per-entry refusals whose receipt names the offending entries (metadata only,
# never contents). Bounded so a wholly unsafe tree cannot flood the receipt.
OFFENDER_REASONS = ("foreign-owner", "unsafe-permissions", "unreadable-directory",
                    "unreadable-or-special-entry")
MAX_OFFENDERS = 20


def require(condition, reason):
    if not condition:
        raise Undetermined(reason)


def identity(st):
    return st.st_dev, st.st_ino


def clean_path(value):
    require(value and not any(c in value for c in "\n\r\x00"), "invalid-path")
    require(".." not in Path(value).parts, "path-traversal")
    path = Path(os.path.abspath(value))
    if sys.platform == "darwin":
        # Normalize only these two system roots. Never resolve target parents
        # or leaves: arbitrary symlinks remain visible to the NOFOLLOW opens.
        for alias in (Path("/var"), Path("/tmp")):
            if path == alias or alias in path.parents:
                physical = alias.resolve(strict=True)
                require(physical == Path("/private") / alias.name,
                        "unexpected-system-alias")
                path = physical / path.relative_to(alias)
                break
    return path


def beneath(path, parent):
    return path == parent or parent in path.parents


def git(workspace, *args):
    # Repository identity must not be redirected by the caller's Git environment.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    result = subprocess.run(["git", "-C", str(workspace), *args], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, check=False)
    require(len(result.stdout) < 1048576, "git-output-bound")
    return result


def owned(st, directory=False):
    require(st.st_uid == os.getuid(), "foreign-owner")
    require(not st.st_mode & 0o022, "unsafe-permissions")
    if directory:
        require(stat.S_ISDIR(st.st_mode) and st.st_mode & 0o500 == 0o500,
                "unreadable-directory")
    else:
        require(stat.S_ISREG(st.st_mode) and st.st_mode & 0o400,
                "unreadable-or-special-entry")


def entry_type(mode):
    for test, name in ((stat.S_ISLNK, "symlink"), (stat.S_ISDIR, "directory"),
                       (stat.S_ISREG, "file"), (stat.S_ISFIFO, "fifo"),
                       (stat.S_ISSOCK, "socket"), (stat.S_ISCHR, "char-device"),
                       (stat.S_ISBLK, "block-device")):
        if test(mode):
            return name
    return "other"


def offender(st, relative, reason):
    return {"path": str(relative), "type": entry_type(st.st_mode),
            "mode": format(stat.S_IMODE(st.st_mode), "04o"), "uid": st.st_uid,
            "reason": reason}


def owned_at(st, relative, directory=False, link=False):
    """owned(), or the symlink owner-only exemption, naming the entry on refusal."""
    try:
        if link:
            require(st.st_uid == os.getuid(), "foreign-owner")
        else:
            owned(st, directory)
    except Undetermined as error:
        if str(error) not in OFFENDER_REASONS:
            raise
        # A single-entry check scans nothing beyond this entry (Cache.evict stops
        # here), so never claim completeness; measure() re-raises with its own.
        raise Undetermined(str(error), [offender(st, relative, str(error))],
                           complete=False) from None


def open_chain(path):
    """Open every component without following a symlink, returning the leaf fd."""
    require(DIRECTORY is not None, "nofollow-unavailable")
    fd = os.open(path.anchor, DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def related_paths(left, right):
    """Detect physical containment and identity aliases without granting authority."""
    left, right = left.resolve(strict=False), right.resolve(strict=False)
    if beneath(left, right) or beneath(right, left):
        return True

    def existing_id(path):
        try:
            return identity(path.stat())
        except FileNotFoundError:
            return None

    left_id, right_id = existing_id(left), existing_id(right)
    return (left_id is not None and any(existing_id(p) == left_id for p in (right, *right.parents))
            or right_id is not None and any(existing_id(p) == right_id for p in (left, *left.parents)))


def protect_target(target, protected):
    require(not any(related_paths(target, p) for p in protected), "protected-target")


def git_common_directory(workspace):
    result = git(workspace, "rev-parse", "--path-format=absolute", "--git-common-dir")
    require(result.returncode == 0, "git-common-unreadable")
    return clean_path(os.fsdecode(result.stdout).strip()).resolve(strict=True)


def bounded_shared_lock(fd):
    """Acquire/downgrade SH without an unbounded kernel wait."""
    deadline = time.monotonic() + LEASE_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "helper-lease-held")
            time.sleep(min(LEASE_RETRY_SECONDS, remaining))


def lease_holders(fd):
    """Name only kernel-observed PIDs/modes bound to this lease's dev/inode."""
    if not sys.platform.startswith("linux"):
        return "UNKNOWN"
    subject = os.fstat(fd)
    try:
        with open("/proc/locks", encoding="ascii") as stream:
            data = stream.read(1048577)
        if len(data) > 1048576:
            return "UNKNOWN"
        holders = set()
        for line in data.splitlines():
            match = re.fullmatch(r"\d+: (?:FLOCK|POSIX|OFDLCK) +ADVISORY +(READ|WRITE) +(-?\d+) +([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+) +\S+ +\S+", line)
            if not match:
                continue  # Waiting arrows and unrelated lock kinds are not holders.
            mode, pid, major, minor, inode = match.groups()
            if (int(major, 16), int(minor, 16), int(inode)) == (
                    os.major(subject.st_dev), os.minor(subject.st_dev), subject.st_ino):
                if int(pid) <= 0:
                    return "UNKNOWN"
                holders.add((int(pid), mode))
        return [{"pid": pid, "mode": mode} for pid, mode in sorted(holders)] or "UNKNOWN"
    except (OSError, UnicodeError, ValueError):
        return "UNKNOWN"


DARWIN_FILESYSTEM_PROBE = r"""
import ctypes, sys
class StatFS(ctypes.Structure):
    _fields_ = [("bsize", ctypes.c_uint32), ("iosize", ctypes.c_int32),
                ("counts", ctypes.c_uint64 * 5), ("fsid", ctypes.c_int32 * 2),
                ("owner", ctypes.c_uint32), ("type", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("subtype", ctypes.c_uint32),
                ("fstypename", ctypes.c_char * 16), ("mntonname", ctypes.c_char * 1024),
                ("mntfromname", ctypes.c_char * 1024), ("reserved", ctypes.c_uint32 * 8)]
libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
libc.statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(StatFS)]
libc.statfs.restype = ctypes.c_int
result = StatFS()
if libc.statfs(sys.argv[1].encode(), ctypes.byref(result)) != 0:
    sys.exit(1)
print(result.fstypename.decode('ascii'))
"""


def darwin_filesystem_type(target):
    # Native statfs runs in a bounded child: an unresponsive remote filesystem
    # cannot hang admission. No shell, host installs or inherited credentials.
    try:
        result = subprocess.run([sys.executable, "-c", DARWIN_FILESYSTEM_PROBE, str(target)],
                                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=2, check=False)
        name = result.stdout.decode("ascii").strip().lower()
        if result.returncode == 0 and re.fullmatch(r"[a-z0-9_.-]{1,32}", name):
            return name
    except (OSError, UnicodeError, subprocess.SubprocessError):
        pass
    return None


def filesystem_type(target, mounts):
    """Linux mounts is a mountpoint -> fstype mapping; longest prefix wins."""
    if sys.platform == "darwin":
        return darwin_filesystem_type(target)
    matches = [point for point in mounts if beneath(target, point)]
    return mounts[max(matches, key=lambda point: len(point.parts))] if matches else None


def network_filesystem(name):
    return bool(name and (name in {"nfs", "nfs4", "cifs"}
                          or name.startswith(("smb", "fuse."))))


def read_mountinfo():
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as stream:
            data = stream.read(4194305)
        require(len(data) <= 4194304, "mountinfo-unreadable")
        mounts = {}
        for line in data.splitlines():
            left, right = line.split(" - ", 1)
            fields, trailing = left.split(), right.split()
            require(len(fields) >= 6 and len(trailing) >= 3, "mountinfo-unreadable")
            point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
            require(point.startswith("/") and re.fullmatch(r"[A-Za-z0-9_.-]+", trailing[0]),
                    "mountinfo-unreadable")
            mounts[Path(point)] = trailing[0].lower()
        return mounts
    except (OSError, UnicodeError, IndexError, ValueError):
        raise Undetermined("mountinfo-unreadable") from None


def authorize(args):
    # Resolve the workspace's system aliases (e.g. macOS /tmp), then disallow
    # symlinks in the entire target chain under its physical authority root.
    workspace = clean_path(args.workspace).resolve(strict=True)
    require((workspace / "Cargo.toml").is_file(), "workspace-manifest-missing")
    top = git(workspace, "rev-parse", "--show-toplevel")
    require(top.returncode == 0 and Path(os.fsdecode(top.stdout).strip()).resolve() == workspace,
            "workspace-not-git-root")
    # Cargo normalizes its metadata path, so inspect raw final-env overrides
    # before that normalization can erase a forbidden parent-traversal component.
    for key in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR"):
        if key in os.environ:
            clean_path(os.environ[key])
    target = clean_path(args.resolved_target)
    if args.target_dir:
        require(clean_path(args.target_dir) == target, "target-selection-conflict")
    common = git_common_directory(workspace)
    protected = [workspace / ".git", common]
    for key, default in (("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")):
        protected.append(clean_path(os.environ.get(key, str(Path.home() / default))).resolve())
    protect_target(target, protected)
    if args.ephemeral_root:
        root = clean_path(args.ephemeral_root)
        temporary = clean_path(tempfile.gettempdir())
        require(re.fullmatch(r"csq-windows-compile\.[A-Za-z0-9]{6,}", root.name)
                and temporary in (root.parent, root / "tmp")
                and target.parent == root
                and target.name == "target", "unknown-ephemeral-domain")
        root_fd = open_chain(root)
        try:
            root_st = os.fstat(root_fd)
            owned(root_st, True)
            require(stat.S_IMODE(root_st.st_mode) == 0o700, "ephemeral-root-not-private")
            if temporary == root / "tmp":
                temporary_fd = os.open("tmp", DIRECTORY, dir_fd=root_fd)
                try:
                    owned(os.fstat(temporary_fd), True)
                finally:
                    os.close(temporary_fd)
            if not target.exists():
                os.mkdir("target", 0o700, dir_fd=root_fd)
        finally:
            os.close(root_fd)
    else:
        # An effective path alone does not grant cleanup authority. The only
        # normal domain is the ignored target of this exact checkout/mirror.
        canonical = workspace / "target"
        if target != canonical:
            # First compare identities without imposing canonical ownership on
            # unrelated external targets. Only a matching alias gains authority.
            try:
                selected = os.stat(target)
                canonical_st = os.stat(canonical)
                same = identity(selected) == identity(canonical_st)
            except FileNotFoundError:
                same = False
            if not same:
                require(not related_paths(target, canonical), "overlapping-target")
                return workspace, target, None
            root_fd = open_chain(workspace)
            canonical_fd = None
            try:
                canonical_fd = os.open("target", DIRECTORY, dir_fd=root_fd)
                require(identity(selected) == identity(os.fstat(canonical_fd)), "entry-changed")
                owned(os.fstat(root_fd), True)
                owned(os.fstat(canonical_fd), True)
            finally:
                if canonical_fd is not None:
                    os.close(canonical_fd)
                os.close(root_fd)
            target = canonical
            protect_target(target, protected)
        require(git(workspace, "check-ignore", "-q", "--", "target/").returncode == 0,
                "target-not-ignored")
        root = workspace
        if not target.exists():
            root_fd = open_chain(root)
            try:
                owned(os.fstat(root_fd), True)
                os.mkdir("target", 0o700, dir_fd=root_fd)
            finally:
                os.close(root_fd)
    if beneath(target, workspace):
        tracked = git(workspace, "ls-files", "-z", "--", str(target.relative_to(workspace)))
        require(tracked.returncode == 0 and not tracked.stdout, "git-tracked-target")
    root_fd = open_chain(root)
    try:
        owned(os.fstat(root_fd), True)
        target_fd = os.open("target", DIRECTORY, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        owned(os.fstat(target_fd), True)
    except BaseException:
        os.close(target_fd)
        raise
    return workspace, target, target_fd


class Cache:
    def __init__(self, target, fd, common=None):
        self.target, self.fd = target, fd  # Target fd remains owned by the caller.
        self.subject = identity(os.fstat(fd))
        self.profile_locks = {}
        self.exclusive = False
        self.payload_lease = self.lock = self.common_fd = None
        self.holders = "UNKNOWN"
        try:
            mounts = read_mountinfo() if sys.platform.startswith("linux") else {}
            self.mounts = set(mounts)
            self.fstype = filesystem_type(target, mounts)
            self.eviction_safe = self.fstype in LOCAL_FILESYSTEMS and not network_filesystem(self.fstype)
            require(target not in self.mounts and not os.path.ismount(target), "target-is-mount")
            self.common = common if common is not None else git_common_directory(target.parent)
            self.common_fd = open_chain(self.common)
            common_st = os.fstat(self.common_fd)
            owned(common_st, True)
            self.common_subject = identity(common_st)
            try:
                before = os.stat(LEASE, dir_fd=self.common_fd, follow_symlinks=False)
            except FileNotFoundError:
                before = None
            self.lock = os.open(LEASE, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                0o600, dir_fd=self.common_fd)
            st = os.fstat(self.lock)
            owned(st)
            require(st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600
                    and (before is None or identity(before) == identity(st))
                    and identity(st) == identity(os.stat(LEASE, dir_fd=self.common_fd,
                                                        follow_symlinks=False)), "unsafe-lease")
            os.set_inheritable(self.lock, False)
            try:
                fcntl.flock(self.lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Undetermined("helper-lease-held") from None
            self.binding()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.release_profiles()
        for name in ("payload_lease", "lock", "common_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def try_eviction(self):
        """Only an exclusive helper lease permits deletion under this target."""
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.holders = lease_holders(self.lock)
            # Conversion can drop SH; a bounded NB reacquire must succeed
            # before admission. A timeout never starts a payload unprotected.
            bounded_shared_lock(self.lock)
            self.binding()
            return False
        self.exclusive = True
        self.binding()
        return True

    def inherit_shared_lease(self):
        # Control stays CLOEXEC; only duplicate a successfully downgraded SH.
        bounded_shared_lock(self.lock)
        self.exclusive = False
        self.binding()
        self.payload_lease = os.dup(self.lock)
        os.set_inheritable(self.payload_lease, True)

    def binding(self):
        for path, subject in ((self.target, self.subject), (self.common, self.common_subject)):
            fd = open_chain(path)
            try:
                require(identity(os.fstat(fd)) == subject,
                        "target-identity-changed" if path == self.target else "lease-identity-changed")
            finally:
                os.close(fd)
        require(identity(os.stat(LEASE, dir_fd=self.common_fd, follow_symlinks=False)) ==
                identity(os.fstat(self.lock)), "lease-identity-changed")

    def measure(self):
        self.binding()
        seen, entries, total = set(), 0, 0
        start = time.monotonic()
        offenders, offender_count = [], 0

        def check(st, relative, directory=False, link=False):
            # Record a per-entry refusal and keep scanning so the receipt can
            # name every offender; the admission still refuses after the scan.
            nonlocal offender_count
            try:
                owned_at(st, relative, directory, link)
            except Undetermined as error:
                if not error.offenders:
                    raise
                offender_count += 1
                if len(offenders) < MAX_OFFENDERS:
                    offenders.extend(error.offenders)
                return str(error) != "unreadable-directory"
            return True

        def visit(fd, relative, depth):
            nonlocal entries, total, offender_count
            require(depth <= MAX_DEPTH, "traversal-depth-bound")
            st = os.fstat(fd)
            if not check(st, relative, True):
                return
            if identity(st) not in seen:
                total += st.st_blocks * 512
                seen.add(identity(st))
            with os.scandir(fd) as children:
                for entry in children:
                    entries += 1
                    require(entries <= MAX_ENTRIES and time.monotonic() - start < MAX_SECONDS,
                            "traversal-bound")
                    rel = relative / entry.name
                    before = entry.stat(follow_symlinks=False)
                    if protected_interior(entry.name, rel):
                        # Name the protected entry exactly like every other
                        # per-entry refusal, then keep scanning: admission still
                        # refuses, and the receipt says WHICH entry and where.
                        offender_count += 1
                        if len(offenders) < MAX_OFFENDERS:
                            offenders.append(offender(before, rel, "protected-interior"))
                        continue
                    path = self.target / rel
                    require(path not in self.mounts and not os.path.ismount(path), "interior-mount")
                    require(before.st_dev == self.subject[0], "foreign-filesystem")
                    if stat.S_ISDIR(before.st_mode):
                        child = os.open(entry.name, DIRECTORY, dir_fd=fd)
                        try:
                            require(identity(before) == identity(os.fstat(child)), "entry-changed")
                            visit(child, rel, depth + 1)
                        finally:
                            os.close(child)
                    else:
                        if stat.S_ISLNK(before.st_mode):
                            # Symlinks are opaque leaves, including broken links and venvs.
                            check(before, rel, link=True)
                        else:
                            check(before, rel)
                        if identity(before) not in seen:
                            total += before.st_blocks * 512
                            seen.add(identity(before))
        try:
            visit(self.fd, Path(), 0)
        except (Undetermined, OSError):
            # The first offender preceded this failure, so it remains the refusal
            # reason, as it was when the scan stopped at the first offender.
            if not offender_count:
                raise
            raise Undetermined(offenders[0]["reason"], offenders, offender_count,
                               complete=False) from None
        if offender_count:
            raise Undetermined(offenders[0]["reason"], offenders, offender_count)
        self.binding()
        return total

    def nested_profile(self, parts):
        """True when every segment is a REAL directory, never a symlink.

        A symlink is an opaque leaf to both walks, so following one here would
        let a profile outside the target be locked or evicted.
        """
        parent = self.fd
        opened = []
        try:
            for part in parts:
                try:
                    before = os.stat(part, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                if not stat.S_ISDIR(before.st_mode):
                    return False
                child = os.open(part, DIRECTORY, dir_fd=parent)
                opened.append(child)
                require(identity(before) == identity(os.fstat(child)), "entry-changed")
                parent = child
            return True
        finally:
            for fd in reversed(opened):
                os.close(fd)

    def nested_trybuild_profiles(self):
        """The nested cargo profiles trybuild actually creates.

        trybuild passes `--target <TRIPLE>` by DEFAULT (its `target()` returns the
        triple unless the `trybuild_no_target` cfg is set, and csq sets nothing),
        so the real output is tests/trybuild/<TRIPLE>/debug. A build that did set
        that cfg uses tests/trybuild/debug. BOTH are counted toward the cap, so
        both must be reclaimable or the cap wedges. Every segment is checked by
        `nested_profile`, so a symlinked tests/ or tests/trybuild/ is never a
        profile and nothing behind it is entered.
        """
        result = []
        if not self.nested_profile(("tests", "trybuild")):
            return result
        if self.nested_profile(("tests", "trybuild", "debug")):
            result.append(Path("tests") / "trybuild" / "debug")
        tests = os.open("tests", DIRECTORY, dir_fd=self.fd)
        try:
            trybuild = os.open("trybuild", DIRECTORY, dir_fd=tests)
            try:
                count, started = 0, time.monotonic()
                with os.scandir(trybuild) as children:
                    for entry in children:
                        count += 1
                        require(count <= MAX_ENTRIES and
                                time.monotonic() - started < MAX_SECONDS,
                                "traversal-bound")
                        if not re.fullmatch(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+",
                                            entry.name):
                            continue
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        parts = ("tests", "trybuild", entry.name, "debug")
                        if self.nested_profile(parts):
                            result.append(Path(*parts))
            finally:
                os.close(trybuild)
        finally:
            os.close(tests)
        return result

    def profiles(self):
        result = []
        count, started = 0, time.monotonic()
        with os.scandir(self.fd) as children:
            for entry in children:
                count += 1
                require(count <= MAX_ENTRIES and time.monotonic() - started < MAX_SECONDS,
                        "traversal-bound")
                if entry.name == "debug" and entry.is_dir(follow_symlinks=False):
                    result.append(Path("debug"))
                elif entry.name == "tests":
                    # trybuild's nested cargo builds under tests/trybuild and
                    # takes THAT directory's .cargo-lock, so it is a cache
                    # profile for lock/evict purposes exactly when it is a real
                    # directory. Measured wedge: its bytes count toward the cap,
                    # so omitting it here evicted every real profile and still
                    # refused admission. `nested_profile` rejects a symlinked
                    # part, which the walks treat as an opaque leaf.
                    result.extend(self.nested_trybuild_profiles())
                elif (entry.is_dir(follow_symlinks=False) and
                      re.fullmatch(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+", entry.name)):
                    child = os.open(entry.name, DIRECTORY, dir_fd=self.fd)
                    try:
                        if stat.S_ISDIR(os.stat("debug", dir_fd=child, follow_symlinks=False).st_mode):
                            result.append(Path(entry.name) / "debug")
                    except FileNotFoundError:
                        pass  # A recognized triple need not contain a debug profile.
                    finally:
                        os.close(child)
        return sorted(result)

    def lock_profile(self, profile):
        """Take Cargo's own build lock nonblocking before any profile deletion."""
        self.binding()
        parent = self.fd
        opened = []
        lock = None
        try:
            for part in profile.parts:
                parent = os.open(part, DIRECTORY, dir_fd=parent)
                opened.append(parent)
                owned(os.fstat(parent), True)
            try:
                before = os.stat(".cargo-lock", dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                before = None
            if before is not None:
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                        "unsafe-cargo-build-lock")
            lock = os.open(".cargo-lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                           0o600, dir_fd=parent)
            st = os.fstat(lock)
            owned(st)
            require(st.st_nlink == 1 and (before is None or identity(before) == identity(st))
                    and identity(st) == identity(os.stat(".cargo-lock", dir_fd=parent,
                                                        follow_symlinks=False)),
                    "unsafe-cargo-build-lock")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            os.set_inheritable(lock, False)
            self.profile_locks[profile] = lock
            lock = None
            return True
        finally:
            if lock is not None:
                os.close(lock)
            for fd in reversed(opened):
                os.close(fd)

    def release_profiles(self):
        for lock in self.profile_locks.values():
            os.close(lock)
        self.profile_locks.clear()

    def evict(self, relative):
        # A complete known cache directory is the smallest eviction unit. Never
        # truncate/chmod files: a cache inode can be hardlinked outside target.
        self.binding()
        require(self.exclusive, "helper-exclusive-lease-required")
        require(relative.parent in self.profile_locks, "cargo-build-lock-required")
        parent = self.fd
        opened = []
        try:
            for part in relative.parts[:-1]:
                parent = os.open(part, DIRECTORY, dir_fd=parent)
                opened.append(parent)
            name = relative.name
            path = self.target / relative
            require(path not in self.mounts and not os.path.ismount(path), "interior-mount")
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if stat.S_ISLNK(before.st_mode):
                owned_at(before, relative, link=True)
                os.unlink(name, dir_fd=parent)
                return True
            fd = os.open(name, DIRECTORY, dir_fd=parent)
            require(identity(before) == identity(os.fstat(fd)), "entry-changed")
            try:
                owned_at(os.fstat(fd), relative, True)
                require(os.fstat(fd).st_dev == self.subject[0], "foreign-filesystem")
                count, started = 0, time.monotonic()
                def remove(contents, rel, depth):
                    nonlocal count
                    require(depth <= MAX_DEPTH, "traversal-depth-bound")
                    with os.scandir(contents) as children:
                        for entry in children:
                            count += 1
                            require(count <= MAX_ENTRIES and time.monotonic() - started < MAX_SECONDS,
                                    "traversal-bound")
                            path = self.target / rel / entry.name
                            require(path not in self.mounts and not os.path.ismount(path),
                                    "interior-mount")
                            st = entry.stat(follow_symlinks=False)
                            require(st.st_dev == self.subject[0], "foreign-filesystem")
                            if protected_interior(entry.name, rel / entry.name):
                                raise Undetermined(
                                    "protected-interior",
                                    [offender(st, rel / entry.name, "protected-interior")],
                                    complete=False)
                            if stat.S_ISDIR(st.st_mode):
                                owned_at(st, rel / entry.name, True)
                                nested = os.open(entry.name, DIRECTORY, dir_fd=contents)
                                try:
                                    require(identity(st) == identity(os.fstat(nested)), "entry-changed")
                                    remove(nested, rel / entry.name, depth + 1)
                                finally:
                                    os.close(nested)
                                os.rmdir(entry.name, dir_fd=contents)
                            else:
                                if stat.S_ISLNK(st.st_mode):
                                    owned_at(st, rel / entry.name, link=True)
                                else:
                                    owned_at(st, rel / entry.name)
                                os.unlink(entry.name, dir_fd=contents)
                remove(fd, relative, 0)
                require(identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=parent,
                            follow_symlinks=False)), "entry-changed")
                os.rmdir(name, dir_fd=parent)
            finally:
                os.close(fd)
            return True
        finally:
            for fd in reversed(opened):
                os.close(fd)


REMEDIATION = {
    "invalid-path": "Supply a nonempty target path without control characters.",
    "path-traversal": "Supply an absolute target path without parent traversal.",
    "unexpected-system-alias": "Restore the standard system temporary-directory alias before retrying.",
    "workspace-manifest-missing": "Select the Git workspace root containing Cargo.toml.",
    "workspace-not-git-root": "Select the exact Git workspace root.",
    "target-selection-conflict": "Make the explicit target match Cargo's resolved target.",
    "git-common-unreadable": "Restore access to the workspace Git common directory.",
    "git-output-bound": "Inspect the oversized Git identity response before retrying.",
    "protected-target": "Select a target disjoint from Git, Cargo and Rustup state.",
    "overlapping-target": "Select the canonical target or a physically disjoint external target.",
    "over-cap-concurrent": "Release inactive lease holders or reclaim the inactive target before retrying.",
    "unknown-ephemeral-domain": "Use a private managed csq-windows-compile temporary root.",
    "ephemeral-root-not-private": "Restore mode 0700 on the managed temporary root.",
    "target-not-ignored": "Ignore the workspace target directory before authorizing eviction.",
    "git-tracked-target": "Move tracked files out of target before authorizing eviction.",
    "foreign-owner": "Have the target owner inspect and relocate foreign-owned entries.",
    "unsafe-permissions": "Have the owner remove group and other write access from target entries.",
    "unreadable-directory": "Restore owner read and search access on target directories.",
    "unreadable-or-special-entry": "Have the owner relocate unreadable files or special entries outside target.",
    "unsafe-lease": "Stop admissions and have the owner replace the lease with a private regular file.",
    "helper-lease-held": "Wait for the active exclusive target operation to finish before retrying.",
    "helper-exclusive-lease-required": "Repair the helper so it acquires the exclusive target lease before eviction.",
    "target-identity-changed": "Stop target replacement and retry against the original workspace target.",
    "lease-identity-changed": "Stop lease replacement and retry with a stable private lease.",
    "traversal-depth-bound": "Have the owner relocate deeply nested preserved content outside target.",
    "traversal-bound": "Have the owner reduce target entries or reclaim the inactive target before retrying.",
    "protected-interior": "Have the owner relocate protected source or toolchain content outside target.",
    "target-is-mount": "Choose an authorized target that is not a mount point.",
    "interior-mount": "Have the owner unmount or relocate mounted content before retrying.",
    "foreign-filesystem": "Have the owner relocate cross-filesystem content outside target.",
    "entry-changed": "Stop concurrent target mutations and retry admission.",
    "cargo-build-lock-held": "Wait for Cargo to release the skipped profile lock before retrying.",
    "unsafe-cargo-build-lock": "Stop Cargo and have the owner replace the profile lock with a private single-link regular file.",
    "cargo-build-lock-required": "Repair the helper so it acquires Cargo's profile lock before eviction.",
    "preserved-bytes-exceed-cap": "Have the owner move preserved artifacts outside target or reclaim them manually.",
    "invalid-cap": "Supply a positive integer cap no greater than the 32 GiB policy limit.",
    "whole-leg-command-required": "Supply the complete workload command after --.",
    "payload-target-override": "Resolve target selection before admission and remove payload target overrides.",
    "nofollow-unavailable": "Use a supported Python platform providing O_NOFOLLOW and O_DIRECTORY.",
    "mountinfo-unreadable": "Restore readable valid mount information before retrying on Linux.",
    "helper-internal-error": "Repair the helper internal failure before retrying admission.",
    "subprocess-unavailable": "Restore Git subprocess availability before retrying admission.",
    "io-error-eacces": "Restore owner access to the target path before retrying admission.",
    "io-error-eperm": "Have the owner resolve filesystem permission restrictions before retrying.",
    "io-error-enoent": "Restore the missing target path or command before retrying admission.",
    "io-error-enotdir": "Restore directory components in the target path before retrying.",
    "io-error-eloop": "Have the owner remove symlinks from the target authority chain before retrying.",
    "io-error-enospc": "Have the owner reclaim disk space before retrying admission.",
    "io-error-erofs": "Restore write access to the target filesystem before retrying.",
    "io-error-eio": "Restore healthy filesystem I/O before retrying admission.",
    "io-error-ebusy": "Stop the conflicting filesystem operation before retrying admission.",
    "io-error-estale": "Restore a stable target filesystem binding before retrying.",
}


def receipt(status, cap, before=None, after=None, actions=None, reason=None, skipped=None,
            holders="UNKNOWN", fstype=None, refusal=None):
    remediation = None
    if status == "UNDETERMINED":
        remediation = REMEDIATION.get(reason, "Repair the helper unclassified admission failure before retrying.")
    body = {"instrument": "cargo-target-highwater",
            "scope": "exclusive-cargo-target", "status": status,
            "cap_bytes": cap, "before_bytes": before, "after_bytes": after,
            "actions": actions or [], "reason": reason,
            "remediation": remediation, "skipped_profiles": skipped or [],
            "lease_holders": holders, "filesystem_type": fstype or "UNKNOWN"}
    if refusal is not None and refusal.offenders:
        first = refusal.offenders[0]
        more = refusal.offender_count - 1
        # Entry metadata only; json.dumps quotes the path so control bytes stay escaped.
        print("cargo-target-highwater: refused " + reason + ": first offender " +
              json.dumps(first["path"]) + " (" + first["type"] + ", mode " + first["mode"] +
              ", uid " + str(first["uid"]) + ")" +
              (", " + str(more) + " more" if more > 0 else "") +
              ("" if refusal.offender_scan_complete else ", scan stopped early"),
              file=sys.stderr, flush=True)
        body["offenders"] = refusal.offenders
        body["offender_count"] = refusal.offender_count
        body["offender_scan_complete"] = refusal.offender_scan_complete
    print(json.dumps(body, sort_keys=True), file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=os.getcwd())
    parser.add_argument("--resolved-target", required=True)
    parser.add_argument("--target-dir", default="")
    parser.add_argument("--cap-bytes", type=int, default=LIMIT)
    parser.add_argument("--ephemeral-root", default="")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    before = after = None
    actions, skipped = [], []
    cache = fd = None
    try:
        require(0 < args.cap_bytes <= LIMIT, "invalid-cap")
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        require(command, "whole-leg-command-required")
        require(not any("--target-dir" in arg or "--config" in arg or
                        re.search(r"CARGO_(?:BUILD_)?TARGET_DIR\s*=", arg)
                        for arg in command), "payload-target-override")
        workspace, target, fd = authorize(args)
        if fd is None:
            receipt("NOT_APPLICABLE", args.cap_bytes,
                    reason="external-target: not under budget authority")
            os.chdir(workspace)
            os.execvpe(command[0], command, os.environ)
        cache = Cache(target, fd, common=git_common_directory(workspace))
        before = after = cache.measure()
        if after > args.cap_bytes and not cache.eviction_safe:
            actions.append("eviction-skipped:network-fs")
        elif after > args.cap_bytes and cache.try_eviction():
            profiles = cache.profiles()
            if after > args.cap_bytes:
                available = []
                for profile in profiles:
                    if cache.lock_profile(profile):
                        available.append(profile)
                    else:
                        skipped.append({"profile": str(profile), "reason": "cargo-build-lock-held"})
                profiles = available
            if after > args.cap_bytes:
                after = None  # A partially failed eviction has no measured after-size.
                for profile in profiles:
                    if cache.evict(profile / "incremental"):
                        actions.append("incremental")
                after = cache.measure()
            if after > args.cap_bytes:
                after = None
                # Evict the whole dependency/fingerprint/build cohort together.
                # Top-level binaries, examples, release and unknown directories stay.
                for profile in profiles:
                    for name in (".fingerprint", "build", "deps"):
                        if cache.evict(profile / name):
                            actions.append("debug-cache:" + name)
                after = cache.measure()
            require(after <= args.cap_bytes,
                    "cargo-build-lock-held" if skipped else "preserved-bytes-exceed-cap")
        elif after > args.cap_bytes:
            require(after <= min(LIMIT, args.cap_bytes * 2), "over-cap-concurrent")
            actions.append("eviction-skipped:concurrent-leg")
        cache.binding()
        cache.release_profiles()
        cache.inherit_shared_lease()
        receipt("ADMITTED", args.cap_bytes, before, after, actions, skipped=skipped,
                holders=cache.holders, fstype=cache.fstype)
        os.chdir(workspace)
        os.execvpe(command[0], command, os.environ)
    except Exception as error:
        if isinstance(error, Undetermined):
            reason = str(error)
        elif isinstance(error, OSError):
            reason = "io-error-" + errno.errorcode.get(error.errno, "UNKNOWN").lower()
        elif isinstance(error, subprocess.SubprocessError):
            reason = "subprocess-unavailable"
        else:
            reason = "helper-internal-error"
        receipt("UNDETERMINED", args.cap_bytes, before, after, actions, reason, skipped,
                holders=cache.holders if cache is not None else "UNKNOWN",
                fstype=cache.fstype if cache is not None else None,
                refusal=error if isinstance(error, Undetermined) else None)
        return 75
    finally:
        if cache is not None:
            cache.close()
        if fd is not None:
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
