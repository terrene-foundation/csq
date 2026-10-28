#!/usr/bin/env python3
"""Bound release transfers and verify complete signing-tool payloads. 0=yes, 1=no, 2=unknown."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MAX_BYTES = 2 * 1024**3
MAX_EXPANDED = 4 * 1024**3
MAX_FILES = 20000
CHUNK = 1024 * 1024
VERSION = "2.11.5"
PACKAGES = ("@tauri-apps/cli", "@tauri-apps/cli-linux-x64-gnu")


class Mismatch(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Mismatch(message)


def digest_file(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(data):
    try:
        return json.loads(data, object_pairs_hook=pairs_unique)
    except (ValueError, UnicodeError) as exc:
        raise Mismatch("invalid JSON") from exc


def sha256(value):
    require(re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value) is not None,
            "invalid SHA256")
    return value.removeprefix("sha256:")


def safe_name(name):
    require(isinstance(name, str) and name and "\\" not in name and
            not any(ord(c) < 32 or c == ":" for c in name), "unsafe archive path")
    parts = name.rstrip("/").split("/")
    require(all(p not in ("", ".", "..") and p == p.rstrip(" .") for p in parts),
            "unsafe archive path")
    require(not PurePosixPath(name).is_absolute(), "absolute archive path")
    return "/".join(parts)


def add_name(seen, name, directory=False):
    name = safe_name(name)
    parts = name.split("/")
    require(len(parts) <= 64 and len(name) <= 4096, "archive path bound")
    for index in range(1, len(parts) + 1):
        prefix = "/".join(parts[:index])
        key = unicodedata.normalize("NFC", prefix).casefold()
        leaf = index == len(parts)
        if key in seen:
            spelling, isdir, explicit = seen[key]
            require(spelling == prefix and isdir and (not leaf or (directory and not explicit)),
                    "duplicate, parent or case-colliding archive path")
        seen[key] = (prefix, directory if leaf else True, leaf or seen.get(key, (None, None, False))[2])
        require(len(seen) <= MAX_FILES, "archive entry bound")
    return name


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, sink, limit, token=None, redirects=False):
    """Only the initial GitHub API request receives authorization; redirects receive none."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 300
    for hop in range(6):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname and not parsed.username and
                not parsed.password and parsed.port in (None, 443), "unsafe download URL")
        headers = {"User-Agent": "csq-release-artifact-guard", "Accept": "application/vnd.github+json"}
        if token and hop == 0:
            require(parsed.netloc == "api.github.com", "credential destination rejected")
            headers["Authorization"] = "Bearer " + token
        try:
            response = opener.open(urllib.request.Request(url, headers=headers), timeout=30)
        except urllib.error.HTTPError as exc:
            if redirects and exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                url = urllib.parse.urljoin(url, exc.headers["Location"])
                exc.close()
                continue
            raise OSError("HTTP measurement unavailable") from None
        with response:
            require(response.status == 200, "unexpected HTTP status")
            length = response.headers.get("Content-Length")
            require(length is None or (length.isdigit() and int(length) <= limit), "download too large")
            total = 0
            while True:
                if time.monotonic() > deadline:
                    raise OSError("download deadline exceeded")
                block = response.read1(min(CHUNK, limit - total + 1))
                if not block:
                    return
                total += len(block)
                require(total <= limit, "download too large")
                sink.write(block)
    raise OSError("redirect limit exceeded")


def extract_zip(archive, root):
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        require(0 < len(entries) <= MAX_FILES, "archive entry bound")
        require(sum(e.file_size for e in entries) <= MAX_EXPANDED, "archive expansion bound")
        seen = {}
        planned = []
        for entry in entries:
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "archive special file")
            require(not entry.flag_bits & 1, "encrypted archive")
            require(entry.file_size <= max(entry.compress_size, 1) * 1000, "archive expansion ratio")
            name = add_name(seen, entry.filename, entry.is_dir())
            planned.append((entry, root / name, mode))
        for entry, target, mode in planned:
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry) as source, target.open("xb") as dest:
                total = 0
                while block := source.read(CHUNK):
                    total += len(block)
                    require(total <= entry.file_size, "archive size mismatch")
                    dest.write(block)
                require(total == entry.file_size, "archive size mismatch")
            target.chmod(0o755 if mode & 0o111 else 0o644)


def download(args):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is not None,
            "invalid repository")
    require(args.run_id.isdigit() and args.artifact_id.isdigit(), "invalid artifact identity")
    expected = sha256(args.sha256)
    require(re.fullmatch(r"[0-9a-f]{40}", args.head_sha) is not None, "invalid head SHA")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise OSError("GH_TOKEN unavailable")
    url = f"https://api.github.com/repos/{args.repository}/actions/artifacts/{args.artifact_id}"
    metadata = io.BytesIO()
    fetch(url, metadata, 1024 * 1024, token)
    data = read_json(metadata.getvalue())
    require(isinstance(data, dict), "invalid artifact metadata")
    run = data.get("workflow_run") or {}
    require(data.get("id") == int(args.artifact_id) and run.get("id") == int(args.run_id)
            and run.get("head_sha") == args.head_sha and data.get("expired") is False,
            "artifact identity mismatch")
    if data.get("digest"):
        require(data["digest"] == "sha256:" + expected, "artifact metadata digest mismatch")
    output = Path(args.output).absolute()
    require(not output.exists() and not output.is_symlink(), "output must not exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".artifact-", dir=output.parent) as tmp:
        tmp = Path(tmp)
        archive = tmp / "artifact.zip"
        with archive.open("xb") as sink:
            fetch(url + "/zip", sink, MAX_BYTES, token, redirects=True)
        require(digest_file(archive) == expected, "artifact ZIP digest mismatch")
        root = tmp / "content"
        root.mkdir()
        extract_zip(archive, root)
        root.rename(output)


def tree_files(root, excluded=None):
    if not root.exists() and not root.is_symlink():
        raise FileNotFoundError("tree unavailable")
    require(root.is_dir() and not root.is_symlink(), "invalid tree root")
    files, total = {}, 0
    seen = {}
    def unavailable(error):
        raise error
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=unavailable):
        for name in sorted(dirs + names):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "tree special file")
            rel = path.relative_to(root).as_posix()
            add_name(seen, rel, stat.S_ISDIR(mode))
            require(len(seen) <= MAX_FILES, "tree entry bound")
            if stat.S_ISREG(mode) and path != excluded:
                total += path.stat().st_size
                require(total <= MAX_EXPANDED, "tree size bound")
                files[rel] = digest_file(path)
    return files


def manifest(args):
    root, target = Path(args.root).absolute(), Path(args.manifest).absolute()
    files = tree_files(root, target)
    require(files, "empty manifest subject")
    expected = {"version": 1, "files": files}
    if args.command == "manifest-write":
        target.write_text(json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        require(target.stat().st_size <= 8 * 1024**2, "manifest too large")
        if args.sha256:
            require(digest_file(target) == sha256(args.sha256), "manifest digest mismatch")
        require(read_json(target.read_bytes()) == expected, "manifest tree mismatch")


def tar_files(blob):
    files, seen, total = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        for member in archive:
            require(member.isfile() or member.isdir(), "registry archive special file")
            name = add_name(seen, member.name, member.isdir())
            require(len(seen) <= MAX_FILES, "registry entry bound")
            require(name == "package" or name.startswith("package/"), "registry package prefix")
            if member.isfile():
                require(name.startswith("package/"), "registry package prefix")
                total += member.size
                require(total <= MAX_EXPANDED, "registry expansion bound")
                with archive.extractfile(member) as stream:
                    files[name[len("package/"):]] = hashlib.file_digest(stream, "sha256").hexdigest()
    require(files, "empty registry package")
    return files


def tauri_verify(args):
    project, lock = Path(args.project).absolute(), Path(args.lock)
    require(lock.stat().st_size <= 8 * 1024**2, "lock too large")
    document = read_json(lock.read_bytes())
    packages = document.get("packages", {})
    require(isinstance(packages, dict), "invalid lock packages")
    # Exact node_modules inventory also prevents NODE_PATH-style dependency substitution.
    expected_tree = {}
    for package in PACKAGES:
        entry = packages.get("node_modules/" + package, {})
        basename = package.split("/")[-1]
        url = f"https://registry.npmjs.org/{package}/-/{basename}-{VERSION}.tgz"
        require(entry.get("version") == VERSION and entry.get("resolved") == url,
                "Tauri lock identity mismatch")
        integrity = entry.get("integrity", "")
        require(re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", integrity) is not None,
                "Tauri lock requires SHA512 SRI")
        blob = io.BytesIO()
        fetch(url, blob, 128 * 1024**2)
        payload = blob.getvalue()
        require(base64.b64encode(hashlib.sha512(payload).digest()).decode() == integrity[7:],
                "registry tarball integrity mismatch")
        contents = tar_files(payload)
        installed = project / "node_modules" / package
        require(tree_files(installed) == contents, "installed Tauri package mismatch")
        expected_tree.update({package + "/" + name: digest for name, digest in contents.items()})
    require(tree_files(project / "node_modules") == expected_tree, "unexpected installed dependency")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("download")
    for name in ("repository", "run-id", "artifact-id", "sha256", "head-sha", "output"):
        command.add_argument("--" + name, required=True)
    command.set_defaults(action=download)
    for name in ("manifest-write", "manifest-check"):
        command = commands.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument("--manifest", required=True)
        command.add_argument("--sha256")
        command.set_defaults(action=manifest)
    command = commands.add_parser("tauri-verify")
    command.add_argument("--project", required=True)
    command.add_argument("--lock", required=True)
    command.set_defaults(action=tauri_verify)
    args = parser.parse_args(argv)
    try:
        args.action(args)
    except (Mismatch, zipfile.BadZipFile, tarfile.TarError) as exc:
        print("MISMATCH: " + (str(exc) if isinstance(exc, Mismatch) else "invalid archive"), file=sys.stderr)
        return 1
    except (OSError, TimeoutError, urllib.error.URLError):
        print("UNKNOWN: required input or transport unavailable", file=sys.stderr)
        return 2
    except (TypeError, KeyError, AttributeError, ValueError):
        print("MISMATCH: malformed input", file=sys.stderr)
        return 1
    print("VERIFIED: " + args.command)
    return 0


if __name__ == "__main__":
    sys.exit(main())
