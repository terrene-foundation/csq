#!/usr/bin/env python3
"""Preseed Tauri CLI 2.11.5's five Linux tools and explicit AppImage runtime.

The official CLI tag embeds tauri-bundler 2.9.4. Its prepare_tools() uses
$XDG_CACHE_HOME/tauri when bundle.useLocalToolsDir=false, and otherwise downloads
missing files. Pass --config "$CSQ_TAURI_LINUX_TOOLS_CONFIG" to Tauri and verify
again after bundling. A fresh, private cache prevents reuse of host tools.
LDAI_RUNTIME_FILE selects the verified runtime through the AppImage plugin's
--runtime-file option; appimagetool refuses an unreadable explicit runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import urllib.request

PIN = Path(__file__).with_name("tauri-linux-tools.json")
COMMIT = "9452ddee5ebefd9b678a94ff003521379df6c9ae"
CLI_NAMES = {"AppRun-x86_64", "linuxdeploy-x86_64.AppImage", "linuxdeploy-plugin-gtk.sh",
         "linuxdeploy-plugin-gstreamer.sh", "linuxdeploy-plugin-appimage.AppImage"}
RUNTIME_NAME = "runtime-x86_64"
NAMES = CLI_NAMES | {RUNTIME_NAME}
ASSETS = {"linuxdeploy-plugin-appimage.AppImage":
          ("linuxdeploy/linuxdeploy-plugin-appimage", "linuxdeploy-plugin-appimage-x86_64.AppImage"),
          RUNTIME_NAME: ("AppImage/type2-runtime", RUNTIME_NAME)}
MAX_BYTES = 64 * 1024 * 1024
RECEIPT = ".csq-tauri-linux-tools.json"
CONFIG = "tauri-linux-tools.config.json"


class Refused(ValueError):
    """Measured pin, cache, or configuration violation."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_pin(path=PIN):
    raw = path.read_bytes()
    if len(raw) > 32768:
        raise Refused("pin file exceeds bound")
    pin = json.loads(raw)
    if not isinstance(pin, dict):
        raise Refused("pin must be an object")
    if (pin.get("schema") != 1 or pin.get("tauri_cli_version") != "2.11.5"
            or pin.get("tauri_bundler_version") != "2.9.4" or pin.get("tauri_commit") != COMMIT
            or pin.get("arch") != "x86_64"):
        raise Refused("unsupported toolchain identity")
    records = pin.get("tools")
    if not isinstance(records, list) or len(records) != len(NAMES):
        raise Refused("incomplete tool pin set")
    names = set()
    for record in records:
        if not isinstance(record, dict):
            raise Refused("tool pin must be an object")
        name = record.get("name")
        if name not in NAMES or name in names:
            raise Refused("unexpected or duplicate tool name")
        names.add(name)
        expected_role = "appimage-runtime" if name == RUNTIME_NAME else "tauri-prepare-tool"
        if record.get("role") != expected_role:
            raise Refused("tool role does not match its cache contract")
        for field in ("sha256", "installed_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(record.get(field, ""))):
                raise Refused("invalid SHA256 pin")
        size = record.get("size")
        if type(size) is not int or not 1 <= size <= MAX_BYTES:
            raise Refused("invalid download size bound")
        url = record.get("url", "")
        if name.endswith(".sh"):
            repo = name[:-3]
            revision = record.get("revision", "")
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                raise Refused("plugin must use an exact source commit")
            expected = f"https://raw.githubusercontent.com/tauri-apps/{repo}/{revision}/{name}"
        elif name in ASSETS:
            asset_id = record.get("asset_id")
            repo, asset_name = ASSETS[name]
            if type(asset_id) is not int or not 1 <= asset_id < 2**63 or record.get("asset_name") != asset_name:
                raise Refused("invalid immutable release asset identity")
            expected = f"https://api.github.com/repos/{repo}/releases/assets/{asset_id}"
        else:
            tag = "apprun-old" if name == "AppRun-x86_64" else "linuxdeploy"
            expected = f"https://github.com/tauri-apps/binary-releases/releases/download/{tag}/{name}"
        if url != expected or not record.get("version"):
            raise Refused("tool URL or version is not bound to its identity")
        if name != "linuxdeploy-x86_64.AppImage" and record["sha256"] != record["installed_sha256"]:
            raise Refused("unexpected tool normalization")
    return pin, digest(raw)


def no_symlinks(path):
    for item in [path, *path.parents]:
        if item.is_symlink():
            raise Refused("symlink cache/source path")


def checked_bytes(stream, record, deadline):
    data = bytearray()
    while True:
        if time.monotonic() > deadline:
            raise Refused("download time bound exceeded")
        chunk = stream.read(min(65536, record["size"] + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > record["size"]:
            raise Refused("download size bound exceeded")
    if len(data) != record["size"] or digest(data) != record["sha256"]:
        raise Refused("download size/SHA256 mismatch: " + record["name"])
    return bytes(data)


def installed_bytes(data, record):
    # This is exactly the upstream prepare_tools dd at bytes 8..10, performed
    # before installation so post-bundle integrity checks have a stable digest.
    if record["name"] == "linuxdeploy-x86_64.AppImage":
        data = data[:8] + bytes(3) + data[11:]
    if digest(data) != record["installed_sha256"]:
        raise Refused("installed SHA256 mismatch")
    return data


def verify_cache(cache, pin, identity):
    no_symlinks(cache)
    if not cache.is_absolute() or not cache.is_dir():
        raise Refused("cache must be an absolute private directory")
    info = cache.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused("cache must be owned by this user with mode 0700")
    receipt = cache / RECEIPT
    no_symlinks(receipt)
    if json.loads(receipt.read_text()) != {"pin_sha256": identity}:
        raise Refused("cache pin identity mismatch")
    tools = cache / "tauri"
    no_symlinks(tools)
    if {p.name for p in tools.iterdir()} != NAMES:
        raise Refused("cache has missing or unexpected tools")
    for record in pin["tools"]:
        path = tools / record["name"]
        no_symlinks(path)
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size != record["size"]
                or stat.S_IMODE(info.st_mode) != 0o700
                or digest(path.read_bytes()) != record["installed_sha256"]):
            raise Refused("cached tool integrity mismatch: " + record["name"])
    config = cache / CONFIG
    no_symlinks(config)
    if json.loads(config.read_text()) != {"bundle": {"useLocalToolsDir": False}}:
        raise Refused("cache selector config mismatch")
    return tools


def preseed(cache, pin, identity, source=None):
    no_symlinks(cache)
    if not cache.is_absolute() or cache == Path.home() / ".cache":
        raise Refused("use an absolute job-owned cache, not the host cache")
    if cache.exists():
        verify_cache(cache, pin, identity)
        return
    cache.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".tauri-tools-", dir=cache.parent))
    try:
        os.chmod(stage, 0o700)
        tools = stage / "tauri"
        tools.mkdir(mode=0o700)
        deadline = time.monotonic() + 120
        for record in pin["tools"]:
            if source is not None:
                path = source / record["name"]
                no_symlinks(path)
                with path.open("rb") as stream:
                    data = checked_bytes(stream, record, deadline)
            else:
                headers = {"User-Agent": "csq-tauri-tool-preseed/1"}
                if record["name"] in ASSETS:
                    headers["Accept"] = "application/octet-stream"
                request = urllib.request.Request(record["url"], headers=headers)
                with urllib.request.urlopen(request, timeout=15) as stream:
                    data = checked_bytes(stream, record, deadline)
            path = tools / record["name"]
            with path.open("xb") as output:
                output.write(installed_bytes(data, record))
                output.flush()
                os.fsync(output.fileno())
            path.chmod(0o700)
        (stage / RECEIPT).write_text(json.dumps({"pin_sha256": identity}))
        (stage / CONFIG).write_text(json.dumps({"bundle": {"useLocalToolsDir": False}}))
        verify_cache(stage, pin, identity)
        # A competing writer cannot replace a nonempty destination directory.
        stage.rename(cache)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def cache_environment(cache):
    return {"XDG_CACHE_HOME": str(cache), "APPIMAGE_EXTRACT_AND_RUN": "1",
            "LDAI_RUNTIME_FILE": str(cache / "tauri" / RUNTIME_NAME),
            "CSQ_TAURI_LINUX_TOOLS_CONFIG": str(cache / CONFIG)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--source-dir", type=Path, help="offline source files; all pins still verified")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        cache = args.cache_dir.absolute()
        if any(c in str(cache) for c in "\r\n"):
            raise Refused("invalid cache path")
        pin, identity = load_pin()
        if not args.verify_only:
            preseed(cache, pin, identity, args.source_dir)
        tools = verify_cache(cache, pin, identity)
        environment = cache_environment(cache)
        if args.verify_only and any(os.environ.get(k) != v for k, v in environment.items()):
            raise Refused("bundle environment does not select the verified cache")
        if args.github_env:
            with args.github_env.open("a") as output:
                output.write("".join(f"{k}={v}\n" for k, v in environment.items()))
        print(f"VERIFIED tauri-cli=2.11.5 bundler=2.9.4 pin_sha256={identity} tools={tools}")
        return 0
    except Refused as exc:
        print("REFUSED: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("UNDETERMINED: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
