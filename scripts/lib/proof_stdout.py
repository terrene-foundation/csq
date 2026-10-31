"""Private D2 raw stdout export; transport completeness is not product PASS."""
import hashlib
import json
from pathlib import Path
import re

PREFIX = b"D2_EXPORT_"

# The transport envelope needs only receipt -> rows -> row (3 containers)
# and manifest -> cases -> case -> edits -> edit (5). Allow 64 to leave ample
# room for embedded phase metadata while staying well below recursive JSON
# encoder stack limits. Lower/custom encoder limits remain exception-guarded.
# This bounds nesting only, never the number of phase rows or sibling values.
_MAX_JSON_NESTING = 64


class TransportUnavailable(RuntimeError):
    pass


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _check_json_structure(value, label):
    """Walk iteratively; reject excess container depth and ancestor cycles.

    Iterator frames use memory proportional to nesting, not sibling count.
    Only active ancestors are tracked, so repeated acyclic values stay valid.
    """
    def children(item):
        if isinstance(item, dict):
            return iter(item.values())
        if isinstance(item, (list, tuple)):
            return iter(item)
        return None

    try:
        iterator = children(value)
        if iterator is None:
            return
        identity = id(value)
        ancestors = {identity}
        stack = [(identity, iterator)]
        while stack:
            identity, iterator = stack[-1]
            try:
                item = next(iterator)
            except StopIteration:
                stack.pop()
                ancestors.remove(identity)
                continue
            iterator = children(item)
            if iterator is None:
                continue
            identity = id(item)
            if identity in ancestors:
                raise TransportUnavailable(label + " JSON contains a cycle")
            if len(stack) >= _MAX_JSON_NESTING:
                raise TransportUnavailable(label + " JSON exceeds the nesting budget")
            ancestors.add(identity)
            stack.append((identity, iterator))
    except TransportUnavailable:
        raise
    except Exception:
        raise TransportUnavailable(label + " JSON structure is unavailable") from None


def _record(stream, kind, value):
    _check_json_structure(value, "export record")
    try:
        encoded = json.dumps(value, sort_keys=True).encode()
    except Exception:
        raise TransportUnavailable("export record cannot be encoded") from None
    stream.write(PREFIX + kind.encode() + b" " + encoded + b"\n")
    stream.flush()


def emit(stream, output, manifest, payload_sha256):
    _check_json_structure(manifest, "export manifest")
    output = Path(output)
    files = {}
    for path in sorted(output.iterdir()):
        if not path.is_file() or path.is_symlink() or path.suffix not in (".log", ".json"):
            raise TransportUnavailable("export contains an unsupported artifact")
        raw = path.read_bytes()
        if any(line.startswith(PREFIX) for line in raw.splitlines()):
            raise TransportUnavailable("raw artifact contains ambiguous reserved framing")
        files[path.name] = raw
    if "receipt.json" not in files or "manifest.json" not in files:
        raise TransportUnavailable("export lacks final receipt or manifest")
    binding = {key: manifest[key] for key in ("commit", "tree", "platform")}
    _record(stream, "BEGIN", dict(payload_sha256=payload_sha256, **binding))
    index = []
    for name, raw in files.items():
        metadata = dict(name=name, bytes=len(raw), sha256=_sha(raw))
        _record(stream, "FILE_BEGIN", metadata)
        stream.write(raw); stream.write(b"\n")
        _record(stream, "FILE_END", metadata)
        index.append(metadata)
    _record(stream, "END", dict(payload_sha256=payload_sha256, files=index))


def _object_json(raw, label):
    try:
        value = json.loads(raw)
    except Exception:
        raise TransportUnavailable("malformed " + label + " JSON") from None
    _check_json_structure(value, label)
    if not isinstance(value, dict):
        raise TransportUnavailable(label + " must be an object")
    return value


def _source(value, manifest):
    return (isinstance(value, dict) and value.get("reference_commit") == manifest["commit"]
            and value.get("tree") == manifest["tree"] and value.get("clean") is True
            and value.get("ancestor") is True and isinstance(value.get("carried_head"), str)
            and re.fullmatch(r"[a-f0-9]{40}", value["carried_head"]) is not None)


def decode(native, manifest, payload_sha256, native_run):
    """Validate frames, every byte hash, source/cleanup and real native terminal."""
    if not isinstance(native, bytes):
        raise TransportUnavailable("native stdout bytes are unavailable")
    if not isinstance(manifest, dict) or any(not isinstance(manifest.get(key), str)
                                           for key in ("commit", "tree", "platform")):
        raise TransportUnavailable("final manifest identity is unavailable")
    if (not isinstance(payload_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", payload_sha256) is None
            or not isinstance(native_run, str) or re.fullmatch(r"r-[a-f0-9]{16}", native_run) is None):
        raise TransportUnavailable("native payload or run identity is unavailable")
    _check_json_structure(manifest, "final manifest")
    try:
        expected_manifest = (json.dumps(manifest, indent=2) + "\n").encode()
    except Exception:
        raise TransportUnavailable("final manifest cannot be encoded") from None
    offset = 0; begun = ended = False; cleanup = None; files = {}; index = []; terminals = []
    binding = {key: manifest[key] for key in ("commit", "tree", "platform")}
    while offset < len(native):
        newline = native.find(b"\n", offset)
        if newline < 0:
            if native[offset:].strip():
                raise TransportUnavailable("native stdout ends in an incomplete line")
            break
        line = native[offset:newline]; offset = newline + 1
        if terminals and line.strip():
            raise TransportUnavailable("native terminal must be the last nonblank record")
        if line.startswith(PREFIX):
            try:
                tag, raw = line[len(PREFIX):].split(b" ", 1)
            except ValueError:
                raise TransportUnavailable("malformed export record") from None
            value = _object_json(raw, "export record")
            if tag == b"BEGIN":
                if begun or ended or value != dict(payload_sha256=payload_sha256, **binding):
                    raise TransportUnavailable("duplicate or wrong export identity")
                begun = True
            elif tag == b"FILE_BEGIN":
                if not begun or ended or set(value) != {"name", "bytes", "sha256"}:
                    raise TransportUnavailable("artifact frame is out of order")
                name, size = value["name"], value["bytes"]
                if (not isinstance(name, str) or Path(name).name != name or name in files
                        or "\x00" in name or "\\" in name or type(size) is not int or size < 0
                        or Path(name).suffix not in (".log", ".json")):
                    raise TransportUnavailable("invalid artifact identity")
                body = native[offset:offset + size]; offset += size
                if len(body) != size or _sha(body) != value["sha256"] or native[offset:offset + 1] != b"\n":
                    raise TransportUnavailable("raw artifact length or digest differs")
                if any(part.startswith(PREFIX) for part in body.splitlines()):
                    raise TransportUnavailable("ambiguous raw artifact framing")
                offset += 1; ending = native.find(b"\n", offset)
                expected = PREFIX + b"FILE_END " + json.dumps(value, sort_keys=True).encode()
                if ending < 0 or native[offset:ending] != expected:
                    raise TransportUnavailable("raw artifact end frame is missing or differs")
                offset = ending + 1; files[name] = body; index.append(value)
            elif tag == b"END":
                if not begun or ended or value != dict(payload_sha256=payload_sha256, files=index):
                    raise TransportUnavailable("export index differs or is duplicated")
                ended = True
            elif tag == b"CLEANUP":
                if not ended or cleanup is not None or value.get("payload_sha256") != payload_sha256:
                    raise TransportUnavailable("cleanup frame is missing identity or out of order")
                cleanup = value
            else:
                raise TransportUnavailable("unknown or ambiguous export frame")
        elif line.startswith(b"[trestle-run] exit=") and b"arbiter:detached" not in line:
            try:
                match = re.fullmatch(rb"\[trestle-run\] exit=(-?\d+) ([a-z]+) run=(r-[a-f0-9]{16})", line)
                if match is None or cleanup is None:
                    raise TransportUnavailable("native terminal is malformed or precedes cleanup")
                terminals.append((int(match[1]), match[2].decode("ascii"), match[3].decode("ascii")))
            except Exception as error:
                raise TransportUnavailable("native terminal cannot be decoded") from error
    if (not begun or not ended or not files or cleanup is None
            or cleanup.get("complete") is not True or terminals != [(0, "command", native_run)]):
        raise TransportUnavailable("export, cleanup or native outer0 is incomplete")
    before, after = cleanup.get("source_before"), cleanup.get("source_after")
    if not _source(before, manifest) or before != after:
        raise TransportUnavailable("bootstrap source identity changed or is unavailable")
    for key in ("carrier_identity", "output_identity"):
        value = cleanup.get(key)
        if not isinstance(value, dict) or any(type(value.get(k)) is not int for k in ("device", "inode", "uid")):
            raise TransportUnavailable("external cleanup lacks retained lease identity")
    if files.get("manifest.json") != expected_manifest or "receipt.json" not in files:
        raise TransportUnavailable("exported final manifest differs or receipt is missing")
    receipt = _object_json(files["receipt.json"], "exported receipt")
    if any(receipt.get(key) != manifest[key] for key in binding):
        raise TransportUnavailable("exported receipt source/platform differs")
    rows = receipt.get("rows")
    if not isinstance(rows, list) or not rows:
        raise TransportUnavailable("exported receipt rows must be a nonempty list")
    for row in rows:
        if not isinstance(row, dict):
            raise TransportUnavailable("exported receipt row must be an object")
        name, digest = row.get("log"), row.get("log_sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            raise TransportUnavailable("phase raw log identity is unavailable")
        if name not in files or _sha(files[name]) != digest:
            raise TransportUnavailable("phase raw bytes are missing or differ from receipt")
    return dict(files=files, receipt=receipt, cleanup=cleanup,
                state="TRANSPORT_COMPLETE_NOT_PRODUCT_PASS", native_run=native_run)


def materialize(decoded, owned_leg):
    """Write verified flat data only through a live external parent lease."""
    from proof_paths import OwnedLeg
    if not isinstance(owned_leg, OwnedLeg) or decoded.get("state") != "TRANSPORT_COMPLETE_NOT_PRODUCT_PASS":
        raise TransportUnavailable("materialization requires verified transport and a live external lease")
    if any(not isinstance(name, str) or "\x00" in name or Path(name).name != name or "\\" in name
           or not isinstance(raw, bytes) for name, raw in decoded["files"].items()):
        raise TransportUnavailable("materialization data is not a flat byte export")
    destination = owned_leg.child("collected")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in decoded["files"].items():
        with (destination / name).open("xb") as stream:
            stream.write(raw)
    return destination
