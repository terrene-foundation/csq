"""Source-bound native libtest inventory and serial runtime observations.

Callers retain the actual list/run argv, native execution receipts and source
guards. This module scores one binary's complete, untruncated serial output;
it does not establish those external authorities from a caller's labels.
"""

import hashlib
import json
import re

from proof_types import ProofUnavailable


_BINDING_KEYS = {
    "source_commit", "source_tree", "platform", "edition", "features", "runtime_argv"
}
_NAME = re.compile(r"\S+")
_LIST_ROW = re.compile(r"(\S+): test")
_LIST_SUMMARY = re.compile(r"(\d+) tests?, (\d+) benchmarks?")
_HEADER = re.compile(r"running (\d+) tests?")
_ROW = re.compile(r"test (\S+) \.\.\. ?(.*)")
_SUMMARY = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out(?:;.*)?"
)
_VERDICT = re.compile(r"(ok|FAILED|ignored)(?:, .+)?")


def _sha(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _names(values, label):
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(name, str) or not _NAME.fullmatch(name) for name in values
    ):
        raise ProofUnavailable(f"{label}: expected exact nonempty test names")
    if len(set(values)) != len(values):
        raise ProofUnavailable(f"{label}: duplicate test names")
    return list(values)


def _binding(value):
    if not isinstance(value, dict) or set(value) != _BINDING_KEYS:
        raise ProofUnavailable("binding: incomplete or unsupported identity schema")
    for key in ("source_commit", "source_tree"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[a-f0-9]{40}", value[key]):
            raise ProofUnavailable(f"binding: {key} must be a full frozen Git identity")
    if value["platform"] not in ("linux", "darwin", "win32"):
        raise ProofUnavailable("binding: unsupported native platform")
    if value["edition"] not in ("community", "enterprise"):
        raise ProofUnavailable("binding: unsupported edition")
    features = _names(value["features"], "binding features")
    argv = value["runtime_argv"]
    if not isinstance(argv, (list, tuple)) or not argv or any(
        not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv
    ):
        raise ProofUnavailable("binding: runtime argv is unavailable or malformed")
    thread_args = [arg for arg in argv if arg == "--test-threads" or arg.startswith("--test-threads=")]
    if thread_args != ["--test-threads=1"]:
        raise ProofUnavailable("binding: only explicitly serial libtest output is supported")
    return {**value, "features": features, "runtime_argv": list(argv)}


def _seal(value):
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _terminal(value):
    match = _VERDICT.fullmatch(value.strip())
    if match and (match[1] == "ignored" or value.strip() in ("ok", "FAILED")):
        return match[1]
    return None


def make_inventory(listing, binding, required, allowed_ignored, *, actual_rc):
    """Validate a successful same-leg native --list result before runtime scoring.

    Missing inventory authority raises ProofUnavailable, rather than assigning a
    product verdict. No hardcoded platform total is accepted as an oracle.
    """
    identity = _binding(binding)
    if type(actual_rc) is not int or actual_rc != 0 or not isinstance(listing, str):
        raise ProofUnavailable("inventory: native list command did not complete successfully")
    names = _names(
        [match.group(1) for line in listing.splitlines()
         if (match := _LIST_ROW.fullmatch(line))],
        "inventory",
    )
    summaries = [match.groups() for line in listing.splitlines()
                 if (match := _LIST_SUMMARY.fullmatch(line))]
    if not names or summaries != [(str(len(names)), "0")]:
        raise ProofUnavailable("inventory: missing, zero, multiple or inconsistent native listing")
    needed = _names(required, "required")
    ignored = _names(allowed_ignored, "allowed ignored")
    if not needed or not set(needed).issubset(names):
        raise ProofUnavailable("inventory: required exact tests are absent")
    if not set(ignored).issubset(names) or set(ignored).intersection(needed):
        raise ProofUnavailable("inventory: ignored fixture policy conflicts with exact inventory")
    inventory = {
        "schema": "csq.native-libtest-inventory.v1",
        "binding": identity,
        "names": names,
        "required": needed,
        "allowed_ignored": ignored,
        "listing_sha256": _sha(listing),
    }
    return {**inventory, "inventory_sha256": _seal(inventory)}


def _read_inventory(value):
    if not isinstance(value, dict):
        raise ProofUnavailable("inventory: missing serialized inventory")
    keys = {"schema", "binding", "names", "required", "allowed_ignored",
            "listing_sha256", "inventory_sha256"}
    if set(value) != keys or value["schema"] != "csq.native-libtest-inventory.v1":
        raise ProofUnavailable("inventory: unsupported serialized schema")
    unsigned = {key: item for key, item in value.items() if key != "inventory_sha256"}
    if value["inventory_sha256"] != _seal(unsigned):
        raise ProofUnavailable("inventory: serialized inventory digest changed")
    identity = _binding(value["binding"])
    names = _names(value["names"], "inventory")
    required = _names(value["required"], "required")
    ignored = _names(value["allowed_ignored"], "allowed ignored")
    if not names or not required or not set(required).issubset(names):
        raise ProofUnavailable("inventory: empty or incomplete named selection")
    if not set(ignored).issubset(names) or set(required).intersection(ignored):
        raise ProofUnavailable("inventory: invalid ignored fixture policy")
    if not isinstance(value["listing_sha256"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", value["listing_sha256"]
    ):
        raise ProofUnavailable("inventory: missing native listing content identity")
    return identity, names, required, ignored


def _runtime_rows(raw, names):
    """Parse the outer serial harness, retaining nested helpers as child sections."""
    depth = 0
    started = False
    complete = False
    pending = None
    rows = {}
    summary = None
    for line in raw.splitlines():
        header = _HEADER.fullmatch(line)
        if header:
            if complete:
                raise ProofUnavailable("runtime: more than one primary test section")
            if not started:
                if int(header[1]) != len(names):
                    raise ProofUnavailable("runtime: selected count differs from native inventory")
                started = True
            depth += 1
            continue
        total = _SUMMARY.fullmatch(line)
        if total:
            if depth > 1:
                depth -= 1
                continue
            if depth != 1 or complete:
                raise ProofUnavailable("runtime: unpaired or multiple primary summaries")
            if pending is not None and pending not in rows:
                raise ProofUnavailable("runtime: primary test has no terminal outcome")
            summary = total.groups()
            complete = True
            depth = 0
            continue
        if depth > 1:
            continue
        row = _ROW.fullmatch(line)
        if row:
            if depth != 1:
                raise ProofUnavailable("runtime: test row outside the primary section")
            if pending is not None and pending not in rows:
                raise ProofUnavailable("runtime: previous serial test has no outcome")
            pending, tail = row.groups()
            if pending not in names or pending in rows:
                raise ProofUnavailable("runtime: unknown or duplicate primary test name")
            verdict = _terminal(tail)
            if verdict:
                rows[pending] = verdict
            continue
        verdict = _terminal(line)
        if verdict and depth == 1:
            if pending is None or pending in rows:
                raise ProofUnavailable("runtime: ambiguous standalone serial outcome")
            rows[pending] = verdict
    if not complete or depth or set(rows) != set(names):
        raise ProofUnavailable("runtime: incomplete primary section or missing exact test names")
    return rows, summary


def evaluate_runtime(raw, actual_rc, inventory, observed_binding):
    """Return PASS/0, measured FAIL/1, or UNDETERMINED/2 with retained identity.

    Compiler errors, transport exits, missing observations and inconsistent
    native output remain instrumentation uncertainty. Only complete bound
    libtest failure evidence establishes a product FAIL.
    """
    result = {"state": "UNDETERMINED", "code": 2, "reason": "unavailable observation"}
    try:
        identity, names, required, ignored = _read_inventory(inventory)
        result.update(binding=identity, inventory_sha256=inventory["inventory_sha256"])
        if _binding(observed_binding) != identity:
            raise ProofUnavailable("runtime: source/platform/edition/features/argv identity mismatch")
        if not isinstance(raw, str) or type(actual_rc) is not int:
            raise ProofUnavailable("runtime: raw output or direct command status unavailable")
        result.update(raw_sha256=_sha(raw), actual_rc=actual_rc)
        rows, summary = _runtime_rows(raw, names)
        outcome, passed, failed, skipped, measured, filtered = summary
        counts = {"passed": int(passed), "failed": int(failed), "ignored": int(skipped)}
        observed = {"passed": list(rows.values()).count("ok"),
                    "failed": list(rows.values()).count("FAILED"),
                    "ignored": list(rows.values()).count("ignored")}
        if counts != observed or int(measured) != 0:
            raise ProofUnavailable("runtime: primary summary disagrees with named outcomes")
        if any(rows[name] == "ignored" and name not in ignored for name in names):
            raise ProofUnavailable("runtime: ignored test lacks explicit fixture permission")
        if any(rows[name] == "ignored" for name in required):
            raise ProofUnavailable("runtime: required test did not execute")
        result.update(counts=counts, names=rows, selected=len(names), filtered_out=int(filtered))
        if counts["failed"]:
            if outcome != "FAILED" or actual_rc <= 0:
                raise ProofUnavailable("runtime: failed tests lack consistent direct failure status")
            return {**result, "state": "FAIL", "code": 1, "reason": "named native tests failed"}
        if outcome != "ok" or actual_rc != 0 or counts["passed"] == 0:
            raise ProofUnavailable("runtime: no positive complete successful native result")
        return {**result, "state": "PASS", "code": 0, "reason": "all native inventory rows accounted for"}
    except (ProofUnavailable, TypeError, ValueError, KeyError) as error:
        return {**result, "state": "UNDETERMINED", "code": 2, "reason": str(error)}
