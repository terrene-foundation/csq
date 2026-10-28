#!/usr/bin/env python3
"""Route spec 10 §10.5 from a commit-bound declaration; unknown always enforces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unicodedata

SOURCE = "coc-eval/phase-declaration.json"
AUTHORITY = "specs/10-capability-layer-architecture.md#1055"
LIMIT = 16 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
# Unicode 17.0.0 Default_Ignorable_Code_Point; numeric intervals are facts.
# https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt
# Source SHA256: 24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08
DEFAULT_IGNORABLE = (
    (0xAD, 0xAD), (0x34F, 0x34F), (0x61C, 0x61C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF))
FILLERS = {0x2800, 0x3164, 0x115F, 0x1160, 0xFFA0}
# Owner-approved initial schema: introduced by 34903e2a090a0caa079329fe42e4f29c55b4b53b.
# Only its exact blob at the earliest first-parent introduction may normalize.
INITIAL_LEGACY_BLOB = "5e7c77da5fcd9bc188b64f88d9fbc76c8658c622"


class RouteError(Exception):
    pass


def git_env(environment):
    """Never inherit Git overrides or read the operator's global/system config."""
    result = {k: environment[k] for k in
              ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "SystemRoot")
              if k in environment}
    result.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                  GIT_CONFIG_SYSTEM=os.devnull, GIT_NO_REPLACE_OBJECTS="1")
    return result


def git_read(repo, *args):
    try:
        return subprocess.run(
            ["git", "--no-pager", "--literal-pathspecs", "-C", str(repo),
             "-c", "safe.directory=" + str(Path(repo).resolve()),
             "-c", "core.fsmonitor=", "-c", "core.hooksPath=" + os.devnull, *args],
            env=git_env(os.environ), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise RouteError("git_error") from error


def read_worktree(repo):
    """No symlinks, directories or special files can stand in for a declaration."""
    try:
        if not stat.S_ISDIR((repo / "coc-eval").lstat().st_mode):
            raise RouteError("source_not_regular")
        path = repo / SOURCE
        if not stat.S_ISREG(path.lstat().st_mode):
            raise RouteError("source_not_regular")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise RouteError("source_not_regular")
            data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise RouteError("source_oversized")
        return data
    except OSError as error:
        raise RouteError("source_unreadable") from error


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def visible_reason(reason):
    return any(unicodedata.category(character)[:1] in {"L", "N", "P", "S"}
               and ord(character) not in FILLERS
               and not any(start <= ord(character) <= end for start, end in DEFAULT_IGNORABLE)
               for character in reason)


def parse_declaration(data, initial_blob=None):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
        if (initial_blob == INITIAL_LEGACY_BLOB and isinstance(value, dict)
                and set(value) == {"schema_version", "phase", "authority"}
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["phase"] == "2a" and value["authority"] == AUTHORITY):
            value["history"] = []
        if (not isinstance(value, dict)
                or set(value) != {"schema_version", "phase", "authority", "history"}
                or type(value["schema_version"]) is not int
                or value["schema_version"] != 1
                or value["phase"] not in ("2a", "2b")
                or value["authority"] != AUTHORITY
                or not isinstance(value["history"], list)):
            raise ValueError("invalid schema")
        previous = None
        for entry in value["history"]:
            if (not isinstance(entry, dict)
                    or set(entry) not in ({"from", "to"}, {"from", "to", "reason"})
                    or entry["from"] not in ("2a", "2b") or entry["to"] not in ("2a", "2b")
                    or entry["from"] == entry["to"]
                    or (previous is not None and entry["from"] != previous)
                    or ("reason" in entry and not isinstance(entry["reason"], str))
                    or (entry["from"] == "2b" and not visible_reason(entry.get("reason", "")))):
                raise ValueError("invalid history")
            previous = entry["to"]
        if previous is not None and previous != value["phase"]:
            raise ValueError("history does not end at declared phase")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise RouteError("source_invalid_schema") from error


def parse_phase(data):
    return parse_declaration(data)["phase"]


def committed_blob(repo, commit, git):
    entry = git(repo, "ls-tree", "-z", commit, "--", SOURCE)
    if not entry:
        return None
    metadata, path = entry.rstrip(b"\0").split(b"\t", 1)
    mode, kind, oid = metadata.split()
    if mode not in (b"100644", b"100755") or kind != b"blob" or path != SOURCE.encode():
        raise RouteError("source_not_regular")
    oid = oid.decode("ascii")
    if not SHA.fullmatch(oid):
        raise RouteError("git_error")
    if int(git(repo, "cat-file", "-s", oid)) > LIMIT:
        raise RouteError("source_oversized")
    data = git(repo, "cat-file", "blob", oid)
    if len(data) > LIMIT:
        raise RouteError("source_oversized")
    return oid, data


def verify_parent(repo, sha, declaration, git, legacy_parent=False):
    # Raw object headers retain real parents even at a shallow boundary.
    headers = git(repo, "cat-file", "commit", sha).split(b"\n\n", 1)[0].splitlines()
    parents = [line[7:].decode("ascii") for line in headers if line.startswith(b"parent ")]
    if not parents:
        return
    if not SHA.fullmatch(parents[0]):
        raise RouteError("git_error")
    previous = committed_blob(repo, parents[0], git)
    if previous is None:
        return
    old = parse_declaration(previous[1], previous[0] if legacy_parent else None)
    history, prior = declaration["history"], old["history"]
    changed = declaration["phase"] != old["phase"]
    if history[:len(prior)] != prior or len(history) != len(prior) + int(changed):
        raise RouteError("source_invalid_schema")
    if changed and (history[-1]["from"] != old["phase"] or history[-1]["to"] != declaration["phase"]):
        raise RouteError("source_invalid_schema")


def verify_history(repo, sha, declaration, git):
    if git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise RouteError("git_error")
    commits = git(repo, "rev-list", "--first-parent", "--full-history", sha, "--", SOURCE).decode("ascii").splitlines()
    if not commits or any(not SHA.fullmatch(commit) for commit in commits):
        raise RouteError("git_error")
    seen, latest, prior_oid = False, None, None
    for commit in reversed(commits):
        blob = committed_blob(repo, commit, git)
        if blob is None:
            if seen:
                raise RouteError("source_invalid_schema")  # deletion cannot reset authority
            continue
        latest = parse_declaration(blob[1], blob[0] if not seen else None)
        verify_parent(repo, commit, latest, git, legacy_parent=prior_oid == INITIAL_LEGACY_BLOB)
        seen = True
        prior_oid = blob[0]
    if latest != declaration:
        raise RouteError("source_invalid_schema")


def classify(repo, sha, git=git_read, read=read_worktree):
    report = {"schema_version": 1, "phase": None, "effective_phase": "2b",
              "enforce": True, "allow_undetermined": False,
              "disposition": "ENFORCE", "reason": "git_error",
              "source": {"path": SOURCE, "commit": sha, "blob": None, "sha256": None}}
    try:
        if not SHA.fullmatch(sha):
            raise RouteError("invalid_commit")
        repo = Path(repo).resolve()
        if Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel")).strip()).resolve() != repo:
            raise RouteError("repo_invalid")
        if git(repo, "rev-parse", "--verify", "HEAD").decode().strip() != sha:
            raise RouteError("head_mismatch")
        blob = committed_blob(repo, sha, git)
        if blob is None:
            raise RouteError("source_absent")
        oid, data = blob
        report["source"]["blob"] = oid
        report["source"]["sha256"] = hashlib.sha256(data).hexdigest()
        if read(repo) != data:
            raise RouteError("source_tampered")
        declaration = parse_declaration(data, oid)
        verify_history(repo, sha, declaration, git)
        phase = declaration["phase"]
        report.update(phase=phase, effective_phase=phase, enforce=phase != "2a",
                      allow_undetermined=phase == "2a",
                      disposition="ORDINARY" if phase == "2a" else "ENFORCE",
                      reason="declared_" + phase)
    except RouteError as error:
        report["reason"] = str(error)
    except (OSError, ValueError, UnicodeError) as error:
        report["reason"] = "git_error"
    return report


def publish(report, destination, environment):
    Path(destination).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    commit = report["source"]["commit"]
    identity = commit if SHA.fullmatch(commit) else "invalid SHA"
    summary = (f"Phase routing: {report['disposition']} — {report['reason']}; "
               f"effective phase {report['effective_phase']}.\n\n"
               f"Source: `{SOURCE}@{identity}`\n")
    if "GITHUB_STEP_SUMMARY" in environment:
        with open(environment["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(summary)
    print(summary, end="", flush=True)
    # Eligibility for exit-2 handling is published only after all reporting.
    if "GITHUB_OUTPUT" in environment:
        with open(environment["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("allow_undetermined=" + str(report["allow_undetermined"]).lower() + "\n")


def main(argv=None, environment=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    try:
        publish(classify(args.repo, args.sha), args.report,
                os.environ if environment is None else environment)
    except OSError:
        print("Phase routing report/output write failed; enforcement required.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
