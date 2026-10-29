#!/usr/bin/env python3
"""Skip Windows only for a complete, identity-bound PR of allowlisted paths.

No diff API: its truncation can hide risky paths. The files API is paginated;
its 3,000-file ceiling, incomplete responses and every error fail closed.
UNDETERMINED is recorded separately from a measured run/allowlisted-skip decision.

The Rust input guard covers statically resolved files and configured walker
directory roots. Unanchored runtime, temporary and user paths remain in the
scanner's runtime inventory and are outside this guard. This is a bounded
static check, not complete Rust dataflow or runtime portability analysis.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import unicodedata
import urllib.request


def read_checkout_inputs(scanner=None, git_read=None):
    """Read tracked names and known Rust inputs from one unchanged checkout.

    This is the merge checkout Windows will receive. No network or Git auth is
    needed; inherited Git routing/configuration cannot change the read subject.
    """
    root = Path.cwd().resolve()
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1")

    def bounded_git(*arguments):
        result = subprocess.run(["git", "-c", "core.fsmonitor=false", *arguments],
                                cwd=root, env=environment, check=True, timeout=5,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if len(result.stdout) > 16 * 1024 * 1024:
            raise ValueError("checkout enumeration exceeds budget")
        return result.stdout

    git = git_read or bounded_git
    source = Path(__file__).resolve()
    scanner_source = root / "scripts/ci/windows-rust-inputs.py"
    if (source != root / "scripts/ci/windows-rust-changes.py" or
            not scanner_source.resolve().is_relative_to(root)):
        raise ValueError("detector must run at its checkout root")

    def snapshot():
        top = Path(git("rev-parse", "--show-toplevel").decode("utf-8").rstrip("\n")).resolve()
        if top != root or Path.cwd().resolve() != root:
            raise ValueError("checkout root changed")
        head = git("rev-parse", "--verify", "HEAD").decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{40}", head):
            raise ValueError("invalid checkout identity")
        index = Path(git("rev-parse", "--git-path", "index").decode("utf-8").rstrip("\n"))
        if not index.is_absolute():
            index = root / index
        # A worktree source edit is drift even if HEAD/index have not changed.
        git("diff-files", "--quiet", "--no-ext-diff")
        return (head, index.resolve(), hashlib.sha256(index.read_bytes()).digest(),
                hashlib.sha256(source.read_bytes()).digest(),
                hashlib.sha256(scanner_source.read_bytes()).digest())

    before = snapshot()
    raw = git("ls-files", "--cached", "-z")
    if not raw or not raw.endswith(b"\0"):
        raise ValueError("empty or malformed tracked paths")
    tracked = raw[:-1].decode("utf-8").split("\0")
    if any(not path for path in tracked) or len(set(tracked)) != len(tracked):
        raise ValueError("invalid or unmerged tracked paths")
    if scanner is None:
        spec = importlib.util.spec_from_file_location("windows_rust_inputs", scanner_source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        scanner = module.scan
    scanned = scanner(root)
    if (not isinstance(scanned, dict) or not isinstance(scanned.get("unresolved"), list)
            or scanned["unresolved"]):
        raise ValueError("Rust input census is unresolved")
    protected = scanned["paths"]
    prefixes = scanned["prefixes"]
    runtime_inventory = scanned["runtime_inventory"]
    if not isinstance(runtime_inventory, list):
        raise ValueError("invalid out-of-guard runtime inventory")
    for paths in (protected, prefixes):
        if not isinstance(paths, (list, set, tuple)) or any(
                not isinstance(path, str) or not path or path.startswith("/") or
                "\\" in path or any(part in {"", ".", ".."} or part.endswith((".", " "))
                                    for part in path.split("/")) for path in paths):
            raise ValueError("invalid static Rust input paths")
    source_hashes = scanned["source_hashes"]
    if not isinstance(source_hashes, dict):
        raise ValueError("invalid Rust source identities")
    for path, expected in source_hashes.items():
        if (not isinstance(path, str) or not path.endswith(".rs") or
                not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("invalid Rust source identity")
        source_path = (root / path).resolve()
        if not source_path.is_relative_to(root):
            raise ValueError("Rust source escapes checkout")
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != expected:
            raise ValueError("Rust source changed during census")
    if before != snapshot():
        raise ValueError("checkout identity changed during enumeration")
    return tracked, protected, prefixes


def safe_to_skip_path(path):
    if not isinstance(path, str) or not path or path.startswith("/"):
        raise ValueError("invalid changed-file path")
    parts = path.split("/")
    if ".." in parts:
        raise ValueError("invalid changed-file path")
    # Windows filename rules apply before the allowlist. Bound both components
    # and the relative path in UTF-16 units; 200 leaves 59 units for the checkout
    # prefix plus NUL under legacy MAX_PATH=260, without assuming longpaths.
    if len(path.encode("utf-16-le")) // 2 > 200:
        return False
    for part in parts:
        if (not part or part == "." or part.endswith((".", " ")) or
                len(part.encode("utf-16-le")) // 2 > 255 or
                any(character in ':<>"|?*\\' or unicodedata.category(character) == "Cc"
                    for character in part) or
                # Win32 also reserves COM/LPT superscript 1, 2 and 3 aliases:
                # https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
                re.fullmatch(r"con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³]",
                             part.split(".", 1)[0].rstrip(" ").casefold()) or
                re.search(r"~[0-9]", part)):
            return False
    # A Rust source is never safe to skip, whatever directory holds it (the
    # allowlisted docs/, specs/, ... trees can carry a module pulled in by
    # `include!` or `#[path]`).
    if path.casefold().endswith(".rs"):
        return False
    # Markdown under a source directory can be an include_str! build input.
    if any(part.casefold() == "src" for part in parts):
        return False
    # This is an allowlist: every path outside these explicitly safe classes
    # runs Windows. Known Rust-consumed data narrows it separately below; this
    # path classifier alone does not prove that an allowlisted file is unused.
    return (path.endswith(".md") or
            (len(parts) > 1 and parts[0] in
             {"docs", "workspaces", ".claude", ".agents", ".codex", "specs"}))


def paths_relevant(changed, checkout_inputs=None):
    """True when ANY changed path (renames: both names) must run Windows.

    The single path classifier: the CI detect job (`decide`) and any local
    caller that must reach the same verdict use it, so the two cannot drift.
    `checkout_inputs` returns (tracked, protected, prefixes).
    """
    folded = {}
    directories = set()
    relevant = False
    for path in changed:
        relevant = not safe_to_skip_path(path) or relevant
        key = path.casefold()
        parents = ["/".join(key.split("/")[:length])
                   for length in range(1, len(key.split("/")))]
        if ((key in folded and folded[key] != path) or key in directories or
                any(parent in folded for parent in parents)):
            relevant = True
        folded[key] = path
        directories.update(parents)
    if not relevant:
        tracked, protected, prefixes = (checkout_inputs or read_checkout_inputs)()
        # Compare against unchanged tracked files too. Case-only renames
        # conservatively run Windows, even when the old name was removed.
        for path in tracked:
            key = path.casefold()
            parents = ["/".join(key.split("/")[:length])
                       for length in range(1, len(key.split("/")))]
            if ((key in folded and folded[key] != path) or key in directories or
                    any(parent in folded for parent in parents)):
                relevant = True
        relevant = bool(set(folded).intersection(path.casefold() for path in protected)) or relevant
        # Protect newly added files under configured walker roots, including
        # dotfiles; exact component boundaries avoid matching sibling names.
        for prefix in prefixes:
            key = prefix.casefold()
            relevant = any(path == key or path.startswith(key + "/") for path in folded) or relevant
    return relevant


def decide(event_name, event, repository, fetch, checkout_inputs=None):
    """Return (run_windows, determination, reason); fetch is injectable for tests."""
    if event_name in {"push", "workflow_dispatch"}:
        return True, "RUN", "push/manual invocation always runs Windows"
    try:
        if event_name != "pull_request":
            raise ValueError("unsupported event")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository identity")
        pr = event["pull_request"]
        number = event["number"]
        if type(number) is not int or number <= 0 or pr["number"] != number:
            raise ValueError("invalid PR identity")
        identity = (pr["head"]["sha"], pr["base"]["sha"])
        if not all(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha)
                   for sha in identity):
            raise ValueError("invalid commit identity")
        endpoint = "/repos/{}/pulls/{}".format(repository, number)

        def metadata():
            value = fetch(endpoint)
            if (value["number"] != number or
                    (value["head"]["sha"], value["base"]["sha"]) != identity):
                raise ValueError("PR commits changed during detection")
            count = value["changed_files"]
            # GitHub returns at most 3,000 files. At the ceiling we cannot
            # distinguish a complete enumeration from a capped response.
            if type(count) is not int or not 0 < count < 3000:
                raise ValueError("empty or API-limited changed-file count")
            return count

        count = metadata()
        seen = set()
        changed = []
        for page in range(1, (count + 99) // 100 + 1):
            files = fetch(endpoint + "/files?per_page=100&page=" + str(page))
            expected = min(100, count - len(seen))
            if not isinstance(files, list) or len(files) != expected:
                raise ValueError("incomplete changed-file pagination")
            for item in files:
                # Without a valid status we cannot know whether a safe-looking
                # path was renamed from a risky input. Uncertainty runs Windows.
                status = item["status"]
                if status not in {"added", "removed", "modified", "renamed",
                                  "copied", "changed", "unchanged"}:
                    raise ValueError("invalid changed-file status")
                path = item["filename"]
                changed.append(path)
                if path in seen:
                    raise ValueError("duplicate changed-file pagination")
                seen.add(path)
                # A safe destination cannot hide a change to a risky input.
                if status == "renamed":
                    changed.append(item["previous_filename"])
        if len(seen) != count or metadata() != count:
            raise ValueError("changed-file count changed during detection")
        relevant = paths_relevant(changed, checkout_inputs)
        return relevant, "RUN" if relevant else "SKIP", "complete PR files and guarded checkout inputs"
    except Exception as error:
        # Do not print API error bodies, URLs or supplied values (possibly
        # sensitive). Unknown is distinct from a measured risky change.
        return True, "UNDETERMINED", "{}; running Windows".format(type(error).__name__)


def main():
    started = time.monotonic()

    def fetch(endpoint):
        if time.monotonic() - started > 90:
            raise TimeoutError("API enumeration budget exhausted")
        request = urllib.request.Request(
            "https://api.github.com" + endpoint,
            headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=10) as response:
            # A bounded response protects the detector budget on malformed API data.
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError("API response exceeds detection budget")
            return json.loads(data)

    try:
        event_name = os.environ["GITHUB_EVENT_NAME"]
        event = (json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
                 if event_name == "pull_request" else {})
        run, state, reason = decide(event_name, event,
                                    os.environ.get("GITHUB_REPOSITORY", ""), fetch)
    except Exception as error:
        run, state, reason = True, "UNDETERMINED", type(error).__name__
    print("Windows relevance: {} ({})".format(state, reason))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("rust={}\ndetermination={}\n".format(str(run).lower(), state))


if __name__ == "__main__":
    main()
