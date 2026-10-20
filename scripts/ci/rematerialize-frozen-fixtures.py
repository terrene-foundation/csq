#!/usr/bin/env python3
"""Repair incremental checkouts of byte-pinned JSON; verify raw Git blob custody."""

import argparse
import os
import stat
import shlex
import sys
from pathlib import Path
import subprocess
import tempfile


# Only these tracked JSON fixture families may be overwritten. Source, README,
# untracked files and every other test fixture remain outside this operation.
FIXTURE_DIRS = (
    "csq-core/tests/fixtures/canonical_form",
    "csq-core/tests/fixtures/hook_registry_1b",
    "csq-core/tests/fixtures/hook-registry",
)


def git(repo, *args, data=None, env=None):
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
    ).stdout


def regular_path(repo, path):
    target = repo / path
    # Refuse symlinks, junctions and reparse-point ancestors. The final
    # entry must also be a regular file, never a followed link/device.
    for parent in (target.parent, *target.parent.parents):
        if parent == repo.parent:
            break
        info = parent.lstat()
        reparse = getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
        if not stat.S_ISDIR(info.st_mode) or reparse:
            raise RuntimeError(f"non-directory or linked frozen fixture ancestor: {path}")
    try:
        info = target.lstat()
    except FileNotFoundError:
        return 0o644
    reparse = getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
    if not stat.S_ISREG(info.st_mode) or reparse:
        raise RuntimeError(f"non-regular or linked frozen fixture destination: {path}")
    return stat.S_IMODE(info.st_mode)


def write_raw_blob(repo, path, content):
    mode = regular_path(repo, path)
    target = repo / path
    fd, temporary = tempfile.mkstemp(prefix='.csq-frozen-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        # Recheck types before publication; replace publishes atomically
        # without opening or following the final destination entry.
        regular_path(repo, path)
        os.replace(temporary, target)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def raw_blobs(repo, pinned, env=None):
    data = git(repo, 'cat-file', '--batch',
               data=b''.join(blob + b'\n' for _, _, blob in pinned), env=env)
    result = []
    position = 0
    for path, _, expected in pinned:
        ending = data.find(b'\n', position)
        if ending < 0:
            raise RuntimeError(f"missing raw blob header: {path}")
        header = data[position:ending].split()
        if len(header) != 3 or header[:2] != [expected, b'blob'] or not header[2].isdigit():
            raise RuntimeError(f"wrong raw fixture object: {path}")
        length = int(header[2])
        start = ending + 1
        stop = start + length
        if stop >= len(data) or data[stop:stop+1] != b'\n':
            raise RuntimeError(f"incomplete raw fixture blob: {path}")
        content = data[start:stop]
        actual = git(repo, 'hash-object', '--no-filters', '--stdin', data=content, env=env).strip()
        if actual != expected:
            raise RuntimeError(f"raw object differs from index blob: {path}")
        result.append(content)
        position = stop + 1
    if position != len(data):
        raise RuntimeError('unexpected trailing raw fixture object bytes')
    return result


def repair(repo, env=None):
    repo = Path(repo).resolve()
    entries = git(repo, "ls-files", "--stage", "-z", "--", *FIXTURE_DIRS, env=env)
    pinned = []
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        path = os.fsdecode(raw_path)
        if Path(path).suffix != ".json" or Path(path).parent.as_posix() not in FIXTURE_DIRS:
            continue
        mode, blob, stage = meta.split()
        if mode != b"100644" or stage != b"0":
            raise RuntimeError(f"non-regular or unmerged frozen fixture: {path}")
        pinned.append((path, raw_path, blob))
    for directory in FIXTURE_DIRS:
        if not any(Path(path).parent.as_posix() == directory for path, _, _ in pinned):
            raise RuntimeError(f"no tracked frozen JSON fixtures in {directory}")
    paths = b"".join(raw + b"\0" for _, raw, _ in pinned)
    attrs = git(repo, "check-attr", "-z", "--stdin", "text", data=paths, env=env)
    fields = attrs.split(b"\0")[:-1]
    if len(fields) != len(pinned) * 3:
        raise RuntimeError("incomplete fixture attribute response")
    for offset, (_, raw_path, _) in zip(range(0, len(fields), 3), pinned):
        if fields[offset:offset + 3] != [raw_path, b"text", b"unset"]:
            raise RuntimeError(f"frozen fixture lacks -text: {os.fsdecode(raw_path)}")
    # Raw objects bypass smudge filters, which checkout-index can still apply
    # to -text paths. Keep the captured stage-0 index as the byte authority.
    contents = raw_blobs(repo, pinned, env)
    for path, _, _ in pinned:
        regular_path(repo, path)
    def index_unchanged():
        if git(repo, 'ls-files', '--stage', '-z', '--', *FIXTURE_DIRS, env=env) != entries:
            raise RuntimeError('frozen fixture index changed during repair')
    index_unchanged()
    for (path, _, _), content in zip(pinned, contents):
        write_raw_blob(repo, path, content)
    index_unchanged()
    for path, _, expected in pinned:
        regular_path(repo, path)
        actual = git(repo, "hash-object", "--no-filters", "--", path, env=env).strip()
        if actual != expected:
            raise RuntimeError(f"raw fixture bytes differ from index blob: {path}")
        print(f"Verified frozen fixture {path}: {actual.decode('ascii')}")
    index_unchanged()
    return len(pinned)


def selftest():
    with tempfile.TemporaryDirectory(prefix="csq-fixture-checkout-") as tmp:
        repo = Path(tmp) / "repo"
        home = Path(tmp) / "home"
        repo.mkdir()
        home.mkdir()
        keys = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "TEMP", "TMP", "TMPDIR")
        env = {key: os.environ[key] for key in keys if key in os.environ}
        env.update(HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_NOSYSTEM="1",
                   GIT_CONFIG_GLOBAL=str(home / "gitconfig"), GIT_ATTR_NOSYSTEM="1")

        def run(*args, data=None):
            return git(repo, "-c", "core.autocrlf=true", "-c", "core.attributesFile=",
                       "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                       *args, env=env, data=data)

        run("init", "--quiet")
        fixtures = [repo / directory / "sample.json" for directory in FIXTURE_DIRS]
        expected = b'{"frozen":true}\n'
        for fixture in fixtures:
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(expected)
        control = repo / "control.json"
        control.write_bytes(b"{}\n")
        excluded = repo / FIXTURE_DIRS[0] / "README.md"
        excluded.write_bytes(b"readme\n")
        nested = repo / FIXTURE_DIRS[0] / "unrelated" / "nested.json"
        nested.parent.mkdir()
        nested.write_bytes(b"{}\n")
        run("add", ".")
        run("commit", "--quiet", "-m", "before attributes")
        old = run("rev-parse", "HEAD").strip().decode("ascii")
        attrs = repo / ".gitattributes"
        attr_bytes = "".join(f"{directory}/*.json -text\n" for directory in FIXTURE_DIRS)
        attrs.write_text(attr_bytes)
        run("add", ".gitattributes")
        run("commit", "--quiet", "-m", "protect frozen bytes")
        new = run("rev-parse", "HEAD").strip().decode("ascii")
        run("checkout", "--force", old)
        for fixture in fixtures:
            fixture.unlink()
        run("checkout-index", "--all", "--force")
        if any(fixture.read_bytes() != expected.replace(b"\n", b"\r\n") for fixture in fixtures):
            raise AssertionError("old checkout did not produce CRLF")
        # actions/checkout cleans the old revision BEFORE checking out the new
        # one. Unchanged fixture index entries retain the previously CRLF bytes.
        run("reset", "--hard", "HEAD")
        run("checkout", "--force", "-B", "incremental", new)
        if any(fixture.read_bytes() == expected for fixture in fixtures):
            raise AssertionError("incremental checkout unexpectedly repaired frozen bytes")
        control.write_bytes(b"unrelated tracked edit\r\n")
        excluded.write_bytes(b"unrelated fixture readme edit\r\n")
        nested.write_bytes(b"unrelated nested tracked edit\r\n")
        untracked = repo / FIXTURE_DIRS[0] / "untracked.json"
        untracked.write_bytes(b"untracked\r\n")
        before = {path: path.read_bytes() for path in (control, excluded, nested, untracked, attrs)}
        if repair(repo, env) != len(fixtures):
            raise AssertionError("repair selected the wrong number of paths")
        if any(fixture.read_bytes() != expected for fixture in fixtures):
            raise AssertionError("repair did not restore frozen LF bytes")
        if any(path.read_bytes() != data for path, data in before.items()):
            raise AssertionError("repair changed a path outside its whitelist")
        # A converting attribute must halt before rewriting any fixture.
        attrs.write_text("".join(f"{directory}/*.json text eol=crlf\n" for directory in FIXTURE_DIRS))
        try:
            repair(repo, env)
        except RuntimeError as error:
            if "lacks -text" not in str(error):
                raise
        else:
            raise AssertionError("converting attributes were accepted")
        if any(fixture.read_bytes() != expected for fixture in fixtures):
            raise AssertionError("attribute rejection modified fixtures")
        # Inject corruption after materialization to prove the raw-blob check
        # detects bytes on disk, independently of Git's clean-filter hashes.
        attrs.write_text(attr_bytes)
        from unittest.mock import patch
        actual_write = write_raw_blob
        def corrupt_materialization(*args, **kwargs):
            output = actual_write(*args, **kwargs)
            fixtures[0].write_bytes(expected + b"corrupt")
            return output

        with patch(__name__ + ".write_raw_blob", side_effect=corrupt_materialization):
            try:
                repair(repo, env)
            except RuntimeError as error:
                if "differ from index blob" not in str(error):
                    raise
            else:
                raise AssertionError("corrupt raw bytes were accepted")
        # A physical clean/smudge filter remains active under -text.
        filter_script = repo / 'fixture-filter.py'
        filter_script.write_text("import sys\nraw=sys.stdin.buffer.read().replace(b'\\r\\n',b'\\n')\n"
                                 "sys.stdout.buffer.write(raw if sys.argv[1]=='clean' else raw.replace(b'\\n',b'\\r\\n'))\n")
        command = shlex.quote(sys.executable.replace('\\', '/')) + ' ' + shlex.quote(filter_script.as_posix())
        run('config', 'filter.frozen.clean', command + ' clean')
        run('config', 'filter.frozen.smudge', command + ' smudge')
        run('config', 'filter.frozen.required', 'true')
        attrs.write_text(''.join(f'{directory}/*.json -text filter=frozen\n' for directory in FIXTURE_DIRS))
        for fixture in fixtures:
            fixture.unlink()
        selected = b''.join(os.fsencode(fixture.relative_to(repo).as_posix()) + b'\0' for fixture in fixtures)
        run('checkout-index', '--force', '-z', '--stdin', data=selected)
        if any(fixture.read_bytes() != expected.replace(b'\n', b'\r\n') for fixture in fixtures):
            raise AssertionError('physical smudge filter did not produce CRLF under -text')
        repair(repo, env)
        if any(fixture.read_bytes() != expected for fixture in fixtures):
            raise AssertionError('raw writer did not bypass active smudge filter')
        # Refuse an index change after the raw plan was read, before writing.
        actual_git = git
        before_change = {fixture: fixture.read_bytes() for fixture in fixtures}
        changed = False
        def change_index_after_read(*args, **kwargs):
            nonlocal changed
            output = actual_git(*args, **kwargs)
            if 'cat-file' in args and '--batch' in args and not changed:
                changed = True
                new_blob = run('hash-object', '-w', '--stdin', data=b'changed indexed object\n').strip().decode('ascii')
                run('update-index', '--cacheinfo', '100644', new_blob, fixtures[0].relative_to(repo).as_posix())
            return output
        with patch(__name__ + '.git', side_effect=change_index_after_read):
            try:
                repair(repo, env)
            except RuntimeError as error:
                if 'index changed' not in str(error):
                    raise
            else:
                raise AssertionError('changed indexed blob was accepted')
        if not changed or any(path.read_bytes() != data for path, data in before_change.items()):
            raise AssertionError('index-change refusal wrote a fixture or injection did not execute')
        print("PASS: incremental CRLF and real -text clean/smudge reproduced; raw repair bypasses filters; unrelated paths preserved; converting attributes, corrupt raw bytes and changed index rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        repair(Path.cwd())
