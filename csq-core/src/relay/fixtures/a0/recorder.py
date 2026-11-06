"""Independent owned-fake recorder. Verdicts: 0 observed yes, 1 no, 2 unavailable.

Current interpreter/source/config hashes are observations of files, not proof of
loaded executable or consumed configuration bytes. Raw grammar is frozen v1.
"""
import argparse
from contextlib import redirect_stderr
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pty
import select
import signal
import subprocess
import sys
import tarfile
import tempfile
import termios
import time
import tty

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
INITIAL = b"alpha\nbeta\n"
EXPECTED = {"clear": b"cleared\n", "compact": b"summary:alpha+beta\n"}
READY = b"ownedfake-ready\n"
LIMIT = 8192
# Termination guards, not performance thresholds or readiness evidence.
DEADLINE = 5
UNAVAILABLE = b"ownedfake-recorder: observation_unavailable\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hx(data):
    return data.hex() if data else "-"


def outside(path):
    path = path.resolve()
    if not path.is_absolute() or path == REPO or REPO in path.parents or "target" in path.parts:
        raise ValueError("outside_checkout_required")
    return path


def attach_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def clean_env(root):
    # Explicit replacement environment is Python's env_clear equivalent.
    # All values are fixed or scratch-rooted; no parent env is inherited.
    return {"HOME": str(root / "home"), "CSQ_BASE_DIR": str(root / "base"),
            "TMPDIR": str(root / "tmp"), "PATH": "/usr/bin:/bin",
            "LANG": "C", "LC_ALL": "C", "TERM": "dumb"}


def wait_child(child, timeout):
    return child.wait(timeout=timeout)


def capture(interpreter, scratch_parent, sources, command, behavior="normal",
            attach_fn=attach_terminal, wait_fn=wait_child):
    observation = {"command": command, "behavior": behavior, "eof": False,
                   "exit": None, "written": "", "output": "", "holder_probe": False}
    raw = None
    # This owns all staged paths; cleanup never targets operator state.
    with tempfile.TemporaryDirectory(prefix="csq-ownedfake-a0-", dir=scratch_parent) as scratch:
        root = Path(scratch)
        for name in ("home", "base", "tmp"):
            (root / name).mkdir(mode=0o700)
        source = sources["fake_cli.py"]
        config = sources["config.txt"]
        (root / "fake_cli.py").write_bytes(source)
        (root / "config.txt").write_bytes(config)
        state = root / "state.bin"
        state.write_bytes(INITIAL)
        before = state.read_bytes()
        executable = digest(interpreter.read_bytes())
        argv = [str(interpreter), "-I", "-S", "fake_cli.py", "--state", "state.bin",
                "--config", "config.txt", "--behavior", behavior]
        env = clean_env(root)
        master, slave = pty.openpty()
        child = None
        output, written = bytearray(), bytearray()
        holder_probe_sent = False
        end = time.monotonic() + DEADLINE
        observation.update(argv=argv, cwd=str(root), environment=env, before=hx(before),
                           executable_sha256=executable, fake_source_sha256=digest(source),
                           config_sha256=digest(config), platform=platform.system() + "-" + platform.machine())
        verdict, reason = 2, "observation_unavailable"
        try:
            tty.setraw(slave)
            child = subprocess.Popen(argv, cwd=root, env=env, stdin=slave, stdout=slave,
                                     stderr=slave, preexec_fn=attach_fn, close_fds=True)
            observation["pid"] = child.pid
            os.close(slave)
            slave = -1
            payload = ("/" + command).encode("ascii") + b"\r"
            while not observation["eof"]:
                remaining = end - time.monotonic()
                if remaining <= 0 or not select.select([master], [], [], remaining)[0]:
                    reason = "pty_deadline"
                    break
                try:
                    part = os.read(master, 1024)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    part = b""  # Unix PTY EIO after last slave closes is EOF.
                if not part:
                    observation["eof"] = True
                    break
                output.extend(part)
                if len(output) > 1024:
                    reason = "output_bound"
                    break
                if bytes(output) == READY and not written:
                    while len(written) < len(payload):
                        count = os.write(master, payload[len(written):])
                        if count <= 0:
                            raise OSError("input_unavailable")
                        written.extend(payload[len(written):len(written) + count])
                if behavior == "hold-pty" and b"ownedfake-holder-ready\n" in output and not holder_probe_sent:
                    if os.write(master, b"?") != 1:
                        raise OSError("holder_probe_unavailable")
                    holder_probe_sent = True
                if behavior == "hold-pty" and b"ownedfake-holder-alive\n" in output:
                    observation["holder_probe"] = True
            if observation["eof"]:
                observation["exit"] = wait_fn(child, max(0.001, end - time.monotonic()))
                after = state.read_bytes()
                reread = state.read_bytes()  # independent post-completion read
                observation.update(after=hx(after), reread=hx(reread))
                if observation["exit"] != 0:
                    verdict, reason = 1, "child_nonzero"
                elif before != INITIAL or after != EXPECTED[command] or reread != after:
                    verdict, reason = 1, "effect_mismatch"
                elif bytes(written) != payload:
                    verdict, reason = 1, "input_mismatch"
                elif digest(interpreter.read_bytes()) != executable:
                    verdict, reason = 2, "executable_changed"
                else:
                    fields = [
                        ["subject", "relay-evidence-v1", "ownedfake-recorder-v1", "relay-extractor-v1",
                         "ownedfake-v1", executable, digest(source), digest(config), observation["platform"],
                         json.dumps(argv, separators=(",", ":")).encode().hex(), "0"],
                        ["input", command, hx(bytes(written)), "-", "-", "0d"],
                        ["effect", hx(before), hx(after)],
                        ["completion", hx(reread), hx(bytes(output)), "exit0-pty-eof"],
                    ]
                    raw = ("\n".join("\t".join(row) for row in fields) + "\n").encode("ascii")
                    if len(raw) > LIMIT:
                        raw = None
                        reason = "raw_bound"
                    else:
                        verdict, reason = 0, "observed_effect_and_completion"
        except (OSError, subprocess.SubprocessError):
            verdict, reason = 2, "observation_unavailable"
        finally:
            if slave >= 0:
                os.close(slave)
            try:
                if child is not None:
                    # Before reap, the owned child pins this process-group ID.
                    # A reaped child plus EOF needs no group cleanup.
                    if not observation["eof"] or child.returncode is None:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    wait_fn(child, DEADLINE)
                    if observation["exit"] is None:
                        observation["exit"] = child.returncode
            finally:
                os.close(master)
            observation.update(written=hx(bytes(written)), output=hx(bytes(output)),
                               verdict=verdict, reason=reason)
    return verdict, raw, observation


def self_test(interpreter, scratch_parent, sources):
    cases = [("clear", "normal", 0, "observed_effect_and_completion"),
             ("compact", "normal", 0, "observed_effect_and_completion"),
             ("clear", "suppress", 1, "effect_mismatch"),
             ("clear", "wrong-state", 1, "effect_mismatch"),
             ("clear", "nonzero", 1, "child_nonzero"),
             ("clear", "hold-pty", 2, "pty_deadline"),
             ("clear", "remove-state", 2, "observation_unavailable")]
    for command, behavior, expected, reason in cases:
        verdict, raw, observation = capture(interpreter, scratch_parent, sources, command, behavior)
        assert (verdict, observation["reason"], raw is not None) == (expected, reason, expected == 0), observation
        if behavior == "hold-pty":
            assert observation["holder_probe"] and not observation["eof"], observation
        print(json.dumps(observation, sort_keys=True), flush=True)
    cli_error_self_test(interpreter, scratch_parent)
    persistence_self_test(interpreter, scratch_parent, sources)
    supervision_self_test(interpreter, scratch_parent, sources)
    publication_self_test(interpreter, scratch_parent, sources)


def cli_error_self_test(interpreter, scratch_parent):
    with tempfile.TemporaryDirectory(prefix="csq-a0-cli-errors-", dir=scratch_parent) as scratch:
        root = Path(scratch)
        for name in ("home", "base", "tmp", "A0-recorder-collision"):
            (root / name).mkdir(mode=0o700)
        foreign = root / "A0-recorder-collision" / "foreign.txt"
        foreign.write_bytes(b"foreign-collision-control\n")
        def snapshot():
            return {str(path.relative_to(root)): (path.stat().st_ino, path.stat().st_mode,
                    path.stat().st_mtime_ns, None if path.is_dir() else path.read_bytes())
                    for path in root.rglob("*")}
        before = snapshot()
        for name, subject, out in (
                ("missing_interpreter", root / "missing-interpreter", root / "A0-recorder-missing"),
                ("output_collision", interpreter, foreign.parent)):
            result = subprocess.run(
                [str(interpreter), "-I", "-S", str(HERE / "recorder.py"),
                 "--interpreter", str(subject), "--scratch-parent", str(root), "--out", str(out)],
                cwd=root, env=clean_env(root), capture_output=True, timeout=DEADLINE)
            assert (result.returncode, result.stdout, result.stderr) == (2, b"", UNAVAILABLE), name
            assert snapshot() == before, name  # no raw/scratch leak; foreign bytes and identity retained
            print(json.dumps({"control": name, "exit": result.returncode, "foreign_unchanged": True}), flush=True)


def persistence_self_test(interpreter, scratch_parent, sources):
    with tempfile.TemporaryDirectory(prefix="csq-a0-persist-error-", dir=scratch_parent) as scratch:
        root = Path(scratch)
        injected = []
        def failing_archive(stage):
            assert all((stage / (command + ".raw")).is_file() for command in EXPECTED)
            injected.append(True)
            raise OSError("injected_archive_failure")
        try:
            package_capture(interpreter, root, sources, root / "A0-recorder-failed", failing_archive)
        except OSError:
            assert injected == [True]  # an earlier acquisition error cannot satisfy this control
            assert list(root.iterdir()) == []  # raw, package and scratch all removed
        else:
            raise AssertionError("archive_failure_not_exercised")
        print(json.dumps({"control": "archive_failure_after_raw_staged", "owned_cleanup": True}), flush=True)


def supervision_self_test(interpreter, scratch_parent, sources):
    with tempfile.TemporaryDirectory(prefix="csq-a0-supervision-", dir=scratch_parent) as scratch:
        root = Path(scratch)
        for mode in ("preexec", "cleanup_timeout"):
            marker, waits, observed = root / "preexec-reached", [], []
            def bad_attach():
                with marker.open("xb") as proof:
                    proof.write(b"reached\n")
                raise RuntimeError("injected_preexec_failure")
            def failed_cleanup_wait(child, timeout):
                result = child.wait(timeout=timeout)  # real child is safely reaped first
                waits.append(result)
                if len(waits) == 2:
                    raise subprocess.TimeoutExpired("ownedfake", timeout)
                return result
            def controlled_capture(*args):
                options = {"attach_fn": bad_attach} if mode == "preexec" else {"wait_fn": failed_cleanup_wait}
                result = capture(*args, **options)
                observed.append((result[0], result[1], result[2]["reason"]))
                return result
            diagnostic = io.StringIO()
            with redirect_stderr(diagnostic):
                result = entrypoint(lambda: package_capture(interpreter, root, sources,
                                    root / "A0-recorder-supervision", capture_fn=controlled_capture))
            assert (result, diagnostic.getvalue().encode()) == (2, UNAVAILABLE), mode
            if mode == "preexec":
                assert marker.read_bytes() == b"reached\n" and observed == [(2, None, "observation_unavailable")]
                marker.unlink()  # only our fixture-created proof file
            else:
                assert waits == [0, 0] and observed == [], mode
            assert list(root.iterdir()) == [], mode
            print(json.dumps({"control": mode, "exit": result, "owned_cleanup": True}), flush=True)


def publication_self_test(interpreter, scratch_parent, sources):
    for kind in ("directory", "file"):
        marker = "publication_file_collision" if kind == "file" else "publication_directory_collision"
        with tempfile.TemporaryDirectory(prefix="csq-a0-publish-", dir=scratch_parent) as scratch:
            root, reached = Path(scratch), []
            out = root / "A0-recorder-final-collision"
            foreign_bytes = b"foreign-publication-control\n"
            def collision_publisher(archive, destination):
                assert archive.is_file()
                if kind == "file":
                    with destination.open("xb") as foreign:
                        foreign.write(foreign_bytes)
                else:
                    destination.mkdir(mode=0o700)
                reached.append(destination.stat())
                publish_exclusive(archive, destination)
            diagnostic = io.StringIO()
            with redirect_stderr(diagnostic):
                result = entrypoint(lambda: package_capture(interpreter, root, sources, out,
                                    publisher=collision_publisher))
            assert (result, diagnostic.getvalue().encode(), len(reached)) == (2, UNAVAILABLE, 1), marker
            current = out.stat(follow_symlinks=False)
            assert (current.st_dev, current.st_ino, current.st_mode) == (reached[0].st_dev, reached[0].st_ino, reached[0].st_mode), marker
            assert (out.read_bytes() == foreign_bytes if kind == "file" else list(out.iterdir()) == []), marker
            assert list(root.iterdir()) == [out], marker
            print(json.dumps({"control": marker, "foreign_unchanged": True}), flush=True)


def write_archive(stage):
    with tarfile.open(stage / "capture.tar", "x") as archive:
        for name in ("fake_cli.py", "recorder.py", "config.txt", "observations.json", "clear.raw", "compact.raw"):
            if (stage / name).exists():
                archive.add(stage / name, arcname=name)


def publish_exclusive(archive, destination):
    os.link(archive, destination)  # A0_GUARD exclusive_publication


def package_capture(interpreter, scratch_parent, sources, out, archive_writer=write_archive,
                    publisher=publish_exclusive, capture_fn=capture):
    # Only our private staging directory is cleaned. Exclusive hard-link
    # publication creates a NEW regular file or preserves any foreign object.
    with tempfile.TemporaryDirectory(prefix=".csq-a0-package-", dir=out.parent) as package:
        stage = Path(package)
        observations, positives = [], []
        for command in EXPECTED:
            verdict, raw, observation = capture_fn(interpreter, scratch_parent, sources, command)
            if verdict == 2:
                raise OSError("capture_unavailable")
            observations.append(observation)
            if raw is not None:
                positives.append((command, raw))
        result = max(observation["verdict"] for observation in observations)
        if result == 0:
            for command, raw in positives:
                (stage / (command + ".raw")).write_bytes(raw)
        for name in ("fake_cli.py", "recorder.py", "config.txt"):
            (stage / name).write_bytes(sources[name])
        manifest = {"verdict": result, "recorder_sha256": digest(sources["recorder.py"]), "observations": observations}
        (stage / "observations.json").write_text(json.dumps(manifest, indent=2) + "\n")
        archive_writer(stage)
        publisher(stage / "capture.tar", out)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--interpreter", type=Path, required=True)
    p.add_argument("--scratch-parent", type=Path, required=True)
    p.add_argument("--out", type=Path, help="new archive file outside the checkout")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if not a.interpreter.is_absolute() or not a.scratch_parent.is_absolute():
        p.error("absolute_paths_required")
    interpreter = a.interpreter.resolve(strict=True)
    scratch_parent = outside(a.scratch_parent)
    sources = {name: (HERE / name).read_bytes() for name in ("fake_cli.py", "recorder.py", "config.txt")}
    if a.self_test:
        self_test(interpreter, scratch_parent, sources)
        return 0
    if a.out is None or not a.out.is_absolute() or not a.out.name.startswith("A0-recorder-"):
        p.error("explicit_A0_recorder_output_required")
    # Resolve/check ancestors only: resolving an existing leaf symlink would
    # redirect publication instead of letting exclusive link refuse it.
    out = outside(a.out.parent) / a.out.name
    return package_capture(interpreter, scratch_parent, sources, out)


def entrypoint(action=main):
    try:
        return action()
    except (OSError, subprocess.SubprocessError):
        # Acquisition/persistence failures cannot become observed-NO verdicts.
        # Keep paths and exception payloads out of the diagnostic.
        sys.stderr.write(UNAVAILABLE.decode("ascii"))
        return 2


if __name__ == "__main__":
    raise SystemExit(entrypoint())
