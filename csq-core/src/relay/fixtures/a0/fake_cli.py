"""Owned PTY fixture only; no vendor behavior or launch-authority claim."""
import argparse
import os
from pathlib import Path
import signal


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--behavior", default="normal", choices=(
        "normal", "suppress", "wrong-state", "nonzero", "hold-pty", "remove-state"))
    a = p.parse_args()
    if Path(a.config).read_bytes() != b"ownedfake-config-v1\n":
        return 2
    os.write(1, b"ownedfake-ready\n")
    command = b""
    while not command.endswith(b"\r") and len(command) < 32:
        part = os.read(0, 1)
        if not part:
            return 3
        command += part
    states = {b"/clear\r": b"cleared\n", b"/compact\r": b"summary:alpha+beta\n"}
    if command not in states or Path(a.state).read_bytes() != b"alpha\nbeta\n":
        return 4
    if a.behavior == "remove-state":
        Path(a.state).unlink()
    elif a.behavior != "suppress":
        stage = Path(a.state + ".stage")
        with stage.open("xb") as f:
            f.write(b"wrong\n" if a.behavior == "wrong-state" else states[command])
        stage.replace(a.state)
    if a.behavior == "hold-pty":
        # Set before fork: session-leader exit must not kill the slave holder.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        if os.fork() == 0:
            os.write(1, b"ownedfake-holder-ready\n")
            if os.read(0, 1) == b"?":
                os.write(1, b"ownedfake-holder-alive\n")
            # The active reply proves a live slave holder before the recorder
            # reaches its deadline; the recorder then kills this owned group.
            os.read(0, 1)
            os._exit(0)
    return 7 if a.behavior == "nonzero" else 0


if __name__ == "__main__":
    raise SystemExit(main())
