#!/usr/bin/env python3
"""Broker recovery test — proves the recovery path heals a dead canonical.

Scenario: CC's own refresh path won a race against the broker and rotated
the refresh token. Canonical still holds the dead RT. At least one live
config-X/.credentials.json holds the rotated (live) RT.

Expected after broker_check():
  - primary refresh with canonical RT returns None (Anthropic 401)
  - recovery iterates live siblings, finds the one with the rotated RT
  - promotes it into canonical, retries refresh, succeeds
  - canonical holds the fresh tokens
  - fanout writes the fresh tokens to every live sibling
  - the broker-failed flag file is NOT present (success clears it)

Also tests the failure path: when EVERY live sibling's RT is dead, broker
returns exit code 2 and touches credentials/N.broker-failed so the
statusline can surface a warning.

POSIX-only (uses multiprocessing.fork).
"""
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path


# Distinguishable token strings so assertions are unambiguous
RT_DEAD = "sk-ant-ort01-DEAD"
AT_DEAD = "sk-ant-oat01-DEAD"
RT_LIVE = "sk-ant-ort01-LIVE"
AT_LIVE = "sk-ant-oat01-LIVE"
RT_RECOVERED = "sk-ant-ort01-RECOVERED"
AT_RECOVERED = "sk-ant-oat01-RECOVERED"
RT_OTHER_DEAD = "sk-ant-ort01-OTHER-DEAD"
AT_OTHER_DEAD = "sk-ant-oat01-OTHER-DEAD"


def _make_creds(rt, at, expires_at):
    return {
        "claudeAiOauth": {
            "refreshToken": rt,
            "accessToken": at,
            "expiresAt": expires_at,
            "scopes": [],
            "subscriptionType": None,
            "rateLimitTier": None,
        }
    }


def child_recovery_success(
    config_dir_str, accounts_dir_str, creds_dir_str, engine_path_str, result_file_str
):
    """Runs in a subprocess: fires broker_check with a mocked refresh_token
    that 401s on dead RTs and succeeds on the live one. Writes the exit code
    of broker_check to result_file so the parent can assert on it.
    """
    import importlib.util
    import json as _json
    import os as _os
    import time as _time
    from pathlib import Path as _Path

    _os.environ["CLAUDE_CONFIG_DIR"] = config_dir_str

    spec = importlib.util.spec_from_file_location("engine", engine_path_str)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    engine.ACCOUNTS_DIR = _Path(accounts_dir_str)
    engine.CREDS_DIR = _Path(creds_dir_str)
    engine.PROFILES_FILE = _Path(accounts_dir_str) / "profiles.json"
    engine.QUOTA_FILE = _Path(accounts_dir_str) / "quota.json"

    def mock_refresh(account_num, quiet=False):
        cred_file = engine.CREDS_DIR / f"{account_num}.json"
        creds = _json.loads(cred_file.read_text())
        rt = creds["claudeAiOauth"]["refreshToken"]
        # Anthropic returns 401 for any RT except the live rotated one
        if rt != RT_LIVE:
            return None
        new_creds = _make_creds(
            RT_RECOVERED, AT_RECOVERED, int(_time.time() * 1000) + 60 * 60 * 1000
        )
        tmp = cred_file.with_suffix(".tmp")
        tmp.write_text(_json.dumps(new_creds, indent=2))
        _os.chmod(tmp, 0o600)
        _os.replace(tmp, cred_file)
        return new_creds

    engine.refresh_token = mock_refresh

    rc = engine.broker_check()
    _Path(result_file_str).write_text(str(rc if rc is not None else 0))


def child_recovery_failure(
    config_dir_str, accounts_dir_str, creds_dir_str, engine_path_str, result_file_str
):
    """Runs in a subprocess: fires broker_check when EVERY live sibling holds
    a dead RT. Broker should exhaust recovery, return 2, and touch the flag.
    """
    import importlib.util
    import json as _json
    import os as _os
    from pathlib import Path as _Path

    _os.environ["CLAUDE_CONFIG_DIR"] = config_dir_str

    spec = importlib.util.spec_from_file_location("engine", engine_path_str)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    engine.ACCOUNTS_DIR = _Path(accounts_dir_str)
    engine.CREDS_DIR = _Path(creds_dir_str)
    engine.PROFILES_FILE = _Path(accounts_dir_str) / "profiles.json"
    engine.QUOTA_FILE = _Path(accounts_dir_str) / "quota.json"

    def mock_refresh(account_num, quiet=False):
        # Every RT is rejected — no recovery candidate can save us
        return None

    engine.refresh_token = mock_refresh

    rc = engine.broker_check()
    _Path(result_file_str).write_text(str(rc if rc is not None else 0))


def child_recovery_clears_flag(
    config_dir_str, accounts_dir_str, creds_dir_str, engine_path_str, result_file_str
):
    """Runs in a subprocess: a broker-failed flag already exists from a prior
    cycle. Broker does a successful primary refresh and should clear the flag.
    """
    import importlib.util
    import json as _json
    import os as _os
    import time as _time
    from pathlib import Path as _Path

    _os.environ["CLAUDE_CONFIG_DIR"] = config_dir_str

    spec = importlib.util.spec_from_file_location("engine", engine_path_str)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    engine.ACCOUNTS_DIR = _Path(accounts_dir_str)
    engine.CREDS_DIR = _Path(creds_dir_str)
    engine.PROFILES_FILE = _Path(accounts_dir_str) / "profiles.json"
    engine.QUOTA_FILE = _Path(accounts_dir_str) / "quota.json"

    def mock_refresh(account_num, quiet=False):
        cred_file = engine.CREDS_DIR / f"{account_num}.json"
        new_creds = _make_creds(
            RT_RECOVERED, AT_RECOVERED, int(_time.time() * 1000) + 60 * 60 * 1000
        )
        tmp = cred_file.with_suffix(".tmp")
        tmp.write_text(_json.dumps(new_creds, indent=2))
        _os.chmod(tmp, 0o600)
        _os.replace(tmp, cred_file)
        return new_creds

    engine.refresh_token = mock_refresh

    rc = engine.broker_check()
    _Path(result_file_str).write_text(str(rc if rc is not None else 0))


def _setup_accounts(tmpdir_prefix):
    tmpdir = Path(tempfile.mkdtemp(prefix=tmpdir_prefix))
    accounts_dir = tmpdir / "accounts"
    creds_dir = accounts_dir / "credentials"
    creds_dir.mkdir(parents=True)
    (accounts_dir / "profiles.json").write_text(
        json.dumps({"accounts": {str(i): {"email": f"a{i}@x"} for i in range(1, 8)}})
    )
    return tmpdir, accounts_dir, creds_dir


def _run_child(target, args):
    ctx = multiprocessing.get_context("fork")
    p = ctx.Process(target=target, args=args)
    p.start()
    p.join(timeout=15)
    if p.is_alive():
        p.terminate()
        return False
    return True


def test_recovery_success(engine_path):
    """Canonical is dead. One sibling has a live rotated RT. Recovery
    promotes it, retries refresh, canonical is healed, fanout reaches all."""
    print("\n=== recovery: dead canonical healed from a live sibling ===")
    tmpdir, accounts_dir, creds_dir = _setup_accounts("csq-recovery-success-")
    try:
        now_ms = int(time.time() * 1000)
        dead_expires = now_ms + 60 * 1000  # 1 min remaining → broker fires

        # Canonical has the dead RT (CC rotated it and canonical was left stale)
        canonical = creds_dir / "1.json"
        canonical.write_text(
            json.dumps(_make_creds(RT_DEAD, AT_DEAD, dead_expires), indent=2)
        )

        # Three config dirs on account 1:
        #   config-1: holds dead RT (matches canonical)
        #   config-2: holds the LIVE rotated RT — this is our rescuer
        #   config-3: holds a DIFFERENT dead RT (sibling that also lost its RT)
        config_1 = accounts_dir / "config-1"
        config_2 = accounts_dir / "config-2"
        config_3 = accounts_dir / "config-3"
        for cd in [config_1, config_2, config_3]:
            cd.mkdir(parents=True)
            (cd / ".csq-account").write_text("1")
        (config_1 / ".credentials.json").write_text(
            json.dumps(_make_creds(RT_DEAD, AT_DEAD, dead_expires), indent=2)
        )
        (config_2 / ".credentials.json").write_text(
            json.dumps(_make_creds(RT_LIVE, AT_LIVE, now_ms + 60 * 60 * 1000), indent=2)
        )
        (config_3 / ".credentials.json").write_text(
            json.dumps(
                _make_creds(RT_OTHER_DEAD, AT_OTHER_DEAD, dead_expires), indent=2
            )
        )

        result_file = tmpdir / "result"
        result_file.write_text("")

        # Run broker_check from config-1 (the one whose CC read canonical)
        ok = _run_child(
            child_recovery_success,
            (
                str(config_1),
                str(accounts_dir),
                str(creds_dir),
                engine_path,
                str(result_file),
            ),
        )
        if not ok:
            print("  ✗ subprocess hung")
            return False

        rc = int(result_file.read_text() or "0")
        canon_after = json.loads(canonical.read_text())
        canon_at = canon_after["claudeAiOauth"]["accessToken"]
        flag = creds_dir / "1.broker-failed"

        results = []
        results.append(("broker_check returned 0 (recovered)", rc == 0))
        results.append(("canonical holds recovered tokens", canon_at == AT_RECOVERED))
        results.append(("broker-failed flag absent after success", not flag.exists()))

        for cd in [config_1, config_2, config_3]:
            live = json.loads((cd / ".credentials.json").read_text())
            live_at = live["claudeAiOauth"]["accessToken"]
            results.append(
                (
                    f"{cd.name} received fanout (live == recovered)",
                    live_at == AT_RECOVERED,
                )
            )

        passed = sum(1 for _, ok in results if ok)
        failed = len(results) - passed
        for name, ok in results:
            icon = "✓" if ok else "✗"
            print(f"  {icon} {name}")
        return failed == 0
    finally:
        shutil.rmtree(tmpdir)


def test_recovery_failure(engine_path):
    """Canonical is dead and every sibling also has a dead RT. Broker
    exhausts recovery, returns 2, touches the failure flag, restores the
    original canonical content."""
    print("\n=== recovery: all siblings dead → return 2, flag touched ===")
    tmpdir, accounts_dir, creds_dir = _setup_accounts("csq-recovery-failure-")
    try:
        now_ms = int(time.time() * 1000)
        dead_expires = now_ms + 60 * 1000

        canonical = creds_dir / "1.json"
        original_canon = _make_creds(RT_DEAD, AT_DEAD, dead_expires)
        canonical.write_text(json.dumps(original_canon, indent=2))

        # Two siblings, both holding different (also dead) RTs
        config_1 = accounts_dir / "config-1"
        config_2 = accounts_dir / "config-2"
        for cd in [config_1, config_2]:
            cd.mkdir(parents=True)
            (cd / ".csq-account").write_text("1")
        (config_1 / ".credentials.json").write_text(
            json.dumps(_make_creds(RT_DEAD, AT_DEAD, dead_expires), indent=2)
        )
        (config_2 / ".credentials.json").write_text(
            json.dumps(
                _make_creds(RT_OTHER_DEAD, AT_OTHER_DEAD, dead_expires), indent=2
            )
        )

        result_file = tmpdir / "result"
        result_file.write_text("")

        ok = _run_child(
            child_recovery_failure,
            (
                str(config_1),
                str(accounts_dir),
                str(creds_dir),
                engine_path,
                str(result_file),
            ),
        )
        if not ok:
            print("  ✗ subprocess hung")
            return False

        rc = int(result_file.read_text() or "0")
        canon_after = json.loads(canonical.read_text())
        canon_rt = canon_after["claudeAiOauth"]["refreshToken"]
        flag = creds_dir / "1.broker-failed"

        results = []
        results.append(("broker_check returned 2 (exhausted)", rc == 2))
        results.append(("broker-failed flag touched", flag.exists()))
        results.append(
            (
                "canonical rolled back to original dead content",
                canon_rt == RT_DEAD,
            )
        )

        passed = sum(1 for _, ok in results if ok)
        failed = len(results) - passed
        for name, ok in results:
            icon = "✓" if ok else "✗"
            print(f"  {icon} {name}")
        return failed == 0
    finally:
        shutil.rmtree(tmpdir)


def test_flag_cleared_on_success(engine_path):
    """A previous cycle left the broker-failed flag behind. A subsequent
    successful refresh must remove it."""
    print("\n=== recovery: stale flag cleared on next successful refresh ===")
    tmpdir, accounts_dir, creds_dir = _setup_accounts("csq-recovery-flag-")
    try:
        now_ms = int(time.time() * 1000)
        # Canonical has a valid RT but is inside the refresh window
        canonical = creds_dir / "1.json"
        canonical.write_text(
            json.dumps(_make_creds(RT_DEAD, AT_DEAD, now_ms + 60 * 1000), indent=2)
        )

        config_1 = accounts_dir / "config-1"
        config_1.mkdir(parents=True)
        (config_1 / ".csq-account").write_text("1")
        (config_1 / ".credentials.json").write_text(
            json.dumps(_make_creds(RT_DEAD, AT_DEAD, now_ms + 60 * 1000), indent=2)
        )

        # Pre-touch the failure flag as if a prior cycle left it behind
        flag = creds_dir / "1.broker-failed"
        flag.touch()

        result_file = tmpdir / "result"
        result_file.write_text("")

        ok = _run_child(
            child_recovery_clears_flag,
            (
                str(config_1),
                str(accounts_dir),
                str(creds_dir),
                engine_path,
                str(result_file),
            ),
        )
        if not ok:
            print("  ✗ subprocess hung")
            return False

        rc = int(result_file.read_text() or "0")

        results = []
        results.append(("broker_check returned 0", rc == 0))
        results.append(("stale flag removed after success", not flag.exists()))

        passed = sum(1 for _, ok in results if ok)
        failed = len(results) - passed
        for name, ok in results:
            icon = "✓" if ok else "✗"
            print(f"  {icon} {name}")
        return failed == 0
    finally:
        shutil.rmtree(tmpdir)


def main():
    engine_path = str((Path(__file__).parent / "rotation-engine.py").resolve())
    if not os.path.exists(engine_path):
        print(f"ERROR: rotation-engine.py not found at {engine_path}")
        sys.exit(1)

    all_passed = True
    all_passed &= test_recovery_success(engine_path)
    all_passed &= test_recovery_failure(engine_path)
    all_passed &= test_flag_cleared_on_success(engine_path)

    print()
    if all_passed:
        print("ALL TESTS PASSED ✓")
        sys.exit(0)
    print("SOME TESTS FAILED ✗")
    sys.exit(1)


if __name__ == "__main__":
    main()
