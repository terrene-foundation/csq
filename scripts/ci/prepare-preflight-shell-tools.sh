#!/usr/bin/env bash
# ci-gate: helper
# ci-gate-reason: Prepares ignored, checkout-local prerequisites for native shell shards.
# ci-gate-invoker: scripts/ci/preflight-shell-tests.mjs before real test population.
set -euo pipefail
exec python3 - "$@" <<'PYTOOLS'
import fcntl, hashlib, json, os, re, shutil, signal, stat, subprocess, sys, tempfile, time, uuid
from pathlib import Path

root = Path(sys.argv[1]).resolve()
names = sys.argv[2:]
pretty_subjects = {'auto-format-hook.test.sh', 'post-edit-dispatch.test.sh'}
yaml_subjects = {'citation-resolution.test.sh', 'oauth-replay-toolchain.test.sh', 'shell-gate-undetermined.test.sh', 'job-budget-audit.test.sh', 'dev-preflight.test.sh'}
full = (root / 'CLAUDE.md').exists() or (root / 'package.json').exists()
pretty, yaml_needed = full or bool(set(names) & pretty_subjects), full or bool(set(names) & yaml_subjects)
report = {'schema': 'csq.preflight_shell_tools.v1', 'test_names': names, 'state': 'UNDETERMINED', 'path_prefixes': []}
deadline = time.monotonic() + 300
log = None
lock = None
active_child = None
cancelled_signal = None
cleanup_error = None
child_event = False

# Recording rather than raising closes the Popen-to-tracking signal race. This
# single-threaded helper polls cancellation; the lock remains held through reap.
def cancel(signum, _frame):
    global cancelled_signal
    if cancelled_signal is None:
        cancelled_signal = signum

for cancellation_signal in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
    signal.signal(cancellation_signal, cancel)

def child_notification(_signum, _frame):
    global child_event
    child_event = True

signal.signal(signal.SIGCHLD, child_notification)

def check_cancelled():
    if cancelled_signal is not None:
        raise RuntimeError('setup cancelled: ' + signal.Signals(cancelled_signal).name)

# Group-membership oracle - kernel metadata only, no dependence on the
# member's uid, on signalability, or on per-pid zombie records (measured
# 2026-10-11: neither PROC_PIDT_SHORTBSDINFO nor PROC_PIDTBSDINFO returns a
# record for a zombie - both report ESRCH - while the PGRP listing DOES
# contain it). Acceptance requires BOTH positive facts: the pinned leader is
# observed EXITED but unreaped (waitid WNOWAIT - its pending PID reserves the
# PGID, so no reuse race) and the complete kernel group listing contains
# exactly that leader. Any other listed pid is live-or-unknown (it may fork
# before dying), so it fails closed; an empty, errored, truncated,
# partially-read or leader-less listing is not emptiness either.
GROUP_ORACLE = None
def group_other_members(leader):
    # Load the shared oracle from this checkout, never an ambient module name.
    global GROUP_ORACLE
    if GROUP_ORACLE is None:
        import importlib.util
        try:
            spec = importlib.util.spec_from_file_location(
                'csq_owned_group_oracle', root / 'scripts/lib/proof_child_groups.py')
            if spec is None or spec.loader is None:
                raise RuntimeError('shared group oracle unavailable')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            GROUP_ORACLE = module.group_other_members
        except Exception as error:
            raise RuntimeError('shared group oracle unavailable') from error
    return GROUP_ORACLE(leader)

def leader_exited(leader):
    # Non-reaping leader-death observation. waitid WNOWAIT where available;
    # otherwise the SIGCHLD hint, the same conservative completion signal the
    # command loop uses - child.wait() below remains the real proof.
    if hasattr(os, 'waitid'):
        return os.waitid(os.P_PID, leader, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    return child_event

def reap_active(grace=0.5):
    global active_child, cleanup_error
    child = active_child
    if child is None:
        return
    # Neither waitid(WNOWAIT) nor the portable SIGCHLD hint reaps the leader:
    # its PID reserves this PG even after exit. Never signal an unrelated group
    # after releasing that identity.
    try:
        refused = False
        # Signalability is permission-based, and start_new_session constrains
        # neither uid nor membership: a member that changed uid stays live yet
        # may refuse every group signal, and a delivered signal reaches only
        # the members it is permitted to reach. Signal results therefore
        # cannot establish group emptiness here; acceptance below rests on
        # kernel membership evidence instead (Darwin refuses even a
        # zombie-only group routinely - measured 2026-10-11 - so the gate
        # engages on every Darwin reap).
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            refused = True
        if grace:
            time.sleep(grace)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            refused = True
        if refused or sys.platform == 'darwin':
            # Positive membership evidence before acceptance: the pinned
            # leader must be observed EXITED-UNREAPED (waitid WNOWAIT - its
            # pending PID reserves the PGID, so the listing cannot race a
            # reused group) and the complete kernel listing must contain
            # exactly that leader. A bounded quiescence window absorbs members
            # that died to the signals but are not yet reaped; every other
            # outcome - unreadable, errored, truncated, leader-less, or any
            # other listed pid - leaves cleanup UNCONFIRMED through the outer
            # handler.
            try:
                quiet_until = time.monotonic() + 2.0
                while True:
                    exited = leader_exited(child.pid)
                    other = group_other_members(child.pid) if exited else []
                    if exited and not other:
                        break
                    if time.monotonic() >= quiet_until:
                        if other:
                            raise OSError('group tear-down left live members ' + repr(other))
                        raise OSError('group cleanup could not be confirmed before the quiescence deadline')
                    time.sleep(0.05)
            except RuntimeError as error:
                raise OSError(str(error))
        child.wait(timeout=0.5)
        active_child = None
    except (OSError, subprocess.TimeoutExpired):
        cleanup_error = 'owned installer cleanup could not be confirmed'
        raise RuntimeError(cleanup_error)

def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= 1024 * 1024, 'input file type/owner/size refused')
        return file.read()

def directory(path, private=False):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'scoped directory type/owner refused')
    if private:
        require(not info.st_mode & 0o077, 'private setup directory permissions refused')

def command(argv, env=None):
    global active_child, child_event
    check_cancelled()
    native_observation = all(hasattr(os, name) for name in ['waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT'])
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'setup deadline exhausted')
    log.write(('PHASE ' + Path(argv[0]).name + '\n').encode()); log.flush()
    with tempfile.TemporaryFile(dir=log_path.parent) as output_file:
        try:
            # A signal during Popen only records cancellation. Assignment still
            # completes before cancellation can unwind or release the lock.
            child_event = False
            active_child = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=output_file, stderr=log, start_new_session=True)
            while True:
                check_cancelled()
                require(time.monotonic() < deadline, 'setup command timed out')
                try:
                    finished = os.waitid(os.P_PID, active_child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) if native_observation else (True if child_event else None)
                except InterruptedError:
                    continue
                if finished is not None:
                    # SIGCHLD is only a conservative hint on platforms without
                    # waitid. Actual reaped status below must still be zero.
                    break
                time.sleep(0.05)
            check_cancelled()
            child = active_child
            reap_active(grace=0)
            output_file.seek(0)
            output = output_file.read(1024 * 1024 + 1)
            log.write(output); log.flush()
            require(child.returncode == 0, 'setup command failed: ' + Path(argv[0]).name + ' exit=' + str(child.returncode))
            require(len(output) <= 1024 * 1024, 'setup response capped')
            return output
        finally:
            try:
                reap_active()
            except RuntimeError:
                # Preserve the original cancellation/timeout/error cause; the
                # final receipt separately refuses unconfirmed cleanup.
                report['cleanup_error'] = cleanup_error

try:
    require(names and len(names) <= 1000 and all(re.fullmatch(r'[A-Za-z0-9_.-]+\.test\.sh', name) for name in names), 'test membership malformed')
    if not pretty and not yaml_needed:
        report['state'] = 'NONE'
    else:
        directory(root / 'target')
        scoped = root / 'target/.csq-preflight-shell-tools'
        directory(scoped, True)
        log_path = scoped / ('setup-' + str(uuid.uuid4()) + '.log')
        log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb')
        command(['git', 'check-ignore', '--no-index', '-q', str(scoped)])
        fd = os.open(scoped / 'setup.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        lock = os.fdopen(fd, 'r+')
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid == os.getuid() and not os.fstat(fd).st_mode & 0o077, 'setup lock type/owner refused')
        while True:
            check_cancelled()
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, 'setup lock deadline exhausted')
                time.sleep(0.1)
        inputs = []
        if pretty:
            manifest = read(root / 'package.json'); locked = read(root / 'package-lock.json')
            package, packages = json.loads(manifest), json.loads(locked)['packages']
            version = package.get('devDependencies', {}).get('prettier')
            require(package.get('name') == 'csq-repo-tooling' and isinstance(version, str) and re.fullmatch(r'\d+\.\d+\.\d+', version), 'manifest Prettier exact pin absent')
            require(packages['']['devDependencies']['prettier'] == version and packages['node_modules/prettier']['version'] == version and packages['node_modules/prettier'].get('integrity'), 'manifest/lock Prettier pin mismatch')
            inputs += [manifest, locked]
            report['prettier_version'] = version
        if yaml_needed:
            requirements = read(root / 'scripts/verify/requirements.txt')
            declaration = ' '.join(line.strip().rstrip('\\') for line in requirements.decode().splitlines() if line.strip() and not line.lstrip().startswith('#'))
            match = re.fullmatch(r'pyyaml==(\d+\.\d+\.\d+)(?:\s+--hash=sha256:[0-9a-f]{64})+', declaration, re.I)
            require(match, 'hashed PyYAML exact requirements absent')
            report['pyyaml_version'] = match[1]
            inputs.append(requirements)
        stamp = hashlib.sha256(b'\x00'.join(inputs)).hexdigest()
        cached = scoped / 'ready.json'
        ready = cached.exists() and json.loads(read(cached)).get('inputs_sha256') == stamp
        # Install configuration cannot redirect these checkout-local commands to a
        # host prefix/target. Distinct empty files also avoid npm double-loading.
        require(not (root / '.npmrc').exists(), 'unbound checkout npm configuration refused')
        for config_name in ['npm-user-config', 'npm-global-config']:
            config_path = scoped / config_name
            if not config_path.exists():
                with os.fdopen(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb'):
                    pass
            require(read(config_path) == b'', 'setup npm configuration changed')
        child_env = {key: value for key, value in os.environ.items()
                     if not key.lower().startswith(('npm_config_', 'pip_')) and key not in ['PYTHONHOME', 'PYTHONPATH']}
        child_env.update(PYTHONNOUSERSITE='1', PYTHONPATH='', PIP_CONFIG_FILE=os.devnull, PIP_CACHE_DIR=str(scoped / 'pip-cache'), npm_config_cache=str(scoped / 'npm-cache'), npm_config_userconfig=str(scoped / 'npm-user-config'), npm_config_globalconfig=str(scoped / 'npm-global-config'))
        if pretty:
            require(shutil.which('npm'), 'npm unavailable')
            require(not (root / 'node_modules').is_symlink(), 'checkout node_modules symlink refused')
            if not ready:
                command(['npm', 'ci', '--no-audit', '--no-fund'], child_env)
            installed = root / 'node_modules/prettier/package.json'
            require(json.loads(read(installed)).get('version') == version, 'installed Prettier package version mismatch')
            require((root / 'node_modules/prettier').resolve().is_relative_to((root / 'node_modules').resolve()), 'Prettier package escapes checkout')
            executable = root / 'node_modules/.bin/prettier'
            require(executable.resolve().is_relative_to((root / 'node_modules/prettier').resolve()), 'Prettier executable escapes package')
            require(command([str(executable), '--version'], child_env).decode().strip() == version, 'actual Prettier version mismatch')
            report['path_prefixes'].append(str(root / 'node_modules/.bin'))
        if yaml_needed:
            venv = scoped / 'venv'
            require(not venv.is_symlink(), 'checkout venv symlink refused')
            if not ready:
                command([sys.executable, '-m', 'venv', str(venv)], child_env)
                command([str(venv / 'bin/python3'), '-I', '-m', 'pip', 'install', '--require-hashes', '--no-input', '--disable-pip-version-check', '-r', str(root / 'scripts/verify/requirements.txt')], child_env)
            probe = command([str(venv / 'bin/python3'), '-I', '-c', 'import json,yaml; print(json.dumps({"version":yaml.__version__,"path":yaml.__file__}))'], child_env)
            actual = json.loads(probe)
            require(actual['version'] == report['pyyaml_version'] and Path(actual['path']).resolve().is_relative_to(venv.resolve()), 'actual checkout PyYAML version/location mismatch')
            report['path_prefixes'].insert(0, str(venv / 'bin'))
            report['python_bin'] = str(venv / 'bin/python3')
        stamp_path = scoped / ('ready-' + str(uuid.uuid4()) + '.json')
        with os.fdopen(os.open(stamp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'w') as file:
            json.dump({'inputs_sha256': stamp}, file)
        stamp_path.replace(cached)
        check_cancelled()
        report['state'] = 'READY'
except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
    report['reason'] = str(error) if isinstance(error, RuntimeError) else 'checkout prerequisite evidence unavailable'
finally:
    # The command finally owns cleanup; this also protects future callsites.
    try:
        reap_active()
    except RuntimeError:
        report['state'] = 'UNDETERMINED'
        report['cleanup_error'] = cleanup_error
    if cancelled_signal is not None:
        report['state'] = 'UNDETERMINED'
        report.setdefault('reason', 'setup cancelled: ' + signal.Signals(cancelled_signal).name)
    if lock:
        lock.close()
    if log:
        log.close()
        report['setup_output_evidence'] = {'path': str(log_path), 'sha256': hashlib.sha256(log_path.read_bytes()).hexdigest()}
print(json.dumps(report))
raise SystemExit(0 if report['state'] in ['READY', 'NONE'] else 2)
PYTOOLS
