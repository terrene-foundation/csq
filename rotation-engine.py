#!/usr/bin/env python3
"""
Claude Squad — Rotation Engine

Tracks quota across accounts. Auto-rotates by refreshing OAuth tokens
and writing credentials for the current terminal.

Each terminal runs CC with CLAUDE_CONFIG_DIR=~/.claude/accounts/config-N,
giving it isolated credentials. On macOS, each config dir also gets a
unique keychain entry: Claude Code-credentials-<sha256(dir)[:8]>.
On Linux/WSL/Windows, file-only credential storage is used.

State files (all in ~/.claude/accounts/):
  credentials/N.json   Stored OAuth credentials per account (1-7)
  profiles.json        Email→account mapping
  quota.json           Per-account quota from statusline
  config-N/            Per-account CC config dir (CLAUDE_CONFIG_DIR target)
  config-N/.current-account   Which account's creds are in this terminal

Commands:
  update               Update quota from statusline JSON (stdin)
  status               Show all accounts and quota
  statusline           Compact string for statusline display
  suggest              Suggest best account to switch to (JSON)
  swap <N>             Refresh account N's token and write to this terminal's creds
  auto-rotate          Check + swap if current account is exhausted
  auto-rotate --force  Force-rotate (marks current exhausted first)
  check                JSON check: should this terminal rotate? (for hooks)
  init-keychain <N>    Write stored creds for account N to this terminal (macOS: keychain)
  snapshot             Refresh .current-account on CC restart (statusline hook)
  cleanup              Remove stale PID cache files
  python-cmd           Print the resolved Python 3 command for this platform
"""

import ctypes
import getpass
import hashlib
import json
import os
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

# ─── Platform Detection ─────────────────────────────────

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# ─── Win32 ctypes signatures ─────────────────────────────
# CRITICAL: Windows API handles are pointer-sized (64 bits on 64-bit Windows).
# Without explicit restype/argtypes, ctypes defaults restype to c_int (32 bits)
# and silently truncates handles. The truncated handle then fails every
# subsequent kernel call without any error indication. We declare every
# signature explicitly so handles round-trip correctly.

if IS_WINDOWS:
    _kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    # Mutex
    _kernel32.CreateMutexW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    ]
    _kernel32.CreateMutexW.restype = ctypes.c_void_p
    _kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    _kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    _kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
    _kernel32.ReleaseMutex.restype = ctypes.c_bool
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = ctypes.c_bool

    # Process query
    _kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.GetExitCodeProcess.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    _kernel32.GetExitCodeProcess.restype = ctypes.c_bool

    # Process tree walk
    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    _kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    _kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    _kernel32.Process32FirstW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_PROCESSENTRY32W),
    ]
    _kernel32.Process32FirstW.restype = ctypes.c_bool
    _kernel32.Process32NextW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_PROCESSENTRY32W),
    ]
    _kernel32.Process32NextW.restype = ctypes.c_bool

    _WAIT_OBJECT_0 = 0
    _STILL_ACTIVE = 259
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ─── File Locking ────────────────────────────────────────
# POSIX: fcntl.flock() — advisory, whole-file, blocks indefinitely.
# Windows: named mutex via kernel32 — cooperative, blocks indefinitely.
# NOT msvcrt.locking() — wrong semantics (mandatory byte-range, 10s timeout).

if IS_WINDOWS:

    def _lock_file(lock_path):
        """Acquire a named mutex derived from the lock file path.
        Returns the handle on success, None on failure."""
        name = "csq_" + str(lock_path).replace("\\", "_").replace("/", "_").replace(
            ":", "_"
        )
        handle = _kernel32.CreateMutexW(None, False, name)
        if not handle:
            return None
        wait_result = _kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)  # INFINITE
        if wait_result != _WAIT_OBJECT_0:
            _kernel32.CloseHandle(handle)
            return None
        return handle

    def _try_lock_file(lock_path):
        """Non-blocking variant: returns handle on success, None if held."""
        name = "csq_" + str(lock_path).replace("\\", "_").replace("/", "_").replace(
            ":", "_"
        )
        handle = _kernel32.CreateMutexW(None, False, name)
        if not handle:
            return None
        wait_result = _kernel32.WaitForSingleObject(handle, 0)  # immediate
        if wait_result != _WAIT_OBJECT_0:
            _kernel32.CloseHandle(handle)
            return None
        return handle

    def _unlock_file(handle):
        if handle:
            _kernel32.ReleaseMutex(handle)
            _kernel32.CloseHandle(handle)

else:
    import fcntl

    def _lock_file(lock_path):
        fd = open(lock_path, "w")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _try_lock_file(lock_path):
        """Non-blocking variant: returns fd on success, None if held."""
        fd = open(lock_path, "w")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except (BlockingIOError, OSError):
            fd.close()
            return None

    def _unlock_file(fd):
        if fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
            except Exception:
                pass


def _secure_file(path):
    """Set file permissions to owner-only. No-op on Windows."""
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _atomic_replace(tmp_path, target_path):
    """Atomic rename with retry for Windows file-in-use conflicts."""
    for attempt in range(5):
        try:
            os.replace(str(tmp_path), str(target_path))
            return
        except PermissionError:
            if IS_WINDOWS and attempt < 4:
                time.sleep(0.1)
                continue
            raise


def _python_cmd():
    """Return the Python 3 command for this platform."""
    if IS_WINDOWS:
        for cmd in ["python3", "python", "py"]:
            try:
                r = subprocess.run(
                    [cmd, "--version"], capture_output=True, text=True, timeout=3
                )
                if r.returncode == 0 and "Python 3" in r.stdout:
                    return cmd
            except FileNotFoundError:
                continue
        return "python"
    return "python3"


ACCOUNTS_DIR = Path.home() / ".claude" / "accounts"
CREDS_DIR = ACCOUNTS_DIR / "credentials"
QUOTA_FILE = ACCOUNTS_DIR / "quota.json"
PROFILES_FILE = ACCOUNTS_DIR / "profiles.json"
MAX_ACCOUNTS = 999  # README promises "unlimited"; 999 is the practical ceiling

# OAuth constants (from Claude Code source)
TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
SCOPES = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"


def _load(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save(path, data):
    """Atomic write: temp file + rename. Sets 600 permissions."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    _secure_file(tmp)
    _atomic_replace(tmp, path)


def load_state():
    state = _load(QUOTA_FILE, {"accounts": {}})
    now = time.time()
    for acct_data in state.get("accounts", {}).values():
        for window in ("five_hour", "seven_day"):
            w = acct_data.get(window, {})
            if (
                w.get("resets_at", 0)
                and w["resets_at"] < now
                and w.get("used_percentage", 0) > 0
            ):
                w["used_percentage"] = 0
    return state


def get_email(n):
    return _load(PROFILES_FILE, {}).get("accounts", {}).get(str(n), {}).get("email", "")


def configured_accounts():
    profiles = _load(PROFILES_FILE, {}).get("accounts", {})
    return sorted(profiles.keys(), key=int)


# ─── Account Detection ──────────────────────────────────


def _config_dir():
    """Get CLAUDE_CONFIG_DIR if set."""
    return os.environ.get("CLAUDE_CONFIG_DIR", "")


def which_account():
    """Which account is this terminal on?

    Fast path: reads .current-account from CLAUDE_CONFIG_DIR.
    Fallback: extracts from config dir name (config-N).
    Last resort: claude auth status --json.

    NOTE: .current-account is updated by the statusline `snapshot` command
    which detects new CC processes via PID. swap_to() also writes this file
    directly so the statusline picks up swaps immediately.
    """
    config_dir = _config_dir()
    if config_dir:
        # Check .current-account file (updated by snapshot on CC restart)
        current_file = Path(config_dir) / ".current-account"
        if current_file.exists():
            try:
                n = current_file.read_text().strip()
                if n:
                    return n
            except OSError:
                pass
        # Initial state: extract from config dir name
        basename = os.path.basename(config_dir.rstrip("/"))
        if basename.startswith("config-") and basename[7:].isdigit():
            n = basename[7:]
            try:
                current_file.write_text(n)
            except OSError:
                pass
            return n

    # Fallback: ask CC directly
    try:
        r = subprocess.run(
            ["claude", "auth", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return None
        email = json.loads(r.stdout).get("email", "")
    except Exception:
        return None

    profiles = _load(PROFILES_FILE, {}).get("accounts", {})
    for n, info in profiles.items():
        if info.get("email") == email:
            return n

    return None


# ─── Live-Account Snapshot ──────────────────────────────
#
# Why this exists: the statusline runs in our process, not CC's. To know
# which account is "live" for a given CC instance, we use a per-CC-process
# snapshot triggered from the statusline. We detect "new CC process" via
# .live-pid: if the recorded PID is dead or absent, the next snapshot
# refreshes the account identity from disk. While the same CC process is
# alive, the snapshot is a single os.kill probe and a no-op.


def _is_pid_alive(pid):
    """Return True if the given PID exists."""
    if IS_WINDOWS:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = _kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
        )
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        ok = _kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        _kernel32.CloseHandle(handle)
        return bool(ok) and exit_code.value == _STILL_ACTIVE
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (ValueError, OSError):
        return False
    return True


def _is_cc_command(cmd):
    """Check if a command string looks like Claude Code CLI."""
    cmd = cmd.lower()
    return (
        "claude" in cmd
        and "claude-squad" not in cmd
        and "rotation-engine" not in cmd
        and "statusline" not in cmd
        and "/csq" not in cmd
        and " csq" not in cmd
    )


def _find_cc_pid():
    """Walk the parent process tree from this Python process upward,
    returning the PID of the first ancestor that looks like the Claude Code
    CLI. Skips csq/rotation-engine/statusline helpers in the chain.

    Used by snapshot_account() to identify "the CC process that owns this
    statusline invocation" so its lifetime can act as the snapshot key.
    """
    if IS_WINDOWS:
        return _find_cc_pid_windows()
    return _find_cc_pid_posix()


def _find_cc_pid_posix():
    """POSIX process tree walk using ps."""
    pid = os.getppid()
    for _ in range(20):
        if pid <= 1:
            break
        try:
            r = subprocess.run(
                ["ps", "-p", str(pid), "-o", "ppid=,command="],
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if r.returncode != 0:
            return None
        line = r.stdout.strip()
        if not line:
            return None
        parts = line.split(None, 1)
        if len(parts) != 2:
            return None
        try:
            ppid = int(parts[0])
        except ValueError:
            return None
        if _is_cc_command(parts[1]):
            return pid
        pid = ppid
    return None


def _find_cc_pid_windows():
    """Windows process tree walk using CreateToolhelp32Snapshot.

    Single kernel call returns all processes. Walk parent chain from our PID
    upward. Zero startup cost (no PowerShell/wmic subprocess).
    """
    TH32CS_SNAPPROCESS = 0x00000002

    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == _INVALID_HANDLE_VALUE:
        return None

    # Build PID → (parent_pid, exe_name) map
    procs = {}
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    if _kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
        while True:
            procs[entry.th32ProcessID] = (
                entry.th32ParentProcessID,
                entry.szExeFile,
            )
            if not _kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    _kernel32.CloseHandle(snapshot)

    # Walk parent chain
    pid = os.getppid()
    for _ in range(20):
        if pid <= 1 or pid not in procs:
            break
        parent_pid, exe = procs[pid]
        if _is_cc_command(exe):
            return pid
        pid = parent_pid
    return None


def _match_token_to_account(access_token):
    """Return the account number whose stored credential file has a matching
    access token, or None."""
    if not access_token:
        return None
    for n in configured_accounts():
        cred_file = CREDS_DIR / f"{n}.json"
        if not cred_file.exists():
            continue
        try:
            stored = json.loads(cred_file.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if stored.get("claudeAiOauth", {}).get("accessToken") == access_token:
            return n
    return None


def credentials_file_account():
    """Read <CLAUDE_CONFIG_DIR>/.credentials.json and identify which account
    its access token belongs to.

    Used as a fallback when the .csq-account marker is missing (legacy
    setups). Primary source is csq_account_marker(), which is more reliable
    because it survives CC's internal token refreshes (refreshing changes
    the access_token but not the account, so token-matching breaks the
    moment CC writes a refreshed token to .credentials.json).
    """
    config_dir = _config_dir()
    if not config_dir:
        return None
    cred_path = Path(config_dir) / ".credentials.json"
    if not cred_path.exists():
        return None
    try:
        data = json.loads(cred_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return _match_token_to_account(data.get("claudeAiOauth", {}).get("accessToken", ""))


def live_credentials_account():
    """Return the account number whose canonical credentials/N.json has the
    SAME refresh token as this terminal's live .credentials.json, or None.

    This is race-proof ground truth for "which account is this terminal
    actually running". Refresh tokens are unique per account and persist
    across access-token rotation, so the match cannot be fooled by CC's
    internal token refreshes.

    Why this exists alongside csq_account_marker(): the marker files
    (.csq-account, .current-account) record csq's INTENT. But if CC has
    cached an older account's refresh token in memory and subsequently
    writes it back to .credentials.json, the live creds drift away from
    the marker's intent. Any code that attributes live API-response data
    (like rate_limits) to the marker-claimed account will then corrupt
    that account's stats. Those code paths MUST verify with this function.
    """
    config_dir = _config_dir()
    if not config_dir:
        return None
    live_creds_file = Path(config_dir) / ".credentials.json"
    if not live_creds_file.exists():
        return None
    try:
        live_data = json.loads(live_creds_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    live_refresh = live_data.get("claudeAiOauth", {}).get("refreshToken", "")
    if not live_refresh:
        return None
    for n in configured_accounts():
        canonical = CREDS_DIR / f"{n}.json"
        if not canonical.exists():
            continue
        try:
            canon_data = json.loads(canonical.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if canon_data.get("claudeAiOauth", {}).get("refreshToken", "") == live_refresh:
            return n
    return None


def csq_account_marker():
    """Read the .csq-account marker from <CLAUDE_CONFIG_DIR>.

    This is the PRIMARY source of truth for "which account does csq think
    is loaded in this config dir". csq writes it from `csq run N` and
    `csq swap N` — both operations csq fully controls, so the marker is
    always correct relative to csq's intent. The snapshot then promotes
    the marker into .current-account at CC startup time (gated by PID).

    Why a separate marker instead of token-matching .credentials.json:
    .credentials.json may be updated by token refresh during a session,
    which would change the access_token and break token-based account
    identification. The marker is durable across refreshes because the
    account number doesn't change just because the token rotates.
    """
    config_dir = _config_dir()
    if not config_dir:
        return None
    marker = Path(config_dir) / ".csq-account"
    if not marker.exists():
        return None
    try:
        n = marker.read_text().strip()
    except OSError:
        return None
    if n.isdigit() and 1 <= int(n) <= MAX_ACCOUNTS:
        return n
    return None


def write_csq_account_marker(account_num):
    """Atomically write the .csq-account marker. Per-config-dir, no global
    state, no contention with other csq terminals."""
    config_dir = _config_dir()
    if not config_dir:
        return False
    marker = Path(config_dir) / ".csq-account"
    try:
        tmp = marker.with_suffix(".tmp")
        tmp.write_text(str(account_num))
        _secure_file(tmp)
        _atomic_replace(tmp, marker)
        return True
    except OSError:
        return False


def snapshot_account():
    """Refresh .current-account when a new CC process is detected. Called
    from the statusline hook on every invocation.

    Cheap path (same CC process still alive): one os.kill probe, then return.
    Expensive path (CC restarted or first run): walk the process tree to
    find the live CC PID, read the per-config-dir state to identify the
    account CC just loaded, and write .current-account + .live-pid.

    Source-of-truth chain (per-config-dir, no global resources touched):
      1. .csq-account marker — written by csq run/swap, durable across CC's
         internal token refreshes
      2. .credentials.json token-match against credentials/N.json — fallback
         for legacy setups that pre-date the marker
      (The macOS keychain is deliberately NOT consulted: it's a global
       resource that doesn't scale with many concurrent csq terminals.)
    """
    config_dir = _config_dir()
    if not config_dir:
        return

    pid_file = Path(config_dir) / ".live-pid"
    try:
        if pid_file.exists():
            old_pid = pid_file.read_text().strip()
            if old_pid and _is_pid_alive(old_pid):
                return  # Same CC process; .current-account is still valid.
    except OSError:
        pass

    cc_pid = _find_cc_pid()
    if cc_pid is None:
        return  # Not invoked from a CC subprocess; can't snapshot reliably.

    account = csq_account_marker()
    if account is None:
        account = credentials_file_account()
    if account is None:
        return  # Couldn't identify the loaded account; leave state alone.

    try:
        (Path(config_dir) / ".current-account").write_text(account)
        pid_file.write_text(str(cc_pid))
    except OSError:
        pass


# ─── Pick Best ───────────────────────────────────────────


def pick_best(state, exclude=None):
    """Pick the account with the most available quota."""
    now = time.time()
    available = []
    exhausted = []

    for n in configured_accounts():
        if n == str(exclude):
            continue
        acct = state.get("accounts", {}).get(n, {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        seven_pct = acct.get("seven_day", {}).get("used_percentage", 0)
        five_reset = acct.get("five_hour", {}).get("resets_at", 0)

        if five_pct >= 100 or seven_pct >= 100:
            exhausted.append((n, five_reset))
            continue
        available.append((n, five_pct))

    if available:
        available.sort(key=lambda x: x[1])
        return available[0][0]

    if exhausted:
        future = [(n, r) for n, r in exhausted if r > now]
        if future:
            future.sort(key=lambda x: x[1])
            return future[0][0]

    return None


# ─── OAuth Token Refresh ────────────────────────────────


def _validate_account(n):
    """Validate account number is 1-7. Prevents path traversal."""
    s = str(n)
    if not s.isdigit() or int(s) < 1 or int(s) > MAX_ACCOUNTS:
        print(
            f"Invalid account number: {n} (must be 1-{MAX_ACCOUNTS})", file=sys.stderr
        )
        sys.exit(1)
    return s


def refresh_token(account_num, quiet=False):
    """Refresh an account's OAuth token. Returns new token data or None.
    If quiet=True, suppresses error output (caller handles messaging)."""
    import urllib.request
    import urllib.error

    cred_file = CREDS_DIR / f"{account_num}.json"
    if not cred_file.exists():
        return None

    creds = json.loads(cred_file.read_text())
    refresh_tok = creds.get("claudeAiOauth", {}).get("refreshToken")
    if not refresh_tok:
        return None

    body = json.dumps(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_tok,
            "client_id": CLIENT_ID,
            "scope": SCOPES,
        }
    ).encode()

    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "claude-code/2.1.91",
        },
    )

    try:
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read().decode()) if e.code < 500 else {}
        if not quiet:
            print(
                f"  Token refresh failed: {err.get('error', {}).get('message', e.code)}",
                file=sys.stderr,
            )
        return None
    except Exception as e:
        if not quiet:
            print(f"  Token refresh error: {e}", file=sys.stderr)
        return None

    access_token = data.get("access_token")
    new_refresh = data.get("refresh_token", refresh_tok)
    expires_in = data.get("expires_in", 18000)

    if not access_token:
        return None

    # Update stored credentials
    new_creds = {
        "claudeAiOauth": {
            "accessToken": access_token,
            "refreshToken": new_refresh,
            "expiresAt": int(time.time() * 1000) + expires_in * 1000,
            "scopes": SCOPES.split(),
            "subscriptionType": creds.get("claudeAiOauth", {}).get("subscriptionType"),
            "rateLimitTier": creds.get("claudeAiOauth", {}).get("rateLimitTier"),
        }
    }
    # Atomic write to prevent credential corruption on crash
    tmp = cred_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(new_creds, indent=2))
    _secure_file(tmp)
    _atomic_replace(tmp, cred_file)

    return new_creds


# ─── Keychain Write ──────────────────────────────────────


def _keychain_service():
    """Keychain service name for the current CLAUDE_CONFIG_DIR. macOS only.
    Default (no config dir): 'Claude Code-credentials'
    With config dir: 'Claude Code-credentials-{sha256(dir)[:8]}'"""
    config_dir = _config_dir()
    if config_dir:
        normalized = unicodedata.normalize("NFC", config_dir)
        h = hashlib.sha256(normalized.encode()).hexdigest()[:8]
        return f"Claude Code-credentials-{h}"
    return "Claude Code-credentials"


def write_keychain(creds):
    """Write credentials to macOS keychain for THIS terminal's config dir.
    No-op on non-macOS platforms (returns True for success)."""
    if not IS_MACOS:
        return True
    service = _keychain_service()
    username = getpass.getuser()
    json_str = json.dumps(creds)
    hex_value = json_str.encode("utf-8").hex()

    r = subprocess.run(
        [
            "security",
            "add-generic-password",
            "-U",
            "-a",
            username,
            "-s",
            service,
            "-X",
            hex_value,
        ],
        capture_output=True,
        text=True,
        timeout=3,  # Don't hang under keychain contention
    )
    return r.returncode == 0


def write_credentials_file(creds):
    """Atomically write credentials to <CLAUDE_CONFIG_DIR>/.credentials.json.

    This is the file CC v2.1+ reads at startup to load OAuth credentials.
    Returns True on success, False if no CLAUDE_CONFIG_DIR is set or the
    write failed. Failures here are surfaced loudly by swap_to() because
    they mean the next CC restart will load the wrong account.
    """
    config_dir = _config_dir()
    if not config_dir:
        return False
    cred_path = Path(config_dir) / ".credentials.json"
    try:
        tmp = cred_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(creds, indent=2))
        _secure_file(tmp)
        _atomic_replace(tmp, cred_path)
        return True
    except OSError:
        return False


# ─── Swap ────────────────────────────────────────────────


def swap_to(target_account):
    """Swap this terminal to target account — works in-place, no restart.

    Reuses the existing access token if still valid; only refreshes when
    expired. Writes per-config-dir state for THIS terminal so 15+ concurrent
    csq terminals don't contend on a global resource.

    Files written (all under <CLAUDE_CONFIG_DIR>/):
      .credentials.json    OAuth creds — picked up by CC on next interaction
      .csq-account         account number marker (durable across refreshes)
      .current-account     statusline display — written directly to bypass
                           the PID-gated snapshot
    Plus the per-config-dir keychain entry (best-effort; failures non-fatal).

    No restart required — verified empirically that updating .credentials.json
    is picked up by the running CC instance on its next interaction.
    """
    target_account = str(target_account)
    email = get_email(target_account)

    # Write cached credentials directly — NEVER call the refresh endpoint.
    # CC handles its own token refresh on 401 via its built-in retry path.
    # If csq also refreshes, we double the load on the OAuth endpoint and
    # trigger Anthropic's per-client-id throttle, which then blocks BOTH
    # csq AND CC from refreshing — killing all terminals simultaneously.
    #
    # The cached creds in credentials/N.json always have a valid refresh_token
    # (~1 year lifetime). Even if the access_token is expired, CC will exchange
    # the refresh_token for a fresh access_token on its next API call.
    cred_file = CREDS_DIR / f"{target_account}.json"
    if not cred_file.exists():
        print(
            f"No credentials for account {target_account} — run: csq login {target_account}",
            file=sys.stderr,
        )
        return False

    try:
        new_creds = json.loads(cred_file.read_text())
    except (OSError, json.JSONDecodeError):
        print(
            f"Corrupt credentials for account {target_account} — run: csq login {target_account}",
            file=sys.stderr,
        )
        return False

    if not new_creds.get("claudeAiOauth", {}).get("refreshToken"):
        print(
            f"No refresh token for account {target_account} — run: csq login {target_account}",
            file=sys.stderr,
        )
        return False

    oauth = new_creds.get("claudeAiOauth", {})
    expires_at = oauth.get("expiresAt", 0)
    now_ms = int(time.time() * 1000)
    if expires_at > now_ms:
        remaining_min = (expires_at - now_ms) / 60_000
        print(
            f"Swapping to account {target_account} ({email}) — token valid {remaining_min:.0f}m",
            file=sys.stderr,
        )
    else:
        print(
            f"Swapping to account {target_account} ({email}) — token expired, CC will refresh on next use",
            file=sys.stderr,
        )

    config_dir = _config_dir()
    if not config_dir:
        print(
            "  csq swap requires CLAUDE_CONFIG_DIR (run from a csq terminal).",
            file=sys.stderr,
        )
        return False

    # Write .credentials.json — this is the actual swap. If this fails,
    # the swap is a no-op and we report failure.
    if not write_credentials_file(new_creds):
        print(
            f"  Failed to write {config_dir}/.credentials.json — swap aborted.",
            file=sys.stderr,
        )
        return False

    # IMPORTANT: do NOT delete the .quota-cursor on swap. Leaving the OLD
    # cursor in place is exactly what protects against stale-rate-limits
    # corruption: the next statusline render will see "current account
    # changed but the rate_limits payload hash is the same as what the
    # previous account already wrote" and refuse the update. Only an actual
    # API call on the new account produces a different payload, which
    # then writes the cursor for the new account.

    # Best-effort keychain write. CC primarily reads .credentials.json, but
    # may fall back to the keychain for token refresh. We don't block or fail
    # on keychain errors because:
    #   - The `security` command can hang under concurrent load (15 terminals)
    #   - .credentials.json is the source of truth for the next CC startup
    #   - The per-config-dir keychain entry (hash suffix) is already isolated
    # If it succeeds, CC has a fresh fallback. If not, CC still has the file.
    try:
        write_keychain(new_creds)
    except Exception:
        pass

    # Write the .csq-account marker — durable identity record that survives
    # CC's internal token refreshes (which would otherwise change the
    # access_token and break token-based identification).
    if not write_csq_account_marker(target_account):
        print(
            f"  WARNING: failed to write {config_dir}/.csq-account — "
            "snapshot may misidentify the account on next CC restart.",
            file=sys.stderr,
        )

    # Write .current-account directly — bypasses the PID-gated snapshot which
    # would otherwise leave the statusline showing the old account until CC
    # restarts. The new credentials are picked up on the next CC interaction
    # regardless of process lifetime.
    try:
        live_account_file = Path(config_dir) / ".current-account"
        tmp = live_account_file.with_suffix(".tmp")
        tmp.write_text(target_account)
        _secure_file(tmp)
        _atomic_replace(tmp, live_account_file)
    except OSError as e:
        print(
            f"  WARNING: failed to update {config_dir}/.current-account: {e}",
            file=sys.stderr,
        )

    # Verify the swap by reading back what we wrote
    config_dir_p = Path(config_dir)
    try:
        readback = json.loads((config_dir_p / ".credentials.json").read_text())
        rb_rt = readback.get("claudeAiOauth", {}).get("refreshToken", "")[:20]
        expected_rt = new_creds.get("claudeAiOauth", {}).get("refreshToken", "")[:20]
        if rb_rt != expected_rt:
            print(
                f"  DIAG: .credentials.json readback MISMATCH — "
                f"expected {expected_rt}… got {rb_rt}…",
                file=sys.stderr,
            )
    except OSError:
        pass

    print(
        f"Swapped to account {target_account} ({email}) — next API call will use new credentials",
        file=sys.stderr,
    )

    # Delayed verification: catch CC overwriting us within 2 seconds.
    # Runs in background — doesn't block the swap.
    import threading  # noqa: late import — only used here

    def _delayed_verify():
        time.sleep(2)
        try:
            live = json.loads((config_dir_p / ".credentials.json").read_text())
            live_rt = live.get("claudeAiOauth", {}).get("refreshToken", "")[:20]
            expected = new_creds.get("claudeAiOauth", {}).get("refreshToken", "")[:20]
            if live_rt != expected:
                live_acct = live_credentials_account()
                print(
                    f"  DIAG(+2s): .credentials.json OVERWRITTEN — "
                    f"now has acct {live_acct} (rt={live_rt}…), "
                    f"expected acct {target_account} (rt={expected}…). "
                    f"CC likely refreshed the old account's token.",
                    file=sys.stderr,
                )
        except OSError:
            pass

    threading.Thread(target=_delayed_verify, daemon=True).start()
    return True


# ─── Suggest (fallback when no config dir) ───────────────


def suggest():
    """Suggest the best account to switch to. Outputs JSON."""
    current = which_account()
    state = load_state()
    target = pick_best(state, exclude=current)

    if not target:
        show_status()
        print("\nAll accounts exhausted.", file=sys.stderr)
        print(json.dumps({"exhausted": True}))
        return

    email = get_email(target)
    acct = state.get("accounts", {}).get(target, {})
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)

    print(
        json.dumps(
            {
                "account": target,
                "email": email,
                "five_hour_used": five_pct,
                "current": current,
            }
        )
    )


# ─── Auto-Rotate ─────────────────────────────────────────


def auto_rotate(force=False):
    """Auto-rotate this terminal to the best available account.
    Requires CLAUDE_CONFIG_DIR (per-terminal keychain isolation).
    Without it, falls back to suggest."""
    if not _config_dir():
        suggest()
        return

    current = which_account()

    if force and current:
        # Mark current account as exhausted on disk (locked, load raw)
        lock_path = QUOTA_FILE.with_suffix(".lock")
        lock_handle = _lock_file(lock_path)
        if lock_handle is None:
            # Lock acquisition failed (e.g., Windows mutex unavailable).
            # Refuse to write rather than risk a torn quota file.
            print(
                "  WARNING: could not acquire quota lock — skipping force-rotate",
                file=sys.stderr,
            )
        else:
            try:
                raw = _load(QUOTA_FILE, {"accounts": {}})
                raw.setdefault("accounts", {}).setdefault(current, {})["five_hour"] = {
                    "used_percentage": 100,
                    "resets_at": time.time() + 18000,
                }
                _save(QUOTA_FILE, raw)
            finally:
                _unlock_file(lock_handle)

    state = load_state()
    acct = state.get("accounts", {}).get(current or "", {})
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)

    if five_pct >= 100 or force:
        target = pick_best(state, exclude=current)
        if target:
            swap_to(target)
        else:
            show_status()
            print("\nAll accounts exhausted.", file=sys.stderr)


# ─── Quota Update ────────────────────────────────────────


def update_quota(json_str):
    """Called from statusline. Saves quota data for the current account.

    Two corruption vectors this defends against:

    1. After `csq swap`, CC's statusline JSON still contains rate_limits
       from the PREVIOUS account's last API call (CC hasn't made a call
       on the new account yet). Attributing those to the new account
       would corrupt the quota. Defense: payload-hash cursor check against
       the previous accepted update — identical payload under a different
       account is refused.

       Known gap: if an API call happened between the last pre-swap
       render and the swap, the payload hash differs from the cursor's
       and this check lets it through. We accept that narrow race rather
       than blanket-skipping all first-post-swap updates — the latter
       drops legitimate accumulated-agent data when renders are hours
       apart (heavy background agent workflows).

    2. CC can hold an old account's refresh token in memory across a
       swap_to() and overwrite the .credentials.json we just wrote when
       it next refreshes. The marker files (.csq-account, .current-account)
       then record csq's swap INTENT while the live credentials still
       belong to the old account. If we trust the marker, we attribute
       CC's (old-account) rate_limits to the new account. Defense: verify
       the marker against the refresh-token content match and attribute
       rate_limits to the account CC is ACTUALLY running on.
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return

    rate_limits = data.get("rate_limits")
    if not rate_limits:
        return

    # Ground truth: match the live refresh token against canonical creds.
    # The refresh token uniquely identifies the account CC is running and
    # persists across access-token rotation. Fall back to the marker only
    # when no canonical match is found (fresh login not yet captured).
    live_acct = live_credentials_account()
    current = live_acct if live_acct is not None else which_account()
    if not current:
        return

    config_dir = _config_dir()

    # Build a deterministic fingerprint of this rate_limits payload.
    # Two payloads are "the same data" iff their fingerprints match.
    payload_fp = json.dumps(rate_limits, sort_keys=True)
    payload_hash = hashlib.sha256(payload_fp.encode()).hexdigest()[:12]
    cursor_value = f"{current}:{payload_hash}"

    cursor_file = None
    if config_dir:
        cursor_file = Path(config_dir) / ".quota-cursor"
        try:
            if cursor_file.exists():
                prev = cursor_file.read_text().strip()
                prev_acct, _, prev_hash = prev.partition(":")
                if prev_hash == payload_hash and prev_acct != current:
                    # Same exact payload, different account — this is stale
                    # data left over from before the swap. Refuse it.
                    return
                if prev == cursor_value:
                    # Already processed this exact (account, payload) — no-op.
                    return
        except OSError:
            pass

    # Lock, load, modify, save, unlock — prevents concurrent terminal races
    lock_path = QUOTA_FILE.with_suffix(".lock")
    lock_handle = _lock_file(lock_path)
    if lock_handle is None:
        # Lock acquisition failed. Skip the update rather than risk a torn
        # quota file. The next statusline render will retry.
        return
    try:
        state = _load(QUOTA_FILE, {"accounts": {}})
        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        _save(QUOTA_FILE, state)
    finally:
        _unlock_file(lock_handle)

    # Record what we just processed
    if cursor_file is not None:
        try:
            tmp = cursor_file.with_suffix(".tmp")
            tmp.write_text(cursor_value)
            _atomic_replace(tmp, cursor_file)
        except OSError:
            pass

    # NOTE: Auto-rotate from update_quota() is DISABLED.
    # It caused random account switching when triggered on stale rate_limits
    # after a manual swap (CC's statusline JSON contains rate_limits from
    # the PREVIOUS account until the next API call). Users now manually
    # swap with `! csq swap N` when they hit a rate limit. The user is in
    # control; csq does not silently change accounts behind their back.


# ─── Status ──────────────────────────────────────────────


def fmt_time(epoch):
    diff = epoch - time.time()
    if diff <= 0:
        return "now"
    h, m = int(diff // 3600), int((diff % 3600) // 60)
    if h >= 24:
        return f"{h // 24}d{h % 24}h"
    return f"{h}h{m}m" if h > 0 else f"{m}m"


def show_status():
    state = load_state()
    current = which_account()

    if current:
        print(f"Active: account {current} ({get_email(current)})")
    else:
        print("Active: unknown")
    print("=" * 50)

    for n in configured_accounts():
        acct = state.get("accounts", {}).get(n, {})
        email = get_email(n)
        marker = "→" if n == current else " "
        five = acct.get("five_hour", {})
        seven = acct.get("seven_day", {})
        five_pct = five.get("used_percentage", 0)
        seven_pct = seven.get("used_percentage", 0)
        five_reset = five.get("resets_at", 0)
        seven_reset = seven.get("resets_at", 0)

        icon = "●" if five_pct < 80 else ("◐" if five_pct < 100 else "○")
        print(f" {marker} {n}  {icon} {email}")
        if acct:
            r5 = fmt_time(five_reset) if five_reset else "?"
            r7 = fmt_time(seven_reset) if seven_reset else "?"
            print(f"       5h:{five_pct:.0f}% ↻{r5}  7d:{seven_pct:.0f}% ↻{r7}")
    print()


def statusline_str():
    # Display the account number the user INTENDED (marker = csq's swap
    # target). When CC is silently still running on a different account
    # (the stuck-swap case — see update_quota docstring), append a small
    # ⚠ warning flag so the user knows their last swap didn't take effect,
    # without alarming them by flipping the primary label. The quota file
    # itself is protected from corruption by update_quota's content-match
    # routing.
    current = which_account()
    if not current:
        return ""
    live_acct = live_credentials_account()
    stuck = live_acct is not None and live_acct != current
    state = load_state()
    acct = state.get("accounts", {}).get(current, {})
    email = get_email(current)
    user = email.split("@")[0][:10] if email else ""
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
    seven_pct = acct.get("seven_day", {}).get("used_percentage", 0)
    label = f"#{current}⚠:{user}" if stuck else f"#{current}:{user}"
    parts = [label]
    if five_pct > 0 or seven_pct > 0:
        parts.append(f"5h:{five_pct:.0f}%")
        parts.append(f"7d:{seven_pct:.0f}%")
    result = " ".join(parts)

    # Broker-failure warning: when broker_check exhausted both the primary
    # refresh and the live-sibling recovery, it touches credentials/N.broker-failed.
    # Surface a visible, unmissable prefix so the user sees it in their
    # statusline on the very next render — no need to check logs. The flag
    # is cleared automatically on the next successful broker refresh.
    flag_acct = csq_account_marker() or current
    if flag_acct and _broker_failure_flag(flag_acct).exists():
        result = f"⚠LOGIN-NEEDED {result}"

    return result


# ─── Init Keychain ───────────────────────────────────────


def init_keychain(account_num):
    """Write stored creds for account N to this CLAUDE_CONFIG_DIR's keychain entry."""
    cred_file = CREDS_DIR / f"{account_num}.json"
    if not cred_file.exists():
        print(f"No stored credentials for account {account_num}", file=sys.stderr)
        return False
    creds = json.loads(cred_file.read_text())
    if write_keychain(creds):
        print(f"Keychain entry written for account {account_num}", file=sys.stderr)
        return True
    print(f"Failed to write keychain for account {account_num}", file=sys.stderr)
    return False


# ─── Cleanup ─────────────────────────────────────────────


def cleanup():
    """Remove stale .account.* PID cache files."""
    removed = 0
    for f in ACCOUNTS_DIR.glob(".account.*"):
        try:
            pid = int(f.name.split(".")[-1])
            if not _is_pid_alive(pid):
                f.unlink(missing_ok=True)
                removed += 1
        except ValueError:
            try:
                f.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
    remaining = len(list(ACCOUNTS_DIR.glob(".account.*")))
    print(f"Removed {removed} stale cache files. {remaining} remaining.")


# ─── Back-Sync ──────────────────────────────────────────
#
# CC rotates refresh tokens during sessions: old token → new token.
# The new token lives in config-N/.credentials.json. But credentials/N.json
# (the canonical store csq swap reads from) still has the old token.
# If another terminal does `csq swap N`, it writes the revoked token → 401.
#
# Strategy: on every statusline render, look up which canonical credentials/N
# file the LIVE token belongs to (by refresh token match — refresh tokens
# survive access token rotation), and update that canonical file.
#
# CRITICAL: we identify the account by CONTENT MATCH, not by reading any
# marker file. Marker files can be temporarily inconsistent during a swap_to()
# call, leading to cross-account poisoning. Content match is race-proof: if
# the live token matches credentials/N.json's refresh token, then by definition
# this terminal is running account N right now, regardless of what any marker says.


def backsync():
    """Update the canonical credentials/N.json that matches this terminal's
    live tokens. Called from statusline hook (background, on every render).

    Strategy: refresh-token content match first (race-proof when tokens are
    stable). If no match (= Anthropic rotated the refresh token during a
    normal refresh), fall back to the .csq-account marker, which records
    csq's intent for this config dir and is durable across token rotations.

    The marker fallback is critical: without it, a rotated refresh token
    leaves credentials/N.json frozen with the OLD token. The next csq swap
    from another terminal would write that stale token back into
    .credentials.json, overwriting CC's valid rotated token and causing
    a 401 on the next refresh → forced re-login."""
    config_dir = _config_dir()
    if not config_dir:
        return

    live_creds_file = Path(config_dir) / ".credentials.json"
    if not live_creds_file.exists():
        return

    try:
        live_data = json.loads(live_creds_file.read_text())
    except (OSError, json.JSONDecodeError):
        return

    live_oauth = live_data.get("claudeAiOauth", {})
    live_refresh = live_oauth.get("refreshToken", "")
    live_access = live_oauth.get("accessToken", "")
    if not live_refresh or not live_access:
        return  # don't trust empty creds

    # Primary: find which canonical file matches by refresh token. Prefer
    # matching both refresh AND access (exact match → up to date). If only
    # refresh matches, the access token has been rotated → update the canonical
    # IF our live expiresAt is strictly newer (monotonicity / ping-pong guard).
    #
    # Ping-pong scenario: two config dirs running the same account share the
    # same refresh token. When one refreshes its access token, Anthropic
    # invalidates the other's cached AT, which then refreshes to a new AT.
    # Without the expiresAt guard, both terminals would overwrite canonical
    # with their own "latest" on every render. With the guard, only the
    # strictly-newest-refresh winner writes.
    live_expires = live_oauth.get("expiresAt", 0)
    target_canonical = None
    needs_update = False
    for n in configured_accounts():
        canonical = CREDS_DIR / f"{n}.json"
        if not canonical.exists():
            continue
        try:
            canon_data = json.loads(canonical.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        canon_oauth = canon_data.get("claudeAiOauth", {})
        canon_refresh = canon_oauth.get("refreshToken", "")
        if canon_refresh == live_refresh:
            target_canonical = canonical
            canon_access = canon_oauth.get("accessToken", "")
            canon_expires_primary = canon_oauth.get("expiresAt", 0)
            if canon_access != live_access and live_expires > canon_expires_primary:
                needs_update = True
            break

    # Fallback: content match failed. This typically means Anthropic
    # rotated the refresh token during CC's internal token refresh. The
    # .csq-account marker is written by csq run/swap and is the durable
    # intent record for this config dir. Trust it.
    #
    # Safety 1 — swap atomicity: we only land here when the LIVE refresh
    # token matches no canonical. A well-formed csq swap to account M
    # atomically writes credentials/M.json's tokens into .credentials.json,
    # so the content match on M succeeds immediately and this fallback
    # does not run. The only code path that reaches this fallback is CC's
    # own refresh writing back a rotated token.
    #
    # Safety 2 — multi-terminal ping-pong: if two config dirs are running
    # the same account (e.g., config-4 running account 4 natively and
    # config-2 swapped to account 4), they may each hold a DIFFERENT
    # valid refresh token (two OAuth sessions). Without a guard, both
    # would fight to rewrite the canonical on every statusline render.
    # Defense: only overwrite canonical if our live expiresAt is STRICTLY
    # NEWER than what's currently in canonical. Whichever terminal
    # refreshed most recently wins; older terminals leave canonical alone.
    if target_canonical is None:
        marker_acct = csq_account_marker()
        if marker_acct:
            marker_canonical = CREDS_DIR / f"{marker_acct}.json"
            if marker_canonical.exists():
                canon_expires_fb = 0
                try:
                    canon_data_fb = json.loads(marker_canonical.read_text())
                    canon_expires_fb = canon_data_fb.get("claudeAiOauth", {}).get(
                        "expiresAt", 0
                    )
                except (OSError, json.JSONDecodeError):
                    pass
                if live_expires > canon_expires_fb:
                    target_canonical = marker_canonical
                    needs_update = True

    if target_canonical is None or not needs_update:
        return  # no match and no marker (pre-login) or already in sync

    # Acquire a per-canonical lock so concurrent backsyncs from multiple
    # csq terminals (each running a different account) don't race on the
    # same canonical file. Without this, two terminals refreshing tokens
    # for the same account could write half-and-half data.
    lock_path = target_canonical.with_suffix(".lock")
    lock_handle = _lock_file(lock_path)
    if lock_handle is None:
        return  # lock acquisition failed; will retry on next render
    try:
        # Re-read canonical inside the lock to avoid clobbering a write
        # that another process just made. Two conditions abort the write:
        # 1. Canonical's access token already matches ours — in sync.
        # 2. Canonical's expiresAt is >= ours — a concurrent process wrote
        #    a newer (or equal) version; downgrading would lose data.
        try:
            current = json.loads(target_canonical.read_text())
            cur_oauth = current.get("claudeAiOauth", {})
            cur_access = cur_oauth.get("accessToken", "")
            cur_expires = cur_oauth.get("expiresAt", 0)
            if cur_access == live_access or cur_expires >= live_expires:
                return  # in sync, or concurrent process wrote newer → abort
        except (OSError, json.JSONDecodeError):
            pass

        try:
            tmp = target_canonical.with_suffix(".tmp")
            tmp.write_text(json.dumps(live_data, indent=2))
            _secure_file(tmp)
            _atomic_replace(tmp, target_canonical)
        except OSError:
            pass
    finally:
        _unlock_file(lock_handle)


# ─── Broker (Option C: single refresher per account) ────
#
# The broker is csq's solution to the "N concurrent terminals on the same
# OAuth account" problem. csq becomes the SOLE process that calls Anthropic's
# /v1/oauth/token refresh endpoint. Per-account refresh locks prevent two
# terminals from racing on the same refresh, eliminating the rotation-induced
# 401s that plagued multi-terminal use.
#
# How it works:
#   1. Statusline render fires broker_check() for the current config dir
#   2. Broker reads credentials/N.json (the canonical for the marker's account)
#   3. If expiresAt - now < REFRESH_AHEAD_SECS, try-acquire credentials/N.refresh-lock
#   4. If lock acquired: POST to TOKEN_URL with current refresh token
#   5. Write the new tokens to credentials/N.json (canonical)
#   6. Fan out the new tokens to every config-X/.credentials.json where marker=N
#   7. Release the lock
#
# Why this prevents 401s:
#   - All terminals share the same refresh token
#   - Only ONE refresh happens at a time (per-account lock)
#   - Anthropic only sees ONE refresh per cycle, not N
#   - If Anthropic rotates the refresh token in the response, the broker writes
#     the new RT to canonical AND fans it out to all live configs
#   - CC's mtime check picks up the new tokens on its next API call
#   - CC never tries to refresh on its own because the access token is always
#     fresh (broker keeps it ahead of the curve)
#
# What this does NOT prevent:
#   - Anthropic invalidating a token mid-API-call (rare server-side event)
#   - The very first refresh after CC starts, IF the token is already < REFRESH_AHEAD
#     when CC starts and CC makes an API call before the broker fires
#
# These edge cases recover via CC's own 401 retry path, which re-reads
# .credentials.json from disk — and the broker keeps that file fresh.
#
# Residual failure mode: if CC's own refresh path wins a race against the
# broker and rotates Anthropic's refresh token, canonical is left holding
# a dead RT. Subsequent broker_check calls then 401 on the dead RT and
# silently return, leaving canonical stuck. _broker_recover_from_live()
# below handles this by promoting a live sibling's rotated RT into
# canonical and retrying the refresh.

# Refresh window: 2 hours. Broker tries to refresh whenever the token has
# less than this much life remaining. A wide window (vs. a tight 10-min
# window) makes it near-certain that SOME rendering terminal fires the
# broker before expiry, which is what keeps CC's own refresh path from
# racing against us and rotating the RT out from under canonical.
REFRESH_AHEAD_SECS = 7200


def _scan_config_dirs_for_account(account_num):
    """Return all config-N/ paths whose .csq-account marker matches.

    Used by broker fanout to push fresh tokens to every active terminal
    running this account. Skips dirs without a marker or with a different
    account.
    """
    matches = []
    if not ACCOUNTS_DIR.exists():
        return matches
    for d in ACCOUNTS_DIR.iterdir():
        if not d.is_dir():
            continue
        if not d.name.startswith("config-"):
            continue
        marker_file = d / ".csq-account"
        if not marker_file.exists():
            continue
        try:
            marker_val = marker_file.read_text().strip()
        except OSError:
            continue
        if marker_val == str(account_num):
            matches.append(d)
    return matches


def _fan_out_credentials(account_num, new_creds):
    """Write new credentials to every config-N/.credentials.json with marker=N.

    Atomic per-file write. Failures on individual files are logged-and-continue
    so a single permission error doesn't block the others.
    """
    for config_dir_path in _scan_config_dirs_for_account(account_num):
        live_file = config_dir_path / ".credentials.json"
        # Skip if live already has these credentials (avoid touching mtime)
        try:
            existing = json.loads(live_file.read_text())
            existing_at = existing.get("claudeAiOauth", {}).get("accessToken", "")
            new_at = new_creds.get("claudeAiOauth", {}).get("accessToken", "")
            if existing_at == new_at:
                continue
        except (OSError, json.JSONDecodeError):
            pass  # missing or corrupt — write fresh data anyway
        try:
            tmp = live_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(new_creds, indent=2))
            _secure_file(tmp)
            _atomic_replace(tmp, live_file)
        except OSError:
            pass  # tolerate per-file failures, broker will retry next render


def _broker_failure_flag(account_num):
    """Path to the per-account broker-failure flag.

    Touched by broker_check when both the primary refresh and the live-sibling
    recovery fail. Removed on any successful refresh. The statusline
    subcommand surfaces a warning glyph while this flag exists, so a silent
    broker failure can't go unnoticed.
    """
    return CREDS_DIR / f"{account_num}.broker-failed"


def _broker_mark_failed(account_num):
    try:
        _broker_failure_flag(account_num).touch()
    except OSError:
        pass


def _broker_mark_recovered(account_num):
    try:
        _broker_failure_flag(account_num).unlink()
    except (OSError, FileNotFoundError):
        pass


def _broker_recover_from_live(account_num, dead_canonical_content):
    """Revive a dead canonical by trying each live sibling's refresh token.

    Called by broker_check when the primary refresh returns None (Anthropic
    401'd the canonical RT, typically because CC's own refresh path won a
    race and rotated the RT). At least one live config-X/.credentials.json
    should hold the rotated RT, so we promote each candidate into canonical
    in turn and retry the Anthropic refresh.

    MUST be called with the per-account refresh-lock held by the caller.

    Args:
        account_num: the account whose canonical is dead
        dead_canonical_content: the original canonical dict, kept so we can
            roll canonical back if every recovery attempt also fails (so we
            don't leave canonical holding whichever candidate was tried last)

    Returns:
        new_creds dict on success (canonical is freshly updated on disk by
        refresh_token), or None if no live sibling could refresh successfully.
    """
    canonical = CREDS_DIR / f"{account_num}.json"
    dead_rt = dead_canonical_content.get("claudeAiOauth", {}).get("refreshToken", "")
    tried_rts = {dead_rt} if dead_rt else set()

    for d in _scan_config_dirs_for_account(account_num):
        live_file = d / ".credentials.json"
        if not live_file.exists():
            continue
        try:
            live_data = json.loads(live_file.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        live_rt = live_data.get("claudeAiOauth", {}).get("refreshToken", "")
        if not live_rt or live_rt in tried_rts:
            continue  # empty, or we already tried this RT from another dir
        tried_rts.add(live_rt)

        # Promote this live sibling's creds into canonical so refresh_token()
        # picks up the candidate RT. Atomic write keeps canonical consistent
        # even if the process dies mid-recovery.
        try:
            tmp = canonical.with_suffix(".tmp")
            tmp.write_text(json.dumps(live_data, indent=2))
            _secure_file(tmp)
            _atomic_replace(tmp, canonical)
        except OSError:
            continue

        new_creds = refresh_token(account_num, quiet=True)
        if new_creds is not None:
            return new_creds  # canonical now holds Anthropic's fresh response

    # Every candidate failed. Restore the original dead canonical so the
    # next broker_check has a predictable starting point instead of
    # retrying whichever candidate we tried last (which may also be dead
    # or belong to a logically-different OAuth session).
    try:
        tmp = canonical.with_suffix(".tmp")
        tmp.write_text(json.dumps(dead_canonical_content, indent=2))
        _secure_file(tmp)
        _atomic_replace(tmp, canonical)
    except OSError:
        pass

    return None


def broker_check():
    """Check if the current account's token needs refresh, and refresh if so.

    Called from the statusline hook (background) on every render. Uses a
    per-account try-lock so only one terminal refreshes per cycle. The lock
    is non-blocking — if another terminal holds it, this caller skips and
    will retry on the next render.

    The broker is what makes N concurrent terminals on the same account safe:
    only ONE of them will actually call Anthropic's refresh endpoint.

    Returns:
        0 on success, no-op, or skipped (lock contention / token still fresh);
        2 if a refresh was attempted but both the primary and the recovery
        path failed, meaning canonical is genuinely stuck and the user must
        `csq login N` to recover. Exit code is propagated only by the
        `broker` subcommand; the `sync` subcommand (from statusline) ignores
        it because the statusline backgrounds the call.
    """
    config_dir = _config_dir()
    if not config_dir:
        return 0
    marker_acct = csq_account_marker()
    if not marker_acct:
        return 0

    canonical = CREDS_DIR / f"{marker_acct}.json"
    if not canonical.exists():
        return 0

    try:
        canon_data = json.loads(canonical.read_text())
    except (OSError, json.JSONDecodeError):
        return 0

    expires_at = canon_data.get("claudeAiOauth", {}).get("expiresAt", 0)
    refresh_tok = canon_data.get("claudeAiOauth", {}).get("refreshToken", "")
    if not refresh_tok:
        return 0

    now_ms = int(time.time() * 1000)
    seconds_remaining = (expires_at - now_ms) / 1000
    if seconds_remaining > REFRESH_AHEAD_SECS:
        return 0  # token still has plenty of life — no refresh needed

    # Try to acquire the refresh lock. Non-blocking: if another terminal
    # is already refreshing, skip this cycle.
    refresh_lock = canonical.with_suffix(".refresh-lock")
    lock_handle = _try_lock_file(refresh_lock)
    if lock_handle is None:
        return 0  # another terminal is refreshing

    try:
        # Re-read inside the lock to detect a concurrent refresh that
        # finished while we were waiting (shouldn't happen with try-lock,
        # but defensive).
        try:
            canon_data = json.loads(canonical.read_text())
            new_expires = canon_data.get("claudeAiOauth", {}).get("expiresAt", 0)
            new_seconds = (new_expires - now_ms) / 1000
            if new_seconds > REFRESH_AHEAD_SECS:
                return 0  # someone else already refreshed
        except (OSError, json.JSONDecodeError):
            pass

        # Primary: refresh via Anthropic using canonical's current RT.
        # refresh_token() writes the new tokens to canonical on success.
        new_creds = refresh_token(marker_acct, quiet=True)

        # Recovery: canonical's RT is dead (likely rotated by CC's own
        # refresh winning a race). Try each live sibling's RT in turn.
        # Stays under the refresh-lock so nothing else races us.
        if new_creds is None:
            new_creds = _broker_recover_from_live(marker_acct, canon_data)

        if new_creds is None:
            # Both primary and recovery exhausted. Canonical is genuinely
            # stuck — the user must `csq login N`. Touch the failure flag
            # so the statusline surfaces a warning; caller (broker subcommand)
            # returns exit 2 so `csq run` can abort with a clear message.
            _broker_mark_failed(marker_acct)
            return 2

        # Success (primary or recovery). Clear any stale failure flag from
        # a prior broken cycle.
        _broker_mark_recovered(marker_acct)

        # Fan out to every config-X/.credentials.json where marker=N.
        # CC's mtime check picks them up on the next API call without
        # triggering CC's own refresh.
        _fan_out_credentials(marker_acct, new_creds)
        return 0
    finally:
        _unlock_file(lock_handle)


# ─── Pullsync ────────────────────────────────────────────
#
# Inverse of backsync. Pulls fresh credentials FROM the canonical store TO
# this terminal's live .credentials.json when the canonical has a strictly
# newer expiresAt. This is what makes "5 terminals on the same account"
# tolerable: when terminal A's CC refreshes a token, A's backsync writes
# the new credentials to credentials/N.json. Terminal B's next statusline
# render then pulls those credentials into config-B/.credentials.json
# before B's CC tries to refresh — so B never attempts to use a stale
# (just-rotated) refresh token and never 401s.
#
# Safety: only writes when canonical.expiresAt > live.expiresAt (strictly
# newer). Never downgrades. Uses atomic_replace so a partial write cannot
# corrupt CC's view.


def pullsync():
    """Pull fresh credentials from canonical to live when canonical is newer.

    Called from the statusline hook on every render, alongside backsync().
    Combined, the two converge to "newest token wins everywhere":
      - backsync: live → canonical when live is newer
      - pullsync: canonical → live when canonical is newer
    """
    config_dir = _config_dir()
    if not config_dir:
        return

    marker_acct = csq_account_marker()
    if not marker_acct:
        return  # no marker — nothing to pull from

    marker_canonical = CREDS_DIR / f"{marker_acct}.json"
    if not marker_canonical.exists():
        return

    live_creds_file = Path(config_dir) / ".credentials.json"
    if not live_creds_file.exists():
        return

    try:
        canon_data = json.loads(marker_canonical.read_text())
    except (OSError, json.JSONDecodeError):
        return

    canon_oauth = canon_data.get("claudeAiOauth", {})
    canon_refresh = canon_oauth.get("refreshToken", "")
    canon_access = canon_oauth.get("accessToken", "")
    canon_expires = canon_oauth.get("expiresAt", 0)
    if not canon_refresh or not canon_access:
        return  # don't trust empty canonical

    try:
        live_data = json.loads(live_creds_file.read_text())
    except (OSError, json.JSONDecodeError):
        # Live file is corrupt or missing — pulling fresh data is exactly
        # what we want. Fall through to the write.
        live_data = {}

    live_oauth = live_data.get("claudeAiOauth", {})
    live_expires = live_oauth.get("expiresAt", 0)
    live_access = live_oauth.get("accessToken", "")

    # Only pull if canonical is strictly newer. Tied or older → no-op.
    # The strict-newer check prevents oscillation when canonical and live
    # have identical (already-in-sync) data.
    if canon_expires <= live_expires:
        return
    if canon_access == live_access:
        return  # identical access token, no need to write

    try:
        tmp = live_creds_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(canon_data, indent=2))
        _secure_file(tmp)
        _atomic_replace(tmp, live_creds_file)
    except OSError:
        pass


# ─── Main ────────────────────────────────────────────────


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        show_status()
    elif cmd == "update":
        update_quota(sys.stdin.read())
    elif cmd == "swap":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py swap <N>", file=sys.stderr)
            sys.exit(1)
        _validate_account(sys.argv[2])
        if not swap_to(sys.argv[2]):
            sys.exit(1)
    elif cmd == "auto-rotate":
        auto_rotate(force="--force" in sys.argv)
    elif cmd == "suggest":
        suggest()
    elif cmd == "statusline":
        print(statusline_str())
    elif cmd == "check":
        current = which_account()
        state = load_state()
        acct = state.get("accounts", {}).get(current or "", {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        should = five_pct >= 100
        target = pick_best(state, exclude=current) if should else None
        print(
            json.dumps(
                {"should_rotate": should and target is not None, "target": target}
            )
        )
    elif cmd == "init-keychain":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py init-keychain <N>", file=sys.stderr)
            sys.exit(1)
        _validate_account(sys.argv[2])
        if not init_keychain(sys.argv[2]):
            sys.exit(1)
    elif cmd == "snapshot":
        snapshot_account()
    elif cmd == "backsync":
        backsync()
    elif cmd == "pullsync":
        pullsync()
    elif cmd == "broker":
        # Synchronous broker invocation — e.g. from `csq run` before it
        # copies canonical into .credentials.json. Exit code 2 signals that
        # both the primary refresh and the live-sibling recovery failed, so
        # `csq run` can abort with a clear "run csq login N" message instead
        # of letting CC inherit a dead canonical.
        rc = broker_check()
        sys.exit(rc if rc else 0)
    elif cmd == "sync":
        # Full sync cycle for the statusline hook:
        #   1. broker_check: refresh proactively if token < 10 min from expiry
        #      (writes canonical AND fans out to all live configs for this account)
        #   2. backsync: propagate any locally-refreshed tokens to canonical
        #   3. pullsync: pull canonical → live if canonical is newer
        # Combined, these eliminate the multi-terminal-on-same-account 401
        # problem: only one terminal calls Anthropic per refresh cycle, and
        # all other terminals receive the new tokens via fanout or pullsync.
        broker_check()
        backsync()
        pullsync()
    elif cmd == "email":
        if len(sys.argv) >= 3:
            _validate_account(sys.argv[2])
            print(get_email(sys.argv[2]))
    elif cmd == "cleanup":
        cleanup()
    elif cmd == "python-cmd":
        print(_python_cmd())
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
