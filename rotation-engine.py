#!/usr/bin/env python3
"""
Claude Code Account Rotation Engine — Config Dir Model

Each terminal launches with CLAUDE_CONFIG_DIR pointing to a per-account
config directory. Credentials are file-based (no shared keychain).
Mid-session rotation overwrites .credentials.json in the config dir.

State files:
  quota.json           Per-account quota data
  credentials/N.json   Stored OAuth credentials per account (1-7)
  config-N/            Per-account config dir (symlinked settings + own creds)
  profiles.json        Email→account mapping
  blocked.json         Accounts that hit invisible limits (e.g., weekly "all models")
  rotation.log         Audit log (JSONL)

Commands:
  rotation-engine.py status              Show all accounts and quota
  rotation-engine.py setup               Create/update config dirs for all accounts
  rotation-engine.py update              Update quota from statusline (stdin)
  rotation-engine.py swap <N>            Swap THIS terminal to account N (mid-session)
  rotation-engine.py auto-rotate         Check + swap if needed (hook)
  rotation-engine.py auto-rotate --force Mark current blocked, then rotate
  rotation-engine.py extract <N>         Extract current creds as account N
  rotation-engine.py verify              Check credential integrity
  rotation-engine.py refresh             Poll all accounts for quota
  rotation-engine.py statusline          Compact string for statusline display
  rotation-engine.py which               Print which account this terminal is on
"""

import fcntl
import json
import os
import sys
import time
import subprocess
from pathlib import Path

ACCOUNTS_DIR = Path.home() / ".claude" / "accounts"
CREDS_DIR = ACCOUNTS_DIR / "credentials"
CONFIG_DIR_PREFIX = ACCOUNTS_DIR / "config"  # config-1/, config-2/, etc.
QUOTA_FILE = ACCOUNTS_DIR / "quota.json"
PROFILES_FILE = ACCOUNTS_DIR / "profiles.json"
BLOCKED_FILE = ACCOUNTS_DIR / "blocked.json"
LOG_FILE = ACCOUNTS_DIR / "rotation.log"
LOCK_FILE = ACCOUNTS_DIR / ".lock"
KEYCHAIN_SERVICE = "Claude Code-credentials"
MAX_ACCOUNTS = 7
GLOBAL_CLAUDE_DIR = Path.home() / ".claude"
ROTATION_COOLDOWN = 30  # seconds — debounce rapid-fire rotations
LAST_ROTATION_FILE = ACCOUNTS_DIR / ".last_rotation"
SESSION_NAMES_FILE = ACCOUNTS_DIR / "session-names.json"


# ─── Locking ─────────────────────────────────────────────


class Lock:
    def __init__(self):
        ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
        self._fd = None

    def __enter__(self):
        self._fd = open(LOCK_FILE, "w")
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *args):
        if self._fd:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()


# ─── State ───────────────────────────────────────────────


def _load(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save(path, data):
    path.write_text(json.dumps(data, indent=2))


def load_state():
    state = _load(QUOTA_FILE, {"accounts": {}})
    _clean_expired_quotas(state)
    return state


def _clean_expired_quotas(state):
    """Reset used_percentage to 0 for any window whose resets_at has passed.
    This prevents stale high-percentage data from persisting after terminal restart."""
    now = time.time()
    changed = False
    for acct_data in state.get("accounts", {}).values():
        for window in ("five_hour", "seven_day"):
            w = acct_data.get(window, {})
            resets_at = w.get("resets_at", 0)
            if resets_at and resets_at < now and w.get("used_percentage", 0) > 0:
                w["used_percentage"] = 0
                changed = True
    if changed:
        state["last_updated"] = now


def save_state(state):
    _save(QUOTA_FILE, state)


def load_profiles():
    return _load(PROFILES_FILE, {"accounts": {}})


def get_email(n):
    return load_profiles().get("accounts", {}).get(str(n), {}).get("email", "")


def load_blocked():
    """Load blocked accounts. Unblock when EITHER reset window has passed.
    The 7d "all models" limit is the most common block reason, so we check
    both 5h and 7d resets_at timestamps from quota.json (populated by the
    statusline when the account was last active)."""
    data = _load(BLOCKED_FILE, {})
    now = time.time()
    state = load_state()
    active = {}
    for acct, blocked_at in data.items():
        acct_data = state.get("accounts", {}).get(acct, {})
        five_reset = acct_data.get("five_hour", {}).get("resets_at", 0)
        seven_reset = acct_data.get("seven_day", {}).get("resets_at", 0)
        # Unblock if EITHER window has reset — the account may have recovered
        if five_reset and five_reset < now:
            continue
        if seven_reset and seven_reset < now:
            continue
        # Fallback: 8h max (covers one full 5h cycle + buffer)
        if now - blocked_at > 28800:
            continue
        active[acct] = blocked_at
    return active


def mark_blocked(account_num):
    blocked = _load(BLOCKED_FILE, {})
    blocked[str(account_num)] = time.time()
    _save(BLOCKED_FILE, blocked)


def log_rotation(from_acct, to_acct, reason):
    entry = {"time": time.time(), "from": from_acct, "to": to_acct, "reason": reason}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ─── Session Names ───────────────────────────────────────
# ccc-managed name registry. Claude Code cleans up its session files,
# so we keep our own mapping of name → session UUID per project dir.


def save_session_name(name, session_id, project_dir):
    """Store a session name so ccc resume can find it later."""
    with Lock():
        data = _load(SESSION_NAMES_FILE, {})
        data.setdefault(project_dir, {})[name] = {
            "session_id": session_id,
            "saved_at": time.time(),
        }
        _save(SESSION_NAMES_FILE, data)


def find_session_by_name(name, project_dir=None):
    """Look up a session UUID by name. Returns session_id or None."""
    data = _load(SESSION_NAMES_FILE, {})
    if project_dir:
        entry = data.get(project_dir, {}).get(name)
        if entry:
            return entry["session_id"]
    # Search all projects
    for proj_dir, names in data.items():
        entry = names.get(name)
        if entry:
            return entry["session_id"]
    return None


def list_session_names(project_dir=None):
    """List all named sessions, optionally filtered by project dir."""
    data = _load(SESSION_NAMES_FILE, {})
    if project_dir:
        return data.get(project_dir, {})
    return data


# ─── This Terminal ───────────────────────────────────────

CURRENT_ACCOUNT_FILE = ACCOUNTS_DIR / ".current_accounts"


def this_account():
    """Which account is THIS terminal on?
    After mid-session swap, the config dir name no longer matches the account.
    Keyed by CLAUDE_CONFIG_DIR — stable across all subprocesses in a terminal."""
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "")
    if not config_dir:
        return None

    # Check swap tracking first (keyed by config dir path)
    data = _load(CURRENT_ACCOUNT_FILE, {})
    if config_dir in data:
        return data[config_dir]

    # Fallback: derive from config dir name (initial launch, no swap yet)
    name = Path(config_dir).name
    if name.startswith("config-") and name[7:].isdigit():
        return name[7:]
    return None


def set_this_account(account_num):
    """Track which account this terminal is actually on (after swap).
    Keyed by CLAUDE_CONFIG_DIR so statusline, hooks, and CLI all agree."""
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "")
    if not config_dir:
        return
    with Lock():
        data = _load(CURRENT_ACCOUNT_FILE, {})
        data[config_dir] = str(account_num)
        _save(CURRENT_ACCOUNT_FILE, data)


def this_config_dir():
    """Path to this terminal's config dir."""
    return os.environ.get("CLAUDE_CONFIG_DIR", "")


# ─── Config Dir Management ───────────────────────────────


def config_dir_for(n):
    return ACCOUNTS_DIR / f"config-{n}"


def _symlink(target, link_path):
    """Create or replace a symlink."""
    if link_path.is_symlink() or link_path.exists():
        if link_path.is_dir() and not link_path.is_symlink():
            # Real directory — merge contents into global, then replace with symlink
            import shutil

            global_path = GLOBAL_CLAUDE_DIR / link_path.name
            if global_path.exists():
                # Copy any unique files from config dir to global
                for item in link_path.iterdir():
                    dest = global_path / item.name
                    if not dest.exists():
                        if item.is_dir():
                            shutil.copytree(item, dest)
                        else:
                            shutil.copy2(item, dest)
            shutil.rmtree(link_path)
        else:
            link_path.unlink()
    link_path.symlink_to(target)


def setup_config_dirs():
    """Create/update config dirs for all accounts with credentials.
    Shared state (projects, sessions, memory) is symlinked to ~/.claude/
    so all terminals see the same conversation history and memory."""
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        cred_file = CREDS_DIR / f"{n}.json"
        if not cred_file.exists():
            continue
        cdir = config_dir_for(n)
        cdir.mkdir(parents=True, exist_ok=True)

        # Credential file — copy (not symlink) so each dir has its own
        target_cred = cdir / ".credentials.json"
        creds = json.loads(cred_file.read_text())
        target_cred.write_text(json.dumps(creds))
        target_cred.chmod(0o600)

        # Symlink shared state to global ~/.claude/
        # - settings.json: hooks, permissions, statusline config
        # - projects/: conversation history, project memory, CLAUDE.md context
        # - plugins/: installed plugins (pyright-lsp, etc.)
        # - sessions/: session metadata (PID files with names) — shared so
        #   /rename + /resume work across config dirs after terminal restart
        _symlink(GLOBAL_CLAUDE_DIR / "settings.json", cdir / "settings.json")
        _symlink(GLOBAL_CLAUDE_DIR / "projects", cdir / "projects")
        _symlink(GLOBAL_CLAUDE_DIR / "sessions", cdir / "sessions")
        if (GLOBAL_CLAUDE_DIR / "plugins").exists():
            _symlink(GLOBAL_CLAUDE_DIR / "plugins", cdir / "plugins")

        email = get_email(n)
        print(f"  {n}  {email} → {cdir}")

    print("\nConfig dirs ready. Launch terminals with: ccc <N>")


# ─── Keychain (legacy, for extract only) ─────────────────


def read_keychain():
    r = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        return None


# ─── Account Selection ───────────────────────────────────


def pick_best(state, exclude=None):
    """Pick best account to rotate to.
    1. Filter: must have quota (both 5h < 100% and 7d < 100%)
    2. Sort: shortest 7d runway first (exhaust expiring quota before it resets)
    3. Tiebreak: shortest 5h runway (same logic — use what's expiring)
    When all exhausted, pick the one whose window resets soonest."""
    blocked = load_blocked()
    now = time.time()
    available = []
    exhausted = []

    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        if n == str(exclude):
            continue
        if n in blocked:
            continue
        if not (CREDS_DIR / f"{n}.json").exists():
            continue
        acct = state.get("accounts", {}).get(n, {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        seven_pct = acct.get("seven_day", {}).get("used_percentage", 0)
        five_reset = acct.get("five_hour", {}).get("resets_at", 0)
        seven_reset = acct.get("seven_day", {}).get("resets_at", 0)

        # Must have quota on both windows
        if five_pct >= 100:
            exhausted.append((n, five_reset))
            continue
        if seven_pct >= 100:
            exhausted.append((n, seven_reset))
            continue

        available.append((n, five_reset, seven_reset))

    if available:

        def sort_key(item):
            _, five_reset, seven_reset = item
            # Soonest 7d reset first (exhaust expiring quota)
            r7 = seven_reset if seven_reset > 0 else float("inf")
            # Tiebreak: soonest 5h reset
            r5 = five_reset if five_reset > 0 else float("inf")
            return (r7, r5)

        available.sort(key=sort_key)
        return available[0][0]

    # All exhausted — pick the one whose window resets soonest
    if exhausted:
        future = [(n, r) for n, r in exhausted if r > now]
        if future:
            future.sort(key=lambda x: x[1])
            return future[0][0]

    return None


# ─── Swap (Mid-Session) ─────────────────────────────────


def _keychain_service_for(config_dir):
    """Get the keychain service name for a config dir.
    Claude Code uses: Claude Code-credentials-{sha256(dir)[:8]}"""
    import hashlib

    h = hashlib.sha256(config_dir.encode()).hexdigest()[:8]
    return f"Claude Code-credentials-{h}"


def _write_keychain(service, creds_json):
    """Write credentials to macOS keychain."""
    import getpass

    account = getpass.getuser()
    # Delete existing entry first (security add fails if it exists)
    subprocess.run(
        ["security", "delete-generic-password", "-s", service, "-a", account],
        capture_output=True,
    )
    # Add new entry
    r = subprocess.run(
        [
            "security",
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            creds_json,
        ],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def _read_keychain(service):
    """Read credentials from macOS keychain.
    Returns raw JSON string. Handles both hex-encoded (Claude Code native)
    and plain JSON (written by swap_to) formats."""
    r = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-w"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    raw = r.stdout.strip()
    if not raw:
        return None
    # If it starts with '{', it's already JSON
    if raw.startswith("{"):
        return raw
    # Otherwise it's hex-encoded — decode
    try:
        return bytes.fromhex(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return raw


def swap_to(target_account):
    """Swap THIS terminal to a different account.
    Updates both .credentials.json AND the macOS keychain entry
    for this config dir (Claude Code reads from keychain)."""
    target_account = str(target_account)
    source_cred = CREDS_DIR / f"{target_account}.json"
    if not source_cred.exists():
        print(f"error: no credentials for account {target_account}", file=sys.stderr)
        return False

    config_dir = this_config_dir()
    if not config_dir:
        print(
            "error: CLAUDE_CONFIG_DIR not set — launch via 'ccc <N>'", file=sys.stderr
        )
        return False

    service = _keychain_service_for(config_dir)

    with Lock():
        # Write target credentials to keychain (Claude Code reads this)
        target_creds = source_cred.read_text()
        _write_keychain(service, target_creds)

        # Also write .credentials.json (fallback + polling)
        target_path = Path(config_dir) / ".credentials.json"
        target_path.write_text(target_creds)
        target_path.chmod(0o600)

    # Track the actual account this terminal is on
    set_this_account(target_account)

    # Update oauthAccount in .claude.json so Claude Code picks up the new identity
    _update_oauth_account(config_dir, target_creds)

    email = get_email(target_account)
    print(f"Swapped to account {target_account} ({email})")
    return True


def _update_oauth_account(config_dir, creds_json):
    """Update oauthAccount in .claude.json from credential data.
    Claude Code reads this to identify the current account."""
    claude_json_path = Path(config_dir) / ".claude.json"
    if not claude_json_path.exists():
        return
    try:
        creds = json.loads(creds_json) if isinstance(creds_json, str) else creds_json
        oauth = creds.get("claudeAiOauth", {})
        # Get account info via auth status (fast, no API call)
        r = subprocess.run(
            ["claude", "auth", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "CLAUDE_CONFIG_DIR": str(config_dir)},
        )
        if r.returncode == 0:
            status = json.loads(r.stdout)
            claude_data = json.loads(claude_json_path.read_text())
            claude_data["oauthAccount"] = {
                "accountUuid": status.get("orgId", ""),
                "emailAddress": status.get("email", ""),
                "organizationName": status.get("orgName", ""),
                "subscriptionType": status.get("subscriptionType", ""),
            }
            claude_json_path.write_text(json.dumps(claude_data))
    except Exception:
        pass  # Non-critical — swap still works via keychain


def extract_current(account_num):
    """Save current keychain credentials as account N."""
    creds = read_keychain()
    if not creds:
        print("error: no credentials in keychain", file=sys.stderr)
        return False

    CREDS_DIR.mkdir(parents=True, exist_ok=True)
    cred_file = CREDS_DIR / f"{account_num}.json"
    cred_file.write_text(json.dumps(creds, indent=2))
    cred_file.chmod(0o600)

    r = subprocess.run(
        ["claude", "auth", "status", "--json"], capture_output=True, text=True
    )
    email = "unknown"
    if r.returncode == 0:
        try:
            email = json.loads(r.stdout).get("email", "unknown")
        except json.JSONDecodeError:
            pass

    p = load_profiles()
    p.setdefault("accounts", {})[str(account_num)] = {"email": email, "method": "oauth"}
    _save(PROFILES_FILE, p)

    # Reset quota
    with Lock():
        state = load_state()
        state.setdefault("accounts", {})[str(account_num)] = {
            "five_hour": {"used_percentage": 0, "resets_at": 0},
            "seven_day": {"used_percentage": 0, "resets_at": 0},
            "updated_at": time.time(),
        }
        save_state(state)

    # Update config dir
    cdir = config_dir_for(account_num)
    if cdir.exists():
        (cdir / ".credentials.json").write_text(json.dumps(creds))
        (cdir / ".credentials.json").chmod(0o600)

    print(f"Extracted credentials for account {account_num} ({email})")
    return True


# ─── Quota Update ────────────────────────────────────────


def update_quota(json_str):
    """Called from statusline after every response. Updates quota for THIS terminal's account.
    When rate-limited (100%), polls all other accounts and rotates immediately —
    so the NEXT prompt goes through a fresh account without the user noticing."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return

    rate_limits = data.get("rate_limits")
    if not rate_limits:
        return

    current = this_account()
    if not current:
        return

    five_pct = rate_limits.get("five_hour", {}).get("used_percentage", 0)

    with Lock():
        state = load_state()
        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        save_state(state)

    # At 100%: poll all others for fresh data, then rotate
    if five_pct >= 100:
        _poll_and_rotate(current)
    else:
        # Periodic background poll to keep data fresh (every 5min)
        _maybe_poll_others(current)


POLL_INTERVAL = 300  # 5 minutes
POLL_LOCK = ACCOUNTS_DIR / ".poll_lock"
POLL_STAMP = ACCOUNTS_DIR / ".last_poll"


def _maybe_poll_others(current):
    """Poll other accounts in background if last poll was >5min ago."""
    try:
        last = float(POLL_STAMP.read_text().strip())
        if time.time() - last < POLL_INTERVAL:
            return
    except (FileNotFoundError, ValueError):
        pass

    # Non-blocking lock — only one terminal polls
    try:
        fd = open(POLL_LOCK, "w")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        return

    POLL_STAMP.write_text(str(time.time()))
    fcntl.flock(fd, fcntl.LOCK_UN)
    fd.close()

    others = [
        n
        for n in map(str, range(1, MAX_ACCOUNTS + 1))
        if n != current and (CREDS_DIR / f"{n}.json").exists()
    ]
    if not others:
        return

    # Spawn detached background process
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "_poll_others"] + others,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _merge_poll_data(existing, data):
    """Merge poll results into existing account state.
    Poll only gets binary allowed/rejected — not exact percentages.
    Preserve real percentages from statusline; only overwrite with
    100% (rejected) or update resets_at timestamps."""
    if isinstance(data, dict) and (data.get("five_hour") or data.get("seven_day")):
        merged = {"updated_at": time.time()}
        for window in ("five_hour", "seven_day"):
            poll = data.get(window)
            old = existing.get(window, {})
            if poll is None:
                merged[window] = old
            else:
                pct = poll.get("used_percentage")
                merged[window] = {
                    # None = allowed (unknown %) → keep existing; 100 = rejected → overwrite
                    "used_percentage": (
                        old.get("used_percentage", 0) if pct is None else pct
                    ),
                    # resets_at from API is always accurate
                    "resets_at": poll.get("resets_at") or old.get("resets_at", 0),
                }
        return merged
    if isinstance(data, dict) and data.get("rate_limited"):
        return {
            "five_hour": {
                "used_percentage": 100,
                "resets_at": existing.get("five_hour", {}).get("resets_at", 0),
            },
            "seven_day": existing.get("seven_day", {}),
            "updated_at": time.time(),
        }
    if isinstance(data, dict) and data.get("available"):
        # No rate_limit_event at all — account is accessible and not rate-limited.
        # Preserve existing percentages if we have them; default to 0% if no prior data.
        _default = {"used_percentage": 0, "resets_at": 0}
        return {
            "five_hour": existing.get("five_hour") or _default,
            "seven_day": existing.get("seven_day") or _default,
            "updated_at": time.time(),
        }
    return None


def _run_poll_others(accounts):
    """Poll accounts in parallel. Each subprocess sets CLAUDE_CONFIG_DIR +
    CLAUDE_SQUAD_POLL=1, so the statusline fires synchronously and writes
    real percentages to quota.json. After all polls finish, we read quota.json
    (which now has statusline data) and only supplement with rate_limit_event
    data for any gaps."""
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(accounts), 7)) as ex:
        results = dict(ex.map(lambda n: _poll_account(n), accounts))

    # Read state AFTER polls — statusline writes are already in quota.json
    with Lock():
        state = load_state()
        for n, data in results.items():
            if data is None or (isinstance(data, dict) and data.get("expired")):
                continue
            existing = state.get("accounts", {}).get(n, {})
            # Only merge poll data to fill gaps — don't overwrite statusline data
            if isinstance(data, dict) and (
                data.get("five_hour") or data.get("seven_day")
            ):
                acct = state.setdefault("accounts", {}).setdefault(n, {})
                for window in ("five_hour", "seven_day"):
                    poll_window = data.get(window)
                    if poll_window is None:
                        continue
                    existing_window = acct.get(window, {})
                    pct = poll_window.get("used_percentage")
                    # Only fill in if statusline didn't provide a percentage
                    if (
                        existing_window.get("used_percentage") is None
                        and pct is not None
                    ):
                        existing_window["used_percentage"] = pct
                    # Always update resets_at from API (more accurate)
                    poll_reset = poll_window.get("resets_at")
                    if poll_reset:
                        existing_window["resets_at"] = poll_reset
                    acct[window] = existing_window
                acct["updated_at"] = time.time()
            elif isinstance(data, dict) and data.get("rate_limited"):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": {
                        "used_percentage": 100,
                        "resets_at": existing.get("five_hour", {}).get("resets_at", 0),
                    },
                    "seven_day": existing.get("seven_day", {}),
                    "updated_at": time.time(),
                }
            elif isinstance(data, dict) and data.get("available"):
                # Account responded — if statusline wrote data, keep it.
                # If no data at all, mark as available with 0%.
                acct = state.setdefault("accounts", {}).setdefault(n, {})
                _default = {"used_percentage": 0, "resets_at": 0}
                if not acct.get("five_hour"):
                    acct["five_hour"] = _default.copy()
                if not acct.get("seven_day"):
                    acct["seven_day"] = _default.copy()
                acct["updated_at"] = time.time()
        save_state(state)


# ─── Auto-Rotate ───────────────────────────────────────


def _rotation_on_cooldown():
    """Return True if a rotation happened within the last ROTATION_COOLDOWN seconds."""
    try:
        last = float(LAST_ROTATION_FILE.read_text().strip())
        return (time.time() - last) < ROTATION_COOLDOWN
    except (FileNotFoundError, ValueError):
        return False


def _stamp_rotation():
    """Record that a rotation just happened."""
    LAST_ROTATION_FILE.write_text(str(time.time()))


def _poll_and_rotate(current):
    """Poll all other accounts for fresh data, then rotate.
    Called from statusline when current account hits 100%.
    Debounced: skips if a rotation happened in the last 30 seconds."""
    if _rotation_on_cooldown():
        return
    import concurrent.futures

    others = [
        n
        for n in map(str, range(1, MAX_ACCOUNTS + 1))
        if n != current and (CREDS_DIR / f"{n}.json").exists()
    ]
    if not others:
        return

    # Poll all others in parallel for fresh data
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(others), 7)) as ex:
        results = dict(ex.map(lambda n: _poll_account(n), others))
    with Lock():
        state = load_state()
        for n, data in results.items():
            if data is None or (isinstance(data, dict) and data.get("expired")):
                continue
            existing = state.get("accounts", {}).get(n, {})
            merged = _merge_poll_data(existing, data)
            if merged:
                state.setdefault("accounts", {})[n] = merged
        save_state(state)

    # Now pick best with fresh data and rotate
    state = load_state()
    target = pick_best(state, exclude=current)
    if target:
        if swap_to(target):
            _stamp_rotation()
            log_rotation(current, target, "statusline-auto")
            email = get_email(target)
            print(f"[auto-rotate] → account {target} ({email})", file=sys.stderr)


def auto_rotate(force=False):
    """Called from UserPromptSubmit hook (backup) or --force (manual).
    Statusline-triggered rotation is primary (see update_quota).
    This is a backup: if statusline rotation didn't fire, catch it here."""
    current = this_account()
    if not current:
        print("error: CLAUDE_CONFIG_DIR not set", file=sys.stderr)
        return

    if not force and _rotation_on_cooldown():
        return

    if force:
        mark_blocked(current)

    with Lock():
        state = load_state()
        if force:
            state.setdefault("accounts", {}).setdefault(current, {})["five_hour"] = {
                "used_percentage": 100,
                "resets_at": time.time() + 18000,
            }
            save_state(state)

    acct = state.get("accounts", {}).get(current, {})
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)

    if five_pct >= 100 or force:
        # Poll fresh data then rotate
        _poll_and_rotate(current)
        if not force:
            return
        # Force: if _poll_and_rotate didn't find a target, show status
        state = load_state()
        target = pick_best(state, exclude=current)
        if not target:
            show_status()
            print("\nNo accounts available — all blocked or in cooldown.")


# ─── Status ──────────────────────────────────────────────


def fmt_time(epoch):
    diff = epoch - time.time()
    if diff <= 0:
        return "now"
    h, m = int(diff // 3600), int((diff % 3600) // 60)
    if h >= 24:
        return f"{h//24}d{h%24}h"
    return f"{h}h{m}m" if h > 0 else f"{m}m"


def show_status():
    state = load_state()
    current = this_account()
    blocked = load_blocked()

    cur_label = (
        f"account {current} ({get_email(current)})"
        if current
        else "none (not launched via ccc)"
    )
    print(f"Claude Code Rotation — this terminal: {cur_label}")
    print("=" * 55)

    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        if not (CREDS_DIR / f"{n}.json").exists():
            continue
        acct = state.get("accounts", {}).get(n, {})
        email = get_email(n)
        marker = "→" if n == current else " "
        five = acct.get("five_hour", {})
        seven = acct.get("seven_day", {})
        five_pct = five.get("used_percentage", 0)
        seven_pct = seven.get("used_percentage", 0)
        five_reset = five.get("resets_at", 0)
        seven_reset = seven.get("resets_at", 0)
        updated = acct.get("updated_at", 0)
        stale = " (stale)" if updated and time.time() - updated > 300 else ""
        block = " BLOCKED" if n in blocked else ""

        icon = (
            "✗"
            if n in blocked
            else ("●" if five_pct < 80 else "◐" if five_pct < 90 else "◌")
        )

        print(f" {marker} {n}  {icon} {email}{block}")
        if acct:
            r5 = fmt_time(five_reset) if five_reset else "?"
            r7 = fmt_time(seven_reset) if seven_reset else "?"
            print(f"       5h:{five_pct:.0f}% ↻{r5}  7d:{seven_pct:.0f}% ↻{r7}{stale}")
    print()


def statusline_str():
    current = this_account()
    if not current:
        return ""
    state = load_state()
    acct = state.get("accounts", {}).get(current, {})
    email = get_email(current)
    user = email.split("@")[0][:10] if email else ""
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
    seven_pct = acct.get("seven_day", {}).get("used_percentage", 0)
    parts = [f"#{current}:{user}"]
    if five_pct > 0 or seven_pct > 0:
        parts.append(f"5h:{five_pct:.0f}%")
        parts.append(f"7d:{seven_pct:.0f}%")
    return " ".join(parts)


# ─── Verify & Refresh ───────────────────────────────────


def verify_credentials():
    import hashlib

    hashes = {}
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        cf = CREDS_DIR / f"{n}.json"
        if not cf.exists():
            continue
        h = hashlib.md5(cf.read_bytes()).hexdigest()[:12]
        hashes.setdefault(h, []).append(n)

    contaminated = False
    for h, accts in hashes.items():
        if len(accts) > 1:
            contaminated = True
            emails = [get_email(n) for n in accts]
            print(f"  CONTAMINATED: accounts {', '.join(accts)} — {', '.join(emails)}")
    for h, accts in hashes.items():
        if len(accts) == 1:
            print(f"  OK: account {accts[0]} ({get_email(accts[0])})")
    print(f"\n{'Contamination detected!' if contaminated else 'All unique.'}")


def _poll_account(n):
    """Poll a single account via direct Anthropic API call.
    Sends a tiny haiku request and reads rate limit headers —
    gives real utilization percentages for both 5h and 7d windows."""
    cf = CREDS_DIR / f"{n}.json"
    if not cf.exists():
        return n, None
    try:
        import urllib.request
        import urllib.error

        creds = json.loads(cf.read_text())
        token = creds.get("claudeAiOauth", {}).get("accessToken", "")
        if not token:
            return n, None

        body = json.dumps(
            {
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "x"}],
            }
        ).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "x-api-key": token,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            headers = resp.headers
        except urllib.error.HTTPError as e:
            headers = e.headers

        info = {}
        for window, prefix in (
            ("five_hour", "anthropic-ratelimit-unified-5h"),
            ("seven_day", "anthropic-ratelimit-unified-7d"),
        ):
            util = headers.get(f"{prefix}-utilization")
            reset = headers.get(f"{prefix}-reset")
            status = headers.get(f"{prefix}-status")
            pct = None
            if status == "rejected":
                pct = 100
            elif util is not None:
                pct = round(float(util) * 100)
            if pct is not None or reset:
                info[window] = {
                    "used_percentage": pct,
                    "resets_at": int(reset) if reset else 0,
                }

        if info:
            return n, info

        # Check overall status
        overall = headers.get("anthropic-ratelimit-unified-status", "")
        if overall == "rejected":
            return n, {"rate_limited": True}
        return n, {"available": True}
    except Exception:
        return n, None


def refresh_all():
    import concurrent.futures

    accounts = [
        n
        for n in map(str, range(1, MAX_ACCOUNTS + 1))
        if (CREDS_DIR / f"{n}.json").exists()
    ]
    if not accounts:
        print("No accounts.")
        return
    print(f"Polling {len(accounts)} accounts...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
        results = {}
        for future in concurrent.futures.as_completed(
            {ex.submit(_poll_account, n): n for n in accounts}
        ):
            n, data = future.result()
            results[n] = data
            email = get_email(n)
            if data is None:
                print(f"  {n}  ✗ {email} — failed")
            elif data.get("expired"):
                print(f"  {n}  ✗ {email} — expired")
            elif data.get("rate_limited"):
                print(f"  {n}  ◌ {email} — rate limited")
            elif data.get("available"):
                print(f"  {n}  ● {email} — ok")
            else:
                fh = data.get("five_hour")
                status = fh.get("used_percentage") if isinstance(fh, dict) else None
                if status == 100:
                    print(f"  {n}  ◌ {email} — 5h exhausted")
                else:
                    print(f"  {n}  ● {email} — ok")
    with Lock():
        state = load_state()
        for n, data in results.items():
            if data is None or data.get("expired"):
                continue
            existing = state.get("accounts", {}).get(n, {})
            merged = _merge_poll_data(existing, data)
            if merged:
                state.setdefault("accounts", {})[n] = merged
        save_state(state)
    print()
    show_status()


# ─── Main ────────────────────────────────────────────────


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        show_status()
    elif cmd == "setup":
        setup_config_dirs()
    elif cmd == "update":
        update_quota(sys.stdin.read())
    elif cmd == "swap":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py swap <N>", file=sys.stderr)
            sys.exit(1)
        if swap_to(sys.argv[2]):
            log_rotation(this_account(), sys.argv[2], "manual")
        else:
            sys.exit(1)
    elif cmd == "extract":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py extract <N>", file=sys.stderr)
            sys.exit(1)
        if not extract_current(sys.argv[2]):
            sys.exit(1)
    elif cmd == "auto-rotate":
        auto_rotate(force="--force" in sys.argv)
    elif cmd == "check":
        current = this_account()
        with Lock():
            state = load_state()
        if not current:
            print(json.dumps({"should_rotate": False, "reason": "no config dir"}))
            sys.exit(0)
        acct = state.get("accounts", {}).get(current, {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        should = five_pct >= 100
        target = pick_best(state, exclude=current) if should else None
        print(
            json.dumps(
                {
                    "should_rotate": should and target is not None,
                    "target": target,
                    "reason": f"5h:{five_pct:.0f}%",
                }
            )
        )
    elif cmd == "which":
        current = this_account()
        if current:
            print(f"account {current} ({get_email(current)})")
        else:
            print("not launched via ccc (no CLAUDE_CONFIG_DIR)")
    elif cmd == "statusline":
        print(statusline_str())
    elif cmd == "verify":
        verify_credentials()
    elif cmd == "refresh":
        refresh_all()
    elif cmd == "save-name":
        if len(sys.argv) < 4:
            print(
                "usage: rotation-engine.py save-name <name> <session-id> [project-dir]",
                file=sys.stderr,
            )
            sys.exit(1)
        name = sys.argv[2]
        sid = sys.argv[3]
        pdir = sys.argv[4] if len(sys.argv) > 4 else os.getcwd()
        save_session_name(name, sid, pdir)
        print(f"Saved: {name} → {sid}")
    elif cmd == "find-name":
        if len(sys.argv) < 3:
            print(
                "usage: rotation-engine.py find-name <name> [project-dir]",
                file=sys.stderr,
            )
            sys.exit(1)
        name = sys.argv[2]
        pdir = sys.argv[3] if len(sys.argv) > 3 else os.getcwd()
        sid = find_session_by_name(name, pdir)
        if sid:
            print(sid)
        else:
            print(f"No session named '{name}' found", file=sys.stderr)
            sys.exit(1)
    elif cmd == "list-names":
        pdir = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
        names = list_session_names(pdir)
        if isinstance(names, dict) and any(
            isinstance(v, dict) and "session_id" in v for v in names.values()
        ):
            # Single project
            for n, entry in names.items():
                print(f"  {n} → {entry['session_id']}")
        elif names:
            for pd, nd in names.items():
                if isinstance(nd, dict):
                    for n, entry in nd.items():
                        if isinstance(entry, dict):
                            print(f"  {n} → {entry['session_id']}  ({pd})")
        else:
            print("No named sessions")
    elif cmd == "_poll_others":
        _run_poll_others(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
