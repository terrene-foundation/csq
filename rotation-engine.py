#!/usr/bin/env python3
"""
Claude Code Account Rotation Engine — Multi-Terminal Edition

15 terminals share 7 accounts. Each terminal "claims" an account.
The statusline (called every few seconds) drives quota updates AND
triggers auto-rotation when rate limits hit.

State files:
  quota-state.json     Per-account quota (shared, all terminals write)
  assignments.json     Which PID owns which account (terminal→account map)
  credentials/N.json   Stored OAuth credentials per account
  profiles.json        Email→account mapping
  rotation-history.jsonl  Audit log

Commands:
  rotation-engine.py status              Show all accounts, assignments, priority
  rotation-engine.py check               Check if rotation needed (JSON output)
  rotation-engine.py claim [--pid PID]   Claim best available account for this terminal
  rotation-engine.py release [--pid PID] Release account assignment
  rotation-engine.py swap <N>            Force swap keychain to account N
  rotation-engine.py update <json>       Update quota from statusline + auto-rotate if needed
  rotation-engine.py extract <N>         Extract current keychain creds to account N
  rotation-engine.py statusline          Compact quota string for statusline
  rotation-engine.py auto-rotate         Check + swap if needed (for hooks)
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
QUOTA_FILE = ACCOUNTS_DIR / "quota-state.json"
ASSIGNMENTS_FILE = ACCOUNTS_DIR / "assignments.json"
PROFILES_FILE = ACCOUNTS_DIR / "profiles.json"
CURRENT_FILE = ACCOUNTS_DIR / ".current"
HISTORY_FILE = ACCOUNTS_DIR / "rotation-history.jsonl"
LOCK_FILE = ACCOUNTS_DIR / ".lock"
KEYCHAIN_SERVICE = "Claude Code-credentials"
MAX_ACCOUNTS = 7


# ─── File Locking ─────────────────────────────────────────

class StateLock:
    """flock-based lock for multi-terminal coordination."""
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


# ─── State Management ─────────────────────────────────────

def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2))


def load_quota_state():
    return load_json(QUOTA_FILE, {"accounts": {}})


def save_quota_state(state):
    state["last_updated"] = time.time()
    save_json(QUOTA_FILE, state)


def load_assignments():
    return load_json(ASSIGNMENTS_FILE, {"terminals": {}})


def save_assignments(assignments):
    save_json(ASSIGNMENTS_FILE, assignments)


def load_profiles():
    return load_json(PROFILES_FILE, {"accounts": {}})


def get_my_pid():
    """Get the Claude Code parent PID (the terminal session)."""
    # Walk up to find the claude process PID
    # Use PPID if we're called from a hook/statusline (child of claude)
    ppid = os.getppid()
    return str(ppid)


def is_pid_alive(pid):
    """Check if a process is still running."""
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


def cleanup_dead_terminals(assignments):
    """Remove assignments for terminals that no longer exist."""
    dead = []
    for pid, info in assignments.get("terminals", {}).items():
        if not is_pid_alive(pid):
            dead.append(pid)
    for pid in dead:
        del assignments["terminals"][pid]
    return len(dead) > 0


def get_account_for_pid(assignments, pid):
    """Get which account a terminal PID is using."""
    info = assignments.get("terminals", {}).get(pid, {})
    return info.get("account")


def get_pids_for_account(assignments, account):
    """Get all terminal PIDs using a given account."""
    pids = []
    for pid, info in assignments.get("terminals", {}).items():
        if info.get("account") == str(account):
            pids.append(pid)
    return pids


def count_account_users(assignments, account):
    """How many live terminals are using this account."""
    return len(get_pids_for_account(assignments, account))


def log_rotation(from_acct, to_acct, reason, pid=None):
    entry = {
        "time": time.time(),
        "pid": pid or get_my_pid(),
        "from": from_acct,
        "to": to_acct,
        "reason": reason,
    }
    with open(HISTORY_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ─── Priority Algorithm ───────────────────────────────────

def calculate_priority(acct_data):
    """
    Higher score = should be used first.
    Use-it-or-lose-it: drain accounts whose weekly quota expires soonest.
    """
    now = time.time()
    weekly = acct_data.get("seven_day", {})
    hourly = acct_data.get("five_hour", {})

    weekly_used = weekly.get("used_percentage", 0)
    weekly_reset = weekly.get("resets_at", 0)
    hourly_used = hourly.get("used_percentage", 0)
    hourly_reset = hourly.get("resets_at", 0)

    if weekly_used >= 95:
        return -1000  # Dead

    hours_until_weekly = max(0, (weekly_reset - now) / 3600)
    urgency = max(0, 1000 - (hours_until_weekly * 6))
    remaining = 100 - weekly_used

    if hourly_used >= 90 and hourly_reset > now:
        return -(urgency + remaining)  # Negative = cooling

    return urgency + remaining


def is_available(acct_data):
    """Account's 5hr window is not in cooldown."""
    now = time.time()
    hourly = acct_data.get("five_hour", {})
    if hourly.get("used_percentage", 0) >= 90:
        return hourly.get("resets_at", 0) <= now
    return True


def is_weekly_exhausted(acct_data):
    return acct_data.get("seven_day", {}).get("used_percentage", 0) >= 95


def format_time_until(epoch):
    now = time.time()
    diff = epoch - now
    if diff <= 0:
        return "now"
    hours = int(diff // 3600)
    minutes = int((diff % 3600) // 60)
    if hours >= 24:
        return f"{hours // 24}d{hours % 24}h"
    if hours > 0:
        return f"{hours}h{minutes}m"
    return f"{minutes}m"


def pick_best_account(state, assignments, exclude=None):
    """
    Pick the best account considering:
    1. Priority (use-it-or-lose-it)
    2. Availability (not in 5hr cooldown)
    3. Load balancing (prefer accounts with fewer terminals)
    """
    candidates = []
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        if n == exclude:
            continue
        if not (CREDS_DIR / f"{n}.json").exists():
            continue

        acct_data = state.get("accounts", {}).get(n, {})

        # Skip if weekly exhausted (with data)
        if acct_data and is_weekly_exhausted(acct_data):
            continue
        # Skip if 5hr cooling (with data)
        if acct_data and not is_available(acct_data):
            continue

        priority = calculate_priority(acct_data) if acct_data else 500  # Unknown = mid priority
        terminal_count = count_account_users(assignments, n)

        # Penalize accounts with many terminals already on them
        adjusted_priority = priority - (terminal_count * 100)

        candidates.append((n, adjusted_priority, terminal_count))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


# ─── Rotation Decision ────────────────────────────────────

def check_rotation_for_pid(state, assignments, pid):
    """
    Check if a specific terminal should rotate.
    Returns: (should_rotate, target, reason)
    """
    current = get_account_for_pid(assignments, pid)
    if not current:
        return False, None, "no assignment"

    current_data = state.get("accounts", {}).get(current, {})
    if not current_data:
        return False, None, ""

    current_priority = calculate_priority(current_data)

    # Trigger 1: 5hr exhausted
    if not is_available(current_data) and not is_weekly_exhausted(current_data):
        target = pick_best_account(state, assignments, exclude=current)
        if target:
            return True, target, "5hr limit hit"
        return False, None, "5hr limit but no alternatives"

    # Trigger 2: Weekly exhausted
    if is_weekly_exhausted(current_data):
        target = pick_best_account(state, assignments, exclude=current)
        if target:
            return True, target, "weekly quota exhausted"
        return False, None, "weekly exhausted, no alternatives"

    # Trigger 3: Higher-priority account became available
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        if n == current:
            continue
        acct_data = state.get("accounts", {}).get(n, {})
        if not acct_data or not is_available(acct_data) or is_weekly_exhausted(acct_data):
            continue

        other_priority = calculate_priority(acct_data)
        terminal_count = count_account_users(assignments, n)
        # Only rotate back if significantly better AND not overloaded
        if other_priority > current_priority + 150 and terminal_count < 3:
            return True, n, f"account {n} higher priority (weekly resets sooner)"

    return False, None, ""


# ─── Credential Operations ────────────────────────────────

def read_keychain():
    result = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return None


def write_keychain(creds):
    creds_json = json.dumps(creds)
    result = subprocess.run(
        ["security", "add-generic-password", "-U",
         "-a", os.environ.get("USER", "esperie"),
         "-s", KEYCHAIN_SERVICE,
         "-w", creds_json],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"error: keychain write failed: {result.stderr}", file=sys.stderr)
        return False

    # Update .credentials.json so Claude Code picks up the new credentials
    creds_file = Path.home() / ".claude" / ".credentials.json"
    creds_file.touch()
    return True


def extract_current(account_num):
    creds = read_keychain()
    if not creds:
        print("error: no credentials in keychain", file=sys.stderr)
        return False

    CREDS_DIR.mkdir(parents=True, exist_ok=True)
    cred_file = CREDS_DIR / f"{account_num}.json"
    cred_file.write_text(json.dumps(creds, indent=2))
    cred_file.chmod(0o600)

    result = subprocess.run(
        ["claude", "auth", "status", "--json"],
        capture_output=True, text=True
    )
    email = "unknown"
    if result.returncode == 0:
        try:
            email = json.loads(result.stdout).get("email", "unknown")
        except json.JSONDecodeError:
            pass

    profiles = load_profiles()
    profiles.setdefault("accounts", {})[str(account_num)] = {
        "email": email, "method": "oauth",
    }
    save_json(PROFILES_FILE, profiles)
    print(f"Extracted credentials for account {account_num} ({email})")
    return True


def swap_to(account_num, pid=None, save_current=True):
    """Swap keychain to account N. Updates assignment for PID."""
    cred_file = CREDS_DIR / f"{account_num}.json"
    if not cred_file.exists():
        print(f"error: no credentials for account {account_num}", file=sys.stderr)
        return False

    # Save current credentials before overwriting
    if save_current:
        current = get_account_for_pid(load_assignments(), pid or get_my_pid())
        if current and (CREDS_DIR / f"{current}.json").exists():
            current_creds = read_keychain()
            if current_creds:
                cf = CREDS_DIR / f"{current}.json"
                cf.write_text(json.dumps(current_creds, indent=2))
                cf.chmod(0o600)

    creds = json.loads(cred_file.read_text())
    if not write_keychain(creds):
        return False

    # Update assignment
    pid = pid or get_my_pid()
    assignments = load_assignments()
    assignments.setdefault("terminals", {})[pid] = {
        "account": str(account_num),
        "assigned_at": time.time(),
    }
    save_assignments(assignments)

    profiles = load_profiles()
    email = profiles.get("accounts", {}).get(str(account_num), {}).get("email", "unknown")
    print(f"Swapped to account {account_num} ({email})")
    return True


# ─── Claim / Release ──────────────────────────────────────

def claim_account(pid=None):
    """Claim the best available account for a terminal."""
    pid = pid or get_my_pid()

    with StateLock():
        state = load_quota_state()
        assignments = load_assignments()
        cleanup_dead_terminals(assignments)

        # Already assigned?
        existing = get_account_for_pid(assignments, pid)
        if existing:
            profiles = load_profiles()
            email = profiles.get("accounts", {}).get(existing, {}).get("email", "?")
            print(f"Already on account {existing} ({email})")
            return existing

        target = pick_best_account(state, assignments)
        if not target:
            print("error: no accounts available", file=sys.stderr)
            return None

        assignments.setdefault("terminals", {})[pid] = {
            "account": target,
            "assigned_at": time.time(),
        }
        save_assignments(assignments)

    # Swap keychain (outside lock — keychain has its own locking)
    if swap_to(target, pid=pid, save_current=False):
        log_rotation(None, target, "initial claim", pid)
        return target
    return None


def release_account(pid=None):
    """Release a terminal's account assignment."""
    pid = pid or get_my_pid()
    with StateLock():
        assignments = load_assignments()
        account = get_account_for_pid(assignments, pid)
        if pid in assignments.get("terminals", {}):
            del assignments["terminals"][pid]
            save_assignments(assignments)
            print(f"Released account {account}")
        else:
            print("No assignment to release")


# ─── Quota Update + Auto-Rotate ───────────────────────────

def update_and_maybe_rotate(json_str, pid=None):
    """
    Called from statusline every few seconds.
    1. Updates quota state for current account
    2. Checks if rotation needed
    3. Auto-swaps if needed
    """
    pid = pid or get_my_pid()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return

    rate_limits = data.get("rate_limits")
    if not rate_limits:
        return

    with StateLock():
        state = load_quota_state()
        assignments = load_assignments()
        cleanup_dead_terminals(assignments)

        # Determine which account this terminal is on
        current = get_account_for_pid(assignments, pid)

        if not current:
            # Auto-claim on first statusline call
            target = pick_best_account(state, assignments)
            if target:
                assignments.setdefault("terminals", {})[pid] = {
                    "account": target,
                    "assigned_at": time.time(),
                }
                current = target
                save_assignments(assignments)
            else:
                return

        # Update quota for this account
        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        save_quota_state(state)

        # Check if THIS terminal should rotate
        should, target, reason = check_rotation_for_pid(state, assignments, pid)

    # Swap outside the lock
    if should and target:
        with StateLock():
            # Re-check assignments under lock (another terminal may have claimed it)
            assignments = load_assignments()
            cleanup_dead_terminals(assignments)
            # Update our assignment
            assignments.setdefault("terminals", {})[pid] = {
                "account": target,
                "assigned_at": time.time(),
            }
            save_assignments(assignments)

        if swap_to(target, pid=pid):
            log_rotation(current, target, reason, pid)
            # Output goes to stderr so statusline still works
            print(f"[auto-rotate] → account {target} ({reason})", file=sys.stderr)


# ─── Status Display ────────────────────────────────────────

def show_status():
    state = load_quota_state()
    profiles = load_profiles()
    assignments = load_assignments()
    cleanup_dead_terminals(assignments)

    print("Claude Code Account Rotation")
    print("=" * 55)

    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        acct_data = state.get("accounts", {}).get(n, {})
        profile = profiles.get("accounts", {}).get(n, {})
        email = profile.get("email", "")
        has_creds = (CREDS_DIR / f"{n}.json").exists()

        if not email and not has_creds:
            continue

        terminals = get_pids_for_account(assignments, n)
        terminal_str = f" [{len(terminals)} terminal{'s' if len(terminals)!=1 else ''}]" if terminals else ""

        if not has_creds:
            print(f"   {n}  {email} (no credentials)")
            continue

        if not acct_data:
            print(f"   {n}  {email} (no quota data){terminal_str}")
            continue

        five = acct_data.get("five_hour", {})
        seven = acct_data.get("seven_day", {})
        five_pct = five.get("used_percentage", 0)
        five_reset = five.get("resets_at", 0)
        seven_pct = seven.get("used_percentage", 0)
        seven_reset = seven.get("resets_at", 0)

        icon = "●"
        if is_weekly_exhausted(acct_data):
            icon = "✗"
        elif not is_available(acct_data):
            icon = "◌"
        elif five_pct > 80:
            icon = "◐"

        stale = ""
        updated = acct_data.get("updated_at", 0)
        if updated and time.time() - updated > 300:
            stale = " (stale)"

        reset_7d = format_time_until(seven_reset) if seven_reset else "?"
        reset_5h = format_time_until(five_reset) if five_reset else "?"
        pri = calculate_priority(acct_data)

        print(f"   {n}  {icon} {email}{terminal_str}")
        print(f"       5h:{five_pct:.0f}% ↻{reset_5h}  "
              f"7d:{seven_pct:.0f}% ↻{reset_7d}  "
              f"pri:{pri:.0f}{stale}")

    print()


def statusline_quota(pid=None):
    """Compact string for statusline."""
    pid = pid or get_my_pid()
    assignments = load_assignments()
    current = get_account_for_pid(assignments, pid)

    if not current:
        # Fallback: read .current file
        try:
            current = Path(CURRENT_FILE).read_text().strip()
        except FileNotFoundError:
            return ""

    state = load_quota_state()
    acct = state.get("accounts", {}).get(current, {})
    if not acct:
        profiles = load_profiles()
        email = profiles.get("accounts", {}).get(current, {}).get("email", "")
        user = email.split("@")[0] if email else ""
        return f"#{current}:{user}" if user else f"#{current}"

    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
    seven_pct = acct.get("seven_day", {}).get("used_percentage", 0)
    seven_reset = acct.get("seven_day", {}).get("resets_at", 0)

    profiles = load_profiles()
    email = profiles.get("accounts", {}).get(current, {}).get("email", "")
    user = email.split("@")[0][:10] if email else ""

    parts = [f"#{current}:{user}"]
    if five_pct > 0:
        parts.append(f"5h:{five_pct:.0f}%")
    if seven_pct > 0:
        parts.append(f"7d:{seven_pct:.0f}%")
    if seven_reset:
        parts.append(f"↻{format_time_until(seven_reset)}")

    return " ".join(parts)


# ─── Main ─────────────────────────────────────────────────

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        show_status()

    elif cmd == "check":
        pid = get_my_pid()
        state = load_quota_state()
        assignments = load_assignments()
        should, target, reason = check_rotation_for_pid(state, assignments, pid)
        result = {"should_rotate": should, "target": target, "reason": reason}
        if should:
            profiles = load_profiles()
            result["target_email"] = profiles.get("accounts", {}).get(target, {}).get("email", "")
        print(json.dumps(result))

    elif cmd == "claim":
        pid = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "--pid" else None
        if "--pid" in sys.argv:
            idx = sys.argv.index("--pid")
            pid = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        claim_account(pid)

    elif cmd == "release":
        pid = None
        if "--pid" in sys.argv:
            idx = sys.argv.index("--pid")
            pid = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        release_account(pid)

    elif cmd == "swap":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py swap <N>", file=sys.stderr)
            sys.exit(1)
        if swap_to(sys.argv[2]):
            log_rotation(None, sys.argv[2], "manual")
        else:
            sys.exit(1)

    elif cmd == "extract":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py extract <N>", file=sys.stderr)
            sys.exit(1)
        if not extract_current(sys.argv[2]):
            sys.exit(1)

    elif cmd == "update":
        json_str = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
        update_and_maybe_rotate(json_str)

    elif cmd == "statusline":
        print(statusline_quota())

    elif cmd == "auto-rotate":
        pid = get_my_pid()
        state = load_quota_state()
        assignments = load_assignments()
        should, target, reason = check_rotation_for_pid(state, assignments, pid)
        if should and target:
            with StateLock():
                assignments = load_assignments()
                cleanup_dead_terminals(assignments)
                assignments.setdefault("terminals", {})[pid] = {
                    "account": target,
                    "assigned_at": time.time(),
                }
                save_assignments(assignments)
            if swap_to(target, pid=pid):
                log_rotation(get_account_for_pid(load_assignments(), pid), target, reason, pid)
                profiles = load_profiles()
                email = profiles.get("accounts", {}).get(target, {}).get("email", "")
                print(f"[auto-rotate] → account {target} ({email}) — {reason}")
            else:
                sys.exit(1)

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
