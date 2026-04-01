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
TOKENS_DIR = ACCOUNTS_DIR / "tokens"
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
    return load_json(ASSIGNMENTS_FILE, {"sessions": {}})


def save_assignments(assignments):
    save_json(ASSIGNMENTS_FILE, assignments)


def load_profiles():
    return load_json(PROFILES_FILE, {"accounts": {}})


SESSION_ID_FILE = ACCOUNTS_DIR / ".session_id"


def _get_ppid_flag():
    """Extract --ppid <value> from sys.argv if present."""
    if "--ppid" in sys.argv:
        idx = sys.argv.index("--ppid")
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return None


def get_session_id(claude_pid=None):
    """Get current session ID. Passed via env, per-terminal file, or shared file.

    claude_pid: The Claude Code process PID (PPID of the calling script).
    Used to disambiguate sessions in multi-terminal setups.
    """
    sid = os.environ.get("CLAUDE_SQUAD_SESSION")
    if sid:
        return sid
    # Per-terminal file (keyed by Claude Code process PID)
    if claude_pid:
        try:
            return (ACCOUNTS_DIR / f".session_id.{claude_pid}").read_text().strip()
        except FileNotFoundError:
            pass
    # Fallback: shared file (last statusline call)
    try:
        return SESSION_ID_FILE.read_text().strip()
    except FileNotFoundError:
        return None


def set_session_id(sid, claude_pid=None):
    """Cache session ID for non-statusline callers (hooks)."""
    if claude_pid:
        (ACCOUNTS_DIR / f".session_id.{claude_pid}").write_text(sid)
    # Always write shared file for backward compatibility
    SESSION_ID_FILE.write_text(sid)


def cleanup_stale_sessions(assignments):
    """Remove sessions older than 24 hours (likely dead)."""
    now = time.time()
    stale = []
    for sid, info in assignments.get("sessions", {}).items():
        age = now - info.get("assigned_at", 0)
        if age > 86400:  # 24 hours
            stale.append(sid)
    for sid in stale:
        del assignments["sessions"][sid]
    return len(stale) > 0


def get_account_for_session(assignments, session_id):
    """Get which account a session is using."""
    info = assignments.get("sessions", {}).get(session_id, {})
    return info.get("account")


def get_sessions_for_account(assignments, account):
    """Get all session IDs using a given account."""
    return [
        sid for sid, info in assignments.get("sessions", {}).items()
        if info.get("account") == str(account)
    ]


def count_account_users(assignments, account):
    """How many sessions are using this account."""
    return len(get_sessions_for_account(assignments, account))


def log_rotation(from_acct, to_acct, reason, pid=None):
    entry = {
        "time": time.time(),
        "pid": pid or get_session_id(),
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

def check_rotation_for_session(state, assignments, session_id):
    """
    Check if a specific session should rotate.
    Returns: (should_rotate, target, reason)
    """
    current = get_account_for_session(assignments, session_id)
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

    # Touch .credentials.json to trigger Claude Code cache invalidation
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


def swap_to(account_num, session_id=None):
    """Swap keychain to account N. Updates assignment for session."""
    cred_file = CREDS_DIR / f"{account_num}.json"
    if not cred_file.exists():
        print(f"error: no credentials for account {account_num}", file=sys.stderr)
        return False

    # Save current keychain credentials back to the CORRECT file.
    # Identify by matching refresh tokens, NOT session assignment — prevents cross-contamination.
    current_creds = read_keychain()
    if current_creds:
        kc_refresh = current_creds.get("claudeAiOauth", {}).get("refreshToken", "")
        if kc_refresh:
            for n in map(str, range(1, MAX_ACCOUNTS + 1)):
                if n == str(account_num):
                    continue  # Don't overwrite target before loading it
                cf = CREDS_DIR / f"{n}.json"
                if not cf.exists():
                    continue
                try:
                    stored = json.loads(cf.read_text())
                    stored_refresh = stored.get("claudeAiOauth", {}).get("refreshToken", "")
                    if stored_refresh == kc_refresh:
                        cf.write_text(json.dumps(current_creds, indent=2))
                        cf.chmod(0o600)
                        break
                except (json.JSONDecodeError, OSError):
                    continue

    creds = json.loads(cred_file.read_text())
    if not write_keychain(creds):
        return False

    # Update assignment if we have a session
    sid = session_id or get_session_id()
    if sid:
        assignments = load_assignments()
        assignments.setdefault("sessions", {})[sid] = {
            "account": str(account_num),
            "assigned_at": time.time(),
        }
        save_assignments(assignments)

    # Also update .current for non-session callers (ccc swap)
    CURRENT_FILE.write_text(str(account_num))

    profiles = load_profiles()
    email = profiles.get("accounts", {}).get(str(account_num), {}).get("email", "unknown")
    print(f"Swapped to account {account_num} ({email})")
    return True


# ─── Claim / Release ──────────────────────────────────────

def claim_account(pid=None):
    """Claim the best available account for a terminal."""
    pid = pid or get_session_id()

    with StateLock():
        state = load_quota_state()
        assignments = load_assignments()
        cleanup_stale_sessions(assignments)

        # Already assigned?
        existing = get_account_for_session(assignments, pid)
        if existing:
            profiles = load_profiles()
            email = profiles.get("accounts", {}).get(existing, {}).get("email", "?")
            print(f"Already on account {existing} ({email})")
            return existing

        target = pick_best_account(state, assignments)
        if not target:
            print("error: no accounts available", file=sys.stderr)
            return None

        assignments.setdefault("sessions", {})[pid] = {
            "account": target,
            "assigned_at": time.time(),
        }
        save_assignments(assignments)

    # Swap keychain (outside lock — keychain has its own locking)
    if swap_to(target, session_id=pid):
        log_rotation(None, target, "initial claim", pid)
        return target
    return None


def release_account(pid=None):
    """Release a terminal's account assignment."""
    pid = pid or get_session_id()
    with StateLock():
        assignments = load_assignments()
        account = get_account_for_session(assignments, pid)
        if pid in assignments.get("sessions", {}):
            del assignments["sessions"][pid]
            save_assignments(assignments)
            print(f"Released account {account}")
        else:
            print("No assignment to release")


# ─── Quota Update + Auto-Rotate ───────────────────────────

def update_and_maybe_rotate(json_str, claude_pid=None):
    """
    Called from statusline every few seconds.
    1. Extracts session_id from the statusline JSON
    2. Updates quota state for current account
    3. Checks if rotation needed
    4. Auto-swaps if needed
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return

    rate_limits = data.get("rate_limits")
    if not rate_limits:
        return

    # Extract session_id from statusline input — this is stable per Claude Code session
    sid = data.get("session_id")
    if not sid:
        return

    # Cache session_id for hooks (which don't get the JSON input)
    set_session_id(sid, claude_pid=claude_pid)

    with StateLock():
        state = load_quota_state()
        assignments = load_assignments()
        cleanup_stale_sessions(assignments)

        # Determine which account this session is on
        current = get_account_for_session(assignments, sid)

        if not current:
            # Auto-claim on first statusline call
            target = pick_best_account(state, assignments)
            if target:
                assignments.setdefault("sessions", {})[sid] = {
                    "account": target,
                    "assigned_at": time.time(),
                }
                current = target
                save_assignments(assignments)
            else:
                return

        # Update quota ONLY for this session's account
        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        save_quota_state(state)

    # Keep stored credentials fresh — match by refresh token to prevent cross-contamination.
    # Unlike the old email-based check (which called `claude auth status` subprocess and was
    # racey in multi-terminal setups), token matching is atomic and subprocess-free.
    cred_file = CREDS_DIR / f"{current}.json"
    if cred_file.exists():
        try:
            current_creds = read_keychain()
            if current_creds:
                kc_refresh = current_creds.get("claudeAiOauth", {}).get("refreshToken", "")
                stored = json.loads(cred_file.read_text())
                stored_refresh = stored.get("claudeAiOauth", {}).get("refreshToken", "")
                if kc_refresh and stored_refresh and kc_refresh == stored_refresh:
                    cred_file.write_text(json.dumps(current_creds, indent=2))
                    cred_file.chmod(0o600)
        except Exception:
            pass

    with StateLock():

        # Check if THIS session should rotate
        should, target, reason = check_rotation_for_session(state, assignments, sid)

    # Swap outside the lock
    if should and target:
        with StateLock():
            assignments = load_assignments()
            cleanup_stale_sessions(assignments)
            assignments.setdefault("sessions", {})[sid] = {
                "account": target,
                "assigned_at": time.time(),
            }
            save_assignments(assignments)

        if swap_to(target, session_id=sid):
            log_rotation(current, target, reason, sid)
            # Output goes to stderr so statusline still works
            print(f"[auto-rotate] → account {target} ({reason})", file=sys.stderr)


# ─── Status Display ────────────────────────────────────────

def show_status():
    state = load_quota_state()
    profiles = load_profiles()
    assignments = load_assignments()
    cleanup_stale_sessions(assignments)

    print("Claude Code Account Rotation")
    print("=" * 55)

    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        acct_data = state.get("accounts", {}).get(n, {})
        profile = profiles.get("accounts", {}).get(n, {})
        email = profile.get("email", "")
        has_creds = (CREDS_DIR / f"{n}.json").exists()

        if not email and not has_creds:
            continue

        terminals = get_sessions_for_account(assignments, n)
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
    pid = pid or get_session_id()
    assignments = load_assignments()
    current = get_account_for_session(assignments, pid)

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


# ─── Refresh All Accounts (parallel) ──────────────────────

def refresh_account_quota(account_num):
    """
    Run a sandboxed claude -p call with account N's refresh token.
    Refresh tokens are long-lived (~1 year). Claude Code auto-refreshes
    the access token internally. Costs ~5 output tokens per call.
    Returns (account_num, result_dict) or (account_num, None).
    """
    cred_file = CREDS_DIR / f"{account_num}.json"
    if not cred_file.exists():
        return account_num, None

    try:
        creds = json.loads(cred_file.read_text())
        refresh_token = creds.get("claudeAiOauth", {}).get("refreshToken", "")
        if not refresh_token:
            return account_num, None

        env = os.environ.copy()
        env["CLAUDE_CODE_OAUTH_REFRESH_TOKEN"] = refresh_token
        env["CLAUDE_CODE_OAUTH_SCOPES"] = "user:inference"

        result = subprocess.run(
            ["claude", "-p", "x", "--system-prompt", "Reply x", "--output-format", "json"],
            capture_output=True, text=True, timeout=30, env=env
        )

        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                # Output is a JSON array of events
                if isinstance(output, list):
                    rate_info = {}
                    for item in output:
                        # rate_limit_event has the quota data
                        if item.get("type") == "rate_limit_event":
                            rli = item.get("rate_limit_info", {})
                            rtype = rli.get("rateLimitType", "")
                            resets = rli.get("resetsAt", 0)
                            status = rli.get("status", "")
                            if rtype == "five_hour":
                                rate_info["five_hour"] = {
                                    "used_percentage": 100 if status == "rejected" else 0,
                                    "resets_at": resets,
                                }
                            elif rtype == "seven_day":
                                rate_info["seven_day"] = {
                                    "used_percentage": 100 if status == "rejected" else 0,
                                    "resets_at": resets,
                                }
                    if rate_info:
                        return account_num, rate_info
                    # Call succeeded but no rate_limit_event = account has quota
                    return account_num, {"available": True}
            except json.JSONDecodeError:
                pass
            return account_num, {"available": True}

        # Check stderr for rate limit / auth errors
        stderr = result.stderr.lower()
        if "rate" in stderr or "limit" in stderr:
            return account_num, {"rate_limited": True}
        if "401" in result.stderr or "auth" in stderr:
            return account_num, {"expired": True}

        return account_num, None
    except subprocess.TimeoutExpired:
        return account_num, None
    except Exception:
        return account_num, None


def refresh_all_accounts():
    """Poll all accounts in parallel using sandboxed claude calls."""
    import concurrent.futures

    profiles = load_profiles()
    accounts = [n for n in map(str, range(1, MAX_ACCOUNTS + 1))
                if (CREDS_DIR / f"{n}.json").exists()]

    if not accounts:
        print("No accounts configured.")
        return

    print(f"Refreshing {len(accounts)} accounts in parallel...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(refresh_account_quota, n): n for n in accounts}
        results = {}
        for future in concurrent.futures.as_completed(futures):
            n, data = future.result()
            results[n] = data
            email = profiles.get("accounts", {}).get(n, {}).get("email", "?")
            if data is None:
                print(f"  {n}  ✗ {email} — failed")
            elif data.get("expired"):
                print(f"  {n}  ✗ {email} — token expired (re-login needed)")
            elif data.get("rate_limited"):
                print(f"  {n}  ◌ {email} — rate limited")
            elif data.get("five_hour") or data.get("seven_day"):
                five_pct = data.get("five_hour", {}).get("used_percentage", "?")
                seven_pct = data.get("seven_day", {}).get("used_percentage", "?")
                print(f"  {n}  ● {email} — 5h:{five_pct}% 7d:{seven_pct}%")
            elif data.get("available"):
                print(f"  {n}  ● {email} — available")
            else:
                print(f"  {n}  ? {email} — unknown")

    # Update quota state
    with StateLock():
        state = load_quota_state()
        for n, data in results.items():
            if data is None or data.get("expired"):
                continue
            existing = state.get("accounts", {}).get(n, {})

            if data.get("five_hour") or data.get("seven_day"):
                # Got real rate_limits data
                state.setdefault("accounts", {})[n] = {
                    "five_hour": data.get("five_hour", existing.get("five_hour", {})),
                    "seven_day": data.get("seven_day", existing.get("seven_day", {})),
                    "updated_at": time.time(),
                }
            elif data.get("rate_limited"):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": {"used_percentage": 100, "resets_at": existing.get("five_hour", {}).get("resets_at", 0)},
                    "seven_day": existing.get("seven_day", {"used_percentage": 0, "resets_at": 0}),
                    "updated_at": time.time(),
                }
            elif data.get("available") and not existing:
                state.setdefault("accounts", {})[n] = {
                    "five_hour": {"used_percentage": 0, "resets_at": 0},
                    "seven_day": {"used_percentage": 0, "resets_at": 0},
                    "updated_at": time.time(),
                }
        save_quota_state(state)

    print("\nDone.")


# ─── Credential Verification ─────────────────────────────

def verify_credentials():
    """Check credential files for cross-contamination."""
    import hashlib

    profiles = load_profiles()
    hashes = {}

    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        cred_file = CREDS_DIR / f"{n}.json"
        if not cred_file.exists():
            continue
        content = cred_file.read_bytes()
        h = hashlib.md5(content).hexdigest()[:12]
        hashes.setdefault(h, []).append(n)

    if not hashes:
        print("No credential files found.")
        return

    contaminated = False
    for h, accounts in hashes.items():
        if len(accounts) > 1:
            contaminated = True
            emails = [profiles.get("accounts", {}).get(n, {}).get("email", "?") for n in accounts]
            print(f"  CONTAMINATED: accounts {', '.join(accounts)} have identical credentials")
            print(f"    Expected different creds for: {', '.join(emails)}")
            print(f"    Fix: re-login each with 'ccc login N'")

    for h, accounts in hashes.items():
        if len(accounts) == 1:
            n = accounts[0]
            email = profiles.get("accounts", {}).get(n, {}).get("email", "?")
            print(f"  OK: account {n} ({email}) — unique credentials")

    if contaminated:
        print(f"\nCredential contamination detected! Re-login affected accounts.")
    else:
        print("\nAll credentials are unique. No contamination detected.")


# ─── Main ─────────────────────────────────────────────────

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        show_status()

    elif cmd == "check":
        ppid = _get_ppid_flag()
        pid = get_session_id(claude_pid=ppid)
        state = load_quota_state()
        assignments = load_assignments()
        should, target, reason = check_rotation_for_session(state, assignments, pid)
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
        ppid = _get_ppid_flag()
        json_str = sys.stdin.read()
        update_and_maybe_rotate(json_str, claude_pid=ppid)

    elif cmd == "statusline":
        print(statusline_quota())

    elif cmd == "refresh":
        refresh_all_accounts()

    elif cmd == "auto-rotate":
        ppid = _get_ppid_flag()
        force = "--force" in sys.argv
        pid = get_session_id(claude_pid=ppid)

        if force and pid:
            # Force: mark current as exhausted and swap immediately, bypassing checks.
            # The user is telling us they're rate-limited — don't second-guess them.
            with StateLock():
                state = load_quota_state()
                assignments = load_assignments()
                current = get_account_for_session(assignments, pid)
                if current:
                    acct = state.setdefault("accounts", {}).setdefault(current, {})
                    acct["five_hour"] = {
                        "used_percentage": 100,
                        "resets_at": time.time() + 18000,
                    }
                    save_quota_state(state)

            state = load_quota_state()
            assignments = load_assignments()
            current = get_account_for_session(assignments, pid)
            target = pick_best_account(state, assignments, exclude=current)
            if target:
                with StateLock():
                    assignments = load_assignments()
                    assignments.setdefault("sessions", {})[pid] = {
                        "account": target,
                        "assigned_at": time.time(),
                    }
                    save_assignments(assignments)
                if swap_to(target, session_id=pid):
                    log_rotation(current, target, "force rotate", pid)
                    profiles = load_profiles()
                    email = profiles.get("accounts", {}).get(target, {}).get("email", "")
                    print(f"[force-rotate] → account {target} ({email})")
                else:
                    sys.exit(1)
            else:
                show_status()
                print("\nNo accounts available to rotate to — all in cooldown.")
        else:
            # Normal: check quota data and rotate if needed
            state = load_quota_state()
            assignments = load_assignments()
            should, target, reason = check_rotation_for_session(state, assignments, pid)
            if should and target:
                with StateLock():
                    assignments = load_assignments()
                    cleanup_stale_sessions(assignments)
                    assignments.setdefault("sessions", {})[pid] = {
                        "account": target,
                        "assigned_at": time.time(),
                    }
                    save_assignments(assignments)
                if swap_to(target, session_id=pid):
                    log_rotation(get_account_for_session(load_assignments(), pid), target, reason, pid)
                    profiles = load_profiles()
                    email = profiles.get("accounts", {}).get(target, {}).get("email", "")
                    print(f"[auto-rotate] → account {target} ({email}) — {reason}")
                else:
                    sys.exit(1)

    elif cmd == "verify":
        verify_credentials()

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
