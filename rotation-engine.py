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
    return _load(QUOTA_FILE, {"accounts": {}})

def save_state(state):
    _save(QUOTA_FILE, state)

def load_profiles():
    return _load(PROFILES_FILE, {"accounts": {}})

def get_email(n):
    return load_profiles().get("accounts", {}).get(str(n), {}).get("email", "")

def load_blocked():
    """Load blocked accounts. An account is unblocked when its earliest
    reset time (5h or 7d) has passed — not an arbitrary timer."""
    data = _load(BLOCKED_FILE, {})
    now = time.time()
    state = load_state()
    active = {}
    for acct, blocked_at in data.items():
        # Check if any reset has passed since blocking
        acct_data = state.get("accounts", {}).get(acct, {})
        five_reset = acct_data.get("five_hour", {}).get("resets_at", 0)
        seven_reset = acct_data.get("seven_day", {}).get("resets_at", 0)
        # Unblock if 5h window has reset (most common recovery)
        if five_reset and five_reset < now:
            continue  # Reset passed — unblocked
        # Fallback: 6h max in case we have no reset data
        if now - blocked_at > 21600:
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


# ─── This Terminal ───────────────────────────────────────

CURRENT_ACCOUNT_FILE = ACCOUNTS_DIR / ".current_accounts"


def this_account():
    """Which account is THIS terminal on?
    After mid-session swap, the config dir name no longer matches the account.
    Use a per-PID tracking file instead."""
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "")
    if not config_dir:
        return None

    pid = str(os.getpid())
    ppid = str(os.getppid())

    # Check per-process tracking first (survives mid-session swaps)
    data = _load(CURRENT_ACCOUNT_FILE, {})
    old_len = len(data)
    _cleanup_dead_pids(data)
    if len(data) < old_len:
        _save(CURRENT_ACCOUNT_FILE, data)
    # Check PPID (Claude Code PID) then own PID
    for check_pid in (ppid, pid):
        if check_pid in data:
            return data[check_pid]

    # Fallback: derive from config dir name (initial launch)
    name = Path(config_dir).name
    if name.startswith("config-") and name[7:].isdigit():
        return name[7:]
    return None


def set_this_account(account_num):
    """Track which account this terminal is actually on (after swap)."""
    pid = str(os.getpid())
    ppid = str(os.getppid())
    with Lock():
        data = _load(CURRENT_ACCOUNT_FILE, {})
        data[pid] = str(account_num)
        data[ppid] = str(account_num)
        # Cleanup dead PIDs — keep file small
        _cleanup_dead_pids(data)
        _save(CURRENT_ACCOUNT_FILE, data)


def _cleanup_dead_pids(data):
    """Remove entries for PIDs that no longer exist."""
    dead = []
    for pid_str in data:
        try:
            os.kill(int(pid_str), 0)  # Check if process exists
        except (ProcessLookupError, ValueError):
            dead.append(pid_str)
        except PermissionError:
            pass  # Process exists but we can't signal it
    for pid_str in dead:
        del data[pid_str]

def this_config_dir():
    """Path to this terminal's config dir."""
    return os.environ.get("CLAUDE_CONFIG_DIR", "")


# ─── Config Dir Management ───────────────────────────────

def config_dir_for(n):
    return ACCOUNTS_DIR / f"config-{n}"

def setup_config_dirs():
    """Create/update config dirs for all accounts with credentials."""
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

        # Settings — symlink to global settings.json
        settings_link = cdir / "settings.json"
        global_settings = GLOBAL_CLAUDE_DIR / "settings.json"
        if global_settings.exists():
            if settings_link.exists() or settings_link.is_symlink():
                settings_link.unlink()
            settings_link.symlink_to(global_settings)

        email = get_email(n)
        print(f"  {n}  {email} → {cdir}")

    print("\nConfig dirs ready. Launch terminals with: ccc <N>")


# ─── Keychain (legacy, for extract only) ─────────────────

def read_keychain():
    r = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        return None


# ─── Account Selection ───────────────────────────────────

def pick_best(state, exclude=None):
    """Pick account with most 5h headroom. Skips blocked + 5h-exhausted.
    When multiple accounts are available, picks lowest usage.
    When all known accounts are exhausted, picks the one whose reset is soonest."""
    blocked = load_blocked()
    now = time.time()
    available = []   # (account, score) — accounts with quota
    exhausted = []   # (account, resets_at) — accounts waiting for reset

    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        if n == str(exclude):
            continue
        if n in blocked:
            continue
        if not (CREDS_DIR / f"{n}.json").exists():
            continue
        acct = state.get("accounts", {}).get(n, {})
        five = acct.get("five_hour", {})
        pct = five.get("used_percentage", 0)
        resets_at = five.get("resets_at", 0)
        updated = acct.get("updated_at", 0)
        stale = (now - updated) > 1800 if updated else True

        if not stale and pct >= 90:
            exhausted.append((n, resets_at))
            continue

        score = (100 - pct) if (not stale and pct > 0) else 50
        available.append((n, score))

    # Prefer available accounts (sorted by most headroom)
    if available:
        available.sort(key=lambda x: x[1], reverse=True)
        return available[0][0]

    # All exhausted — pick the one whose 5h window resets soonest
    if exhausted:
        # Filter to only those whose reset is in the future
        future = [(n, r) for n, r in exhausted if r > now]
        if future:
            future.sort(key=lambda x: x[1])
            return future[0][0]

    return None


# ─── Swap (Mid-Session) ─────────────────────────────────

def swap_to(target_account):
    """Swap THIS terminal to a different account by overwriting its .credentials.json."""
    target_account = str(target_account)
    source_cred = CREDS_DIR / f"{target_account}.json"
    if not source_cred.exists():
        print(f"error: no credentials for account {target_account}", file=sys.stderr)
        return False

    config_dir = this_config_dir()
    if not config_dir:
        print("error: CLAUDE_CONFIG_DIR not set — launch via 'ccc <N>'", file=sys.stderr)
        return False

    with Lock():
        # Save current credentials back to the source file (keep tokens fresh)
        current = this_account()
        if current and current != target_account:
            current_cred = Path(config_dir) / ".credentials.json"
            if current_cred.exists():
                creds = json.loads(current_cred.read_text())
                save_back = CREDS_DIR / f"{current}.json"
                save_back.write_text(json.dumps(creds, indent=2))
                save_back.chmod(0o600)

        # Write target credentials to this terminal's config dir
        creds = json.loads(source_cred.read_text())
        target_path = Path(config_dir) / ".credentials.json"
        target_path.write_text(json.dumps(creds))
        target_path.chmod(0o600)

    # Track the actual account this terminal is on (survives mid-session swaps)
    set_this_account(target_account)

    email = get_email(target_account)
    print(f"Swapped to account {target_account} ({email})")
    return True


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

    r = subprocess.run(["claude", "auth", "status", "--json"],
                       capture_output=True, text=True)
    email = "unknown"
    if r.returncode == 0:
        try: email = json.loads(r.stdout).get("email", "unknown")
        except json.JSONDecodeError: pass

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
    """Called from statusline. Updates quota for THIS terminal's account."""
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

    with Lock():
        state = load_state()
        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        save_state(state)

    # Quota tracking only — rotation is the hook's job.
    # But poll OTHER accounts in background so pick_best has data for all 7,
    # not just the ones with active terminals.
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

    others = [n for n in map(str, range(1, MAX_ACCOUNTS + 1))
              if n != current and (CREDS_DIR / f"{n}.json").exists()]
    if not others:
        return

    # Spawn detached background process
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "_poll_others"] + others,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _run_poll_others(accounts):
    """Background process: poll accounts in parallel, update state."""
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(accounts), 7)) as ex:
        results = dict(ex.map(lambda n: _poll_account(n), accounts))
    with Lock():
        state = load_state()
        for n, data in results.items():
            if data is None or (isinstance(data, dict) and data.get("expired")):
                continue
            existing = state.get("accounts", {}).get(n, {})
            if isinstance(data, dict) and (data.get("five_hour") or data.get("seven_day")):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": data.get("five_hour", existing.get("five_hour", {})),
                    "seven_day": data.get("seven_day", existing.get("seven_day", {})),
                    "updated_at": time.time(),
                }
            elif isinstance(data, dict) and data.get("rate_limited"):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": {"used_percentage": 100,
                                  "resets_at": existing.get("five_hour", {}).get("resets_at", 0)},
                    "seven_day": existing.get("seven_day", {}),
                    "updated_at": time.time(),
                }
            elif isinstance(data, dict) and data.get("available"):
                # Poll succeeded without rate_limit_event = account has quota.
                # Record as low usage so pick_best treats it as a viable target.
                # Preserve existing reset times if we have them.
                state.setdefault("accounts", {})[n] = {
                    "five_hour": existing.get("five_hour", {"used_percentage": 0, "resets_at": 0}),
                    "seven_day": existing.get("seven_day", {"used_percentage": 0, "resets_at": 0}),
                    "updated_at": time.time(),
                }
        save_state(state)


# ─── Auto-Rotate (Hook) ─────────────────────────────────

def auto_rotate(force=False):
    """Called from UserPromptSubmit hook or /rotate."""
    current = this_account()
    if not current:
        print("error: CLAUDE_CONFIG_DIR not set", file=sys.stderr)
        return

    if force:
        mark_blocked(current)

    with Lock():
        state = load_state()
        if force:
            state.setdefault("accounts", {}).setdefault(current, {})["five_hour"] = {
                "used_percentage": 100, "resets_at": time.time() + 18000,
            }
            save_state(state)

    acct = state.get("accounts", {}).get(current, {})
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)

    if five_pct >= 90 or force:
        target = pick_best(state, exclude=current)
        if target:
            if swap_to(target):
                log_rotation(current, target, "force" if force else "hook")
                email = get_email(target)
                print(f"[{'force' if force else 'auto'}-rotate] → account {target} ({email})")
            else:
                sys.exit(1)
        else:
            if force:
                show_status()
                print("\nNo accounts available — all blocked or in cooldown.")


# ─── Status ──────────────────────────────────────────────

def fmt_time(epoch):
    diff = epoch - time.time()
    if diff <= 0: return "now"
    h, m = int(diff // 3600), int((diff % 3600) // 60)
    if h >= 24: return f"{h//24}d{h%24}h"
    return f"{h}h{m}m" if h > 0 else f"{m}m"

def show_status():
    state = load_state()
    current = this_account()
    blocked = load_blocked()

    cur_label = f"account {current} ({get_email(current)})" if current else "none (not launched via ccc)"
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

        icon = "✗" if n in blocked else ("●" if five_pct < 80 else "◐" if five_pct < 90 else "◌")

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
    parts = [f"#{current}:{user}"]
    if five_pct > 0: parts.append(f"5h:{five_pct:.0f}%")
    return " ".join(parts)


# ─── Verify & Refresh ───────────────────────────────────

def verify_credentials():
    import hashlib
    hashes = {}
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        cf = CREDS_DIR / f"{n}.json"
        if not cf.exists(): continue
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
    cf = CREDS_DIR / f"{n}.json"
    if not cf.exists(): return n, None
    try:
        creds = json.loads(cf.read_text())
        rt = creds.get("claudeAiOauth", {}).get("refreshToken", "")
        if not rt: return n, None
        env = os.environ.copy()
        env["CLAUDE_CODE_OAUTH_REFRESH_TOKEN"] = rt
        env["CLAUDE_CODE_OAUTH_SCOPES"] = "user:inference"
        r = subprocess.run(
            ["claude", "-p", "x", "--system-prompt", "Reply x", "--output-format", "json"],
            capture_output=True, text=True, timeout=30, env=env)
        if r.returncode == 0:
            output = json.loads(r.stdout)
            if isinstance(output, list):
                info = {}
                for item in output:
                    if item.get("type") == "rate_limit_event":
                        rli = item.get("rate_limit_info", {})
                        rtype = rli.get("rateLimitType", "")
                        resets = rli.get("resetsAt", 0)
                        status = rli.get("status", "")
                        if rtype in ("five_hour", "seven_day"):
                            # Poll only gets allowed/rejected, not exact %.
                            # Use 0% for allowed (available) and 100% for rejected (exhausted).
                            # resetsAt is always accurate — key for pick_best timing.
                            info[rtype] = {"used_percentage": 100 if status == "rejected" else 0,
                                           "resets_at": resets / 1000 if resets > 1e12 else resets}
                if info: return n, info
            return n, {"available": True}
        stderr = r.stderr.lower()
        if "rate" in stderr or "limit" in stderr: return n, {"rate_limited": True}
        if "401" in r.stderr or "auth" in stderr: return n, {"expired": True}
        return n, None
    except: return n, None

def refresh_all():
    import concurrent.futures
    accounts = [n for n in map(str, range(1, MAX_ACCOUNTS + 1)) if (CREDS_DIR / f"{n}.json").exists()]
    if not accounts: print("No accounts."); return
    print(f"Refreshing {len(accounts)} accounts...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
        results = {}
        for future in concurrent.futures.as_completed({ex.submit(_poll_account, n): n for n in accounts}):
            n, data = future.result()
            results[n] = data
            email = get_email(n)
            if data is None: print(f"  {n}  ✗ {email} — failed")
            elif data.get("expired"): print(f"  {n}  ✗ {email} — expired")
            elif data.get("rate_limited"): print(f"  {n}  ◌ {email} — rate limited")
            elif data.get("available"): print(f"  {n}  ● {email} — available")
            else:
                fh = data.get("five_hour")
                fp = fh.get("used_percentage", "?") if isinstance(fh, dict) else "?"
                print(f"  {n}  ● {email} — 5h:{fp}%")
    with Lock():
        state = load_state()
        for n, data in results.items():
            if data is None or data.get("expired"): continue
            existing = state.get("accounts", {}).get(n, {})
            if data.get("five_hour") or data.get("seven_day"):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": data.get("five_hour", existing.get("five_hour", {})),
                    "seven_day": data.get("seven_day", existing.get("seven_day", {})),
                    "updated_at": time.time(),
                }
            elif data.get("rate_limited"):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": {"used_percentage": 100,
                                  "resets_at": existing.get("five_hour", {}).get("resets_at", 0)},
                    "seven_day": existing.get("seven_day", {}),
                    "updated_at": time.time(),
                }
            elif data.get("available"):
                state.setdefault("accounts", {})[n] = {
                    "five_hour": existing.get("five_hour", {"used_percentage": 0, "resets_at": 0}),
                    "seven_day": existing.get("seven_day", {"used_percentage": 0, "resets_at": 0}),
                    "updated_at": time.time(),
                }
        save_state(state)
    print("\nDone.")


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
            print("usage: rotation-engine.py swap <N>", file=sys.stderr); sys.exit(1)
        if swap_to(sys.argv[2]):
            log_rotation(this_account(), sys.argv[2], "manual")
        else:
            sys.exit(1)
    elif cmd == "extract":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py extract <N>", file=sys.stderr); sys.exit(1)
        if not extract_current(sys.argv[2]): sys.exit(1)
    elif cmd == "auto-rotate":
        auto_rotate(force="--force" in sys.argv)
    elif cmd == "check":
        current = this_account()
        with Lock():
            state = load_state()
        if not current:
            print(json.dumps({"should_rotate": False, "reason": "no config dir"})); sys.exit(0)
        acct = state.get("accounts", {}).get(current, {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        should = five_pct >= 90
        target = pick_best(state, exclude=current) if should else None
        print(json.dumps({"should_rotate": should and target is not None, "target": target,
                          "reason": f"5h:{five_pct:.0f}%"}))
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
    elif cmd == "_poll_others":
        _run_poll_others(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr); sys.exit(1)

if __name__ == "__main__":
    main()
