#!/usr/bin/env python3
"""
Claude Code Account Rotation Engine — Fleet Model

All terminals share ONE keychain entry and ONE active account.
When quota runs low, swap the keychain — all terminals move together.

State files:
  quota.json           Current account + quota (single source of truth)
  credentials/N.json   Stored OAuth credentials per account (1-7)
  profiles.json        Email→account mapping
  rotation.log         Audit log (JSONL)

Commands:
  rotation-engine.py status              Show all accounts and quota
  rotation-engine.py update <json>       Update quota from statusline (via stdin)
  rotation-engine.py swap <N>            Force swap to account N
  rotation-engine.py extract <N>         Extract current keychain creds as account N
  rotation-engine.py auto-rotate         Check + swap if needed (for hooks)
  rotation-engine.py auto-rotate --force Mark current as exhausted, then rotate
  rotation-engine.py verify              Check credential integrity
  rotation-engine.py refresh             Poll all accounts for quota
  rotation-engine.py statusline          Compact string for statusline display
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
QUOTA_FILE = ACCOUNTS_DIR / "quota.json"
PROFILES_FILE = ACCOUNTS_DIR / "profiles.json"
CURRENT_FILE = ACCOUNTS_DIR / ".current"
LOG_FILE = ACCOUNTS_DIR / "rotation.log"
LOCK_FILE = ACCOUNTS_DIR / ".lock"
KEYCHAIN_SERVICE = "Claude Code-credentials"
MAX_ACCOUNTS = 7


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
    return _load(QUOTA_FILE, {"current": None, "accounts": {}})

def save_state(state):
    _save(QUOTA_FILE, state)

def load_profiles():
    return _load(PROFILES_FILE, {"accounts": {}})

def get_email(n):
    return load_profiles().get("accounts", {}).get(str(n), {}).get("email", "")

def log_rotation(from_acct, to_acct, reason):
    entry = {"time": time.time(), "from": from_acct, "to": to_acct, "reason": reason}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ─── Keychain ────────────────────────────────────────────

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

def write_keychain(creds):
    r = subprocess.run(
        ["security", "add-generic-password", "-U",
         "-a", os.environ.get("USER", "esperie"),
         "-s", KEYCHAIN_SERVICE, "-w", json.dumps(creds)],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"error: keychain write failed: {r.stderr}", file=sys.stderr)
        return False
    # Trigger Claude Code to re-read credentials
    (Path.home() / ".claude" / ".credentials.json").touch()
    return True


# ─── Account Selection ───────────────────────────────────

def pick_best(state, exclude=None):
    """Pick account with most 5h headroom. Skips weekly-exhausted."""
    best, best_score = None, -1
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        if n == str(exclude):
            continue
        if not (CREDS_DIR / f"{n}.json").exists():
            continue
        acct = state.get("accounts", {}).get(n, {})
        five = acct.get("five_hour", {})
        seven = acct.get("seven_day", {})
        pct = five.get("used_percentage", 0)
        weekly_pct = seven.get("used_percentage", 0)
        updated = acct.get("updated_at", 0)
        stale = (time.time() - updated) > 1800 if updated else True

        if not stale and weekly_pct >= 95:
            continue  # Weekly dead
        if not stale and pct >= 95:
            continue  # 5h exhausted

        # Score: lower usage = better. Stale/unknown = 50 (worth trying)
        score = (100 - pct) if (not stale and pct > 0) else 50
        if score > best_score:
            best, best_score = n, score
    return best


# ─── Swap ────────────────────────────────────────────────

def swap_to(account_num, state=None):
    """Swap keychain to account N. Fully locked."""
    account_num = str(account_num)
    cred_file = CREDS_DIR / f"{account_num}.json"
    if not cred_file.exists():
        print(f"error: no credentials for account {account_num}", file=sys.stderr)
        return False

    with Lock():
        # Save current keychain back to correct file (match by refresh token)
        current_creds = read_keychain()
        if current_creds:
            kc_refresh = current_creds.get("claudeAiOauth", {}).get("refreshToken", "")
            if kc_refresh:
                for n in map(str, range(1, MAX_ACCOUNTS + 1)):
                    if n == account_num:
                        continue
                    cf = CREDS_DIR / f"{n}.json"
                    if not cf.exists():
                        continue
                    try:
                        stored = json.loads(cf.read_text())
                        if stored.get("claudeAiOauth", {}).get("refreshToken", "") == kc_refresh:
                            cf.write_text(json.dumps(current_creds, indent=2))
                            cf.chmod(0o600)
                            break
                    except (json.JSONDecodeError, OSError):
                        continue

        # Load and write target credentials
        creds = json.loads(cred_file.read_text())
        if not write_keychain(creds):
            return False

        # Update global current account
        if state is None:
            state = load_state()
        state["current"] = account_num
        save_state(state)
        CURRENT_FILE.write_text(account_num)

    email = get_email(account_num)
    print(f"Swapped to account {account_num} ({email})")
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

    profiles = load_profiles()
    profiles.setdefault("accounts", {})[str(account_num)] = {"email": email, "method": "oauth"}
    _save(PROFILES_FILE, profiles)

    # Reset quota — fresh login = fresh quota
    with Lock():
        state = load_state()
        state["current"] = str(account_num)
        state.setdefault("accounts", {})[str(account_num)] = {
            "five_hour": {"used_percentage": 0, "resets_at": 0},
            "seven_day": {"used_percentage": 0, "resets_at": 0},
            "updated_at": time.time(),
        }
        save_state(state)
    CURRENT_FILE.write_text(str(account_num))

    print(f"Extracted credentials for account {account_num} ({email})")
    return True


# ─── Quota Update ────────────────────────────────────────

def update_quota(json_str):
    """Called from statusline. Updates quota for current account, auto-rotates if needed."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return

    rate_limits = data.get("rate_limits")
    if not rate_limits:
        return

    with Lock():
        state = load_state()
        current = state.get("current")
        if not current:
            # Detect current account from keychain on first call
            current = _detect_current_account()
            if current:
                state["current"] = current
            else:
                return

        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        save_state(state)

        # Check if rotation needed
        five_pct = rate_limits.get("five_hour", {}).get("used_percentage", 0)
        weekly_pct = rate_limits.get("seven_day", {}).get("used_percentage", 0)

    # Rotate at 95% (proactive) — don't wait for hard limit
    if five_pct >= 95 or weekly_pct >= 95:
        target = pick_best(state, exclude=current)
        if target:
            old = current
            if swap_to(target, state):
                log_rotation(old, target, f"auto ({five_pct:.0f}% 5h, {weekly_pct:.0f}% 7d)")
                email = get_email(target)
                print(f"[auto-rotate] → account {target} ({email})", file=sys.stderr)


def _detect_current_account():
    """One-time: figure out which account the keychain currently holds."""
    kc = read_keychain()
    if not kc:
        return None
    kc_refresh = kc.get("claudeAiOauth", {}).get("refreshToken", "")
    if not kc_refresh:
        return None
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        cf = CREDS_DIR / f"{n}.json"
        if not cf.exists():
            continue
        try:
            stored = json.loads(cf.read_text())
            if stored.get("claudeAiOauth", {}).get("refreshToken", "") == kc_refresh:
                return n
        except (json.JSONDecodeError, OSError):
            continue
    return None


# ─── Auto-Rotate (Hook) ─────────────────────────────────

def auto_rotate(force=False):
    """Called from UserPromptSubmit hook."""
    with Lock():
        state = load_state()
        current = state.get("current")

        if not current:
            current = _detect_current_account()
            if current:
                state["current"] = current
                save_state(state)
            else:
                return

        if force:
            state.setdefault("accounts", {}).setdefault(current, {})["five_hour"] = {
                "used_percentage": 100, "resets_at": time.time() + 18000,
            }
            save_state(state)

        acct = state.get("accounts", {}).get(current, {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        weekly_pct = acct.get("seven_day", {}).get("used_percentage", 0)

    if five_pct >= 95 or weekly_pct >= 95 or force:
        target = pick_best(state, exclude=current)
        if target:
            if swap_to(target, state):
                log_rotation(current, target, "force" if force else "hook")
                email = get_email(target)
                print(f"[{'force' if force else 'auto'}-rotate] → account {target} ({email})")
            else:
                sys.exit(1)
        else:
            if force:
                show_status()
                print("\nNo accounts available — all in cooldown.")


# ─── Status ──────────────────────────────────────────────

def fmt_time(epoch):
    diff = epoch - time.time()
    if diff <= 0: return "now"
    h, m = int(diff // 3600), int((diff % 3600) // 60)
    if h >= 24: return f"{h//24}d{h%24}h"
    return f"{h}h{m}m" if h > 0 else f"{m}m"

def show_status():
    state = load_state()
    current = state.get("current", "?")
    profiles = load_profiles()

    print(f"Claude Code Fleet — current: account {current} ({get_email(current)})")
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

        icon = "●" if five_pct < 80 else "◐" if five_pct < 95 else "◌" if seven_pct < 95 else "✗"

        print(f" {marker} {n}  {icon} {email}")
        if acct:
            r5 = fmt_time(five_reset) if five_reset else "?"
            r7 = fmt_time(seven_reset) if seven_reset else "?"
            print(f"       5h:{five_pct:.0f}% ↻{r5}  7d:{seven_pct:.0f}% ↻{r7}{stale}")
    print()

def statusline_str():
    state = load_state()
    current = state.get("current")
    if not current:
        try: current = CURRENT_FILE.read_text().strip()
        except FileNotFoundError: return ""
    acct = state.get("accounts", {}).get(current, {})
    email = get_email(current)
    user = email.split("@")[0][:10] if email else ""
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
    seven_pct = acct.get("seven_day", {}).get("used_percentage", 0)
    parts = [f"#{current}:{user}"]
    if five_pct > 0: parts.append(f"5h:{five_pct:.0f}%")
    if seven_pct > 0: parts.append(f"7d:{seven_pct:.0f}%")
    return " ".join(parts)


# ─── Verify & Refresh ───────────────────────────────────

def verify_credentials():
    import hashlib
    profiles = load_profiles()
    hashes = {}
    for n in map(str, range(1, MAX_ACCOUNTS + 1)):
        cf = CREDS_DIR / f"{n}.json"
        if not cf.exists(): continue
        h = hashlib.md5(cf.read_bytes()).hexdigest()[:12]
        hashes.setdefault(h, []).append(n)

    if not hashes:
        print("No credential files found."); return

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

def refresh_all():
    import concurrent.futures
    profiles = load_profiles()
    accounts = [n for n in map(str, range(1, MAX_ACCOUNTS + 1)) if (CREDS_DIR / f"{n}.json").exists()]
    if not accounts:
        print("No accounts configured."); return

    print(f"Refreshing {len(accounts)} accounts...")

    def poll(n):
        cf = CREDS_DIR / f"{n}.json"
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
                                info[rtype] = {"used_percentage": 100 if status == "rejected" else 0, "resets_at": resets}
                    return n, info if info else {"available": True}
                return n, {"available": True}
            stderr = r.stderr.lower()
            if "rate" in stderr or "limit" in stderr: return n, {"rate_limited": True}
            if "401" in r.stderr or "auth" in stderr: return n, {"expired": True}
            return n, None
        except: return n, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
        results = {}
        for future in concurrent.futures.as_completed({ex.submit(poll, n): n for n in accounts}):
            n, data = future.result()
            results[n] = data
            email = get_email(n)
            if data is None: print(f"  {n}  ✗ {email} — failed")
            elif data.get("expired"): print(f"  {n}  ✗ {email} — expired")
            elif data.get("rate_limited"): print(f"  {n}  ◌ {email} — rate limited")
            elif data.get("available"): print(f"  {n}  ● {email} — available")
            else:
                fp = data.get("five_hour", {}).get("used_percentage", "?")
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
                    "five_hour": {"used_percentage": 100, "resets_at": existing.get("five_hour", {}).get("resets_at", 0)},
                    "seven_day": existing.get("seven_day", {}),
                    "updated_at": time.time(),
                }
            elif data.get("available") and not existing:
                state.setdefault("accounts", {})[n] = {
                    "five_hour": {"used_percentage": 0, "resets_at": 0},
                    "seven_day": {"used_percentage": 0, "resets_at": 0},
                    "updated_at": time.time(),
                }
        save_state(state)
    print("\nDone.")


# ─── Main ────────────────────────────────────────────────

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        show_status()
    elif cmd == "update":
        update_quota(sys.stdin.read())
    elif cmd == "swap":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py swap <N>", file=sys.stderr); sys.exit(1)
        if swap_to(sys.argv[2]):
            log_rotation(None, sys.argv[2], "manual")
        else:
            sys.exit(1)
    elif cmd == "extract":
        if len(sys.argv) < 3:
            print("usage: rotation-engine.py extract <N>", file=sys.stderr); sys.exit(1)
        if not extract_current(sys.argv[2]): sys.exit(1)
    elif cmd == "auto-rotate":
        auto_rotate(force="--force" in sys.argv)
    elif cmd == "check":
        # Backward compat for hook — just output JSON
        state = load_state()
        current = state.get("current")
        if not current:
            print(json.dumps({"should_rotate": False})); sys.exit(0)
        acct = state.get("accounts", {}).get(current, {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        weekly_pct = acct.get("seven_day", {}).get("used_percentage", 0)
        should = five_pct >= 95 or weekly_pct >= 95
        target = pick_best(state, exclude=current) if should else None
        print(json.dumps({"should_rotate": should and target is not None, "target": target,
                          "reason": f"5h:{five_pct:.0f}% 7d:{weekly_pct:.0f}%"}))
    elif cmd == "statusline":
        print(statusline_str())
    elif cmd == "verify":
        verify_credentials()
    elif cmd == "refresh":
        refresh_all()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr); sys.exit(1)

if __name__ == "__main__":
    main()
