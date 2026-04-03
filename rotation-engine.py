#!/usr/bin/env python3
"""
Claude Squad — Quota Tracker

Tracks quota across accounts from statusline data.
When rate limited, tells you which account to /login to.

State files (all in ~/.claude/accounts/):
  credentials/N.json   Stored OAuth credentials per account (for identity only)
  profiles.json        Email→account mapping
  quota.json           Per-account quota from statusline

Commands:
  update              Update quota from statusline JSON (stdin)
  status              Show all accounts and quota
  statusline          Compact string for statusline display
  suggest             Suggest which account to /login to
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ACCOUNTS_DIR = Path.home() / ".claude" / "accounts"
CREDS_DIR = ACCOUNTS_DIR / "credentials"
QUOTA_FILE = ACCOUNTS_DIR / "quota.json"
PROFILES_FILE = ACCOUNTS_DIR / "profiles.json"
MAX_ACCOUNTS = 7


def _load(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save(path, data):
    path.write_text(json.dumps(data, indent=2))


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


def which_account():
    """Which account is this terminal on? Cached per parent PID."""
    import os

    ppid = os.getppid()
    cache_file = ACCOUNTS_DIR / f".account.{ppid}"

    if cache_file.exists():
        try:
            return cache_file.read_text().strip() or None
        except OSError:
            pass

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
            cache_file.write_text(n)
            return n

    return None


# ─── Suggest Best ────────────────────────────────────────


def suggest_best(state, exclude=None):
    """Suggest the best account to /login to.
    Picks lowest 5h usage. If all exhausted, picks soonest reset."""
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


# ─── Quota Update ────────────────────────────────────────


def update_quota(json_str):
    """Called from statusline. Saves quota data for this terminal's account."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return

    rate_limits = data.get("rate_limits")
    if not rate_limits:
        return

    current = which_account()
    if not current:
        return

    state = load_state()
    state.setdefault("accounts", {})[current] = {
        "five_hour": rate_limits.get("five_hour", {}),
        "seven_day": rate_limits.get("seven_day", {}),
        "updated_at": time.time(),
    }
    _save(QUOTA_FILE, state)


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
    current = which_account()
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


def show_suggest():
    """Print which account to /login to."""
    current = which_account()
    state = load_state()
    target = suggest_best(state, exclude=current)
    if target:
        email = get_email(target)
        five_pct = (
            state.get("accounts", {})
            .get(target, {})
            .get("five_hour", {})
            .get("used_percentage", 0)
        )
        print(f"Suggest: account {target} ({email}) — 5h:{five_pct:.0f}%")
        print(f"Run /login and sign in as {email}")
    else:
        print("No accounts with available quota.")
        show_status()


# ─── Main ────────────────────────────────────────────────


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "status":
        show_status()
    elif cmd == "update":
        update_quota(sys.stdin.read())
    elif cmd == "suggest":
        show_suggest()
    elif cmd == "statusline":
        print(statusline_str())
    elif cmd == "check":
        current = which_account()
        state = load_state()
        acct = state.get("accounts", {}).get(current or "", {})
        five_pct = acct.get("five_hour", {}).get("used_percentage", 0)
        print(json.dumps({"exhausted": five_pct >= 100, "current": current}))
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
