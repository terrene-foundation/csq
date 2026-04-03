#!/usr/bin/env python3
"""
Claude Squad — Rotation Engine

Tracks quota across accounts. Swaps by writing ~/.claude/.credentials.json.
Claude Code picks up new credentials on next 401 — no config dirs needed.

State files (all in ~/.claude/accounts/):
  credentials/N.json   Stored OAuth credentials per account (1-7)
  profiles.json        Email→account mapping
  quota.json           Per-account quota from statusline

Commands:
  update              Update quota from statusline JSON (stdin)
  status              Show all accounts and quota
  statusline          Compact string for statusline display
  swap <N>            Write account N's creds to ~/.claude/.credentials.json
  auto-rotate         Check + swap if needed
  auto-rotate --force Force-rotate (marks current exhausted)
"""

import json
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
    return [
        str(n) for n in range(1, MAX_ACCOUNTS + 1) if (CREDS_DIR / f"{n}.json").exists()
    ]


def which_account():
    """Which stored account is this terminal on?
    Uses a per-parent-PID cache so we only call 'claude auth status' once."""
    import os
    import subprocess

    ppid = os.getppid()
    cache_file = ACCOUNTS_DIR / f".account.{ppid}"

    # Check cache first
    if cache_file.exists():
        try:
            return cache_file.read_text().strip() or None
        except OSError:
            pass

    # Get email from claude auth status
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

    # Match email to stored account
    profiles = _load(PROFILES_FILE, {}).get("accounts", {})
    for n, info in profiles.items():
        if info.get("email") == email:
            cache_file.write_text(n)
            return n

    return None


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


# ─── Swap ────────────────────────────────────────────────


def swap_to(target_account):
    """Write target account's credentials to ~/.claude/.credentials.json.
    CC picks up new creds on next 401."""
    target_account = str(target_account)
    source = CREDS_DIR / f"{target_account}.json"
    if not source.exists():
        print(f"error: no credentials for account {target_account}", file=sys.stderr)
        return False

    creds_target = Path.home() / ".claude" / ".credentials.json"
    creds_target.write_text(source.read_text())
    creds_target.chmod(0o600)

    # Invalidate account cache for this terminal
    import os

    cache_file = ACCOUNTS_DIR / f".account.{os.getppid()}"
    cache_file.write_text(target_account)

    email = get_email(target_account)
    print(f"Swapped to account {target_account} ({email})")
    return True


# ─── Quota Update ────────────────────────────────────────


def update_quota(json_str):
    """Called from statusline. Saves quota data, auto-rotates at 100%."""
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

    # Auto-rotate at 100%
    five_pct = rate_limits.get("five_hour", {}).get("used_percentage", 0)
    if five_pct >= 100:
        target = pick_best(state, exclude=current)
        if target and swap_to(target):
            print(
                f"[auto-rotate] → account {target} ({get_email(target)})",
                file=sys.stderr,
            )


# ─── Auto-Rotate ─────────────────────────────────────────


def auto_rotate(force=False):
    """Called from hook or /rotate."""
    current = which_account()
    state = load_state()

    if force and current:
        state.setdefault("accounts", {}).setdefault(current, {})["five_hour"] = {
            "used_percentage": 100,
            "resets_at": time.time() + 18000,
        }
        _save(QUOTA_FILE, state)

    acct = state.get("accounts", {}).get(current or "", {})
    five_pct = acct.get("five_hour", {}).get("used_percentage", 0)

    if five_pct >= 100 or force:
        target = pick_best(state, exclude=current)
        if target:
            if swap_to(target):
                print(
                    f"[auto-rotate] → account {target} ({get_email(target)})",
                    file=sys.stderr,
                )
        elif force:
            show_status()
            print("\nAll accounts exhausted.")


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
        print("Active: unknown (no matching credentials)")
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
        if not swap_to(sys.argv[2]):
            sys.exit(1)
    elif cmd == "auto-rotate":
        auto_rotate(force="--force" in sys.argv)
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
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
