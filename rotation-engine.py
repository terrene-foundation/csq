#!/usr/bin/env python3
"""
Claude Squad — Rotation Engine

Tracks quota across accounts. Auto-rotates by refreshing OAuth tokens
and writing to macOS keychain — CC picks up new creds seamlessly.

State files (all in ~/.claude/accounts/):
  credentials/N.json   Stored OAuth credentials per account (1-7)
  profiles.json        Email→account mapping
  quota.json           Per-account quota from statusline

Commands:
  update              Update quota from statusline JSON (stdin)
  status              Show all accounts and quota
  statusline          Compact string for statusline display
  swap <N>            Refresh account N's token and write to keychain
  auto-rotate         Check + swap if needed
  auto-rotate --force Force-rotate (marks current exhausted)
"""

import getpass
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ACCOUNTS_DIR = Path.home() / ".claude" / "accounts"
CREDS_DIR = ACCOUNTS_DIR / "credentials"
QUOTA_FILE = ACCOUNTS_DIR / "quota.json"
PROFILES_FILE = ACCOUNTS_DIR / "profiles.json"
MAX_ACCOUNTS = 7

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


def refresh_token(account_num):
    """Refresh an account's OAuth token. Returns new token data or None."""
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
        print(
            f"  Token refresh failed: {err.get('error', {}).get('message', e.code)}",
            file=sys.stderr,
        )
        return None
    except Exception as e:
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
    cred_file.write_text(json.dumps(new_creds, indent=2))
    cred_file.chmod(0o600)

    return new_creds


# ─── Keychain Write ──────────────────────────────────────


def _keychain_service():
    """Get keychain service name for the current config dir.
    Default (no CLAUDE_CONFIG_DIR): 'Claude Code-credentials'
    Custom: 'Claude Code-credentials-{sha256(dir)[:8]}'"""
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    if config_dir:
        h = hashlib.sha256(config_dir.encode()).hexdigest()[:8]
        return f"Claude Code-credentials-{h}"
    return "Claude Code-credentials"


def write_keychain(creds):
    """Write credentials to macOS keychain (hex-encoded, same as CC)."""
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
    )
    return r.returncode == 0


# ─── Swap ────────────────────────────────────────────────


def swap_to(target_account):
    """Refresh target account's token and write to keychain.
    CC picks up new creds on next API call."""
    target_account = str(target_account)
    email = get_email(target_account)

    print(
        f"Refreshing token for account {target_account} ({email})...", file=sys.stderr
    )
    new_creds = refresh_token(target_account)
    if not new_creds:
        print(f"  Failed to refresh token", file=sys.stderr)
        return False

    if not write_keychain(new_creds):
        print(f"  Failed to write keychain", file=sys.stderr)
        return False

    # Invalidate PID cache
    ppid = os.getppid()
    cache_file = ACCOUNTS_DIR / f".account.{ppid}"
    cache_file.write_text(target_account)

    print(f"Swapped to account {target_account} ({email})", file=sys.stderr)
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
        if target:
            swap_to(target)


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
            swap_to(target)
        elif force:
            show_status()
            print("\nAll accounts exhausted.", file=sys.stderr)


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
