#!/usr/bin/env python3
"""
Claude Squad — Rotation Engine

Tracks quota across accounts. Auto-rotates by refreshing OAuth tokens
and writing to the per-terminal macOS keychain entry.

Each terminal runs CC with CLAUDE_CONFIG_DIR=~/.claude/accounts/config-N,
giving it a unique keychain entry: Claude Code-credentials-<sha256(dir)[:8]>.
Auto-rotate writes to THAT entry only — other terminals are unaffected.

State files (all in ~/.claude/accounts/):
  credentials/N.json   Stored OAuth credentials per account (1-7)
  profiles.json        Email→account mapping
  quota.json           Per-account quota from statusline
  config-N/            Per-account CC config dir (CLAUDE_CONFIG_DIR target)
  config-N/.current-account   Which account's creds are in this keychain slot

Commands:
  update               Update quota from statusline JSON (stdin)
  status               Show all accounts and quota
  statusline           Compact string for statusline display
  suggest              Suggest best account to switch to (JSON)
  swap <N>             Refresh account N's token and write to this terminal's keychain
  auto-rotate          Check + swap if current account is exhausted
  auto-rotate --force  Force-rotate (marks current exhausted first)
  check                JSON check: should this terminal rotate? (for hooks)
  init-keychain <N>    Write stored creds for account N to this terminal's keychain
  cleanup              Remove stale PID cache files
"""

import getpass
import hashlib
import json
import os
import subprocess
import sys
import time
import unicodedata
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


# ─── Account Detection ──────────────────────────────────


def _config_dir():
    """Get CLAUDE_CONFIG_DIR if set."""
    return os.environ.get("CLAUDE_CONFIG_DIR", "")


def which_account():
    """Which account is this terminal on?

    Fast path: reads .current-account from CLAUDE_CONFIG_DIR.
    Fallback: extracts from config dir name (config-N).
    Last resort: claude auth status --json.
    """
    config_dir = _config_dir()
    if config_dir:
        # Check .current-account file (updated after swaps)
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
    """Keychain service name for the current CLAUDE_CONFIG_DIR.
    Default (no config dir): 'Claude Code-credentials'
    With config dir: 'Claude Code-credentials-{sha256(dir)[:8]}'

    Uses NFC normalization to match CC's behavior."""
    config_dir = _config_dir()
    if config_dir:
        normalized = unicodedata.normalize("NFC", config_dir)
        h = hashlib.sha256(normalized.encode()).hexdigest()[:8]
        return f"Claude Code-credentials-{h}"
    return "Claude Code-credentials"


def write_keychain(creds):
    """Write credentials to macOS keychain for THIS terminal's config dir."""
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
    """Refresh target account's token and write to this terminal's keychain.
    Only this terminal is affected — other terminals have their own keychain entries."""
    target_account = str(target_account)
    email = get_email(target_account)

    print(
        f"Refreshing token for account {target_account} ({email})...", file=sys.stderr
    )
    new_creds = refresh_token(target_account)
    if not new_creds:
        print("  Failed to refresh token", file=sys.stderr)
        return False

    if not write_keychain(new_creds):
        print("  Failed to write keychain", file=sys.stderr)
        return False

    # Update .current-account tracker
    config_dir = _config_dir()
    if config_dir:
        try:
            (Path(config_dir) / ".current-account").write_text(target_account)
        except OSError:
            pass

    print(f"Swapped to account {target_account} ({email})", file=sys.stderr)
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
        else:
            show_status()
            print("\nAll accounts exhausted.", file=sys.stderr)


# ─── Quota Update ────────────────────────────────────────


def update_quota(json_str):
    """Called from statusline. Saves quota data for the current account."""
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

    # Auto-rotate at 100% (only if config dir is set)
    if _config_dir():
        five_pct = rate_limits.get("five_hour", {}).get("used_percentage", 0)
        if five_pct >= 100:
            target = pick_best(state, exclude=current)
            if target:
                swap_to(target)


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
            os.kill(pid, 0)
        except (ValueError, ProcessLookupError):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
        except PermissionError:
            pass
    remaining = len(list(ACCOUNTS_DIR.glob(".account.*")))
    print(f"Removed {removed} stale cache files. {remaining} remaining.")


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
        if not init_keychain(sys.argv[2]):
            sys.exit(1)
    elif cmd == "email":
        if len(sys.argv) >= 3:
            print(get_email(sys.argv[2]))
    elif cmd == "cleanup":
        cleanup()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
