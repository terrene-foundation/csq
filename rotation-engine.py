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
  snapshot             Refresh .current-account from keychain on CC restart (statusline hook)
  cleanup              Remove stale PID cache files
"""

import fcntl
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
    """Atomic write: temp file + rename. Sets 600 permissions."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.chmod(0o600)
    tmp.rename(path)


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

    NOTE: .current-account reflects the account whose OAuth token is in the
    *running* CC instance, NOT what the keychain currently holds. The
    statusline `snapshot` command keeps it accurate by detecting CC restarts
    via PID and re-reading the keychain only then. swap_to() deliberately
    does NOT touch this file — its writes only take effect on CC restart.
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
# Why this exists: csq swap rewrites the macOS keychain entry for this
# config dir. The statusline runs in our process, not CC's, so we use a
# per-CC-process snapshot to know which account is "live" for a given CC.
# done mid-session updates the keychain and .current-account, but the
# We detect "new CC process" via .live-pid: if the PID is dead or absent, the
# status line then displays the wrong account.
#
# The fix: stop writing .current-account from swap_to(). Instead, snapshot
# the keychain → .current-account exactly once per CC process, triggered
# from the statusline hook. We detect "new CC process" via .live-pid: if
# the recorded PID is dead or absent, the next snapshot reads the keychain
# fresh and identifies the account it holds. While the same CC process is
# alive, the snapshot is a single os.kill probe and a no-op.


def _is_pid_alive(pid):
    """Return True if the given PID exists. PermissionError means the
    process exists but is owned by another user — still alive."""
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (ValueError, OSError):
        return False
    return True


def _find_cc_pid():
    """Walk the parent process tree from this Python process upward,
    returning the PID of the first ancestor that looks like the Claude Code
    CLI. Skips csq/rotation-engine/statusline helpers in the chain.

    Used by snapshot_account() to identify "the CC process that owns this
    statusline invocation" so its lifetime can act as the snapshot key.
    """
    pid = os.getppid()
    for _ in range(20):  # Bounded depth to avoid runaway loops
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
        cmd = parts[1].lower()
        # Match Claude Code CLI; exclude our own helper processes.
        if (
            "claude" in cmd
            and "claude-squad" not in cmd
            and "rotation-engine" not in cmd
            and "statusline" not in cmd
            and "/csq" not in cmd
            and " csq" not in cmd
        ):
            return pid
        pid = ppid
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


def csq_account_marker():
    """Read the .csq-account marker from <CLAUDE_CONFIG_DIR>.

    This is the PRIMARY source of truth for "which account does csq think
    is loaded in this config dir". csq writes it from `csq run N` and
    `csq swap N` — both operations csq fully controls, so the marker is
    always correct relative to csq's intent. The snapshot then promotes
    the marker into .current-account at CC startup time (gated by PID).

    Why a separate marker instead of token-matching .credentials.json:
    .credentials.json may be updated by token refresh during a session,
    to .credentials.json. The new token won't match credentials/N.json
    anymore, so token-based identification would silently fail. The
    marker is durable across refreshes because the account number doesn't
    change just because the token rotates.
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
        tmp.rename(marker)
        return True
    except OSError:
        return False


def keychain_account():
    """Read the macOS keychain entry for this config dir and identify which
    stored credential file holds a matching access token. Used as a fallback
    by snapshot_account() when .credentials.json is missing — historically
    csq used the keychain as the only credential store, and some older
    setups may not have a .credentials.json yet.
    """
    service = _keychain_service()
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-w"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    raw = r.stdout.strip()
    if not raw:
        return None

    # The password is normally stored as a JSON string. swap_to() writes it
    # via `security add-generic-password -X <hex>`, where -X tells security
    # to interpret the input as hex and store the decoded bytes — so on read
    # we get the JSON directly. Defensive fallback: try hex-decoding too.
    kc_data = None
    try:
        kc_data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            kc_data = json.loads(bytes.fromhex(raw).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None

    return _match_token_to_account(
        kc_data.get("claudeAiOauth", {}).get("accessToken", "")
    )


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
    # Atomic write to prevent credential corruption on crash
    tmp = cred_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(new_creds, indent=2))
    tmp.chmod(0o600)
    tmp.rename(cred_file)

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
        tmp.chmod(0o600)
        tmp.rename(cred_path)
        return True
    except OSError:
        return False


# ─── Swap ────────────────────────────────────────────────


def swap_to(target_account):
    """Swap this terminal to target account.

    Reuses the existing access token if still valid; only refreshes when
    expired. Writes ONLY per-config-dir state — never the macOS keychain —
    so 15+ concurrent csq terminals don't contend on a global resource.

    Files written (all under <CLAUDE_CONFIG_DIR>/):
      .credentials.json    OAuth creds — picked up by CC on next interaction
      .csq-account         account number marker (durable across refreshes)

    IMPORTANT: Does NOT touch .current-account. The snapshot owns that file.
    If a CC process is already running for this CLAUDE_CONFIG_DIR, its
    OAuth credentials are loaded from .credentials.json when CC starts.
    its startup time — rewriting either file now will not affect the
    running process. CC must be restarted for the swap to take effect. We
    detect that situation and print a clear warning so the user isn't
    fooled by a status line that promotes the new marker prematurely.
    """
    target_account = str(target_account)
    email = get_email(target_account)

    # Try to reuse existing token if it's still valid (with a 5-minute safety
    # buffer). The OAuth refresh endpoint is shared across all accounts on
    # this client_id and gets aggressively throttled by Anthropic — only call
    # it when truly needed.
    cred_file = CREDS_DIR / f"{target_account}.json"
    new_creds = None
    if cred_file.exists():
        try:
            existing = json.loads(cred_file.read_text())
            oauth = existing.get("claudeAiOauth", {})
            expires_at = oauth.get("expiresAt", 0)
            now_ms = int(time.time() * 1000)
            buffer_ms = 5 * 60 * 1000  # 5 minutes
            if oauth.get("accessToken") and expires_at > now_ms + buffer_ms:
                remaining_min = (expires_at - now_ms) / 60_000
                print(
                    f"Using cached token for account {target_account} ({email}) — valid {remaining_min:.0f}m",
                    file=sys.stderr,
                )
                new_creds = existing
        except (OSError, json.JSONDecodeError):
            pass

    if new_creds is None:
        print(
            f"Refreshing token for account {target_account} ({email})...",
            file=sys.stderr,
        )
        new_creds = refresh_token(target_account)
        if not new_creds:
            print("  Failed to refresh token", file=sys.stderr)
            return False

    config_dir = _config_dir()
    if not config_dir:
        print(
            "  csq swap requires CLAUDE_CONFIG_DIR (run from a csq terminal).",
            file=sys.stderr,
        )
        return False

    # Write .credentials.json — this is the actual swap. If this fails,
    # actual swap. If this fails, the swap is a no-op and we report failure.
    if not write_credentials_file(new_creds):
        print(
            f"  Failed to write {config_dir}/.credentials.json — swap aborted.",
            file=sys.stderr,
        )
        return False

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

    # If a CC process is already running with this config dir, neither file
    # rewrite affects the active session. Warn the user so they know to
    # restart CC.
    stale_cc = False
    pid_file = Path(config_dir) / ".live-pid"
    live_account_file = Path(config_dir) / ".current-account"
    try:
        if pid_file.exists():
            live_pid = pid_file.read_text().strip()
            if live_pid and _is_pid_alive(live_pid):
                live_account = ""
                if live_account_file.exists():
                    try:
                        live_account = live_account_file.read_text().strip()
                    except OSError:
                        pass
                if live_account and live_account != target_account:
                    stale_cc = True
                    print(
                        f"\n  WARNING: CC process {live_pid} in this config dir is still using account {live_account}.",
                        file=sys.stderr,
                    )
                    print(
                        f"  .credentials.json and .csq-account now point at account {target_account}, but CC won't pick it up until restart.",
                        file=sys.stderr,
                    )
    except OSError:
        pass

    if stale_cc:
        print(
            f"Swapped to account {target_account} ({email}) — restart CC to activate.",
            file=sys.stderr,
        )
    else:
        print(
            f"Swapped to account {target_account} ({email})",
            file=sys.stderr,
        )
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
        lock_file = QUOTA_FILE.with_suffix(".lock")
        lock_fd = None
        try:
            lock_fd = open(lock_file, "w")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            raw = _load(QUOTA_FILE, {"accounts": {}})
            raw.setdefault("accounts", {}).setdefault(current, {})["five_hour"] = {
                "used_percentage": 100,
                "resets_at": time.time() + 18000,
            }
            _save(QUOTA_FILE, raw)
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    lock_fd.close()
                except Exception:
                    pass

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
    Uses file locking to prevent concurrent terminals from clobbering each other."""
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

    # Lock, load, modify, save, unlock — prevents concurrent terminal races
    lock_file = QUOTA_FILE.with_suffix(".lock")
    lock_fd = None
    try:
        lock_fd = open(lock_file, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = _load(QUOTA_FILE, {"accounts": {}})
        state.setdefault("accounts", {})[current] = {
            "five_hour": rate_limits.get("five_hour", {}),
            "seven_day": rate_limits.get("seven_day", {}),
            "updated_at": time.time(),
        }
        _save(QUOTA_FILE, state)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
            except Exception:
                pass

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
    elif cmd == "email":
        if len(sys.argv) >= 3:
            _validate_account(sys.argv[2])
            print(get_email(sys.argv[2]))
    elif cmd == "cleanup":
        cleanup()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
