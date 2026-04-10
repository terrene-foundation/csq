#!/usr/bin/env python3
"""
Dashboard — Proactive Token Refresher

Background thread that monitors OAuth token expiry for all Anthropic accounts
and refreshes tokens before they expire. Eliminates LOGIN-NEEDED in terminals.

Key behaviors:
- Checks expiresAt for all Anthropic accounts every 5 minutes
- Refreshes tokens proactively when they expire within 30 minutes
- Uses monotonicity guard to prevent conflicts with rotation-engine.py
- Atomic writes (temp file + os.replace) for credential safety
- File permissions set to 0o600 on credential files
- 10-minute cooldown after refresh failures

Coordinate with rotation-engine.py:
  The rotation engine also refreshes tokens. To prevent conflicts, this
  module reads the credential file BEFORE refreshing, then re-reads AFTER
  the HTTP refresh. If expiresAt is now NEWER than what we started with,
  another process beat us -- we skip the write.

No external dependencies -- stdlib only.
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


# ─── Constants ───────────────────────────────────────────

# How far ahead of expiry to trigger a refresh (30 minutes in seconds)
REFRESH_AHEAD_SECONDS = 1800

# How often to check all tokens (5 minutes in seconds)
CHECK_INTERVAL_SECONDS = 300

# How long to wait before retrying after a refresh failure (10 minutes)
COOLDOWN_AFTER_FAILURE_SECONDS = 600

# HTTP timeout for refresh requests
HTTP_TIMEOUT = 15

# OAuth constants (same as rotation-engine.py -- kept self-contained)
TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
SCOPES = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"


class TokenRefresher:
    """Background thread that proactively refreshes OAuth tokens.

    Monitors all Anthropic accounts and refreshes tokens before they
    expire, preventing LOGIN-NEEDED states in terminals.
    """

    def __init__(self, accounts, credentials_dir, token_url=None):
        """
        Args:
            accounts: List of AccountInfo objects (filters to anthropic only)
            credentials_dir: Path to the credentials/ directory
                (e.g., ~/.claude/accounts/credentials/)
            token_url: Override token endpoint URL (for testing)
        """
        self._accounts = list(accounts)
        self._credentials_dir = Path(credentials_dir)
        self._token_url = token_url or TOKEN_URL
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        # account_id -> epoch float of last failure
        self._failure_timestamps = {}
        # account_id -> epoch float of last successful refresh
        self._last_refresh = {}

    def start(self):
        """Start the background refresh-check thread."""
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="dashboard-refresher",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """Signal the background thread to stop."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def is_running(self):
        """Return True if the refresh thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def refresh_account(self, account_id):
        """Manually trigger a token refresh for one account.

        Args:
            account_id: The account identifier (e.g., "anthropic-1")

        Returns:
            dict with keys:
                success: bool
                reason: str (on failure)
                account_id: str
        """
        account = self._find_account(account_id)
        if account is None:
            return {
                "success": False,
                "reason": f"Account {account_id!r} not found",
                "account_id": account_id,
            }

        if account.provider != "anthropic":
            return {
                "success": False,
                "reason": f"Account {account_id!r} is not an Anthropic account (provider={account.provider!r})",
                "account_id": account_id,
            }

        # Check cooldown
        with self._lock:
            last_failure = self._failure_timestamps.get(account_id, 0)
        if time.time() - last_failure < COOLDOWN_AFTER_FAILURE_SECONDS:
            return {
                "success": False,
                "reason": "cooldown: refresh failed recently, waiting before retry",
                "account_id": account_id,
            }

        return self._do_refresh(account)

    def get_token_status(self, account_id):
        """Return token health status for one account.

        Args:
            account_id: The account identifier

        Returns:
            dict with keys:
                is_healthy: bool
                expires_in_seconds: int (seconds until expiry, negative if expired)
                last_refresh: float or None (epoch of last successful refresh)
                error: str (only on error conditions)
        """
        account = self._find_account(account_id)
        if account is None:
            return {
                "is_healthy": False,
                "error": f"Account {account_id!r} not found",
            }

        # Non-Anthropic accounts don't have OAuth token expiry
        if account.provider != "anthropic":
            return {
                "is_healthy": True,
                "expires_in_seconds": None,
                "last_refresh": None,
            }

        # Extract account number from ID (e.g., "anthropic-1" -> "1")
        account_num = account_id.split("-", 1)[-1]
        cred_file = self._credentials_dir / f"{account_num}.json"

        if not cred_file.exists():
            return {
                "is_healthy": False,
                "expires_in_seconds": 0,
                "last_refresh": None,
                "error": f"Credential file not found: {cred_file.name}",
            }

        try:
            data = json.loads(cred_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            return {
                "is_healthy": False,
                "expires_in_seconds": 0,
                "last_refresh": None,
                "error": f"Failed to read credential file: {exc}",
            }

        oauth = data.get("claudeAiOauth", {})
        expires_at_ms = oauth.get("expiresAt", 0)
        expires_at_s = expires_at_ms / 1000.0
        now = time.time()
        expires_in = expires_at_s - now

        with self._lock:
            last_refresh = self._last_refresh.get(account_id)

        return {
            "is_healthy": expires_in > REFRESH_AHEAD_SECONDS,
            "expires_in_seconds": int(expires_in),
            "last_refresh": last_refresh,
        }

    def get_all_token_statuses(self):
        """Return token status for all accounts.

        Returns:
            dict mapping account_id -> status dict
        """
        result = {}
        for account in self._accounts:
            result[account.id] = self.get_token_status(account.id)
        return result

    def _run_loop(self):
        """Main loop: check tokens and refresh if needed."""
        while not self._stop_event.is_set():
            for account in self._accounts:
                if self._stop_event.is_set():
                    return

                if account.provider != "anthropic":
                    continue

                status = self.get_token_status(account.id)
                if not status.get("is_healthy", True) and "error" not in status:
                    # Token needs refresh -- check cooldown first
                    with self._lock:
                        last_failure = self._failure_timestamps.get(account.id, 0)
                    if time.time() - last_failure >= COOLDOWN_AFTER_FAILURE_SECONDS:
                        result = self._do_refresh(account)
                        if result["success"]:
                            print(
                                f"[dashboard/refresher] Proactively refreshed token for {account.id}",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                f"[dashboard/refresher] WARN: Failed to refresh {account.id}: "
                                f"{result.get('reason', 'unknown')}",
                                file=sys.stderr,
                            )

            self._stop_event.wait(timeout=CHECK_INTERVAL_SECONDS)

    def _do_refresh(self, account):
        """Execute the token refresh flow for one account.

        1. Read current credentials
        2. POST to token endpoint with refresh_token
        3. Re-read credentials (monotonicity guard)
        4. If our pre-read expiresAt >= current file's expiresAt, write new creds
        5. Otherwise, another process beat us -- skip write

        Returns:
            dict with success, reason, account_id
        """
        account_id = account.id
        account_num = account_id.split("-", 1)[-1]
        cred_file = self._credentials_dir / f"{account_num}.json"

        # Step 1: Read current credentials
        if not cred_file.exists():
            return {
                "success": False,
                "reason": f"Credential file not found: {cred_file.name}",
                "account_id": account_id,
            }

        try:
            pre_data = json.loads(cred_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            return {
                "success": False,
                "reason": f"Failed to read credentials: {exc}",
                "account_id": account_id,
            }

        pre_oauth = pre_data.get("claudeAiOauth", {})
        refresh_token = pre_oauth.get("refreshToken")
        if not refresh_token:
            return {
                "success": False,
                "reason": "No refresh token in credential file",
                "account_id": account_id,
            }

        pre_expires_at = pre_oauth.get("expiresAt", 0)

        # Step 2: HTTP refresh
        http_result = self._do_http_refresh(account_num, refresh_token)
        if http_result is None:
            with self._lock:
                self._failure_timestamps[account_id] = time.time()
            return {
                "success": False,
                "reason": "Token refresh HTTP request failed",
                "account_id": account_id,
            }

        # Step 3: Re-read credentials (monotonicity guard)
        try:
            post_data = json.loads(cred_file.read_text())
            post_expires_at = post_data.get("claudeAiOauth", {}).get("expiresAt", 0)
        except (json.JSONDecodeError, OSError):
            post_expires_at = pre_expires_at

        # Step 4: Check if another process wrote newer credentials
        if post_expires_at > pre_expires_at:
            # Another process refreshed more recently -- skip our write
            print(
                f"[dashboard/refresher] Monotonicity guard: another process refreshed "
                f"{account_id} (post={post_expires_at} > pre={pre_expires_at}), skipping write",
                file=sys.stderr,
            )
            with self._lock:
                self._last_refresh[account_id] = time.time()
            return {
                "success": True,
                "reason": "Another process refreshed first (monotonicity guard)",
                "account_id": account_id,
            }

        # Step 5: Build and write new credentials
        access_token = http_result.get("access_token")
        new_refresh = http_result.get("refresh_token", refresh_token)
        expires_in = http_result.get("expires_in", 18000)

        if not access_token:
            with self._lock:
                self._failure_timestamps[account_id] = time.time()
            return {
                "success": False,
                "reason": "Token refresh response missing access_token",
                "account_id": account_id,
            }

        new_creds = {
            "claudeAiOauth": {
                "accessToken": access_token,
                "refreshToken": new_refresh,
                "expiresAt": int(time.time() * 1000) + expires_in * 1000,
                "scopes": SCOPES.split(),
                "subscriptionType": pre_oauth.get("subscriptionType"),
                "rateLimitTier": pre_oauth.get("rateLimitTier"),
            }
        }

        # Atomic write: temp file + os.replace
        self._atomic_write_credentials(cred_file, new_creds)

        # Update account's in-memory token
        account.token = access_token

        with self._lock:
            self._last_refresh[account_id] = time.time()

        token_prefix = access_token[:8] if len(access_token) > 8 else access_token[:4]
        print(
            f"[dashboard/refresher] Refreshed {account_id} "
            f"(token: {token_prefix}..., expires_in: {expires_in}s)",
            file=sys.stderr,
        )

        return {
            "success": True,
            "account_id": account_id,
        }

    def _do_http_refresh(self, account_num, refresh_token):
        """POST to the token endpoint to refresh an OAuth token.

        Args:
            account_num: Account number string (e.g., "1")
            refresh_token: Current refresh token

        Returns:
            dict with access_token, refresh_token, expires_in on success.
            None on failure.
        """
        body = json.dumps(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": CLIENT_ID,
                "scope": SCOPES,
            }
        ).encode()

        req = urllib.request.Request(
            self._token_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "claude-code/2.1.91",
            },
        )

        try:
            resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
            data = json.loads(resp.read().decode())
            return data
        except urllib.error.HTTPError as exc:
            try:
                err_body = json.loads(exc.read().decode()) if exc.code < 500 else {}
            except (json.JSONDecodeError, OSError):
                err_body = {}
            print(
                f"[dashboard/refresher] WARN: Token refresh failed for account {account_num}: "
                f"HTTP {exc.code} - {err_body.get('error', {}).get('message', exc.reason)}",
                file=sys.stderr,
            )
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            print(
                f"[dashboard/refresher] WARN: Token refresh error for account {account_num}: {exc}",
                file=sys.stderr,
            )
            return None

    def _atomic_write_credentials(self, cred_file, data):
        """Write credentials atomically: temp file -> os.replace.

        Also sets file permissions to 0o600.
        """
        cred_file = Path(cred_file)
        tmp_file = cred_file.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(data, indent=2))

        # Set secure permissions before replacing
        try:
            os.chmod(str(tmp_file), 0o600)
        except OSError:
            pass

        os.replace(str(tmp_file), str(cred_file))

        # Ensure final file also has correct permissions
        try:
            os.chmod(str(cred_file), 0o600)
        except OSError:
            pass

    def _find_account(self, account_id):
        """Find an AccountInfo by ID."""
        for acct in self._accounts:
            if acct.id == account_id:
                return acct
        return None
