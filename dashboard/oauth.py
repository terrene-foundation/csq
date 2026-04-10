#!/usr/bin/env python3
"""
Dashboard — OAuth PKCE Login Flow

Implements the OAuth 2.0 Authorization Code flow with PKCE for adding
new Anthropic accounts via the dashboard.

The flow:
1. Dashboard generates a PKCE code_verifier + code_challenge
2. Dashboard returns an authorize URL for the browser
3. User authorizes in their browser
4. Anthropic redirects to localhost callback with an auth code
5. Dashboard exchanges the auth code for tokens using code_verifier
6. Dashboard writes tokens to credentials/{N}.json

Security:
- PKCE prevents authorization code interception
- State parameter prevents CSRF
- Each state is single-use (consumed on callback)
- Credentials written atomically with 0o600 permissions
- Never logs full tokens

No external dependencies -- stdlib only.
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# ─── OAuth Constants (same as rotation-engine.py) ────────

OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_SCOPES = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
OAUTH_AUTHORIZE_URL = "https://platform.claude.com/v1/oauth/authorize"

# HTTP timeout for token exchange requests
HTTP_TIMEOUT = 15


class OAuthLogin:
    """Manages OAuth PKCE login flow for adding accounts via the dashboard.

    Usage:
        oauth = OAuthLogin(credentials_dir="/path/to/credentials")
        result = oauth.start_login(account_num=3)
        # User opens result["auth_url"] in browser
        # After redirect, call:
        callback_result = oauth.handle_callback(code="...", state=result["state"])
    """

    def __init__(
        self, credentials_dir, redirect_port=8420, token_url=None, authorize_url=None
    ):
        """
        Args:
            credentials_dir: Path to the credentials/ directory
            redirect_port: Port for the localhost OAuth callback
            token_url: Override token endpoint URL (for testing)
            authorize_url: Override authorize endpoint URL (for testing)
        """
        self._credentials_dir = Path(credentials_dir)
        self._redirect_port = redirect_port
        self._token_url = token_url or OAUTH_TOKEN_URL
        self._authorize_url = authorize_url or OAUTH_AUTHORIZE_URL
        # state -> {code_verifier, code_challenge, account_num, created_at}
        self._pending_logins = {}

    def start_login(self, account_num):
        """Start an OAuth login flow for the given account number.

        Generates PKCE code verifier/challenge and builds the authorize URL.

        Args:
            account_num: The account slot number (1-8)

        Returns:
            dict with keys:
                auth_url: str - URL to open in the browser
                state: str - State parameter for CSRF protection

        Raises:
            ValueError: If account_num is invalid
        """
        if not isinstance(account_num, int) or account_num < 1:
            raise ValueError(
                f"account_num must be a positive integer, got {account_num!r}"
            )

        # Generate PKCE values
        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)

        # Generate unique state for CSRF protection
        state = secrets.token_urlsafe(32)

        # Store pending login
        self._pending_logins[state] = {
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "account_num": account_num,
            "created_at": time.time(),
        }

        # Build redirect URI
        redirect_uri = f"http://127.0.0.1:{self._redirect_port}/oauth/callback"

        # Build authorize URL
        params = {
            "client_id": OAUTH_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": OAUTH_SCOPES,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        auth_url = f"{self._authorize_url}?{urllib.parse.urlencode(params)}"

        return {
            "auth_url": auth_url,
            "state": state,
        }

    def handle_callback(self, code, state):
        """Handle the OAuth callback after user authorization.

        Exchanges the authorization code for tokens and writes credentials.

        Args:
            code: The authorization code from the callback
            state: The state parameter from the callback

        Returns:
            dict with keys:
                success: bool
                account_num: int (on success)
                error: str (on failure)
        """
        # Validate state (CSRF protection)
        pending = self._pending_logins.pop(state, None)
        if pending is None:
            return {
                "success": False,
                "error": f"Unknown or already-used state parameter",
            }

        account_num = pending["account_num"]
        code_verifier = pending["code_verifier"]

        # Build redirect URI (must match what was sent in the authorize request)
        redirect_uri = f"http://127.0.0.1:{self._redirect_port}/oauth/callback"

        # Exchange authorization code for tokens
        token_data = self._exchange_code(code, code_verifier, redirect_uri)
        if token_data is None:
            return {
                "success": False,
                "error": "Token exchange failed",
                "account_num": account_num,
            }

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 18000)

        if not access_token:
            return {
                "success": False,
                "error": "Token response missing access_token",
                "account_num": account_num,
            }

        # Build credential data
        cred_data = {
            "claudeAiOauth": {
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "expiresAt": int(time.time() * 1000) + expires_in * 1000,
                "scopes": OAUTH_SCOPES.split(),
            }
        }

        # Write credential file atomically
        cred_file = self._credentials_dir / f"{account_num}.json"
        self._atomic_write_credentials(cred_file, cred_data)

        token_prefix = access_token[:8] if len(access_token) > 8 else access_token[:4]
        print(
            f"[dashboard/oauth] Logged in account {account_num} "
            f"(token: {token_prefix}...)",
            file=sys.stderr,
        )

        return {
            "success": True,
            "account_num": account_num,
        }

    def _exchange_code(self, code, code_verifier, redirect_uri):
        """Exchange an authorization code for tokens via POST to token endpoint.

        Args:
            code: The authorization code
            code_verifier: The PKCE code verifier
            redirect_uri: The redirect URI used in the authorize request

        Returns:
            dict with access_token, refresh_token, expires_in on success.
            None on failure.
        """
        body = json.dumps(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": OAUTH_CLIENT_ID,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
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
                f"[dashboard/oauth] WARN: Token exchange failed: "
                f"HTTP {exc.code} - {err_body.get('error', exc.reason)}",
                file=sys.stderr,
            )
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            print(
                f"[dashboard/oauth] WARN: Token exchange error: {exc}",
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

    @staticmethod
    def _generate_code_verifier():
        """Generate a cryptographically random PKCE code verifier.

        Returns a URL-safe base64-encoded string of 32 random bytes (43 chars).
        RFC 7636 requires 43-128 characters.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def _generate_code_challenge(verifier):
        """Generate the PKCE code challenge from a code verifier.

        challenge = base64url(sha256(verifier))

        Args:
            verifier: The code verifier string

        Returns:
            base64url-encoded SHA256 hash of the verifier (no padding)
        """
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
