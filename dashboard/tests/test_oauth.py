#!/usr/bin/env python3
"""
Tier 1 (Unit) + Tier 2 (Integration) tests for dashboard/oauth.py.

Tests the OAuth PKCE login flow: code verifier/challenge generation,
authorize URL construction, callback handling, token exchange, and
credential file writing.

Uses real temp directories and real HTTP servers -- no mocks.
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.oauth import OAuthLogin, OAUTH_CLIENT_ID, OAUTH_SCOPES


# ─── Helpers ─────────────────────────────────────────────


class _MockOAuthTokenServer(BaseHTTPRequestHandler):
    """Mock OAuth token endpoint for testing the code exchange."""

    response_code = 200
    response_body = None
    request_log = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        _MockOAuthTokenServer.request_log.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "body": json.loads(body.decode()) if body else {},
                "time": time.time(),
            }
        )

        self.send_response(_MockOAuthTokenServer.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        resp = _MockOAuthTokenServer.response_body
        if resp is None:
            resp = json.dumps(
                {
                    "access_token": "sk-ant-oat01-oauth-new-access",
                    "refresh_token": "rt-oauth-new-refresh",
                    "expires_in": 18000,
                }
            )
        self.wfile.write(resp.encode() if isinstance(resp, str) else resp)

    def log_message(self, _format, *_args):
        pass


def _start_mock_oauth_server():
    server = HTTPServer(("127.0.0.1", 0), _MockOAuthTokenServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# ─── Tier 1: OAuth constants ─────────────────────────


def test_oauth_client_id_matches_rotation_engine():
    """The OAuth client ID must match what rotation-engine.py uses."""
    assert (
        OAUTH_CLIENT_ID == "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    ), f"Client ID mismatch: {OAUTH_CLIENT_ID}"


def test_oauth_scopes_match_rotation_engine():
    """The OAuth scopes must match what rotation-engine.py uses."""
    expected = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
    assert OAUTH_SCOPES == expected, f"Scopes mismatch: {OAUTH_SCOPES}"


# ─── Tier 1: PKCE code generation ────────────────────


def test_start_login_returns_auth_url():
    """start_login generates an authorization URL with PKCE parameters."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        oauth = OAuthLogin(credentials_dir=creds_dir)
        result = oauth.start_login(account_num=1)

        assert "auth_url" in result, f"Missing auth_url in {result.keys()}"
        assert "state" in result, f"Missing state in {result.keys()}"

        url = result["auth_url"]
        assert "code_challenge=" in url, f"Missing code_challenge in URL: {url}"
        assert "code_challenge_method=S256" in url, f"Missing S256 in URL: {url}"
        assert "response_type=code" in url, f"Missing response_type=code in URL: {url}"
        assert OAUTH_CLIENT_ID in url, f"Missing client_id in URL: {url}"


def test_start_login_generates_unique_state():
    """Each call to start_login should produce a unique state value."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        oauth = OAuthLogin(credentials_dir=creds_dir)
        result1 = oauth.start_login(account_num=1)
        result2 = oauth.start_login(account_num=2)

        assert (
            result1["state"] != result2["state"]
        ), "Each login should have a unique state for CSRF protection"


def test_start_login_includes_redirect_uri():
    """The auth URL must include a redirect_uri pointing to localhost."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        oauth = OAuthLogin(credentials_dir=creds_dir, redirect_port=9999)
        result = oauth.start_login(account_num=1)

        url = result["auth_url"]
        assert "redirect_uri=" in url, f"Missing redirect_uri in URL"
        assert (
            "127.0.0.1%3A9999" in url or "127.0.0.1:9999" in url
        ), f"Redirect URI should point to 127.0.0.1:9999, URL: {url}"


def test_pkce_challenge_is_sha256_of_verifier():
    """The code_challenge must be the base64url-encoded SHA256 of the verifier."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        oauth = OAuthLogin(credentials_dir=creds_dir)
        result = oauth.start_login(account_num=1)
        state = result["state"]

        # Access the internal pending login to get the verifier
        pending = oauth._pending_logins.get(state)
        assert pending is not None, f"No pending login for state {state}"

        verifier = pending["code_verifier"]
        # Compute expected challenge
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        )

        challenge = pending["code_challenge"]
        assert (
            challenge == expected_challenge
        ), f"PKCE challenge mismatch: got {challenge}, expected {expected_challenge}"


def test_start_login_validates_account_num():
    """start_login must reject invalid account numbers."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        oauth = OAuthLogin(credentials_dir=creds_dir)

        try:
            oauth.start_login(account_num=0)
            assert False, "Should have raised ValueError for account_num=0"
        except ValueError:
            pass

        try:
            oauth.start_login(account_num=-1)
            assert False, "Should have raised ValueError for negative account_num"
        except ValueError:
            pass


# ─── Tier 2: Token exchange (callback handling) ──────


def test_handle_callback_exchanges_code_for_tokens():
    """handle_callback sends the auth code to the token endpoint and gets tokens."""
    _MockOAuthTokenServer.response_code = 200
    _MockOAuthTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-exchanged-token",
            "refresh_token": "rt-exchanged-refresh",
            "expires_in": 18000,
        }
    )
    _MockOAuthTokenServer.request_log = []
    server, port = _start_mock_oauth_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            oauth = OAuthLogin(
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            # Start login to create pending state
            login_result = oauth.start_login(account_num=3)
            state = login_result["state"]

            # Simulate callback with an authorization code
            callback_result = oauth.handle_callback(
                code="auth-code-from-anthropic-xyz",
                state=state,
            )

            assert (
                callback_result["success"] is True
            ), f"Callback should succeed, got {callback_result}"
            assert callback_result["account_num"] == 3

            # Verify the token exchange request
            assert len(_MockOAuthTokenServer.request_log) == 1
            req = _MockOAuthTokenServer.request_log[0]
            body = req["body"]
            assert body["grant_type"] == "authorization_code"
            assert body["code"] == "auth-code-from-anthropic-xyz"
            assert body["client_id"] == OAUTH_CLIENT_ID
            assert "code_verifier" in body, "Must include code_verifier for PKCE"
    finally:
        server.shutdown()


def test_handle_callback_writes_credential_file():
    """After successful token exchange, credentials are written to disk."""
    _MockOAuthTokenServer.response_code = 200
    _MockOAuthTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-callback-written",
            "refresh_token": "rt-callback-written",
            "expires_in": 18000,
        }
    )
    _MockOAuthTokenServer.request_log = []
    server, port = _start_mock_oauth_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            oauth = OAuthLogin(
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            login_result = oauth.start_login(account_num=5)
            state = login_result["state"]
            oauth.handle_callback(code="test-auth-code", state=state)

            # Verify credential file was created
            cred_file = Path(creds_dir) / "5.json"
            assert cred_file.exists(), f"Credential file not created at {cred_file}"

            data = json.loads(cred_file.read_text())
            oauth_data = data["claudeAiOauth"]
            assert oauth_data["accessToken"] == "sk-ant-oat01-callback-written"
            assert oauth_data["refreshToken"] == "rt-callback-written"
            assert oauth_data["expiresAt"] > int(time.time() * 1000)
    finally:
        server.shutdown()


def test_handle_callback_sets_file_permissions():
    """Credential file from OAuth login must have 0600 permissions."""
    _MockOAuthTokenServer.response_code = 200
    _MockOAuthTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-perms-callback",
            "refresh_token": "rt-perms-callback",
            "expires_in": 18000,
        }
    )
    _MockOAuthTokenServer.request_log = []
    server, port = _start_mock_oauth_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            oauth = OAuthLogin(
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            login_result = oauth.start_login(account_num=2)
            state = login_result["state"]
            oauth.handle_callback(code="perms-test-code", state=state)

            cred_file = Path(creds_dir) / "2.json"
            mode = cred_file.stat().st_mode & 0o777
            assert mode == 0o600, f"Credential file should be 0600, got {oct(mode)}"
    finally:
        server.shutdown()


def test_handle_callback_rejects_unknown_state():
    """handle_callback must reject callbacks with unknown state (CSRF protection)."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        oauth = OAuthLogin(credentials_dir=creds_dir)

        result = oauth.handle_callback(
            code="some-code",
            state="completely-unknown-state",
        )

        assert result["success"] is False, f"Should reject unknown state, got {result}"
        assert "error" in result, f"Should have error message, got {result}"


def test_handle_callback_rejects_reused_state():
    """A state value must not be usable twice (replay protection)."""
    _MockOAuthTokenServer.response_code = 200
    _MockOAuthTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-replay-test",
            "refresh_token": "rt-replay-test",
            "expires_in": 18000,
        }
    )
    _MockOAuthTokenServer.request_log = []
    server, port = _start_mock_oauth_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            oauth = OAuthLogin(
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            login_result = oauth.start_login(account_num=1)
            state = login_result["state"]

            # First callback succeeds
            result1 = oauth.handle_callback(code="first-code", state=state)
            assert result1["success"] is True

            # Second callback with same state must fail
            result2 = oauth.handle_callback(code="second-code", state=state)
            assert (
                result2["success"] is False
            ), f"Reused state should be rejected, got {result2}"
    finally:
        server.shutdown()


def test_handle_callback_handles_token_endpoint_error():
    """If the token endpoint returns an error, handle_callback reports failure."""
    _MockOAuthTokenServer.response_code = 400
    _MockOAuthTokenServer.response_body = json.dumps(
        {
            "error": "invalid_grant",
            "error_description": "Authorization code expired",
        }
    )
    _MockOAuthTokenServer.request_log = []
    server, port = _start_mock_oauth_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            oauth = OAuthLogin(
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            login_result = oauth.start_login(account_num=1)
            state = login_result["state"]

            result = oauth.handle_callback(code="expired-code", state=state)
            assert (
                result["success"] is False
            ), f"Should report failure on token endpoint error, got {result}"
            # No credential file should be created
            cred_file = Path(creds_dir) / "1.json"
            assert (
                not cred_file.exists()
            ), "Credential file should not be created on token exchange failure"
    finally:
        server.shutdown()


def test_handle_callback_uses_atomic_write():
    """Credential file from OAuth login must use atomic writes (no .tmp leftovers)."""
    _MockOAuthTokenServer.response_code = 200
    _MockOAuthTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-atomic-oauth",
            "refresh_token": "rt-atomic-oauth",
            "expires_in": 18000,
        }
    )
    _MockOAuthTokenServer.request_log = []
    server, port = _start_mock_oauth_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            oauth = OAuthLogin(
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            login_result = oauth.start_login(account_num=4)
            state = login_result["state"]
            oauth.handle_callback(code="atomic-test-code", state=state)

            # Verify no .tmp files remain
            tmp_file = Path(creds_dir) / "4.tmp"
            assert not tmp_file.exists(), f"Temp file should not remain: {tmp_file}"

            # Verify the file is valid JSON
            cred_file = Path(creds_dir) / "4.json"
            data = json.loads(cred_file.read_text())
            assert "claudeAiOauth" in data
    finally:
        server.shutdown()


# ─── Runner ──────────────────────────────────────────────

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test_fn in tests:
        name = test_fn.__name__
        try:
            test_fn()
            print(f"  PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name} -- {e}")
            import traceback

            traceback.print_exc()
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
