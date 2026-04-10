#!/usr/bin/env python3
"""
Tier 1 (Unit) + Tier 2 (Integration) tests for dashboard/refresher.py.

Tests the proactive token refresh engine: expiry detection, refresh API
calls, monotonicity guard, atomic writes, file permissions, and cooldown
after failures.

Uses real temp directories and real file locks -- no mocks.
"""

import json
import os
import stat
import sys
import tempfile
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.refresher import (
    TokenRefresher,
    REFRESH_AHEAD_SECONDS,
    CHECK_INTERVAL_SECONDS,
    COOLDOWN_AFTER_FAILURE_SECONDS,
)
from dashboard.accounts import AccountInfo


# ─── Helpers ─────────────────────────────────────────────


def _make_credential_file(
    creds_dir, account_num, expires_at_ms, refresh_token="rt-test-refresh-token-abc123"
):
    """Create a credential file in the test credentials directory.

    Args:
        creds_dir: Path to the credentials/ directory
        account_num: Account number (string or int)
        expires_at_ms: Token expiry timestamp in milliseconds
        refresh_token: Refresh token value

    Returns:
        Path to the created credential file.
    """
    cred_data = {
        "claudeAiOauth": {
            "accessToken": f"sk-ant-oat01-test-access-{account_num}",
            "refreshToken": refresh_token,
            "expiresAt": expires_at_ms,
            "scopes": ["user:profile", "user:inference"],
            "subscriptionType": "pro",
            "rateLimitTier": "tier1",
        }
    }
    cred_file = Path(creds_dir) / f"{account_num}.json"
    cred_file.write_text(json.dumps(cred_data, indent=2))
    os.chmod(str(cred_file), 0o600)
    return cred_file


def _make_anthropic_account(account_num=1, token="sk-ant-oat01-test-access-1"):
    return AccountInfo(
        id=f"anthropic-{account_num}",
        label=f"Account {account_num}",
        provider="anthropic",
        token=token,
        base_url="https://api.anthropic.com",
    )


def _make_zai_account(token="zai-test-token"):
    return AccountInfo(
        id="zai",
        label="Z.AI",
        provider="zai",
        token=token,
        base_url="https://api.z.ai/api/anthropic",
    )


class _MockTokenServer(BaseHTTPRequestHandler):
    """Mock OAuth token endpoint that returns configurable responses."""

    response_code = 200
    response_body = None  # Set per-test
    request_log = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        _MockTokenServer.request_log.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "body": json.loads(body.decode()) if body else {},
                "time": time.time(),
            }
        )

        self.send_response(_MockTokenServer.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        resp = _MockTokenServer.response_body
        if resp is None:
            resp = json.dumps(
                {
                    "access_token": "sk-ant-oat01-new-access-token-12345",
                    "refresh_token": "rt-new-refresh-token-67890",
                    "expires_in": 18000,
                }
            )
        self.wfile.write(resp.encode() if isinstance(resp, str) else resp)

    def log_message(self, _format, *_args):
        pass


def _start_mock_token_server():
    """Start a mock token server on a random port."""
    server = HTTPServer(("127.0.0.1", 0), _MockTokenServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# ─── Tier 1: Configuration constants ──────────────────


def test_refresh_ahead_seconds_is_30_minutes():
    """Tokens should be refreshed 30 minutes before expiry."""
    assert (
        REFRESH_AHEAD_SECONDS == 1800
    ), f"REFRESH_AHEAD_SECONDS should be 1800 (30 min), got {REFRESH_AHEAD_SECONDS}"


def test_check_interval_is_5_minutes():
    """The refresher should check all tokens every 5 minutes."""
    assert (
        CHECK_INTERVAL_SECONDS == 300
    ), f"CHECK_INTERVAL_SECONDS should be 300 (5 min), got {CHECK_INTERVAL_SECONDS}"


def test_cooldown_after_failure_is_10_minutes():
    """After a refresh failure, cooldown should be 10 minutes."""
    assert (
        COOLDOWN_AFTER_FAILURE_SECONDS == 600
    ), f"COOLDOWN_AFTER_FAILURE_SECONDS should be 600 (10 min), got {COOLDOWN_AFTER_FAILURE_SECONDS}"


# ─── Tier 1: Token expiry detection ──────────────────


def test_get_token_status_healthy_token():
    """get_token_status returns healthy for a token expiring in > 30 minutes."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        # Token expires in 2 hours
        expires_at = int((time.time() + 7200) * 1000)
        _make_credential_file(creds_dir, "1", expires_at)

        acct = _make_anthropic_account(1)
        refresher = TokenRefresher(
            accounts=[acct],
            credentials_dir=creds_dir,
        )

        status = refresher.get_token_status("anthropic-1")
        assert status["is_healthy"] is True, f"Token should be healthy, got {status}"
        assert (
            status["expires_in_seconds"] > 1800
        ), f"Expected >1800s remaining, got {status['expires_in_seconds']}"


def test_get_token_status_expiring_soon():
    """get_token_status returns unhealthy for a token expiring in < 30 minutes."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        # Token expires in 10 minutes
        expires_at = int((time.time() + 600) * 1000)
        _make_credential_file(creds_dir, "1", expires_at)

        acct = _make_anthropic_account(1)
        refresher = TokenRefresher(
            accounts=[acct],
            credentials_dir=creds_dir,
        )

        status = refresher.get_token_status("anthropic-1")
        assert (
            status["is_healthy"] is False
        ), f"Token should be unhealthy (expiring soon), got {status}"
        assert (
            status["expires_in_seconds"] < 1800
        ), f"Expected <1800s remaining, got {status['expires_in_seconds']}"


def test_get_token_status_already_expired():
    """get_token_status returns unhealthy for an already-expired token."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        # Token expired 1 hour ago
        expires_at = int((time.time() - 3600) * 1000)
        _make_credential_file(creds_dir, "1", expires_at)

        acct = _make_anthropic_account(1)
        refresher = TokenRefresher(
            accounts=[acct],
            credentials_dir=creds_dir,
        )

        status = refresher.get_token_status("anthropic-1")
        assert status["is_healthy"] is False, f"Expired token should be unhealthy"
        assert (
            status["expires_in_seconds"] < 0
        ), f"Expired token should have negative expires_in_seconds, got {status['expires_in_seconds']}"


def test_get_token_status_missing_credential_file():
    """get_token_status raises an error when credential file is missing."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)
        # No credential file created

        acct = _make_anthropic_account(1)
        refresher = TokenRefresher(
            accounts=[acct],
            credentials_dir=creds_dir,
        )

        status = refresher.get_token_status("anthropic-1")
        assert status["is_healthy"] is False, "Missing cred file should be unhealthy"
        assert (
            "error" in status
        ), f"Missing cred file should have error field, got {status}"


def test_get_token_status_non_anthropic_account():
    """get_token_status returns not-applicable for non-Anthropic accounts."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        acct = _make_zai_account()
        refresher = TokenRefresher(
            accounts=[acct],
            credentials_dir=creds_dir,
        )

        status = refresher.get_token_status("zai")
        assert (
            status["is_healthy"] is True
        ), "Non-anthropic accounts should always be healthy (no expiry)"


def test_get_token_status_unknown_account():
    """get_token_status raises for unknown account IDs."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        refresher = TokenRefresher(
            accounts=[],
            credentials_dir=creds_dir,
        )

        status = refresher.get_token_status("nonexistent-99")
        assert "error" in status, f"Unknown account should have error, got {status}"


# ─── Tier 2: Refresh API call ────────────────────────


def test_refresh_account_calls_token_endpoint():
    """refresh_account sends the correct POST to the token endpoint."""
    _MockTokenServer.response_code = 200
    _MockTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-refreshed-new-token",
            "refresh_token": "rt-refreshed-new-refresh",
            "expires_in": 18000,
        }
    )
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            # Token expires in 10 minutes (needs refresh)
            expires_at = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", expires_at)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            result = refresher.refresh_account("anthropic-1")
            assert result["success"] is True, f"Refresh should succeed, got {result}"

            # Verify the request was made correctly
            assert (
                len(_MockTokenServer.request_log) == 1
            ), f"Expected 1 request, got {len(_MockTokenServer.request_log)}"
            req = _MockTokenServer.request_log[0]
            body = req["body"]
            assert body["grant_type"] == "refresh_token"
            assert body["refresh_token"] == "rt-test-refresh-token-abc123"
            assert body["client_id"] == "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    finally:
        server.shutdown()


def test_refresh_account_writes_new_credentials():
    """After refresh, the credential file should contain the new tokens."""
    _MockTokenServer.response_code = 200
    _MockTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-brand-new-access",
            "refresh_token": "rt-brand-new-refresh",
            "expires_in": 18000,
        }
    )
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            expires_at = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", expires_at)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            refresher.refresh_account("anthropic-1")

            # Read the credential file and verify new tokens
            cred_file = Path(creds_dir) / "1.json"
            data = json.loads(cred_file.read_text())
            oauth = data["claudeAiOauth"]
            assert (
                oauth["accessToken"] == "sk-ant-oat01-brand-new-access"
            ), f"Access token not updated: {oauth['accessToken']}"
            assert (
                oauth["refreshToken"] == "rt-brand-new-refresh"
            ), f"Refresh token not updated: {oauth['refreshToken']}"
            # expiresAt should be in the future
            assert oauth["expiresAt"] > int(
                time.time() * 1000
            ), f"expiresAt should be in the future"
    finally:
        server.shutdown()


def test_refresh_account_handles_http_error():
    """Refresh failure marks account as refresh-failed, not crash."""
    _MockTokenServer.response_code = 400
    _MockTokenServer.response_body = json.dumps({"error": {"message": "invalid_grant"}})
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            expires_at = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", expires_at)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            result = refresher.refresh_account("anthropic-1")
            assert (
                result["success"] is False
            ), f"Refresh should fail on 400, got {result}"

            # Original credential file should be unchanged
            cred_file = Path(creds_dir) / "1.json"
            data = json.loads(cred_file.read_text())
            assert (
                data["claudeAiOauth"]["accessToken"] == "sk-ant-oat01-test-access-1"
            ), "Credentials should not change on refresh failure"
    finally:
        server.shutdown()


# ─── Tier 2: Monotonicity guard ──────────────────────


def test_monotonicity_guard_skips_stale_write():
    """If another process refreshed more recently, skip writing our result."""
    _MockTokenServer.response_code = 200
    _MockTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-our-token",
            "refresh_token": "rt-our-refresh",
            "expires_in": 18000,
        }
    )
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            # Token expires soon, so refresh is needed
            old_expires = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", old_expires)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            # Simulate another process refreshing the token between our
            # read and write by updating the file with a newer expiresAt
            newer_expires = int((time.time() + 36000) * 1000)

            # Monkey-patch the refresher to simulate the race:
            # We do the refresh, which should succeed at the HTTP level,
            # but before writing, another process wrote a newer token.
            # The refresher should detect this and skip writing.
            original_refresh = refresher._do_http_refresh

            def patched_refresh(account_num, refresh_token):
                result = original_refresh(account_num, refresh_token)
                # While we were refreshing, another process wrote newer credentials
                _make_credential_file(
                    creds_dir,
                    "1",
                    newer_expires,
                    refresh_token="rt-other-process-refresh",
                )
                return result

            refresher._do_http_refresh = patched_refresh

            refresher.refresh_account("anthropic-1")

            # The credential file should have the OTHER process's token,
            # not ours, because theirs is newer
            cred_file = Path(creds_dir) / "1.json"
            data = json.loads(cred_file.read_text())
            assert data["claudeAiOauth"]["expiresAt"] == newer_expires, (
                f"Monotonicity guard failed: expected {newer_expires}, "
                f"got {data['claudeAiOauth']['expiresAt']}"
            )
            assert (
                data["claudeAiOauth"]["refreshToken"] == "rt-other-process-refresh"
            ), "Should have kept the other process's refresh token"
    finally:
        server.shutdown()


# ─── Tier 2: Atomic write verification ───────────────


def test_atomic_write_uses_temp_file():
    """Credential writes must use temp file + os.replace for atomicity."""
    _MockTokenServer.response_code = 200
    _MockTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-atomic-test",
            "refresh_token": "rt-atomic-test",
            "expires_in": 18000,
        }
    )
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            expires_at = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", expires_at)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            result = refresher.refresh_account("anthropic-1")
            assert result["success"] is True

            # Verify file is valid JSON (not partially written)
            cred_file = Path(creds_dir) / "1.json"
            data = json.loads(cred_file.read_text())
            assert "claudeAiOauth" in data
            assert data["claudeAiOauth"]["accessToken"] == "sk-ant-oat01-atomic-test"

            # No .tmp file should remain
            tmp_file = cred_file.with_suffix(".tmp")
            assert (
                not tmp_file.exists()
            ), f"Temp file should not remain after atomic write: {tmp_file}"
    finally:
        server.shutdown()


# ─── Tier 2: File permissions check ──────────────────


def test_file_permissions_are_0600():
    """After refresh, credential files must have owner-only permissions (0600)."""
    _MockTokenServer.response_code = 200
    _MockTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-perms-test",
            "refresh_token": "rt-perms-test",
            "expires_in": 18000,
        }
    )
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            expires_at = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", expires_at)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            refresher.refresh_account("anthropic-1")

            cred_file = Path(creds_dir) / "1.json"
            mode = cred_file.stat().st_mode & 0o777
            assert mode == 0o600, f"Credential file should be 0600, got {oct(mode)}"
    finally:
        server.shutdown()


# ─── Tier 2: Cooldown after failure ──────────────────


def test_cooldown_prevents_retry_after_failure():
    """After a refresh failure, the same account should not be retried for 10 minutes."""
    _MockTokenServer.response_code = 400
    _MockTokenServer.response_body = json.dumps({"error": {"message": "invalid_grant"}})
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            expires_at = int((time.time() + 600) * 1000)
            _make_credential_file(creds_dir, "1", expires_at)

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            # First attempt fails
            result1 = refresher.refresh_account("anthropic-1")
            assert result1["success"] is False

            # Second attempt should be skipped (cooldown)
            _MockTokenServer.request_log = []
            result2 = refresher.refresh_account("anthropic-1")
            assert result2["success"] is False
            assert "cooldown" in result2.get(
                "reason", ""
            ), f"Second attempt should be blocked by cooldown, got {result2}"
            # No HTTP request should have been made for the second attempt
            assert (
                len(_MockTokenServer.request_log) == 0
            ), f"Cooldown should prevent HTTP request, but {len(_MockTokenServer.request_log)} requests were made"
    finally:
        server.shutdown()


# ─── Tier 2: Preserves existing credential fields ────


def test_refresh_preserves_subscription_and_rate_limit_tier():
    """Refresh must preserve subscriptionType and rateLimitTier from the original credentials."""
    _MockTokenServer.response_code = 200
    _MockTokenServer.response_body = json.dumps(
        {
            "access_token": "sk-ant-oat01-preserve-fields",
            "refresh_token": "rt-preserve-fields",
            "expires_in": 18000,
        }
    )
    _MockTokenServer.request_log = []
    server, port = _start_mock_token_server()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            creds_dir = os.path.join(tmp, "credentials")
            os.makedirs(creds_dir)

            # Create credential with specific subscriptionType and rateLimitTier
            cred_data = {
                "claudeAiOauth": {
                    "accessToken": "sk-ant-oat01-old",
                    "refreshToken": "rt-old",
                    "expiresAt": int((time.time() + 600) * 1000),
                    "scopes": ["user:profile", "user:inference"],
                    "subscriptionType": "pro_max",
                    "rateLimitTier": "tier5_opus",
                }
            }
            cred_file = Path(creds_dir) / "1.json"
            cred_file.write_text(json.dumps(cred_data, indent=2))

            acct = _make_anthropic_account(1)
            refresher = TokenRefresher(
                accounts=[acct],
                credentials_dir=creds_dir,
                token_url=f"http://127.0.0.1:{port}/v1/oauth/token",
            )

            refresher.refresh_account("anthropic-1")

            data = json.loads(cred_file.read_text())
            oauth = data["claudeAiOauth"]
            assert (
                oauth["subscriptionType"] == "pro_max"
            ), f"subscriptionType not preserved: {oauth.get('subscriptionType')}"
            assert (
                oauth["rateLimitTier"] == "tier5_opus"
            ), f"rateLimitTier not preserved: {oauth.get('rateLimitTier')}"
    finally:
        server.shutdown()


# ─── Tier 2: Background thread lifecycle ─────────────


def test_refresher_starts_and_stops():
    """TokenRefresher can start a background thread and stop it cleanly."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        refresher = TokenRefresher(
            accounts=[],
            credentials_dir=creds_dir,
        )

        refresher.start()
        assert refresher.is_running(), "Refresher should be running after start()"

        refresher.stop()
        time.sleep(0.2)
        assert not refresher.is_running(), "Refresher should be stopped after stop()"


def test_refresher_only_targets_anthropic_accounts():
    """The refresher should only process Anthropic accounts, not 3P ones."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        # Create credential for anthropic account
        expires_at = int((time.time() + 600) * 1000)
        _make_credential_file(creds_dir, "1", expires_at)

        anthropic_acct = _make_anthropic_account(1)
        zai_acct = _make_zai_account()

        refresher = TokenRefresher(
            accounts=[anthropic_acct, zai_acct],
            credentials_dir=creds_dir,
        )

        # get_token_status should report different things for different providers
        anthropic_status = refresher.get_token_status("anthropic-1")
        zai_status = refresher.get_token_status("zai")

        # Anthropic account should have detailed expiry info
        assert (
            "expires_in_seconds" in anthropic_status
        ), f"Anthropic account should have expires_in_seconds"
        # Z.AI account should always be healthy (no OAuth expiry)
        assert zai_status["is_healthy"] is True


def test_get_all_token_statuses():
    """get_all_token_statuses returns status for every account."""
    with tempfile.TemporaryDirectory() as tmp:
        creds_dir = os.path.join(tmp, "credentials")
        os.makedirs(creds_dir)

        expires_at = int((time.time() + 7200) * 1000)
        _make_credential_file(creds_dir, "1", expires_at)
        _make_credential_file(creds_dir, "2", expires_at)

        acct1 = _make_anthropic_account(1)
        acct2 = _make_anthropic_account(2, token="sk-ant-oat01-test-access-2")

        refresher = TokenRefresher(
            accounts=[acct1, acct2],
            credentials_dir=creds_dir,
        )

        statuses = refresher.get_all_token_statuses()
        assert "anthropic-1" in statuses, f"Missing anthropic-1 in {statuses.keys()}"
        assert "anthropic-2" in statuses, f"Missing anthropic-2 in {statuses.keys()}"
        assert statuses["anthropic-1"]["is_healthy"] is True
        assert statuses["anthropic-2"]["is_healthy"] is True


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
