#!/usr/bin/env python3
"""
Tier 1 (Unit) + Tier 2 (Integration) tests for dashboard/poller.py.

Tests the background polling engine: interval enforcement, rate-limit
respect, staggered polling, error handling (429, 401, timeout), and
exponential backoff.

Uses real threading and real temp directories — no mocks.
"""

import sys
import os
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.poller import (
    UsagePoller,
    poll_anthropic_usage,
    poll_3p_usage,
    ANTHROPIC_POLL_INTERVAL,
    THREEP_POLL_INTERVAL,
)
from dashboard.cache import UsageCache
from dashboard.accounts import AccountInfo


# ─── Helpers ─────────────────────────────────────────────


def _make_anthropic_account(account_num=1, token="sk-ant-oat01-test"):
    return AccountInfo(
        id=f"anthropic-{account_num}",
        label=f"Account {account_num}",
        provider="anthropic",
        token=token,
        base_url="https://api.anthropic.com",
    )


def _make_3p_account(provider="zai", token="zai-test-token"):
    return AccountInfo(
        id=provider,
        label=f"{provider.upper()} Account",
        provider=provider,
        token=token,
        base_url=f"https://api.{provider}.example/anthropic",
    )


class _MockUsageServer(BaseHTTPRequestHandler):
    """Minimal HTTP handler that returns canned usage responses."""

    # Class-level state so tests can control responses
    response_code = 200
    response_body = json.dumps(
        {
            "five_hour": {"utilization": 0.42, "resets_at": "2099-01-01T00:00:00Z"},
            "seven_day": {"utilization": 0.15, "resets_at": "2099-01-14T00:00:00Z"},
        }
    )
    response_headers = {}
    request_log = []

    def do_GET(self):
        _MockUsageServer.request_log.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "time": time.time(),
            }
        )
        self.send_response(_MockUsageServer.response_code)
        for k, v in _MockUsageServer.response_headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(_MockUsageServer.response_body.encode())

    def do_POST(self):
        # For 3P probe requests
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        _MockUsageServer.request_log.append(
            {
                "path": self.path,
                "method": "POST",
                "headers": dict(self.headers),
                "body": body.decode() if body else "",
                "time": time.time(),
            }
        )
        self.send_response(_MockUsageServer.response_code)
        for k, v in _MockUsageServer.response_headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = _MockUsageServer.response_body
        self.wfile.write(resp.encode() if isinstance(resp, str) else resp)

    def log_message(self, _format, *_args):
        pass  # Suppress server logs during tests


def _start_mock_server():
    """Start a mock HTTP server on a random port, return (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), _MockUsageServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# ─── Tier 1: Polling interval constants ──────────────────


def test_anthropic_poll_interval_is_at_least_300():
    """Anthropic polling must be at least 300s (5 min) to match claude.ai."""
    assert (
        ANTHROPIC_POLL_INTERVAL >= 300
    ), f"Anthropic poll interval {ANTHROPIC_POLL_INTERVAL}s is too aggressive, must be >= 300s"


def test_3p_poll_interval_is_at_least_900():
    """3P polling must be at least 900s (15 min) to minimize API costs."""
    assert (
        THREEP_POLL_INTERVAL >= 900
    ), f"3P poll interval {THREEP_POLL_INTERVAL}s is too short, must be >= 900s"


# ─── Tier 2: Anthropic usage polling ─────────────────────


def test_poll_anthropic_usage_parses_response():
    """poll_anthropic_usage correctly parses the usage endpoint response."""
    _MockUsageServer.response_code = 200
    _MockUsageServer.response_body = json.dumps(
        {
            "five_hour": {"utilization": 0.55, "resets_at": "2099-01-01T15:00:00Z"},
            "seven_day": {"utilization": 0.20, "resets_at": "2099-01-14T00:00:00Z"},
            "seven_day_opus": {
                "utilization": 0.08,
                "resets_at": "2099-01-14T00:00:00Z",
            },
            "seven_day_oauth_apps": {
                "utilization": 0.12,
                "resets_at": "2099-01-14T00:00:00Z",
            },
        }
    )
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        account = _make_anthropic_account()
        result = poll_anthropic_usage(
            account, base_url_override=f"http://127.0.0.1:{port}"
        )

        assert result is not None, "poll_anthropic_usage returned None on 200"
        assert "five_hour" in result, f"Missing five_hour in {result}"
        assert result["five_hour"]["utilization"] == 0.55
        assert "seven_day" in result
        assert "seven_day_opus" in result
        assert "seven_day_oauth_apps" in result
    finally:
        server.shutdown()


def test_poll_anthropic_usage_sends_correct_headers():
    """Must send Authorization: Bearer and anthropic-beta headers."""
    _MockUsageServer.response_code = 200
    _MockUsageServer.response_body = json.dumps(
        {
            "five_hour": {"utilization": 0.1, "resets_at": "2099-01-01T00:00:00Z"},
            "seven_day": {"utilization": 0.1, "resets_at": "2099-01-14T00:00:00Z"},
        }
    )
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        account = _make_anthropic_account(token="sk-ant-oat01-testtoken123")
        poll_anthropic_usage(account, base_url_override=f"http://127.0.0.1:{port}")

        assert len(_MockUsageServer.request_log) == 1, "Expected exactly 1 request"
        headers = _MockUsageServer.request_log[0]["headers"]
        auth = headers.get("Authorization", "")
        assert auth == "Bearer sk-ant-oat01-testtoken123", f"Bad auth header: {auth}"
        beta = headers.get("Anthropic-Beta", headers.get("anthropic-beta", ""))
        assert "oauth-2025-04-20" in beta, f"Missing anthropic-beta header: {beta}"
    finally:
        server.shutdown()


def test_poll_anthropic_usage_handles_429():
    """429 response returns None and signals rate limiting."""
    _MockUsageServer.response_code = 429
    _MockUsageServer.response_body = json.dumps({"error": "rate limited"})
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        account = _make_anthropic_account()
        result = poll_anthropic_usage(
            account, base_url_override=f"http://127.0.0.1:{port}"
        )
        assert (
            result is None or result.get("error") == "rate_limited"
        ), f"Expected None or rate_limited error on 429, got {result}"
    finally:
        server.shutdown()


def test_poll_anthropic_usage_handles_401():
    """401 response returns error indicating expired token."""
    _MockUsageServer.response_code = 401
    _MockUsageServer.response_body = json.dumps({"error": "unauthorized"})
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        account = _make_anthropic_account()
        result = poll_anthropic_usage(
            account, base_url_override=f"http://127.0.0.1:{port}"
        )
        assert (
            result is None or result.get("error") == "expired"
        ), f"Expected None or expired error on 401, got {result}"
    finally:
        server.shutdown()


# ─── Tier 2: 3P usage polling ───────────────────────────


def test_poll_3p_usage_captures_rate_limit_headers():
    """3P polling captures rate-limit headers from API response."""
    _MockUsageServer.response_code = 200
    _MockUsageServer.response_body = json.dumps(
        {
            "id": "msg_test",
            "content": [{"type": "text", "text": "hi"}],
            "role": "assistant",
            "model": "test",
            "type": "message",
        }
    )
    _MockUsageServer.response_headers = {
        "anthropic-ratelimit-requests-limit": "100",
        "anthropic-ratelimit-requests-remaining": "87",
        "anthropic-ratelimit-tokens-limit": "100000",
        "anthropic-ratelimit-tokens-remaining": "95000",
        "anthropic-ratelimit-input-tokens-limit": "80000",
        "anthropic-ratelimit-output-tokens-limit": "20000",
    }
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        account = _make_3p_account(provider="zai", token="zai-test")
        result = poll_3p_usage(account, base_url_override=f"http://127.0.0.1:{port}")

        assert result is not None, "poll_3p_usage returned None on 200"
        assert "rate_limits" in result, f"Missing rate_limits in {result}"
        rl = result["rate_limits"]
        assert rl.get("requests_limit") == 100
        assert rl.get("requests_remaining") == 87
        assert rl.get("tokens_limit") == 100000
        assert rl.get("tokens_remaining") == 95000
    finally:
        _MockUsageServer.response_headers = {}
        server.shutdown()


def test_poll_3p_usage_sends_minimal_request():
    """3P probe sends max_tokens: 1 to minimize cost."""
    _MockUsageServer.response_code = 200
    _MockUsageServer.response_body = json.dumps(
        {
            "id": "msg_test",
            "content": [{"type": "text", "text": "h"}],
            "role": "assistant",
            "model": "test",
            "type": "message",
        }
    )
    _MockUsageServer.response_headers = {}
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        account = _make_3p_account()
        poll_3p_usage(account, base_url_override=f"http://127.0.0.1:{port}")

        assert len(_MockUsageServer.request_log) >= 1
        req = _MockUsageServer.request_log[0]
        body = json.loads(req["body"])
        assert (
            body.get("max_tokens") == 1
        ), f"Expected max_tokens=1, got {body.get('max_tokens')}"
        assert body.get("messages"), "Missing messages in 3P probe"
    finally:
        server.shutdown()


# ─── Tier 2: UsagePoller lifecycle ───────────────────────


def test_poller_starts_and_stops():
    """UsagePoller can start a background thread and stop it cleanly."""
    cache = UsageCache()
    poller = UsagePoller(accounts=[], cache=cache)
    poller.start()
    assert poller.is_running(), "Poller should be running after start()"
    poller.stop()
    # Give the thread a moment to die
    time.sleep(0.1)
    assert not poller.is_running(), "Poller should be stopped after stop()"


def test_poller_respects_rate_limits_on_force_refresh():
    """force_refresh should skip accounts that were polled recently."""
    cache = UsageCache()
    account = _make_anthropic_account()
    # Pre-populate cache with fresh data
    cache.set(account.id, {"five_hour": {"utilization": 0.5}})

    poller = UsagePoller(accounts=[account], cache=cache)
    # last_poll_time set to now — should skip
    poller._last_poll_time[account.id] = time.time()

    skipped = poller.force_refresh()
    assert (
        account.id in skipped
    ), f"Expected {account.id} to be skipped (recently polled), skipped={skipped}"


def test_poller_updates_cache_on_successful_poll():
    """After a successful poll, the cache should contain the new data."""
    _MockUsageServer.response_code = 200
    _MockUsageServer.response_body = json.dumps(
        {
            "five_hour": {"utilization": 0.77, "resets_at": "2099-01-01T00:00:00Z"},
            "seven_day": {"utilization": 0.33, "resets_at": "2099-01-14T00:00:00Z"},
        }
    )
    _MockUsageServer.response_headers = {}
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        cache = UsageCache()
        account = _make_anthropic_account()
        poller = UsagePoller(
            accounts=[account],
            cache=cache,
            base_url_override=f"http://127.0.0.1:{port}",
        )
        # Do a single poll cycle manually
        poller._poll_account(account)

        cached = cache.get(account.id)
        assert cached is not None, "Cache should have data after poll"
        assert cached["five_hour"]["utilization"] == 0.77
    finally:
        server.shutdown()


def test_poller_marks_account_expired_on_401():
    """401 sets account status to 'expired'."""
    _MockUsageServer.response_code = 401
    _MockUsageServer.response_body = json.dumps({"error": "unauthorized"})
    _MockUsageServer.response_headers = {}
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        cache = UsageCache()
        account = _make_anthropic_account()
        poller = UsagePoller(
            accounts=[account],
            cache=cache,
            base_url_override=f"http://127.0.0.1:{port}",
        )
        poller._poll_account(account)

        assert (
            account.status == "expired"
        ), f"Expected status 'expired', got '{account.status}'"
    finally:
        server.shutdown()


def test_poller_backs_off_on_429():
    """429 increases the next poll interval for that account (exponential backoff)."""
    _MockUsageServer.response_code = 429
    _MockUsageServer.response_body = json.dumps({"error": "rate limited"})
    _MockUsageServer.response_headers = {}
    _MockUsageServer.request_log = []
    server, port = _start_mock_server()
    try:
        cache = UsageCache()
        account = _make_anthropic_account()
        poller = UsagePoller(
            accounts=[account],
            cache=cache,
            base_url_override=f"http://127.0.0.1:{port}",
        )
        initial_interval = poller._get_poll_interval(account)
        poller._poll_account(account)
        new_interval = poller._get_poll_interval(account)

        assert (
            new_interval > initial_interval
        ), f"Expected backoff: initial={initial_interval}, after 429={new_interval}"
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
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
