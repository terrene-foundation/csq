#!/usr/bin/env python3
"""
Tier 2 (Integration) + Tier 3 (E2E) tests for dashboard/server.py.

Tests the HTTP server endpoints, static file serving, and API responses.
Uses real HTTP connections against a real server instance.
"""

import sys
import os
import json
import threading
import tempfile
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.server import create_server
from dashboard.cache import UsageCache
from dashboard.accounts import AccountInfo


# ─── Helpers ─────────────────────────────────────────────


def _start_test_server(cache=None, accounts=None, port=0):
    """Start a dashboard server on a random port for testing.
    Returns (server, port, base_url)."""
    if cache is None:
        cache = UsageCache()
    if accounts is None:
        accounts = []

    server = create_server(
        host="127.0.0.1",
        port=port,
        cache=cache,
        accounts=accounts,
        start_poller=False,  # Don't start background polling in tests
    )
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port, f"http://127.0.0.1:{actual_port}"


def _get(url, timeout=5):
    """GET request, returns (status_code, headers, body_str)."""
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode()
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return e.code, dict(e.headers), body


def _post(url, data=None, timeout=5):
    """POST request with JSON body, returns (status_code, headers, body_str)."""
    body_bytes = json.dumps(data).encode() if data else b""
    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode()
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return e.code, dict(e.headers), body


def _make_account(id="anthropic-1", label="Account 1", provider="anthropic"):
    return AccountInfo(
        id=id,
        label=label,
        provider=provider,
        token="sk-ant-oat01-testtoken",
        base_url="https://api.anthropic.com",
    )


# ─── Tier 2: Static file serving ────────────────────────


def test_root_serves_index_html():
    """GET / returns the dashboard HTML page."""
    server, _, base = _start_test_server()
    try:
        status, headers, body = _get(f"{base}/")
        assert status == 200, f"Expected 200, got {status}"
        assert "text/html" in headers.get(
            "Content-Type", ""
        ), f"Expected text/html, got {headers.get('Content-Type')}"
        assert "<html" in body.lower(), "Response should contain HTML"
    finally:
        server.shutdown()


def test_static_css_served():
    """GET /static/style.css returns the stylesheet."""
    server, _, base = _start_test_server()
    try:
        status, headers, _ = _get(f"{base}/static/style.css")
        assert status == 200, f"Expected 200, got {status}"
        assert "text/css" in headers.get(
            "Content-Type", ""
        ), f"Expected text/css content type"
    finally:
        server.shutdown()


def test_static_js_served():
    """GET /static/dashboard.js returns the JavaScript."""
    server, _, base = _start_test_server()
    try:
        status, headers, _ = _get(f"{base}/static/dashboard.js")
        assert status == 200, f"Expected 200, got {status}"
        ct = headers.get("Content-Type", "")
        assert (
            "javascript" in ct or "text/plain" in ct
        ), f"Expected javascript content type, got {ct}"
    finally:
        server.shutdown()


def test_404_for_unknown_path():
    """GET /nonexistent returns 404."""
    server, _, base = _start_test_server()
    try:
        status, _, _ = _get(f"{base}/nonexistent")
        assert status == 404, f"Expected 404, got {status}"
    finally:
        server.shutdown()


# ─── Tier 2: API endpoints ──────────────────────────────


def test_api_accounts_returns_json():
    """GET /api/accounts returns a JSON array of accounts."""
    acct = _make_account()
    cache = UsageCache()
    cache.set(
        acct.id,
        {
            "five_hour": {"utilization": 0.42, "resets_at": "2099-01-01T00:00:00Z"},
            "seven_day": {"utilization": 0.15, "resets_at": "2099-01-14T00:00:00Z"},
        },
    )

    server, _, base = _start_test_server(cache=cache, accounts=[acct])
    try:
        status, headers, body = _get(f"{base}/api/accounts")
        assert status == 200, f"Expected 200, got {status}"
        assert "application/json" in headers.get("Content-Type", "")

        data = json.loads(body)
        assert isinstance(data, dict), f"Expected dict response, got {type(data)}"
        assert "accounts" in data, f"Missing 'accounts' key in {data.keys()}"
        accounts = data["accounts"]
        assert len(accounts) >= 1, f"Expected at least 1 account, got {len(accounts)}"

        acct_data = accounts[0]
        assert "id" in acct_data
        assert "label" in acct_data
        assert "provider" in acct_data
        assert "status" in acct_data
    finally:
        server.shutdown()


def test_api_accounts_includes_usage_data():
    """GET /api/accounts includes cached usage for each account."""
    acct = _make_account()
    cache = UsageCache()
    cache.set(
        acct.id,
        {
            "five_hour": {"utilization": 0.65, "resets_at": "2099-01-01T15:00:00Z"},
            "seven_day": {"utilization": 0.30, "resets_at": "2099-01-14T00:00:00Z"},
        },
    )

    server, _, base = _start_test_server(cache=cache, accounts=[acct])
    try:
        status, _, body = _get(f"{base}/api/accounts")
        data = json.loads(body)
        acct_data = data["accounts"][0]
        assert (
            "usage" in acct_data
        ), f"Missing 'usage' in account data: {acct_data.keys()}"
        usage = acct_data["usage"]
        assert "five_hour" in usage, f"Missing five_hour in usage: {usage}"
        assert usage["five_hour"]["utilization"] == 0.65
    finally:
        server.shutdown()


def test_api_accounts_no_full_tokens():
    """API responses must NEVER contain full tokens."""
    acct = _make_account()
    acct.token = "sk-ant-oat01-SUPERSECRETTOKEN123456"
    cache = UsageCache()

    server, _, base = _start_test_server(cache=cache, accounts=[acct])
    try:
        _, _, body = _get(f"{base}/api/accounts")
        assert (
            "SUPERSECRETTOKEN123456" not in body
        ), "Full token leaked in API response!"
        assert (
            "sk-ant-oat01-SUPER" not in body
        ), "Too much of the token is visible in the response"
    finally:
        server.shutdown()


def test_api_account_detail():
    """GET /api/account/{id}/usage returns detailed usage for one account."""
    acct = _make_account(id="anthropic-3")
    cache = UsageCache()
    cache.set(
        "anthropic-3",
        {
            "five_hour": {"utilization": 0.88, "resets_at": "2099-01-01T15:00:00Z"},
            "seven_day": {"utilization": 0.45, "resets_at": "2099-01-14T00:00:00Z"},
            "seven_day_opus": {
                "utilization": 0.10,
                "resets_at": "2099-01-14T00:00:00Z",
            },
        },
    )

    server, _, base = _start_test_server(cache=cache, accounts=[acct])
    try:
        status, _, body = _get(f"{base}/api/account/anthropic-3/usage")
        assert status == 200, f"Expected 200, got {status}"
        data = json.loads(body)
        assert "five_hour" in data, f"Missing five_hour in detail: {data}"
        assert data["five_hour"]["utilization"] == 0.88
        assert "seven_day_opus" in data
    finally:
        server.shutdown()


def test_api_account_detail_404_for_unknown():
    """GET /api/account/nonexistent/usage returns 404."""
    server, _, base = _start_test_server()
    try:
        status, _, _ = _get(f"{base}/api/account/nonexistent/usage")
        assert status == 404, f"Expected 404, got {status}"
    finally:
        server.shutdown()


def test_api_refresh_returns_status():
    """GET /api/refresh triggers a refresh and returns status."""
    cache = UsageCache()
    acct = _make_account()
    server, _, base = _start_test_server(cache=cache, accounts=[acct])
    try:
        status, _, body = _get(f"{base}/api/refresh")
        assert status == 200, f"Expected 200, got {status}"
        data = json.loads(body)
        assert "status" in data, f"Missing 'status' in refresh response: {data}"
    finally:
        server.shutdown()


def test_post_accounts_adds_manual_account():
    """POST /api/accounts adds a new manual account."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir = os.path.join(tmp, ".claude", "accounts")
        os.makedirs(accounts_dir, exist_ok=True)

        cache = UsageCache()
        server, _, base = _start_test_server(cache=cache, accounts=[])
        # Inject accounts_dir into handler
        server.accounts_dir = accounts_dir
        try:
            status, _, body = _post(
                f"{base}/api/accounts",
                data={
                    "label": "My Custom Account",
                    "token": "sk-custom-123",
                    "provider": "anthropic",
                    "base_url": "https://api.anthropic.com",
                },
            )
            assert status == 200 or status == 201, f"Expected 200/201, got {status}"
            data = json.loads(body)
            assert "id" in data, f"Missing 'id' in response: {data}"
            assert data["id"].startswith("manual-")
        finally:
            server.shutdown()


def test_post_accounts_rejects_missing_fields():
    """POST /api/accounts with missing required fields returns 400."""
    cache = UsageCache()
    server, _, base = _start_test_server(cache=cache)
    try:
        status, _, body = _post(f"{base}/api/accounts", data={"label": "Incomplete"})
        assert status == 400, f"Expected 400 for missing fields, got {status}"
    finally:
        server.shutdown()


# ─── Tier 2: Server binds to localhost only ──────────────


def test_server_binds_to_localhost():
    """Server must bind to 127.0.0.1 by default for security."""
    cache = UsageCache()
    server = create_server(
        host="127.0.0.1",
        port=0,
        cache=cache,
        accounts=[],
        start_poller=False,
    )
    host, port = server.server_address
    assert host == "127.0.0.1", f"Server bound to {host}, expected 127.0.0.1"
    server.server_close()


# ─── Tier 3: E2E dashboard flow ─────────────────────────


def test_e2e_full_dashboard_flow():
    """E2E: Load dashboard, fetch accounts, check data flow."""
    acct1 = _make_account(id="anthropic-1", label="Account 1")
    acct2 = _make_account(id="anthropic-2", label="Account 2")
    cache = UsageCache()
    cache.set(
        "anthropic-1",
        {
            "five_hour": {"utilization": 0.30, "resets_at": "2099-01-01T15:00:00Z"},
            "seven_day": {"utilization": 0.10, "resets_at": "2099-01-14T00:00:00Z"},
        },
    )
    cache.set(
        "anthropic-2",
        {
            "five_hour": {"utilization": 0.85, "resets_at": "2099-01-01T15:00:00Z"},
            "seven_day": {"utilization": 0.60, "resets_at": "2099-01-14T00:00:00Z"},
        },
    )

    server, _, base = _start_test_server(cache=cache, accounts=[acct1, acct2])
    try:
        # Step 1: Load dashboard
        status, _, body = _get(f"{base}/")
        assert status == 200, "Dashboard page failed to load"
        assert "Claude Squad" in body, "Dashboard title missing"

        # Step 2: Fetch accounts API
        status, _, body = _get(f"{base}/api/accounts")
        assert status == 200
        data = json.loads(body)
        assert len(data["accounts"]) == 2

        # Step 3: Check individual account detail
        status, _, body = _get(f"{base}/api/account/anthropic-2/usage")
        assert status == 200
        detail = json.loads(body)
        assert detail["five_hour"]["utilization"] == 0.85

        # Step 4: Fetch static assets
        for path in ["/static/style.css", "/static/dashboard.js"]:
            status, _, _ = _get(f"{base}{path}")
            assert status == 200, f"Static asset {path} returned {status}"

    finally:
        server.shutdown()


def test_e2e_last_updated_timestamp():
    """E2E: API response includes last_updated timestamp for each account."""
    acct = _make_account()
    cache = UsageCache()
    cache.set(
        acct.id,
        {
            "five_hour": {"utilization": 0.5, "resets_at": "2099-01-01T00:00:00Z"},
        },
    )

    server, _, base = _start_test_server(cache=cache, accounts=[acct])
    try:
        status, _, body = _get(f"{base}/api/accounts")
        data = json.loads(body)
        acct_data = data["accounts"][0]
        assert (
            "last_updated" in acct_data
        ), f"Missing last_updated in account data: {acct_data.keys()}"
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
