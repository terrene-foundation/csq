#!/usr/bin/env python3
"""
Dashboard — HTTP Server

Serves the dashboard UI and API endpoints using stdlib http.server.

Endpoints:
    GET  /                          → static/index.html
    GET  /static/{file}             → static files (css, js)
    GET  /api/accounts              → list all accounts with usage + token health
    GET  /api/account/{id}/usage    → detailed usage for one account
    GET  /api/refresh               → force refresh all accounts
    GET  /api/tokens                → token health for all accounts
    GET  /api/login/{N}             → start OAuth login flow for account N
    GET  /oauth/callback            → OAuth redirect handler
    POST /api/accounts              → add a manual account
    POST /api/refresh-token/{id}    → manually trigger token refresh

Binds to 127.0.0.1 only (local access). No authentication required
since it runs locally on the developer's machine.

No external dependencies — stdlib only.
"""

import json
import os
import re
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from .accounts import AccountInfo, discover_all_accounts, save_manual_account
from .cache import UsageCache
from .oauth import OAuthLogin
from .poller import UsagePoller
from .refresher import TokenRefresher

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"

# MIME types for static files
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".svg": "image/svg+xml",
}

# Default port
DEFAULT_PORT = 8420


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "":
            self._serve_static("index.html")
        elif path.startswith("/static/"):
            filename = path[len("/static/") :]
            self._serve_static(filename)
        elif path == "/api/accounts":
            self._handle_api_accounts()
        elif path.startswith("/api/account/") and path.endswith("/usage"):
            # Extract account ID from /api/account/{id}/usage
            match = re.match(r"^/api/account/([^/]+)/usage$", path)
            if match:
                self._handle_api_account_detail(match.group(1))
            else:
                self._send_404()
        elif path == "/api/refresh":
            self._handle_api_refresh()
        elif path == "/api/tokens":
            self._handle_api_tokens()
        elif path.startswith("/api/login/"):
            # Extract account number from /api/login/{N}
            account_num_str = path[len("/api/login/") :]
            self._handle_api_login(account_num_str)
        elif path == "/oauth/callback":
            self._handle_oauth_callback(parsed)
        else:
            self._send_404()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/accounts":
            self._handle_post_account()
        elif path.startswith("/api/refresh-token/"):
            account_id = path[len("/api/refresh-token/") :]
            self._handle_api_refresh_token(account_id)
        else:
            self._send_404()

    # ─── API handlers ────────────────────────────────────

    def _handle_api_accounts(self):
        """GET /api/accounts — list all accounts with current usage and token health."""
        server = self.server
        accounts = getattr(server, "dashboard_accounts", [])
        cache = getattr(server, "dashboard_cache", UsageCache())
        refresher = getattr(server, "dashboard_refresher", None)

        result = []
        for acct in accounts:
            acct_dict = acct.to_dict()
            cached_usage = cache.get(
                acct.id, max_age_seconds=7200
            )  # 2hr staleness window for display
            if cached_usage is not None:
                acct_dict["usage"] = cached_usage
            else:
                acct_dict["usage"] = None
            ts = cache.get_timestamp(acct.id)
            acct_dict["last_updated"] = ts

            # Include token health if refresher is available
            if refresher is not None:
                acct_dict["token_health"] = refresher.get_token_status(acct.id)
            result.append(acct_dict)

        self._send_json(200, {"accounts": result})

    def _handle_api_account_detail(self, account_id):
        """GET /api/account/{id}/usage — detailed usage for one account."""
        server = self.server
        accounts = getattr(server, "dashboard_accounts", [])
        cache = getattr(server, "dashboard_cache", UsageCache())

        # Verify account exists
        found = any(a.id == account_id for a in accounts)
        if not found:
            self._send_json(404, {"error": f"Account {account_id!r} not found"})
            return

        cached_usage = cache.get(account_id, max_age_seconds=7200)
        if cached_usage is None:
            self._send_json(200, {"message": "No usage data available yet"})
            return

        self._send_json(200, cached_usage)

    def _handle_api_refresh(self):
        """GET /api/refresh — trigger force refresh of all accounts."""
        server = self.server
        poller = getattr(server, "dashboard_poller", None)

        if poller is None:
            self._send_json(
                200, {"status": "no_poller", "message": "Poller not running"}
            )
            return

        results = poller.force_refresh()
        self._send_json(200, {"status": "ok", "results": results})

    def _handle_post_account(self):
        """POST /api/accounts — add a manual account."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json(400, {"error": "Empty request body"})
            return

        try:
            body = self.rfile.read(content_length)
            data = json.loads(body.decode())
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json(400, {"error": f"Invalid JSON: {exc}"})
            return

        # Validate required fields
        required = ["label", "token", "provider", "base_url"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            self._send_json(
                400, {"error": f"Missing required fields: {', '.join(missing)}"}
            )
            return

        server = self.server
        accounts_dir = getattr(server, "accounts_dir", None)
        if accounts_dir is None:
            # Default to ~/.claude/accounts/
            accounts_dir = str(Path.home() / ".claude" / "accounts")

        try:
            new_acct = save_manual_account(
                accounts_dir=accounts_dir,
                label=data["label"],
                token=data["token"],
                provider=data["provider"],
                base_url=data["base_url"],
            )
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        # Add to live accounts list and poller
        accounts = getattr(server, "dashboard_accounts", [])
        accounts.append(new_acct)
        poller = getattr(server, "dashboard_poller", None)
        if poller:
            poller.add_account(new_acct)

        self._send_json(200, {"id": new_acct.id, "label": new_acct.label})

    def _handle_api_tokens(self):
        """GET /api/tokens — token health for all accounts."""
        server = self.server
        refresher = getattr(server, "dashboard_refresher", None)

        if refresher is None:
            self._send_json(
                200,
                {
                    "tokens": {},
                    "auto_refresh": False,
                    "message": "Token refresher not running",
                },
            )
            return

        statuses = refresher.get_all_token_statuses()
        self._send_json(
            200,
            {
                "tokens": statuses,
                "auto_refresh": refresher.is_running(),
            },
        )

    def _handle_api_refresh_token(self, account_id):
        """POST /api/refresh-token/{id} — manually trigger token refresh."""
        server = self.server
        refresher = getattr(server, "dashboard_refresher", None)

        if refresher is None:
            self._send_json(
                200,
                {
                    "success": False,
                    "reason": "Token refresher not configured",
                    "account_id": account_id,
                },
            )
            return

        result = refresher.refresh_account(account_id)
        self._send_json(200, result)

    def _handle_api_login(self, account_num_str):
        """GET /api/login/{N} — start OAuth login flow for account N."""
        server = self.server
        oauth = getattr(server, "dashboard_oauth", None)

        if oauth is None:
            self._send_json(500, {"error": "OAuth login not configured"})
            return

        # Validate account number
        if not account_num_str.isdigit():
            self._send_json(
                400,
                {
                    "error": f"Invalid account number: {account_num_str!r} (must be numeric)"
                },
            )
            return

        account_num = int(account_num_str)
        if account_num < 1:
            self._send_json(
                400, {"error": f"Invalid account number: {account_num} (must be >= 1)"}
            )
            return

        try:
            result = oauth.start_login(account_num=account_num)
            self._send_json(200, result)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})

    def _handle_oauth_callback(self, parsed):
        """GET /oauth/callback — OAuth redirect handler."""
        from urllib.parse import parse_qs

        server = self.server
        oauth = getattr(server, "dashboard_oauth", None)

        if oauth is None:
            self._send_json(500, {"error": "OAuth login not configured"})
            return

        params = parse_qs(parsed.query)
        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]

        if not code or not state:
            self._send_json(400, {"error": "Missing code or state parameter"})
            return

        result = oauth.handle_callback(code=code, state=state)

        if result.get("success"):
            # Return a simple HTML page indicating success
            html = (
                "<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding:60px'>"
                "<h2>Login successful</h2>"
                f"<p>Account {result.get('account_num')} has been configured.</p>"
                "<p>You can close this tab and return to the dashboard.</p>"
                "</body></html>"
            )
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(400, result)

    # ─── Static file serving ─────────────────────────────

    def _serve_static(self, filename):
        """Serve a file from the static/ directory."""
        # Sanitize filename to prevent path traversal
        filename = filename.replace("..", "").lstrip("/")
        filepath = STATIC_DIR / filename

        if not filepath.is_file():
            self._send_404()
            return

        ext = filepath.suffix.lower()
        content_type = MIME_TYPES.get(ext, "application/octet-stream")

        try:
            content = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except OSError as exc:
            print(
                f"[dashboard/server] ERROR: failed to read {filepath}: {exc}",
                file=sys.stderr,
            )
            self._send_json(500, {"error": "Internal server error"})

    # ─── Response helpers ────────────────────────────────

    def _send_json(self, status_code, data):
        """Send a JSON response."""
        body = json.dumps(data).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_404(self):
        """Send a 404 Not Found response."""
        self._send_json(404, {"error": "Not found"})

    def log_message(self, format, *args):
        """Suppress default request logging to stderr."""
        pass


def create_server(
    host="127.0.0.1",
    port=DEFAULT_PORT,
    cache=None,
    accounts=None,
    start_poller=True,
    accounts_dir=None,
    claude_dir=None,
):
    """Create and configure the dashboard HTTP server.

    Args:
        host: Bind address (default 127.0.0.1 for security)
        port: Port number (default 8420, 0 for random)
        cache: UsageCache instance (created if None)
        accounts: List of AccountInfo (auto-discovered if None)
        start_poller: Whether to start background polling
        accounts_dir: Override for ~/.claude/accounts/
        claude_dir: Override for ~/.claude/

    Returns:
        Configured HTTPServer instance. Call serve_forever() to start.
    """
    if cache is None:
        cache = UsageCache()

    if claude_dir is None:
        claude_dir = str(Path.home() / ".claude")
    if accounts_dir is None:
        accounts_dir = str(Path(claude_dir) / "accounts")

    if accounts is None:
        accounts = discover_all_accounts(claude_dir, accounts_dir)
        if accounts:
            print(
                f"[dashboard] Discovered {len(accounts)} account(s): "
                + ", ".join(a.id for a in accounts),
                file=sys.stderr,
            )
        else:
            print("[dashboard] WARNING: No accounts discovered", file=sys.stderr)

    credentials_dir = str(Path(accounts_dir) / "credentials")

    server = HTTPServer((host, port), DashboardHandler)
    server.dashboard_cache = cache
    server.dashboard_accounts = accounts
    server.accounts_dir = accounts_dir
    server.credentials_dir = credentials_dir
    server.dashboard_poller = None
    server.dashboard_refresher = None
    server.dashboard_oauth = None

    if start_poller and accounts:
        poller = UsagePoller(accounts=accounts, cache=cache)
        poller.start()
        server.dashboard_poller = poller
        print(
            f"[dashboard] Background poller started for {len(accounts)} account(s)",
            file=sys.stderr,
        )

    # Start the proactive token refresher for Anthropic accounts
    if accounts:
        refresher = TokenRefresher(
            accounts=accounts,
            credentials_dir=credentials_dir,
        )
        refresher.start()
        server.dashboard_refresher = refresher
        print(
            f"[dashboard] Token refresher started (checks every 5 min, "
            f"refreshes 30 min before expiry)",
            file=sys.stderr,
        )

    # Set up OAuth login handler
    oauth = OAuthLogin(
        credentials_dir=credentials_dir,
        redirect_port=port,
    )
    server.dashboard_oauth = oauth

    return server


def main():
    """Entry point: start the dashboard server."""
    import argparse

    parser = argparse.ArgumentParser(description="Claude Squad Usage Dashboard")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--no-poll", action="store_true", help="Disable background polling"
    )
    args = parser.parse_args()

    server = create_server(
        host=args.host,
        port=args.port,
        start_poller=not args.no_poll,
    )

    actual_port = server.server_address[1]
    print(f"\n  Claude Squad — Usage Dashboard", file=sys.stderr)
    print(f"  http://{args.host}:{actual_port}/\n", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] Shutting down...", file=sys.stderr)
        if server.dashboard_poller:
            server.dashboard_poller.stop()
        if server.dashboard_refresher:
            server.dashboard_refresher.stop()
        server.shutdown()


if __name__ == "__main__":
    main()
