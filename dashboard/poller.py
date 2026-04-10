#!/usr/bin/env python3
"""
Dashboard — Background Usage Poller

Polls usage data for all discovered accounts in a background thread.

- Anthropic accounts: GET /api/oauth/usage with bearer token + beta header
- 3P accounts (zai, mm): POST /v1/messages with max_tokens=1, capture
  rate-limit headers from the response

Polling intervals:
- Anthropic: every 10 minutes minimum (to avoid 429s)
- 3P: every 15 minutes minimum (to minimize API costs)

Error handling:
- 429: exponential backoff (double interval)
- 401: mark as expired
- Timeout/connection error: retry once then mark error

No external dependencies — stdlib only (urllib.request for HTTP).
"""

import json
import sys
import threading
import time
import urllib.error
import urllib.request

from .cache import UsageCache
from .accounts import AccountInfo

# ─── Polling interval constants ──────────────────────────
# These are minimums. Backoff can increase them per-account.

ANTHROPIC_POLL_INTERVAL = 600  # 10 minutes — aggressive rate limiting on usage endpoint
THREEP_POLL_INTERVAL = 900  # 15 minutes — minimize API costs for probes

# Maximum backoff: 1 hour
MAX_BACKOFF_INTERVAL = 3600

# HTTP timeout for individual requests (seconds)
HTTP_TIMEOUT = 15


def poll_anthropic_usage(account, base_url_override=None):
    """Poll the Anthropic OAuth usage endpoint for one account.

    Args:
        account: AccountInfo with provider="anthropic"
        base_url_override: Override base URL (for testing with mock server)

    Returns:
        dict with usage data on success, or None/error dict on failure.
        On 429: returns {"error": "rate_limited"}
        On 401: returns {"error": "expired"}
        On other errors: returns None
    """
    base_url = base_url_override or account.base_url
    url = f"{base_url}/api/oauth/usage"

    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {account.token}")
    req.add_header("Anthropic-Beta", "oauth-2025-04-20")
    req.add_header("Accept", "application/json")

    try:
        resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        body = resp.read().decode()
        data = json.loads(body)
        data["last_updated"] = time.time()
        return data
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            print(
                f"[dashboard/poller] WARN: 429 rate limited for {account.id} "
                f"(token {account.token[:8]}...)",
                file=sys.stderr,
            )
            return {"error": "rate_limited"}
        elif exc.code == 401:
            print(
                f"[dashboard/poller] WARN: 401 unauthorized for {account.id} "
                f"(token {account.token[:8]}...)",
                file=sys.stderr,
            )
            return {"error": "expired"}
        else:
            print(
                f"[dashboard/poller] ERROR: HTTP {exc.code} for {account.id}: {exc.reason}",
                file=sys.stderr,
            )
            return None
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        print(
            f"[dashboard/poller] ERROR: connection failed for {account.id}: {exc}",
            file=sys.stderr,
        )
        return None


def poll_3p_usage(account, base_url_override=None):
    """Poll a 3P provider by sending a minimal messages API request.

    Sends max_tokens=1 to minimize cost. Captures rate-limit headers
    from the response.

    Args:
        account: AccountInfo with provider in ("zai", "mm")
        base_url_override: Override base URL (for testing)

    Returns:
        dict with rate_limits data on success, or None on failure.
    """
    base_url = base_url_override or account.base_url
    url = f"{base_url}/v1/messages"

    payload = json.dumps(
        {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}],
        }
    ).encode()

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-api-key", account.token)
    req.add_header("anthropic-version", "2023-06-01")
    req.add_header("Accept", "application/json")

    try:
        resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        headers = dict(resp.headers)
        resp.read()  # drain the body

        rate_limits = _extract_rate_limit_headers(headers)
        return {
            "rate_limits": rate_limits,
            "last_updated": time.time(),
        }
    except urllib.error.HTTPError as exc:
        # Even on error responses, rate-limit headers may be present
        headers = dict(exc.headers) if exc.headers else {}
        rate_limits = _extract_rate_limit_headers(headers)
        if rate_limits:
            return {
                "rate_limits": rate_limits,
                "last_updated": time.time(),
                "http_status": exc.code,
            }
        print(
            f"[dashboard/poller] ERROR: HTTP {exc.code} for 3P {account.id}: {exc.reason}",
            file=sys.stderr,
        )
        return None
    except (urllib.error.URLError, OSError) as exc:
        print(
            f"[dashboard/poller] ERROR: connection failed for 3P {account.id}: {exc}",
            file=sys.stderr,
        )
        return None


def _extract_rate_limit_headers(headers):
    """Extract anthropic-ratelimit-* headers into a structured dict.

    Args:
        headers: dict of HTTP response headers

    Returns:
        dict with parsed rate limit values, or empty dict if none found.
    """
    # Normalize header names to lowercase for case-insensitive matching
    lower_headers = {k.lower(): v for k, v in headers.items()}

    mapping = {
        "requests_limit": "anthropic-ratelimit-requests-limit",
        "requests_remaining": "anthropic-ratelimit-requests-remaining",
        "tokens_limit": "anthropic-ratelimit-tokens-limit",
        "tokens_remaining": "anthropic-ratelimit-tokens-remaining",
        "input_tokens_limit": "anthropic-ratelimit-input-tokens-limit",
        "output_tokens_limit": "anthropic-ratelimit-output-tokens-limit",
    }

    result = {}
    for key, header_name in mapping.items():
        value = lower_headers.get(header_name)
        if value is not None:
            try:
                result[key] = int(value)
            except (ValueError, TypeError):
                result[key] = value  # Keep as string if not parseable

    return result


class UsagePoller:
    """Background thread that polls usage for all accounts.

    Manages per-account polling intervals, exponential backoff on
    rate-limit responses, and staggered polling to avoid hitting
    all accounts simultaneously.
    """

    def __init__(self, accounts, cache, base_url_override=None):
        """
        Args:
            accounts: List of AccountInfo objects to poll
            cache: UsageCache instance to store results
            base_url_override: Override base URL for all accounts (testing)
        """
        if not isinstance(cache, UsageCache):
            raise TypeError(f"cache must be UsageCache, got {type(cache).__name__}")
        self._accounts = list(accounts)
        self._cache = cache
        self._base_url_override = base_url_override
        self._thread = None
        self._stop_event = threading.Event()
        self._last_poll_time = {}  # account_id -> epoch float
        self._backoff_factor = {}  # account_id -> multiplier (1, 2, 4, ...)
        self._lock = threading.Lock()

    def start(self):
        """Start the background polling thread."""
        if self._thread is not None and self._thread.is_alive():
            return  # Already running

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="dashboard-poller",
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
        """Return True if the polling thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def force_refresh(self):
        """Force a refresh of all accounts, respecting rate limits.

        Returns:
            dict of account_id -> "skipped" for accounts that were polled
            too recently, or "refreshed" for accounts that were polled.
        """
        results = {}
        for account in self._accounts:
            with self._lock:
                last_poll = self._last_poll_time.get(account.id, 0)
            interval = self._get_poll_interval(account)
            elapsed = time.time() - last_poll
            if elapsed < interval:
                results[account.id] = "skipped"
            else:
                self._poll_account(account)
                results[account.id] = "refreshed"
        return results

    def _run_loop(self):
        """Main polling loop. Runs until stop_event is set."""
        # Stagger initial polls: wait (index * 5) seconds between accounts
        for i, account in enumerate(self._accounts):
            if self._stop_event.is_set():
                return
            if i > 0:
                # Stagger by 5 seconds between accounts
                self._stop_event.wait(timeout=5)
                if self._stop_event.is_set():
                    return

            self._poll_account(account)

        # Main loop: check each account and poll if interval has elapsed
        while not self._stop_event.is_set():
            for account in self._accounts:
                if self._stop_event.is_set():
                    return

                with self._lock:
                    last_poll = self._last_poll_time.get(account.id, 0)
                interval = self._get_poll_interval(account)
                elapsed = time.time() - last_poll

                if elapsed >= interval:
                    self._poll_account(account)

            # Check every 30 seconds if any account needs polling
            self._stop_event.wait(timeout=30)

    def _poll_account(self, account):
        """Poll a single account and update cache + status."""
        result = None

        if account.provider == "anthropic":
            result = poll_anthropic_usage(
                account, base_url_override=self._base_url_override
            )
        elif account.provider in ("zai", "mm"):
            result = poll_3p_usage(account, base_url_override=self._base_url_override)
        else:
            print(
                f"[dashboard/poller] WARN: unknown provider {account.provider!r} "
                f"for {account.id}, skipping",
                file=sys.stderr,
            )
            return

        with self._lock:
            self._last_poll_time[account.id] = time.time()

        if result is None:
            # Connection error or unexpected failure
            account.status = "error"
            return

        error = result.get("error")
        if error == "rate_limited":
            account.status = "rate-limited"
            # Exponential backoff
            with self._lock:
                current = self._backoff_factor.get(account.id, 1)
                self._backoff_factor[account.id] = min(current * 2, 8)
            return

        if error == "expired":
            account.status = "expired"
            return

        # Success — reset backoff and update cache
        account.status = "active"
        with self._lock:
            self._backoff_factor[account.id] = 1
        self._cache.set(account.id, result)

    def _get_poll_interval(self, account):
        """Get the effective polling interval for an account.

        Takes the base interval and multiplies by backoff factor.
        """
        if account.provider == "anthropic":
            base = ANTHROPIC_POLL_INTERVAL
        else:
            base = THREEP_POLL_INTERVAL

        with self._lock:
            factor = self._backoff_factor.get(account.id, 1)

        interval = base * factor
        return min(interval, MAX_BACKOFF_INTERVAL)

    def add_account(self, account):
        """Add a new account to the polling list."""
        self._accounts.append(account)

    @property
    def accounts(self):
        """Return the current list of accounts."""
        return list(self._accounts)
