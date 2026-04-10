#!/usr/bin/env python3
"""
Dashboard — In-Memory Cache with TTL

Thread-safe dict-based cache for usage data. Each entry stores
the data payload and a timestamp. get() respects max_age_seconds
to return None for stale entries.

No external dependencies — stdlib only.
"""

import threading
import time


class UsageCache:
    """Thread-safe in-memory cache with TTL-based expiry.

    Each entry is stored as {"data": <payload>, "timestamp": <epoch_float>}.
    get() returns the payload only if the entry is younger than max_age_seconds.
    """

    def __init__(self):
        self._data = {}  # account_id -> {"data": ..., "timestamp": float}
        self._lock = threading.Lock()

    def get(self, account_id, max_age_seconds=600):
        """Return cached data for account_id, or None if missing/expired.

        Args:
            account_id: The account identifier.
            max_age_seconds: Maximum age in seconds. Data older than this
                returns None. Default 600 (10 minutes).

        Returns:
            The cached data dict, or None if missing or expired.
        """
        with self._lock:
            entry = self._data.get(account_id)
            if entry is None:
                return None
            age = time.time() - entry["timestamp"]
            if age >= max_age_seconds:
                return None
            return entry["data"]

    def set(self, account_id, data):
        """Store data for account_id with the current timestamp.

        Args:
            account_id: The account identifier.
            data: The data dict to cache.
        """
        with self._lock:
            self._data[account_id] = {
                "data": data,
                "timestamp": time.time(),
            }

    def delete(self, account_id):
        """Remove an entry from the cache. No-op if the key doesn't exist.

        Args:
            account_id: The account identifier to remove.
        """
        with self._lock:
            self._data.pop(account_id, None)

    def get_all(self):
        """Return a snapshot of all cache entries.

        Returns:
            dict mapping account_id -> {"data": ..., "timestamp": float}
        """
        with self._lock:
            # Return a shallow copy so callers can iterate without holding the lock
            return dict(self._data)

    def get_timestamp(self, account_id):
        """Return the timestamp when account_id was last set, or None.

        Args:
            account_id: The account identifier.

        Returns:
            float (epoch seconds) or None if the key is not cached.
        """
        with self._lock:
            entry = self._data.get(account_id)
            if entry is None:
                return None
            return entry["timestamp"]
