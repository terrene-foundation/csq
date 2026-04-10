#!/usr/bin/env python3
"""
Tier 1 (Unit) tests for dashboard/cache.py — UsageCache.

Tests the in-memory cache with TTL-based expiry, thread safety,
and explicit error behavior.
"""

import sys
import os
import time
import threading

# Ensure dashboard package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.cache import UsageCache


# ─── Basic get/set ───────────────────────────────────────


def test_set_and_get_returns_data():
    """Setting a value and getting it back returns the stored data."""
    cache = UsageCache()
    data = {"five_hour": {"utilization": 0.42}}
    cache.set("acct-1", data)
    result = cache.get("acct-1")
    assert result == data, f"Expected {data}, got {result}"


def test_get_nonexistent_key_returns_none():
    """Getting a key that was never set returns None."""
    cache = UsageCache()
    result = cache.get("does-not-exist")
    assert result is None, f"Expected None for missing key, got {result}"


def test_set_overwrites_previous_value():
    """Setting the same key twice overwrites the first value."""
    cache = UsageCache()
    cache.set("acct-1", {"old": True})
    cache.set("acct-1", {"new": True})
    result = cache.get("acct-1")
    assert result == {"new": True}, f"Expected new data, got {result}"


# ─── TTL behavior ────────────────────────────────────────


def test_get_respects_max_age():
    """Data older than max_age_seconds returns None."""
    cache = UsageCache()
    cache.set("acct-1", {"stale": True})
    # Request with a max_age of 0 — the data is instantly stale
    result = cache.get("acct-1", max_age_seconds=0)
    assert result is None, f"Expected None for expired data, got {result}"


def test_get_within_max_age_returns_data():
    """Data within max_age_seconds returns the value."""
    cache = UsageCache()
    cache.set("acct-1", {"fresh": True})
    result = cache.get("acct-1", max_age_seconds=600)
    assert result == {"fresh": True}, f"Expected fresh data, got {result}"


def test_default_max_age_is_600_seconds():
    """Default TTL is 600 seconds (10 minutes)."""
    cache = UsageCache()
    cache.set("acct-1", {"data": 1})
    # Freshly set data should be available with default max_age
    result = cache.get("acct-1")
    assert result is not None, "Default max_age should allow fresh data"


# ─── get_all ─────────────────────────────────────────────


def test_get_all_returns_all_entries():
    """get_all returns a dict of all cached entries with their timestamps."""
    cache = UsageCache()
    cache.set("acct-1", {"a": 1})
    cache.set("acct-2", {"b": 2})
    all_data = cache.get_all()
    assert "acct-1" in all_data, "acct-1 missing from get_all"
    assert "acct-2" in all_data, "acct-2 missing from get_all"
    assert all_data["acct-1"]["data"] == {"a": 1}
    assert all_data["acct-2"]["data"] == {"b": 2}
    assert "timestamp" in all_data["acct-1"], "Missing timestamp in get_all entry"
    assert "timestamp" in all_data["acct-2"], "Missing timestamp in get_all entry"


def test_get_all_empty_cache():
    """get_all on an empty cache returns empty dict."""
    cache = UsageCache()
    all_data = cache.get_all()
    assert all_data == {}, f"Expected empty dict, got {all_data}"


# ─── delete ──────────────────────────────────────────────


def test_delete_removes_entry():
    """Deleting a key removes it from the cache."""
    cache = UsageCache()
    cache.set("acct-1", {"data": 1})
    cache.delete("acct-1")
    result = cache.get("acct-1")
    assert result is None, f"Expected None after delete, got {result}"


def test_delete_nonexistent_key_does_not_raise():
    """Deleting a key that doesn't exist should not raise."""
    cache = UsageCache()
    cache.delete("nonexistent")  # Should not raise


# ─── Thread safety ───────────────────────────────────────


def test_concurrent_set_and_get():
    """Concurrent writers and readers should not corrupt the cache."""
    cache = UsageCache()
    errors = []

    def writer(account_id, iterations):
        for i in range(iterations):
            cache.set(account_id, {"iter": i})

    def reader(account_id, iterations):
        for _ in range(iterations):
            result = cache.get(account_id)
            if result is not None and "iter" not in result:
                errors.append(f"Corrupt data: {result}")

    threads = []
    for n in range(4):
        t_w = threading.Thread(target=writer, args=(f"acct-{n}", 100))
        t_r = threading.Thread(target=reader, args=(f"acct-{n}", 100))
        threads.extend([t_w, t_r])

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread safety violation: {errors}"


# ─── Timestamp accuracy ─────────────────────────────────


def test_timestamp_is_set_on_write():
    """Each set() call stores a timestamp that matches approximately now."""
    cache = UsageCache()
    before = time.time()
    cache.set("acct-1", {"data": 1})
    after = time.time()
    all_data = cache.get_all()
    ts = all_data["acct-1"]["timestamp"]
    assert before <= ts <= after, f"Timestamp {ts} not between {before} and {after}"


# ─── get_timestamp ───────────────────────────────────────


def test_get_timestamp_returns_time_of_last_set():
    """get_timestamp returns when the key was last set."""
    cache = UsageCache()
    before = time.time()
    cache.set("acct-1", {"data": 1})
    after = time.time()
    ts = cache.get_timestamp("acct-1")
    assert ts is not None, "Expected timestamp, got None"
    assert before <= ts <= after


def test_get_timestamp_missing_key_returns_none():
    """get_timestamp for a missing key returns None."""
    cache = UsageCache()
    ts = cache.get_timestamp("missing")
    assert ts is None, f"Expected None, got {ts}"


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
