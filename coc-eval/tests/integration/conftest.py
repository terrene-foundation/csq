"""Integration test fixtures.

H5-T-6: integration tests share a process with the rest of the suite,
so the module-global `lib.auth._AUTH_CACHE` can be poisoned by an
earlier integration test that probes a real CLI. An autouse fixture in
ONE test file (test_zero_auth_first_run.py) does not protect the others.
A session-scoped fixture in this conftest resets the cache for every
integration test.
"""

from __future__ import annotations

import pytest

from lib import auth


@pytest.fixture(autouse=True)
def reset_auth_cache_for_every_integration_test():
    """Snapshot + restore semantics aren't useful here — the cache is
    process-wide and rebuilds itself on the next probe. Just clear it
    before AND after each integration test so neither direction leaks.
    """
    auth.reset_cache()
    yield
    auth.reset_cache()
