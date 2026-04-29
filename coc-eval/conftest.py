"""pytest configuration for coc-eval.

Adds `coc-eval/` to sys.path so tests can import `from lib.validators import ...`
without needing the parent dir to be a Python package (it has a hyphen, which
isn't a valid Python module name).

Also registers the `@pytest.mark.integration` marker (H3+) so `pytest --strict-markers`
treats it as known. Integration tests live under `tests/integration/` and may
spawn real CLI processes (cc/codex/gemini) — they are NOT part of the default
fast-loop `tests/lib/` suite.
"""

import sys
from pathlib import Path

EVAL_DIR = Path(__file__).parent.resolve()
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))


def pytest_configure(config):
    """Register custom markers used across the harness test tree."""
    config.addinivalue_line(
        "markers",
        "integration: integration tests that may spawn real CLI processes "
        "(cc/codex/gemini). NOT part of the fast-loop tests/lib/ suite.",
    )
