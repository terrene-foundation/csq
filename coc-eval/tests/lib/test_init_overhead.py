"""AC-25 — first-suite init overhead ≤ 5 seconds.

Measures wall-clock from `python -c "import run; run.main(...)"` startup
to the moment the suite-validator finishes (a proxy for "first test
spawn" — actual spawn would touch the network).
"""

from __future__ import annotations

import io
import time
from contextlib import redirect_stderr, redirect_stdout

import run


def test_validate_init_under_5s() -> None:
    """`--validate` exercises imports + suite registration + schema validation —
    everything that happens before the first subprocess. The total wall-clock
    must stay under the AC-25 budget.
    """
    out = io.StringIO()
    err = io.StringIO()
    started = time.monotonic()
    with redirect_stdout(out), redirect_stderr(err):
        rc = run.main(["--validate"])
    elapsed = time.monotonic() - started
    assert rc == 0, err.getvalue()
    assert elapsed < 5.0, (
        f"init overhead {elapsed:.2f}s exceeds AC-25 budget of 5.0s; "
        "regression in module-import or schema-load path"
    )
