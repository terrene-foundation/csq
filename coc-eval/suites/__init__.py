"""Suite modules.

Each suite is a Python module that exports a top-level `SUITE` dict
conforming to `coc-eval/schemas/suite-v1.json`. The runner discovers
suites via `SUITE_REGISTRY` (NOT glob — CRIT-03).
"""

from __future__ import annotations

from typing import Any

from .capability import SUITE as CAPABILITY_SUITE
from .compliance import SUITE as COMPLIANCE_SUITE
from .implementation import SUITE as IMPLEMENTATION_SUITE

SUITE_REGISTRY: dict[str, dict[str, Any]] = {
    "capability": CAPABILITY_SUITE,
    "compliance": COMPLIANCE_SUITE,
    "implementation": IMPLEMENTATION_SUITE,
}

__all__ = ["SUITE_REGISTRY"]
