"""Implementation suite — EVAL-A004/A006/B001/P003/P010 under SUITE shape.

H7. Wraps the existing csq tier-scoring tests (`coc-eval/tests/eval_*.py`)
under the v1.0.0 SUITE schema so the unified runner dispatches them
alongside capability/compliance/safety. Backend: `tiered_artifact`
(per ADR-E). Phase 1: cc only (per ADR-B).

Each entry imports the existing `TEST_DEF` from a `tests/eval_*.py`
module and adapts the field shape:

    legacy TEST_DEF                     SUITE entry
    ───────────────                     ───────────
    id              "EVAL-A004"     →   name
    prompt                          →   prompt
    scoring                         →   scoring (extension; tiered_artifact)
    scaffold        "eval-a004"     →   scaffold (extension)
    timeout / max_turns             →   (passed through as extensions)

The fixture for every test is `coc-env` — a minimal empty COC base.
Per-test scaffold files (under `coc-eval/scaffolds/<eval-id>/`) are
layered on top by the runner's `_build_scaffold_setup_fn` before
`git init` (INV-ISO-5).

Cross-references:
- Plan: workspaces/coc-harness-unification/02-plans/01-implementation-plan.md §H7
- Backend: coc-eval/lib/scoring_backends.py
- Tests: coc-eval/tests/eval_a004.py … eval_p010.py (preserved as-is)
- Scaffolds: coc-eval/scaffolds/eval-a004/ … eval-p010/
- Spec: specs/08-coc-eval-harness.md (Tiered_artifact backend section)
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any, Mapping

# Ensure `tests/` is importable when this module is loaded outside
# pytest. `conftest.py` adds `coc-eval/` to sys.path during pytest, but
# `coc-eval/run.py implementation` imports through `lib.runner` which
# imports `suites.implementation` — at that point the legacy `tests/`
# package needs to be reachable too.
_EVAL_ROOT = Path(__file__).resolve().parent.parent
if str(_EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(_EVAL_ROOT))

# Imported AFTER sys.path manipulation. Type-checker pragmas are local
# because the legacy `tests/` package has no `__init__.py` typing stubs.
from tests import (  # noqa: E402
    eval_a004,
    eval_a006,
    eval_b001,
    eval_p003,
    eval_p010,
)


# Per-CLI fixture map: every implementation test runs against `coc-env`
# (minimal empty COC base). codex/gemini cells use a sentinel
# `_unwired_phase1` (R1-A-LOW-2) so a future H10/H11 activation that
# flips the `cli != "cc"` gate cannot silently route codex through
# `coc-env` without an explicit wiring step. The runner already raises
# on missing fixturePerCli entries; the sentinel forces a deliberate
# choice (drop sentinel + plumb codex sandbox profile) rather than
# accidental routing.
_FIXTURE_MAP: dict[str, str] = {
    "cc": "coc-env",
    "codex": "_unwired_phase1",
    "gemini": "_unwired_phase1",
}


def _adapt(eval_module: Any, *, tags: list[str]) -> dict[str, Any]:
    """Render a legacy TEST_DEF as a SUITE-shape entry.

    The legacy `tests/eval_*.py` modules export `TEST_DEF` dicts whose
    field names diverge from the SUITE schema (`id` vs `name`,
    `scoring.tiers` vs `expect`). This adapter makes the runner happy
    without modifying the legacy modules — H13 may retire them, but
    H7 ships them in-place.

    Required test_def fields: `id`, `name`, `prompt`, `scaffold`,
    `scoring.tiers`, `timeout`, `max_turns`.
    """
    test_def: Mapping[str, Any] = eval_module.TEST_DEF
    # R1-A-MED-1: deep-copy the scoring sub-dict (tiers list is the same
    # object as the legacy TEST_DEF) so SUITE construction does not
    # alias the source list. Mutation of the SUITE entry — by a future
    # legacy-scorer refactor or per-attempt retry path — would
    # otherwise pollute the shared source.
    entry: dict[str, Any] = {
        "name": test_def["id"],
        "fixturePerCli": dict(_FIXTURE_MAP),
        "prompt": test_def["prompt"],
        "scoring_backend": "tiered_artifact",
        "tags": list(tags),
        # Extension fields. Schema permits unknown properties, and the
        # runner consults these explicitly.
        "scoring": copy.deepcopy(dict(test_def["scoring"])),
        "scaffold": test_def["scaffold"],
        "max_turns": int(test_def["max_turns"]),
        "timeout_sec": int(test_def["timeout"]),
        # Empty `expect` keeps the runner's parity check trivial — the
        # tiered_artifact backend never reads `expect`. Per-CLI keys
        # are intentionally absent so the regex-backend gate catches
        # configuration mistakes (a future test that mixed regex +
        # tiered_artifact criteria would surface immediately).
    }
    return entry


SUITE: dict[str, Any] = {
    "name": "implementation",
    "version": "1.0.0",
    "permission_profile": "write",
    "fixture_strategy": "coc-env",
    "tests": [
        _adapt(eval_a004, tags=["implementation", "analysis", "security"]),
        _adapt(eval_a006, tags=["implementation", "analysis"]),
        _adapt(eval_b001, tags=["implementation", "build"]),
        _adapt(eval_p003, tags=["implementation", "patch"]),
        _adapt(eval_p010, tags=["implementation", "patch"]),
    ],
}
