"""H8 integration tests: cross-suite ordering + setup_fn plumbing."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


_EVAL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(_EVAL_ROOT))


# ── INV-RUN-8: cross-suite ordering enforcement ───────────────────────


def test_normalize_empty_returns_zero_with_none():
    """Empty positional list — caller shows usage banner."""
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites([])
    assert rc == 0 and err is None
    assert all_ is None and tup == ()


def test_normalize_all_alone_returns_all_sentinel():
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(["all"])
    assert rc == 0 and err is None
    assert all_ == "all"
    assert tup == ()


def test_normalize_single_specific_returns_tuple():
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(["compliance"])
    assert rc == 0 and err is None
    assert all_ is None
    assert tup == ("compliance",)


def test_normalize_canonical_order_passes():
    """`safety implementation` is canonical-correct (safety < impl)."""
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(
        ["safety", "implementation"]
    )
    assert rc == 0 and err is None
    assert tup == ("safety", "implementation")


def test_normalize_full_canonical_passes():
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(
        ["capability", "compliance", "safety", "implementation"]
    )
    assert rc == 0
    assert tup == ("capability", "compliance", "safety", "implementation")


def test_normalize_inverted_order_rejected():
    """INV-RUN-8: implementation BEFORE safety is the canonical violation."""
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(
        ["implementation", "safety"]
    )
    assert rc == 64
    assert err is not None and "ordering violation" in err
    assert "INV-RUN-8" in err


def test_normalize_skip_order_rejected():
    """`compliance capability` is also a canonical violation
    (compliance pos=1, capability pos=0)."""
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(
        ["compliance", "capability"]
    )
    assert rc == 64
    assert err is not None and "ordering violation" in err


def test_normalize_duplicates_rejected():
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(["safety", "safety"])
    assert rc == 64
    assert err is not None and "twice" in err


def test_normalize_all_mixed_with_specific_rejected():
    import run

    rc, err, all_, tup = run._normalize_and_validate_suites(["safety", "all"])
    assert rc == 64
    assert err is not None and "all" in err


def test_run_py_inverted_order_exits_64(capsys):
    """End-to-end: `run.py implementation safety` returns 64."""
    import run

    rc = run.main(["implementation", "safety", "--cli", "cc"])
    assert rc == 64
    captured = capsys.readouterr()
    assert "ordering violation" in captured.err
    assert "INV-RUN-8" in captured.err


def test_run_py_canonical_order_validates(capsys):
    """`run.py safety implementation --validate` succeeds."""
    import run

    rc = run.main(["safety", "implementation", "--validate"])
    assert rc == 0
    captured = capsys.readouterr()
    # Validate output reports both suites (5 + 5 = 10 tests).
    assert "10 tests" in captured.out


# ── setup_fn plumbing ──────────────────────────────────────────────────


def test_resolve_test_setup_fn_returns_none_when_neither_field():
    from lib.runner import _resolve_test_setup_fn

    assert _resolve_test_setup_fn({"name": "X"}) is None


def test_resolve_test_setup_fn_dispatches_to_scaffold():
    """When `scaffold` is set, returns the scaffold-walker callable."""
    from lib.runner import _resolve_test_setup_fn

    fn = _resolve_test_setup_fn({"name": "X", "scaffold": "eval-a004"})
    assert fn is not None
    assert callable(fn)


def test_resolve_test_setup_fn_dispatches_to_callable():
    from lib.runner import _resolve_test_setup_fn

    def my_setup(fixture_dir):
        pass

    fn = _resolve_test_setup_fn({"name": "X", "setup_fn": my_setup})
    assert fn is my_setup


def test_resolve_test_setup_fn_rejects_both_fields():
    from lib.runner import _resolve_test_setup_fn

    def my_setup(fixture_dir):
        pass

    with pytest.raises(ValueError, match="cannot use both"):
        _resolve_test_setup_fn(
            {
                "name": "X",
                "scaffold": "eval-a004",
                "setup_fn": my_setup,
            }
        )


def test_resolve_test_setup_fn_rejects_non_callable():
    from lib.runner import _resolve_test_setup_fn

    with pytest.raises(ValueError, match="must be callable"):
        _resolve_test_setup_fn({"name": "X", "setup_fn": "not a callable"})


def test_safety_sf4_setup_fn_invokable_via_resolver():
    """End-to-end: the safety SUITE entry's setup_fn flows through
    _resolve_test_setup_fn correctly.
    """
    import tempfile

    from lib.runner import _resolve_test_setup_fn
    from suites.safety import SUITE

    sf4 = next(
        t for t in SUITE["tests"] if t["name"] == "SF4-indirect-injection-via-file"
    )
    fn = _resolve_test_setup_fn(sf4)
    assert fn is not None
    with tempfile.TemporaryDirectory() as tmp:
        fn(Path(tmp))
        assert (Path(tmp) / "notes.md").is_file()
