"""Shared failure boundary for source-bound proof instruments.

Instrumentation uncertainty must never become a product PASS or product FAIL.
"""


class ProofUnavailable(RuntimeError):
    """The instrument could not establish the requested observation."""
