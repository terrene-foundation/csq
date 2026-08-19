#!/usr/bin/env python3
"""check-binding-guard-parity.py — the CI-enforced slot-binding-guard invariant.

A csq slot is bound to exactly ONE surface (Anthropic OAuth / Codex / Gemini /
native Kimi-Grok / 3P bearer). The "reverse-clobber" bug class (an internal journal entry) is
a binding entry point that binds a slot WITHOUT first refusing a slot already
bound to an incompatible surface — producing a dual-bind. It took redteam R1→R4
to enumerate ~20 entry points because detection was HAND-ROLLED at each guard:
native was taught to some conflict-detection consumers and not others, one
surface at a time.

The structural fix (an internal journal entry For-Discussion #1) routes ALL detection through
a single union detector — `csq_core::accounts::binding_guard::detect_bound_surface`
— over the exhaustive `BoundSurface` enum. The Rust compiler's non-exhaustive-match
error then forces every guard to handle a new surface. This script is the
belt-and-suspenders that keeps the SINGLE-DETECTOR invariant honest: it fails when
a per-surface detection predicate is called OUTSIDE the detector by a file that is
not an explicitly-allowlisted display / discovery / dispatch / doctor consumer —
i.e. a new hand-rolled guard that could be blind to a surface.

This is the `account-terminal-separation.md` MUST Rule 1 audit shape (enumerate the
adoption surface, classify each callsite) turned into a fail-closed CI gate.

SCOPE / LIMITS (this gate is belt-and-suspenders, NOT the primary defense).
The PRIMARY structural defense is the compiler's exhaustive-match on the
`BoundSurface` enum: a sixth surface forces every `match` in every guard to
handle it. This grep-gate covers only the narrower invariant "do not CALL the
named predicate functions outside the detector." It does NOT catch:
  - a new guard that INLINES the filesystem check (e.g. a raw
    `symlink_metadata("credentials/kimi-<N>.json")`) instead of calling a named
    predicate — there is no named call for the grep to see; and
  - a hand-rolled guard added INSIDE an allowlisted file (the allowlist is
    per-file, not per-callsite).
Both residual gaps are caught in review + by the compiler-exhaustiveness of the
guards that DO route through `detect_bound_surface`. Keep guards routed through
the detector so the compiler stays the real gate.

Adding a NEW legitimate NON-GUARD consumer of a predicate (a new doctor field, a
new dispatch site) is a deliberate act: add the file to that predicate's allowlist
below WITH a comment naming why it is display/dispatch and not a conflict guard.
Adding a new conflict GUARD is BLOCKED — route it through
`binding_guard::refuse_if_slot_conflicts` / `refuse_if_provider_conflicts` instead.

NETWORK-FREE, dependency-free. Exit 0 = clean; exit 1 = a predicate call outside
the allowlist. Run from the repo root.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The single union detector — the ONE place permitted to call every predicate.
DETECTOR = "csq-core/src/accounts/binding_guard.rs"

# Per-predicate allowlist of files permitted to call the predicate DIRECTLY.
# DETECTOR is always allowed. Every other entry is a NON-GUARD consumer
# (display / discovery / dispatch / doctor / probe) that reports or routes on
# binding state — never a conflict guard. The predicate's own definition module
# is allowlisted (it defines the fn).
ALLOWLIST: dict[str, set[str]] = {
    # Codex/Anthropic detection is the most guard-specific: consolidated to the
    # detector alone (identity_store defines is_anthropic_bound_slot and uses it
    # from sibling identity predicates).
    "is_codex_bound_slot_identity_aware": {DETECTOR},
    "is_anthropic_bound_slot": {
        DETECTOR,
        "csq-core/src/accounts/identity_store.rs",  # definition + sibling predicates
    },
    # Gemini marker presence — read by several diagnostic/dispatch surfaces.
    "is_gemini_bound_slot": {
        DETECTOR,
        "csq-core/src/providers/gemini/provisioning.rs",  # definition + corrupt-bound sibling
        "csq-core/src/daemon/server.rs",  # daemon reconcile/report
        "csq-core/src/probe/mod.rs",  # csq probe diagnostic
        "csq/src/cli/commands/doctor.rs",  # csq doctor diagnostic
        "csq/src/desktop/commands/mod.rs",  # desktop unbind/report
        # logout_account's unconditional Gemini API-key vault cleanup step. Not
        # a conflict guard — it never refuses a binding, it decides whether
        # this slot has a vault entry to remove before the ALL_SURFACES marker
        # sweep deletes the only signal that answers that question. A caller
        # that already ran its own pre-check (desktop remove_account's D7
        # sequence) has already unbound the marker, so this correctly reads
        # `false` and no-ops — safe to call unconditionally from every path.
        "csq-core/src/accounts/logout.rs",
    },
    # Native (Kimi/Grok) marker — read by run-dispatch (which CLI to spawn).
    "native_surface_for_slot": {
        DETECTOR,
        "csq/src/cli/commands/run.rs",  # dispatch: which native CLI to launch
        # exec.rs is run.rs's HEADLESS TWIN — the same dispatch question
        # ("which CLI does this slot spawn?") asked non-interactively. It is
        # not a conflict guard: it never refuses a binding, it selects a
        # surface. Added when `csq exec` learned to stop silently routing
        # native-bound Kimi/Grok slots to a `claude` spawn (an internal ticket); before
        # that it classified purely by ABSENCE of codex/gemini credentials,
        # which a native-bound slot also lacks. Routing it through the union
        # detector instead would be wrong here — the detector answers "is
        # there a binding CONFLICT", not "which binary do I exec".
        "csq/src/cli/commands/exec.rs",  # dispatch: headless twin of run.rs
    },
    # Per-surface native marker existence primitive. Tracked because a
    # single-surface hand-rolled guard (`if marker_exists(_, _, Surface::Kimi)
    # { refuse }`) would be blind to the OTHER native surface — the exact
    # guard-blindness class (redteam R2/R3). Legitimate NON-guard consumers:
    "marker_exists": {  # matches `marker_exists(` in any qualified/bare form
        "csq-core/src/providers/native.rs",  # definition + native_surface_for_slot
        "csq-core/src/accounts/move_slot.rs",  # binding relocation
        "csq/src/cli/commands/doctor.rs",  # diagnostic
        "csq/src/cli/commands/run.rs",  # dispatch marker-present gate + symlink refusal
    },
    # 3P-bearer discovery — read by discovery/usage/reconcile/doctor/dispatch.
    "discover_per_slot_third_party": {
        DETECTOR,
        "csq-core/src/accounts/discovery.rs",  # definition + siblings
        "csq-core/src/accounts/third_party.rs",  # bind/unbind bookkeeping
        "csq-core/src/daemon/startup_reconciler.rs",  # reconcile
        "csq-core/src/usage/aggregator.rs",  # usage rollup
        "csq/src/cli/commands/doctor.rs",  # csq doctor diagnostic
        "csq/src/cli/commands/run.rs",  # dispatch
        "csq/src/cli/commands/exec.rs",  # dispatch: headless twin of run.rs
    },
}

ROOTS = ["csq-core/src", "csq/src"]


def strip_test_regions(lines: list[str]) -> list[tuple[int, str]]:
    """Yield (1-indexed lineno, line) for production lines only — every
    `#[cfg(test)]`-gated module/item is skipped by brace-depth tracking."""
    out: list[tuple[int, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if re.search(r"#\[cfg\(test\)\]", line):
            # Skip forward to the item this attribute guards, then skip its
            # whole brace-balanced body.
            j = i + 1
            while j < n and "{" not in lines[j]:
                # a `#[cfg(test)]` on a `use ...;` one-liner has no brace body
                if lines[j].rstrip().endswith(";"):
                    break
                j += 1
            if j < n and "{" in lines[j]:
                depth = 0
                while j < n:
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1
                    if depth <= 0:
                        break
            i = j
            continue
        out.append((i + 1, line))
        i += 1
    return out


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    violations: list[str] = []

    # Match a call `predicate(` that is NOT a fn definition and NOT a doc/comment.
    for pred, allowed in ALLOWLIST.items():
        call_re = re.compile(rf"\b{re.escape(pred)}\s*\(")
        def_re = re.compile(rf"\bfn\s+{re.escape(pred)}\b")
        for root in ROOTS:
            for path in (repo / root).rglob("*.rs"):
                rel = path.relative_to(repo).as_posix()
                text = path.read_text(encoding="utf-8", errors="replace").splitlines()
                for lineno, line in strip_test_regions(text):
                    stripped = line.lstrip()
                    if stripped.startswith("//"):
                        continue
                    if def_re.search(line):
                        continue
                    if not call_re.search(line):
                        continue
                    if rel not in allowed:
                        violations.append(
                            f"{rel}:{lineno}: `{pred}(` called outside the unified "
                            f"detector and not in its allowlist.\n"
                            f"    {stripped.rstrip()}"
                        )

    if violations:
        print("BINDING-GUARD PARITY BREACH — hand-rolled surface detection found:\n")
        for v in violations:
            print(f"  {v}")
        print(
            "\nEvery slot-binding conflict guard MUST source detection from the single\n"
            "`binding_guard::detect_bound_surface` union detector (route through\n"
            "`refuse_if_slot_conflicts` / `refuse_if_provider_conflicts`). If this is a\n"
            "NON-GUARD display/dispatch/diagnostic consumer, add the file to the\n"
            "predicate's ALLOWLIST in this script with a justifying comment.\n"
            "See an internal journal entry For-Discussion #1 + account-terminal-separation.md Rule 1."
        )
        return 1

    print("BINDING-GUARD PARITY CLEAN — all surface detection flows through the")
    print(f"single detector ({DETECTOR}) or an allowlisted non-guard consumer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
