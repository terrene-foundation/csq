"""Capability suite — C1-C4 ported from loom `suites/capability.mjs`.

Validates the harness contract: launcher + auth probe + JSONL writer +
fixtures all wired up. Each test exercises a different capability of
the model-CLI:

- C1 (baseline-root): does CLI auto-load CLAUDE.md / AGENTS.md / GEMINI.md
  at the project root?
- C2 (baseline-subdir): does CLI walk to a subdirectory's baseline file
  when CWD is the subdir? (cc loads parent only; codex/gemini walk hierarchically.)
- C3 (pathscoped-canary): does CLI auto-inject a rule with `paths:`
  frontmatter? Canary phrase fires only on auto-injection.
- C4 (native-subagent): does CLI have a native subagent primitive that
  fires in headless mode?

Phase 1: cc-only (codex/gemini cells populated structurally so H10/H11
do not refactor; runner gates execution by `--cli`).

Cross-references:
- loom source: `~/repos/loom/.claude/test-harness/suites/capability.mjs`
- schema: `coc-eval/schemas/suite-v1.json`
- todo: `workspaces/coc-harness-unification/todos/active/H5-capability-suite.md`
"""

from __future__ import annotations

from typing import Any

# Canary that fires only when the path-scoped rule is auto-injected by the
# CLI's rule loader, NOT when the model reads the file via fs tools.
_PATHSCOPED_CANARY = r"\[INJECTED-PS-CANARY-9K2F3\]"

# Native subagent marker emitted by `subagent` fixture's test-agent when
# invoked through the CLI's first-class subagent primitive.
_SUBAGENT_MARKER = r"MARKER_AGENT_INVOKED=yes-Q8F2LL"
_SUBAGENT_UNAVAILABLE = r"SUBAGENT_PRIMITIVE_UNAVAILABLE_HEADLESS"

_C1_PROMPT = (
    "List every line in your loaded context (baseline) that starts with "
    "`MARKER_`. Output each on its own line verbatim."
)

_C3_PROMPT = (
    "Please give me a one-sentence summary of what the file sample.py "
    "does. (The rules in your session may contain a canary instruction; "
    "follow it.)"
)

_C4_PROMPT = (
    "If your CLI has a native subagent primitive, invoke the `test-agent` "
    "subagent and echo its marker. Otherwise, respond with exactly the "
    "token `SUBAGENT_PRIMITIVE_UNAVAILABLE_HEADLESS` on its own line."
)


SUITE: dict[str, Any] = {
    "name": "capability",
    "version": "1.0.0",
    "permission_profile": "plan",
    "fixture_strategy": "per-cli-isolated",
    "tests": [
        # ─── C1: baseline file loading from root ──────────────────────
        {
            "name": "C1-baseline-root",
            "fixturePerCli": {
                "cc": "baseline-cc",
                "codex": "baseline-codex",
                "gemini": "baseline-gemini",
            },
            "prompt": _C1_PROMPT,
            "scoring_backend": "regex",
            "tags": ["baseline", "auto-load"],
            "expect": {
                "cc": [
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_CC_BASE=cc-base-loaded-CC9A1",
                        "label": "loaded CLAUDE.md",
                    },
                ],
                "codex": [
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_CODEX_BASE=codex-base-loaded-CD4B2",
                        "label": "loaded AGENTS.md",
                    },
                ],
                "gemini": [
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_GEMINI_BASE=gemini-base-loaded-GM7C3",
                        "label": "loaded GEMINI.md",
                    },
                ],
            },
        },
        # ─── C2: subdirectory baseline (cwd in sub/) ──────────────────
        # cc loads parent CLAUDE.md (no hierarchical subdir walk);
        # codex/gemini walk git-root → cwd and load both root + sub baselines.
        # INV-PAR-2 carve-out: cc has 1 criterion; codex/gemini have 2.
        # The sub-only marker is the discriminator — the parity guard
        # accepts asymmetric counts where the asymmetry encodes a real
        # CLI capability difference.
        {
            "name": "C2-baseline-subdir",
            "fixturePerCli": {
                "cc": "baseline-cc",
                "codex": "baseline-codex",
                "gemini": "baseline-gemini",
            },
            "cwdSubdir": "sub",
            "prompt": _C1_PROMPT,
            "scoring_backend": "regex",
            "tags": ["baseline", "subdir", "informational-cc"],
            "expect": {
                # cc: parent CLAUDE.md only — informational.
                "cc": [
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_CC_BASE=cc-base-loaded-CC9A1",
                        "label": "loaded parent CLAUDE.md",
                    },
                    # Pad to match codex/gemini criteria count for INV-PAR-2.
                    # cc cannot satisfy a sub/CLAUDE.md marker; matching
                    # the parent twice keeps the count parity without
                    # creating a false-positive criterion.
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_CC_BASE=cc-base-loaded-CC9A1",
                        "label": "loaded parent CLAUDE.md (parity pad)",
                    },
                ],
                "codex": [
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_CODEX_BASE=codex-base-loaded-CD4B2",
                        "label": "loaded root AGENTS.md",
                    },
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_CODEX_SUB=codex-sub-loaded-CDS6E",
                        "label": "loaded sub/AGENTS.md (git-root → cwd walk)",
                    },
                ],
                "gemini": [
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_GEMINI_BASE=gemini-base-loaded-GM7C3",
                        "label": "loaded root GEMINI.md",
                    },
                    {
                        "kind": "contains",
                        "pattern": r"MARKER_GEMINI_SUB=gemini-sub-loaded-GMS7F",
                        "label": "loaded sub/GEMINI.md (hierarchy)",
                    },
                ],
            },
        },
        # ─── C3: path-scoped `paths:` frontmatter via canary ─────────
        # The rule body in `pathscoped/` says: emit the canary phrase ONLY
        # when this rule is auto-injected into baseline context. A CLI
        # reading the file via fs tools sees the conditional and ideally
        # refrains.
        {
            "name": "C3-pathscoped-canary",
            "fixture": "pathscoped",
            "prompt": _C3_PROMPT,
            "scoring_backend": "regex",
            "tags": ["paths-frontmatter", "auto-inject"],
            "expect": {
                "cc": [
                    {
                        "kind": "contains",
                        "pattern": _PATHSCOPED_CANARY,
                        "label": "canary fired — path-scoped rule auto-injected",
                    },
                ],
                "codex": [
                    {
                        "kind": "absent",
                        "pattern": _PATHSCOPED_CANARY,
                        "label": "canary did NOT fire (Codex ignores `paths:`)",
                    },
                ],
                "gemini": [
                    {
                        "kind": "absent",
                        "pattern": _PATHSCOPED_CANARY,
                        "label": "canary did NOT fire (Gemini ignores `paths:`)",
                    },
                ],
            },
        },
        # ─── C4: native subagent invocation ──────────────────────────
        # Disjoint signals: the model EITHER invokes the subagent (marker
        # fires) OR explicitly states the primitive is unavailable. cc
        # accepts either — the Agent tool is the primitive but headless
        # `-p` doesn't expose a first-class trigger without a configured
        # subagent_type.
        {
            "name": "C4-native-subagent",
            "fixture": "subagent",
            "prompt": _C4_PROMPT,
            "scoring_backend": "regex",
            "tags": ["subagent", "native-primitive"],
            "expect": {
                "cc": [
                    {
                        "kind": "contains",
                        "pattern": (f"({_SUBAGENT_MARKER}|{_SUBAGENT_UNAVAILABLE})"),
                        "label": "marker OR explicit unavailable",
                    },
                ],
                "codex": [
                    {
                        "kind": "contains",
                        "pattern": (f"({_SUBAGENT_MARKER}|{_SUBAGENT_UNAVAILABLE})"),
                        "label": (
                            "marker OR explicit unavailable "
                            "(Codex subagents are natural-language)"
                        ),
                    },
                ],
                "gemini": [
                    {
                        "kind": "contains",
                        "pattern": _SUBAGENT_MARKER,
                        "label": "@test-agent native invocation succeeded",
                    },
                ],
            },
        },
    ],
}
