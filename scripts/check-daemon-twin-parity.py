#!/usr/bin/env python3
"""check-daemon-twin-parity.py — the CI-enforced daemon-twin subsystem invariant.

csq's daemon has TWO twin session bodies that are the SAME product launched two
ways:

  - CLI     `csq/src/cli/commands/daemon.rs::run_daemon_session`
  - Desktop `csq/src/desktop/daemon_supervisor.rs::run_daemon`

They are mutually exclusive at runtime (one `PidFile`, one socket), so a
subsystem wired into only ONE twin is not "covered by the other" — it simply
never runs for whichever launch mode omits it. That is a silent capability loss
with no error, no log line, and no failing test.

This gate exists because that is exactly what happened. `coc_cache_sweeper` was
added to the CLI daemon and never mirrored to the desktop twin, which already
existed at the time; a later restructure only MOVED the CLI copy, so
`git log -S coc_cache_sweeper -- csq/src/desktop/daemon_supervisor.rs` returned
empty — the subsystem was never added there, not removed. Until it was fixed,
desktop-only users GC'd zero parse caches and saw
`csq doctor --json::cache_sweeper.status == "never_run"` indefinitely. Two
separate reviews NOTICED the asymmetry and both filed it as an open question
rather than a defect, because nothing mechanical said which of the two lists was
wrong.

(This file ships to the public community repo. Keep the rationale technical:
internal commit SHAs, ticket numbers and user-impact post-mortems do not belong
here. The extraction scrubs ticket and journal citations, but it cannot safely
regex a bare SHA or a narrative claim, so those are the author's responsibility.)

The invariant this gate enforces: **the supervised subsystem label sets of the
two twins are identical**, except for entries explicitly justified in
`INTENTIONAL_DIFFERENCES` below.

Why a source-scanning gate rather than a Rust test: the two `Vec<Subsystem>`s are
built from local variables inside two long async session bodies, each with its own
error plumbing and log facade. There is no shared runtime value a unit test could
compare without a refactor far larger than the invariant is worth. The labels are
`&'static str` literals in a `vec![...]` — a stable, greppable surface. This is
the `account-terminal-separation.md` MUST Rule 1 audit shape ("enumerate the
adoption surface, do not trust a named list") turned into a fail-closed CI gate,
matching `check-binding-guard-parity.py`.

SCOPE / LIMITS (read before trusting this gate).
It compares the LABEL SETS of the two `subsystems` collections. It does NOT
verify:
  - that a label is wired to the same subsystem in both twins (a desktop
    `("refresher", log_gc)` mis-wiring passes this gate);
  - that a spawned-but-unwatched task is present in both twins (only members of
    the supervised set are compared — a `tokio::spawn` never added to the Vec is
    invisible here, and invisible to `await_session_stop` too, which is its own
    hazard);
  - non-subsystem wiring drift (startup ordering, `$CLAUDE_HOME` resolution,
    one-shot startup emissions like the M19 capture matrix). Those are review
    surface, not gate surface.
The label-set check is the narrow mechanical invariant; it is not a substitute
for reading both twins when either changes.

Adding a subsystem to ONE twin only is a deliberate act: add its label to
`INTENTIONAL_DIFFERENCES` WITH a comment naming why the other twin must not run
it. Anything else is BLOCKED.

NETWORK-FREE, dependency-free. Exit 0 = parity holds; exit 1 = drift. Run from
the repo root.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CLI_TWIN = "csq/src/cli/commands/daemon.rs"
DESKTOP_TWIN = "csq/src/desktop/daemon_supervisor.rs"

# Labels permitted to appear in ONE twin only. Each entry MUST carry a comment
# naming the structural reason the other twin cannot or must not run it.
# EMPTY IS THE CORRECT STEADY STATE — an entry here is a documented capability
# gap, not a free pass.
INTENTIONAL_DIFFERENCES: dict[str, str] = {
    # (none — both twins currently run the identical subsystem set)
}

# Matches a subsystem entry: ("label", <handle expr>),
# Anchored on the opening paren + quoted label so a bare string elsewhere in the
# vec body cannot match.
ENTRY_RE = re.compile(r'\(\s*"([a-z0-9_]+)"\s*,')

# The declaration that opens the supervised set in both twins.
VEC_DECL_RE = re.compile(
    r"let\s+mut\s+subsystems\s*:\s*Vec<daemon::supervise::Subsystem>\s*=\s*vec!\["
)

# A `subsystems.push((...))` line — the conditional / feature-gated members that
# live outside the vec literal.
PUSH_RE = re.compile(r'subsystems\.push\(\s*\(\s*"([a-z0-9_]+)"\s*,')


def strip_comments_and_strings(src: str) -> str:
    """Blanks out `//` line comments, `/* */` blocks, and string literals,
    preserving byte offsets and newlines so downstream spans stay aligned.

    This is load-bearing, not cosmetic. Without it the gate has three
    false-PASS vectors, all of which keep it GREEN while a twin is missing a
    subsystem:

      1. A commented-out entry still matches `ENTRY_RE` — and commenting one
         out is the NATURAL way to disable a subsystem:
             // ("coc_cache_sweeper", coc_cache_sweeper.join),  // debugging
      2. A stray `]` inside a comment in the vec body silently truncates the
         bracket walk, dropping every label after it.
      3. A `subsystems.push((...))` inside `#[cfg(test)]` or a comment counts
         as production wiring.

    A gate that a comment can satisfy is worse than no gate: it reports
    parity over a tree that does not have it.
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
        elif c == '"':
            out.append(" ")
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def extract_labels(path: Path) -> set[str]:
    """Returns the supervised subsystem labels declared in `path`.

    Covers both the `vec![...]` literal and every `subsystems.push((...))`
    (the `#[cfg(feature = "enterprise")]` / conditional members). Fails loudly
    when the vec declaration is absent — a silent empty set would make the
    parity check vacuously pass, which is the one failure mode a gate must not
    have.
    """
    raw = path.read_text(encoding="utf-8")

    # Blank comments/strings BEFORE any matching. Label literals are quoted, so
    # we match against the raw text within spans located on the blanked copy.
    blanked = strip_comments_and_strings(raw)

    # Exactly one supervised-set declaration per twin. A second one would be
    # invisible to a `search()`-based parser, which only sees the first.
    decls = list(VEC_DECL_RE.finditer(blanked))
    if len(decls) > 1:
        sys.exit(
            f"FATAL: {path} declares {len(decls)} supervised-subsystem vecs; this gate\n"
            "assumes exactly one. Update the parser rather than weakening the check."
        )
    src = raw

    decl = VEC_DECL_RE.search(blanked)
    if decl is None:
        sys.exit(
            f"FATAL: could not locate the supervised-subsystem vec declaration in {path}.\n"
            "The gate's parser is stale — the twins were refactored without updating\n"
            "scripts/check-daemon-twin-parity.py. Fix the parser; do NOT delete the gate."
        )

    # Walk from the `vec![` to its matching `]` on the BLANKED copy, so a
    # bracket inside a comment or string cannot move the boundary.
    start = decl.end()
    depth = 1
    i = start
    while i < len(blanked) and depth > 0:
        if blanked[i] == "[":
            depth += 1
        elif blanked[i] == "]":
            depth -= 1
        i += 1
    if depth != 0:
        sys.exit(f"FATAL: unbalanced brackets in the subsystems vec in {path}")
    vec_end = i - 1

    # Entries: match on raw text (labels are quoted, so the blanked copy has
    # them erased) but ONLY where the blanked copy shows live code — that is
    # how a commented-out entry is excluded.
    labels = {
        m.group(1)
        for m in ENTRY_RE.finditer(src[start:vec_end])
        if blanked[start + m.start() : start + m.end()].strip()
    }

    # Conditional members appended after the literal, bounded to the region
    # between the vec's close bracket and `await_session_stop` (where the set is
    # consumed). Unbounded scanning would count pushes in `#[cfg(test)]`
    # modules and other unrelated functions as production wiring.
    consume = blanked.find("await_session_stop", vec_end)
    push_region_end = consume if consume != -1 else len(blanked)
    labels |= {
        m.group(1)
        for m in PUSH_RE.finditer(src[vec_end:push_region_end])
        if blanked[vec_end + m.start() : vec_end + m.end()].strip()
    }

    if not labels:
        sys.exit(f"FATAL: parsed zero subsystem labels from {path} — parser is stale.")
    return labels


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    cli_path = root / CLI_TWIN
    desktop_path = root / DESKTOP_TWIN

    for p in (cli_path, desktop_path):
        if not p.is_file():
            sys.exit(f"FATAL: expected twin not found: {p}")

    cli = extract_labels(cli_path)
    desktop = extract_labels(desktop_path)

    cli_only = cli - desktop
    desktop_only = desktop - cli

    unjustified_cli = sorted(cli_only - INTENTIONAL_DIFFERENCES.keys())
    unjustified_desktop = sorted(desktop_only - INTENTIONAL_DIFFERENCES.keys())

    # A label listed as an intentional difference that is now in BOTH twins means
    # the allowlist is stale — drop it so the entry stops excusing future drift.
    stale = sorted(k for k in INTENTIONAL_DIFFERENCES if k in cli and k in desktop)

    if not (unjustified_cli or unjustified_desktop or stale):
        print(
            f"DAEMON TWIN PARITY CLEAN — {len(cli)} supervised subsystems in both twins:"
        )
        for label in sorted(cli):
            print(f"  - {label}")
        return 0

    print("DAEMON TWIN PARITY VIOLATION\n")
    if unjustified_cli:
        print(f"Supervised in the CLI twin ({CLI_TWIN}) but NOT the desktop twin:")
        for label in unjustified_cli:
            print(f"  - {label}")
        print(
            "\n  A desktop-launched daemon will never run these. The two daemons are\n"
            "  mutually exclusive (one PidFile), so the CLI twin does NOT cover them.\n"
        )
    if unjustified_desktop:
        print(f"Supervised in the desktop twin ({DESKTOP_TWIN}) but NOT the CLI twin:")
        for label in unjustified_desktop:
            print(f"  - {label}")
        print(
            "\n  A CLI-launched daemon (`csq daemon start`, the launchd-managed\n"
            "  background daemon) will never run these.\n"
        )
    if stale:
        print("Stale INTENTIONAL_DIFFERENCES entries (now present in BOTH twins):")
        for label in stale:
            print(f"  - {label}")
        print(
            "\n  Remove these from INTENTIONAL_DIFFERENCES so they stop excusing\n"
            "  future drift.\n"
        )

    print(
        "FIX: wire the missing subsystem into the other twin's `subsystems` vec.\n"
        "If a twin genuinely must NOT run it, add the label to\n"
        "INTENTIONAL_DIFFERENCES in scripts/check-daemon-twin-parity.py with a\n"
        "comment naming the structural reason."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
