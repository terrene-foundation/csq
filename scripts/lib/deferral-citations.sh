#!/usr/bin/env bash
# ONE definition of "what counts as an in-code deferral that cites a GitHub
# issue", sourced by every gate that needs it. Not a gate itself — no
# `# ci-gate:` marker is required here because run-ci-gates.sh globs
# scripts/verify/*.sh, and this file deliberately lives at scripts/lib/.
#
# WHY THIS IS SHARED RATHER THAN COPIED
# -------------------------------------
# Two gates now ask about the same object from opposite directions:
#
#   scripts/verify/todo-closed-issue.sh    — every id a deferral cites must be OPEN
#   scripts/verify/self-closing-tracker.sh — a PR must not CLOSE an id its own
#                                            resulting tree cites as a live deferral
#
# Those two verdicts are only coherent if both compute "the set of ids this tree
# cites as live deferrals" identically. Two hand-maintained copies of this
# vocabulary would drift on the first widening — and the widening is not
# hypothetical: `tracked in`, `tracked by` and `pending verified` were all added
# on 2026-08-12 after production code falsified the previous set. Had the second
# gate carried its own copy, it would have been blind to exactly the nine
# citations that produced the incident it exists to prevent.
#
# Every regex and every exclusion below therefore has ONE home. The long-form
# rationale for each term also lives here, so a future widening reads the
# measurement that justified the current set before touching it.
#
# CONTRACT
#   deferral_scan_hits <ROOT>   -> prints matching `path:line:text` rows on
#                                  stdout. rc 0 = scan completed (possibly zero
#                                  rows); rc 2 = the scan itself failed and the
#                                  caller must report UNDETERMINED, never clean.
#   deferral_ids                -> stdin: hit rows. stdout: sorted, unique,
#                                  bare in-repo ids, one per line.

# Any `#` immediately followed by digits. Broad on purpose — a Rust attribute
# is `#[...]` (next char `[`, never a digit) so it never matches; a hex color
# `#ff0000` starts with a letter so it never matches either. The vocabulary
# join in deferral_scan_hits is what keeps this from over-firing.
DEFERRAL_ID_RE='#[0-9]+'

# NARROWER than milestone-refs.sh's vocabulary — measured on THIS repo,
# `follow-up` and bare `deferred` are false-positive generators for issue
# citations specifically, in a way they are not for milestone ids:
#
#   - `follow-up` is this codebase's PROVENANCE convention: "Origin: redteam
#     follow-up to PRs an internal ticket-an internal ticket", "(an internal ticket follow-up)", "an internal ticket follow-up:
#     typed ToolCall extraction". Every one of #1, #2, an internal ticket, an internal ticket, an internal ticket,
#     an internal ticket, an internal ticket, an internal ticket, an internal ticket, an internal ticket, an internal ticket verified CLOSED/MERGED on this repo
#     and hits ONLY on `follow-up` — they cite the PR/issue that specified
#     ALREADY-SHIPPED code, not a still-open gap. Milestone ids don't carry
#     this convention, so milestone-refs.sh's inclusion of `follow-up` is not
#     evidence for including it here. KNOWN RESIDUAL (see an internal ticket below): a
#     genuine live deferral phrased as "#NNN follow-up" with no OTHER
#     deferral word on the SAME line is still invisible to this gate. That
#     is the false-positive/false-negative trade this exclusion accepts;
#     `not yet` / `pending verified`-class phrasing on the SAME line (as
#     every an internal ticket site this repo has) is what closes it per-site instead.
#   - bare `deferred` matches identifier substrings
#     (`deferred_chain_unavailable`, `deferred_pending_count` — word-boundary
#     wrapped below to fix that) AND a real prose false positive:
#     `mcp_gate_outbox.rs` documents a boolean field "the MCP-gate drain was
#     deferred because the chain was not appendable" — DESIGNED, IMPLEMENTED,
#     TESTED runtime behavior (see `drain_reports_deferred_pending_count_
#     when_chain_unavailable`), not an incomplete-implementation deferral.
#
# `\b`-wrapped so a term cannot match mid-identifier.
#
# an internal ticket (2026-08-12): the vocabulary USED to stop at `tracked under` /
# `pending implementation`, on the claim that "every genuine deferral this gate
# needs to catch (an internal ticket) ALSO uses `not yet` / `unimplemented`-class
# phrasing". That was falsified by production code on THIS repo:
#
#   csq-core/src/usage/ledger.rs:15   "...(follow-up, tracked in an internal ticket) is a
#                                       daemon-written ledger..."
#   csq-core/src/usage/ledger.rs:87   "...bill cache at $0 pending verified
#                                       per-provider rates."
#   csq-core/src/audit/authority/mod.rs:76
#                                      "...Keychain-anchoring the floor is
#                                       tracked in an internal ticket."
#
# All three cite issues CLOSED with no successor and none matched the old
# vocabulary: "tracked in" is not "tracked under" (a different phrase, not a
# typo of it), and "pending verified" is not "pending implementation". Two
# terms close the observed miss, each checked against this repo before
# landing (a term that fires on unrelated CLOSED/MERGED ids is worse than no
# term — see the `follow-up`/`deferred` measurement above):
#
#   - `tracked in`/`tracked by` — measured against every `#NNN` site in the
#     tree (2026-08-12): 3 real hits (the two above, plus a `terrene#40`
#     cross-repo id already out of scope by the qualified-token rule), zero
#     false positives.
#   - `pending verified` (NOT bare `pending`) — bare `pending` was measured
#     and REJECTED: it collides with this repo's `Pending` state-machine
#     enum variant (CLOSED an internal ticket), a `.pending-mcp-gate/` directory name
#     (CLOSED an internal ticket), and a test name "renders ... a pending state" (MERGED
#     an internal ticket) — three false positives from one word. The two-word phrase
#     "pending verified" is unique in the tree and carries none of that risk.
#
# A FULL inversion — flag every `#NNN` resolving CLOSED regardless of
# co-occurring vocabulary, with an opt-out marker for legitimate historical
# citations — was considered and is the structurally cleaner fix (issue
# STATE is the enumerable axis; deferral PROSE is not, `cc-artifacts.md`
# Rule 10). It was NOT adopted: measured against this tree (2026-08-12),
# bare `#[0-9]+` matches 164 distinct issue ids across ~1874 lines outside
# the already-excluded vendor/journal/sweeps trees, the overwhelming majority
# provenance ("an internal ticket Phase 2", "M6 an internal ticket", "an internal ticket redteam R1 HIGH-1") that
# would each need a historical-opt-out marker by hand. Worse, `coc-eval/`
# eval-suite fixtures embed synthetic PR-reference TEXT as prompt content —
# `coc-eval/suites/compliance.py:174` contains the literal string `an internal ticket`
# as sample text, and `an internal ticket` is coincidentally a REAL, MERGED PR on this
# repo — so a blind state check convicts eval fixture content that was never
# a deferral at all. Retrofitting the whole tree is its own shard; tracked as
# an internal ticket rather than attempted inline (`autonomous-execution.md` Rule 4
# — exceeds the ≤500 LOC / ≤3-4 call-graph-hop shard bound).
DEFERRAL_DEFER_RE='(\bnot yet\b|\bnot currently\b|\bunimplemented\b|\bnot implemented\b|\bnot supported\b|\bnot wired\b|\bpending implementation\b|\bpending verified\b|\btracked under\b|\btracked in\b|\btracked by\b)'

# `Fixes #N` / `Closes #N` / `Resolves #N` on a SOURCE line are SUPPOSED to
# name a closed issue — excluded outright, never scored.
#
# Deliberately NARROWER than the PR-body keyword set in
# scripts/verify/self-closing-tracker.sh, and the asymmetry is intentional:
# this one filters SOURCE COMMENTS (where the past-tense/bare forms `fix #N`,
# `closed #N` occur constantly as ordinary English about work already done and
# excluding them would blind the scan), while that one must reproduce GitHub's
# ACTUAL closing-keyword set exactly, because GitHub's parser — not this
# repo's prose habits — decides what a merge closes.
DEFERRAL_CLOSING_KEYWORD_RE='\b(fixes|closes|resolves)\b[[:space:]]*#'

# Emits `path:line:text` rows for every source line that cites a `#NNN` AND
# carries deferral vocabulary. rc 2 (NOT 1, NOT 0) when the scan itself failed.
deferral_scan_hits() {
    local root="$1"
    local scan_err raw id_scan_rc
    scan_err="$(mktemp -t deferral-citations-err-XXXXXX)" || return 2

    raw="$(cd "$root" && grep -rEn "$DEFERRAL_ID_RE" \
               --include='*.rs' --include='*.ts' --include='*.svelte' --include='*.py' \
               . 2>"$scan_err")"
    id_scan_rc=$?

    # grep: 0 = matched, 1 = no match, >=2 = ERROR. Collapsing the third into
    # the second turns a broken detector into a green gate.
    if [ "$id_scan_rc" -ge 2 ] || [ -s "$scan_err" ]; then
        sed 's/^/    /' "$scan_err" >&2
        rm -f "$scan_err"
        return 2
    fi
    rm -f "$scan_err"

    # VENDORED THIRD-PARTY TREES ARE EXCLUDED, and this is load-bearing rather
    # than tidiness. A `#NNN` in someone else's source is THEIR issue number,
    # and these gates resolve ids against *csq's* tracker — so every such line
    # is resolved against an unrelated repo and the verdict is meaningless in
    # both directions.
    #
    # Measured 2026-08-08, before this filter, on a tree with `coc-env/.venv/`
    # populated: 5 of 6 reported findings came from site-packages —
    #
    #   tqdm/std.py            "*args intentionally not supported (see an internal ticket, an internal ticket)"
    #   sympy/solvers/ode.py   "an internal ticket: nonhomogeneous linear systems are not supported"
    #   joblib/.../popen.py    "Child process not yet created. See an internal ticket"
    #   kaizen/core/base_agent.py  "... not yet discovered (an internal ticket)"
    #
    # `an internal ticket` is a Launchpad bug id; csq will never have an issue that high.
    # An audit primitive that cries wolf is one nobody runs
    # (`tooling-self-verification.md` Rule 5), and at a 5-in-6 false-positive
    # rate the real finding is the one that gets skipped.
    printf '%s\n' "$raw" \
        | grep -Ei "$DEFERRAL_DEFER_RE" \
        | grep -v '/target/' \
        | grep -v '/workspaces/' \
        | grep -v '/node_modules/' \
        | grep -v '/\.claude/' \
        | grep -v '/sweeps/' \
        | grep -v '/journal/' \
        | grep -v '/\.venv/' \
        | grep -v '/site-packages/' \
        | grep -v '/coc-env/' \
        | grep -v '/vendor/' \
        | grep -vEi "$DEFERRAL_CLOSING_KEYWORD_RE"

    # The pipeline's own rc is meaningless here (a trailing `grep -v` exits 1
    # when it filters everything out, which is a CLEAN tree, not an error).
    # The only failure this function reports is the scan failure above.
    return 0
}

# stdin: hit rows. stdout: sorted unique bare ids.
#
# Extracts every `#NNN`-shaped token WITH its preceding character (if any).
# A token that is exactly `#NNN` (no captured prefix) is a BARE, in-repo
# reference — in scope. A token with a captured word-char prefix (`e#40`
# from `terrene#40`) is a QUALIFIED cross-repo reference — out of scope,
# silently dropped, never resolved (repo-scope-discipline.md).
deferral_ids() {
    grep -oE '[A-Za-z0-9_]?#[0-9]+' \
        | grep -E '^#[0-9]+$' \
        | sed 's/^#//' \
        | sort -un
}
