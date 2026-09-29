#!/usr/bin/env python3
"""The ONE implementation of the UNDETERMINED-allowlist policy.

Both consumers call this — the CI step `Run shell gate self-tests`
(.github/workflows/test.yml) and the `shell-gate` gate in
scripts/ci/dev-preflight.mjs — so they cannot disagree on what is allowed.
The first version implemented the policy twice and the two copies drifted in
three ways within one commit (review of face6473: local-vs-UTC "today", a
prefix-less entry matched in one and not the other, and a string date compare
that failed OPEN on "TBD" / "never" / "2026-1-5").

Output, one line per entry, TAB-separated:
    ALLOW<TAB><scripts/tests/...><TAB><token>
    INVALID<TAB><test or ?><TAB><reason>
Only ALLOW lines grant anything. Every validation failure is INVALID, so the
entry grants nothing and its test FAILS on exit 2 — fail closed.

Exit 0 when the declaration was read (even if every entry is INVALID).
Exit 2 when the declaration itself cannot be read or parsed: the caller must
then allow NOTHING. There is no exit path that widens the allowlist.
"""
import datetime
import json
import re
import shutil
import sys

DECL = "scripts/tests/undetermined-allowlist.json"
PREFIX = "scripts/tests/"
# An exemption must be revisited within this many days of TODAY. A far-future
# date is otherwise a permanent exemption with a warning attached, which is the
# decay ci-job-budget.md forbids ("no exemption without a dated revisit").
MAX_HORIZON_DAYS = 90
# [0-9], not \d: \d also matches non-ASCII digits.
ISO_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
# Exit 2 is NOT reserved for "could not measure": bash exits 2 on a syntax
# error, on builtin misuse, and grep/diff exit 2 on errors. An exemption keyed
# on (path, exit 2) alone therefore absorbed a BROKEN test as UNDETERMINED
# (round-3 security review). So an exemption must also carry its REASON:
#   token          — the test must print a line beginning UNDETERMINED[<token>]
#                    for the exit 2 to count; a crash never prints it.
#   requires_absent — the tool whose absence is the reason. Where that tool IS
#                    installed the exemption is void and the test must measure,
#                    so the exemption expires by itself once the cause is fixed.
TOKEN = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")
TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# A test path is matched EXACTLY by callers, but it is also embedded in CI
# output; keep it to a boring alphabet so no caller can misread it.
# fullmatch, never match: Python's `$` also matches before ONE trailing \n.
SAFE_PATH = re.compile(r"^scripts/tests/[A-Za-z0-9_.-]+\.test\.sh$")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DECL
    try:
        with open(path, encoding="utf-8") as fh:
            decl = json.load(fh)
        entries = decl["allow"]
        if not isinstance(entries, list):
            raise TypeError("'allow' is not a list")
    except Exception as exc:  # unreadable declaration -> caller allows NOTHING
        print(
            f"UNDETERMINED: cannot read {path}: {type(exc).__name__}", file=sys.stderr
        )
        return 2

    # UTC on purpose: the CI runner and a +08 developer host must agree on
    # which day it is, or one goes green while the other goes red.
    today = datetime.datetime.now(datetime.timezone.utc).date()
    horizon = today + datetime.timedelta(days=MAX_HORIZON_DAYS)

    for e in entries:
        test = e.get("test") if isinstance(e, dict) else None
        revisit = e.get("revisit") if isinstance(e, dict) else None
        # NEVER print an untrusted value raw into this TSV. A rejected `test`
        # of "zz\nALLOW\tscripts/tests/x.test.sh" printed verbatim on its
        # INVALID line becomes a SECOND record — an ALLOW that both consumers
        # honour (measured 2026-09-24: a rejected entry granted an exemption).
        # json.dumps escapes \n and \t, so every INVALID line stays ONE record.
        label = json.dumps(test)
        if not isinstance(test, str) or not SAFE_PATH.fullmatch(test):
            print(f"INVALID\t{label}\ttest must match {SAFE_PATH.pattern}")
            continue
        if not isinstance(revisit, str) or not ISO_DATE.fullmatch(revisit):
            print(
                f"INVALID\t{test}\trevisit {json.dumps(revisit)} is not a zero-padded YYYY-MM-DD date"
            )
            continue
        try:
            when = datetime.date.fromisoformat(revisit)
        except ValueError:
            print(f"INVALID\t{test}\trevisit {json.dumps(revisit)} is not a real calendar date")
            continue
        if when < today:
            print(
                f"INVALID\t{test}\texemption EXPIRED on {revisit} (today {today} UTC)"
            )
            continue
        if when > horizon:
            print(
                f"INVALID\t{test}\trevisit {revisit} is more than {MAX_HORIZON_DAYS} days out"
            )
            continue
        token = e.get("token")
        tool = e.get("requires_absent")
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            print(f"INVALID\t{test}\ttoken {json.dumps(token)} must match {TOKEN.pattern}")
            continue
        if not isinstance(tool, str) or not TOOL.fullmatch(tool):
            print(f"INVALID\t{test}\trequires_absent {json.dumps(tool)} must name a tool")
            continue
        if shutil.which(tool):
            print(f"INVALID\t{test}\tprecondition not met: {tool} IS installed here, so this test must measure")
            continue
        print(f"ALLOW\t{test}\t{token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
