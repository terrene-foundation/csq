#!/usr/bin/env bash
#
# Self-test for `scripts/verify/tarball-traversal-guard.sh` — the release
# workflow's pre-extraction path-traversal guard.
#
# WHY THIS EXISTS
#
# The guard used to be `tar tzf X | grep -qE '(^|/)\.\.($|/)|^/'` under  # pipefail-ok: prose quoting the refused form
# pipefail. grep -q exits at its FIRST match, tar takes SIGPIPE, the pipeline
# reports 141, and the `if` is FALSE on exactly the hostile archive the guard
# exists to refuse. The attacker controls entry order, so the fail-open arm is
# steerable: put `../` FIRST and pad the listing.
#
# Rows:
#   * HOSTILE ORDERING — `../evil` is the FIRST entry, followed by padding:
#     must be rc 1 and name the entry (the R1-steerable fail-open case);
#   * an absolute-path entry: rc 1;
#   * a clean archive: rc 0 (the false-positive control);
#   * a TRUNCATED valid gzip: rc 2 (unmeasured, never a pass);
#   * non-gzip garbage: rc 2;
#   * a missing file: rc 2.
#
# Bash 3.2 compatible. Exits 0 on success, 1 on any failed assertion.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/../verify/tarball-traversal-guard.sh"
[ -f "$GUARD" ] || { echo "FATAL: guard not found at $GUARD" >&2; exit 64; }

PASS=0; FAIL=0; SKIP=0
TMPROOT="$(mktemp -d -t traversal-guard-selftest-XXXXXX)" || { echo "FATAL: mktemp failed" >&2; exit 64; }
trap 'rm -rf "$TMPROOT"' EXIT

expect_rc() { # name want got
    if [ "$3" -eq "$2" ]; then PASS=$((PASS+1)); echo "  PASS  $1 (rc $3)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $1 — expected rc $2, got $3"; fi
}
expect_stderr() { # name file substring
    if grep -qF -- "$3" "$2" 2>/dev/null; then PASS=$((PASS+1)); echo "  PASS  $1"
    else FAIL=$((FAIL+1)); echo "  FAIL  $1 — stderr lacks '$3'"; sed 's/^/         /' "$2" >&2; fi
}

# python3 writes an archive with EXACT entry names (tar itself normalises `..`
# away, which would defeat the fixture).
make_tar() { # outfile python-expression producing the name list
    python3 -I - "$1" "$2" <<'PY'
import sys, tarfile, io
out, mode = sys.argv[1], sys.argv[2]
names = []
if mode == "hostile":
    names = ["../evil"] + ["pad/%04d.txt" % i for i in range(200)]
elif mode == "absolute":
    names = ["/etc/passwd", "pad.txt"]
elif mode == "clean":
    names = ["csq.app/Contents/Info.plist", "csq.app/Contents/Helpers/csq-cli"]
with tarfile.open(out, "w:gz") as t:
    for n in names:
        data = b"x"
        ti = tarfile.TarInfo(n)
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
PY
}

echo "tarball-traversal-guard self-test"

D="$TMPROOT/clean"; mkdir -p "$D"; make_tar "$D/clean.tar.gz" clean
"$GUARD" "$D/clean.tar.gz" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "a clean archive passes" 0 "$RC"

D="$TMPROOT/hostile"; mkdir -p "$D"; make_tar "$D/hostile.tar.gz" hostile
"$GUARD" "$D/hostile.tar.gz" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "HOSTILE ORDERING: ../ is the FIRST entry" 1 "$RC"
expect_stderr "the hostile refusal names the first entry" "$D/err" "../evil"

D="$TMPROOT/absolute"; mkdir -p "$D"; make_tar "$D/absolute.tar.gz" absolute
"$GUARD" "$D/absolute.tar.gz" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "an absolute-path entry is refused" 1 "$RC"
expect_stderr "the absolute refusal names the entry" "$D/err" "/etc/passwd"

# Truncated VALID gzip: tar lists the first entries, then fails. The guard must
# read that as UNMEASURED (rc 2), never as "no traversal found".
D="$TMPROOT/trunc"; mkdir -p "$D"
python3 -I - "$D/full.tar.gz" <<'PY'
import tarfile, io, sys
with tarfile.open(sys.argv[1], "w:gz") as t:
    for i in range(400):
        data = b"y" * 200
        ti = tarfile.TarInfo("pad/%04d.txt" % i); ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
PY
FULL_BYTES="$(wc -c < "$D/full.tar.gz" | tr -d ' ')"
CUT=$((FULL_BYTES * 6 / 10))
head -c "$CUT" "$D/full.tar.gz" > "$D/trunc.tar.gz"
"$GUARD" "$D/trunc.tar.gz" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "a truncated valid gzip is UNDETERMINED" 2 "$RC"
expect_stderr "the truncated refusal says it cannot list" "$D/err" "cannot list"

printf 'not a gzip archive\n' > "$D/garbage.tar.gz"
"$GUARD" "$D/garbage.tar.gz" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "non-gzip garbage is UNDETERMINED" 2 "$RC"

"$GUARD" "$D/does-not-exist.tar.gz" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "a missing file is UNDETERMINED" 2 "$RC"

"$GUARD" "$D/clean.tar.gz" "ten" >"$D/out" 2>"$D/err"; RC=$?
expect_rc "a non-integer max-listed is UNDETERMINED" 2 "$RC"

echo ""
echo "tarball-traversal-guard self-test: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
