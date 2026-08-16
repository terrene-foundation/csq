#!/usr/bin/env bash
# Self-test for scripts/verify/fixture-timebombs.sh.
#
# The point is NOT that the script runs — it is that the script DISCRIMINATES in
# both directions. A time-bomb detector that also reds a correct parser assertion
# gets deleted by the first person it blocks, so the false-positive cases below
# carry as much weight as the true-positive one.
#
# Fixture epoch values are chosen to be STABLE regardless of when this test runs:
#   1_786_101_155 = 2026-08-07 — already past, so inside the horizon forever
#   4_102_444_800 = 2100-01-01 — beyond a 5-year horizon until ~2095
#
# Deliberately no `set -e` — most cases expect a non-zero exit.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/verify/fixture-timebombs.sh"
[ -f "$SCRIPT" ] || { echo "FATAL: $SCRIPT not found"; exit 2; }

TMPROOT="$(mktemp -d -t fixture-timebombs-selftest-XXXXXX)"
if [ -z "$TMPROOT" ] || [ ! -d "$TMPROOT" ]; then
  echo "FATAL: mktemp failed"; exit 2
fi
trap 'rm -rf "$TMPROOT"' EXIT

PASS=0; FAIL=0
check() { # check <desc> <expected-rc> <actual-rc>
  if [ "$2" -eq "$3" ]; then printf '  PASS  %s (exit %s)\n' "$1" "$3"; PASS=$((PASS+1))
  else printf '  FAIL  %s — expected exit %s, got %s\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}

# Builds a fixture tree containing exactly one .rs file with $2 as its body.
make_tree() {
  local name="$1" body="$2"
  local root="$TMPROOT/$name"
  mkdir -p "$root/csq-core/src/quota"
  printf '%s\n' "$body" > "$root/csq-core/src/quota/thing.rs"
  printf '%s' "$root"
}

echo "fixture-timebombs self-test"

# ── 1. The defect this exists to catch ───────────────────────────────────────
root="$(make_tree bomb '            resets_at: 1_786_101_155,')"
"$SCRIPT" "$root" --quiet; check "struct-literal past resets_at -> time-bomb" 1 "$?"

# ── 2. The mandated sentinel is clean ────────────────────────────────────────
root="$(make_tree sentinel '            resets_at: 4_102_444_800,')"
"$SCRIPT" "$root" --quiet; check "Rule-1 sentinel 4_102_444_800 -> clean" 0 "$?"

# ── 3. THE false-positive that would get this gate deleted ───────────────────
# usage_poller/grok.rs asserts an ISO string parses to this epoch. No liveness
# dependency; the test is correct. If the gate reds it, the gate is wrong.
root="$(make_tree parser_assert '        assert_eq!(w.resets_at, 1786101155);')"
"$SCRIPT" "$root" --quiet; check "assert_eq! parser assertion -> NOT flagged" 0 "$?"

# ── 4. The prescribed alternative must not be flagged ────────────────────────
root="$(make_tree computed '            resets_at: now_secs() + 86_400,')"
"$SCRIPT" "$root" --quiet; check "computed from now() -> NOT flagged" 0 "$?"

# ── 5. A commented-out bomb is not live code ─────────────────────────────────
root="$(make_tree commented '            // resets_at: 1_786_101_155,')"
"$SCRIPT" "$root" --quiet; check "commented-out literal -> NOT flagged" 0 "$?"

# ── 5b. Synthetic-past sentinel must NOT be flagged ──────────────────────────
# Regression guard for SIX false positives the first draft of this gate produced
# on the very tree it was written to clean: `resets_at: 1000` / `2000` / `5000` in
# quota/mod.rs::clear_expired_removes_old_windows and quota/state.rs are
# DELIBERATELY expired — they prove `clear_expired` nulls a past window. Flagging a
# correct test is how a gate earns deletion. This is why the check is a BAND.
root="$(make_tree synthetic_past '            resets_at: 1000,')"
"$SCRIPT" "$root" --quiet; check "1970-era synthetic sentinel -> NOT flagged" 0 "$?"

root="$(make_tree synthetic_past2 '            resets_at: 5000,')"
"$SCRIPT" "$root" --quiet; check "second synthetic sentinel -> NOT flagged" 0 "$?"

# ── 6. Nothing to find ───────────────────────────────────────────────────────
root="$(make_tree nothing 'let x = 1; // ordinary code')"
"$SCRIPT" "$root" --quiet; check "tree with no resets_at -> clean" 0 "$?"

# ── 7. Bad root -> UNDETERMINED, never a pass ────────────────────────────────
"$SCRIPT" "$TMPROOT/does-not-exist" --quiet; check "nonexistent root -> undetermined" 2 "$?"

# ── 8. Both literal spellings are caught ─────────────────────────────────────
# A gate matching only the underscore form would miss half the real tree.
root="$(make_tree plain '            resets_at: 1786101155,')"
"$SCRIPT" "$root" --quiet; check "non-underscored literal -> time-bomb" 1 "$?"

# ── 9. --quiet suppresses the REPORT but preserves the VERDICT ───────────────
root="$(make_tree quietcase '            resets_at: 1_786_101_155,')"
out="$("$SCRIPT" "$root" --quiet 2>/dev/null)"; rc=$?
if [ "$rc" -eq 1 ] && [ -z "$out" ]; then
  printf '  PASS  --quiet keeps the verdict and prints nothing\n'; PASS=$((PASS+1))
else
  printf '  FAIL  --quiet: expected rc=1 with empty stdout, got rc=%s out=%s\n' "$rc" "${out:0:60}"
  FAIL=$((FAIL+1))
fi

# ── 10. Non-quiet DOES report, and names the file and line ──────────────────
out="$("$SCRIPT" "$root" 2>/dev/null)"
if printf '%s' "$out" | grep -q 'thing.rs:1' && printf '%s' "$out" | grep -q '4_102_444_800'; then
  printf '  PASS  report names the site and the remedy\n'; PASS=$((PASS+1))
else
  printf '  FAIL  report missing site or remedy: %s\n' "${out:0:120}"; FAIL=$((FAIL+1))
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
