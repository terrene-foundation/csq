#!/usr/bin/env bash
# Run one evaluator invocation; retain its verdict even under Actions' bash -e.
# Usage: bash phase-2b-evaluate.sh OUTDIR -- COMMAND [ARG...]
set -euo pipefail
if [[ $# -lt 3 || "$2" != -- ]]; then
    echo 'usage: phase-2b-evaluate.sh OUTDIR -- COMMAND [ARG...]' >&2
    exit 64
fi
report_dir="$1"
shift 2
io_rc=0
if ! mkdir -p "$report_dir"; then
    io_rc=74
fi

# Strict mode was enabled above. Disable errexit only for this pipeline, capture
# both stages before any command resets PIPESTATUS, then restore strict mode.
set +e
"$@" | tee "$report_dir/gate-report.json"
pipeline_status=("${PIPESTATUS[@]}")
set -e
evaluator_rc=${pipeline_status[0]}
tee_rc=${pipeline_status[1]}
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    if {
        printf '## Phase 2a → 2b transition gate\n\n' &&
        printf 'Evaluator exit code: \140%s\140 (0 ship · 1 DEFER · 2 UNDETERMINED).\n\n' "$evaluator_rc" &&
        printf 'Report transport exit code: \140%s\140.\n\n\140\140\140json\n' "$tee_rc" &&
        cat "$report_dir/gate-report.json" &&
        printf '\n\140\140\140\n'
    } >> "$GITHUB_STEP_SUMMARY"; then
        :
    else
        io_rc=74
    fi
fi
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    if ! printf 'evaluator_rc=%s\n' "$evaluator_rc" >> "$GITHUB_OUTPUT"; then
        io_rc=74
    fi
fi
if ! printf '{"evaluator_exit_code":%s,"tee_exit_code":%s,"report_io_exit_code":%s}\n' \
    "$evaluator_rc" "$tee_rc" "$io_rc" > "$report_dir/gate-status.json"; then
    io_rc=74
fi
printf 'Evaluator exit code: %s; report transport exit code: %s; report IO exit code: %s\n' \
    "$evaluator_rc" "$tee_rc" "$io_rc"
# A failed measurement stays its original nonzero verdict even if reporting also
# failed. A successful measurement cannot hide a broken report/summary transport.
if [[ "$evaluator_rc" -ne 0 ]]; then
    exit "$evaluator_rc"
fi
if [[ "$tee_rc" -ne 0 || "$io_rc" -ne 0 ]]; then
    exit 74
fi
exit 0
