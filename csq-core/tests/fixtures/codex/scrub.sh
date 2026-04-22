#!/usr/bin/env bash
# PII scrub for wham/usage live captures.
#
# Replaces `user_id`, `account_id`, `email`, and any `sub` JWT claim at the
# top level with fixed REDACTED sentinels. Input is a raw curl capture from
# `GET chatgpt.com/backend-api/wham/usage`; output is safe to commit as a
# test fixture. See workspaces/codex/journal/0010 for the captured schema
# and redteam H5 for the redaction target set.
#
# Usage:
#   ./scrub.sh < raw.json > golden.json
#
# Requires: jq >= 1.6.

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "scrub.sh: jq is required but not installed" >&2
  exit 2
fi

jq '
  (.user_id // empty)    |= "REDACTED-user-id"
  | (.account_id // empty) |= "REDACTED-account-id"
  | (.email // empty)      |= "REDACTED@example.invalid"
  | (.sub // empty)        |= "REDACTED-sub"
'
