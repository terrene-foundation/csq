#!/usr/bin/env bash
# Statusline hook — pure shell + Rust csq binary, no Python.
# `csq statusline` handles snapshot, sync, quota update, and rendering.

command -v jq >/dev/null 2>&1 || { echo ""; exit 0; }

# Locate the csq binary. Prefer PATH (user's installed version, likely
# most recent) over the legacy ~/.claude/accounts/csq location which
# may be a stale copy from a prior install.
CSQ=""
for candidate in "$(command -v csq 2>/dev/null)" "$HOME/.claude/accounts/csq"; do
    if [ -x "$candidate" ]; then
        CSQ="$candidate"
        break
    fi
done
[[ -n "$CSQ" ]] || { echo ""; exit 0; }

# Read JSON input from stdin
input=$(cat)

# Extract basic information from JSON
current_dir=$(echo "$input" | jq -r '.workspace.current_dir')
model_name=$(echo "$input" | jq -r '.model.display_name')
project_name=$(basename "$current_dir")

# Context window usage
ctx_input=$(echo "$input" | jq -r '.context_window.current_usage.input_tokens // 0')
ctx_output=$(echo "$input" | jq -r '.context_window.current_usage.output_tokens // 0')
ctx_cache_create=$(echo "$input" | jq -r '.context_window.current_usage.cache_creation_input_tokens // 0')
ctx_cache_read=$(echo "$input" | jq -r '.context_window.current_usage.cache_read_input_tokens // 0')
ctx_used_pct=$(echo "$input" | jq -r '.context_window.used_percentage // 0')

# Session cost
session_cost=$(echo "$input" | jq -r '.cost.total_cost_usd // 0')

# Change to the current directory for git operations
cd "$current_dir" 2>/dev/null || cd ~

# csq statusline: reads CC JSON from stdin, runs snapshot + sync + quota update,
# outputs the formatted account + quota string. All in one Rust binary call.
get_claude_account() {
    local quota
    quota=$(echo "$input" | "$CSQ" statusline 2>/dev/null)

    if [ -n "$quota" ]; then
        echo "${quota}"
    elif [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        # Fallback: read the .csq-account marker inside the handle dir
        # (or config dir). In the handle-dir model the marker is a
        # symlink to config-<N>/.csq-account containing the account
        # number. Reading the file (following symlinks) always gives
        # the correct account number regardless of the dir name.
        local marker="${CLAUDE_CONFIG_DIR}/.csq-account"
        if [ -f "$marker" ]; then
            cat "$marker"
        else
            local dir_name
            dir_name=$(basename "$CLAUDE_CONFIG_DIR")
            # Strip config- prefix for legacy dirs; term-<pid> dirs
            # pass through as-is (better than nothing).
            echo "${dir_name##config-}"
        fi
    fi
}

# Git status (branch + dirty indicator)
get_git_status() {
    if git rev-parse --git-dir > /dev/null 2>&1; then
        local branch=$(git branch --show-current 2>/dev/null || echo "detached")
        local dirty=""
        if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
            dirty="●"
        fi
        echo "git:${branch}${dirty}"
    fi
}

# Format token count (compact: 1.2k, 45k, 1.2M)
fmt_tokens() {
    local n="$1"
    if [ "$n" -ge 1000000 ]; then
        awk "BEGIN{printf \"%.1fM\", $n/1000000}"
    elif [ "$n" -ge 1000 ]; then
        awk "BEGIN{printf \"%.0fk\", $n/1000}"
    else
        echo "$n"
    fi
}

# Detect if THIS terminal is csq-managed. Both legacy config-N dirs
# and modern term-<pid> handle dirs live under ~/.claude/accounts/.
is_csq_terminal=false
if [ -n "${CLAUDE_CONFIG_DIR:-}" ] && [[ "$CLAUDE_CONFIG_DIR" == "$HOME/.claude/accounts/"* ]]; then
    is_csq_terminal=true
fi

# Build the status line
status_parts=()

claude_account=$(get_claude_account)
if $is_csq_terminal; then
    if [ -n "$claude_account" ]; then
        status_parts+=("⚡csq ${claude_account}")
    else
        status_parts+=("⚡csq")
    fi
elif [ -n "$claude_account" ]; then
    status_parts+=("${claude_account}")
fi

# Context window
ctx_total=$((ctx_input + ctx_output + ctx_cache_create + ctx_cache_read))
if [ "$ctx_total" -gt 0 ]; then
    ctx_fmt=$(fmt_tokens "$ctx_total")
    cost_fmt=$(printf '$%.2f' "$session_cost")
    status_parts+=("ctx:${ctx_fmt} ${ctx_used_pct}% | ${cost_fmt}")
fi

# Model and project
status_parts+=("🤖${model_name}")
status_parts+=("📁${project_name}")

# Git status
git_status=$(get_git_status)
if [ -n "$git_status" ]; then
    status_parts+=("$git_status")
fi

# Join all parts with " | "
result=""
for part in "${status_parts[@]}"; do
    if [ -n "$result" ]; then
        result="${result} | ${part}"
    else
        result="$part"
    fi
done
echo "$result"
