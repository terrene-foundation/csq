#!/bin/bash
# Statusline hook — shows account + quota, feeds data to rotation engine

command -v jq >/dev/null 2>&1 || { echo ""; exit 0; }

# Read JSON input from stdin
input=$(cat)

# Extract basic information from JSON
current_dir=$(echo "$input" | jq -r '.workspace.current_dir')
model_name=$(echo "$input" | jq -r '.model.display_name')
project_name=$(basename "$current_dir")

# Extract context window usage (current turn — what's actually in the window)
# cache_creation = new content being cached, cache_read = reused from cache
# input_tokens = non-cached input, output_tokens = model output
ctx_input=$(echo "$input" | jq -r '.context_window.current_usage.input_tokens // 0')
ctx_output=$(echo "$input" | jq -r '.context_window.current_usage.output_tokens // 0')
ctx_cache_create=$(echo "$input" | jq -r '.context_window.current_usage.cache_creation_input_tokens // 0')
ctx_cache_read=$(echo "$input" | jq -r '.context_window.current_usage.cache_read_input_tokens // 0')
ctx_used_pct=$(echo "$input" | jq -r '.context_window.used_percentage // 0')

# Session cost
session_cost=$(echo "$input" | jq -r '.cost.total_cost_usd // 0')

# Snapshot the live account from the keychain when CC has just (re)started.
# Cheap path: one os.kill probe and return. Expensive path runs only on a CC
# restart, when it walks the parent process tree, reads the keychain, and
# rewrites .current-account to match what CC actually loaded into memory.
# MUST run synchronously and BEFORE `update`, so update_quota() attributes
# the incoming rate_limits to the correct (live) account.
python3 "$HOME/.claude/accounts/rotation-engine.py" snapshot 2>/dev/null

# Feed quota data to rotation engine.
echo "$input" | python3 "$HOME/.claude/accounts/rotation-engine.py" update 2>/dev/null &

# Change to the current directory for git operations
cd "$current_dir" 2>/dev/null || cd ~

# Function to get account + quota info
get_claude_account() {
    local quota
    quota=$(python3 "$HOME/.claude/accounts/rotation-engine.py" statusline 2>/dev/null)

    if [ -n "$quota" ]; then
        echo "${quota}"
    elif [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        local dir_name
        dir_name=$(basename "$CLAUDE_CONFIG_DIR")
        echo "${dir_name##config-}"
    fi
}

# Function to get git status (branch + dirty indicator only)
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

# Function to format token count (compact: 1.2k, 45k, 1.2M)
fmt_tokens() {
    local n="$1"
    if [ "$n" -ge 1000000 ]; then
        printf "%.1fM" "$(echo "scale=1; $n / 1000000" | bc)"
    elif [ "$n" -ge 1000 ]; then
        printf "%.0fk" "$(echo "scale=0; $n / 1000" | bc)"
    else
        echo "$n"
    fi
}

# Detect if THIS terminal is a csq-managed terminal
# (CLAUDE_CONFIG_DIR points to ~/.claude/accounts/config-N)
is_csq_terminal=false
if [ -n "${CLAUDE_CONFIG_DIR:-}" ] && [[ "$CLAUDE_CONFIG_DIR" == "$HOME/.claude/accounts/config-"* ]]; then
    is_csq_terminal=true
fi

# Build the status line
status_parts=()

# Add csq marker + account information first (most prominent)
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

# Context window: total tokens in current window + % used
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
