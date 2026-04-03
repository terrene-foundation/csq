
#!/bin/bash

# Read JSON input from stdin
input=$(cat)

# Extract basic information from JSON
current_dir=$(echo "$input" | jq -r '.workspace.current_dir')
model_name=$(echo "$input" | jq -r '.model.display_name')
project_name=$(basename "$current_dir")

# Extract token usage and cost
total_in=$(echo "$input" | jq -r '.context_window.total_input_tokens // 0')
total_out=$(echo "$input" | jq -r '.context_window.total_output_tokens // 0')
session_cost=$(echo "$input" | jq -r '.cost.total_cost_usd // 0')

# Feed quota data to rotation engine (per-terminal, uses CLAUDE_CONFIG_DIR)
# Run synchronously during polls (CLAUDE_SQUAD_POLL=1) so data writes before subprocess exits.
# Background for interactive sessions to keep the statusline fast.
if [ "${CLAUDE_SQUAD_POLL:-}" = "1" ]; then
    echo "$input" | python3 "$HOME/.claude/accounts/rotation-engine.py" update 2>/dev/null
else
    echo "$input" | python3 "$HOME/.claude/accounts/rotation-engine.py" update 2>/dev/null &
fi

# Change to the current directory for git operations
cd "$current_dir" 2>/dev/null || cd ~

# Function to get account + quota info
get_claude_account() {
    # rotation-engine.py statusline returns: #N:user 5h:X% 7d:Y%
    # It reads CLAUDE_CONFIG_DIR to determine which account this terminal is on.
    local quota
    quota=$(python3 "$HOME/.claude/accounts/rotation-engine.py" statusline 2>/dev/null)

    if [ -n "$quota" ]; then
        echo "${quota}"
    elif [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        # Config dir set but no quota yet — show account number
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

# Build the status line
status_parts=()

# Add Claude account information first (most prominent)
claude_account=$(get_claude_account)
if [ -n "$claude_account" ]; then
    # Squad indicator: ⚡ if auto-rotate is active (credentials exist for 2+ accounts)
    local_creds=$(ls "$HOME/.claude/accounts/credentials/"*.json 2>/dev/null | wc -l | tr -d ' ')
    if [ "$local_creds" -ge 2 ]; then
        status_parts+=("⚡${claude_account}")
    else
        status_parts+=("${claude_account}")
    fi
fi

# Token usage (this context) + session cost (all agents combined)
if [ "$total_in" -gt 0 ] || [ "$total_out" -gt 0 ]; then
    total=$((total_in + total_out))
    tin=$(fmt_tokens "$total_in")
    tout=$(fmt_tokens "$total_out")
    ttotal=$(fmt_tokens "$total")
    cost_fmt=$(printf '$%.2f' "$session_cost")
    status_parts+=("in:${tin} out:${tout} ctx:${ttotal} | ${cost_fmt}")
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