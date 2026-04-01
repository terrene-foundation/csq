
#!/bin/bash

# Read JSON input from stdin
input=$(cat)

# Extract basic information from JSON
current_dir=$(echo "$input" | jq -r '.workspace.current_dir')
model_name=$(echo "$input" | jq -r '.model.display_name')
project_name=$(basename "$current_dir")

# Feed quota data to rotation engine (non-blocking, background)
echo "$input" | python3 "$HOME/.claude/accounts/rotation-engine.py" update 2>/dev/null &

# Change to the current directory for git operations
cd "$current_dir" 2>/dev/null || cd ~

# Function to get account + quota info
get_claude_account() {
    local current_file="$HOME/.claude/accounts/.current"
    local profiles_file="$HOME/.claude/accounts/profiles.json"
    local account_num=""
    local account_info=""

    # Get current account number
    if [ -f "$current_file" ]; then
        account_num=$(cat "$current_file" 2>/dev/null)
    fi

    # Get email from profiles
    if [ -n "$account_num" ] && [ -f "$profiles_file" ]; then
        account_info=$(python3 -c "
import json
try:
    d = json.load(open('$profiles_file'))
    email = d.get('accounts', {}).get('$account_num', {}).get('email', '')
    if email:
        user = email.split('@')[0]
        print(f'#{account_num}:{user}' if len(user) <= 12 else f'#{account_num}:{user[:10]}..')
except: pass
" 2>/dev/null)
    fi

    # Fallback
    if [ -z "$account_info" ]; then
        account_info=$(whoami)
    fi

    # Get quota from rotation engine
    local quota
    quota=$(python3 "$HOME/.claude/accounts/rotation-engine.py" statusline 2>/dev/null)

    # Squad indicator: ⚡ = auto-rotate active, dim if no quota data yet
    local squad=""
    if [ -f "$HOME/.claude/accounts/rotation-engine.py" ] && [ -f "$HOME/.claude/accounts/credentials/1.json" ]; then
        squad="⚡squad"
    fi

    if [ -n "$quota" ]; then
        echo "👤${account_info} ${quota} ${squad}"
    elif [ -n "$squad" ]; then
        echo "👤${account_info} ${squad}"
    else
        echo "👤${account_info}"
    fi
}

# Function to get git status
get_git_status() {
    if git rev-parse --git-dir > /dev/null 2>&1; then
        local branch=$(git branch --show-current 2>/dev/null || echo "detached")
        local status=""
        local changes=""
        
        # Check for uncommitted changes
        local modified=$(git diff --name-only | wc -l | tr -d ' ')
        local staged=$(git diff --cached --name-only | wc -l | tr -d ' ')
        local untracked=$(git ls-files --others --exclude-standard | wc -l | tr -d ' ')
        
        # Calculate total changes
        local total_changes=$((modified + staged + untracked))
        
        # Set status indicator
        if [ $total_changes -gt 0 ]; then
            status="●" # Dirty (red dot)
            if [ $total_changes -gt 0 ]; then
                changes="($total_changes)"
            fi
        else
            status="●" # Clean (green dot)
        fi
        
        echo "⚡git:${branch}${status}${changes}"
    fi
}

# Function to get Python virtual environment
get_python_env() {
    if [ -n "$VIRTUAL_ENV" ]; then
        local env_name=$(basename "$VIRTUAL_ENV")
        echo "🐍${env_name}"
    elif [ -n "$CONDA_DEFAULT_ENV" ]; then
        echo "🐍${CONDA_DEFAULT_ENV}"
    elif [ -f "pyproject.toml" ] || [ -f "requirements.txt" ] || [ -f "Pipfile" ]; then
        echo "🐍system"
    fi
}

# Function to get Node.js info
get_node_info() {
    if [ -f "package.json" ]; then
        local node_version=""
        local package_manager=""
        
        # Detect package manager
        if [ -f "yarn.lock" ]; then
            package_manager="yarn"
        elif [ -f "pnpm-lock.yaml" ]; then
            package_manager="pnpm"
        elif [ -f "package-lock.json" ]; then
            package_manager="npm"
        else
            package_manager="npm"
        fi
        
        # Get Node version if available
        if command -v node > /dev/null 2>&1; then
            node_version=$(node --version 2>/dev/null | sed 's/v//')
        fi
        
        if [ -n "$node_version" ]; then
            echo "⬢${node_version}(${package_manager})"
        else
            echo "⬢${package_manager}"
        fi
    fi
}

# Function to check Docker status
get_docker_status() {
    if [ -n "$DOCKER_CONTAINER_ID" ] || [ -f "/.dockerenv" ]; then
        echo "🐳container"
    elif [ -f "Dockerfile" ] || [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
        if command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
            local running_containers=$(docker ps -q | wc -l | tr -d ' ')
            if [ "$running_containers" -gt 0 ]; then
                echo "🐳${running_containers}"
            else
                echo "🐳ready"
            fi
        else
            echo "🐳offline"
        fi
    fi
}

# Function to get current time
get_time() {
    echo "🕐$(date '+%H:%M')"
}

# Function to get system resources (if available)
get_resources() {
    local mem_info=""
    local cpu_info=""
    
    # Memory usage (macOS)
    if command -v vm_stat > /dev/null 2>&1; then
        local mem_pressure=$(memory_pressure 2>/dev/null | grep "System-wide memory free percentage" | awk '{print $5}' | sed 's/%//' 2>/dev/null)
        if [ -n "$mem_pressure" ] && [ "$mem_pressure" -lt 20 ]; then
            mem_info="📊mem:${mem_pressure}%"
        elif [ -n "$mem_pressure" ] && [ "$mem_pressure" -lt 50 ]; then
            mem_info="📊mem:${mem_pressure}%"
        fi
    fi
    
    # CPU load (simplified)
    if command -v uptime > /dev/null 2>&1; then
        local load=$(uptime | awk -F'load averages: ' '{print $2}' | awk '{print $1}' | sed 's/,//')
        if [ -n "$load" ]; then
            local load_int=$(echo "$load" | cut -d. -f1)
            if [ "$load_int" -gt 2 ]; then
                cpu_info="⚡${load}"
            elif [ "$load_int" -gt 1 ]; then
                cpu_info="⚡${load}"
            fi
        fi
    fi
    
    # Combine resource info
    local resources=""
    if [ -n "$mem_info" ]; then
        resources="$mem_info"
    fi
    if [ -n "$cpu_info" ]; then
        if [ -n "$resources" ]; then
            resources="${resources} ${cpu_info}"
        else
            resources="$cpu_info"
        fi
    fi
    
    if [ -n "$resources" ]; then
        echo "$resources"
    fi
}

# Function to get test status
get_test_status() {
    local test_indicator=""
    
    # Check for recent test files or common test directories
    if [ -d "tests" ] || [ -d "test" ] || [ -f "pytest.ini" ] || [ -f "tox.ini" ] || [ -f "jest.config.js" ]; then
        # Check for recent test artifacts
        if [ -f ".coverage" ] || [ -f "coverage.xml" ] || [ -d "htmlcov" ]; then
            test_indicator="✓tests"
        elif [ -f ".pytest_cache/CACHEDIR.TAG" ] || [ -d "node_modules/.cache/jest" ]; then
            test_indicator="⚠tests"
        else
            test_indicator="○tests"
        fi
    fi
    
    if [ -n "$test_indicator" ]; then
        echo "$test_indicator"
    fi
}

# Function to get background processes
get_bg_processes() {
    local bg_count=$(jobs | wc -l | tr -d ' ')
    if [ "$bg_count" -gt 0 ]; then
        echo "⚙${bg_count}"
    fi
}

# Build the status line
status_parts=()

# Add Claude account information first (most prominent)
claude_account=$(get_claude_account)
if [ -n "$claude_account" ]; then
    status_parts+=("$claude_account")
fi

# Always include model and project
status_parts+=("🤖${model_name}")
status_parts+=("📁${project_name}")

# Add git status
git_status=$(get_git_status)
if [ -n "$git_status" ]; then
    status_parts+=("$git_status")
fi

# Add Python environment
python_env=$(get_python_env)
if [ -n "$python_env" ]; then
    status_parts+=("$python_env")
fi

# Add Node.js info
node_info=$(get_node_info)
if [ -n "$node_info" ]; then
    status_parts+=("$node_info")
fi

# Add Docker status
docker_status=$(get_docker_status)
if [ -n "$docker_status" ]; then
    status_parts+=("$docker_status")
fi

# Add test status
test_status=$(get_test_status)
if [ -n "$test_status" ]; then
    status_parts+=("$test_status")
fi

# Add background processes
bg_processes=$(get_bg_processes)
if [ -n "$bg_processes" ]; then
    status_parts+=("$bg_processes")
fi

# Add system resources (only if there are issues)
resources=$(get_resources)
if [ -n "$resources" ]; then
    status_parts+=("$resources")
fi

# Add time
time_info=$(get_time)
status_parts+=("$time_info")

# Join all parts with " | "
IFS=" | "
echo "${status_parts[*]}"