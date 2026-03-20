#!/bin/bash
################################################################################
# Technieum - Shared Bash Utilities
# Source this file from every module:
#   source "$(dirname "$0")/../lib/common.sh"
################################################################################

# ── Tool PATH setup ───────────────────────────────────────────────────────────
# Ensure Go binaries, user-local installs, and pdtm tools are always reachable
# regardless of how the scanner was launched (Python subprocess, SSH, cron …).
#
# The repo's own bin/ directory is prepended FIRST so that shims (e.g. amass)
# take priority over broken system wrappers (e.g. /usr/bin/amass which tries
# to sudo-download libpostal data and hangs without a TTY).
_TECHNIEUM_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
_TECHNIEUM_BIN_DIR="${_TECHNIEUM_REPO_ROOT}/bin"
[ -d "$_TECHNIEUM_BIN_DIR" ] && export PATH="${_TECHNIEUM_BIN_DIR}:${PATH}"
unset _TECHNIEUM_REPO_ROOT _TECHNIEUM_BIN_DIR

_TECHNIEUM_EXTRA_PATHS=(
    "$HOME/go/bin"
    "$HOME/.local/bin"
    "$HOME/.pdtm/go/bin"
    "/usr/local/go/bin"
    "/usr/lib/go-1.24/bin"
    "/usr/local/bin"
)
for _p in "${_TECHNIEUM_EXTRA_PATHS[@]}"; do
    case ":$PATH:" in
        *":$_p:"*) ;;  # already present
        *) [ -d "$_p" ] && export PATH="$_p:$PATH" ;;
    esac
done
unset _p _TECHNIEUM_EXTRA_PATHS

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Ensure required bins are visible in non-interactive shells too.
export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin:$HOME/bin"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Warn once when executing under Windows mounted filesystem in WSL.
if [ -z "${TECHNIEUM_MNT_WARNED:-}" ] && [ -n "${PWD:-}" ] && [[ "$PWD" == /mnt/* ]]; then
    log_warn "Running under /mnt/* (Windows filesystem) can cause slower scans and tool execution issues. Prefer Linux home paths (e.g. ~/recon)."
    export TECHNIEUM_MNT_WARNED=1
fi

# resolve_tool_path <tool>
# Prints the best path for a tool (PATH + common fallback locations).
resolve_tool_path() {
    local tool="$1"
    local candidate=""
    if candidate="$(command -v "$tool" 2>/dev/null)" && [ -n "$candidate" ]; then
        echo "$candidate"
        return 0
    fi

    local fallback_paths=(
        "$HOME/go/bin/$tool"
        "$HOME/.local/bin/$tool"
        "$HOME/bin/$tool"
        "/usr/local/bin/$tool"
        "/usr/bin/$tool"
    )
    for candidate in "${fallback_paths[@]}"; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# have_tool <tool>
# Returns success if tool can be resolved via PATH or fallback locations.
have_tool() {
    resolve_tool_path "$1" >/dev/null 2>&1
}

# check_tool <tool>
# Prints standard status line and returns 0 when tool exists, else 1.
check_tool() {
    local tool="$1"
    if have_tool "$tool"; then
        echo "[OK] $tool found"
        return 0
    fi
    echo "[WARN] $tool missing — skipping"
    return 1
}

# run_optional <label> <timeout_seconds> <command...>
# Runs command safely with timeout; logs warning on failure and never hard-fails pipeline.
run_optional() {
    local label="$1"
    local timeout_seconds="$2"
    shift 2
    if run_timeout "$timeout_seconds" "$@"; then
        return 0
    fi
    local ec=$?
    if [ "$ec" -eq 124 ]; then
        log_warn "$label timed out after ${timeout_seconds}s"
    else
        log_warn "$label failed (exit=$ec)"
    fi
    return "$ec"
}

# ensure_goblob_wordlist
# Ensures a default goblob container wordlist exists and prints its path.
ensure_goblob_wordlist() {
    local out_path="${TECHNIEUM_GOBLOB_WORDLIST:-$HOME/wordlists/goblob-containers.txt}"
    local out_dir
    out_dir="$(dirname "$out_path")"
    mkdir -p "$out_dir"

    if [ -s "$out_path" ]; then
        echo "$out_path"
        return 0
    fi

    local url="${TECHNIEUM_GOBLOB_WORDLIST_URL:-https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt}"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$out_path" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$out_path" 2>/dev/null || true
    fi

    if [ ! -s "$out_path" ]; then
        cat > "$out_path" << 'EOF'
admin
api
backup
bucket
cdn
dev
files
media
prod
stage
storage
test
EOF
    fi

    echo "$out_path"
    return 0
}

# ensure_python_repo_tool <repo_dir> <repo_url> <entry_script> [requirements_file]
# Best-effort helper for Python repo tools. Prints absolute script path if available.
ensure_python_repo_tool() {
    local repo_dir="$1"
    local repo_url="$2"
    local entry_script="$3"
    local req_file="${4:-requirements.txt}"

    if [ ! -d "$repo_dir" ] && command -v git >/dev/null 2>&1; then
        mkdir -p "$(dirname "$repo_dir")"
        git clone --depth 1 "$repo_url" "$repo_dir" >/dev/null 2>&1 || true
    fi

    if [ -f "$repo_dir/$entry_script" ]; then
        if [ -f "$repo_dir/$req_file" ] && command -v python3 >/dev/null 2>&1; then
            python3 -m pip install -r "$repo_dir/$req_file" >/dev/null 2>&1 || true
        fi
        echo "$repo_dir/$entry_script"
        return 0
    fi

    return 1
}

# safe_cat <output_file> [input_files...]
# Concatenate non-empty input files into output_file, never failing.
safe_cat() {
    local output_file="$1"
    shift

    > "$output_file"

    for file in "$@"; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            cat "$file" >> "$output_file" 2>/dev/null || true
        fi
    done

    return 0
}

# safe_grep — wrapper around grep that never returns exit code 1 on no match.
safe_grep() {
    grep "$@" || true
}

# check_disk_space <directory>
# Returns 1 (and logs an error) if free space is below MIN_DISK_MB (default 1024).
check_disk_space() {
    local dir="$1"
    local min_mb="${MIN_DISK_MB:-1024}"
    local avail_kb
    avail_kb=$(df -k "$dir" 2>/dev/null | awk 'NR==2{print $4}')
    if [ -n "$avail_kb" ] && [ "$avail_kb" -lt $(( min_mb * 1024 )) ]; then
        log_error "Low disk space: $(( avail_kb / 1024 ))MB free (minimum: ${min_mb}MB). Stopping scan."
        return 1
    fi
    return 0
}

# tool_supports_flag <tool> <flag>
# Returns 0 if <tool> help output mentions <flag>, 1 otherwise.
tool_supports_flag() {
    local tool="$1"
    local flag="$2"
    "$tool" --help 2>&1 | grep -q -- "$flag"
}

# run_tool <tool_cmd...>
# Run a tool, suppressing stderr, and always succeed (exit 0).
run_tool() {
    "$@" 2>/dev/null || true
}

# run_timeout SECONDS cmd [args...]
# Portable timeout: use timeout/gtimeout if available, else run in background and kill after SECONDS (macOS).
run_timeout() {
    local t="$1"
    shift
    if command -v timeout &>/dev/null; then
        timeout "$t" "$@"
        return $?
    fi
    if command -v gtimeout &>/dev/null; then
        gtimeout "$t" "$@"
        return $?
    fi
    # Fallback: run in background, poll until done or timeout expires, then kill.
    # Returns the real exit code if the command finishes early, or 124 on timeout.
    "$@" &
    local pid=$!
    local elapsed=0
    while [ "$elapsed" -lt "$t" ]; do
        # If process has already exited, harvest its exit code immediately.
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            return $?
        fi
        sleep 1
        elapsed=$(( elapsed + 1 ))
    done
    # Timeout reached — kill the process and return 124 (same as GNU timeout).
    kill -- "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 124
}

export -f log_info
export -f log_error
export -f log_warn
export -f resolve_tool_path
export -f have_tool
export -f check_tool
export -f run_optional
export -f ensure_goblob_wordlist
export -f ensure_python_repo_tool
export -f safe_cat
export -f safe_grep
export -f run_timeout
export -f check_disk_space
export -f tool_supports_flag
export -f run_tool
