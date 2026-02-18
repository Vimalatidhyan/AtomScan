#!/bin/bash
################################################################################
# ReconX - Shared Bash Utilities
# Source this file from every module:
#   source "$(dirname "$0")/../lib/common.sh"
################################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
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
export -f safe_cat
export -f safe_grep
export -f run_timeout
export -f check_disk_space
export -f tool_supports_flag
export -f run_tool
