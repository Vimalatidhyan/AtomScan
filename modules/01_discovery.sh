#!/bin/bash
################################################################################
# ReconX - Phase 1: Horizontal & Vertical Discovery
# Comprehensive subdomain enumeration using ALL tools
# FIXED: Removed fail-fast, added proper error handling
################################################################################

# DO NOT use set -e - we want to continue even if tools fail
set -o pipefail  # Catch errors in pipelines

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

# Validate target format (basic domain validation)
if ! echo "$TARGET" | grep -E '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' > /dev/null; then
    echo "Error: Invalid target format: $TARGET"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase1_discovery"
mkdir -p "$PHASE_DIR"

echo "[*] Phase 1: Discovery & Enumeration for $TARGET"
echo "[*] Output directory: $PHASE_DIR"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Tool execution tracking
TOOLS_SUCCESS=0
TOOLS_FAILED=0
TOOLS_SKIPPED=0

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Enhanced run_tool function with timeout and proper error handling
run_tool() {
    local tool_name="$1"
    local output_file="$2"
    local timeout_duration="${3:-600}"  # Default 10 min timeout
    shift 3
    local cmd="$@"

    if ! command -v "$tool_name" &> /dev/null; then
        log_warn "$tool_name not installed, skipping..."
        ((TOOLS_SKIPPED++))
        return 2
    fi

    log_info "Running $tool_name (timeout: ${timeout_duration}s)..."
    local start_time=$(date +%s)

    # Run with timeout and capture exit code
    if timeout "$timeout_duration" bash -c "$cmd" 2>"${output_file}.err"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_info "$tool_name completed successfully (${duration}s)"
        ((TOOLS_SUCCESS++))
        return 0
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [ $exit_code -eq 124 ]; then
            log_error "$tool_name timed out after ${timeout_duration}s"
        else
            log_error "$tool_name failed with exit code $exit_code (${duration}s)"
        fi

        ((TOOLS_FAILED++))
        return 1
    fi
}

# Safe cat/merge function that doesn't fail on empty files
safe_cat() {
    local output_file="$1"
    shift

    > "$output_file"  # Create empty file

    for file in "$@"; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            cat "$file" >> "$output_file" 2>/dev/null || true
        fi
    done

    return 0
}

# Safe grep that doesn't fail on no matches
safe_grep() {
    grep "$@" || true
}

################################################################################
# PHASE 1A: HORIZONTAL DISCOVERY (Acquisitions)
################################################################################

log_info "=== HORIZONTAL DISCOVERY ==="

# Whois domain information
if command -v whois &> /dev/null; then
    log_info "Running whois..."
    timeout 30 whois "$TARGET" > "$PHASE_DIR/whois.txt" 2>/dev/null || log_warn "Whois failed or timed out"
else
    log_warn "whois not found"
    ((TOOLS_SKIPPED++))
fi

# Amass Intel/Enum (version-aware)
if command -v amass &> /dev/null; then
    if amass intel -h >/dev/null 2>&1; then
        run_tool "amass" "$PHASE_DIR/amass_intel.txt" 300 \
            "amass intel -d '$TARGET' -whois -timeout 10 -o '$PHASE_DIR/amass_intel.txt'" || true
    else
        log_warn "Amass intel not supported; using passive enum instead"
        run_tool "amass" "$PHASE_DIR/amass_intel.txt" 300 \
            "amass enum -d '$TARGET' -passive -timeout 15 -o '$PHASE_DIR/amass_intel.txt'" || true
    fi
else
    log_warn "Amass not found"
    ((TOOLS_SKIPPED++))
fi

# Get subsidiaries (if tool exists)
if [ -f "/opt/getSubsidiaries/getSubsidiaries.py" ]; then
    log_info "Running getSubsidiaries..."
    timeout 300 python3 /opt/getSubsidiaries/getSubsidiaries.py "$TARGET" > "$PHASE_DIR/subsidiaries.txt" 2>/dev/null || log_warn "getSubsidiaries failed"
else
    log_warn "getSubsidiaries not found"
    ((TOOLS_SKIPPED++))
fi

################################################################################
# PHASE 1B: VERTICAL DISCOVERY (Subdomains)
################################################################################

log_info "=== VERTICAL DISCOVERY (SUBDOMAIN ENUMERATION) ==="

# Create temp directory for individual tool outputs
TEMP_SUBS="$PHASE_DIR/temp_subdomains"
mkdir -p "$TEMP_SUBS"

# Launch all subdomain enumeration tools in parallel with proper error handling
pids=()
declare -A tool_pids

# 1. Sublist3r
if command -v sublist3r &> /dev/null || [ -f "/opt/Sublist3r/sublist3r.py" ]; then
    log_info "Launching Sublist3r..."
    (
        timeout 900 bash -c "
            if [ -f '/opt/Sublist3r/sublist3r.py' ]; then
                python3 /opt/Sublist3r/sublist3r.py -d '$TARGET' -o '$TEMP_SUBS/sublist3r.txt'
            else
                sublist3r -d '$TARGET' -o '$TEMP_SUBS/sublist3r.txt'
            fi
        " 2>/dev/null || touch "$TEMP_SUBS/sublist3r.txt"
    ) &
    tool_pids[sublist3r]=$!
    pids+=($!)
else
    log_warn "Sublist3r not found"
    ((TOOLS_SKIPPED++))
fi

# 2. OWASP Amass Enum
if command -v amass &> /dev/null; then
    log_info "Launching Amass enum..."
    (
        timeout 900 amass enum -d "$TARGET" -passive -timeout 15 -o "$TEMP_SUBS/amass.txt" 2>/dev/null || touch "$TEMP_SUBS/amass.txt"
    ) &
    tool_pids[amass]=$!
    pids+=($!)
else
    log_warn "Amass not found"
    ((TOOLS_SKIPPED++))
fi

# 3. Assetfinder
if command -v assetfinder &> /dev/null; then
    log_info "Launching Assetfinder..."
    (
        timeout 600 assetfinder --subs-only "$TARGET" > "$TEMP_SUBS/assetfinder.txt" 2>/dev/null || touch "$TEMP_SUBS/assetfinder.txt"
    ) &
    tool_pids[assetfinder]=$!
    pids+=($!)
else
    log_warn "Assetfinder not found"
    ((TOOLS_SKIPPED++))
fi

# 4. Subfinder
if command -v subfinder &> /dev/null; then
    log_info "Launching Subfinder..."
    (
        timeout 600 subfinder -d "$TARGET" -silent -o "$TEMP_SUBS/subfinder.txt" 2>/dev/null || touch "$TEMP_SUBS/subfinder.txt"
    ) &
    tool_pids[subfinder]=$!
    pids+=($!)
else
    log_warn "Subfinder not found"
    ((TOOLS_SKIPPED++))
fi

# 5. Subdominator (RevoltSecurities)
SUBDOMINATOR_PY=""
for candidate in \
    "/opt/Subdominator/subdominator.py" \
    "/opt/Subdominator/Subdominator.py" \
    "/opt/SubDominator/subdominator.py" \
    "/opt/SubDominator/SubDominator.py"; do
    if [ -f "$candidate" ]; then
        SUBDOMINATOR_PY="$candidate"
        break
    fi
done

if command -v subdominator &> /dev/null || [ -n "$SUBDOMINATOR_PY" ]; then
    log_info "Launching Subdominator..."
    (
        timeout 600 bash -c "
            if command -v subdominator &> /dev/null; then
                subdominator -d '$TARGET' -o '$TEMP_SUBS/subdominator.txt' -nc
            else
                python3 '$SUBDOMINATOR_PY' -d '$TARGET' -o '$TEMP_SUBS/subdominator.txt' -nc
            fi
        " 2>/dev/null || touch "$TEMP_SUBS/subdominator.txt"
    ) &
    tool_pids[subdominator]=$!
    pids+=($!)
else
    log_warn "Subdominator not found"
    ((TOOLS_SKIPPED++))
fi

# 6. crt.sh via curl
log_info "Launching crt.sh..."
(
    timeout 300 bash -c "
        curl -s 'https://crt.sh/?q=%25.$TARGET&output=json' 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | \
            sort -u > '$TEMP_SUBS/crtsh.txt'
    " || touch "$TEMP_SUBS/crtsh.txt"
) &
tool_pids[crtsh]=$!
pids+=($!)

# 7. SecurityTrails (if API key is set)
if [ ! -z "$SECURITYTRAILS_API_KEY" ]; then
    log_info "Launching SecurityTrails..."
    (
        timeout 300 bash -c "
            curl -s 'https://api.securitytrails.com/v1/domain/$TARGET/subdomains' \
                -H 'APIKEY: $SECURITYTRAILS_API_KEY' 2>/dev/null | \
                jq -r '.subdomains[]' 2>/dev/null | \
                awk -v domain='$TARGET' '{print \$0\".\"domain}' > '$TEMP_SUBS/securitytrails.txt'
        " || touch "$TEMP_SUBS/securitytrails.txt"
    ) &
    tool_pids[securitytrails]=$!
    pids+=($!)
fi

# Wait for all passive enumeration tools to complete
log_info "Waiting for passive enumeration tools to complete..."
for pid in "${pids[@]}"; do
    if wait "$pid"; then
        ((TOOLS_SUCCESS++))
    else
        local exit_code=$?
        if [ $exit_code -ne 0 ]; then
            ((TOOLS_FAILED++))
        fi
    fi
done

log_info "Passive enumeration completed (Success: $TOOLS_SUCCESS, Failed: $TOOLS_FAILED, Skipped: $TOOLS_SKIPPED)"

# Merge all subdomain outputs with safe operations
log_info "Merging subdomain results..."
safe_cat "$PHASE_DIR/passive_subdomains_raw.txt" "$TEMP_SUBS"/*.txt

# Filter and validate subdomains
if [ -s "$PHASE_DIR/passive_subdomains_raw.txt" ]; then
    safe_grep -E '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$' \
        "$PHASE_DIR/passive_subdomains_raw.txt" | sort -u > "$PHASE_DIR/passive_subdomains.txt" || touch "$PHASE_DIR/passive_subdomains.txt"
else
    touch "$PHASE_DIR/passive_subdomains.txt"
fi

PASSIVE_COUNT=$(wc -l < "$PHASE_DIR/passive_subdomains.txt" 2>/dev/null | tr -d ' ')
log_info "Found $PASSIVE_COUNT unique subdomains from passive enumeration"

################################################################################
# PHASE 1C: ACTIVE SUBDOMAIN DISCOVERY
################################################################################

log_info "=== ACTIVE SUBDOMAIN DISCOVERY ==="

# Only run active discovery if we have some passive results
if [ "$PASSIVE_COUNT" -gt 0 ] || [ -s "$PHASE_DIR/passive_subdomains.txt" ]; then
    # 8. Dnsbruter (DNS bruteforcing)
    DNSBRUTER_PY=""
    for candidate in \
        "/opt/Dnsbruter/dnsbruter.py" \
        "/opt/dnsbruter/dnsbruter.py"; do
        if [ -f "$candidate" ]; then
            DNSBRUTER_PY="$candidate"
            break
        fi
    done

    if command -v dnsbruter &> /dev/null; then
        run_tool "dnsbruter" "$TEMP_SUBS/dnsbruter.txt" 900 \
            "dnsbruter -d '$TARGET' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -wd -o '$TEMP_SUBS/dnsbruter.txt'" || true
    elif [ -n "$DNSBRUTER_PY" ]; then
        log_info "Running Dnsbruter (Python)..."
        timeout 900 python3 "$DNSBRUTER_PY" -d "$TARGET" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -wd -o "$TEMP_SUBS/dnsbruter.txt" 2>/dev/null || log_warn "Dnsbruter failed"
    else
        log_warn "Dnsbruter not found"
        ((TOOLS_SKIPPED++))
    fi

    # 9. Dnsprober (DNS probing)
    if command -v dnsprober &> /dev/null && [ -s "$PHASE_DIR/passive_subdomains.txt" ]; then
        run_tool "dnsprober" "$TEMP_SUBS/dnsprober.txt" 600 \
            "dnsprober -l '$PHASE_DIR/passive_subdomains.txt' -o '$TEMP_SUBS/dnsprober.txt'" || true
    else
        log_warn "Dnsprober not found or no passive subdomains"
        ((TOOLS_SKIPPED++))
    fi

    # Merge active results safely
    safe_cat "$PHASE_DIR/active_subdomains_raw.txt" "$TEMP_SUBS/dnsbruter.txt" "$TEMP_SUBS/dnsprober.txt"

    if [ -s "$PHASE_DIR/active_subdomains_raw.txt" ]; then
        safe_grep -E '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$' \
            "$PHASE_DIR/active_subdomains_raw.txt" | sort -u > "$PHASE_DIR/active_subdomains.txt" || touch "$PHASE_DIR/active_subdomains.txt"
    else
        touch "$PHASE_DIR/active_subdomains.txt"
    fi
else
    log_warn "No passive subdomains found, skipping active discovery"
    touch "$PHASE_DIR/active_subdomains.txt"
fi

# Final merge of all subdomains
safe_cat "$PHASE_DIR/all_subdomains_raw.txt" "$PHASE_DIR/passive_subdomains.txt" "$PHASE_DIR/active_subdomains.txt"

if [ -s "$PHASE_DIR/all_subdomains_raw.txt" ]; then
    sort -u "$PHASE_DIR/all_subdomains_raw.txt" > "$PHASE_DIR/all_subdomains.txt"
else
    touch "$PHASE_DIR/all_subdomains.txt"
fi

TOTAL_SUBS=$(wc -l < "$PHASE_DIR/all_subdomains.txt" 2>/dev/null | tr -d ' ')
log_info "Total unique subdomains found: $TOTAL_SUBS"

################################################################################
# PHASE 1D: DNS RESOLUTION
################################################################################

log_info "=== DNS RESOLUTION ==="

# Only proceed if we have subdomains
if [ "$TOTAL_SUBS" -gt 0 ] && [ -s "$PHASE_DIR/all_subdomains.txt" ]; then
    # DNSx for resolution
    if command -v dnsx &> /dev/null; then
        log_info "Running DNSx for resolution..."
        timeout 900 bash -c "cat '$PHASE_DIR/all_subdomains.txt' | dnsx -silent -a -resp -json -o '$PHASE_DIR/dnsx_resolved.json'" 2>/dev/null || log_warn "DNSx failed or timed out"

        # Extract resolved domains
        if [ -f "$PHASE_DIR/dnsx_resolved.json" ] && [ -s "$PHASE_DIR/dnsx_resolved.json" ]; then
            jq -r '.host' "$PHASE_DIR/dnsx_resolved.json" 2>/dev/null | sort -u > "$PHASE_DIR/resolved_subdomains.txt" || cp "$PHASE_DIR/all_subdomains.txt" "$PHASE_DIR/resolved_subdomains.txt"
        else
            cp "$PHASE_DIR/all_subdomains.txt" "$PHASE_DIR/resolved_subdomains.txt"
        fi
    else
        log_warn "DNSx not found, using all subdomains as resolved"
        cp "$PHASE_DIR/all_subdomains.txt" "$PHASE_DIR/resolved_subdomains.txt"
    fi
else
    log_warn "No subdomains to resolve"
    touch "$PHASE_DIR/resolved_subdomains.txt"
fi

RESOLVED_COUNT=$(wc -l < "$PHASE_DIR/resolved_subdomains.txt" 2>/dev/null | tr -d ' ')
log_info "Resolved subdomains: $RESOLVED_COUNT"

################################################################################
# PHASE 1E: HTTP VALIDATION
################################################################################

log_info "=== HTTP VALIDATION ==="

# Only proceed if we have resolved subdomains
if [ "$RESOLVED_COUNT" -gt 0 ] && [ -s "$PHASE_DIR/resolved_subdomains.txt" ]; then
    # HTTPx for live host detection
    if command -v httpx &> /dev/null; then
        log_info "Running HTTPx to find alive hosts..."
        timeout 1800 bash -c "cat '$PHASE_DIR/resolved_subdomains.txt' | httpx -silent -json -status-code -follow-redirects -threads 50 -timeout 10 -o '$PHASE_DIR/httpx_alive.json'" 2>/dev/null || log_warn "HTTPx failed or timed out"

        # Extract alive hosts
        if [ -f "$PHASE_DIR/httpx_alive.json" ] && [ -s "$PHASE_DIR/httpx_alive.json" ]; then
            jq -r '.url' "$PHASE_DIR/httpx_alive.json" 2>/dev/null | \
                sed -E 's|^https?://||' | sed 's|/.*||' | sort -u > "$PHASE_DIR/alive_hosts.txt" || touch "$PHASE_DIR/alive_hosts.txt"

            ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            if [ "$ALIVE_COUNT" -eq 0 ]; then
                log_warn "HTTPx parsed but no alive hosts; falling back to resolved subdomains"
                cp "$PHASE_DIR/resolved_subdomains.txt" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
                ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            fi
            log_info "Alive hosts: $ALIVE_COUNT"
        else
            log_warn "HTTPx produced no output; falling back to resolved subdomains"
            cp "$PHASE_DIR/resolved_subdomains.txt" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
            ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            log_info "Alive hosts (fallback): $ALIVE_COUNT"
        fi
    else
        log_warn "HTTPx not found, skipping live validation"
        cp "$PHASE_DIR/resolved_subdomains.txt" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
        ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
    fi
else
    log_warn "No resolved subdomains to validate"
    touch "$PHASE_DIR/alive_hosts.txt"
    ALIVE_COUNT=0
fi

################################################################################
# CLEANUP AND SUMMARY
################################################################################

log_info "=== PHASE 1 SUMMARY ==="
echo "Target: $TARGET"
echo "Total Subdomains: $TOTAL_SUBS"
echo "Resolved: $RESOLVED_COUNT"
echo "Alive Hosts: ${ALIVE_COUNT:-0}"
echo "Tools Success: $TOOLS_SUCCESS"
echo "Tools Failed: $TOOLS_FAILED"
echo "Tools Skipped: $TOOLS_SKIPPED"
echo ""
echo "Output files:"
echo "  - all_subdomains.txt: All discovered subdomains"
echo "  - resolved_subdomains.txt: DNS-resolved subdomains"
echo "  - alive_hosts.txt: Live HTTP/HTTPS hosts"
echo "  - httpx_alive.json: Detailed HTTPx results"
echo "  - dnsx_resolved.json: Detailed DNSx results"

# Create phase completion marker
touch "$PHASE_DIR/.completed"

# Determine exit code based on whether we got ANY results
if [ "$TOTAL_SUBS" -gt 0 ] || [ "$TOOLS_SUCCESS" -gt 0 ]; then
    log_info "Phase 1 completed with results!"
    exit 0
else
    log_warn "Phase 1 completed but found no subdomains"
    exit 0  # Still exit 0 so scan continues
fi
