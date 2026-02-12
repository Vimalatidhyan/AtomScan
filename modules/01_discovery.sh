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

# Tunables (increase timeouts/threads for stability & speed)
WHOIS_TIMEOUT="${RECONX_WHOIS_TIMEOUT:-60}"
AMASS_INTEL_TIMEOUT="${RECONX_AMASS_INTEL_TIMEOUT:-600}"
AMASS_ENUM_TIMEOUT="${RECONX_AMASS_ENUM_TIMEOUT:-1200}"
SUBLIST3R_TIMEOUT="${RECONX_SUBLIST3R_TIMEOUT:-1200}"
SUBFINDER_TIMEOUT="${RECONX_SUBFINDER_TIMEOUT:-900}"
SUBFINDER_THREADS="${RECONX_SUBFINDER_THREADS:-50}"
ASSETFINDER_TIMEOUT="${RECONX_ASSETFINDER_TIMEOUT:-900}"
SUBDOMINATOR_TIMEOUT="${RECONX_SUBDOMINATOR_TIMEOUT:-1200}"
CRT_TIMEOUT="${RECONX_CRTSH_TIMEOUT:-60}"
SECURITYTRAILS_TIMEOUT="${RECONX_SECURITYTRAILS_TIMEOUT:-60}"
DNSBRUTER_TIMEOUT="${RECONX_DNSBRUTER_TIMEOUT:-1800}"
DNSPROBER_TIMEOUT="${RECONX_DNSPROBER_TIMEOUT:-1200}"
DNSX_TIMEOUT="${RECONX_DNSX_TIMEOUT:-1800}"
DNSX_THREADS="${RECONX_DNSX_THREADS:-100}"
HTTPX_TIMEOUT="${RECONX_HTTPX_TIMEOUT:-15}"
HTTPX_THREADS="${RECONX_HTTPX_THREADS:-100}"
HTTPX_RUN_TIMEOUT="${RECONX_HTTPX_RUN_TIMEOUT:-3600}"
CERTSPOTTER_TIMEOUT="${RECONX_CERTSPOTTER_TIMEOUT:-60}"
CT_MONITOR_TIMEOUT="${RECONX_CT_MONITOR_TIMEOUT:-900}"
ASNMAP_TIMEOUT="${RECONX_ASNMAP_TIMEOUT:-900}"
MAPCIDR_TIMEOUT="${RECONX_MAPCIDR_TIMEOUT:-1200}"
CLOUD_ENUM_TIMEOUT="${RECONX_CLOUD_ENUM_TIMEOUT:-1800}"
S3SCANNER_TIMEOUT="${RECONX_S3SCANNER_TIMEOUT:-1800}"
GOBLOB_TIMEOUT="${RECONX_GOBLOB_TIMEOUT:-1800}"
GCPBRUTE_TIMEOUT="${RECONX_GCPBRUTE_TIMEOUT:-1800}"
CLOUD_THREADS="${RECONX_CLOUD_THREADS:-30}"
CLOUD_KEYWORDS_LIMIT="${RECONX_CLOUD_KEYWORDS_LIMIT:-400}"

echo "[*] Phase 1: Discovery & Enumeration for $TARGET"
echo "[*] Output directory: $PHASE_DIR"

# Shared utilities (log_info, log_error, log_warn, safe_cat, safe_grep, check_disk_space)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

# Tool execution tracking
TOOLS_SUCCESS=0
TOOLS_FAILED=0
TOOLS_SKIPPED=0

# Enhanced run_tool function with timeout and proper error handling
# (overrides the simple run_tool from lib/common.sh with a richer version)
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

    # Run with timeout and capture exit code (run_timeout is portable on macOS)
    if run_timeout "$timeout_duration" bash -c "$cmd" 2>"${output_file}.err"; then
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

# Check if a tool supports a specific flag
tool_supports_flag() {
    local tool="$1"
    local flag="$2"
    if ! command -v "$tool" &> /dev/null; then
        return 1
    fi
    "$tool" -h 2>&1 | grep -q -- "$flag"
}

################################################################################
# PHASE 1A: HORIZONTAL DISCOVERY (Acquisitions)
################################################################################

log_info "=== HORIZONTAL DISCOVERY ==="

# Whois domain information
if command -v whois &> /dev/null; then
    log_info "Running whois..."
    run_timeout "$WHOIS_TIMEOUT" whois "$TARGET" > "$PHASE_DIR/whois.txt" 2>/dev/null || log_warn "Whois failed or timed out"
else
    log_warn "whois not found"
    ((TOOLS_SKIPPED++))
fi

# Amass Intel/Enum (version-aware)
if command -v amass &> /dev/null; then
    if amass intel -h >/dev/null 2>&1; then
        run_tool "amass" "$PHASE_DIR/amass_intel.txt" "$AMASS_INTEL_TIMEOUT" \
            "amass intel -d '$TARGET' -whois -timeout 15 -o '$PHASE_DIR/amass_intel.txt'" || true
    else
        log_warn "Amass intel not supported; using passive enum instead"
        run_tool "amass" "$PHASE_DIR/amass_intel.txt" "$AMASS_INTEL_TIMEOUT" \
            "amass enum -d '$TARGET' -passive -timeout 20 -o '$PHASE_DIR/amass_intel.txt'" || true
    fi
else
    log_warn "Amass not found"
    ((TOOLS_SKIPPED++))
fi

# Get subsidiaries (if tool exists)
if [ -f "/opt/getSubsidiaries/getSubsidiaries.py" ]; then
    log_info "Running getSubsidiaries..."
    run_timeout 600 python3 /opt/getSubsidiaries/getSubsidiaries.py "$TARGET" > "$PHASE_DIR/subsidiaries.txt" 2>/dev/null || log_warn "getSubsidiaries failed"
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

# Certificate Transparency (CT) outputs
CT_DIR="$PHASE_DIR/ct"
mkdir -p "$CT_DIR"

# Launch all subdomain enumeration tools in parallel with proper error handling
pids=()

# 1. Sublist3r
if command -v sublist3r &> /dev/null || [ -f "/opt/Sublist3r/sublist3r.py" ]; then
    log_info "Launching Sublist3r..."
    (
        run_timeout "$SUBLIST3R_TIMEOUT" bash -c "
            if [ -f '/opt/Sublist3r/sublist3r.py' ]; then
                python3 /opt/Sublist3r/sublist3r.py -d '$TARGET' -o '$TEMP_SUBS/sublist3r.txt'
            else
                sublist3r -d '$TARGET' -o '$TEMP_SUBS/sublist3r.txt'
            fi
        " 2>/dev/null || touch "$TEMP_SUBS/sublist3r.txt"
    ) &
    pids+=($!)
else
    log_warn "Sublist3r not found"
    ((TOOLS_SKIPPED++))
fi

# 2. OWASP Amass Enum
if command -v amass &> /dev/null; then
    log_info "Launching Amass enum..."
    (
        run_timeout "$AMASS_ENUM_TIMEOUT" amass enum -d "$TARGET" -passive -timeout 20 -o "$TEMP_SUBS/amass.txt" 2>/dev/null || touch "$TEMP_SUBS/amass.txt"
    ) &
    pids+=($!)
else
    log_warn "Amass not found"
    ((TOOLS_SKIPPED++))
fi

# 3. Assetfinder
if command -v assetfinder &> /dev/null; then
    log_info "Launching Assetfinder..."
    (
        run_timeout "$ASSETFINDER_TIMEOUT" assetfinder --subs-only "$TARGET" > "$TEMP_SUBS/assetfinder.txt" 2>/dev/null || touch "$TEMP_SUBS/assetfinder.txt"
    ) &
    pids+=($!)
else
    log_warn "Assetfinder not found"
    ((TOOLS_SKIPPED++))
fi

# 4. Subfinder
if command -v subfinder &> /dev/null; then
    log_info "Launching Subfinder..."
    (
        run_timeout "$SUBFINDER_TIMEOUT" subfinder -d "$TARGET" -silent -t "$SUBFINDER_THREADS" -o "$TEMP_SUBS/subfinder.txt" 2>/dev/null || touch "$TEMP_SUBS/subfinder.txt"
    ) &
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
        run_timeout "$SUBDOMINATOR_TIMEOUT" bash -c "
            if command -v subdominator &> /dev/null; then
                subdominator -d '$TARGET' -o '$TEMP_SUBS/subdominator.txt' -nc
            else
                python3 '$SUBDOMINATOR_PY' -d '$TARGET' -o '$TEMP_SUBS/subdominator.txt' -nc
            fi
        " 2>/dev/null || touch "$TEMP_SUBS/subdominator.txt"
    ) &
    pids+=($!)
else
    log_warn "Subdominator not found"
    ((TOOLS_SKIPPED++))
fi

# 6. crt.sh via curl
log_info "Launching crt.sh..."
(
    run_timeout "$CRT_TIMEOUT" bash -c "
        curl -s 'https://crt.sh/?q=%25.$TARGET&output=json' 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | \
            sort -u > '$TEMP_SUBS/crtsh.txt'
    " || touch "$TEMP_SUBS/crtsh.txt"
) &
pids+=($!)

# 6.1 CertSpotter (CT API)
log_info "Launching CertSpotter..."
(
    run_timeout "$CERTSPOTTER_TIMEOUT" bash -c "
        curl -s 'https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names' 2>/dev/null | \
            jq -r '.[].dns_names[]' 2>/dev/null | \
            sed 's/\\*\\.//g' | sort -u > '$CT_DIR/certspotter.txt'
    " || touch "$CT_DIR/certspotter.txt"
) &
pids+=($!)

# 6.2 ct-monitor (optional)
if command -v ct-monitor &> /dev/null; then
    log_info "Launching ct-monitor..."
    (
        CT_CMD="ct-monitor '$TARGET'"
        if tool_supports_flag "ct-monitor" "--domain"; then
            CT_CMD="ct-monitor --domain '$TARGET'"
        elif tool_supports_flag "ct-monitor" "-d"; then
            CT_CMD="ct-monitor -d '$TARGET'"
        fi

        run_timeout "$CT_MONITOR_TIMEOUT" bash -c "$CT_CMD" > "$CT_DIR/ct_monitor_raw.txt" 2>/dev/null || true
        if [ -s "$CT_DIR/ct_monitor_raw.txt" ]; then
            safe_grep -E '[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9-]{1,})+\\.[a-zA-Z]{2,}' "$CT_DIR/ct_monitor_raw.txt" | \
                sed 's/\\*\\.//g' | sort -u > "$CT_DIR/ct_monitor.txt" || touch "$CT_DIR/ct_monitor.txt"
        else
            touch "$CT_DIR/ct_monitor.txt"
        fi
    ) &
    pids+=($!)
else
    log_warn "ct-monitor not found"
    ((TOOLS_SKIPPED++))
fi

# 7. SecurityTrails (if API key is set)
if [ ! -z "$SECURITYTRAILS_API_KEY" ]; then
    log_info "Launching SecurityTrails..."
    (
        run_timeout "$SECURITYTRAILS_TIMEOUT" bash -c "
            curl -s 'https://api.securitytrails.com/v1/domain/$TARGET/subdomains' \
                -H 'APIKEY: $SECURITYTRAILS_API_KEY' 2>/dev/null | \
                jq -r '.subdomains[]' 2>/dev/null | \
                awk -v domain='$TARGET' '{print \$0\".\"domain}' > '$TEMP_SUBS/securitytrails.txt'
        " || touch "$TEMP_SUBS/securitytrails.txt"
    ) &
    pids+=($!)
fi

# Wait for all passive enumeration tools to complete
log_info "Waiting for passive enumeration tools to complete..."
for pid in "${pids[@]}"; do
    if wait "$pid"; then
        ((TOOLS_SUCCESS++))
    else
        exit_code=$?
        if [ $exit_code -ne 0 ]; then
            ((TOOLS_FAILED++))
        fi
    fi
done

log_info "Passive enumeration completed (Success: $TOOLS_SUCCESS, Failed: $TOOLS_FAILED, Skipped: $TOOLS_SKIPPED)"

# Merge all subdomain outputs with safe operations
log_info "Merging subdomain results..."
safe_cat "$PHASE_DIR/passive_subdomains_raw.txt" \
    "$TEMP_SUBS"/*.txt \
    "$CT_DIR/certspotter.txt" \
    "$CT_DIR/ct_monitor.txt"

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
        run_tool "dnsbruter" "$TEMP_SUBS/dnsbruter.txt" "$DNSBRUTER_TIMEOUT" \
            "dnsbruter -d '$TARGET' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -wd -o '$TEMP_SUBS/dnsbruter.txt'" || true
    elif [ -n "$DNSBRUTER_PY" ]; then
        log_info "Running Dnsbruter (Python)..."
        run_timeout "$DNSBRUTER_TIMEOUT" python3 "$DNSBRUTER_PY" -d "$TARGET" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -wd -o "$TEMP_SUBS/dnsbruter.txt" 2>/dev/null || log_warn "Dnsbruter failed"
    else
        log_warn "Dnsbruter not found"
        ((TOOLS_SKIPPED++))
    fi

    # 9. Dnsprober (DNS probing)
    if command -v dnsprober &> /dev/null && [ -s "$PHASE_DIR/passive_subdomains.txt" ]; then
        run_tool "dnsprober" "$TEMP_SUBS/dnsprober.txt" "$DNSPROBER_TIMEOUT" \
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

# When no subdomains found, add root domain so at least the main host gets probed (DNS + HTTP)
TOTAL_SUBS=$(wc -l < "$PHASE_DIR/all_subdomains.txt" 2>/dev/null | tr -d ' ')
if [ "$TOTAL_SUBS" -eq 0 ]; then
    log_info "No subdomains from enumeration; adding root domain $TARGET for probing"
    echo "$TARGET" >> "$PHASE_DIR/all_subdomains.txt"
    TOTAL_SUBS=1
fi
log_info "Total unique subdomains found: $TOTAL_SUBS"

################################################################################
# PHASE 1D: ASN EXPANSION
################################################################################

log_info "=== ASN EXPANSION ==="
ASN_DIR="$PHASE_DIR/asn"
mkdir -p "$ASN_DIR"

ASN_CIDRS_FILE="$ASN_DIR/asn_cidrs.txt"
ASN_IPS_FILE="$ASN_DIR/asn_ips.txt"

if command -v asnmap &> /dev/null; then
    log_info "Running asnmap to discover CIDRs..."
    ASN_CMD="asnmap -silent '$TARGET' > '$ASN_CIDRS_FILE'"
    if tool_supports_flag "asnmap" "-d"; then
        ASN_CMD="asnmap -d '$TARGET' -silent > '$ASN_CIDRS_FILE'"
    fi
    run_timeout "$ASNMAP_TIMEOUT" bash -c "$ASN_CMD" 2>"$ASN_DIR/asnmap.err" || log_warn "asnmap failed or timed out"
else
    log_warn "asnmap not found"
    ((TOOLS_SKIPPED++))
fi

if [ -s "$ASN_CIDRS_FILE" ] && command -v mapcidr &> /dev/null; then
    log_info "Expanding ASN CIDRs to IPs..."
    MAP_CMD="mapcidr < '$ASN_CIDRS_FILE' > '$ASN_IPS_FILE'"
    if tool_supports_flag "mapcidr" "-silent"; then
        MAP_CMD="mapcidr -silent < '$ASN_CIDRS_FILE' > '$ASN_IPS_FILE'"
    fi
    run_timeout "$MAPCIDR_TIMEOUT" bash -c "$MAP_CMD" 2>"$ASN_DIR/mapcidr.err" || log_warn "mapcidr failed or timed out"
else
    touch "$ASN_IPS_FILE"
fi

ASN_IP_COUNT=$(wc -l < "$ASN_IPS_FILE" 2>/dev/null | tr -d ' ')
log_info "ASN-derived IPs: ${ASN_IP_COUNT:-0}"

################################################################################
# PHASE 1E: DNS RESOLUTION
################################################################################

log_info "=== DNS RESOLUTION ==="

# Only proceed if we have subdomains
if [ "$TOTAL_SUBS" -gt 0 ] && [ -s "$PHASE_DIR/all_subdomains.txt" ]; then
    # DNSx for resolution
    if command -v dnsx &> /dev/null; then
        log_info "Running DNSx for resolution..."
        run_timeout "$DNSX_TIMEOUT" bash -c "cat '$PHASE_DIR/all_subdomains.txt' | dnsx -silent -a -resp -json -t $DNSX_THREADS -o '$PHASE_DIR/dnsx_resolved.json'" 2>/dev/null || log_warn "DNSx failed or timed out"

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
# PHASE 1F: HTTP VALIDATION
################################################################################

log_info "=== HTTP VALIDATION ==="

# Build HTTPx targets (resolved subdomains + ASN IPs)
HTTPX_TARGETS="$PHASE_DIR/httpx_targets.txt"
safe_cat "$HTTPX_TARGETS" "$PHASE_DIR/resolved_subdomains.txt" "$ASN_IPS_FILE"
if [ -s "$HTTPX_TARGETS" ]; then
    sort -u "$HTTPX_TARGETS" > "$HTTPX_TARGETS.tmp" 2>/dev/null || true
    mv "$HTTPX_TARGETS.tmp" "$HTTPX_TARGETS" 2>/dev/null || true
fi

# Only proceed if we have targets
if [ -s "$HTTPX_TARGETS" ]; then
    # HTTPx for live host detection
    if command -v httpx &> /dev/null; then
        log_info "Running HTTPx to find alive hosts..."
        run_timeout "$HTTPX_RUN_TIMEOUT" bash -c "cat '$HTTPX_TARGETS' | httpx -silent -json -status-code -follow-redirects -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -o '$PHASE_DIR/httpx_alive.json'" 2>/dev/null || log_warn "HTTPx failed or timed out"

        # Extract alive hosts
        if [ -f "$PHASE_DIR/httpx_alive.json" ] && [ -s "$PHASE_DIR/httpx_alive.json" ]; then
            jq -r '.url' "$PHASE_DIR/httpx_alive.json" 2>/dev/null | \
                sed -E 's|^https?://||' | sed 's|/.*||' | sort -u > "$PHASE_DIR/alive_hosts.txt" || touch "$PHASE_DIR/alive_hosts.txt"

            ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            if [ "$ALIVE_COUNT" -eq 0 ]; then
                log_warn "HTTPx parsed but no alive hosts; falling back to HTTPx targets"
                cp "$HTTPX_TARGETS" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
                ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            fi
            log_info "Alive hosts: $ALIVE_COUNT"
        else
            log_warn "HTTPx produced no output; falling back to HTTPx targets"
            cp "$HTTPX_TARGETS" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
            ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            log_info "Alive hosts (fallback): $ALIVE_COUNT"
        fi
    else
        log_warn "HTTPx not found, skipping live validation"
        cp "$HTTPX_TARGETS" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
        ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
    fi
else
    log_warn "No HTTP validation targets"
    touch "$PHASE_DIR/alive_hosts.txt"
    ALIVE_COUNT=0
fi

################################################################################
# PHASE 1G: CLOUD EXPOSURE CHECKS
################################################################################

log_info "=== CLOUD EXPOSURE CHECKS ==="
CLOUD_DIR="$PHASE_DIR/cloud"
mkdir -p "$CLOUD_DIR"
CLOUD_KEYWORDS="$CLOUD_DIR/keywords.txt"

{
    echo "$TARGET"
    echo "${TARGET//./-}"
    echo "${TARGET//./}"
    echo "$(echo "$TARGET" | cut -d. -f1)"
    if [ -s "$PHASE_DIR/all_subdomains.txt" ]; then
        head -n "$CLOUD_KEYWORDS_LIMIT" "$PHASE_DIR/all_subdomains.txt" | sed 's/\\./-/g'
        head -n "$CLOUD_KEYWORDS_LIMIT" "$PHASE_DIR/all_subdomains.txt" | awk -F. '{print $1}'
    fi
} | tr 'A-Z' 'a-z' | sort -u > "$CLOUD_KEYWORDS"

if [ -s "$CLOUD_KEYWORDS" ]; then
    if command -v cloud_enum &> /dev/null; then
        log_info "Running cloud_enum..."
        if tool_supports_flag "cloud_enum" "-l"; then
            run_timeout "$CLOUD_ENUM_TIMEOUT" cloud_enum -l "$CLOUD_KEYWORDS" -t "$CLOUD_THREADS" > "$CLOUD_DIR/cloud_enum.txt" 2>/dev/null || log_warn "cloud_enum failed"
        elif tool_supports_flag "cloud_enum" "-k"; then
            run_timeout "$CLOUD_ENUM_TIMEOUT" cloud_enum -k "$TARGET" -t "$CLOUD_THREADS" > "$CLOUD_DIR/cloud_enum.txt" 2>/dev/null || log_warn "cloud_enum failed"
        else
            run_timeout "$CLOUD_ENUM_TIMEOUT" cloud_enum "$TARGET" > "$CLOUD_DIR/cloud_enum.txt" 2>/dev/null || log_warn "cloud_enum failed"
        fi
    else
        log_warn "cloud_enum not found"
        touch "$CLOUD_DIR/cloud_enum.txt"
    fi

    if command -v s3scanner &> /dev/null; then
        log_info "Running S3Scanner..."
        if tool_supports_flag "s3scanner" "-l"; then
            run_timeout "$S3SCANNER_TIMEOUT" s3scanner -l "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/s3scanner.txt" 2>/dev/null || log_warn "S3Scanner failed"
        else
            run_timeout "$S3SCANNER_TIMEOUT" s3scanner "$CLOUD_KEYWORDS" "$CLOUD_DIR/s3scanner.txt" 2>/dev/null || log_warn "S3Scanner failed"
        fi
    else
        log_warn "S3Scanner not found"
        touch "$CLOUD_DIR/s3scanner.txt"
    fi

    if command -v goblob &> /dev/null; then
        log_info "Running goblob..."
        if tool_supports_flag "goblob" "-w"; then
            run_timeout "$GOBLOB_TIMEOUT" goblob -w "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/goblob.txt" 2>/dev/null || log_warn "goblob failed"
        else
            run_timeout "$GOBLOB_TIMEOUT" goblob "$CLOUD_KEYWORDS" > "$CLOUD_DIR/goblob.txt" 2>/dev/null || log_warn "goblob failed"
        fi
    else
        log_warn "goblob not found"
        touch "$CLOUD_DIR/goblob.txt"
    fi

    if command -v gcpbucketbrute &> /dev/null; then
        log_info "Running GCPBucketBrute..."
        if tool_supports_flag "gcpbucketbrute" "-w"; then
            run_timeout "$GCPBRUTE_TIMEOUT" gcpbucketbrute -w "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/gcpbucketbrute.txt" 2>/dev/null || log_warn "GCPBucketBrute failed"
        else
            run_timeout "$GCPBRUTE_TIMEOUT" gcpbucketbrute "$CLOUD_KEYWORDS" > "$CLOUD_DIR/gcpbucketbrute.txt" 2>/dev/null || log_warn "GCPBucketBrute failed"
        fi
    else
        log_warn "GCPBucketBrute not found"
        touch "$CLOUD_DIR/gcpbucketbrute.txt"
    fi
else
    log_warn "No cloud keywords generated; skipping cloud exposure checks"
fi

safe_cat "$CLOUD_DIR/cloud_assets_raw.txt" \
    "$CLOUD_DIR/cloud_enum.txt" \
    "$CLOUD_DIR/s3scanner.txt" \
    "$CLOUD_DIR/goblob.txt" \
    "$CLOUD_DIR/gcpbucketbrute.txt"

if [ -s "$CLOUD_DIR/cloud_assets_raw.txt" ]; then
    safe_grep -Ei 's3://|amazonaws\\.com|blob\\.core\\.windows\\.net|azureedge\\.net|storage\\.googleapis\\.com' \
        "$CLOUD_DIR/cloud_assets_raw.txt" | sort -u > "$CLOUD_DIR/cloud_assets.txt" || touch "$CLOUD_DIR/cloud_assets.txt"
else
    touch "$CLOUD_DIR/cloud_assets.txt"
fi

if [ -s "$CLOUD_DIR/cloud_assets.txt" ]; then
    CLOUD_FINDINGS=$(wc -l < "$CLOUD_DIR/cloud_assets.txt" 2>/dev/null | tr -d ' ')
else
    CLOUD_FINDINGS=0
fi

################################################################################
# CLEANUP AND SUMMARY
################################################################################

log_info "=== PHASE 1 SUMMARY ==="
echo "Target: $TARGET"
echo "Total Subdomains: $TOTAL_SUBS"
echo "Resolved: $RESOLVED_COUNT"
echo "Alive Hosts: ${ALIVE_COUNT:-0}"
echo "ASN IPs: ${ASN_IP_COUNT:-0}"
echo "Cloud Findings: ${CLOUD_FINDINGS:-0}"
echo "Tools Success: $TOOLS_SUCCESS"
echo "Tools Failed: $TOOLS_FAILED"
echo "Tools Skipped: $TOOLS_SKIPPED"
echo ""
echo "Output files:"
echo "  - all_subdomains.txt: All discovered subdomains"
echo "  - resolved_subdomains.txt: DNS-resolved subdomains"
echo "  - alive_hosts.txt: Live HTTP/HTTPS hosts"
echo "  - httpx_targets.txt: HTTP validation targets (domains + IPs)"
echo "  - httpx_alive.json: Detailed HTTPx results"
echo "  - dnsx_resolved.json: Detailed DNSx results"
echo "  - ct/: Certificate Transparency sources"
echo "  - asn/: ASN CIDR and IP expansion"
echo "  - cloud/: Cloud exposure checks"

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
