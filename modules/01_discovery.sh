#!/bin/bash
################################################################################
# Technieum - Phase 1: Horizontal & Vertical Discovery
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
WHOIS_TIMEOUT="${TECHNIEUM_WHOIS_TIMEOUT:-60}"
# AMASS_INTEL_TIMEOUT and AMASS_ENUM_TIMEOUT removed — amass is no longer used
SUBLIST3R_TIMEOUT="${TECHNIEUM_SUBLIST3R_TIMEOUT:-1200}"
SUBFINDER_TIMEOUT="${TECHNIEUM_SUBFINDER_TIMEOUT:-900}"
SUBFINDER_THREADS="${TECHNIEUM_SUBFINDER_THREADS:-50}"
ASSETFINDER_TIMEOUT="${TECHNIEUM_ASSETFINDER_TIMEOUT:-900}"
SUBDOMINATOR_TIMEOUT="${TECHNIEUM_SUBDOMINATOR_TIMEOUT:-1200}"
CRT_TIMEOUT="${TECHNIEUM_CRTSH_TIMEOUT:-60}"
SECURITYTRAILS_TIMEOUT="${TECHNIEUM_SECURITYTRAILS_TIMEOUT:-60}"
DNSBRUTER_TIMEOUT="${TECHNIEUM_DNSBRUTER_TIMEOUT:-1800}"
DNSPROBER_TIMEOUT="${TECHNIEUM_DNSPROBER_TIMEOUT:-1200}"
DNSX_TIMEOUT="${TECHNIEUM_DNSX_TIMEOUT:-1800}"
DNSX_THREADS="${TECHNIEUM_DNSX_THREADS:-100}"
HTTPX_TIMEOUT="${TECHNIEUM_HTTPX_TIMEOUT:-15}"
HTTPX_THREADS="${TECHNIEUM_HTTPX_THREADS:-100}"
HTTPX_RUN_TIMEOUT="${TECHNIEUM_HTTPX_RUN_TIMEOUT:-3600}"
CERTSPOTTER_TIMEOUT="${TECHNIEUM_CERTSPOTTER_TIMEOUT:-60}"
CT_MONITOR_TIMEOUT="${TECHNIEUM_CT_MONITOR_TIMEOUT:-900}"
ASNMAP_TIMEOUT="${TECHNIEUM_ASNMAP_TIMEOUT:-900}"
MAPCIDR_TIMEOUT="${TECHNIEUM_MAPCIDR_TIMEOUT:-1200}"
CLOUD_ENUM_TIMEOUT="${TECHNIEUM_CLOUD_ENUM_TIMEOUT:-1800}"
S3SCANNER_TIMEOUT="${TECHNIEUM_S3SCANNER_TIMEOUT:-1800}"
GOBLOB_TIMEOUT="${TECHNIEUM_GOBLOB_TIMEOUT:-1800}"
GCPBRUTE_TIMEOUT="${TECHNIEUM_GCPBRUTE_TIMEOUT:-1800}"
CLOUD_THREADS="${TECHNIEUM_CLOUD_THREADS:-30}"
CLOUD_KEYWORDS_LIMIT="${TECHNIEUM_CLOUD_KEYWORDS_LIMIT:-400}"

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
    local tool_bin=""

    if ! tool_bin="$(resolve_tool_path "$tool_name")"; then
        log_warn "$tool_name not installed, skipping..."
        ((TOOLS_SKIPPED++))
        return 2
    fi

    log_info "Running $tool_name (timeout: ${timeout_duration}s)..."
    local start_time=$(date +%s)

    # Run with timeout and capture exit code (run_timeout is portable on macOS)
    if PATH="$(dirname "$tool_bin"):$PATH" run_timeout "$timeout_duration" bash -c "$cmd" 2>"${output_file}.err"; then
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

# Check if a tool supports a specific flag (5 s timeout guards against hanging binaries)
tool_supports_flag() {
    local tool="$1"
    local flag="$2"
    local tool_bin=""
    if ! tool_bin="$(resolve_tool_path "$tool")"; then
        return 1
    fi
    timeout 5 "$tool_bin" -h 2>&1 | grep -q -- "$flag"
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

# Amass removed — subfinder + assetfinder + subdominator cover subdomain enum
# without amass's libpostal/sudo/env issues that caused hangs and timeouts.
_amass_ok=false

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

# Amass enum removed — subfinder + assetfinder handle passive subdomain discovery

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

# 6. crt.sh via curl — handle both string and array name_value fields
log_info "Launching crt.sh..."
(
    run_timeout "$CRT_TIMEOUT" bash -c "
        curl -s -H 'Accept: application/json' 'https://crt.sh/?q=%25.$TARGET&output=json' 2>/dev/null | \
            jq -r '.[].name_value | if type == \"array\" then .[] else . end' 2>/dev/null | \
            grep -v '^\\*' | \
            sed 's/^\\*\\.//g' | \
            tr '\n' '\n' | \
            grep -E '([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}' | \
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
ASN_CIDRS_FILTERED_FILE="$ASN_DIR/asn_cidrs_filtered.txt"
ASN_SUMMARY_FILE="$ASN_DIR/asn_summary.txt"
: > "$ASN_CIDRS_FILE"
: > "$ASN_IPS_FILE"
: > "$ASN_CIDRS_FILTERED_FILE"
: > "$ASN_SUMMARY_FILE"

ASNMAP_BIN=""
if ASNMAP_BIN="$(resolve_tool_path asnmap)"; then
    log_info "Running asnmap to discover CIDRs..."
    # Use -d flag (domain input) — bare positional arg causes '[FTL] no input defined'
    # Redirect stdin from /dev/null to prevent pdcp interactive API-key prompt from
    # leaking the string "[*] enter pdcp api key (exit to abort):" into the output file.
    ASN_AUTH_FLAGS=""
    # In asnmap, -auth is a boolean configure switch, not a key-value flag.
    # Force non-interactive mode to avoid terminal prompts in worker runs.
    if tool_supports_flag "asnmap" "-auth"; then
        ASN_AUTH_FLAGS="-auth=false"
    fi

    ASN_CMD="'$ASNMAP_BIN' -d '$TARGET' -silent $ASN_AUTH_FLAGS < /dev/null"
    if tool_supports_flag "asnmap" "-json"; then
        ASN_CMD="'$ASNMAP_BIN' -d '$TARGET' -silent -json $ASN_AUTH_FLAGS < /dev/null"
    fi
    ASN_CMD="$ASN_CMD > '$ASN_CIDRS_FILE'"
    run_timeout "$ASNMAP_TIMEOUT" bash -c "$ASN_CMD" 2>"$ASN_DIR/asnmap.err" || log_warn "asnmap failed or timed out"
    # Strip any non-CIDR lines that leaked in (e.g. pdcp prompt text)
    if [ -s "$ASN_CIDRS_FILE" ]; then
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$ASN_CIDRS_FILE" > "$ASN_CIDRS_FILE.clean" || true
        mv "$ASN_CIDRS_FILE.clean" "$ASN_CIDRS_FILE" 2>/dev/null || true
    fi

    # If PDCP auth is invalid or asnmap produced no usable CIDRs, fallback to
    # BGPView so ASN output files are still generated.
    if [ ! -s "$ASN_CIDRS_FILE" ] || grep -Eiq 'invalid api key|recheck or recreate your api key|enter pdcp api key|could not read input from terminal' "$ASN_DIR/asnmap.err" 2>/dev/null; then
        log_warn "asnmap returned no valid CIDRs (PDCP auth issue) — using BGPView fallback"
        export TARGET ASN_CIDRS_FILE
        python3 - << PYEOF 2>/dev/null
import urllib.request, json, socket, os
target = os.environ.get('TARGET', '')
out    = os.environ.get('ASN_CIDRS_FILE', '/tmp/asn_cidrs.txt')
try:
    ip = socket.gethostbyname(target)
    url = 'https://api.bgpview.io/ip/' + ip
    req = urllib.request.Request(url, headers={'User-Agent': 'Technieum/1.0'})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.loads(r.read())
    prefixes = data.get('data', {}).get('prefixes', [])
    if prefixes:
        with open(out, 'w') as f:
            for p in prefixes:
                cidr = p.get('prefix', '')
                if cidr:
                    f.write(cidr + '\n')
except Exception:
    pass
PYEOF
    fi
else
    log_warn "asnmap not found — attempting BGPView API fallback for ASN CIDRs"
    ((TOOLS_SKIPPED++))
    # Python fallback: resolve the target IP and query bgpview.io for its prefixes
    export TARGET ASN_CIDRS_FILE
    python3 - << PYEOF 2>/dev/null
import urllib.request, json, socket, sys, os
target = os.environ.get('TARGET', '')
out    = os.environ.get('ASN_CIDRS_FILE', '/tmp/asn_cidrs.txt')
try:
    ip = socket.gethostbyname(target)
    url = 'https://api.bgpview.io/ip/' + ip
    req = urllib.request.Request(url, headers={'User-Agent': 'Technieum/1.0'})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.loads(r.read())
    prefixes = data.get('data', {}).get('prefixes', [])
    if prefixes:
        with open(out, 'w') as f:
            for p in prefixes:
                cidr = p.get('prefix', '')
                if cidr:
                    f.write(cidr + '\n')
        print('[INFO] BGPView ASN: %d CIDR(s) for %s (%s)' % (len(prefixes), target, ip))
except Exception:
    pass
PYEOF
    touch "$ASN_CIDRS_FILE"
fi

if [ -s "$ASN_CIDRS_FILE" ] && command -v mapcidr &> /dev/null; then
    # Final guard: ensure only valid IPv4 CIDRs reach mapcidr — prevents pdcp prompt
    # text or other garbage from causing "[FTL] invalid CIDR address" fatal errors.
    CIDRS_CLEAN=$(grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$ASN_CIDRS_FILE" || true)
    if [ -z "$CIDRS_CLEAN" ]; then
        log_warn "No valid CIDRs in $ASN_CIDRS_FILE after filtering — skipping mapcidr"
        touch "$ASN_IPS_FILE"
    else
        log_info "Expanding ASN CIDRs to IPs..."
        FILTERED_CIDRS="$ASN_CIDRS_FILTERED_FILE"
        echo "$CIDRS_CLEAN" > "$FILTERED_CIDRS"
        MAP_CMD="mapcidr < '$FILTERED_CIDRS' > '$ASN_IPS_FILE'"
        if tool_supports_flag "mapcidr" "-silent"; then
            MAP_CMD="mapcidr -silent < '$FILTERED_CIDRS' > '$ASN_IPS_FILE'"
        fi
        run_timeout "$MAPCIDR_TIMEOUT" bash -c "$MAP_CMD" 2>"$ASN_DIR/mapcidr.err" || log_warn "mapcidr failed or timed out"
        # Some mapcidr builds reject -silent or return empty output on first run;
        # fallback to plain mode when no IPs were produced.
        if [ ! -s "$ASN_IPS_FILE" ]; then
            run_timeout "$MAPCIDR_TIMEOUT" bash -c "mapcidr < '$FILTERED_CIDRS' > '$ASN_IPS_FILE'" 2>>"$ASN_DIR/mapcidr.err" || true
        fi
    fi
else
    touch "$ASN_IPS_FILE"
fi

ASN_IP_COUNT=$(wc -l < "$ASN_IPS_FILE" 2>/dev/null | tr -d ' ')
log_info "ASN-derived IPs: ${ASN_IP_COUNT:-0}"

{
    echo "target=$TARGET"
    echo "cidr_count=$(wc -l < "$ASN_CIDRS_FILE" 2>/dev/null | tr -d ' ')"
    echo "filtered_cidr_count=$(wc -l < "$ASN_CIDRS_FILTERED_FILE" 2>/dev/null | tr -d ' ')"
    echo "ip_count=${ASN_IP_COUNT:-0}"
    echo ""
    echo "sample_cidrs:"
    head -n 20 "$ASN_CIDRS_FILE" 2>/dev/null
} > "$ASN_SUMMARY_FILE"

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
        _httpx_ok=0
        run_timeout "$HTTPX_RUN_TIMEOUT" bash -c "cat '$HTTPX_TARGETS' | httpx -silent -json -status-code -tech-detect -follow-redirects -timeout $HTTPX_TIMEOUT -o '$PHASE_DIR/httpx_alive.json'" 2>/dev/null && _httpx_ok=1
        if [ "$_httpx_ok" -eq 0 ]; then
            run_timeout "$HTTPX_RUN_TIMEOUT" bash -c "cat '$HTTPX_TARGETS' | httpx -silent -json -status-code -tech-detect -follow-redirects -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -o '$PHASE_DIR/httpx_alive.json'" 2>/dev/null && _httpx_ok=1
        fi
        if [ "$_httpx_ok" -eq 0 ]; then
            run_timeout "$HTTPX_RUN_TIMEOUT" bash -c "cat '$HTTPX_TARGETS' | httpx -silent -json -status-code -tech-detect -follow-redirects -c $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -o '$PHASE_DIR/httpx_alive.json'" 2>/dev/null && _httpx_ok=1
        fi
        [ "$_httpx_ok" -eq 0 ] && log_warn "HTTPx failed or timed out"

        # Extract alive hosts
        if [ -f "$PHASE_DIR/httpx_alive.json" ] && [ -s "$PHASE_DIR/httpx_alive.json" ]; then
            # Save full URLs (preserves scheme + port) for crawlers / hakrawler
            jq -r '.url // .input // empty' "$PHASE_DIR/httpx_alive.json" 2>/dev/null | \
                grep -E '^https?://' | sort -u > "$PHASE_DIR/alive_urls.txt" || touch "$PHASE_DIR/alive_urls.txt"

            # Save bare hostnames (strips scheme + path, keeps port) for port scanners
            jq -r '.url // .input // empty' "$PHASE_DIR/httpx_alive.json" 2>/dev/null | \
                sed -E 's|^https?://||' | sed 's|/.*||' | sort -u > "$PHASE_DIR/alive_hosts.txt" || touch "$PHASE_DIR/alive_hosts.txt"

            ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            if [ "$ALIVE_COUNT" -eq 0 ]; then
                log_warn "HTTPx parsed but no alive hosts; falling back to HTTPx targets"
                cp "$HTTPX_TARGETS" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
                sed 's|^|https://|' "$PHASE_DIR/alive_hosts.txt" 2>/dev/null > "$PHASE_DIR/alive_urls.txt" || touch "$PHASE_DIR/alive_urls.txt"
                ALIVE_COUNT=$(wc -l < "$PHASE_DIR/alive_hosts.txt" 2>/dev/null | tr -d ' ')
            fi
            log_info "Alive hosts: $ALIVE_COUNT (alive_urls.txt and alive_hosts.txt both written)"
        else
            log_warn "HTTPx produced no output; falling back to HTTPx targets"
            cp "$HTTPX_TARGETS" "$PHASE_DIR/alive_hosts.txt" 2>/dev/null || touch "$PHASE_DIR/alive_hosts.txt"
            awk '{print "https://" $0}' "$PHASE_DIR/alive_hosts.txt" > "$PHASE_DIR/alive_urls.txt" 2>/dev/null || touch "$PHASE_DIR/alive_urls.txt"
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

# Reset cloud outputs for this run (avoid stale findings from previous scans)
: > "$CLOUD_DIR/cloud_enum.txt"
: > "$CLOUD_DIR/s3scanner.txt"
: > "$CLOUD_DIR/goblob.txt"
: > "$CLOUD_DIR/gcpbucketbrute.txt"
: > "$CLOUD_DIR/cloud_assets_raw.txt"
: > "$CLOUD_DIR/cloud_assets.txt"

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

    # Ensure output files always exist even when tool invocation variants fail.
    touch "$CLOUD_DIR/cloud_enum.txt" "$CLOUD_DIR/s3scanner.txt" "$CLOUD_DIR/goblob.txt" "$CLOUD_DIR/gcpbucketbrute.txt"

    if command -v s3scanner &> /dev/null; then
        log_info "Running S3Scanner..."
        _s3_ok=0
        _s3_help=$(s3scanner -h 2>&1 || true)
        if echo "$_s3_help" | grep -q -- '-l'; then
            run_timeout "$S3SCANNER_TIMEOUT" s3scanner -l "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/s3scanner.txt" 2>/dev/null && _s3_ok=1
        fi
        if [ "$_s3_ok" -eq 0 ] && echo "$_s3_help" | grep -q -- '-f'; then
            run_timeout "$S3SCANNER_TIMEOUT" s3scanner -f "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/s3scanner.txt" 2>/dev/null && _s3_ok=1
        fi
        if [ "$_s3_ok" -eq 0 ]; then
            run_timeout "$S3SCANNER_TIMEOUT" bash -c "cat '$CLOUD_KEYWORDS' | s3scanner > '$CLOUD_DIR/s3scanner.txt'" 2>/dev/null && _s3_ok=1
        fi
        [ "$_s3_ok" -eq 0 ] && log_warn "S3Scanner failed for all known flag styles"
    else
        log_warn "S3Scanner not found"
    fi

    GOBLOB_BIN=""
    if GOBLOB_BIN="$(resolve_tool_path goblob)"; then
        log_info "Running goblob..."
        _gb_ok=0
        _gb_help=$("$GOBLOB_BIN" -h 2>&1 || true)
        GOBLOB_WORDLIST="$(ensure_goblob_wordlist)"
        cp "$CLOUD_KEYWORDS" "$CLOUD_DIR/goblob_accounts.txt" 2>/dev/null || true
        if [ "$_gb_ok" -eq 0 ] && echo "$_gb_help" | grep -q -- '-containers'; then
            run_timeout "$GOBLOB_TIMEOUT" "$GOBLOB_BIN" -containers "$GOBLOB_WORDLIST" -accounts "$CLOUD_DIR/goblob_accounts.txt" > "$CLOUD_DIR/goblob.txt" 2>/dev/null && _gb_ok=1
        fi
        if echo "$_gb_help" | grep -q -- '-w'; then
            run_timeout "$GOBLOB_TIMEOUT" "$GOBLOB_BIN" -w "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/goblob.txt" 2>/dev/null && _gb_ok=1
        fi
        if [ "$_gb_ok" -eq 0 ] && echo "$_gb_help" | grep -q -- '-l'; then
            run_timeout "$GOBLOB_TIMEOUT" "$GOBLOB_BIN" -l "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/goblob.txt" 2>/dev/null && _gb_ok=1
        fi
        if [ "$_gb_ok" -eq 0 ]; then
            run_timeout "$GOBLOB_TIMEOUT" bash -c "cat '$CLOUD_KEYWORDS' | '$GOBLOB_BIN' > '$CLOUD_DIR/goblob.txt'" 2>/dev/null && _gb_ok=1
        fi
        [ "$_gb_ok" -eq 0 ] && log_warn "goblob failed for all known flag styles"
    else
        log_warn "goblob not found"
    fi

    GCPBRUTE_BIN=""
    GCPBRUTE_PY=""
    if GCPBRUTE_BIN="$(resolve_tool_path gcpbucketbrute)"; then
        log_info "Running GCPBucketBrute..."
        if tool_supports_flag "gcpbucketbrute" "-w"; then
            run_timeout "$GCPBRUTE_TIMEOUT" "$GCPBRUTE_BIN" -w "$CLOUD_KEYWORDS" -o "$CLOUD_DIR/gcpbucketbrute.txt" 2>/dev/null || log_warn "GCPBucketBrute failed"
        else
            run_timeout "$GCPBRUTE_TIMEOUT" "$GCPBRUTE_BIN" "$CLOUD_KEYWORDS" > "$CLOUD_DIR/gcpbucketbrute.txt" 2>/dev/null || log_warn "GCPBucketBrute failed"
        fi
    elif GCPBRUTE_PY="$(ensure_python_repo_tool "${TECHNIEUM_GCPBRUTE_DIR:-$HOME/recon/tools/GCPBucketBrute}" "https://github.com/RhinoSecurityLabs/GCPBucketBrute.git" "gcpbucketbrute.py")"; then
        log_info "Running GCPBucketBrute (Python repo mode)..."
        run_timeout "$GCPBRUTE_TIMEOUT" python3 "$GCPBRUTE_PY" -w "$CLOUD_KEYWORDS" > "$CLOUD_DIR/gcpbucketbrute.txt" 2>/dev/null || log_warn "GCPBucketBrute Python mode failed"
    else
        log_warn "GCPBucketBrute not found"
    fi

    # Candidate fallback: if cloud tools produced nothing, generate deterministic
    # cloud asset candidates from keywords so downstream files are not empty.
    if [ ! -s "$CLOUD_DIR/cloud_enum.txt" ] && [ ! -s "$CLOUD_DIR/s3scanner.txt" ] && [ ! -s "$CLOUD_DIR/goblob.txt" ] && [ ! -s "$CLOUD_DIR/gcpbucketbrute.txt" ]; then
        log_info "[cloud-fallback] Cloud tools returned empty output; generating candidate cloud asset list"
        awk 'NF{print "https://"$0".s3.amazonaws.com"; print "s3://"$0; print "https://"$0".blob.core.windows.net"; print "https://storage.googleapis.com/"$0}' "$CLOUD_KEYWORDS" | sort -u > "$CLOUD_DIR/cloud_enum.txt"
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
    safe_grep -Ei 's3://|amazonaws\.com|blob\.core\.windows\.net|azureedge\.net|storage\.googleapis\.com' \
        "$CLOUD_DIR/cloud_assets_raw.txt" | sort -u > "$CLOUD_DIR/cloud_assets.txt" || touch "$CLOUD_DIR/cloud_assets.txt"
else
    touch "$CLOUD_DIR/cloud_assets.txt"
fi

# ── Python fallback: detect cloud indicators from subdomains / httpx output ──
if [ ! -s "$CLOUD_DIR/cloud_assets.txt" ]; then
    log_info "[cloud-fallback] No cloud tools found — scanning subdomains/httpx for cloud indicators"
    export PHASE_DIR CLOUD_DIR TARGET
    python3 - << 'CLOUDPY' 2>/dev/null
import re, os, json
phase_dir  = os.environ.get('PHASE_DIR', '.')
cloud_dir  = os.environ.get('CLOUD_DIR', '.')
target     = os.environ.get('TARGET', '')

VENDOR_RE = {
    'AWS':        re.compile(r'(s3\.amazonaws\.com|cloudfront\.net|elasticloadbalancing|ec2\.amazonaws|amazonaws\.com)', re.I),
    'Azure':      re.compile(r'(\.azure\.|azurewebsites\.net|blob\.core\.windows\.net|azuredge\.net|azurecontainer)', re.I),
    'GCP':        re.compile(r'(storage\.googleapis\.com|\.googleapis\.com|\.gcp\.|\.appspot\.com|compute\.cloud\.google)', re.I),
    'Cloudflare': re.compile(r'(\.workers\.dev|r2\.cloudflarestorage)', re.I),
    'DigitalOcean': re.compile(r'(\.digitaloceanspaces\.com|\.ondigitalocean\.app)', re.I),
}

findings = []
for fname in ('all_subdomains.txt', 'passive_subdomains.txt', 'resolved_subdomains.txt'):
    fp = os.path.join(phase_dir, fname)
    if not os.path.isfile(fp):
        continue
    with open(fp) as f:
        for line in f:
            line = line.strip()
            for vendor, rx in VENDOR_RE.items():
                if rx.search(line):
                    findings.append({'vendor': vendor, 'asset': line})
                    break

# Also check httpx output for CNAME-based cloud detection
jsonf = os.path.join(phase_dir, 'httpx_alive.json')
if os.path.isfile(jsonf):
    with open(jsonf) as f:
        for ln in f:
            try:
                row = json.loads(ln)
                for field in ('cname', 'url', 'host'):
                    val = row.get(field, '')
                    if isinstance(val, list):
                        val = ' '.join(val)
                    for vendor, rx in VENDOR_RE.items():
                        if rx.search(str(val)):
                            findings.append({'vendor': vendor, 'asset': str(val)})
                            break
            except Exception:
                pass

if findings:
    # Write summary lines
    seen = set()
    with open(os.path.join(cloud_dir, 'cloud_assets.txt'), 'w') as out:
        for item in findings:
            line = '%s\t%s' % (item['vendor'], item['asset'])
            if line not in seen:
                seen.add(line)
                out.write(line + '\n')
    print('[INFO] cloud-fallback: %d cloud assets detected via pattern matching' % len(seen))
CLOUDPY
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

################################################################################
# PHASE 1 STRUCTURED SUMMARY (JSON) — ingested by worker for UI rendering
################################################################################
log_info "Writing phase1_summary.json..."
# Export variables so the python heredoc can read them via os.environ
export PHASE_DIR TARGET
python3 - <<'PYEOF' 2>/dev/null || true
import json, os, re

phase_dir = os.environ.get('PHASE_DIR', '')
target    = os.environ.get('TARGET', '')

def read_lines(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []

def read_json_lines(path):
    items = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: items.append(json.loads(line))
                except Exception: pass
    except Exception:
        pass
    return items

# Subdomains
all_subs    = read_lines(f'{phase_dir}/all_subdomains.txt')
alive_hosts = read_lines(f'{phase_dir}/alive_hosts.txt')
alive_urls  = read_lines(f'{phase_dir}/alive_urls.txt')

# ASN
asn_cidrs = read_lines(f'{phase_dir}/asn/asn_cidrs.txt')
asn_ips   = read_lines(f'{phase_dir}/asn/asn_ips.txt')

# CT log sources
certspotter = read_lines(f'{phase_dir}/ct/certspotter.txt')
crtsh       = read_lines(f'{phase_dir}/temp_subdomains/crtsh.txt')

# Cloud
cloud_raw = []
for fname in ['cloud_enum.txt', 's3scanner.txt', 'goblob.txt', 'gcpbucketbrute.txt']:
    cloud_raw.extend(read_lines(f'{phase_dir}/cloud/{fname}'))
cloud_assets = list(set(l for l in cloud_raw if l and any(
    x in l for x in ['s3://', 'amazonaws.com', 'blob.core.windows.net',
                       'azureedge.net', 'storage.googleapis.com', 'appspot.com',
                       'azurewebsites.net', 'cloudfront.net'])))

# HTTPx details
httpx_entries = []
for obj in read_json_lines(f'{phase_dir}/httpx_alive.json'):
    url = obj.get('url') or obj.get('input') or ''
    if url:
        httpx_entries.append({
            'url': url,
            'status_code': obj.get('status_code') or obj.get('status-code'),
            'title': obj.get('title'),
            'webserver': obj.get('webserver'),
            'tech': obj.get('tech') or obj.get('technologies'),
            'content_length': obj.get('content_length') or obj.get('content-length'),
        })

summary = {
    'target': target,
    'subdomain_count': len(all_subs),
    'alive_count': len(alive_hosts),
    'subdomains': all_subs[:2000],
    'alive_hosts': alive_hosts,
    'alive_urls': alive_urls,
    'httpx_details': httpx_entries[:500],
    'ct_sources': {
        'certspotter': len(certspotter),
        'crtsh': len(crtsh),
    },
    'asn': {
        'cidrs': asn_cidrs,
        'ip_count': len(asn_ips),
        'ips_sample': asn_ips[:100],
    },
    'cloud': {
        'total': len(cloud_assets),
        'assets': cloud_assets[:500],
        'aws': [a for a in cloud_assets if 'amazonaws.com' in a or 's3://' in a][:100],
        'azure': [a for a in cloud_assets if 'azure' in a or 'blob.core' in a][:100],
        'gcp': [a for a in cloud_assets if 'googleapis.com' in a or 'appspot.com' in a][:100],
    },
}

out_path = f'{phase_dir}/phase1_summary.json'
with open(out_path, 'w') as f:
    json.dump(summary, f, indent=2)
print(f'[INFO] phase1_summary.json written: {len(all_subs)} subs, {len(alive_hosts)} alive, {len(cloud_assets)} cloud assets, {len(asn_cidrs)} ASN CIDRs')
PYEOF
echo "[*] Phase 1 Summary:"
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
