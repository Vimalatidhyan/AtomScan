#!/bin/bash
################################################################################
# ReconX - Phase 4: Vulnerability Scanning
# Comprehensive vulnerability assessment using multiple scanners
################################################################################

# DO NOT use set -e - we want to continue even if tools fail
set -o pipefail  # Catch errors in pipelines
TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase4_vulnscan"
PHASE1_DIR="$OUTPUT_DIR/phase1_discovery"
PHASE3_DIR="$OUTPUT_DIR/phase3_content"
mkdir -p "$PHASE_DIR"

echo "[*] Phase 4: Vulnerability Scanning for $TARGET"
echo "[*] Output directory: $PHASE_DIR"

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

# Concurrency controls
THREADS="${RECONX_THREADS:-5}"
SQLMAP_THREADS="${RECONX_SQLMAP_THREADS:-3}"
TIMEOUT_DEFAULT="${RECONX_VULN_TIMEOUT:-1200}"

export -f log_info
export -f log_warn
export -f log_error

run_with_timeout() {
    local timeout_duration="$1"
    shift
    timeout "$timeout_duration" bash -c "$*" 2>/dev/null
}

run_parallel_from_file() {
    local input_file="$1"
    local parallelism="$2"
    local command="$3"

    if [ ! -s "$input_file" ]; then
        log_warn "No inputs found in $input_file"
        return 0
    fi

    xargs -I{} -P "$parallelism" bash -c "$command" _ {} < "$input_file"
}

# Check prerequisites
if [ ! -f "$PHASE1_DIR/alive_hosts.txt" ]; then
    log_error "Phase 1 output not found. Run Phase 1 first!"
    exit 1
fi

ALIVE_HOSTS="$PHASE1_DIR/alive_hosts.txt"
ALIVE_COUNT=$(wc -l < "$ALIVE_HOSTS" | tr -d ' ')
log_info "Found $ALIVE_COUNT alive hosts from Phase 1"

# Prepare URLs for scanning
cat "$ALIVE_HOSTS" | sed 's|^|https://|' | head -n 50 > "$PHASE_DIR/scan_urls.txt"

# Add discovered URLs from Phase 3 if available
if [ -f "$PHASE3_DIR/urls/all_urls.txt" ]; then
    head -n 200 "$PHASE3_DIR/urls/all_urls.txt" >> "$PHASE_DIR/scan_urls.txt"
fi

sort -u "$PHASE_DIR/scan_urls.txt" -o "$PHASE_DIR/scan_urls.txt"
SCAN_COUNT=$(wc -l < "$PHASE_DIR/scan_urls.txt" | tr -d ' ')
log_info "Prepared $SCAN_COUNT URLs for vulnerability scanning"

################################################################################
# PHASE 4A: NUCLEI - COMPREHENSIVE TEMPLATE SCANNING
################################################################################

log_info "=== NUCLEI SCANNING ==="

NUCLEI_DIR="$PHASE_DIR/nuclei"
mkdir -p "$NUCLEI_DIR"

if command -v nuclei &> /dev/null && [ "$SCAN_COUNT" -gt 0 ]; then
    log_info "Running Nuclei with all templates..."

    # Update Nuclei templates
    log_info "Updating Nuclei templates..."
    run_with_timeout "$TIMEOUT_DEFAULT" "nuclei -update-templates" || log_warn "Failed to update Nuclei templates"

    # Run Nuclei with different severity levels
    log_info "Nuclei: Critical & High severity scan..."
    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -json -severity critical,high -rate-limit 50 \
        -o "$NUCLEI_DIR/nuclei_critical_high.json" 2>/dev/null || log_warn "Nuclei critical/high scan failed"

    log_info "Nuclei: Medium severity scan..."
    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -json -severity medium -rate-limit 100 \
        -o "$NUCLEI_DIR/nuclei_medium.json" 2>/dev/null || log_warn "Nuclei medium scan failed"

    log_info "Nuclei: Low & Info severity scan..."
    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -json -severity low,info -rate-limit 150 \
        -o "$NUCLEI_DIR/nuclei_low_info.json" 2>/dev/null || log_warn "Nuclei low/info scan failed"

    # Specific template scans
    log_info "Nuclei: CVE templates..."
    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -json -tags cve -rate-limit 50 \
        -o "$NUCLEI_DIR/nuclei_cve.json" 2>/dev/null || log_warn "Nuclei CVE scan failed"

    log_info "Nuclei: Misconfiguration templates..."
    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -json -tags misconfiguration,config -rate-limit 100 \
        -o "$NUCLEI_DIR/nuclei_misconfig.json" 2>/dev/null || log_warn "Nuclei misconfig scan failed"

    # Merge all Nuclei results
    cat "$NUCLEI_DIR"/nuclei_*.json 2>/dev/null > "$NUCLEI_DIR/nuclei_all.json" || touch "$NUCLEI_DIR/nuclei_all.json"

    NUCLEI_COUNT=$(cat "$NUCLEI_DIR/nuclei_all.json" | jq -s 'length' 2>/dev/null || echo "0")
    log_info "Nuclei findings: $NUCLEI_COUNT"
else
    log_warn "Nuclei not found or no scan URLs"
fi

################################################################################
# PHASE 4B: TRIVY - CONFIGURATION & IMAGE SCANNING
################################################################################

log_info "=== TRIVY SCANNING ==="

TRIVY_DIR="$PHASE_DIR/trivy"
mkdir -p "$TRIVY_DIR"

if command -v trivy &> /dev/null; then
    log_info "Running Trivy..."

    # Scan current directory for misconfigurations
    if [ -d ".git" ]; then
        log_info "Trivy: Scanning repository for misconfigurations..."
        run_with_timeout "$TIMEOUT_DEFAULT" "trivy fs --scanners config,secret --format json --output \"$TRIVY_DIR/trivy_repo_config.json\" ." || log_warn "Trivy repo scan failed"
    fi

    # Scan for vulnerabilities in dependencies if package files exist
    for pkg_file in package.json requirements.txt Gemfile go.mod pom.xml; do
        if [ -f "$pkg_file" ]; then
            log_info "Trivy: Scanning $pkg_file..."
            run_with_timeout "$TIMEOUT_DEFAULT" "trivy fs --scanners vuln --format json --output \"$TRIVY_DIR/trivy_${pkg_file//[^a-zA-Z0-9]/_}.json\" ." || true
        fi
    done

    # Scan Docker images if any are found
    if command -v docker &> /dev/null; then
        docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | head -n 10 | while IFS= read -r image; do
            if [ ! -z "$image" ] && [ "$image" != "<none>:<none>" ]; then
                log_info "Trivy: Scanning Docker image $image..."
                run_with_timeout "$TIMEOUT_DEFAULT" "trivy image --format json --output \"$TRIVY_DIR/trivy_image_${image//[^a-zA-Z0-9]/_}.json\" \"$image\"" || true
            fi
        done
    fi

    # Merge Trivy results
    cat "$TRIVY_DIR"/trivy_*.json 2>/dev/null > "$TRIVY_DIR/trivy_all.json" || touch "$TRIVY_DIR/trivy_all.json"

    TRIVY_COUNT=$(cat "$TRIVY_DIR/trivy_all.json" | jq '[.Results[]?.Vulnerabilities[]?] | length' 2>/dev/null || echo "0")
    log_info "Trivy vulnerabilities: $TRIVY_COUNT"
else
    log_warn "Trivy not found"
fi

################################################################################
# PHASE 4C: XSS SCANNING - DALFOX
################################################################################

log_info "=== XSS SCANNING ==="

XSS_DIR="$PHASE_DIR/xss"
mkdir -p "$XSS_DIR"

# Dalfox
if command -v dalfox &> /dev/null; then
    log_info "Running Dalfox for XSS detection..."

    # Use URLs from Phase 3 with parameters
    if [ -f "$PHASE3_DIR/urls/all_urls.txt" ]; then
        # Filter URLs with parameters
        grep -E '\?.*=' "$PHASE3_DIR/urls/all_urls.txt" 2>/dev/null | head -n 100 > "$XSS_DIR/param_urls.txt" || touch "$XSS_DIR/param_urls.txt"

        if [ -s "$XSS_DIR/param_urls.txt" ]; then
            log_info "Testing $(wc -l < "$XSS_DIR/param_urls.txt" | tr -d ' ') URLs with parameters..."

            cat "$XSS_DIR/param_urls.txt" | \
                dalfox pipe --silence --output "$XSS_DIR/dalfox_results.txt" 2>/dev/null || log_warn "Dalfox scan failed"

            DALFOX_COUNT=$(grep -c "VULN\|POC" "$XSS_DIR/dalfox_results.txt" 2>/dev/null || echo "0")
            log_info "Dalfox XSS vulnerabilities: $DALFOX_COUNT"
        else
            log_info "No parameterized URLs found for XSS testing"
        fi
    else
        log_warn "No URLs from Phase 3 available for XSS testing"
    fi
else
    log_warn "Dalfox not found"
fi

# XSStrike (alternative)
if [ -f "/opt/XSStrike/xsstrike.py" ] && [ -f "$XSS_DIR/param_urls.txt" ]; then
    log_info "Running XSStrike..."

    head -n 20 "$XSS_DIR/param_urls.txt" | while IFS= read -r url; do
        python3 /opt/XSStrike/xsstrike.py -u "$url" --crawl --skip-dom \
            >> "$XSS_DIR/xsstrike_results.txt" 2>/dev/null || true
    done
else
    log_warn "XSStrike not found or no parameterized URLs"
fi

################################################################################
# PHASE 4D: SQL INJECTION - SQLMAP
################################################################################

log_info "=== SQL INJECTION SCANNING ==="

SQLI_DIR="$PHASE_DIR/sqli"
mkdir -p "$SQLI_DIR"

if command -v sqlmap &> /dev/null; then
    log_info "Running SQLMap..."

    # Use parameterized URLs
    if [ -f "$XSS_DIR/param_urls.txt" ] && [ -s "$XSS_DIR/param_urls.txt" ]; then
        log_info "Testing $(wc -l < "$XSS_DIR/param_urls.txt" | tr -d ' ') URLs for SQL injection..."

        head -n 30 "$XSS_DIR/param_urls.txt" | awk 'NF' > "$SQLI_DIR/sqlmap_targets.txt"

        export SQLI_DIR SQLMAP_THREADS
        run_parallel_from_file "$SQLI_DIR/sqlmap_targets.txt" "$THREADS" '
            url="$1"
            log_info "SQLMap: $url"
            sqlmap -u "$url" --batch --random-agent --level=1 --risk=1 \
                --output-dir="$SQLI_DIR" --flush-session --threads="$SQLMAP_THREADS" \
                >> "$SQLI_DIR/sqlmap_results.txt" 2>&1 || true
        '

        SQLI_COUNT=$(grep -c "vulnerable" "$SQLI_DIR/sqlmap_results.txt" 2>/dev/null || echo "0")
        log_info "SQLMap vulnerabilities: $SQLI_COUNT"
    else
        log_info "No parameterized URLs for SQL injection testing"
    fi
else
    log_warn "SQLMap not found"
fi

################################################################################
# PHASE 4E: CORS MISCONFIGURATION - CORSY
################################################################################

log_info "=== CORS MISCONFIGURATION SCANNING ==="

CORS_DIR="$PHASE_DIR/cors"
mkdir -p "$CORS_DIR"

if command -v corsy &> /dev/null || [ -f "/opt/Corsy/corsy.py" ]; then
    log_info "Running Corsy..."

    if [ "$SCAN_COUNT" -eq 0 ]; then
        log_warn "No scan URLs for Corsy"
    elif [ -f "/opt/Corsy/corsy.py" ]; then
        run_with_timeout "$TIMEOUT_DEFAULT" "python3 /opt/Corsy/corsy.py -i \"$PHASE_DIR/scan_urls.txt\" -o \"$CORS_DIR/corsy_results.txt\"" || log_warn "Corsy failed"
    else
        run_with_timeout "$TIMEOUT_DEFAULT" "corsy -i \"$PHASE_DIR/scan_urls.txt\" -o \"$CORS_DIR/corsy_results.txt\"" || log_warn "Corsy failed"
    fi

    if [ -f "$CORS_DIR/corsy_results.txt" ]; then
        CORS_COUNT=$(grep -c "Vulnerable\|Misconfigured" "$CORS_DIR/corsy_results.txt" 2>/dev/null || echo "0")
        log_info "CORS misconfigurations: $CORS_COUNT"
    fi
else
    log_warn "Corsy not found"
fi

################################################################################
# PHASE 4F: ADDITIONAL VULNERABILITY SCANNERS
################################################################################

log_info "=== ADDITIONAL SCANNERS ==="

MISC_DIR="$PHASE_DIR/misc"
mkdir -p "$MISC_DIR"

# Nikto (Web server scanner)
if command -v nikto &> /dev/null; then
    log_info "Running Nikto..."

    head -n 10 "$ALIVE_HOSTS" | awk 'NF' > "$MISC_DIR/nikto_targets.txt"

    export MISC_DIR
    run_parallel_from_file "$MISC_DIR/nikto_targets.txt" "$THREADS" '
        host="$1"
        log_info "Nikto: $host"
        nikto -h "https://$host" -Format json -output "$MISC_DIR/nikto_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
    '

    cat "$MISC_DIR"/nikto_*.json 2>/dev/null > "$MISC_DIR/nikto_all.json" || touch "$MISC_DIR/nikto_all.json"
else
    log_warn "Nikto not found"
fi

# WPScan (WordPress scanner)
if command -v wpscan &> /dev/null; then
    log_info "Checking for WordPress installations..."

    grep -i "wp-content\|wp-includes\|wp-admin" "$PHASE3_DIR/urls/all_urls.txt" 2>/dev/null | \
        sed -E 's|(https?://[^/]+).*|\1|' | sort -u | head -n 5 > "$MISC_DIR/wordpress_sites.txt" || touch "$MISC_DIR/wordpress_sites.txt"

    if [ -s "$MISC_DIR/wordpress_sites.txt" ]; then
        log_info "Found WordPress sites, running WPScan..."

        export MISC_DIR
        run_parallel_from_file "$MISC_DIR/wordpress_sites.txt" "$THREADS" '
            wp_url="$1"
            log_info "WPScan: $wp_url"
            wpscan --url "$wp_url" --random-agent --format json \
                --output "$MISC_DIR/wpscan_${wp_url//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
        '

        cat "$MISC_DIR"/wpscan_*.json 2>/dev/null > "$MISC_DIR/wpscan_all.json" || touch "$MISC_DIR/wpscan_all.json"
    fi
else
    log_warn "WPScan not found"
fi

# Wapiti (Web application vulnerability scanner)
if command -v wapiti &> /dev/null; then
    log_info "Running Wapiti..."

    head -n 5 "$PHASE_DIR/scan_urls.txt" | awk 'NF' > "$MISC_DIR/wapiti_targets.txt"

    export MISC_DIR
    run_parallel_from_file "$MISC_DIR/wapiti_targets.txt" "$THREADS" '
        url="$1"
        log_info "Wapiti: $url"
        wapiti -u "$url" -f json -o "$MISC_DIR/wapiti_${url//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
    '

    cat "$MISC_DIR"/wapiti_*.json 2>/dev/null > "$MISC_DIR/wapiti_all.json" || touch "$MISC_DIR/wapiti_all.json"
else
    log_warn "Wapiti not found"
fi

# CMSmap (CMS scanner)
if command -v cmsmap &> /dev/null; then
    log_info "Running CMSmap..."

    head -n 10 "$PHASE_DIR/scan_urls.txt" | awk 'NF' > "$MISC_DIR/cmsmap_targets.txt"

    export MISC_DIR
    run_parallel_from_file "$MISC_DIR/cmsmap_targets.txt" "$THREADS" '
        url="$1"
        log_info "CMSmap: $url"
        cmsmap -t "$url" -o "$MISC_DIR/cmsmap_${url//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || true
    '

    cat "$MISC_DIR"/cmsmap_*.txt 2>/dev/null > "$MISC_DIR/cmsmap_all.txt" || touch "$MISC_DIR/cmsmap_all.txt"
else
    log_warn "CMSmap not found"
fi

# Retire.js (JavaScript library vulnerability scanner)
if command -v retire &> /dev/null; then
    log_info "Running Retire.js..."

    head -n 50 "$PHASE3_DIR/urls/javascript_files.txt" 2>/dev/null | awk 'NF' > "$MISC_DIR/retire_targets.txt"

    export MISC_DIR
    run_parallel_from_file "$MISC_DIR/retire_targets.txt" "$THREADS" '
        js_url="$1"
        retire --jspath "$js_url" --outputformat json >> "$MISC_DIR/retirejs_results.json" 2>/dev/null || true
    '
else
    log_warn "Retire.js not found"
fi

################################################################################
# PHASE 4G: SSL/TLS SCANNING
################################################################################

log_info "=== SSL/TLS SECURITY SCANNING ==="

SSL_DIR="$PHASE_DIR/ssl"
mkdir -p "$SSL_DIR"

# testssl.sh
if command -v testssl.sh &> /dev/null || [ -f "/opt/testssl.sh/testssl.sh" ]; then
    log_info "Running testssl.sh..."

    head -n 10 "$ALIVE_HOSTS" | awk 'NF' > "$SSL_DIR/testssl_targets.txt"

    export SSL_DIR
    run_parallel_from_file "$SSL_DIR/testssl_targets.txt" "$THREADS" '
        host="$1"
        log_info "testssl.sh: $host"
        if [ -f "/opt/testssl.sh/testssl.sh" ]; then
            /opt/testssl.sh/testssl.sh --jsonfile "$SSL_DIR/testssl_${host//[^a-zA-Z0-9]/_}.json" "$host" 2>/dev/null || true
        else
            testssl.sh --jsonfile "$SSL_DIR/testssl_${host//[^a-zA-Z0-9]/_}.json" "$host" 2>/dev/null || true
        fi
    '

    cat "$SSL_DIR"/testssl_*.json 2>/dev/null > "$SSL_DIR/testssl_all.json" || touch "$SSL_DIR/testssl_all.json"
else
    log_warn "testssl.sh not found"
fi

# SSLyze (alternative)
if command -v sslyze &> /dev/null; then
    log_info "Running SSLyze..."

    head -n 10 "$ALIVE_HOSTS" | awk 'NF' > "$SSL_DIR/sslyze_targets.txt"

    export SSL_DIR
    run_parallel_from_file "$SSL_DIR/sslyze_targets.txt" "$THREADS" '
        host="$1"
        log_info "SSLyze: $host"
        sslyze --json_out="$SSL_DIR/sslyze_${host//[^a-zA-Z0-9]/_}.json" "$host" 2>/dev/null || true
    '

    cat "$SSL_DIR"/sslyze_*.json 2>/dev/null > "$SSL_DIR/sslyze_all.json" || touch "$SSL_DIR/sslyze_all.json"
else
    log_warn "SSLyze not found"
fi

################################################################################
# CLEANUP AND SUMMARY
################################################################################

log_info "=== PHASE 4 SUMMARY ==="
echo "Target: $TARGET"
echo "URLs Scanned: $SCAN_COUNT"
echo ""
echo "Vulnerability Findings:"
echo "  - Nuclei: ${NUCLEI_COUNT:-0}"
echo "  - Trivy: ${TRIVY_COUNT:-0}"
echo "  - Dalfox (XSS): ${DALFOX_COUNT:-0}"
echo "  - SQLMap (SQLi): ${SQLI_COUNT:-0}"
echo "  - Corsy (CORS): ${CORS_COUNT:-0}"
echo ""
echo "Output directories:"
echo "  - $NUCLEI_DIR: Nuclei results"
echo "  - $TRIVY_DIR: Trivy configuration/image scans"
echo "  - $XSS_DIR: XSS vulnerability results"
echo "  - $SQLI_DIR: SQL injection results"
echo "  - $CORS_DIR: CORS misconfiguration results"
echo "  - $MISC_DIR: Additional scanner results"
echo "  - $SSL_DIR: SSL/TLS security results"

# Count critical findings
CRITICAL_COUNT=0
if [ -f "$NUCLEI_DIR/nuclei_all.json" ]; then
    CRITICAL_COUNT=$(cat "$NUCLEI_DIR/nuclei_all.json" | jq '[.[] | select(.info.severity == "critical")] | length' 2>/dev/null || echo "0")
fi

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    log_error "WARNING: Found $CRITICAL_COUNT CRITICAL vulnerabilities!"
fi

# Create phase completion marker
touch "$PHASE_DIR/.completed"
log_info "Phase 4 completed successfully!"

exit 0
