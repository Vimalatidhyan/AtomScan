#!/bin/bash
################################################################################
# ReconX - Phase 2: Intelligence & Infrastructure
# Port scanning, OSINT, Takeover detection, Repo leaks
################################################################################

# Do not fail-fast; continue even if some tools error
set -o pipefail
TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase2_intel"
PHASE1_DIR="$OUTPUT_DIR/phase1_discovery"
mkdir -p "$PHASE_DIR"

echo "[*] Phase 2: Intelligence & Infrastructure for $TARGET"
echo "[*] Output directory: $PHASE_DIR"

# Shared utilities (log_info, log_error, log_warn, safe_cat, safe_grep, check_disk_space)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

# Tunables (increase speed where safe)
RUSTSCAN_BATCH="${RECONX_RUSTSCAN_BATCH:-1000}"
RUSTSCAN_TIMEOUT="${RECONX_RUSTSCAN_TIMEOUT:-3000}"
SUBJACK_THREADS="${RECONX_SUBJACK_THREADS:-100}"
NMAP_MAX_HOSTS="${RECONX_NMAP_MAX_HOSTS:-50}"
NMAP_HOST_TIMEOUT="${RECONX_NMAP_HOST_TIMEOUT:-600}"
NMAP_MAX_FILE_MB="${RECONX_NMAP_MAX_FILE_MB:-500}"
MIN_DISK_MB="${RECONX_MIN_DISK_MB:-1024}"


run_shodanx_mode() {
    local mode="$1"
    local out_file="$2"
    local help_text

    help_text="$(shodanx "$mode" -h 2>&1 || true)"
    if [ -z "$help_text" ]; then
        return 1
    fi

    local target_flag=""
    local output_flag=""

    if echo "$help_text" | grep -q -- "--domain"; then
        target_flag="--domain"
    elif echo "$help_text" | grep -q -- " -d"; then
        target_flag="-d"
    elif echo "$help_text" | grep -q -- "--target"; then
        target_flag="--target"
    elif echo "$help_text" | grep -q -- " -t"; then
        target_flag="-t"
    fi

    if echo "$help_text" | grep -q -- "--output"; then
        output_flag="--output"
    elif echo "$help_text" | grep -q -- " -o"; then
        output_flag="-o"
    fi

    if [ -n "$output_flag" ]; then
        if [ -n "$target_flag" ]; then
            shodanx "$mode" "$target_flag" "$TARGET" "$output_flag" "$out_file" 2>/dev/null || return 1
        else
            shodanx "$mode" "$TARGET" "$output_flag" "$out_file" 2>/dev/null || return 1
        fi
    else
        if [ -n "$target_flag" ]; then
            shodanx "$mode" "$target_flag" "$TARGET" > "$out_file" 2>/dev/null || return 1
        else
            shodanx "$mode" "$TARGET" > "$out_file" 2>/dev/null || return 1
        fi
    fi

    return 0
}

# Check if alive hosts exist from Phase 1 (fallback to resolved subdomains)
if [ ! -s "$PHASE1_DIR/alive_hosts.txt" ] && [ -f "$PHASE1_DIR/resolved_subdomains.txt" ]; then
    log_warn "alive_hosts.txt missing/empty; using resolved_subdomains as fallback"
    cp "$PHASE1_DIR/resolved_subdomains.txt" "$PHASE1_DIR/alive_hosts.txt" 2>/dev/null || true
fi

if [ ! -f "$PHASE1_DIR/alive_hosts.txt" ]; then
    log_error "Phase 1 output not found. Run Phase 1 first!"
    exit 1
fi

ALIVE_HOSTS="$PHASE1_DIR/alive_hosts.txt"
ALIVE_COUNT=$(wc -l < "$ALIVE_HOSTS" | tr -d ' ')
log_info "Found $ALIVE_COUNT alive hosts from Phase 1"
if [ "$ALIVE_COUNT" -eq 0 ]; then
    log_warn "No alive hosts found in Phase 1; Phase 2 will be limited"
fi

################################################################################
# PHASE 2A: LIVE HOST VALIDATION
################################################################################

log_info "=== LIVE HOST VALIDATION ==="

# SubProber - Double check live hosts
SUBPROBER_PY=""
for candidate in \
    "/opt/SubProber/subprober.py" \
    "/opt/SubProber/SubProber.py" \
    "/opt/subprober/subprober.py"; do
    if [ -f "$candidate" ]; then
        SUBPROBER_PY="$candidate"
        break
    fi
done

if command -v subprober &> /dev/null; then
    log_info "Running SubProber for validation..."
    subprober -f "$ALIVE_HOSTS" -o "$PHASE_DIR/subprober_validated.txt" 2>/dev/null || log_warn "SubProber failed"
elif [ -n "$SUBPROBER_PY" ]; then
    log_info "Running SubProber (Python)..."
    python3 "$SUBPROBER_PY" -f "$ALIVE_HOSTS" -o "$PHASE_DIR/subprober_validated.txt" 2>/dev/null || log_warn "SubProber failed"
else
    log_warn "SubProber not found, using Phase 1 alive hosts"
    cp "$ALIVE_HOSTS" "$PHASE_DIR/subprober_validated.txt" 2>/dev/null || touch "$PHASE_DIR/subprober_validated.txt"
fi

if [ ! -s "$PHASE_DIR/subprober_validated.txt" ]; then
    log_warn "SubProber produced no output, falling back to Phase 1 alive hosts"
    cp "$ALIVE_HOSTS" "$PHASE_DIR/subprober_validated.txt" 2>/dev/null || touch "$PHASE_DIR/subprober_validated.txt"
fi

if [ -f "$PHASE_DIR/subprober_validated.txt" ]; then
    VALIDATED_COUNT=$(wc -l < "$PHASE_DIR/subprober_validated.txt" | tr -d ' ')
    log_info "SubProber validated $VALIDATED_COUNT hosts"
fi

# Use union of Phase 1 alive hosts and SubProber results for remaining scans
safe_cat "$PHASE_DIR/scan_hosts.txt" "$ALIVE_HOSTS" "$PHASE_DIR/subprober_validated.txt"
sort -u "$PHASE_DIR/scan_hosts.txt" -o "$PHASE_DIR/scan_hosts.txt"
SCAN_HOSTS="$PHASE_DIR/scan_hosts.txt"

################################################################################
# PHASE 2B: PORT SCANNING
################################################################################

log_info "=== PORT SCANNING ==="

PORTS_DIR="$PHASE_DIR/ports"
mkdir -p "$PORTS_DIR"

# Extract just hostnames/IPs for port scanning
cat "$SCAN_HOSTS" | sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|:.*||' | sort -u > "$PORTS_DIR/targets_raw.txt"

# Resolve hostnames to IPs in bulk
if command -v dnsx &> /dev/null; then
    log_info "Resolving hostnames via dnsx..."
    cat "$PORTS_DIR/targets_raw.txt" | dnsx -silent -a -resp-only > "$PORTS_DIR/resolved_ips.txt" 2>/dev/null || true
    # Also keep original entries that are already IPs
    grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$PORTS_DIR/targets_raw.txt" >> "$PORTS_DIR/resolved_ips.txt" 2>/dev/null || true
    sort -u "$PORTS_DIR/resolved_ips.txt" -o "$PORTS_DIR/targets.txt"
else
    # Fallback: parallel dig with xargs
    cat "$PORTS_DIR/targets_raw.txt" | xargs -P 20 -I{} sh -c '
        host="{}"
        if echo "$host" | grep -Eq "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
            echo "$host"
        else
            dig +short "$host" 2>/dev/null | grep -E "^[0-9]+\." | head -n 1
        fi
    ' > "$PORTS_DIR/targets.txt" 2>/dev/null
    sort -u "$PORTS_DIR/targets.txt" -o "$PORTS_DIR/targets.txt"
fi
TARGETS_COUNT=$(wc -l < "$PORTS_DIR/targets.txt" 2>/dev/null | tr -d ' ')

# RustScan - Fast initial scan (all targets at once)
if command -v rustscan &> /dev/null && [ "$TARGETS_COUNT" -gt 0 ]; then
    log_info "Running RustScan (fast port discovery on all targets)..."
    RUSTSCAN_NO_NMAP=""

    if rustscan -h 2>&1 | grep -q -- "--no-nmap"; then
        RUSTSCAN_NO_NMAP="--no-nmap"
    fi

    TARGETS_CSV=$(paste -sd, "$PORTS_DIR/targets.txt")
    rustscan -a "$TARGETS_CSV" -b "$RUSTSCAN_BATCH" -t "$RUSTSCAN_TIMEOUT" \
        --ulimit 5000 --range 1-65535 $RUSTSCAN_NO_NMAP \
        > "$PORTS_DIR/rustscan_raw.txt" 2>/dev/null || log_warn "RustScan failed"

    # Parse RustScan output to extract ports
    if [ -f "$PORTS_DIR/rustscan_raw.txt" ]; then
        grep -oP '\d+\.\d+\.\d+\.\d+:\d+|\[.*?\]' "$PORTS_DIR/rustscan_raw.txt" 2>/dev/null > "$PORTS_DIR/rustscan_ports.txt" || true
    fi
else
    log_warn "RustScan not found or no scan targets"
fi

# Nmap - Deep scan on discovered ports
if command -v nmap &> /dev/null && [ "$TARGETS_COUNT" -gt 0 ]; then
    log_info "Running Nmap (deep service detection)..."

    # Cap target count to prevent runaway scans
    NMAP_TARGETS="$PORTS_DIR/nmap_targets.txt"
    head -n "$NMAP_MAX_HOSTS" "$PORTS_DIR/targets.txt" > "$NMAP_TARGETS"
    NMAP_TARGET_COUNT=$(wc -l < "$NMAP_TARGETS" | tr -d ' ')
    if [ "$TARGETS_COUNT" -gt "$NMAP_MAX_HOSTS" ]; then
        log_warn "Capping Nmap from $TARGETS_COUNT to $NMAP_MAX_HOSTS hosts (set RECONX_NMAP_MAX_HOSTS to change)"
    fi

    # Build smart port list from RustScan results if available
    NMAP_PORT_FLAG="-p-"
    if [ -f "$PORTS_DIR/rustscan_ports.txt" ] && [ -s "$PORTS_DIR/rustscan_ports.txt" ]; then
        DISCOVERED_PORTS=$(grep -oP ':\K\d+' "$PORTS_DIR/rustscan_ports.txt" 2>/dev/null | sort -un | paste -sd, -)
        if [ -n "$DISCOVERED_PORTS" ]; then
            NMAP_PORT_FLAG="-p $DISCOVERED_PORTS"
            log_info "Using RustScan-discovered ports: $DISCOVERED_PORTS"
        fi
    fi

    if [ -f "$NMAP_TARGETS" ]; then
        # Check disk space before starting
        if ! check_disk_space "$PORTS_DIR"; then
            log_error "Aborting Nmap due to low disk space"
        else
            log_info "Nmap scanning $NMAP_TARGET_COUNT targets via -iL..."
            run_timeout $((NMAP_HOST_TIMEOUT * NMAP_MAX_HOSTS)) \
                nmap -sV -sC -T4 -Pn $NMAP_PORT_FLAG \
                --host-timeout "${NMAP_HOST_TIMEOUT}s" \
                --min-parallelism 10 \
                -iL "$NMAP_TARGETS" \
                -oX "$PORTS_DIR/nmap_all.xml" \
                -oN "$PORTS_DIR/nmap_all.txt" \
                2>/dev/null || log_warn "Nmap failed or timed out"
        fi
    fi
else
    log_warn "Nmap not found or no scan targets"
fi

################################################################################
# PHASE 2C: OSINT & INFRASTRUCTURE
################################################################################

log_info "=== OSINT & INFRASTRUCTURE ==="

OSINT_DIR="$PHASE_DIR/osint"
mkdir -p "$OSINT_DIR"

# Shodan CLI
if command -v shodan &> /dev/null && [ ! -z "$SHODAN_API_KEY" ] && [ "$ALIVE_COUNT" -gt 0 ]; then
    log_info "Running Shodan..."

    while IFS= read -r host; do
        # Extract IP or hostname
        target=$(echo "$host" | sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|:.*||')
        log_info "Shodan: $target"
        shodan host "$target" > "$OSINT_DIR/shodan_${target//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || log_warn "Shodan failed for $target"
    done < "$SCAN_HOSTS"

    # Merge results
    safe_cat "$OSINT_DIR/shodan_all.txt" "$OSINT_DIR"/shodan_*.txt
else
    log_warn "Shodan CLI not found, SHODAN_API_KEY not set, or no scan hosts"
fi

# ShodanX (Revolt suite)
if command -v shodanx &> /dev/null && [ ! -z "$SHODAN_API_KEY" ]; then
    log_info "Running ShodanX..."

    if run_shodanx_mode "domain" "$OSINT_DIR/shodanx_domain.txt"; then
        log_info "ShodanX domain lookup completed"
    else
        log_warn "ShodanX domain lookup failed"
    fi

    if run_shodanx_mode "subdomain" "$OSINT_DIR/shodanx_subdomains.txt"; then
        log_info "ShodanX subdomain lookup completed"
    else
        log_warn "ShodanX subdomain lookup failed"
    fi
elif [ -f "/opt/shodanx/shodanx.py" ] && [ ! -z "$SHODAN_API_KEY" ]; then
    log_info "Running ShodanX (Python)..."
    python3 /opt/shodanx/shodanx.py -d "$TARGET" -o "$OSINT_DIR/shodanx.json" 2>/dev/null || log_warn "ShodanX failed"
else
    log_warn "ShodanX not found"
fi

# GoogleDorker (Revolt suite)
GOOGLEDORKER_PY=""
for candidate in \
    "/opt/GoogleDorker/dorker.py" \
    "/opt/GoogleDorker/GoogleDorker.py"; do
    if [ -f "$candidate" ]; then
        GOOGLEDORKER_PY="$candidate"
        break
    fi
done

DORKS_FILE="$OSINT_DIR/googledorker_queries.txt"
cat > "$DORKS_FILE" <<EOF
site:$TARGET
site:*.$TARGET
site:$TARGET inurl:admin
site:$TARGET inurl:login
site:$TARGET ext:sql
site:$TARGET ext:env
site:$TARGET ext:bak
site:$TARGET "index of" "backup"
EOF

if command -v dorker &> /dev/null; then
    log_info "Running GoogleDorker..."
    if ! dorker -l "$DORKS_FILE" -o "$OSINT_DIR/googledorker.txt" 2>/dev/null; then
        log_warn "GoogleDorker list mode failed, falling back to single queries"
        > "$OSINT_DIR/googledorker.txt"
        while IFS= read -r dork; do
            dorker -q "$dork" 2>/dev/null >> "$OSINT_DIR/googledorker.txt" || true
        done < "$DORKS_FILE"
    fi
elif [ -n "$GOOGLEDORKER_PY" ]; then
    log_info "Running GoogleDorker (Python)..."
    python3 "$GOOGLEDORKER_PY" -l "$DORKS_FILE" -o "$OSINT_DIR/googledorker.txt" 2>/dev/null || log_warn "GoogleDorker failed"
else
    log_warn "GoogleDorker not found"
fi

# Censys CLI
if command -v censys &> /dev/null && [ ! -z "$CENSYS_API_ID" ] && [ ! -z "$CENSYS_API_SECRET" ] && [ "$ALIVE_COUNT" -gt 0 ]; then
    log_info "Running Censys..."

    while IFS= read -r host; do
        target=$(echo "$host" | sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|:.*||')
        log_info "Censys: $target"
        censys search "$target" > "$OSINT_DIR/censys_${target//[^a-zA-Z0-9]/_}.json" 2>/dev/null || log_warn "Censys failed for $target"
    done < "$SCAN_HOSTS"

    # Merge results
    safe_cat "$OSINT_DIR/censys_all.json" "$OSINT_DIR"/censys_*.json
else
    log_warn "Censys CLI not found, API credentials not set, or no scan hosts"
fi

# Additional OSINT: ASN Lookup
if command -v whois &> /dev/null && [ "$ALIVE_COUNT" -gt 0 ]; then
    log_info "Gathering ASN information..."

    # Get unique IPs from dnsx results
    if [ -f "$PHASE1_DIR/dnsx_resolved.json" ]; then
        cat "$PHASE1_DIR/dnsx_resolved.json" | jq -r '.a[]?' 2>/dev/null | sort -u > "$OSINT_DIR/all_ips.txt"

        # Lookup ASN for each IP (sample first 50 to avoid rate limits)
        head -n 50 "$OSINT_DIR/all_ips.txt" | while IFS= read -r ip; do
            whois "$ip" | grep -E "^(origin|OrgName|Organization|ASN)" >> "$OSINT_DIR/asn_info.txt" 2>/dev/null || true
        done
    fi
fi

################################################################################
# PHASE 2D: SUBDOMAIN TAKEOVER
################################################################################

log_info "=== SUBDOMAIN TAKEOVER DETECTION ==="

TAKEOVER_DIR="$PHASE_DIR/takeover"
mkdir -p "$TAKEOVER_DIR"

# Subjack
if command -v subjack &> /dev/null; then
    log_info "Running Subjack..."

    if [ -f "$PHASE1_DIR/all_subdomains.txt" ]; then
        subjack -w "$PHASE1_DIR/all_subdomains.txt" \
            -t "$SUBJACK_THREADS" -timeout 30 -ssl -v \
            -o "$TAKEOVER_DIR/subjack_results.txt" 2>/dev/null || log_warn "Subjack failed"

        if [ -f "$TAKEOVER_DIR/subjack_results.txt" ]; then
            TAKEOVER_COUNT=$(wc -l < "$TAKEOVER_DIR/subjack_results.txt" | tr -d ' ')
            if [ "$TAKEOVER_COUNT" -gt 0 ]; then
                log_warn "Found $TAKEOVER_COUNT potential subdomain takeovers!"
            else
                log_info "No subdomain takeovers detected"
            fi
        fi
    fi
else
    log_warn "Subjack not found"
fi

# SubOver (alternative)
if command -v subover &> /dev/null && [ -f "$PHASE1_DIR/all_subdomains.txt" ]; then
    log_info "Running SubOver..."
    subover -l "$PHASE1_DIR/all_subdomains.txt" -o "$TAKEOVER_DIR/subover_results.txt" 2>/dev/null || log_warn "SubOver failed"
else
    log_warn "SubOver not found or no subdomains"
fi

################################################################################
# PHASE 2E: REPOSITORY LEAK DETECTION
################################################################################

log_info "=== REPOSITORY LEAK DETECTION ==="

LEAKS_DIR="$PHASE_DIR/leaks"
mkdir -p "$LEAKS_DIR"

# Gitleaks - Scan for secrets in git repos
if command -v gitleaks &> /dev/null; then
    log_info "Running Gitleaks..."

    # Check if target is a git repository or try to find company repos
    if [ -d ".git" ]; then
        log_info "Scanning local repository with Gitleaks..."
        gitleaks detect --source . --report-path "$LEAKS_DIR/gitleaks_report.json" 2>/dev/null || log_warn "Gitleaks scan failed"
    else
        log_info "No local git repository found for Gitleaks scan"
    fi

    # Try to scan GitHub if organization name matches
    if command -v gh &> /dev/null; then
        ORG_NAME=$(echo "$TARGET" | cut -d'.' -f1)
        log_info "Attempting to scan GitHub org: $ORG_NAME"

        # List repos (requires gh auth)
        gh repo list "$ORG_NAME" --limit 10 --json name -q '.[].name' 2>/dev/null | while read -r repo; do
            log_info "Scanning repo: $ORG_NAME/$repo"
            TEMP_DIR=$(mktemp -d)
            git clone --depth 1 "https://github.com/$ORG_NAME/$repo" "$TEMP_DIR/$repo" 2>/dev/null || continue
            gitleaks detect --source "$TEMP_DIR/$repo" --report-path "$LEAKS_DIR/gitleaks_${repo}.json" 2>/dev/null || true
            rm -rf "$TEMP_DIR"
        done
    fi
else
    log_warn "Gitleaks not found"
fi

# GitHunt - Search GitHub for leaked secrets
if [ -f "/opt/GitHunt/githunt.py" ] && [ ! -z "$GITHUB_TOKEN" ]; then
    log_info "Running GitHunt..."
    python3 /opt/GitHunt/githunt.py -t "$TARGET" -o "$LEAKS_DIR/githunt_results.txt" 2>/dev/null || log_warn "GitHunt failed"
elif command -v githunt &> /dev/null && [ ! -z "$GITHUB_TOKEN" ]; then
    log_info "Running GitHunt..."
    githunt -t "$TARGET" -o "$LEAKS_DIR/githunt_results.txt" 2>/dev/null || log_warn "GitHunt failed"
else
    log_warn "GitHunt not found or GITHUB_TOKEN not set"
fi

# TruffleHog (alternative secret scanner)
if command -v trufflehog &> /dev/null; then
    log_info "Running TruffleHog..."

    if [ -d ".git" ]; then
        trufflehog git file://. --json > "$LEAKS_DIR/trufflehog_report.json" 2>/dev/null || log_warn "TruffleHog failed"
    fi

    # Scan GitHub org
    if [ ! -z "$GITHUB_TOKEN" ]; then
        ORG_NAME=$(echo "$TARGET" | cut -d'.' -f1)
        trufflehog github --org="$ORG_NAME" --json > "$LEAKS_DIR/trufflehog_github.json" 2>/dev/null || log_warn "TruffleHog GitHub scan failed"
    fi
else
    log_warn "TruffleHog not found"
fi

# GitLeaks alternative: git-secrets
if command -v git-secrets &> /dev/null && [ -d ".git" ]; then
    log_info "Running git-secrets..."
    git secrets --scan --recursive > "$LEAKS_DIR/git_secrets.txt" 2>&1 || log_warn "git-secrets found issues (check output)"
else
    log_warn "git-secrets not found or not a git repo"
fi

################################################################################
# CLEANUP AND SUMMARY
################################################################################

log_info "=== PHASE 2 SUMMARY ==="
echo "Target: $TARGET"
echo "Scanned Hosts: $(wc -l < "$SCAN_HOSTS" 2>/dev/null | tr -d ' ')"

if [ -f "$PORTS_DIR/nmap_all.xml" ]; then
    OPEN_PORTS=$(grep -c "state=\"open\"" "$PORTS_DIR/nmap_all.xml" 2>/dev/null || echo "0")
    echo "Open Ports Found: $OPEN_PORTS"
fi

if [ -f "$TAKEOVER_DIR/subjack_results.txt" ]; then
    TAKEOVERS=$(wc -l < "$TAKEOVER_DIR/subjack_results.txt" 2>/dev/null | tr -d ' ')
    echo "Potential Takeovers: $TAKEOVERS"
fi

if [ -f "$LEAKS_DIR/gitleaks_report.json" ]; then
    GITLEAKS=$(jq length "$LEAKS_DIR/gitleaks_report.json" 2>/dev/null || echo "0")
    echo "Gitleaks Findings: $GITLEAKS"
fi

echo ""
echo "Output directories:"
echo "  - $PORTS_DIR: Port scan results"
echo "  - $OSINT_DIR: OSINT and infrastructure data"
echo "  - $TAKEOVER_DIR: Subdomain takeover results"
echo "  - $LEAKS_DIR: Repository leak detection"

# Create phase completion marker
touch "$PHASE_DIR/.completed"
log_info "Phase 2 completed successfully!"

exit 0
