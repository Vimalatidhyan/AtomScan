#!/bin/bash
################################################################################
# Technieum - Phase 2: Intelligence & Infrastructure
# Port scanning, OSINT, Takeover detection, Repo leaks
################################################################################

# Do not fail-fast; continue even if some tools error
set +e
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

# ── Tool-run counters ─────────────────────────────────────────────────────────
TOOLS_SUCCESS=0
TOOLS_FAILED=0
TOOLS_SKIPPED=0

# ── Generic tool runner with timeout and availability check ───────────────────
run_tool() {
    local tool_name="$1"
    local output_file="$2"
    local timeout_duration="${3:-600}"
    shift 3
    local cmd="$*"
    if ! command -v "$tool_name" &>/dev/null; then
        log_warn "$tool_name not installed, skipping"
        ((TOOLS_SKIPPED++)); return 2
    fi
    touch "${output_file}" 2>/dev/null || true
    if run_timeout "$timeout_duration" bash -c "$cmd" 2>"${output_file}.err"; then
        log_info "$tool_name completed"
        ((TOOLS_SUCCESS++)); return 0
    else
        local ec=$?
        [ $ec -eq 124 ] && log_error "$tool_name timed out after ${timeout_duration}s" \
                        || log_error "$tool_name failed (exit $ec)"
        ((TOOLS_FAILED++)); return 1
    fi
}

# Tunables (increase speed where safe)
RUSTSCAN_BATCH="${TECHNIEUM_RUSTSCAN_BATCH:-1000}"
RUSTSCAN_TIMEOUT="${TECHNIEUM_RUSTSCAN_TIMEOUT:-3000}"
SUBJACK_THREADS="${TECHNIEUM_SUBJACK_THREADS:-100}"
NMAP_MAX_HOSTS="${TECHNIEUM_NMAP_MAX_HOSTS:-50}"
# Default host timeout reduced to 120s (was 600s). CDN/cloud hosts (Cloudflare,
# CloudFront, AWS GA) only expose HTTP/HTTPS so a 600s timeout per host caused
# 20+ minute stalls with -p- scanning all 65535 ports.
NMAP_HOST_TIMEOUT="${TECHNIEUM_NMAP_HOST_TIMEOUT:-120}"
NMAP_MAX_FILE_MB="${TECHNIEUM_NMAP_MAX_FILE_MB:-500}"
# Common ports used as nmap fallback when RustScan is not installed.
# These are the ports that actually matter for web/cloud targets.
_NMAP_COMMON_PORTS="21,22,23,25,53,80,110,135,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8000,8008,8888,9200,27017"
MIN_DISK_MB="${TECHNIEUM_MIN_DISK_MB:-1024}"


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
    log_warn "Phase 1 alive_hosts.txt not found; creating empty file and continuing with limited data"
    mkdir -p "$PHASE1_DIR"
    touch "$PHASE1_DIR/alive_hosts.txt"
fi

ALIVE_HOSTS="$PHASE1_DIR/alive_hosts.txt"
ALIVE_COUNT=$(wc -l < "$ALIVE_HOSTS" | tr -d ' ')
log_info "Found $ALIVE_COUNT alive hosts from Phase 1"
if [ "$ALIVE_COUNT" -eq 0 ]; then
    log_warn "No alive hosts found in Phase 1; Phase 2 will be limited"
fi

# Prefer full URLs if available (used for normalization + tool fallbacks)
if [ -s "$PHASE1_DIR/alive_urls.txt" ]; then
    ALIVE_URLS="$PHASE1_DIR/alive_urls.txt"
else
    ALIVE_URLS="$PHASE_DIR/alive_urls_generated.txt"
    sed -E 's|^https?://||' "$ALIVE_HOSTS" | awk 'NF{print "https://"$0}' > "$ALIVE_URLS" 2>/dev/null || touch "$ALIVE_URLS"
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

# Use union of alive_hosts + alive_urls + SubProber results, then normalize.
# This guarantees every alive endpoint is directed into the Phase-2 nmap target set.
safe_cat "$PHASE_DIR/scan_hosts_raw.txt" "$ALIVE_HOSTS" "$ALIVE_URLS" "$PHASE_DIR/subprober_validated.txt"
cat "$PHASE_DIR/scan_hosts_raw.txt" 2>/dev/null | \
    sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|[[:space:]]*$||' | awk 'NF' | sort -u > "$PHASE_DIR/scan_hosts.txt"
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
        log_warn "Capping Nmap from $TARGETS_COUNT to $NMAP_MAX_HOSTS hosts (set TECHNIEUM_NMAP_MAX_HOSTS to change)"
    fi

    # Build smart port list from RustScan results if available.
    # Fall back to common web/service ports (NOT -p-) when RustScan has no
    # results. Scanning all 65535 ports on CDN/cloud hosts (Cloudflare,
    # CloudFront, AWS Global Accelerator) with a 600s host timeout caused
    # 20+ minute stalls; common ports complete in under 2 minutes each.
    NMAP_PORT_FLAG="-p ${_NMAP_COMMON_PORTS}"  # safe default
    if [ -f "$PORTS_DIR/rustscan_ports.txt" ] && [ -s "$PORTS_DIR/rustscan_ports.txt" ]; then
        DISCOVERED_PORTS=$(grep -oP ':\K\d+' "$PORTS_DIR/rustscan_ports.txt" 2>/dev/null | sort -un | paste -sd, -)
        if [ -n "$DISCOVERED_PORTS" ]; then
            NMAP_PORT_FLAG="-p $DISCOVERED_PORTS"
            log_info "Using RustScan-discovered ports for Nmap: $DISCOVERED_PORTS"
        else
            log_info "RustScan file present but no ports parsed; using common ports for Nmap"
        fi
    else
        log_info "RustScan not available; using common ports for Nmap (set TECHNIEUM_NMAP_FULL=1 to enable -p-)"
    fi

    # Allow full -p- scan via env override (useful when scan type is 'deep')
    if [ "${TECHNIEUM_NMAP_FULL:-0}" = "1" ] || [ "${SCAN_TYPE:-full}" = "deep" ]; then
        NMAP_PORT_FLAG="-p-"
        log_info "Full port scan enabled (TECHNIEUM_NMAP_FULL=1 or scan_type=deep)"
    fi

    if [ -f "$NMAP_TARGETS" ]; then
        # Check disk space before starting
        if ! check_disk_space "$PORTS_DIR"; then
            log_error "Aborting Nmap due to low disk space"
        else
            # Cap total nmap time to 3600s regardless of host count.
            # With parallelism=10: 10 hosts run in parallel, so effective
            # wall time ≈ ceil(hosts/10) × host_timeout ≤ 3600s.
            _NMAP_TIMEOUT=$(( NMAP_HOST_TIMEOUT * (NMAP_MAX_HOSTS / 10 + 1) ))
            [ "$_NMAP_TIMEOUT" -gt 3600 ] && _NMAP_TIMEOUT=3600
            log_info "Nmap scanning $NMAP_TARGET_COUNT targets via -iL (timeout=${_NMAP_TIMEOUT}s, port-flag=${NMAP_PORT_FLAG})..."
            run_timeout "$_NMAP_TIMEOUT" \
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
if command -v shodan &> /dev/null && [ -n "$SHODAN_API_KEY" ] && [ "$ALIVE_COUNT" -gt 0 ]; then
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
if command -v shodanx &> /dev/null && [ -n "$SHODAN_API_KEY" ]; then
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
elif [ -f "/opt/shodanx/shodanx.py" ] && [ -n "$SHODAN_API_KEY" ]; then
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
            sleep 2   # Rate-limit: avoid Google 429
        done < "$DORKS_FILE"
    fi
elif [ -n "$GOOGLEDORKER_PY" ]; then
    log_info "Running GoogleDorker (Python)..."
    python3 "$GOOGLEDORKER_PY" -l "$DORKS_FILE" -o "$OSINT_DIR/googledorker.txt" 2>/dev/null || log_warn "GoogleDorker failed"
else
    log_warn "GoogleDorker tool not found; running Python dork fallback..."
    # Export env vars for the Python subshell
    export TARGET DORKS_FILE
    export DORK_OUT="$OSINT_DIR/googledorker.txt"
    # Python fallback: uses googlesearch-python (pip install googlesearch-python)
    python3 - <<'DORKEOF' 2>/dev/null || true
import os, time, json
    from urllib.parse import quote_plus
target = os.environ.get('TARGET', '')
out_file = os.environ.get('DORK_OUT', '/tmp/googledorker.txt')
dork_file = os.environ.get('DORKS_FILE', '')
results = []
    dorks = []
    if dork_file and os.path.exists(dork_file):
        with open(dork_file) as f:
            dorks = [l.strip() for l in f if l.strip()]
    if not dorks:
        dorks = [
            f'site:{target}',
            f'site:{target} inurl:admin',
            f'site:{target} ext:env OR ext:sql OR ext:bak',
            f'site:{target} "index of" "backup"',
        ]
try:
    from googlesearch import search as gsearch
    for dork in dorks[:6]:   # cap to 6 queries to avoid blocks
        try:
            for url in gsearch(dork, num_results=10, sleep_interval=3):
                results.append({'dork': dork, 'url': url})
        except Exception as e:
            pass
        time.sleep(4)  # polite rate-limiting
except ImportError:
        # Dependency-free fallback: emit direct Google query URLs so output file is
        # still useful and downstream parsers don't see hard errors.
        for dork in dorks[:20]:
            results.append({'dork': dork, 'url': f'https://www.google.com/search?q={quote_plus(dork)}'})
except Exception as e:
        for dork in dorks[:20]:
            results.append({'dork': dork, 'url': f'https://www.google.com/search?q={quote_plus(dork)}'})
with open(out_file, 'w') as f:
    for r in results:
            if r.get('url'):
                f.write(r.get('url') + '\n')
print(f'[INFO] Google dorks: {len([r for r in results if r.get("url")])} results')
DORKEOF
fi

# Censys CLI
if command -v censys &> /dev/null && [ -n "$CENSYS_API_ID" ] && [ -n "$CENSYS_API_SECRET" ] && [ "$ALIVE_COUNT" -gt 0 ]; then
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
    touch "$OSINT_DIR/asn_info.txt" "$OSINT_DIR/asn_by_ip.txt" "$OSINT_DIR/asn_summary.txt"

    # Get unique IPs from dnsx results
    if [ -f "$PHASE1_DIR/dnsx_resolved.json" ]; then
        cat "$PHASE1_DIR/dnsx_resolved.json" | jq -r '.a[]?' 2>/dev/null | sort -u > "$OSINT_DIR/all_ips.txt"

        # Lookup ASN for each IP (sample first 50 to avoid rate limits)
        # Use timeout 10s per lookup to avoid indefinite stalls
        head -n 50 "$OSINT_DIR/all_ips.txt" | while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            _w=$(timeout 10 whois "$ip" 2>/dev/null || true)
            echo "$_w" | grep -E "^(origin|OrgName|Organization|ASN)" >> "$OSINT_DIR/asn_info.txt" 2>/dev/null || true
            _asn=$(echo "$_w" | grep -Ei '^(origin|ASN)' | head -n1 | sed -E 's/^[^:]*:[[:space:]]*//' )
            _org=$(echo "$_w" | grep -Ei '^(OrgName|Organization)' | head -n1 | sed -E 's/^[^:]*:[[:space:]]*//' )
            [ -z "$_asn" ] && _asn="unknown"
            [ -z "$_org" ] && _org="unknown"
            echo "$ip | $_asn | $_org" >> "$OSINT_DIR/asn_by_ip.txt"
        done

        {
            echo "target=$TARGET"
            echo "ip_count=$(wc -l < "$OSINT_DIR/all_ips.txt" 2>/dev/null | tr -d ' ')"
            echo "asn_records=$(wc -l < "$OSINT_DIR/asn_by_ip.txt" 2>/dev/null | tr -d ' ')"
            echo ""
            echo "top_asn:"
            cut -d'|' -f2 "$OSINT_DIR/asn_by_ip.txt" 2>/dev/null | sed 's/^ *//;s/ *$//' | grep -v '^unknown$' | sort | uniq -c | sort -nr | head -n 20
        } > "$OSINT_DIR/asn_summary.txt"
    fi
fi

################################################################################
# PHASE 2D: SUBDOMAIN TAKEOVER
################################################################################

log_info "=== SUBDOMAIN TAKEOVER DETECTION ==="

TAKEOVER_DIR="$PHASE_DIR/takeover"
mkdir -p "$TAKEOVER_DIR"

# Subjack
SUBJACK_BIN=""
if SUBJACK_BIN="$(resolve_tool_path subjack)"; then
    log_info "Running Subjack..."

    if [ -s "$PHASE1_DIR/all_subdomains.txt" ]; then
        # Run without -v (verbose) — verbose mode writes ALL subdomains to output,
        # inflating the count.  Without -v, only confirmed/potential takeovers appear.
        "$SUBJACK_BIN" -w "$PHASE1_DIR/all_subdomains.txt" \
            -t "$SUBJACK_THREADS" -timeout 30 -ssl \
            -o "$TAKEOVER_DIR/subjack_results.txt" 2>/dev/null || log_warn "Subjack failed"

        if [ -f "$TAKEOVER_DIR/subjack_results.txt" ]; then
            # Only count non-empty lines (subjack writes one line per confirmed finding)
            TAKEOVER_COUNT=$(grep -c '.' "$TAKEOVER_DIR/subjack_results.txt" 2>/dev/null || echo "0")
            if [ "$TAKEOVER_COUNT" -gt 0 ]; then
                log_warn "Found $TAKEOVER_COUNT potential subdomain takeovers — verify manually: $TAKEOVER_DIR/subjack_results.txt"
            else
                log_info "No subdomain takeovers detected"
            fi
        fi
    else
        log_warn "Subjack skipped: no subdomains available"
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

# Gitleaks - Scan for secrets in git repos (version-aware: v7 vs v8)
if command -v gitleaks &> /dev/null; then
    log_info "Running Gitleaks..."
    _GL_VER=$(gitleaks version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo '8.0')
    _GL_MAJOR=$(echo "$_GL_VER" | cut -d. -f1)

    # v8+ uses 'detect' subcommand; older versions use bare flags
    if [ "$_GL_MAJOR" -ge 8 ] 2>/dev/null; then
        _GL_CMD_LOCAL="gitleaks detect --source . --report-format json --report-path"
        _GL_CMD_REPO="gitleaks detect --source"
        _GL_CMD_REPO_SUFFIX="--report-format json --report-path"
    else
        _GL_CMD_LOCAL="gitleaks --path . --repo-config --report"
        _GL_CMD_REPO="gitleaks --path"
        _GL_CMD_REPO_SUFFIX="--report"
    fi

    if [ -d ".git" ]; then
        # Default OFF: local repo scan produces noisy findings unrelated to target recon.
        # Enable explicitly only when desired.
        if [ "${TECHNIEUM_GITLEAKS_SCAN_LOCAL:-false}" = "true" ]; then
            log_info "Scanning local repository with Gitleaks (TECHNIEUM_GITLEAKS_SCAN_LOCAL=true)..."
            # gitleaks exits 0 = no secrets, 1 = secrets found (CI/CD fail), 2+ = error
            $_GL_CMD_LOCAL "$LEAKS_DIR/gitleaks_report.json" 2>/dev/null; _gl_ec=$?
            if [ "$_gl_ec" -eq 0 ]; then
                log_info "Gitleaks: no secrets found"
            elif [ "$_gl_ec" -eq 1 ]; then
                log_warn "Gitleaks: secrets detected — review $LEAKS_DIR/gitleaks_report.json"
            else
                log_warn "Gitleaks scan failed (exit $_gl_ec) — check gitleaks version/config"
            fi
        else
            log_info "Skipping local Gitleaks scan (set TECHNIEUM_GITLEAKS_SCAN_LOCAL=true to enable)"
            echo "[]" > "$LEAKS_DIR/gitleaks_report.json"
        fi
    else
        log_info "No local git repository found for Gitleaks scan"
        echo "[]" > "$LEAKS_DIR/gitleaks_report.json"
    fi

    # Scan GitHub org repos if gh is available
    if command -v gh &> /dev/null; then
        ORG_NAME=$(echo "$TARGET" | cut -d'.' -f1)
        log_info "Attempting to scan GitHub org: $ORG_NAME"
        gh repo list "$ORG_NAME" --limit 10 --json name -q '.[].name' 2>/dev/null | while read -r repo; do
            log_info "Scanning repo: $ORG_NAME/$repo"
            TEMP_DIR=$(mktemp -d)
            git clone --depth 1 "https://github.com/$ORG_NAME/$repo" "$TEMP_DIR/$repo" 2>/dev/null || { rm -rf "$TEMP_DIR"; continue; }
            $_GL_CMD_REPO "$TEMP_DIR/$repo" $_GL_CMD_REPO_SUFFIX "$LEAKS_DIR/gitleaks_${repo}.json" 2>/dev/null || true
            rm -rf "$TEMP_DIR"
        done
    fi
else
    log_warn "Gitleaks not found"
fi

# GitHunt - Search GitHub for leaked secrets
GITHUNT_PY=""
for _gh_path in "/opt/GitHunt/githunt.py" "$HOME/tools/GitHunt/githunt.py"; do
    [ -f "$_gh_path" ] && GITHUNT_PY="$_gh_path" && break
done

if [ -n "$GITHUNT_PY" ] && [ -n "$GITHUB_TOKEN" ]; then
    log_info "Running GitHunt ($GITHUNT_PY)..."
    python3 "$GITHUNT_PY" -t "$TARGET" -o "$LEAKS_DIR/githunt_results.txt" 2>/dev/null || log_warn "GitHunt failed"
elif command -v githunt &> /dev/null && [ -n "$GITHUB_TOKEN" ]; then
    log_info "Running GitHunt..."
    githunt -t "$TARGET" -o "$LEAKS_DIR/githunt_results.txt" 2>/dev/null || log_warn "GitHunt failed"
elif [ -z "$GITHUB_TOKEN" ]; then
    log_info "GitHunt skipped — GITHUB_TOKEN not set (set it in config.yaml or environment to enable)"
else
    log_warn "GitHunt not found or GITHUB_TOKEN not set"
fi

# TruffleHog (v3+: trufflehog git|github; v2: trufflehog --regex)
if command -v trufflehog &> /dev/null; then
    log_info "Running TruffleHog..."
    _TH_VER=$(trufflehog --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo '3.0')
    _TH_MAJOR=$(echo "$_TH_VER" | cut -d. -f1)
    touch "$LEAKS_DIR/trufflehog_report.json"

    if [ -d ".git" ]; then
        if [ "$_TH_MAJOR" -ge 3 ] 2>/dev/null; then
            # Prefer filesystem mode on modern trufflehog; fallback to git mode.
            if trufflehog --help 2>&1 | grep -q 'filesystem'; then
                trufflehog filesystem . --json --only-verified \
                    > "$LEAKS_DIR/trufflehog_report.json" 2>/dev/null || log_warn "TruffleHog local filesystem scan failed"
            else
                trufflehog git file://. --json --only-verified \
                    > "$LEAKS_DIR/trufflehog_report.json" 2>/dev/null || log_warn "TruffleHog local git scan failed"
            fi
        else
            trufflehog --regex --entropy=False file://. \
                > "$LEAKS_DIR/trufflehog_report.json" 2>/dev/null || log_warn "TruffleHog v2 scan failed"
        fi
    fi

    # Scan GitHub org (verified secrets only to reduce noise)
    if [ -n "$GITHUB_TOKEN" ]; then
        ORG_NAME=$(echo "$TARGET" | cut -d'.' -f1)
        if [ "$_TH_MAJOR" -ge 3 ] 2>/dev/null; then
            GITHUB_TOKEN="$GITHUB_TOKEN" trufflehog github --org="$ORG_NAME" \
                --json --only-verified \
                > "$LEAKS_DIR/trufflehog_github.json" 2>/dev/null || log_warn "TruffleHog GitHub scan failed"
        else
            GITHUB_TOKEN="$GITHUB_TOKEN" trufflehog --regex --entropy=False \
                "https://github.com/$ORG_NAME" \
                > "$LEAKS_DIR/trufflehog_github.json" 2>/dev/null || log_warn "TruffleHog v2 GitHub scan failed"
        fi
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
log_info "Phase 2 complete: success=$TOOLS_SUCCESS failed=$TOOLS_FAILED skipped=$TOOLS_SKIPPED"

exit 0
