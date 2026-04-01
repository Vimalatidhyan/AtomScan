#!/bin/bash
################################################################################
# Technieum - Phase 5: Threat Intelligence
# Multi-source threat intel aggregation. Does not change phases 1-4.
################################################################################

set +e
set -o pipefail

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase5_threat_intel"
PHASE1_DIR="$OUTPUT_DIR/phase1_discovery"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

mkdir -p "$PHASE_DIR"/{data_leaks,malware,ip_reputation,domain_reputation,blocklists,breach_monitoring}

TIMEOUT_HTTP="${TECHNIEUM_THREAT_INTEL_TIMEOUT:-60}"

echo "[*] Phase 5: Threat Intelligence for $TARGET"
echo "[*] Output directory: $PHASE_DIR"

# Resolved IPs and hosts from Phase 1 (or use target as single host)
IPS_FILE="$PHASE_DIR/ips_to_check.txt"
HOSTS_FILE="$PHASE_DIR/hosts_to_check.txt"
if [ -s "$PHASE1_DIR/resolved_subdomains.txt" ]; then
    # Try to get IPs from dnsx JSON if present
    if [ -s "$PHASE1_DIR/dnsx_resolved.json" ]; then
        jq -r '.a[]?' "$PHASE1_DIR/dnsx_resolved.json" 2>/dev/null | sort -u > "$IPS_FILE" || true
    fi
    cp "$PHASE1_DIR/resolved_subdomains.txt" "$HOSTS_FILE"
elif [ -s "$PHASE1_DIR/all_subdomains.txt" ]; then
    cp "$PHASE1_DIR/all_subdomains.txt" "$HOSTS_FILE"
else
    echo "$TARGET" > "$HOSTS_FILE"
fi
[ ! -s "$IPS_FILE" ] && echo "" > "$IPS_FILE"

log_info "=== 5A: Data Leak Detection (optional APIs) ==="
if [ -n "$EMAILREP_API_KEY" ]; then
    log_info "EmailRep: check emails from assets if available"
    # Placeholder: would need list of emails; skip if none
fi
if [ -n "$DEHASHED_EMAIL" ] && [ -n "$DEHASHED_KEY" ]; then
    log_info "DeHashed: API key set (use from Python/API for queries)"
fi

log_info "=== 5B: Malware & Phishing (FREE - abuse.ch) ==="
MAL_DIR="$PHASE_DIR/malware"
# URLhaus: check host
run_timeout "$TIMEOUT_HTTP" bash -c "curl -s -X POST 'https://urlhaus-api.abuse.ch/v1/host/' --data 'host=$TARGET' 2>/dev/null" > "$MAL_DIR/urlhaus_host.json" 2>/dev/null || touch "$MAL_DIR/urlhaus_host.json"
# ThreatFox: search IOC
run_timeout "$TIMEOUT_HTTP" bash -c "curl -s -X POST 'https://threatfox-api.abuse.ch/api/v1/' -H 'Content-Type: application/json' -d '{\"query\":\"search_ioc\",\"search_term\":\"$TARGET\"}' 2>/dev/null" > "$MAL_DIR/threatfox.json" 2>/dev/null || touch "$MAL_DIR/threatfox.json"

log_info "=== 5C: IP Reputation ==="
IP_DIR="$PHASE_DIR/ip_reputation"
while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    safe_ip=$(echo "$ip" | tr -cd '.[:digit:]')
    [ -z "$safe_ip" ] && continue
    if [ -n "$ABUSEIPDB_API_KEY" ]; then
        run_timeout 15 curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$safe_ip" -H "Key: $ABUSEIPDB_API_KEY" 2>/dev/null > "$IP_DIR/abuseipdb_${safe_ip}.json" || true
    fi
    if [ -n "$GREYNOISE_API_KEY" ]; then
        run_timeout 15 curl -s "https://api.greynoise.io/v3/community/$safe_ip" -H "key: $GREYNOISE_API_KEY" 2>/dev/null > "$IP_DIR/greynoise_${safe_ip}.json" || true
    fi
    [ -n "$OTX_API_KEY" ] && run_timeout 15 curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$safe_ip/general" -H "X-OTX-API-KEY: $OTX_API_KEY" 2>/dev/null > "$IP_DIR/otx_${safe_ip}.json" || true
done < "$IPS_FILE" 2>/dev/null
# If no IPs from Phase 1, do one lookup for root domain
if [ ! -s "$IPS_FILE" ] && command -v host &>/dev/null; then
    ip=$(run_timeout 10 host "$TARGET" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    [ -n "$ip" ] && echo "$ip" > "$IPS_FILE"
    [ -n "$ip" ] && [ -n "$ABUSEIPDB_API_KEY" ] && run_timeout 15 curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" -H "Key: $ABUSEIPDB_API_KEY" 2>/dev/null > "$IP_DIR/abuseipdb_${ip}.json" || true
fi

log_info "=== 5D: Domain Reputation ==="
DOM_DIR="$PHASE_DIR/domain_reputation"
# ThreatMiner (free, no key)
run_timeout "$TIMEOUT_HTTP" curl -s "https://api.threatminer.org/v2/domain.php?q=$TARGET&rt=1" 2>/dev/null > "$DOM_DIR/threatminer.json" || touch "$DOM_DIR/threatminer.json"
[ -n "$OTX_API_KEY" ] && run_timeout "$TIMEOUT_HTTP" curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/general" -H "X-OTX-API-KEY: $OTX_API_KEY" 2>/dev/null > "$DOM_DIR/otx_domain.json" || true

log_info "=== 5E: Blocklist Checking (DNS) ==="
BL_DIR="$PHASE_DIR/blocklists"
while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    safe_ip=$(echo "$ip" | tr -cd '.[:digit:]')
    [ -z "$safe_ip" ] && continue
    rev=$(echo "$safe_ip" | awk -F. '{print $4"."$3"."$2"."$1}')
    if command -v dig &>/dev/null; then
        dig +short "$rev.zen.spamhaus.org" A 2>/dev/null | grep -q . && echo "$ip,spamhaus,listed" >> "$BL_DIR/blocklists.csv" || true
    fi
done < "$IPS_FILE" 2>/dev/null
[ ! -f "$BL_DIR/blocklists.csv" ] && touch "$BL_DIR/blocklists.csv"

log_info "=== 5F: Breach / Paste Monitoring ==="
BR_DIR="$PHASE_DIR/breach_monitoring"
# Psbdmp.ws (paste search) - no key
run_timeout "$TIMEOUT_HTTP" curl -s "https://psbdmp.ws/api/search/$TARGET" 2>/dev/null > "$BR_DIR/psbdmp.json" || touch "$BR_DIR/psbdmp.json"

log_info "=== Aggregating Phase 5 results ==="
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SUMMARY="$PHASE_DIR/phase5_threat_intel_summary.json"
DB_PATH="${TECHNIEUM_DB_PATH:-technieum.db}"
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"
if PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}" python3 -m intelligence.threat_intel.aggregator --target "$TARGET" --phase-dir "$PHASE_DIR" --output "$SUMMARY" --db "$DB_PATH" 2>/dev/null; then
    log_info "Phase 5 summary written to $SUMMARY"
else
    PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}" python3 -m intelligence.threat_intel.aggregator --target "$TARGET" --phase-dir "$PHASE_DIR" --output "$SUMMARY" 2>/dev/null || true
fi
echo "[+] Phase 5 completed successfully!"
