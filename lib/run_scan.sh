#!/usr/bin/env bash
# Technieum Scan Harness — UI/API Orchestrator
#
# This harness is invoked by the API worker and is responsible for running
# ALL Technieum phase modules (00–09) so that scans triggered from the UI
# execute the full pipeline, not just a subset of tools.
#
# It preserves the worker protocol:
#   - Prints structured log lines
#   - Emits phase markers like [phase:N] (N=0..9)
#   - Never fail-fast; missing tools/scripts lead to warnings, not aborts
#   - Collates key outputs into the scan output root so ingestion works
#
# Arguments:
#   $1  scan_run_id   — integer, used for log correlation
#   $2  domain        — target domain (validated upstream)
#   $3  scan_type     — full | quick | deep | custom (default: full)
#
# Exit codes:
#   0  — scan completed successfully
#   1  — scan failed (see stderr / last log line)
#   2  — invalid arguments

set -u
SCAN_RUN_ID="${1:?Usage: run_scan.sh <scan_run_id> <domain> <scan_type>}"
DOMAIN="${2:?domain required}"
SCAN_TYPE="${3:-full}"

TIMEOUT_PHASE="${TIMEOUT_PHASE:-7200}"
# Resolve important paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULES_DIR="$ROOT_DIR/modules"

OUTPUT_BASE="${TECHNIEUM_OUTPUT_DIR:-$ROOT_DIR/output}"
OUTPUT_DIR="${OUTPUT_BASE}/${DOMAIN//\./_}_scan_${SCAN_RUN_ID}"

# Ensure output base/run directory is valid and writable even when launched from
# varied environments (worker, cron, manual shell).
mkdir -p "$OUTPUT_BASE"
if [ -e "$OUTPUT_DIR" ] && [ ! -d "$OUTPUT_DIR" ]; then
    mv -f "$OUTPUT_DIR" "${OUTPUT_DIR}.bak.$(date +%s)" 2>/dev/null || rm -f "$OUTPUT_DIR" 2>/dev/null || true
fi
mkdir -p "$OUTPUT_DIR"

# Prepend repo bin/ shims so they override broken system wrappers (e.g. the
# /usr/bin/amass wrapper that calls sudo libpostal_data without a TTY).
[ -d "$ROOT_DIR/bin" ] && export PATH="$ROOT_DIR/bin:$PATH"

# Do not exit on command or pipeline failure; run every phase and every tool.
set +e
set +o pipefail
set +u

# ── Default empty API keys (prevent unset-variable errors) ────────────────
SECURITYTRAILS_API_KEY="${SECURITYTRAILS_API_KEY:-}"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
CENSYS_API_ID="${CENSYS_API_ID:-}"
CENSYS_API_SECRET="${CENSYS_API_SECRET:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
PASTEBIN_API_KEY="${PASTEBIN_API_KEY:-}"
EMAILREP_API_KEY="${EMAILREP_API_KEY:-}"
DEHASHED_EMAIL="${DEHASHED_EMAIL:-}"
DEHASHED_KEY="${DEHASHED_KEY:-}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
GREYNOISE_API_KEY="${GREYNOISE_API_KEY:-}"
OTX_API_KEY="${OTX_API_KEY:-}"
NVD_API_KEY="${NVD_API_KEY:-}"

# ProjectDiscovery Cloud Platform key (used by asnmap/subfinder/katana in some builds)
PDCP_API_KEY="${PDCP_API_KEY:-}"
PROJECTDISCOVERY_API_KEY="${PROJECTDISCOVERY_API_KEY:-}"

# Fill missing env vars from config/api_keys.yaml (best-effort, non-fatal)
API_KEYS_FILE="$ROOT_DIR/config/api_keys.yaml"
if [ -f "$API_KEYS_FILE" ]; then
    _yaml_pdcp="$(awk -F: '/^[[:space:]]*pdcp_api_key:[[:space:]]*/{sub(/^[^:]*:[[:space:]]*/, ""); gsub(/"/, ""); gsub(/\r/, ""); print; exit}' "$API_KEYS_FILE" 2>/dev/null)"
    if [ -z "$PDCP_API_KEY" ] && [ -n "$_yaml_pdcp" ]; then
        PDCP_API_KEY="$_yaml_pdcp"
    fi
    if [ -z "$PROJECTDISCOVERY_API_KEY" ] && [ -n "$PDCP_API_KEY" ]; then
        PROJECTDISCOVERY_API_KEY="$PDCP_API_KEY"
    fi
fi

# Cross-populate both names so downstream tools can use either variable.
if [ -z "$PDCP_API_KEY" ] && [ -n "$PROJECTDISCOVERY_API_KEY" ]; then
    PDCP_API_KEY="$PROJECTDISCOVERY_API_KEY"
fi
if [ -z "$PROJECTDISCOVERY_API_KEY" ] && [ -n "$PDCP_API_KEY" ]; then
    PROJECTDISCOVERY_API_KEY="$PDCP_API_KEY"
fi

export SECURITYTRAILS_API_KEY SHODAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET
export GITHUB_TOKEN PASTEBIN_API_KEY EMAILREP_API_KEY DEHASHED_EMAIL DEHASHED_KEY
export ABUSEIPDB_API_KEY GREYNOISE_API_KEY OTX_API_KEY NVD_API_KEY
export PDCP_API_KEY PROJECTDISCOVERY_API_KEY

# ── Logging helpers ───────────────────────────────────────────────────────
ts()      { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log_info(){ echo "[$(ts)] [INFO]  $*"; }
log_warn(){ echo "[$(ts)] [WARN]  $*"; }
log_err() { echo "[$(ts)] [ERROR] $*" >&2; echo "[$(ts)] [ERROR] $*"; }

tool_ok() { command -v "$1" >/dev/null 2>&1; }

# Run a command with timeout; never exit the script (return 0 on timeout/failure so scan continues)
run_with_timeout() {
    local t="$1"; shift
    if tool_ok timeout; then
        timeout "$t" "$@" || true
    else
        "$@" &
        local pid=$!
        local elapsed=0
        while [ "$elapsed" -lt "$t" ]; do
            if ! kill -0 "$pid" 2>/dev/null; then
                wait "$pid" || true
                return 0
            fi
            sleep 1; elapsed=$(( elapsed + 1 ))
        done
        kill -- "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; true
    fi
}

# ── Start ─────────────────────────────────────────────────────────────────
log_info "scan start: id=$SCAN_RUN_ID domain=$DOMAIN type=$SCAN_TYPE"
log_info "output dir: $OUTPUT_DIR"

#############################################
# Phase 0 — DNS validation
#############################################
log_info "[phase:0] DNS validation"
RESOLVED=""
if tool_ok dig; then
    RESOLVED=$(dig +short "$DOMAIN" 2>/dev/null | head -5 || true)
    if [ -n "$RESOLVED" ]; then
        log_info "[dns] $DOMAIN resolved: $(echo "$RESOLVED" | tr '\n' ' ')"
    else
        log_warn "[dns] no A record for $DOMAIN (may be CNAME-only or private)"
    fi
elif tool_ok nslookup; then
    RESOLVED=$(nslookup "$DOMAIN" 2>/dev/null | awk '/^Address:/{print $2}' | tail -n+2 | head -3 || true)
    log_info "[dns] nslookup: $RESOLVED"
elif tool_ok host; then
    RESOLVED=$(host "$DOMAIN" 2>/dev/null | head -3 || true)
    log_info "[dns] host: $RESOLVED"
else
    log_warn "[dns] no DNS tool available (dig/nslookup/host); proceeding without validation"
fi

# Quick scan: DNS only, then exit
if [ "$SCAN_TYPE" = "quick" ]; then
    log_info "[scan:quick] Quick scan complete"
    log_info "[scan:complete] scan finished: id=$SCAN_RUN_ID domain=$DOMAIN"
    exit 0
fi

#############################################
# Helpers — module runner + collators
#############################################
module_path() {
    echo "$MODULES_DIR/$1"
}

run_module() {
    local mod="$1"; shift
    local phase="$1"; shift
    local path; path=$(module_path "$mod")
    if [ ! -f "$path" ]; then
        log_warn "[$mod] script not found; skipping"
        return 2
    fi
    if [ ! -x "$path" ]; then chmod +x "$path" 2>/dev/null || true; fi
    log_info "[phase:${phase}] Running $mod"
    # Use TIMEOUT_PHASE per phase, modules handle their own subtasks timeouts
    run_with_timeout "$(( TIMEOUT_PHASE * 2 ))" bash "$path" "$DOMAIN" "$OUTPUT_DIR" || true
}

# Collate key outputs into root for worker ingestion
collate_phase1() {
    local p1="$OUTPUT_DIR/phase1_discovery"
    [ -f "$p1/all_subdomains.txt" ] && cp -f "$p1/all_subdomains.txt" "$OUTPUT_DIR/subdomains.txt" && \
        log_info "[collate] subdomains.txt prepared"
    [ -f "$p1/httpx_alive.json" ] && cp -f "$p1/httpx_alive.json" "$OUTPUT_DIR/httpx_alive.json" && \
        log_info "[collate] httpx_alive.json prepared"
    # Copy alive_urls.txt so phases 2/3 can use full URLs directly
    [ -f "$p1/alive_urls.txt" ] && cp -f "$p1/alive_urls.txt" "$OUTPUT_DIR/alive_urls.txt" && \
        log_info "[collate] alive_urls.txt prepared"
    # Copy structured phase1 summary so worker can ingest ASN + cloud data
    [ -f "$p1/phase1_summary.json" ] && cp -f "$p1/phase1_summary.json" "$OUTPUT_DIR/phase1_summary.json" && \
        log_info "[collate] phase1_summary.json prepared"
}
collate_phase2() {
    local p2="$OUTPUT_DIR/phase2_intel"
    if [ -f "$p2/ports/nmap_all.xml" ]; then
        cp -f "$p2/ports/nmap_all.xml" "$OUTPUT_DIR/nmap.xml"
        log_info "[collate] nmap.xml prepared"
    elif [ -f "$p2/ports/nmap_all.txt" ]; then
        cp -f "$p2/ports/nmap_all.txt" "$OUTPUT_DIR/nmap.txt"
        log_info "[collate] nmap.txt prepared"
    fi
}
collate_phase3() {
    local p3="$OUTPUT_DIR/phase3_content"
    local brute="$p3/bruteforce"
    # FFUF JSONs (in bruteforce/ subdirectory)
    for f in "$brute"/ffuf_*.json "$p3"/ffuf_*.json; do
        [ -f "$f" ] && cp -f "$f" "$OUTPUT_DIR/" && log_info "[collate] $(basename "$f") prepared"
    done
    # Feroxbuster / Dirsearch text (in bruteforce/ subdirectory)
    for f in "$brute"/feroxbuster_*.txt "$brute"/dirsearch_*.txt \
             "$p3"/feroxbuster_*.txt "$p3"/dirsearch_*.txt; do
        [ -f "$f" ] && cp -f "$f" "$OUTPUT_DIR/" && log_info "[collate] $(basename "$f") prepared"
    done
    # Cariddi secrets + Mantra secret scan results
    local cariddi="$p3/urls/cariddi"
    [ -f "$cariddi/cariddi_secrets.txt" ] && cp -f "$cariddi/cariddi_secrets.txt" "$OUTPUT_DIR/cariddi_secrets.txt" && \
        log_info "[collate] cariddi_secrets.txt prepared"
    [ -f "$cariddi/mantra_secrets.txt" ] && cp -f "$cariddi/mantra_secrets.txt" "$OUTPUT_DIR/mantra_secrets.txt" && \
        log_info "[collate] mantra_secrets.txt prepared"
    [ -f "$cariddi/cariddi_results.json" ] && cp -f "$cariddi/cariddi_results.json" "$OUTPUT_DIR/cariddi_results.json" && \
        log_info "[collate] cariddi_results.json prepared"
    # Gitleaks + TruffleHog web secret scan results (from Phase 3)
    local secrets="$p3/urls/secrets"
    [ -f "$secrets/gitleaks_web.json" ] && cp -f "$secrets/gitleaks_web.json" "$OUTPUT_DIR/gitleaks_web.json" && \
        log_info "[collate] gitleaks_web.json prepared"
    [ -f "$secrets/trufflehog_web.json" ] && cp -f "$secrets/trufflehog_web.json" "$OUTPUT_DIR/trufflehog_web.json" && \
        log_info "[collate] trufflehog_web.json prepared"
    # JavaScript files list
    [ -f "$p3/urls/javascript_files.txt" ] && cp -f "$p3/urls/javascript_files.txt" "$OUTPUT_DIR/javascript_files.txt" && \
        log_info "[collate] javascript_files.txt prepared"
}
collate_phase4() {
    local p4="$OUTPUT_DIR/phase4_vulnscan"
    # Nuclei writes to $PHASE_DIR/nuclei/nuclei_all.json
    if [ -f "$p4/nuclei/nuclei_all.json" ]; then
        cp -f "$p4/nuclei/nuclei_all.json" "$OUTPUT_DIR/nuclei.json" && log_info "[collate] nuclei.json prepared"
    elif [ -f "$p4/nuclei.json" ]; then
        cp -f "$p4/nuclei.json" "$OUTPUT_DIR/nuclei.json" && log_info "[collate] nuclei.json prepared"
    elif [ -f "$p4/nuclei_results.json" ]; then
        cp -f "$p4/nuclei_results.json" "$OUTPUT_DIR/nuclei.json" && log_info "[collate] nuclei.json prepared"
    fi
    # Secret scan results from Phase 4
    local secrets="$p4/secrets"
    [ -f "$secrets/gitleaks_web.json" ] && [ ! -f "$OUTPUT_DIR/gitleaks_web.json" ] && \
        cp -f "$secrets/gitleaks_web.json" "$OUTPUT_DIR/gitleaks_web.json" && log_info "[collate] gitleaks_web.json prepared (from phase4)"
    [ -f "$secrets/trufflehog_web.json" ] && [ ! -f "$OUTPUT_DIR/trufflehog_web.json" ] && \
        cp -f "$secrets/trufflehog_web.json" "$OUTPUT_DIR/trufflehog_web.json" && log_info "[collate] trufflehog_web.json prepared (from phase4)"
    # Nuclei vulnerability summary
    [ -f "$p4/vulnerabilities_summary.json" ] && cp -f "$p4/vulnerabilities_summary.json" "$OUTPUT_DIR/vulnerabilities_summary.json" && \
        log_info "[collate] vulnerabilities_summary.json prepared"
    # GoWitness screenshot summary + report
    local gw="$p4/gowitness"
    [ -f "$gw/gowitness_summary.json" ] && cp -f "$gw/gowitness_summary.json" "$OUTPUT_DIR/gowitness_summary.json" && \
        log_info "[collate] gowitness_summary.json prepared"
    [ -f "$gw/gowitness_report.html" ] && cp -f "$gw/gowitness_report.html" "$OUTPUT_DIR/gowitness_report.html" && \
        log_info "[collate] gowitness_report.html prepared"
    # Also collate SubProber results from phase2 if available
    local p2="$OUTPUT_DIR/phase2_intel"
    for f in "$p2"/subprober_*.json; do
        [ -f "$f" ] && cp -f "$f" "$OUTPUT_DIR/" && log_info "[collate] $(basename "$f") prepared"
    done
}

#############################################
# Phase 0 — Pre-scan module (if present)
#############################################
run_module "00_prescan.sh" 0

#############################################
# Phases 1–4 — Bash modules
#############################################
run_module "01_discovery.sh" 1
collate_phase1

run_module "02_intel.sh" 2
collate_phase2

run_module "03_content.sh" 3
collate_phase3

run_module "04_vuln.sh" 4
collate_phase4

collate_phase5() {
    local p5="$OUTPUT_DIR/phase5_threat_intel"
    [ -f "$p5/phase5_threat_intel_summary.json" ] && cp -f "$p5/phase5_threat_intel_summary.json" "$OUTPUT_DIR/threat_intel_summary.json" && \
        log_info "[collate] threat_intel_summary.json prepared"
}
collate_phase6() {
    local p6="$OUTPUT_DIR/phase6_cve_correlation"
    [ -f "$p6/cve_summary.json" ] && cp -f "$p6/cve_summary.json" "$OUTPUT_DIR/cve_summary.json" && \
        log_info "[collate] cve_summary.json prepared"
    [ -f "$p6/risk_scores/risk_summary.json" ] && cp -f "$p6/risk_scores/risk_summary.json" "$OUTPUT_DIR/risk_summary.json" && \
        log_info "[collate] risk_summary.json prepared"
    [ -f "$p6/cve_data/cve_matches.json" ] && cp -f "$p6/cve_data/cve_matches.json" "$OUTPUT_DIR/cve_matches.json" && \
        log_info "[collate] cve_matches.json prepared"
}
collate_phase7() {
    local p7="$OUTPUT_DIR/phase7_change_detection"
    [ -f "$p7/change_detection_summary.json" ] && cp -f "$p7/change_detection_summary.json" "$OUTPUT_DIR/change_detection_summary.json" && \
        log_info "[collate] change_detection_summary.json prepared"
    [ -f "$p7/delta/change_delta.json" ] && cp -f "$p7/delta/change_delta.json" "$OUTPUT_DIR/change_delta.json" && \
        log_info "[collate] change_delta.json prepared"
    [ -f "$p7/alerts/change_alerts.json" ] && cp -f "$p7/alerts/change_alerts.json" "$OUTPUT_DIR/change_alerts.json" && \
        log_info "[collate] change_alerts.json prepared"
}
collate_phase8() {
    local p8="$OUTPUT_DIR/phase8_compliance"
    [ -f "$p8/reports/compliance_summary.json" ] && cp -f "$p8/reports/compliance_summary.json" "$OUTPUT_DIR/compliance_summary.json" && \
        log_info "[collate] compliance_summary.json prepared"
}
collate_phase9() {
    local p9="$OUTPUT_DIR/phase9_attack_graph"
    [ -f "$p9/reports/attack_graph_summary.json" ] && cp -f "$p9/reports/attack_graph_summary.json" "$OUTPUT_DIR/attack_graph_summary.json" && \
        log_info "[collate] attack_graph_summary.json prepared"
    [ -f "$p9/visualizations/graph_d3.json" ] && cp -f "$p9/visualizations/graph_d3.json" "$OUTPUT_DIR/graph_d3.json" && \
        log_info "[collate] graph_d3.json prepared"
    [ -f "$p9/graph/attack_graph.json" ] && cp -f "$p9/graph/attack_graph.json" "$OUTPUT_DIR/attack_graph.json" && \
        log_info "[collate] attack_graph.json prepared"
}

#############################################
# Optional phases 5–9 — run when present
#############################################
run_module "05_threat_intel.sh" 5
collate_phase5

run_module "06_cve_correlation.sh" 6
collate_phase6

run_module "07_change_detection.sh" 7
collate_phase7

run_module "08_compliance.sh" 8
collate_phase8

run_module "09_attack_graph.sh" 9
collate_phase9

log_info "[scan:complete] scan finished: id=$SCAN_RUN_ID domain=$DOMAIN"
exit 0
