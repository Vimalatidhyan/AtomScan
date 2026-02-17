#!/usr/bin/env bash
# ReconX Scan Harness
# Called by the Python worker for each scan job.
#
# Arguments:
#   $1  scan_run_id   — integer, used for log correlation
#   $2  domain        — target domain (validated upstream)
#   $3  scan_type     — full | quick | deep | custom (default: full)
#
# Output protocol:
#   Each stdout line is captured as a ScanEvent by the Python worker.
#   Phase markers use the format:  [phase:N]  (N=0..4)
#   The worker parses these to update ScanProgress.current_phase and
#   progress_percentage in real time.
#
# Exit codes:
#   0  — scan completed successfully
#   1  — scan failed (see stderr / last log line)
#   2  — invalid arguments
#
# The script runs whatever tools are available.  If no tool is present
# for a phase it logs a warning and continues — it does NOT silently skip.
#
# Resilience: Tool failures never stop the scan. Every phase runs; every
# available tool in each phase runs. Failed tools only log a warning so we
# collect all possible results (complete ASM behavior).

set -u
SCAN_RUN_ID="${1:?Usage: run_scan.sh <scan_run_id> <domain> <scan_type>}"
DOMAIN="${2:?domain required}"
SCAN_TYPE="${3:-full}"

TIMEOUT_PHASE="${TIMEOUT_PHASE:-180}"
OUTPUT_BASE="${RECONX_OUTPUT_DIR:-./output}"
OUTPUT_DIR="${OUTPUT_BASE}/${DOMAIN//\./_}_${SCAN_RUN_ID}"
mkdir -p "$OUTPUT_DIR"

# Do not exit on command or pipeline failure; run every phase and every tool.
# Unset vars (set +u) so optional/conditional vars never abort the script.
set +e
set +o pipefail
set +u

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

# ── Phase 0: DNS validation ───────────────────────────────────────────────
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
    exit 0
fi

# ── Phase 1: Subdomain discovery (run all available tools, merge results) ─
log_info "[phase:1] Subdomain discovery"
SUBDOMAIN_FILE="$OUTPUT_DIR/subdomains.txt"
touch "$SUBDOMAIN_FILE"

if tool_ok subfinder; then
    log_info "[subfinder] running on $DOMAIN"
    ( run_with_timeout "$TIMEOUT_PHASE" subfinder -d "$DOMAIN" -silent -o "$SUBDOMAIN_FILE" 2>&1; true ) || log_warn "[subfinder] non-zero exit"
    COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)
    log_info "[subfinder] found $COUNT subdomains"
fi
if tool_ok amass; then
    log_info "[amass] running enum on $DOMAIN"
    _amass_out="$OUTPUT_DIR/amass_subdomains.txt"
    ( run_with_timeout "$TIMEOUT_PHASE" amass enum -passive -d "$DOMAIN" -o "$_amass_out" 2>&1; true ) || log_warn "[amass] non-zero exit"
    if [ -s "$_amass_out" ]; then
        cat "$_amass_out" >> "$SUBDOMAIN_FILE"
        sort -u "$SUBDOMAIN_FILE" -o "$SUBDOMAIN_FILE"
        COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)
        log_info "[amass] merged; total subdomains: $COUNT"
    fi
fi
if ! [ -s "$SUBDOMAIN_FILE" ]; then
    log_info "[phase:1] no subdomains yet; probing common prefixes via DNS"
    FOUND=0
    for sub in www mail ftp vpn remote dev api portal admin staging test; do
        if tool_ok dig; then
            RES=$(dig +short "${sub}.${DOMAIN}" 2>/dev/null | head -1 || true)
            if [ -n "$RES" ]; then
                echo "${sub}.${DOMAIN}" >> "$SUBDOMAIN_FILE"
                log_info "[dns-brute] ${sub}.${DOMAIN} -> $RES"
                FOUND=$(( FOUND + 1 ))
            fi
        fi
    done
    log_info "[dns-brute] found $FOUND common subdomains"
fi
COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)
log_info "[phase:1] total subdomains: $COUNT"
log_info "[phase:1] complete — continuing to phase 2"

# ── Phase 2: Port scanning (run available scanner; failure does not stop scan) ─
log_info "[phase:2] Port scanning"
if tool_ok nmap; then
    log_info "[nmap] scanning top ports on $DOMAIN"
    ( run_with_timeout "$TIMEOUT_PHASE" nmap -T4 --open -oN "$OUTPUT_DIR/nmap.txt" "$DOMAIN" 2>&1 | grep -E "(PORT|[0-9]+/)" || true; true )
    log_info "[nmap] port scan complete"
fi
if tool_ok nc && [ ! -s "$OUTPUT_DIR/nmap.txt" ]; then
    log_info "[nc] probing common ports on $DOMAIN (nmap had no output or was skipped)"
    for port in 22 25 53 80 443 3000 3306 5432 6379 8080 8443 8888 9200; do
        if nc -zw2 "$DOMAIN" "$port" 2>/dev/null; then
            log_info "[port] $DOMAIN:$port OPEN"
        fi
    done
fi
if ! tool_ok nmap && ! tool_ok nc; then
    log_warn "[phase:2] no port scanner available (nmap/nc); skipping"
fi
log_info "[phase:2] complete — continuing to phase 3"

# ── Phase 3: Web service discovery (run all available tools) ──────────────
log_info "[phase:3] Web service discovery"
WEB_FILE="$OUTPUT_DIR/web_services.txt"
touch "$WEB_FILE"
if [ -s "$SUBDOMAIN_FILE" ]; then PROBE_INPUT="$SUBDOMAIN_FILE"; else
    echo "$DOMAIN" > "$OUTPUT_DIR/single_target.txt"
    PROBE_INPUT="$OUTPUT_DIR/single_target.txt"
fi

if tool_ok httpx; then
    log_info "[httpx] probing live web services"
    ( run_with_timeout "$TIMEOUT_PHASE" httpx -l "$PROBE_INPUT" -silent -status-code -title -o "$WEB_FILE" 2>&1; true ) || log_warn "[httpx] non-zero exit"
    WEB_COUNT=$(wc -l < "$WEB_FILE" 2>/dev/null || echo 0)
    log_info "[httpx] found $WEB_COUNT live web services"
fi
if tool_ok curl; then
    log_info "[curl] probing $DOMAIN over http/https"
    for proto in http https; do
        CODE=$(curl -sI --max-time 10 -o /dev/null -w "%{http_code}" "${proto}://${DOMAIN}" 2>/dev/null || echo "err")
        log_info "[curl] ${proto}://${DOMAIN} -> HTTP $CODE"
    done
fi
if ! tool_ok httpx && ! tool_ok curl; then
    log_warn "[phase:3] no web probe tool available (httpx/curl); skipping"
fi
log_info "[phase:3] complete — continuing to phase 4"

# Only skip vulnerability phase for explicit "quick" scans
if [ "$SCAN_TYPE" = "quick" ]; then
    log_info "[scan:quick] skipping vulnerability phase; done"
    exit 0
fi
log_info "[scan:$SCAN_TYPE] including vulnerability phase (phase 4)"

# ── Phase 4: Vulnerability scanning (run all available tools) ──────────────
log_info "[phase:4] Vulnerability scanning"
NUCLEI_OUT="$OUTPUT_DIR/nuclei.json"
NIKTO_OUT="$OUTPUT_DIR/nikto.txt"
if tool_ok nuclei; then
    log_info "[nuclei] running vulnerability templates on $DOMAIN"
    ( run_with_timeout "$(( TIMEOUT_PHASE * 2 ))" nuclei -u "https://$DOMAIN" -silent -json -o "$NUCLEI_OUT" 2>&1; true ) || log_warn "[nuclei] non-zero exit (may be no findings)"
    VULN_COUNT=$(wc -l < "$NUCLEI_OUT" 2>/dev/null || echo 0)
    log_info "[nuclei] found $VULN_COUNT potential vulnerabilities"
fi
if tool_ok nikto; then
    log_info "[nikto] running web vulnerability scan on $DOMAIN"
    ( run_with_timeout "$TIMEOUT_PHASE" nikto -h "https://$DOMAIN" -nointeractive 2>&1 | tee "$NIKTO_OUT" | grep -E "^[-+]" || true; true )
    log_info "[nikto] scan complete"
fi
if ! tool_ok nuclei && ! tool_ok nikto; then
    log_warn "[phase:4] no vulnerability scanner available (nuclei/nikto); skipping"
fi
log_info "[phase:4] complete — all phases finished"

log_info "[scan:complete] scan finished: id=$SCAN_RUN_ID domain=$DOMAIN"
exit 0
