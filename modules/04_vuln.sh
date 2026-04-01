#!/bin/bash
################################################################################
# Technieum - Phase 4: Vulnerability Scanning
# Comprehensive vulnerability assessment using multiple scanners
################################################################################

# DO NOT use set -e - we want to continue even if tools fail
set +e
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

# Concurrency controls
THREADS="${TECHNIEUM_THREADS:-10}"
SQLMAP_THREADS="${TECHNIEUM_SQLMAP_THREADS:-5}"
TIMEOUT_DEFAULT="${TECHNIEUM_VULN_TIMEOUT:-3600}"
NUCLEI_RATE_HIGH="${TECHNIEUM_NUCLEI_RATE_HIGH:-100}"

# Sanitize concurrency values
if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -lt 1 ]; then
    THREADS=10
fi
if ! [[ "$SQLMAP_THREADS" =~ ^[0-9]+$ ]] || [ "$SQLMAP_THREADS" -lt 1 ]; then
    SQLMAP_THREADS=5
fi

export -f log_info
export -f log_warn
export -f log_error

run_with_timeout() {
    local timeout_duration="$1"
    shift
    run_timeout "$timeout_duration" bash -c "$*" 2>/dev/null
}

run_parallel_from_file() {
    local input_file="$1"
    local parallelism="$2"
    local command="$3"

    if [ ! -s "$input_file" ]; then
        log_warn "No inputs found in $input_file"
        return 0
    fi

    tr '\n' '\0' < "$input_file" | xargs -0 -I{} -P "$parallelism" bash -c "$command" _ "{}"
}

# Check prerequisites — non-fatal: create empty file and continue
if [ ! -f "$PHASE1_DIR/alive_hosts.txt" ]; then
    log_warn "Phase 1 alive_hosts.txt not found; creating empty file and continuing with limited data"
    mkdir -p "$PHASE1_DIR"
    touch "$PHASE1_DIR/alive_hosts.txt"
fi

ALIVE_HOSTS="$PHASE1_DIR/alive_hosts.txt"
ALIVE_COUNT=$(wc -l < "$ALIVE_HOSTS" | tr -d ' ')
log_info "Found $ALIVE_COUNT alive hosts from Phase 1"

# Prepare URLs for scanning (strip existing scheme to avoid double-prefix)
cat "$ALIVE_HOSTS" | sed 's|^https\?://||' | sed 's|^|https://|' | head -n 50 > "$PHASE_DIR/scan_urls.txt"

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
    log_info "Running Nuclei with tech-stack-aware templates..."

    # Update Nuclei templates only when TECHNIEUM_NUCLEI_UPDATE=true (opt-in).
    TECHNIEUM_NUCLEI_UPDATE="${TECHNIEUM_NUCLEI_UPDATE:-false}"
    if [ "$TECHNIEUM_NUCLEI_UPDATE" = "true" ]; then
        log_info "Updating Nuclei templates (TECHNIEUM_NUCLEI_UPDATE=true)..."
        run_with_timeout "$TIMEOUT_DEFAULT" "nuclei -update-templates" || log_warn "Failed to update Nuclei templates"
    else
        log_info "Skipping Nuclei template update (set TECHNIEUM_NUCLEI_UPDATE=true to enable)"
    fi

    # Ensure templates are present; check multiple possible locations.
    _nuclei_tmpl_dir="${NUCLEI_TEMPLATES_PATH:-}"
    if [ -z "$_nuclei_tmpl_dir" ]; then
        for _tmpl_candidate in \
            "$HOME/nuclei-templates" \
            "$HOME/.local/nuclei-templates" \
            "/opt/nuclei-templates" \
            "/usr/share/nuclei-templates" \
            "$HOME/.config/nuclei/templates"; do
            if [ -d "$_tmpl_candidate" ]; then
                _nuclei_tmpl_dir="$_tmpl_candidate"
                break
            fi
        done
        [ -z "$_nuclei_tmpl_dir" ] && _nuclei_tmpl_dir="$HOME/nuclei-templates"
    fi

    if [ ! -d "$_nuclei_tmpl_dir" ]; then
        log_info "Nuclei templates not found at $_nuclei_tmpl_dir — fetching initial templates..."
        nuclei -update-templates 2>/dev/null || log_warn "Nuclei template fetch failed (network required)"
        # Re-check after fetch — nuclei may store templates in a different location
        for _tmpl_candidate in \
            "$HOME/nuclei-templates" \
            "$HOME/.local/nuclei-templates" \
            "$HOME/.config/nuclei/templates"; do
            if [ -d "$_tmpl_candidate" ]; then
                _nuclei_tmpl_dir="$_tmpl_candidate"
                log_info "Nuclei templates found at $_nuclei_tmpl_dir after fetch"
                break
            fi
        done
    else
        log_info "Using Nuclei templates from: $_nuclei_tmpl_dir"
    fi

    # ==========================================================================
    # STEP 1: Detect technologies using Nuclei's own tech-detection templates
    # ==========================================================================
    log_info "Nuclei STEP 1: Running technology detection templates..."

    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -jsonl \
        -tags tech \
        -rate-limit "$NUCLEI_RATE_HIGH" \
        -o "$NUCLEI_DIR/nuclei_techdetect.json" 2>/dev/null || true

    # Also try the technologies template directory if -tags tech found nothing
    if [ ! -s "$NUCLEI_DIR/nuclei_techdetect.json" ]; then
        for _tdir in "$_nuclei_tmpl_dir/http/technologies" "$_nuclei_tmpl_dir/technologies"; do
            if [ -d "$_tdir" ]; then
                log_info "Nuclei: retrying tech detect with template dir: $_tdir"
                cat "$PHASE_DIR/scan_urls.txt" | \
                    nuclei -silent -jsonl \
                    -t "$_tdir" \
                    -rate-limit "$NUCLEI_RATE_HIGH" \
                    -o "$NUCLEI_DIR/nuclei_techdetect.json" 2>/dev/null || true
                [ -s "$NUCLEI_DIR/nuclei_techdetect.json" ] && break
            fi
        done
    fi

    TECHDETECT_COUNT=$(wc -l < "$NUCLEI_DIR/nuclei_techdetect.json" 2>/dev/null | tr -d ' ')
    [ -z "$TECHDETECT_COUNT" ] && TECHDETECT_COUNT=0
    log_info "Nuclei tech-detection findings: $TECHDETECT_COUNT"

    # ==========================================================================
    # STEP 2: Build Nuclei tags from detected tech (Nuclei + httpx combined)
    # Reads from 3 sources:
    #   1. Nuclei tech-detection NDJSON (from STEP 1 above)
    #   2. httpx -tech-detect JSON output (from Phase 1)
    #   3. Phase 1 summary JSON (fallback)
    # ==========================================================================
    log_info "Nuclei STEP 2: Building tech-stack tag list..."

    _PY_OUT=$(NUCLEI_TECHDETECT="$NUCLEI_DIR/nuclei_techdetect.json" \
              HTTPX_FILE="$PHASE1_DIR/httpx_alive.json" \
              PHASE1_SUMMARY="$PHASE1_DIR/phase1_summary.json" \
              python3 << 'PYEOF'
import json, sys, os

# Mapping: keyword (lowercase) -> actual Nuclei template tags
# These are REAL tags found in nuclei-templates, not guesses.
TECH_TO_TAGS = {
    # CMS / Frameworks
    'wordpress':      ['wordpress', 'wp-plugin', 'wp-theme'],
    'joomla':         ['joomla'],
    'drupal':         ['drupal'],
    'magento':        ['magento'],
    'shopify':        ['shopify'],
    'prestashop':     ['prestashop'],
    'typo3':          ['typo3'],
    'ghost':          ['ghost'],
    'strapi':         ['strapi'],
    'umbraco':        ['umbraco'],
    'moodle':         ['moodle'],
    'woocommerce':    ['wordpress', 'woocommerce'],
    # PHP
    'laravel':        ['laravel', 'php'],
    'symfony':        ['symfony', 'php'],
    'codeigniter':    ['codeigniter', 'php'],
    'yii':            ['yii', 'php'],
    'cakephp':        ['cakephp', 'php'],
    'php':            ['php'],
    # Python
    'django':         ['django', 'python'],
    'flask':          ['flask', 'python'],
    'fastapi':        ['fastapi', 'python'],
    # Java
    'spring':         ['spring', 'springboot', 'java'],
    'springboot':     ['spring', 'springboot', 'java'],
    'struts':         ['struts', 'apache', 'java'],
    'tomcat':         ['tomcat', 'apache'],
    'weblogic':       ['weblogic', 'oracle'],
    'websphere':      ['websphere', 'ibm'],
    'jboss':          ['jboss', 'wildfly'],
    'wildfly':        ['jboss', 'wildfly'],
    'jetty':          ['jetty'],
    'java':           ['java'],
    # JavaScript / Node
    'express':        ['express', 'nodejs'],
    'next.js':        ['nextjs'],
    'nextjs':         ['nextjs'],
    'nuxt':           ['nuxtjs'],
    'node.js':        ['nodejs'],
    'nodejs':         ['nodejs'],
    # Ruby
    'ruby on rails':  ['rails', 'ruby'],
    'rails':          ['rails', 'ruby'],
    'ruby':           ['ruby'],
    # .NET
    'asp.net':        ['asp', 'microsoft', 'iis'],
    '.net':           ['asp', 'microsoft'],
    # Web servers
    'apache':         ['apache'],
    'nginx':          ['nginx'],
    'iis':            ['iis', 'microsoft'],
    'litespeed':      ['litespeed'],
    'caddy':          ['caddy'],
    'lighttpd':       ['lighttpd'],
    # Reverse proxies / LB / CDN
    'cloudflare':     ['cloudflare'],
    'varnish':        ['varnish'],
    'haproxy':        ['haproxy'],
    'traefik':        ['traefik'],
    'envoy':          ['envoy'],
    'akamai':         ['akamai'],
    'fastly':         ['fastly'],
    # Cloud
    'aws':            ['aws', 'amazon', 'cloud'],
    'amazon':         ['aws', 'amazon', 'cloud'],
    'azure':          ['azure', 'microsoft', 'cloud'],
    'google cloud':   ['gcp', 'google', 'cloud'],
    'firebase':       ['firebase', 'google'],
    # DevOps / CI-CD
    'jenkins':        ['jenkins'],
    'gitlab':         ['gitlab'],
    'github':         ['github'],
    'bitbucket':      ['bitbucket', 'atlassian'],
    'bamboo':         ['bamboo', 'atlassian'],
    'teamcity':       ['teamcity'],
    'circleci':       ['circleci'],
    'argo':           ['argocd'],
    # Monitoring / Observability
    'grafana':        ['grafana'],
    'prometheus':     ['prometheus'],
    'kibana':         ['kibana', 'elastic'],
    'elasticsearch':  ['elasticsearch', 'elastic'],
    'logstash':       ['elastic'],
    'datadog':        ['datadog'],
    'zabbix':         ['zabbix'],
    'nagios':         ['nagios'],
    'splunk':         ['splunk'],
    'graylog':        ['graylog'],
    'sonarqube':      ['sonarqube'],
    # Databases
    'mysql':          ['mysql'],
    'postgresql':     ['postgresql', 'postgres'],
    'mongodb':        ['mongodb'],
    'redis':          ['redis'],
    'memcached':      ['memcached'],
    'couchdb':        ['couchdb'],
    'cassandra':      ['cassandra'],
    'mssql':          ['mssql', 'microsoft'],
    'oracle':         ['oracle'],
    'phpmyadmin':     ['phpmyadmin'],
    'adminer':        ['adminer'],
    # Collaboration / Project
    'confluence':     ['confluence', 'atlassian'],
    'jira':           ['jira', 'atlassian'],
    'sharepoint':     ['sharepoint', 'microsoft'],
    'mattermost':     ['mattermost'],
    'rocket.chat':    ['rocketchat'],
    'slack':          ['slack'],
    # Container / Orchestration
    'docker':         ['docker'],
    'kubernetes':     ['kubernetes', 'k8s'],
    'portainer':      ['portainer'],
    'rancher':        ['rancher'],
    # API
    'graphql':        ['graphql'],
    'swagger':        ['swagger', 'openapi'],
    # Network / Security appliances
    'fortinet':       ['fortinet', 'fortigate'],
    'fortigate':      ['fortinet', 'fortigate'],
    'palo alto':      ['paloalto'],
    'citrix':         ['citrix'],
    'f5':             ['f5', 'bigip'],
    'big-ip':         ['f5', 'bigip'],
    'sonicwall':      ['sonicwall'],
    'zyxel':          ['zyxel'],
    'mikrotik':       ['mikrotik'],
    'cisco':          ['cisco'],
    # Mail
    'zimbra':         ['zimbra'],
    'roundcube':      ['roundcube'],
    'exchange':       ['exchange', 'microsoft'],
    # CRM / ERP
    'sap':            ['sap'],
    'salesforce':     ['salesforce'],
    'odoo':           ['odoo'],
    # Other
    'coldfusion':     ['coldfusion', 'adobe'],
    'adobe':          ['adobe'],
    'vmware':         ['vmware'],
    'solarwinds':     ['solarwinds'],
    'minio':          ['minio'],
    'harbor':         ['harbor'],
    'nexus':          ['nexus', 'sonatype'],
    'artifactory':    ['artifactory', 'jfrog'],
    'keycloak':       ['keycloak'],
    'auth0':          ['auth0'],
    'okta':           ['okta'],
    'hashicorp':      ['hashicorp', 'vault'],
    'vault':          ['hashicorp', 'vault'],
    'consul':         ['consul', 'hashicorp'],
    'terraform':      ['terraform'],
    'ansible':        ['ansible'],
    'puppet':         ['puppet'],
}

tags = set()
techs_found = []

# ── Source 1: Nuclei tech-detection output ──
nuclei_tech_file = os.environ.get('NUCLEI_TECHDETECT', '')
if nuclei_tech_file and os.path.isfile(nuclei_tech_file):
    with open(nuclei_tech_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            # Nuclei tech-detect template IDs are like "tech-wordpress", "tech-nginx"
            tmpl_id = (obj.get('template-id') or obj.get('templateID') or '').lower()
            tmpl_name = (obj.get('info', {}).get('name') or '').lower()
            matched = obj.get('matched-at', '')
            for keyword in tmpl_id.replace('-', ' ').replace('_', ' ').split():
                if keyword in ('tech', 'detect', 'http', 'https'):
                    continue
                for key, tag_list in TECH_TO_TAGS.items():
                    if keyword in key or key in keyword:
                        tags.update(tag_list)
                        techs_found.append(keyword)
            for key, tag_list in TECH_TO_TAGS.items():
                if key in tmpl_name or key in tmpl_id:
                    tags.update(tag_list)
                    techs_found.append(key)

# ── Source 2: httpx tech-detect JSON ──
httpx_file = os.environ.get('HTTPX_FILE', '')
if httpx_file and os.path.isfile(httpx_file):
    with open(httpx_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            tech_list = obj.get('tech') or obj.get('technologies') or []
            if isinstance(tech_list, str):
                tech_list = [tech_list]
            webserver = obj.get('webserver') or ''
            if webserver:
                tech_list.append(webserver)
            for t in tech_list:
                tl = t.lower().strip()
                for key, tag_list in TECH_TO_TAGS.items():
                    if key in tl or tl in key:
                        tags.update(tag_list)
                        techs_found.append(tl)

# ── Source 3: Phase 1 summary (fallback) ──
summary_file = os.environ.get('PHASE1_SUMMARY', '')
if summary_file and os.path.isfile(summary_file):
    try:
        with open(summary_file) as f:
            summary = json.load(f)
        for entry in summary.get('httpx_details', []):
            tech_val = entry.get('tech') or entry.get('technologies') or []
            if isinstance(tech_val, str):
                tech_val = [tech_val]
            ws = entry.get('webserver') or ''
            if ws:
                tech_val.append(ws)
            for t in tech_val:
                tl = t.lower().strip()
                for key, tag_list in TECH_TO_TAGS.items():
                    if key in tl or tl in key:
                        tags.update(tag_list)
                        techs_found.append(tl)
    except Exception:
        pass

if tags:
    print(','.join(sorted(tags)))
    print('|'.join(sorted(set(techs_found))))
else:
    print('')
    print('')
PYEOF
    )

    TECH_TAGS=$(echo "$_PY_OUT" | head -1)
    TECH_NAMES=$(echo "$_PY_OUT" | sed -n '2p' | tr '|' ', ')

    # ==========================================================================
    # STEP 3: Run targeted Nuclei scans based on detected technologies
    # ==========================================================================

    if [ -n "$TECH_TAGS" ]; then
        log_info "Detected technologies: $TECH_NAMES"
        log_info "Mapped Nuclei tags: $TECH_TAGS"

        # Save detected tech for reference
        echo "$TECH_TAGS" | tr ',' '\n' | sort -u > "$NUCLEI_DIR/detected_tech_tags.txt"
        echo "$TECH_NAMES" > "$NUCLEI_DIR/detected_technologies.txt"
        log_info "Tech tags saved to $NUCLEI_DIR/detected_tech_tags.txt"

        # ── Run 1: Tech-targeted CVE + vulnerability scan ──
        log_info "Nuclei RUN 1: tech-targeted vulnerability scan (tags: $TECH_TAGS)..."
        cat "$PHASE_DIR/scan_urls.txt" | \
            nuclei -silent -jsonl \
            -severity critical,high,medium,low \
            -tags "$TECH_TAGS" \
            -rate-limit "$NUCLEI_RATE_HIGH" \
            -o "$NUCLEI_DIR/nuclei_tech_vulns.json" 2>/dev/null || true

        NUCLEI_TECH_COUNT=$(wc -l < "$NUCLEI_DIR/nuclei_tech_vulns.json" 2>/dev/null | tr -d ' ')
        [ -z "$NUCLEI_TECH_COUNT" ] && NUCLEI_TECH_COUNT=0
        log_info "Nuclei tech-targeted vuln findings: $NUCLEI_TECH_COUNT"

        # ── Run 2: General CVE + misconfiguration scan ──
        log_info "Nuclei RUN 2: general CVE + misconfiguration scan..."
        cat "$PHASE_DIR/scan_urls.txt" | \
            nuclei -silent -jsonl \
            -severity critical,high,medium,low,info \
            -tags cve,misconfiguration,config,exposure,default-login \
            -rate-limit "$NUCLEI_RATE_HIGH" \
            -o "$NUCLEI_DIR/nuclei_general.json" 2>/dev/null || true

        # ── Merge: tech-detect + tech-vulns + general → nuclei_all.json ──
        # Use Python to deduplicate NDJSON (sort -u can break on field order)
        python3 -c "
import json, sys
seen = set()
results = []
for fname in sys.argv[1:]:
    try:
        with open(fname) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    obj = json.loads(line)
                    key = (obj.get('template-id',''), obj.get('matched-at',''), obj.get('host',''))
                    if key not in seen:
                        seen.add(key)
                        results.append(line)
                except: pass
    except FileNotFoundError: pass
with open('$NUCLEI_DIR/nuclei_all.json', 'w') as f:
    f.write('\n'.join(results) + '\n' if results else '')
" "$NUCLEI_DIR/nuclei_techdetect.json" "$NUCLEI_DIR/nuclei_tech_vulns.json" "$NUCLEI_DIR/nuclei_general.json" \
        2>/dev/null || {
            # Fallback: simple cat + dedup
            cat "$NUCLEI_DIR/nuclei_techdetect.json" "$NUCLEI_DIR/nuclei_tech_vulns.json" "$NUCLEI_DIR/nuclei_general.json" 2>/dev/null | \
                awk '!seen[$0]++' > "$NUCLEI_DIR/nuclei_all.json" || touch "$NUCLEI_DIR/nuclei_all.json"
        }
    else
        log_info "No specific tech-stack detected — running Nuclei with broad coverage..."

        # Fallback: full severity scan with common tags
        log_info "Nuclei: broad scan (all severities + cve + misconfiguration + exposure)..."
        cat "$PHASE_DIR/scan_urls.txt" | \
            nuclei -silent -jsonl \
            -severity critical,high,medium,low,info \
            -tags cve,misconfiguration,config,exposure,default-login \
            -rate-limit "$NUCLEI_RATE_HIGH" \
            -o "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null || true

        # If nothing found with -tags, retry without filter
        if [ ! -s "$NUCLEI_DIR/nuclei_all.json" ]; then
            log_info "Nuclei: retrying without -tags filter..."
            cat "$PHASE_DIR/scan_urls.txt" | \
                nuclei -silent -jsonl \
                -severity critical,high,medium,low,info \
                -rate-limit "$NUCLEI_RATE_HIGH" \
                -o "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null || log_warn "Nuclei scan failed"
        fi

        # Prepend tech-detect results if any
        if [ -s "$NUCLEI_DIR/nuclei_techdetect.json" ]; then
            cat "$NUCLEI_DIR/nuclei_techdetect.json" >> "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null || true
        fi
    fi

    NUCLEI_COUNT=$(wc -l < "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null | tr -d ' ')
    [ -z "$NUCLEI_COUNT" ] || [ "$NUCLEI_COUNT" = "0" ] && NUCLEI_COUNT=0
    log_info "Nuclei findings: $NUCLEI_COUNT"
else
    log_warn "Nuclei not found or no scan URLs"
fi

################################################################################
# PHASE 4B: XSS SCANNING - DALFOX
################################################################################

log_info "=== XSS SCANNING ==="

XSS_DIR="$PHASE_DIR/xss"
mkdir -p "$XSS_DIR"

# Dalfox
if command -v dalfox &> /dev/null; then
    log_info "Running Dalfox for XSS detection..."

    # Resolve URL source for XSS testing with multi-path fallback
    _xss_url_src=""
    for _xss_cand in \
        "$PHASE3_DIR/urls/all_urls.txt" \
        "$PHASE3_DIR/all_urls.txt" \
        "$OUTPUT_DIR/phase3_content/urls/all_urls.txt" \
        "$PHASE_DIR/scan_urls.txt"; do
        if [ -s "$_xss_cand" ]; then
            _xss_url_src="$_xss_cand"
            break
        fi
    done

    if [ -n "$_xss_url_src" ]; then
        log_info "XSS: using URL source: $_xss_url_src"
        # Prefer parameterized URLs; fall back to all URLs (dalfox can crawl and inject)
        safe_grep -E '\?.*=' "$_xss_url_src" | head -n 100 > "$XSS_DIR/param_urls.txt"
        if [ ! -s "$XSS_DIR/param_urls.txt" ]; then
            head -n 50 "$_xss_url_src" > "$XSS_DIR/param_urls.txt"
        fi

        if [ -s "$XSS_DIR/param_urls.txt" ]; then
            log_info "Testing $(wc -l < "$XSS_DIR/param_urls.txt" | tr -d ' ') URLs for XSS..."

            cat "$XSS_DIR/param_urls.txt" | \
                dalfox pipe --silence --output "$XSS_DIR/dalfox_results.txt" 2>/dev/null || log_warn "Dalfox scan failed"

            DALFOX_COUNT=$(grep -c "VULN\|POC" "$XSS_DIR/dalfox_results.txt" 2>/dev/null || echo "0")
            log_info "Dalfox XSS vulnerabilities: $DALFOX_COUNT"
        else
            log_info "No URLs found for XSS testing"
        fi
    else
        log_warn "No URLs from Phase 3 available for XSS testing (run Phase 3 first)"
        touch "$XSS_DIR/param_urls.txt"
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
# PHASE 4C: SQL INJECTION - SQLMAP
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

        mkdir -p "$SQLI_DIR/results"
        export SQLI_DIR SQLMAP_THREADS
        run_parallel_from_file "$SQLI_DIR/sqlmap_targets.txt" "$THREADS" '
            url="$1"
            log_info "SQLMap: $url"
            out_file="$SQLI_DIR/results/sqlmap_${url//[^a-zA-Z0-9]/_}.txt"
            sqlmap -u "$url" --batch --random-agent --level=1 --risk=1 \
                --output-dir="$SQLI_DIR" --flush-session --threads="$SQLMAP_THREADS" \
                > "$out_file" 2>&1 || true
        '

        cat "$SQLI_DIR"/results/sqlmap_*.txt 2>/dev/null > "$SQLI_DIR/sqlmap_results.txt" || touch "$SQLI_DIR/sqlmap_results.txt"

        SQLI_COUNT=$(grep -c "vulnerable" "$SQLI_DIR/sqlmap_results.txt" 2>/dev/null || echo "0")
        log_info "SQLMap vulnerabilities: $SQLI_COUNT"
    else
        log_info "No parameterized URLs for SQL injection testing"
    fi
else
    log_warn "SQLMap not found"
fi

################################################################################
# PHASE 4D: CORS MISCONFIGURATION - CORSY
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
# PHASE 4E: ADDITIONAL VULNERABILITY SCANNERS
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
    # Always pre-create the output file so it's valid JSON even if no WP sites found
    echo '[]' > "$MISC_DIR/wpscan_all.json"

    grep -i "wp-content\|wp-includes\|wp-admin" "$PHASE3_DIR/urls/all_urls.txt" 2>/dev/null | \
        sed -E 's|(https?://[^/]+).*|\1|' | sort -u | head -n 5 > "$MISC_DIR/wordpress_sites.txt" || touch "$MISC_DIR/wordpress_sites.txt"

    if [ -s "$MISC_DIR/wordpress_sites.txt" ]; then
        log_info "Found WordPress sites, running WPScan..."

        export MISC_DIR
        run_parallel_from_file "$MISC_DIR/wordpress_sites.txt" "$THREADS" '
            wp_url="$1"
            log_info "WPScan: $wp_url"
            echo "[]" > "$MISC_DIR/wpscan_${wp_url//[^a-zA-Z0-9]/_}.json"
            wpscan --url "$wp_url" --random-agent --format json \
                --output "$MISC_DIR/wpscan_${wp_url//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
        '

        # Merge: use Python for valid JSON concat instead of raw cat
        python3 -c "
import json, glob, sys
results = []
for f in sorted(glob.glob('$MISC_DIR/wpscan_*.json')):
    try:
        with open(f) as fh:
            d = json.load(fh)
            if isinstance(d, list): results.extend(d)
            elif d: results.append(d)
    except Exception: pass
with open('$MISC_DIR/wpscan_all.json', 'w') as out:
    json.dump(results, out)
" 2>/dev/null || echo '[]' > "$MISC_DIR/wpscan_all.json"
    else
        log_info "No WordPress sites detected; wpscan_all.json initialized as empty array"
    fi
else
    log_warn "WPScan not found"
    echo '[]' > "$MISC_DIR/wpscan_all.json"
fi

# Wapiti (Web application vulnerability scanner)
if command -v wapiti &> /dev/null; then
    log_info "Running Wapiti..."

    # Detect the correct output-format flag: wapiti3 uses --format, older uses -f
    _WAPITI_FMT="--format"
    wapiti --help 2>&1 | grep -q -- '-f ' && ! wapiti --help 2>&1 | grep -q -- '--format' && _WAPITI_FMT="-f"
    export _WAPITI_FMT MISC_DIR

    head -n 5 "$PHASE_DIR/scan_urls.txt" | awk 'NF' > "$MISC_DIR/wapiti_targets.txt"

    run_parallel_from_file "$MISC_DIR/wapiti_targets.txt" "$THREADS" '
        url="$1"
        log_info "Wapiti: $url"
        outf="$MISC_DIR/wapiti_${url//[^a-zA-Z0-9]/_}.json"
        echo "{}" > "$outf"
        wapiti -u "$url" "$_WAPITI_FMT" json --flush-attacks --max-scan-time 120 \
            -o "$outf" 2>/dev/null || true
    '

    # Merge individual wapiti JSON reports into a combined array
    python3 -c "
import json, glob, sys
results = []
for f in sorted(glob.glob('$MISC_DIR/wapiti_*.json')):
    try:
        with open(f) as fh:
            d = json.load(fh)
            if isinstance(d, list): results.extend(d)
            elif d: results.append(d)
    except Exception: pass
with open('$MISC_DIR/wapiti_all.json', 'w') as out:
    json.dump(results, out)
" 2>/dev/null || echo '[]' > "$MISC_DIR/wapiti_all.json"
else
    log_warn "Wapiti not found"
    echo '[]' > "$MISC_DIR/wapiti_all.json"
fi

# Skipfish (web application security scanner)
if command -v skipfish &> /dev/null; then
    log_info "Running Skipfish..."

    SKIPFISH_DIR="$PHASE_DIR/skipfish"
    mkdir -p "$SKIPFISH_DIR"

    SKIPFISH_DICT=""
    if [ -f "/usr/share/skipfish/dictionaries/minimal.wl" ]; then
        SKIPFISH_DICT="/usr/share/skipfish/dictionaries/minimal.wl"
    elif [ -f "/usr/share/skipfish/dictionaries/complete.wl" ]; then
        SKIPFISH_DICT="/usr/share/skipfish/dictionaries/complete.wl"
    fi

    # Skipfish performance tuning (faster defaults)
    SKIPFISH_TIME="${TECHNIEUM_SKIPFISH_TIME:-1:00:00}"
    SKIPFISH_RPS="${TECHNIEUM_SKIPFISH_RPS:-50}"
    SKIPFISH_MAX_HOSTS="${TECHNIEUM_SKIPFISH_MAX_HOSTS:-3}"
    SKIPFISH_CONN_GLOBAL="${TECHNIEUM_SKIPFISH_CONN_GLOBAL:-40}"
    SKIPFISH_CONN_PERIP="${TECHNIEUM_SKIPFISH_CONN_PERIP:-12}"
    SKIPFISH_REQ_TIMEOUT="${TECHNIEUM_SKIPFISH_REQ_TIMEOUT:-10}"
    SKIPFISH_DEPTH="${TECHNIEUM_SKIPFISH_DEPTH:-4}"
    SKIPFISH_CHILDREN="${TECHNIEUM_SKIPFISH_CHILDREN:-20}"
    SKIPFISH_MAX_REQUESTS="${TECHNIEUM_SKIPFISH_MAX_REQUESTS:-5000}"
    SKIPFISH_MAX_DESC="${TECHNIEUM_SKIPFISH_MAX_DESC:-1000}"
    SKIPFISH_PARTIAL="${TECHNIEUM_SKIPFISH_PARTIAL:-90}"
    SKIPFISH_RESP_SIZE="${TECHNIEUM_SKIPFISH_RESP_SIZE:-262144}"

    if [ -z "$SKIPFISH_DICT" ]; then
        log_warn "Skipfish dictionary not found; skipping Skipfish"
    else
        head -n "$SKIPFISH_MAX_HOSTS" "$ALIVE_HOSTS" | sed -E 's|^https?://||' | sed 's|/.*||' | awk 'NF' > "$SKIPFISH_DIR/skipfish_targets.txt"

        if [ ! -s "$SKIPFISH_DIR/skipfish_targets.txt" ]; then
            log_warn "Skipfish: no valid targets available, skipping"
        else

            while IFS= read -r host; do
                host="$(echo "$host" | xargs)"
                [ -z "$host" ] && continue
                log_info "Skipfish: $host"
                out_dir="$SKIPFISH_DIR/skipfish_${host//[^a-zA-Z0-9]/_}"
                run_with_timeout "$TIMEOUT_DEFAULT" "skipfish \
                    -l $SKIPFISH_RPS \
                    -k $SKIPFISH_TIME \
                    -g $SKIPFISH_CONN_GLOBAL \
                    -m $SKIPFISH_CONN_PERIP \
                    -t $SKIPFISH_REQ_TIMEOUT \
                    -s $SKIPFISH_RESP_SIZE \
                    -e \
                    -d $SKIPFISH_DEPTH \
                    -c $SKIPFISH_CHILDREN \
                    -r $SKIPFISH_MAX_REQUESTS \
                    -x $SKIPFISH_MAX_DESC \
                    -p $SKIPFISH_PARTIAL \
                    -S '$SKIPFISH_DICT' -o '$out_dir' 'https://$host/'" || log_warn "Skipfish failed for $host"
            done < "$SKIPFISH_DIR/skipfish_targets.txt"
        fi
    fi
else
    log_warn "Skipfish not found"
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
        outf="$MISC_DIR/retirejs_${js_url//[^a-zA-Z0-9]/_}.json"
        # Pre-initialize to [] so file is always valid JSON even when retire finds nothing
        echo "[]" > "$outf"
        retire --jspath "$js_url" --outputformat json > "$outf" 2>/dev/null || true
        # If retire produced empty output (no vuln), restore the [] placeholder
        [ ! -s "$outf" ] && echo "[]" > "$outf"
    '

    # Merge all per-file reports into one valid JSON structure
    python3 -c "
import json, glob, sys
results = []
for f in sorted(glob.glob('$MISC_DIR/retirejs_*.json')):
    try:
        with open(f) as fh:
            d = json.load(fh)
            if isinstance(d, list): results.extend(d)
            elif d: results.append(d)
    except Exception: pass
with open('$MISC_DIR/retirejs_results.json', 'w') as out:
    json.dump({'findings': results, 'total': len(results)}, out, indent=2)
" 2>/dev/null || echo '{"findings":[],"total":0}' > "$MISC_DIR/retirejs_results.json"
else
    log_warn "Retire.js not found"
    echo '{"findings":[],"total":0}' > "$MISC_DIR/retirejs_results.json"
fi



# ── Gitleaks + TruffleHog web content secret scanning (Phase 4 level) ──────
# Complements Phase 3 secret scanning with vuln-phase depth
SECRETS_VULN_DIR="$PHASE_DIR/secrets"
mkdir -p "$SECRETS_VULN_DIR"

# Scan Phase 3 secret results if not already done
_phase3_secrets="$PHASE3_DIR/urls/secrets"
if [ -d "$_phase3_secrets" ]; then
    # Copy phase3 secret scan results to phase4 for consolidated reporting
    for _sf in gitleaks_web.json trufflehog_web.json; do
        [ -f "$_phase3_secrets/$_sf" ] && cp -f "$_phase3_secrets/$_sf" "$SECRETS_VULN_DIR/" 2>/dev/null || true
    done
    log_info "Phase 3 secret scan results imported to Phase 4"
else
    log_info "No Phase 3 secret scan results found — running standalone secret scan"

    # Run gitleaks on any downloaded content from Phase 3
    _download_dir="$PHASE3_DIR/urls/secrets/downloaded_js"
    [ ! -d "$_download_dir" ] && _download_dir="$PHASE3_DIR/urls/cariddi"

    if command -v gitleaks &>/dev/null && [ -d "$_download_dir" ]; then
        _GL_VER=$(gitleaks version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo '8.0')
        _GL_MAJOR=$(echo "$_GL_VER" | cut -d. -f1)
        if [ "$_GL_MAJOR" -ge 8 ] 2>/dev/null; then
            run_with_timeout 600 "gitleaks detect --no-git --source '$_download_dir' --report-format json --report-path '$SECRETS_VULN_DIR/gitleaks_web.json'" \
                2>/dev/null || true
        fi
    fi

    if command -v trufflehog &>/dev/null && [ -d "$_download_dir" ]; then
        if trufflehog --help 2>&1 | grep -q 'filesystem'; then
            run_with_timeout 600 "trufflehog filesystem '$_download_dir' --json --only-verified > '$SECRETS_VULN_DIR/trufflehog_web.json'" \
                2>/dev/null || true
        fi
    fi
fi

################################################################################
# PHASE 4F: SSL/TLS SCANNING
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
# PHASE 4G: GOWITNESS — WEB SCREENSHOTS & VISUAL RECON
################################################################################

log_info "=== GOWITNESS SCREENSHOT CAPTURE ==="

GOWITNESS_DIR="$PHASE_DIR/gowitness"
mkdir -p "$GOWITNESS_DIR/screenshots"

if command -v gowitness &>/dev/null; then
    # ── Build comprehensive URL list for screenshots (ALL discovered live URLs) ──
    GOWITNESS_URLS="$GOWITNESS_DIR/gowitness_urls.txt"
    : > "$GOWITNESS_URLS"
    for _gw_src in \
        "$PHASE1_DIR/alive_urls.txt" \
        "$PHASE_DIR/scan_urls.txt" \
        "$PHASE3_DIR/urls/all_urls.txt"; do
        [ -s "$_gw_src" ] && cat "$_gw_src" >> "$GOWITNESS_URLS" 2>/dev/null || true
    done
    # Ensure every line has a scheme; deduplicate
    sed -i '/^$/d' "$GOWITNESS_URLS" 2>/dev/null || true
    sort -u "$GOWITNESS_URLS" -o "$GOWITNESS_URLS" 2>/dev/null || true
    GW_URL_COUNT=$(wc -l < "$GOWITNESS_URLS" 2>/dev/null | tr -d ' ')

    if [ "$GW_URL_COUNT" -gt 0 ]; then
        log_info "Running GoWitness to capture screenshots of $GW_URL_COUNT URLs..."

        # ── Detect GoWitness version (v2 vs v3 have different CLI) ──────────
        _GW_VER="v2"
        _gw_help=$(gowitness --help 2>&1 || true)
        # v3 exposes "file" as a top-level subcommand; v2 nests it under "scan"
        if echo "$_gw_help" | grep -qE '^\s+file\s'; then
            _GW_VER="v3"
        fi
        log_info "Detected GoWitness $_GW_VER CLI"

        if [ "$_GW_VER" = "v3" ]; then
            # GoWitness v3 syntax: gowitness file -f <file>
            #   --db-location replaces --db-path; --write-db defaults to true
            gowitness file \
                -f "$GOWITNESS_URLS" \
                --screenshot-path "$GOWITNESS_DIR/screenshots" \
                --threads "$THREADS" \
                --timeout 15 \
                --db-location "sqlite://$GOWITNESS_DIR/gowitness.sqlite3" \
                2>/dev/null || log_warn "GoWitness v3 scan encountered errors"
        else
            # GoWitness v2 syntax: gowitness scan file -f <file>
            gowitness scan file \
                -f "$GOWITNESS_URLS" \
                --screenshot-path "$GOWITNESS_DIR/screenshots" \
                --threads "$THREADS" \
                --timeout 15 \
                --write-db \
                --db-path "$GOWITNESS_DIR/gowitness.sqlite3" \
                2>/dev/null || log_warn "GoWitness v2 scan encountered errors"
        fi

        # Count captured screenshots
        SCREENSHOT_COUNT=$(find "$GOWITNESS_DIR/screenshots" -name '*.png' 2>/dev/null | wc -l | tr -d ' ')
        log_info "GoWitness captured $SCREENSHOT_COUNT screenshots"

        # ── Generate report / summary ──────────────────────────────────────
        if [ "$SCREENSHOT_COUNT" -gt 0 ]; then
            if [ "$_GW_VER" = "v2" ]; then
                # v2: static HTML report
                gowitness report generate \
                    --db-path "$GOWITNESS_DIR/gowitness.sqlite3" \
                    --screenshot-path "$GOWITNESS_DIR/screenshots" \
                    -n "$GOWITNESS_DIR/gowitness_report.html" \
                    2>/dev/null || log_warn "GoWitness HTML report generation failed"
                log_info "GoWitness HTML report saved to $GOWITNESS_DIR/gowitness_report.html"
            else
                # v3: no static HTML export; note interactive report availability
                log_info "GoWitness v3: view interactive report with: gowitness report serve --db-location sqlite://$GOWITNESS_DIR/gowitness.sqlite3"
            fi

            # Generate JSON summary for downstream consumption (works with both versions)
            python3 -c "
import json, os, glob

screenshots = sorted(glob.glob(os.path.join('$GOWITNESS_DIR', 'screenshots', '*.png')))
results = []
for ss in screenshots:
    fname = os.path.basename(ss)
    results.append({'screenshot': ss, 'filename': fname})

with open(os.path.join('$GOWITNESS_DIR', 'gowitness_summary.json'), 'w') as f:
    json.dump({
        'total_screenshots': len(results),
        'screenshot_dir': '$GOWITNESS_DIR/screenshots',
        'screenshots': results
    }, f, indent=2)
print(f'GoWitness summary: {len(results)} screenshots')
" 2>/dev/null || log_warn "GoWitness JSON summary generation failed"
        fi
    else
        log_warn "No URLs available for GoWitness screenshots"
    fi
else
    log_warn "GoWitness not found — install via: go install github.com/sensepost/gowitness@latest"
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
echo "  - Dalfox (XSS): ${DALFOX_COUNT:-0}"
echo "  - SQLMap (SQLi): ${SQLI_COUNT:-0}"
echo "  - Corsy (CORS): ${CORS_COUNT:-0}"
echo "  - GoWitness screenshots: ${SCREENSHOT_COUNT:-0} (from ${GW_URL_COUNT:-0} URLs)"
echo "  - Secrets (gitleaks+trufflehog): see $PHASE_DIR/secrets/"
echo ""
echo "Output directories:"
echo "  - $NUCLEI_DIR: Nuclei results"
echo "  - $XSS_DIR: XSS vulnerability results"
echo "  - $SQLI_DIR: SQL injection results"
echo "  - $CORS_DIR: CORS misconfiguration results"
echo "  - $MISC_DIR: Additional scanner results (Nikto, WPScan, Skipfish, Retire.js)"
echo "  - $SSL_DIR: SSL/TLS security results"
echo "  - $PHASE_DIR/secrets: Secret scanning results (gitleaks + trufflehog)"
echo "  - $GOWITNESS_DIR: GoWitness screenshot results"

# Count critical findings (nuclei writes NDJSON; use -s to slurp)
CRITICAL_COUNT=0
if [ -f "$NUCLEI_DIR/nuclei_all.json" ]; then
    CRITICAL_COUNT=$(jq -s '[.[] | select(.info.severity == "critical")] | length' "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null || echo "0")
fi

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    log_error "WARNING: Found $CRITICAL_COUNT CRITICAL vulnerabilities!"
fi

# ── Generate vulnerabilities_summary.json for downstream phases (07, 09) ──
log_info "Generating vulnerabilities_summary.json..."
python3 - <<PYEOF 2>/dev/null || true
import json, os, glob

vulns = []

# Parse Nuclei NDJSON
nuclei_file = '$NUCLEI_DIR/nuclei_all.json'
if os.path.exists(nuclei_file):
    with open(nuclei_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                vulns.append({
                    'id': obj.get('template-id', obj.get('templateID', '')),
                    'name': obj.get('info', {}).get('name', ''),
                    'severity': obj.get('info', {}).get('severity', 'unknown'),
                    'host': obj.get('host', obj.get('matched-at', '')),
                    'target': obj.get('matched-at', ''),
                    'cvss_score': float(obj.get('info', {}).get('classification', {}).get('cvss-score', 0) or 0),
                    'cve_id': ','.join(obj.get('info', {}).get('classification', {}).get('cve-id', []) or []),
                    'tool': 'nuclei',
                    'description': obj.get('info', {}).get('description', ''),
                })
            except Exception:
                pass

# Parse Gitleaks web findings
for gl_file in ['$PHASE_DIR/secrets/gitleaks_web.json', '$PHASE3_DIR/urls/secrets/gitleaks_web.json']:
    if os.path.isfile(gl_file):
        try:
            data = json.load(open(gl_file))
            for item in data if isinstance(data, list) else []:
                vulns.append({
                    'id': 'gitleaks-' + (item.get('RuleID', item.get('rule', 'secret')) or 'secret'),
                    'name': f"Secret Leak: {item.get('RuleID', item.get('rule', 'unknown'))}",
                    'severity': 'high',
                    'host': item.get('File', item.get('file', '')),
                    'tool': 'gitleaks',
                    'description': (item.get('Match', item.get('offender', '')) or '')[:200],
                })
        except Exception:
            pass
        break

# Parse TruffleHog web findings
for th_file in ['$PHASE_DIR/secrets/trufflehog_web.json', '$PHASE3_DIR/urls/secrets/trufflehog_web.json']:
    if os.path.isfile(th_file):
        try:
            with open(th_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    vulns.append({
                        'id': 'trufflehog-' + (obj.get('DetectorName', obj.get('detectorName', 'secret')) or 'secret'),
                        'name': f"Verified Secret: {obj.get('DetectorName', obj.get('detectorName', 'unknown'))}",
                        'severity': 'critical',
                        'host': '$TARGET',
                        'tool': 'trufflehog',
                        'description': (obj.get('Raw', obj.get('raw', '')) or '')[:200],
                    })
        except Exception:
            pass
        break

# Parse Dalfox results
dalfox_file = '$XSS_DIR/dalfox_results.txt'
if os.path.exists(dalfox_file):
    with open(dalfox_file) as f:
        for line in f:
            if 'VULN' in line or 'POC' in line:
                vulns.append({
                    'id': 'dalfox-xss',
                    'name': 'XSS Vulnerability (Dalfox)',
                    'severity': 'high',
                    'host': line.strip()[:200],
                    'tool': 'dalfox',
                })

# Parse SQLMap results
sqli_file = '$SQLI_DIR/sqlmap_results.txt'
if os.path.exists(sqli_file):
    with open(sqli_file) as f:
        content = f.read()
    if 'vulnerable' in content.lower():
        vulns.append({
            'id': 'sqlmap-sqli',
            'name': 'SQL Injection (SQLMap)',
            'severity': 'critical',
            'host': '$TARGET',
            'tool': 'sqlmap',
        })

with open('$PHASE_DIR/vulnerabilities_summary.json', 'w') as f:
    json.dump(vulns, f, indent=2)
print(f"Generated vulnerabilities_summary.json: {len(vulns)} findings")
PYEOF

# Create phase completion marker
touch "$PHASE_DIR/.completed"
log_info "Phase 4 complete: success=$TOOLS_SUCCESS failed=$TOOLS_FAILED skipped=$TOOLS_SKIPPED"

exit 0
