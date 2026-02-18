#!/bin/bash
################################################################################
# ReconX - Phase 3: Deep Web & Content Discovery
# Crawling, Archives, Directory Bruting, JS Analysis, Pastebin
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

PHASE_DIR="$OUTPUT_DIR/phase3_content"
PHASE1_DIR="$OUTPUT_DIR/phase1_discovery"
mkdir -p "$PHASE_DIR"

# Tunables (increase threads for speed; timeouts handled by phase)
GAU_THREADS="${RECONX_GAU_THREADS:-10}"
GOSPIDER_THREADS="${RECONX_GOSPIDER_THREADS:-20}"
GOSPIDER_CONCURRENCY="${RECONX_GOSPIDER_CONCURRENCY:-20}"
KATANA_CONCURRENCY="${RECONX_KATANA_CONCURRENCY:-30}"
FFUF_THREADS="${RECONX_FFUF_THREADS:-80}"
FFUF_TIMEOUT="${RECONX_FFUF_TIMEOUT:-15}"
FEROX_THREADS="${RECONX_FEROX_THREADS:-80}"
DIRSEARCH_THREADS="${RECONX_DIRSEARCH_THREADS:-80}"

echo "[*] Phase 3: Deep Web & Content Discovery for $TARGET"
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

# Check if alive hosts exist from Phase 1
if [ ! -f "$PHASE1_DIR/alive_hosts.txt" ]; then
    log_warn "Phase 1 alive_hosts.txt not found; creating empty file and continuing with limited data"
    mkdir -p "$PHASE1_DIR"
    touch "$PHASE1_DIR/alive_hosts.txt"
fi
ALIVE_HOSTS="$PHASE1_DIR/alive_hosts.txt"
ALIVE_COUNT=$(wc -l < "$ALIVE_HOSTS" | tr -d ' ')
log_info "Found $ALIVE_COUNT alive hosts from Phase 1"

################################################################################
# PHASE 3A: URL DISCOVERY FROM ARCHIVES
################################################################################

log_info "=== ARCHIVE & URL DISCOVERY ==="

URLS_DIR="$PHASE_DIR/urls"
mkdir -p "$URLS_DIR"

# Create combined target list (both domain and subdomains)
cat "$PHASE1_DIR/all_subdomains.txt" 2>/dev/null > "$URLS_DIR/targets.txt"
echo "$TARGET" >> "$URLS_DIR/targets.txt"
sort -u "$URLS_DIR/targets.txt" -o "$URLS_DIR/targets.txt"

# Launch archive crawlers in parallel
pids=()
SPIDEYX_AVAILABLE=0
HAKRAWLER_AVAILABLE=0
KATANA_AVAILABLE=0

# 1. GAU (GetAllUrls)
if command -v gau &> /dev/null; then
    log_info "Launching GAU (GetAllUrls)..."
    (
        cat "$URLS_DIR/targets.txt" | gau --threads "$GAU_THREADS" --blacklist png,jpg,gif,jpeg,svg,css,woff,woff2,ttf,eot \
            > "$URLS_DIR/gau.txt" 2>/dev/null || log_warn "GAU failed"
    ) &
    pids+=($!)
else
    log_warn "GAU not found"
    touch "$URLS_DIR/gau.txt"
fi

# 2. Waybackurls
if command -v waybackurls &> /dev/null; then
    log_info "Launching waybackurls..."
    (
        cat "$URLS_DIR/targets.txt" | waybackurls > "$URLS_DIR/waybackurls.txt" 2>/dev/null || log_warn "waybackurls failed"
    ) &
    pids+=($!)
else
    log_warn "waybackurls not found"
    touch "$URLS_DIR/waybackurls.txt"
fi

# 3. SpideyX (Revolt suite)
if command -v spideyx &> /dev/null; then
    SPIDEYX_AVAILABLE=1
    log_info "Launching SpideyX crawler..."
    (
        SPIDEYX_CMD=""
        if spideyx crawler -h 2>&1 | grep -qi "usage"; then
            SPIDEYX_CMD="crawler"
        elif spideyx crawl -h 2>&1 | grep -qi "usage"; then
            SPIDEYX_CMD="crawl"
        fi

        if [ -z "$SPIDEYX_CMD" ]; then
            log_warn "SpideyX crawler mode not available"
            touch "$URLS_DIR/spideyx.txt"
            exit 0
        fi

        SPIDEYX_TARGETS="$URLS_DIR/spideyx_targets.txt"
        cat "$ALIVE_HOSTS" | sed 's|^|https://|' > "$SPIDEYX_TARGETS"

        if cat "$SPIDEYX_TARGETS" | spideyx "$SPIDEYX_CMD" 2>/dev/null > "$URLS_DIR/spideyx_raw.txt"; then
            safe_grep -oP 'https?://[^\s]+' "$URLS_DIR/spideyx_raw.txt" | sort -u > "$URLS_DIR/spideyx.txt"
        else
            touch "$URLS_DIR/spideyx.txt"
        fi
    ) &
    pids+=($!)
else
    log_warn "SpideyX not found"
    touch "$URLS_DIR/spideyx.txt"
fi

# 4. Gospider (fallback crawler)
if command -v gospider &> /dev/null; then
    log_info "Launching gospider..."
    (
        while IFS= read -r host; do
            url="https://$host"
            gospider -s "$url" -d 3 -c "$GOSPIDER_CONCURRENCY" -t "$GOSPIDER_THREADS" --sitemap --robots \
                >> "$URLS_DIR/gospider_raw.txt" 2>/dev/null || true
        done < "$ALIVE_HOSTS"

        # Parse gospider output
        safe_grep -oP 'https?://[^\s]+' "$URLS_DIR/gospider_raw.txt" | sort -u > "$URLS_DIR/gospider.txt"
    ) &
    pids+=($!)
else
    log_warn "gospider not found"
    touch "$URLS_DIR/gospider.txt"
fi

# 5. Hakrawler
if command -v hakrawler &> /dev/null; then
    HAKRAWLER_AVAILABLE=1
    log_info "Launching hakrawler..."
    (
        cat "$ALIVE_HOSTS" | sed 's|^|https://|' | hakrawler -depth 3 -plain \
            > "$URLS_DIR/hakrawler.txt" 2>/dev/null || log_warn "hakrawler failed"
    ) &
    pids+=($!)
else
    log_warn "hakrawler not found"
    touch "$URLS_DIR/hakrawler.txt"
fi

# 6. Katana (ProjectDiscovery)
if command -v katana &> /dev/null; then
    KATANA_AVAILABLE=1
    log_info "Launching Katana..."
    (
        cat "$ALIVE_HOSTS" | katana -d 5 -c "$KATANA_CONCURRENCY" -silent -jc -kf all \
            > "$URLS_DIR/katana.txt" 2>/dev/null || log_warn "Katana failed"
    ) &
    pids+=($!)
else
    log_warn "Katana not found"
    touch "$URLS_DIR/katana.txt"
fi

# Wait for all URL discovery tools
log_info "Waiting for archive crawlers to complete..."
for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Fallback: if crawler tools are missing, rely on GAU/Wayback only
if [ "$SPIDEYX_AVAILABLE" -eq 0 ] && [ "$HAKRAWLER_AVAILABLE" -eq 0 ] && [ "$KATANA_AVAILABLE" -eq 0 ]; then
    log_warn "Crawler tools (SpideyX/hakrawler/katana) missing; relying on GAU/Wayback only"
fi

# Merge all URLs
log_info "Merging discovered URLs..."
safe_cat "$URLS_DIR/all_urls_raw.txt" \
    "$URLS_DIR/gau.txt" \
    "$URLS_DIR/waybackurls.txt" \
    "$URLS_DIR/spideyx.txt" \
    "$URLS_DIR/gospider.txt" \
    "$URLS_DIR/hakrawler.txt" \
    "$URLS_DIR/katana.txt"

cat "$URLS_DIR/all_urls_raw.txt" 2>/dev/null | \
    safe_grep -E '^https?://' | \
    sort -u > "$URLS_DIR/all_urls.txt"

URL_COUNT=$(wc -l < "$URLS_DIR/all_urls.txt" 2>/dev/null | tr -d ' ')
log_info "Total unique URLs discovered: $URL_COUNT"

# Filter URLs by extension for further analysis
safe_grep -E '\.(js|json)' "$URLS_DIR/all_urls.txt" > "$URLS_DIR/javascript_files.txt"
JS_COUNT=$(wc -l < "$URLS_DIR/javascript_files.txt" 2>/dev/null | tr -d ' ')
log_info "JavaScript files found: $JS_COUNT"

# SpideyX JS scraping
if command -v spideyx &> /dev/null && [ -s "$URLS_DIR/javascript_files.txt" ]; then
    log_info "Running SpideyX JS scraper..."
    (
        if spideyx jsscrapy -h 2>&1 | grep -qi "usage"; then
            cat "$URLS_DIR/javascript_files.txt" | spideyx jsscrapy 2>/dev/null > "$URLS_DIR/spideyx_jsscrapy.txt" || touch "$URLS_DIR/spideyx_jsscrapy.txt"
        else
            log_warn "SpideyX jsscrapy mode not available"
            touch "$URLS_DIR/spideyx_jsscrapy.txt"
        fi
    )
else
    log_warn "SpideyX not found or no JavaScript URLs for scraping"
    touch "$URLS_DIR/spideyx_jsscrapy.txt"
fi

################################################################################
# PHASE 3B: ACTIVE DIRECTORY/FILE BRUTE-FORCING
################################################################################

log_info "=== DIRECTORY & FILE BRUTE-FORCING ==="

BRUTE_DIR="$PHASE_DIR/bruteforce"
mkdir -p "$BRUTE_DIR"

# Common wordlist paths
WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
if [ ! -f "$WORDLIST" ]; then
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
fi
if [ ! -f "$WORDLIST" ]; then
    log_warn "No wordlist found, creating basic one..."
    echo -e "admin\napi\nbackup\nconfig\ntest\ndev\n.git\n.env" > "$BRUTE_DIR/basic_wordlist.txt"
    WORDLIST="$BRUTE_DIR/basic_wordlist.txt"
fi

log_info "Using wordlist: $WORDLIST"

# Select top alive hosts for brute-forcing (limit to avoid excessive time)
head -n 20 "$ALIVE_HOSTS" > "$BRUTE_DIR/brute_targets.txt"
BRUTE_COUNT=$(wc -l < "$BRUTE_DIR/brute_targets.txt" | tr -d ' ')
log_info "Brute-forcing $BRUTE_COUNT hosts..."

# 1. FFUF (Fast) — run all hosts in parallel (up to 5 at once)
if command -v ffuf &> /dev/null; then
    log_info "Running FFUF (parallel, up to 5 hosts)..."

    export BRUTE_DIR WORDLIST FFUF_THREADS FFUF_TIMEOUT
    tr '\n' '\0' < "$BRUTE_DIR/brute_targets.txt" | \
        xargs -0 -P 5 -I{} bash -c '
            host="{}"
            log_info() { echo -e "\033[0;32m[+]\033[0m $1"; }
            log_warn() { echo -e "\033[1;33m[!]\033[0m $1"; }
            log_info "FFUF: $host"
            ffuf -u "https://$host/FUZZ" -w "$WORDLIST" \
                -mc 200,201,202,203,204,301,302,307,308,401,403 \
                -t "$FFUF_THREADS" -timeout "$FFUF_TIMEOUT" -s -json \
                -o "$BRUTE_DIR/ffuf_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || \
                log_warn "FFUF failed for $host"
        '

    # Merge FFUF results
    cat "$BRUTE_DIR"/ffuf_*.json 2>/dev/null > "$BRUTE_DIR/ffuf_all.json" || touch "$BRUTE_DIR/ffuf_all.json"
else
    log_warn "FFUF not found"
fi

# 2. Feroxbuster (Recursive) — run all hosts in parallel (up to 5 at once)
if command -v feroxbuster &> /dev/null; then
    log_info "Running Feroxbuster (parallel, up to 5 hosts)..."

    export BRUTE_DIR WORDLIST FEROX_THREADS
    tr '\n' '\0' < "$BRUTE_DIR/brute_targets.txt" | \
        xargs -0 -P 5 -I{} bash -c '
            host="{}"
            log_info() { echo -e "\033[0;32m[+]\033[0m $1"; }
            log_warn() { echo -e "\033[1;33m[!]\033[0m $1"; }
            log_info "Feroxbuster: $host"
            feroxbuster -u "https://$host" -w "$WORDLIST" \
                -t "$FEROX_THREADS" -d 2 --auto-bail --random-agent \
                -o "$BRUTE_DIR/feroxbuster_${host//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || \
                log_warn "Feroxbuster failed for $host"
        '

    # Merge results
    cat "$BRUTE_DIR"/feroxbuster_*.txt 2>/dev/null > "$BRUTE_DIR/feroxbuster_all.txt" || touch "$BRUTE_DIR/feroxbuster_all.txt"
else
    log_warn "Feroxbuster not found"
fi

# 3. Dirsearch (Classic) — run all hosts in parallel (up to 5 at once)
if command -v dirsearch &> /dev/null; then
    log_info "Running Dirsearch (parallel, up to 5 hosts)..."

    export BRUTE_DIR WORDLIST DIRSEARCH_THREADS
    tr '\n' '\0' < "$BRUTE_DIR/brute_targets.txt" | \
        xargs -0 -P 5 -I{} bash -c '
            host="{}"
            log_info() { echo -e "\033[0;32m[+]\033[0m $1"; }
            log_warn() { echo -e "\033[1;33m[!]\033[0m $1"; }
            log_info "Dirsearch: $host"
            dirsearch -u "https://$host" -w "$WORDLIST" \
                -t "$DIRSEARCH_THREADS" --random-agent --exclude-status 404,400,500,502,503 \
                -o "$BRUTE_DIR/dirsearch_${host//[^a-zA-Z0-9]/_}.txt" 2>/dev/null || \
                log_warn "Dirsearch failed for $host"
        '

    # Merge results
    cat "$BRUTE_DIR"/dirsearch_*.txt 2>/dev/null > "$BRUTE_DIR/dirsearch_all.txt" || touch "$BRUTE_DIR/dirsearch_all.txt"
else
    log_warn "Dirsearch not found"
fi

# Merge all discovered paths
cat "$BRUTE_DIR"/ffuf_all.json "$BRUTE_DIR"/feroxbuster_all.txt "$BRUTE_DIR"/dirsearch_all.txt 2>/dev/null | \
    grep -oE 'https?://[^\s"]+' | sort -u > "$BRUTE_DIR/all_discovered_paths.txt" || touch "$BRUTE_DIR/all_discovered_paths.txt"

PATHS_COUNT=$(wc -l < "$BRUTE_DIR/all_discovered_paths.txt" 2>/dev/null | tr -d ' ')
log_info "Total discovered paths: $PATHS_COUNT"

################################################################################
# PHASE 3C: JAVASCRIPT ANALYSIS
################################################################################

log_info "=== JAVASCRIPT ANALYSIS ==="

JS_DIR="$PHASE_DIR/javascript"
mkdir -p "$JS_DIR"

if [ ! -s "$URLS_DIR/javascript_files.txt" ]; then
    log_warn "No JavaScript files found, skipping JS analysis"
else
    # 1. LinkFinder - Extract endpoints from JS (parallel, up to 10 at once)
    if command -v linkfinder &> /dev/null || [ -f "/opt/LinkFinder/linkfinder.py" ]; then
        log_info "Running LinkFinder (parallel, up to 10 JS files)..."

        export JS_DIR
        head -n 100 "$URLS_DIR/javascript_files.txt" | \
            tr '\n' '\0' | \
            xargs -0 -P 10 -I{} bash -c '
                js_url="{}"
                if [ -f "/opt/LinkFinder/linkfinder.py" ]; then
                    python3 /opt/LinkFinder/linkfinder.py -i "$js_url" -o cli \
                        >> "$JS_DIR/linkfinder_endpoints.txt" 2>/dev/null || true
                else
                    linkfinder -i "$js_url" -o cli >> "$JS_DIR/linkfinder_endpoints.txt" 2>/dev/null || true
                fi
            '

        sort -u "$JS_DIR/linkfinder_endpoints.txt" -o "$JS_DIR/linkfinder_endpoints.txt" 2>/dev/null || true
    else
        log_warn "LinkFinder not found"
    fi

    # 2. SecretFinder - Find secrets in JS (parallel, up to 10 at once)
    if [ -f "/opt/SecretFinder/SecretFinder.py" ]; then
        log_info "Running SecretFinder (parallel, up to 10 JS files)..."

        export JS_DIR
        head -n 100 "$URLS_DIR/javascript_files.txt" | \
            tr '\n' '\0' | \
            xargs -0 -P 10 -I{} bash -c '
                js_url="{}"
                python3 /opt/SecretFinder/SecretFinder.py -i "$js_url" -o cli \
                    >> "$JS_DIR/secretfinder_secrets.txt" 2>/dev/null || true
            '

        sort -u "$JS_DIR/secretfinder_secrets.txt" -o "$JS_DIR/secretfinder_secrets.txt" 2>/dev/null || true
    else
        log_warn "SecretFinder not found"
    fi

    # 3. JSScanner alternative
    if command -v jsscanner &> /dev/null; then
        log_info "Running JSScanner..."
        head -n 50 "$URLS_DIR/javascript_files.txt" | jsscanner > "$JS_DIR/jsscanner_results.txt" 2>/dev/null || log_warn "JSScanner failed"
    fi

    SECRETS_COUNT=$(wc -l < "$JS_DIR/secretfinder_secrets.txt" 2>/dev/null | tr -d ' ')
    ENDPOINTS_COUNT=$(wc -l < "$JS_DIR/linkfinder_endpoints.txt" 2>/dev/null | tr -d ' ')
    log_info "JS Endpoints found: $ENDPOINTS_COUNT"
    log_info "JS Secrets found: $SECRETS_COUNT"
fi

################################################################################
# PHASE 3D: PASTEBIN MONITORING
################################################################################

log_info "=== PASTEBIN MONITORING ==="

PASTE_DIR="$PHASE_DIR/pastebin"
mkdir -p "$PASTE_DIR"

# PasteHunter
if [ -f "/opt/PasteHunter/pastehunter.py" ]; then
    log_info "Running PasteHunter..."
    python3 /opt/PasteHunter/pastehunter.py -q "$TARGET" -o "$PASTE_DIR/pastehunter_results.txt" 2>/dev/null || log_warn "PasteHunter failed"
else
    log_warn "PasteHunter not found"
fi

# PasteBin scraper alternative (using API)
if [ -n "$PASTEBIN_API_KEY" ]; then
    log_info "Searching Pastebin via API..."
    curl -s "https://scrape.pastebin.com/api_scraping.php?limit=100" 2>/dev/null | \
        grep -i "$TARGET" > "$PASTE_DIR/pastebin_api_results.txt" || touch "$PASTE_DIR/pastebin_api_results.txt"
else
    log_warn "PASTEBIN_API_KEY not set, skipping Pastebin API"
fi

# PastebinMonitor (third option)
if command -v pbin &> /dev/null; then
    log_info "Running pbin monitor..."
    pbin search "$TARGET" > "$PASTE_DIR/pbin_results.txt" 2>/dev/null || log_warn "pbin failed"
else
    log_warn "pbin not found"
fi

PASTE_COUNT=$(cat "$PASTE_DIR"/*.txt 2>/dev/null | wc -l | tr -d ' ')
log_info "Pastebin mentions found: $PASTE_COUNT"

################################################################################
# PHASE 3E: API COLLECTION TESTING
################################################################################

log_info "=== API TESTING ==="

API_DIR="$PHASE_DIR/api"
mkdir -p "$API_DIR"

# Postman/Newman (if collections are provided)
if command -v newman &> /dev/null; then
    log_info "Checking for Postman collections..."

    # Look for Postman collection files
    if ls ./*.json 2>/dev/null | grep -i "postman\|collection" >/dev/null; then
        for collection in ./*.json; do
            if grep -q "schema.*postman" "$collection" 2>/dev/null; then
                log_info "Running Newman on $collection"
                newman run "$collection" --reporters json \
                    --reporter-json-export "$API_DIR/newman_$(basename "$collection").json" 2>/dev/null || log_warn "Newman failed for $collection"
            fi
        done
    else
        log_info "No Postman collections found"
    fi
else
    log_warn "Newman not found"
fi

# Kiterunner (API endpoint discovery alternative)
if command -v kr &> /dev/null; then
    log_info "Running Kiterunner for API discovery..."

    head -n 10 "$ALIVE_HOSTS" | while IFS= read -r host; do
        url="https://$host"
        log_info "Kiterunner: $host"
        kr scan "$url" -w /usr/share/wordlists/kiterunner/routes-small.txt \
            -o json > "$API_DIR/kiterunner_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
    done

    cat "$API_DIR"/kiterunner_*.json 2>/dev/null > "$API_DIR/kiterunner_all.json" || touch "$API_DIR/kiterunner_all.json"
else
    log_warn "Kiterunner not found"
fi

# Arjun (Parameter discovery)
if command -v arjun &> /dev/null; then
    log_info "Running Arjun for parameter discovery..."

    head -n 10 "$ALIVE_HOSTS" | while IFS= read -r host; do
        url="https://$host"
        log_info "Arjun: $host"
        arjun -u "$url" -oJ "$API_DIR/arjun_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
    done

    cat "$API_DIR"/arjun_*.json 2>/dev/null > "$API_DIR/arjun_all.json" || touch "$API_DIR/arjun_all.json"
else
    log_warn "Arjun not found"
fi

################################################################################
# CLEANUP AND SUMMARY
################################################################################

log_info "=== PHASE 3 SUMMARY ==="
echo "Target: $TARGET"
echo "URLs Discovered: $URL_COUNT"
echo "JavaScript Files: $JS_COUNT"
echo "Discovered Paths: $PATHS_COUNT"
echo "JS Endpoints: ${ENDPOINTS_COUNT:-0}"
echo "JS Secrets: ${SECRETS_COUNT:-0}"
echo "Pastebin Mentions: $PASTE_COUNT"
echo ""
echo "Output directories:"
echo "  - $URLS_DIR: URL discovery results"
echo "  - $BRUTE_DIR: Directory brute-force results"
echo "  - $JS_DIR: JavaScript analysis"
echo "  - $PASTE_DIR: Pastebin monitoring"
echo "  - $API_DIR: API testing"

# Create phase completion marker
touch "$PHASE_DIR/.completed"
log_info "Phase 3 complete: success=$TOOLS_SUCCESS failed=$TOOLS_FAILED skipped=$TOOLS_SKIPPED"

exit 0
