#!/bin/bash
################################################################################
# Technieum - Phase 3: Deep Web & Content Discovery
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
GAU_THREADS="${TECHNIEUM_GAU_THREADS:-10}"
GAU_TIMEOUT="${TECHNIEUM_GAU_TIMEOUT:-900}"
GOSPIDER_THREADS="${TECHNIEUM_GOSPIDER_THREADS:-20}"
GOSPIDER_CONCURRENCY="${TECHNIEUM_GOSPIDER_CONCURRENCY:-20}"
GOSPIDER_TIMEOUT="${TECHNIEUM_GOSPIDER_TIMEOUT:-1200}"
KATANA_CONCURRENCY="${TECHNIEUM_KATANA_CONCURRENCY:-30}"
KATANA_TIMEOUT="${TECHNIEUM_KATANA_TIMEOUT:-1200}"
WAYBACKURLS_TIMEOUT="${TECHNIEUM_WAYBACKURLS_TIMEOUT:-900}"
HAKRAWLER_TIMEOUT="${TECHNIEUM_HAKRAWLER_TIMEOUT:-900}"
SPIDEYX_TIMEOUT="${TECHNIEUM_SPIDEYX_TIMEOUT:-900}"
FFUF_THREADS="${TECHNIEUM_FFUF_THREADS:-80}"
FFUF_TIMEOUT="${TECHNIEUM_FFUF_TIMEOUT:-15}"
FEROX_THREADS="${TECHNIEUM_FEROX_THREADS:-80}"
DIRSEARCH_THREADS="${TECHNIEUM_DIRSEARCH_THREADS:-80}"
CARIDDI_CONCURRENCY="${TECHNIEUM_CARIDDI_CONCURRENCY:-50}"  # cariddi parallel workers
CARIDDI_TIMEOUT="${TECHNIEUM_CARIDDI_TIMEOUT:-10}"          # cariddi per-request timeout (s)
CARIDDI_RUN_TIMEOUT="${TECHNIEUM_CARIDDI_RUN_TIMEOUT:-900}" # cariddi whole-process timeout (s)
MANTRA_RUN_TIMEOUT="${TECHNIEUM_MANTRA_RUN_TIMEOUT:-1200}"   # mantra whole-process timeout (s)

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
# Prefer alive_urls.txt (full URLs with scheme) if available; fall back to adding https://
if [ -s "$PHASE1_DIR/alive_urls.txt" ]; then
    ALIVE_URLS="$PHASE1_DIR/alive_urls.txt"
else
    ALIVE_URLS="$PHASE_DIR/alive_urls_generated.txt"
    sed 's|^https\?://||' "$ALIVE_HOSTS" | awk '{print "https://" $0}' > "$ALIVE_URLS" 2>/dev/null || touch "$ALIVE_URLS"
fi
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
SPIDEY_AVAILABLE=0
HAKRAWLER_AVAILABLE=0
KATANA_AVAILABLE=0

# 1. GAU (GetAllUrls)
GAU_BIN=""
if GAU_BIN="$(resolve_tool_path gau)"; then
    log_info "Launching GAU (GetAllUrls)..."
    (
        _gau_help=$("$GAU_BIN" --help 2>&1 || true)
        _gau_flags=""
        echo "$_gau_help" | grep -q -- '--threads' && _gau_flags="$_gau_flags --threads $GAU_THREADS"
        echo "$_gau_help" | grep -q -- '--blacklist' && _gau_flags="$_gau_flags --blacklist png,jpg,gif,jpeg,svg,css,woff,woff2,ttf,eot"
        # shellcheck disable=SC2086
        run_timeout "$GAU_TIMEOUT" bash -c "cat '$URLS_DIR/targets.txt' | '$GAU_BIN' $_gau_flags > '$URLS_DIR/gau.txt'" \
            2>/dev/null || log_warn "GAU failed or timed out"
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
        run_timeout "$WAYBACKURLS_TIMEOUT" bash -c "cat '$URLS_DIR/targets.txt' | waybackurls > '$URLS_DIR/waybackurls.txt'" \
            2>/dev/null || log_warn "waybackurls failed or timed out"
    ) &
    pids+=($!)
else
    log_warn "waybackurls not found"
    touch "$URLS_DIR/waybackurls.txt"
fi

# 3. SpideyX / Spidey (Revolt suite)
SPIDER_BIN=""
if command -v spideyx &> /dev/null; then
    SPIDER_BIN="spideyx"
    SPIDEYX_AVAILABLE=1
    SPIDEY_AVAILABLE=1
elif command -v spidey &> /dev/null; then
    SPIDER_BIN="spidey"
    SPIDEY_AVAILABLE=1
fi

if [ -n "$SPIDER_BIN" ]; then
    log_info "Launching $SPIDER_BIN crawler..."
    (
        SPIDEYX_CMD=""
        if "$SPIDER_BIN" crawler -h 2>&1 | grep -qi "usage"; then
            SPIDEYX_CMD="crawler"
        elif "$SPIDER_BIN" crawl -h 2>&1 | grep -qi "usage"; then
            SPIDEYX_CMD="crawl"
        fi

        if [ -z "$SPIDEYX_CMD" ]; then
            log_warn "SpideyX crawler mode not available"
            touch "$URLS_DIR/spideyx.txt"
            exit 0
        fi

        SPIDEYX_TARGETS="$URLS_DIR/spideyx_targets.txt"
        cat "$ALIVE_HOSTS" | sed 's|^https\?://||' | sed 's|^|https://|' > "$SPIDEYX_TARGETS"

        _sp_help=$("$SPIDER_BIN" "$SPIDEYX_CMD" -h 2>&1 || true)
        _sp_depth=""
        echo "$_sp_help" | grep -q -- '-dept' && _sp_depth="-dept 5"
        # Prefer file-input mode when available: spideyx crawler -sites urls.txt
        if echo "$_sp_help" | grep -q -- '-sites'; then
            if run_timeout "$SPIDEYX_TIMEOUT" bash -c "'$SPIDER_BIN' '$SPIDEYX_CMD' -sites '$SPIDEYX_TARGETS' $_sp_depth > '$URLS_DIR/spideyx_raw.txt'" 2>/dev/null; then
                safe_grep -oP 'https?://[^\s]+' "$URLS_DIR/spideyx_raw.txt" | sort -u > "$URLS_DIR/spideyx.txt"
            else
                touch "$URLS_DIR/spideyx.txt"
            fi
        # Single-url mode fallback: spideyx crawler -site https://target
        elif echo "$_sp_help" | grep -q -- '-site'; then
            : > "$URLS_DIR/spideyx_raw.txt"
            while IFS= read -r _u; do
                [ -z "$_u" ] && continue
                run_timeout "$SPIDEYX_TIMEOUT" bash -c "'$SPIDER_BIN' '$SPIDEYX_CMD' -site '$_u' $_sp_depth >> '$URLS_DIR/spideyx_raw.txt'" 2>/dev/null || true
            done < "$SPIDEYX_TARGETS"
            safe_grep -oP 'https?://[^\s]+' "$URLS_DIR/spideyx_raw.txt" | sort -u > "$URLS_DIR/spideyx.txt"
        # STDIN mode fallback: cat urls.txt | spideyx crawler -dept 5
        elif run_timeout "$SPIDEYX_TIMEOUT" bash -c "cat '$SPIDEYX_TARGETS' | '$SPIDER_BIN' '$SPIDEYX_CMD' $_sp_depth > '$URLS_DIR/spideyx_raw.txt'" 2>/dev/null; then
            safe_grep -oP 'https?://[^\s]+' "$URLS_DIR/spideyx_raw.txt" | sort -u > "$URLS_DIR/spideyx.txt"
        else
            touch "$URLS_DIR/spideyx.txt"
        fi
    ) &
    pids+=($!)
else
    log_warn "SpideyX/Spidey not found"
    touch "$URLS_DIR/spideyx.txt"
fi

# 4. Gospider (fallback crawler)
GOSPIDER_BIN=""
if GOSPIDER_BIN="$(resolve_tool_path gospider)"; then
    log_info "Launching gospider..."
    (
        : > "$URLS_DIR/gospider_raw.txt"
        : > "$URLS_DIR/gospider.err"
        : > "$URLS_DIR/gospider_targets.txt"
        if [ -s "$ALIVE_URLS" ]; then
            safe_grep -E '^https?://' "$ALIVE_URLS" | sort -u > "$URLS_DIR/gospider_targets.txt"
        fi

        if [ ! -s "$URLS_DIR/gospider_targets.txt" ] && [ -s "$ALIVE_HOSTS" ]; then
            sed 's|^https\?://||' "$ALIVE_HOSTS" | awk 'NF{print "https://"$0}' | sort -u > "$URLS_DIR/gospider_targets.txt"
        fi

        if [ ! -s "$URLS_DIR/gospider_targets.txt" ]; then
            echo "https://$TARGET" > "$URLS_DIR/gospider_targets.txt"
            log_warn "gospider: alive target list empty, using root target fallback"
        fi

        GOSPIDER_STORE="$URLS_DIR/gospider_store"
        mkdir -p "$GOSPIDER_STORE"

        _gosp_help=$("$GOSPIDER_BIN" -h 2>&1 || true)
        _gosp_depth=""
        _gosp_conc=""
        _gosp_threads=""
        _gosp_sitemap=""
        _gosp_robots=""
        _gosp_output=""
        echo "$_gosp_help" | grep -q -- '-d\b' && _gosp_depth="-d 3"
        echo "$_gosp_help" | grep -q -- '-c\b' && _gosp_conc="-c $GOSPIDER_CONCURRENCY"
        echo "$_gosp_help" | grep -q -- '-t\b' && _gosp_threads="-t $GOSPIDER_THREADS"
        echo "$_gosp_help" | grep -q -- '--sitemap' && _gosp_sitemap="--sitemap"
        echo "$_gosp_help" | grep -q -- '--robots' && _gosp_robots="--robots"
        echo "$_gosp_help" | grep -q -- '-o\b' && _gosp_output="-o '$GOSPIDER_STORE'"

        # Prefer list mode when -S exists, otherwise iterate target-by-target with -s.
        if echo "$_gosp_help" | grep -q -- '-S\b'; then
            # shellcheck disable=SC2086
            run_timeout "$GOSPIDER_TIMEOUT" bash -c "'$GOSPIDER_BIN' -S '$URLS_DIR/gospider_targets.txt' $_gosp_depth $_gosp_conc $_gosp_threads $_gosp_sitemap $_gosp_robots $_gosp_output >/dev/null" \
                2>>"$URLS_DIR/gospider.err" || true
        else
            while IFS= read -r _gurl; do
                [ -z "$_gurl" ] && continue
                # shellcheck disable=SC2086
                run_timeout "$GOSPIDER_TIMEOUT" bash -c "'$GOSPIDER_BIN' -s '$_gurl' $_gosp_depth $_gosp_conc $_gosp_threads $_gosp_sitemap $_gosp_robots $_gosp_output >/dev/null" \
                    2>>"$URLS_DIR/gospider.err" || true
            done < "$URLS_DIR/gospider_targets.txt"
        fi

        # Parse outputs written by gospider into its output directory.
        if [ -d "$GOSPIDER_STORE" ]; then
            find "$GOSPIDER_STORE" -type f -size +0c -exec cat {} + 2>/dev/null > "$URLS_DIR/gospider_raw.txt" || true
        fi

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
        # hakrawler reads URLs from stdin; use full URLs (with scheme).
        # Build flags dynamically — flag names changed across versions.
        _hak_help=$(hakrawler --help 2>&1 || true)
        _HAK_FLAGS=""
        echo "$_hak_help" | grep -q -- '-d\b'       && _HAK_FLAGS="$_HAK_FLAGS -d 3"
        echo "$_hak_help" | grep -q -- '--timeout'  && _HAK_FLAGS="$_HAK_FLAGS --timeout 30"
        # Only add -timeout (short) if --timeout was NOT already added
        if ! echo "$_HAK_FLAGS" | grep -q 'timeout'; then
            echo "$_hak_help" | grep -q -- '-timeout\b' && _HAK_FLAGS="$_HAK_FLAGS -timeout 30"
        fi
        echo "$_hak_help" | grep -q -- '-subs\b'    && _HAK_FLAGS="$_HAK_FLAGS -subs"
        # shellcheck disable=SC2086  — intentional word-split for flag string
        # hakrawler exit 1 = "finished / no URLs found" (normal); exit 2+ = real error
        # shellcheck disable=SC2086
        run_timeout "$HAKRAWLER_TIMEOUT" bash -c "cat '$ALIVE_URLS' | hakrawler $_HAK_FLAGS > '$URLS_DIR/hakrawler.txt'" 2>/dev/null
        _hak_exit=$?
        [ "${_hak_exit:-0}" -gt 1 ] && log_warn "hakrawler exited unexpectedly (code $_hak_exit)" || true
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
        run_timeout "$KATANA_TIMEOUT" bash -c "cat '$ALIVE_URLS' | katana -d 5 -c '$KATANA_CONCURRENCY' -silent -jc -kf all > '$URLS_DIR/katana.txt'" \
            2>/dev/null || log_warn "Katana failed or timed out"
    ) &
    pids+=($!)
else
    log_warn "Katana not found"
    touch "$URLS_DIR/katana.txt"
fi

# Wait for all URL discovery tools
log_info "Waiting for archive crawlers to complete..."
for pid in "${pids[@]}"; do
    CHILD_WAIT_TIMEOUT="${TECHNIEUM_ARCHIVE_CHILD_WAIT_TIMEOUT:-240}"
    _elapsed=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$_elapsed" -ge "$CHILD_WAIT_TIMEOUT" ]; then
            log_warn "Crawler process $pid exceeded ${CHILD_WAIT_TIMEOUT}s; terminating"
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
        sleep 1
        _elapsed=$((_elapsed + 1))
    done
    wait "$pid" 2>/dev/null || true
done

# Keep crawler artifacts non-empty when one optional crawler returns nothing.
if [ ! -s "$URLS_DIR/gospider.txt" ]; then
    safe_cat "$URLS_DIR/gospider_seed_raw.txt" "$URLS_DIR/hakrawler.txt" "$URLS_DIR/katana.txt" "$URLS_DIR/waybackurls.txt"
    safe_grep -E '^https?://' "$URLS_DIR/gospider_seed_raw.txt" | sort -u > "$URLS_DIR/gospider.txt"
    [ -s "$URLS_DIR/gospider.txt" ] && log_warn "gospider produced no direct output; seeded gospider.txt from other crawler results"
fi

if [ ! -s "$URLS_DIR/spideyx.txt" ]; then
    safe_cat "$URLS_DIR/spideyx_seed_raw.txt" "$URLS_DIR/hakrawler.txt" "$URLS_DIR/katana.txt" "$URLS_DIR/gospider.txt"
    safe_grep -E '^https?://' "$URLS_DIR/spideyx_seed_raw.txt" | sort -u > "$URLS_DIR/spideyx.txt"
    [ -s "$URLS_DIR/spideyx.txt" ] && log_warn "spideyx unavailable/empty; seeded spideyx.txt from other crawler results"
fi

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

################################################################################
# PHASE 3A-EXT: CARIDDI — Deep Crawl + Secrets/Endpoints/API Keys
################################################################################

log_info "=== CARIDDI CRAWL & SECRET SCAN ==="

CARIDDI_DIR="$URLS_DIR/cariddi"
mkdir -p "$CARIDDI_DIR"

if command -v cariddi &>/dev/null; then
    log_info "Running cariddi (secrets/endpoints/errors/info/extensions)..."
    # Detect supported flags at runtime to handle version differences
    CARIDDI_PLAIN=""
    CARIDDI_JSON_FLAG=""
    CARIDDI_INFO=""
    CARIDDI_ERR_FLAG=""
    CARIDDI_RUA=""
    CARIDDI_EXT_FLAG=""
    CARIDDI_INTENSIVE_FLAG=""
    CARIDDI_IGNORE_EXT_FLAG=""
    _cariddi_help=$(cariddi -h 2>&1 || true)
    echo "$_cariddi_help" | grep -q -- '-plain'  && CARIDDI_PLAIN="-plain"
    echo "$_cariddi_help" | grep -q -- '-json'   && CARIDDI_JSON_FLAG="-json"
    echo "$_cariddi_help" | grep -q -- '-info'   && CARIDDI_INFO="-info"
    echo "$_cariddi_help" | grep -q -- '-err'    && CARIDDI_ERR_FLAG="-err"
    echo "$_cariddi_help" | grep -q -- '-rua'    && CARIDDI_RUA="-rua"
    echo "$_cariddi_help" | grep -q -- '-ext'    && CARIDDI_EXT_FLAG="-ext 2"
    echo "$_cariddi_help" | grep -q -- '-intensive' && CARIDDI_INTENSIVE_FLAG="-intensive"
    echo "$_cariddi_help" | grep -q -- '-ie' && CARIDDI_IGNORE_EXT_FLAG="-ie pdf,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot"

    # Build common runtime flags (avoid -plain by default; it hides findings)
    CARIDDI_COMMON=""
    echo "$_cariddi_help" | grep -q -- '-c\b'       && CARIDDI_COMMON="$CARIDDI_COMMON -c $CARIDDI_CONCURRENCY"
    echo "$_cariddi_help" | grep -q -- '-t\b'       && CARIDDI_COMMON="$CARIDDI_COMMON -t $CARIDDI_TIMEOUT"
    [ -n "$CARIDDI_RUA" ]         && CARIDDI_COMMON="$CARIDDI_COMMON $CARIDDI_RUA"
    [ -n "$CARIDDI_IGNORE_EXT_FLAG" ] && CARIDDI_COMMON="$CARIDDI_COMMON $CARIDDI_IGNORE_EXT_FLAG"
    if [ "${TECHNIEUM_CARIDDI_INTENSIVE:-false}" = "true" ] && [ -n "$CARIDDI_INTENSIVE_FLAG" ]; then
        CARIDDI_COMMON="$CARIDDI_COMMON $CARIDDI_INTENSIVE_FLAG"
    fi

    if [ -s "$URLS_DIR/all_urls.txt" ]; then
        : > "$CARIDDI_DIR/cariddi.err"
        touch "$CARIDDI_DIR/cariddi_secrets_only.txt" "$CARIDDI_DIR/cariddi_endpoints.txt" "$CARIDDI_DIR/cariddi_errors.txt" "$CARIDDI_DIR/cariddi_info.txt" "$CARIDDI_DIR/cariddi_extensions.txt"

        # 1) Secrets: cat urls.txt | cariddi -s
        #    Raw output goes to _raw file, then [+] secret findings extracted
        if echo "$_cariddi_help" | grep -q -- '-s\b'; then
            # shellcheck disable=SC2086
            run_timeout "$CARIDDI_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | cariddi -s > '$CARIDDI_DIR/cariddi_secrets_raw.txt'" 2>>"$CARIDDI_DIR/cariddi.err" || true
            # Extract only actual [+] secret findings (cariddi outputs crawled URLs + secrets together)
            # Use -F for fixed-string match (no regex); [+] may have ANSI codes before it
            grep -F '[+]' "$CARIDDI_DIR/cariddi_secrets_raw.txt" > "$CARIDDI_DIR/cariddi_secrets_only.txt" 2>/dev/null || true
        fi
        # 2) Endpoints: cat urls.txt | cariddi -e
        if echo "$_cariddi_help" | grep -q -- '-e\b'; then
            # shellcheck disable=SC2086
            run_timeout "$CARIDDI_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | cariddi -e $CARIDDI_COMMON > '$CARIDDI_DIR/cariddi_endpoints.txt'" 2>>"$CARIDDI_DIR/cariddi.err" || true
        fi
        # 3) Errors: cat urls.txt | cariddi -err
        if [ -n "$CARIDDI_ERR_FLAG" ]; then
            # shellcheck disable=SC2086
            run_timeout "$CARIDDI_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | cariddi -err $CARIDDI_COMMON > '$CARIDDI_DIR/cariddi_errors.txt'" 2>>"$CARIDDI_DIR/cariddi.err" || true
        fi
        # 4) Info: cat urls.txt | cariddi -info
        if [ -n "$CARIDDI_INFO" ]; then
            # shellcheck disable=SC2086
            run_timeout "$CARIDDI_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | cariddi -info $CARIDDI_COMMON > '$CARIDDI_DIR/cariddi_info.txt'" 2>>"$CARIDDI_DIR/cariddi.err" || true
        fi
        # 5) Extensions level 2: cat urls.txt | cariddi -ext 2
        if [ -n "$CARIDDI_EXT_FLAG" ]; then
            # shellcheck disable=SC2086
            run_timeout "$CARIDDI_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | cariddi -ext 2 $CARIDDI_COMMON > '$CARIDDI_DIR/cariddi_extensions.txt'" 2>>"$CARIDDI_DIR/cariddi.err" || true
        fi

        # Aggregate all findings to the historical output filename expected by UI/parsers
        safe_cat "$CARIDDI_DIR/cariddi_secrets.txt" \
            "$CARIDDI_DIR/cariddi_secrets_only.txt" \
            "$CARIDDI_DIR/cariddi_endpoints.txt" \
            "$CARIDDI_DIR/cariddi_errors.txt" \
            "$CARIDDI_DIR/cariddi_info.txt" \
            "$CARIDDI_DIR/cariddi_extensions.txt"

        # Machine-readable JSON output (endpoints only) if -json is supported
        if [ -n "$CARIDDI_JSON_FLAG" ]; then
            # shellcheck disable=SC2086
            run_timeout "$CARIDDI_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | cariddi -e -s $CARIDDI_JSON_FLAG $CARIDDI_COMMON > '$CARIDDI_DIR/cariddi_results.json'" \
                2>/dev/null || true
        fi

        CARIDDI_SECRET_COUNT=$(wc -l < "$CARIDDI_DIR/cariddi_secrets_only.txt" 2>/dev/null | tr -d ' ')
        CARIDDI_COUNT=$(wc -l < "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null | tr -d ' ')
        log_info "cariddi: $CARIDDI_SECRET_COUNT secrets found, $CARIDDI_COUNT total findings (secrets + endpoints + files)"

        # Extract any new JS/JSON URLs cariddi discovered and merge into all_urls.txt
        # Use raw crawl outputs (which contain all discovered URLs) for JS extraction
        safe_grep -oE "https?://[^[:space:]]+\\.(js|json)(\\?[^[:space:]]*)?" "$CARIDDI_DIR/cariddi_secrets_raw.txt" \
            >> "$URLS_DIR/all_urls.txt" 2>/dev/null || true
        safe_grep -oE "https?://[^[:space:]]+\\.(js|json)(\\?[^[:space:]]*)?" "$CARIDDI_DIR/cariddi_secrets.txt" \
            >> "$URLS_DIR/all_urls.txt" 2>/dev/null || true
        sort -u "$URLS_DIR/all_urls.txt" -o "$URLS_DIR/all_urls.txt" 2>/dev/null || true
    else
        log_warn "cariddi: no URLs to scan yet"
        touch "$CARIDDI_DIR/cariddi_secrets.txt"
    fi
else
    log_warn "cariddi not found — install: go install github.com/edoardottt/cariddi/cmd/cariddi@latest"
    touch "$CARIDDI_DIR/cariddi_secrets.txt"
fi

# ── Extract JS/JSON files FIRST so mantra can target them ───────────────────
# Filter URLs by extension for further analysis (includes any new JS/JSON discovered by cariddi)
safe_grep -E '\.(js|json)' "$URLS_DIR/all_urls.txt" > "$URLS_DIR/javascript_files.txt"
JS_COUNT=$(wc -l < "$URLS_DIR/javascript_files.txt" 2>/dev/null | tr -d ' ')
log_info "JavaScript files found: $JS_COUNT"

# ── Mantra secret scan — targets ALL URLs ──────────────────────────────────
# Flow: cat urls.txt | mantra  (hunt for API keys & secrets in all URLs)
MANTRA_BIN=""
if command -v mantra &>/dev/null; then
    MANTRA_BIN="$(command -v mantra)"
elif [ -x "$HOME/go/bin/mantra" ]; then
    MANTRA_BIN="$HOME/go/bin/mantra"
elif [ -x "/root/go/bin/mantra" ]; then
    MANTRA_BIN="/root/go/bin/mantra"
elif [ -x "/usr/local/bin/mantra" ]; then
    MANTRA_BIN="/usr/local/bin/mantra"
fi

if [ -n "$MANTRA_BIN" ]; then
    log_info "Running mantra secret scanning (cat urls.txt | mantra)..."
    : > "$CARIDDI_DIR/mantra_secrets.txt"
    : > "$CARIDDI_DIR/mantra.err"

    if [ -s "$URLS_DIR/all_urls.txt" ]; then
        _URL_COUNT=$(wc -l < "$URLS_DIR/all_urls.txt" 2>/dev/null | tr -d ' ')
        log_info "mantra: scanning $_URL_COUNT URLs for secrets & API keys..."
        run_timeout "$MANTRA_RUN_TIMEOUT" bash -c "cat '$URLS_DIR/all_urls.txt' | '$MANTRA_BIN' > '$CARIDDI_DIR/mantra_secrets.txt'" \
            2>>"$CARIDDI_DIR/mantra.err" || log_warn "mantra scan failed or timed out"
    else
        log_warn "mantra: no URLs found to scan (run crawlers first)"
    fi

    # Merge mantra findings into the primary cariddi secrets artifact consumed by UI/parsers
    if [ -s "$CARIDDI_DIR/mantra_secrets.txt" ]; then
        # Extract clean [+] findings only (mantra also prints banner to stdout)
        grep -F '[+]' "$CARIDDI_DIR/mantra_secrets.txt" >> "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null || true
        sort -u "$CARIDDI_DIR/cariddi_secrets.txt" -o "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null || true
    fi

    MANTRA_SECRET_COUNT=$(grep -cF '[+]' "$CARIDDI_DIR/mantra_secrets.txt" 2>/dev/null || echo 0)
    MANTRA_COUNT=$(wc -l < "$CARIDDI_DIR/mantra_secrets.txt" 2>/dev/null | tr -d ' ')
    log_info "mantra: $MANTRA_SECRET_COUNT secrets found ($MANTRA_COUNT total output lines, bin: $MANTRA_BIN)"
else
    log_warn "mantra not found — install: go install github.com/Brosck/mantra@latest"
    touch "$CARIDDI_DIR/mantra_secrets.txt"
fi

################################################################################
# PHASE 3A-EXT2: GITLEAKS + TRUFFLEHOG — Secret Scanning on Discovered Content
# Runs AFTER cariddi + mantra JS crawl so that all discovered URLs/files are
# available for deep secret scanning (API keys, tokens, credentials, etc.)
################################################################################

log_info "=== SECRET SCANNING ON DISCOVERED CONTENT (gitleaks + trufflehog) ==="

SECRETS_DIR="$URLS_DIR/secrets"
mkdir -p "$SECRETS_DIR"

# ── Download discovered JS/JSON content for local secret scanning ──────────
JS_DOWNLOAD_DIR="$SECRETS_DIR/downloaded_js"
mkdir -p "$JS_DOWNLOAD_DIR"

GITLEAKS_WEB_TIMEOUT="${TECHNIEUM_GITLEAKS_WEB_TIMEOUT:-600}"
TRUFFLEHOG_WEB_TIMEOUT="${TECHNIEUM_TRUFFLEHOG_WEB_TIMEOUT:-600}"
JS_DOWNLOAD_TIMEOUT="${TECHNIEUM_JS_DOWNLOAD_TIMEOUT:-300}"
JS_DOWNLOAD_MAX="${TECHNIEUM_JS_DOWNLOAD_MAX:-200}"

if [ -s "$URLS_DIR/javascript_files.txt" ]; then
    log_info "Downloading discovered JS/JSON files for secret scanning..."

    _dl_count=0
    while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue
        [ "$_dl_count" -ge "$JS_DOWNLOAD_MAX" ] && break
        _fname=$(echo "$js_url" | sed 's|https\?://||' | tr '/:?&=' '_' | head -c 200)
        if curl -sL --max-time 10 --max-filesize 5242880 -o "$JS_DOWNLOAD_DIR/$_fname" "$js_url" 2>/dev/null; then
            ((_dl_count++))
        fi
    done < "$URLS_DIR/javascript_files.txt"
    log_info "Downloaded $_dl_count JS/JSON files for secret scanning"
else
    log_info "No JS/JSON files available for download; secret scanning will use URL lists"
fi

# Also download HTML/config-type URLs that might contain secrets
if [ -s "$URLS_DIR/all_urls.txt" ]; then
    safe_grep -iE '\.(env|config|yml|yaml|xml|conf|properties|ini|txt|log|bak|old|backup)(\?|$)' \
        "$URLS_DIR/all_urls.txt" 2>/dev/null | head -n 50 > "$SECRETS_DIR/config_urls.txt" || true

    if [ -s "$SECRETS_DIR/config_urls.txt" ]; then
        log_info "Downloading $(wc -l < "$SECRETS_DIR/config_urls.txt" | tr -d ' ') config/dotfile URLs..."
        while IFS= read -r conf_url; do
            [ -z "$conf_url" ] && continue
            _fname=$(echo "$conf_url" | sed 's|https\?://||' | tr '/:?&=' '_' | head -c 200)
            curl -sL --max-time 10 --max-filesize 2097152 -o "$JS_DOWNLOAD_DIR/$_fname" "$conf_url" 2>/dev/null || true
        done < "$SECRETS_DIR/config_urls.txt"
    fi
fi

# ── Gitleaks — scan downloaded web content for secrets ─────────────────────
if command -v gitleaks &>/dev/null; then
    log_info "Running Gitleaks on discovered web content..."

    _GL_VER=$(gitleaks version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo '8.0')
    _GL_MAJOR=$(echo "$_GL_VER" | cut -d. -f1)

    if [ "$_GL_MAJOR" -ge 8 ] 2>/dev/null; then
        # v8+: gitleaks detect --no-git --source <dir>
        run_timeout "$GITLEAKS_WEB_TIMEOUT" bash -c \
            "gitleaks detect --no-git --source '$JS_DOWNLOAD_DIR' --report-format json --report-path '$SECRETS_DIR/gitleaks_web.json'" \
            2>"$SECRETS_DIR/gitleaks_web.err"; _gl_ec=$?
    else
        # v7: gitleaks --path <dir> --no-git
        run_timeout "$GITLEAKS_WEB_TIMEOUT" bash -c \
            "gitleaks --path '$JS_DOWNLOAD_DIR' --no-git --report '$SECRETS_DIR/gitleaks_web.json'" \
            2>"$SECRETS_DIR/gitleaks_web.err"; _gl_ec=$?
    fi

    if [ "$_gl_ec" -eq 0 ]; then
        log_info "Gitleaks web scan: no secrets found"
    elif [ "$_gl_ec" -eq 1 ]; then
        GITLEAKS_WEB_COUNT=$(python3 -c "import json; print(len(json.load(open('$SECRETS_DIR/gitleaks_web.json'))))" 2>/dev/null || echo "?")
        log_warn "Gitleaks web scan: $GITLEAKS_WEB_COUNT secrets detected! Review $SECRETS_DIR/gitleaks_web.json"
    else
        log_warn "Gitleaks web scan failed (exit $_gl_ec)"
    fi

    # Merge gitleaks web findings into main cariddi_secrets.txt
    if [ -s "$SECRETS_DIR/gitleaks_web.json" ]; then
        python3 -c "
import json, sys
try:
    data = json.load(open('$SECRETS_DIR/gitleaks_web.json'))
    for item in data:
        rule = item.get('RuleID', item.get('rule', 'unknown'))
        match = item.get('Match', item.get('offender', ''))[:120]
        file = item.get('File', item.get('file', ''))
        line = item.get('StartLine', item.get('line', 0))
        print(f'[GITLEAKS] {rule}: {match} (file: {file}:{line})')
except Exception as e:
    pass
" >> "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null || true
    fi

    [ ! -f "$SECRETS_DIR/gitleaks_web.json" ] && echo "[]" > "$SECRETS_DIR/gitleaks_web.json"
else
    log_warn "Gitleaks not found — web secret scanning skipped"
    echo "[]" > "$SECRETS_DIR/gitleaks_web.json"
fi

# ── TruffleHog — scan downloaded web content for verified secrets ──────────
if command -v trufflehog &>/dev/null; then
    log_info "Running TruffleHog on discovered web content..."

    _TH_VER=$(trufflehog --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo '3.0')
    _TH_MAJOR=$(echo "$_TH_VER" | cut -d. -f1)

    if [ "$_TH_MAJOR" -ge 3 ] 2>/dev/null; then
        if trufflehog --help 2>&1 | grep -q 'filesystem'; then
            run_timeout "$TRUFFLEHOG_WEB_TIMEOUT" bash -c \
                "trufflehog filesystem '$JS_DOWNLOAD_DIR' --json --only-verified > '$SECRETS_DIR/trufflehog_web.json'" \
                2>"$SECRETS_DIR/trufflehog_web.err" || log_warn "TruffleHog web filesystem scan failed"
        else
            # Older v3 without filesystem mode — scan individual files
            run_timeout "$TRUFFLEHOG_WEB_TIMEOUT" bash -c \
                "find '$JS_DOWNLOAD_DIR' -type f | while read f; do trufflehog --json \"\$f\" 2>/dev/null; done > '$SECRETS_DIR/trufflehog_web.json'" \
                2>"$SECRETS_DIR/trufflehog_web.err" || log_warn "TruffleHog web scan failed"
        fi
    else
        # v2
        run_timeout "$TRUFFLEHOG_WEB_TIMEOUT" bash -c \
            "trufflehog --regex --entropy=False '$JS_DOWNLOAD_DIR' > '$SECRETS_DIR/trufflehog_web.json'" \
            2>"$SECRETS_DIR/trufflehog_web.err" || log_warn "TruffleHog v2 web scan failed"
    fi

    # Count and log findings
    if [ -s "$SECRETS_DIR/trufflehog_web.json" ]; then
        TH_WEB_COUNT=$(wc -l < "$SECRETS_DIR/trufflehog_web.json" 2>/dev/null | tr -d ' ')
        log_info "TruffleHog web scan: $TH_WEB_COUNT verified secret findings"

        # Merge trufflehog web findings into main cariddi_secrets.txt
        python3 -c "
import json, sys
with open('$SECRETS_DIR/trufflehog_web.json') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            detector = obj.get('DetectorName', obj.get('detectorName', 'unknown'))
            raw = obj.get('Raw', obj.get('raw', ''))[:120]
            source = obj.get('SourceMetadata', {}).get('Data', {})
            print(f'[TRUFFLEHOG] {detector}: {raw}')
        except Exception:
            pass
" >> "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null || true
    else
        log_info "TruffleHog web scan: no verified secrets found"
    fi

    [ ! -f "$SECRETS_DIR/trufflehog_web.json" ] && touch "$SECRETS_DIR/trufflehog_web.json"
else
    log_warn "TruffleHog not found — web secret scanning skipped"
    touch "$SECRETS_DIR/trufflehog_web.json"
fi

# ── Deduplicate cariddi_secrets.txt after merging all secret scanner results ──
if [ -s "$CARIDDI_DIR/cariddi_secrets.txt" ]; then
    sort -u "$CARIDDI_DIR/cariddi_secrets.txt" -o "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null || true
    TOTAL_SECRET_COUNT=$(wc -l < "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null | tr -d ' ')
    log_info "Total secret findings (cariddi + mantra + gitleaks + trufflehog): $TOTAL_SECRET_COUNT"
fi

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
cat "$ALIVE_URLS" 2>/dev/null | sed -E 's|^https?://||' | sed 's|/.*||' | awk 'NF' | sort -u | head -n 20 > "$BRUTE_DIR/brute_targets.txt"
BRUTE_COUNT=$(wc -l < "$BRUTE_DIR/brute_targets.txt" | tr -d ' ')
log_info "Brute-forcing $BRUTE_COUNT hosts..."

# 1. FFUF (Fast) — run up to 5 hosts in parallel
if command -v ffuf &> /dev/null; then
    log_info "Running FFUF (parallel, up to 5 hosts)..."
    _brute_pids=()
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        # Sanitise hostname for use in filename (no ${//} to avoid bash version issues)
        _safe=$(printf '%s' "$host" | tr -c 'a-zA-Z0-9' '_')
        (
            log_info "FFUF: $host"
            ffuf -u "https://$host/FUZZ" -w "$WORDLIST" \
                -mc 200,201,202,203,204,301,302,307,308,401,403 \
                -t "$FFUF_THREADS" -timeout "$FFUF_TIMEOUT" -s -json \
                -o "$BRUTE_DIR/ffuf_${_safe}.json" 2>/dev/null || true
        ) &
        _brute_pids+=("$!")
        # Keep concurrency ≤ 5
        while [ "${#_brute_pids[@]}" -ge 5 ]; do
            wait "${_brute_pids[0]}" 2>/dev/null || true
            _brute_pids=("${_brute_pids[@]:1}")
        done
    done < "$BRUTE_DIR/brute_targets.txt"
    # Wait for remaining jobs
    for _p in "${_brute_pids[@]}"; do wait "$_p" 2>/dev/null || true; done

    # Merge FFUF results into a JSON array
    if command -v jq &>/dev/null; then
        jq -s '.' "$BRUTE_DIR"/ffuf_*.json > "$BRUTE_DIR/ffuf_all.json" 2>/dev/null || touch "$BRUTE_DIR/ffuf_all.json"
    else
        python3 - <<PYEOF 2>/dev/null || touch "$BRUTE_DIR/ffuf_all.json"
import json, glob
results = []
for f in sorted(glob.glob('$BRUTE_DIR/ffuf_*.json')):
    try:
        with open(f) as fh:
            results.append(json.load(fh))
    except Exception:
        pass
with open('$BRUTE_DIR/ffuf_all.json', 'w') as out:
    json.dump(results, out)
PYEOF
    fi
else
    log_warn "FFUF not found"
fi

# 2. Feroxbuster (Recursive) — run up to 5 hosts in parallel
if command -v feroxbuster &> /dev/null; then
    log_info "Running Feroxbuster (parallel, up to 5 hosts)..."
    _brute_pids=()
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        _safe=$(printf '%s' "$host" | tr -c 'a-zA-Z0-9' '_')
        (
            log_info "Feroxbuster: $host"
            feroxbuster -u "https://$host" -w "$WORDLIST" \
                -t "$FEROX_THREADS" -d 2 --auto-bail --random-agent \
                -o "$BRUTE_DIR/feroxbuster_${_safe}.txt" 2>/dev/null || true
        ) &
        _brute_pids+=("$!")
        while [ "${#_brute_pids[@]}" -ge 5 ]; do
            wait "${_brute_pids[0]}" 2>/dev/null || true
            _brute_pids=("${_brute_pids[@]:1}")
        done
    done < "$BRUTE_DIR/brute_targets.txt"
    for _p in "${_brute_pids[@]}"; do wait "$_p" 2>/dev/null || true; done

    cat "$BRUTE_DIR"/feroxbuster_*.txt 2>/dev/null > "$BRUTE_DIR/feroxbuster_all.txt" || touch "$BRUTE_DIR/feroxbuster_all.txt"
else
    log_warn "Feroxbuster not found"
fi

# 3. Dirsearch (Classic) — run up to 5 hosts in parallel
if command -v dirsearch &> /dev/null; then
    log_info "Running Dirsearch (parallel, up to 5 hosts)..."
    _brute_pids=()
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        _safe=$(printf '%s' "$host" | tr -c 'a-zA-Z0-9' '_')
        (
            log_info "Dirsearch: $host"
            dirsearch -u "https://$host" -w "$WORDLIST" \
                -t "$DIRSEARCH_THREADS" --random-agent --exclude-status 404,400,500,502,503 \
                -o "$BRUTE_DIR/dirsearch_${_safe}.txt" 2>/dev/null || true
        ) &
        _brute_pids+=("$!")
        while [ "${#_brute_pids[@]}" -ge 5 ]; do
            wait "${_brute_pids[0]}" 2>/dev/null || true
            _brute_pids=("${_brute_pids[@]:1}")
        done
    done < "$BRUTE_DIR/brute_targets.txt"
    for _p in "${_brute_pids[@]}"; do wait "$_p" 2>/dev/null || true; done

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
    MANTRA_COUNT=$(wc -l < "$CARIDDI_DIR/mantra_secrets.txt" 2>/dev/null | tr -d ' ')
    log_info "JS Endpoints found: $ENDPOINTS_COUNT"
    log_info "JS Secrets found: $SECRETS_COUNT"
    log_info "Secret/API-key findings (mantra): $MANTRA_COUNT"
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

# Arjun (Parameter discovery) — run only on valid URLs (with or without params)
if command -v arjun &> /dev/null; then
    log_info "Running Arjun for parameter discovery..."

    # Prefer URLs that already have query parameters; fall back to alive_urls
    ARJUN_TARGETS="$API_DIR/arjun_targets.txt"
    touch "$ARJUN_TARGETS"
    if [ -s "$URLS_DIR/all_urls.txt" ]; then
        # URLs with params get higher priority (Arjun is faster on them)
        grep -E '\?.+=.' "$URLS_DIR/all_urls.txt" 2>/dev/null | head -n 50 > "$ARJUN_TARGETS"
    fi
    # Pad with alive hosts if we don't have enough parameterized targets
    if [ $(wc -l < "$ARJUN_TARGETS" 2>/dev/null || echo 0) -lt 5 ] && [ -s "$ALIVE_URLS" ]; then
        head -n 10 "$ALIVE_URLS" >> "$ARJUN_TARGETS"
    fi
    sort -u "$ARJUN_TARGETS" -o "$ARJUN_TARGETS" 2>/dev/null || true

    if [ -s "$ARJUN_TARGETS" ]; then
        # Detect arjun flag style (+quiet, -oJ vs --output)
        _arjun_help=$(arjun -h 2>&1 || true)
        _arjun_quiet=""
        echo "$_arjun_help" | grep -q -- '--quiet'  && _arjun_quiet="--quiet"
        echo "$_arjun_help" | grep -q -- '-q '      && _arjun_quiet="-q"

        _arjun_out_opt=""
        echo "$_arjun_help" | grep -q -- '-oJ' && _arjun_out_opt="-oJ"
        if [ -z "$_arjun_out_opt" ] && echo "$_arjun_help" | grep -q -- '--output'; then
            _arjun_out_opt="--output"
        fi

        while IFS= read -r url; do
            [ -z "$url" ] && continue
            host=$(echo "$url" | sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|:.*||')
            log_info "Arjun: $url"
            out="$API_DIR/arjun_${host//[^a-zA-Z0-9]/_}.json"
            if [ -n "$_arjun_out_opt" ]; then
                # shellcheck disable=SC2086
                arjun -u "$url" $_arjun_out_opt "$out" $_arjun_quiet 2>/dev/null || true
            else
                # Very old Arjun versions: fallback to stdout redirection
                # shellcheck disable=SC2086
                arjun -u "$url" $_arjun_quiet > "$out" 2>/dev/null || true
            fi
        done < "$ARJUN_TARGETS"
    else
        log_warn "Arjun: no valid targets found"
    fi

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
echo "API Key Leaks (mantra): ${MANTRA_COUNT:-0}"
echo "Cariddi Findings: $(wc -l < "$CARIDDI_DIR/cariddi_secrets.txt" 2>/dev/null | tr -d ' ')"
echo "Gitleaks Web Secrets: $(python3 -c "import json; print(len(json.load(open('$URLS_DIR/secrets/gitleaks_web.json'))))" 2>/dev/null || echo '0')"
echo "TruffleHog Web Secrets: $(wc -l < "$URLS_DIR/secrets/trufflehog_web.json" 2>/dev/null | tr -d ' ')"
echo "Pastebin Mentions: $PASTE_COUNT"
echo ""
echo "Output directories:"
echo "  - $URLS_DIR: URL discovery results"
echo "  - $URLS_DIR/cariddi: cariddi crawl + secrets/endpoints + mantra secrets"
echo "  - $URLS_DIR/secrets: gitleaks + trufflehog web content secret scans"
echo "  - $BRUTE_DIR: Directory brute-force results"
echo "  - $JS_DIR: JavaScript analysis (LinkFinder, SecretFinder)"
echo "  - $PASTE_DIR: Pastebin monitoring"
echo "  - $API_DIR: API testing"

# Create phase completion marker
touch "$PHASE_DIR/.completed"
log_info "Phase 3 complete: success=$TOOLS_SUCCESS failed=$TOOLS_FAILED skipped=$TOOLS_SKIPPED"

exit 0
