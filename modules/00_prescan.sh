#!/bin/bash
################################################################################
# Technieum - Phase 0: Pre-Scan Intelligence
# Risk profiling before scanning begins. Does not modify existing phases.
################################################################################

set +e
set -o pipefail

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase0_prescan"
mkdir -p "$PHASE_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

PRESCAN_TIMEOUT="${TECHNIEUM_PRESCAN_TIMEOUT:-120}"

echo "[*] Phase 0: Pre-Scan Intelligence for $TARGET"
echo "[*] Output directory: $PHASE_DIR"

log_info "=== PRE-SCAN RISK PROFILING ==="

# 1. WHOIS for organization / company
WHOIS_FILE="$PHASE_DIR/whois.txt"
if command -v whois &>/dev/null; then
    log_info "Running whois..."
    run_timeout "$PRESCAN_TIMEOUT" whois "$TARGET" > "$WHOIS_FILE" 2>/dev/null || log_warn "Whois failed or timed out"
else
    log_warn "Whois not found"
    touch "$WHOIS_FILE"
fi

# 2. Extract company / org from whois
COMPANY=""
if [ -s "$WHOIS_FILE" ]; then
    COMPANY=$(grep -iE '^(org-name|organization|orgname|registrant organization|owner):' "$WHOIS_FILE" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/^"//;s/"$//' | head -c 200)
fi
[ -z "$COMPANY" ] && COMPANY="Unknown"

# 3. Baseline: check for previous scan (query DB from Python later if needed; here we only note)
LAST_SCAN_DATE=""
if [ -n "$TECHNIEUM_DB_PATH" ] && [ -f "$TECHNIEUM_DB_PATH" ]; then
    LAST_SCAN_DATE=$(sqlite3 "$TECHNIEUM_DB_PATH" "SELECT updated_at FROM scan_progress WHERE target='$TARGET' LIMIT 1;" 2>/dev/null || true)
fi

# 4. Inherent risk (0-100): simple heuristic without external APIs
# Base 50; adjust by TLD and company name length as a stand-in for "size"
INHERENT_RISK=50
echo "$TARGET" | grep -qE '\.(gov|mil)$' && INHERENT_RISK=$(( INHERENT_RISK + 10 ))
echo "$TARGET" | grep -qE '\.(edu|org)$' && INHERENT_RISK=$(( INHERENT_RISK + 5 ))
[ ${#COMPANY} -gt 30 ] && INHERENT_RISK=$(( INHERENT_RISK + 5 ))
[ "$COMPANY" = "Unknown" ] && INHERENT_RISK=$(( INHERENT_RISK - 5 ))
[ $INHERENT_RISK -lt 0 ] && INHERENT_RISK=0
[ $INHERENT_RISK -gt 100 ] && INHERENT_RISK=100

# 5. Scan intensity from risk
if [ $INHERENT_RISK -ge 75 ]; then
    SCAN_INTENSITY="deep"
elif [ $INHERENT_RISK -ge 50 ]; then
    SCAN_INTENSITY="standard"
else
    SCAN_INTENSITY="light"
fi

# 6. Known breaches placeholder (optional: HIBP/API later)

# 7. Write prescan_risk_profile.json (Python for safe JSON)
OUTPUT_JSON="$PHASE_DIR/prescan_risk_profile.json"
export COMPANY TARGET INHERENT_RISK SCAN_INTENSITY LAST_SCAN_DATE OUTPUT_JSON
python3 -c "
import json, os
d = {
    'company': os.environ.get('COMPANY', 'Unknown'),
    'target': os.environ.get('TARGET', ''),
    'industry': 'Unknown',
    'naics_code': '',
    'size': '',
    'inherent_risk': int(os.environ.get('INHERENT_RISK', 50)),
    'previous_scans': 0,
    'last_scan_date': (os.environ.get('LAST_SCAN_DATE') or '').strip(),
    'known_breaches': [],
    'scan_intensity': os.environ.get('SCAN_INTENSITY', 'standard'),
}
with open(os.environ.get('OUTPUT_JSON', ''), 'w') as f:
    json.dump(d, f, indent=2)
"

log_info "Pre-scan profile written to $OUTPUT_JSON"
log_info "Inherent risk: $INHERENT_RISK | Scan intensity: $SCAN_INTENSITY"
echo "[+] Phase 0 completed successfully!"
